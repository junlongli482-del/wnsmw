const {baseUrl,curveBorder=false}=require('../../config')
Page({
  data:{status:'正在连接扫描服务…',ready:false,processing:false,pages:[]},
  onLoad(){this.active=true;this.busy=false;this.generation=0;this.lastFrame=0;this.networkTask=null},
  onReady(){
    wx.createSelectorQuery().select('#outline').fields({node:true,size:true}).exec(result=>{
      if(!this.active||!result[0])return
      const info=result[0],dpr=wx.getWindowInfo().pixelRatio
      this.canvas=info.node;this.viewWidth=info.width;this.viewHeight=info.height
      this.canvas.width=info.width*dpr;this.canvas.height=info.height*dpr
      this.context=this.canvas.getContext('2d');this.context.scale(dpr,dpr)
    })
    this.connect()
  },
  connect(){
    const generation=this.generation
    this.healthTask=wx.request({url:baseUrl+'/health',timeout:15000,success:r=>{
      if(!this.active||generation!==this.generation)return
      if(r.statusCode===200)this.setData({status:'请将整张试卷放入画面',ready:true})
      else this.setData({status:'扫描服务尚未就绪'})
    },fail:()=>{if(this.active&&generation===this.generation)this.setData({status:'未连接扫描服务，请检查服务地址'})}})
  },
  cameraReady(){
    if(this.listener)this.listener.stop()
    this.camera=wx.createCameraContext()
    this.listener=this.camera.onCameraFrame(frame=>this.frame(frame));this.listener.start()
  },
  cameraError(event){this.setData({status:event.detail.errMsg||'无法打开相机，请检查权限'})},
  onHide(){this.active=false;this.generation++;if(this.listener)this.listener.stop();for(const task of [this.networkTask,this.scanTask,this.healthTask])if(task)task.abort();this.networkTask=null;this.scanTask=null;this.healthTask=null;this.busy=false;this.setData({processing:false,ready:false});this.draw(null)},
  onShow(){const returning=!this.active;this.active=true;if(this.listener)this.listener.start();if(returning)this.connect()},
  onUnload(){this.onHide()},
  draw(quad,width,height,stable,curve){
    const ctx=this.context;if(!ctx)return
    ctx.clearRect(0,0,this.viewWidth,this.viewHeight)
    if(!quad||quad.length!==8)return
    // Camera preview fills its view. Verify frame orientation/cover mapping on the target phone.
    const scale=Math.max(this.viewWidth/width,this.viewHeight/height)
    const left=(this.viewWidth-width*scale)/2,top=(this.viewHeight-height*scale)/2
    ctx.strokeStyle=stable?'#6ff0bc':'#ffce68';ctx.lineWidth=3;ctx.beginPath()
    const points=Array.isArray(curve)&&curve.length===160?curve:quad
    for(let i=0;i<points.length/2;i++){const x=left+points[i*2]*scale,y=top+points[i*2+1]*scale;i?ctx.lineTo(x,y):ctx.moveTo(x,y)}
    ctx.closePath();ctx.stroke()
  },
  frame(frame){
    const now=Date.now()
    if(!this.active||!this.data.ready||this.data.processing||this.busy||now-this.lastFrame<400)return
    this.busy=true;this.lastFrame=now;const generation=this.generation
    const task=wx.request({url:baseUrl+(curveBorder?'/detect-curve-rgba':'/detect-rgba'),method:'POST',data:frame.data,timeout:10000,
      header:{'content-type':'application/octet-stream','x-frame-width':String(frame.width),'x-frame-height':String(frame.height)},
      success:r=>{
        if(!this.active||this.data.processing||generation!==this.generation)return
        if(r.statusCode===429){this.draw(null);return}
        if(r.statusCode!==200){this.setData({status:'边框服务响应异常'});this.draw(null);return}
        this.draw(r.data.quad,r.data.width,r.data.height,r.data.stable,r.data.curve)
        this.setData({status:r.data.quad.length===8?(r.data.stable?'已识别边框，可以拍摄':'请保持稳定…'):'寻找纸张…'})
      },fail:()=>{if(this.active&&!this.data.processing&&generation===this.generation){this.setData({status:'边框连接中断，请检查网络'});this.draw(null)}},
      complete:()=>{if(this.networkTask===task){this.busy=false;this.networkTask=null}}
    })
    this.networkTask=task
  },
  capture(){
    if(this.data.processing||!this.camera)return
    this.generation++;const generation=this.generation
    const current=()=>this.active&&generation===this.generation
    this.setData({processing:true,status:'正在拍摄…'});this.draw(null)
    const take=()=>this.camera.takePhoto({quality:'high',success:photo=>{
      if(!current())return
      this.setData({status:'正在处理试卷…'})
      wx.getFileSystemManager().readFile({filePath:photo.tempImagePath,success:file=>{if(current())this.scan(file.data)},fail:error=>{if(current())this.finishError(error.errMsg)}})
    },fail:error=>{if(current())this.finishError(error.errMsg)}})
    // Wait for the single outstanding detection to complete before queuing the full image.
    const wait=()=>{if(!current())return;if(this.busy){setTimeout(wait,80);return}take()};wait()
  },
  scan(data){
    const generation=this.generation,current=()=>this.active&&generation===this.generation
    this.scanTask=wx.request({url:baseUrl+'/scan',method:'POST',data,responseType:'arraybuffer',timeout:120000,header:{'content-type':'image/jpeg'},
      success:result=>{
        if(!current())return
        if(result.statusCode!==200){this.finishError('未识别到完整纸张或处理失败，请重新拍摄');return}
        const path=wx.env.USER_DATA_PATH+'/scan-'+Date.now()+'.png'
        wx.getFileSystemManager().writeFile({filePath:path,data:result.data,success:()=>{if(current())this.setData({pages:this.data.pages.concat([{path}]),processing:false,status:'已完成，可继续拍下一页'})},fail:error=>{if(current())this.finishError(error.errMsg)}})
      },fail:error=>{if(current())this.finishError(error.errMsg)}
    })
  },
  finishError(message){this.setData({processing:false,status:message||'处理失败，请重试'})},
  previewPage(event){wx.previewImage({current:this.data.pages[Number(event.currentTarget.dataset.index)].path,urls:this.data.pages.map(page=>page.path)})}
})
