package org.localresearch.scanner;

/** Ordinary four-corner display deadband from restored DetectPreviewBorderHandle.
 * Source: m662200 + m6626O8O8008, threshold supplied by AutoDrawBorderHandle
 * as dip2px(5)^2. Only controls drawing; never modifies detection or crop input.
 * Curved-border 7dp matching and sensor gating are separate original branches.
 */
final class RecoveredBorderDisplay {
    private final int[] displayed=new int[8];
    private final int thresholdSquared;
    RecoveredBorderDisplay(float density) {
        int pixels=(int)(5*density+0.5f);
        thresholdSquared=pixels*pixels;
    }
    int[] update(int[] quad) {
        if(quad==null || quad.length!=8){reset();return null;}
        for(int i=0;i<8;i+=2) {
            int dx=displayed[i]-quad[i],dy=displayed[i+1]-quad[i+1];
            if((int)Math.pow(dx,2)+(int)Math.pow(dy,2)>thresholdSquared) {
                displayed[i]=quad[i];displayed[i+1]=quad[i+1];
            }
        }
        return displayed.clone();
    }
    void reset(){java.util.Arrays.fill(displayed,0);}
}
