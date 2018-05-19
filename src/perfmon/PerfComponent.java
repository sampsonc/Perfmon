/*
 * The MIT License
 *
 * Copyright 2017 Carl Sampson <chs@chs.us>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package perfmon;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.awt.GridLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Carl Sampson <chs@chs.us>
 */
public class PerfComponent extends JPanel implements Runnable
{

    IBurpExtenderCallbacks callbacks;
    BurpExtender extender;
    JLabel lblThread;
    JLabel lblThreadValue;
    JLabel lblTotalMemory;
    JLabel lblTotalMemoryValue;
    JLabel lblUsedMemory;
    JLabel lblUsedMemoryValue;

    private Thread t;

    public PerfComponent(IBurpExtenderCallbacks callbacks, BurpExtender extender)
    {
        this.callbacks = callbacks;
        this.extender = extender;
        t = null;
        initComponents();
    }

    private void initComponents()
    {
       lblThread = new JLabel("Threads: ");
       callbacks.customizeUiComponent(lblThread);
       
       lblThreadValue = new JLabel("0");
       callbacks.customizeUiComponent(lblThreadValue);
       
       lblUsedMemory = new JLabel("Memory Currently Used: ");
       callbacks.customizeUiComponent(lblUsedMemory);
       
       lblUsedMemoryValue = new JLabel("0");
       callbacks.customizeUiComponent(lblUsedMemoryValue);
       
       lblTotalMemory = new JLabel("Memory Allocated:");
       callbacks.customizeUiComponent(lblTotalMemory);
       
       lblTotalMemoryValue = new JLabel("0");
       callbacks.customizeUiComponent(lblTotalMemoryValue);

       GridLayout layout = new GridLayout(0, 2);
       this.setLayout(layout);
       
       this.add(lblThread);
       this.add(lblThreadValue);
       this.add(lblUsedMemory);
       this.add(lblUsedMemoryValue);
       this.add(lblTotalMemory);
       this.add(lblTotalMemoryValue);
    }

    @Override
    public void run()
    {
        int maxThreads = 0; 
        long maxTotalMemory = 0;
        long maxUsedMemory = 0;
        while (true)
        {
            try
            {  
                //Get current
                Set<Thread> threadSet = Thread.getAllStackTraces().keySet();
                int curThreads = threadSet.size();
                long totalMemory = Runtime.getRuntime().totalMemory();
                long usedMemory = Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
                
                //Get maxes
                maxThreads = curThreads > maxThreads ? curThreads : maxThreads;
                maxTotalMemory = totalMemory > maxTotalMemory ? totalMemory : maxTotalMemory;
                maxUsedMemory = usedMemory > maxUsedMemory ? usedMemory : maxUsedMemory;
                
                //Set labels.  Need to change to StringBuffers
                lblThreadValue.setText(Integer.toString(threadSet.size()) + " (" + Integer.toString(maxThreads) + ")");
                lblTotalMemoryValue.setText(String.format("%,d", totalMemory) + " (" + String.format("%,d", maxTotalMemory) + ")");
                lblUsedMemoryValue.setText(String.format("%,d", usedMemory) + " (" + String.format("%,d", maxUsedMemory) + ")");
                
                //Sleep
                Thread.sleep(3000);
            } catch (InterruptedException ex)
            {
                Logger.getLogger(PerfComponent.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
     public void start () {
      if (t == null) {
         t = new Thread (this, "Thread");
         t.start ();
      }
   }
}