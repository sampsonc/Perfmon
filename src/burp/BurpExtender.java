package burp;

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import perfmon.PerfComponent;
import perfmon.PerfTab;

/**
 *
 * @author csampson
 */
public class BurpExtender implements IBurpExtender
{
    private IExtensionHelpers helpers;
    private static final String EXTENSION_NAME = "Perfmon";
    private OutputStream os;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {     
        helpers = callbacks.getHelpers();  //Helper functions available to use
        callbacks.setExtensionName(EXTENSION_NAME);  //Set the extension name
        os = callbacks.getStdout();  //Handle to the outputstream
        
        //Add UI
        PerfTab tab = new PerfTab("Perfmon", callbacks);
        PerfComponent comp = new PerfComponent(callbacks, this);
        tab.addComponent(comp);
        comp.start();
                
        println("Perfmon Loaded");
    }
    
    public void println(String msg)
    {
        try
        {
            os.write(msg.getBytes());
            os.write("\n".getBytes());
        } catch (IOException ex)
        {
            Logger.getLogger(BurpExtender.class.getName()).log(Level.SEVERE, null, ex);
        } 
    }
    
}
