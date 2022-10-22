package dqj.dfido2lib.demo

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.EditText
import android.widget.TextView
import dqj.dfido2lib.core.internal.Fido2Logger
import dqj.dfido2lib.core.client.Fido2Core
import dqj.dfido2lib.core.client.Fido2Error
import dqj.dfido2lib.core.client.Fido2Util
import kotlinx.coroutines.*

class MainActivity : AppCompatActivity() {
    private val fido2SvrURL = "https://mac.dqj-macpro.com" /*"http://192.168.0.124:3000"*/

    private lateinit var helloTxt: TextView
    private lateinit var inside_storage_text: TextView
    private lateinit var fido2Client:Fido2Core

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        Fido2Logger.confLogLevel(Fido2Logger.Companion.Level.debug)

        helloTxt = findViewById(R.id.hello_text)
        inside_storage_text = findViewById(R.id.inside_storage_text)

        fido2Client = Fido2Core(this)

        //Fido2Core.configInsideAuthenticatorResidentStorage(false)

        inside_storage_text.text =
            if(Fido2Core.enabledInsideAuthenticatorResidentStorage()) "Enabled inside ResidentStorage"
            else  "Disabled inside ResidentStorage"
    }

    fun clickReg(view: View){
        helloTxt.text = "Registration..."

        var unm = (findViewById<EditText>(R.id.user_name)).text.toString()
        if(unm.isEmpty()){
            unm = "dqj001"
        }
        var disp = (findViewById<EditText>(R.id.display_name)).text.toString()
        if( disp.isEmpty()){
            disp = "Display_$unm"
        }

        val opt = Fido2Util.getDefaultRegisterOptions(unm, disp)
        try {
            GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                try {
                    val succ = fido2Client.registerAuthenticator(
                        fido2SvrURL, unm, disp, opt,
                        "Register", "Register your FIDO2 account", true
                    )

                    if (succ) {
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = "Register succ"
                        }
                    } else {
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = "Register error"
                        }
                    }
                } catch (err: Fido2Error) {
                    Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
                    GlobalScope.launch(Dispatchers.Main) {
                        helloTxt.text = err.fullMessage()
                    }
                } catch (ex: Exception) {
                    val msg = ex.localizedMessage + "|" + ex.message
                    Fido2Logger.err(MainActivity::class.simpleName, msg)
                    GlobalScope.launch(Dispatchers.Main) {
                        helloTxt.text = ex.localizedMessage + "|" + ex.message
                    }
                }
            }
        } catch (err: Fido2Error) {
            Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
            GlobalScope.launch(Dispatchers.Main) {
                helloTxt.text = err.fullMessage()
            }
        }catch (ex: Exception) {
            val msg=ex.localizedMessage + "|" + ex.message
            Fido2Logger.err(MainActivity::class.simpleName, msg)
            helloTxt.text = ex.localizedMessage + "|" + ex.message
        }
    }

    fun clickAuth(view: View){
        helloTxt.text = "Authentication..."

        var unm = (findViewById<EditText>(R.id.user_name)).text.toString()
        if(unm.isEmpty()){
            unm = "dqj001"
        }

        val opt = Fido2Util.getDefaultAuthenticateOptions(unm)
        try {
            GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                try {
                    val succ = fido2Client.authenticate(
                        fido2SvrURL, opt,
                        "Authentication", "Authenticate your FIDO2 account", true
                    )

                    if (succ) {
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = "Authentication succ"
                        }
                    } else {
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = "Authentication error"
                        }
                    }
                } catch (err: Fido2Error) {
                    Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
                    GlobalScope.launch(Dispatchers.Main) {
                        helloTxt.text = err.fullMessage()
                    }
                } catch (ex: Exception) {
                    val msg = ex.localizedMessage + "|" + ex.message
                    Fido2Logger.err(MainActivity::class.simpleName, msg)
                    GlobalScope.launch(Dispatchers.Main) {
                        helloTxt.text = ex.localizedMessage + "|" + ex.message
                    }
                }
            }
        } catch (err: Fido2Error) {
            Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
            GlobalScope.launch(Dispatchers.Main) {
                helloTxt.text = err.fullMessage()
            }
        }catch (ex: Exception) {
            val msg=ex.localizedMessage + "|" + ex.message
            Fido2Logger.err(MainActivity::class.simpleName, msg)
            helloTxt.text = ex.localizedMessage + "|" + ex.message
        }
    }

    fun clickAuthDiscover(view: View){
        if(Fido2Core.enabledInsideAuthenticatorResidentStorage()){
            helloTxt.text = "Auth(discover)..."
            val opt = Fido2Util.getDefaultAuthenticateOptions()
            try {
                GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                    try {
                        val succ = fido2Client.authenticate(
                            fido2SvrURL, opt,
                            "Authentication", "Authenticate your FIDO2 account", true
                        )

                        if (succ) {
                            GlobalScope.launch(Dispatchers.Main) {
                                helloTxt.text = "Auth(discover) succ"
                            }
                        } else {
                            GlobalScope.launch(Dispatchers.Main) {
                                helloTxt.text = "Auth(discover) error"
                            }
                        }
                    } catch (err: Fido2Error) {
                        Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = err.fullMessage()
                        }
                    } catch (ex: Exception) {
                        val msg = ex.localizedMessage + "|" + ex.message
                        Fido2Logger.err(MainActivity::class.simpleName, msg)
                        GlobalScope.launch(Dispatchers.Main) {
                            helloTxt.text = ex.localizedMessage + "|" + ex.message
                        }
                    }
                }
            } catch (err: Fido2Error) {
                Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
                GlobalScope.launch(Dispatchers.Main) {
                    helloTxt.text = err.fullMessage()
                }
            }catch (ex: Exception) {
                val msg=ex.localizedMessage + "|" + ex.message
                Fido2Logger.err(MainActivity::class.simpleName, msg)
                helloTxt.text = ex.localizedMessage + "|" + ex.message
            }
        }else{
            helloTxt.text = "Resident storage is disabled!"
        }
    }

    fun clearKeys(view: View){
        helloTxt.text = "clearKeys..."
       try {
            GlobalScope.launch(Dispatchers.Default){//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                fido2Client.clearKeys(null)
                GlobalScope.launch(Dispatchers.Main) {
                    helloTxt.text = "clearKeys done"
                }
            }
        } catch (err: Fido2Error) {
           Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
           GlobalScope.launch(Dispatchers.Main) {
               helloTxt.text = err.fullMessage()
           }
       } catch (e: java.lang.Exception) {
            e.localizedMessage?.let { Fido2Logger.err(MainActivity::class.simpleName, it) }
            helloTxt.text = e.localizedMessage
       }
    }

    fun reset(view: View){
        helloTxt.text = "Reset..."
        try {
            GlobalScope.launch(Dispatchers.Default){//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                fido2Client.reset()
                GlobalScope.launch(Dispatchers.Main) {
                    helloTxt.text = "Reset done"

                    inside_storage_text.text =
                        if(Fido2Core.enabledInsideAuthenticatorResidentStorage()) "Enabled inside ResidentStorage"
                        else  "Disabled inside ResidentStorage"
                }
            }
        } catch (err: Fido2Error) {
            Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
            GlobalScope.launch(Dispatchers.Main) {
                helloTxt.text = err.fullMessage()
            }
        } catch (e: java.lang.Exception) {
            e.localizedMessage?.let { Fido2Logger.err(MainActivity::class.simpleName, it) }
            helloTxt.text = e.localizedMessage
        }
    }

    fun clearRp(view: View){
        helloTxt.text = "Clear RP..."
        var rp = (findViewById<EditText>(R.id.clear_rp)).text.toString()
        if(rp.isEmpty()){
            helloTxt.text = "Input rpId to clear, please."
        }else{
            try {
                GlobalScope.launch(Dispatchers.Default){//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                    fido2Client.clearKeys(rp)
                    GlobalScope.launch(Dispatchers.Main) {
                        helloTxt.text = "cleared RP: $rp"
                    }
                }
            } catch (err: Fido2Error) {
                Fido2Logger.err(MainActivity::class.simpleName, err.fullMessage())
                GlobalScope.launch(Dispatchers.Main) {
                    helloTxt.text = err.fullMessage()
                }
            } catch (e: java.lang.Exception) {
                e.localizedMessage?.let { Fido2Logger.err(MainActivity::class.simpleName, it) }
                helloTxt.text = e.localizedMessage
            }
        }
    }
}