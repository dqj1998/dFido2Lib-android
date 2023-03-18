package dqj.dfido2lib.demo

import android.content.Context
import android.content.DialogInterface
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import dqj.dfido2lib.core.LibConfig
import dqj.dfido2lib.core.authenticator.decodeBasee64URLTry
import dqj.dfido2lib.core.client.Fido2Core
import dqj.dfido2lib.core.client.Fido2Error
import dqj.dfido2lib.core.client.Fido2Util
import dqj.dfido2lib.core.internal.Fido2Logger
import dqj.dfido2lib.ext.ClientExt
import kotlinx.coroutines.*


@OptIn(DelicateCoroutinesApi::class)
class MainActivity : AppCompatActivity() {
    private val fido2SvrURL = "https://mac.dqj-macpro.com" /*"http://192.168.0.124:3000"*/

    private lateinit var helloTxt: TextView
    private lateinit var inside_storage_text: TextView
    private lateinit var fido2Client:Fido2Core
    private lateinit var fido2Ext:ClientExt

    private var curBase64CredId = ArrayList<String>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        LibConfig.enableRooted = true //For development, comment out for product!

        Fido2Logger.confLogLevel(Fido2Logger.Companion.Level.debug)

        helloTxt = findViewById(R.id.hello_text)
        inside_storage_text = findViewById(R.id.inside_storage_text)

        fido2Client = Fido2Core(this)

        fido2Ext = ClientExt(this)

        //LibConfig.configInsideAuthenticatorResidentStorage(false)

        LibConfig.configAccountListExt(true)

        //Configs for enterprise attestation
        ///Hex of 16 char, Cannot double with aaguids in FIDO2 meta data(https://mds3.fidoalliance.org/)
        ///Have to set enterprise to true and set enterprise_aaguids in doamn.json on server
        /// Changing to an unregistered aaguid will get error of registration.
        LibConfig.setPlatformAuthenticatorAAGUID("aaaaaaaaaaa888888888999999999000")

        LibConfig.addEnterpriseRPIds(arrayOf("rp01.abc.com", "rp02.def.com"))

        inside_storage_text.text =
            if(LibConfig.enabledInsideAuthenticatorResidentStorage()) "Enabled inside ResidentStorage"
            else  "Disabled inside ResidentStorage"

        val adapter = ArrayAdapter<String>(this, android.R.layout.simple_spinner_item)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        adapter.add("mac.dqj-macpro.com")
        adapter.add("rp01.abc.com")
        adapter.add("rp02.def.com")
        val spinner = findViewById<View>(R.id.rpid) as Spinner
        spinner.adapter = adapter
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

        var rpid = (findViewById<Spinner>(R.id.rpid)).selectedItem.toString()

        val opt = Fido2Util.getDefaultRegisterOptions(unm, disp, rpid)
        try {
            GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                try {
                    val succ = fido2Client.registerAuthenticator(fido2SvrURL, opt,
                        "Register", "Register your FIDO2 account",
                        true, view.context
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

        var rpid = (findViewById<Spinner>(R.id.rpid)).selectedItem.toString()

        val opt = Fido2Util.getDefaultAuthenticateOptions(unm, rpid)
        try {
            GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                try {
                    val succ = fido2Client.authenticate(
                        fido2SvrURL, opt,
                        "Authentication", "Authenticate your FIDO2 account",
                        true, null, view.context
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
        curBase64CredId.clear()
        if(Fido2Core.enableAccountsList){
            var rpid = (findViewById<Spinner>(R.id.rpid)).selectedItem.toString()
            var accounts=fido2Ext.listAccounts(fido2SvrURL, rpid)
            if(null!=accounts && 1<accounts.accounts.size) {
                val mNumberPicker = NumberPicker(this)
                var accList = ArrayList<String>();
                accounts?.accounts?.forEach { acc ->
                    accList.add(if (acc.displayname != null) acc.displayname else acc.username)
                    curBase64CredId.add(acc.credIdBase64)
                }

                mNumberPicker.displayedValues = accList.toTypedArray() as Array<out String>?
                mNumberPicker.minValue = 0
                mNumberPicker.maxValue = accList.size - 1

                val builder: AlertDialog.Builder = AlertDialog.Builder(this)
                builder.setTitle("select rp")
                builder.setView(mNumberPicker)
                builder.setPositiveButton(android.R.string.ok)
                { _, i ->
                    val indx=mNumberPicker.value
                    authDiscover(curBase64CredId[indx], view.context)
                }
                builder.setNegativeButton(android.R.string.cancel, null)
                builder.create().show()
            } else curBase64CredId.clear()
        }

        if(curBase64CredId.isEmpty())authDiscover(null, view.context)
    }

    private fun authDiscover(selectedCredId: String?, context: Context){
        if(LibConfig.enabledInsideAuthenticatorResidentStorage()){
            helloTxt.text = "Auth(discover)..."
            var rpid = (findViewById<Spinner>(R.id.rpid)).selectedItem.toString()
            val opt = Fido2Util.getDefaultAuthenticateOptions("", rpid)
            try {
                GlobalScope.launch(Dispatchers.Default) {//Does NOT use main routine because Fido2Lib need block it routine and launch UI(main)
                    try {
                        val succ = fido2Client.authenticate(
                            fido2SvrURL, opt,
                            "Authentication", "Authenticate your FIDO2 account",
                            true, selectedCredId?.let { decodeBasee64URLTry(it) }, context
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
                        if(LibConfig.enabledInsideAuthenticatorResidentStorage()) "Enabled inside ResidentStorage"
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
        var rp = (findViewById<Spinner>(R.id.rpid)).selectedItem.toString()
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