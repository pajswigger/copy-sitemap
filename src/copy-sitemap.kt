package burp

import java.awt.Component
import java.awt.Frame
import java.awt.event.ActionEvent
import java.net.URL
import java.util.*
import javax.swing.*
import kotlin.concurrent.thread


class BurpExtender : IBurpExtender {
    companion object {
        lateinit var cb: IBurpExtenderCallbacks
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        cb = callbacks
        callbacks.setExtensionName("Copy Site Map")
        callbacks.registerContextMenuFactory(ContextMenuFactory())
    }
}


class ContextMenuFactory : IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation): List<JMenuItem> {
        if (invocation.invocationContext != IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE) {
            return arrayListOf()
        }

        val selection = invocation.selectedMessages!!
        if (selection.size != 1) {
            return arrayListOf()
        }

        val menuItem = JMenuItem("Copy branch")
        menuItem.addActionListener(ContextMenuListener(invocation))
        return Arrays.asList(menuItem)
    }
}


class ContextMenuListener(var invocation: IContextMenuInvocation) : AbstractAction() {
    override fun actionPerformed(e: ActionEvent) {
        val item = invocation.selectedMessages!![0]
        val requestInfo = BurpExtender.cb.helpers.analyzeRequest(item.httpService, item.request)
        var source = requestInfo.url
        if(source.port == source.defaultPort) {
            source = URL(source.protocol, source.host, -1, source.file)
        }
        val target = JOptionPane.showInputDialog(e.source as Component, "Target URL", source.toString())
        val progressDialog = ProgressDialog(getBurpFrame(), true)
        progressDialog.setLocationRelativeTo(getBurpFrame())
        SwingUtilities.invokeLater {
            progressDialog.isVisible = true
        }
        UrlCopier(progressDialog, source, URL(target)).start()
    }
}


class UrlCopier(val progressDialog: ProgressDialog, val source: URL, val target: URL) : Thread("UrlCopier") {
    fun hostHeader(url: URL): String {
        return if (url.port == -1 || url.port == url.defaultPort) { url.host } else { "${url.host}:${url.port}" }
    }

    override fun run() {
        val targetHost = hostHeader(target)
        val port = if(target.port == - 1) { target.defaultPort } else { target.port }
        val targetService = BurpExtender.cb.helpers.buildHttpService(target.host, port, target.protocol)

        for (item in BurpExtender.cb.getSiteMap(source.toString())) {
            try {
                if (item.response == null) {
                    continue
                }
                val requestInfo = BurpExtender.cb.helpers.analyzeRequest(item.httpService, item.request)
                val headers = requestInfo.headers.toMutableList()
                val body = Arrays.copyOfRange(item.request, requestInfo.bodyOffset, item.request.size)

                headers[0] = headers[0].replace(source.path, target.path)
                for (i in headers.indices) {
                    if (headers[i].startsWith("Host:")) {
                        headers[i] = "Host: ${targetHost}"
                    }
                    if (headers[i].startsWith("Referer:")) {
                        headers[i] = headers[i].replace(source.toString(), target.toString())
                    }
                }

                val newItem = EditableHttpRequestResponse(item)
                newItem.request = BurpExtender.cb.helpers.buildHttpMessage(headers, body)
                newItem.httpService = targetService
                BurpExtender.cb.addToSiteMap(newItem)
            } catch (ex: Exception) {
                BurpExtender.cb.printError(ex.toString())
            }
        }
        SwingUtilities.invokeLater {
            progressDialog.isVisible = false
        }
    }
}


class EditableHttpRequestResponse(ihrr: IHttpRequestResponse) : IHttpRequestResponse {
    override var request = ihrr.request
    override var response = ihrr.response
    override var comment = ihrr.comment
    override var highlight = ihrr.highlight
    override var httpService = ihrr.httpService
}


fun getBurpFrame(): JFrame? {
    for (f in Frame.getFrames()) {
        if (f.isVisible && f.title.startsWith("Burp Suite")) {
            return f as JFrame
        }
    }
    return null
}
