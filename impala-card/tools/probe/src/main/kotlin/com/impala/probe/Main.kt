package com.impala.probe

import javax.smartcardio.CommandAPDU
import javax.smartcardio.TerminalFactory
import kotlin.system.exitProcess

/**
 * Probes the card in a PC/SC reader: `impala-probe [reader name substring]`.
 * The probe CAP must be installed on it first (README.md). Reads only; the
 * card is left as it was.
 */
fun main(args: Array<String>) {
    val want = args.firstOrNull()?.lowercase() ?: ""
    val terminal = TerminalFactory.getDefault().terminals().list()
        .firstOrNull { it.name.lowercase().contains(want) && it.isCardPresent }
    if (terminal == null) {
        System.err.println("no reader with a card" + if (want.isEmpty()) "" else " matching '$want'")
        exitProcess(1)
    }
    val card = terminal.connect("*")
    try {
        val channel = card.basicChannel
        System.err.println("reader: ${terminal.name}")
        System.err.println("ATR:    ${Probe.hex(card.atr.bytes)}")
        val aid = Probe.unhex(Probe.APPLET_AID)
        val select = channel.transmit(CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid))
        if (select.sw != 0x9000) {
            System.err.println("the probe applet is not on this card (SELECT answered %04X): install build/ImpalaProbe.cap first".format(select.sw))
            exitProcess(1)
        }
        val (findings, verdict) = Probe { cmd -> channel.transmit(CommandAPDU(cmd)).bytes }.run()
        print(Probe.render(findings, verdict))
    } finally {
        card.disconnect(false)
    }
}
