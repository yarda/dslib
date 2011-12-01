# encoding: utf-8

#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*

MESSAGE_STATUS = {
	1: u"zpráva byla podána (vznikla v ISDS)",
	2: u"datová zpráva včetně písemností podepsána časovým razítkem",
	3: u"zpráva neprošla AV kontrolou; nakažená písemnost je smazána; konečný \
stav zprávy před smazáním",
	4: u"zpráva dodána do ISDS (zapsán čas dodání)",
	5: u"uplynulo 10 dní od dodání veřejné zprávy, která dosud nebyla doručena \
přihlášením (předpoklad doručení fikcí u neOVM DS); u komerční zprávy nemůže\
tento stav nastat",
	6: u"osoba oprávněná číst tuto zprávu se přihlásila - dodaná zpráva byla \
doručena;",
	7: u"zpráva byla přečtena (na portále nebo akcí ESS)",
	8: u"zpráva byla označena jako nedoručitelná, protože DS adresáta byla \
zpětně znepřístupněna",
	9: u"obsah zprávy byl smazán, obálka zprávy včetně hashů přesunuta do \
archivu",
	10: u"zpráva je v Datovém trezoru",
}

ORG_TYPE_NUM_TO_TEXT = {10:"OVM",20:"PO",30:"PFO",40:"FO"}
