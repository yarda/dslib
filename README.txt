This is UNOFFICIAL fork of dslib.
The dslib upstream is: https://git.nic.cz/redmine/projects/dslib
The purpose of this fork is to help dslib upstream to switch to upstream version of suds (http://fedorahosted.org/suds/).

=====
dslib
=====

dslib je svobodná (licence LGPL) knihovna pro přístup k Datovým schránkám.
Knihovna je napsaná v jazyce Python a ve svém základě jde v podstatě o tenkou
vrstvu nad SOAP rozhraním, které systém datových schránek poskytuje.

V současné verzi jsou implementovány následující funkce:

 * GetListOfSentMessages
 * GetListOfReceivedMessages
 * MessageEnvelopeDownload
 * MessageDownload
 * SignedMessageDownload
 * SignedSentMessageDownload
 * GetDeliveryInfo
 * GetSignedDeliveryInfo
 * GetOwnerInfoFromLogin
 * GetUserInfoFromLogin
 * GetPasswordInfo
 * ChangeISDSPassword
 * FindDataBox
 * CreateMessage
 * MarkMessageAsDownloaded
 * DummyOperation
 
Autentizace je implementovaná v plném rozsahu a lze tedy využít kombinaci jména
a hesla, jednorázová hesla i autentizaci pomocí klientského certifikátu.

Ukázkový kód pro knihovnu je k disposici v souboru tests.py


SOAP knihovna
==============

Pro potřeby komunikace se serverem datových schránek pomocí SOAP rozhraní
využívá dslib upravenou verzi knihovny "suds" (https://fedorahosted.org/suds).
Ta je vydávána pod názvem sudsds a je stejně jako dslib a suds vydávána pod
licencí LGPL. Balíčky ke stažení jsou k dispozici na stránkách projektu
Datovka - 
Pokud bude v budoucnosti možné použít oficiální verzi "suds", bude naše upravená
verze z balíčku nahrazena upsteamovou verzí.


Knihovna pyasn1
================

dslib verze 1.4.1 a nižší obsahovaly přibalenou upravenou knihovnu pyasn1
založenou na upstreamové verzi 0.0.9a. V rámci usnadnění balíčkování byla v
dslib odstraněna nutnost používat modifikovanou knihovnu pyasn1 a je možné
využít upstreamovou verzi. Je však nutno použít verzi minimálně 0.0.13b.
Protože tato verze není ve většině distribucí k dispozici, obsahovala dslib
do verze 1.7 přibalenou kopii pyans1-0.0.13b.
Od verze 1.8 již není pyasn1 k dslib přibalena a v případě, že není možné
nainstalovat požadovanou minimální verzi pyasn1 do systému s pomocí systémových
zdrojů (např. balíčkovacího systému), lze zdrojové kódy pyasn1 rozbalit přímo do
adresáře dslib pod jménem pyasn1. Tím by mělo být zaručeno že bude přednostně
importována tato verze knihovny a ne verze systémová.


Autoři
=======

Knihovna dslib byla vytvořená ve vývojových laboratořích CZ.NIC, z.s.p.o.- 
CZ.NIC Labs (http://labs.nic.cz/) 

