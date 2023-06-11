[![Say Thanks!](https://img.shields.io/badge/Say%20Thanks-!-1EAEDB.svg)](https://docs.google.com/forms/d/e/1FAIpQLSfBEe5B_zo69OBk19l3hzvBmz3cOV6ol1ufjh0ER1q3-xd2Rg/viewform)

# goIP
goIP is a Go package which validates, parses, and formats IPv4 and IPv6 addresses, as well as creates simple, lightweight structures to store and return common information about IPs which are well suited to be used in iteration.

To import goIP into your project:  
`go get github.com/ScriptTiger/goIP`  
Then just `import "github.com/ScriptTiger/goIP"` and call `goIP.NewIP(<IP>[/<prefix length>])` to get started. Please refer to the reference implementation for more details and ideas on how to integrate goIP into your project.  
https://github.com/ScriptTiger/goIP/tree/main/ref

# Reference Implementation

**Data_Update**

Usage: `Data_Update`

On first run, enter your MaxMind license key when prompted. This will update all relevant files from MaxMind, Tor, Snort, and AlienVault

**IP_Search**

Usage: `IP_Search [options...] [input file] [output file]`

Argument               | Description
-----------------------|--------------------------------------------------------------------------------------------------------
 `-i <file>`           | File with one IP per line to resolve
 `-o <file>`           | File to write results to in CSV format
 `-language <iso>`     | Language of output data
 `-rest <address:port>`| Start REST API on given socket
 `-ipv4`               | Only load IPv4 data
 `-ipv6`               | Only load IPv6 data

This application in no way tries to compare itself or compete with other applications using the official MaxMind DB file format. This application merely provides an alternative for users that wish to import CSV files instead of MMDB files.

Since MMDB is a file format closely developed by MaxMind, it inherently comes with some security concerns. Obviously, MaxMind itself as an entity is well trusted in the industry, and that is not the major concern. The major concern being that since MMDB is still in active development by a small group of people, the file format itself is continuing to change under their guidance and there are no guarantees that MMDB readers will continue to function from one release to another. The CSV format, on the other hand, has been a well-accepted standard since about 1972, without much variation since.

As an added benefit to being able to import CSV files, this naturally means it also makes customization of the imported files much easier to allow users to insert their own private IP block information for private IP blocks under their personal management, as opposed to trying to edit the binary MMDB files.

**Network_Calculator**

Usage: `Network_Calculator <ip address>[/<prefix length>]`

# IPv4, IPv6, and Myth Versus Design

**The Myth**

A common myth about IP addresses is that they were initially designed using the entirety of their address space as a single integer. So, for example, it is commonly thought that because an IPv4 address takes up 32 bits, then it should be therefore treated as an unsigned 32-bit integer, or as a single 32-bit number. And accordingly, it is also commonly thought that because an IPv6 address takes up 128 bits, then it should be therefore treated as an unsigned 128-bit integer. However, this was never actually the initial design of either IPv4 nor IPv6, and they were both initially designed as tuples containing exactly 2 separate and distinct unsigned integers. While today, the newer IPv6 tuple is yet unbroken and there is a clear division between a 64-bit network address and 64-bit host address, many people mistakenly try to apply concepts from the older IPv4 thinking that actually the mess that came to be of the 32-bit IPv4 address space due to a bundle of quick fixes to avoid IP exhaustion is somehow still relevant and that IPv6 just works in the same messy way but with a bigger address space.

**The Misunderstanding**

This common misconception comes from the misunderstanding that IP addresses operate by simply assigning a single integer to each network device, and from there they can simply send each other messages, or packets, by addressing these packets to each other's single-integer addresses as if they were unique device IDs. However, if you liken this to a real-world example, it would be like addressing every building on earth a unique building ID and expecting to be able to just address mail to these building IDs without issue.

Now, continuing the mail example, this might seem like it may work initially, after we have achieved world peace and everyone on earth has agreed to unique building IDs that don't pose any conflicts to each other. But what happens when someone wants to redevelop an old area to tear down old houses and put up a single office building instead? Then, of course, there would be extra IDs left over. Should everyone on earth make a new agreement about new numbers again? Should these numbers just be reused elsewhere on earth by the next new buildings? Or should these numbers just be left unused and new building IDs in the future just continue to increment in value without limit? And what happens when someone wants to build a new house in an old area that's surrounded by houses that already have IDs? Should the new house have an ID that is wildly higher in value than the old houses? Or, again, should everyone on earth get together again to agree on new numbers? If everyone's building ID is unique and not guaranteed to even be close in value to other buildings near them, how then would mail carriers even know where houses are from just a single ID alone? Would there need to be a global register of all buildings on earth that every mail carrier would have to reference for every piece of mail they wish to deliver?

As you probably already know, that's not quite how mail works, right? When someone addresses you, can you imagine only putting the street address number and leaving it at that? Of course, you would need to also include the street name, city name, and other relevant details, like postal code, province, and even country. This is because local authorities can act autonomously within their own autonomous systems, or domains of influence, and manage addresses how they see fit and they don't need to consult everyone else on earth first. So, the other pieces of information in an address are needed so that those authorities can route the mail properly within their respective domains.

Now, how is all this related to IP addresses? IP addresses, since their conception, have always been divided between information for the routing between these autonomous systems, or "authorities", and information to identify the exact host within that authority. This allows those autonomous systems to manage their IP addresses themselves so they can organize much more efficiently, as opposed to waiting for a global system to organize the entirety of itself. Also, as we all know, every country, and maybe even some provinces and cities, have their own rules and regulations about accessing the Internet. Some areas impose censorship. Some areas distribute Internet access for free. Most people pay monthly to an ISP, Internet service provider, for this access and the ISP manages whether or not someone has access and what, exactly, they have access to, in accordance with their local policies.

**The Breakdown**

So, hopefully, by this point you can see the importance of having two distinct pieces of information, the routing information as well as the host information. But, still, where did this misconception of having only one piece of information come from? When the Internet first came online, the first byte, 8 bits, of information were used as the routing information to identify the network, and the last 24 bits were used to identify the host. So, two very clear-cut unsigned integers, or numbers, the 8-bit routing information and the 24-bit host identification. As hard as it may be for modern Internet users to fathom, at the time having a simple limit of 254 networks globally (Not 256! As 2 addresses in every network were unusable as host addresses due to being set aside for the purposes of network ID and broadcast address) seemed totally acceptable since it was just a small group of nerdy institutions accessing it at the time.

What happened next is where things start getting messy. As more and more entities saw the importance of the Internet and wanted access to it, the nerdy governing body, Internet Engineering Task Force (IETF), had to quickly get together and solve the very obvious issue that having 254 total global authorities just was not going to cut it and this thing was going to become a lot more popular than they ever could have imagined.

So, as a quick fix, since these were engineers and, of course, logically numbering their networks starting from 0 onward, they had not yet reached the second-most upper bit, or 64. Yes, there actually was a time when the Internet had less than 64 networks! So, in order to make room for more networks and also allow older systems to continue to operate, the uppermost bits were quickly repurposed to designate network class, and thus began classful routing and the downfall of an organized IPv4 address tuple.

While at the time the uppermost 2 bits were, as of yet, unused, the length of the leading bits designating class was, itself, variable, and the remainder of the bits in the uppermost byte, or uppermost 8 bits, being part of the network identification. The leading bits designating class could be anywhere from just the first bit alone as a 0, designating Class A, all the way up to the uppermost 4 bits all 1s, designating Class E. Now, while this broke the clear-cut tuple, it still confined most of the variable messiness to only the uppermost byte. Once the first byte was parsed and the class identified, the next three bytes, or 24 bits, could still be parsed rather quickly. If it was a Class A network with a leading 0 bit, only the next 7 bits were used to identify the network, and all of the remaining 3 bytes could be used by those respective networks to designate host. If it was a Class B network with leading bits of 1 and 0, respectively, then the remaining 6 bits of the first byte were concatenated to the second uppermost byte and used together to identify the network, while the remaining 2 bytes were used to identify the host. Following suit, Class C networks led with a binary series of 110, concatenating the remaining 5 bits of the first byte with the next 2 bytes, and using only the remaining 1 byte to designate host. Class D multicast addresses were then designated by a leading 1110, and a reserved space was given to addresses leading with 1111.

This classful routing approach worked for about a decade, until it reached a tipping point in 1993, when things really started to explode and lead up to the dot-com boom, and eventual bust around 1995. The average company by that point was needing well over 254 hosts, so Class Cs were becoming more and more impractical, especially for commercial uses. However, at the same time, assigning everyone that needed more than 254 addresses a full Class B was also impractical because that would automatically mean jumping to 65,534 addresses, when maybe they would only need a few hundred or few thousand addresses. It was quickly seen this was obviously not sustainable, as global IP exhaustion would only come faster.

So, once more hastily gathering to solve the imminent IP exhausting problem while at the same time not breaking the system already in place, it was decided to then just drop the concept of classful routing altogether and just totally make the entire 32-bit address space a complete mix of routing and host information together, known as Classless Inter-Domain Routing (CIDR), where the number of bits used to designate a network and the number of bits used to designate a host were no longer pre-defined or fixed at all and both variable numbers within that 32-bit space. This meant that now IP blocks could be allocated more efficiently by bits and not just jump entire 8-bit ranges. However, it also meant that parsing the routing information and host information required a bit more processing power, and even an entirely new and separate 32-bit space that would now accompany the IPv4 address as a bit mask to untangle the network and host portions, known as a variable-length subnet mask, or VLSM. Despite maybe only adding an additional bitwise operation or two to the mix to enable classless routing, it must be kept in mind these additional steps would have to be done on every IP calculation from now on and were additional steps added to the very fabric of routing, which can add up to orders of magnitude more cycles used than before as you progress up the networking layers and add to the overall network latency for all network devices involved.

Yes, subnet masks did not actually exist, nor were they needed, until CIDR came about in 1993! The entire concept of a subnet mask was invented as a Band-Aid to keep IPv4 going and was never actually part of the initial design! And please do not confuse subnet masks with subnetting, which had been around since 1985 and applies only to the network portion of the address to subdivide larger networks into smaller networks within a shared controlling authority and was never designed nor intended to be relevant in any way to the host portion of an address. Because VLSM emerged at the same time as a necessity to facilitate CIDR, both terms are often mistakenly used interchangeably. However, obviously, CIDR refers only to the specific type of routing, while VLSM refers only to the type of bit mask required to make the new CIDR possible. Which is why the popular "CIDR notation" describes a network prefix and the bit length of that prefix, since this prefix information is what is used for routing. Although, obviously, the VLSM and prefix length can easily be derived from each other and are thus closely linked, they both describe two different things and are used for two different purposes. And although this distinction may seem to be of little import and simply semantics, it is extremely important to keep this in mind when thinking about IPv6. IPv6 drops subnet masks entirely, since there are once again two clearly defined integers that no longer need to be untangled, but it does hold on to the concept of prefix lengths for subnetting purposes.

Even after tricks like NAT (1994) came about to conserve global IP space further by masking entire networks behind one or more global IP addresses, it was still clear a new IP version would need to come about to resolve all of these growing issues, which would require a bit more intention and design than just a hasty meeting to solve a current crisis and keep the system only just one more slight step away from failure.

**Back to First Principles**

Enter IPv6. In the midst of the dot-com bubble bursting in 1995, the same year the IETF got together to think about the future of IP. But instead of really coming up with anything super new, they really just went back to first principles of the initial concepts which governed IP those many years before it got messy, having a single tuple known as an IP address containing 2 clearly defined integers, one for routing and one to identify a host, which can each be efficiently parsed completely independently of each other without needing a bit mask or any other additional operations. The only difference this time would be a bigger space which defined the routing portion as the first 64 bits and defined the host portion as the last 64 bits. And although IPv6 was conceived before 64-bit processors became mainstream, having 2 integers which both natively fit perfectly snug on a 64-bit register was also a huge win for processor efficiency.

**Nuances**

Now, while subnetting still works the same way it always has within the first 64-bit network portion of the address, there are some other important nuances to IPv6 which distinguish it from IPv4. One of the biggest ones being the concept of multicast has been expanded upon and broadcast addresses no longer need to be reserved within every network. This, along with the concept of reserved network IDs also being dropped, means that host portions can use all 64 bits without having to subtract 2 reserved addresses.

**Conclusion**

And so, in conclusion, all IPv6 networks, and subnetworks, will all have exactly the same amount of host addresses available to them, taking up exactly the 64-bit host address space. The concept of supernetworks and subnetworks is completely indistinguishable, irrelevant, and unimportant to the host, which only needs to know the network it is sending to and doesn't need to know about the politics and subdivisions of the controlling authority. At no time will a 128-bit integer ever be used, acted upon, calculated, etc. IPv6 is a tuple containing two discrete 64-bit unsigned integers, period.

# More About ScriptTiger

For more ScriptTiger scripts and goodies, check out ScriptTiger's GitHub Pages website:  
https://scripttiger.github.io/

[![Donate](https://www.paypalobjects.com/en_US/i/btn/btn_donateCC_LG.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=MZ4FH4G5XHGZ4)
