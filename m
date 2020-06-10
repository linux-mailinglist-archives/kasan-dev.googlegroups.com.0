Return-Path: <kasan-dev+bncBDZJDJ5I5QFRBVEBQL3QKGQEEPIYI3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 16DD81F4E57
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Jun 2020 08:42:30 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id w8sf595697oiw.15
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 23:42:30 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AbZu3AH8N0AmQIfRVn6ah8oJ5Cpp6vcpclO/rWPP5Ls=;
        b=jXqi3IlkmT1TosmkVpYykxNV8cRi+FXe/RIWH7AYPGfSiFZNOAKRsoH9rlxk4HAGRu
         v/bBTRPBdKVQiIetF5Rz+FhhDxhi3HzSeW6uzvjjAlN8TmGe2PROLsQ07o5mNaN7LPTI
         PzeLN+y0VVMCuv0eM/TOFBglQKCQxqhx7g0cLYrO7WwKwXw7iD5BFVKVJNf7OicnmUrx
         pFsUA8LgIlMl3MTXDhoQyzSu+fQlJ5k5m9BiFGZMiwOeXuXYrypmnRy1xvSKAIy2kWON
         3lQg78u6KctWACVcNk9Q0EIhGBXB/FUUfbrpHEfcWDamRmHf9gw1d69Nulmwg/V1iBgU
         jcBg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AbZu3AH8N0AmQIfRVn6ah8oJ5Cpp6vcpclO/rWPP5Ls=;
        b=l9gFRwng6jZlUz94yfkRVZvfareSKTsiNW/lJIjm8qLmbriauhay3r8J+CbAoPdpwb
         YZzI9pemJBSu/Gh4W5Hw0cQobBLFpaii8GLTfJ0nmKOr75yMx1fQ4d+gmevIdeFz8dOx
         h9CsursBXs0/mXjXROCvBFySFZmlCakWm16jVQeoHg5tIIQAJBmx3MuCbdPpue1edKvs
         kt4e3vRQCjETfAwbYZMqIZ5qqJrhU+ishrNOcYdYJDtK4eJu/rcBHSJCkU7Sc+X8en51
         c8mns5cLkDcA05KCX0RMMSqUWYISFNUfPTB/CgwKHeTr2X0qhCOayxQvdQlQaYphkoDy
         8xRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AbZu3AH8N0AmQIfRVn6ah8oJ5Cpp6vcpclO/rWPP5Ls=;
        b=dcuviSwAqgYQcpcklmWNOVkjJbsNM/mkzKMwZLlDqs5xJYWheWTEIwjQ0hWcb7OFeq
         OVeWob9XNdUUGTm0nhPAKUDFhGAB7FGfd5wxRNpNbZ6HRz98hmmUV48lLrEYdw5mDIjz
         vy2+0UxHHCZ+xZRkn0BlOc2REVhAS4AJSvkohKSURNUEi4HgVZR/Uaj8YQqQlSe/zETK
         Kwv+SaHngZBYxaj7RJXRBbHM4ORSaxw0Xhg7ZDF0YtYLz7mDbfwC8vWPMgUwV7V/sYwx
         AG4ibL/IrSVRewD58a/JyV187ChwS/3yj52MKhpSrMAW6CF2irX0/4cHLGIRZMSCZ1pk
         VUlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eZxtCDB9c6Qw/ScpxjX9VS+Yzkbn357y8wNmIBFsEgGlehdQs
	FLC7rNkOCLPPOBTfNLw7U1M=
X-Google-Smtp-Source: ABdhPJzeCmjdJ5FNv3VMgieW6z+qf5Yn772P56ks1J6C88D8DOC0CSZjHKL/CWH2v6isdY81n+v2Aw==
X-Received: by 2002:a9d:d6e:: with SMTP id 101mr1483570oti.166.1591771348724;
        Tue, 09 Jun 2020 23:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4c51:: with SMTP id a78ls736444oob.6.gmail; Tue, 09 Jun
 2020 23:42:28 -0700 (PDT)
X-Received: by 2002:a4a:d41:: with SMTP id 62mr1297695oob.10.1591771347153;
        Tue, 09 Jun 2020 23:42:27 -0700 (PDT)
Date: Tue, 9 Jun 2020 23:42:26 -0700 (PDT)
From: info.mylesturner@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <0e7df8fe-2822-4eae-8137-6382a45d5865o@googlegroups.com>
Subject: Dankrevolutionstore - Buy Cannabis Oils Online, Buy Marijuana
 Edibles Online, Buy CBD Oils Online, Buy Marijuana Hash, Buy THC Oil
 Cartridges Online. etc.
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_692_1454174470.1591771346449"
X-Original-Sender: info.mylesturner@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_692_1454174470.1591771346449
Content-Type: multipart/alternative; 
	boundary="----=_Part_693_1819666814.1591771346450"

------=_Part_693_1819666814.1591771346450
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable



Buy Cannabis Oils Online, Buy CBD Oils Online Without Prescription, Buy=20
Marijuana Edibles Online, Buy Marijuana Shatter Wax Online, Buy THC Oil=20
Cartridges Online =E2=80=93 Dankrevolutionstore etc.

We supply top quality products at good prices, we also offer Interstates=20
and worldwide shipping which is very safe-reliable and we guarantee that=20
your order will make it through the customs of your country / state because=
=20
we package it and register our products discreetly. We also do double=20
vacuum sealed packages on all orders So it cannot be scent detected by dogs=
=20
(Dogs) or electronics sniffers.

(Our contact details as below )

Website: https://www.dankrevolutionstore.com/
Email us via :info@dankrevolutionstore.com
What=E2=80=99s App: +31 627856624

(Product List Below )
Cannabis Oils

CBD Oils

Marijuana Edibles
Marijuana Hash
THC Oil Cartridges
420 Bars Dark Chocolate CBD

420 Carat Feminized

Absolutextract
Afghan Fem
Afghan Kush
AK-47 Fem
Banana Blast Candy
Big Bud Fem
Blue Dream Cartridge
Blue Dream Shatter
Blue Label CBD Hemp Oil
Brass Knuckles THC Oil
Bubba Kush
Cannabis Wax
CBD eLiquid

https://www.dankrevolutionstore.com/product-category/cannabis-oils/
http://dankrevolutionstore.com/product-category/cbd-oils/
https://www.dankrevolutionstore.com/product-category/marijuana-edibles/
https://www.dankrevolutionstore.com/product-category/marijuana-hash/
https://www.dankrevolutionstore.com/product-category/thc-oil-cartridges/
https://www.dankrevolutionstore.com/product/420-bars-dark-chocolate-cbd-bar=
s/

https://www.dankrevolutionstore.com/product/afghan-kush/

https://www.dankrevolutionstore.com/product/absolutextracts/

https://www.dankrevolutionstore.com/product/ak-47-fem/

https://www.dankrevolutionstore.com/product/banana-blast-candy/

https://www.dankrevolutionstore.com/product/420-bars-dark-chocolate-cbd-bar=
s/

https://www.dankrevolutionstore.com/product-category/cannabis-oils/

https://www.dankrevolutionstore.com/product-category/cbd-oils/

https://www.dankrevolutionstore.com/product-category/marijuana-edibles/

=20



We offer Overnight shipping with a tracking number provided for your=20
shipment (Fast, safe and reliable delivery). -We ship to USA, U.K,=20
AUSTRALIA, CANADA, GERMANY, POLAND, SWEDEN, NEW ZEALAND and many other=20
countries not listed here. We keep the promise to deliver and looking=20
forward to open good business relationship with you all. Fast and Reliable=
=20
delivery -Tracking Available! =E2=80=94 Various shipping option (Overnight =
and=20
Airmail). - No Prescription Required! - 100% Customer Satisfaction=20
Guaranteed.


(Our contact details as below)

Website: https://www.dankrevolutionstore.com/
Email us via: info@dankrevolutionstore.com

What=E2=80=99s App: +31 627856624

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/0e7df8fe-2822-4eae-8137-6382a45d5865o%40googlegroups.com.

------=_Part_693_1819666814.1591771346450
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><p class=3D"MsoNormal" style=3D""><span style=3D"font-size=
: 13pt; line-height: 107%; font-family: Arial, sans-serif; color: rgb(66, 6=
6, 66); background-image: initial; background-position: initial; background=
-size: initial; background-repeat: initial; background-attachment: initial;=
 background-origin: initial; background-clip: initial;">Buy Cannabis Oils O=
nline, Buy CBD Oils Online
Without Prescription, Buy Marijuana Edibles Online, Buy Marijuana Shatter W=
ax
Online, Buy THC Oil Cartridges Online =E2=80=93 Dankrevolutionstore etc.</s=
pan><span style=3D"font-size:13.0pt;line-height:107%;font-family:&quot;Aria=
l&quot;,&quot;sans-serif&quot;;
color:#424242"><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">We supply to=
p quality products at good prices,
we also offer Interstates and worldwide shipping which is very safe-reliabl=
e
and we guarantee that your order will make it through the customs of your
country / state because we package it and register our products discreetly.=
 We
also do double vacuum sealed packages on all orders So it cannot be scent
detected by dogs (Dogs) or electronics sniffers.</span><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">(Our contact=
 details as below )</span><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Website:=C2=
=A0</span></span><span style=3D"font-family:&quot;Arial&quot;,&quot;sans-se=
rif&quot;"><a href=3D"https://www.dankrevolutionstore.com/"><span style=3D"=
font-size: 13pt; line-height: 107%; color: rgb(42, 120, 192); border-width:=
 1pt; border-style: none; border-color: windowtext; padding: 0cm; backgroun=
d-image: initial; background-position: initial; background-size: initial; b=
ackground-repeat: initial; background-attachment: initial; background-origi=
n: initial; background-clip: initial;">https://www.dankrevolutionstore.com/=
</span></a></span><span style=3D"font-size:13.0pt;line-height:107%;font-fam=
ily:&quot;Arial&quot;,&quot;sans-serif&quot;;
color:#424242"><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Email us via=
 :info@dankrevolutionstore.com<br>
What=E2=80=99s App: +31 627856624</span><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">(Product Lis=
t Below )<br>
</span></span><span style=3D"line-height: 107%; font-family: Arial, sans-se=
rif; color: black; background-image: initial; background-position: initial;=
 background-size: initial; background-repeat: initial; background-attachmen=
t: initial; background-origin: initial; background-clip: initial;">Cannabis=
 Oils</span><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"line-height: 107%; font-family: Arial, sans-serif; color: blac=
k; background-image: initial; background-position: initial; background-size=
: initial; background-repeat: initial; background-attachment: initial; back=
ground-origin: initial; background-clip: initial;">CBD Oils<o:p></o:p></spa=
n></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"line-height: 107%; font-family: Arial, sans-serif; color: blac=
k; background-image: initial; background-position: initial; background-size=
: initial; background-repeat: initial; background-attachment: initial; back=
ground-origin: initial; background-clip: initial;">Marijuana Edibles</span>=
<br>
Marijuana Hash<br>
THC Oil Cartridges<span style=3D"font-size:13.0pt;line-height:107%;
font-family:&quot;Arial&quot;,&quot;sans-serif&quot;;color:#424242"><br>
</span><span style=3D"font-size: 13pt; line-height: 107%; font-family: Aria=
l, sans-serif; color: rgb(64, 64, 64); background-image: initial; backgroun=
d-position: initial; background-size: initial; background-repeat: initial; =
background-attachment: initial; background-origin: initial; background-clip=
: initial;">420 Bars
Dark Chocolate CBD<o:p></o:p></span></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"font-size: 13pt; line-height: 107%; font-family: Arial, sans-s=
erif; color: rgb(64, 64, 64); background-image: initial; background-positio=
n: initial; background-size: initial; background-repeat: initial; backgroun=
d-attachment: initial; background-origin: initial; background-clip: initial=
;">420
Carat Feminized<o:p></o:p></span></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"font-size: 13pt; line-height: 107%; font-family: Arial, sans-s=
erif; color: rgb(64, 64, 64); background-image: initial; background-positio=
n: initial; background-size: initial; background-repeat: initial; backgroun=
d-attachment: initial; background-origin: initial; background-clip: initial=
;">Absolutextract</span><span style=3D"font-size:13.0pt;line-height:107%;fo=
nt-family:&quot;Arial&quot;,&quot;sans-serif&quot;;
color:#424242"><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Afghan Fem</=
span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Afghan Kush<=
/span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">AK-47 Fem</s=
pan><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Banana Blast=
 Candy</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Big Bud Fem<=
/span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Blue Dream C=
artridge</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Blue Dream S=
hatter</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Blue Label C=
BD Hemp Oil</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Brass Knuckl=
es THC Oil</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Bubba Kush</=
span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Cannabis Wax=
</span><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">CBD eLiquid<=
/span><br>
<!--[if !supportLineBreakNewLine]--><br>
<!--[endif]--><o:p></o:p></span></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product-category/cannabis-oils=
/">https://www.dankrevolutionstore.com/product-category/cannabis-oils/</a><=
br>
<a href=3D"http://dankrevolutionstore.com/product-category/cbd-oils/">http:=
//dankrevolutionstore.com/product-category/cbd-oils/</a><br>
<a href=3D"https://www.dankrevolutionstore.com/product-category/marijuana-e=
dibles/">https://www.dankrevolutionstore.com/product-category/marijuana-edi=
bles/</a><br>
<a href=3D"https://www.dankrevolutionstore.com/product-category/marijuana-h=
ash/">https://www.dankrevolutionstore.com/product-category/marijuana-hash/<=
/a><br>
<a href=3D"https://www.dankrevolutionstore.com/product-category/thc-oil-car=
tridges/">https://www.dankrevolutionstore.com/product-category/thc-oil-cart=
ridges/</a><span style=3D"font-size:13.0pt;line-height:107%;font-family:&qu=
ot;Arial&quot;,&quot;sans-serif&quot;;
color:#424242"><br>
</span><a href=3D"https://www.dankrevolutionstore.com/product/420-bars-dark=
-chocolate-cbd-bars/">https://www.dankrevolutionstore.com/product/420-bars-=
dark-chocolate-cbd-bars/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product/afghan-kush/">https://=
www.dankrevolutionstore.com/product/afghan-kush/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product/absolutextracts/">http=
s://www.dankrevolutionstore.com/product/absolutextracts/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product/ak-47-fem/">https://ww=
w.dankrevolutionstore.com/product/ak-47-fem/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product/banana-blast-candy/">h=
ttps://www.dankrevolutionstore.com/product/banana-blast-candy/</a><o:p></o:=
p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product/420-bars-dark-chocolat=
e-cbd-bars/">https://www.dankrevolutionstore.com/product/420-bars-dark-choc=
olate-cbd-bars/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product-category/cannabis-oils=
/">https://www.dankrevolutionstore.com/product-category/cannabis-oils/</a><=
o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product-category/cbd-oils/">ht=
tps://www.dankrevolutionstore.com/product-category/cbd-oils/</a><o:p></o:p>=
</p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><a=
 href=3D"https://www.dankrevolutionstore.com/product-category/marijuana-edi=
bles/">https://www.dankrevolutionstore.com/product-category/marijuana-edibl=
es/</a><o:p></o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><o=
:p>=C2=A0</o:p></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"font-size:13.0pt;line-height:107%;font-family:&quot;Arial&quot=
;,&quot;sans-serif&quot;;
color:#424242"><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">We offer Ove=
rnight shipping with a tracking
number provided for your shipment (Fast, safe and reliable delivery). -We s=
hip
to USA, U.K, AUSTRALIA, CANADA, GERMANY, POLAND, SWEDEN, NEW ZEALAND and ma=
ny
other countries not listed here. We keep the promise to deliver and looking
forward to open good business relationship with you all. Fast and Reliable
delivery -Tracking Available! =E2=80=94 Various shipping option (Overnight =
and Airmail).
- No Prescription Required! - 100% Customer Satisfaction Guaranteed.</span>=
<br>
<br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">(Our contact=
 details as below)</span><br>
<br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Website:=C2=
=A0</span></span><span style=3D"font-family:&quot;Arial&quot;,&quot;sans-se=
rif&quot;"><a href=3D"https://www.dankrevolutionstore.com/"><span style=3D"=
font-size: 13pt; line-height: 107%; color: rgb(42, 120, 192); border-width:=
 1pt; border-style: none; border-color: windowtext; padding: 0cm; backgroun=
d-image: initial; background-position: initial; background-size: initial; b=
ackground-repeat: initial; background-attachment: initial; background-origi=
n: initial; background-clip: initial;">https://www.dankrevolutionstore.com/=
</span></a></span><span style=3D"font-size:13.0pt;line-height:107%;font-fam=
ily:&quot;Arial&quot;,&quot;sans-serif&quot;;
color:#424242"><br>
<span style=3D"background-image: initial; background-position: initial; bac=
kground-size: initial; background-repeat: initial; background-attachment: i=
nitial; background-origin: initial; background-clip: initial;">Email us via=
: info@dankrevolutionstore.com<o:p></o:p></span></span></p>

<p class=3D"MsoNormal" style=3D"margin-bottom:0cm;margin-bottom:.0001pt"><s=
pan style=3D"font-size: 13pt; line-height: 107%; font-family: Arial, sans-s=
erif; color: rgb(66, 66, 66); background-image: initial; background-positio=
n: initial; background-size: initial; background-repeat: initial; backgroun=
d-attachment: initial; background-origin: initial; background-clip: initial=
;">What=E2=80=99s App: +31 627856624</span><span style=3D"font-size: 10pt; =
line-height: 107%; font-family: Arial, sans-serif; color: black; background=
-image: initial; background-position: initial; background-size: initial; ba=
ckground-repeat: initial; background-attachment: initial; background-origin=
: initial; background-clip: initial;"><o:p></o:p></span></p></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/0e7df8fe-2822-4eae-8137-6382a45d5865o%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/0e7df8fe-2822-4eae-8137-6382a45d5865o%40googlegroups.com</a>.<b=
r />

------=_Part_693_1819666814.1591771346450--

------=_Part_692_1454174470.1591771346449--
