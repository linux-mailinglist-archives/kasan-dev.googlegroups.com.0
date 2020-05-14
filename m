Return-Path: <kasan-dev+bncBDML5AWB7ANRBEUD6T2QKGQE5TF4IJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A1631D2A13
	for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 10:30:12 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id h4sf18041852oie.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 May 2020 01:30:12 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=n469VaN1P3ftKDUZtSNLPgYkAPxPxxdvfyJ9Q7OshjQ=;
        b=mz1PNZ8/re3fiHbiPV968GRadaJnc6OVQiuawas8ofsaGh1NTKoPGOFrgIwtumiof7
         dhu2pdzPkGvp3BJtlhCzaGzGOESE04L4L7PSOmUI7Ztrqq1NOLV1ZW4LdXYG8xgZmbLk
         FDUBSd/1sLFDSaoi7QmFS8HT8nn2T08xPIF09akbwDo+3iHLShQsAWSgespc4+fj7ueI
         8SZTBKUJWIHsLl+mhh9tTH09y6wON2D/Upcqca5XlLCTk+bJC5CyT+K3Q3V8o24B/C36
         Tb6qG4EU3UnTeuv/cTy3Bx421/NbEULhpniWRo6TGnw2tlWzWxcygaTSmjxavomDDO3x
         VQAA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n469VaN1P3ftKDUZtSNLPgYkAPxPxxdvfyJ9Q7OshjQ=;
        b=rCZ1PB4NOP6OfQmCh7KHwTHiWzDZoa0pr8D052dvvmq3lv45rDu4exMqQHJ38cMSna
         6BTgJfoSriKmi9Mmi1POwV3sc4pPYR1TN1CaGmMBRGOLThAxczckaYNrkGsbiQfNsDOg
         35ESqs9mGzuWh42dnG9yVhZ4+7kftw15KIUSFCLOv5UsuKOckoOHFtxqm9/3+tQFgs6n
         lnMPO1Yt7dxgYfmXGRx0EzJkfJCvuh3LjOQLLm0PG9zxVPYqzjO3pWRZ3by9ot0Q/aCm
         qO7uu0zCceLYLp5kF36pslaWnbDC03KJX1JTpD7LeUqfbulKqZ2jPhtqnSzyvnU1aC+d
         rKTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=n469VaN1P3ftKDUZtSNLPgYkAPxPxxdvfyJ9Q7OshjQ=;
        b=mF6iQPnW6ylrvVVdaKT9gl0G+9v1TZ7wcag4rYA+voOrSSitk/GMPW424I393ePISU
         o57N7RmHiWxnI4ow9PMooIgiIWcqDwYDdpjkP9KTaqP37tLGMRbUNwKOKtfcnmv/1men
         5IQZT1sG45I9chK1MsiH4PXQBI7PonYdNajtp+saCq8dRk/V+08FHP3J166KUlKzNYag
         JKjDcin+vcLGOLonA9za4qQOzz374IvDV0vSGxePgb0aUQSG5N1q2ttlouRNLfAsq+yI
         eNd6baTnIvXyfCezt71kDwknqTy/eSarqKteXIh/fttwRdYZSEhGDEN1PZQzvuPCz1a6
         Pq8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYJNqQKK3i1VLX+VvWRd9Zu1hDWxgP+8fvSVEBbgnFPgnrtE0s9
	PCtOH62xm1akxDkY98Tt0YY=
X-Google-Smtp-Source: APiQypLPD6JJiWK+hs4BGSJ2cl5rTy2WDsj6t+iaB3dSUbjfqMCr+ZVFupApsnMm2fKnTH7vUsmPfg==
X-Received: by 2002:a54:4f1a:: with SMTP id e26mr29939836oiy.45.1589445010845;
        Thu, 14 May 2020 01:30:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:aace:: with SMTP id t197ls64032oie.4.gmail; Thu, 14 May
 2020 01:30:10 -0700 (PDT)
X-Received: by 2002:aca:ba05:: with SMTP id k5mr29057039oif.35.1589445010469;
        Thu, 14 May 2020 01:30:10 -0700 (PDT)
Date: Thu, 14 May 2020 01:30:09 -0700 (PDT)
From: Jude Serge <siijude6@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <e48d7b7a-5762-4610-bb7e-e807566cf216@googlegroups.com>
Subject: buy marijuana, CANNABIS PRODUCER. High Grade Medical Marijuana
 Sativa, Indica & hybrid strains, shrooms, vapes, Hash, (RSO), BHO, HEMP
 OILS, THC OILS, Cannabis Oil and Edibles FOR SALE.
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_3329_111209783.1589445009918"
X-Original-Sender: siijude6@gmail.com
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

------=_Part_3329_111209783.1589445009918
Content-Type: multipart/alternative; 
	boundary="----=_Part_3330_482836368.1589445009918"

------=_Part_3330_482836368.1589445009918
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

our website link: https://marijuannashop.com/

https://marijuannashop.com/product-category/savita/

https://marijuannashop.com/product-category/hybrid/

https://marijuannashop.com/product-category/indica/

https://marijuannashop.com/product-category/shrooms/

Our email: sale@mar......na.com
Call Text & WhatsApp us at: +1 (424) 269-5782

>>>>>>>> Fast and Reliable delivery -Tracking Available!
>>>>>>>>Good quality products.
>>>>>>>>>Good and affordable prices.
>>>>>>>>>Various shipping option (Overnight and Airmail).
>>>>>>>>>No Prescription Required!
>>>>>>>>>Buy Direct and Save Time and Money!
         100% Customer Satisfaction Guaranteed ! -Additional Discounts on=
=20
Bulk Orders
We guarantee the safety passage of your package ,all our packages are=20
customized and diplomatic sealed packages this means that they are custom=
=20
free. We offer triple vacuum seal and stealth package on all orders so it=
=20
can=E2=80=99t be scent detected by canine (dogs) or electronic sniffers, We=
 do=20
provide refunds or replace your order if there is a failure in delivering.=
=20
Weed for sale, Where to buy weed, Hash oil for sale, Cannabis oil for sale,=
=20
Buy marijuana online, THC oil for sale, How to buy weed online, Marijuana=
=20
for sale, Order weed online, Buy medical marijuana online

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e48d7b7a-5762-4610-bb7e-e807566cf216%40googlegroups.com.

------=_Part_3330_482836368.1589445009918
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div>our website link: https://marijuannashop.com/</div><d=
iv><br></div><div>https://marijuannashop.com/product-category/savita/</div>=
<div><br></div><div>https://marijuannashop.com/product-category/hybrid/</di=
v><div><br></div><div>https://marijuannashop.com/product-category/indica/</=
div><div><br></div><div>https://marijuannashop.com/product-category/shrooms=
/</div><div><br></div><div>Our email: sale@mar......na.com</div><div>Call T=
ext &amp; WhatsApp us at: +1 (424) 269-5782</div><div><br></div><div>&gt;&g=
t;&gt;&gt;&gt;&gt;&gt;&gt; Fast and Reliable delivery -Tracking Available!<=
/div><div>&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;Good quality products.</div><div>=
&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;Good and affordable prices.</div><div>&=
gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;Various shipping option (Overnight and A=
irmail).</div><div>&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;No Prescription Requ=
ired!</div><div>&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;&gt;Buy Direct and Save Tim=
e and Money!</div><div>=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0100% Customer Sati=
sfaction Guaranteed ! -Additional Discounts on Bulk Orders</div><div>We gua=
rantee the safety passage of your package ,all our packages are customized =
and diplomatic sealed packages this means that they are custom free. We off=
er triple vacuum seal and stealth package on all orders so it can=E2=80=99t=
 be scent detected by canine (dogs) or electronic sniffers, We do provide r=
efunds or replace your order if there is a failure in delivering. Weed for =
sale, Where to buy weed, Hash oil for sale, Cannabis oil for sale, Buy mari=
juana online, THC oil for sale, How to buy weed online, Marijuana for sale,=
 Order weed online, Buy medical marijuana online</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/e48d7b7a-5762-4610-bb7e-e807566cf216%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/e48d7b7a-5762-4610-bb7e-e807566cf216%40googlegroups.com</a>.<br =
/>

------=_Part_3330_482836368.1589445009918--

------=_Part_3329_111209783.1589445009918--
