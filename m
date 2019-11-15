Return-Path: <kasan-dev+bncBAABBTUUXDXAKGQE7MMOKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 73C0EFD2DC
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 03:15:43 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id r206sf4218029oih.6
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 18:15:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573784142; cv=pass;
        d=google.com; s=arc-20160816;
        b=wKjf76GecRVsVKO7xGn/ez8XSBJMfONOPmCXhcomtYHI727sXA8/whJZeBb1jkxE4y
         B42hTETkm4Pi3lmYGXY75siw8jsIFWLgD+KdJksI6Y3U/3NZxI0A3CMuo+1hiNrFyu1K
         But3+9g+wQQgevkgngp2QMFuBpmKfKGFjS85M6ubuLtelSSwtiLWbPMSYuVTXF5ANiff
         fccnALgOMGF7b7Q4mzfvYn1zLrjZlojZ8QdoY5DNMTFzFXkadyg/Cm8EzhqPTpVEDZEe
         D6rmkGziizOfgqGzdOPdC3c+yg+RmhB0j4Fl/M5tySrbyXhMyfOMs06BSKaW/gFLau8u
         3g0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:subject
         :references:in-reply-to:message-id:cc:to:from:date:dkim-signature;
        bh=J7QFHDx5eHqgaK3Bp3o0nfTgNrmR3U5axdmyRu+jifA=;
        b=xapXW5GHn9N88ZtXOyMmOf5Jin+Ho/yZdll+homaefj261iBML3W4DuHm7kejGXhwN
         c6okQUt7LsvyiPBeBK+9mSBSKdzFBbdxi23oY5PLCvSzG8qlxT59v4toew21cG/r9nJy
         eNWHbuIAvhF723+CgHnDgN/2X+KhI+FyAkQypP7hWb99Hh9ruLKYSLAXVg2RRnMppUk+
         5n6dTeiHlw/63IP4nqEgmqEL/JDTfSAHZzO79+3QIudbnfV9XN5H0n6IBpMbJ/U+e8wm
         psj4XtGMU0fH60qeiyqM3ExftQwyD868OJfw3XiBysLvUfnCOTNsH9o5Ztw+cENffEj7
         q1og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=UyS9Ofi5;
       spf=pass (google.com: domain of matyaz@yahoo.com designates 74.6.129.218 as permitted sender) smtp.mailfrom=matyaz@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=J7QFHDx5eHqgaK3Bp3o0nfTgNrmR3U5axdmyRu+jifA=;
        b=qI67FksaN0QH9TlObMl0Zmh6zexm6GKu7JvWhcsES8uBal2/WK3xon1+d1jdIvSySc
         PRGRHxscqFmcYsRcmvTmxL9OfpLLRdv2Z137jcCzPYY3P/f0dso4rUcYjiHywsXVUxqs
         5N1k5EOPaJkjxldff2EMJHc1IMN4beZTIUVqj1eqnh790+i5Z9SOtg0Pp8ieIn44V7de
         KWy7ffXRlAKQGaxciZKbuZ7GXWwMFxdLQiV5mXqEUy6C6i+7UtY6ZZRTKYqmXyevAAhm
         Rj77XPyJ56peAuQh8422+EkkbnDWLCj6huYZComiqtGMZSv2Q6kQo8RalVE/doo7fbMj
         fb5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J7QFHDx5eHqgaK3Bp3o0nfTgNrmR3U5axdmyRu+jifA=;
        b=NJ5ZLcTCKYYIHULI1h6iTqVJD+vYTqDZZ2DSn1GEhzxV4naNaFCVxl7BGLjrYWbwOw
         IG6f/HLxR8sO6XQfbnyDjArezjHDug6AuIFp9GTiu3+cMK9OEIEM0hse7sA2ZO1P+WEV
         PU7Qaot4RPQwB12ocRpdWciMmHTbgvjLHBjfUED6kHw/jO8pxO/lkEv2eV6wZ1qEsKOJ
         VMOfzsGiJWp9QCu6c+e/Y9RTCfKBbnyOz25hUM59kG0h56Im8XkjPIFuKJvZBINpXkDt
         P0Eg3COA+3BYcEL5YITxdRXHoWJ3ne39Uxrex2C9alQ2xjWRJcVhzFX9v6Cc7q7hZpCt
         b76A==
X-Gm-Message-State: APjAAAVjL5Wr3V823HqUykCHu7HyTwHkQVhugz3lA6iJst8x9WXoGuaB
	uNEIGVkYao3xjEJO7rmD4E4=
X-Google-Smtp-Source: APXvYqxcBrQ4otwNFhcHwoJhZevnikHBEPLm0i6PLAq/m3QgPt856HBjueMBYWFX/IjeMLPg6LbxRg==
X-Received: by 2002:aca:b909:: with SMTP id j9mr6142787oif.121.1573784142099;
        Thu, 14 Nov 2019 18:15:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:d410:: with SMTP id l16ls2159996oig.2.gmail; Thu, 14 Nov
 2019 18:15:39 -0800 (PST)
X-Received: by 2002:aca:b286:: with SMTP id b128mr6141875oif.1.1573784139027;
        Thu, 14 Nov 2019 18:15:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573784139; cv=none;
        d=google.com; s=arc-20160816;
        b=WiSMVflviPWrlaP6SZJ5V8/MC4MR7y60H5Fh8dq6tt0JaNBgoTL0Ncp2zLMVgC0FEb
         V0vb8/lIuS6829iXLBLB+tzB/LN87fy+g74ecBNTOuygVdLIQS0vS2jf4O++obMS49oA
         jsMfgx8/8Mqn8RO0e9gGeIndviMDfzYkKhhyfg+DNnp03UqUTlEwRBcIDKCyrt65zLEv
         njMrJQcayzI0Se/3n0Zdbq3Jwmz9lhSaKO/U2XkREXcyI/b0SKJ33Z4MLBl8+hhJqGGr
         +eOGVd8IkHrn1Gn8FKd2FZJi28EjE+3V7Nyj6wTIdbysCnpjg6+w9SclH5w7W5tXuxEJ
         +02A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:subject:references:in-reply-to:message-id:cc:to:from
         :date:dkim-signature;
        bh=C+s/pcKUAh6zBlVje3f241DL958jTrffFEhgECkKcwg=;
        b=qhjOYZwSfKYyFnhLqragrPWvhdCzTyPlSPjncu5WEVlj1eaEH9EuIOCPaT71Mq3WbP
         GHJyhNrhSDPVv5kAIyexRuffM/q3upaCDeiCI6L28MzeppeAJmpSh0GIJ05fdvx4rW3Y
         8ZJs63eFqmqd8Ya/I3wfM7Igmva+Sr5SqCim54u1Xr+izmtssYhCSqGdE6MlPrLPUWqq
         NWd8Q84XXlMF2vQNYWuhU4+GSIu/OT2MCtaxUbm2DAPwrcIovIq8GY/wGlGcdmpmwg5n
         Xs76cYifdTklYaDtamqh/hFxyxBD4yoKIF0hZu64LkiDP1vDu0GzqyrB2cHutXifp2RY
         4vmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yahoo.com header.s=s2048 header.b=UyS9Ofi5;
       spf=pass (google.com: domain of matyaz@yahoo.com designates 74.6.129.218 as permitted sender) smtp.mailfrom=matyaz@yahoo.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=yahoo.com
Received: from sonic309-44.consmr.mail.bf2.yahoo.com (sonic309-44.consmr.mail.bf2.yahoo.com. [74.6.129.218])
        by gmr-mx.google.com with ESMTPS id g5si183423oti.4.2019.11.14.18.15.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 18:15:39 -0800 (PST)
Received-SPF: pass (google.com: domain of matyaz@yahoo.com designates 74.6.129.218 as permitted sender) client-ip=74.6.129.218;
X-YMail-OSG: N_6BpMEVRDvd.miR6A7lED5GPdAEx7ojsA--
Received: from sonic.gate.mail.ne1.yahoo.com by sonic309.consmr.mail.bf2.yahoo.com with HTTP; Fri, 15 Nov 2019 02:15:38 +0000
Date: Fri, 15 Nov 2019 02:13:37 +0000 (UTC)
From: "'Matjaz Matjaz' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Felsch <m.felsch@pengutronix.de>, 
	Florian Fainelli <f.fainelli@gmail.com>
Cc: alexandre.belloni@bootlin.com, mhocko@suse.com, catalin.marinas@arm.com, 
	dhowells@redhat.com, yamada.masahiro@socionext.com, 
	ryabinin.a.a@gmail.com, glider@google.com, 
	kvmarm@lists.cs.columbia.edu, corbet@lwn.net, liuwenliang@huawei.com, 
	daniel.lezcano@linaro.org, linux@armlinux.org.uk, 
	kasan-dev@googlegroups.com, geert@linux-m68k.org, dvyukov@google.com, 
	bcm-kernel-feedback-list@broadcom.com, keescook@chromium.org, 
	arnd@arndb.de, marc.zyngier@arm.com, andre.przywara@arm.com, 
	pombredanne@nexb.com, jinb.park7@gmail.com, tglx@linutronix.de, 
	kernel@pengutronix.de, linux-arm-kernel@lists.infradead.org, 
	nico@fluxnic.net, gregkh@linuxfoundation.org, 
	ard.biesheuvel@linaro.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, rob@landley.net, philip@cog.systems, 
	akpm@linux-foundation.org, thgarnie@google.com, 
	kirill.shutemov@linux.intel.com
Message-ID: <231794607.364474.1573784017752@mail.yahoo.com>
In-Reply-To: <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
References: <20190617221134.9930-1-f.fainelli@gmail.com> <20191114181243.q37rxoo3seds6oxy@pengutronix.de> <7322163f-e08e-a6b7-b143-e9d59917ee5b@gmail.com>
Subject: Re: [PATCH v6 0/6] KASan for arm
MIME-Version: 1.0
Content-Type: multipart/alternative; 
	boundary="----=_Part_364473_1006591184.1573784017750"
X-Mailer: WebService/1.1.14728 YMailNorrin Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36
X-Original-Sender: matyaz@yahoo.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yahoo.com header.s=s2048 header.b=UyS9Ofi5;       spf=pass
 (google.com: domain of matyaz@yahoo.com designates 74.6.129.218 as permitted
 sender) smtp.mailfrom=matyaz@yahoo.com;       dmarc=pass (p=REJECT sp=REJECT
 dis=NONE) header.from=yahoo.com
X-Original-From: Matjaz Matjaz <matyaz@yahoo.com>
Reply-To: Matjaz Matjaz <matyaz@yahoo.com>
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

------=_Part_364473_1006591184.1573784017750
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

 [::1]:2869=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0hp-PC:53166=C2=
=A0 =C2=A0=C2=A0ios 2.1.2 I sign on it
    Dne petek, 15. november 2019 00:01:38 GMT+1 je uporabnik Florian Fainel=
li <f.fainelli@gmail.com> napisal: =20
=20
 Hello Marco,

On 11/14/19 10:12 AM, Marco Felsch wrote:
> Hi Florian,
>=20
> first of all, many thanks for your work on this series =3D) I picked your
> and Arnd patches to make it compilable. Now it's compiling but my imx6q
> board didn't boot anymore. I debugged the code and found that the branch
> to 'start_kernel' won't be reached
>=20
> 8<------- arch/arm/kernel/head-common.S -------
> ....
>=20
> #ifdef CONFIG_KASAN
>=C2=A0 =C2=A0 =C2=A0 =C2=A0 bl=C2=A0 =C2=A0 =C2=A0 kasan_early_init
> #endif
> =C2=A0=C2=A0=C2=A0 mov=C2=A0 =C2=A0 lr, #0
> =C2=A0=C2=A0=C2=A0 b=C2=A0 =C2=A0 =C2=A0 start_kernel
> ENDPROC(__mmap_switched)
>=20
> ....
> 8<----------------------------------------------
>=20
> Now, I found also that 'KASAN_SHADOW_OFFSET' isn't set due to missing
> 'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=3Dxxxxx' is
> added. Can that be the reason why my board isn't booted anymore?

The latest that I have is here, though not yet submitted since I needed
to solve one issue on a specific platform with a lot of memory:

https://github.com/ffainelli/linux/pull/new/kasan-v7

Can you share your branch as well? I did not pick all of Arnd's patches
since some appeared to be seemingly independent from KASan on ARM. This
is the KASAN related options that are set in my configuration:

grep KASAN build/linux-custom/.config
CONFIG_HAVE_ARCH_KASAN=3Dy
CONFIG_CC_HAS_KASAN_GENERIC=3Dy
CONFIG_KASAN=3Dy
CONFIG_KASAN_GENERIC=3Dy
CONFIG_KASAN_OUTLINE=3Dy
# CONFIG_KASAN_INLINE is not set
CONFIG_KASAN_STACK=3D1
CONFIG_TEST_KASAN=3Dm

are you using something different by any chance?
--=20
Florian
_______________________________________________
kvmarm mailing list
kvmarm@lists.cs.columbia.edu
https://lists.cs.columbia.edu/mailman/listinfo/kvmarm
 =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/231794607.364474.1573784017752%40mail.yahoo.com.

------=_Part_364473_1006591184.1573784017750
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><head></head><body><div class=3D"ydp4bb2ab2ayahoo-style-wrap" style=
=3D"font-family:Helvetica Neue, Helvetica, Arial, sans-serif;font-size:16px=
;"><div></div>
        <div dir=3D"ltr" data-setdir=3D"false"><div><div>[::1]:2869&nbsp; &=
nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;hp-PC:53166&nbsp; &nbsp;&nbsp;</div=
></div>ios 2.1.2 I sign on it</div><div><br></div>
       =20
        </div><div id=3D"yahoo_quoted_3822534166" class=3D"yahoo_quoted">
            <div style=3D"font-family:'Helvetica Neue', Helvetica, Arial, s=
ans-serif;font-size:13px;color:#26282a;">
               =20
                <div>
                    Dne petek, 15. november 2019 00:01:38 GMT+1 je uporabni=
k Florian Fainelli &lt;f.fainelli@gmail.com&gt; napisal:
                </div>
                <div><br></div>
                <div><br></div>
                <div><div dir=3D"ltr">Hello Marco,<br></div><div dir=3D"ltr=
"><br></div><div dir=3D"ltr">On 11/14/19 10:12 AM, Marco Felsch wrote:<br><=
/div><div dir=3D"ltr">&gt; Hi Florian,<br></div><div dir=3D"ltr">&gt; <br><=
/div><div dir=3D"ltr">&gt; first of all, many thanks for your work on this =
series =3D) I picked your<br></div><div dir=3D"ltr">&gt; and Arnd patches t=
o make it compilable. Now it's compiling but my imx6q<br></div><div dir=3D"=
ltr">&gt; board didn't boot anymore. I debugged the code and found that the=
 branch<br></div><div dir=3D"ltr">&gt; to 'start_kernel' won't be reached<b=
r></div><div dir=3D"ltr">&gt; <br></div><div dir=3D"ltr">&gt; 8&lt;------- =
arch/arm/kernel/head-common.S -------<br></div><div dir=3D"ltr">&gt; ....<b=
r></div><div dir=3D"ltr">&gt; <br></div><div dir=3D"ltr">&gt; #ifdef CONFIG=
_KASAN<br></div><div dir=3D"ltr">&gt;&nbsp; &nbsp; &nbsp; &nbsp;  bl&nbsp; =
&nbsp; &nbsp; kasan_early_init<br></div><div dir=3D"ltr">&gt; #endif<br></d=
iv><div dir=3D"ltr">&gt; &nbsp;&nbsp;&nbsp; mov&nbsp; &nbsp;  lr, #0<br></d=
iv><div dir=3D"ltr">&gt; &nbsp;&nbsp;&nbsp; b&nbsp; &nbsp; &nbsp;  start_ke=
rnel<br></div><div dir=3D"ltr">&gt; ENDPROC(__mmap_switched)<br></div><div =
dir=3D"ltr">&gt; <br></div><div dir=3D"ltr">&gt; ....<br></div><div dir=3D"=
ltr">&gt; 8&lt;----------------------------------------------<br></div><div=
 dir=3D"ltr">&gt; <br></div><div dir=3D"ltr">&gt; Now, I found also that 'K=
ASAN_SHADOW_OFFSET' isn't set due to missing<br></div><div dir=3D"ltr">&gt;=
 'CONFIG_KASAN_SHADOW_OFFSET' and so no '-fasan-shadow-offset=3Dxxxxx' is<b=
r></div><div dir=3D"ltr">&gt; added. Can that be the reason why my board is=
n't booted anymore?<br></div><div dir=3D"ltr"><br></div><div dir=3D"ltr">Th=
e latest that I have is here, though not yet submitted since I needed<br></=
div><div dir=3D"ltr">to solve one issue on a specific platform with a lot o=
f memory:<br></div><div dir=3D"ltr"><br></div><div dir=3D"ltr"><a href=3D"h=
ttps://github.com/ffainelli/linux/pull/new/kasan-v7" target=3D"_blank">http=
s://github.com/ffainelli/linux/pull/new/kasan-v7</a><br></div><div dir=3D"l=
tr"><br></div><div dir=3D"ltr">Can you share your branch as well? I did not=
 pick all of Arnd's patches<br></div><div dir=3D"ltr">since some appeared t=
o be seemingly independent from KASan on ARM. This<br></div><div dir=3D"ltr=
">is the KASAN related options that are set in my configuration:<br></div><=
div dir=3D"ltr"><br></div><div dir=3D"ltr">grep KASAN build/linux-custom/.c=
onfig<br></div><div dir=3D"ltr">CONFIG_HAVE_ARCH_KASAN=3Dy<br></div><div di=
r=3D"ltr">CONFIG_CC_HAS_KASAN_GENERIC=3Dy<br></div><div dir=3D"ltr">CONFIG_=
KASAN=3Dy<br></div><div dir=3D"ltr">CONFIG_KASAN_GENERIC=3Dy<br></div><div =
dir=3D"ltr">CONFIG_KASAN_OUTLINE=3Dy<br></div><div dir=3D"ltr"># CONFIG_KAS=
AN_INLINE is not set<br></div><div dir=3D"ltr">CONFIG_KASAN_STACK=3D1<br></=
div><div dir=3D"ltr">CONFIG_TEST_KASAN=3Dm<br></div><div dir=3D"ltr"><br></=
div><div dir=3D"ltr">are you using something different by any chance?<br></=
div><div dir=3D"ltr">-- <br></div><div dir=3D"ltr">Florian<br></div><div di=
r=3D"ltr">_______________________________________________<br></div><div dir=
=3D"ltr">kvmarm mailing list<br></div><div dir=3D"ltr"><a ymailto=3D"mailto=
:kvmarm@lists.cs.columbia.edu" href=3D"mailto:kvmarm@lists.cs.columbia.edu"=
>kvmarm@lists.cs.columbia.edu</a><br></div><div dir=3D"ltr"><a href=3D"http=
s://lists.cs.columbia.edu/mailman/listinfo/kvmarm" target=3D"_blank">https:=
//lists.cs.columbia.edu/mailman/listinfo/kvmarm</a><br></div></div>
            </div>
        </div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/231794607.364474.1573784017752%40mail.yahoo.com?utm_me=
dium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-d=
ev/231794607.364474.1573784017752%40mail.yahoo.com</a>.<br />

------=_Part_364473_1006591184.1573784017750--
