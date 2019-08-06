Return-Path: <kasan-dev+bncBCTM5HN3U4ORBGMOUTVAKGQE2OVMN7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D2FB82A8F
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Aug 2019 06:50:34 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id y15sf52967050edu.19
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 21:50:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565067033; cv=pass;
        d=google.com; s=arc-20160816;
        b=iI0z6Tr82074u/1YhdeO5Puss80/LS/zhhXQgwYrytiX3cmyV2445ixZkp752dTAKj
         N0wIZwkTw2wFw/hwfGRvu6IQXewKgOwUr+b3e7zWAcndp+MuWWmx0nR17FHhI66Mbmyn
         q9CE2erTV+t9oO1iP5LzCvlAPlYluSWhXJ7zsSz6NDoSR2mCRZYYjmbRAJTH0Hrt10ZZ
         ZbgbOsrVmvokAVfiuPzM0LRCVKpf2pHn78QrvATj1W2MTHvTV69gWgBmndGXqpdIaPie
         L5Au0FDHGhSrFrJ8UwgODaCaabDBoVCD+T/Ymhnl6SqA6QuWIlSiT4VpfrQ9sZPW3I/x
         ZEjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=w2Eb/lel/tUedM1V7Jbnr+5N+WH39gSklpEv+lUnqEo=;
        b=ZyumcHHqx3IzpE1T4doePEzjjjvtvLyKOGj0mOQOAjo/J3UDfQLpg4dlfivd0TACjz
         t0ZVAfB8CO2jNgukTOQ3TxGy8EoXnwuEhvtdefO9oVMZAcqrouVQPptc9ODRDxLmaY69
         SlahNQr1358HtmNo0c5abhUOGZZRpOds27CCvEoeS52F7QzV9+IJ5YFq+rEg4WI6MbQt
         AUfZk+a+SvO4mix4gUNcYHLuYXvDZYlgWNYr6KBrbglKoNOA+PKheOXrFaVw6loglOvh
         MxhE8np4VtJGr9Ekf5uqDWcuXiVTWJQj7sCIsdLgKLvUxUG9dVQScx5+1k0k9XPkFgV3
         GGtQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IvL0rWiL;
       spf=pass (google.com: domain of manikantavstk@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=manikantavstk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w2Eb/lel/tUedM1V7Jbnr+5N+WH39gSklpEv+lUnqEo=;
        b=IgPWyUu+cLMzM1B6XH8vxQ1Qgsfg9uh8PAgByr/8puaP+B755ED816YvM4X0MWCSsV
         DHlqF3whtHl8pSgHrIv/Vqa1xVxWfWObqDUCHDIUJRI+bHO5QGDmgsGmsAzxzu3dkK06
         c1Cn4scPVH7TvedaoO6GDpZMbM1ZRFVSmy0Pa/VYsC1Iq9GfSXXQFzEbc0aaT7X8mJUX
         nvUw+fBKw5mGP/lS7cxo7yFGydjH0R4QFF/F+1A4FhjZEVhtEQk2OJ0gLu6Q0/iC2j0l
         cMmFL1nQfM+r+HoTKMARvVT98BljdbmggjgDYRJZNq3RXYvOqa767mOtsHV+2HcfpA20
         rs5g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w2Eb/lel/tUedM1V7Jbnr+5N+WH39gSklpEv+lUnqEo=;
        b=PLrYVo+XaTLBW78LHHx2fY9ibZA+oK/2R8FQEUjdGDrGlVq41ZbJQvULawuyo0Etkc
         MMUWUoZNrUxpaiGrvzKcUAfZW+AA/bxEL4PFIW24umku3Jl2xDVLKEvvDzYymWl+y4RF
         3FvILs56z8uuH7CPX4anaXMeBBn1mjp5fUSNuBc5hz80KuHDbMcaX0va/ozGdtkrUkus
         ktlWp3EPtVmPSX5lYATjWw4Qf0oXBt+gFfOnlfFwILPBZ0PnYlzgCaXol4oto9KfL/0o
         B3x4T+dGFA3oca2O2XDBUXTFKMZmQrXoJT4RKwKPrBoFOW/nbBBvAgwHvMVNv1/NUDCV
         z90g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w2Eb/lel/tUedM1V7Jbnr+5N+WH39gSklpEv+lUnqEo=;
        b=JvNcfB1tbxvj1SfYCKVOfsBLkI+v2Ah26BV/ZGXgfmWiK/VXQH1khNOyBbBQPx9E3j
         M7ACJSvWOBeOc5DGwggg0uYpTz5T+kc3lAPwkyApCW4fpHYUwss4A8x61r3QrrFeFZ91
         R5BWOh9AwwXUXng+tN8Os83Zc5FWOLWnx0S5JLHjGPDLFgyw0IGuOzpK4B/ZiR3nbAuS
         5k33OsGmHHwIXmTfBBGzYO9FbdBYfpw5pwTyVmTBLTZa2wqy6Tlag+/t+nSNKTACosC9
         9yKejSjqasSfX1v37Hr1LUjGmhkb0soQQPhEA+PslKNCl8XIsYA35uIqAO7k+Dzzbliy
         A1Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUYhmlWYQkd1g3aHEMXMTKjbeZojzQl12yYhvlmzB7H/ic6kdXc
	jEIW6LAtiUEACcjD1YPr8nk=
X-Google-Smtp-Source: APXvYqyu6fO7BecjHbH2oftEcZmW4TNIkHBb86LPGM7ClMQvwBaZlpBgxkbkoHY3PIAhkFfl0yPG5g==
X-Received: by 2002:a17:906:4911:: with SMTP id b17mr1287569ejq.158.1565067033801;
        Mon, 05 Aug 2019 21:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8efb:: with SMTP id x56ls22263044edx.9.gmail; Mon, 05
 Aug 2019 21:50:33 -0700 (PDT)
X-Received: by 2002:a50:9177:: with SMTP id f52mr1808553eda.294.1565067033393;
        Mon, 05 Aug 2019 21:50:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565067033; cv=none;
        d=google.com; s=arc-20160816;
        b=uGdeMUGRmh9I9Zb8NC1rJoqwDhhoipbMu9+R7EVN/olF8dLOFE8sItjhMc/4zl+Yqf
         FIyJ63wxvKZvKjtdmJd5N33sTE/PzkRPToGPGpJiGycx7oQvo3qA7xj04giLyeCPVOXx
         +xKxS0ooJqUAXEbkyY0xoLmE5DBzIFgHxYraA+fMegGJnCzMHvHZVKG/OM14jP6tlNOF
         OSXp6K8UXD56GozZO+yDHrBgXmfs36+WkTxJ4bXyQXY9AZHQskDhnaU2feG4SLhYPQ/T
         u5xucxcQRBjmCfYu2Bzi5iXWdPjQa1HJ/3GuJSk3roVVxU5uonfC+iV4yIoZ4AEKeIi3
         RxYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mPh33fKndWKdFBa17e3Es+KRuqVonpNKFWFjNCtKoVI=;
        b=BD/40D/gOcxinRyyM42aB5vktb0sG5s/vR6ohlZ0b7ZjmSIfx99FUKHiipL8Ti6Txs
         Hj/qYlG3sFdsE0eKprgIN2r7aXph6d8+JtD0jdkNIybyZqH0D1uX2sjUmQ94zULyrG0l
         EJbUgJXnxZWHpiEm14CLZJEnpPGBLz+aUx0FphdMCz6j1wka3gTuBlHfnnG68O0OF/XI
         0Oja4WvQs5PRB/Gh0YmtJG6OQ6BlqKp0Ni5uQNTbAjKatflkOLnOEwV4/imHC6/U8D/6
         ItZa1gQuYnmVl75OlKdLxbAzgR9KoxY31KvUhqclk1D7X+jZX8kvF0dCX2FF3DoaOIoL
         9mDg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=IvL0rWiL;
       spf=pass (google.com: domain of manikantavstk@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) smtp.mailfrom=manikantavstk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x142.google.com (mail-lf1-x142.google.com. [2a00:1450:4864:20::142])
        by gmr-mx.google.com with ESMTPS id s30si1630293eda.4.2019.08.05.21.50.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Aug 2019 21:50:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of manikantavstk@gmail.com designates 2a00:1450:4864:20::142 as permitted sender) client-ip=2a00:1450:4864:20::142;
Received: by mail-lf1-x142.google.com with SMTP id u10so21109367lfm.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2019 21:50:33 -0700 (PDT)
X-Received: by 2002:ac2:5a01:: with SMTP id q1mr922196lfn.20.1565067032917;
 Mon, 05 Aug 2019 21:50:32 -0700 (PDT)
MIME-Version: 1.0
References: <96b2546a-3540-4c08-9817-0468c3146fab@googlegroups.com> <CAAeHK+wp7BduMoNQEOLgwB28pYLoKrp=cHiAzRW1ysu27UBn2A@mail.gmail.com>
In-Reply-To: <CAAeHK+wp7BduMoNQEOLgwB28pYLoKrp=cHiAzRW1ysu27UBn2A@mail.gmail.com>
From: sai manikanta <manikantavstk@gmail.com>
Date: Tue, 6 Aug 2019 10:20:20 +0530
Message-ID: <CADVap6u4DtVVr5SRw6Qw=GZDWvuVO3wTLDzFdC+P-m4pGYBjBA@mail.gmail.com>
Subject: Re: I'm trying to build kasan for pixel 2 xl ( PQ3A.190705.001 ), But
 touch is not working.
To: Andrey Konovalov <andreyknvl@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/alternative; boundary="0000000000008bfb82058f6b90ac"
X-Original-Sender: manikantavstk@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=IvL0rWiL;       spf=pass
 (google.com: domain of manikantavstk@gmail.com designates 2a00:1450:4864:20::142
 as permitted sender) smtp.mailfrom=manikantavstk@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000008bfb82058f6b90ac
Content-Type: text/plain; charset="UTF-8"

Hi Andrey,

Thanks for the reply. I have 2 qsns:
1. What is the driver for pixel 2 xl or if you don't know, can you tell us
how to find it?
2. The touch screen isn't working, so I was unable to do "adb shell" due to
unable to set VENDOR KEYS as touch is not working.

On Mon, Aug 5, 2019 at 5:04 PM Andrey Konovalov <andreyknvl@google.com>
wrote:

> Most likely the issue is caused by a mismatching touchscreen driver
> module. You need to flash/copy a KASAN-built one to the device as
> well. I don't know any details on how to do it though.
>
> On Mon, Aug 5, 2019 at 1:22 PM <manikantavstk@gmail.com> wrote:
> >
> > Without kasan same build works fine. But after enabling kasan,
> compilation is successful but after flashing the images device touchscreen
> is not working.
> >
> > Applied this patch:
> >
> > +CONFIG_INPUT_TOUCHSCREEN=y
> > +CONFIG_LGE_TOUCH_CORE=y
> > +CONFIG_LGE_TOUCH_LGSIC_SW49408=m
> > +CONFIG_TOUCHSCREEN_FTM4=y
> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=y
> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=y
> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=y
> > +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=y
> >
> > Still no luck and touch isn't working.
> > Can you provide any patch/ any inputs to resolve this touch problem?
> >
> > --
> > You received this message because you are subscribed to the Google
> Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send
> an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit
> https://groups.google.com/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com
> .
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADVap6u4DtVVr5SRw6Qw%3DGZDWvuVO3wTLDzFdC%2BP-m4pGYBjBA%40mail.gmail.com.

--0000000000008bfb82058f6b90ac
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hi Andrey,<div><br></div><div>Thanks for the reply. I have=
 2 qsns:</div><div>1. What is the driver for pixel 2 xl or if you don&#39;t=
 know, can you tell us how to find it?</div><div>2. The touch screen isn&#3=
9;t=C2=A0working, so I was unable to do &quot;adb shell&quot; due to unable=
 to set VENDOR KEYS as touch is not working.</div></div><br><div class=3D"g=
mail_quote"><div dir=3D"ltr" class=3D"gmail_attr">On Mon, Aug 5, 2019 at 5:=
04 PM Andrey Konovalov &lt;<a href=3D"mailto:andreyknvl@google.com">andreyk=
nvl@google.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" st=
yle=3D"margin:0px 0px 0px 0.8ex;border-left:1px solid rgb(204,204,204);padd=
ing-left:1ex">Most likely the issue is caused by a mismatching touchscreen =
driver<br>
module. You need to flash/copy a KASAN-built one to the device as<br>
well. I don&#39;t know any details on how to do it though.<br>
<br>
On Mon, Aug 5, 2019 at 1:22 PM &lt;<a href=3D"mailto:manikantavstk@gmail.co=
m" target=3D"_blank">manikantavstk@gmail.com</a>&gt; wrote:<br>
&gt;<br>
&gt; Without kasan same build works fine. But after enabling kasan, compila=
tion is successful but after flashing the images device touchscreen is not =
working.<br>
&gt;<br>
&gt; Applied this patch:<br>
&gt;<br>
&gt; +CONFIG_INPUT_TOUCHSCREEN=3Dy<br>
&gt; +CONFIG_LGE_TOUCH_CORE=3Dy<br>
&gt; +CONFIG_LGE_TOUCH_LGSIC_SW49408=3Dm<br>
&gt; +CONFIG_TOUCHSCREEN_FTM4=3Dy<br>
&gt; +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_HTC=3Dy<br>
&gt; +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_CORE_HTC=3Dy<br>
&gt; +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_RMI_DEV_HTC=3Dy<br>
&gt; +CONFIG_TOUCHSCREEN_SYNAPTICS_DSX_FW_UPDATE_HTC=3Dy<br>
&gt;<br>
&gt; Still no luck and touch isn&#39;t working.<br>
&gt; Can you provide any patch/ any inputs to resolve this touch problem?<b=
r>
&gt;<br>
&gt; --<br>
&gt; You received this message because you are subscribed to the Google Gro=
ups &quot;kasan-dev&quot; group.<br>
&gt; To unsubscribe from this group and stop receiving emails from it, send=
 an email to <a href=3D"mailto:kasan-dev%2Bunsubscribe@googlegroups.com" ta=
rget=3D"_blank">kasan-dev+unsubscribe@googlegroups.com</a>.<br>
&gt; To view this discussion on the web visit <a href=3D"https://groups.goo=
gle.com/d/msgid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegrou=
ps.com" rel=3D"noreferrer" target=3D"_blank">https://groups.google.com/d/ms=
gid/kasan-dev/96b2546a-3540-4c08-9817-0468c3146fab%40googlegroups.com</a>.<=
br>
</blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CADVap6u4DtVVr5SRw6Qw%3DGZDWvuVO3wTLDzFdC%2BP-m4pGYBjB=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CADVap6u4DtVVr5SRw6Qw%3DGZDWvuVO3wTLDzFdC%2BP-m=
4pGYBjBA%40mail.gmail.com</a>.<br />

--0000000000008bfb82058f6b90ac--
