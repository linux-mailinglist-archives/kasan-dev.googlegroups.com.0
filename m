Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBD6J4OIAMGQEXTV626Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id BFC9B4C4730
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 15:15:43 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id n31-20020a05600c3b9f00b003812242973asf1375803wms.4
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Feb 2022 06:15:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645798543; cv=pass;
        d=google.com; s=arc-20160816;
        b=GFsBZ8sq3jNTAnik1ytf88PDzGKfD52UWW1sjRfr1Soxugnt2dD1bKlp5fzoTEyswj
         b/7QYKRTTUCFAUL32QU/pOXXD9T+s3vc/Xv58CYk9rWqK4Dqq/boIeyE6jxSknjOfJlc
         Qi0GFCfRdEfMUipYMYZHeftl1jTIsTHfbpfZiya5+43vlJJ71qQd1UeONAqZhh7LZeOW
         o2zCjzyBujoHuB1D6MQj5iWI33RGHlybBRU0YMWLtAT4nPCA4PXGntaYoQJWq5JOVqEz
         FycM/HXBsaLOmcybPsZtn05ui0VnUossGPBkj+ov6wctX+B7uA1iR8BFPnH/GaU9Y1Qh
         hd1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=j/pbQ1F0sW2ch5/72UbR5OeBNe+ENrYJuqJLMKy9vHY=;
        b=EshfBl4XsBVjGFr1WQmZ+n7nUcutPa/Z02pmZiY3oW09ugm4VjM+EIBT1xoIViOLku
         0CkLAmCYpnYnyJgnjNlOcD2uq16Lj1NsABisNHLJUz3Jp+2m+GcqG2A7+adv51LBBDD4
         C9lQ5Kq1i+HvKLr+qNExElLFNf+pLcCq7nwlkow8P/VOgFggr2JAyw1CQIwBn1QN9+xD
         NBFxERjyclvDsPxlX8GdsyZNPmLaHY0hFphmJsSGNSStIKWXKSCA0OmtBNkJObVV4CTG
         usVwFFazGDmdmyeTdOyiMhvCAv1+48HYEk4yHcds4Sj4aNoarlMEHn76qzbC31u7gSto
         UrTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=e4P+lAWa;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j/pbQ1F0sW2ch5/72UbR5OeBNe+ENrYJuqJLMKy9vHY=;
        b=lgXEjOu12ucl4bxXjeFZ+EUjSgLn8DrqprYRKuVOPVuSkUGiHreLKsthSSN/4QUMQ3
         duP7fCnc54EYhei6JSWdQfEPxQpGwy6xcVmnK0Vl5LX/RvBpI3Ab1WsLN+8+3AYTMKuQ
         pD/Y6Kme+CGBOQsewuEnCvTsuv1YhP6LG2eQMiGnZGYzvK1irx+euClQvEEk56xnApsW
         gUS4I69o/h8hG+qqPyb2aUk12kS+RH5YFURfAhgu8S0OmzxIY/CRJ5I4tUmjXwGl1Ibf
         YOZBXCyIv4B2YMWjAxYATcz06tX0XUeooHv09CzEy+1oBGZZzW6QPwdsLWmV50qZERDK
         asBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j/pbQ1F0sW2ch5/72UbR5OeBNe+ENrYJuqJLMKy9vHY=;
        b=71unfbxj47ledOMXI7TmrvqdyZlH0m4cQSRCEr373c1ElaXaKVPGWUBQ7dS7r1KxCW
         +UsmygI+vwH8ACpaK1H6NHyQMJLnxmGMgJJq6p3mlE5DszYsuIHS7S565UgP3Qw+BoK0
         nFTdvnCkYS5U00IYndVqkjiefTDZhfq2ctWIhOCYaX7O1IEt5cMuG2vUJx1ASUzyZcvK
         pmXR3sSIdDqUxg/jbqxuGQEUx3A6jQwTnoNDoFKg6PP1W1zjaREOKqBKzIBr0toUSg7w
         VaZwRgZimf9c7+jzxIKlr4C+4Ucahk9sIT8p54iEMkK19sB/dUoKgwzks9TegyXQcuJy
         oyHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pZ31N4uhPJhaKkEoYfQ2CPQnpSU42IDfLd9jqhveZMEPi+INr
	OfAoQVBpCOeMdgiVgHPVo+E=
X-Google-Smtp-Source: ABdhPJwCVkAVDrIS8Ch0bp2f0XkGK3LwQMWkUVYCECXJMS/JCihTVMlxes2CZI6XfN9qW7fVenKznw==
X-Received: by 2002:adf:f710:0:b0:1ed:af2d:dc44 with SMTP id r16-20020adff710000000b001edaf2ddc44mr6586809wrp.44.1645798543442;
        Fri, 25 Feb 2022 06:15:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4575:0:b0:1ea:7cfe:601b with SMTP id a21-20020a5d4575000000b001ea7cfe601bls335458wrc.1.gmail;
 Fri, 25 Feb 2022 06:15:42 -0800 (PST)
X-Received: by 2002:adf:8067:0:b0:1ea:9c01:d8f3 with SMTP id 94-20020adf8067000000b001ea9c01d8f3mr6379192wrk.556.1645798542587;
        Fri, 25 Feb 2022 06:15:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645798542; cv=none;
        d=google.com; s=arc-20160816;
        b=PHK4wrsXjd3lTMpz2C5olzBAIe0kyLz+lY90QTjppqIxHpDyU9U7V3oWBi5/4THPmz
         R8OFy6nGSBT0rcTZNQyy6xYxXq/5puAdb7xZPYPCOaRmyoOB/VI910dT9LN+5Lz2DU7P
         ZKvywr99J2JFAi4053oRzcudowa1utkdiCXbuhlk5JikdbDYp5+V6lC2xAAjvy2O8ygy
         WEVFNdNrCAyyCHPOW25yhtG3JAxpwi33Qf7BHQFARdoBBBkxVk1Huf9uon4Zz+TJDeoy
         WA0uk1rSN6XX+KhNpS/T5Hlg7Qc8Dgr0CRzMsyW9tmXu16cJfR7EzJgjENajSjko0IU6
         lLOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=BHkRiN2+iHrNe9IyAVbFKEoIknvTuRWbCd0yRYKLYmo=;
        b=HUJiCGDaVf2dhK3jdJ3CdCF9dBNTuceqefdWfy4hpPwDbSM3CuxEK/MiKTArXGzP/G
         qdWT/u6/8LQdkyZntkm8FQlImZna13o3XJVz4DV1L6tvP9kEqEA3bX2NFXMLlUrn5KHu
         8aaapcuU4WdtcjLCNAGkIb43jCCGWFBndgWAIfDlB9q6JaT4tE4ruwEVSngkugFiVpFr
         wzhKsRxITvAbFjGxiDj8BTFZS5BNA5hY8W0++1UI/G1rxzaBafGNX/Nl+CdFbkLzahzW
         /e/4v/bf+NA2ZfAm0gCNzrTcMv9XpdDTRpPLwXx7v8QELsdNDoCopudMYQVBrCcKCAw8
         NMmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=e4P+lAWa;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id b4-20020adfd1c4000000b001e5c7933e8esi112301wrd.5.2022.02.25.06.15.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Feb 2022 06:15:42 -0800 (PST)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ej1-f70.google.com (mail-ej1-f70.google.com [209.85.218.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id 0D9DF3FCA5
	for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 14:15:41 +0000 (UTC)
Received: by mail-ej1-f70.google.com with SMTP id k21-20020a1709063e1500b006d0777c06d6so2735129eji.1
        for <kasan-dev@googlegroups.com>; Fri, 25 Feb 2022 06:15:41 -0800 (PST)
X-Received: by 2002:a17:906:d9db:b0:6ce:8bfb:53c9 with SMTP id qk27-20020a170906d9db00b006ce8bfb53c9mr6213787ejb.10.1645798540439;
        Fri, 25 Feb 2022 06:15:40 -0800 (PST)
X-Received: by 2002:a17:906:d9db:b0:6ce:8bfb:53c9 with SMTP id
 qk27-20020a170906d9db00b006ce8bfb53c9mr6213767ejb.10.1645798540184; Fri, 25
 Feb 2022 06:15:40 -0800 (PST)
MIME-Version: 1.0
References: <20220225123953.3251327-1-alexandre.ghiti@canonical.com>
 <CANpmjNN304EZfFN2zobxKGXbXWXAfr92nP1KvtR7j-YqSFShvQ@mail.gmail.com>
 <CA+zEjCtuwnKdi8EuyGWaYNFa7KsYcH9B1mYke6YALo+C1Nq+Dw@mail.gmail.com> <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com>
In-Reply-To: <CAG_fn=WYmkqPX_qCVmxv1dx87JkXHGF1-a6_8K0jwWuBWzRJfA@mail.gmail.com>
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Date: Fri, 25 Feb 2022 15:15:29 +0100
Message-ID: <CA+zEjCsQPVYSV7CdhKnvjujXkMXuRQd=VPok1awb20xifYmidw@mail.gmail.com>
Subject: Re: [PATCH -fixes v3 0/6] Fixes KASAN and other along the way
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Paul Walmsley <paul.walmsley@sifive.com>, 
	Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, Nick Hu <nickhu@andestech.com>, 
	linux-riscv@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=e4P+lAWa;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.122 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

On Fri, Feb 25, 2022 at 3:10 PM Alexander Potapenko <glider@google.com> wro=
te:
>
>
>
> On Fri, Feb 25, 2022 at 3:04 PM Alexandre Ghiti <alexandre.ghiti@canonica=
l.com> wrote:
>>
>> On Fri, Feb 25, 2022 at 2:06 PM Marco Elver <elver@google.com> wrote:
>> >
>> > On Fri, 25 Feb 2022 at 13:40, Alexandre Ghiti
>> > <alexandre.ghiti@canonical.com> wrote:
>> > >
>> > > As reported by Aleksandr, syzbot riscv is broken since commit
>> > > 54c5639d8f50 ("riscv: Fix asan-stack clang build"). This commit actu=
ally
>> > > breaks KASAN_INLINE which is not fixed in this series, that will com=
e later
>> > > when found.
>> > >
>> > > Nevertheless, this series fixes small things that made the syzbot
>> > > configuration + KASAN_OUTLINE fail to boot.
>> > >
>> > > Note that even though the config at [1] boots fine with this series,=
 I
>> > > was not able to boot the small config at [2] which fails because
>> > > kasan_poison receives a really weird address 0x4075706301000000 (may=
be a
>> > > kasan person could provide some hint about what happens below in
>> > > do_ctors -> __asan_register_globals):
>> >
>> > asan_register_globals is responsible for poisoning redzones around
>> > globals. As hinted by 'do_ctors', it calls constructors, and in this
>> > case a compiler-generated constructor that calls
>> > __asan_register_globals with metadata generated by the compiler. That
>> > metadata contains information about global variables. Note, these
>> > constructors are called on initial boot, but also every time a kernel
>> > module (that has globals) is loaded.
>> >
>> > It may also be a toolchain issue, but it's hard to say. If you're
>> > using GCC to test, try Clang (11 or later), and vice-versa.
>>
>> I tried 3 different gcc toolchains already, but that did not fix the
>> issue. The only thing that worked was setting asan-globals=3D0 in
>> scripts/Makefile.kasan, but ok, that's not a fix.
>> I tried to bisect this issue but our kasan implementation has been
>> broken quite a few times, so it failed.
>>
>> I keep digging!
>>
>
> The problem does not reproduce for me with GCC 11.2.0: kernels built with=
 both [1] and [2] are bootable.

Do you mean you reach userspace? Because my image boots too, and fails
at some point:

[    0.000150] sched_clock: 64 bits at 10MHz, resolution 100ns, wraps
every 4398046511100ns
[    0.015847] Console: colour dummy device 80x25
[    0.016899] printk: console [tty0] enabled
[    0.020326] printk: bootconsole [ns16550a0] disabled

It traps here.

> FWIW here is how I run them:
>
> qemu-system-riscv64 -m 2048 -smp 1 -nographic -no-reboot \
>   -device virtio-rng-pci -machine virt -device \
>   virtio-net-pci,netdev=3Dnet0 -netdev \
>   user,id=3Dnet0,restrict=3Don,hostfwd=3Dtcp:127.0.0.1:12529-:22 -device =
\
>   virtio-blk-device,drive=3Dhd0 -drive \
>   file=3D${IMAGE},if=3Dnone,format=3Draw,id=3Dhd0 -snapshot \
>   -kernel ${KERNEL_SRC_DIR}/arch/riscv/boot/Image -append "root=3D/dev/vd=
a
>   console=3DttyS0 earlyprintk=3Dserial"
>
>
>>
>> Thanks for the tips,
>>
>> Alex
>
>
>
> --
> Alexander Potapenko
> Software Engineer
>
> Google Germany GmbH
> Erika-Mann-Stra=C3=9Fe, 33
> 80636 M=C3=BCnchen
>
> Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
> Registergericht und -nummer: Hamburg, HRB 86891
> Sitz der Gesellschaft: Hamburg
>
> Diese E-Mail ist vertraulich. Falls Sie diese f=C3=A4lschlicherweise erha=
lten haben sollten, leiten Sie diese bitte nicht an jemand anderes weiter, =
l=C3=B6schen Sie alle Kopien und Anh=C3=A4nge davon und lassen Sie mich bit=
te wissen, dass die E-Mail an die falsche Person gesendet wurde.
>
>
>
> This e-mail is confidential. If you received this communication by mistak=
e, please don't forward it to anyone else, please erase all copies and atta=
chments, and please let me know that it has gone to the wrong person.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BzEjCsQPVYSV7CdhKnvjujXkMXuRQd%3DVPok1awb20xifYmidw%40mail.gm=
ail.com.
