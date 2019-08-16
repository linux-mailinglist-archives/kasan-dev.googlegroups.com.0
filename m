Return-Path: <kasan-dev+bncBDQ27FVWWUFRB56Z3DVAKGQEWI6SA3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A1A6E8F99F
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 06:11:36 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id v135sf1918377vke.4
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 21:11:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565928695; cv=pass;
        d=google.com; s=arc-20160816;
        b=RDQUNgvTA3OcAAFfGqnAOe/QC1X4UQV21nS3YT4hDrXEZgMjRLa0NNrno8S422EnBm
         b9kirDPJgmwTOK7Do7t2lBXD7ERmNLKRaD8Dm73zQUGgNrhK7igBtDNPxV4uWV2Sh8ZB
         TY0R3UBK2uxiLl+MSTWKS9M3nmue/35zSHVVHmNs6imKzFl8RKmttg/wniusycZ8yh/q
         rcuS3HBaxmkivh5HO9sUHzZ2JCEu1n6eyBwTEr+fjXAqvQD1aU4vYskLnRGEacJPlOgK
         C7TJ8jhaOafSH1dUIo0bUxooi2+M6DbRXLUP2nlzhmfMl8C4Q5iBnlpaVAI4glKgWI62
         a93g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=2EbexNOppeekcYJEsNaGoFNtGfvJCNqzNfwttD1izjY=;
        b=UJkmMOv0fe8WphM4E2Ustp0XQKdCCBG5lgeJPHwpwebkXiLXqAzpo1PjZ7fzmXl4rn
         mCp2eslYJIolFC03x1/QjKQUAirT2BHPUzt+a5i4qrikjagsrYP0E963Hw76yumQs0GJ
         COjbuu+Vh2zUKDmHKQrGU/oW61kSHqJAtCXdwyEd7DxZ+KzCoMUAgfDSbqDrD1vYdiZB
         VszmSf2dP6Vb4TOAK+UucJbr7iyBb4MxhAGES54IfT8Q6UUubhKJS0ox6uWLjQFaqW1r
         qQ4J1kStLqdGVW3dqfvTSsez+Ga9/apsHAsMDw7sEK6qLRNA7oUWcLGXMw/Ku/o/g7DO
         Evdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NXiOb2Ib;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2EbexNOppeekcYJEsNaGoFNtGfvJCNqzNfwttD1izjY=;
        b=df88gg6/ZI0jPIbROCsY4hhXPYUi03ebg3mI8ijjjKRFdpTQeEH4gbadEC7nPiK+Kr
         G0uOG94wDc+yntSBCn0VUXgpkF+qtFqdtOs/HSiBf5Wr+pLKQzkIxmhCLYj53hyC1+SE
         +uay7ThVLs8mxcE9dlehNpryiNAbbpAd6aFY7NfWzzL6ec5tGcjrxXXNL3hq+x9TxGBk
         UxccOihu0fuUrjsJmblihiWhcGR+MgOed8R1kDHVOBDq6iL32KYB7AKzQKBBJ3N3kqhu
         8uTSgsrQIn3SiEZV3Mqib0BzegX2IbnWZADt/XzkFaA8YO7fHd/Hf5wRD9H+c+JqWULQ
         XrMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2EbexNOppeekcYJEsNaGoFNtGfvJCNqzNfwttD1izjY=;
        b=Pkcq/uayPyQog2h6Lpl63qh8q8hyhTPAZ/KxGYxoZubxvvIGRa3ZvxGFr9mKo6ONrM
         pdpO+N+t7gPqvY1Dg0S7wHQIwH9r3UEUcVdYw9hM2FGvR4Osd4VS8Vrt7yDf7eAfkxqr
         6hlR8xAosBd0eRBJbUzlGKUeWTPzeDU8lhiVtowLjswQFl3nrTzz1i2WljYcXbwFXX6v
         fXQv6GLmlNPEJBxSExEavmhXnQKbboNLBUIkHeZoOc+ktznQwmF5hUzQSEdjhwOleYvm
         VwnN9gM+VGo28W1lOV64/E3P5bHO/9Q40hwsOYU1J3IZAbs/SJpb6sqUG4vn0JhZ1H7C
         D5sA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV98usy/N+UbbJA95xdt1vkAnm5BM3+MSwDDErfC7tIrnJDHtxm
	WPBLzcZJd+XXAD1ibmk4Otk=
X-Google-Smtp-Source: APXvYqyZQoxgP9TABS0ucASIPgOSrvKI3AJcMH0bVG6bo1TU4cpTrR0p0nwOu4K3bgfX+JPYzi/O9w==
X-Received: by 2002:a67:d911:: with SMTP id t17mr5593165vsj.186.1565928695168;
        Thu, 15 Aug 2019 21:11:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:68d1:: with SMTP id d200ls897790vsc.9.gmail; Thu, 15 Aug
 2019 21:11:34 -0700 (PDT)
X-Received: by 2002:a67:d801:: with SMTP id e1mr5431068vsj.128.1565928694858;
        Thu, 15 Aug 2019 21:11:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565928694; cv=none;
        d=google.com; s=arc-20160816;
        b=HQspLOzkw2UZaoX9pzTcOYtvutWcaVL00e1I45zsE4a0A46NnDmOBN51A27VIxECkM
         VDQrNzIFakKU8nyLD7BaLf7Md85REN/A7BOmXPOFYlh8ZcCRDElT4J2vMYfySolU9VOg
         9rWVIOSAldmjY9YT4YNyongwGkgj+flphW+gsl9xXUmvGq7ihBJ7ALJozHjVYTLX6N0i
         WKIjtYlzX1zGu0ysmZQGIq9ne0MKKzHckQPXeocWmwTB+/IYNqhJjNq+tPdKApt8N/6l
         M95+5+BjiK6AX4Y4EYSH2AyhpvR9cMKhAQtJL7fbCiMgd01yRjFIvvWA3GnC/u7Ehhx9
         Y/xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=wkLW+QCz58nlrQENUl4iKN6nR8hpfPIajfbfonDVy48=;
        b=FeQTnuFv4ZhPFGWMcawxOqzgciCzpr9+H1uyCXETgrMG7F62kJCbrQhNp/U+4Etqcq
         xc7GGAQZx3SrjtKYrZtngp5M04dEuxckUoVlfRR+sUPaj4rEYAPXaPu3FL6gzcQB0hF7
         /dItYRm/cwShI70DPY0Rm1YQmJON1Jx6gau5tScmcrMowmpuxIFjlDewtQ3fXdfORq+p
         tPIHnaLB56cEN/iv67Is9PZ6tAXKhLypWzNQW6fugflWwZuZ2BKSw8veE5QEDxFJykcB
         yhjNse9hoiaWyy9V5ONwG8JMNyhqkNU7R0WRJzSanE941Ea1O2+rVFY5WB7qiFLuXwis
         Kmag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NXiOb2Ib;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id b5si177303vsd.2.2019.08.15.21.11.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Aug 2019 21:11:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id p3so2271321pgb.9
        for <kasan-dev@googlegroups.com>; Thu, 15 Aug 2019 21:11:34 -0700 (PDT)
X-Received: by 2002:a62:8344:: with SMTP id h65mr8846322pfe.85.1565928693727;
        Thu, 15 Aug 2019 21:11:33 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id n128sm4298287pfn.46.2019.08.15.21.11.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2019 21:11:32 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/4] powerpc: KASAN for 64-bit Book3S on Radix
In-Reply-To: <fe758b6c-93ec-7069-5151-a395c8666844@c-s.fr>
References: <20190806233827.16454-1-dja@axtens.net> <fe758b6c-93ec-7069-5151-a395c8666844@c-s.fr>
Date: Fri, 16 Aug 2019 14:11:28 +1000
Message-ID: <87lfvtg367.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=NXiOb2Ib;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Christophe Leroy <christophe.leroy@c-s.fr> writes:

> Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
>> Building on the work of Christophe, Aneesh and Balbir, I've ported
>> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>>=20
>> It builds on top Christophe's work on 32bit. It also builds on my
>> generic KASAN_VMALLOC series, available at:
>> https://patchwork.kernel.org/project/linux-mm/list/?series=3D153209
>
> Would be good to send that one to the powerpc list as well.
>

Done for v4.

>>=20
>> This provides full inline instrumentation on radix, but does require
>> that you be able to specify the amount of memory on the system at
>> compile time. More details in patch 4.
>>=20
>> Notable changes from the RFC:
>>=20
>>   - I've dropped Book3E 64-bit for now.
>>=20
>>   - Now instead of hacking into the KASAN core to disable module
>>     allocations, we use KASAN_VMALLOC.
>>=20
>>   - More testing, including on real hardware. This revealed that
>>     discontiguous memory is a bit of a headache, at the moment we
>>     must disable memory not contiguous from 0.
>>    =20
>>   - Update to deal with kasan bitops instrumentation that landed
>>     between RFC and now.
>
> This is rather independant and also applies to PPC32. Could it be a=20
> separate series that Michael could apply earlier ?
>

Will do this and address your feedback on the rest of the series later.

Regards,
Daniel

> Christophe
>
>>=20
>>   - Documentation!
>>=20
>>   - Various cleanups and tweaks.
>>=20
>> I am getting occasional problems on boot of real hardware where it
>> seems vmalloc space mappings don't get installed in time. (We get a
>> BUG that memory is not accessible, but by the time we hit xmon the
>> memory then is accessible!) It happens once every few boots. I haven't
>> yet been able to figure out what is happening and why. I'm going to
>> look in to it, but I think the patches are in good enough shape to
>> review while I work on it.
>>=20
>> Regards,
>> Daniel
>>=20
>> Daniel Axtens (4):
>>    kasan: allow arches to provide their own early shadow setup
>>    kasan: support instrumented bitops with generic non-atomic bitops
>>    powerpc: support KASAN instrumentation of bitops
>>    powerpc: Book3S 64-bit "heavyweight" KASAN support
>>=20
>>   Documentation/dev-tools/kasan.rst            |   7 +-
>>   Documentation/powerpc/kasan.txt              | 111 ++++++++++++++
>>   arch/powerpc/Kconfig                         |   4 +
>>   arch/powerpc/Kconfig.debug                   |  21 +++
>>   arch/powerpc/Makefile                        |   7 +
>>   arch/powerpc/include/asm/bitops.h            |  25 ++--
>>   arch/powerpc/include/asm/book3s/64/radix.h   |   5 +
>>   arch/powerpc/include/asm/kasan.h             |  35 ++++-
>>   arch/powerpc/kernel/process.c                |   8 ++
>>   arch/powerpc/kernel/prom.c                   |  57 +++++++-
>>   arch/powerpc/mm/kasan/Makefile               |   1 +
>>   arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  76 ++++++++++
>>   include/asm-generic/bitops-instrumented.h    | 144 ++++++++++---------
>>   include/linux/kasan.h                        |   2 +
>>   lib/Kconfig.kasan                            |   3 +
>>   mm/kasan/init.c                              |  10 ++
>>   16 files changed, 431 insertions(+), 85 deletions(-)
>>   create mode 100644 Documentation/powerpc/kasan.txt
>>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87lfvtg367.fsf%40dja-thinkpad.axtens.net.
