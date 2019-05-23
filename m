Return-Path: <kasan-dev+bncBCXLBLOA7IGBBYHSTDTQKGQE3DI3NZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 86199275DB
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:10:40 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id q20sf958866ljg.0
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:10:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558591840; cv=pass;
        d=google.com; s=arc-20160816;
        b=BBBN+VNUKUDZt7j6D+ZwQshyAJp/jfSQQNMqmWEi20zlLNPLMNmq8vihQESKw5w2Cz
         COMP0nuk5PPvKgFBk1IzcDpBBXft5mdCEIYYrn/c2997S4xlIW8nFqTKpFwnKntfjK0A
         M+cx017fRne8sMeSmOuZAcPUNcEHklgQKpCHbBRQeBkZWXmHofhJOO7Yp9FgS3xl1OeE
         rITf886YiuxD37+Z/JVJwplvTnEDSYBPoXKx3NtFlBA6c8FR0oL7on8CPTEC9m3b8SoN
         rkiuco/if0tqJk5y6Kf3TVo/11VOwqW3AfMg8qEaSePOsh/RYIJ4+gwHGahaUOib3pNs
         rWug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=R4IfdudsZtO9k0Lds5dHr8PPLLUxkK1CamJsGH8xcHU=;
        b=bP+w2SflIQpFuua4QfyH9EQGPlmMexWcg2bu/D3RcnS9I/wiKUDP8isQfVHW+MIhcm
         33ex5ka9QXrM4MfJo2jTDnBoaBxrW/jwFjg72emUhmYSiHBklRCv/ObFZdx2/hWxQI+i
         fGkKh83OAtv8tbL8fiLbQhJEwSXKEAMbN30y2IxBn8sHdqzGKglxoJfzExA1XbEKVZSY
         SK3bOLW1Hc8ER7+EZz0FnqCw7nLv2gfGRiLtZs4V3m/FQHMMgW0eyYU+j9hkjHyJ6p8U
         bWQxtDEk1K3uxQBLvWBeCNqsfXV/iZgF1pqxE/II75Wd4/zZ/Z/UaCQq1J68ig7IseFk
         zgOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=KIibV85s;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R4IfdudsZtO9k0Lds5dHr8PPLLUxkK1CamJsGH8xcHU=;
        b=KWJx0xub2qCR0arHYI12hwwFCz7nL0hD6X5cc0AtbLVQu3YmXgJ8/wrFm8kJuOhrTo
         3Hq6BBo1M8G+eYBVd+ce6S54Qru9Kx9zf6NmPYBRVqvEOmqRsj0/UDaamdIknIX6oJV9
         HQoPmy8PFcprqovcdPyAf+7qnxA2D2USMUnHUPtV8n3UOWbEh3H7I4dtZWxWUk0aQGeS
         gOqlqAlZQntdi/bBhPCnbqh3uvjubukgTM8vtOs60HAik6tTxFYKLsZ8CCof2lztl+09
         DKFziDiNFCIug1Un1uu5a2zauQeocQKzi5P3xvssZB/WJ9+FIr8gebU6uY5UOsPl5zG/
         8RuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R4IfdudsZtO9k0Lds5dHr8PPLLUxkK1CamJsGH8xcHU=;
        b=P2cK99XKgwRdd5P+8NiHLUMuOQ0iCz2ODlIFwQoUxQ9fUISR/vxzD8ly93IdjZGI68
         Cry4gAIHiGeEg07H03iF07Z8+Nj1OnhiBuHN98sNoRdGoc/nYKAuQPxUzf3eITnbFOh3
         Y8UAtPV43B4QHf9f7ZPqDNRl+jPvqs8QYIOeESJbLasjBGZbyQjmlPQQYS9PXnxFspWw
         LDnNlUljBr8XiAk6IhOQXvynz970bnOaaVVIhcH4RTtD7lWw8uZSwY2mgQK+7Zti112P
         NJvq7amhPc6gu24d+iaznsyaZq3T67n/BfAL5Uc/HQEd/mWRFf117pEhi1byoybBXfq9
         hWlA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXKAO52TaR82vQgERx4v/eZDVxtH0iv/jI7rIVJadAurKZ5IIlo
	R5otOdpqeS6o3tZODN9rXDk=
X-Google-Smtp-Source: APXvYqwVN1zxXQ+hTtu7gEPrNztON8uCwPP1J3QVXm8PA/kOA+0lZP+6Atp6NxaT9/ZsannKALqLhQ==
X-Received: by 2002:a19:6a08:: with SMTP id u8mr18389768lfu.143.1558591840042;
        Wed, 22 May 2019 23:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:864a:: with SMTP id i10ls536835ljj.5.gmail; Wed, 22 May
 2019 23:10:39 -0700 (PDT)
X-Received: by 2002:a2e:9157:: with SMTP id q23mr8335267ljg.188.1558591839599;
        Wed, 22 May 2019 23:10:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558591839; cv=none;
        d=google.com; s=arc-20160816;
        b=Ra57/paSYGTg8r+pamdyhGRJjubYmyNblBQ0zK6DV1pNbGC3szNicx93Ce7etbGQhc
         ncykfNSyf6GUIBNTK4oJ6luxMkLHT890a0BpNccye9fZuhoDTTMLIfTurApTIHYy9lc3
         E7HTpMuhWvglT9Cv90L633QfNnQ+abwGZbayPYLf14iQcIuXBNG9yPygWnT6ijC26H7H
         tRGlZhAn0aJW1/gXfkA2rV7AwQxDJoJqyQR5qI4KotAfFBxUoSF5t0aLeO+e76QIukrx
         IPAgCJbSOX8nUlzU1XOZ5phyAarlYmyIh25ZaNM9oTQ7rgisDALjIvIu3OdobCMLhLr2
         nn5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=mEtzr68QIZ6n04SJViNreCwFTR7jtAU3pf67FXKkQtI=;
        b=X6+llHuvU3+jCxVcyEKX6sp3v/sVKMmt8wXOTfqB7IgSGU/R//wJTCRs8cGyz7q6k/
         PE6wudkg3Q4EqXLyX0upHVqGqEmm14Xn/EcPeTr8q90IjHIyPTHeQeZeWO1T9Ctcu92p
         GyGuXlQABftXPSobMUgAEtDA7IaAKEyztSemOy0eVFjyYWsL8gWw/UkBIBhjqd0NPGcV
         W7TzzIxrCDdk2QEvQJBIH99ldgm/ZdrDKApxb9lo+mIDigChzavE2ytX7/5zon3LLmaL
         AJG8KWRV8nk7WVqQnwBuUFZ88om2/WtvwpiC3EzTZOQfOaQfszCCVSO8Jn6aneTQbPGR
         zbng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=KIibV85s;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id z22si1796037lfe.1.2019.05.22.23.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 458fHx5dVhz9v1QY;
	Thu, 23 May 2019 08:10:37 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id DwnaUkC2PeVT; Thu, 23 May 2019 08:10:37 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 458fHx4Vfcz9v1QW;
	Thu, 23 May 2019 08:10:37 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 7E7268B75A;
	Thu, 23 May 2019 08:10:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id pNwkkhka3wQq; Thu, 23 May 2019 08:10:38 +0200 (CEST)
Received: from PO15451 (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 569268B77D;
	Thu, 23 May 2019 08:10:37 +0200 (CEST)
Subject: Re: [RFC PATCH 0/7] powerpc: KASAN for 64-bit 3s radix
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190523052120.18459-1-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <584b6b5b-7051-e2de-ca4e-a686c5491aad@c-s.fr>
Date: Thu, 23 May 2019 08:10:37 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=KIibV85s;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Hi Daniel,

Le 23/05/2019 =C3=A0 07:21, Daniel Axtens a =C3=A9crit=C2=A0:
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to Book3S radix.
>=20
> It builds on top Christophe's work on 32bit, and includes my work for
> 64-bit Book3E (3S doesn't really depend on 3E, but it was handy to
> have around when developing and debugging).
>=20
> This provides full inline instrumentation on radix, but does require
> that you be able to specify the amount of memory on the system at
> compile time. More details in patch 7.
>=20
> Regards,
> Daniel
>=20
> Daniel Axtens (7):
>    kasan: do not open-code addr_has_shadow
>    kasan: allow architectures to manage the memory-to-shadow mapping
>    kasan: allow architectures to provide an outline readiness check
>    powerpc: KASAN for 64bit Book3E

I see you are still hacking the core part of KASAN.

Did you have a look at my RFC patch=20
(https://patchwork.ozlabs.org/patch/1068260/) which demonstrate that=20
full KASAN can be implemented on book3E/64 without those hacks ?

Christophe

>    kasan: allow arches to provide their own early shadow setup
>    kasan: allow arches to hook into global registration
>    powerpc: Book3S 64-bit "heavyweight" KASAN support
>=20
>   arch/powerpc/Kconfig                         |   2 +
>   arch/powerpc/Kconfig.debug                   |  17 ++-
>   arch/powerpc/Makefile                        |   7 ++
>   arch/powerpc/include/asm/kasan.h             | 116 +++++++++++++++++++
>   arch/powerpc/kernel/prom.c                   |  40 +++++++
>   arch/powerpc/mm/kasan/Makefile               |   2 +
>   arch/powerpc/mm/kasan/kasan_init_book3e_64.c |  50 ++++++++
>   arch/powerpc/mm/kasan/kasan_init_book3s_64.c |  67 +++++++++++
>   arch/powerpc/mm/nohash/Makefile              |   5 +
>   include/linux/kasan.h                        |  13 +++
>   mm/kasan/generic.c                           |   9 +-
>   mm/kasan/generic_report.c                    |   2 +-
>   mm/kasan/init.c                              |  10 ++
>   mm/kasan/kasan.h                             |   6 +-
>   mm/kasan/report.c                            |   6 +-
>   mm/kasan/tags.c                              |   3 +-
>   16 files changed, 345 insertions(+), 10 deletions(-)
>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3e_64.c
>   create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/584b6b5b-7051-e2de-ca4e-a686c5491aad%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
