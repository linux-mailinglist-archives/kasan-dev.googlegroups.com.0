Return-Path: <kasan-dev+bncBDLKPY4HVQKBB6UD43CAMGQEG2L6L2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D657B1FEB3
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 07:39:08 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-61831157d7esf541454a12.2
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 22:39:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754890747; cv=pass;
        d=google.com; s=arc-20240605;
        b=fsMa6q+Txl0kywG6Ek2U1EbKLvLcyN/hlj5/cg8sfeigDgNYx80JOZNGnHSGGI9Rbp
         IhLXREEgTYrATfpdPNaMiD9bYHzAKfB1TwcrVuPIJjx4ipuBWLtelPQxzgJpFII/tBqq
         LjnXE6/rR5fAiFFwKIfVrNSuZKcnB/HdoepsndtmnaEDfSmfo5ZH4C1Oq8wBrvaKNGXt
         9LWRnlGdYajSGvJ/mv6PraDOh1fQV1bIYG6tYt6ThhwLRHEspdM9vslWA84Ayq5cynC+
         QqdMu2ScRG4gDAqs+JVE5uaE/royEU43K6iH8tZmhPK8CgABJi/tjQIhQrE1lgGwJk8/
         ayjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=vk7K1cJDauiQspVRTNuQvoNs9EO77frPbqQDzrpln/g=;
        fh=lhQdP+12WWqzGUYY/8753PS5DlkABb+770Y/9PxLaZM=;
        b=NFMm/s3xgMSiQNaSi6vnUt2g2VR/nYyN5rQTDJRkq0KAF26GXcV+Pv0IWp5TmRGw35
         tEH91ma11CvzKUYi1Y9I1To++VFzn9102IMv/B3FW+Z2adFTI3OL2IAqsQSCtIvdD1al
         ArVcVFlpFwUKrZt/Xii6RxulxmzcVrQ1Wq8cwIXlbBasnGNoVvd2H7UBjGu/oscGzOSv
         kJFGPo46+H2YTwRfOiCSOSZVrcigPVtZ2/nCIzYG+0oKuRLHPTScRKcY9wUFbdFZw9Vi
         pokQ1Z8MMYFrgKCbnSll0ZTwIeVDrMhFXGxbW+ZfR9hBcM9DZeRxnGyfVrwuCD6qBz/c
         UNFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754890747; x=1755495547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vk7K1cJDauiQspVRTNuQvoNs9EO77frPbqQDzrpln/g=;
        b=lFeAeE8q5H6qcJ4BkUMFKVZcmL4m0aSigujzOZ7PpIQglKJCNfJHZ3EortPwEja3tJ
         2Odh4aJBaj3+Jx7D3bMi/sH8fOdUpo3VWF4FWDcyAeCCYVopRfnKsQAsI9jQpddkQF8v
         4oivufUMNRw4vGZ82ih7kJIhywKOGBABCsnHQ5t3Iis9NgtewvSBEmSz1GFZ0QbNWSon
         /FSS+O9OuZIl5rfV1UmQdixmH9x06tdOsD+jp4hwZfeZvmgZGd/u9n5m+dA0UChGuMoa
         pirevpTo9czYAQha3OlRRQMCw681W8Pb4B2KpcAGr0JeQFwT61RhFEvQZXBUh7etl/eK
         Zg1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754890747; x=1755495547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vk7K1cJDauiQspVRTNuQvoNs9EO77frPbqQDzrpln/g=;
        b=e7FrlWKJ+wEo4N37JLhzIYR4fAkisj/lPx8hQXPBo4p4HNzWQGZOgV2llG+x1BAE52
         m7NV70JBG2NS5vjMpCcJ2ZgYfCi+IdfWEPEC8JSyXRM9Pddr1/brn/vcpoeMODeLgsw2
         VDt477IojNMXk9BAxhMmMpGv19jMw1BWtqDQT7G/7t7dXAkRk/sXyGadrd2kD7iJC+Cl
         0tb6qce02PdfcqugveHZC1nCDnyvw1kwTbO7Q4sHfszf64PCA7aOPcnJKviaE1DSJ22E
         DZiapMew3n1vJc1lci7GFdlggPJxD6g0vJVkhi1sSzHUQLsF7vpPR0L2qVBphb6tUmpD
         7lEA==
X-Forwarded-Encrypted: i=2; AJvYcCWC8P8Us63YdttDzEI/Nccfel5zfyvcGugUelXy4cR633AK3o4e91iHu6ZKG7hFXs+igu3JEQ==@lfdr.de
X-Gm-Message-State: AOJu0YzOOMSnkiNUSIZLFh2Iq8RR1XY5t5BvLSEqzhiUJJKFHyakXmzI
	vluZU9ik02jBMjh70u44aNOQGI+35qMbXk3F5Wzuo9B62JVYEYlMsCOX
X-Google-Smtp-Source: AGHT+IE+rus2RIa9ot2Pa4MBgPp6l+/HesaraYhLTDZpVN5A4qenTdg/nYors+GfxSrlmLO/EyLV0g==
X-Received: by 2002:a05:6402:1d4f:b0:618:3ed6:7b91 with SMTP id 4fb4d7f45d1cf-6183ed6b9f3mr358040a12.13.1754890747310;
        Sun, 10 Aug 2025 22:39:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfgZ1p9DEBXORBeycakwt3Brc6rz5OPzoJT0iz1drTG+g==
Received: by 2002:aa7:c398:0:b0:617:ec6b:e590 with SMTP id 4fb4d7f45d1cf-617ec6c3053ls1423345a12.1.-pod-prod-01-eu;
 Sun, 10 Aug 2025 22:39:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4LA90K9iRNT6ianyTqprp1f1euJumuMbKknUl6cjeLQdWMT0CzBL5A7BNejdlZr30WU+6TwyaPko=@googlegroups.com
X-Received: by 2002:a17:907:9496:b0:ad5:5210:749c with SMTP id a640c23a62f3a-af9c6369d42mr1061715266b.22.1754890744698;
        Sun, 10 Aug 2025 22:39:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754890744; cv=none;
        d=google.com; s=arc-20240605;
        b=QOgLTtGyIuVnzK21KRaxcws1Ld8Yoa8+rcGdcdU1fUNm4FXYIM1JBOl6K7WhYaYgwL
         L8gg66OG49fJt8szSMDZHb4+J/cNJ/1RA8CAYt/3gaJwPV9xn7z3dkjjCIdB3M8YlitP
         elJ2burxKPMXoBt6iN3UOqvD3vPiohtDR14MzSTL/xNyQEH9UyhnQy8QgssYaJGSBEtR
         SIEhQ9S+aNSu0ZlbI76mV+8p7soApi9M7lKUqe+aE4C5pfKEhzEWzDXHYlZC/aCrOCWr
         JcUgodRnMjsMotlYthbuP5Uoe2dwqvriLBpDh1kjsgw0npOsgHTtjwkCWAd9y621OLzM
         2wTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=1+62RvIlGZfmQnxVgcVSsABjdaj8FSJ42aUXvVPiGuY=;
        fh=6jNhEXFfCXnHEo2T0z5V39ZHwXcnkiUubqLxF8WHKEo=;
        b=KxNKpAB0X0QT3IgTCFhvSOGYKw4hNPjV3TCxsvBqWaf0RpQNTqzqG1YK+N0Le16xUF
         JzQZpvM/9cQZ0vuMABYmQX+IZs+MIdAEO/oNRoehOdcLUkwAi2RoQt6V9q0876ApLWU6
         OWNrnNdqCOrPfzen5nYTULZ6Al+UsF2Ak7uWNyUh3QMvdT9dxN1XNx6oFVy2ynKXqC+F
         IvR2rLFmR24T0b/qP+HqX979K1Rv3LOyF4nGVIZyE6qVVAkmsyWd0I4lcstOAd26XmeM
         qI4ulEXiNCSixxFmM3R02naQNyMQDoz4eveA2lUfPcMOmKc/0xEVCqdtb9C9xVibZtxh
         n3Bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-af919eac6c6si59982766b.0.2025.08.10.22.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 22:39:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4c0k2w2kRcz9sSL;
	Mon, 11 Aug 2025 07:39:04 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 3Mxf0H61E1tl; Mon, 11 Aug 2025 07:39:04 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4c0k2w1bMnz9sSK;
	Mon, 11 Aug 2025 07:39:04 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 199008B764;
	Mon, 11 Aug 2025 07:39:04 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id bIxmuQ19phXS; Mon, 11 Aug 2025 07:39:03 +0200 (CEST)
Received: from [10.25.207.160] (unknown [10.25.207.160])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BAC418B763;
	Mon, 11 Aug 2025 07:39:03 +0200 (CEST)
Message-ID: <b8345cfe-0bde-44cd-b9b7-9a946ff8fc36@csgroup.eu>
Date: Mon, 11 Aug 2025 07:39:03 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 2/2] kasan: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 bhe@redhat.com, hca@linux.ibm.com, andreyknvl@gmail.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 davidgow@google.com, glider@google.com, dvyukov@google.com,
 alexghiti@rivosinc.com
Cc: alex@ghiti.fr, agordeev@linux.ibm.com, vincenzo.frascino@arm.com,
 elver@google.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250810125746.1105476-1-snovitoll@gmail.com>
 <20250810125746.1105476-3-snovitoll@gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <20250810125746.1105476-3-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 10/08/2025 =C3=A0 14:57, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Call kasan_init_generic() which handles Generic KASAN initialization.
> For architectures that do not select ARCH_DEFER_KASAN,
> this will be a no-op for the runtime flag but will
> print the initialization banner.
>=20
> For SW_TAGS and HW_TAGS modes, their respective init functions will
> handle the flag enabling, if they are enabled/implemented.
>=20
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
> Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>

> ---
> Changes in v6:
> - Call kasan_init_generic() in arch/riscv _after_ local_flush_tlb_all()
> ---
>   arch/arm/mm/kasan_init.c    | 2 +-
>   arch/arm64/mm/kasan_init.c  | 4 +---
>   arch/riscv/mm/kasan_init.c  | 1 +
>   arch/s390/kernel/early.c    | 3 ++-
>   arch/x86/mm/kasan_init_64.c | 2 +-
>   arch/xtensa/mm/kasan_init.c | 2 +-
>   6 files changed, 7 insertions(+), 7 deletions(-)
>=20
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 111d4f703136..c6625e808bf8 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -300,6 +300,6 @@ void __init kasan_init(void)
>   	local_flush_tlb_all();
>  =20
>   	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> -	pr_info("Kernel address sanitizer initialized\n");
>   	init_task.kasan_depth =3D 0;
> +	kasan_init_generic();
>   }
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d541ce45daeb..abeb81bf6ebd 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -399,14 +399,12 @@ void __init kasan_init(void)
>   {
>   	kasan_init_shadow();
>   	kasan_init_depth();
> -#if defined(CONFIG_KASAN_GENERIC)
> +	kasan_init_generic();
>   	/*
>   	 * Generic KASAN is now fully initialized.
>   	 * Software and Hardware Tag-Based modes still require
>   	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
>   	 */
> -	pr_info("KernelAddressSanitizer initialized (generic)\n");
> -#endif
>   }
>  =20
>   #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 41c635d6aca4..c4a2a9e5586e 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -533,4 +533,5 @@ void __init kasan_init(void)
>  =20
>   	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
>   	local_flush_tlb_all();
> +	kasan_init_generic();
>   }
> diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
> index 9adfbdd377dc..544e5403dd91 100644
> --- a/arch/s390/kernel/early.c
> +++ b/arch/s390/kernel/early.c
> @@ -21,6 +21,7 @@
>   #include <linux/kernel.h>
>   #include <asm/asm-extable.h>
>   #include <linux/memblock.h>
> +#include <linux/kasan.h>
>   #include <asm/access-regs.h>
>   #include <asm/asm-offsets.h>
>   #include <asm/machine.h>
> @@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
>   {
>   #ifdef CONFIG_KASAN
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   #endif
>   }
>  =20
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 0539efd0d216..998b6010d6d3 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -451,5 +451,5 @@ void __init kasan_init(void)
>   	__flush_tlb_all();
>  =20
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   }
> diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
> index f39c4d83173a..0524b9ed5e63 100644
> --- a/arch/xtensa/mm/kasan_init.c
> +++ b/arch/xtensa/mm/kasan_init.c
> @@ -94,5 +94,5 @@ void __init kasan_init(void)
>  =20
>   	/* At this point kasan is fully initialized. Enable error messages. */
>   	current->kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b=
8345cfe-0bde-44cd-b9b7-9a946ff8fc36%40csgroup.eu.
