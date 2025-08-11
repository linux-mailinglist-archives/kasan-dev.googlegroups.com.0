Return-Path: <kasan-dev+bncBDLKPY4HVQKBBZUD43CAMGQEIS5E3WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 40FB9B1FEB2
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 07:38:48 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-458b9ded499sf25911695e9.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Aug 2025 22:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754890728; cv=pass;
        d=google.com; s=arc-20240605;
        b=e5qktv6wptiXbZzkhEjmyR8uhHAOAtJq0WwQ29MF+pqP4lQ2Aw6gIpGagIWgwAafeA
         KHuUxRPnamyTKFdUNx1O6b3z1MG2F6CHDb+sktrTyEj14FU4VXUj2oXx3dEea/2fIWqM
         sz7SVGW2JI2NbuwdrGoq8+gB16q67V0iOsocytwCkTzXfVgXgx+QI9g6EWc3gp5PyQFh
         xs6rr+QApKr9kdo0nx8slPULZtwybXZ9KdB8Mx9Go/awEWrdHsQEjcLVdvS8rdFQ+YPM
         tbr8C/zi0CkMmN0AbjRC9j1wlv/BsRSZJP96dlZwNg6XteQ0U0sn8Iwc0GCcslRjLrWv
         N/zQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=Bzrn5B+mT6SnBAPXbKAAEkel0NG2+bjcTIdKeewRYvw=;
        fh=Et7PlBCGPskcNEPxkXeHrXvOQRocRQC6XB8i8C/O+8o=;
        b=VME7pGNjSsdOwMrzKwY77vE8VLW4dbHqoKVogUJbNF4xQjvc0QHlzkEKez0DWc7UTf
         iHNwVzg+O7jz3wV8bSLrugAgYHuAB9H5+WFOK29M2YsWhhiKINeflpc/Dd+v0fdVPgDM
         bYzwWqht02viNuuQPPBPxwqnVajNtcjlI1KH0ZVQnr1mmYG30bAoHNS0Nk5FbrHbT9lL
         lVFISDfSh6Wa1ineDri8AOC9ncn6ZuAvXQ5og2zvYviKtLYgAtb+BQmm52kNYN5lpRaF
         Gbe9xyBsHELr4a1cKpJ6dlNkhwRaA7ugVFaL4ccci6PTiHr9AygMtBEIDmP8/8Bem4CO
         Rs9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754890728; x=1755495528; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Bzrn5B+mT6SnBAPXbKAAEkel0NG2+bjcTIdKeewRYvw=;
        b=Mz/E0CRJq0bGZcpx7SLX4IBMsNbfvTIfybZ4RZ2xMavWBSCzLlhSHKydSp2rGPZc9x
         NaExYkczUPZ4q7GF9yJx7ewKt+MwHHFAczW4GanBQrTzs9B2Vzi/+v+aYC5AM5ihGTNU
         ThlJ9nZCvfCY5Cw+A5joDehtZTPK5wcdWWT/Dvy9+sjmc1/unGMw3qFRuZFNtoNYsosz
         208dWYu7dxOpkMPh2yIzhs2aTD3hn4UGZ3NQLKyF5hC6+DSV7+Ct82nzoTVCgP/BnkP0
         kHAdf8/9PzOZswkf1IC8P2FX2xaZNZm40jN0rnKAhSptywXR8J9mAc8GqrhdxXQaKJR7
         6UBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754890728; x=1755495528;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bzrn5B+mT6SnBAPXbKAAEkel0NG2+bjcTIdKeewRYvw=;
        b=iJbSD9Ih7TUj/NZAWM5YP16+3flmrUh6sET8svfDD4a3D1kXfYC/ioyBxcRjAmUS3G
         IUOfOuQZmoJTlHy4mV8NgCVTyzBlX4Ivnz6dGyIrcIOMX4JQ9y+XP1y1cm0IH453kj2F
         as0BmdMm+8uusM10ZKsE/Bu03rEtkiF6go6P4EgT+0zztAsb2+ciC3h2Lq2xk4j89pzC
         Uu2e8jIlrkon2lGtgx7Hce87l7xuUKXT4xmWYHxtjIXKBCR7lTGD5p1VQ6PPN3G7OP3z
         hLl2kqWL4kLFci3msvaXkSqDDCJQxmRst7DoHCReORCEA4dgWwt8YypT+MMCCi3aCsat
         0ZhQ==
X-Forwarded-Encrypted: i=2; AJvYcCXToxfUhhH6Ut0qCRuM+OaEoUYRGy/lZFwJL1g5Sn1y56SCAMOTrwZlXPNkdxhbwYd0cPXX+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzOEJGNZZ5zwHrw8EoH9kv2uduOhJhplkO/tEoprPrz1NrjOQqY
	ACRScer61ExyLNoBH7cHoFK0jQxamDo2+NpWQ6+YwQYlj0LFoCILaSJO
X-Google-Smtp-Source: AGHT+IEIxjJAzX2AVZE6P8290Wnk4jAe5ybEVqFn1A+7zRHE6vRIWPrTExGCpg10nX1rx+tlDmtMGA==
X-Received: by 2002:a05:600c:4713:b0:43c:fc04:6d35 with SMTP id 5b1f17b1804b1-459f4f3d958mr98885525e9.4.1754890727219;
        Sun, 10 Aug 2025 22:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsLnVMk/S1JngC45oTbVsRb6sO72GcQi4p9wE4/1hjbg==
Received: by 2002:a05:6000:2908:b0:3b7:7a92:8205 with SMTP id
 ffacd0b85a97d-3b8f97acd5fls2225987f8f.2.-pod-prod-02-eu; Sun, 10 Aug 2025
 22:38:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJmkN+FKPXKJ9Ck0G/i2uazsbbBVVcDR1PQ2vUAgNBjMYnZFjDETKwYgbiv1griGnx62ISskYVlRg=@googlegroups.com
X-Received: by 2002:a5d:5d07:0:b0:3b8:fe01:cc29 with SMTP id ffacd0b85a97d-3b900b83cfemr9699262f8f.45.1754890724277;
        Sun, 10 Aug 2025 22:38:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754890724; cv=none;
        d=google.com; s=arc-20240605;
        b=g5aGvR7v5LJz6tDjP/38ckdbv/Czcz6tZYpsdULMjfQIYeb9W1WzpiLrowlgAJfnUe
         SSsvsvOq05BSrfMsJuehFbUYU4S2kSj0DF5YZzU/ieb7JCEbNVQHTIl8T7zDlowhbXKk
         ES62wNvGxXgg/Qzr+bSCoW1z3DruGu78E5S85lr3F9V0ifB8MlW9NyttT+3VtYvz5nVe
         kW2KF0ptSoS4yhvsma/3iuiF3ljpOeLLeVe8OG4J19KkXdbXrY4R+efWInh+Bv5hYpEb
         ZvP57KL6kajcibisPjlEg51llnxxctSYws5OGiYqb6QvlsNjQrhmLZVn4IGr/V9YH7nI
         et3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=2Wk/MAmyzdOJZ6icdcl6I1NThERaQgtdguReH9nvT2c=;
        fh=6jNhEXFfCXnHEo2T0z5V39ZHwXcnkiUubqLxF8WHKEo=;
        b=lK/9WqrxR1Ne3fkfZUscROfQk294Kg8J0DGb8LTAIpfTicOMCo6fCQ3/9d9MNVeo+V
         nveYlJB5z9qZ9L4X3X8Ub3uBBryGm+Z+IjX7VZmtmNtFoDNUULI4WSPh0+yqp+7mkpvn
         Dj+XfAHL/cwtEynvp0tckf9Y5Gmzw6/mteP1vBiRiIbQEGOEONTD0pydEXYoA1o5HDNV
         62U6uWIg0seOd0N2T+LsnW9jQyLr6FrJri+CToquYKQD49vT/USJcoQs+mT8spSSpsrJ
         07OaeY8xIl32cIusflBndFQyIAKKZfwJT6VuEoolNHGYIAW15xSay/S+i+U4yaMDjypW
         qL9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-458b5f2f5fcsi4345215e9.0.2025.08.10.22.38.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Aug 2025 22:38:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4c0k2W4h0wz9sSH;
	Mon, 11 Aug 2025 07:38:43 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id eQCBaLgl2JSn; Mon, 11 Aug 2025 07:38:43 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4c0k2W31Tyz9sSC;
	Mon, 11 Aug 2025 07:38:43 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4671D8B764;
	Mon, 11 Aug 2025 07:38:43 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id mku_Tio6DSSz; Mon, 11 Aug 2025 07:38:43 +0200 (CEST)
Received: from [10.25.207.160] (unknown [10.25.207.160])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C3C2C8B763;
	Mon, 11 Aug 2025 07:38:42 +0200 (CEST)
Message-ID: <123a3290-ac87-4fbd-af7c-12858aa76f32@csgroup.eu>
Date: Mon, 11 Aug 2025 07:38:42 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static
 key across modes
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
 <20250810125746.1105476-2-snovitoll@gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <20250810125746.1105476-2-snovitoll@gmail.com>
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
> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that need
> to defer KASAN initialization until shadow memory is properly set up,
> and unify the static key infrastructure across all KASAN modes.
>=20
> [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
>=20
> The core issue is that different architectures haveinconsistent approache=
s
> to KASAN readiness tracking:
> - PowerPC, LoongArch, and UML arch, each implement own
>    kasan_arch_is_ready()
> - Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
> - Generic and SW_TAGS modes relied on arch-specific solutions or always-o=
n
>      behavior
>=20
> This patch addresses the fragmentation in KASAN initialization
> across architectures by introducing a unified approach that eliminates
> duplicate static keys and arch-specific kasan_arch_is_ready()
> implementations.
>=20
> Let's replace kasan_arch_is_ready() with existing kasan_enabled() check,
> which examines the static key being enabled if arch selects
> ARCH_DEFER_KASAN or has HW_TAGS mode support.
> For other arch, kasan_enabled() checks the enablement during compile time=
.
>=20
> Now KASAN users can use a single kasan_enabled() check everywhere.
>=20
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>

> ---
> Changes in v6:
> - Added more details in git commit message
> - Fixed commenting format per coding style in UML (Christophe Leroy)
> - Changed exporting to GPL for kasan_flag_enabled (Christophe Leroy)
> - Converted ARCH_DEFER_KASAN to def_bool depending on KASAN to avoid
>          arch users to have `if KASAN` condition (Christophe Leroy)
> - Forgot to add __init for kasan_init in UML
>=20
> Changes in v5:
> - Unified patches where arch (powerpc, UML, loongarch) selects
>      ARCH_DEFER_KASAN in the first patch not to break
>      bisectability
> - Removed kasan_arch_is_ready completely as there is no user
> - Removed __wrappers in v4, left only those where it's necessary
>      due to different implementations
>=20
> Changes in v4:
> - Fixed HW_TAGS static key functionality (was broken in v3)
> - Merged configuration and implementation for atomicity
> ---
>   arch/loongarch/Kconfig                 |  1 +
>   arch/loongarch/include/asm/kasan.h     |  7 ------
>   arch/loongarch/mm/kasan_init.c         |  8 +++----
>   arch/powerpc/Kconfig                   |  1 +
>   arch/powerpc/include/asm/kasan.h       | 12 ----------
>   arch/powerpc/mm/kasan/init_32.c        |  2 +-
>   arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
>   arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
>   arch/um/Kconfig                        |  1 +
>   arch/um/include/asm/kasan.h            |  5 ++--
>   arch/um/kernel/mem.c                   | 13 ++++++++---
>   include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--------
>   include/linux/kasan.h                  |  6 +++++
>   lib/Kconfig.kasan                      | 12 ++++++++++
>   mm/kasan/common.c                      | 17 ++++++++++----
>   mm/kasan/generic.c                     | 19 +++++++++++----
>   mm/kasan/hw_tags.c                     |  9 +-------
>   mm/kasan/kasan.h                       |  8 ++++++-
>   mm/kasan/shadow.c                      | 12 +++++-----
>   mm/kasan/sw_tags.c                     |  1 +
>   mm/kasan/tags.c                        |  2 +-
>   21 files changed, 106 insertions(+), 70 deletions(-)
>=20
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index f0abc38c40ac..e449e3fcecf9 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -9,6 +9,7 @@ config LOONGARCH
>   	select ACPI_PPTT if ACPI
>   	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
>   	select ARCH_BINFMT_ELF_STATE
> +	select ARCH_NEEDS_DEFER_KASAN
>   	select ARCH_DISABLE_KASAN_INLINE
>   	select ARCH_ENABLE_MEMORY_HOTPLUG
>   	select ARCH_ENABLE_MEMORY_HOTREMOVE
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/=
asm/kasan.h
> index 62f139a9c87d..0e50e5b5e056 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -66,7 +66,6 @@
>   #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KAS=
AN_OFFSET)
>   #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KAS=
AN_OFFSET)
>  =20
> -extern bool kasan_early_stage;
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  =20
>   #define kasan_mem_to_shadow kasan_mem_to_shadow
> @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
>   #define kasan_shadow_to_mem kasan_shadow_to_mem
>   const void *kasan_shadow_to_mem(const void *shadow_addr);
>  =20
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	return !kasan_early_stage;
> -}
> -
>   #define addr_has_metadata addr_has_metadata
>   static __always_inline bool addr_has_metadata(const void *addr)
>   {
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_ini=
t.c
> index d2681272d8f0..170da98ad4f5 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __a=
ligned(PAGE_SIZE);
>   #define __pte_none(early, pte) (early ? pte_none(pte) : \
>   ((pte_val(pte) & _PFN_MASK) =3D=3D (unsigned long)__pa(kasan_early_shad=
ow_page)))
>  =20
> -bool kasan_early_stage =3D true;
> -
>   void *kasan_mem_to_shadow(const void *addr)
>   {
> -	if (!kasan_arch_is_ready()) {
> +	if (!kasan_enabled()) {
>   		return (void *)(kasan_early_shadow_page);
>   	} else {
>   		unsigned long maddr =3D (unsigned long)addr;
> @@ -298,7 +296,8 @@ void __init kasan_init(void)
>   	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START)=
,
>   					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
>  =20
> -	kasan_early_stage =3D false;
> +	/* Enable KASAN here before kasan_mem_to_shadow(). */
> +	kasan_init_generic();
>  =20
>   	/* Populate the linear mapping */
>   	for_each_mem_range(i, &pa_start, &pa_end) {
> @@ -329,5 +328,4 @@ void __init kasan_init(void)
>  =20
>   	/* At this point kasan is fully initialized. Enable error messages */
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized.\n");
>   }
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 93402a1d9c9f..4730c676b6bf 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -122,6 +122,7 @@ config PPC
>   	# Please keep this list sorted alphabetically.
>   	#
>   	select ARCH_32BIT_OFF_T if PPC32
> +	select ARCH_NEEDS_DEFER_KASAN		if PPC_RADIX_MMU
>   	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
>   	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
>   	select ARCH_ENABLE_MEMORY_HOTPLUG
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index b5bbb94c51f6..957a57c1db58 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -53,18 +53,6 @@
>   #endif
>  =20
>   #ifdef CONFIG_KASAN
> -#ifdef CONFIG_PPC_BOOK3S_64
> -DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	if (static_branch_likely(&powerpc_kasan_enabled_key))
> -		return true;
> -	return false;
> -}
> -
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -#endif
>  =20
>   void kasan_early_init(void);
>   void kasan_mmu_init(void);
> diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init=
_32.c
> index 03666d790a53..1d083597464f 100644
> --- a/arch/powerpc/mm/kasan/init_32.c
> +++ b/arch/powerpc/mm/kasan/init_32.c
> @@ -165,7 +165,7 @@ void __init kasan_init(void)
>  =20
>   	/* At this point kasan is fully initialized. Enable error messages */
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>   }
>  =20
>   void __init kasan_late_init(void)
> diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kas=
an/init_book3e_64.c
> index 60c78aac0f63..0d3a73d6d4b0 100644
> --- a/arch/powerpc/mm/kasan/init_book3e_64.c
> +++ b/arch/powerpc/mm/kasan/init_book3e_64.c
> @@ -127,7 +127,7 @@ void __init kasan_init(void)
>  =20
>   	/* Enable error messages */
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>   }
>  =20
>   void __init kasan_late_init(void) { }
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kas=
an/init_book3s_64.c
> index 7d959544c077..dcafa641804c 100644
> --- a/arch/powerpc/mm/kasan/init_book3s_64.c
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -19,8 +19,6 @@
>   #include <linux/memblock.h>
>   #include <asm/pgalloc.h>
>  =20
> -DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
>   static void __init kasan_init_phys_region(void *start, void *end)
>   {
>   	unsigned long k_start, k_end, k_cur;
> @@ -92,11 +90,9 @@ void __init kasan_init(void)
>   	 */
>   	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>  =20
> -	static_branch_inc(&powerpc_kasan_enabled_key);
> -
>   	/* Enable error messages */
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>   }
>  =20
>   void __init kasan_early_init(void) { }
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 9083bfdb7735..1d4def0db841 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -5,6 +5,7 @@ menu "UML-specific options"
>   config UML
>   	bool
>   	default y
> +	select ARCH_NEEDS_DEFER_KASAN if STATIC_LINK
>   	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
>   	select ARCH_HAS_CACHE_LINE_SIZE
>   	select ARCH_HAS_CPU_FINALIZE_INIT
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> index f97bb1f7b851..b54a4e937fd1 100644
> --- a/arch/um/include/asm/kasan.h
> +++ b/arch/um/include/asm/kasan.h
> @@ -24,10 +24,9 @@
>  =20
>   #ifdef CONFIG_KASAN
>   void kasan_init(void);
> -extern int kasan_um_is_ready;
>  =20
> -#ifdef CONFIG_STATIC_LINK
> -#define kasan_arch_is_ready() (kasan_um_is_ready)
> +#if defined(CONFIG_STATIC_LINK) && defined(CONFIG_KASAN_INLINE)
> +#error UML does not work in KASAN_INLINE mode with STATIC_LINK enabled!
>   #endif
>   #else
>   static inline void kasan_init(void) { }
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 76bec7de81b5..32e3b1972dc1 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -21,10 +21,10 @@
>   #include <os.h>
>   #include <um_malloc.h>
>   #include <linux/sched/task.h>
> +#include <linux/kasan.h>
>  =20
>   #ifdef CONFIG_KASAN
> -int kasan_um_is_ready;
> -void kasan_init(void)
> +void __init kasan_init(void)
>   {
>   	/*
>   	 * kasan_map_memory will map all of the required address space and
> @@ -32,7 +32,11 @@ void kasan_init(void)
>   	 */
>   	kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
>   	init_task.kasan_depth =3D 0;
> -	kasan_um_is_ready =3D true;
> +	/*
> +	 * Since kasan_init() is called before main(),
> +	 * KASAN is initialized but the enablement is deferred after
> +	 * jump_label_init(). See arch_mm_preinit().
> +	 */
>   }
>  =20
>   static void (*kasan_init_ptr)(void)
> @@ -58,6 +62,9 @@ static unsigned long brk_end;
>  =20
>   void __init arch_mm_preinit(void)
>   {
> +	/* Safe to call after jump_label_init(). Enables KASAN. */
> +	kasan_init_generic();
> +
>   	/* clear the zero-page */
>   	memset(empty_zero_page, 0, PAGE_SIZE);
>  =20
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index 6f612d69ea0c..9eca967d8526 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,32 +4,46 @@
>  =20
>   #include <linux/static_key.h>
>  =20
> -#ifdef CONFIG_KASAN_HW_TAGS
> -
> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> +/*
> + * Global runtime flag for KASAN modes that need runtime control.
> + * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
> + */
>   DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  =20
> +/*
> + * Runtime control for shadow memory initialization or HW_TAGS mode.
> + * Uses static key for architectures that need deferred KASAN or HW_TAGS=
.
> + */
>   static __always_inline bool kasan_enabled(void)
>   {
>   	return static_branch_likely(&kasan_flag_enabled);
>   }
>  =20
> -static inline bool kasan_hw_tags_enabled(void)
> +static inline void kasan_enable(void)
>   {
> -	return kasan_enabled();
> +	static_branch_enable(&kasan_flag_enabled);
>   }
> -
> -#else /* CONFIG_KASAN_HW_TAGS */
> -
> -static inline bool kasan_enabled(void)
> +#else
> +/* For architectures that can enable KASAN early, use compile-time check=
. */
> +static __always_inline bool kasan_enabled(void)
>   {
>   	return IS_ENABLED(CONFIG_KASAN);
>   }
>  =20
> +static inline void kasan_enable(void) {}
> +#endif /* CONFIG_ARCH_DEFER_KASAN || CONFIG_KASAN_HW_TAGS */
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +static inline bool kasan_hw_tags_enabled(void)
> +{
> +	return kasan_enabled();
> +}
> +#else
>   static inline bool kasan_hw_tags_enabled(void)
>   {
>   	return false;
>   }
> -
>   #endif /* CONFIG_KASAN_HW_TAGS */
>  =20
>   #endif /* LINUX_KASAN_ENABLED_H */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..51a8293d1af6 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -543,6 +543,12 @@ void kasan_report_async(void);
>  =20
>   #endif /* CONFIG_KASAN_HW_TAGS */
>  =20
> +#ifdef CONFIG_KASAN_GENERIC
> +void __init kasan_init_generic(void);
> +#else
> +static inline void kasan_init_generic(void) { }
> +#endif
> +
>   #ifdef CONFIG_KASAN_SW_TAGS
>   void __init kasan_init_sw_tags(void);
>   #else
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f82889a830fa..a4bb610a7a6f 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -19,6 +19,18 @@ config ARCH_DISABLE_KASAN_INLINE
>   	  Disables both inline and stack instrumentation. Selected by
>   	  architectures that do not support these instrumentation types.
>  =20
> +config ARCH_NEEDS_DEFER_KASAN
> +	bool
> +
> +config ARCH_DEFER_KASAN
> +	def_bool y
> +	depends on KASAN && ARCH_NEEDS_DEFER_KASAN
> +	help
> +	  Architectures should select this if they need to defer KASAN
> +	  initialization until shadow memory is properly set up. This
> +	  enables runtime control via static keys. Otherwise, KASAN uses
> +	  compile-time constants for better performance.
> +
>   config CC_HAS_KASAN_GENERIC
>   	def_bool $(cc-option, -fsanitize=3Dkernel-address)
>  =20
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9142964ab9c9..e3765931a31f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -32,6 +32,15 @@
>   #include "kasan.h"
>   #include "../slab.h"
>  =20
> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> +/*
> + * Definition of the unified static key declared in kasan-enabled.h.
> + * This provides consistent runtime enable/disable across KASAN modes.
> + */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +EXPORT_SYMBOL_GPL(kasan_flag_enabled);
> +#endif
> +
>   struct slab *kasan_addr_to_slab(const void *addr)
>   {
>   	if (virt_addr_valid(addr))
> @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem_cac=
he *cache, void *object,
>   bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>   				unsigned long ip)
>   {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))
>   		return false;
>   	return check_slab_allocation(cache, object, ip);
>   }
> @@ -254,7 +263,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, =
void *object,
>   bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool ini=
t,
>   		       bool still_accessible)
>   {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))
>   		return false;
>  =20
>   	/*
> @@ -293,7 +302,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void=
 *object, bool init,
>  =20
>   static inline bool check_page_allocation(void *ptr, unsigned long ip)
>   {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return false;
>  =20
>   	if (ptr !=3D page_address(virt_to_head_page(ptr))) {
> @@ -522,7 +531,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigne=
d long ip)
>   		return true;
>   	}
>  =20
> -	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> +	if (is_kfence_address(ptr))
>   		return true;
>  =20
>   	slab =3D folio_slab(folio);
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e7..b413c46b3e04 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -36,6 +36,17 @@
>   #include "kasan.h"
>   #include "../slab.h"
>  =20
> +/*
> + * Initialize Generic KASAN and enable runtime checks.
> + * This should be called from arch kasan_init() once shadow memory is re=
ady.
> + */
> +void __init kasan_init_generic(void)
> +{
> +	kasan_enable();
> +
> +	pr_info("KernelAddressSanitizer initialized (generic)\n");
> +}
> +
>   /*
>    * All functions below always inlined so compiler could
>    * perform better optimizations in each of __asan_loadX/__assn_storeX
> @@ -165,7 +176,7 @@ static __always_inline bool check_region_inline(const=
 void *addr,
>   						size_t size, bool write,
>   						unsigned long ret_ip)
>   {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return true;
>  =20
>   	if (unlikely(size =3D=3D 0))
> @@ -193,7 +204,7 @@ bool kasan_byte_accessible(const void *addr)
>   {
>   	s8 shadow_byte;
>  =20
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return true;
>  =20
>   	shadow_byte =3D READ_ONCE(*(s8 *)kasan_mem_to_shadow(addr));
> @@ -495,7 +506,7 @@ static void release_alloc_meta(struct kasan_alloc_met=
a *meta)
>  =20
>   static void release_free_meta(const void *object, struct kasan_free_met=
a *meta)
>   {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return;
>  =20
>   	/* Check if free meta is valid. */
> @@ -562,7 +573,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, =
void *object, gfp_t flags)
>   	kasan_save_track(&alloc_meta->alloc_track, flags);
>   }
>  =20
> -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
>   {
>   	struct kasan_free_meta *free_meta;
>  =20
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9a6927394b54..c8289a3feabf 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
>   static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>   static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>  =20
> -/*
> - * Whether KASAN is enabled at all.
> - * The value remains false until KASAN is initialized by kasan_init_hw_t=
ags().
> - */
> -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> -EXPORT_SYMBOL(kasan_flag_enabled);
> -
>   /*
>    * Whether the selected mode is synchronous, asynchronous, or asymmetri=
c.
>    * Defaults to KASAN_MODE_SYNC.
> @@ -260,7 +253,7 @@ void __init kasan_init_hw_tags(void)
>   	kasan_init_tags();
>  =20
>   	/* KASAN is now initialized, enable it. */
> -	static_branch_enable(&kasan_flag_enabled);
> +	kasan_enable();
>  =20
>   	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, vmall=
oc=3D%s, stacktrace=3D%s)\n",
>   		kasan_mode_info(),
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..8a9d8a6ea717 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -398,7 +398,13 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, d=
epot_flags_t depot_flags);
>   void kasan_set_track(struct kasan_track *track, depot_stack_handle_t st=
ack);
>   void kasan_save_track(struct kasan_track *track, gfp_t flags);
>   void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_=
t flags);
> -void kasan_save_free_info(struct kmem_cache *cache, void *object);
> +
> +void __kasan_save_free_info(struct kmem_cache *cache, void *object);
> +static inline void kasan_save_free_info(struct kmem_cache *cache, void *=
object)
> +{
> +	if (kasan_enabled())
> +		__kasan_save_free_info(cache, object);
> +}
>  =20
>   #ifdef CONFIG_KASAN_GENERIC
>   bool kasan_quarantine_put(struct kmem_cache *cache, void *object);
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d2c70cd2afb1..2e126cb21b68 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -125,7 +125,7 @@ void kasan_poison(const void *addr, size_t size, u8 v=
alue, bool init)
>   {
>   	void *shadow_start, *shadow_end;
>  =20
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return;
>  =20
>   	/*
> @@ -150,7 +150,7 @@ EXPORT_SYMBOL_GPL(kasan_poison);
>   #ifdef CONFIG_KASAN_GENERIC
>   void kasan_poison_last_granule(const void *addr, size_t size)
>   {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return;
>  =20
>   	if (size & KASAN_GRANULE_MASK) {
> @@ -390,7 +390,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsign=
ed long size)
>   	unsigned long shadow_start, shadow_end;
>   	int ret;
>  =20
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return 0;
>  =20
>   	if (!is_vmalloc_or_module_addr((void *)addr))
> @@ -560,7 +560,7 @@ void kasan_release_vmalloc(unsigned long start, unsig=
ned long end,
>   	unsigned long region_start, region_end;
>   	unsigned long size;
>  =20
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return;
>  =20
>   	region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
> @@ -611,7 +611,7 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>   	 * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ignored=
.
>   	 */
>  =20
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return (void *)start;
>  =20
>   	if (!is_vmalloc_or_module_addr(start))
> @@ -636,7 +636,7 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>    */
>   void __kasan_poison_vmalloc(const void *start, unsigned long size)
>   {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>   		return;
>  =20
>   	if (!is_vmalloc_or_module_addr(start))
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index b9382b5b6a37..c75741a74602 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -44,6 +44,7 @@ void __init kasan_init_sw_tags(void)
>   		per_cpu(prng_state, cpu) =3D (u32)get_cycles();
>  =20
>   	kasan_init_tags();
> +	kasan_enable();
>  =20
>   	pr_info("KernelAddressSanitizer initialized (sw-tags, stacktrace=3D%s)=
\n",
>   		str_on_off(kasan_stack_collection_enabled()));
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index d65d48b85f90..b9f31293622b 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -142,7 +142,7 @@ void kasan_save_alloc_info(struct kmem_cache *cache, =
void *object, gfp_t flags)
>   	save_stack_info(cache, object, flags, false);
>   }
>  =20
> -void kasan_save_free_info(struct kmem_cache *cache, void *object)
> +void __kasan_save_free_info(struct kmem_cache *cache, void *object)
>   {
>   	save_stack_info(cache, object, 0, true);
>   }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1=
23a3290-ac87-4fbd-af7c-12858aa76f32%40csgroup.eu.
