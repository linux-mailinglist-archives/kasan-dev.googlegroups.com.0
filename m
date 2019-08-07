Return-Path: <kasan-dev+bncBCXLBLOA7IGBBPOVVPVAKGQEU3IPWSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id E9E6684F94
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 17:14:05 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id i12sf2170743lfp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 08:14:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565190845; cv=pass;
        d=google.com; s=arc-20160816;
        b=IABvlICfe6otgQJTWjiChCfS8bBipLh3uz3/qEershOj0320HAB1mwMKcNU5mIdNYE
         /7YIlHtMPxHDPKxAI2pZ0i6Mv6lbSI2DwWfu/2vwpRjc6b764v4+Giq1fUf166yef0d8
         rQLfgKGk4E85fOA5k4BeYqU4pF1QHkmX54W4oavCOMkx5zb1WHUv0+dWct03G/scBRG7
         pqxKwQKOVLTaLHrSGxyJzTn1nnhR3IE5rdR6mnlNAI6ywZU9iKrb8U5HLyEihvtL3CjN
         avYLyFQDmo+lp/cfO2lVcIItSY4CTIdXM+5/VA3iLcL3XSO9DXahKZOmty5Poy+/JE29
         DiXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=0b7NN9K5l37Jq8QdCKTod8ObK3VD37IyfYrBFO9zDo0=;
        b=hVH92AMP1qj8ujpqS8FFieCPlAKLNGeoZ0t9y1WSJ+e/tZiizw0oUlaFR4LF57wD9g
         S96XULJMuBQN3ThG+AXHfSKhf8sKVrU+9jjQqT66Vw1nTe+YVr47btTMiJa90XHj8JFM
         wdntjBUkJakqnrHNo7Lg2RaAmgNw2ie3VNlgNx7ALd9pC6QaN22r4rEM65X/9a5nlHaR
         FGYrNSBXtjcVxP4SyCGXFaEuG1s+2+Zh3XPfeYu1HC+FcgwQru6krk2rb8WLNDUsHZKx
         Dh5g1R1f4xrriEnaM11r22PT7ll4srCsCCCRloSR64tqzzI4wzILSn0A5fxelcxENhwR
         BFpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Iv+MmC10;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0b7NN9K5l37Jq8QdCKTod8ObK3VD37IyfYrBFO9zDo0=;
        b=FOJ4NLQNkeK4UFw66/imFanMiFfPX5RYpFNojIPAeebGlITVVc0ROqkHnAIyvPSx6B
         RkVPBYCuVCUXxqa+Os1u8CQ5BdHr1Ysv1at7I6jV/Y1F3NgLZTLhF5jvSYLQqSkD9gLH
         0rjaUtCe8AswwZAmA6rtPAgvbCQEJAlcWWIJ1qDdLF8pXYTyt/UDZpd2yXQR8eyxYWPi
         pqR5BKsl0qRxilY/4xg2hOR4RsgflG7s8VYf4RsBAuFzwgSTB2p7m8G+ivaHyeaBw8pg
         yY1nQMtRoyz0P3wkv6CQHEiPKN/4egQvj3w1q7IRhrITfHhne2qSC9suPS/2nw/GYt0H
         QqPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0b7NN9K5l37Jq8QdCKTod8ObK3VD37IyfYrBFO9zDo0=;
        b=rmFqTxmtgtq7HdQn4zSWC6Cje1ae/nepF+JYCGVZzJ7WsBdhQGJRyL/mtg43AdQ+WI
         n8YovVoUdxGiWP9oqpx47F4pRJNSeLp/tDCx8mscbR9Yql18WqdBth5+7/8d787iZnBh
         mqQ6Hk94QKFKGHJvmyh4wUEI+f3YqifbsqGVS8pvMMO7wk5ZVoDLl6EkiX8aq/4umznL
         0LdgppqvI9tHlbK4bnPQqtTJb3Pb+GoVUy9Hn4NfHefGm1v0vEMOlIY3jHMPGtfmeYj8
         262oUL+YPJXzccoyj83cuPqV0xY36IRrUz9HdTMHeqVDNHDuqiRd+ZLnalQsi8vDC6yT
         PMVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXNY/VhDvyqUhs/SAODO6vGlsgBSt/dROdlIHccp63UH2fRLL1e
	6Dk3DgmHxVjracoif5HBs3g=
X-Google-Smtp-Source: APXvYqyizZCW1nUfI3yhiA01TtKUhDKtwVPZf55oTosJ0jWGSjVhnAlrLGBdEttg8EeA5CDGhQAxtA==
X-Received: by 2002:ac2:4901:: with SMTP id n1mr6325679lfi.0.1565190845561;
        Wed, 07 Aug 2019 08:14:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:553:: with SMTP id 80ls10306198ljf.4.gmail; Wed, 07 Aug
 2019 08:14:05 -0700 (PDT)
X-Received: by 2002:a2e:6e0c:: with SMTP id j12mr5125653ljc.123.1565190845093;
        Wed, 07 Aug 2019 08:14:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565190845; cv=none;
        d=google.com; s=arc-20160816;
        b=OYO1Yge54vBu2AZ8u7aDTqfMCY1qedxil4ahbpIT9/MbLQNfImDaSRs4Tqubr3Tcf0
         Ld6YqjfigUdK4nAlsjXH4C45uUgRpcQRRAy8N3XfkKNFloh1KgHO4IEEf9i3oxX6ccQM
         90B+JwSYwv0wLI3r349iJwpJlox/IU1G7OAVBdjEF9OqerJGGmWnyL2M5cLwBvu7+MJD
         lsOec9PuAlHltgDx3WA8qHMR19LGDyvv3/PIOY2lgURj9WGr4cgHh2qtUzmcvAUVD1YE
         Ad5z1CBmsjmqRIKCv383XJpg8TbIZ6MYsucIAC99+cxzTwgnCZ3lmpLXHHKQragy2hqQ
         1AMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=rYoOzHlpzhdAeooJ2ys1zxWQvB9wTJwGi1JptDkR2XE=;
        b=w+A1pASfjxwOE8SV1+ooDJDe+8U4dyGhprN3FjjcioJxRJ6mIINPbS4WnMpRRclu2r
         e9GiO/+IakBywfwCtVhlTn5HT0Zwfg/FhLGhCmuNL6lbOOEiuaQc2ynLsh/GYWuUuZrm
         0MTzF9LH+m1AX141dTr7LfGj62g5D2uK6JyRx0xOjBI6AjmOCoLK6zKPt3CBDy2ofGuM
         ajrADU5n1939OB45Y/75//wa4Wu9LW7UTNVZNKp/ZCJXtddyYF8dRl6rQAfGJvs++gfW
         gZk88G+xUDJTPNkCTL05ZPDeAmeABuyGdTLLnWD9IJW63SeKHwY12ImIR3ePdDGWe2sV
         RJ2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Iv+MmC10;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id u10si744302lfk.0.2019.08.07.08.14.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 08:14:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 463Zlt34WCzB09ZG;
	Wed,  7 Aug 2019 17:14:02 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id UkWrvKqFskXm; Wed,  7 Aug 2019 17:14:02 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 463Zlt1yBvzB09ZD;
	Wed,  7 Aug 2019 17:14:02 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id F10298B835;
	Wed,  7 Aug 2019 17:14:03 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id BmeBMEgwHiAR; Wed,  7 Aug 2019 17:14:03 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C02EA8B832;
	Wed,  7 Aug 2019 17:14:03 +0200 (CEST)
Subject: Re: [PATCH 1/4] kasan: allow arches to provide their own early shadow
 setup
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <023863f0-0aa5-17f5-41c9-88acfc9a786b@c-s.fr>
Date: Wed, 7 Aug 2019 17:14:03 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190806233827.16454-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Iv+MmC10;       spf=pass (google.com:
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



Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
> powerpc supports several different MMUs. In particular, book3s
> machines support both a hash-table based MMU and a radix MMU.
> These MMUs support different numbers of entries per directory
> level: the PTES_PER_* defines evaluate to variables, not constants.
> This leads to complier errors as global variables must have constant
> sizes.
>=20
> Allow architectures to manage their own early shadow variables so we
> can work around this on powerpc.

This seems rather strange to move the early shadow tables out of=20
mm/kasan/init.c allthough they are used there still.

What about doing for all what is already done for=20
kasan_early_shadow_p4d[], in extenso define constant max sizes=20
MAX_PTRS_PER_PTE, MAX_PTRS_PER_PMD and MAX_PTRS_PER_PUD ?

With a set of the following, it would remain transparent for other arches.
#ifndef MAX_PTRS_PER_PXX
#define MAX_PTRS_PER_PXX PTRS_PER_PXX
#endif

Then you would just need to do the following for Radix:

#define MAX_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
#define MAX_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
#define MAX_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)


For the kasan_early_shadow_page[], I don't think we have variable=20
PAGE_SIZE, have we ?

Christophe


>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> ---
> Changes from RFC:
>=20
>   - To make checkpatch happy, move ARCH_HAS_KASAN_EARLY_SHADOW from
>     a random #define to a config option selected when building for
>     ppc64 book3s
> ---
>   include/linux/kasan.h |  2 ++
>   lib/Kconfig.kasan     |  3 +++
>   mm/kasan/init.c       | 10 ++++++++++
>   3 files changed, 15 insertions(+)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ec81113fcee4..15933da52a3e 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -14,11 +14,13 @@ struct task_struct;
>   #include <asm/kasan.h>
>   #include <asm/pgtable.h>
>  =20
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>   extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>   extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>   extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
> +#endif
>  =20
>   int kasan_populate_early_shadow(const void *shadow_start,
>   				const void *shadow_end);
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index a320dc2e9317..0621a0129c04 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
>   config	HAVE_ARCH_KASAN_VMALLOC
>   	bool
>  =20
> +config ARCH_HAS_KASAN_EARLY_SHADOW
> +	bool
> +
>   config CC_HAS_KASAN_GENERIC
>   	def_bool $(cc-option, -fsanitize=3Dkernel-address)
>  =20
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ce45c491ebcd..7ef2b87a7988 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -31,10 +31,14 @@
>    *   - Latter it reused it as zero shadow to cover large ranges of memo=
ry
>    *     that allowed to access, but not handled by kasan (vmalloc/vmemma=
p ...).
>    */
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
> +#endif
>  =20
>   #if CONFIG_PGTABLE_LEVELS > 4
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
> +#endif
>   static inline bool kasan_p4d_table(pgd_t pgd)
>   {
>   	return pgd_page(pgd) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
4d));
> @@ -46,7 +50,9 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 3
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +#endif
>   static inline bool kasan_pud_table(p4d_t p4d)
>   {
>   	return p4d_page(p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
ud));
> @@ -58,7 +64,9 @@ static inline bool kasan_pud_table(p4d_t p4d)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 2
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +#endif
>   static inline bool kasan_pmd_table(pud_t pud)
>   {
>   	return pud_page(pud) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
md));
> @@ -69,7 +77,9 @@ static inline bool kasan_pmd_table(pud_t pud)
>   	return false;
>   }
>   #endif
> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>   pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
> +#endif
>  =20
>   static inline bool kasan_pte_table(pmd_t pmd)
>   {
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/023863f0-0aa5-17f5-41c9-88acfc9a786b%40c-s.fr.
