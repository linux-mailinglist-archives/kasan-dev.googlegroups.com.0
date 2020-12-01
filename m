Return-Path: <kasan-dev+bncBAABBVPKTH7AKGQENCYKZRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B7592CA8D0
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:54:46 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id dv25sf446075ejb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:54:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841686; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1/8ad0YMH7p6nYNQnWNwK0nmmfzxvrECJ5dQTouMWiQbrPJJCuh4hwwOOLcG2JVOW
         McGRaqgLDIp9gkPqdhXab1TbdHzfKgN3JsvUCvti26qVm3qQlllkitbk8Wf6jBCi5jlq
         EM6pyCQhQsC0gQwomMDRhORNbuXfVQikJM5MIwIpuCZNrxcimMY/JwkLPf7eI5Bled0c
         3TsYzITQDHAo2oLKnPGVC0r0jqeFNwkLutDXz568Z2NOwX8JqZvC64Xd8qe8ja7sdXVY
         PpzOXFhawABdrUNwCOrXJeVMzkAduMFl+Yb5oj+Hu+Iz1VywhDn0vrM3etU2fMTwV3Fn
         2wlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=/qG4KnqDCqtsFtt9wE4PGvrwUu4DLrimzjtUWjFjMRc=;
        b=idhKTwhws6qJYrkqFzvA3VsAXFfM9Ra+IVlRTfIzwWhq+rOocaexfWS8TVPbuJbdSY
         gEiM7dJJKjM4Ysw7ZbuXGXSbfsVH7JpOWDIHIp83f+M+XxU3kkbdZlMyPVSI+nqMfAyv
         ysQSxbsmxrZfXVt3SCrL52lVQdo47NBWMYQtVPOQOHx2CfwtE/Bjls0iP5FOih5Zpx4V
         gGYBNh0JoHcaGVZ6Xd2HKpDy2cUwHZuG6MeOSD5odLIIVKt48SMQCct1yHDfz1vn8UT7
         6DbKGRrQQpU7wBTMAfwVgpHIsHl5esabDkG9NkvNZzBAaAvOUlMSV/R/bk45hIgb0MnI
         mmHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/qG4KnqDCqtsFtt9wE4PGvrwUu4DLrimzjtUWjFjMRc=;
        b=XYF5oSUB9zXPIFg/pyu6mAcmTM9EDcB7BVjqffm4b0J6cVOvUDniw7ttGVN9FesBKF
         crXOdd+t5b7wMofq+O0D6lwkuJhaDKai3vfpGBgk53qdYsgzRPuxRRgxvryAaT0advmI
         tCldGRK5s6VgQfKsMvjGLjIXG/xhwBUi/WivDAtJjo4vzcuSf4idZF2bIymsKFmjLcLT
         fewmWv2MVShgOYebqJBAQyBaROpQVkj3ttDPjltpc1H32UbPvDAkd75gxii7MqeESokG
         zeDqV+xuFSuku0seqCIWo0Ycg3ArgDy2BfoJmzBvw0ktya+PVVP3grFMK8oBOk+xi/Dp
         HscQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/qG4KnqDCqtsFtt9wE4PGvrwUu4DLrimzjtUWjFjMRc=;
        b=RLUTANGDwxgG3vSLNXl6EjCHtm8FLvUoifEm1QbvGX/QqUoLyaVr7x418oMUKH8bCj
         ezHw6njSplFu6MhsXABmnHJiXy9hBha/W6mOkIXuRBnGrALmMNOlk1eAETmwkdEO3yBs
         DXtYkRIqULKqlbYxMqfBuq0f06R6GAzs24veEff1zHK9z2grzweySkGmzWngapv9J/qV
         HRCbISf+dkk+uc7mcGb2Zk2rrE3cYa8P3oHnfFAbYcc20ZP0nKaYazgN6GD9LM9R6mKS
         iDkg1Bg+YDJU1X+l/IcSwmiDsqqXKSkDbHvcR1Z9niqs461LYxXx+/V9lLqIDUqOGUJC
         YQIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WlxOe0IQPDNvZCwEtT7BNkkk/rZx8rRoMRPETI8ufONmeKC6b
	qVZ3/tVVr8gGLoWl2lflQ+o=
X-Google-Smtp-Source: ABdhPJxduud6I8o9GLF8rexy7L26e4FhP5F0YQq0bcTSCOn+d1BQ8grWF8haMnMz/Ko4RMCY5nTu+A==
X-Received: by 2002:a50:ed04:: with SMTP id j4mr4118848eds.84.1606841686150;
        Tue, 01 Dec 2020 08:54:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:4396:: with SMTP id ne6ls1284778ejb.2.gmail; Tue, 01
 Dec 2020 08:54:45 -0800 (PST)
X-Received: by 2002:a17:906:3899:: with SMTP id q25mr3840673ejd.173.1606841685389;
        Tue, 01 Dec 2020 08:54:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841685; cv=none;
        d=google.com; s=arc-20160816;
        b=vlJF4YPn3ezbuxL4NlPgVttw87djgLyRq9W30hM1hPSyBis7O9IgHj5zUiVlBcGZuL
         Bi70+nEaQxMXYkhqYle80eQ3dsQYxz8jAu9WrGENcIvyGxmUHGQKRjpvglTE90pLBtk7
         aqWdPRk82XrjFrqANSp3dp5+FjL6EuyxuKyw1rvr8Xt/DcdzIdK5UBTUy5amwxerO128
         lZifFJnwcDY3+p2itQFd31rM6umFHfTgZJf+dj3iSOS2TJXA3wyTolICBDDfgFU3VlZz
         +PeUxtkrGrJHPWoBiYP4ALPS4wpsrzQucejhGH3F+4NZK6xtBikwU2EnqllnoFC9Qmny
         Aeag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=s4yMyjBApZjlv4H6GsG2Cp7oNIEWC8xKw7mcPeJmomY=;
        b=ET+o6AkCemtIviXnyTQtvfVIWCAB/lk7LIka92PFHSw1UYtuqdyL/dkzMPvahquCZK
         HxutlYKZKrZhrMu49oYcLfWIbB1ncg8pJKm5Id5FwVyE2XUmlzgGOPHS+tNaw2KvgJpk
         swi8zFgPmVW3QSXZxQdSQxCCMXM0VagVLA9lrxQ0YjvIg4E62uEXEZGGg8NFvsVS6zN2
         Ua42eTnUeaiQSpbhDTOOyjem+rdm7YAxS0FE4yBaDoIjeE5jkQuTQwAcWyCnc0eAcs9o
         jrqrXzmLRSzSmenMQK6WAQ6hw2GZAtAs2Q+0abWMFZTBJ7sI2r89psnr4VPFj6m7LA+S
         ROTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id v7si25744edj.5.2020.12.01.08.54.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:54:45 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Clp9b1pFmz9v401;
	Tue,  1 Dec 2020 17:54:43 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id nxZDn_ePIsb5; Tue,  1 Dec 2020 17:54:43 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Clp9b0kvcz9v3yy;
	Tue,  1 Dec 2020 17:54:43 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 519FA8B7BD;
	Tue,  1 Dec 2020 17:54:44 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Yy_vIq-izRbX; Tue,  1 Dec 2020 17:54:43 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 7FBEA8B7B7;
	Tue,  1 Dec 2020 17:54:39 +0100 (CET)
Subject: Re: [PATCH v9 3/6] kasan: define and use MAX_PTRS_PER_* for early
 shadow tables
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <dc20689a-27cd-b629-7dd3-c29b81b285ba@csgroup.eu>
Date: Tue, 1 Dec 2020 17:54:34 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-4-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 01/12/2020 =C3=A0 17:16, Daniel Axtens a =C3=A9crit=C2=A0:
> powerpc has a variable number of PTRS_PER_*, set at runtime based
> on the MMU that the kernel is booted under.
>=20
> This means the PTRS_PER_* are no longer constants, and therefore
> breaks the build.
>=20
> Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
> As KASAN is the only user at the moment, just define them in the kasan
> header, and have them default to PTRS_PER_* unless overridden in arch
> code.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>

My neww address is : christophe.leroy@csgroup.eu

> Suggested-by: Balbir Singh <bsingharora@gmail.com>
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

Same

> Reviewed-by: Balbir Singh <bsingharora@gmail.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   include/linux/kasan.h | 18 +++++++++++++++---
>   mm/kasan/init.c       |  6 +++---
>   2 files changed, 18 insertions(+), 6 deletions(-)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 3df66fdf6662..893d054aad6f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -24,10 +24,22 @@ struct kunit_kasan_expectation {
>   static inline bool kasan_arch_is_ready(void)	{ return true; }
>   #endif
>  =20
> +#ifndef MAX_PTRS_PER_PTE
> +#define MAX_PTRS_PER_PTE PTRS_PER_PTE
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PMD
> +#define MAX_PTRS_PER_PMD PTRS_PER_PMD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PUD
> +#define MAX_PTRS_PER_PUD PTRS_PER_PUD
> +#endif
> +
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>   extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  =20
>   int kasan_populate_early_shadow(const void *shadow_start,
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index fe6be0be1f76..42bca3d27db8 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 3
> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>   static inline bool kasan_pud_table(p4d_t p4d)
>   {
>   	return p4d_page(p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
ud));
> @@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 2
> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>   static inline bool kasan_pmd_table(pud_t pud)
>   {
>   	return pud_page(pud) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
md));
> @@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>   	return false;
>   }
>   #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
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
kasan-dev/dc20689a-27cd-b629-7dd3-c29b81b285ba%40csgroup.eu.
