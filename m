Return-Path: <kasan-dev+bncBCXLBLOA7IGBBV7EVTVAKGQEWEL77BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B5DD8546F
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 22:19:36 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id u5sf2475128lfu.12
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2019 13:19:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565209175; cv=pass;
        d=google.com; s=arc-20160816;
        b=lgeEy2AAV3ZV5QB593h+oqhdlH9WKSTzQH7ytXJnCQ+Z6KOWaMKCIp8JKyI6bqFARO
         VnW1BcDEifE8pETNv+rP3DPjadFN7/625hMZ0Nd26FMw+hHlZwQT/3T0wqJ/QsP0aLJE
         QwDvEn/++s+095EBA7XuBmSuIAmcVNRXeHloT9H25hbt86vNhda4CdGILswnj+Gba6nS
         6W7RAB0s8hwx+gZfVlgi4l5NjtYp3ze+2jcRKoHt7gQkt8PLd22ZgeF5Y5u2lQ4GbUpa
         wZOpYnak0kof+7gEX0n0DN7fBEnxNLiUoBkixxolNI2rjuAgCJUAmnXlWE4jkcxZ5qjR
         s/xA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=8Pa1Ps7k5icwHuQS/SumY9ZMh5sFtvmPvjEYX9u+R78=;
        b=UPNmmS6RLTD4IT9laTT4xDwGtob5BmkXtbGQJGzr6eRd2Pw1NjyWW47LLoZamsvNUA
         ljUytUBJpfunDOqYuGgoBT99PyRXhmqR2bLj+OUr/btyrmpJmDs3Il+sagUnoEGLlNZr
         hDvw0CmoJT3oWCe7PcSHRGnZu1TlxwbUmN8sj3/xNVJkU87asrq7/eOHO83UuQJzZY6b
         it3qMruYj/zN2P4J72/llJJU/thmBp9ta86TRFm+KZL4QLPY8pKNziyhbGQtBrnrJdxm
         llagQBBoc8tCRzT2fS+o7qgyMQALtjWVA9VPF7KERSyTMMf0uE9uQgVzTA0kCD0hRI2I
         Z6yA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=KTQQgedC;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Pa1Ps7k5icwHuQS/SumY9ZMh5sFtvmPvjEYX9u+R78=;
        b=Iwdblc2Vae4xzSNFZ4PhB5hj+P/LCb5wE48DzMzrx07wPNB/Zbrjkz2gwuCIiSo5Vq
         uc8Y9sOeIZ8Y3ERH2HUNY+fhHTsWTMrNOOZakOplkqTiVWMHVloXOxBL80iHSY1MqoAZ
         nuzRoqx6ZehtQqY2VRNcrr5k4+6TaxB+0WQfiuPCH1wVXQ2zuj376Ot/uMLSAK1tw2RE
         AAXtcvhVyPYHB9VjWTuM2mOJLs6YSggj2dpFQIIMeWctleSW749K7UoRTt4C5boRk1Sl
         aJq+qCIyJHcEJl3CYfw50YzYuafzQzyoG5A1UR2ilV97/fOGU8vlJfIaXzHJw2hUEmWK
         Amog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Pa1Ps7k5icwHuQS/SumY9ZMh5sFtvmPvjEYX9u+R78=;
        b=KDLutMXIb0tRKdtZfm+34XsbDmIU5cmb9/CcrxG+/w9UAT0olfrEQD4p0nFE7EnMP+
         fQD8X4tjbBROAhAoA1Jhl8dfnLt7bRTweMgqvBJBKq1k/xMX0qvh5GcsslAwPqq/mZI0
         wt/x5uuwEMSxZ3XDDVtayTmUItgpHYBfXogZcfqUXZZjYGipqweHgijarxIPsO9+3d7W
         hJVjCQsm9U/t4aT/IoLeUBGbRHOOetIdDOHXZF0VfCArMJOPlBIoFyVvqHA/FsSiVL+2
         oDkXNTJ53tiK5oXy9vzwS99yK8MqrbCfMo82Umir7x+YKgauc3i/RmSyGeO/LAviTzwL
         sHVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX1zGo7kpTYhkwwyKiwLTTZT0QNPQ7fPHtltHYCaFz6Zb+yfNnw
	2w0bDyYrX/aNzSfv+wibHQA=
X-Google-Smtp-Source: APXvYqwqPWzuT/h6PKEkIWOwdK535D7bWxQ3rveBmF2X8CXZuQz0VfW1zZwi0dD9Vt7ENCghShbX1Q==
X-Received: by 2002:a2e:9147:: with SMTP id q7mr5683960ljg.19.1565209175671;
        Wed, 07 Aug 2019 13:19:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:998e:: with SMTP id w14ls10388834lji.0.gmail; Wed, 07
 Aug 2019 13:19:35 -0700 (PDT)
X-Received: by 2002:a2e:9b48:: with SMTP id o8mr5909024ljj.122.1565209175070;
        Wed, 07 Aug 2019 13:19:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565209175; cv=none;
        d=google.com; s=arc-20160816;
        b=wuN0BXFE+SBnKRz8HDeqE2WXnyUJUBDZvp5liT6boETaon3Pr5aPUFxFIF/cmMtg/9
         GmN7dEE7TZus8G0UTAVycUxom5Neqq0QqqfDqL+9KSLDmDmuU+gcDgA7vIBjaDs1sDbs
         +CW3XBKrkVBzIw2qb3bihViFENIo7ZDBEGQJpSj4Zy2l0qWBejWWKTDH//FokMVSoNpE
         11+j/szWv++FV2HG6GplGuQrvNCzjjZOqdOfta5fQ1ZzP9cFNqmptmfjubsBOkn02kn9
         2vf1FQcYrE6mErxBI/taTdoKhf5RIlhsq3sIZrVqcLumT+GCJiei/yJtvUQm4/DZqWJD
         NuiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=57DtjlRxMDPWdcwxXXws0HEAdpUFobNq2eg6TQP36p4=;
        b=ZeiuO2CK7OdTTOtSrnZYWY0nBHq6PfdwxfLhAj91PkLmji5NqiyvFunPIrAiT5gFs3
         1jsWsbQ08EvwMqCG/f3oNTecXqF0gqhdx01W/DeevrMW+rkVUUfShdnaztn78pEukEHP
         AuRWBS9lfWnKqcjrQHUG+1rUzqyHgNeNHA5TtD/2lgUZ+JA5OCZb72HdbdPaKQuFjbg7
         ycQZhjWmXOxk1VUm9C3dBXCWEc6mA8qu755CeKR8v8W9kIrK/8cVEu0f5HpTRUrFqxvV
         iJ9f5MiQ2Yw7yWlDnX3uy00ZSFpjwnUcJ+uvoDcEhHSHo6KG1GH+fE22fQYSIl79es7g
         3zEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=KTQQgedC;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id s14si5736058ljg.4.2019.08.07.13.19.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Aug 2019 13:19:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 463jXP6c4Vz9vBLT;
	Wed,  7 Aug 2019 22:19:33 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id vkZg1hjmxe6j; Wed,  7 Aug 2019 22:19:33 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 463jXP5Y4Yz9vBLS;
	Wed,  7 Aug 2019 22:19:33 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D9EF38B83A;
	Wed,  7 Aug 2019 22:19:33 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id Xlnv674J6NDN; Wed,  7 Aug 2019 22:19:33 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C0EB48B839;
	Wed,  7 Aug 2019 22:19:32 +0200 (CEST)
Subject: Re: [PATCH 1/4] kasan: allow arches to provide their own early shadow
 setup
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190806233827.16454-1-dja@axtens.net>
 <20190806233827.16454-2-dja@axtens.net>
 <023863f0-0aa5-17f5-41c9-88acfc9a786b@c-s.fr>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <64256206-7c95-7f3c-f601-c688316ef680@c-s.fr>
Date: Wed, 7 Aug 2019 22:19:32 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <023863f0-0aa5-17f5-41c9-88acfc9a786b@c-s.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=KTQQgedC;       spf=pass (google.com:
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



Le 07/08/2019 =C3=A0 17:14, Christophe Leroy a =C3=A9crit=C2=A0:
>=20
>=20
> Le 07/08/2019 =C3=A0 01:38, Daniel Axtens a =C3=A9crit=C2=A0:
>> powerpc supports several different MMUs. In particular, book3s
>> machines support both a hash-table based MMU and a radix MMU.
>> These MMUs support different numbers of entries per directory
>> level: the PTES_PER_* defines evaluate to variables, not constants.
>> This leads to complier errors as global variables must have constant
>> sizes.
>>
>> Allow architectures to manage their own early shadow variables so we
>> can work around this on powerpc.
>=20
> This seems rather strange to move the early shadow tables out of=20
> mm/kasan/init.c allthough they are used there still.
>=20
> What about doing for all what is already done for=20
> kasan_early_shadow_p4d[], in extenso define constant max sizes=20
> MAX_PTRS_PER_PTE, MAX_PTRS_PER_PMD and MAX_PTRS_PER_PUD ?

To illustrate my suggestion, see commit c65e774fb3f6af21 ("x86/mm: Make=20
PGDIR_SHIFT and PTRS_PER_P4D variable")

The same principle should apply on all variable powerpc PTRS_PER_XXX.

Christophe

>=20
> With a set of the following, it would remain transparent for other arches=
.
> #ifndef MAX_PTRS_PER_PXX
> #define MAX_PTRS_PER_PXX PTRS_PER_PXX
> #endif
>=20
> Then you would just need to do the following for Radix:
>=20
> #define MAX_PTRS_PER_PTE=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (1 << =
RADIX_PTE_INDEX_SIZE)
> #define MAX_PTRS_PER_PMD=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (1 << =
RADIX_PMD_INDEX_SIZE)
> #define MAX_PTRS_PER_PUD=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 (1 << =
RADIX_PUD_INDEX_SIZE)
>=20
>=20
> For the kasan_early_shadow_page[], I don't think we have variable=20
> PAGE_SIZE, have we ?
>=20
> Christophe
>=20
>=20
>>
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>
>> ---
>> Changes from RFC:
>>
>> =C2=A0 - To make checkpatch happy, move ARCH_HAS_KASAN_EARLY_SHADOW from
>> =C2=A0=C2=A0=C2=A0 a random #define to a config option selected when bui=
lding for
>> =C2=A0=C2=A0=C2=A0 ppc64 book3s
>> ---
>> =C2=A0 include/linux/kasan.h |=C2=A0 2 ++
>> =C2=A0 lib/Kconfig.kasan=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 +++
>> =C2=A0 mm/kasan/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 10 ++++++++=
++
>> =C2=A0 3 files changed, 15 insertions(+)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index ec81113fcee4..15933da52a3e 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -14,11 +14,13 @@ struct task_struct;
>> =C2=A0 #include <asm/kasan.h>
>> =C2=A0 #include <asm/pgtable.h>
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>> =C2=A0 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>> =C2=A0 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>> =C2=A0 extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>> =C2=A0 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>> +#endif
>> =C2=A0 int kasan_populate_early_shadow(const void *shadow_start,
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 const void *shadow_end);
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index a320dc2e9317..0621a0129c04 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
>> =C2=A0 config=C2=A0=C2=A0=C2=A0 HAVE_ARCH_KASAN_VMALLOC
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 bool
>> +config ARCH_HAS_KASAN_EARLY_SHADOW
>> +=C2=A0=C2=A0=C2=A0 bool
>> +
>> =C2=A0 config CC_HAS_KASAN_GENERIC
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 def_bool $(cc-option, -fsanitize=3Dkernel=
-address)
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index ce45c491ebcd..7ef2b87a7988 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -31,10 +31,14 @@
>> =C2=A0=C2=A0 *=C2=A0=C2=A0 - Latter it reused it as zero shadow to cover=
 large ranges of=20
>> memory
>> =C2=A0=C2=A0 *=C2=A0=C2=A0=C2=A0=C2=A0 that allowed to access, but not h=
andled by kasan=20
>> (vmalloc/vmemmap ...).
>> =C2=A0=C2=A0 */
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_b=
ss;
>> +#endif
>> =C2=A0 #if CONFIG_PGTABLE_LEVELS > 4
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss=
;
>> +#endif
>> =C2=A0 static inline bool kasan_p4d_table(pgd_t pgd)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return pgd_page(pgd) =3D=3D=20
>> virt_to_page(lm_alias(kasan_early_shadow_p4d));
>> @@ -46,7 +50,9 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>> =C2=A0 }
>> =C2=A0 #endif
>> =C2=A0 #if CONFIG_PGTABLE_LEVELS > 3
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
>> +#endif
>> =C2=A0 static inline bool kasan_pud_table(p4d_t p4d)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return p4d_page(p4d) =3D=3D=20
>> virt_to_page(lm_alias(kasan_early_shadow_pud));
>> @@ -58,7 +64,9 @@ static inline bool kasan_pud_table(p4d_t p4d)
>> =C2=A0 }
>> =C2=A0 #endif
>> =C2=A0 #if CONFIG_PGTABLE_LEVELS > 2
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
>> +#endif
>> =C2=A0 static inline bool kasan_pmd_table(pud_t pud)
>> =C2=A0 {
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return pud_page(pud) =3D=3D=20
>> virt_to_page(lm_alias(kasan_early_shadow_pmd));
>> @@ -69,7 +77,9 @@ static inline bool kasan_pmd_table(pud_t pud)
>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 return false;
>> =C2=A0 }
>> =C2=A0 #endif
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>> =C2=A0 pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
>> +#endif
>> =C2=A0 static inline bool kasan_pte_table(pmd_t pmd)
>> =C2=A0 {
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/64256206-7c95-7f3c-f601-c688316ef680%40c-s.fr.
