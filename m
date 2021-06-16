Return-Path: <kasan-dev+bncBDLKPY4HVQKBBFXHVCDAMGQECSC5IVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 06CAD3AA25B
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 19:23:35 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id i8-20020a2e80880000b0290161f7012dd7sf185604ljg.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:23:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623864214; cv=pass;
        d=google.com; s=arc-20160816;
        b=0XL3GXERyRgS5N+hFMez3qYxuY8/fiP4ddIgDqgrdiOJeYLbXfhaGKx5ca+kB/Kt/A
         Irtr8zEfDXO3NbcMwN8WTWNIJOMBRk2JJBTi2kCtEVBBf9Qml7kPlWrYk9X6M1ZIH8xh
         oBDvVx3q6UOgmvNz2bSyAn4gJEzH85/yPv/0aKF9rDCBk7KV7Yj3sqF5VS8Tl1Wl7mPn
         H/CgaQv1l+KqMZc1KrIdHkjNlpTVkWnyoaSLs1hd6MaJhyBAnUkO33jQ43YBX+U3jRUW
         u6UvF/OjHs+hz2RFioYSzK8hI9yhtg1CHwAW5R/FlhmBT3yJYu1Dgmo7S6q9cBJrNvV3
         E5mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=2oAyH9ZIb5pSgMfP0XGQ55zLkAG+zs4V/F+cb8ti/IQ=;
        b=qVL6vB/2Cu+dSup2BrabID7bEKzqjVADB/AQTNFqYW+ji+3J8kLoN9eiSeUcp5TtHH
         NQONWkgRoNwf6Lypmln67pCbP1FLEJND2z58w+e9pL725LCsqLiZf9JapjidjC6lnzma
         RhD5ml15BUt5jjsYvIWJPkP0FZ5rAs2w+R/bJoAG4t29nLjEt4IalEUnmiRqGxojJF9O
         PwSLhVaDTDt2cFvwGwmXmoOQz0YSasleVlB8O9E0FmXX4UEzGRIWcADjws8WduNftdD6
         b9fOudsT9c5jHoT2JkBDSwV1uuYNdbp7SLXoOwQbHxZQAcARGrPrJE2rII+5N+ze+OQI
         4VGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2oAyH9ZIb5pSgMfP0XGQ55zLkAG+zs4V/F+cb8ti/IQ=;
        b=Ft8qghespqbDd1Xoo9SDB//Bai1ny/t3gTv1sKW1A2mbRYv8ba5nNgSh/bWqmCjtNJ
         t4yspEAAruGAw7Vg5cGl4VOIoT28qqhBVmE8CvbPKtrNPr3B9ly3pRSBa1XlLSjk+YPd
         gDg7y0fBS+7SDXZhgQZV5gNhxe73FlnO30fyeAJeDMQ4mwoLakmFPiIfVT/XAFcGy11P
         HmK8OF5w7nUxAWA4vx+zP9XhGudYHiOUMgmVgkrHHBoyin1ygMqoAlvl9K9PlP9Werpi
         eJq+8CEAASOnpZGbqtU8ElDUP6YULniIdBDIspI2ms17/Gmv9ZY2mVTKbVxS3R8/3AAH
         CJ9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2oAyH9ZIb5pSgMfP0XGQ55zLkAG+zs4V/F+cb8ti/IQ=;
        b=LVhasL7miHu/bj+xBcf1Al1Id3ilhczdH+XExcKgwQGJU5h2gne1LWpyxgAl5ETwbp
         hgYvEd1K65qnoCCdXvsdkzh/3Nf0+mVJYi9Za2OIh6R4ey1dW6V7SDG0vjeINkji61wT
         32BlLFX/2y3SVy5MPc4/SUJx1rHINSYKSjxdh7cIC+hJiRHbxh+vE+QMcheMq7HRGsA3
         x1hWqGGf+elcyFl1Nj5/1VEoS/2d/Rj8ogdQAR8xeVxv2xzkxh1bE6MGpyIxmjNF98jw
         yq01+uPSlvOe24Hvs8RpcxgW27zGw+a5arJUSKjzoyn7SLO6kw8RLWfIaIUdkbOLPB23
         +fwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533UzgbWZYfYRCB7z4WQbRViagzLstkrAgoioXWmogo7IjGs4NXf
	pD2rp1S3U7m57hGrqe4QYaE=
X-Google-Smtp-Source: ABdhPJxvcPADOhVHNlt1GNaDdWFuHGl7fH67XjWGXiBcJrWvDTFSlIExsEoWS73kKokk6APKgV1ZNg==
X-Received: by 2002:a05:6512:c0c:: with SMTP id z12mr535846lfu.19.1623864214509;
        Wed, 16 Jun 2021 10:23:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8790:: with SMTP id n16ls783592lji.11.gmail; Wed, 16 Jun
 2021 10:23:33 -0700 (PDT)
X-Received: by 2002:a2e:7d0f:: with SMTP id y15mr827373ljc.388.1623864213477;
        Wed, 16 Jun 2021 10:23:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623864213; cv=none;
        d=google.com; s=arc-20160816;
        b=NuIqvXRUanGKq3fhcVvKuZxlKBUFmxlgKHXvX7TACmNIGAfokGYwqOPHFjqILM6Vd9
         9JevKMmCFqPo2/2leslVrszCl23uz9UvtKE3aGWj2gV8347V3OMnZtPhGkNVwC+l90x0
         Ab8oRQAEC4/CD/sBwqHOrLlGWBBnslWo+mcJR8OeW/2KdrysMgNitAqt+yVvOXXAPxxM
         7y27PjKOL/x5snz+YUhHpn21K2TehBCiHwQDb2oGOWwhEntxmk54/UBUEVZq26i6J7EE
         fXam5pxCCQ+6bpbccrvqgj6+hZgRX2C44EYl+HWVrrbQBpfXpgxBwHfqVj/mnFRPjVCx
         61IA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=oMG8VmNxvuhgAkLxAgz05H6I6W6GeunfBQeZ9IveMow=;
        b=Kef/Qj9EN5xAQpI32JQJlA9S6GzuJ7Ix7c3BDYm+/He1AfzSmkvemmFRhX6h22xgKC
         DX2MK7x0LxZxLNuNbi7IEW3+WhDJsBL45rLVeOlXizjj9xN3xW1/JP6/redKm/yc7SFa
         ObWDywEi0rx5rRvOZ0Y9O0TwKqVWeI4uUDHufZi3D2VBk4JLTqxOaswp7HuVk9eVv75Z
         PAx0Tcjl4Lv0teEmsS7HeXQeco9wI2FBmZmng3Agwqyfzjx6mBDptkrboZJi3REDNonk
         As5Uj9jzrYB4z7rN8vSEucHBtmz6DM1H6TDIwc3d1wpvliQkFQNJ3mQAYfR09XpvVo0U
         lWSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id d7si114209lfn.7.2021.06.16.10.23.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 10:23:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4G4sTw3h6xzBF2H;
	Wed, 16 Jun 2021 19:23:32 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id yApHasqJizLg; Wed, 16 Jun 2021 19:23:32 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4G4sTw2hZ0zBF2F;
	Wed, 16 Jun 2021 19:23:32 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id ED0A98B7F4;
	Wed, 16 Jun 2021 19:23:31 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id LawfKpjZWmkI; Wed, 16 Jun 2021 19:23:31 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id EBB2C8B7F2;
	Wed, 16 Jun 2021 19:23:30 +0200 (CEST)
Subject: Re: [PATCH v13 3/3] kasan: define and use MAX_PTRS_PER_* for early
 shadow tables
To: Marco Elver <elver@google.com>, Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Andrey Konovalov <andreyknvl@gmail.com>, linuxppc-dev@lists.ozlabs.org,
 aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>
References: <20210616080244.51236-1-dja@axtens.net>
 <20210616080244.51236-4-dja@axtens.net>
 <CANpmjNN2-nkqaQ8J3nU5QJ4KGkX2mwiNTeTCNPGQYdbb1v2OaA@mail.gmail.com>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <86c9cecd-ec51-533c-0903-87b85c733695@csgroup.eu>
Date: Wed, 16 Jun 2021 19:23:28 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNN2-nkqaQ8J3nU5QJ4KGkX2mwiNTeTCNPGQYdbb1v2OaA@mail.gmail.com>
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



Le 16/06/2021 =C3=A0 11:07, Marco Elver a =C3=A9crit=C2=A0:
> On Wed, 16 Jun 2021 at 10:03, Daniel Axtens <dja@axtens.net> wrote:
> [...]
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 768d7d342757..fd65f477ac92 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -40,10 +40,22 @@ struct kunit_kasan_expectation {
>>   #define PTE_HWTABLE_PTRS 0
>>   #endif
>>
>> +#ifndef MAX_PTRS_PER_PTE
>> +#define MAX_PTRS_PER_PTE PTRS_PER_PTE
>> +#endif
>> +
>> +#ifndef MAX_PTRS_PER_PMD
>> +#define MAX_PTRS_PER_PMD PTRS_PER_PMD
>> +#endif
>> +
>> +#ifndef MAX_PTRS_PER_PUD
>> +#define MAX_PTRS_PER_PUD PTRS_PER_PUD
>> +#endif
>=20
> This is introducing new global constants in a <linux/..> header. It
> feels like this should be in <linux/pgtable.h> together with a
> comment. Because <linux/kasan.h> is actually included in
> <linux/slab.h>, most of the kernel will get these new definitions.
> That in itself is fine, but it feels wrong that the KASAN header
> introduces these.
>=20
> Thoughts?
>=20
> Sorry for only realizing this now.

My idea here was to follow the same road as MAX_PTRS_PER_P4D, added by comm=
it=20
https://github.com/linuxppc/linux/commit/c65e774f

That commit spread MAX_PTRS_PER_P4D everywhere.

Instead of doing the same, we found that it would be better to define a fal=
lback for when the=20
architecture doesn't define MAX_PTRS_PER_PxD . Now, it can be made more glo=
bal in pgtable.h, in that=20
case I'd suggest to also include MAX_PTRS_PER_P4D in the dance and avoid ar=
chitectures like s390=20
having to define it, or even not defining it either in asm-generic/pgtable-=
nop4d.h

Christophe

>=20
> Thanks,
> -- Marco
>=20
>>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
>> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS=
];
>> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
>> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>>   extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>>
>>   int kasan_populate_early_shadow(const void *shadow_start,
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index 348f31d15a97..cc64ed6858c6 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -41,7 +41,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>>   }
>>   #endif
>>   #if CONFIG_PGTABLE_LEVELS > 3
>> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
>> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>>   static inline bool kasan_pud_table(p4d_t p4d)
>>   {
>>          return p4d_page(p4d) =3D=3D virt_to_page(lm_alias(kasan_early_s=
hadow_pud));
>> @@ -53,7 +53,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>>   }
>>   #endif
>>   #if CONFIG_PGTABLE_LEVELS > 2
>> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
>> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>>   static inline bool kasan_pmd_table(pud_t pud)
>>   {
>>          return pud_page(pud) =3D=3D virt_to_page(lm_alias(kasan_early_s=
hadow_pmd));
>> @@ -64,7 +64,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>>          return false;
>>   }
>>   #endif
>> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
>> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS]
>>          __page_aligned_bss;
>>
>>   static inline bool kasan_pte_table(pmd_t pmd)
>> --
>> 2.30.2
>>
>> --
>> You received this message because you are subscribed to the Google Group=
s "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send a=
n email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msg=
id/kasan-dev/20210616080244.51236-4-dja%40axtens.net.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/86c9cecd-ec51-533c-0903-87b85c733695%40csgroup.eu.
