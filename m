Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHWIXTXQKGQE5F2J3YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 90B07117F39
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 05:50:39 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id f4sf13179188ybb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 20:50:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575953438; cv=pass;
        d=google.com; s=arc-20160816;
        b=00Q4HrTTQcDnGmwrftuez6ox/IqJSS3spmRq/rAQOThyr61tQfaDkmZ7g5VhZIbCLs
         O10GggJHoZByCk4hXLDeDB7wnuLmwPQ/W93SGsKDm+J48AHzSicUoAXXxB9AjxQMnbv4
         YO6gl4Rs8ChK/PWRga/giIV7AOfy+FZTwJVErPxbj/2//MW5D5vCslIbS9+TTWmNliu0
         Skj38VbojZGvhebNBHAgrh2JTjvW78KKfQNgJmWby+ny64j4JD3TJZDvxrXLww6pq58W
         D5W/g3ifSbi9l55NAchJyYV82m8z6pdgvd3lMI7DTJ3O9TDOjPVu19qcyIayhlRUSQnh
         2yyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=cXBld4jvQWVLH448Bg9FUg7ZgRA0SVT2SMQAArzp2Yk=;
        b=q6VSWlYj3LfUlcE2vo0ds0zoW3ruVFrgcQe1AeDfvy0xXJ7yJZBrONgOD1FyWRGroH
         F1MZ+D6lnWkjD7v9A+HqHwt4O4W/AhfdZr4KhCsv8Zvq4FWP9Ugs62OuidYRDlisx1vP
         LP6FusHTz7h31WmJgIqyL6bCqRB1L86LJAMmDV8MgDdgqzDNOOJ0EigOCZyYv5L/vIbf
         p/k8qIe60hFENoUT2vyKiu+Pa2Z8oF0j/qwHqH9eeKgi/eMKfrOcKv/dR8rt0I/A93YZ
         W4Ca6j/UG0+z4ljYHSeIcr0xVFWKg/jpE2WzCXtYNI4+L7K1IdovvO/Xf5uEsmhSFdPa
         tH4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=c2X7ViWA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cXBld4jvQWVLH448Bg9FUg7ZgRA0SVT2SMQAArzp2Yk=;
        b=NqrbdwFPz3/opcT/cyhLNI/UkW0lySSuS77k6Bt8X/C/+J4hhD4BkKJEslaDNYfT3z
         33Vx1PmbLefTZzPwAS3ADkuo+5M7SuR3FKxF92ZpACudeNlweAAbINCD29ipOocqRgem
         nvvdPNZBNDxWlohpuKrzITV1Mu0pJismWFdNSQm/9I5LUlPZvo6XniVYPGBdiyi6qXHv
         l2Q2kXsXCVkj9bsuUcfTHIMrnDh7aaz9fKYxSGesnZxYUGEmCdckog6reQhReZne+9ul
         ZpBXMW9c2ZpFoYcExBtiwI6Q89u2jnO8E/yZiLflM2Cf5X0fdds2dtj2QMxzHVOHAQLP
         2iSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cXBld4jvQWVLH448Bg9FUg7ZgRA0SVT2SMQAArzp2Yk=;
        b=rvL5lkunvS54hKeF3PxH8xT2OS29zZthI05xWvw8jWG+VAXMdZWLLujdHkNrYWOUO+
         YjJV6utrLrvyLoHg8MIFKoVP+2/AAYaYay3bBS7HOypWxsIJU0E8PTr88jXCzI+zd51V
         X9j1np/X+rw5P430Z216PoyS0Ozwct36rzyiH5sOxRo2JZO+uaS4XyOcmTejzdia64Gv
         5d1OEwNkIH2o162+Di9tqqYfWKt4bVC9GeInco3JfCgGwSylV4RXyCGbycQrTrrdNyF3
         b+nkP9iCFdZ9NF8q2Tb8QbtREbmHExNDl+Jitqym7IGpBjvzAihE/BKHnBhIHJpYMStJ
         qgbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU0lIosSup4rOXtFdxlc9j0LoLOQuaAMd7xSQoTyvUiwLCvDUUa
	pBn9c6wTzOelvq/xRgqh+zM=
X-Google-Smtp-Source: APXvYqwU9ZwoG0GDQSu8JJ0wTs+qnyCJJkF7SUlqCcO1Olh+pmwqGCH39f445avWv58odV+1/LtqpA==
X-Received: by 2002:a81:a450:: with SMTP id b77mr22796262ywh.96.1575953438356;
        Mon, 09 Dec 2019 20:50:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:4709:: with SMTP id u9ls2357707ywa.4.gmail; Mon, 09 Dec
 2019 20:50:38 -0800 (PST)
X-Received: by 2002:a81:6655:: with SMTP id a82mr24206011ywc.348.1575953437918;
        Mon, 09 Dec 2019 20:50:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575953437; cv=none;
        d=google.com; s=arc-20160816;
        b=BHO8jXpF+9PkvWYifnYgpjwn0DyzH38mbQHB0iHkKCENYkGPYshBUtj8kWomwlzR4S
         auLy9Ur9MiHofmmgagvtyUAXN2jF32gsg+r8Aixt5saCIuzdGtdJRChYI9T2QZXFvch4
         H3p1NtTqiYX7aP5Z0Y+ybY+7+MoPmbskyTj2hRQq7XwBATi4cvMgn39j4NxgSv547DUa
         3Ww+AtmaSWRzjpAJ0af3rCYJYmtcH8EVqWoU+OkCiga93EnzMAOy/NL4hROh8ikskgly
         CRIRiNxaQkFIiWU0viM9SHbnYLyL4mImxfOQle9jsAzxZGOfLagpm8XFLrpzqm71VTS3
         FSyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=FsMIdfl3m8/c1WE+yOFhND7ZsJwRTVkCLazOCGjZnN8=;
        b=OCRtAOe/61wK3E+tkhtD3ucMAo5o/YgdwEWELWx3rbcYuQyOAtwLNJpX4uaBdTTVQX
         QrSqMb8W3CK83WUB9zYF1jHNxJ0EvTBRXq1d1PK7ut6bQjRmtIxLbqqJeTj/ceF6RjWd
         4+z6qpRXnhi0WBtXvym4HQruN1DtXPZy4UrpFVLMqz/WHENGKLAmfLcBEc7LyjtCV+Au
         JK8JWGLXZ22Yn4CbT8TBbe/SqIT5fXhOE4TeLM/ofEw8v/K1cfa4hHTRFZ+V0skGS2bX
         n7GTTzHIa3myVju1dHYU0ZiyhDwlgE3K1wRqNRAoI02VIMsTsmPJ3zYxM24PYxaSSFVo
         Ukhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=c2X7ViWA;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id j7si93460ybo.5.2019.12.09.20.50.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 20:50:37 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id x17so1506355pln.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 20:50:37 -0800 (PST)
X-Received: by 2002:a17:90b:941:: with SMTP id dw1mr3203291pjb.21.1575953437115;
        Mon, 09 Dec 2019 20:50:37 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-e460-0b66-7007-c654.static.ipv6.internode.on.net. [2001:44b8:1113:6700:e460:b66:7007:c654])
        by smtp.gmail.com with ESMTPSA id i127sm1250009pfe.54.2019.12.09.20.50.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Dec 2019 20:50:36 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Christophe Leroy <christophe.leroy@c-s.fr>, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/4] kasan: allow arches to provide their own early shadow setup
In-Reply-To: <023863f0-0aa5-17f5-41c9-88acfc9a786b@c-s.fr>
References: <20190806233827.16454-1-dja@axtens.net> <20190806233827.16454-2-dja@axtens.net> <023863f0-0aa5-17f5-41c9-88acfc9a786b@c-s.fr>
Date: Tue, 10 Dec 2019 15:50:33 +1100
Message-ID: <87blsgdbs6.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=c2X7ViWA;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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
>> powerpc supports several different MMUs. In particular, book3s
>> machines support both a hash-table based MMU and a radix MMU.
>> These MMUs support different numbers of entries per directory
>> level: the PTES_PER_* defines evaluate to variables, not constants.
>> This leads to complier errors as global variables must have constant
>> sizes.
>>=20
>> Allow architectures to manage their own early shadow variables so we
>> can work around this on powerpc.
>
> This seems rather strange to move the early shadow tables out of=20
> mm/kasan/init.c allthough they are used there still.
>
> What about doing for all what is already done for=20
> kasan_early_shadow_p4d[], in extenso define constant max sizes=20
> MAX_PTRS_PER_PTE, MAX_PTRS_PER_PMD and MAX_PTRS_PER_PUD ?

I have added this. I haven't tried the ifndef magic, I've just defined
the constant for all arches that implement KASAN.

Regards,
Daniel

>
> With a set of the following, it would remain transparent for other arches=
.
> #ifndef MAX_PTRS_PER_PXX
> #define MAX_PTRS_PER_PXX PTRS_PER_PXX
> #endif
>
> Then you would just need to do the following for Radix:
>
> #define MAX_PTRS_PER_PTE		(1 << RADIX_PTE_INDEX_SIZE)
> #define MAX_PTRS_PER_PMD		(1 << RADIX_PMD_INDEX_SIZE)
> #define MAX_PTRS_PER_PUD		(1 << RADIX_PUD_INDEX_SIZE)
>
>
> For the kasan_early_shadow_page[], I don't think we have variable=20
> PAGE_SIZE, have we ?
>
> Christophe
>
>
>>=20
>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>=20
>> ---
>> Changes from RFC:
>>=20
>>   - To make checkpatch happy, move ARCH_HAS_KASAN_EARLY_SHADOW from
>>     a random #define to a config option selected when building for
>>     ppc64 book3s
>> ---
>>   include/linux/kasan.h |  2 ++
>>   lib/Kconfig.kasan     |  3 +++
>>   mm/kasan/init.c       | 10 ++++++++++
>>   3 files changed, 15 insertions(+)
>>=20
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index ec81113fcee4..15933da52a3e 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -14,11 +14,13 @@ struct task_struct;
>>   #include <asm/kasan.h>
>>   #include <asm/pgtable.h>
>>  =20
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>>   extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
>>   extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
>>   extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>> +#endif
>>  =20
>>   int kasan_populate_early_shadow(const void *shadow_start,
>>   				const void *shadow_end);
>> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
>> index a320dc2e9317..0621a0129c04 100644
>> --- a/lib/Kconfig.kasan
>> +++ b/lib/Kconfig.kasan
>> @@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
>>   config	HAVE_ARCH_KASAN_VMALLOC
>>   	bool
>>  =20
>> +config ARCH_HAS_KASAN_EARLY_SHADOW
>> +	bool
>> +
>>   config CC_HAS_KASAN_GENERIC
>>   	def_bool $(cc-option, -fsanitize=3Dkernel-address)
>>  =20
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index ce45c491ebcd..7ef2b87a7988 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -31,10 +31,14 @@
>>    *   - Latter it reused it as zero shadow to cover large ranges of mem=
ory
>>    *     that allowed to access, but not handled by kasan (vmalloc/vmemm=
ap ...).
>>    */
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
>> +#endif
>>  =20
>>   #if CONFIG_PGTABLE_LEVELS > 4
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
>> +#endif
>>   static inline bool kasan_p4d_table(pgd_t pgd)
>>   {
>>   	return pgd_page(pgd) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_=
p4d));
>> @@ -46,7 +50,9 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>>   }
>>   #endif
>>   #if CONFIG_PGTABLE_LEVELS > 3
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
>> +#endif
>>   static inline bool kasan_pud_table(p4d_t p4d)
>>   {
>>   	return p4d_page(p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_=
pud));
>> @@ -58,7 +64,9 @@ static inline bool kasan_pud_table(p4d_t p4d)
>>   }
>>   #endif
>>   #if CONFIG_PGTABLE_LEVELS > 2
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
>> +#endif
>>   static inline bool kasan_pmd_table(pud_t pud)
>>   {
>>   	return pud_page(pud) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_=
pmd));
>> @@ -69,7 +77,9 @@ static inline bool kasan_pmd_table(pud_t pud)
>>   	return false;
>>   }
>>   #endif
>> +#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
>>   pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
>> +#endif
>>  =20
>>   static inline bool kasan_pte_table(pmd_t pmd)
>>   {
>>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87blsgdbs6.fsf%40dja-thinkpad.axtens.net.
