Return-Path: <kasan-dev+bncBAABBLPQWLEAMGQEWLAXA2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D601C3BECC
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 16:01:11 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-594269af95fsf594745e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 07:01:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762441263; cv=pass;
        d=google.com; s=arc-20240605;
        b=TowWwU0yvouBefxGleKz4dfbzB80PRdaQ40OaWXn9Y8OScxzEfvEinP7x+Fz14eA+c
         UwRXmlX/K5nLWALoeIvUBArYseWVyT6OZ/QaA1m/YGQgEBiTZw05fjOdoZZ3kvptHVBo
         eDRhrRAEPB7wZgbCrb0dH6ZJJqUb2SWdWE+ci340lwSYY6dEs+Z4vSgGJsvsLOI+UGLd
         SG+h+HNPm+Hx+AJuRuCmsOYYoCBh1cgIf/4L/ZCziB3J67F6peXEwUxmcA9pCTixaHrw
         fURU6H5ycwVz9SHKIVkyau5htVaQkMp+Virt6Rj1Jwsnr1XQWSth5p5OGE8hVitgkjIe
         8p9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=N1g+EQW1nmZZgDlAhpqi4SeXKaCD5lQGdx8HvoYd8ig=;
        fh=Eo5XFzt/nEiTgFLTTljNZ85UaIas67aGN9flC/4eYBU=;
        b=NTgG0d5FpplsAeoacChY7e8cipdC1yFDMxXWg5aTgHQpyUdAn3L6MFDljY3th3yBkw
         N29bjkGqkrcjdr4J7ROe4W3jix6zFJc/1zTnQplF2BMeAKJ5FquXImrV8tu9D58tZzwX
         6qnXZpsUDrZvA1SK/JwTHasmSRh+PuoFbeoza136ANiLKRmpZleD8pUDfbY28F23YCDX
         R581vsdsbfuM/YDV9skDt36A6sdQQpq56b2lKLX0o65bgaCVjLDj/zjsfv1vo1lDj9nk
         44VejQdEuzIb0xnMQ7A2MYS7lwUdN7CzfrJyM0lTp3EM8Fe/GDR/6WPdquTsYWkSrSsT
         AlJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GDYgoEl4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762441263; x=1763046063; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=N1g+EQW1nmZZgDlAhpqi4SeXKaCD5lQGdx8HvoYd8ig=;
        b=Ae40RJZ/90VncQuuMXQjy+HaeUEL53RbUmJ4TvE1pyZSRdEL0OzWa5SjwKGCqvrBPi
         vaCPuxhkjTg2HyC1ZhMFLNGzKfStYgP5OZRttCYykHQN5sYGYGyrONL9FG5QxVYcrgW/
         uWPcJ77dhgjQ5XbVpUKmQvQP9L6j7M1kszH5sO9W4+lqXcPvL3GilzrGo9yYqUyXn42L
         M6/SyUm22679Pm1j1pDJrR6/sFrtoM9xBl2JFTlbcZg+3ktj3Zgpwc7GunZQQiVRgDVr
         EZBgxYoFTLjegLV3+HSQBBqndU/Kls2NJ3wwl7S1qZqDL9wCKfiel4+Y9BMTLpjjiuDu
         3vyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762441263; x=1763046063;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=N1g+EQW1nmZZgDlAhpqi4SeXKaCD5lQGdx8HvoYd8ig=;
        b=oi4kJcDiFZ0SAhENOxR8CH9752VJPyk8TM4i3FymFuMf/QnfWkd/EYtHg++SfumtOH
         NJsiXqm3QcahefrWlZr5NnHlGeWFaxapNnbwc0bW2sMkphlTW6z0+7R03xDAlx6E/aqg
         7o1nYeztzzEnhxponYrtvJ9/U6wbdWBoO5KM1HJegEG7zOdad2kpAr6tPJQ2fS0MDdHL
         TsMexJby2PPnviSH4CqCdLjvr3bCN9T9db4OxYYmca5bMI7112PB6uDnrqGN4DHMPv4F
         RsCWxR5+apO8+YONzkNH32Lez7z+X4XumlYNGoh0KVIuRFUNClgGBhy2B4MoZDaBnGOQ
         6L/w==
X-Forwarded-Encrypted: i=2; AJvYcCW+qzU4Fz+xOE9OSu8qcXMoBfZVBZm3QZzTNpSor6k2CxwDeDL0cOCXyHydiOSju/2J123bww==@lfdr.de
X-Gm-Message-State: AOJu0Yy+J5fedsn7ckwARqp5r4nK4b4LDgKoKOyMUo+BD3WWECRPap87
	U0BnMabekFml3g/o9XnEOUVCLVjpyAs5iNQlJWktHy93cz2FdOxlHLxt
X-Google-Smtp-Source: AGHT+IEJEUuSPYcsDkFeWOAc1D3JnOxpZ+H7u70Uxw77jkK113Zg4PPqffAGMR2nO6tTR5ULm14X0g==
X-Received: by 2002:ac2:4e04:0:b0:591:c53f:3b6f with SMTP id 2adb3069b0e04-5943d7ed978mr2530790e87.52.1762441262537;
        Thu, 06 Nov 2025 07:01:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZgZhBnfopzw+4lVPnOUCLii3/r475ELEnxNRR1upZoDw=="
Received: by 2002:ac2:4f0d:0:b0:594:5147:a114 with SMTP id 2adb3069b0e04-5945147a156ls185933e87.2.-pod-prod-04-eu;
 Thu, 06 Nov 2025 07:01:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUcv6BC8fJAyDFievJobntzbg9MRqqHJGGQXQCjXuCr3iPbDFK/VNkP/7A5VWtYn9CvtNwCUFIT+Ts=@googlegroups.com
X-Received: by 2002:a05:6512:3b8c:b0:594:4ff1:52e8 with SMTP id 2adb3069b0e04-5944ff155a5mr724513e87.0.1762441260086;
        Thu, 06 Nov 2025 07:01:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762441260; cv=none;
        d=google.com; s=arc-20240605;
        b=YDJzWOzxfh6oqgFz/eqAmo9zWxRCEMjzuiuqzhL6Me2s6m0AW6v2VdQw5gJaMhEvR6
         nRz8f9mjkQEepbjmOmc5wTX6DpCPdLjJrswm3WHY39hnTh4EetR/0KhGZR94R0Y8IpTu
         8KPdsyIfQp8KDJvO1NDhKvXIPpcriTcI4/As7mup5su0/GsVRJELj/YibcSdlR0ienZc
         p37dPkccA64xlkcAnGcxz8W2xOa8soThZWmSG2AoA9WfYl5oJRtdfP1MuQHRw6nF3FP0
         uS/rbU50uI7s2MXmhEXzGCTiU6I7Fmw5CCukyInKesmUCmnfYKbfNpNuBbNvgco9ga0+
         JBaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=N20bsF88qmtxzuIu4gZ0s1r8sTe/QYH+2BKK9mK/6ww=;
        fh=GJOhrM8NJ0+eLmup2Enjs35t7rpDm4758X8H6iBgpj4=;
        b=iiOqnt8vuMwerRf+Qzw03MlEAgFCt5D2qpPj5zDOYGOhXUBRVBSvQ+7NqdAH3yr0OW
         5Tr9aGWP90c1/LpSFpHN+F+a/CumLLhdXCXl86NkWOvnvGyVzYBUQ9pEtVBzx+5yYsDr
         Fw8k8DpW2PkHO/qL13SYtlgopwFajPVTNDtz2p6xvrPAlph2Um2/kXlU3uf/nol+fppA
         S9SOYL9UbEcaL9zzLfNjNq5E9lPZ6txvcS00Qn6EnCfX8zqs3e7kyniryaSKxKKNTOxR
         dBlq0jchd8haCa2REZC05D6DuKitRd/1VgL1CzEKRVGTlIeEbA401YhUND7L27tCBYK/
         qt6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=GDYgoEl4;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5944a0635aesi56175e87.4.2025.11.06.07.01.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 06 Nov 2025 07:01:00 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Thu, 06 Nov 2025 15:00:48 +0000
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, Baoquan He <bhe@redhat.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v1 1/2] kasan: Unpoison pcpu chunks with base address tag
Message-ID: <v75jgljobtrc6d7plw2x5caloipqkclfhh6w3quylarqrzczkk@5blzaptwme4l>
In-Reply-To: <00818656-41d0-4ebd-8a82-ad6922586ac4@lucifer.local>
References: <cover.1762267022.git.m.wieczorretman@pm.me> <821677dd824d003cc5b7a77891db4723e23518ea.1762267022.git.m.wieczorretman@pm.me> <00818656-41d0-4ebd-8a82-ad6922586ac4@lucifer.local>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 321924270825e08940ed773dce8975504f8a0244
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=GDYgoEl4;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

As Andrey noticed I'll have to rework this function to be a proper
refactor of the previous thing.

This solution seems okay, after noticing the issue I was thinking about
adding a new file for vmalloc code that is shared between different
KASAN modes. But I'll have to add different mode code in here too
anyway. So it's probably okay to keep this function behind the ifdef, I
see shadow.c and hw-tags.c doing something similar too.

On 2025-11-05 at 22:00:41 +0000, Lorenzo Stoakes wrote:
>Hi,
>
>This patch is breaking the build for mm-new with KASAN enabled:
>
>mm/kasan/common.c:587:6: error: no previous prototype for =E2=80=98__kasan=
_unpoison_vmap_areas=E2=80=99 [-Werror=3Dmissing-prototypes]
>  587 | void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vm=
s)
>
>Looks to be because CONFIG_KASAN_VMALLOC is not set in my configuration, s=
o you
>probably need to do:
>
>#ifdef CONFIG_KASAN_VMALLOC
>void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>{
>	int area;
>
>	for (area =3D 0 ; area < nr_vms ; area++) {
>		kasan_poison(vms[area]->addr, vms[area]->size,
>			     arch_kasan_get_tag(vms[area]->addr), false);
>	}
>}
>#endif
>
>That fixes the build for me.
>
>Andrew - can we maybe apply this just to fix the build as a work around un=
til
>Maciej has a chance to see if he agrees with this fix?
>
>Thanks, Lorenzo
>
>On Tue, Nov 04, 2025 at 02:49:08PM +0000, Maciej Wieczor-Retman wrote:
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> A KASAN tag mismatch, possibly causing a kernel panic, can be observed
>> on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
>> It was reported on arm64 and reproduced on x86. It can be explained in
>> the following points:
>>
>> 	1. There can be more than one virtual memory chunk.
>> 	2. Chunk's base address has a tag.
>> 	3. The base address points at the first chunk and thus inherits
>> 	   the tag of the first chunk.
>> 	4. The subsequent chunks will be accessed with the tag from the
>> 	   first chunk.
>> 	5. Thus, the subsequent chunks need to have their tag set to
>> 	   match that of the first chunk.
>>
>> Refactor code by moving it into a helper in preparation for the actual
>> fix.
>>
>> Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
>> Cc: <stable@vger.kernel.org> # 6.1+
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> Tested-by: Baoquan He <bhe@redhat.com>
>> ---
>> Changelog v1 (after splitting of from the KASAN series):
>> - Rewrite first paragraph of the patch message to point at the user
>>   impact of the issue.
>> - Move helper to common.c so it can be compiled in all KASAN modes.
>>
>>  include/linux/kasan.h | 10 ++++++++++
>>  mm/kasan/common.c     | 11 +++++++++++
>>  mm/vmalloc.c          |  4 +---
>>  3 files changed, 22 insertions(+), 3 deletions(-)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index d12e1a5f5a9a..b00849ea8ffd 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -614,6 +614,13 @@ static __always_inline void kasan_poison_vmalloc(co=
nst void *start,
>>  		__kasan_poison_vmalloc(start, size);
>>  }
>>
>> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms);
>> +static __always_inline void kasan_unpoison_vmap_areas(struct vm_struct =
**vms, int nr_vms)
>> +{
>> +	if (kasan_enabled())
>> +		__kasan_unpoison_vmap_areas(vms, nr_vms);
>> +}
>> +
>>  #else /* CONFIG_KASAN_VMALLOC */
>>
>>  static inline void kasan_populate_early_vm_area_shadow(void *start,
>> @@ -638,6 +645,9 @@ static inline void *kasan_unpoison_vmalloc(const voi=
d *start,
>>  static inline void kasan_poison_vmalloc(const void *start, unsigned lon=
g size)
>>  { }
>>
>> +static inline void kasan_unpoison_vmap_areas(struct vm_struct **vms, in=
t nr_vms)
>> +{ }
>> +
>>  #endif /* CONFIG_KASAN_VMALLOC */
>>
>>  #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) &&=
 \
>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index d4c14359feaf..c63544a98c24 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -28,6 +28,7 @@
>>  #include <linux/string.h>
>>  #include <linux/types.h>
>>  #include <linux/bug.h>
>> +#include <linux/vmalloc.h>
>>
>>  #include "kasan.h"
>>  #include "../slab.h"
>> @@ -582,3 +583,13 @@ bool __kasan_check_byte(const void *address, unsign=
ed long ip)
>>  	}
>>  	return true;
>>  }
>> +
>> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>> +{
>> +	int area;
>> +
>> +	for (area =3D 0 ; area < nr_vms ; area++) {
>> +		kasan_poison(vms[area]->addr, vms[area]->size,
>> +			     arch_kasan_get_tag(vms[area]->addr), false);
>> +	}
>> +}
>> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
>> index 798b2ed21e46..934c8bfbcebf 100644
>> --- a/mm/vmalloc.c
>> +++ b/mm/vmalloc.c
>> @@ -4870,9 +4870,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigne=
d long *offsets,
>>  	 * With hardware tag-based KASAN, marking is skipped for
>>  	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
>>  	 */
>> -	for (area =3D 0; area < nr_vms; area++)
>> -		vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->addr,
>> -				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
>> +	kasan_unpoison_vmap_areas(vms, nr_vms);
>>
>>  	kfree(vas);
>>  	return vms;
>> --
>> 2.51.0
>>
>>
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/v=
75jgljobtrc6d7plw2x5caloipqkclfhh6w3quylarqrzczkk%405blzaptwme4l.
