Return-Path: <kasan-dev+bncBCMIZB7QWENRBZXS52OQMGQEMW4VJUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A9732661ED6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Jan 2023 07:51:18 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id g9-20020a7bc4c9000000b003d214cffa4esf1277562wmk.5
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Jan 2023 22:51:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673247078; cv=pass;
        d=google.com; s=arc-20160816;
        b=UfDiByQ5E+g+HvuJexKSY32MsaxGNqSFlMxuAZGP0APEXYMWRD7U9vqNZGS2CQeFly
         6kwmA9zMt83+kNakftN6RDvXEEs8lvbvCJw6Z93OdkOQ4NbIJGoNzHpiB/gX6+s8OhU5
         7lmGDVp9KGP/nIRTWF0aODgvDTqwZNLJae+jOs22UTQTgEwE441/FsxrJvVzH7pn3UiJ
         xy2/q4hU4JVjWbz2SX+WvJzwqNhgJrsr29d1X6+XzUPGG+1yA+XNnNJe5ZqEk/eoI6fH
         8/EpAe1F/a8SgecwOhmgEWsFGiSR6tCUTNLLRS/vHlA1dWDUnFKQX9QfQBRVwmmf7+80
         9cVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YmiScBQZgsKU8TeE2jN+I8Tqvl2N4d+p/aaM20+zfMQ=;
        b=Ba68VRfVGicL2LdnMHoOIvlDmX6f2+tgmobp5zqZ5TWsRwLTYHUUYjRLiO2JnePfRf
         eKwacAb7zDUrxu3NjNnrUDxcafRuUVlNp5qWf1NVJSupgfM52jkwOngz0m+A8nvbrTBV
         Yan4fYhRBbd+XcdT5nlMvL3o3Hr6VlEubi4xhk44izML0e4m58hCPA+dJB6J8QFIwCh2
         auD3eKg/UQxr/Mgqeb21Wj+JwDVgf15v5+M8BJPfopq6uyfS28ZOIH3dSkLgkLzN0z5x
         OKphePFeD+HKcYfMGMzu+OBH+UyjsujWmmuoxDjheRKIsKRFmb3Tker4Eq4dRgGSGorE
         MEjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OyMUf+5B;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YmiScBQZgsKU8TeE2jN+I8Tqvl2N4d+p/aaM20+zfMQ=;
        b=OQkj2IpeYpGgX3Ved52LpwofoTlZ48OQC1kBpm1gsLBNNfJLS7Lkl7eCDYAYwEM5io
         URC0jlWfUqpMYOuvZ8Ip7ks8wC6fOI8ahD2TbFYMhoDM4Pow73o8ZasfD6DYdNRVc2Vl
         G+8az3xkrDACv96EISU7bHomLjAYkUX5h8qdGp0I0sknmu/dkpvSuGZjHruODytTy09u
         vscsLGqaFcTMGD7yTjzGBBr2hFjEMfR1WxKdHIcWIv5loI11uMNyxKrdpmuLKIqhGBB+
         NMARh14N35BFvcr5qfUyxj7Bfi0pPtoJCaA7v3GOr8elOn+jqTuI6FChu7tyEGAB7lm/
         2VAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=YmiScBQZgsKU8TeE2jN+I8Tqvl2N4d+p/aaM20+zfMQ=;
        b=7ychIlkM+yM/C8+CqU+VVgGp0dKi9Rhq0mlEJgF19sl3Zk2ETboOniDQABJR5CxQ68
         tG4fEvutOe43zlDcHcwUr8sFjwbrhNa+iCtuusiVIyy9vmGqBb73ub48pKbMeTvsO+CR
         CLdB3nzzb2y6MIv2nu5nVMTIMyyvHZ3Miw6BZv2026E9PkwvItvDclgaUBETYZ1yZPj9
         4DHYOamC6ei275LK0z8FSmTXP+c10ZD4502kBQLl1Uh1VEmURanoirPCQn4gVOUa+oTD
         PK8ojh7YEubxtYCixJxrZwb/9P4haSxN8sW+ZRGK7PEyoF74nBHybq1DXkx7zliUOElq
         poeA==
X-Gm-Message-State: AFqh2kpYJjMpraaj4lE8gbj9wLOBMXsIXKl7jhXVCZu4Ht0gx0/Mjkww
	MN3IiSbc/P2SEOvLYMsa9cA=
X-Google-Smtp-Source: AMrXdXvXfNXGv8Fkecnm6Z/lZD9JI5R3R37tBmdCm+ryei/XNW6dLsQtCq/LMQCvNLGZHE9e9hhz8w==
X-Received: by 2002:a5d:51c7:0:b0:290:3648:36aa with SMTP id n7-20020a5d51c7000000b00290364836aamr1246109wrv.213.1673247078194;
        Sun, 08 Jan 2023 22:51:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:e909:0:b0:3d9:c8dd:fd3f with SMTP id q9-20020a1ce909000000b003d9c8ddfd3fls2646230wmc.0.-pod-control-gmail;
 Sun, 08 Jan 2023 22:51:17 -0800 (PST)
X-Received: by 2002:a05:600c:3acc:b0:3d9:a145:91a with SMTP id d12-20020a05600c3acc00b003d9a145091amr24304283wms.28.1673247077164;
        Sun, 08 Jan 2023 22:51:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673247077; cv=none;
        d=google.com; s=arc-20160816;
        b=Ksukdnx9M8lYq9g02s2aAywJ0wxT2hy+XjVGrryWe0wy5BSp5UM3nk+8ymwIYAmUEr
         bSXHPbgWz1Fm1TDAvvK+LI6PLZVn9vK9cM8Yi1v2yVy8kJf6gPhsi6ieNbMtdt+jKaVa
         CnMMCG4GmMjpA1cM+KcqExNDGDuimpEi0FxK9wm6ODjcvX/miJpKfuSQrjTQNTX4o/L0
         kVAbSgUA5gpGZWW4IlmsYWHHqRqcO+cy2J1S2Eh/LZ2Tdrt4dxihNY6VApQZxRznGM1x
         a6c3hDp7lscvfiZelNT9QulRiTw7vKmcYmQY7xhCnudIs7cCCsMPB3VcDZT6EMwUuRgc
         vDMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8fHjJ5mqa9cPGpS5KD+GC/eZ7abKkX/dkmk/DvDpfNA=;
        b=dtuZBZ2TBSzIHnitr3gr8b0Z58LkK7DDTeuW3RBHEm2I3PROBxDWpfT2sk+yIpwWqe
         OAxmFv6Rl6ZtLrO++7Nphpyz5i1yu6LsZyWISnNhQtXX1Hpaw2bf2rq2mwBc15y+7IK8
         JTPW/465cTv2ZmlXG7jcXNiiP52jxEuDzusHftXnUiyCnZ1svl1Hw7QEG5aE50qpDbTK
         LlCXTfTVajjEmACwRWxaN59rbUtUu2pSM7mghpLs6/1ELL59KCt/6biV+W0LQU+VGkUt
         b7TZVpOuS5RM7qHD2uJzf9JKFM0oco6lJPKHXRZtkLsamyigy0eno9HDzse9f5WMtjA8
         bL8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OyMUf+5B;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id bw27-20020a0560001f9b00b0029c9b8d8aafsi253321wrb.6.2023.01.08.22.51.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Jan 2023 22:51:17 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id bu8so11516667lfb.4
        for <kasan-dev@googlegroups.com>; Sun, 08 Jan 2023 22:51:17 -0800 (PST)
X-Received: by 2002:a05:6512:12c4:b0:4a2:676e:cf60 with SMTP id
 p4-20020a05651212c400b004a2676ecf60mr2640163lfg.624.1673247076285; Sun, 08
 Jan 2023 22:51:16 -0800 (PST)
MIME-Version: 1.0
References: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20230103075603.12294-1-Kuan-Ying.Lee@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Jan 2023 07:51:04 +0100
Message-ID: <CACT4Y+b5hbCod=Gj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA@mail.gmail.com>
Subject: Re: [PATCH] kasan: infer the requested size by scanning shadow memory
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	chinwen.chang@mediatek.com, qun-wei.lin@mediatek.com, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=OyMUf+5B;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, 3 Jan 2023 at 08:56, 'Kuan-Ying Lee' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> We scan the shadow memory to infer the requested size instead of
> printing cache->object_size directly.
>
> This patch will fix the confusing generic kasan report like below. [1]
> Report shows "cache kmalloc-192 of size 192", but user
> actually kmalloc(184).
>
> ==================================================================
> BUG: KASAN: slab-out-of-bounds in _find_next_bit+0x143/0x160 lib/find_bit.c:109
> Read of size 8 at addr ffff8880175766b8 by task kworker/1:1/26
> ...
> The buggy address belongs to the object at ffff888017576600
>  which belongs to the cache kmalloc-192 of size 192
> The buggy address is located 184 bytes inside of
>  192-byte region [ffff888017576600, ffff8880175766c0)
> ...
> Memory state around the buggy address:
>  ffff888017576580: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
>  ffff888017576600: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >ffff888017576680: 00 00 00 00 00 00 00 fc fc fc fc fc fc fc fc fc
>                                         ^
>  ffff888017576700: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>  ffff888017576780: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> ==================================================================
>
> After this patch, report will show "cache kmalloc-192 of size 184".
>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=216457 [1]
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> ---
>  mm/kasan/kasan.h          |  5 +++++
>  mm/kasan/report.c         |  3 ++-
>  mm/kasan/report_generic.c | 18 ++++++++++++++++++
>  3 files changed, 25 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 32413f22aa82..7bb627d21580 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -340,8 +340,13 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
>
>  #ifdef CONFIG_KASAN_GENERIC
>  void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
> +int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache);
>  #else
>  static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
> +static inline int kasan_get_alloc_size(void *object_addr, struct kmem_cache *cache)
> +{
> +       return cache->object_size;
> +}
>  #endif
>
>  bool kasan_report(unsigned long addr, size_t size,
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 1d02757e90a3..6de454bb2cad 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -236,12 +236,13 @@ static void describe_object_addr(const void *addr, struct kmem_cache *cache,
>  {
>         unsigned long access_addr = (unsigned long)addr;
>         unsigned long object_addr = (unsigned long)object;
> +       int real_size = kasan_get_alloc_size((void *)object_addr, cache);
>         const char *rel_type;
>         int rel_bytes;
>
>         pr_err("The buggy address belongs to the object at %px\n"
>                " which belongs to the cache %s of size %d\n",
> -               object, cache->name, cache->object_size);
> +               object, cache->name, real_size);
>
>         if (access_addr < object_addr) {
>                 rel_type = "to the left";
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 043c94b04605..01b38e459352 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -43,6 +43,24 @@ void *kasan_find_first_bad_addr(void *addr, size_t size)
>         return p;
>  }
>
> +int kasan_get_alloc_size(void *addr, struct kmem_cache *cache)
> +{
> +       int size = 0;
> +       u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
> +
> +       while (size < cache->object_size) {
> +               if (*shadow == 0)
> +                       size += KASAN_GRANULE_SIZE;
> +               else if (*shadow >= 1 && *shadow <= KASAN_GRANULE_SIZE - 1)
> +                       size += *shadow;
> +               else
> +                       return size;
> +               shadow++;

This only works for out-of-bounds reports, but I don't see any checks
for report type. Won't this break reporting for all other report
types?

I would also print the cache name anyway. Sometimes reports are
perplexing and/or this logic may return a wrong result for some
reason. The total object size may be useful to understand harder
cases.

> +       }
> +
> +       return cache->object_size;
> +}
> +
>  static const char *get_shadow_bug_type(struct kasan_report_info *info)
>  {
>         const char *bug_type = "unknown-crash";

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb5hbCod%3DGj6oGxFrq5CaFPbz5T9A0nomzhWooiXQy5aA%40mail.gmail.com.
