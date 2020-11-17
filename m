Return-Path: <kasan-dev+bncBCMIZB7QWENRB4GYZ36QKGQEGJMMCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FDCB2B5D5C
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 11:56:50 +0100 (CET)
Received: by mail-io1-xd40.google.com with SMTP id o3sf12853385iou.10
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Nov 2020 02:56:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605610609; cv=pass;
        d=google.com; s=arc-20160816;
        b=KXUpqHSR0TAXfZ8Z1zPfASZjXpAe0q1mZokojv/AwTToJKfV1qAa3hiqUYVsqoyZE6
         +HmBjU2rWh0l9KW6mqJYrdDEFX5j47BZMmmZ367TSyFKQffskTU00cKUjxY/PBKk1Bxz
         slhsg5MHskOlVplGhzh0Ygr6/aW2QlYYohgeiOZDoBYfGnsEnVP+zEucLZ8pJQLmCdg0
         nb4bVj+qkJpFUk1vXb6H54cnTqnThzp5EiTM8hGCl3LLPn6TCFLk90QHN+NxyyCKXFPO
         4uvvyxxO1/FSGucXI4rdamH168cojdKfM/mXJX8XgWlv1vuGBSHZN0/8HD/HJnvSQEVV
         lMfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YYDvbi0XXPBDaLoM16PlZL/186r0woOk27DBWJdH07k=;
        b=lxeLR/FidatvR830U7NpvP9+wHI7HFATZFdZ9PX9k+YSb/oW953hp0IUK7DbvQbEdk
         eOntLkSK1A9yTrRcQP4keCmw906gYMO0vHopqiPnbXV6RE8Ivz2dvGtQKw7gOL+f8HqO
         PgHQ97mwYOiZ8Oo4whrgTRo+uKhpi4y+qGvSzYGhlUfar8xFaRuIs5BvMnkRiFxGrDhR
         OrOyIKDTan4tfhyixJHq8ZcVbFifMnHXdpkAHgJ+Yw2wa3a+9PAiwHf9xyleLGURB+1/
         DHxTnrWv+Jpi1yUgk1422CbHO0axuypm1oqJ+PY9aCAhOlja5cIN0X0wAGNB58SJMkIH
         ylPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/pl5jqI";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YYDvbi0XXPBDaLoM16PlZL/186r0woOk27DBWJdH07k=;
        b=XcvBVluTS6LytHPSQneagENmiNaviDeiBoq1GvbdKNstT5u5ts59rSTKX8KF9/hhWJ
         Hc2+dTvJ6OmUjpDEaQCuhkz1oXP2HEZO6NdkE2r0tsdtFvwSLUpAO2aPns7+qzS9wjRw
         qTrLkimp+Ml4+gRibi8yCXJKUOqOF2nht2tqd6Zg6wvf0kJpI90+egCsIu/jPKp0SJaj
         xpiJrYrpkwUFd42bHdYMeLBFjazt4/3fmDua3MKlcCQTeJXWkxOyvyFr9DM3q43jIDLg
         wkkE84rhYWZ0jfFg6gbCbemhMNw3RT514QX4qQDYjHnxd+yi+lznt0S9cUxcxdh+ADfg
         FOQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YYDvbi0XXPBDaLoM16PlZL/186r0woOk27DBWJdH07k=;
        b=SxwVU0IndPVDb/1Fhq14CZ55/8VHiOmnlIHeoSkoJK73Yy3FXRnbKX2DDX3gvywf6G
         Dc4TWS6r+ADI61baJ1JB6pPzwc+CVuOSPP2URSfEAejBhbtuMOusTHKTgHO6VTSoxLPX
         NyOaQKbdHzi6IbGMxHNnK3yXhJUMHQk705Pj8yrnccSp7t4YeCmQ3ysZv2hUw0iS8gMl
         1aeCREhz83YFiFQwcZ0jqMz1uDTOCCX9uLXX2Je4si0PZN6Z0lta7+r56yxfbj9u3wBn
         lZMgtjQgbGQX3d65sFrutyoCIWdDeOgUyKiu/DiYh5ZoCs4VgpcPKFzeqI5/D0Tfx1L/
         2hxg==
X-Gm-Message-State: AOAM530T6jT7061XdRQ/kDYITuFu6cb1PvaKz3d3DUw277omNm9QH6VN
	EgsebyL1nB+OdVJhqqbTVhY=
X-Google-Smtp-Source: ABdhPJw8CzUUJPDfuL0RCv8c9ZZfo+xt00MSv2pfXhTjYZXkCUi6xGrkg2lOurhT6sJ6VEO/JwR6HA==
X-Received: by 2002:a05:6e02:ec2:: with SMTP id i2mr11255017ilk.209.1605610609044;
        Tue, 17 Nov 2020 02:56:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:700f:: with SMTP id l15ls2503836ioc.9.gmail; Tue, 17 Nov
 2020 02:56:48 -0800 (PST)
X-Received: by 2002:a6b:5809:: with SMTP id m9mr11001361iob.186.1605610608600;
        Tue, 17 Nov 2020 02:56:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605610608; cv=none;
        d=google.com; s=arc-20160816;
        b=O75PvRODPZKo5kTWddEzRzpb9I0F7yGyB6Etzo4P39A78+4dqLrzxTGQooh5/pu6r/
         wt/M4jjqKdA23biN7wa7fStuwA2J7f4QoE1DIU9Bw8s3QJFehx12nZreWQp66UK1+9k4
         ovSD+QCy8C6Ou6f3SIryqUOQVGNPtcHrUjN4D+G/jZFYqLqd/xI+gduP9jabDU2IATYV
         7FKpawxvUbupBNZD875zY+YVhAmVRcAi+FYr5QIzMr2z+vqJ9WUbKQAZ8nN2auaYQCIL
         ZoAZGfceZdKkuOxtGFe9y/uCki7WlzoHKlymcOZfjKeyiZhza/yzr2XTwrLEiL1kUkRK
         Et9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6ELfOh3o2Oz00GU28PxWEqBY//Oi7TOLxsG1nguiQlU=;
        b=zceLiSX/r2e96lhBTCPDfILiEgj6k7cyS5lO+FIgZncacgtf2zUn1m6zgqa6Ze42UU
         vx3r79Jwxt8Ar0EjPvClgoKDitnSlK+U7X1PLs++upndBOrtRb6kzuGajdC67lXy/vjD
         9pqg553U59OG7AYh7VtGmAQfzAfinpavbXo0mbG9GE3KuYPHtC1O6Gr7ekxAFhRFhHjJ
         oWbX/Phqh0VBuY3OppT/4oCGioebVdZfwywf/zKCesR8WJe8cCahJeawUwdki/tBkNkt
         7wfhYszhZsBk/sKYlMeEuWqzTWUVr6p8IUoALOeT24oSNQKvQ59Duz4RH82MseXiEvZP
         4uMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/pl5jqI";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id y11si644037ily.1.2020.11.17.02.56.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Nov 2020 02:56:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id u23so2923129qvf.1
        for <kasan-dev@googlegroups.com>; Tue, 17 Nov 2020 02:56:48 -0800 (PST)
X-Received: by 2002:a05:6214:20a3:: with SMTP id 3mr253140qvd.13.1605610607646;
 Tue, 17 Nov 2020 02:56:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com> <4c2a23ccb3572459da7585a776d2d45f6e8b8580.1605305978.git.andreyknvl@google.com>
In-Reply-To: <4c2a23ccb3572459da7585a776d2d45f6e8b8580.1605305978.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 17 Nov 2020 11:56:36 +0100
Message-ID: <CACT4Y+a8DFk_CqAV0JWSG57D-gQkSgEERYaHQwZAcPNUtZDvdQ@mail.gmail.com>
Subject: Re: [PATCH mm v3 07/19] kasan: inline kasan_reset_tag for tag-based modes
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="V/pl5jqI";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Fri, Nov 13, 2020 at 11:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Using kasan_reset_tag() currently results in a function call. As it's
> called quite often from the allocator code, this leads to a noticeable
> slowdown. Move it to include/linux/kasan.h and turn it into a static
> inline function. Also remove the now unneeded reset_tag() internal KASAN
> macro and use kasan_reset_tag() instead.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
> ---
>  include/linux/kasan.h     | 5 ++++-
>  mm/kasan/common.c         | 6 +++---
>  mm/kasan/hw_tags.c        | 9 ++-------
>  mm/kasan/kasan.h          | 4 ----
>  mm/kasan/report.c         | 4 ++--
>  mm/kasan/report_hw_tags.c | 2 +-
>  mm/kasan/report_sw_tags.c | 4 ++--
>  mm/kasan/shadow.c         | 4 ++--
>  mm/kasan/sw_tags.c        | 9 ++-------
>  9 files changed, 18 insertions(+), 29 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f2109bf0c5f9..1594177f86bb 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -193,7 +193,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
> -void *kasan_reset_tag(const void *addr);
> +static inline void *kasan_reset_tag(const void *addr)
> +{
> +       return (void *)arch_kasan_reset_tag(addr);
> +}
>
>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index fabd843eff3d..1ac4f435c679 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -180,14 +180,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
>                                               const void *object)
>  {
> -       return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
> +       return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
>  }
>
>  struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>                                             const void *object)
>  {
>         BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
> -       return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
> +       return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>
>  void kasan_poison_slab(struct page *page)
> @@ -284,7 +284,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>
>         tag = get_tag(object);
>         tagged_object = object;
> -       object = reset_tag(object);
> +       object = kasan_reset_tag(object);
>
>         if (is_kfence_address(object))
>                 return false;
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 68e77363e58b..a34476764f1d 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -31,18 +31,13 @@ void __init kasan_init_hw_tags(void)
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> -void *kasan_reset_tag(const void *addr)
> -{
> -       return reset_tag(addr);
> -}
> -
>  void poison_range(const void *address, size_t size, u8 value)
>  {
>         /* Skip KFENCE memory if called explicitly outside of sl*b. */
>         if (is_kfence_address(address))
>                 return;
>
> -       hw_set_mem_tag_range(reset_tag(address),
> +       hw_set_mem_tag_range(kasan_reset_tag(address),
>                         round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>
> @@ -52,7 +47,7 @@ void unpoison_range(const void *address, size_t size)
>         if (is_kfence_address(address))
>                 return;
>
> -       hw_set_mem_tag_range(reset_tag(address),
> +       hw_set_mem_tag_range(kasan_reset_tag(address),
>                         round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
>  }
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 0eab7e4cecb8..5e8cd2080369 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -248,15 +248,11 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>         return addr;
>  }
>  #endif
> -#ifndef arch_kasan_reset_tag
> -#define arch_kasan_reset_tag(addr)     ((void *)(addr))
> -#endif
>  #ifndef arch_kasan_get_tag
>  #define arch_kasan_get_tag(addr)       0
>  #endif
>
>  #define set_tag(addr, tag)     ((void *)arch_kasan_set_tag((addr), (tag)))
> -#define reset_tag(addr)                ((void *)arch_kasan_reset_tag(addr))
>  #define get_tag(addr)          arch_kasan_get_tag(addr)
>
>  #ifdef CONFIG_KASAN_HW_TAGS
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index df16bef0d810..76a0e3ae2049 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -328,7 +328,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>         unsigned long flags;
>         u8 tag = get_tag(object);
>
> -       object = reset_tag(object);
> +       object = kasan_reset_tag(object);
>
>  #if IS_ENABLED(CONFIG_KUNIT)
>         if (current->kunit_test)
> @@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>         disable_trace_on_warning();
>
>         tagged_addr = (void *)addr;
> -       untagged_addr = reset_tag(tagged_addr);
> +       untagged_addr = kasan_reset_tag(tagged_addr);
>
>         info.access_addr = tagged_addr;
>         if (addr_has_metadata(untagged_addr))
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index da543eb832cd..57114f0e14d1 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -22,7 +22,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>
>  void *find_first_bad_addr(void *addr, size_t size)
>  {
> -       return reset_tag(addr);
> +       return kasan_reset_tag(addr);
>  }
>
>  void metadata_fetch_row(char *buffer, void *row)
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 317100fd95b9..7604b46239d4 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -41,7 +41,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>         int i;
>
>         tag = get_tag(info->access_addr);
> -       addr = reset_tag(info->access_addr);
> +       addr = kasan_reset_tag(info->access_addr);
>         page = kasan_addr_to_page(addr);
>         if (page && PageSlab(page)) {
>                 cache = page->slab_cache;
> @@ -72,7 +72,7 @@ const char *get_bug_type(struct kasan_access_info *info)
>  void *find_first_bad_addr(void *addr, size_t size)
>  {
>         u8 tag = get_tag(addr);
> -       void *p = reset_tag(addr);
> +       void *p = kasan_reset_tag(addr);
>         void *end = p + size;
>
>         while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index d8a122f887a0..37153bd1c126 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -82,7 +82,7 @@ void poison_range(const void *address, size_t size, u8 value)
>          * some of the callers (e.g. kasan_poison_object_data) pass tagged
>          * addresses to this function.
>          */
> -       address = reset_tag(address);
> +       address = kasan_reset_tag(address);
>
>         /* Skip KFENCE memory if called explicitly outside of sl*b. */
>         if (is_kfence_address(address))
> @@ -103,7 +103,7 @@ void unpoison_range(const void *address, size_t size)
>          * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
>          * addresses to this function.
>          */
> -       address = reset_tag(address);
> +       address = kasan_reset_tag(address);
>
>         /*
>          * Skip KFENCE memory if called explicitly outside of sl*b. Also note
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 6d7648cc3b98..e17de2619bbf 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -67,11 +67,6 @@ u8 random_tag(void)
>         return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>
> -void *kasan_reset_tag(const void *addr)
> -{
> -       return reset_tag(addr);
> -}
> -
>  bool check_memory_region(unsigned long addr, size_t size, bool write,
>                                 unsigned long ret_ip)
>  {
> @@ -107,7 +102,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>         if (tag == KASAN_TAG_KERNEL)
>                 return true;
>
> -       untagged_addr = reset_tag((const void *)addr);
> +       untagged_addr = kasan_reset_tag((const void *)addr);
>         if (unlikely(untagged_addr <
>                         kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
>                 return !kasan_report(addr, size, write, ret_ip);
> @@ -126,7 +121,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>  bool check_invalid_free(void *addr)
>  {
>         u8 tag = get_tag(addr);
> -       u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
> +       u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
>
>         return (shadow_byte == KASAN_TAG_INVALID) ||
>                 (tag != KASAN_TAG_KERNEL && tag != shadow_byte);
> --
> 2.29.2.299.gdc1121823c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba8DFk_CqAV0JWSG57D-gQkSgEERYaHQwZAcPNUtZDvdQ%40mail.gmail.com.
