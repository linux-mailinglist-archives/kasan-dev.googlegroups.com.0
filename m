Return-Path: <kasan-dev+bncBCMIZB7QWENRBUFP4X6AKGQEO2UYJ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id C5E7329CFBA
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 12:36:49 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id t13sf2848064qvm.14
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 04:36:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603885009; cv=pass;
        d=google.com; s=arc-20160816;
        b=KJJBWI+yiEr8M/OvJXDTE6IvR+XNNycGWYdMcJ4bIzCV1gJ6CViJTXnu18RvAWSlhA
         0w9iztsHVW+yLlDXWwP3RVbmFfLpoUsK4umZy7bw1n98xXFrRyxQzPB2mfA4VMT74QDq
         VD1ho4cHz1Z78EAems8L59305P1qlxCtnTwaYrqXFzou6aucEV7Lu53abu/AeD3dJiF5
         kXARXF9t7UrhrrZ2uL3uN/JfZL3pvrVoZSmaEs8Zn1Ae8xqWNHMvnSmoV36aHue/sTAJ
         ra7l7aiNP0ShkEG2ZQKvoeEWKPt7mR7CEzhlOPSgxgSHMhIDhTsLqw8GP0uZG1enxF9b
         XeVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=kCz7CxUzYaztvZEieVHjzFkOplSwZPEKafNDKqFRlOI=;
        b=uVK/ONnIOLKebHKNL799wd7Xb4+NMLJ9dhbgMOfexjhzSJybGRjbe4T+rib2pomE94
         Dc8I1+XHMWUcsEMm6vXGZ+09kNsWt7D1xMinOWFjg8o73qioXlZaifyMlQx9WZ7y/Kwp
         OLGk9emFT0VJxaMfpC/XNCVCyEv3U25fje6uPLRmfEFH37wt7c//SglgcHbGrkhZ9o7L
         uYhBnDVrwomnwk8r/xhfzg8EzcxV5Zv+Tli4HQdoqtIYDXFi2VPWqBm/ujySHnrpJK3C
         Fec1vDq2304F8SQ8AA6yjWVsHgmRr6XLwIe5oKQRHgUETXo6wyXycSIbQrFRJ/afESIW
         ItBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVxi4Qml;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kCz7CxUzYaztvZEieVHjzFkOplSwZPEKafNDKqFRlOI=;
        b=FmNZZxQmGZB+ewSWrShbBxp62O2IsUyZaVOesoTCdXZjpCMl/rFskAKUuZ4wJd1CXw
         tD9n/WUYBkuTJdg3oE2XKJR++51Iad+D3OEN3oHa6lGppRtCrqVShMyJeht2QQUKdCHI
         O0xuu6dZTU7dTooxg8ZZ6+JXoK3tjSdI0x71I+iet/KO0FNInutyu9zf8YBDdhTi4H6E
         HKZ+NhSXDi8vbiiHKYQ6LLrsLG/oAAH0LcxSjOYQ2ZQGSHEQnzRkzZCsBjI5G1HMbu2K
         D5PKMvf5dxYaFtgvr7NHkXbPF70F1OlTQkjpf+8ELBW5t/Llxy4SubMNpxrq7/VhqPdb
         OI1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kCz7CxUzYaztvZEieVHjzFkOplSwZPEKafNDKqFRlOI=;
        b=iyElPNPDBglQ9mCR0sJNklUcZenthxgCbo848YTsprxE0sp7o5+KFVcHnoTX5Foayz
         PrYTZpwgzOU9TZp6ifp7mn+nrV4ciXHtlyOsvhLePqNAz0+pvP0aLmOGPTJAUs3dm9py
         1KPKJu0X3UOG3mYHONdqemgKzF2+dQXdqNP5oay9TWHiFIWXSXM6neleNWozJQAeEIpL
         0l5pQZuWX5rF7cdxwbRtBzPQiH4yUTijYF/ppmheVSmrVPbOjRKGr91R9rNPwkaDvoEl
         5Kg8e3sPgkmcEqoql/eTgwhuNsbfGHafmUkckchoiQOnGxNzCt9+BvsLSvB8dBdB/DBU
         g0UA==
X-Gm-Message-State: AOAM531ReRZgTYGhNPfdVSQf4YEIq5/fGBiusCVDUuntg/hi/hhWHKZn
	HtPGggZogtFMm6LRKq7fn4E=
X-Google-Smtp-Source: ABdhPJxbwluAu/6tmwg5bmf600EAQ4gr5rHq3fW/uLJReNgj5/Zq+CRVRC4//H8UEouDgAFDZ71kiw==
X-Received: by 2002:ac8:2638:: with SMTP id u53mr6511264qtu.288.1603885008787;
        Wed, 28 Oct 2020 04:36:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:31a7:: with SMTP id 36ls1770408qth.8.gmail; Wed, 28 Oct
 2020 04:36:48 -0700 (PDT)
X-Received: by 2002:aed:23f1:: with SMTP id k46mr6707824qtc.377.1603885008344;
        Wed, 28 Oct 2020 04:36:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603885008; cv=none;
        d=google.com; s=arc-20160816;
        b=PuJt+uBFy0RylcI8ahOW3PIt8HX3/4lCr2T3CzxJ74ufyncqMHw48e0YV71qvoCmuM
         uxRzzPhTDG3bNZKD+f/Y2w+nRD1CAejD4Rjz/nLTYGpi38cipaRWs0NISjiSNCwOnan1
         YFusuE1trwW8tWrBh871j5DXUpMw4D1tgcq1/cniHw9df3mi9vKF+cukLMNR3MaGcyDM
         6Qm7PNTxFJQp4JRU1O9Si/pakHdNY8xJRSyD1/ONsVWq5+NHwDcpcLao1Vy6W/zOe9b9
         QzpqXVFHPwCxwy3NwHknJJhHEK3rCVfbsrjnJI7RcTOIOht+zFPYQ6TOF6j3IRelNlpO
         3bzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xtWeH9vKHS87nYy3SpCk02misk39ek51FjthjBeLR7U=;
        b=f31S3Ygs20KsWPRzF02GHA4X21NjR3iFRS8IfMy4wa73tIA83J6AE8cqjBLzPYKQsM
         7xBV5CZZYtYWpqp+gAyHO65+TwMHDcexOMSgTZnJqVDwz/9OUYIf0Ses/0UHLR2AVvw5
         920U3vnf330OYd6ACttkxDWwKyaik+zUyKroKp7DbLYWewvH8HbQ2vpZJ0H3ac72D2tZ
         thypV1shfkn8yepWiiTAzIy6jh2fLgECAwdmQMNgVUuj+mBVPwXFQb6aJqeknoigt71i
         SaYW0fJ302GlsDnxrGtZv14TA50TgSCofteX+6DZNB97LQ6xTpq3DHrbICQhDLUYLnFX
         sAnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVxi4Qml;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id 70si250546qkm.2.2020.10.28.04.36.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 04:36:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id m14so3219194qtc.12
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 04:36:48 -0700 (PDT)
X-Received: by 2002:ac8:44ae:: with SMTP id a14mr6754128qto.67.1603885007705;
 Wed, 28 Oct 2020 04:36:47 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 12:36:36 +0100
Message-ID: <CACT4Y+bJxJ+EeStyytnnRyjRwoZNPGJ9ws20GfoCBFGWvUSBPg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 12/21] kasan: inline and rename kasan_unpoison_memory
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nVxi4Qml;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently kasan_unpoison_memory() is used as both an external annotation
> and as internal memory poisoning helper. Rename external annotation to
> kasan_unpoison_data() and inline the internal helper for for hardware
> tag-based mode to avoid undeeded function calls.
>
> There's the external annotation kasan_unpoison_slab() that is currently
> defined as static inline and uses kasan_unpoison_memory(). With this
> change it's turned into a function call. Overall, this results in the
> same number of calls for hardware tag-based mode as
> kasan_unpoison_memory() is now inlined.

Can't we leave kasan_unpoison_slab as is? Or there are other reasons
to uninline it?
It seems that uninling it is orthogonal to the rest of this patch.

> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
> ---
>  include/linux/kasan.h | 16 ++++++----------
>  kernel/fork.c         |  2 +-
>  mm/kasan/common.c     | 10 ++++++++++
>  mm/kasan/hw_tags.c    |  6 ------
>  mm/kasan/kasan.h      |  7 +++++++
>  mm/slab_common.c      |  2 +-
>  6 files changed, 25 insertions(+), 18 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 6377d7d3a951..2b9023224474 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -66,14 +66,15 @@ static inline void kasan_disable_current(void) {}
>
>  #ifdef CONFIG_KASAN
>
> -void kasan_unpoison_memory(const void *address, size_t size);
> -
>  void kasan_alloc_pages(struct page *page, unsigned int order);
>  void kasan_free_pages(struct page *page, unsigned int order);
>
>  void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         slab_flags_t *flags);
>
> +void kasan_unpoison_data(const void *address, size_t size);
> +void kasan_unpoison_slab(const void *ptr);
> +
>  void kasan_poison_slab(struct page *page);
>  void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
>  void kasan_poison_object_data(struct kmem_cache *cache, void *object);
> @@ -98,11 +99,6 @@ struct kasan_cache {
>         int free_meta_offset;
>  };
>
> -size_t __ksize(const void *);
> -static inline void kasan_unpoison_slab(const void *ptr)
> -{
> -       kasan_unpoison_memory(ptr, __ksize(ptr));
> -}
>  size_t kasan_metadata_size(struct kmem_cache *cache);
>
>  bool kasan_save_enable_multi_shot(void);
> @@ -110,8 +106,6 @@ void kasan_restore_multi_shot(bool enabled);
>
>  #else /* CONFIG_KASAN */
>
> -static inline void kasan_unpoison_memory(const void *address, size_t size) {}
> -
>  static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
>  static inline void kasan_free_pages(struct page *page, unsigned int order) {}
>
> @@ -119,6 +113,9 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
>                                       unsigned int *size,
>                                       slab_flags_t *flags) {}
>
> +static inline void kasan_unpoison_data(const void *address, size_t size) { }
> +static inline void kasan_unpoison_slab(const void *ptr) { }
> +
>  static inline void kasan_poison_slab(struct page *page) {}
>  static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
>                                         void *object) {}
> @@ -158,7 +155,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>         return false;
>  }
>
> -static inline void kasan_unpoison_slab(const void *ptr) { }
>  static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>
>  #endif /* CONFIG_KASAN */
> diff --git a/kernel/fork.c b/kernel/fork.c
> index b41fecca59d7..858d78eee6ec 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -225,7 +225,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>                         continue;
>
>                 /* Mark stack accessible for KASAN. */
> -               kasan_unpoison_memory(s->addr, THREAD_SIZE);
> +               kasan_unpoison_data(s->addr, THREAD_SIZE);
>
>                 /* Clear stale pointers from reused stack. */
>                 memset(s->addr, 0, THREAD_SIZE);
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9008fc6b0810..1a5e6c279a72 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -184,6 +184,16 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
>         return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
>  }
>
> +void kasan_unpoison_data(const void *address, size_t size)
> +{
> +       kasan_unpoison_memory(address, size);
> +}
> +
> +void kasan_unpoison_slab(const void *ptr)
> +{
> +       kasan_unpoison_memory(ptr, __ksize(ptr));
> +}
> +
>  void kasan_poison_slab(struct page *page)
>  {
>         unsigned long i;
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index f03161f3da19..915142da6b57 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -24,12 +24,6 @@ void __init kasan_init_tags(void)
>         pr_info("KernelAddressSanitizer initialized\n");
>  }
>
> -void kasan_unpoison_memory(const void *address, size_t size)
> -{
> -       set_mem_tag_range(reset_tag(address),
> -                         round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> -}
> -
>  void kasan_set_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8d84ae6f58f1..da08b2533d73 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -280,6 +280,12 @@ static inline void kasan_poison_memory(const void *address, size_t size, u8 valu
>                           round_up(size, KASAN_GRANULE_SIZE), value);
>  }
>
> +static inline void kasan_unpoison_memory(const void *address, size_t size)
> +{
> +       set_mem_tag_range(reset_tag(address),
> +                         round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> +}
> +
>  static inline bool check_invalid_free(void *addr)
>  {
>         u8 ptr_tag = get_tag(addr);
> @@ -292,6 +298,7 @@ static inline bool check_invalid_free(void *addr)
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  void kasan_poison_memory(const void *address, size_t size, u8 value);
> +void kasan_unpoison_memory(const void *address, size_t size);
>  bool check_invalid_free(void *addr);
>
>  #endif /* CONFIG_KASAN_HW_TAGS */
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 53d0f8bb57ea..f1b0c4a22f08 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
>          * We assume that ksize callers could use whole allocated area,
>          * so we need to unpoison this area.
>          */
> -       kasan_unpoison_memory(objp, size);
> +       kasan_unpoison_data(objp, size);
>         return size;
>  }
>  EXPORT_SYMBOL(ksize);
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbJxJ%2BEeStyytnnRyjRwoZNPGJ9ws20GfoCBFGWvUSBPg%40mail.gmail.com.
