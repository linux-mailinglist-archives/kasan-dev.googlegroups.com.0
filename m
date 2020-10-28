Return-Path: <kasan-dev+bncBCMIZB7QWENRBKWG436AKGQE6B7MKGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B3F29D12C
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 17:58:19 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id q16sf3883pfj.7
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 09:58:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904298; cv=pass;
        d=google.com; s=arc-20160816;
        b=stjB2xs1YeVjRqTwIU6Fhl13GuySk8x/S+oasuFlbzbaliPREv/l8LtGZaex9sFo1l
         CjE5Hk9eCK735cB+8XpV+vSeSgpljl7Ja+qrCrftTSbudNTEwPqvSu3d5z/cuqZSh44B
         v/nKvN0jDChokBNamOp8z/RfwjC+WVZeQCCO4Rm2Bjg1NPVFIXMDRy/rlVbCEylpNnNK
         7ZMOTmMzLPS4Djt5+Z5+kMcdibplhLkHeXYVQ438zQnBgHzQZYeI4i8N5CtzrF4HFf2p
         OmKh8p236c3ixGroaF2ET8chv78PanZCj8nNpX7lFbLZ6+A0R62zIyZhO8HtiFfwZaA3
         5yig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1RKWgDPkzf4AKgTHlCRqhPShOIUjdZtifrwYtWyaKQY=;
        b=xaEzWpeuY+SI1rIQI0gssRjuVS4xfIOUAyvQGRyz9oTlvRjhDe/k42J/vibGIwAQcS
         A+AVSiVH/y1Hq30oihxAlZwmCwMbrJ8Of8XbD8k/JHAAn5f0kROqQk2I9SbpRePSKhzo
         usCtsTOTqVkfg3PeX6a3hHv5mG5mojxwUciIU/hfbSF6kc86jxCUvBNRDeSdeFRGgYMO
         W9o1Bx7ySFSc17qClfOyPrpKEpYKkVoQvzqxaN4ithoKjscp+W6FBaQy1ssKX++IMu+c
         qRurCG9SfjDH7FRSA7HCWuoCebgLpE4wa17Qc2CMucUnyXc5sZUXmVQFCA31dR6YM9MI
         PT1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E6BSgQbS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1RKWgDPkzf4AKgTHlCRqhPShOIUjdZtifrwYtWyaKQY=;
        b=AcGXO9iiiPPIixlt5lO3DWR+AvTT40Fnmxq57wSmmxjZqGAGgjnIbK0C0JClj5omp2
         FGsMYwJ1ZJmAqDruConF599KTifmXPIY5HZ5rCI542+pmRWlLKdVwWuIE3SPONi9aw5C
         JMOTxUzSvuIbbDVEHHdS5G/HCAZTrOQ3MjTR+zPBS3Dh0f+AjxQZmfnKch7k/JkicnSW
         Gvg1cj3Lq9PKHsHjfx/4ZcjsRr2UVxf/vpHnuQLy7+EaIm3I9G0IFSmMiQxcgZU6kabg
         8SPOcgNUQ5RfjZbd07dpv4l6iXlLtRGlBxUUHkrqk1hJHuZ87+8KB5HLdSZSsJQpwusq
         baQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1RKWgDPkzf4AKgTHlCRqhPShOIUjdZtifrwYtWyaKQY=;
        b=Jbn7tLBvLEYVcMxG65vu3oBGvEU7sLitLDTo6IDtpAM8v0IirvTPIK5ztR2ZkpJDVC
         aZ8XKX1PcSTHVFb7aJ4q7F5bTQs4ILICPD5AdXj06up+ozHCZOxJ/ce8rkfRD358ebIa
         nW35LxNFcfShtCCsGi+eLtmqFh4g9OPenfltZdneMwODOEqM6SA74S/X+pOuEZaOp58g
         RWG/WYf/4r0Y5SSy2nf9c8b9E750pQCGzMA3ktcpD13pp8pgm0W2gcnjr7SVI3KGfr2w
         Dm2GEuhMq1J+FbjqEy6mmChze2M2ucRp90ahMF3vfjfHJqkGohZEwhs9acrN/X3hHmO1
         v2Hw==
X-Gm-Message-State: AOAM5337y7uBLXOLXw2FVKrSFp3BbROFAdJz31fhcFc5UFh2QdBDfcV2
	cffi2y1wV6groM6g57VuIZc=
X-Google-Smtp-Source: ABdhPJwgFlclc+/jHmUtMcdmbnfRoJLWEgetFVQjMOnoqwfvNDyx6NBoCyrnEUaMTR0NVgeByHyliw==
X-Received: by 2002:a17:90a:4a85:: with SMTP id f5mr274852pjh.216.1603904298481;
        Wed, 28 Oct 2020 09:58:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7786:: with SMTP id o6ls2617659pll.0.gmail; Wed, 28
 Oct 2020 09:58:16 -0700 (PDT)
X-Received: by 2002:a17:90a:1bca:: with SMTP id r10mr298129pjr.4.1603904296470;
        Wed, 28 Oct 2020 09:58:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904296; cv=none;
        d=google.com; s=arc-20160816;
        b=Z13y3CprY9/79Xj4+wn1/qbHsvq8e04KniU4fI/LFl5RuoRWm5VSaUJo6F5Tt/PUdQ
         T/vCurb+H6jnT9OlCoEFPKams8/DPu9nFQph+k0/TFfXB5JQ6UxQ4mhkOaxs7PCOUni/
         pkXG/mGKsYHskOkCJzBBNuqaq4HT7R3wv2GmIPKHj+viqgU8FuL+mosDT02Ur2jdst1b
         pAI75dU47yU3p7fsNU1KFKgiCdoufWLxr/GJVKsE0+0tXn9KkDtPHmmeM5eD/Uov2VaV
         7IpuVU6pN/oGl4Dz7vVtTktmCUqgrjwLSK63V/8sVuprBf1zAJ/vaSX+N/p1kJXrcSxO
         JeYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Xc9c29FA+GYfQKQjFulHFDr1xP7AG55TTtOHUWqRAY=;
        b=T9LvA89eBF7clxS4fdPBM41exldVj978b+QZu9fOtLb89ldEcLdMo0BcQ4JSyTdM8L
         Y9LVLr4dhnrXqBGKzAzBXwMJySWm34ZmNtRc5OcRfAXjdbKneOTz6hzxCpAr/BKSBBKC
         WuYF2jh7SrJWtO808GnW+oCLEDXqpLLtIa5HAStW8mslFCnaxv4TQMOaBJK+gl1Cq8uW
         ys8PBxQ0YUoCE3L53mJ19aW7U+W7yskGNaw0FDFv+G/8Jo9nruTobfcb2C4ML8/1JfmH
         lFrwusmbxG/POvVP619xoR3X3AI5OQr62EYXvsG0bnspxGWB5UM0b6Rl8U8Yf4X0/1nG
         zELw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E6BSgQbS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id x6si3661pjn.2.2020.10.28.09.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 09:58:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id x20so5192552qkn.1
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 09:58:16 -0700 (PDT)
X-Received: by 2002:a05:620a:1188:: with SMTP id b8mr8384202qkk.265.1603904295369;
 Wed, 28 Oct 2020 09:58:15 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <5a6f32308101c49da5eef652437bd3da9234c0da.1603372719.git.andreyknvl@google.com>
In-Reply-To: <5a6f32308101c49da5eef652437bd3da9234c0da.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 17:58:03 +0100
Message-ID: <CACT4Y+Z88xqdz4vbPeLzPwxX77FJUxbz+bqiSs1aMDVSGxcpUg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 18/21] kasan: rename kasan_poison_kfree
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
 header.i=@google.com header.s=20161025 header.b=E6BSgQbS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Rename kasan_poison_kfree() into kasan_slab_free_mempool() as it better
> reflects what this annotation does.
>
> No functional changes.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  include/linux/kasan.h | 16 ++++++++--------
>  mm/kasan/common.c     | 16 ++++++++--------
>  mm/mempool.c          |  2 +-
>  3 files changed, 17 insertions(+), 17 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 8654275aa62e..2ae92f295f76 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -162,6 +162,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
>         return false;
>  }
>
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
> +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +       if (static_branch_likely(&kasan_enabled))
> +               __kasan_slab_free_mempool(ptr, ip);
> +}
> +
>  void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
>                                        void *object, gfp_t flags);
>  static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
> @@ -202,13 +209,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
>         return (void *)object;
>  }
>
> -void __kasan_poison_kfree(void *ptr, unsigned long ip);
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -       if (static_branch_likely(&kasan_enabled))
> -               __kasan_poison_kfree(ptr, ip);
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static inline void kasan_kfree_large(void *ptr, unsigned long ip)
>  {
> @@ -244,6 +244,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
>  {
>         return false;
>  }
> +static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>                                    gfp_t flags)
>  {
> @@ -264,7 +265,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
>  {
>         return (void *)object;
>  }
> -static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
>  static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
>
>  #endif /* CONFIG_KASAN */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b82dbae0c5d6..5622b0ec0907 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -334,6 +334,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
>         return ____kasan_slab_free(cache, object, ip, true);
>  }
>
> +void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
> +{
> +       struct page *page;
> +
> +       page = virt_to_head_page(ptr);
> +       ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> +}
> +
>  static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
>  {
>         kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
> @@ -436,14 +444,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>                                                 flags, true);
>  }
>
> -void __kasan_poison_kfree(void *ptr, unsigned long ip)
> -{
> -       struct page *page;
> -
> -       page = virt_to_head_page(ptr);
> -       ____kasan_slab_free(page->slab_cache, ptr, ip, false);
> -}
> -
>  void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>         if (ptr != page_address(virt_to_head_page(ptr)))
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 79bff63ecf27..0e8d877fbbc6 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -106,7 +106,7 @@ static inline void poison_element(mempool_t *pool, void *element)
>  static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
>  {
>         if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
> -               kasan_poison_kfree(element, _RET_IP_);
> +               kasan_slab_free_mempool(element, _RET_IP_);
>         if (pool->alloc == mempool_alloc_pages)
>                 kasan_free_pages(element, (unsigned long)pool->pool_data);
>  }
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ88xqdz4vbPeLzPwxX77FJUxbz%2BbqiSs1aMDVSGxcpUg%40mail.gmail.com.
