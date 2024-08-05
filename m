Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDNKYK2QMGQEG6V5PPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D29959477D8
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 11:02:07 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39b3e750e48sf16035425ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2024 02:02:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722848526; cv=pass;
        d=google.com; s=arc-20160816;
        b=T8fNSLJ/Te1wdxyYlM+TSg+owpSUOhYnBDQxVDm63DdU17bhWeWg1fXTRnO9DbR+c3
         KQF5qkBRvQNZhIS3EWMo9Kb5Wc6fl2AMnuEJrbRsxWQt9NceIlzsx+mNzh4IHSSf/kK8
         42vuWuegyJi2MA3ypdijJNZwgPPNEfZJ3pmiFbDQH7FKDmAd9ulJFVwZOoNSYXXewBmY
         fdPivry7w6qR3odSv4bZRSQVSO3Sh0V1Fd3RWiUN8bpoRuQe9kDCHt+agq7c01klk422
         E0LYzHvxjBJsCoeuDuUEUFjS3yzNl7NS+SDKzWDCjriy03od9+gZVCIxOexG6C/YE6kd
         6qoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wm5fERziKEOAlodfc2n1nW8/ME8fHPXpAkxvEPTHfUU=;
        fh=R3lLsDDAAaKgGGOXjYoeEHm5Ca+DSHm84BLdwTf+cXY=;
        b=Oj445UePVwzkZjT+a9aXuFbxDhbnXSMxTitU2dw/GctWd4lGHwuOlNGhvfUCI/3S6x
         JPLcsTZ7k34xMVr2SI7BeJSBmbsqKLaBNftWNSfVjKXd76p2HYgzdTHYAl7bLxb2tic/
         DUhOnwY/1EovuIQMORh2oe3f6c3njg7nQ+LI1VgVntNpIvh9iRvMoft6Rl9Z7Y86ukU3
         RU2VSYCW2pPrWBCXmGTSeWZXj68k7ne/2erhAHvfK2QmzAGlOim9m/c+L6q/X9OeHpMR
         MwiaNSk+edEErtdIYrgJsdiNAE/i1e5JyOwnlqBRr28DzV1qBlnIeQzPOPOemgJjWeQX
         rSMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=apAd+u8S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722848526; x=1723453326; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wm5fERziKEOAlodfc2n1nW8/ME8fHPXpAkxvEPTHfUU=;
        b=s875nhLxdG3k6Nnrx+b8q8WoW2aAh/zcj06nADOO4MWo4n3vPnkQq4MZZPE56yg0OY
         4COOf9GqIm67yhEaA4V677faqQ1x5U6ErWC4vIOCTvFZZMg/FmRFL5KLHWXtYLxbBjLa
         W+X0w72Q1EWZvJSqXkv4oKMI2aP0kDF3jJ5SjdcG8XBsHRx/tjKNoX+eCTtwkm4n8bxt
         h70VUwe65VuSxTp22E5WQhwuNXu0YTzPoRWqHHHgfAfBnNxRLNb2xNgkohl/gvNIRYlY
         wf5+UcM0cf4diGBvmywZbz1HOvL5ej4Hx411rVEirCobmfFu/745DCMry/eSlJjnVQxD
         X22A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722848526; x=1723453326;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wm5fERziKEOAlodfc2n1nW8/ME8fHPXpAkxvEPTHfUU=;
        b=diucHlhldrdM8dFPLUJn6x7ouR7Ht5h9QNJsDOK4Yc34RI7ShSDzAMcGen9xc2vVE9
         U4xMdbLVhzQeupd/+R0NIanDTIaTHugXh6vhV0aFAr7UNC/Di7PRWaWQzm2IZj61spVQ
         dCbvsrODO1oD51EU2QraLMLcBAW90NYOTFeY63z16//mbL4yCbetL2m4lIDxJLZwEQ4O
         6vFL1XOiVTqTPO9VkYdiR2Iz2Sxonr0GcdubQrqWAeoe5Njs0bsUztkYeTpz+DNq1e68
         SNZLmc1nAHxU75egHSfwwD5EZTabJR6e4krn1wPAa/9GArpJpmXie6ommYl8e2b4h5j0
         WdAw==
X-Forwarded-Encrypted: i=2; AJvYcCVbAFy57DJLnDJx8RHF4y1imx5mWv5vnwhHNWwFjMkMJilHZGhLRa3zt4zgXh+wOBeddI0zE8kwvdcaUTuC5SomX8AXbxBa2A==
X-Gm-Message-State: AOJu0YzyyL+jtSPV7NXFY3jKs/sH9hhRp2bT7srzd1EiYCoVCsiWX5Yz
	OpEgx69fBj8nzZGoZebKryGfsO45flryteKN4TIxDK3CV2sTHKRR
X-Google-Smtp-Source: AGHT+IECtcUsNS3hP8Xe3PjfqaUFQuSBd/ODLVnF9fIfnJLUWbKi1rdN/47YjRHUFKidtnpuudoiKA==
X-Received: by 2002:a05:6e02:1d95:b0:380:f340:ad66 with SMTP id e9e14a558f8ab-39b1fc1348dmr151393525ab.26.1722848525963;
        Mon, 05 Aug 2024 02:02:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c64f:0:b0:39b:3b79:7045 with SMTP id e9e14a558f8ab-39b3b7972a7ls7958625ab.2.-pod-prod-04-us;
 Mon, 05 Aug 2024 02:02:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVr36HMvBsiUczvZf2Ijxa4VX+vndz3Or6FxIY5kzDVhvvS0yrL7r8ui4pA59DmZ2jQbA8Y+ET/GGcqr+eiHvcZi7MDgBwl1h+67Q==
X-Received: by 2002:a05:6602:3418:b0:81f:a28b:d43c with SMTP id ca18e2360f4ac-81fd434bb7emr1460175439f.7.1722848524972;
        Mon, 05 Aug 2024 02:02:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722848524; cv=none;
        d=google.com; s=arc-20160816;
        b=aawJmP6JGeKmfNoGD7Cdz3t6nr6lRxIeejhrWEGIENdcyRhHsR9sGiiNofVqPpUysG
         P6TLHO9Z7LBLT+rrUWYP6ll9A1QJvAlekfvFJ2yfDi0C3TytdyAK4Rd63vKqjffJJums
         1swEnB2UqHDHlU0kCRkSdEfXz1wYynNjE4Ch+3sHPAdJggqIzkBtO5bHTSOwwqBpS8Wi
         IS66/9teZahExDXdz28YefJmw9S0FgoAj++n3Pz86AcfEhwRIVsZO5Bk+1oC0FPZs+/0
         ou/v/xqen3OYDRMM9M5lAQdFMPcSPb0fvhUh2zAiYE5UWdRKYqKtRdeJfo0sEiOY739A
         6K5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vFCc5Uy7LPDHm6rtMOh8ozCWpQlk4J3KiAiDHNdvNUI=;
        fh=OdKz7Jnh3cB3u2dckKnwaynQm6IjzisgkemepLFIoZc=;
        b=QOKUwhbuFhg9UMbFkE6y4My7VHgaC7JS4lKGlgx5Efujgh2Y7ygnlcdaL1Vagn6Igz
         BtHjAMt5OBMIVbs/K09PT6TiXef2Ts/uBPb1Acg0Xk9B7G2BGtVur7PFd0ZIJxVPAZLd
         TSYwtVzdjQ3B6Wicj5IVEw/8fbmcuQMTLaGsp21kdMgdn5labFfk6B0KeQIXgv9X42zz
         b30D2SIV1Hor/oCpyT2vgsZCfwE9SY7Yf27lWD1WI2O2ZSBgUqCEBZmXtbsz7vD+lLY4
         CLDjGXNTkDjVdbzCKOaRkJmqcdyfSUmzD5IX000TNyCyWq9YWqBTd+gnDDFsZi4IQv9D
         /3Yw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=apAd+u8S;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-81fd4d01e38si25460139f.1.2024.08.05.02.02.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Aug 2024 02:02:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-821db15a930so3056473241.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2024 02:02:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXjDr/X2nrbP8Ag+itH5TG+34BKIqZvxVu7MjVQuV9c1K38TMIzU65N/4TnD2bzUW/yGRPJ19BlhN77TteLEKLqSpzBo9RkPgjWw==
X-Received: by 2002:a05:6102:c4e:b0:492:7ac7:33c6 with SMTP id
 ada2fe7eead31-4945bdf1be7mr14355373137.10.1722848523928; Mon, 05 Aug 2024
 02:02:03 -0700 (PDT)
MIME-Version: 1.0
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com> <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
In-Reply-To: <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2024 11:01:27 +0200
Message-ID: <CANpmjNNadRtLijEZLgE3HpyCGW=gkhunsFZ9FmwFZrpyWGUrnA@mail.gmail.com>
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=apAd+u8S;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 2 Aug 2024 at 22:32, Jann Horn <jannh@google.com> wrote:
>
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
>
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
>
> For now I've configured Kconfig.debug to default-enable this feature in the
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
> mode because I'm not sure if it might have unwanted performance degradation
> effects there.
>
> Note that this is mostly useful with KASAN in the quarantine-based GENERIC
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
>
> Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Marco Elver <elver@google.com>

Looks good - let's see what the fuzzers will find with it. :-)

Feel free to ignore the below comments if there isn't a v+1.

> ---
>  include/linux/kasan.h | 17 +++++++----
>  mm/Kconfig.debug      | 30 +++++++++++++++++++
>  mm/kasan/common.c     | 11 +++----
>  mm/kasan/kasan_test.c | 46 ++++++++++++++++++++++++++++++
>  mm/slab_common.c      | 12 ++++++++
>  mm/slub.c             | 79 +++++++++++++++++++++++++++++++++++++++++++++------
>  6 files changed, 176 insertions(+), 19 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 1570c7191176..00a3bf7c0d8f 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -193,40 +193,44 @@ static __always_inline bool kasan_slab_pre_free(struct kmem_cache *s,
>  {
>         if (kasan_enabled())
>                 return __kasan_slab_pre_free(s, object, _RET_IP_);
>         return false;
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init);
> +bool __kasan_slab_free(struct kmem_cache *s, void *object, bool init,
> +                      bool still_accessible);
>  /**
>   * kasan_slab_free - Poison, initialize, and quarantine a slab object.
>   * @object: Object to be freed.
>   * @init: Whether to initialize the object.
> + * @still_accessible: Whether the object contents are still accessible.
>   *
>   * This function informs that a slab object has been freed and is not
> - * supposed to be accessed anymore, except for objects in
> - * SLAB_TYPESAFE_BY_RCU caches.
> + * supposed to be accessed anymore, except when @still_accessible is set
> + * (indicating that the object is in a SLAB_TYPESAFE_BY_RCU cache and an RCU
> + * grace period might not have passed yet).
>   *
>   * For KASAN modes that have integrated memory initialization
>   * (kasan_has_integrated_init() == true), this function also initializes
>   * the object's memory. For other modes, the @init argument is ignored.
>   *
>   * This function might also take ownership of the object to quarantine it.
>   * When this happens, KASAN will defer freeing the object to a later
>   * stage and handle it internally until then. The return value indicates
>   * whether KASAN took ownership of the object.
>   *
>   * This function is intended only for use by the slab allocator.
>   *
>   * @Return true if KASAN took ownership of the object; false otherwise.
>   */
>  static __always_inline bool kasan_slab_free(struct kmem_cache *s,
> -                                               void *object, bool init)
> +                                               void *object, bool init,
> +                                               bool still_accessible)
>  {
>         if (kasan_enabled())
> -               return __kasan_slab_free(s, object, init);
> +               return __kasan_slab_free(s, object, init, still_accessible);
>         return false;
>  }
>
>  void __kasan_kfree_large(void *ptr, unsigned long ip);
>  static __always_inline void kasan_kfree_large(void *ptr)
>  {
> @@ -416,13 +420,14 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
>
>  static inline bool kasan_slab_pre_free(struct kmem_cache *s, void *object)
>  {
>         return false;
>  }
>
> -static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
> +static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
> +                                  bool init, bool still_accessible)
>  {
>         return false;
>  }
>  static inline void kasan_kfree_large(void *ptr) {}
>  static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
>                                    gfp_t flags, bool init)
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index afc72fde0f03..8e440214aac8 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -67,12 +67,42 @@ config SLUB_DEBUG_ON
>           equivalent to specifying the "slab_debug" parameter on boot.
>           There is no support for more fine grained debug control like
>           possible with slab_debug=xxx. SLUB debugging may be switched
>           off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
>           "slab_debug=-".
>
> +config SLUB_RCU_DEBUG
> +       bool "Enable UAF detection in TYPESAFE_BY_RCU caches (for KASAN)"
> +       depends on SLUB_DEBUG
> +       depends on KASAN # not a real dependency; currently useless without KASAN

This comment is odd. If it's useless without KASAN then it definitely
depends on KASAN. I suppose the code compiles without KASAN, but I
think that's secondary.

> +       default KASAN_GENERIC || KASAN_SW_TAGS
> +       help
> +         Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the cache
> +         was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
> +         kfree_rcu() instead.
> +
> +         This is intended for use in combination with KASAN, to enable KASAN to
> +         detect use-after-free accesses in such caches.
> +         (KFENCE is able to do that independent of this flag.)
> +
> +         This might degrade performance.
> +         Unfortunately this also prevents a very specific bug pattern from
> +         triggering (insufficient checks against an object being recycled
> +         within the RCU grace period); so this option can be turned off even on
> +         KASAN builds, in case you want to test for such a bug.
> +
> +         If you're using this for testing bugs / fuzzing and care about
> +         catching all the bugs WAY more than performance, you might want to
> +         also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
> +
> +         WARNING:
> +         This is designed as a debugging feature, not a security feature.
> +         Objects are sometimes recycled without RCU delay under memory pressure.
> +
> +         If unsure, say N.
> +
>  config PAGE_OWNER
>         bool "Track page owner"
>         depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
>         select DEBUG_FS
>         select STACKTRACE
>         select STACKDEPOT
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index f26bbc087b3b..ed4873e18c75 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -227,43 +227,44 @@ static bool check_slab_allocation(struct kmem_cache *cache, void *object,
>         }
>
>         return false;
>  }
>
>  static inline void poison_slab_object(struct kmem_cache *cache, void *object,
> -                                     bool init)
> +                                     bool init, bool still_accessible)
>  {
>         void *tagged_object = object;
>
>         object = kasan_reset_tag(object);
>
>         /* RCU slabs could be legally used after free within the RCU period. */
> -       if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (unlikely(still_accessible))
>                 return;
>
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
>                         KASAN_SLAB_FREE, init);
>
>         if (kasan_stack_collection_enabled())
>                 kasan_save_free_info(cache, tagged_object);
>  }
>
>  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>                                 unsigned long ip)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>         return check_slab_allocation(cache, object, ip);
>  }
>
> -bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init)
> +bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
> +                      bool still_accessible)
>  {
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init);
> +       poison_slab_object(cache, object, init, still_accessible);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the object
>          * onto the freelist for now. The object's metadata is kept until the
>          * object gets evicted from quarantine.
>          */
> @@ -515,13 +516,13 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>
>         slab = folio_slab(folio);
>
>         if (check_slab_allocation(slab->slab_cache, ptr, ip))
>                 return false;
>
> -       poison_slab_object(slab->slab_cache, ptr, false);
> +       poison_slab_object(slab->slab_cache, ptr, false, false);
>         return true;
>  }
>
>  void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
>  {
>         struct slab *slab;
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 7b32be2a3cf0..567d33b493e2 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -993,12 +993,57 @@ static void kmem_cache_invalid_free(struct kunit *test)
>          */
>         kmem_cache_free(cache, p);
>
>         kmem_cache_destroy(cache);
>  }
>
> +static void kmem_cache_rcu_uaf(struct kunit *test)
> +{
> +       char *p;
> +       size_t size = 200;
> +       struct kmem_cache *cache;
> +
> +       KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_SLUB_RCU_DEBUG);
> +
> +       cache = kmem_cache_create("test_cache", size, 0, SLAB_TYPESAFE_BY_RCU,
> +                                 NULL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
> +
> +       p = kmem_cache_alloc(cache, GFP_KERNEL);
> +       if (!p) {
> +               kunit_err(test, "Allocation failed: %s\n", __func__);
> +               kmem_cache_destroy(cache);
> +               return;
> +       }
> +       *p = 1;
> +
> +       rcu_read_lock();
> +
> +       /* Free the object - this will internally schedule an RCU callback. */
> +       kmem_cache_free(cache, p);
> +
> +       /*
> +        * We should still be allowed to access the object at this point because
> +        * the cache is SLAB_TYPESAFE_BY_RCU and we've been in an RCU read-side
> +        * critical section since before the kmem_cache_free().
> +        */
> +       READ_ONCE(*p);
> +
> +       rcu_read_unlock();
> +
> +       /*
> +        * Wait for the RCU callback to execute; after this, the object should
> +        * have actually been freed from KASAN's perspective.
> +        */
> +       rcu_barrier();
> +
> +       KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*p));
> +
> +       kmem_cache_destroy(cache);
> +}
> +
>  static void empty_cache_ctor(void *object) { }
>
>  static void kmem_cache_double_destroy(struct kunit *test)
>  {
>         struct kmem_cache *cache;
>
> @@ -1934,12 +1979,13 @@ static struct kunit_case kasan_kunit_test_cases[] = {
>         KUNIT_CASE(workqueue_uaf),
>         KUNIT_CASE(kfree_via_page),
>         KUNIT_CASE(kfree_via_phys),
>         KUNIT_CASE(kmem_cache_oob),
>         KUNIT_CASE(kmem_cache_double_free),
>         KUNIT_CASE(kmem_cache_invalid_free),
> +       KUNIT_CASE(kmem_cache_rcu_uaf),
>         KUNIT_CASE(kmem_cache_double_destroy),
>         KUNIT_CASE(kmem_cache_accounted),
>         KUNIT_CASE(kmem_cache_bulk),
>         KUNIT_CASE(mempool_kmalloc_oob_right),
>         KUNIT_CASE(mempool_kmalloc_large_oob_right),
>         KUNIT_CASE(mempool_slab_oob_right),
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 40b582a014b8..df09066d56fe 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -539,12 +539,24 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
>                 kmem_cache_release(s);
>         }
>  }
>
>  static int shutdown_cache(struct kmem_cache *s)
>  {
> +       if (IS_ENABLED(CONFIG_SLUB_RCU_DEBUG) &&
> +           (s->flags & SLAB_TYPESAFE_BY_RCU)) {
> +               /*
> +                * Under CONFIG_SLUB_RCU_DEBUG, when objects in a
> +                * SLAB_TYPESAFE_BY_RCU slab are freed, SLUB will internally
> +                * defer their freeing with call_rcu().
> +                * Wait for such call_rcu() invocations here before actually
> +                * destroying the cache.
> +                */
> +               rcu_barrier();
> +       }
> +
>         /* free asan quarantined objects */
>         kasan_cache_shutdown(s);
>
>         if (__kmem_cache_shutdown(s) != 0)
>                 return -EBUSY;
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 0c98b6a2124f..a89f2006d46e 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2197,45 +2197,81 @@ static inline bool memcg_slab_post_alloc_hook(struct kmem_cache *s,
>  static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
>                                         void **p, int objects)
>  {
>  }
>  #endif /* CONFIG_MEMCG */
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
> +
> +struct rcu_delayed_free {
> +       struct rcu_head head;
> +       void *object;
> +};
> +#endif
> +
>  /*
>   * Hooks for other subsystems that check memory allocations. In a typical
>   * production configuration these hooks all should produce no code at all.
>   *
>   * Returns true if freeing of the object can proceed, false if its reuse
> - * was delayed by KASAN quarantine, or it was returned to KFENCE.
> + * was delayed by CONFIG_SLUB_RCU_DEBUG or KASAN quarantine, or it was returned
> + * to KFENCE.
>   */
>  static __always_inline
> -bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> +bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
> +                   bool after_rcu_delay)
>  {
> +       /* Are the object contents still accessible? */
> +       bool still_accessible = (s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay;
> +
>         kmemleak_free_recursive(x, s->flags);
>         kmsan_slab_free(s, x);
>
>         debug_check_no_locks_freed(x, s->object_size);
>
>         if (!(s->flags & SLAB_DEBUG_OBJECTS))
>                 debug_check_no_obj_freed(x, s->object_size);
>
>         /* Use KCSAN to help debug racy use-after-free. */
> -       if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
> +       if (!still_accessible)
>                 __kcsan_check_access(x, s->object_size,
>                                      KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
>
>         if (kfence_free(x))
>                 return false;
>
>         /*
>          * Give KASAN a chance to notice an invalid free operation before we
>          * modify the object.
>          */
>         if (kasan_slab_pre_free(s, x))
>                 return false;
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +       if (still_accessible) {
> +               struct rcu_delayed_free *delayed_free;
> +
> +               delayed_free = kmalloc(sizeof(*delayed_free), GFP_NOWAIT);
> +               if (delayed_free) {
> +                       /*
> +                        * Let KASAN track our call stack as a "related work
> +                        * creation", just like if the object had been freed
> +                        * normally via kfree_rcu().
> +                        * We have to do this manually because the rcu_head is
> +                        * not located inside the object.
> +                        */
> +                       kasan_record_aux_stack_noalloc(x);
> +
> +                       delayed_free->object = x;
> +                       call_rcu(&delayed_free->head, slab_free_after_rcu_debug);
> +                       return false;
> +               }
> +       }
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>         /*
>          * As memory initialization might be integrated into KASAN,
>          * kasan_slab_free and initialization memset's must be
>          * kept together to avoid discrepancies in behavior.
>          *
>          * The initialization memset's clear the object and the metadata,
> @@ -2253,42 +2289,42 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
>                         memset(kasan_reset_tag(x), 0, s->object_size);
>                 rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
>                 memset((char *)kasan_reset_tag(x) + inuse, 0,
>                        s->size - inuse - rsize);
>         }
>         /* KASAN might put x into memory quarantine, delaying its reuse. */
> -       return !kasan_slab_free(s, x, init);
> +       return !kasan_slab_free(s, x, init, still_accessible);
>  }
>
>  static __fastpath_inline
>  bool slab_free_freelist_hook(struct kmem_cache *s, void **head, void **tail,
>                              int *cnt)
>  {
>
>         void *object;
>         void *next = *head;
>         void *old_tail = *tail;
>         bool init;
>
>         if (is_kfence_address(next)) {
> -               slab_free_hook(s, next, false);
> +               slab_free_hook(s, next, false, false);
>                 return false;
>         }
>
>         /* Head and tail of the reconstructed freelist */
>         *head = NULL;
>         *tail = NULL;
>
>         init = slab_want_init_on_free(s);
>
>         do {
>                 object = next;
>                 next = get_freepointer(s, object);
>
>                 /* If object's reuse doesn't have to be delayed */
> -               if (likely(slab_free_hook(s, object, init))) {
> +               if (likely(slab_free_hook(s, object, init, false))) {
>                         /* Move object to the new freelist */
>                         set_freepointer(s, object, *head);
>                         *head = object;
>                         if (!*tail)
>                                 *tail = object;
>                 } else {
> @@ -4474,40 +4510,67 @@ static __fastpath_inline
>  void slab_free(struct kmem_cache *s, struct slab *slab, void *object,
>                unsigned long addr)
>  {
>         memcg_slab_free_hook(s, slab, &object, 1);
>         alloc_tagging_slab_free_hook(s, slab, &object, 1);
>
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>                 do_slab_free(s, slab, object, object, 1, addr);
>  }
>
>  #ifdef CONFIG_MEMCG
>  /* Do not inline the rare memcg charging failed path into the allocation path */
>  static noinline
>  void memcg_alloc_abort_single(struct kmem_cache *s, void *object)
>  {
> -       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s))))
> +       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s), false)))
>                 do_slab_free(s, virt_to_slab(object), object, object, 1, _RET_IP_);
>  }
>  #endif
>
>  static __fastpath_inline
>  void slab_free_bulk(struct kmem_cache *s, struct slab *slab, void *head,
>                     void *tail, void **p, int cnt, unsigned long addr)
>  {
>         memcg_slab_free_hook(s, slab, p, cnt);
>         alloc_tagging_slab_free_hook(s, slab, p, cnt);
>         /*
>          * With KASAN enabled slab_free_freelist_hook modifies the freelist
>          * to remove objects, whose reuse must be delayed.
>          */
>         if (likely(slab_free_freelist_hook(s, &head, &tail, &cnt)))
>                 do_slab_free(s, slab, head, tail, cnt, addr);
>  }
>
> +#ifdef CONFIG_SLUB_RCU_DEBUG
> +static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
> +{
> +       struct rcu_delayed_free *delayed_free =
> +                       container_of(rcu_head, struct rcu_delayed_free, head);

Minor: Some of these line breaks are unnecessary (kernel allows 100+
cols) - but up to you if you want to change it.

> +       void *object = delayed_free->object;
> +       struct slab *slab = virt_to_slab(object);
> +       struct kmem_cache *s;
> +
> +       if (WARN_ON(is_kfence_address(object)))
> +               return;
> +
> +       /* find the object and the cache again */
> +       if (WARN_ON(!slab))
> +               return;
> +       s = slab->slab_cache;
> +       if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
> +               return;
> +
> +       /* resume freeing */
> +       if (!slab_free_hook(s, object, slab_want_init_on_free(s), true))
> +               return;
> +       do_slab_free(s, slab, object, object, 1, _THIS_IP_);
> +       kfree(delayed_free);
> +}
> +#endif /* CONFIG_SLUB_RCU_DEBUG */
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  {
>         do_slab_free(cache, virt_to_slab(x), x, x, 1, addr);
>  }
>  #endif
>
> --
> 2.46.0.rc2.264.g509ed76dc8-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNadRtLijEZLgE3HpyCGW%3DgkhunsFZ9FmwFZrpyWGUrnA%40mail.gmail.com.
