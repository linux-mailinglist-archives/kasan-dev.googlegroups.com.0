Return-Path: <kasan-dev+bncBCMIZB7QWENRBO6I5HTQKGQEYY5EMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EEF7F38B66
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Jun 2019 15:18:52 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id i133sf1627625ioa.11
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Jun 2019 06:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559913532; cv=pass;
        d=google.com; s=arc-20160816;
        b=xh6srMJvoeq1bYHSkF2AXJPjx+OZ/Bri2cMmPbg2UfdKQq7+ta7xIyc3AI6IcQPc4Y
         E+xCs5+xbEDzCYK3thnF+8gHpU+dI2SaNVAd+tpVt0f8OsoCiErtdspTaUtBzyekTNag
         vEl2hBFGccd3vhoB7cn9PaVR6oTnheZ3tCUw5QLn5h0QLl05RhgWUr8JV8+fgsViEl0m
         kUFXMe4vB3yyUHm+G7e2xLPfB5hanNW9WdYhPZtTpKYgQJihMrRM1zWtV+L+TZh/P2o8
         M5ELRFoTFSMucZZqI56aXH6DQwFgkS7PcT3qy1Lb3rRLiZVX+egAWQ8sDu3tBgtDrlO2
         DEtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=POoVt7Xj09piGZC6nrbq8m4AEFdQsQN6YWdJajEQcic=;
        b=pOOLimKc9HcUx2m28/1QHQEsKUOJF78SkLnpIobT20aYuSQ66kCD0Wsra3MqP4SPBQ
         dW9BN9E62plFJZcJmUw71iXoQOWMKB158DNp+G0zEbkTYm1+iUFczDWM4YjwWmKmLmOl
         aOL029EUUFQXVBMfXJ+cr1roT1/VI4fB3zZeUuhnRNJlEokCDgKckORW9A2rVxwr7a57
         ZajX51IxYzjVsYcE9771tE7dz9mrlj0Dze9wQMbcp7prYohDVtCCYVQB/CGVO0Z67MFl
         RzqASJrH+OpvDILKtGFcYHRbZyLre4TZlmvoTNdqPtzPb3Tdg9nYEGDxkrmPRcLhVXMa
         lGRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fFQZdcxf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POoVt7Xj09piGZC6nrbq8m4AEFdQsQN6YWdJajEQcic=;
        b=Vdy+sC6lRvZ7KJibCWQ5g4N8bQ0ocQqzNP7RuS2j2Ezx8ySzZBqc59gSZefLT7Vcr1
         1wvFCbSY3fhLqAkMJ7PDoEFoRbJYd84kOH+r65dwxS2sgUpzx9+iLrUx6HMRgsKMZmlb
         3wZqulT5ifjoP/QKRFxxRlZrWvqZA3+Xg8blbEhASHdgA55WNRJDvfU7Y6gv/O85H92+
         5zipkEOY8kUzMF06JsmP44SNOttqOT3DDPCHf0RsYhwAm/bYeGlY1786Q+w3H8byy+Ce
         GS/T6OChLwlWn2eU968Df4C0M4mH0Gi6+I105E8xKV6clLpMjuaGzvQNX1mGp7Y92xDK
         +igg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=POoVt7Xj09piGZC6nrbq8m4AEFdQsQN6YWdJajEQcic=;
        b=Llj4w+eFiN0dtcgYfO3G0ALOukdFcdyYGh41wT4z7XQINbMtQdo8uQHkyEgz35Zxyz
         rFXaOts9X06YOqrnojvrVe7Z6i+DdOFk+n1rmXG66rHuATciElURx2NzH4nJgJL9vlC5
         UmzjVt+03ihy5nbd7qOdVZE35UOml3mc14RffTYM9aCP0a4IoshyUfRwH/gOOQtmElTI
         Pwi+8jmTYB61bfq5yz0FK/R5pCitWaCw74UGuG8I3GpUNJRaecT7SXRAwGF7YW12Ol3Y
         +O+ZgpX7f+rs/PimR9aROBzl+XNNZChISGjOIw1HQmkayvNsJxggnBP5J9nITUSXdDlw
         K5Aw==
X-Gm-Message-State: APjAAAWcg62vVCY565L3eYK3WZtPpnEgZQNbRWQmkoi0dyGjXJY7sI/C
	sQDD+hdM+y6vvvXPy7npXS8=
X-Google-Smtp-Source: APXvYqzob+hB8DgakJU+LVV8c+Jra8XeNjF8jv0Ip8ZvSBvc3GIQx3JckEO9dtfS0MzkeAzj7XXq+g==
X-Received: by 2002:a24:dc41:: with SMTP id q62mr3771679itg.165.1559913531866;
        Fri, 07 Jun 2019 06:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6303:: with SMTP id p3ls1406137iog.11.gmail; Fri, 07 Jun
 2019 06:18:51 -0700 (PDT)
X-Received: by 2002:a5e:9e03:: with SMTP id i3mr4432966ioq.66.1559913531534;
        Fri, 07 Jun 2019 06:18:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559913531; cv=none;
        d=google.com; s=arc-20160816;
        b=S8YBR2TMzfy2BSsajchp4CF/q2/48GIHwdedL2SPU9rg53K+iOldNla2puhlKovH3e
         NTuBOKU+wXesFqbSoySBnb7OAG6/ljKC6BL9OqWPX6Jg2uzP2H/Yt98o8lYtK2jsoSHf
         slI4q5VVtTavRciGuP/tP179Uun6p1lZeCqY4S7V7Yh5Qit85O1oGUkkQ5W8hGAuy0ML
         GGXne0mdEcP1yA7VztKPekIvoB+z4WDMKrZ3C76A4K9QsoP5AKO99OKkZvMiU7Qp9YID
         /LUm03HuYSy+BD+vbBR6ka1YXaEXeDvF1tNWBxicMY82+wGPpuWFcD+cafSS9ZQxczLj
         zkYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3RwN85TIST9Pu6olIcDwmmCao8JJAImV1IlPOw2oE0c=;
        b=oS9RKm06t7JuV8IHVBz4RejOTI2E7MRkddC/1B+mOfqR4O1F9ta+wm8CuzMPj7ip6I
         xZ7GdJDhEZPezWBPXo2ZSE1GsUP0kZSXRB86g0u4N1uhnXcKpgrLkIa2W4/74K+CymAr
         DvgWOBLHtAKkOuHyttmZm3s0mmy4JuAwS6i52WRNLy3iQF0dzXI/iLEpL2CjtExfWoYd
         DFNfLPGjNEOeb2vP4sVVSRsTalhKhDHGWCz4dDboI+h1MeznxwrumHS9W47OKvXrnrIY
         RvZEut0uoX4qCk3FF3mUYZToAKAZnWLNvN5sC4mSUEAP1eLWaRm7SlDxnJ7o1RWBwuct
         fuIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fFQZdcxf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-it1-x12b.google.com (mail-it1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id j135si117387itj.2.2019.06.07.06.18.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Jun 2019 06:18:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-it1-x12b.google.com with SMTP id q14so1586879itc.5
        for <kasan-dev@googlegroups.com>; Fri, 07 Jun 2019 06:18:51 -0700 (PDT)
X-Received: by 2002:a02:22c6:: with SMTP id o189mr22322508jao.35.1559913530765;
 Fri, 07 Jun 2019 06:18:50 -0700 (PDT)
MIME-Version: 1.0
References: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
In-Reply-To: <1559651172-28989-1-git-send-email-walter-zh.wu@mediatek.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Jun 2019 15:18:39 +0200
Message-ID: <CACT4Y+Y9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add memory corruption identification for
 software tag-based mode
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Martin Schwidefsky <schwidefsky@de.ibm.com>, Arnd Bergmann <arnd@arndb.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"Jason A. Donenfeld" <Jason@zx2c4.com>, Miles Chen <miles.chen@mediatek.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fFQZdcxf;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::12b
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

On Tue, Jun 4, 2019 at 2:26 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This patch adds memory corruption identification at bug report for
> software tag-based mode, the report show whether it is "use-after-free"
> or "out-of-bound" error instead of "invalid-access" error.This will make
> it easier for programmers to see the memory corruption problem.
>
> Now we extend the quarantine to support both generic and tag-based kasan.
> For tag-based kasan, the quarantine stores only freed object information
> to check if an object is freed recently. When tag-based kasan reports an
> error, we can check if the tagged addr is in the quarantine and make a
> good guess if the object is more like "use-after-free" or "out-of-bound".
>
> Due to tag-based kasan, the tag values are stored in the shadow memory,
> all tag comparison failures are memory corruption. Even if those freed
> object have been deallocated, we still can get the memory corruption.
> So the freed object doesn't need to be kept in quarantine, it can be
> immediately released after calling kfree(). We only need the freed object
> information in quarantine, the error handler is able to use object
> information to know if it has been allocated or deallocated, therefore
> every slab memory corruption can be identified whether it's
> "use-after-free" or "out-of-bound".
>
> The difference between generic kasan and tag-based kasan quarantine is
> slab memory usage. Tag-based kasan only stores freed object information
> rather than the object itself. So tag-based kasan quarantine memory usage
> is smaller than generic kasan.
>
>
> ====== Benchmarks
>
> The following numbers were collected in QEMU.
> Both generic and tag-based KASAN were used in inline instrumentation mode
> and no stack checking.
>
> Boot time :
> * ~1.5 sec for clean kernel
> * ~3 sec for generic KASAN
> * ~3.5  sec for tag-based KASAN
> * ~3.5 sec for tag-based KASAN + corruption identification
>
> Slab memory usage after boot :
> * ~10500 kb  for clean kernel
> * ~30500 kb  for generic KASAN
> * ~12300 kb  for tag-based KASAN
> * ~17100 kb  for tag-based KASAN + corruption identification
>
> ====== Changes
>
> Change since v1:
> - add feature option CONFIG_KASAN_SW_TAGS_IDENTIFY.
> - change QUARANTINE_FRACTION to reduce quarantine size.
> - change the qlist order in order to find the newest object in quarantine
> - reduce the number of calling kmalloc() from 2 to 1 time.
> - remove global variable to use argument to pass it.
> - correct the amount of qobject cache->size into the byes of qlist_head.
> - only use kasan_cache_shrink() to shink memory.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>  include/linux/kasan.h  |   4 ++
>  lib/Kconfig.kasan      |   9 +++
>  mm/kasan/Makefile      |   1 +
>  mm/kasan/common.c      |   4 +-
>  mm/kasan/kasan.h       |  50 +++++++++++++-
>  mm/kasan/quarantine.c  | 146 ++++++++++++++++++++++++++++++++++++-----
>  mm/kasan/report.c      |  37 +++++++----
>  mm/kasan/tags.c        |  47 +++++++++++++
>  mm/kasan/tags_report.c |   8 ++-
>  mm/slub.c              |   2 +-
>  10 files changed, 273 insertions(+), 35 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b40ea104dd36..be0667225b58 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -164,7 +164,11 @@ void kasan_cache_shutdown(struct kmem_cache *cache);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +void kasan_cache_shrink(struct kmem_cache *cache);
> +#else

Please restructure the code so that we don't duplicate this function
name 3 times in this header.

>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
> +#endif
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>
>  #endif /* CONFIG_KASAN_GENERIC */
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 9950b660e62d..17a4952c5eee 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -134,6 +134,15 @@ config KASAN_S390_4_LEVEL_PAGING
>           to 3TB of RAM with KASan enabled). This options allows to force
>           4-level paging instead.
>
> +config KASAN_SW_TAGS_IDENTIFY
> +       bool "Enable memory corruption idenitfication"

s/idenitfication/identification/

> +       depends on KASAN_SW_TAGS
> +       help
> +         Now tag-based KASAN bug report always shows invalid-access error, This
> +         options can identify it whether it is use-after-free or out-of-bound.
> +         This will make it easier for programmers to see the memory corruption
> +         problem.

This description looks like a change description, i.e. it describes
the current behavior and how it changes. I think code comments should
not have such, they should describe the current state of the things.
It should also mention the trade-off, otherwise it raises reasonable
questions like "why it's not enabled by default?" and "why do I ever
want to not enable it?".
I would do something like:

This option enables best-effort identification of bug type
(use-after-free or out-of-bounds)
at the cost of increased memory consumption for object quarantine.




> +
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
>         depends on m && KASAN
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 5d1065efbd47..d8540e5070cb 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -19,3 +19,4 @@ CFLAGS_tags.o := $(call cc-option, -fno-conserve-stack -fno-stack-protector)
>  obj-$(CONFIG_KASAN) := common.o init.o report.o
>  obj-$(CONFIG_KASAN_GENERIC) += generic.o generic_report.o quarantine.o
>  obj-$(CONFIG_KASAN_SW_TAGS) += tags.o tags_report.o
> +obj-$(CONFIG_KASAN_SW_TAGS_IDENTIFY) += quarantine.o
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 80bbe62b16cd..e309fbbee831 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -81,7 +81,7 @@ static inline depot_stack_handle_t save_stack(gfp_t flags)
>         return depot_save_stack(&trace, flags);
>  }
>
> -static inline void set_track(struct kasan_track *track, gfp_t flags)
> +void set_track(struct kasan_track *track, gfp_t flags)

If you make it non-static, it should get kasan_ prefix. The name is too generic.


>  {
>         track->pid = current->pid;
>         track->stack = save_stack(flags);
> @@ -457,7 +457,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                 return false;
>
>         set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAIT);
> -       quarantine_put(get_free_info(cache, object), cache);
> +       quarantine_put(get_free_info(cache, tagged_object), cache);
>
>         return IS_ENABLED(CONFIG_KASAN_GENERIC);
>  }
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 3e0c11f7d7a1..1be04abe2e0d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -98,6 +98,12 @@ struct kasan_alloc_meta {
>  struct qlist_node {
>         struct qlist_node *next;
>  };
> +struct qlist_object {
> +       unsigned long addr;
> +       unsigned int size;
> +       struct kasan_track free_track;
> +       struct qlist_node qnode;
> +};
>  struct kasan_free_meta {
>         /* This field is used while the object is in the quarantine.
>          * Otherwise it might be used for the allocator freelist.
> @@ -133,11 +139,12 @@ void kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip);
>
> -#if defined(CONFIG_KASAN_GENERIC) && \
> -       (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
> +#if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS_IDENTIFY)) \
> +       && (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
>  void quarantine_reduce(void);
>  void quarantine_remove_cache(struct kmem_cache *cache);
> +void set_track(struct kasan_track *track, gfp_t flags);
>  #else
>  static inline void quarantine_put(struct kasan_free_meta *info,
>                                 struct kmem_cache *cache) { }
> @@ -151,6 +158,31 @@ void print_tags(u8 addr_tag, const void *addr);
>
>  u8 random_tag(void);
>
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +bool quarantine_find_object(void *object,
> +               struct kasan_track *free_track);
> +
> +struct qlist_object *qobject_create(struct kasan_free_meta *info,
> +               struct kmem_cache *cache);
> +
> +void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache);
> +#else
> +static inline bool quarantine_find_object(void *object,
> +               struct kasan_track *free_track)
> +{
> +       return false;
> +}
> +
> +static inline struct qlist_object *qobject_create(struct kasan_free_meta *info,
> +               struct kmem_cache *cache)
> +{
> +       return NULL;
> +}
> +
> +static inline void qobject_free(struct qlist_node *qlink,
> +               struct kmem_cache *cache) {}
> +#endif
> +
>  #else
>
>  static inline void print_tags(u8 addr_tag, const void *addr) { }
> @@ -160,6 +192,20 @@ static inline u8 random_tag(void)
>         return 0;
>  }
>
> +static inline bool quarantine_find_object(void *object,


Please restructure the code so that we don't duplicate this function
name 3 times in this header.

> +               struct kasan_track *free_track)
> +{
> +       return false;
> +}
> +
> +static inline struct qlist_object *qobject_create(struct kasan_free_meta *info,
> +               struct kmem_cache *cache)
> +{
> +       return NULL;
> +}
> +
> +static inline void qobject_free(struct qlist_node *qlink,
> +               struct kmem_cache *cache) {}
>  #endif
>
>  #ifndef arch_kasan_set_tag
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 978bc4a3eb51..43b009659d80 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -61,12 +61,16 @@ static void qlist_init(struct qlist_head *q)
>  static void qlist_put(struct qlist_head *q, struct qlist_node *qlink,
>                 size_t size)
>  {
> -       if (unlikely(qlist_empty(q)))
> +       struct qlist_node *prev_qlink = q->head;
> +
> +       if (unlikely(qlist_empty(q))) {
>                 q->head = qlink;
> -       else
> -               q->tail->next = qlink;
> -       q->tail = qlink;
> -       qlink->next = NULL;
> +               q->tail = qlink;
> +               qlink->next = NULL;
> +       } else {
> +               q->head = qlink;
> +               qlink->next = prev_qlink;
> +       }
>         q->bytes += size;
>  }
>
> @@ -121,7 +125,11 @@ static unsigned long quarantine_batch_size;
>   * Quarantine doesn't support memory shrinker with SLAB allocator, so we keep
>   * the ratio low to avoid OOM.
>   */
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#define QUARANTINE_FRACTION 128

Explain in a comment why we use lower value for sw tags mode.

> +#else
>  #define QUARANTINE_FRACTION 32
> +#endif
>
>  static struct kmem_cache *qlink_to_cache(struct qlist_node *qlink)
>  {
> @@ -139,16 +147,24 @@ static void *qlink_to_object(struct qlist_node *qlink, struct kmem_cache *cache)
>
>  static void qlink_free(struct qlist_node *qlink, struct kmem_cache *cache)
>  {
> -       void *object = qlink_to_object(qlink, cache);
>         unsigned long flags;
> +       struct kmem_cache *obj_cache;
> +       void *object;
>
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_save(flags);
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> +               qobject_free(qlink, cache);
> +       } else {
> +               obj_cache = cache ? cache :     qlink_to_cache(qlink);
> +               object = qlink_to_object(qlink, obj_cache);
>
> -       ___cache_free(cache, object, _THIS_IP_);
> +               if (IS_ENABLED(CONFIG_SLAB))
> +                       local_irq_save(flags);
>
> -       if (IS_ENABLED(CONFIG_SLAB))
> -               local_irq_restore(flags);
> +               ___cache_free(obj_cache, object, _THIS_IP_);
> +
> +               if (IS_ENABLED(CONFIG_SLAB))
> +                       local_irq_restore(flags);
> +       }
>  }
>
>  static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
> @@ -160,11 +176,9 @@ static void qlist_free_all(struct qlist_head *q, struct kmem_cache *cache)
>
>         qlink = q->head;
>         while (qlink) {
> -               struct kmem_cache *obj_cache =
> -                       cache ? cache : qlink_to_cache(qlink);
>                 struct qlist_node *next = qlink->next;
>
> -               qlink_free(qlink, obj_cache);
> +               qlink_free(qlink, cache);
>                 qlink = next;
>         }
>         qlist_init(q);
> @@ -175,6 +189,8 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>         unsigned long flags;
>         struct qlist_head *q;
>         struct qlist_head temp = QLIST_INIT;
> +       struct kmem_cache *qobject_cache;
> +       struct qlist_object *free_obj_info;
>
>         /*
>          * Note: irq must be disabled until after we move the batch to the
> @@ -187,7 +203,19 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>         local_irq_save(flags);
>
>         q = this_cpu_ptr(&cpu_quarantine);
> -       qlist_put(q, &info->quarantine_link, cache->size);
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> +               free_obj_info = qobject_create(info, cache);
> +               if (!free_obj_info) {
> +                       local_irq_restore(flags);
> +                       return;
> +               }
> +
> +               qobject_cache = qlink_to_cache(&free_obj_info->qnode);
> +               qlist_put(q, &free_obj_info->qnode, qobject_cache->size);

We could use sizeof(*free_obj_info), which looks simpler. Any reason
to do another hop through the cache?

> +       } else {
> +               qlist_put(q, &info->quarantine_link, cache->size);
> +       }
> +
>         if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
>                 qlist_move_all(q, &temp);
>
> @@ -220,7 +248,6 @@ void quarantine_reduce(void)
>         if (likely(READ_ONCE(quarantine_size) <=
>                    READ_ONCE(quarantine_max_size)))
>                 return;
> -
>         /*
>          * srcu critical section ensures that quarantine_remove_cache()
>          * will not miss objects belonging to the cache while they are in our
> @@ -327,3 +354,90 @@ void quarantine_remove_cache(struct kmem_cache *cache)
>
>         synchronize_srcu(&remove_cache_srcu);
>  }
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +static noinline bool qlist_find_object(struct qlist_head *from, void *arg)
> +{
> +       struct qlist_node *curr;
> +       struct qlist_object *curr_obj;
> +       struct qlist_object *target = (struct qlist_object *)arg;
> +
> +       if (unlikely(qlist_empty(from)))
> +               return false;
> +
> +       curr = from->head;
> +       while (curr) {
> +               struct qlist_node *next = curr->next;
> +
> +               curr_obj = container_of(curr, struct qlist_object, qnode);
> +               if (unlikely((target->addr >= curr_obj->addr) &&
> +                       (target->addr < (curr_obj->addr + curr_obj->size)))) {
> +                       target->free_track = curr_obj->free_track;
> +                       return true;
> +               }
> +
> +               curr = next;
> +       }
> +       return false;
> +}
> +
> +static noinline int per_cpu_find_object(void *arg)
> +{
> +       struct qlist_head *q;
> +
> +       q = this_cpu_ptr(&cpu_quarantine);
> +       return qlist_find_object(q, arg);
> +}
> +
> +struct cpumask cpu_allowed_mask __read_mostly;
> +
> +bool quarantine_find_object(void *addr, struct kasan_track *free_track)
> +{
> +       unsigned long flags;
> +       bool find = false;
> +       int cpu, i;
> +       struct qlist_object target;
> +
> +       target.addr = (unsigned long)addr;
> +
> +       cpumask_copy(&cpu_allowed_mask, cpu_online_mask);
> +       for_each_cpu(cpu, &cpu_allowed_mask) {
> +               find = smp_call_on_cpu(cpu, per_cpu_find_object,
> +                               (void *)&target, true);
> +               if (find) {
> +                       if (free_track)
> +                               *free_track = target.free_track;
> +                       return true;
> +               }
> +       }
> +
> +       raw_spin_lock_irqsave(&quarantine_lock, flags);
> +       for (i = quarantine_tail; i >= 0; i--) {
> +               if (qlist_empty(&global_quarantine[i]))
> +                       continue;
> +               find = qlist_find_object(&global_quarantine[i],
> +                               (void *)&target);
> +               if (find) {
> +                       if (free_track)
> +                               *free_track = target.free_track;
> +                       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> +                       return true;
> +               }
> +       }
> +       for (i = QUARANTINE_BATCHES-1; i > quarantine_tail; i--) {

Find a way to calculate the right index using a single loop, rather
that copy-paste the whole loop body to do a small adjustment to index.

> +               if (qlist_empty(&global_quarantine[i]))
> +                       continue;
> +               find = qlist_find_object(&global_quarantine[i],
> +                               (void *)&target);
> +               if (find) {
> +                       if (free_track)
> +                               *free_track = target.free_track;
> +                       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> +                       return true;
> +               }
> +       }
> +       raw_spin_unlock_irqrestore(&quarantine_lock, flags);
> +
> +       return false;
> +}
> +#endif
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index ca9418fe9232..3cbc24cd3d43 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -150,18 +150,27 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>  }
>
>  static void describe_object(struct kmem_cache *cache, void *object,
> -                               const void *addr)
> +                               const void *tagged_addr)
>  {
> +       void *untagged_addr = reset_tag(tagged_addr);
>         struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
> +       struct kasan_track free_track;
>
>         if (cache->flags & SLAB_KASAN) {
> -               print_track(&alloc_info->alloc_track, "Allocated");
> -               pr_err("\n");
> -               print_track(&alloc_info->free_track, "Freed");
> -               pr_err("\n");
> +               if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY) &&
> +                       quarantine_find_object((void *)tagged_addr,
> +                               &free_track)) {
> +                       print_track(&free_track, "Freed");
> +                       pr_err("\n");
> +               } else {
> +                       print_track(&alloc_info->alloc_track, "Allocated");
> +                       pr_err("\n");
> +                       print_track(&alloc_info->free_track, "Freed");
> +                       pr_err("\n");
> +               }
>         }
>
> -       describe_object_addr(cache, object, addr);
> +       describe_object_addr(cache, object, untagged_addr);
>  }
>
>  static inline bool kernel_or_module_addr(const void *addr)
> @@ -180,23 +189,25 @@ static inline bool init_task_stack_addr(const void *addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> -static void print_address_description(void *addr)
> +static void print_address_description(void *tagged_addr)
>  {
> -       struct page *page = addr_to_page(addr);
> +       void *untagged_addr = reset_tag(tagged_addr);
> +       struct page *page = addr_to_page(untagged_addr);
>
>         dump_stack();
>         pr_err("\n");
>
>         if (page && PageSlab(page)) {
>                 struct kmem_cache *cache = page->slab_cache;
> -               void *object = nearest_obj(cache, page, addr);
> +               void *object = nearest_obj(cache, page, untagged_addr);
>
> -               describe_object(cache, object, addr);
> +               describe_object(cache, object, tagged_addr);
>         }
>
> -       if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
> +       if (kernel_or_module_addr(untagged_addr) &&
> +                       !init_task_stack_addr(untagged_addr)) {
>                 pr_err("The buggy address belongs to the variable:\n");
> -               pr_err(" %pS\n", addr);
> +               pr_err(" %pS\n", untagged_addr);
>         }
>
>         if (page) {
> @@ -314,7 +325,7 @@ void kasan_report(unsigned long addr, size_t size,
>         pr_err("\n");
>
>         if (addr_has_shadow(untagged_addr)) {
> -               print_address_description(untagged_addr);
> +               print_address_description(tagged_addr);
>                 pr_err("\n");
>                 print_shadow_for_address(info.first_bad_addr);
>         } else {
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index 63fca3172659..7804b48f760e 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -124,6 +124,53 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
>         }
>  }
>
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +void kasan_cache_shrink(struct kmem_cache *cache)
> +{
> +       quarantine_remove_cache(cache);

This does not look to be necessary. There are no objects from that
cache in the quarantine in general. Let's not over-complicate this.



> +}
> +
> +struct qlist_object *qobject_create(struct kasan_free_meta *info,
> +                                               struct kmem_cache *cache)
> +{
> +       struct qlist_object *qobject_info;
> +       void *object;
> +
> +       object = ((void *)info) - cache->kasan_info.free_meta_offset;
> +       qobject_info = kmalloc(sizeof(struct qlist_object), GFP_NOWAIT);
> +       if (!qobject_info)
> +               return NULL;
> +       qobject_info->addr = (unsigned long) object;
> +       qobject_info->size = cache->object_size;
> +       set_track(&qobject_info->free_track, GFP_NOWAIT);
> +
> +       return qobject_info;
> +}
> +
> +static struct kmem_cache *qobject_to_cache(struct qlist_object *qobject)
> +{
> +       return virt_to_head_page(qobject)->slab_cache;

This looks identical to the existing qlink_to_cache, please use the
existing function.

> +}
> +
> +void qobject_free(struct qlist_node *qlink, struct kmem_cache *cache)
> +{
> +       struct qlist_object *qobject = container_of(qlink,
> +                       struct qlist_object, qnode);
> +       unsigned long flags;
> +
> +       struct kmem_cache *qobject_cache =
> +                       cache ? cache : qobject_to_cache(qobject);

I don't understand this part.
Will caller ever pass us the right cache? Or cache is always NULL? If
it's always NULL, why do we accept it at all?
We also allocate qobjects with kmalloc always, so we must use kfree,
why do we even mess with caches?


> +
> +       if (IS_ENABLED(CONFIG_SLAB))
> +               local_irq_save(flags);
> +
> +       ___cache_free(qobject_cache, (void *)qobject, _THIS_IP_);
> +
> +       if (IS_ENABLED(CONFIG_SLAB))
> +               local_irq_restore(flags);
> +}
> +#endif
> +
>  #define DEFINE_HWASAN_LOAD_STORE(size)                                 \
>         void __hwasan_load##size##_noabort(unsigned long addr)          \
>         {                                                               \
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 8eaf5f722271..63b0b1f381ff 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,7 +36,13 @@
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> -       return "invalid-access";
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_IDENTIFY)) {
> +               if (quarantine_find_object((void *)info->access_addr, NULL))
> +                       return "use-after-free";
> +               else
> +                       return "out-of-bounds";
> +       } else
> +               return "invalid-access";
>  }
>
>  void *find_first_bad_addr(void *addr, size_t size)
> diff --git a/mm/slub.c b/mm/slub.c
> index 1b08fbcb7e61..751429d02846 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -3004,7 +3004,7 @@ static __always_inline void slab_free(struct kmem_cache *s, struct page *page,
>                 do_slab_free(s, page, head, tail, cnt, addr);
>  }
>
> -#ifdef CONFIG_KASAN_GENERIC
> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS_IDENTIFY)
>  void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
>  {
>         do_slab_free(cache, virt_to_head_page(x), x, NULL, 1, addr);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY9_85YB8CCwmKerDWc45Z00hMd6Pc-STEbr0cmYSqnoA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
