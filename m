Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJMZXLVQKGQEWHIZOBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A2E7DA6D53
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 17:54:14 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id n6sf14293192ybf.19
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 08:54:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567526053; cv=pass;
        d=google.com; s=arc-20160816;
        b=lwNOOW24dUzjCgevSu4be7q8aMouADx2Vd9NzNrJqkSISdw7SGak6h7/EiSNH8z8Ce
         vJHrhE/eXr9i2usVmem9SX8HGAO8uI7mqi2V5tM8Lu5DpPqiYQvUThhP/8wwdsKY72fd
         qBJ84z5G0Lv0eJxK2q1AUDhiyBx2yFEAcKVZCz2/1U4ggGMgByT2CJ1Ov9FEdRKmFR6R
         A4tZ3vfxLQUWblOETjmQmdDprnR6JAbCTZArUCV/g1nyNWTqEqx/zcpzezL9+e0PUWAg
         IHcAVEv/7i9Lxv0LYeAyK5KrrFRe9NHcXtQU3sQ/PDGfjWvcaYiuFga7U9Gv3coAayTe
         qexA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ANXmixdC0V/eDZs66JPYFKgOYKKrInbWdIK6b6H34kw=;
        b=QtdljPGRosahQlVMzeJZm4nS9NDM4IqtRUUiKrq+htbNdtDm/u9qkWQ74VYJOkGZS7
         cmrZoii3Kn4o8SHBnG1idKmxa+PGZB5c28ybIpngTz4pQn2u1XOIEp8IU1Rm+B1cOyfo
         UQiSQuu5KnJj1nz+nwgOIVNbJZu5KKsN5yq/cD2IpeV1nLPP8kPeoJbN+xguLrvDz5xo
         nHmjbd3/niZLzQ0Xk1AhjP9EiDXpClU61eEdSncqj0gw0X8Dz1gBtdOhKupkSoKue3V+
         Hgc724EkVESo7uevJEQWzqdeaUNUntI54ubQXWayb0i7EQSOuxVg1K4/RolGWgTAhr1y
         Apjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ikgeVUo3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ANXmixdC0V/eDZs66JPYFKgOYKKrInbWdIK6b6H34kw=;
        b=PPgNJEQ1w0M/gYMXkPm/cxUzteduTMDEbpDUZcVkIg4tvIVMRfKJtj6zyueO/BnWjL
         ltXvmXIaydFkpRx/kfMRLTMJENSa25pSV/vpa2qK6MzPdjG7XupvIinKOGfAw/HUyNrQ
         7/RHu0xotDKhZVElOsqwdcw0vlCLD3QQ0S5v9KNNUo76z9LZFc0VICXF1msCMqltgr1U
         /akioCdMSrdojHpt2XEz1D5ymToHijwL2w6ttcGv3ilYVEoUp2/jr3Nc8SvLnupTrhJB
         u4yfK4PTNoUDlT4Z2s7W1XjPu1ONeVr6T/TgXQVCQQAi6lC9Hjopm+pcZJUjZiFiIlYj
         zy2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ANXmixdC0V/eDZs66JPYFKgOYKKrInbWdIK6b6H34kw=;
        b=IuOLotxypTWZjebC9wZnjEdy7Zgj3phTjgfernqb4AnORc6aarxwwsDGsKJ1NOajqr
         1IOYrt0JZP5CTRyhIbPz3h3zZ/Ne9IAAR41thXuPRfNpbtQJrjmclE3MNfqPNhTXKFVa
         diVzOp0ufsq742ypWeu7/V7cMcFtrIbI6PTsYDTzi+i1QNY9FAUzk8ar0SRYHnoDZ117
         21F9L2XV9TBX2FYdpycQlCwomEccSnUmUoWIh+4hc5K/o8R0FpBgegIepMfbjxCk1PAb
         +9/OWyFRfFyMFxGLuSHTeUG+n42MIRhcHDTQdL5565e8bJX3C9gDvlGboe2LuxuJOT4D
         9hYQ==
X-Gm-Message-State: APjAAAVJJQ+V2WYrhgvyRSS7jc5m5p8waPTLFU45zW55uvQcXjBvIdA+
	b/XuEY4NcLGCLcAZZoNt7Dc=
X-Google-Smtp-Source: APXvYqxdpuQJyY3ONQVwZv4E2B8LfRMtQf5AvDnn95olEHXOLlkBfSXHKFSVbIAUfvZfWXVhf05gAQ==
X-Received: by 2002:a25:c708:: with SMTP id w8mr11126046ybe.358.1567526053685;
        Tue, 03 Sep 2019 08:54:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:42c8:: with SMTP id p191ls2416479yba.4.gmail; Tue, 03
 Sep 2019 08:54:13 -0700 (PDT)
X-Received: by 2002:a25:d345:: with SMTP id e66mr25747516ybf.251.1567526053398;
        Tue, 03 Sep 2019 08:54:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567526053; cv=none;
        d=google.com; s=arc-20160816;
        b=opDiMSexbzj3o9a/k0ax2SL0/US/TqtpEMimb3xBn1iGnZoqf5EJe+AQeS1GLUQYl3
         zLAgsORMQU5Qp6lhTJxa6f0kY3XA9zqVkHbA2VaUMYHaetTSfnrUGzBlvUMLsqzUBBBC
         kexfPuN0de7N7bNL/LLo4PU2By2zmQqOovAFA/oulLqvpjjoYgv56VRSw6st2d13XSeC
         TiGllGAJbBM0IFKZ70C4YuyLYYhkdBZjmXGwRBdbvMSpIT1mOiyAl2QBzRFuELhhkNwA
         QsW+046KjT35khQVYVGUPgvfsiPeZHIctIj7TFYfA65K2XpxZFz5ch9xWFp1MrvR5PcE
         Gb6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i2XyPuhqSIg3qjxxxx2GWzZfZ8oeUSUoF9dv9bk32A8=;
        b=Gf7vPn3tOQI2/Aa2V+Q6koR1Tz5pz0Nf3IB84YIZGSk3xCF7sKq6iy7AUFb1RbQUSU
         +xje+r8QzsLHugTitcdllquWX1E7DPL2br7HBzzXlVmsvZShAktPrFcdN5JxShb/Fq+M
         V/oIFh8XQyd/hae6gfbgARQrrzR26seJ65ysBSdyp0geii+fE0cyxRImx2mrElmP28W4
         RP/T9Y/JrIBBUB4iVVD9X4b+DFNnczlgxZLZav5q1MX+/aFiP7WpP9xiF/tNYTRPehIn
         HOFy2355Xiy02dwlRl5QQ2rceLMkFbnga3Om6zg6usPODRJ5W725tb0VxtRfoq049RWb
         UeDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ikgeVUo3;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id c76si1067875ybf.3.2019.09.03.08.54.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 08:54:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id y9so11047570pfl.4
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 08:54:13 -0700 (PDT)
X-Received: by 2002:a62:db84:: with SMTP id f126mr15457590pfg.25.1567526052507;
 Tue, 03 Sep 2019 08:54:12 -0700 (PDT)
MIME-Version: 1.0
References: <20190821180332.11450-1-aryabinin@virtuozzo.com>
In-Reply-To: <20190821180332.11450-1-aryabinin@virtuozzo.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Sep 2019 17:54:01 +0200
Message-ID: <CAAeHK+xO-gcep1DbuJKqZy4j=aQKukvvJZ=OQYivqCmwXB5dqA@mail.gmail.com>
Subject: Re: [PATCH v5] kasan: add memory corruption identification for
 software tag-based mode
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Walter Wu <walter-zh.wu@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ikgeVUo3;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Aug 21, 2019 at 8:03 PM Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>
> From: Walter Wu <walter-zh.wu@mediatek.com>
>
> This patch adds memory corruption identification at bug report for
> software tag-based mode, the report show whether it is "use-after-free"
> or "out-of-bound" error instead of "invalid-access" error. This will make
> it easier for programmers to see the memory corruption problem.
>
> We extend the slab to store five old free pointer tag and free backtrace,
> we can check if the tagged address is in the slab record and make a
> good guess if the object is more like "use-after-free" or "out-of-bound".
> therefore every slab memory corruption can be identified whether it's
> "use-after-free" or "out-of-bound".
>
> [aryabinin@virtuozzo.com: simplify & clenup code:
>   https://lkml.kernel.org/r/3318f9d7-a760-3cc8-b700-f06108ae745f@virtuozzo.com]
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> ---
>
> ====== Changes
> Change since v1:
> - add feature option CONFIG_KASAN_SW_TAGS_IDENTIFY.
> - change QUARANTINE_FRACTION to reduce quarantine size.
> - change the qlist order in order to find the newest object in quarantine
> - reduce the number of calling kmalloc() from 2 to 1 time.
> - remove global variable to use argument to pass it.
> - correct the amount of qobject cache->size into the byes of qlist_head.
> - only use kasan_cache_shrink() to shink memory.
>
> Change since v2:
> - remove the shinking memory function kasan_cache_shrink()
> - modify the description of the CONFIG_KASAN_SW_TAGS_IDENTIFY
> - optimize the quarantine_find_object() and qobject_free()
> - fix the duplicating function name 3 times in the header.
> - modify the function name set_track() to kasan_set_track()
>
> Change since v3:
> - change tag-based quarantine to extend slab to identify memory corruption
>
> Changes since v4:
>  - Simplify and cleanup code.
>
>  lib/Kconfig.kasan      |  8 ++++++++
>  mm/kasan/common.c      | 22 +++++++++++++++++++--
>  mm/kasan/kasan.h       | 14 +++++++++++++-
>  mm/kasan/report.c      | 44 ++++++++++++++++++++++++++++++++----------
>  mm/kasan/tags_report.c | 24 +++++++++++++++++++++++
>  5 files changed, 99 insertions(+), 13 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 7fa97a8b5717..6c9682ce0254 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -134,6 +134,14 @@ config KASAN_S390_4_LEVEL_PAGING
>           to 3TB of RAM with KASan enabled). This options allows to force
>           4-level paging instead.
>
> +config KASAN_SW_TAGS_IDENTIFY
> +       bool "Enable memory corruption identification"
> +       depends on KASAN_SW_TAGS
> +       help
> +         This option enables best-effort identification of bug type
> +         (use-after-free or out-of-bounds) at the cost of increased
> +         memory consumption.
> +
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
>         depends on m && KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 3b8cde0cb5b2..6814d6d6a023 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -304,7 +304,6 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
>  struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
>                                         const void *object)
>  {
> -       BUILD_BUG_ON(sizeof(struct kasan_alloc_meta) > 32);
>         return (void *)object + cache->kasan_info.alloc_meta_offset;
>  }
>
> @@ -315,6 +314,24 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
>         return (void *)object + cache->kasan_info.free_meta_offset;
>  }
>
> +
> +static void kasan_set_free_info(struct kmem_cache *cache,
> +               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       u8 idx = 0;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       idx = alloc_meta->free_track_idx;
> +       alloc_meta->free_pointer_tag[idx] = tag;
> +       alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> +#endif
> +
> +       set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> +}
> +
>  void kasan_poison_slab(struct page *page)
>  {
>         unsigned long i;
> @@ -451,7 +468,8 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>                         unlikely(!(cache->flags & SLAB_KASAN)))
>                 return false;
>
> -       set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAIT);
> +       kasan_set_free_info(cache, object, tag);
> +
>         quarantine_put(get_free_info(cache, object), cache);
>
>         return IS_ENABLED(CONFIG_KASAN_GENERIC);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 014f19e76247..35cff6bbb716 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -95,9 +95,19 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#define KASAN_NR_FREE_STACKS 5
> +#else
> +#define KASAN_NR_FREE_STACKS 1
> +#endif
> +
>  struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
> -       struct kasan_track free_track;
> +       struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> +       u8 free_track_idx;
> +#endif
>  };
>
>  struct qlist_node {
> @@ -146,6 +156,8 @@ void kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip);
>
> +struct page *kasan_addr_to_page(const void *addr);
> +
>  #if defined(CONFIG_KASAN_GENERIC) && \
>         (defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
>  void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0e5f965f1882..621782100eaa 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -111,7 +111,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
>         }
>  }
>
> -static struct page *addr_to_page(const void *addr)
> +struct page *kasan_addr_to_page(const void *addr)
>  {
>         if ((addr >= (void *)PAGE_OFFSET) &&
>                         (addr < high_memory))
> @@ -151,15 +151,38 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
>                 (void *)(object_addr + cache->object_size));
>  }
>
> +static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> +               void *object, u8 tag)
> +{
> +       struct kasan_alloc_meta *alloc_meta;
> +       int i = 0;
> +
> +       alloc_meta = get_alloc_info(cache, object);
> +
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> +               if (alloc_meta->free_pointer_tag[i] == tag)
> +                       break;
> +       }
> +       if (i == KASAN_NR_FREE_STACKS)
> +               i = alloc_meta->free_track_idx;
> +#endif
> +
> +       return &alloc_meta->free_track[i];
> +}
> +
>  static void describe_object(struct kmem_cache *cache, void *object,
> -                               const void *addr)
> +                               const void *addr, u8 tag)
>  {
>         struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
>
>         if (cache->flags & SLAB_KASAN) {
> +               struct kasan_track *free_track;
> +
>                 print_track(&alloc_info->alloc_track, "Allocated");
>                 pr_err("\n");
> -               print_track(&alloc_info->free_track, "Freed");
> +               free_track = kasan_get_free_track(cache, object, tag);
> +               print_track(free_track, "Freed");
>                 pr_err("\n");
>         }
>
> @@ -344,9 +367,9 @@ static void print_address_stack_frame(const void *addr)
>         print_decoded_frame_descr(frame_descr);
>  }
>
> -static void print_address_description(void *addr)
> +static void print_address_description(void *addr, u8 tag)
>  {
> -       struct page *page = addr_to_page(addr);
> +       struct page *page = kasan_addr_to_page(addr);
>
>         dump_stack();
>         pr_err("\n");
> @@ -355,7 +378,7 @@ static void print_address_description(void *addr)
>                 struct kmem_cache *cache = page->slab_cache;
>                 void *object = nearest_obj(cache, page, addr);
>
> -               describe_object(cache, object, addr);
> +               describe_object(cache, object, addr, tag);
>         }
>
>         if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
> @@ -435,13 +458,14 @@ static bool report_enabled(void)
>  void kasan_report_invalid_free(void *object, unsigned long ip)
>  {
>         unsigned long flags;
> +       u8 tag = get_tag(object);
>
> +       object = reset_tag(object);
>         start_report(&flags);
>         pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
> -       print_tags(get_tag(object), reset_tag(object));
> -       object = reset_tag(object);
> +       print_tags(tag, object);
>         pr_err("\n");
> -       print_address_description(object);
> +       print_address_description(object, tag);
>         pr_err("\n");
>         print_shadow_for_address(object);
>         end_report(&flags);
> @@ -479,7 +503,7 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
>         pr_err("\n");
>
>         if (addr_has_shadow(untagged_addr)) {
> -               print_address_description(untagged_addr);
> +               print_address_description(untagged_addr, get_tag(tagged_addr));
>                 pr_err("\n");
>                 print_shadow_for_address(info.first_bad_addr);
>         } else {
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> index 8eaf5f722271..969ae08f59d7 100644
> --- a/mm/kasan/tags_report.c
> +++ b/mm/kasan/tags_report.c
> @@ -36,6 +36,30 @@
>
>  const char *get_bug_type(struct kasan_access_info *info)
>  {
> +#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +       struct kasan_alloc_meta *alloc_meta;
> +       struct kmem_cache *cache;
> +       struct page *page;
> +       const void *addr;
> +       void *object;
> +       u8 tag;
> +       int i;
> +
> +       tag = get_tag(info->access_addr);
> +       addr = reset_tag(info->access_addr);
> +       page = kasan_addr_to_page(addr);
> +       if (page && PageSlab(page)) {
> +               cache = page->slab_cache;
> +               object = nearest_obj(cache, page, (void *)addr);
> +               alloc_meta = get_alloc_info(cache, object);
> +
> +               for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
> +                       if (alloc_meta->free_pointer_tag[i] == tag)
> +                               return "use-after-free";
> +               return "out-of-bounds";

I think we should keep the "invalid-access" bug type here if we failed
to identify the bug as a "use-after-free" (and change the patch
description accordingly).

Other than that:

Acked-by: Andrey Konovalov <andreyknvl@google.com>

> +       }
> +
> +#endif
>         return "invalid-access";
>  }
>
> --
> 2.21.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxO-gcep1DbuJKqZy4j%3DaQKukvvJZ%3DOQYivqCmwXB5dqA%40mail.gmail.com.
