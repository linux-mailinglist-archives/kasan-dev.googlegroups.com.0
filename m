Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIGZ7GQQMGQEFBMQIFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8ACE16E5E4B
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 12:10:41 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-32b62107509sf6948855ab.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 03:10:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681812640; cv=pass;
        d=google.com; s=arc-20160816;
        b=rDD9N+Mg7H5GuHWWcTQRcCA3OagtnVEevDGuxtAr7u8QO5D3IIcRtBXujgv6d5qAfv
         niZEqPbgkdOwIHVf6jL5GD+kAMLia2W7Aiq59DZ5dnmgaKrbRt/S1i6mQ4x4kA38FxAh
         5FaDhjPc+t9tQPDds05tVbV+lIMl2cz3N4vuLb6AZH+lugU3elxEobxCOtTtk9Ivkspk
         g9YzPOXmdkSMeoQQ3OXWA7LFPOm+3KxPQX9Y42N6Hd+I5NQwFiwPRSil5O2Oz84iLLU+
         qkG1DaZ+aqcM+18H0PUrZFHlgQo9rTpS7WfsVAQ2DZ0GlEeyfcImNYQV5dAltn30Qmi4
         c3Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HkkGsAM3OQhhOGa/FxozUsBy1w1sx2IM4oiKnL1JK+0=;
        b=mtQw/OUy5So9yTZU2wQ2auHj6zPeFcH1X7R3RqJJnYxfMjzgkkUx0bYkcNKyS0E91p
         RR6Sgz/Z1NX9H6Ls+kfVivESV1XKngfPIabb/YWQIU3WgOBW2EWCkMZNKqyEtHC8Uo8k
         Ao7EbVey5WARUNt1nh7EmxZMsirxpYUgPw53vYlC9De+HQRY+/3xBfAO4Kz4U5vcMXU9
         tD42/qOM+sJPGZEJTkxSB7eaE9LHcPU97r4+TvpA0haknQuyBn1IRHsKWzVexb1JTaR6
         pVe/Q+M5bYtUnfk+IaH10V2YMSOfJblxuNbHfe7HpxNOyCsgNNwFI6NklpISpHo27v48
         xRXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=q6JfMBnu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681812640; x=1684404640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HkkGsAM3OQhhOGa/FxozUsBy1w1sx2IM4oiKnL1JK+0=;
        b=fui2SlWoqKILNxwzApP3OajO7TrGatJC7uYsKPWnTxcI7PLP56tqPpabpwinrnyuY3
         FcR7oAtJsrgr6WP+oLQRrKMbB19YJvKYbKxCfyrflNk9n3x6rho+tsIXLjiyte4PPY5Y
         BM2/pgl1oDxLs2i3W0PULONjrgHfh3/9p3nOTtELDKeCdkTXsAYA20u+s0o8yPnsAMKC
         /roZmnGcnhbev6d2g0oU5zXfbI0qIbbPG9rkN9QYEakGvVnvOQwHEflOQMqyNgsAOUx0
         hZOq5uBKz/A213fmnqneVJhaiMp5prB+jd8FHH3YIt/LlgzPXqErHYHwtc3lfNZ2pKek
         Dafg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681812640; x=1684404640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HkkGsAM3OQhhOGa/FxozUsBy1w1sx2IM4oiKnL1JK+0=;
        b=khIq5OqBekt9qhMGX/aIuuwhS7GhvXH82kSQ0oTJMyEhCYVZGZoVvNMUty32npO7dy
         4s4GzoGv7mgIRxwPaIkyVqtwf+fPEb82wgSLPS4SEwZfvMc9TrjuW8ELbEIcG9JeUu1e
         L++rdZ4BgCbUVsrGXCZglyNd0rTo/4e6Uv0c7thCXwCXPgIBZLrxod3b0cmzGMn7r/SC
         g+xVDa+orjdnpqDQyms1Ix/9W3Rvncg1Aaon5L1rnbblx08SNgcijGixbfliP2pEYwCg
         P+GNGpWcPumGSnxf/7L0ckI7bx7bPcE/gvWUodKOTBEjFBUQXBl8+enN1VvdHgQDGMee
         S7/A==
X-Gm-Message-State: AAQBX9c20q76urd6c0FEkjqDX/QnOfPulv3PswaRf8H+lgP3dj03ZvRA
	m80TabNBmpiopwTKGDFGZaY=
X-Google-Smtp-Source: AKy350aXP/epaFD39aniYWpZr5uLS9imtoz9ugDVDs6cLU+bFP70K6nwR+rzUlAyGo0zykaktjchpg==
X-Received: by 2002:a05:6e02:6c9:b0:328:7b75:a5fe with SMTP id p9-20020a056e0206c900b003287b75a5femr8459159ils.5.1681812640114;
        Tue, 18 Apr 2023 03:10:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:400b:b0:760:abd7:d605 with SMTP id
 bk11-20020a056602400b00b00760abd7d605ls1219900iob.0.-pod-prod-gmail; Tue, 18
 Apr 2023 03:10:39 -0700 (PDT)
X-Received: by 2002:a6b:ec1a:0:b0:763:5f51:aff7 with SMTP id c26-20020a6bec1a000000b007635f51aff7mr1393105ioh.5.1681812639555;
        Tue, 18 Apr 2023 03:10:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681812639; cv=none;
        d=google.com; s=arc-20160816;
        b=y0mMnionpXLaLlMgqoAt8/nzWspqZVwG3np5oy8ba0IaJwHcYDsznr1v/gDAuDOhmd
         s84kl1K72GWlaD9AnqU6rpEM8+7i3L51oO5wqhsanU8HQWfZZFlp6CQhrS34uDSmkydb
         9inP8yA6N9+SyrAw5/7O20dRCuB8B/yMnQCh9eBfXImsh3WERd+pb2DALr3ZYjHgwtx1
         MoFzc/Sv3YyrNdoKC53iC2CmLhp1yHwyLbpyZNVfCxRhqs1M/Sxyr9k1usYfOOcyM8KH
         uYsT7HvpZfKDivPvu5ZarakjDoK/2gHuIP1Fco1ibSendl0f7UdQ6NoefKDZks1vrKwF
         3xcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=galNuw/biFG4LXA5HDGOsFD5DzMSzVWuBOk2kSXMjaQ=;
        b=QCLE8zgNuqf8poowYvFlgHHg9Z+cQUXdFXrz4oVuHiVoYcYvFWKvMifRkf7aJo4bhl
         50U8PrQaaXLPasLEye3mHrveuFmd4aXSysMZp9lUmlk56yVRYLPV9mtVTYIb9KmexM1F
         RFrQsLRzcQFEEhwqxY4LEAKJgCFg7dq/I7Ym8WzYjaE234TeWZoLtmUZR5+OewM35Bsd
         iP/C9HFoOLN/Mj86BT4scHxniNd5wLKAUsG47N6Phu7gWWi+DVAgREsMqKpVPuICU4/F
         1sHQf8YtZwEQGykzQAKcvoIYtcvbuUsOkImnqZ8xtqqbZVnTjMgfKdtYMRypeobdRGeU
         KCrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=q6JfMBnu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id bb5-20020a056602380500b007624b031dc8si287716iob.0.2023.04.18.03.10.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 03:10:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id ca18e2360f4ac-760a5e0f752so50782439f.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 03:10:39 -0700 (PDT)
X-Received: by 2002:a6b:7210:0:b0:75d:b1:b718 with SMTP id n16-20020a6b7210000000b0075d00b1b718mr1205992ioc.9.1681812639142;
 Tue, 18 Apr 2023 03:10:39 -0700 (PDT)
MIME-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com>
In-Reply-To: <20230413131223.4135168-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 12:10:02 +0200
Message-ID: <CANpmjNMd-p6ejwsMugOM84mkqcuLrXpNg1EUJTYRUsEtV1swpQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] mm: kmsan: handle alloc failures in kmsan_vmap_pages_range_noflush()
To: Alexander Potapenko <glider@google.com>
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=q6JfMBnu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d2d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 13 Apr 2023 at 15:12, Alexander Potapenko <glider@google.com> wrote:
>
> As reported by Dipanjan Das, when KMSAN is used together with kernel
> fault injection (or, generally, even without the latter), calls to
> kcalloc() or __vmap_pages_range_noflush() may fail, leaving the
> metadata mappings for the virtual mapping in an inconsistent state.
> When these metadata mappings are accessed later, the kernel crashes.
>
> To address the problem, we return a non-zero error code from
> kmsan_vmap_pages_range_noflush() in the case of any allocation/mapping
> failure inside it, and make vmap_pages_range_noflush() return an error
> if KMSAN fails to allocate the metadata.
>
> This patch also removes KMSAN_WARN_ON() from vmap_pages_range_noflush(),
> as these allocation failures are not fatal anymore.
>
> Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
> Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
> Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Looks reasonable, thanks.

> ---
> v2:
>  -- return 0 from the inline version of kmsan_vmap_pages_range_noflush()
>     (spotted by kernel test robot <lkp@intel.com>)
> ---
>  include/linux/kmsan.h | 20 +++++++++++---------
>  mm/kmsan/shadow.c     | 27 ++++++++++++++++++---------
>  mm/vmalloc.c          |  6 +++++-
>  3 files changed, 34 insertions(+), 19 deletions(-)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index e38ae3c346184..c7ff3aefc5a13 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -134,11 +134,12 @@ void kmsan_kfree_large(const void *ptr);
>   * @page_shift:        page_shift passed to vmap_range_noflush().
>   *
>   * KMSAN maps shadow and origin pages of @pages into contiguous ranges in
> - * vmalloc metadata address range.
> + * vmalloc metadata address range. Returns 0 on success, callers must check
> + * for non-zero return value.
>   */
> -void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
> -                                   pgprot_t prot, struct page **pages,
> -                                   unsigned int page_shift);
> +int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
> +                                  pgprot_t prot, struct page **pages,
> +                                  unsigned int page_shift);
>
>  /**
>   * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
> @@ -281,12 +282,13 @@ static inline void kmsan_kfree_large(const void *ptr)
>  {
>  }
>
> -static inline void kmsan_vmap_pages_range_noflush(unsigned long start,
> -                                                 unsigned long end,
> -                                                 pgprot_t prot,
> -                                                 struct page **pages,
> -                                                 unsigned int page_shift)
> +static inline int kmsan_vmap_pages_range_noflush(unsigned long start,
> +                                                unsigned long end,
> +                                                pgprot_t prot,
> +                                                struct page **pages,
> +                                                unsigned int page_shift)
>  {
> +       return 0;
>  }
>
>  static inline void kmsan_vunmap_range_noflush(unsigned long start,
> diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> index a787c04e9583c..b8bb95eea5e3d 100644
> --- a/mm/kmsan/shadow.c
> +++ b/mm/kmsan/shadow.c
> @@ -216,27 +216,29 @@ void kmsan_free_page(struct page *page, unsigned int order)
>         kmsan_leave_runtime();
>  }
>
> -void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
> -                                   pgprot_t prot, struct page **pages,
> -                                   unsigned int page_shift)
> +int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
> +                                  pgprot_t prot, struct page **pages,
> +                                  unsigned int page_shift)
>  {
>         unsigned long shadow_start, origin_start, shadow_end, origin_end;
>         struct page **s_pages, **o_pages;
> -       int nr, mapped;
> +       int nr, mapped, err = 0;
>
>         if (!kmsan_enabled)
> -               return;
> +               return 0;
>
>         shadow_start = vmalloc_meta((void *)start, KMSAN_META_SHADOW);
>         shadow_end = vmalloc_meta((void *)end, KMSAN_META_SHADOW);
>         if (!shadow_start)
> -               return;
> +               return 0;
>
>         nr = (end - start) / PAGE_SIZE;
>         s_pages = kcalloc(nr, sizeof(*s_pages), GFP_KERNEL);
>         o_pages = kcalloc(nr, sizeof(*o_pages), GFP_KERNEL);
> -       if (!s_pages || !o_pages)
> +       if (!s_pages || !o_pages) {
> +               err = -ENOMEM;
>                 goto ret;
> +       }
>         for (int i = 0; i < nr; i++) {
>                 s_pages[i] = shadow_page_for(pages[i]);
>                 o_pages[i] = origin_page_for(pages[i]);
> @@ -249,10 +251,16 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
>         kmsan_enter_runtime();
>         mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
>                                             s_pages, page_shift);
> -       KMSAN_WARN_ON(mapped);
> +       if (mapped) {
> +               err = mapped;
> +               goto ret;
> +       }
>         mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
>                                             o_pages, page_shift);
> -       KMSAN_WARN_ON(mapped);
> +       if (mapped) {
> +               err = mapped;
> +               goto ret;
> +       }
>         kmsan_leave_runtime();
>         flush_tlb_kernel_range(shadow_start, shadow_end);
>         flush_tlb_kernel_range(origin_start, origin_end);
> @@ -262,6 +270,7 @@ void kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
>  ret:
>         kfree(s_pages);
>         kfree(o_pages);
> +       return err;
>  }
>
>  /* Allocate metadata for pages allocated at boot time. */
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index a50072066221a..1355d95cce1ca 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -605,7 +605,11 @@ int __vmap_pages_range_noflush(unsigned long addr, unsigned long end,
>  int vmap_pages_range_noflush(unsigned long addr, unsigned long end,
>                 pgprot_t prot, struct page **pages, unsigned int page_shift)
>  {
> -       kmsan_vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
> +       int ret = kmsan_vmap_pages_range_noflush(addr, end, prot, pages,
> +                                                page_shift);
> +
> +       if (ret)
> +               return ret;
>         return __vmap_pages_range_noflush(addr, end, prot, pages, page_shift);
>  }
>
> --
> 2.40.0.577.gac1e443424-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMd-p6ejwsMugOM84mkqcuLrXpNg1EUJTYRUsEtV1swpQ%40mail.gmail.com.
