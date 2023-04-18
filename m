Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOGZ7GQQMGQEGVOSOPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id D5E2B6E5E4D
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 12:11:05 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-54685706a5csf199144eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 03:11:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681812664; cv=pass;
        d=google.com; s=arc-20160816;
        b=0hj/Ipq8ul5BJALAhGmcxPfSjj6AkzLGho/hSNy3+Jg2OL5wRjupkH5BlxuU69ZxUK
         q6f9fiWqEsyVtAFg8B/91Q+HFpPN6jj3MSlMRzccvoJ6PKK6y68pdq4R1iPYf57Q4HEk
         PdlhdxKdGwhIXoeUpIXCVqwNpiGZ28HPoE17f5gyDmd9wnsZtvayymGoP/YOgZV/6a2N
         MF1tLnl81yAwrrtQXrNhIezZhOFSm8BJ19BnwklHYTt+hW0hNQLHdEf/cXyeuD7yb+Oa
         Bj6uqJa6FyblodQbXhsY8YAJxdVRf8V/HGQPTLmH+BFdPq6uEbICexBE41UJv7y9abXX
         93/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A88My/X08sp9YSNBxrhuEgeWK7NdDQDZT2W07rKtWZo=;
        b=F0xubqwtN1vWaRJ6wMaieYtgQwX0JgQ9KA84h73VjBz9Fx/eTWJS6zeZn8EwhniLBq
         aVExryXShmOVDTRv+3Zz8SGXEhOp3jiiZNKwPYkbJecOhFV0M2frIUCGtUOeNt60KMPx
         QKeMdA76apsNtNZDcrO1NDlm2zi5txLvVzu9ynVrujWsMe6U03mKE7ezTqxUqPW9Hdam
         dFpa3rbArYuWwSKkI6IM7FLMpLZ3oIJsupNgDXK66WmeRCPJlWouNuoW5RlMCvA3vzZO
         s9pQqXEvrNyFY5QDHyM6CA5bMaZxARU7amlkRNfhUJdLa+1rPwFDoEWMiXDTlQCwEBH8
         Wz6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MmwB5ib1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681812664; x=1684404664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=A88My/X08sp9YSNBxrhuEgeWK7NdDQDZT2W07rKtWZo=;
        b=dru8MAuj/NEIq4PwnQr33fJPBtbtM5hqQ/CVDg8PvRmAcsCkeo497jNifUPG7+kY/W
         49FOObZSLam2BOBtINv8Adjwk9ojMI4RgJkoFGAmrwNyZx6A5RfJYeaUOJ7uCucFWrk1
         WSqIQjUps254iiD3RfKOO4xIHVQG+rjf6+xw2CiJqk1VoMWpsPYAJTTQ+iQbYu+mj1Ur
         3gdNWeTYsCcF75MjKWPyHH/UADFfxxeOKVCTa0xelwUWeL/X/LT7AMfST2N0xsRMLoPe
         j2ax8jEvSQmF0LBpSEakITXb9CvQSToeFbZaWQmdaR4jqZp01VycsAMXqJFzMn5VovQO
         q69g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681812664; x=1684404664;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=A88My/X08sp9YSNBxrhuEgeWK7NdDQDZT2W07rKtWZo=;
        b=WxNqpg1eW6uEYaruPQ4KQT2Bc9fEtCKT8NdaeC8WN9fORRAWzvi+iF02TROcFxoHxV
         K5pQzm6QBn2OLT+2r5Ko1oHoPtHMMDwGQTDEOIj27LTnGwIRQ4o+fpBwBn/8dqXo6vdb
         WezABQ8B6WJ7hCt+Hsz1o7KBVh5u+90T45gXzhtNw+UxQ6oamJG9DkPmv8PQDVaPJVZd
         f8cO/UthahkUzBmU95S+OhqkjxQTh+2oyGvyy+uriOiGk8GhqsaWvGO454lTdj5fBVxn
         esQIAcnd0Ay9VoY9ycUL1sG/Tz9IR27SCeW+tUkTQNQ1gYowOAEKQbldKcKaOZJEWCS1
         xYkQ==
X-Gm-Message-State: AAQBX9e4l7WBnF2tLf/+3Z3l0zLH28oOeGTdSdsmXFTc6IJNOWpkOFj4
	UcmlB0LLp++hRD5wuzzzvHM=
X-Google-Smtp-Source: AKy350ZZ6wa+t2g2g+duDLTjmd1bSlJ+oPmkZCaojy6iPEalFXl3KhyTLZqqE8biE9deX3BcmvG6pw==
X-Received: by 2002:a05:6870:c1c6:b0:17f:f1f4:b006 with SMTP id i6-20020a056870c1c600b0017ff1f4b006mr770500oad.11.1681812664502;
        Tue, 18 Apr 2023 03:11:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:b92:b0:6a3:d400:61a1 with SMTP id
 a18-20020a0568300b9200b006a3d40061a1ls5173366otv.8.-pod-prod-gmail; Tue, 18
 Apr 2023 03:11:04 -0700 (PDT)
X-Received: by 2002:a05:6830:1510:b0:69f:1257:a93b with SMTP id k16-20020a056830151000b0069f1257a93bmr802479otp.36.1681812664000;
        Tue, 18 Apr 2023 03:11:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681812663; cv=none;
        d=google.com; s=arc-20160816;
        b=Z0YIF3jU3bjWjwdLwqihU3ZBlPeKc40S7YeZ2cJv4zWCwTdmvX1G65bkklfa/ApbrB
         YH6pf2kGxm2CQ5CFVW3r3ZL12dSRo/qhkEJA/iluTt6OCVmZfr0B185pUYKW4ooKPgwH
         mT81dQK0hdr1FN+D3cHzoH4c0+J9oFHCGbPPEVMJ9kjEDrBEJeh3QCZLBYt8Zl0II5H9
         umoCWAxpSHv+cGwY8HpGbTSLkl7awSu3UxHEvb9up2xf3ZUX7Hjq4X5E7Q5+tmF2Frcx
         4xh3EbfGzgwOw5G23C/OoqxccyH0Foosv0TL6LJjeB544KqV3QIiLmqVfVFcwKSxlgNG
         l5vA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qkfA+RN8+NxglUFBtFLBAQbfb++ZPOPFuIp98xxhha0=;
        b=iTbE3RhJYrRdqL2FtS+MmDepiW7CSZoUXunNEyNWSDoXJNiisk8/sRO/PysTB4OH2C
         KxfK5W5jx84tI7+J7IiW0Xs3vmOtS/7C+inmhOCsMRSeIFHaIhQr8rGXKAMN4Peec35n
         3ZkoelHL2luMX+SBnvrqUObgM5qp2sJaKtPVFuKIQwP82cD9m2BUI5xwU4GsbCscDgR0
         TB+KBwfhuK9P7VFK4m47gNoE3rpx/rnPhCvPFwjZqfOnEEivNDkQ/vurccTh1tXIWdEC
         KusztOgtVoRKLi0h/P6M1Ypovv1WlMUe9rWlMutcrI5gD658gDz2EXCHQjwhScwqa+pA
         6V4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=MmwB5ib1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::130 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x130.google.com (mail-il1-x130.google.com. [2607:f8b0:4864:20::130])
        by gmr-mx.google.com with ESMTPS id bq20-20020a056830389400b006a5ec143a43si417118otb.1.2023.04.18.03.11.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 03:11:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::130 as permitted sender) client-ip=2607:f8b0:4864:20::130;
Received: by mail-il1-x130.google.com with SMTP id e9e14a558f8ab-3293e4b2d32so4334785ab.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 03:11:03 -0700 (PDT)
X-Received: by 2002:a92:1301:0:b0:326:68bc:b423 with SMTP id
 1-20020a921301000000b0032668bcb423mr12482145ilt.20.1681812663485; Tue, 18 Apr
 2023 03:11:03 -0700 (PDT)
MIME-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com> <20230413131223.4135168-2-glider@google.com>
In-Reply-To: <20230413131223.4135168-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 12:10:27 +0200
Message-ID: <CANpmjNML3wQjaxujkAxWiTVwgBaUtbCPEQES7duh0ktyT2ddTQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/4] mm: kmsan: handle alloc failures in kmsan_ioremap_page_range()
To: Alexander Potapenko <glider@google.com>
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com, Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=MmwB5ib1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::130 as
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
> Similarly to kmsan_vmap_pages_range_noflush(),
> kmsan_ioremap_page_range() must also properly handle allocation/mapping
> failures. In the case of such, it must clean up the already created
> metadata mappings and return an error code, so that the error can be
> propagated to ioremap_page_range(). Without doing so, KMSAN may silently
> fail to bring the metadata for the page range into a consistent state,
> which will result in user-visible crashes when trying to access them.
>
> Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
> Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
> Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> v2:
>  -- updated patch description as requested by Andrew Morton
>  -- check the return value of __vmap_pages_range_noflush(), as suggested by Dipanjan Das
>  -- return 0 from the inline version of kmsan_ioremap_page_range()
>     (spotted by kernel test robot <lkp@intel.com>)
> ---
>  include/linux/kmsan.h | 19 ++++++++-------
>  mm/kmsan/hooks.c      | 55 ++++++++++++++++++++++++++++++++++++-------
>  mm/vmalloc.c          |  4 ++--
>  3 files changed, 59 insertions(+), 19 deletions(-)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index c7ff3aefc5a13..30b17647ce3c7 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -160,11 +160,12 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
>   * @page_shift:        page_shift argument passed to vmap_range_noflush().
>   *
>   * KMSAN creates new metadata pages for the physical pages mapped into the
> - * virtual memory.
> + * virtual memory. Returns 0 on success, callers must check for non-zero return
> + * value.
>   */
> -void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
> -                             phys_addr_t phys_addr, pgprot_t prot,
> -                             unsigned int page_shift);
> +int kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
> +                            phys_addr_t phys_addr, pgprot_t prot,
> +                            unsigned int page_shift);
>
>  /**
>   * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
> @@ -296,12 +297,12 @@ static inline void kmsan_vunmap_range_noflush(unsigned long start,
>  {
>  }
>
> -static inline void kmsan_ioremap_page_range(unsigned long start,
> -                                           unsigned long end,
> -                                           phys_addr_t phys_addr,
> -                                           pgprot_t prot,
> -                                           unsigned int page_shift)
> +static inline int kmsan_ioremap_page_range(unsigned long start,
> +                                          unsigned long end,
> +                                          phys_addr_t phys_addr, pgprot_t prot,
> +                                          unsigned int page_shift)
>  {
> +       return 0;
>  }
>
>  static inline void kmsan_iounmap_page_range(unsigned long start,
> diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
> index 3807502766a3e..ec0da72e65aa0 100644
> --- a/mm/kmsan/hooks.c
> +++ b/mm/kmsan/hooks.c
> @@ -148,35 +148,74 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end)
>   * into the virtual memory. If those physical pages already had shadow/origin,
>   * those are ignored.
>   */
> -void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
> -                             phys_addr_t phys_addr, pgprot_t prot,
> -                             unsigned int page_shift)
> +int kmsan_ioremap_page_range(unsigned long start, unsigned long end,
> +                            phys_addr_t phys_addr, pgprot_t prot,
> +                            unsigned int page_shift)
>  {
>         gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;
>         struct page *shadow, *origin;
>         unsigned long off = 0;
> -       int nr;
> +       int nr, err = 0, clean = 0, mapped;
>
>         if (!kmsan_enabled || kmsan_in_runtime())
> -               return;
> +               return 0;
>
>         nr = (end - start) / PAGE_SIZE;
>         kmsan_enter_runtime();
> -       for (int i = 0; i < nr; i++, off += PAGE_SIZE) {
> +       for (int i = 0; i < nr; i++, off += PAGE_SIZE, clean = i) {
>                 shadow = alloc_pages(gfp_mask, 1);
>                 origin = alloc_pages(gfp_mask, 1);
> -               __vmap_pages_range_noflush(
> +               if (!shadow || !origin) {
> +                       err = -ENOMEM;
> +                       goto ret;
> +               }
> +               mapped = __vmap_pages_range_noflush(
>                         vmalloc_shadow(start + off),
>                         vmalloc_shadow(start + off + PAGE_SIZE), prot, &shadow,
>                         PAGE_SHIFT);
> -               __vmap_pages_range_noflush(
> +               if (mapped) {
> +                       err = mapped;
> +                       goto ret;
> +               }
> +               shadow = NULL;
> +               mapped = __vmap_pages_range_noflush(
>                         vmalloc_origin(start + off),
>                         vmalloc_origin(start + off + PAGE_SIZE), prot, &origin,
>                         PAGE_SHIFT);
> +               if (mapped) {
> +                       __vunmap_range_noflush(
> +                               vmalloc_shadow(start + off),
> +                               vmalloc_shadow(start + off + PAGE_SIZE));
> +                       err = mapped;
> +                       goto ret;
> +               }
> +               origin = NULL;
> +       }
> +       /* Page mapping loop finished normally, nothing to clean up. */
> +       clean = 0;
> +
> +ret:
> +       if (clean > 0) {
> +               /*
> +                * Something went wrong. Clean up shadow/origin pages allocated
> +                * on the last loop iteration, then delete mappings created
> +                * during the previous iterations.
> +                */
> +               if (shadow)
> +                       __free_pages(shadow, 1);
> +               if (origin)
> +                       __free_pages(origin, 1);
> +               __vunmap_range_noflush(
> +                       vmalloc_shadow(start),
> +                       vmalloc_shadow(start + clean * PAGE_SIZE));
> +               __vunmap_range_noflush(
> +                       vmalloc_origin(start),
> +                       vmalloc_origin(start + clean * PAGE_SIZE));
>         }
>         flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
>         flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
>         kmsan_leave_runtime();
> +       return err;
>  }
>
>  void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 1355d95cce1ca..31ff782d368b0 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -313,8 +313,8 @@ int ioremap_page_range(unsigned long addr, unsigned long end,
>                                  ioremap_max_page_shift);
>         flush_cache_vmap(addr, end);
>         if (!err)
> -               kmsan_ioremap_page_range(addr, end, phys_addr, prot,
> -                                        ioremap_max_page_shift);
> +               err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
> +                                              ioremap_max_page_shift);
>         return err;
>  }
>
> --
> 2.40.0.577.gac1e443424-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNML3wQjaxujkAxWiTVwgBaUtbCPEQES7duh0ktyT2ddTQ%40mail.gmail.com.
