Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR6Z7GQQMGQE6VD6VUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 017D86E5E58
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 12:11:21 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2475e9ec1c5sf508317a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 03:11:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681812679; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBmy0g7oSzGITmLlJ5R0hPFU96ivPKQIqbRB9gamg90Ox8jnsIYZ6ClAtqeOKfIpqK
         ds0i6/RpIgcof8/Ah++4qguXcBtedvXSLLgf2S49RztaWGM3k3Q68vNTD4l86H0ITMXj
         5sjlUgPB2luF822k1f0cpLtj1nE1QohUqsUWHe5oTujq9LsmhveJXELVjWPR0wmYABC4
         +yGjfLdzwv9D2PxcKqFEI9mbObXN2t4Z8zQNR7N5dSalHL/kHK4F7LVp4UsMQc5vzUlb
         iXN1ShQlBtCXDkCE8u1i8bnehUNOJKqOSwP4QEFAf/bcI0b9PzrnlrGK18jsCx5h48PP
         uWyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2aR5lhxKf+7OA5vwEPmr3/u48WVOrGUYUV0uZeQxpgs=;
        b=L0xxyFS7NqUx5dAhj6gK80Tb1cF3WJnr/YMkpFqkZIvLyDj2EB54ap9mKStp0y62Tk
         7F5obsoMsMwviwxwcosvA93tW9acJFCeKkjUXTKiK+reKLUSYFQ5eFLXg44dJpG9UEd2
         dQ63upT8hjUm1rlPKh4KgpoPdgWVhydo8pE99xhTzxirqKSIslYwQT4yNgN+lPI0o5zX
         nPZ9mqAaQFZXnNujxPTWz0Nv0/oXBd9f0t4JPNItakRvK8dUBbxHxAhPY7wp/J/zXm9g
         B0PCYKBSMuEbiD8Tg3yItrU7qKmkHIqAN1fKiZ9ISG7kx6CZEilhkTm4Ptfx3o2CkqMk
         sF9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ifC3WCXP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681812679; x=1684404679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2aR5lhxKf+7OA5vwEPmr3/u48WVOrGUYUV0uZeQxpgs=;
        b=aTQpd+SYHdOHB0bFcnRo63O2XBKnHh/Te6Ozx3p6FoahEt5I4syfksSncCoR/efykz
         e49k3RbabwryVYd1PoqLLx0a9M4x/7gOFLKw2f1WPaMvkPcsC63EpBuY9mwB3tOHXQYM
         WFlLxt5I5pO9Tz5wz5yDEOAX43Ku1rfWbJrpangnN8vlkeQ62WFmnBz0DI/WGYTYWe5y
         MhxiK6MUSx/cgwpXWaZwOsbF3iwRvqv7BYsHyGbuPhC4FxPD0IVhwQhxRJH7ftFGTpAf
         z1SSzNrcbHb1f0EfTi94zWq8p9vsWrm90Gb4Y9CO7Tn6DqcrYPSiUcPpreVasL6s7oTz
         b8Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681812679; x=1684404679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2aR5lhxKf+7OA5vwEPmr3/u48WVOrGUYUV0uZeQxpgs=;
        b=BO5YG/RJh8NIZFJyHW/2yA1V1B6KFwaX4lYi65v31eJujgT7783P/s+VG2nW2nqDSy
         miOIj0gw7kPT4G0F1ekbXiZRZBdUxxOGzBINoX6xzv+AhYAKYkRIRFDy3i85MivEPCs1
         d3oSUQspp9guqp+lJxQXjvvq+oEP/xn/qWI0C43Eq2ZQhRCAHJI7YqxN/iEYpGfJfS+R
         OWESQdHWX14j9T2PSei5NjxENHHAN2zt7w20wZu4aKlTpIBwfUTtZUyYq50JWC5JYCkv
         tFvM6LPT22WF3H+riGNhdbGm5x+vAdIbIJxuGxXkXIOX8HZVyQQxcnfxBuo92XamwIT/
         +YBw==
X-Gm-Message-State: AAQBX9cz/PH/WdvZqt6gDG7crs/+LzCi0XLY8sYn0u2u5KL7qb/fhjsp
	QyjgbKeg1fVvVMW/3iWfJQI=
X-Google-Smtp-Source: AKy350Zevpwacsj98Nb0pA3sZjFwFWlGgK7uijtXMNsaqXcCQj82keOWiuI84wUzFXh0kA10IIEIeg==
X-Received: by 2002:a17:90a:4e4a:b0:247:2d9d:14a9 with SMTP id t10-20020a17090a4e4a00b002472d9d14a9mr463573pjl.9.1681812679244;
        Tue, 18 Apr 2023 03:11:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:fa46:b0:19c:a86d:b340 with SMTP id
 lb6-20020a170902fa4600b0019ca86db340ls10301925plb.9.-pod-prod-gmail; Tue, 18
 Apr 2023 03:11:18 -0700 (PDT)
X-Received: by 2002:a17:90b:1a92:b0:247:bab1:d901 with SMTP id ng18-20020a17090b1a9200b00247bab1d901mr1468490pjb.17.1681812678456;
        Tue, 18 Apr 2023 03:11:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681812678; cv=none;
        d=google.com; s=arc-20160816;
        b=J9rMMsJSlbMO3/UhzLXruxXI4r1+X6+NIonF4JGrpX11exkYJQq9/t68w3rlMn5z8c
         PHd3gqOMHaAPwkJ1JGKuukrVSF93iurF+hjRd55ikbJwo/H1tgIuk4kQR9v3AvXQECaK
         qJi3xbyP1oIJv5clPHQGBq1Cm22J7HcXym6RvxgABf/3KNiirC/qKLGjxwtx19pSHZnm
         zkBuJaRmEjpkJJZJEegwhJ3yibXhFlM6vMqC94etnz1h7Bl4czXQNlAfT86t5FzId9y+
         Gz/0kWweYqJScyUxcz+k6z6Gv0rbIqTaA2No1TqUfFWJcNZUrXPL8UTuQcBhzCj+uRKR
         LRtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ng21oiPWmKz3a89ft5u8IMQfso9W3BdH67nYr79Gs5M=;
        b=eq27ikFEieaiFvMoz52OjXwwBObTRAFNjr3EXh4u2gtl85QQTgx1lc7uqQ8i+xi7Wg
         vaIxFBKFWhyFOswjgDYyFd2rnm8/Jb5ck1SNfuTezQOE/19RbXVa9KLdrU7J7ouUf3HE
         tZSUfaXoOme0RLVpo65Zx5Ku4Cew+KwmBMBLIr0A0YBq5yhhGOFe4WjYC30PxEQmp2/i
         bVmSDG4LfWGXzTug+jdotxa4hgnSQ/uTSzpgtS/3F6d7Xqd4e1pnEfsFlmxu7mMxA4DA
         BnWR8iu/oxn4H5zC19EdO0l3I6NyLjZMdyTEcma1BqsneDj3LKPpvutzVJofPLTbGYKF
         qsRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ifC3WCXP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id nt20-20020a17090b249400b0023d1e5feec0si839501pjb.0.2023.04.18.03.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Apr 2023 03:11:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id ca18e2360f4ac-7606cf9926cso50920639f.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Apr 2023 03:11:18 -0700 (PDT)
X-Received: by 2002:a6b:ec1a:0:b0:763:5f51:aff7 with SMTP id
 c26-20020a6bec1a000000b007635f51aff7mr1394065ioh.5.1681812677553; Tue, 18 Apr
 2023 03:11:17 -0700 (PDT)
MIME-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com> <20230413131223.4135168-3-glider@google.com>
In-Reply-To: <20230413131223.4135168-3-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Apr 2023 12:10:41 +0200
Message-ID: <CANpmjNPuKyOOKptYU19E2Q=YX7rNv6EuY9ajnVw6BYRw-g79vg@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] mm: kmsan: apply __must_check to non-void functions
To: Alexander Potapenko <glider@google.com>
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ifC3WCXP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d31 as
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

On Thu, 13 Apr 2023 at 15:12, 'Alexander Potapenko' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Non-void KMSAN hooks may return error codes that indicate that KMSAN
> failed to reflect the changed memory state in the metadata (e.g. it
> could not create the necessary memory mappings). In such cases the
> callers should handle the errors to prevent the tool from using the
> inconsistent metadata in the future.
>
> We mark non-void hooks with __must_check so that error handling is not
> skipped.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  include/linux/kmsan.h | 43 ++++++++++++++++++++++---------------------
>  1 file changed, 22 insertions(+), 21 deletions(-)
>
> diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
> index 30b17647ce3c7..e0c23a32cdf01 100644
> --- a/include/linux/kmsan.h
> +++ b/include/linux/kmsan.h
> @@ -54,7 +54,8 @@ void __init kmsan_init_runtime(void);
>   * Freed pages are either returned to buddy allocator or held back to be used
>   * as metadata pages.
>   */
> -bool __init kmsan_memblock_free_pages(struct page *page, unsigned int order);
> +bool __init __must_check kmsan_memblock_free_pages(struct page *page,
> +                                                  unsigned int order);
>
>  /**
>   * kmsan_alloc_page() - Notify KMSAN about an alloc_pages() call.
> @@ -137,9 +138,11 @@ void kmsan_kfree_large(const void *ptr);
>   * vmalloc metadata address range. Returns 0 on success, callers must check
>   * for non-zero return value.
>   */
> -int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
> -                                  pgprot_t prot, struct page **pages,
> -                                  unsigned int page_shift);
> +int __must_check kmsan_vmap_pages_range_noflush(unsigned long start,
> +                                               unsigned long end,
> +                                               pgprot_t prot,
> +                                               struct page **pages,
> +                                               unsigned int page_shift);
>
>  /**
>   * kmsan_vunmap_kernel_range_noflush() - Notify KMSAN about a vunmap.
> @@ -163,9 +166,9 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
>   * virtual memory. Returns 0 on success, callers must check for non-zero return
>   * value.
>   */
> -int kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
> -                            phys_addr_t phys_addr, pgprot_t prot,
> -                            unsigned int page_shift);
> +int __must_check kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
> +                                         phys_addr_t phys_addr, pgprot_t prot,
> +                                         unsigned int page_shift);
>
>  /**
>   * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
> @@ -237,8 +240,8 @@ static inline void kmsan_init_runtime(void)
>  {
>  }
>
> -static inline bool kmsan_memblock_free_pages(struct page *page,
> -                                            unsigned int order)
> +static inline bool __must_check kmsan_memblock_free_pages(struct page *page,
> +                                                         unsigned int order)
>  {
>         return true;
>  }
> @@ -251,10 +254,9 @@ static inline void kmsan_task_exit(struct task_struct *task)
>  {
>  }
>
> -static inline int kmsan_alloc_page(struct page *page, unsigned int order,
> -                                  gfp_t flags)
> +static inline void kmsan_alloc_page(struct page *page, unsigned int order,
> +                                   gfp_t flags)
>  {
> -       return 0;
>  }
>
>  static inline void kmsan_free_page(struct page *page, unsigned int order)
> @@ -283,11 +285,9 @@ static inline void kmsan_kfree_large(const void *ptr)
>  {
>  }
>
> -static inline int kmsan_vmap_pages_range_noflush(unsigned long start,
> -                                                unsigned long end,
> -                                                pgprot_t prot,
> -                                                struct page **pages,
> -                                                unsigned int page_shift)
> +static inline int __must_check kmsan_vmap_pages_range_noflush(
> +       unsigned long start, unsigned long end, pgprot_t prot,
> +       struct page **pages, unsigned int page_shift)
>  {
>         return 0;
>  }
> @@ -297,10 +297,11 @@ static inline void kmsan_vunmap_range_noflush(unsigned long start,
>  {
>  }
>
> -static inline int kmsan_ioremap_page_range(unsigned long start,
> -                                          unsigned long end,
> -                                          phys_addr_t phys_addr, pgprot_t prot,
> -                                          unsigned int page_shift)
> +static inline int __must_check kmsan_ioremap_page_range(unsigned long start,
> +                                                       unsigned long end,
> +                                                       phys_addr_t phys_addr,
> +                                                       pgprot_t prot,
> +                                                       unsigned int page_shift)
>  {
>         return 0;
>  }
> --
> 2.40.0.577.gac1e443424-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413131223.4135168-3-glider%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPuKyOOKptYU19E2Q%3DYX7rNv6EuY9ajnVw6BYRw-g79vg%40mail.gmail.com.
