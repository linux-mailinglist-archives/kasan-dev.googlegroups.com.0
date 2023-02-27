Return-Path: <kasan-dev+bncBDW2JDUY5AORBNXO56PQMGQENKJVBMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 274F06A35E5
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 01:20:08 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id w10-20020a056e021c8a00b003174d233ebfsf1387422ill.18
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Feb 2023 16:20:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677457206; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDhXXF50UEt7FXlhJS5zFaFKYLY3qpTy8TPK7jPpupIrc0d1oDcEO+wr/IPvVSrNg/
         6rcH7xPteiTLV4gUapjiGGPkEzyfyADZM90PJ2wXcEIvNx5yi0WA81uOZ/aZMyqqEW5f
         FV/4DQFB6m1j3edDZcmxghMZ9GZskv/IQVo1j2O9j6cJCcf/IVQ8hX/zOzgzn5ElJs/1
         /RUdjLlun6ggcAhv36267rE8HCbfAIV0dT5AquoDYt5bi+NY9qMxX+OMYfH20zBupMTT
         55RoEGuzRfWzP1Uh2JMg/9nQ83x0u+mjQzs21EJqwIWMO6sp+RvrvtvBCDh8ev+Usw5S
         4NNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=1z4m+pkjKNsUTbwHqcMVWxd7Em26iRZ3GhRn/y84aFQ=;
        b=R7B9a+kusVQBVgoABSfhC1PnBom44098WvThKmru4xbbamTlswVVOUBE0RiPT4zs2O
         ycp9s/UQPUwDx7v8nuA1BZX15MRuQ38EdNhJMkbCAlD3qEJlC9VM6ANoYlCeckZCXgs4
         PlDokt6TEaQwQ2Albo31eCp7BIZqI2uaAllipYC1+c02Vbd53ASi8vzivg2Y98bigFKe
         zqr04XxcjMIThGC03X08XRVPOXtdw+UwxJv3xHQcNSktkyQdZTh7R1U+wumCgRGAW3C9
         aTnFfps/zRf10VhQYoCdcKR9A0JQvhncIlXHcNrC2Y0NMMxCK9SYU4ng7s65+7Dv68rR
         0oug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=U0jNu4jU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1z4m+pkjKNsUTbwHqcMVWxd7Em26iRZ3GhRn/y84aFQ=;
        b=PLi7+5NS9ieFitA1Tt8RLjL5pisFzdw4et5FdzqGWSOYMJ3yXp4npQ7vjmtsSkwUjf
         DHMGAl7acRf+9ck0G+A2FFvbOgHzKGIq5Bz6XoQHpdb12ybtayX7piEzwyoDfR8q2oxa
         n7SwZEDk89mOo4aZUmZbaQoe8nZLcHszNpnb80dhjEUKYDuYvOcxdgh523V+2iT1Oh4j
         iWCndybW1TK3jOemq0CWFzqL41iDZ1T7X/l1duukc0t+LmW3q6JA6Ge2iTh5eTd0J7vE
         jYaS/Ig1KXec7PVc46KIVB4z6zygKvrYTAVptK30OUCHMhJs+U26cTEpdoP133nBzief
         CBeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=1z4m+pkjKNsUTbwHqcMVWxd7Em26iRZ3GhRn/y84aFQ=;
        b=gwjRvZfhZbEcF/pS7tUPg0LYR0XB51ohJ8+DLFROI++ZJd+N2KWLcBmoBaXtx/P8a1
         32MAYZ1VvPBm6NQjBy4TGeDMNorvWp1pzh69JjwOCPDSivoBhon3MjWYZApdnB49IIsL
         ikAk1axh/bsLM65naew5dKTweocsTA2OrfeHPt9zVxWwuXU9ygVutKkDhDXdCq1mAIsY
         Tg6eu3HIy0KRS/x7Y7CupJa3UcMnilBQxdkFgK2Q7bEqMKQXSmffQVFBcqpZ3H6xtR8I
         2Uj4G/HfFz7D+H04uwmkQC+XAO1l8X73+5P3SAYcsc/3mfrCmcR2xC3TT7L8U40jD36v
         gEUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1z4m+pkjKNsUTbwHqcMVWxd7Em26iRZ3GhRn/y84aFQ=;
        b=wMXydZxcqMWEQHF7277ROFEBEunk27afcvZNWwqCwIFQqjSdcK71BkH0GeWf9Smn8y
         OCcN0h9pcTQoFTKEQlZr7wNY6Ovh6BZ/cvSp0Camwy9RhD2rSW6aqaskcDoXPe9w1ApE
         3vZ5Uilff+lgJiFEuGH5m91Kz3gLkdFMme19SB+bvKLt3MnTY+I9nniPONTxWp5EDPs2
         BQdGvTPaKdK1aohSduJO2epkHbfooHoZ9pJu9RK/M0Y0T2dLqnlxcRaR/Gx6BxLBD2oP
         ikVnI3bnl/eSGiLf7GfBqj6LTZXiKw2q9nA/PHs8IonfmoZSVJukpT4B24N/lGB9Tp56
         AVxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVlKzBLc57lW24/mylZRVCBe+2nHN8xwMpZYtXB0ne10JfiTfmb
	bo8bTOYEDBfpxFDYZrgH1hw=
X-Google-Smtp-Source: AK7set9I7PMJff4SUOtksvHRBeIWyt3+cU0z1beXm1EFNFRRmURGZ0MPoQmx2WeuHTJDD9BF7GcOJw==
X-Received: by 2002:a05:6638:cd0:b0:3c4:88de:524 with SMTP id e16-20020a0566380cd000b003c488de0524mr9854748jak.3.1677457206498;
        Sun, 26 Feb 2023 16:20:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9d97:0:b0:71e:5d17:7fe5 with SMTP id ay23-20020a5d9d97000000b0071e5d177fe5ls2041043iob.1.-pod-prod-gmail;
 Sun, 26 Feb 2023 16:20:05 -0800 (PST)
X-Received: by 2002:a05:6602:189:b0:71b:cd72:192d with SMTP id m9-20020a056602018900b0071bcd72192dmr10289263ioo.20.1677457205638;
        Sun, 26 Feb 2023 16:20:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677457205; cv=none;
        d=google.com; s=arc-20160816;
        b=xtKxB4d1mSAcHF5GiniSOd/sB32yAxKDkqNd5dRxH7NyYEpoeaXcrE4I7+CtiTll1G
         RuXyqQiZqcNZxLq/h0ida+JXzeD6ud0B/qyL1SWZIR4McxeT0KZMDJaP9IuycRRxFslw
         E5asYySwWZxiqKQB5UigH5dn/q22FSazPCV52kK2zHBZII245mX3PSDS3R4gNvSoMRQi
         O/eqNi6fjyQHziqc72R3xaK80CgqDtHyA+H93SumxYIH9CvElFhMMtdcXw0shc+AgWny
         qcysa7mo0o8ZS7FMluTAIr2lZ8Lk8SAapxYtup1ySP8t4TG9tEO7Q2vAK9cjy/uj2HPN
         pP/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QaBhu4nRrGvT6uybXjxPcv2+70gLwq36FlwiKtV0inw=;
        b=mZJoL5bsjDZZQk2L9t0DsJqUPxbu378LaBrPEhQlzzNiEL+AIxcigj+8mkxYU6uqZA
         CYkXbI8DvNjvJBieTrhdz7C265lt5EsMfS6tJEU3kNcbNYzJu4sGhDU1Q/KMclp9tZ9M
         rwMlnsNCMEyIY6hEe1wUojplrb6NWgdAtUd0+L1+36Re3MKkrZnn9zjrnNPy2A9mwTQp
         nje1+HDu2VRsvv7aRGeyTcNkHW0XWGuUc8yg9JoU5Br50y58EWkjdTnzogV/yihqkV1h
         3jUFX7WCpu3NCWOsv23hFf7+dL3+gF3rX5wp9uRe2XwMAzQvEP/u+TM62EAVlffSURv+
         6+Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=U0jNu4jU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id y2-20020a056602164200b0074c8a593b88si355707iow.0.2023.02.26.16.20.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Feb 2023 16:20:05 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id fd25so2540074pfb.1
        for <kasan-dev@googlegroups.com>; Sun, 26 Feb 2023 16:20:05 -0800 (PST)
X-Received: by 2002:a63:7b49:0:b0:502:f4c6:b96 with SMTP id
 k9-20020a637b49000000b00502f4c60b96mr3813256pgn.5.1677457204959; Sun, 26 Feb
 2023 16:20:04 -0800 (PST)
MIME-Version: 1.0
References: <20230224065128.505605-1-pcc@google.com>
In-Reply-To: <20230224065128.505605-1-pcc@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 27 Feb 2023 01:19:53 +0100
Message-ID: <CA+fCnZc-iLXbEUzYhEZtY5wHc=G3p=m-fuNdVsmovg-MT8c-6g@mail.gmail.com>
Subject: Re: [PATCH] kasan: remove PG_skip_kasan_poison flag
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=U0jNu4jU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Feb 24, 2023 at 7:51 AM Peter Collingbourne <pcc@google.com> wrote:
>
> Code inspection reveals that PG_skip_kasan_poison is redundant with
> kasantag, because the former is intended to be set iff the latter is
> the match-all tag. It can also be observed that it's basically pointless
> to poison pages which have kasantag=0, because any pages with this tag
> would have been pointed to by pointers with match-all tags, so poisoning
> the pages would have little to no effect in terms of bug detection.
> Therefore, change the condition in should_skip_kasan_poison() to check
> kasantag instead, and remove PG_skip_kasan_poison.

This seems reasonable.

> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I57f825f2eaeaf7e8389d6cf4597c8a5821359838
> ---
> I sent this independently of
> https://lore.kernel.org/all/20230224061550.177541-1-pcc@google.com/
> because I initially thought that the patches were independent.
> But moments after sending it, I realized that this patch depends on
> that one, because without that patch, this patch will end up disabling
> page poisoning altogether! But it's too late to turn them into a series
> now; I'll do that for v2.
>
>  include/linux/page-flags.h     |  9 ---------
>  include/trace/events/mmflags.h |  9 +--------
>  mm/page_alloc.c                | 28 ++++++++--------------------
>  3 files changed, 9 insertions(+), 37 deletions(-)
>
> diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
> index a7e3a3405520..74f81a52e7e1 100644
> --- a/include/linux/page-flags.h
> +++ b/include/linux/page-flags.h
> @@ -135,9 +135,6 @@ enum pageflags {
>  #ifdef CONFIG_ARCH_USES_PG_ARCH_X
>         PG_arch_2,
>         PG_arch_3,
> -#endif
> -#ifdef CONFIG_KASAN_HW_TAGS
> -       PG_skip_kasan_poison,
>  #endif
>         __NR_PAGEFLAGS,
>
> @@ -594,12 +591,6 @@ TESTCLEARFLAG(Young, young, PF_ANY)
>  PAGEFLAG(Idle, idle, PF_ANY)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -PAGEFLAG(SkipKASanPoison, skip_kasan_poison, PF_HEAD)
> -#else
> -PAGEFLAG_FALSE(SkipKASanPoison, skip_kasan_poison)
> -#endif
> -
>  /*
>   * PageReported() is used to track reported free pages within the Buddy
>   * allocator. We can use the non-atomic version of the test and set
> diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
> index 9db52bc4ce19..c448694fc7e9 100644
> --- a/include/trace/events/mmflags.h
> +++ b/include/trace/events/mmflags.h
> @@ -96,12 +96,6 @@
>  #define IF_HAVE_PG_ARCH_X(flag,string)
>  #endif
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string) ,{1UL << flag, string}
> -#else
> -#define IF_HAVE_PG_SKIP_KASAN_POISON(flag,string)
> -#endif
> -
>  #define __def_pageflag_names                                           \
>         {1UL << PG_locked,              "locked"        },              \
>         {1UL << PG_waiters,             "waiters"       },              \
> @@ -130,8 +124,7 @@ IF_HAVE_PG_HWPOISON(PG_hwpoison,    "hwpoison"      )               \
>  IF_HAVE_PG_IDLE(PG_young,              "young"         )               \
>  IF_HAVE_PG_IDLE(PG_idle,               "idle"          )               \
>  IF_HAVE_PG_ARCH_X(PG_arch_2,           "arch_2"        )               \
> -IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )               \
> -IF_HAVE_PG_SKIP_KASAN_POISON(PG_skip_kasan_poison, "skip_kasan_poison")
> +IF_HAVE_PG_ARCH_X(PG_arch_3,           "arch_3"        )
>
>  #define show_page_flags(flags)                                         \
>         (flags) ? __print_flags(flags, "|",                             \
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index 7136c36c5d01..2509b8bde8d5 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -1380,7 +1380,7 @@ static inline bool should_skip_kasan_poison(struct page *page, fpi_t fpi_flags)
>         return deferred_pages_enabled() ||
>                (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
>                 (fpi_flags & FPI_SKIP_KASAN_POISON)) ||
> -              PageSkipKASanPoison(page);
> +              page_kasan_tag(page) == 0xff;

Please also update the comment above should_skip_kasan_poison.

I think we can drop #3 and #4 from that comment and instead add a more
generic #3: "Page tags have not been assigned, as unpoisoning has been
skipped".

>  }
>
>  static void kernel_init_pages(struct page *page, int numpages)
> @@ -2511,22 +2511,13 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>                 /* Take note that memory was initialized by the loop above. */
>                 init = false;
>         }
> -       if (!should_skip_kasan_unpoison(gfp_flags)) {
> -               /* Try unpoisoning (or setting tags) and initializing memory. */
> -               if (kasan_unpoison_pages(page, order, init)) {
> -                       /* Take note that memory was initialized by KASAN. */
> -                       if (kasan_has_integrated_init())
> -                               init = false;
> -                       /* Take note that memory tags were set by KASAN. */
> -                       reset_tags = false;
> -               } else {
> -                       /*
> -                        * KASAN decided to exclude this allocation from being
> -                        * (un)poisoned due to sampling. Make KASAN skip
> -                        * poisoning when the allocation is freed.
> -                        */
> -                       SetPageSkipKASanPoison(page);
> -               }
> +       if (!should_skip_kasan_unpoison(gfp_flags) &&
> +           kasan_unpoison_pages(page, order, init)) {
> +               /* Take note that memory was initialized by KASAN. */
> +               if (kasan_has_integrated_init())
> +                       init = false;
> +               /* Take note that memory tags were set by KASAN. */
> +               reset_tags = false;
>         }
>         /*
>          * If memory tags have not been set by KASAN, reset the page tags to
> @@ -2539,9 +2530,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>         /* If memory is still not initialized, initialize it now. */
>         if (init)
>                 kernel_init_pages(page, 1 << order);
> -       /* Propagate __GFP_SKIP_KASAN_POISON to page flags. */
> -       if (kasan_hw_tags_enabled() && (gfp_flags & __GFP_SKIP_KASAN_POISON))
> -               SetPageSkipKASanPoison(page);

With this removed, __GFP_SKIP_KASAN_POISON is no longer used and can
be removed too.


>
>         set_page_owner(page, order, gfp_flags);
>         page_table_check_alloc(page, order);
> --
> 2.39.2.637.g21b0678d19-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc-iLXbEUzYhEZtY5wHc%3DG3p%3Dm-fuNdVsmovg-MT8c-6g%40mail.gmail.com.
