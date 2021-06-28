Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GK4WDAMGQEDOK36VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id E3A3F3B58E0
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jun 2021 08:00:21 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id l13-20020a4ae2cd0000b029024c17ace030sf9479482oot.8
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Jun 2021 23:00:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624860020; cv=pass;
        d=google.com; s=arc-20160816;
        b=i/sjki1wF+su/Zj9CakYVTfM3OmZ4bYYBQ/IYM9KqzVPjpHodI/+a8qNRHWANUmQVP
         RR1hvxLH5HYo7r+uSL9T01pzgmmuZcjRsEgG1aYkz2fR0pEygvcSwoRyRqYoiCsKFSEQ
         AyYoRL46RFClQPZaAIJOWuayJ7qUUa4OzvmF3Cs3+Jx31SJzVNrg8X5k1iZ7Lxjnv1pz
         qmpNDCQEI9Vj2h2T0GeZstrQzcKg5X8c8rR9D4q/sBVbE9Xr1V6cMS3CHWv3kygTNMFh
         2U0UWf+HcfGjNneYK5vC//YW88ztuhwIEt2+Peij0/CGfMbIouhjZIF8hVrHpGQYG8u6
         KBEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aKny+hb5m35lmeavRP5xnPPAFzIZbCwQ0tI+5Li6XhU=;
        b=kjwQozpCdSphdzHSFDkxiZod27bBLEb1LyWHc21wVSLCOJmqiluS1JOrADcxudtrsU
         ulTdMKnX+nRUdjk7fGIovrfy4u9CSAStwxZkCqYDVSMkhwSxl/QLBsoqDB4Z30tx4vzr
         guQ1lF0ZeDfIG1AtSXmVOfwINhq7GyIC8i+UyB8y+YmrrlZq25nmiSbKCJGVfy3bNQWG
         I6g3LmXY5Dj/O5Gnt+mTGYbVGRrhtx1Sr6bXSifuM1PAdtV8eevSmy0NY2T+l5mxf7WW
         SG/PJ/QCpI5CqhFvqyWqE73jvGHr4Jj0dkrzHeW4yCwUsbAkDQDvZZ1Mwh6GASkaH847
         xfQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LMUpZBEy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aKny+hb5m35lmeavRP5xnPPAFzIZbCwQ0tI+5Li6XhU=;
        b=U/7HOIbb4nlPPbidmvC9f2Z1mgYs7fxbMiFXQ2KbLLnnahUOiIRrkzFAtArjVMVnVw
         a6nUrAWaoWsEWrhadGWBcs8SN8cQ4I9QSJValMb4RpR2jhutkM3NQMJCTNwoRQm2knhy
         y8pKrmkKS7CqZHneFJWyE4NK4P9cDDsKVK3zqOUWgPBrPqipF4oZIzvKoaBiVT+PwMv6
         QCIdsSS8MwPcuTBXXdSJ1o0005/9NBcSAUjUqF1HebPSHtYu3u5bT77pawfbfhQvshvh
         7xrsMhV8aLHAthIM5mqQVRKNF14Zrc1sN82amHKKecoTCCf/yzu5CIdfv+KORRpH3Gi/
         Corw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aKny+hb5m35lmeavRP5xnPPAFzIZbCwQ0tI+5Li6XhU=;
        b=PeV4sc5uSbCs6VBO2oZw8FggbEbfXPRQkvEf6yfX9C03uBMVvxViDKgG5qJpKi7YS1
         jePY+Hz+QKk3taa2aH3EqbGt8bWoqxOI09X7odw2pYc58AZ/lTKIS8msCuNT9Q+wrglq
         VXm6LHIm42Wk9RUyHHVCPbFIilTHMqADYY3Dnyxh244iVE5uXYzTkRrKb+KHgyJ39gJI
         2KR4JuBGMbLddw8m63n+gouLSlSGCKMYw5f9UTJVrGJsk2ZTwhxpAE9aLevmKjFyqDlS
         Io0dOzwskJkIlZKq9qbHy3txfBmBbdR0CtJK5SpXJw84jVZrdBlfPS5v9xOwAS77/rZG
         wepw==
X-Gm-Message-State: AOAM532P+CJ5HW09m1tz57dICK2bWWIm3MQcIxDkKylD6GQBR03xiX4P
	GIux7lhjwzibIfNMuyopSBw=
X-Google-Smtp-Source: ABdhPJyYSGFoktCvDGJ+3f+QyDroQnAaW8SeSzbTfQqGbc6YR3+kyN8JGeIvuhOwo7naIPwrZ78SRw==
X-Received: by 2002:a9d:2037:: with SMTP id n52mr2755772ota.303.1624860020670;
        Sun, 27 Jun 2021 23:00:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6242:: with SMTP id i2ls6089794otk.2.gmail; Sun, 27 Jun
 2021 23:00:20 -0700 (PDT)
X-Received: by 2002:a9d:72ca:: with SMTP id d10mr19343057otk.158.1624860020097;
        Sun, 27 Jun 2021 23:00:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624860020; cv=none;
        d=google.com; s=arc-20160816;
        b=WkjSn+33mc+QZyxs9XeajirvRfy77H2zUDCq+dLQkeNWpeP/yH7FeWplP3UmSkV8/q
         K1HIsGp0rwQusr7lvvgMsKvxbnT8aRS7nxIxbDPKNxhT4sbA/2uTHwKLj3YTvT09cXFu
         fNO1dG+b5REzV0bLk6Pt3MdACIzv5W9mnJiffxBjDu5tY0VnPi1JLbiemAtPZQ6AiaG1
         BW46US+3mGy3TfCFAKe5lBdel5O41di1WSOkke/ErnQaKa8GIK2e7FBHC5vILSNWRfIK
         drnHJ5/+GjOfPyJREvrWngz/JleVbsRhSOB3KfYCu3eriL6Gr07kn5b/+6bd0qPaXFxH
         /J4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OxWWpaIFrA1MZdBiGZNBP423mwRSvrkYLeFkLxi+psE=;
        b=Wr8UQLLcWbOWpGqsrhvL0bYpolzKu1/GN8n4KopS+XolTDTdwJ/yfldGBFD19GGomT
         H0+8KjSeUR7/s3y8OyPi9H5GfXSqtsKdY9dni0AA2+cg9ACvB79YZpbomSrb6G9C6nUs
         nrvCQYi9XdjzZfEHXrPAZUx35Pb+BvCc+pJBX/1L49REPepUX2jdb3ibTmcnseom7zM0
         i2amNtiJtqV3sOQe2S0VdS37YEuFIyc0EIC46sVSePDg+Tq2IbUXceZNpKmuSuHEQvWK
         7MIR9OcW/MmJ/AvOEzTwYOaqMGldVl3TAYn9wqPCwgZD8g29AsWccPPQyqsxTCap09J8
         JaqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LMUpZBEy;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22e.google.com (mail-oi1-x22e.google.com. [2607:f8b0:4864:20::22e])
        by gmr-mx.google.com with ESMTPS id m16si1539672oih.4.2021.06.27.23.00.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Jun 2021 23:00:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as permitted sender) client-ip=2607:f8b0:4864:20::22e;
Received: by mail-oi1-x22e.google.com with SMTP id b2so18387425oiy.6
        for <kasan-dev@googlegroups.com>; Sun, 27 Jun 2021 23:00:20 -0700 (PDT)
X-Received: by 2002:aca:ba06:: with SMTP id k6mr16229848oif.70.1624860018200;
 Sun, 27 Jun 2021 23:00:18 -0700 (PDT)
MIME-Version: 1.0
References: <20210626100931.22794-1-Kuan-Ying.Lee@mediatek.com> <20210626100931.22794-2-Kuan-Ying.Lee@mediatek.com>
In-Reply-To: <20210626100931.22794-2-Kuan-Ying.Lee@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 28 Jun 2021 08:00:00 +0200
Message-ID: <CANpmjNO6k5=0HMf-Y3j70iTKLKY8XJAiLDDrfNf4-3cLASxHOA@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to CONFIG_KASAN_TAGS_IDENTIFY
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org, 
	wsd_upstream@mediatek.com, chinwen.chang@mediatek.com, 
	nicholas.tang@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LMUpZBEy;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22e as
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

On Sat, 26 Jun 2021 at 12:09, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> This patch renames CONFIG_KASAN_SW_TAGS_IDENTIFY to
> CONFIG_KASAN_TAGS_IDENTIFY in order to be compatible
> with hardware tag-based mode.
>
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Suggested-by: Marco Elver <elver@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  lib/Kconfig.kasan         | 2 +-
>  mm/kasan/kasan.h          | 4 ++--
>  mm/kasan/report_sw_tags.c | 2 +-
>  mm/kasan/sw_tags.c        | 4 ++--
>  4 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index c3b228828a80..fdb4a08dba83 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -167,7 +167,7 @@ config KASAN_STACK
>           instrumentation is also disabled as it adds inline-style
>           instrumentation that is run unconditionally.
>
> -config KASAN_SW_TAGS_IDENTIFY
> +config KASAN_TAGS_IDENTIFY
>         bool "Enable memory corruption identification"
>         depends on KASAN_SW_TAGS
>         help
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 7b45b17a8106..952df2db7fdd 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -153,7 +153,7 @@ struct kasan_track {
>         depot_stack_handle_t stack;
>  };
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>  #define KASAN_NR_FREE_STACKS 5
>  #else
>  #define KASAN_NR_FREE_STACKS 1
> @@ -170,7 +170,7 @@ struct kasan_alloc_meta {
>  #else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
>  #endif
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
>         u8 free_track_idx;
>  #endif
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 3d20d3451d9e..821a14a19a92 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -31,7 +31,7 @@
>
>  const char *kasan_get_bug_type(struct kasan_access_info *info)
>  {
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         struct kasan_alloc_meta *alloc_meta;
>         struct kmem_cache *cache;
>         struct page *page;
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 9362938abbfa..dd05e6c801fa 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -177,7 +177,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
>         if (!alloc_meta)
>                 return;
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         idx = alloc_meta->free_track_idx;
>         alloc_meta->free_pointer_tag[idx] = tag;
>         alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> @@ -196,7 +196,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
>         if (!alloc_meta)
>                 return NULL;
>
> -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
>         for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
>                 if (alloc_meta->free_pointer_tag[i] == tag)
>                         break;
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210626100931.22794-2-Kuan-Ying.Lee%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO6k5%3D0HMf-Y3j70iTKLKY8XJAiLDDrfNf4-3cLASxHOA%40mail.gmail.com.
