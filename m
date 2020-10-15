Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHOGUD6AKGQEJKYN6ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id E603528F01C
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 12:23:26 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id r4sf1530897pgl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 03:23:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602757405; cv=pass;
        d=google.com; s=arc-20160816;
        b=llXKXHGtJAzc4n2cyEbosJV2MP6breA7S30YaxIsfG4WHmb9rGF4iwaLtZAzslVd8T
         Pe+QrChZ25qFCg1chOceDYFo7bxwqjj8NPVioKawxnenpfvm4dTBSuWLtwvEHd7w1IRe
         iTbAwFlVFsarmpnE5OEuM4GivJHNqzG+825pR4z5WMo4O3h4vuhzAhqwu2rSmGWh/vHV
         1e1/xqi6NxCE7PoyHPqeMAAn4iA7TlJ8KDE6tDb0ngRBa3bi1l/L2/pDR1HtJOgo2COa
         DjeONYSJOPtm28frlpvUKZ0W7F2nwQOzVZXV3GixsXZTezBQ0I/86Enbwo8IQoey+SFT
         iRag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RPmk0zGx4bv2rLMeFAU8WeMRjDqUN7I9DpcqEqDNmf4=;
        b=B+tPHT+MCCorOxQFj4tmuCWa4UMshEZNTJ/wnd9q+3ki18OaTDK3mZcZOrou2ehWHE
         Uq1aLoOTLJm3HGHgjmrShl0u/RqrhPNQ1t2nEgCEMgSu3JVBR3gdL/ogDduPmoyKC7YY
         EDrL4fdWt0r56hTyd0I5VBVxSK/3xXoLLdWDiR3rA3q8OKe4Rcw627nkrTw2YYdLRHxj
         jodwQDMQAhIISX35ye16NV7cGXDtnlcelFhxbKTghV023QGPxgRKv4IYrdlyICRgyBLf
         yJqeL6NnqflJIp6W/037/yAoPe1NHLMtxzHhEA9/dfsBtOWpbociQlgsdIh0HrWvdUGo
         ijgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ix5+GbXn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RPmk0zGx4bv2rLMeFAU8WeMRjDqUN7I9DpcqEqDNmf4=;
        b=RBLV/xrwwKM1Y4igqLnWxEX3BEiEvStN59kFAmi+lVTrKMJWDv1YWYPK6Bnb7Ly1X6
         sZfzkOFirezMF5u0FvUKe7W8w8WWGL6A1rQIdDVmXNjFcjQme1IUZU6ARo+W71DcXGvU
         tlgdHL0tSJWEFUF5qlCu7dMpHg2v7WMxLW2TZAB84PyWXzaZuUYgrE+ochodx1aTCb37
         StQwtf3B8HDitSayOBF5/bJsv8UuhCkSF40MDe86Z+fYnoH9tXu/V4srWoIcXtUnqBxs
         vjC7+GbS9Ca+mKIiNfvwX0ZGm1ffio04rMtx9MJu02gxsqHLdlb4cOelyG07qdOTeDRu
         7xpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RPmk0zGx4bv2rLMeFAU8WeMRjDqUN7I9DpcqEqDNmf4=;
        b=k+twx+rEqPrhiuzMqrMjLZe1y0vKDgseRFu5c9YcyybMAQxO9w2d1q+u08OF63Nn1s
         RWJYkL4P01oUBRuNKI29MTvf5wrZHvXojfHhYeMn6rpLCN/ryNKxX3trlq9fyH8xdg8Q
         E1n2d2Lm0xo/NpYNdKtFPIEklojMbY/PmERpBdUGHaPQXfrYVGctU8E4mu2n9sK32Bo2
         R3vnvCMU455X+mb3CnopPFehkoP9TreoJ5DXRuhRlf4L8l09KFPpt3QTGps3hiBQxnIZ
         jVFs2DHy2dYV2Gbcxu5tj6orHU+I1WDUM8vvLh+//8+Pv23O9bU4jgVI4/i4zYwwV4Uh
         Ralg==
X-Gm-Message-State: AOAM532HSNrvHwELDwCSX9TUedojSm8rIqV7cdA/yZ0sVX90QZFoDgKR
	PLslieFf20s9jVtJtDfx87c=
X-Google-Smtp-Source: ABdhPJyB5w9EvU0EOBhwtVLxKL4h+ZorNBJV25wss6Gx2sgcwrA5Yfq1XAOhxvmprk6US6UMReGyYQ==
X-Received: by 2002:a63:131e:: with SMTP id i30mr2903134pgl.64.1602757405571;
        Thu, 15 Oct 2020 03:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:4486:: with SMTP id t6ls1273772pjg.0.canary-gmail;
 Thu, 15 Oct 2020 03:23:25 -0700 (PDT)
X-Received: by 2002:a17:90b:305:: with SMTP id ay5mr3718730pjb.129.1602757404920;
        Thu, 15 Oct 2020 03:23:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602757404; cv=none;
        d=google.com; s=arc-20160816;
        b=ixHkSpdGxr47Weyk4AzqeDJuIlmg7Uw4CjN83rd8hNcyQ6NUvzBjLJ7x19lz1HVd3h
         YXiIEjI7OZ8IPF5efS2HW2SPfa/5Frvhqmw3YNjlGd77cUCKOsy3oBdTzYm73/5iVkOz
         BIuUneC3+OHUMp56ETrhkRSnmbKXAmVo3hjUQQAlbLo1GVL+/32ztk1QNNmmtWtJfkrM
         znRFTQORdFe36Utm2YVOaqT1T4U9OiBKJ29K3hoaLqi7XHdumJkVtMZXbWJgQ/6zr3HL
         Hn9x+synFtRBhOR8ytQvQOvexpYiR+RluOLS8Hub+SmSjJ5tgZdVIz7S1TPkAdeZEKYL
         qMxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=E3eDemKpeFc1gJYyDDp5vYr/DT8MF8qWffPtgx/Rzdw=;
        b=aLEcRWPxgJwijE+gbdQAY1cXfTsIIJNoTMIho1SO2x0ACpk9qkb+WK7Y0SRtAKza8U
         2dioo0QG8uQvF5gaT8mWBN8EN8kyfY3ytMy0b4n1+pRnSHsUEVWI8OwAkL377+rs8Hpn
         Q99xQ5NhEA4wjX/V74DhWNfLxGhnaULUsxyDajOddPflldJxFNI7Ueiszn9LwW5NqX3S
         e4S7zvMgWz1QCD3U3Q4jZkSjUhCXZTVo41WuGtlFqWvk+soEga5zlQuOs3Km+LbNWF5R
         lNJRBMfcGJa0R+W44zJ3w0TAfBXzcbd7diggBV7fcGqZOqTUUe5Lk7/nfa+VVSAK2MeB
         7GYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ix5+GbXn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id c6si132585pjo.0.2020.10.15.03.23.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Oct 2020 03:23:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id t15so2458487otk.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Oct 2020 03:23:24 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr2228403otn.233.1602757404080;
 Thu, 15 Oct 2020 03:23:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <8fe7b641027ea3151bc84e0d7c81d2d8104d50d7.1602708025.git.andreyknvl@google.com>
In-Reply-To: <8fe7b641027ea3151bc84e0d7c81d2d8104d50d7.1602708025.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Oct 2020 12:23:12 +0200
Message-ID: <CANpmjNOKM8=MWPR2MPPrdu0fhvzwD4dDO-xnfeqcxOY1DQe09g@mail.gmail.com>
Subject: Re: [PATCH RFC 5/8] kasan: mark kasan_init_tags as __init
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ix5+GbXn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Similarly to kasan_init() mark kasan_init_tags() as __init.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558
> ---
>  include/linux/kasan.h | 4 ++--
>  mm/kasan/hw_tags.c    | 2 +-
>  mm/kasan/sw_tags.c    | 2 +-
>  3 files changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 7be9fb9146ac..af8317b416a8 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
>
>  #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
> -void kasan_init_tags(void);
> +void __init kasan_init_tags(void);
>
>  void *kasan_reset_tag(const void *addr);
>
> @@ -194,7 +194,7 @@ bool kasan_report(unsigned long addr, size_t size,
>
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
> -static inline void kasan_init_tags(void) { }
> +static inline void __init kasan_init_tags(void) { }

Should we mark empty static inline functions __init? __init comes with
a bunch of other attributes, but hopefully they don't interfere with
inlining?

>  static inline void *kasan_reset_tag(const void *addr)
>  {
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 2a38885014e3..0128062320d5 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -15,7 +15,7 @@
>
>  #include "kasan.h"
>
> -void kasan_init_tags(void)
> +void __init kasan_init_tags(void)
>  {
>         init_tags(KASAN_TAG_MAX);
>  }
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index c10863a45775..bf1422282bb5 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -35,7 +35,7 @@
>
>  static DEFINE_PER_CPU(u32, prng_state);
>
> -void kasan_init_tags(void)
> +void __init kasan_init_tags(void)
>  {
>         int cpu;
>
> --
> 2.28.0.1011.ga647a8990f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOKM8%3DMWPR2MPPrdu0fhvzwD4dDO-xnfeqcxOY1DQe09g%40mail.gmail.com.
