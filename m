Return-Path: <kasan-dev+bncBDW2JDUY5AORBLO7SOKQMGQEWN64D5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 05CD5547755
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 21:40:31 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id g11-20020a056e021e0b00b002d1b5e8389bsf1784906ila.2
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jun 2022 12:40:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654976429; cv=pass;
        d=google.com; s=arc-20160816;
        b=U4p4PFghdPNQBTi88D0qzoZiT4qvYfG8aKGGqKOABbk4jUQhVAiQQQqSWkAhMKBTsc
         Rqtl/J4djos/uhvk4Sx6OT10EpuQu1XDVG6bhu0eZGFuT77bET7EuubYsITd6jADX5Rm
         lyo8nj5RqT99TmJJd7oEq19YULy4/upzhwRAZHIDhcFTq8REX6eRdkW0YGtTCj5daV1u
         WeEKMyJ9DYZVw9duIKUHD/FMpQu2MnJlTqdPXxNLkkqT6lf65q0ZIZw3Rh1gYiS7hXCt
         ZrZJD0Z24L3Cq62KUY5F7gTwcnaFy1PFGifcuBsoZ/qPzxtrMlR9z50GzIVw6tPwxIaK
         sPRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=VKxlLSAR+RpHxMjIyT7D1ZhsbMjkUzcGNauJ4fDZG9c=;
        b=EEbFE7B/iK1tsjcZGYdWvBNPPRCwiX+PcVMUIaDcyWf6H7SGYPGZYWcYdszG0zG+K+
         1XAMqN/WAggI+DXt+k9tqQuJlz3CfDITJ8Cc0FW2ANhIy+Nhb664uotK7W/m1PJfHoTf
         kKpzDG+NUR/lUNKcVTqkc/zqXs9OqnDGLv1WF9qnuF4/0m3/SU7aenE+X47FFtZwKxLb
         BanXzdUaukU/uE0YHE8T++RQKw/wOCEsz/e80DRa97+bOV0Z29Nte0S6bhnQz0CCc6Pi
         xY6rkZ60KgVtdMmcLpm6wk4wlwjGGmU5ODOmNxYoDLBxpjp6UDLgF91kCAt+H2pzBmW8
         0VLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dQDzxrJO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKxlLSAR+RpHxMjIyT7D1ZhsbMjkUzcGNauJ4fDZG9c=;
        b=gLNddo84YxglFsuOf+So+RjCPMuSS+lK2LyjT1wrMQs6VPqi4M5zz5fB5RMAT5YkfQ
         4l/AeK2ASlI4jiqXU0jWTUmGGdt4lz6lzzIFZUas8ZRy05BrOY+UVktH27QbYq6X8f6f
         JQZz4SOqkKZO2gi8iLRTEjIcFJGP8/94VT73V9QiqFf8yd1mlvUh/UoROKRl3hgOcM0c
         q9IS8l6F3AfBHtFh3h8ydhUj4sTa39ikAIabv6n0aSf6yphW2Aqy1qsBEpzsW4eJDQJ5
         xIoI7l8mLaCz1joR0jCBnK5Yx12edctSE2/PATfGfsfaQ/7H30/VcESlmMZMBWdpEdRl
         IEnA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKxlLSAR+RpHxMjIyT7D1ZhsbMjkUzcGNauJ4fDZG9c=;
        b=P5hJskwRzFvgjHjMPKe5StnOVFkWRpHFoOOsFI0TS3dutPfTSLtCe1eEcMqeuh5OYD
         D3bro792ARJbykvDyamVWpeLCqc4OLFlSlKkHh5udpS+acDre0l8lw/HPtthkvVYainu
         aUvWgI2PwmaDLpBe1v/CKi9f0rqrjxxU3Ra4+3n313mAvgtZijeAQXBwZF3vYPwcTxq6
         v9aZ9ACAezVh6zYDEFtJT73uU5vEGE3GT977f6wEFdNBctEGSxVWXYyapEBvm90vFDzQ
         r07EjvP1dRsxV1xVMyE9joCBMbxWD49AhlDeWJe58HYhuCrRpNVHwTEgyjtvERem/HkZ
         Pvwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VKxlLSAR+RpHxMjIyT7D1ZhsbMjkUzcGNauJ4fDZG9c=;
        b=qMjTKduO4u6etHRKM3OcfoPgJbGpltB0MJNe/JaF35Hpn1d9WpwP1BwouG+g3CVEGo
         ugTraG217LUK61mWusi8hCDA5MCupt955Ejgy4BRpLtWtNDW3lJBSScE9agRbkyX9euv
         bdLZtOhYai7xvPG7wVKSDG9rlvpyi70hcnex2LjTLCYE9KyWpT4zBRPQzjh5kZc6hsNP
         ELjQpi1xetgTLCAzY+e1EeLXEalxFZN5B9M99P8YWUaKzdugpEdmy+HdNFiSwjnXw+X+
         ePYtZqEBOIJt9IHPijllJfelpkk7zkKGtc46Sk7M9fWL/GOGvkcaiGwxH7PHwB4iIz7K
         KfUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x5/VdAedV3mAZG2amrjB/rGyWAjaR8bmgz23jKoO0U6MD6JEf
	XksX9tp0GtEXlHd1zIbUjIc=
X-Google-Smtp-Source: ABdhPJyTXgMI4GHc1lMq8Oox/p8l7Gb3MdsctjjJtnsVWNDkq0/lhBiMZ5YL0Lcm7CyWU56i/WNJFw==
X-Received: by 2002:a05:6638:210e:b0:32e:b8e5:6a95 with SMTP id n14-20020a056638210e00b0032eb8e56a95mr27966876jaj.81.1654976429489;
        Sat, 11 Jun 2022 12:40:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13cf:b0:2d3:ed6a:7dba with SMTP id
 v15-20020a056e0213cf00b002d3ed6a7dbals325341ilj.5.gmail; Sat, 11 Jun 2022
 12:40:29 -0700 (PDT)
X-Received: by 2002:a92:d0a:0:b0:2d1:e698:5c4c with SMTP id 10-20020a920d0a000000b002d1e6985c4cmr29017532iln.316.1654976429091;
        Sat, 11 Jun 2022 12:40:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654976429; cv=none;
        d=google.com; s=arc-20160816;
        b=AMTUaR/XdhQ1nhg2UklMOv20Yu3jq8cHNtAAKkyX/qZWXvHWbcYrr17C3yi8n1h8SW
         O0ghdxPr/JH5fjMfAp5ev960HsErZz62pi5AUMcfh+lhxhvaMMk1qywZHAF0yD+fDaJM
         CYkhZRRpty3CpOqVZJOvSpvIPPo9nLvwGU0lWbZzrKwu7TLCqyOc7Z+xmZAoc6R0nvOx
         HTq1tIQz2QxV3C6hOSr9gua0nPVhX6Gl3WPFIpfpo7+mQevqldQsnsUA0HGr9o0lwk2E
         KNLH1pm0hoe6VS0DM/3mLdXBIrsXQ6PkYT7BZGR5tJIUtl3Pj/Zs4mVQbEZlTWWu4lkK
         Mk9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mBGmgWIEi6th7haHGtOWQls1XjGMLO5xWRfb+f0EMbU=;
        b=g+lgFFpe4s28k9ReANmz39Rkq1xv+1brd0LB1NU15+RD0V5DzcChr59ubSSJfl7OrS
         v+IIIzrVAkyGdOiyxXnyhDKN2pd6BcbAsjuNYSHh2uCoXE8YmGjAYFaABQtFe2dWzUEa
         bRXhAF2jq+d8RJPSYuzqPfFrSMVAnWX+WQb7oiZjxBxwULDW6rv9lc5aLHB5+ciSqPe+
         3jGr2dEM8Fbi5db4wACUBu8+1Frw3m2OK1r/mBrdf0SaXH2lYlbONMsbuhWFX6su4AW7
         1ae7arlMvn89UHemhsINX0HVwle2mzI4ujsvrgzuQw1NufVFazFOGFbYGmPZ/SKNJfZU
         Wlpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dQDzxrJO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id v3-20020a92cd43000000b002d3c49040dasi104147ilq.5.2022.06.11.12.40.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 11 Jun 2022 12:40:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id y79so2316061iof.2
        for <kasan-dev@googlegroups.com>; Sat, 11 Jun 2022 12:40:29 -0700 (PDT)
X-Received: by 2002:a05:6638:d0a:b0:32f:21fd:cbac with SMTP id
 q10-20020a0566380d0a00b0032f21fdcbacmr29083509jaj.22.1654976428952; Sat, 11
 Jun 2022 12:40:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220610152141.2148929-1-catalin.marinas@arm.com> <20220610152141.2148929-4-catalin.marinas@arm.com>
In-Reply-To: <20220610152141.2148929-4-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 11 Jun 2022 21:40:18 +0200
Message-ID: <CA+fCnZdKDh6YS9chzuqED0-uyibBYHMz8Gkd5=aU-eB4ADGJaQ@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dQDzxrJO;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
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

On Fri, Jun 10, 2022 at 5:21 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> Currently post_alloc_hook() skips the kasan unpoisoning if the tags will
> be zeroed (__GFP_ZEROTAGS) or __GFP_SKIP_KASAN_UNPOISON is passed. Since
> __GFP_ZEROTAGS is now accompanied by __GFP_SKIP_KASAN_UNPOISON, remove
> the extra check.
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/page_alloc.c | 12 +++++-------
>  1 file changed, 5 insertions(+), 7 deletions(-)
>
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index f6ed240870bc..bf45a6aa407a 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2361,7 +2361,7 @@ static inline bool check_new_pcp(struct page *page, unsigned int order)
>  }
>  #endif /* CONFIG_DEBUG_VM */
>
> -static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
> +static inline bool should_skip_kasan_unpoison(gfp_t flags)
>  {
>         /* Don't skip if a software KASAN mode is enabled. */
>         if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
> @@ -2373,12 +2373,10 @@ static inline bool should_skip_kasan_unpoison(gfp_t flags, bool init_tags)
>                 return true;
>
>         /*
> -        * With hardware tag-based KASAN enabled, skip if either:
> -        *
> -        * 1. Memory tags have already been cleared via tag_clear_highpage().
> -        * 2. Skipping has been requested via __GFP_SKIP_KASAN_UNPOISON.
> +        * With hardware tag-based KASAN enabled, skip if this has been
> +        * requested via __GFP_SKIP_KASAN_UNPOISON.
>          */
> -       return init_tags || (flags & __GFP_SKIP_KASAN_UNPOISON);
> +       return flags & __GFP_SKIP_KASAN_UNPOISON;
>  }
>
>  static inline bool should_skip_init(gfp_t flags)
> @@ -2430,7 +2428,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>                 /* Note that memory is already initialized by the loop above. */
>                 init = false;
>         }
> -       if (!should_skip_kasan_unpoison(gfp_flags, init_tags)) {
> +       if (!should_skip_kasan_unpoison(gfp_flags)) {
>                 /* Unpoison shadow memory or set memory tags. */
>                 kasan_unpoison_pages(page, order, init);
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdKDh6YS9chzuqED0-uyibBYHMz8Gkd5%3DaU-eB4ADGJaQ%40mail.gmail.com.
