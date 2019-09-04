Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUP7X3VQKGQEJ2OFJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id DD6CAA83E7
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 15:44:50 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id y18sf8081315plr.20
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Sep 2019 06:44:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567604689; cv=pass;
        d=google.com; s=arc-20160816;
        b=ubY8BpVbIYwlYs/rBLvbAIRH730/CSv72WAeh5LNWyyayREDMuDcE9BXwRKp2jRktQ
         XEvXH2TLpqVob9f1Hhs/joFZY7ehhQeWgva3Fn6RlZfMDTyoQZlfJXbNKvpAaPI6O1Bp
         Fye2Hgp7DLvI1RlxderIOTWLx2ezlne6VdhT7flFEc/UEjFHgaGfEbqzEfg3ijCjgjCT
         DxgOQqObNycYZzzVCkP93n2tudbGG5YxWRUCAn0kjxrtRxiWflbU6/5Y5w/UWhngQs5J
         X/EfsKw867x3ZJ1VxqOlIef7VVlj3i1Q7xfyB/b2SQ7RuzSm6nwLiuySDaV/fHTYyDKG
         sPww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aTEyPYcOWQNHl0AoawbKxlh9oWq4a6CapRKHixgyLTQ=;
        b=fwgYV1rKTyDsulSQLxBJh1aIprfGh0U2MH7dScdPAOD0nNgxMkaTh3v5jP7q0Twi3x
         lREtUNekkHojE/r5Klrd3Nt9Rl7fcfwpUlgRF3Pw+JvPDTEmYXgbC/cGiXPsL+xCCmxw
         SC+QDOCNwweCLN5GZ94+KbpTYDjygJk9jU4a8n9zCy+uBsv6nZcAb/ofGnYhM8eu2ZdJ
         jmpdtKz97VI58JnRPOQqvqCyYkQuKoI0OdN/N7A568KB6Tailj/nuLp6DTC0xgXeolxt
         nqBaHlLoxerNNdQAU7gKcKjPoc4Ya0AATupgv5d+uIJrZbnTilq1bkntdHNVCuitBzue
         035A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=luGclcN1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aTEyPYcOWQNHl0AoawbKxlh9oWq4a6CapRKHixgyLTQ=;
        b=NY2b++036oSt6Yzk/kMW3lGxpxB+dBDpgD5xCx82svwXQ/RLXdHGX7y9SEbQZdk7I+
         UhpM7V6ucucRNSsB4aQZUYMQgIyKBoUxwnWeOriLaWw/+7x21XRAEs1PS1c1m6bSZI3Z
         lS5QHef+km7IR/26uK5ZsbsXYjG5iu+/3kuyeWp2w4CxAC6bWz5+qIfegotBjfnKcAHy
         +6XwSTQgSQytL9gJxEL1bLq0DQAWkbvv8f21hzgrGdQSbOcdVLA7Qe5A4H0Ume8jehGx
         HcixbtM06upyQaf32acnXaiAz+MQlQQ6Odsx2FFalEVbHE8R304tOBbaMfj/Xzzqe9fy
         0KhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aTEyPYcOWQNHl0AoawbKxlh9oWq4a6CapRKHixgyLTQ=;
        b=lmTvzszdvYO/V5jhQ1+u4/LXq3rab5wmtevRw5sevp+uvcCY78n4ivEjpg4ph/LaN9
         p+mvuCkeSjAl5sZLh5DeOOVQbSmToCeNX0wVO33ues0/gruLGtB67hFpNY/dJhjVGksL
         abJ0+oA2IUgIowGm4S4Vhcr6GhKWiW1klPFFKdpDWYf6h5SviHWRBAHJq4XVlTf2NYVH
         Gl4RdhTvP1cxsXUxzdtVRpPBA5pf5Qb1fmSLlNfMf10Kw+PMyrhuWvRHFN4JLST+RuC3
         r03EKGO5JB4LnbFrKm1eJyJ5FCX82OWJVR163lZmRuvPUdaLuV6RcFdbA62rr0cSCXP8
         Ih4g==
X-Gm-Message-State: APjAAAWUsKsNvQYmXCkE5tiYgym9bx6jmYdQr0wyeF25swCQmcRG1un4
	/o9ZNTskADU2UrMCARvqG1E=
X-Google-Smtp-Source: APXvYqwVOBsbKNbuPfpW9GcZXqURlZZ9hsLIeCdMM8CfglRkG0nS4ivmbuJtwSe3SryGiuJKznN4Uw==
X-Received: by 2002:aa7:980c:: with SMTP id e12mr18961460pfl.79.1567604689501;
        Wed, 04 Sep 2019 06:44:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:20c8:: with SMTP id v8ls6532030plg.11.gmail; Wed, 04
 Sep 2019 06:44:49 -0700 (PDT)
X-Received: by 2002:a17:902:b605:: with SMTP id b5mr11639171pls.103.1567604689165;
        Wed, 04 Sep 2019 06:44:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567604689; cv=none;
        d=google.com; s=arc-20160816;
        b=uAtDJI2D3OPu7GrOmemBptRqP8P+86Q5pByJcq8JZ8imvZf/YG7DR/0Ioul/bdffnT
         yiOewOgb3RV16MtJiudwGU01yVlYMdc5LuncFGZxw3RP/GJdVlNQKubUtaNqXm8c2ffR
         wrL2EXYMCn7cGhiJ2GOzlOOWSoQdJTMEzb5wUV499dETdTTikEW9BS0f2K7CbZCgOJUm
         SSnZg5P9DaeLfTzNE98TBB0EFUXrrSS598FTmt2YWkHW0Rys8rByKf6iLwnAFJg4B+K+
         aWfzq0UKfsXdbEDIBhROh8iPP/yJfGhGwzMLfn24Is3RaDT4VdAcgoxNkDdZoOwr3Zp9
         /VDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=W721XQEkMG8bC4j2PepgMeY0jTQOErIpXztyfiJXOs8=;
        b=mSlOIqiMG7cm25V0i1g7jpy1Szr1q0Lu2n2AU+07ybXe0r1DJ1EaI4CTypm+OStNUW
         OgsYqs6gsWeZflnzRzOmXojGYiIUKbDMQw8g6sDMKnx7aFvcVh10YA8sI/lyQYKBgslm
         7ODOlBKVTohJoWHGTvaPl7dDuFr+Hy+lbM4/vsDUBB8LHpJklY8Ap0ehorBT5gRxjNWe
         Sx7ujWuLIf09NA2ZPf11kimKjY4VMOj7u0reKI2heukmRivgWikTc32D1CA02tP0ClyE
         iTNdRb5TNXKRTF8tXD01x43MlbGD0Hk8cu9Z4uGjtdf38PNNoIHKcdzDvdi653rtpkV8
         8N8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=luGclcN1;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id c6si690840pls.5.2019.09.04.06.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Sep 2019 06:44:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id w22so4829170pfi.9
        for <kasan-dev@googlegroups.com>; Wed, 04 Sep 2019 06:44:49 -0700 (PDT)
X-Received: by 2002:a17:90a:ff08:: with SMTP id ce8mr4950627pjb.123.1567604688325;
 Wed, 04 Sep 2019 06:44:48 -0700 (PDT)
MIME-Version: 1.0
References: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20190904065133.20268-1-walter-zh.wu@mediatek.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Sep 2019 15:44:37 +0200
Message-ID: <CAAeHK+wyvLF8=DdEczHLzNXuP+oC0CEhoPmp_LHSKVNyAiRGLQ@mail.gmail.com>
Subject: Re: [PATCH 1/2] mm/kasan: dump alloc/free stack for page allocator
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Martin Schwidefsky <schwidefsky@de.ibm.com>, 
	Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream@mediatek.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=luGclcN1;       spf=pass
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

On Wed, Sep 4, 2019 at 8:51 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> This patch is KASAN report adds the alloc/free stacks for page allocator
> in order to help programmer to see memory corruption caused by page.
>
> By default, KASAN doesn't record alloc/free stack for page allocator.
> It is difficult to fix up page use-after-free issue.
>
> This feature depends on page owner to record the last stack of pages.
> It is very helpful for solving the page use-after-free or out-of-bound.
>
> KASAN report will show the last stack of page, it may be:
> a) If page is in-use state, then it prints alloc stack.
>    It is useful to fix up page out-of-bound issue.
>
> BUG: KASAN: slab-out-of-bounds in kmalloc_pagealloc_oob_right+0x88/0x90
> Write of size 1 at addr ffffffc0d64ea00a by task cat/115
> ...
> Allocation stack of page:
>  prep_new_page+0x1a0/0x1d8
>  get_page_from_freelist+0xd78/0x2748
>  __alloc_pages_nodemask+0x1d4/0x1978
>  kmalloc_order+0x28/0x58
>  kmalloc_order_trace+0x28/0xe0
>  kmalloc_pagealloc_oob_right+0x2c/0x90
>
> b) If page is freed state, then it prints free stack.
>    It is useful to fix up page use-after-free issue.
>
> BUG: KASAN: use-after-free in kmalloc_pagealloc_uaf+0x70/0x80
> Write of size 1 at addr ffffffc0d651c000 by task cat/115
> ...
> Free stack of page:
>  kasan_free_pages+0x68/0x70
>  __free_pages_ok+0x3c0/0x1328
>  __free_pages+0x50/0x78
>  kfree+0x1c4/0x250
>  kmalloc_pagealloc_uaf+0x38/0x80
>
>
> This has been discussed, please refer below link.
> https://bugzilla.kernel.org/show_bug.cgi?id=203967
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> ---
>  lib/Kconfig.kasan | 9 +++++++++
>  mm/kasan/common.c | 6 ++++++
>  2 files changed, 15 insertions(+)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 4fafba1a923b..ba17f706b5f8 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -135,6 +135,15 @@ config KASAN_S390_4_LEVEL_PAGING
>           to 3TB of RAM with KASan enabled). This options allows to force
>           4-level paging instead.
>
> +config KASAN_DUMP_PAGE
> +       bool "Dump the page last stack information"
> +       depends on KASAN && PAGE_OWNER
> +       help
> +         By default, KASAN doesn't record alloc/free stack for page allocator.
> +         It is difficult to fix up page use-after-free issue.
> +         This feature depends on page owner to record the last stack of page.
> +         It is very helpful for solving the page use-after-free or out-of-bound.

I'm not sure if we need a separate config for this. Is there any
reason to not have this enabled by default?

> +
>  config TEST_KASAN
>         tristate "Module for testing KASAN for bug detection"
>         depends on m && KASAN
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..2a32474efa74 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -35,6 +35,7 @@
>  #include <linux/vmalloc.h>
>  #include <linux/bug.h>
>  #include <linux/uaccess.h>
> +#include <linux/page_owner.h>
>
>  #include "kasan.h"
>  #include "../slab.h"
> @@ -227,6 +228,11 @@ void kasan_alloc_pages(struct page *page, unsigned int order)
>
>  void kasan_free_pages(struct page *page, unsigned int order)
>  {
> +#ifdef CONFIG_KASAN_DUMP_PAGE
> +       gfp_t gfp_flags = GFP_KERNEL;
> +
> +       set_page_owner(page, order, gfp_flags);
> +#endif
>         if (likely(!PageHighMem(page)))
>                 kasan_poison_shadow(page_address(page),
>                                 PAGE_SIZE << order,
> --
> 2.18.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190904065133.20268-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwyvLF8%3DDdEczHLzNXuP%2BoC0CEhoPmp_LHSKVNyAiRGLQ%40mail.gmail.com.
