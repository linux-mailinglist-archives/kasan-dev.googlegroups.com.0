Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBHSZ74QKGQEUL2SVWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CE3D242B0D
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 16:13:25 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id t13sf1915794pjd.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 07:13:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597241604; cv=pass;
        d=google.com; s=arc-20160816;
        b=yDUe3q1hfvpZ8dbTl3zq/+YNw0b+WOu9SWQO/SE4tvkuZ4a1h/nizRXlCfWh8oq16C
         Z+5ijy0LGjNcgK8HXTUx341D+b3BnyUpgWfcl0cO6yB03/HOHIRjMV3HYx0rWdF2p9OO
         5s1BlsVCL2HrysXaUm5hbnpC5vtnq/AM4/V5S5eAjA5FNprz3yP2IEd52BL/SAA6w4Ew
         TBsi4jSLWtiPyQm+DHskXOwfrL3TPjalCOt9w7J5+0io6S6NxZXBPUIBwRZy6L3Y50Tg
         86s/efuMteEyJFVBHm9oyU+p/9ObM1jhwzJXWEE41SJyeiRbgfhd/rjd8wnSvDlq8pcT
         +XaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+/GM0TzmRpQCwXdo+fMkLlup6o0JxABEVb+e0tImn+E=;
        b=VI8lO7TYCLC7g94DP1o/VpqjXkupZhi4XeI0+qhelM2a0sgrq5TQLLQB91S5i4XAjy
         wFZAc1HW1Nlda/7KzDeQ4zwfg5cAj5P2XSzPJz7cd/sOGyR/6YV4NGXTEOrgEU+Y94G8
         FE92j+ry9gF3uDWLgC8NajnmvDkdhJVoHkJolupMi9V/lMkodfRonD8O//KwJemn/fJZ
         4nK6FL8QI9SQIq7hlfQiByMz3EW3J9RtEYj+tbT31ux5cQQ4iUkSCjmswY3euKPnBfU6
         Yp+NwWgNKtJ+YO3jjSQsyCsDLMHc6JINyR40/7X1N9cZJ9JhSvkzQ4tdRaCB9tcxam4I
         qkSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ZyrDNv/E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+/GM0TzmRpQCwXdo+fMkLlup6o0JxABEVb+e0tImn+E=;
        b=qAjZtPC97ovy2eENA/1RAuqV0aRxxzQMkbOlwCiOa13ObQSbGIWiwxwDWmyjnboWSo
         M6Ssa94zIK6nahBqeJoBP/2jn4dxV7VQBwzO72kLZc2o8XNfRosw8zdR+JyZxJ5IkFOn
         pPIAnkUuXfxRXPmouM8N/OTAUTVThY1Ckvt/58mPS/vX8Krl34VpDMJxsNSrW3/qiEUC
         4cch0ZjQoeQCVy9kK7VleK3bE16iKfXFo2A3oxfPfEnaQat4mP8K8l0wFwRdwLu49j+W
         00BJaBW2v02O5k4p7Qu7Ri2XW8Z0ML0JaC+PLt7FUwpIk37KDCM8bVRO4G8Asz9LIjO2
         gggg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+/GM0TzmRpQCwXdo+fMkLlup6o0JxABEVb+e0tImn+E=;
        b=A3bLjG4FO6ueV5ICcEiTq/Pki9YrIVfqm784RgZcHEwjwaIu2ATKVjB0uGl7iObr/M
         T0YBtgBKACPJJiMS9VJqW+x8fim8Hc9Pk1wu71sKcZxN/MICmo2Z3FB1pchi0PN1fYuH
         MwqYLfNJECKP7hdbUtZgKK0zorw1GEzdHFx8rOirssv0IPT8IAT2g0q9jbwmGr6eYXn/
         yo/i/JYiyx/6QQAcbDtwh7HZLjfOSEVAA8ATw3fCNf2O+jImTcHXMH3o5HZaB6sWhqHR
         cUayU9cSUe/dTCFW6FhXUfmsg6/7DFBd6g8GBanpXA8jpLYATiv6aDmJ3xP1lfaVPCDf
         q0pA==
X-Gm-Message-State: AOAM530Z2od3L19tEBrMxArc6x6BzCnl75t2oqM6ySArxe2MtA5Wqk2A
	tK0GVU4taotzZ7CIZUTKgEQ=
X-Google-Smtp-Source: ABdhPJxcBZc8jHK+q2sAbekyTyKMpWW8gH/ecYP0bXVTSB8zmp6602m79Xw0KoMkweuRMSZsldnc7g==
X-Received: by 2002:a17:902:768a:: with SMTP id m10mr5587392pll.125.1597241604078;
        Wed, 12 Aug 2020 07:13:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls1031782pls.5.gmail; Wed, 12
 Aug 2020 07:13:23 -0700 (PDT)
X-Received: by 2002:a17:902:bd47:: with SMTP id b7mr5716541plx.144.1597241603404;
        Wed, 12 Aug 2020 07:13:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597241603; cv=none;
        d=google.com; s=arc-20160816;
        b=HRuFnUrFy0cmiy/Os7XkqvMbiEyM6EpBkCoS4zkwGv3uhkui2gRzwnsyb1fVUUxfIu
         oVMWX2E3rjiReSIqOyTgJCwIx6Wp17ljkOfwHmLLu7DovyutcfodlNw+og1RdUtzd5+8
         9swZE/6EmQft/pyM6DBePtYaLgcJN6BsVeuHWROwylGSB9CldIEX93p3ei4KphpgLaT2
         3OLWM2yKHJGcXmYg4+Fr/QxOjrfhhrmPC41XWTZeZZakHG0LPXzmjQDTu5wGONPDmyAn
         9tBREaQKsag6dF/uklVMwpTMAEkyP1KL+o35W608fueWiish63ATS35ewn8qPReWaoZh
         M7HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Eny7GtW3fheHTjAaLnI+U+IUiSf5L2wZMby5TEt/uUU=;
        b=UQYLjikikquL+WQbCFqxGHeITAC24j5+OGTSe7phW8+6BjYvgxbYC8aNJWzt6vnqjI
         Xphk4i31EhCzqWsYB0HAXsLTr7bQPRRUkp/Flq6dPUdUAD/KhC8m1p21eF/kW5pIKMhO
         P8vcmbdzECfm8hH/vebV2kDCsKf7LfM4nh0hmPhgyDoMspqDx1XXLAGCvBIYO3aL9ULy
         kFcXlgQN+iYrT2B8ERQx7KAudrzgGbaXUDaKWSTDlfEZLccmlQ11Kjx8vovtB2LXXetb
         61NWn5c49cy82vGCl0NSvSnMxy3TX1+bSY7tHBwE7RfIeKrjafc/j2lTePf57+xDAvfQ
         AjzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="ZyrDNv/E";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id q137si78459pfc.4.2020.08.12.07.13.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Aug 2020 07:13:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id o21so1891303oie.12
        for <kasan-dev@googlegroups.com>; Wed, 12 Aug 2020 07:13:23 -0700 (PDT)
X-Received: by 2002:aca:d4d5:: with SMTP id l204mr7728838oig.70.1597241602391;
 Wed, 12 Aug 2020 07:13:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200810072313.529-1-walter-zh.wu@mediatek.com>
In-Reply-To: <20200810072313.529-1-walter-zh.wu@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Aug 2020 16:13:09 +0200
Message-ID: <CANpmjNO9=JBcSV-nif9a=4Zt7gTCp6e5c2jVXMCSFgP3v2P9-w@mail.gmail.com>
Subject: Re: [PATCH 1/5] timer: kasan: record and print timer stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="ZyrDNv/E";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Mon, 10 Aug 2020 at 09:23, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> This patch records the last two timer queueing stacks and prints
> up to 2 timer stacks in KASAN report. It is useful for programmers
> to solve use-after-free or double-free memory timer issues.
>
> When timer_setup() or timer_setup_on_stack() is called, then it
> prepares to use this timer and sets timer callback, we store
> this call stack in order to print it in KASAN report.
>
> Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Thomas Gleixner <tglx@linutronix.de>
> Cc: John Stultz <john.stultz@linaro.org>
> Cc: Stephen Boyd <sboyd@kernel.org>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> ---
>  include/linux/kasan.h |  2 ++
>  kernel/time/timer.c   |  2 ++
>  mm/kasan/generic.c    | 21 +++++++++++++++++++++
>  mm/kasan/kasan.h      |  4 +++-
>  mm/kasan/report.c     | 11 +++++++++++
>  5 files changed, 39 insertions(+), 1 deletion(-)

I'm commenting on the code here, but it also applies to patch 2/5, as
it's almost a copy-paste.

In general, I'd say the solution to get this feature is poorly
designed, resulting in excessive LOC added. The logic added already
exists for the aux stacks.

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 23b7ee00572d..763664b36dc6 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -175,12 +175,14 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
>  void kasan_cache_shrink(struct kmem_cache *cache);
>  void kasan_cache_shutdown(struct kmem_cache *cache);
>  void kasan_record_aux_stack(void *ptr);
> +void kasan_record_tmr_stack(void *ptr);
>
>  #else /* CONFIG_KASAN_GENERIC */
>
>  static inline void kasan_cache_shrink(struct kmem_cache *cache) {}
>  static inline void kasan_cache_shutdown(struct kmem_cache *cache) {}
>  static inline void kasan_record_aux_stack(void *ptr) {}
> +static inline void kasan_record_tmr_stack(void *ptr) {}

It appears that the 'aux' stack is currently only used for call_rcu
stacks, but this interface does not inherently tie it to call_rcu. The
only thing tying it to call_rcu is the fact that the report calls out
call_rcu.

>  /**
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 4b3cbad7431b..f35dcec990ab 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -347,6 +347,27 @@ void kasan_record_aux_stack(void *addr)
>         alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
>  }
>
> +void kasan_record_tmr_stack(void *addr)
> +{
> +       struct page *page = kasan_addr_to_page(addr);
> +       struct kmem_cache *cache;
> +       struct kasan_alloc_meta *alloc_info;
> +       void *object;
> +
> +       if (!(page && PageSlab(page)))
> +               return;
> +
> +       cache = page->slab_cache;
> +       object = nearest_obj(cache, page, addr);
> +       alloc_info = get_alloc_info(cache, object);
> +
> +       /*
> +        * record the last two timer stacks.
> +        */
> +       alloc_info->tmr_stack[1] = alloc_info->tmr_stack[0];
> +       alloc_info->tmr_stack[0] = kasan_save_stack(GFP_NOWAIT);
> +}

The solution here is, unfortunately, poorly designed. This is a
copy-paste of the kasan_record_aux_stack() function.

>  void kasan_set_free_info(struct kmem_cache *cache,
>                                 void *object, u8 tag)
>  {
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index ef655a1c6e15..c50827f388a3 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -108,10 +108,12 @@ struct kasan_alloc_meta {
>         struct kasan_track alloc_track;
>  #ifdef CONFIG_KASAN_GENERIC
>         /*
> -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> +        * call_rcu() call stack and timer queueing stack are stored
> +        * into struct kasan_alloc_meta.
>          * The free stack is stored into struct kasan_free_meta.
>          */
>         depot_stack_handle_t aux_stack[2];
> +       depot_stack_handle_t tmr_stack[2];
>  #else
>         struct kasan_track free_track[KASAN_NR_FREE_STACKS];
>  #endif
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index fed3c8fdfd25..6fa3bfee381f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -191,6 +191,17 @@ static void describe_object(struct kmem_cache *cache, void *object,
>                         print_stack(alloc_info->aux_stack[1]);
>                         pr_err("\n");
>                 }
> +
> +               if (alloc_info->tmr_stack[0]) {
> +                       pr_err("Last timer stack:\n");
> +                       print_stack(alloc_info->tmr_stack[0]);
> +                       pr_err("\n");
> +               }
> +               if (alloc_info->tmr_stack[1]) {
> +                       pr_err("Second to last timer stack:\n");
> +                       print_stack(alloc_info->tmr_stack[1]);
> +                       pr_err("\n");
> +               }

Why can't we just use the aux stack for everything, and simply change
the message printed in the report. After all, the stack trace will
include all the information to tell if it's call_rcu, timer, or
workqueue.

The reporting code would simply have to be changed to say something
like "Last potentially related work creation:" -- because what the
"aux" thing is trying to abstract are stack traces to work creations
that took an address that is closely related. Whether or not you want
to call it "work" is up to you, but that's the most generic term I
could think of right now (any better terms?).

Another argument for this consolidation is that it's highly unlikely
that aux_stack[a] && tmr_stack[b] && wq_stack[c], and you need to
print all the stacks. If you are worried we need more aux stacks, just
make the array size 3+ (but I think it's not necessary).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9%3DJBcSV-nif9a%3D4Zt7gTCp6e5c2jVXMCSFgP3v2P9-w%40mail.gmail.com.
