Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FDTCIQMGQECHWRVOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FEA04D00BB
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 15:08:42 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id u13-20020a4ab5cd000000b002e021ad5bbcsf11551229ooo.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Mar 2022 06:08:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646662121; cv=pass;
        d=google.com; s=arc-20160816;
        b=EOBxiE0ESNlIh4uX5Zn0J8BiGynoqkj90m+NAnoXa6raSoJqBXwnKsUz8VDRZUQxjo
         6WkerIHEKHCO5YPPE9mwwy0j4Ae1TKO82q/gfQj8t7yhldwH565SElrUhb9xXKX8LgqC
         RvDjmHyfs+hxmTvfraqMRtCEseZ96G0Jh8Xug3bYswaSafnvbT7gQz/oP3tcrAdB/cOc
         JvpLg3KLbCVkkPkagBqgTOP6qpMH8LsbLYvyFKRk8TJbfwRoDnpsm+48/wkH8HTBrOnT
         gFzI0sN6epDs8R/e0b9+H48ESE4PKa0/JlqbE4xu0rvSOEHaX3FlRr/AC5DYtHyt56eA
         29CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SV9bwMffIxmAhIaP9GKZ7fbJMFGZzs4ywYBWi6RuE70=;
        b=DUV4D32MTgkjHHWMbzq1eU23r8QxCOPpSQGtpL5ld+EIjbwJrjPproH92Ms9PZ2/PB
         xtJPKB2ZX4f49ULn4jsV+k2f7YxY2XxGJo7xDgM01QK+VgBVzJren5Q9Pe8Pi0tKD8G0
         DwFnIKw1N6YTUsIgQlt7/gaKlhoZRNdIq7ZEn+OEOBnFHwLM4Q413hG/9icR/nhvatJA
         JH8HacOG58nGuijUoGttTOgmkFvLuNiB/CdXfScYYSdsmnUxtoiyvATvq7oDu2aGHIjL
         tarz/6sFqBtqNlRz1AVmWyfSjAEs42hYCDUtgXIQeYHWELWb/2KFZM3BZCkhhaTNcbr6
         WLBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SmeiVRFm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SV9bwMffIxmAhIaP9GKZ7fbJMFGZzs4ywYBWi6RuE70=;
        b=ng4pAiWUOkyjf0NzbBcgb3Fto5o+jb4u1UI4Whsiyv7m7e+W7K+Er2z9HqfQ1gSWWc
         oWcD9ZKqlvAuuIHU3KjwWUgDCpFQtSRPJVi02l9hdY9P0wSw6QwzsOtra+mJ4DHrWDx3
         VUVilhYjPjYHGUwYaK6RdmO0RhR9Yd2VmioavsoQ41cLbGxE0jETPCmCpi10GQDTkPVT
         gHYpgToNJP5R/ux1qunmha3gqy8/W03VGek+LRe3No5svSPhlnaiO6vNy9JKlJ2Ih/Rf
         xS1az26TPcRjAEqyZ8BkuLSSaD7H76r9Ucubso0PUWfEefTg0Jt8QvxoQ6xPe5A5pnzW
         CLEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SV9bwMffIxmAhIaP9GKZ7fbJMFGZzs4ywYBWi6RuE70=;
        b=iL9HunwgMUHbTBHYr7LUdbXMWazrQZBsNivVtV3wEP6O3sgENYyvUPyP6p+rHoTHa2
         EFHfyjqyECSAP7rVHiu8erCh6Dr38h44Acebh9Jhax0ytaNZEOTAx+4Mne+bxMmn/ZmG
         u78mHkWMQdhIMc72tlc93dZ6z93Yw00n4LR2jRtqted7aMpajrVOPexZh/iiG0NCqEg1
         PPr0YXQyIWG7IQ8svZLaf/b/X6qibIfAjunCiIuhCyaxd8XrWYIZ7Puo0ioBjW6/deqF
         +4x5KGsrrplnL2RHzlXvPZjg2+Z4jUj1iB8LkzBK+kdkbz2GfYfTiNikmZC1uhEh7f6x
         AYkw==
X-Gm-Message-State: AOAM533x9+yrFhGsac1+AaKOUec4kYHH7stops+2g3KWxSmqJT8P6rtW
	k0Nl79FqmAPq+db7emSl38w=
X-Google-Smtp-Source: ABdhPJw2pScu1HKVykG6dj6XoBU7/RjwX5Dk46yNu+49Jz3sxVwQGO1QPqd5GIU6C1v0oPnZfecCag==
X-Received: by 2002:a05:6871:60e:b0:da:b3f:325e with SMTP id w14-20020a056871060e00b000da0b3f325emr6103560oan.270.1646662120968;
        Mon, 07 Mar 2022 06:08:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2456:b0:5af:5a9b:4f3 with SMTP id
 x22-20020a056830245600b005af5a9b04f3ls3168077otr.2.gmail; Mon, 07 Mar 2022
 06:08:40 -0800 (PST)
X-Received: by 2002:a9d:67d4:0:b0:5b2:2644:7696 with SMTP id c20-20020a9d67d4000000b005b226447696mr4658999otn.322.1646662120568;
        Mon, 07 Mar 2022 06:08:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646662120; cv=none;
        d=google.com; s=arc-20160816;
        b=ECDvA5qk2gpWx05UdiSh6eRSJCUXzw3QluQrSE8RO9IvEjQ+WZcQlYGHcq2o0yNLeM
         /XnrV84t6oOaWdrO5ADI9ChuZOlEtpvx8SPGtQV3z3TwEr1WKcys/lfyxOk6EXP3V2yj
         OPIebyxOaw4d2QXa23Uq6PjwbwU2K86eG8AFJkAxRJmlsmzG5XPnY8DGyzXTyYQPsAIv
         pDwZRfhpXjf1wemUpn+1OpQieyqPPXlJJiqsnd1p7wOauTgZvdO/ytZeKZF8kYqUmpCz
         UpgtN1D/X3jUbCcm4WjtUz36ZioEtKnFqo0TtwLakskKV4CIj0EJ6QDqjtdZ1gGiGnCf
         RRBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mfdVxCs2eXbpyZ6nxJcq9Zy4MImVpxL60Izt6BU+nxo=;
        b=yLxNek68mUTecm2pplLppUIbGKOLR57C0cDKvuu6jK0SEqztlu4/uKeNmx0vVqvqvd
         /mt7iWRSiQpl0dSiw6KkCkSpheaSIFDJ57hTeXohgpRHcMHqY1MVzeC6OdkbB5AFGcen
         qSP+1pByJBSRA4YL2UE4gyz6elaU22Gw3iHKLzbOzstiqAnPp3JUBF074yCeTlByySSC
         I7llJueJBGZ3AGqdVGJhAGaheINRfgLQZrnaOUYnjfqVsj/tvWTOFsQLbFlu60SwyF5e
         BbYNDjTTcJrv1PfPDZbEsiNZ1Mshx2MUyTGTYsGRk/naVU96MIf/xtc+mYBR8tOAl5lN
         +Nfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=SmeiVRFm;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id y24-20020a056830071800b005af3a0effdfsi2238599ots.0.2022.03.07.06.08.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Mar 2022 06:08:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id x200so31134256ybe.6
        for <kasan-dev@googlegroups.com>; Mon, 07 Mar 2022 06:08:40 -0800 (PST)
X-Received: by 2002:a25:d50c:0:b0:627:660c:1874 with SMTP id
 r12-20020a25d50c000000b00627660c1874mr7642377ybe.625.1646662120116; Mon, 07
 Mar 2022 06:08:40 -0800 (PST)
MIME-Version: 1.0
References: <20220307074516.6920-1-dtcccc@linux.alibaba.com> <20220307074516.6920-2-dtcccc@linux.alibaba.com>
In-Reply-To: <20220307074516.6920-2-dtcccc@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Mar 2022 15:08:03 +0100
Message-ID: <CANpmjNNMQNd8LnCOaL0JXqS3r3Gv-DHrcw7Q6YvD6uWqnCz03Q@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kfence: Allow re-enabling KFENCE after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=SmeiVRFm;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Mon, 7 Mar 2022 at 08:45, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
>
> If once KFENCE is disabled by:
> echo 0 > /sys/module/kfence/parameters/sample_interval
> KFENCE could never be re-enabled until next rebooting.
>
> Allow re-enabling it by writing a positive num to sample_interval.
>
> Signed-off-by: Tianchen Ding <dtcccc@linux.alibaba.com>

Reviewed-by: Marco Elver <elver@google.com>


> ---
>  mm/kfence/core.c | 21 ++++++++++++++++++---
>  1 file changed, 18 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 13128fa13062..caa4e84c8b79 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -38,14 +38,17 @@
>  #define KFENCE_WARN_ON(cond)                                                   \
>         ({                                                                     \
>                 const bool __cond = WARN_ON(cond);                             \
> -               if (unlikely(__cond))                                          \
> +               if (unlikely(__cond)) {                                        \
>                         WRITE_ONCE(kfence_enabled, false);                     \
> +                       disabled_by_warn = true;                               \
> +               }                                                              \
>                 __cond;                                                        \
>         })
>
>  /* === Data ================================================================= */
>
>  static bool kfence_enabled __read_mostly;
> +static bool disabled_by_warn __read_mostly;
>
>  unsigned long kfence_sample_interval __read_mostly = CONFIG_KFENCE_SAMPLE_INTERVAL;
>  EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
> @@ -55,6 +58,7 @@ EXPORT_SYMBOL_GPL(kfence_sample_interval); /* Export for test modules. */
>  #endif
>  #define MODULE_PARAM_PREFIX "kfence."
>
> +static int kfence_enable_late(void);
>  static int param_set_sample_interval(const char *val, const struct kernel_param *kp)
>  {
>         unsigned long num;
> @@ -65,10 +69,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>
>         if (!num) /* Using 0 to indicate KFENCE is disabled. */
>                 WRITE_ONCE(kfence_enabled, false);
> -       else if (!READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
> -               return -EINVAL; /* Cannot (re-)enable KFENCE on-the-fly. */
>
>         *((unsigned long *)kp->arg) = num;
> +
> +       if (num && !READ_ONCE(kfence_enabled) && system_state != SYSTEM_BOOTING)
> +               return disabled_by_warn ? -EINVAL : kfence_enable_late();
>         return 0;
>  }
>
> @@ -787,6 +792,16 @@ void __init kfence_init(void)
>                 (void *)(__kfence_pool + KFENCE_POOL_SIZE));
>  }
>
> +static int kfence_enable_late(void)
> +{
> +       if (!__kfence_pool)
> +               return -EINVAL;
> +
> +       WRITE_ONCE(kfence_enabled, true);
> +       queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
> +       return 0;
> +}
> +
>  void kfence_shutdown_cache(struct kmem_cache *s)
>  {
>         unsigned long flags;
> --
> 2.27.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNMQNd8LnCOaL0JXqS3r3Gv-DHrcw7Q6YvD6uWqnCz03Q%40mail.gmail.com.
