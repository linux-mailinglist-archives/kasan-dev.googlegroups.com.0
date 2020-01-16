Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZEWQHYQKGQEVNLSITQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 57E5513D927
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 12:39:18 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id bd7sf8598186plb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 03:39:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579174757; cv=pass;
        d=google.com; s=arc-20160816;
        b=ErcjJwMyw8bWfHei2ThAvsux5Csvge7jeHBZ/mkd6Al+5JWryZr7nx1fbmmTxhfPG7
         oJnXpzrQSspmbaZQJpq6OdSC3aAiuPi6MwI7Q1W6dmC7vVPFg23I5VVxKKWiVOorQb55
         BHdKHsf9Xdz6zDEo0/NfZYuUnnbLGoowbOziTODjaT047CBoqJvhAkze+rDC/cvMfP3e
         2iNlnIW/uMkzg9qG+7QX5j2nZyrajwZgWTqNUxbrvqOfgiDxOq7I16feXwAEgFrGzLJu
         e41CpP+AjhbtvXglWX6xFJ/K8shdQdERfivxrk+eKnPmVQMFuZMYKFhQ4y0iFtriXuL1
         qLOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G3UHdgYUfpkxfVOMBiAkr6/5yIhL1X2Vd5D+8c4Pfak=;
        b=aUtBcF5tmGrnnquy+68sbYfznDAhbRMTRwAeNkThNJP9uKpV5T1+4OvEWmB7P7DcCw
         01x6fwikpsvXjybMtHuRK++wfkHGcsF9V/BaKNNEZ8K9Vm5UVHG2hmfyK52AxUDkWPEp
         aDMQPA5CY6dtDf+UOztxaDl/4jflAuaaOab6BCr+3VAqTXQeJdJg+lBeKhlLerXVh/1/
         mu4Ni8uTKZUqtjld0xV3EjI3E2Qi52VOCHwiLXifZBcfTGR3WEyeGRRgjzMTOD845yC4
         kGK9B57yCzP8pgbF+9LfpTNS8f/0aX1T/b9mvrWtoR3Na1xfStPgW4vt5tZYeS21KU0k
         TUDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSzoVn31;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3UHdgYUfpkxfVOMBiAkr6/5yIhL1X2Vd5D+8c4Pfak=;
        b=fRXNa0ApTdxACNJ0VKoPNcHprop7l4DdzbTaYLGnndFEg2QJEXGRMlNr1k+vnz7Ctj
         bjTZl2lGaooCcho8A8x2inX6GaTahYURg1pq62n20edpp6WMgmj21AJcaFCiOvAVc4OV
         teWXoz8zbKnqRdulDsC2D2LTUuLskMn85UEBNAW7xsWKN8ItD9HNr7mD0X4IgAhdLG5z
         Tnn9QdmQERt4I2oXCBzUAnbr16QWlatPJrUfYh56hR2lrlKEWHYms6mBO5Wf59Rrz3yt
         SIHKLOLQxWdawyacQIeV3uWW/Q5bUQHsm1z/TFUogcDbRStsH2VJuThSjnUc3YyejeT3
         HZcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G3UHdgYUfpkxfVOMBiAkr6/5yIhL1X2Vd5D+8c4Pfak=;
        b=s17J5Dk72vLeg6VtgHX+u/W7eDTGaU+vM+AidKW1/OHBi548l12FzltwxfwEH3E7ea
         AE95Z9r9Yj7ZgYIgThEk8Mo+0Ft3y6E5KmFu/2bc2Zh15xgh8iCQi9+gMMjehq0SP6pd
         t7SMDuDos97WKSyRRwHPDNSshG91iUorPDbEg0m8MV/qHdR8JnmgLwLZ/gkNsNAAV7Mj
         33Wul0CFrUUIZMYEvnYtNiiS/8y88CtX80jCulrswQs8ryfWTkjJLyAG3x9HxWhjsq5P
         QyYGpBGhFO9k/UYmAHESuQBHlqT+5k1+r6PTxgeA9GQP7aVhCZPLAnc4bdQhTvSh2m4m
         +yqA==
X-Gm-Message-State: APjAAAWhSHOyHMjlTI/vPjacsgRcb1QnhuZts5y737NBjvE4EEg9hqN5
	nXgyZGvxA49c+0lEIxk+OMQ=
X-Google-Smtp-Source: APXvYqwSnMlCiC6V0z2lFdFdq6EQz5y5QnJ7b3YU6rUbXKXMy9wZ2DNunA5fcLWaF+7XC24HDUDGZg==
X-Received: by 2002:a17:90b:3c9:: with SMTP id go9mr6220863pjb.7.1579174756880;
        Thu, 16 Jan 2020 03:39:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:37e8:: with SMTP id v95ls823839pjb.2.gmail; Thu, 16
 Jan 2020 03:39:16 -0800 (PST)
X-Received: by 2002:a17:902:8eca:: with SMTP id x10mr31898927plo.248.1579174756373;
        Thu, 16 Jan 2020 03:39:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579174756; cv=none;
        d=google.com; s=arc-20160816;
        b=qz7U2UcAxhACe2w/20SL49TmBzz+if3Np90EheouiqBDNyf8OL412nuEDnklQOfMoy
         rkuKKQ8rpNjiehFL8htHqJ2SovKDokKx4TWPuDHyTtYMp2km+CT5mpFLWvYfN8Fz7uSh
         Gng/RT0WwtV/to+7ylDzCfwDPuA3fTOOH5C3RyB9Y4V80mnMLlR+W13Zv59IcR7lbaA7
         EmFgh0yHH66BtavjDWzQbtf0iCDqUTh0XHJDZfybCfCkWobI0z4YNpbyJT/lwn4HLo4u
         jdAnv0402C4+F2Py/ROKh3K2Q/zhJYNRnzh8tw7IU9b3qIfAwxfEw5PSu+iOT5PYo7uB
         UisQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XQ2WYK66tyT9hqx5BTHGPz07wmp8qftkyUQb3t1BOpU=;
        b=MQWYAVDBGIxk9UEzVIhzlfDNNhVRHb9XmVlOROICr9NuqwNJF4qtsL+WzGei4qIFKA
         3dNz1JYsTLeFmhUWiOq2im4VuoAfvNmvkGGCirLKS91lWxNo6rNOEDZILnv1wc/fciP1
         rbntkZJMV2Gb9BgmxdJiBrR71UgrQlRHor5EozBt1jl/RBsj1g854BaVInW8MoFuWe4P
         VKFo/L5upLzeWI53TNwzf0YWAcm9sY8Aq95PjaONO8sb73/uc4gJZ/ARLuTuv8VuO0uG
         v0NNI8OGNM91iHrNFoffdNwEfPQmY8M8FYodrWfJtnc6eKyGoB/sEMz/J/BYXHvsw6NL
         lKwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dSzoVn31;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id y3si136408plr.1.2020.01.16.03.39.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 03:39:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id k3so9774743pgc.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 03:39:16 -0800 (PST)
X-Received: by 2002:a63:358a:: with SMTP id c132mr39524917pga.286.1579174755819;
 Thu, 16 Jan 2020 03:39:15 -0800 (PST)
MIME-Version: 1.0
References: <20200116111449.217744-1-dvyukov@gmail.com>
In-Reply-To: <20200116111449.217744-1-dvyukov@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 12:39:04 +0100
Message-ID: <CAAeHK+x1o+7qvZx0tkqqaSHJfovajywFh5PhACcjDu2PsNNpVw@mail.gmail.com>
Subject: Re: [PATCH] kcov: ignore fault-inject and stacktrace
To: Dmitry Vyukov <dvyukov@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dSzoVn31;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Thu, Jan 16, 2020 at 12:14 PM Dmitry Vyukov <dvyukov@gmail.com> wrote:
>
> From: Dmitry Vyukov <dvyukov@google.com>
>
> Don't instrument 3 more files that contain debugging facilities and
> produce large amounts of uninteresting coverage for every syscall.
> The following snippets are sprinkled all over the place in kcov
> traces in a debugging kernel. We already try to disable instrumentation
> of stack unwinding code and of most debug facilities. I guess we
> did not use fault-inject.c at the time, and stacktrace.c was somehow
> missed (or something has changed in kernel/configs).
> This change both speeds up kcov (kernel doesn't need to store these
> PCs, user-space doesn't need to process them) and frees trace buffer
> capacity for more useful coverage.
>
> should_fail
> lib/fault-inject.c:149
> fail_dump
> lib/fault-inject.c:45
>
> stack_trace_save
> kernel/stacktrace.c:124
> stack_trace_consume_entry
> kernel/stacktrace.c:86
> stack_trace_consume_entry
> kernel/stacktrace.c:89
> ... a hundred frames skipped ...
> stack_trace_consume_entry
> kernel/stacktrace.c:93
> stack_trace_consume_entry
> kernel/stacktrace.c:86
>
> Signed-off-by: Dmitry Vyukov <dvyukov@google.com>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Cc: kasan-dev@googlegroups.com
> Cc: linux-kernel@vger.kernel.org
> ---
>  kernel/Makefile | 1 +
>  lib/Makefile    | 1 +
>  mm/Makefile     | 1 +
>  3 files changed, 3 insertions(+)
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index e5ffd8c002541..5d935b63f812a 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -30,6 +30,7 @@ KCSAN_SANITIZE_softirq.o = n
>  # and produce insane amounts of uninteresting coverage.
>  KCOV_INSTRUMENT_module.o := n
>  KCOV_INSTRUMENT_extable.o := n
> +KCOV_INSTRUMENT_stacktrace.o := n
>  # Don't self-instrument.
>  KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
> diff --git a/lib/Makefile b/lib/Makefile
> index 004a4642938af..6cd19bb3085c5 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -16,6 +16,7 @@ KCOV_INSTRUMENT_rbtree.o := n
>  KCOV_INSTRUMENT_list_debug.o := n
>  KCOV_INSTRUMENT_debugobjects.o := n
>  KCOV_INSTRUMENT_dynamic_debug.o := n
> +KCOV_INSTRUMENT_fault-inject.o := n
>
>  # Early boot use of cmdline, don't instrument it
>  ifdef CONFIG_AMD_MEM_ENCRYPT
> diff --git a/mm/Makefile b/mm/Makefile
> index 3c53198835479..c9696f3ec8408 100644
> --- a/mm/Makefile
> +++ b/mm/Makefile
> @@ -28,6 +28,7 @@ KCOV_INSTRUMENT_kmemleak.o := n
>  KCOV_INSTRUMENT_memcontrol.o := n
>  KCOV_INSTRUMENT_mmzone.o := n
>  KCOV_INSTRUMENT_vmstat.o := n
> +KCOV_INSTRUMENT_failslab.o := n
>
>  CFLAGS_init-mm.o += $(call cc-disable-warning, override-init)
>  CFLAGS_init-mm.o += $(call cc-disable-warning, initializer-overrides)
> --
> 2.25.0.rc1.283.g88dfdc4193-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx1o%2B7qvZx0tkqqaSHJfovajywFh5PhACcjDu2PsNNpVw%40mail.gmail.com.
