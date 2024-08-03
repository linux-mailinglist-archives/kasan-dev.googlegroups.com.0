Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK4IXG2QMGQEZLKQ62Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 847A7946A25
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Aug 2024 16:52:29 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-267b93154c9sf10130727fac.3
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Aug 2024 07:52:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722696748; cv=pass;
        d=google.com; s=arc-20160816;
        b=x4nLyj8aEhqUDdrUSd3aoQ8LtETcIwHr74WbBMjkgL0i+iIGtPrAr8bJScU9T8m7s1
         7QfI6RxneKMnkN8ggxFGkuZQigU/fVzFQvGGkoxQM7vCfLDTPUbZV5TnozLUUb5IqRql
         cvjpV8+1dCjgALxjJhQxYLdvr3xTjROXe1FEC6LvTh6G5OOWz5WXJ6YLaAGITypK3JOL
         b1aliwniBg+jeaj10v4fB2onb2uSQRXXObSB8Abb4STCVhzQZjQ4eJmBgCVjzxLRO7Qb
         WW3On/s4vCzNRuY/7ORQEwyHGjfghOpvKEucwyROBJh+nX3pKNaxOqHD109UV826g690
         hxag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OD6WXNMUm+jIDQjytkbyhSCi2BiLTXW35xa8x/hapOs=;
        fh=kw/WXuWxAnI8RYp1ZKwbJqAiqO5FH6M1bbGQnfuGfp0=;
        b=QWHflSpzPsg0HUGtMpCuFQDMgl90aWtZr7qBfFB6VqubsR+jSn74s28YVgDce7gnOH
         o7nq+AlBtX/omwfe5FKy0+OxWBoQGm+J74/mmA8iOqJ7vgN9vxHp8lk7UzsyFKL+KibN
         O1FnxSpMQXb4ce55Un8m+JjQQTlStHH348FuFWKUseCdrWiW9kQI30gmUQ/IoBW5wgbQ
         Oa2vVKW01uxhVR8pe0MIyol98a0iRiuvAiswuGavXTCpcmHH4dhiu8ebKyObso6UNDwZ
         Bv62rB3hT1aQDhbjPq1CLUTd8y19o8xEM5kOYdkenFIW7f7QSrtVENbKV28+FoxXtRq1
         l37g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DknNmFVq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722696748; x=1723301548; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OD6WXNMUm+jIDQjytkbyhSCi2BiLTXW35xa8x/hapOs=;
        b=syDALNEAz6d4tC/QWvzbSl0RcjUjJf3EN1OYEEcdK/KeyGu0L53YpHX9i5n8lgGNg2
         2n7Lg1tPKETE7xuNsW5cbquwy1CXk0R6RWQhz/ObNu1YDY8MZ7JqXRUdLCFn2ZjrbNS8
         UVcmnKBOKD4R2YsS4h1Sd86ydO+44satU8o+mZNnJGUgQDzOyABL4klX0G+sx5IEiEWg
         ZXvaonmYZraOQkwaViSEbhUBq8bs6Q8CFbC7OJfJvpsAtvYs5WZDibg+2aEGpd40I+xL
         67LEpriHuA7nCIALfFil+Zg9x6Bf1Ch+/nXr4D9iCSeYENalbre0xWRJSgR0GMyITBw2
         PD0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722696748; x=1723301548;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OD6WXNMUm+jIDQjytkbyhSCi2BiLTXW35xa8x/hapOs=;
        b=eVG9qsILuV+crR9aGp8o1XOj60xa3O/ZgLjydm7rHyYx0G3dpPt8Kxc/1qqC++TuWZ
         PtXbC9f0z1UylS3EANoIdQAHs3XZ5Fi8Q9STaMeuchBjr76miz5SxX6Sgr5n5DH0dnvr
         TexX6qPoGr+TIC06gfYk8hReLMbkE7U6zB/7zOZoksRSAOZEvWfXEUoel0J5zQ6QaXYt
         Ve4Vys44b02RhUnTAN5hVNiISr2+9MkJbSoimsTr9CC7XbKsjqPI5hFrEqoIfqBWKAN1
         04GB82Pmw9LZZcE6UWbQRYkcYqpYFHpQi9Jtm7WBIpMy6JxXOYzvwBhaV/xywfILHZPC
         ApWQ==
X-Forwarded-Encrypted: i=2; AJvYcCUU7tTTZYxg/Te3hzFWxd+9CNG99mI9j6y0G4yRMRvFRia4QyIU4bub6h48KIWXTP74ZbX5XImY/YZwRSGbFDGT8mcRblguOw==
X-Gm-Message-State: AOJu0YzONPpNpeyTpRm2wS0xbx/EAVaSrJELXnHjz0Z85t66ZKNwro/t
	0XOHbwpJ+LhWtgBjVXyCNj3a+x5nPpVxDCXtCbnQMUSalnwOrydP
X-Google-Smtp-Source: AGHT+IFDvwkYUH1wDjMJLbss9OALe9dQbbPJOjKaUP7iaX2mCIM0Ha/aIMSeUQHlNawjKZbeZnl0Lw==
X-Received: by 2002:a05:6870:ac11:b0:260:eb3a:1b2 with SMTP id 586e51a60fabf-26891a7da2dmr6935584fac.7.1722696747778;
        Sat, 03 Aug 2024 07:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1ec6:b0:254:7203:f69f with SMTP id
 586e51a60fabf-268ae0a2809ls299870fac.2.-pod-prod-05-us; Sat, 03 Aug 2024
 07:52:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMP4erOYnylqrEsB1/u4UNIN2oO+JHQiFioUKQeICK7HKacuYWGK3XfzhjzznnTYid74g7Tklv4hNSdgwFxthHgxk/jxF5eqw2Rw==
X-Received: by 2002:a05:6870:214:b0:25e:7a1:ea8f with SMTP id 586e51a60fabf-26891ee21d2mr7939742fac.47.1722696746952;
        Sat, 03 Aug 2024 07:52:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722696746; cv=none;
        d=google.com; s=arc-20160816;
        b=lV9fT5GaKnjWYebdnZmTL3DsqwfIX9Hen/kU7nZRr4cDCgBcbnlT5rvrqJaiDQEibt
         s07YbYt4DyDq4KmVKWY3cGdImbQeOt1NNHykEx1zF5dy2tbs0svq2xr1xaanm9fko+1J
         BmV74jh3Z59PmiBQZSFFWXmQSOcl0MB/H6XWp8kz9qvY+mQjnseNXyinL917Z4k3RWrx
         47iUiEMl311djrxesVZy3eEimCINz3VuaQI+SuGEYVtt+uULKGPRkdYwKUIky5oFNAOK
         Xy98hmsUjErQcCAVrMAE5vIMQpN2zlUmBI3j2CF+qzRCz4qmAcdyoSSR7NxmlKn/gNgx
         0wFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=M5wjK5I4/xcaavsdBTsn+WUUr3wkyX/2Ze1oBN2FQzo=;
        fh=ukk1PEJ2gal+72PiLPy2fxJHraR15Wu3GY79lfKVWQ0=;
        b=dFcFhCOAI8t5/6VZjJIFR1IE9KltjIUNl+qCWi3FCGAUdcpIW5oGX/mbickp4ypEvo
         bgOEH2HELUYXLP37l8yU+co5SetSn4kXKmK7cpjPkFan+25v/TXoDGTJA+XRCFh+WFII
         p/vD5mM00TqA+KuSj/BDrBF0ssRFAZkSu74ulHE8HiBGxQjZs4ILO9Y0HcUQtn3L9Zep
         YPzxxfUZ+9pQRvWnotnVKD6LU9ydmbdSiD0euZ+tBHJjBg2IgHU1Os3VIMzA5+g4Atkf
         o0yswr/QSmda4DqMm+Pb0VKEPKtYDp5sdQrSO5oJku1i4PhHWR7LbEV+fWGQpuwAAduQ
         1XJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DknNmFVq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vk1-xa31.google.com (mail-vk1-xa31.google.com. [2607:f8b0:4864:20::a31])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2689a2a724asi159217fac.1.2024.08.03.07.52.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 03 Aug 2024 07:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) client-ip=2607:f8b0:4864:20::a31;
Received: by mail-vk1-xa31.google.com with SMTP id 71dfb90a1353d-4f6b8b7d85bso3232165e0c.1
        for <kasan-dev@googlegroups.com>; Sat, 03 Aug 2024 07:52:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUyCPM61uJIQgzeTRnfI8l1DxSc9biloD8zto3jW+2SEi4drG+4+Io1s90xFmMZdaZ0nqcB8wUvSih2z3BcL36O35+W6rEWMfpAdg==
X-Received: by 2002:a05:6122:291c:b0:4f5:cd00:e492 with SMTP id
 71dfb90a1353d-4f89ff4e8b7mr8061621e0c.7.1722696745916; Sat, 03 Aug 2024
 07:52:25 -0700 (PDT)
MIME-Version: 1.0
References: <20240803133608.2124-1-chenqiwu@xiaomi.com>
In-Reply-To: <20240803133608.2124-1-chenqiwu@xiaomi.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 Aug 2024 16:51:45 +0200
Message-ID: <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
To: Qiwu Chen <qiwuchen55@gmail.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"qiwu.chen" <qiwu.chen@transsion.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DknNmFVq;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sat, 3 Aug 2024 at 15:36, Qiwu Chen <qiwuchen55@gmail.com> wrote:
>
> From: "qiwu.chen" <qiwu.chen@transsion.com>
>
> For a convienince of tracing slab object leak, print the age time for

typo: convenience

What do you mean by "object leak"?

From what I see the additional info is only printed on out-of-bounds access.

Or do you mean when you inspect /sys/kernel/debug/kfence/objects? If
so, that information would be useful in the commit message.

However, to detect leaks there are better tools than KFENCE. Have you
tried KMEMLEAK? KFENCE is really not a good choice to manually look
for old objects, which themselves are sampled, to find leaks.
Have you been able to successfully debug a leak this way?

> alloacted objectes in kfence_print_stack().

typo: allocated objects

> Signed-off-by: qiwu.chen <qiwu.chen@transsion.com>
> ---
>  mm/kfence/report.c | 14 ++++++++++++--
>  1 file changed, 12 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kfence/report.c b/mm/kfence/report.c
> index c509aed326ce..44c3f82b25a8 100644
> --- a/mm/kfence/report.c
> +++ b/mm/kfence/report.c
> @@ -16,6 +16,7 @@
>  #include <linux/sprintf.h>
>  #include <linux/stacktrace.h>
>  #include <linux/string.h>
> +#include <linux/sched/clock.h>
>  #include <trace/events/error_report.h>
>
>  #include <asm/kfence.h>
> @@ -110,9 +111,18 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
>         unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
>
>         /* Timestamp matches printk timestamp format. */
> -       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +       if (meta->state == KFENCE_OBJECT_ALLOCATED) {

In principle, the additonal info is convenient, but I'd like to
generalize if possible.

> +               u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
> +               unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
> +
> +               seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (age: %lu.%06lus):\n",

I've found myself trying to figure out the elapsed time since the
allocation or free, based on the current timestamp.

So something that would be more helpful is if you just change the
printed line for all alloc and free stack infos to say something like:

    seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus
(%lu.%06lus ago):\n",

So rather than saying this info is the "age", we just say the elapsed
time. That generalizes this bit of info, and it'll be available for
both alloc and free stacks.

Does that work for you?

>                        show_alloc ? "allocated" : "freed", track->pid,
> -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> +                          (unsigned long)interval_nsec, rem_interval_nsec / 1000);
> +       } else

Add braces {} even though it's a single statement - it spans several
lines and the above is also {}-enclosed, so it looks balanced.

But if you follow my suggestion, you won't have the else branch anymore.

> +               seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +                                  show_alloc ? "allocated" : "freed", track->pid,
> +                                  track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
>
>         if (track->num_stack_entries) {
>                 /* Skip allocation/free internals stack. */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNf8n%3Dx%2BTnsSQ%3DkDMpDmmFevYdLrB2R0WMtZiirAUX%3DJA%40mail.gmail.com.
