Return-Path: <kasan-dev+bncBCMIZB7QWENRBZGQSKFAMGQECVRGN2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7534940FA5F
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 16:38:29 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id l7-20020a67fdc7000000b002d50b43a8e1sf5857712vsq.22
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 07:38:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631889508; cv=pass;
        d=google.com; s=arc-20160816;
        b=UVBHuj1loB9RnxRoT/cCIyFyeT022W/RunjwhPRKaitk6mXb/LUur1Mg+jN+iu2Z3+
         NdX+dVixlqGP1kA/rOAe/NdFqDC/PHLoA7KzDx6pcQUTQLQrSf7UOk0wToRiqOx6R+Gg
         0rFzHQxv1K1a3LvILuG76B8SdJ2fzPDGGBRTNJFWCya9ehwdEnVBSSMNCihMaOi4TPhN
         21NVMn2Tt1Zv05xaDq5iLJynteNjp1LoPDzRHvnU9++jvkNtOm1qoDgAUABL4ANAgURP
         hdWhKEEeg72d+Ujb6fjbhzospFMZMxueXrQuYMOKMXhSL5QNzKDGHYvP2+Xjk2JewYOH
         KH0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A1jIyHbw8jI5aZN8FcidKEsjDpQJTYxQAcNr8xngeNQ=;
        b=ndLuqs6cvbjdU/5dBNKswX7JHRARpnzVn4buXo19qXDgkuk9V6z7nqTQFqrkPZ0es8
         bugIog8qMxp0f9UPOlILfQ/1aIvUOjXFGVLbQ2aRotkjth0DfuQ4WJqibzxuh4Xr+rL3
         u1JA0vT9EH8HnRYPj0oF7Y+f6IB5DPlnSuJhpfZI1RTKKvWXFWJjhmPXh8v8ycMAadZY
         zX2eSJE8qLps1lVUkamdNHlBTa7yyn4z+/R9gR0iXAU350rKsSZzgz/jQVWoDOlcMFAP
         kfpgQs3wuUKjDkm82WeE43tylka5dIeaeGeI6xo6FELO1ydOqHIJdN540zzzwy6HHxMK
         4hdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lDpUN20I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A1jIyHbw8jI5aZN8FcidKEsjDpQJTYxQAcNr8xngeNQ=;
        b=HxaF5j9NyjMZtQ9BXIO0TqziCmFMlDBQ7KKsJevuTkitXBO4A76c8O5yp6BCOsf6QW
         1w1s8V1nTHB1Mp+RTvzg5/9laDFuySSBDDUNccpZ7FcGCyVzQffk4i1XtNFc0JN8L3bL
         13mcNCSqbXmRPBjM+DdUssZoPqi7+o2p14XFv9ijF9S0RE3bvl96S5Eu0U0VVb0R4lhB
         qzvhZ67zOlB3KWQi8EL/ywEnQHDPK+pjPCbi0cFS7f0VAwtG9jVukC+ll2UhiV7dGZbF
         SCpS4yVJmfC9QJLAafy/b0o2VRdnbPNmwuRZUp262/pfQOkBxx7b5nPQudw6Mt2kRnV1
         dTlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A1jIyHbw8jI5aZN8FcidKEsjDpQJTYxQAcNr8xngeNQ=;
        b=506WjbGFmr+EFEjvVJfeV0f4llvP/fuTzU2O4e2LKjC9ulniFkD1taTOZG803G2L5m
         pGU/MGhgJs6sV8lhbH52wIL0EcGxsZf4hqkloxPr0HfWmNbuoYkr0T+7/vt6d5It8cEG
         G7zynaZT2p3ThpXgm2838/x+FuEKSBz/+fAsk7zUsB37N3x9nEvExnxEu0gKshNpZJWx
         mp7e1+W7/HaX0/E2mcKOOLb0rwtOYG8nhIPxdelnX9JXU6gfRs95lCybgAcW+CZBGO4i
         05KF3qpufHnyMmJqQY6ny+hvlz56lROEbZiXFLtJq5SUePP0PQ5BkCF1H8MK+CIOEnqe
         90Uw==
X-Gm-Message-State: AOAM532UsGjEGS71J5Ep2RLKmZYv9p6AInqlbgyeoi0d2EH/f91ngOqk
	5hQFU5kIkVPRFi8MDlQu8sQ=
X-Google-Smtp-Source: ABdhPJzyk+OJvIkYHq0mWETBHRfpPaDGQSOLod9glQ6rr0NaRGC7fYtMo+QNDkDFN1LbWlyNgzln8w==
X-Received: by 2002:a67:d61d:: with SMTP id n29mr8913215vsj.51.1631889508387;
        Fri, 17 Sep 2021 07:38:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c89a:: with SMTP id v26ls1645861vsk.0.gmail; Fri, 17 Sep
 2021 07:38:27 -0700 (PDT)
X-Received: by 2002:a05:6102:232d:: with SMTP id b13mr9055100vsa.32.1631889507858;
        Fri, 17 Sep 2021 07:38:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631889507; cv=none;
        d=google.com; s=arc-20160816;
        b=vIADFoZ0X3vlWqcPSGNszFedGvuCyGxtC8PwAuicIHniBNtQaw5mrEfZ12fHd/xCHk
         WNHluaixTPjq9wds1mdtTCTWdKivB0jLLR+dZJoE384tvKG6ggXMjwIYMHKYzNz80JJ6
         3TEo7SvF/5SHaU4OwoX/jwbdcHJ2wH2bH9m6JN/07SZUutAD/upFb109kaMzfBZU8sV8
         8ll2TXBluMAR6sQxxl4rDbb/m/ZwsGa91ia3Yc8KPx1Ckv0Ho/p5h7AvU5uWp3+AaHLJ
         FxEWCCeA8Tc8fSqWl1xscSqCQCELysvfysJjYf6aUtC2MG12TkICx22eKwNfKC4fjFP/
         ChZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GO6yNkAO2As+gyaSFwvR3MHVKDXqu7ThxhmfTtq/E50=;
        b=bH8CbjQ7zZtKM9Lalj72dX58Z8sQroLwdUUqqwfR2djBJFFPZHraLJs/9GnHnMCOeM
         3sZZ1rqLxc3vElXHLFPA84CFS+Eu/La+yyT+BvjMFebG2P8JxawN5XNEtwCHHQsFb9S/
         Q+NQ1XenupNZqs/aHIvagTpWLTw58wacOIM2aHcH6oRbBgKCH2nkoGlzr01J1G2AQNSl
         eldUhEbmJcvAnl3Thd74eTH4cVdw90yFmh/3LCNUdaZFcaXIL9t9ei3p3I45hen7Ljax
         aXoiVQ+IP2NeENmKvqqb2wpp1/qsOTpmUw9XZqT3isLhcRJMp3WDkX5IWaae9WUg7r1U
         39mw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lDpUN20I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id k15si860005uab.0.2021.09.17.07.38.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 07:38:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 67-20020a9d0449000000b00546e5a8062aso1051587otc.9
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 07:38:27 -0700 (PDT)
X-Received: by 2002:a05:6830:34b:: with SMTP id h11mr9956039ote.319.1631889507365;
 Fri, 17 Sep 2021 07:38:27 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de> <20210830172627.267989-4-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-4-bigeasy@linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 16:38:16 +0200
Message-ID: <CACT4Y+Z9NqymRB5q-U27P8gGF21UTZzSOuNgZO-EBqQnbKNXhg@mail.gmail.com>
Subject: Re: [PATCH 3/5] kcov: Allocate per-CPU memory on the relevant node.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lDpUN20I;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::331
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> During boot kcov allocates per-CPU memory which is used later if remote/
> softirq processing is enabled.
>
> Allocate the per-CPU memory on the CPU local node to avoid cross node
> memory access.
>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcov.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/kernel/kcov.c b/kernel/kcov.c
> index 80bfe71bbe13e..4f910231d99a2 100644
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -1034,8 +1034,8 @@ static int __init kcov_init(void)
>         int cpu;
>
>         for_each_possible_cpu(cpu) {
> -               void *area = vmalloc(CONFIG_KCOV_IRQ_AREA_SIZE *
> -                               sizeof(unsigned long));
> +               void *area = vmalloc_node(CONFIG_KCOV_IRQ_AREA_SIZE *
> +                               sizeof(unsigned long), cpu_to_node(cpu));
>                 if (!area)
>                         return -ENOMEM;
>                 per_cpu_ptr(&kcov_percpu_data, cpu)->irq_area = area;
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ9NqymRB5q-U27P8gGF21UTZzSOuNgZO-EBqQnbKNXhg%40mail.gmail.com.
