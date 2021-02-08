Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4OQ2AQMGQEJDV4Q6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 17892313DF6
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 19:46:45 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id y34sf11388822pgk.21
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 10:46:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612810004; cv=pass;
        d=google.com; s=arc-20160816;
        b=YBZOCjZc6Fm25JnqVx5rP0va23o60IyOYNeC7i9JIpaIqCycjwHieIftt/J57J3Ntg
         J9hxyU2JxdbfT8pkDRrWhaM0dd/ao1atGLiBV/wk9hNQWjIm5bTEwH4kG49zuHHMI7if
         1E7Yd/GYfTyLjxLVkJeUBeGadxW93ZsMs1WcFQlysTim7PiS1OgAMI/LBEFHaNjOl7SV
         JiqhFUXrfYG26Ym/vrrwZrMj8jtJJPfb0B1uzKV811mkfIOazSZPNcjW6haPYaBk6/e1
         QI8q87/PG/EDY12OkorUU5YYqM4ED2f1Gp0yT6ylwSlPraNAWqNvzReFFX/4UrIKGvIX
         Skpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Tn3ZRmoUHvcvNlbveLSyoD7jJmVv7GhwpY88GBIEzFI=;
        b=X2VKxCjUCEfTDsu+JwLBs31k36ZzuL2r3XVAdlGXiBPbYeTITXD4e21VgtLpIm/h+U
         ZcA3Oj3MZ6L2Ca6f7WNKPkTAUxzpkEsTXbD2qfCmXdfJ1ose043xUCJkG6vJqsNzrM/F
         wYsxUhKR+vukLuj7OtaHXqvLbRl4gFfiLUX+OgRebBRuF22YnefOCtdF1XCYkRMurYPy
         gll9A1GbF6ABN9ytks3RPHaskN1EUwuA4jLagKNYQQ4SiV4Eq/FABnCjf3CUHAqr7l8F
         bjbIUpDDwOOI2tu+0EIpCT76GI+q6/FRtlVSlNZGY9AU6b0xi4v9IDMgvHVNf2VPqXA4
         DbTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCxbX8R2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tn3ZRmoUHvcvNlbveLSyoD7jJmVv7GhwpY88GBIEzFI=;
        b=g0ccWT/C8tq6OvRkj1O5f5rF/wks+ZR2tBfvcy6rJJj/0/2QYYdnibJmovguqRcACS
         snndA7Xl6M3I07CFu12EmBx1J4aDz+ephF5Bg1kttpg7tYgKk3bsvgUfnPCs1o1nB7IV
         +7dwOJRRCuA+CO7TdJHQ8KPeD80FRKtWYHR1brhjufSBRtjg/P0Gbmple2Ni2+578srT
         purSZbkfRAFlxSduIRAsIuy3AA/n3ag6QbFBVZPeeADsa/FG0sXO8Iv/zOmgBlTbp/lT
         vadWsh7CEs4k8y4sx6GwOGcU2qxMVnsSAEgawILUYFOjF+ELjDOEkhO2av6ahotl3BOV
         yUKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Tn3ZRmoUHvcvNlbveLSyoD7jJmVv7GhwpY88GBIEzFI=;
        b=GpmocojbzSGFyAeWxONuCTIq7EoOZQfmvOz38cbDG7jxQYO6f/Jibi1grtCHiXqWNT
         soSWVOfWVnJpTTHjIG8RZLZ0EkX5DO3PRZGQP25igk6Hw9rL3Id8xq+lVQznvvxxXo11
         YjXYO0VJ+TlKqFqmDCnLyiQlN5Y8Fvr33Rw2ubsCQnts03JUNMuwofpkSN0RqdTU0r5w
         ydEwk4BNcp0T4NlfOUyml2+Lw4ZADOJrWzba4hjmBQMu8g1yY6jEWVfM3sxk32z0sghp
         i7YButq4Wf72uESO+6nfrm+a/BlsL96JpIyxMWC2EBuz8WoDANWNweZ0J7O8qof0jgyb
         /whw==
X-Gm-Message-State: AOAM530dbO2jGEBWTVU5KQuB/Xjmv+YdHqKC4ie8w36ICminbCSgulqv
	LFEW+KMFL7QmEBAzRU5Ldmg=
X-Google-Smtp-Source: ABdhPJz5ZsTtl75mjpw+UnezxBUmoWsuQbbpssX9grfklbuqqQY0UaKYmhcV8sHlDzoQAEl4+oBh/A==
X-Received: by 2002:a17:90b:806:: with SMTP id bk6mr197716pjb.16.1612810003830;
        Mon, 08 Feb 2021 10:46:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:296:: with SMTP id 144ls3964514pgc.4.gmail; Mon, 08 Feb
 2021 10:46:43 -0800 (PST)
X-Received: by 2002:a05:6a00:a8d:b029:1ba:71d1:fe3c with SMTP id b13-20020a056a000a8db02901ba71d1fe3cmr19113365pfl.51.1612810003138;
        Mon, 08 Feb 2021 10:46:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612810003; cv=none;
        d=google.com; s=arc-20160816;
        b=lGKLC0RtGFfy4hn1X1MbTh8A5V3U4VaAKbO/BXCTuNLCAQ7YgyJNJhh8OB0PXVxMWd
         NcZX+y1ftzwxeRc23+AQ75tbJBiuA/xCs7Vt5IUX0020sPRRh2IMtVm0/rd8ns8gHkoh
         NjBPZ3tKtJbt7Zc6a96GWl0GI3c6lKz113FnZgC3aRXOQaaMpAQnLbIvZqVHSISzYDWd
         7Hjhqq8GyOnO8MRP9IWAKsSWOX4blPgsIvAaCuIbjLJnhZNbVKm4HZ2tPgOYCpl+RDHI
         AdHr4bhvhqgeHt5YI9anJxaydTGOk4BPAYIaVI4YqSCyv0nldgVL6+2jKJacHU7Mzzqn
         JJ0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uiy4+L1TKc0lecuM77Q8fHlOhBTJ6Asny2DXxHTJcDo=;
        b=IzDyf2f4V7SQ49/k1QdVn5QbweKSTxqvPYLExlLhJ8+wcYH7LezfB+4Z85tj/WcbEM
         og6G6HQY48ectBnwcy0jgPYTrKZ87IzpUHsEvGCpP8k5Igqi5DETCyILwdk+9u25g/dD
         BN83wVOL0aeFReFcjO8a6HmsenED6iIsgUoj2fiTBcIsFG65D2imGNcvZf+xymm94N2/
         hafMNpqTqtLMGEkZeWN0XPqfebQCmQ1wqDvxaW5LHIDDhiSCqxvtvtALHKYrUPiDLUsn
         pA23FQlKtsUNy0TZiXBSDTmpaksteQ5+giKgK5LCwLzuAlD2xf92q55MDkP8FCTP/KNn
         IhKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sCxbX8R2;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc33.google.com (mail-oo1-xc33.google.com. [2607:f8b0:4864:20::c33])
        by gmr-mx.google.com with ESMTPS id q21si756475pgt.3.2021.02.08.10.46.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Feb 2021 10:46:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as permitted sender) client-ip=2607:f8b0:4864:20::c33;
Received: by mail-oo1-xc33.google.com with SMTP id x10so2145327oor.3
        for <kasan-dev@googlegroups.com>; Mon, 08 Feb 2021 10:46:43 -0800 (PST)
X-Received: by 2002:a4a:aa8b:: with SMTP id d11mr10012285oon.36.1612810002329;
 Mon, 08 Feb 2021 10:46:42 -0800 (PST)
MIME-Version: 1.0
References: <6678d77ceffb71f1cff2cf61560e2ffe7bb6bfe9.1612808820.git.andreyknvl@google.com>
In-Reply-To: <6678d77ceffb71f1cff2cf61560e2ffe7bb6bfe9.1612808820.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 8 Feb 2021 19:46:30 +0100
Message-ID: <CANpmjNOkWozE5q2f-w0xTKxi1nDoPy+pMuZ7T78WBMmQ=XpgJg@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix stack traces dependency for HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sCxbX8R2;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c33 as
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

On Mon, 8 Feb 2021 at 19:40, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently, whether the alloc/free stack traces collection is enabled by
> default for hardware tag-based KASAN depends on CONFIG_DEBUG_KERNEL.
> The intention for this dependency was to only enable collection on slow
> debug kernels due to a significant perf and memory impact.
>
> As it turns out, CONFIG_DEBUG_KERNEL is not considered a debug option
> and is enabled on many productions kernels including Android and Ubuntu.
> As the result, this dependency is pointless and only complicates the code
> and documentation.
>
> Having stack traces collection disabled by default would make the hardware
> mode work differently to to the software ones, which is confusing.
>
> This change removes the dependency and enables stack traces collection
> by default.
>
> Looking into the future, this default might makes sense for production
> kernels, assuming we implement a fast stack trace collection approach.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

I'm in favor of this simplification.

The fact that CONFIG_DEBUG_KERNEL cannot be relied upon to determine
if we're running a debug kernel or not is a bit unfortunate though.

Thanks!

> ---
>  Documentation/dev-tools/kasan.rst | 3 +--
>  mm/kasan/hw_tags.c                | 8 ++------
>  2 files changed, 3 insertions(+), 8 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 1651d961f06a..a248ac3941be 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -163,8 +163,7 @@ particular KASAN features.
>  - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
>
>  - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
> -  traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
> -  ``off``).
> +  traces collection (default: ``on``).
>
>  - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
>    report or also panic the kernel (default: ``report``).
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index e529428e7a11..d558799b25b3 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -134,12 +134,8 @@ void __init kasan_init_hw_tags(void)
>
>         switch (kasan_arg_stacktrace) {
>         case KASAN_ARG_STACKTRACE_DEFAULT:
> -               /*
> -                * Default to enabling stack trace collection for
> -                * debug kernels.
> -                */
> -               if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
> -                       static_branch_enable(&kasan_flag_stacktrace);
> +               /* Default to enabling stack trace collection. */
> +               static_branch_enable(&kasan_flag_stacktrace);
>                 break;
>         case KASAN_ARG_STACKTRACE_OFF:
>                 /* Do nothing, kasan_flag_stacktrace keeps its default value. */
> --
> 2.30.0.478.g8a0d178c01-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOkWozE5q2f-w0xTKxi1nDoPy%2BpMuZ7T78WBMmQ%3DXpgJg%40mail.gmail.com.
