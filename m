Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6UZSP5QKGQEFK4GC5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF902270081
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:06:35 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id p65sf796951uap.22
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:06:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600441594; cv=pass;
        d=google.com; s=arc-20160816;
        b=kjh/eodiXa4jY7SOz6VflJZbtnSDBWs+t1FdFRjA4Z/zFpM8RWqsu7utpj43YMpy7p
         M0a5q21UtIgGk4IWM9BwGInWu8ZLXesw5lyi8P4Jn8M6IhsW+h1xwliBSU/iEjNd3uK0
         M9qwbuYIspc2jfw32E+IYmrT9FUqJESPPoue9LZK+Lyi879sWzq9nM8FkYgq6AFVBScX
         PFMMCMp/8dU1PEtDIsEOD7x51Z6sEoFTSVNpINTl+hoG1Z1cZxc1hBThXzUuP2oGKzuL
         sCUINxYWZHKhdBk/U6u7EVbtoSI098pUzseiqDoNNPgjelwNbIeksvip2XenNn6vTly/
         MkqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jZspNMm/Cr29Rs8bzA/AiFFO60BuTIdCagpTB+czBCs=;
        b=0CMRgxYqJK4A/XcApnrTNiknsquzfXbujOpmMnGBguCdx3J6+B+42KTvLJV5sapkuJ
         RRnQNkbz0nQ6GJT957ZOOzNsEv5Ip91ADKZb+SMddJpN0adBCajTZLp+7UpyGK01Fo/3
         mo1Q5UZxjIR3hqQ8Gyv5qnbfqqNXCQlVQI/b5FzMIS6ne4gKV0NqJuorukwK7WhYukTK
         aJrIhENSVZPHBk+7HUEvK+cXH+DKHSr5nOg+X+OKVBPVtuZDduFZ4W3kUtR43vGms/Mn
         8s4rinFOnqmbW7kZZINFQ8fJE1+GYc8evkdHpOpk5iVkROzbUWmtog8dMfFJ8A2kdtWX
         A+xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QngUTfXW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jZspNMm/Cr29Rs8bzA/AiFFO60BuTIdCagpTB+czBCs=;
        b=ptF2hFO4JtVatoRhmTPxqVT0uvJSEkpCWjZsGyYtubS3+SrsmHTCLyeIHYVEBtz1Zv
         j56FcY/Z6cb/BHamUj0USRdyWh8BMt3HS78s+saCkMS7RVnw8AKxUUR1qYnVVU5ZeVwt
         A7DP0zSbnijD05o024VhHkoWvc/Q02zyxvx3rZE+5gt9afuXKK30UhGS+MVJHoXfdyLO
         Mn486zhs8h5siCpzUSfbePAD7eQrNuLq2IiSrFw8foPguRL2VOjBhUYInpU8MG1B8GGS
         kpGjkWU+cyfatZBpLV0VWjTD3/PxLHoyqXaGRD6dvfHWABxp/sHvPaIsSgP2zNkuVugE
         6WEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jZspNMm/Cr29Rs8bzA/AiFFO60BuTIdCagpTB+czBCs=;
        b=a1sTLBoJqHquK6o3L4At4gWeGjg+f+uYikHDElgaCvo9zKqiue2ps+7pOqZI5s4aVn
         n5rssiF8+PcdZVhANHrph9T0lO69fm4QzGQuqvNbVEM+oujtOY7BKta7UDbzt1lgvQri
         WGCYtBKB5xenIlxP17Pj3f0veI0OnFOxAyVkgGbLmhwSZw2d1jwZvH5Ucg0yw0gGu4KD
         IHPblcch85BbZQpbf50pc7nFvyT4rI98tkLwr+5LnauWfp6cYQDSLWiaV22uRPORURdP
         G1kEg/MOtN3QFQdkN9J5OK0lyJUn5WP0//xNwlPWwn6M+yXtgd7610YPm4asGVg8OiL6
         qLug==
X-Gm-Message-State: AOAM530FYk9twHbYoh+78g9qKaKqQC1Nm/awByZ3pm0Q+uD7HJcIVm5Q
	wmzH95SyNz/9fyt00kHq9ic=
X-Google-Smtp-Source: ABdhPJz9ttW4k4hKnh4NdALtWwRMeRnqpZxPi6LUC8vjEBhHja5GQbzs2F30whADiplJ9SJjyx9yfw==
X-Received: by 2002:a1f:6e0e:: with SMTP id j14mr11766324vkc.14.1600441594502;
        Fri, 18 Sep 2020 08:06:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f146:: with SMTP id t6ls747115vsm.7.gmail; Fri, 18 Sep
 2020 08:06:34 -0700 (PDT)
X-Received: by 2002:a67:c887:: with SMTP id v7mr12018709vsk.49.1600441594002;
        Fri, 18 Sep 2020 08:06:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600441593; cv=none;
        d=google.com; s=arc-20160816;
        b=Co0/XIgB6rl5/ej4zgFw057NFWGPt2wsvZGGzvyJau48y4QSPz+zKmLDP3TqqCNCXv
         bsxVEsGucoT6+N6Jmi3myvheuwt0myzkKC+ZVwfOGmERwHoY5CA82OxFrPUJQSlWaAix
         o0jCDFEasI4xOooNJnJT2BPk81davujXiaHHQ/R2o9MdCmy/pP0wAu3hsqWDTTaejn9e
         T/0NxFVVbpJcQGLKcp8+wET4n2HQhvtY++ak2LYIeAcyYQnyJPKZbTsACjiQIxGJA3qj
         HUNZN5/63kgMbDwAmlJi5U+17i3hhrInWDm6Y5kLguJu/Kt4HcjQ0fTORVPZSl+EQnZ0
         6t5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TokX/cApb7HEDUJUqNTQw5zrxkPkqdM85vur5KC2Xr4=;
        b=JKVgW4QvEh2KG01Ui5VzAmQFr2rCTK2mmD35wg91dsDLSRW0Ip0GWMFjWuYjojZRP4
         F7jH5iAvhnW4W/ffzO8ygnBr+TGAiG5dsalYnn704Pngx59Ky32zZKxApq2u6+CALpWY
         Au3fGeUGouV0d39AFqS5AGDMptmtT4e4VbfF7zi/eeq8wf90GL1eKmixZ0QjSX5HWzG5
         /JhCLt1tmudRonLaH30sKZGor62+Ni+Vn95eIB4ZDS7l2tMMbBIVmUnMkCub8u/HgAvE
         +6t/H3r6z41DvaLNx1q00nG+j9xNFOp3sdI7mxIpbeK7oBxqHkDKyC6QzzXnNImmBuZJ
         3NMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QngUTfXW;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id s11si160218vsn.1.2020.09.18.08.06.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:06:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id o20so3604158pfp.11
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:06:33 -0700 (PDT)
X-Received: by 2002:a62:1d51:0:b029:13e:d13d:a0fc with SMTP id
 d78-20020a621d510000b029013ed13da0fcmr33038595pfd.24.1600441592809; Fri, 18
 Sep 2020 08:06:32 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
 <20200918123249.GC2384246@elver.google.com>
In-Reply-To: <20200918123249.GC2384246@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:06:21 +0200
Message-ID: <CAAeHK+wF_tkBqHd7ESSa5jOy50AW1WfzSAM-qNf_+iMkLwptTQ@mail.gmail.com>
Subject: Re: [PATCH v2 21/37] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QngUTfXW;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Fri, Sep 18, 2020 at 2:32 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> > This patch adds a configuration option for a new KASAN mode called
> > hardware tag-based KASAN. This mode uses the memory tagging approach
> > like the software tag-based mode, but relies on arm64 Memory Tagging
> > Extension feature for tag management and access checking.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> > Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> > ---
> >  lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
> >  1 file changed, 39 insertions(+), 17 deletions(-)
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index b4cf6c519d71..17c9ecfaecb9 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
> >  config HAVE_ARCH_KASAN_SW_TAGS
> >       bool
> >
> > -config       HAVE_ARCH_KASAN_VMALLOC
> > +config HAVE_ARCH_KASAN_HW_TAGS
> > +     bool
> > +
> > +config HAVE_ARCH_KASAN_VMALLOC
> >       bool
> >
> >  config CC_HAS_KASAN_GENERIC
> > @@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
> >
> >  menuconfig KASAN
> >       bool "KASAN: runtime memory debugger"
> > -     depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> > -                (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> > +     depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> > +                  (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
> > +                 CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> > +                HAVE_ARCH_KASAN_HW_TAGS
> >       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> > -     depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> >       select SLUB_DEBUG if SLUB
>
> Is SLUB_DEBUG necessary with HW_TAGS?

I'll check and drop it if it's unnecessary.

> >       select CONSTRUCTORS
> >       select STACKDEPOT
> > @@ -38,13 +42,18 @@ choice
> >       prompt "KASAN mode"
> >       default KASAN_GENERIC
> >       help
> > -       KASAN has two modes: generic KASAN (similar to userspace ASan,
> > -       x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
> > -       software tag-based KASAN (a version based on software memory
> > -       tagging, arm64 only, similar to userspace HWASan, enabled with
> > -       CONFIG_KASAN_SW_TAGS).
> > +       KASAN has three modes:
> > +       1. generic KASAN (similar to userspace ASan,
> > +          x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
> > +       2. software tag-based KASAN (arm64 only, based on software
> > +          memory tagging (similar to userspace HWASan), enabled with
> > +          CONFIG_KASAN_SW_TAGS), and
> > +       3. hardware tag-based KASAN (arm64 only, based on hardware
> > +          memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
> >
> > -       Both generic and tag-based KASAN are strictly debugging features.
> > +       All KASAN modes are strictly debugging features.
> > +
> > +       For better error detection enable CONFIG_STACKTRACE.
>
> I don't think CONFIG_STACKTRACE improves error detection, right? It only
> makes the reports more readable

Yes, will fix.

> >
> >  config KASAN_GENERIC
> >       bool "Generic mode"
> > @@ -61,8 +70,6 @@ config KASAN_GENERIC
> >         and introduces an overhead of ~x1.5 for the rest of the allocations.
> >         The performance slowdown is ~x3.
> >
> > -       For better error detection enable CONFIG_STACKTRACE.
> > -
> >         Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> >         (the resulting kernel does not boot).
> >
> > @@ -72,9 +79,11 @@ config KASAN_SW_TAGS
> >       help
> >         Enables software tag-based KASAN mode.
> >
> > -       This mode requires Top Byte Ignore support by the CPU and therefore
> > -       is only supported for arm64. This mode requires Clang version 7.0.0
> > -       or later.
> > +       This mode require software memory tagging support in the form of
> > +       HWASan-like compiler instrumentation.
> > +
> > +       Currently this mode is only implemented for arm64 CPUs and relies on
> > +       Top Byte Ignore. This mode requires Clang version 7.0.0 or later.
> >
> >         This mode consumes about 1/16th of available memory at kernel start
> >         and introduces an overhead of ~20% for the rest of the allocations.
> > @@ -82,15 +91,27 @@ config KASAN_SW_TAGS
> >         casting and comparison, as it embeds tags into the top byte of each
> >         pointer.
> >
> > -       For better error detection enable CONFIG_STACKTRACE.
> > -
> >         Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
> >         (the resulting kernel does not boot).
> >
> > +config KASAN_HW_TAGS
> > +     bool "Hardware tag-based mode"
> > +     depends on HAVE_ARCH_KASAN_HW_TAGS
> > +     depends on SLUB
> > +     help
> > +       Enables hardware tag-based KASAN mode.
> > +
> > +       This mode requires hardware memory tagging support, and can be used
> > +       by any architecture that provides it.
> > +
> > +       Currently this mode is only implemented for arm64 CPUs starting from
> > +       ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
> > +
> >  endchoice
> >
> >  choice
> >       prompt "Instrumentation type"
> > +     depends on KASAN_GENERIC || KASAN_SW_TAGS
> >       default KASAN_OUTLINE
> >
> >  config KASAN_OUTLINE
> > @@ -114,6 +135,7 @@ endchoice
> >
> >  config KASAN_STACK_ENABLE
> >       bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> > +     depends on KASAN_GENERIC || KASAN_SW_TAGS
> >       help
> >         The LLVM stack address sanitizer has a know problem that
> >         causes excessive stack usage in a lot of functions, see
>
> How about something like the below change (introduce KASAN_INSTRUMENTED
> Kconfig var) to avoid the repeated "KASAN_GENERIC || KASAN_SW_TAGS".
> This could then also be used in the various .c/.h files (and make some
> of the code more readable hopefully).

I tried doing that initially, but it didn't really look good. The
reason is that we actually have two properties that are currently
common for the software modes, but aren't actually tied to each other:
instrumentation and shadow memory. Therefore we will end up with two
new configs: KASAN_INSTRUMENTED and KASAN_USES_SHADOW (or something),
and things get quite confusing. I think it's better to keep
KASAN_GENERIC || KASAN_SW_TAGS everywhere.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwF_tkBqHd7ESSa5jOy50AW1WfzSAM-qNf_%2BiMkLwptTQ%40mail.gmail.com.
