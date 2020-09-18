Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7FHSP5QKGQEDUIRUUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7502E27012C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:36:30 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id s18sf3605251plp.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:36:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600443389; cv=pass;
        d=google.com; s=arc-20160816;
        b=jlX5b9Bzm8Od8tbtQL8JOfjc9iOwHEydsA+2MKW674EfQLvnt+dlE49hx6tdjBOSRQ
         sIOVNhyasswTOqMJ7lvQ7eoX+8csIFCVXvPnwbebiW+tQKvy3I474RMwpSkIDvE5HF37
         Hzowk4XwjXWlVWOnNl1gQIBuLepsRu6cSoXEQj01WrnKLWhoeL6IVGgXd4DBJxXrqgAh
         PMe0VGWHE61DOCQ0ee+Y6f0PcLasw+jd4G7dCtUHGFA5OGLM7LWYuNNoy8twbeb0cLFS
         q3h8WyNgpH6IjfHXEiY5brEP1OJKy44xXmuzaPuwPARLrAw3gg+LBd+JO6/HRTwhdQ1Y
         +V5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A0YwMqiGjBza2MkhChnGHbd/NgIYKPw/9953Js+mJ0Q=;
        b=0laCI4E5Wr3pdeiE1n+S4nmJJYwLUhOVSD/j0zm+Vw1j9vaqMdO/2xk3yJ3BOpiq3o
         5Rb5/Tsduxptvsv600JTL14tGi393AgEMAveRiAjMhk6f274roP/AC1/U69xqujeCJHO
         El9aq/6uxJcpgfIGnBHSQ16g5f7KO9j+hFcK/92gMW1gkfutAVE+dgfSwYtWicEVidjC
         xySEozoaQvL+JaMbf91uoU8M9Fak8W1n/xahO+LAZ4QdS49hBMh39v2k6ls/MeldxuFg
         NC92qebUf7DvjAS/6T+l1fYOC1or09TG96M0q6IPL91luwBhPCvUkgvsOejDU8wKmlA2
         lQXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MSGZJCQT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A0YwMqiGjBza2MkhChnGHbd/NgIYKPw/9953Js+mJ0Q=;
        b=LJY7uaWwGVYy2wFE0a1aMaOCzGiVADwN5zttNMAlE49RsKCQ2KV9Mc9S+coXo36anF
         8s18Tu5YH7/LaVyE0ZtGJM4ZSRV8olpMoDbLKv6FcVgRSh0LenkQu4AOfXA5tHjwc7LL
         iImi5w/+hepoomEEpm+KyRrFdGejO5nqS8IrHgHYMDzMsd+Up7PxrtTf+4UedAwmfojO
         E3h26nFwrhsSaX/wIlFaU2bJWDUKHT0UFbOnOiF/NNMdu6VqcHWd06KsHAs1xqb8InP0
         rPDJpT1RysYPcYo7UFOM/9jzhrR/W+ruF4lOawj0dinBcOaWKp0VgoPnCOezShTiyzzD
         WasQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A0YwMqiGjBza2MkhChnGHbd/NgIYKPw/9953Js+mJ0Q=;
        b=bQT570gEb01mv1PviOXc97XkdGyzTDCt/9Yy1HkvQ1rgVXTVx0epVwAclozhQNAQ84
         MdSWNYgz+ZNBt4aQJIoVJTFLLHr2SwlW37R22/Ds5gbRyYGpnI3yt86Atu0rVedhymqp
         Qrur8hP3aYjC6oXnINFBlMveBY+aVCHYY4m3b0Euuk/h89kqGKhrHSFrZvSus7APHaAE
         wnZ2jdGYedwXmwPm/O77J8jRll6zxoDGokVezao+F2ezLlWoUqk8FiQQaq8lhS+tX6lZ
         p7GU3sHBMJLYot+oeMWqW3QA9aCcyF42PG4Nq+yekuPIwm81XBvQSnJx0Iwq7uqO/QZ4
         gIvA==
X-Gm-Message-State: AOAM533eXSuCzPa/qnmSIpRfOVzMNiQZ+5HDX6GaKC2gfOQBA6nc95UL
	Vw8i5FLKxr0XO5JYs9P7EWk=
X-Google-Smtp-Source: ABdhPJxHLoOgud2K5ykPwv+21RqgnCVQyP9fwZdwbqicchhDR8cteVR68Re/Gh9DLYd92IN/Mlf5zQ==
X-Received: by 2002:a62:1410:0:b029:13e:d13d:a129 with SMTP id 16-20020a6214100000b029013ed13da129mr32572256pfu.17.1600443388716;
        Fri, 18 Sep 2020 08:36:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7449:: with SMTP id e9ls2901788plt.0.gmail; Fri, 18
 Sep 2020 08:36:28 -0700 (PDT)
X-Received: by 2002:a17:902:9349:b029:d0:cb2d:f26c with SMTP id g9-20020a1709029349b02900d0cb2df26cmr33020380plp.5.1600443388012;
        Fri, 18 Sep 2020 08:36:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600443388; cv=none;
        d=google.com; s=arc-20160816;
        b=uBk6Nxv79fxmNOHMYDI+gw5Kzleqd75tt5ApnwOFDwh+PKR6dOdyoMPEOeZ/4+rE35
         FtXjoDZn64+Pyf56KiLmA1H7utFCwX0qM7HV1TE7WtCe2F7ApBudk04S+Xf/m5ppB43h
         doBCpwdsQ7hXjB2UFq/AaT22hfAnJvYimmiR8ilfFLvCrSPv5jEfDC4WwwnpQl7ftJZ/
         bprXbcE3SmNDP1K6+rMnYLkCU5IYJ+WaiC2A4LlLsqlr86WBL+6n2cMttRu/c7o71kst
         48VIS6D8lPn3j3pN6+VNjCIzTIFS6AzZRiX9mevBBZ1EpaWarlUY3Kd6WsmeiSeX4KKs
         4F+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+HOkTaJCWTKIpK+3x2SmmkvtVfO2tEwf9L1qfcnwH58=;
        b=dCOnnUO2ZrZRUUgmvKPFZV860leurpk7Xk0KhW4YyfkQiBNGjf37t1Pc0Oltl5bAVA
         brS77CvBfkxjmuI2MUnwLBj6y/dKe9t/DvoYCM84moNRAv/YfdVarWoO6fFL7wISV5Y4
         UKoUzaJerrkayuSt6hIjA996LLbpflNtahiKJ1v6zRkKVaX4q6wPRu862ZeRIPwKRqjD
         f7IXV4dfr/qVsbJWAXb95PRP3Ac1QdZghofTw04HGnsNcPebUDu/8TX+CH0HeDjaqlRh
         K7hlj6Kj3d4Qpldb1AjZlGqaZuuYa38oKOftM4JJMIYfqNZXXbsiyrtZXKvh0HqcAn2f
         CK8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MSGZJCQT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id d60si836050pjk.0.2020.09.18.08.36.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:36:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id z26so7465281oih.12
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:36:27 -0700 (PDT)
X-Received: by 2002:aca:5158:: with SMTP id f85mr10175640oib.121.1600443387052;
 Fri, 18 Sep 2020 08:36:27 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
 <20200918123249.GC2384246@elver.google.com> <CAAeHK+wF_tkBqHd7ESSa5jOy50AW1WfzSAM-qNf_+iMkLwptTQ@mail.gmail.com>
In-Reply-To: <CAAeHK+wF_tkBqHd7ESSa5jOy50AW1WfzSAM-qNf_+iMkLwptTQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:36:15 +0200
Message-ID: <CANpmjNNrBX624GJWY3GK6YR9xoYX8BwstXaRYXJT1QgSFORSaQ@mail.gmail.com>
Subject: Re: [PATCH v2 21/37] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MSGZJCQT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 18 Sep 2020 at 17:06, 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Fri, Sep 18, 2020 at 2:32 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> > > This patch adds a configuration option for a new KASAN mode called
> > > hardware tag-based KASAN. This mode uses the memory tagging approach
> > > like the software tag-based mode, but relies on arm64 Memory Tagging
> > > Extension feature for tag management and access checking.
> > >
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > > ---
> > > Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> > > ---
> > >  lib/Kconfig.kasan | 56 +++++++++++++++++++++++++++++++++--------------
> > >  1 file changed, 39 insertions(+), 17 deletions(-)
> > >
> > > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > > index b4cf6c519d71..17c9ecfaecb9 100644
> > > --- a/lib/Kconfig.kasan
> > > +++ b/lib/Kconfig.kasan
> > > @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
> > >  config HAVE_ARCH_KASAN_SW_TAGS
> > >       bool
> > >
> > > -config       HAVE_ARCH_KASAN_VMALLOC
> > > +config HAVE_ARCH_KASAN_HW_TAGS
> > > +     bool
> > > +
> > > +config HAVE_ARCH_KASAN_VMALLOC
> > >       bool
> > >
> > >  config CC_HAS_KASAN_GENERIC
> > > @@ -20,10 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
> > >
> > >  menuconfig KASAN
> > >       bool "KASAN: runtime memory debugger"
> > > -     depends on (HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> > > -                (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)
> > > +     depends on (((HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC) || \
> > > +                  (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
> > > +                 CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> > > +                HAVE_ARCH_KASAN_HW_TAGS
> > >       depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> > > -     depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> > >       select SLUB_DEBUG if SLUB
> >
> > Is SLUB_DEBUG necessary with HW_TAGS?
>
> I'll check and drop it if it's unnecessary.
>
> > >       select CONSTRUCTORS
> > >       select STACKDEPOT
> > > @@ -38,13 +42,18 @@ choice
> > >       prompt "KASAN mode"
> > >       default KASAN_GENERIC
> > >       help
> > > -       KASAN has two modes: generic KASAN (similar to userspace ASan,
> > > -       x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC) and
> > > -       software tag-based KASAN (a version based on software memory
> > > -       tagging, arm64 only, similar to userspace HWASan, enabled with
> > > -       CONFIG_KASAN_SW_TAGS).
> > > +       KASAN has three modes:
> > > +       1. generic KASAN (similar to userspace ASan,
> > > +          x86_64/arm64/xtensa, enabled with CONFIG_KASAN_GENERIC),
> > > +       2. software tag-based KASAN (arm64 only, based on software
> > > +          memory tagging (similar to userspace HWASan), enabled with
> > > +          CONFIG_KASAN_SW_TAGS), and
> > > +       3. hardware tag-based KASAN (arm64 only, based on hardware
> > > +          memory tagging, enabled with CONFIG_KASAN_HW_TAGS).
> > >
> > > -       Both generic and tag-based KASAN are strictly debugging features.
> > > +       All KASAN modes are strictly debugging features.
> > > +
> > > +       For better error detection enable CONFIG_STACKTRACE.
> >
> > I don't think CONFIG_STACKTRACE improves error detection, right? It only
> > makes the reports more readable
>
> Yes, will fix.
>
> > >
> > >  config KASAN_GENERIC
> > >       bool "Generic mode"
> > > @@ -61,8 +70,6 @@ config KASAN_GENERIC
> > >         and introduces an overhead of ~x1.5 for the rest of the allocations.
> > >         The performance slowdown is ~x3.
> > >
> > > -       For better error detection enable CONFIG_STACKTRACE.
> > > -
> > >         Currently CONFIG_KASAN_GENERIC doesn't work with CONFIG_DEBUG_SLAB
> > >         (the resulting kernel does not boot).
> > >
> > > @@ -72,9 +79,11 @@ config KASAN_SW_TAGS
> > >       help
> > >         Enables software tag-based KASAN mode.
> > >
> > > -       This mode requires Top Byte Ignore support by the CPU and therefore
> > > -       is only supported for arm64. This mode requires Clang version 7.0.0
> > > -       or later.
> > > +       This mode require software memory tagging support in the form of
> > > +       HWASan-like compiler instrumentation.
> > > +
> > > +       Currently this mode is only implemented for arm64 CPUs and relies on
> > > +       Top Byte Ignore. This mode requires Clang version 7.0.0 or later.
> > >
> > >         This mode consumes about 1/16th of available memory at kernel start
> > >         and introduces an overhead of ~20% for the rest of the allocations.
> > > @@ -82,15 +91,27 @@ config KASAN_SW_TAGS
> > >         casting and comparison, as it embeds tags into the top byte of each
> > >         pointer.
> > >
> > > -       For better error detection enable CONFIG_STACKTRACE.
> > > -
> > >         Currently CONFIG_KASAN_SW_TAGS doesn't work with CONFIG_DEBUG_SLAB
> > >         (the resulting kernel does not boot).
> > >
> > > +config KASAN_HW_TAGS
> > > +     bool "Hardware tag-based mode"
> > > +     depends on HAVE_ARCH_KASAN_HW_TAGS
> > > +     depends on SLUB
> > > +     help
> > > +       Enables hardware tag-based KASAN mode.
> > > +
> > > +       This mode requires hardware memory tagging support, and can be used
> > > +       by any architecture that provides it.
> > > +
> > > +       Currently this mode is only implemented for arm64 CPUs starting from
> > > +       ARMv8.5 and relies on Memory Tagging Extension and Top Byte Ignore.
> > > +
> > >  endchoice
> > >
> > >  choice
> > >       prompt "Instrumentation type"
> > > +     depends on KASAN_GENERIC || KASAN_SW_TAGS
> > >       default KASAN_OUTLINE
> > >
> > >  config KASAN_OUTLINE
> > > @@ -114,6 +135,7 @@ endchoice
> > >
> > >  config KASAN_STACK_ENABLE
> > >       bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
> > > +     depends on KASAN_GENERIC || KASAN_SW_TAGS
> > >       help
> > >         The LLVM stack address sanitizer has a know problem that
> > >         causes excessive stack usage in a lot of functions, see
> >
> > How about something like the below change (introduce KASAN_INSTRUMENTED
> > Kconfig var) to avoid the repeated "KASAN_GENERIC || KASAN_SW_TAGS".
> > This could then also be used in the various .c/.h files (and make some
> > of the code more readable hopefully).
>
> I tried doing that initially, but it didn't really look good. The
> reason is that we actually have two properties that are currently
> common for the software modes, but aren't actually tied to each other:
> instrumentation and shadow memory. Therefore we will end up with two
> new configs: KASAN_INSTRUMENTED and KASAN_USES_SHADOW (or something),
> and things get quite confusing. I think it's better to keep
> KASAN_GENERIC || KASAN_SW_TAGS everywhere.

Ah, I see. So in some cases the reason the #ifdef exists is because of
instrumentation, in other cases because there is some shadow memory
(right?).

The only other option I see is to call it what it is ("KASAN_SW" or
"KASAN_SOFTWARE"), but other than that, I don't mind if it stays
as-is.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNrBX624GJWY3GK6YR9xoYX8BwstXaRYXJT1QgSFORSaQ%40mail.gmail.com.
