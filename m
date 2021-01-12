Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVGU677QKGQEYH7FUMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id BF4DF2F38DC
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 19:28:37 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id c7sf4447678iob.10
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:28:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610476116; cv=pass;
        d=google.com; s=arc-20160816;
        b=FnR3fXzZzeidScq9szhti74/ZEXbatx0P9kmBJgdd7FLqjHdu19udLMEZW5jbkcf3f
         vn0Lt18bI5QZxKZi3EkWaioJRsCWjeFsmmUTXoLT1hegv+O0cHqs0s6kRTJNKd1Fulln
         rSzPugfLg0d4Erd1yEr9tQkKzyqpbEkEwhVObNbaRyxRcp8ckgvbeCGSVTEAxO8FcywK
         /5ypu+DNoCWIVzIZeUo8kw6UvAAI+IUIemhKSdp1rpOcawDnxOGl1rgwetDfhP4mMQLP
         Z09cXzmM6HacWVzz578y0hvPBTW0SL3pHBWJoi1Re+Mm7Nyrtt8lbw4Mogg/vCcRmDfF
         v20Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=c92KR06aRQtW6UGdHroLb75R8Zia2MjG2is9KUS5/lY=;
        b=Rnp6W1x9o6Qs0zC3pbZ1+89TA/o62LJ3cOextSVdSIJFWviIPjMGIr3K2AHBt047Z4
         q+49NBEGCx73JpEoYf/Vaxw0KXnewseeXxAA49BC8HWnadIkg2nHR+XY42n4GnwCUPtQ
         GbnYf3E+bHcTDtXX/mA6hEAazlmRmimAZKBakRRNuzYvvA+VjudohLpgVbAFxUFkeh/t
         2bG96AbVLYxA/LtUvjlPbi3oY7ISzNnSBBu2KIDOLWX8QhEC/Jc1byV9erR9+FNQzu77
         OpC2ZgLiV/98rR2mtHzQlzKXV8cMOrr2lu1Qy61d35Bx1xCrbIQyantd3ZhRVi1JoMy4
         bTIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NbtgBBkA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c92KR06aRQtW6UGdHroLb75R8Zia2MjG2is9KUS5/lY=;
        b=pXSaXdUZaqYWQ7ylaV6Pmu3GUXSIbjlZK8M/DDZFYF5B9JgdGcsymkzC+K98GmfF7R
         1NaYvfC5Q9Eq/ZXljYNIyrog1mkBt1Rw0SrE5z0fw6A26cTxYR4742eAzbpJVLoSdpem
         uZv1Y+lKx/TAIM9ko+NMaiPucBESMiX8DsQVeNvIhs0DNfw7nQt33b7jH8qhGDxWUdtu
         V8/lN+Y3ZIaZHRpSfTkCflIbn4+hIpA38jpEy1Oi2FDh6VBsjUy4i19HSZwYdkXOOR3g
         6djNwro+xJq5ISDZMAIchTVdUXrBZ9FsnLh+q+vKitUrD7s7cYD6XGsDD8EVg8N3MDaF
         RJSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c92KR06aRQtW6UGdHroLb75R8Zia2MjG2is9KUS5/lY=;
        b=ZThpV+voxHsQ+SC965pc29MtflyvizaXdR/jRpqRwJZqW4/mdiRW/N13z8/4n0jlVE
         48O4IBDzKWLkNKg9YILrFQyngKF/DofYb271PxiTafIlO0i37sHSgQZc94eb3e6aYQvW
         dXzRBxQB0fLzS2za7forpaC4vv7RHbw24soN08jnEUHsFPU6V9IbsaAzw4G09ujOWL8E
         OvGK0Sb0qYL2X99nnmi5TeylqMtHOYZrjfRs0xyXAtly+cNILmKvj7CjHpCvLyi1g0Ah
         yv3U2nJny9cDL7q4fnxo+I/pD2k6UH/fcyCCYlpJ9Juwt9zNkXz7mW0GRS6anrHWxKz+
         82/A==
X-Gm-Message-State: AOAM532QalGRFvU+uRx8bCYtFjyEZxc9+HJ1VgXCZDKs148Nz2pm6ihr
	+ikaBgG4nlIZUlZVvjX/I2c=
X-Google-Smtp-Source: ABdhPJxqzwnwoYWDIUyQ+8uKdpvdcGyKwK1mtq0fTyerylH5eC6jhoaT41w8TpTJC9WctG4dfClxFQ==
X-Received: by 2002:a92:c692:: with SMTP id o18mr291517ilg.215.1610476116695;
        Tue, 12 Jan 2021 10:28:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls1248861ill.9.gmail; Tue,
 12 Jan 2021 10:28:36 -0800 (PST)
X-Received: by 2002:a05:6e02:e03:: with SMTP id a3mr279975ilk.305.1610476116205;
        Tue, 12 Jan 2021 10:28:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610476116; cv=none;
        d=google.com; s=arc-20160816;
        b=pjIE3u7XayFW6/Qq+Sll/XHCo4vXjauTPSzI02/Sw296woS3HL5ekr01716Tut7C4X
         Ug6xO/XQtDSz7P8tT2BltkECzYaFdYPky/90PRZG2JvwLArWNC3VPBrgiwrQZjJrmSHy
         C4x7M2IDzp9sPxS9XNMwSB8oXvDkxEbFx9FuT3A2QlRV3rOq7tS2/I6vR1C1SK3/P80V
         8TpbhXf9gGRTDkmARacq8X2LgKlf0rzJvfJSv9jEoH9Q9WfM7/mJdfmO1yGwtAPvGRsY
         aCzNk4iIPUEqxoX1zPc9xwsomY4c3BdIbmivjyRg//lED4boQyINiiPXo6Y68rMnfQqq
         VYDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Rph5/YWztZo7f+7iLQyy6pT5CxZC682xIlOwCUdZJGU=;
        b=aLMNFhf6QBEbRDOcxHSmorE7qs0DDVJh+/3flX+QGrbCmiD9hkV+MC2DEKmdQDxzMp
         zb1+YxxoIs/DDsrqfKh3z/hcB0PDXsxbulpHZAzjVDmDfey4k8A16gjfP59n+u9G3ggc
         JiUYtlY5Qc7YeW6uFW+0xQ8wJM8zQ+2d7OMvaGSh+FbMwUbsQLsWjH2aojFaaycNz6MW
         mvfdDeuN+CokonAeYcCH7Vn5jPzNUEyaRnJw7XQIJPf1Fxfb0q3Qc/4v70beqjX6eBEG
         KUJP2sJueUIgVRioBD5cZpaZ09ZgfVWE4MAzDgEoIcoRztHM3RNWSlVnyT5ixuPTXZlr
         ub/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NbtgBBkA;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id y16si434635iln.0.2021.01.12.10.28.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 10:28:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id l23so2239801pjg.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 10:28:36 -0800 (PST)
X-Received: by 2002:a17:90b:1087:: with SMTP id gj7mr421423pjb.41.1610476115545;
 Tue, 12 Jan 2021 10:28:35 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <ae666d8946f586cfc250205cea4ae0b729d818fa.1609871239.git.andreyknvl@google.com>
 <X/2lLAOWi4PHJh/Q@elver.google.com>
In-Reply-To: <X/2lLAOWi4PHJh/Q@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 19:28:24 +0100
Message-ID: <CAAeHK+z0z4gvbBvyPYnG3bRqcsHD88byMAzzWDQ8H4mb0ZYuYA@mail.gmail.com>
Subject: Re: [PATCH 06/11] kasan: rename CONFIG_TEST_KASAN_MODULE
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NbtgBBkA;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
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

On Tue, Jan 12, 2021 at 2:33 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Jan 05, 2021 at 07:27PM +0100, Andrey Konovalov wrote:
> > Rename CONFIG_TEST_KASAN_MODULE to CONFIG_KASAN_MODULE_TEST.
> >
> > This naming is more consistent with the existing CONFIG_KASAN_KUNIT_TEST.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Id347dfa5fe8788b7a1a189863e039f409da0ae5f
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> For this patch, as-is. But we could potentially do better in future --
> see below.
>
> > ---
> >  Documentation/dev-tools/kasan.rst | 6 +++---
> >  lib/Kconfig.kasan                 | 2 +-
> >  lib/Makefile                      | 2 +-
> >  3 files changed, 5 insertions(+), 5 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index 26c99852a852..72535816145d 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -374,8 +374,8 @@ unmapped. This will require changes in arch-specific code.
> >  This allows ``VMAP_STACK`` support on x86, and can simplify support of
> >  architectures that do not have a fixed module region.
> >
> > -CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
> > ---------------------------------------------------
> > +CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
> > +----------------------------------------------------
> >
> >  KASAN tests consist on two parts:
> >
> > @@ -384,7 +384,7 @@ KASAN tests consist on two parts:
> >  automatically in a few different ways, see the instructions below.
> >
> >  2. Tests that are currently incompatible with KUnit. Enabled with
> > -``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
> > +``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
> >  only be verified manually, by loading the kernel module and inspecting the
> >  kernel log for KASAN reports.
> >
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index 3091432acb0a..624ae1df7984 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -192,7 +192,7 @@ config KASAN_KUNIT_TEST
> >         For more information on KUnit and unit tests in general, please refer
> >         to the KUnit documentation in Documentation/dev-tools/kunit.
> >
> > -config TEST_KASAN_MODULE
> > +config KASAN_MODULE_TEST
> >       tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
> >       depends on m && KASAN && !KASAN_HW_TAGS
> >       help
> > diff --git a/lib/Makefile b/lib/Makefile
> > index afeff05fa8c5..122f25d6407e 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -68,7 +68,7 @@ obj-$(CONFIG_TEST_IDA) += test_ida.o
> >  obj-$(CONFIG_KASAN_KUNIT_TEST) += test_kasan.o
> >  CFLAGS_test_kasan.o += -fno-builtin
> >  CFLAGS_test_kasan.o += $(call cc-disable-warning, vla)
> > -obj-$(CONFIG_TEST_KASAN_MODULE) += test_kasan_module.o
> > +obj-$(CONFIG_KASAN_MODULE_TEST) += test_kasan_module.o
> >  CFLAGS_test_kasan_module.o += -fno-builtin
>
> [1] https://www.kernel.org/doc/html/latest/dev-tools/kunit/style.html#test-file-and-module-names
>
> Do we eventually want to rename the tests to follow the style
> recommendation more closely?
>
> Option 1: Rename the KUnit test to kasan_test.c? And then
> also rename test_kasan_module.c -> kasan_module_test.c?  Then the file
> names would be mostly consistent with the config names.
>
> Option 2: The style guide [1] also mentions where there are non-KUnit
> tests around to use _kunit for KUnit test, and _test (or similar) for
> the non-KUnit test. So here we'd end up with kasan_kunit.c and
> kasan_test.c. That would get rid of the confusing "module" part. The
> config variable could either remain CONFIG_KASAN_MODULE_TEST, or simply
> become CONFIG_KASAN_TEST, since we already have CONFIG_KASAN_KUNIT_TEST
> to distinguish.
>
> But I won't bikeshed further. If you do a v2, I leave it to your
> judgement to decide what is most appropriate.

Most tests in lib/ start with test_, so not using that pattern for
KASAN tests could be confusing. Maybe we can move them to mm/kasan.
Anyway, I won't look into this right now.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz0z4gvbBvyPYnG3bRqcsHD88byMAzzWDQ8H4mb0ZYuYA%40mail.gmail.com.
