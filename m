Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWPKUT4QKGQEQGJSXMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DA8323B891
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 12:15:55 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id y11sf13691416pfq.8
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 03:15:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596536153; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cxf04s9GJ6XGemsldaXJVBKWN1VK8Frl7G2Ama+jQyq4GzbgwWWiM4eYxAEGYnw9bO
         7f667wCISRyxtlO5OtRxcrnk4wuV0ycPXOISmydiKYEMimuRT/I1gotwVYM8deAh3Llc
         JbY/84O9ZMWKgCtUKAfUSn7C3TuuxYMqGnohFNqcqxrbvBNOAM5BCPUJNGihrrGAjkqn
         KmRDrV83pN930ic5kOEVK0cXsnOyZtC8H9JRRplhUWxCm8hOex+0EOGLz0s0I4aRUbKt
         YJBPj396FtyBAhYXMeb52MRHttfhBpOY6GtP8relvLkICIT2ZhsOiiq/OJmv4h2L0MRh
         nWeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=be/cGeljhNOSPIQbWn3Te85uCSWLBUdaVmiqrSalCpM=;
        b=sBYDI57t6612J7yKmaBB34JiQQs5jRFhsOvM59yKp8ru1QlNG6SW/0jjB6qQABnm2L
         D/1660PYndW6At9++qOVwXfBLkzjeiyu5vUQUJmFPMYJPODSOzq/K8vr/gY+o2ne9AsW
         FpZkSQLjXrrJECVIllpDTUw1rxGFoIj9DZpVhdXEW/2+0en9GoEtP18cFG9veEsk+87S
         hB+poD/mSAIWXD7lSR8IrQ1vu1LOwVKOsnftWiYgeU4nB8Wxp9u6j/XIOsacF0ssQ2iM
         G4Xzok4vK74k0zx54PaQuuPa5GL/jb15ULe3y4lahm8HBesRq7dYJFj2RySyd9QWmf3B
         nq+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pZim17LZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=be/cGeljhNOSPIQbWn3Te85uCSWLBUdaVmiqrSalCpM=;
        b=be5OhDSf4PvOXukX6Ow5oebQJd7/ricTysRwJCqVWcHDoeUmsRilmnVZmMotsC+nFG
         pVSrff4tJv9ueEI/OnBmZVNLXFWgEOUmuPpYKzSsZRZKDLf2NUyNO8iBHaykGEDwfCY8
         sCFaLQWkUKynnbyyZuK/HmDjmsaU77SCE4FnECePMQWc7T5mTKhO8d3GyZG2JzB3qZte
         9AYPYmLHPmvLmmUwayi2mn4WeU9QNvp7cw66Q6YSX7LVUQmdi3PS5wA9f9waX8ftGt+7
         dWx1z4v4HZ6TYUXLc3WX+E5dimzYO0BZPJReUYPvx0ZfzwKMMpfHJh6wknj8lV9o7u4f
         OlAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=be/cGeljhNOSPIQbWn3Te85uCSWLBUdaVmiqrSalCpM=;
        b=au5MV22Q+Xk3m7fPzCakui/QcR9oml2wmKq/TREykMEtIGjvAj+5KcJJKABVyxKX/R
         3VIGt6ucO+Zzf0XUPENCOcDAsRiGK0C+AdToMHK+WJW1d8D+SQrK7wWK56gqwEUqUWSL
         v9dtPpmmfj1e62vYTTpPtQc0tMtPeguHv2NA5zaTZt5umLyz+UWdtRo/uHjkP1Z2oxW5
         Z5jAzgd8pxodIfMo9r7Qa97YdaSgbfrdaNeKRDMTxEe/tXLhtZSaggjYGEJIRmYO1nZ2
         PZu3kZfCJ600b1876Sh0aJKvXqlq8J2v9nfXGclDaM4u+2LaanXy4RkmDbDwJ9fXDv62
         RgBg==
X-Gm-Message-State: AOAM5316xs4CzUIxhaTxWIzeuCWf7+Z12gGHZMHnHxQdOePw3xtBtzkM
	TH6ZXLo3UiskbbLpP4xIjvU=
X-Google-Smtp-Source: ABdhPJxUNHN1TdxvSLIhIKucJDTn9OT/lQBissRx6H9lHyehkTPNTbEn8IWeCgx73b3GY4YdytiPFA==
X-Received: by 2002:a17:90a:ff92:: with SMTP id hf18mr3781977pjb.107.1596536153651;
        Tue, 04 Aug 2020 03:15:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d86:: with SMTP id i128ls387461pgc.6.gmail; Tue, 04 Aug
 2020 03:15:53 -0700 (PDT)
X-Received: by 2002:aa7:8096:: with SMTP id v22mr20661189pff.132.1596536153273;
        Tue, 04 Aug 2020 03:15:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596536153; cv=none;
        d=google.com; s=arc-20160816;
        b=OQkUG7HVHNVKH2EZI/eWM3VjmEGV0poSBLhHkHz3oq05tTqCxYFLIPKx0MshclaZ9i
         AsjiAUYjrN6BUs1BgT//fiQcmRMZjf9igj71qphPJj+ipLIZhA0BEP0lZkpr1fgA3lEU
         oWVOsAxfY4GEnw+VeOWJC/JeX6ABm6vnMMQ0znknqlImMjRp1Z4Lt+Xk7MEoaYBj0DaF
         O7Q2KdxqKuZi0OQFVZUsPVz59ZjIcKxaB4QeulhuRvUnbzRE4l+skAAUacxdEUB3bPrP
         fLHN0ZXq4LBy/20S9WCWbRtStGS/nM5v+vRPDksXoPRr9pHSEgGYXW9+jJUFLuMZZC/Q
         ivxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Um50ihNeDQB6+aszuU29p3PtU3YChYqBX24eKbUCnk4=;
        b=j2DjH+im2CymlFzJxt49U38+BQugyVbUrdaoZxdn/ltFSCJvq2p1X/FbiOjDcAmH8X
         YD9K9HUIEv8kHko8X7bHfig756ChuSXUv1lQSbbalJBhUAowcjk/OeTJbphsE0i56Gkt
         OJrrRR2vXWKsGziN344ZvPgChN29dsTt4/2+WrMnYOgYoZVl7wA+TFnnaoHBlbjgYGHN
         GTZ6SBuH+hroji3PGWFrd0QFNBOlDRucYE5S2HMwBApj/o6EtB7myx+j8bbcK+trc/bo
         C//Nf4TvVIiMzb5SDBF4iKkDw6NBknmUFRgzciURMzDDeyzdc3ZXNoFEzn1Ksu+aIE++
         q2+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pZim17LZ;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id bk18si44990pjb.3.2020.08.04.03.15.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 03:15:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id y206so9639154pfb.10
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 03:15:53 -0700 (PDT)
X-Received: by 2002:aa7:97a3:: with SMTP id d3mr19768182pfq.178.1596536152759;
 Tue, 04 Aug 2020 03:15:52 -0700 (PDT)
MIME-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com> <20200801070924.1786166-4-davidgow@google.com>
 <CABVgOSnpsnYw=0mAks4Xr2rGe07ER1041TKCCY1izeCfT8TcBQ@mail.gmail.com>
In-Reply-To: <CABVgOSnpsnYw=0mAks4Xr2rGe07ER1041TKCCY1izeCfT8TcBQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Aug 2020 12:15:41 +0200
Message-ID: <CAAeHK+y5KBuAfpeO90X0rxyZmPj4OQGUF=L-q3GAgQUTFNxdsQ@mail.gmail.com>
Subject: Re: [PATCH v10 3/5] KASAN: Port KASAN Tests to KUnit
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pZim17LZ;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
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

On Tue, Aug 4, 2020 at 12:59 AM David Gow <davidgow@google.com> wrote:
>
> On Sat, Aug 1, 2020 at 3:10 PM David Gow <davidgow@google.com> wrote:
> >
> > From: Patricia Alfonso <trishalfonso@google.com>
> >
> > Transfer all previous tests for KASAN to KUnit so they can be run
> > more easily. Using kunit_tool, developers can run these tests with their
> > other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> > report instead of needing to parse each KASAN report to test KASAN
> > functionalities. All KASAN reports are still printed to dmesg.
> >
> > Stack tests do not work properly when KASAN_STACK is enabled so
> > those tests use a check for "if IS_ENABLED(CONFIG_KASAN_STACK)" so they
> > only run if stack instrumentation is enabled. If KASAN_STACK is not
> > enabled, KUnit will print a statement to let the user know this test
> > was not run with KASAN_STACK enabled.
> >
> > copy_user_test and kasan_rcu_uaf cannot be run in KUnit so there is a
> > separate test file for those tests, which can be run as before as a
> > module.
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> > Signed-off-by: David Gow <davidgow@google.com>
> > Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
> > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > ---
> >  lib/Kconfig.kasan       |  22 +-
> >  lib/Makefile            |   7 +-
> >  lib/kasan_kunit.c       | 770 ++++++++++++++++++++++++++++++++
> >  lib/test_kasan.c        | 946 ----------------------------------------
> >  lib/test_kasan_module.c | 111 +++++
> >  5 files changed, 902 insertions(+), 954 deletions(-)
> >  create mode 100644 lib/kasan_kunit.c
> >  delete mode 100644 lib/test_kasan.c
> >  create mode 100644 lib/test_kasan_module.c
>
> Whoops -- this patch had a few nasty whitespace issues make it
> through. I'll send out a new version with those fixed.
>
> I'm pondering splitting it up to do the file rename
> (test_kasan.c->kasan_kunit.c) separately as well, as git's rename
> detection is not particularly happy with it.

Maybe also name it kunit_kasan.c? Probably in the future we'll have
kunit_kmsan.c, etc.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By5KBuAfpeO90X0rxyZmPj4OQGUF%3DL-q3GAgQUTFNxdsQ%40mail.gmail.com.
