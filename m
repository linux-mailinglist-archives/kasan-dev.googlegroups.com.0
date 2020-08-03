Return-Path: <kasan-dev+bncBC6OLHHDVUOBBP5NUL4QKGQEQBIEN7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E9FD023B08E
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 00:59:11 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 136sf11091654lfa.19
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Aug 2020 15:59:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596495551; cv=pass;
        d=google.com; s=arc-20160816;
        b=mSnKpH0LGnK3AlYIm8sO3291LZMLgmVVjz5MELcCQ4Zu0c9mXXLXaoSfVvI8OCOLj3
         r8YS9+ceozmiUAqU0z56fd3SUsaRsDd6z+IesoBhb/LsjAK12rEAsCG0MS5nCTmSqHu+
         xX1u11t1vUn3YrLmkhCYrIj96fRi8aftAzWeD2hyvDLGilBwL6tcAyFpenWKxHZ2vxN3
         gsq9In5zjFDSVKmnZQAJVoOth2mztbpD+Ih1y3zpQU9NPVEiQ/PtKtrAi1l0opbF/vxj
         VTmLCcNxAZrzUBbvGPypR7/HZlzV781WZDN8yX3Oi0QbwnB8x3DJunVnFqwkHGQTLr8d
         WnkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=x6SydOfO+fju/w/ZLsp31lOQGic2as3FZcFmRIBWkyQ=;
        b=rG0wydBeP1/rOelvhzNG9jA68iWZ1313qDeEGG0/SU1pdgU9cct3nfl40c9JpAmrBD
         DFIYVJIqXPaU/TANykUiRHsQn3hr2qYS7wQUmdhowg2+gs9jk2qUBsvNJ+CCBf/IVEKD
         Stm13BL0LdM7mTP4jwdypu18l1YhbYilYfy5/D6NE/vGflyJt5TRwMxT5oa/pXBpON/q
         cO6U8MPNuBsMjsKAkrOYE8E1e8p+f6q+ri6SxJHXgqKFdhz4jiCAZvu2SAOdC5TbV5dO
         iGDLF8WEcIIlWnwt5VID+BCDo5BATrpjSpwdyrWFmRHbux5XLAutN8wQsc+9L8Z3QQp3
         RP0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q7y3ZvBV;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x6SydOfO+fju/w/ZLsp31lOQGic2as3FZcFmRIBWkyQ=;
        b=Gpet0aLBYMCcUlKUURL5AbEsPhzijPdmb/QrXvoxiWdcXmygWZ/4/QbvYxBCFCH9nN
         D791qu/j1Cv0emIRYay1xqytY2+nh1GKzGX0TcYrg9tIwLEByXIHPh1YBrjtHBfjwMmT
         RiqoITNzKu8Xbx/otz+5O9oArSWwELBvxf0bifYSALBXCRrJdDanrr+xQc8uC4lxd/z1
         7aQvGw0sQDhD0P4Te9R652mZpvE4orXRVMwJ3pKbQxaxPTws6IPrzWNrkuyJrxLgY2Ll
         tK4yE4Ij5uHy2iBeyfjRkC0KMfd3rBw55eurIXM+D3qk70PwMmU7DtbqZ4rzgoXCVybJ
         qR9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x6SydOfO+fju/w/ZLsp31lOQGic2as3FZcFmRIBWkyQ=;
        b=rMG9P8UOW53GQmujCEqMXmCs4uprd7SdBFJ1wZDPJ+eI8sQ9FiO4BcwHHu8KKcBFK8
         PbeDmCQtdlKvdBCwjHVh50nAiUu9p/OzZL8qBu83MCGs1+4H2xhts0SRK4vixiqUQUDf
         /Sk41h4fPjslVAfKv2tQIOKChNM+PLQMX6q7fvwABRIwcufQlq6n/fyEl9yXpSnAzLe2
         R1echmrO3QlpvD7iB8SsrkPONUVbqRH+QQ4h2yDX3hkR7Hpp3on+ZvN+jcm9Hzpz8TNo
         GX0Dm4tG34jL39oohKnOVzwcWF/ByL1oaZP0jLkoDtJxtPzLUzYLs81TLu5/+UOm32jw
         w4EQ==
X-Gm-Message-State: AOAM530NXJHHdZ28Z7XQDdZHEN6i5gA/TUa50zgwH7wz2eXM7oeC8Z2X
	F1yVcN7zhWEgr+j6fy8qH3s=
X-Google-Smtp-Source: ABdhPJxJIlU/zW325JBgvhUtgS9vNOOTvtMZcVfL9nX3Fx7U1GoQZoN+gd5TNhc2xZkYn2ddOoXsZA==
X-Received: by 2002:a05:6512:10cc:: with SMTP id k12mr9569456lfg.20.1596495551461;
        Mon, 03 Aug 2020 15:59:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8994:: with SMTP id c20ls207941lji.0.gmail; Mon, 03 Aug
 2020 15:59:10 -0700 (PDT)
X-Received: by 2002:a2e:9d81:: with SMTP id c1mr8979192ljj.198.1596495550763;
        Mon, 03 Aug 2020 15:59:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596495550; cv=none;
        d=google.com; s=arc-20160816;
        b=bsde1YmnIW5QWAwzLlcUie9JTfYAjrvGpMQdOvxn66tYHcGto/7up3Cv66WvuJ60Pf
         ApsnKyDmDGUCkTo+crHc9vIRyqjfT3H/EvvvCTOOvj4sjxnwTwS9nYXXcb1B3Sb+9k1z
         FpEAFO3X0iF1BVtAAXuTyZGLSwSA3OI4pNdfzClOryKvKeFig1s7cocN6HZd7v4tjCaP
         JiTiHw6XPMfX4sCV0qqA38zkbEYAavi6uE+vwmcKJ6pLWxN3LAgs5C4qXIgbvIrYxAbu
         5+7hk054JX21JYkBC/Zgx19RZctXhrOasb7oX1y0oUsMhV620k2byf80K64l2lBx2ND6
         Obeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZVMTuQZIH47WM1WuikLBTLZ1LTQtr65n2lbis/GQnro=;
        b=NJNtXY5TaLxa9PIoQdU9vvG87QZ81xBwJMw9TZZrEmqP7/9fe7OHfdEQvqR0arhE1g
         sgyytGA7r8TcsZSKSJ5JLNKthKWrOi+tq05okv2GBjcSV6cKxRl/wUBT8ISvg2apC8TU
         PyNN0IyJ+4TBIj/NhxFfoMGWPscg7g/6MDzmaoB+N580vgr1ue/XLRIGFK7UqO1Rc85U
         /j2aQtJQ7IwuaC7i1feNhjV2krPMMUfhK1xqNI1I42OIBp6IkwphKd4AcOSXn8DvIH/x
         X+aWihYW1NJQmqvHHK9RgAHptIvBSEdC3ty4Z4eb4DDilzLIZXIz5CZjVDbdUAyMwMF1
         EKOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Q7y3ZvBV;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id c27si1063651ljn.3.2020.08.03.15.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 03 Aug 2020 15:59:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id a5so25677695wrm.6
        for <kasan-dev@googlegroups.com>; Mon, 03 Aug 2020 15:59:10 -0700 (PDT)
X-Received: by 2002:adf:f289:: with SMTP id k9mr17129637wro.203.1596495550006;
 Mon, 03 Aug 2020 15:59:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com> <20200801070924.1786166-4-davidgow@google.com>
In-Reply-To: <20200801070924.1786166-4-davidgow@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 Aug 2020 06:58:58 +0800
Message-ID: <CABVgOSnpsnYw=0mAks4Xr2rGe07ER1041TKCCY1izeCfT8TcBQ@mail.gmail.com>
Subject: Re: [PATCH v10 3/5] KASAN: Port KASAN Tests to KUnit
To: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Shuah Khan <shuah@kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Q7y3ZvBV;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::442
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Sat, Aug 1, 2020 at 3:10 PM David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Transfer all previous tests for KASAN to KUnit so they can be run
> more easily. Using kunit_tool, developers can run these tests with their
> other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> report instead of needing to parse each KASAN report to test KASAN
> functionalities. All KASAN reports are still printed to dmesg.
>
> Stack tests do not work properly when KASAN_STACK is enabled so
> those tests use a check for "if IS_ENABLED(CONFIG_KASAN_STACK)" so they
> only run if stack instrumentation is enabled. If KASAN_STACK is not
> enabled, KUnit will print a statement to let the user know this test
> was not run with KASAN_STACK enabled.
>
> copy_user_test and kasan_rcu_uaf cannot be run in KUnit so there is a
> separate test file for those tests, which can be run as before as a
> module.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Signed-off-by: David Gow <davidgow@google.com>
> Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  lib/Kconfig.kasan       |  22 +-
>  lib/Makefile            |   7 +-
>  lib/kasan_kunit.c       | 770 ++++++++++++++++++++++++++++++++
>  lib/test_kasan.c        | 946 ----------------------------------------
>  lib/test_kasan_module.c | 111 +++++
>  5 files changed, 902 insertions(+), 954 deletions(-)
>  create mode 100644 lib/kasan_kunit.c
>  delete mode 100644 lib/test_kasan.c
>  create mode 100644 lib/test_kasan_module.c

Whoops -- this patch had a few nasty whitespace issues make it
through. I'll send out a new version with those fixed.

I'm pondering splitting it up to do the file rename
(test_kasan.c->kasan_kunit.c) separately as well, as git's rename
detection is not particularly happy with it.

Sorry,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnpsnYw%3D0mAks4Xr2rGe07ER1041TKCCY1izeCfT8TcBQ%40mail.gmail.com.
