Return-Path: <kasan-dev+bncBC6OLHHDVUOBBHNOST4QKGQEA4T6IRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 900F32350F9
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:17:49 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id s25sf3906114ljg.23
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:17:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596266269; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9CptdcDvsdVnwCL/3YGlvRRPqR25VAlGUl0q/1rDQO7PGX8t39RA8H5D40aXvItAE
         NKopKSI6/EpQAU832726X2eOjmDSssHAIpcf7BnmHt5WjpIHMVB+PyYODO56Om2kKwy/
         ZVKM2xzPTPV+EMvQCUGJkroIoFnDtxicCicZdU55Z/Xew1ypzELN7Wvdbkq4SmkmUdqb
         kKyZcWnCDy/9E3jhOngJtwEbvg2o2GQ0RtpEfWJUaOv368wj7vVwnaZTOzVFvcluKME6
         IFa1UeE5bTo2Er7FulS8jbjEgA8RHrU2CXCBiYrLbB99xd2MdxXTdwX6jDacYE4QAILz
         qRMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=H8P9XkI/GH2hVYIvA8UxjoyJ7IhfKNMAJuStAYZApP0=;
        b=pcmZjavp1v9NPXGDrvtLHSPqzKUo4DbAh2sZwbQ9Pl1ohJ0tmcZb1W3TWvg3wtVHCr
         5kpN6V7zsmq7SSrxndnFL6DUsPSh50prwX4YMac7UJ3VB23HCvKNNcYIHh7rRhu8tQ+u
         VbPijGHL8g9ouEYo05rnWhTVlGi9+BdsjfjOtQ/n2oF03GY6HBPSQOATczDOH9Rth15r
         xjgDUixwuqBOj1g609FJapFDZ824lKg5Wt9jItaIfgggjx/WFTVKcJ1BYDB5mOxZbzBv
         JMC9R5qLoOZr5Y5eziN7WyTuuUtuuD+IKsRcNKmBFdwGVSAl4kvFmXqXJdMjR/pvGsSU
         R9jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VO0K6rya;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H8P9XkI/GH2hVYIvA8UxjoyJ7IhfKNMAJuStAYZApP0=;
        b=O/kxdUvCgE8QaC9jJtZ3GacSaTq+V0PV+wCzXw+CHoB+iEs5OECSySzmZnsMUSCG6I
         kKsnDNYIFSqhvUTiP4TJJKDv0atddnJSclwPv5YsgaT3zsw/e3xmvRTe4vY0GmC+lz5B
         I6mBPHZPH7FzYR8h53fqSBu0QW9p6aQc9ethumQbqaAGaqfGkz9VHTPVCpwMr23n0Mar
         hs8JmrEC5L4/kS0U1WzGslVKbLdpMfCVOZxwM4V4LjReAYN+CgIQkwC0C629BOpy/eYa
         BGUi83pF38CK9MwBbdKZDsH+jF1FsRWfItZw5VS5F3v7DYcIsXSkVaSsKpiuKdaAs5EA
         jROw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H8P9XkI/GH2hVYIvA8UxjoyJ7IhfKNMAJuStAYZApP0=;
        b=IvyyiAZhDLnWxH5TnUGCywb23GGGFOGMTHJK0eP8yLqmwmccD6WJXfq0vxyuRGtCUw
         XWHLbEZJCihNN/Hk+ZQL58WFYZaGHauQfHI1xMuqkSgg3YGwQZgHfmZ41zqTqDP+C7c2
         IOiODhhFz246Xku0+U53jBSorKlS6PqL1F82D7jgWFk7aPLlZbf6IS1ULD95Fn8hcX6y
         jHNvxM3HY/LKkgboC/TopV9NHzLsEs1VijNBbKdly4ItmWWEYTKj7q3wv79DJmJg3ihc
         03EUAVv4n4Mt2pWZ0qk2nw3i02UyFF5E6btyJGkCKdla0W+5LKIh3FlkKZVBUeR8EXSD
         wpsA==
X-Gm-Message-State: AOAM5322//fDvCXWJa+lB4Wcj3TAFZPjEnP4mLX9nrl2HsACqRZAYAgE
	3jAhoAaMy/OUIO2cmFygdzE=
X-Google-Smtp-Source: ABdhPJyaFA2cBOr8rgGUfCxQXULVHe3m5ldWmajJ3vBFI7UXS6X4fnoJt4GZNe12PYRoev3RQbA7Uw==
X-Received: by 2002:a05:6512:556:: with SMTP id h22mr3750958lfl.200.1596266269069;
        Sat, 01 Aug 2020 00:17:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4845:: with SMTP id 5ls3498922lfy.2.gmail; Sat, 01 Aug
 2020 00:17:48 -0700 (PDT)
X-Received: by 2002:a19:814c:: with SMTP id c73mr3643330lfd.16.1596266268379;
        Sat, 01 Aug 2020 00:17:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596266268; cv=none;
        d=google.com; s=arc-20160816;
        b=HIJDrmCZc9SARN31SuCR8maR3JzIckNzZBi2dBn6TP18g5mFkWeF+ok26wAWfCHXk4
         eDepqnkwwoNSd/cWcWqMJUgp9Bi28udTAb4rt0NfDuMzd4f4QBr037wqtZ44j+lxnIyx
         ufmnkbgP0cxEN/6xSYG2fxCinr3z7IHOYuxy1O7aThU9jjvwO8doM7W/+Y9gE18CVnpZ
         pnABwZogeBTQ0H0aScBFI+NfvB7Yn7e2i/QtyXJTXIUhGP7YeIRWPJuNnjDqC5NjR5y8
         +IZCvJxLOVP+jVx4Qd9RrZRLgczxmMCiHz6WcxSijB6AFPcLAIW/3IGsuRnWan7C/JF9
         ZnXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9TWNF9js53PcdlvlEQGLSj775mBS94SUQ30AaksVxoQ=;
        b=rpElCy9+U+DPj2cxO4XJUdZv8bGlSZQnD+Vsv1z8sfDY37h7s9cOOziUSOnF8nbrwF
         SYFR9cCXWTbRnaFCY0ekX38VR5u5/6wmaQY46FI5GcKrDhLEym4yqPbbz1echCicKXaP
         axcYpnZPYPISIsM9gbaqVwcHrit1YWffU4gHTW78y/kkLxA4UfidrneTzy1k+a2ZdXa0
         KBXvhgLeWzhCTN0doqTZaMS9sJB70Uj6PoresoF6mJpG3sHZXP7iBggiGx31+Rtdy8PP
         adHWsTa8s0NxqHeuRojCGCHwXrMLKRdYO3fTlOppf3cZHDxtwhKyUBslbWVgviu1j4cZ
         71DA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VO0K6rya;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id z26si738288lfe.5.2020.08.01.00.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:17:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id f18so29794217wrs.0
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:17:48 -0700 (PDT)
X-Received: by 2002:a5d:4e8c:: with SMTP id e12mr6436942wru.19.1596266267633;
 Sat, 01 Aug 2020 00:17:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com> <CAAeHK+z0wJ-3+dXey9o3zysy9fPOqk-YdFFtVOB5==WcG3B8+Q@mail.gmail.com>
In-Reply-To: <CAAeHK+z0wJ-3+dXey9o3zysy9fPOqk-YdFFtVOB5==WcG3B8+Q@mail.gmail.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 1 Aug 2020 15:17:36 +0800
Message-ID: <CABVgOSnFanyCtBFaFAdrArr+hkXCdNu5vCNmciLP0ftQRgAsXQ@mail.gmail.com>
Subject: Re: [PATCH v9 0/5] KASAN-KUnit Integration
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	Shuah Khan <shuah@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VO0K6rya;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::441
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

On Fri, Jul 31, 2020 at 9:25 PM 'Andrey Konovalov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Fri, Jul 31, 2020 at 6:43 AM David Gow <davidgow@google.com> wrote:
> >
> > This patchset contains everything needed to integrate KASAN and KUnit.
> >
> > KUnit will be able to:
> > (1) Fail tests when an unexpected KASAN error occurs
> > (2) Pass tests when an expected KASAN error occurs
> >
> > Convert KASAN tests to KUnit with the exception of copy_user_test
> > because KUnit is unable to test those.
> >
> > Add documentation on how to run the KASAN tests with KUnit and what to
> > expect when running these tests.
> >
> > This patchset depends on:
> > - "kunit: extend kunit resources API" [1]
> >  - This is already present in the kselftest/kunit branch
> >
> > I'd _really_ like to get this into 5.9 if possible: we also have some
> > other changes which depend on some things here.
>
> Hi David,
>
> You'll need to rebase this on top of the mm tree, which currently
> contains Walter's patch titled "kasan: fix KASAN unit tests for
> tag-based KASAN".
>
> There's also another patch that touches KASAN tests in the series I've
> just mailed titled "kasan: support stack instrumentation for tag-based
> mode".
>
> Thanks!
>

I've rebased this on top of a linux-next (with the pending KUnit
patches from kselftest/kunit and the "kasan: support stack
instrumentation for tag-based mode" patchset applied):
https://lore.kernel.org/linux-kselftest/20200801070924.1786166-1-davidgow@google.com/T/#u

Note that the RCU test doesn't seem to be compatible with KUnit's
KASAN integration at present: I'm no expert on RCU, but it looks like
the current test context might not be propagated to the callback, so
expecting the failure doesn't work. Given that KUnit also doesn't look
for the aux stacks (just that a failure occurred), it seemed best to
avoid trying to port that one to KUnit, so I've left it in the
test_kasan_module.c file. It may be possible to port it at a later
date.

Note that I don't have an arm64 setup here, so I haven't actually
tested the tag-based KASAN stuff yet.

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnFanyCtBFaFAdrArr%2BhkXCdNu5vCNmciLP0ftQRgAsXQ%40mail.gmail.com.
