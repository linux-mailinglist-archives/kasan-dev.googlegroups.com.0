Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOU2YCUQMGQEU2Q655Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D01F7CE330
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 18:52:12 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-1ea01dcf2ccsf6096386fac.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 09:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697647931; cv=pass;
        d=google.com; s=arc-20160816;
        b=WkLka3GvXYsFM7qgBFFs22G9gzfRkY1x0pvaCFY7QHj3oE3U7Kd7LE9LHc6pIbZfhe
         dTw2/bqgNRfHRyAn/d/9F4S8avyZcZDmELPi4E6Qb6nFivpfzeQwecTa2knXetg79vVp
         ccaPydnuwBzmSRMo21Vwdnypi0l5OM78PYDJW8GdOnvsGPtajXCDUWWARW8MzRndOaZO
         qoWib6ufMFXyTA7iRmqSMqs/ShpF68qoSLuezFnBJsagWAM7onY9/SvBYgNa+/IeotrG
         h9+/+eIgJxKPbYktbFC1NSJ3/fPfYYrwGVE9Na7WbcJRLeIop8/cPPffakfnmrgi2lHI
         GovQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eZoopOqakGyflSFQxWJpshL3cMlf5NHpy7ZJmHdOrt0=;
        fh=iavFEGiaH83Lc5aDzeABOQpyXUB7IiGge6GRfnQJa9w=;
        b=y4Hs3M6Ja4MZQwVxKC6aEsxfNW5rdspR7sAfXghg2thY3D2Qd27ZkxSjvc6ITfoMSy
         arLdOkZnsjgfGCcWF/0sBWDKgmHxGT4SvOunwpOXsdgxH5DvdntFkLk0J8dcW5rB5tr9
         gJZBDNA6NFW7RpMtveQL1W+jp8OKC688/0+Gkzk3YjJL7t0w91m9JhVflYYTqE3Z2rK/
         r79x/TP7dglHIFDaW2daT18REEylsV1UAxF68mI3YvvDZjCyDKq+pwzJ3N6kNPFtLyw6
         B5nTzjrUbIn54aoR1HltARasqTJBBk1HEVXa31Il1m2PMcZXXkG3OfFy8ugcsDpucavx
         5v6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eAA7FbGu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697647931; x=1698252731; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eZoopOqakGyflSFQxWJpshL3cMlf5NHpy7ZJmHdOrt0=;
        b=b2nORwhcVeee5KOh7ssK2k4dc19rMvlS1HsWrxuAGOf1tJOx24nj160TphIcSAPKqG
         7vkiLL25qCYHXlNhtIP47+uLw7gnKg/RWOFFNy1XCqHlH07A1bPyDSG1cR5jKJ6q1xDO
         aVBQbQlMpyR/savoL6g09AMVyyQiEJq1o/+kYQfNPwXneZFY9SEKNBtJaybm5xnEe1Kg
         hwN/zXo4B2IfB8kkJH7bW1h47TXrAfHNo2Gxq0ZAgpkltV1LftEaHkdaO9sVeFImb28F
         gPx8m6YL/AFoxFLfvBMRixSAJPrmX7HH1GCYpTlLhQ/EU24Y5HmI+W+T5GzVP9/WvcRr
         SO1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697647931; x=1698252731;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eZoopOqakGyflSFQxWJpshL3cMlf5NHpy7ZJmHdOrt0=;
        b=Zca0F1Jcr6eKI8/Nv6jLLfKCHA0Snf2CFQIsWSZ6F7oviE524AP/rlEhJ4Q2xlgzIh
         5KljktsCRs6bLOPf8bGQvbNlvQFY8gNIKPbcYQW3uuMYCFsHdXo9j3waa9iZfS62v2gX
         cPTYRH9hSbnaxvF8SHWfb/sp5IYA5t2HRMp8ru/3yz0SJGpdq/dYej6PJAlWtDfVZ22O
         umuPteYTqerfCZKHMGstfAnn6vxWv/R812rnqeOU98bYxXvKFf6SQ434v/KKQ9lNPUay
         Zx9f52LYb1hdvrMlCMnmQPnh8N3DnGlJqBuobDfzAkh9R/trsOvW4m1WVL/SIZXTR6Lh
         x+sw==
X-Gm-Message-State: AOJu0YznY/vgiOHa6kU4YFKTFON+dWp4Yf33Le7M4PZUuNpQE/04ry0u
	L7NHY9Fc1sj1reU1MTaetNY=
X-Google-Smtp-Source: AGHT+IG7+kYqBVVFTLCwbH4PBqxKyc8poAOhfwolNQxF4AipeKQCqI5pr8vqqvz5+LtGls11yCCgBg==
X-Received: by 2002:a05:6870:b521:b0:1e9:6a4e:6b56 with SMTP id v33-20020a056870b52100b001e96a4e6b56mr3176928oap.3.1697647930844;
        Wed, 18 Oct 2023 09:52:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4307:b0:1d1:3283:6299 with SMTP id
 lu7-20020a056871430700b001d132836299ls2583155oab.1.-pod-prod-00-us; Wed, 18
 Oct 2023 09:52:10 -0700 (PDT)
X-Received: by 2002:a05:6870:44ca:b0:1c8:c9ca:7092 with SMTP id t10-20020a05687044ca00b001c8c9ca7092mr3226789oai.11.1697647929901;
        Wed, 18 Oct 2023 09:52:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697647929; cv=none;
        d=google.com; s=arc-20160816;
        b=axxUXw15qBRMgh/UwTX3pK6tms9S3u/jnIIy9GtOmW4v/hYp8dokJDch04D5wS8Rb0
         T7FTJqQ93T9CCMz1KCkxbq0oqxYsCmUO9q8sTlEVm0NVUeCLfqWJU4gCNNgNGEFj/K44
         Zbaa004WGwYjbZ9VlsigsiDX5tQj125vZO4gSqvoMMYtZcKt0d4s8Cz/O0kE8KXGHbbp
         sDG6TU+3XjcBrkp1fTWUUpLc9O2K7TVPN6F4199AOUndm3ix4ehFOyqeBrR+hCptbj+Z
         5bFq8PPZDSxC/NLMR6leoXTIFgg1awhGWgKJEGzD5Ph0BqsFqcMJu9LfdULOnhnqbOuY
         SOMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/pMxszsWHDpKedI/5pITYv9bsseXhLI86JME0Jv0Euc=;
        fh=iavFEGiaH83Lc5aDzeABOQpyXUB7IiGge6GRfnQJa9w=;
        b=OW0JGjrAjX71bxNfsFqjlDxq7kZuwCEUt7W842vYHiz88LL9pDpCcFUCV+9QwIfJJb
         SkhenlW/G13DhTSRMjCgMDCeWGAoHGr6VBdcI3yE/vLARcYjt6zW1knKnwwF6U5Fsd/7
         coKzBny9oxKf47rnaCZ0cj7DmB3LkgVM7m7aSKiAo/W+AKGS9PMkrmd3CzEI/QRNIdhK
         NXT0efMqfr7OwAktqkKh+47BLmxFcOchBYcIH0BJ0JK5tF8cDlV2nd9hI4+dp+m8mnKn
         TV/hyZtXT7UVoncTKsNXUNEzKtd0Qwde0NsiCqwnh8NrBC6OKUB52zFO+gq0CoGR3DLg
         ZajQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eAA7FbGu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe29.google.com (mail-vs1-xe29.google.com. [2607:f8b0:4864:20::e29])
        by gmr-mx.google.com with ESMTPS id na25-20020a0568706c1900b001e9dab71a2dsi474626oab.4.2023.10.18.09.52.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Oct 2023 09:52:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as permitted sender) client-ip=2607:f8b0:4864:20::e29;
Received: by mail-vs1-xe29.google.com with SMTP id ada2fe7eead31-457e36dcab6so2392861137.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Oct 2023 09:52:09 -0700 (PDT)
X-Received: by 2002:a67:e156:0:b0:452:61eb:dc26 with SMTP id
 o22-20020a67e156000000b0045261ebdc26mr3477209vsl.16.1697647929398; Wed, 18
 Oct 2023 09:52:09 -0700 (PDT)
MIME-Version: 1.0
References: <20231018153147.167393-1-hamza.mahfooz@amd.com>
 <CANpmjNPZ0Eii3ZTrVqEL2Ez0Jv23y-emLBCLSZ==xmH--4E65g@mail.gmail.com> <c7a80dc5-d18f-4a7d-915b-1803cc3e33ca@amd.com>
In-Reply-To: <c7a80dc5-d18f-4a7d-915b-1803cc3e33ca@amd.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Oct 2023 18:51:31 +0200
Message-ID: <CANpmjNN7yvEjvTDHzzEqvN2iKvxjvOjpsz_ugSjwh4VBKDNH6g@mail.gmail.com>
Subject: Re: [PATCH] lib: Kconfig: disable dynamic sanitizers for test builds
To: Hamza Mahfooz <hamza.mahfooz@amd.com>
Cc: linux-kernel@vger.kernel.org, Rodrigo Siqueira <rodrigo.siqueira@amd.com>, 
	Harry Wentland <harry.wentland@amd.com>, Alex Deucher <alexander.deucher@amd.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, Tom Rix <trix@redhat.com>, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, Arnd Bergmann <arnd@arndb.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eAA7FbGu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e29 as
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

On Wed, 18 Oct 2023 at 18:43, Hamza Mahfooz <hamza.mahfooz@amd.com> wrote:
>
> On 10/18/23 12:22, Marco Elver wrote:
> > On Wed, 18 Oct 2023 at 17:32, 'Hamza Mahfooz' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> >>
> >> kasan, kcsan and kmsan all have the tendency to blow up the stack
> >> and there isn't a lot of value in having them enabled for test builds,
> >> since they are intended to be useful for runtime debugging. So, disable
> >> them for test builds.
> >>
> >> Signed-off-by: Hamza Mahfooz <hamza.mahfooz@amd.com>
> >> ---
> >>   lib/Kconfig.kasan | 1 +
> >>   lib/Kconfig.kcsan | 1 +
> >>   lib/Kconfig.kmsan | 1 +
> >>   3 files changed, 3 insertions(+)
> >
> > Do you have links to discussions that motivate this change? This has
> > been discussed in the past. One recommendation is to adjust the
>
> Sure, you can checkout:
> https://lore.kernel.org/amd-gfx/CADnq5_OyO9CHqahFvdnx7-8s9654udgdfhUntyxfjae+iHey0Q@mail.gmail.com/T/#m5d227dc1ef07b1f4953312287dce4568666c5e09

I would add this as a Link context to the patch.

> > build/test scripts to exclude some combination of configs if they are
> > causing issues. Or we increase CONFIG_FRAME_WARN if one of them is
> > enabled (KMSAN sets it to 0, 32-bit KASAN increases it a bit).
> >
> > That being said, we're aware of KASAN having had more issues and there
> > are some suboptions that have been disabled because of that (like
> > KASAN_STACK). I'm not sure if Clang's KASAN instrumentation has had
> > some recent improvements (we did investigate it, but I can't recall
> > what the outcome was [1]) - maybe try a more recent compiler? However,
> > KCSAN and KMSAN shouldn't have any issues (if KMSAN is enabled,
>
> This patch was initially motivated by KCSAN (i.e. I am able to get it to
> blow up the stack with a minimal .config). I don't mind dropping the
> other ones since I only included them because Nathan implied that they
> could cause similar issues.

!COMPILE_TEST is not the solution. Clearly from the link you provided
build testing is helpful in catching early issues, so that these tools
remain usable for everyone. But we know they use a little more stack,
and the warnings need to be adjusted accordingly.

My suggestion is to just increase FRAME_WARN for KCSAN, or set it to 0
(like for KMSAN). My guess is that first trying to increase it is the
safer option.

> > FRAME_WARN is 0). And having build tests with them enabled isn't
> > useless at all: we're making sure that these tools (even though only
> > for debugging), still work. We _want_ them to work during random build
> > testing!
> >
> > Please share the concrete problem you're having, because this change
> > will make things worse for everyone in the long run.
> >
> > [1] https://github.com/llvm/llvm-project/issues/38157
> >
> >> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> >> index fdca89c05745..fbd85c4872c0 100644
> >> --- a/lib/Kconfig.kasan
> >> +++ b/lib/Kconfig.kasan
> >> @@ -38,6 +38,7 @@ menuconfig KASAN
> >>                      CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
> >>                     HAVE_ARCH_KASAN_HW_TAGS
> >>          depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
> >> +       depends on !COMPILE_TEST
> >>          select STACKDEPOT_ALWAYS_INIT
> >>          help
> >>            Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
> >
> > This also disables KASAN_HW_TAGS, which is actually enabled in
> > production kernels and does not use any compiler instrumentation.
> >
> >> diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> >> index 609ddfc73de5..7bcefdbfb46f 100644
> >> --- a/lib/Kconfig.kcsan
> >> +++ b/lib/Kconfig.kcsan
> >> @@ -14,6 +14,7 @@ menuconfig KCSAN
> >>          bool "KCSAN: dynamic data race detector"
> >>          depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
> >>          depends on DEBUG_KERNEL && !KASAN
> >> +       depends on !COMPILE_TEST
> >>          select CONSTRUCTORS
> >>          select STACKTRACE
> >>          help
> >> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> >> index ef2c8f256c57..eb05c885d3fd 100644
> >> --- a/lib/Kconfig.kmsan
> >> +++ b/lib/Kconfig.kmsan
> >> @@ -13,6 +13,7 @@ config KMSAN
> >>          depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> >>          depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> >>          depends on !PREEMPT_RT
> >> +       depends on !COMPILE_TEST
> >
> > KMSAN already selects FRAME_WARN of 0 and should not cause you any
> > issues during build testing.
> >
> > Nack.
> --
> Hamza
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN7yvEjvTDHzzEqvN2iKvxjvOjpsz_ugSjwh4VBKDNH6g%40mail.gmail.com.
