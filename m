Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6V2U36AKGQEIMVM24A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E7006290625
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 15:17:47 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id j21sf1529415iog.8
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 06:17:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602854266; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZC4000iebkdOHQQxhrSmClDBI9N0UoJeQHei4RzR3JeDwzeDIg2glaOE8ovdRMWImw
         PhnYY5iQooRFYWHueMEazSVDGgRyu/TD+uFu7JKW1DUGJB1uI5EHugIAQeIFv46ARymt
         5KWXMLl8pcnBJASqmdwmVrQfyp32khKM11e6XbaumtWqLxEo0BwXHJLBcRs+18j6BXyW
         hghQFKoWCGdjhigUMyWLLvVB8Y4XzAXMBmXBYMgfdtcIIw/UFe1+MBEXS/08d8F/FJin
         jJLvInToUeB4qKK2nimHbrtKleLeLGNZ8uNgeJTDqxDOgQA5s3RVpKzeoJFHBWj9yg2R
         ucGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qJb5RTI+WlONXWYg6i6kT5q1n6zafWOTuRdQGJ3gskc=;
        b=WSh/4am/CxZT0ZhNPKFcCr8cbbaFf6k29Ue4JJcymzoYREwawcrmVJgJ2b7/rTGZyd
         mAM1yY03bmCv23aEwhm/ZB7rKXYGo1HR3AlcIjnwSgl+aCtktaxXQ1W59YVDr4l1VZgA
         74Yp98uGXRMGLZaSh+QmQSqwcQBmfZhx/xbievuS6ozHlzxKGJOjQ8zvMWz3ZAXv1zzZ
         tvswqrtoZ3wetLlqdLAky2c2ugtBb5g7t8bsQr9TQaoSmstZfEzg8QYWJbncmh4jUvZF
         YGOHuGglhlkPm5G14EHnTFZ47pnEyY6apb8FGw7b3FAuUyhWRpJRCwHs/P/P3r/pNeuC
         ADiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GxBuew5M;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJb5RTI+WlONXWYg6i6kT5q1n6zafWOTuRdQGJ3gskc=;
        b=ZmgHFribQcTIcwK0X9A7tgAkXc1F7Zkosf7Gu60mNXtE6+ng6bE3fLrFByi63hSMt6
         He8pCy/FEPxUuwCFkZTagkeg+SmC/no7uSrVO+5rnZmVYqhkJIhocaJAPLmHw1RwuFb4
         kT4KMYC6jzBSlQCj4+MskD6srewAqPoeOlkdFvPjT2bvdZM/VQ9YQjRVdmIjdOXXlSaI
         HF/ie/quk7scSW7Mid8c6D0olyVdA8jmVNtNbhuq0yX7KwfD/+TS4sk8pnRJPqHWc3jb
         3CUe8V5bCuUyLkbOIVYtFJ62w40Ym85XQYzA9TNm8M8ajJCAqQJ9Cv44bulgfSa0wRF7
         hRuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qJb5RTI+WlONXWYg6i6kT5q1n6zafWOTuRdQGJ3gskc=;
        b=XZRH9y+EWN1Q2rNhRAzL27nNKvbNC9zKADpEtO+4A28bQFTxWeF8cq/0Jb76NeTDi9
         R0hfAhzBugRjTZwoTJRAnWE2BYiWixlLdD4BNMDG0RUEHkVieVOk0rZJkI/+U5CX1kiF
         /1QpdbvwIi+FauN/UDewjlMTwJXMV+c0GAU00MB9E+k0dsu90WmAeFbF91yxp26+mu+l
         dR+73L+61eRCpB3bTqQafgWTcrCX+1CU8SYHGbg3UbvPeLKl0DdlbEHfpUM3IR8gz6CA
         4T7/vBDWBcCs6cih8wiHd5Yf+stg9ouViYIltbhfoiTXyVtI7R8QX6QrUck23OEyLqCn
         R86A==
X-Gm-Message-State: AOAM530XXN3MLIp/MM/WYv65kJIM40IlE3T8yw5Jnd3t8UxygnQB4E+J
	1R2h2qYQwxW0pKvLOZITo1g=
X-Google-Smtp-Source: ABdhPJy8AOEPbL++V8SsFepa59Vbkh4iGSABnzf2QbSqYfVQow4fWDA4+LX7TLhRONbXuPHyUnQQVQ==
X-Received: by 2002:a05:6602:1352:: with SMTP id i18mr2374551iov.148.1602854266603;
        Fri, 16 Oct 2020 06:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:890a:: with SMTP id k10ls320673ioj.4.gmail; Fri, 16 Oct
 2020 06:17:46 -0700 (PDT)
X-Received: by 2002:a6b:4e16:: with SMTP id c22mr2395357iob.26.1602854266198;
        Fri, 16 Oct 2020 06:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602854266; cv=none;
        d=google.com; s=arc-20160816;
        b=ETwQcO/QEdnl6cuMc0M639JiCgqFZRyg+okbJqS4OinR6rW+62uiV7XET44n1+Dx1+
         wLQSqyr9lFSw877qO7ZWxN9mGFcWMQvTAlrxc1jVt/xdwfMHb4VQdL9xqLFC6cL0h8NP
         b2xMHh9gAl1t8HmtS7EBf+itvsfyoCEGaq2xLMwRBAZrxLWBSopcnuqkBQgPewlYwqwi
         D9mBuL+q7x/4s3DCXg7ZAmTy+tYQxldWMmuWVRSAzmhskTqtvot78XjBHzWrctWwP5xI
         tD29w9sFlhHvi/M66BTGSvN2zdf067yCc57yWdDioEIWydCqnESflq/4FooAIbKLytZa
         2Sng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QL3/zaLDIDJL7ythZO9+VfLF2/gKs2of9IcU9332u94=;
        b=eaLYpo1Nqj6zqCaVrCGVzlgIZw3y/NJhJcvQlMhkzuNgDEa7YCFcz1okYSdQ06fMc3
         eU1aKefB17MBNW/FJH2+3SSj27s7EFTD2EVy0pQdp3bnL9nDcA7zFnwiyLrODnKYl5RJ
         zNS2vFSSJ/DaTAR+vPXAbxeZT5X99pko0mu3VOkqZ+JGDeJTr3TS2Z4QzDBkTpzCRa36
         zlVDNLizJgL+o18TOcA7ILWc4RVDOfdXVKXHItO28+Cr7pAVqcFImQxMtff7UBFIVEWp
         TASJbRN8hwHfqtcUE/ubUuoqd92bDeGvjsA3OPqIUSY0EhFwPh8tTq3NaL/BWEOsPztd
         gJ3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GxBuew5M;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id i8si124629ioo.0.2020.10.16.06.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 06:17:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id g29so1448242pgl.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 06:17:46 -0700 (PDT)
X-Received: by 2002:a63:5d07:: with SMTP id r7mr3134194pgb.440.1602854265382;
 Fri, 16 Oct 2020 06:17:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com> <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
In-Reply-To: <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 15:17:34 +0200
Message-ID: <CAAeHK+zOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF+LBg@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GxBuew5M;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Thu, Oct 15, 2020 at 4:41 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
> > This patchset is not complete (see particular TODOs in the last patch),
> > and I haven't performed any benchmarking yet, but I would like to start the
> > discussion now and hear people's opinions regarding the questions mentioned
> > below.
> >
> > === Overview
> >
> > This patchset adopts the existing hardware tag-based KASAN mode [1] for
> > use in production as a memory corruption mitigation. Hardware tag-based
> > KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
> > and pointer tagging. Please see [3] and [4] for detailed analysis of how
> > MTE helps to fight memory safety problems.
> >
> > The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
> > boot time switch, that allows to choose between a debugging mode, that
> > includes all KASAN features as they are, and a production mode, that only
> > includes the essentials like tag checking.
> >
> > It is essential that switching between these modes doesn't require
> > rebuilding the kernel with different configs, as this is required by the
> > Android GKI initiative [5].
> >
> > The last patch of this series adds a new boot time parameter called
> > kasan_mode, which can have the following values:
> >
> > - "kasan_mode=on" - only production features
> > - "kasan_mode=debug" - all debug features
> > - "kasan_mode=off" - no checks at all (not implemented yet)
> >
> > Currently outlined differences between "on" and "debug":
> >
> > - "on" doesn't keep track of alloc/free stacks, and therefore doesn't
> >   require the additional memory to store those
> > - "on" uses asyncronous tag checking (not implemented yet)
> >
> > === Questions
> >
> > The intention with this kind of a high level switch is to hide the
> > implementation details. Arguably, we could add multiple switches that allow
> > to separately control each KASAN or MTE feature, but I'm not sure there's
> > much value in that.
> >
> > Does this make sense? Any preference regarding the name of the parameter
> > and its values?
>
> KASAN itself used to be a debugging tool only. So introducing an "on"
> mode which no longer follows this convention may be confusing.

Yeah, perhaps "on" is not the best name here.

> Instead, maybe the following might be less confusing:
>
> "full" - current "debug", normal KASAN, all debugging help available.
> "opt" - current "on", optimized mode for production.

How about "prod" here?

> "on" - automatic selection => chooses "full" if CONFIG_DEBUG_KERNEL,
> "opt" otherwise.
> "off" - as before.

It actually makes sense to depend on CONFIG_DEBUG_KERNEL, I like this idea.

>
> Also, if there is no other kernel boot parameter named "kasan" yet,
> maybe it could just be "kasan=..." ?

Sounds good to me too.

> > What should be the default when the parameter is not specified? I would
> > argue that it should be "debug" (for hardware that supports MTE, otherwise
> > "off"), as it's the implied default for all other KASAN modes.
>
> Perhaps we could make this dependent on CONFIG_DEBUG_KERNEL as above.
> I do not think that having the full/debug KASAN enabled on production
> kernels adds any value because for it to be useful requires somebody
> to actually look at the stacktraces; I think that choice should be
> made explicitly if it's a production kernel. My guess is that we'll
> save explaining performance differences and resulting headaches for
> ourselves and others that way.

Ack.

> > Should we somehow control whether to panic the kernel on a tag fault?
> > Another boot time parameter perhaps?
>
> It already respects panic_on_warn, correct?

Yes, but Android is unlikely to enable panic_on_warn as they have
warnings happening all over. AFAIR Pixel 3/4 kernels actually have a
custom patch that enables kernel panic for KASAN crashes specifically
(even though they don't obviously use KASAN in production), and I
think it's better to provide a similar facility upstream. Maybe call
it panic_on_kasan or something?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzOaGJbG0HbVRHrYv8yNmPV0Anf5hvDGcHoZVZ2bF%2BLBg%40mail.gmail.com.
