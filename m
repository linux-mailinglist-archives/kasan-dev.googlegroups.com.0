Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSHVY36AKGQEMRN5G7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C70C296339
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 19:00:57 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id r10sf570602vsq.7
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 10:00:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603386056; cv=pass;
        d=google.com; s=arc-20160816;
        b=VKtylhLiBtdDLF1+Zsaim5V4Y+U1uRxKt+YUm8BlddNq1HOV4+o/ZGFL7d5uuRClMi
         CWtbRvp038uYDo+xIWmIDEUSA+M92Z1+5A7HJeoA8melUFzc3nEiFUq0GyynHLIZCeJ2
         KknJsv3dVz4k/iyNK8xk1tCAGGrZ5XdGZF+AuqFFpvcHh2X8LIBqo0gnmzNPxGuS13kn
         3XD8yfgJ2Zi8q+vAgPMO9QRtSC/5p/CA7werOSYwSuTewdhmKQJHYk4GCVtcqijIiGyo
         6p4OIQf+/pN0IMM1oPf+/eC/cvwmwIpVmMd6jCO/KjNd0nevX0b6yTnyg8YD0nc0uu5i
         rWUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eiCMRXLkw9djZNHuZnN2aRN34c7WKM5dFy34LpQZs1A=;
        b=tOjFpj0seZ1oSWSabYG3mHclztL7h0XYjIV7VDtQROZovpiKJwtAWtMTZUKtc74MFZ
         171A2DvrvwQJvxzK1kAA9sLs9uVXqreDI7+N65cG4+RFo9TJZIwjYk/NCCXaY0hozBkN
         qZPdNX3dQcCLSjwJZSd6EZmGzYkdx26bmOou4AtslLJJik/6IA3gHHRq/xltOxeSLVvA
         TeZFaMwsOOEE6DEFdUoVc3vZrSzZm2s6zkSlx+hMpCfX6iwdFfFr4md8tkn1hsCaECGS
         bca65wW4PareiyGp82oJkwDH1tb2w1zxHE9AHD1tL4gEAgZz1ncgmhxJs4UYnTaE5HRa
         BQQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YnO2A44c;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eiCMRXLkw9djZNHuZnN2aRN34c7WKM5dFy34LpQZs1A=;
        b=ItpAo7VqPiLwMQkjI7x3Omj5YX2mcWfrrTQvK3CwWMpzXB80ewknR68t4UKgmDqXoW
         v6oKw5RHA3fgxY7CZKY4gCoZJqFES11x1MtHFID6gv2jerAFUYaRS4lxlfKhJ9gY2D20
         YrCttB06GIIhxj96LQifS2ji7oYUE2qVjHmTpiDUQCQk2w2Ay9XY1YVRiwP1KFObE/bB
         e7tqeIrghsHY+PMepJuW5CVr0fOyZmfvVYOnWpjnLdrsRJeMfl0MmZ7S1WUWWAQiwVeP
         Yzw2uGvW5/m4zpqfvjUo2MXVTwvOsgrruOqdUiD7DVESBzFm2EkzyjbHXhOnE7rQ1RMp
         hw4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eiCMRXLkw9djZNHuZnN2aRN34c7WKM5dFy34LpQZs1A=;
        b=riupv4OAEZm4Nh9nvMAWC997JgDHA14t32685BZ4WtB0+hmlPWhHge4mOV+Oa97Sxe
         NWSSp4avC3hR57A75MPvn28f5FP8B9iQBuUwi5TlAEQ0bQDbYwqwjsYogBAFjRchcyyP
         kCzmqiCigfMhnX7KA9E91Ah7XhAdJkOjcGvpSGjQDXd+07s4vktuCJTDoDwJw4wM0LNj
         kFwWMoUvRUrLZ3IPC8hB8kbbN+/traKCx038bG5j103PJkNOnRUuouLcVsJULxrDs2ln
         Jk9m0DbnNGpg8tYu2vwAc+j1jRusL31m5Vs9iPc0C5iFz9yqMmsIOvEcHcyoOr4YWD7r
         OeJw==
X-Gm-Message-State: AOAM531rNSw1hUFQp4w+YpE437H/YlkdfxoKhMlb/plR9/IDdA39a3QQ
	sdR1wYdhndNjNHjXZiHSbyU=
X-Google-Smtp-Source: ABdhPJxmcFnnjdfqzWA04tLJ22AaVrqlATOs2LivqjNW5dTqzFdxDSIKKgXkboKxxch9GVTVOWn9eA==
X-Received: by 2002:a67:f716:: with SMTP id m22mr2840063vso.12.1603386056250;
        Thu, 22 Oct 2020 10:00:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7401:: with SMTP id r1ls162168uap.3.gmail; Thu, 22 Oct
 2020 10:00:55 -0700 (PDT)
X-Received: by 2002:ab0:6f11:: with SMTP id r17mr1988925uah.15.1603386055479;
        Thu, 22 Oct 2020 10:00:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603386055; cv=none;
        d=google.com; s=arc-20160816;
        b=GzB9JRWKOjQv0icY7U0nG753dsOB3J12xxpNXCrUrtO7Y4x/g7MFqShMg71GE3K4X0
         j4R7UuaMcOo0VlULaktdo5wev50wJIwrb7AiMc09u1GqfoYdisJGIWKFKzrQQCZlbRfj
         XpA1iaabxEupiozzBKxSX2eCKp4NCnEWVz7sLByKdxkal7o1ZAG47m3oVZUJ+EKqw4xP
         A40nwk68FqsCh9mbGtvVFxHbgkvM8KWd1rMiphnOtVJdPK4oGeaz9RwT34Wh3VtA6E3t
         qvKyA2/hY6mHyEbmxB+Yno0qw8bFr+lvKuP+VZNPvHRzirOrRWLlZ6zbGKAhUU5KIZdl
         lVqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C9Aq1WFRNzdLR8UtlVTni3Xh5pWCzbV3aMmYTzeHRyk=;
        b=jSo9aMIJOUsQ0wM/8HYOZgz+1WLs58LZnFVBDHN7dycwq62D85jgWXmrQQFU9+4Bgs
         vLHigHfscOnXg1Olb2WtAXKFM1nI8JDvnTwvdINv5mxM2dxKY80h1tzI70Irwo2AlqSN
         YeVC3zv0n1PFbLjPc69LjDPnxgyzWPZGNaYaBEeLX05FXn91i54hsEGjxBvDbG2YDjm0
         TG/G/1dsjwNQwngV+rE2QwqWt36A+xoZ1wS+A6A8HR0iRZSyozcUhSlN/8j089RcVxCm
         t0AN8xcszkOEQ4e2Nv0EXhAC+85o1aKqVgnDn735acn88/LpXmoJ5mW3wuXSOscVXUqV
         3oXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YnO2A44c;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id a14si226544vsp.0.2020.10.22.10.00.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 10:00:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id j7so1290711pgk.5
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 10:00:55 -0700 (PDT)
X-Received: by 2002:a63:d456:: with SMTP id i22mr3020892pgj.440.1603386054345;
 Thu, 22 Oct 2020 10:00:54 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <CACT4Y+bVCADgzweb_gmC9f7m_uc5r73scLPy+D3=Tbf2DFqb6g@mail.gmail.com>
In-Reply-To: <CACT4Y+bVCADgzweb_gmC9f7m_uc5r73scLPy+D3=Tbf2DFqb6g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 19:00:43 +0200
Message-ID: <CAAeHK+xEQ2krRDrPPFmOvp-pR+jR179VDg1iwd+mB0hVZ9rsgg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 00/21] kasan: hardware tag-based mode for
 production use on arm64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YnO2A44c;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
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

On Thu, Oct 22, 2020 at 5:16 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > This patchset is not complete (hence sending as RFC), but I would like to
> > start the discussion now and hear people's opinions regarding the
> > questions mentioned below.
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
> > The patch titled "kasan: add and integrate kasan boot parameters" of this
> > series adds a few new boot parameters:
> >
> > kasan.mode allows choosing one of main three modes:
> >
> > - kasan.mode=off - no checks at all
> > - kasan.mode=prod - only essential production features
> > - kasan.mode=full - all features
> >
> > Those mode configs provide default values for three more internal configs
> > listed below. However it's also possible to override the default values
> > by providing:
> >
> > - kasan.stack=off/on - enable stacks collection
> >                        (default: on for mode=full, otherwise off)
> > - kasan.trap=async/sync - use async or sync MTE mode
> >                           (default: sync for mode=full, otherwise async)
> > - kasan.fault=report/panic - only report MTE fault or also panic
> >                              (default: report)
> >
> > === Benchmarks
> >
> > For now I've only performed a few simple benchmarks such as measuring
> > kernel boot time and slab memory usage after boot. The benchmarks were
> > performed in QEMU and the results below exclude the slowdown caused by
> > QEMU memory tagging emulation (as it's different from the slowdown that
> > will be introduced by hardware and therefore irrelevant).
> >
> > KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
> > impact compared to KASAN_HW_TAGS=n.
> >
> > kasan.mode=prod (without executing the tagging instructions) introduces
> > 7% of both performace and memory impact compared to kasan.mode=off.
> > Note, that 4% of performance and all 7% of memory impact are caused by the
> > fact that enabling KASAN essentially results in CONFIG_SLAB_MERGE_DEFAULT
> > being disabled.
> >
> > Recommended Android config has CONFIG_SLAB_MERGE_DEFAULT disabled (I assume
> > for security reasons), but Pixel 4 has it enabled. It's arguable, whether
> > "disabling" CONFIG_SLAB_MERGE_DEFAULT introduces any security benefit on
> > top of MTE. Without MTE it makes exploiting some heap corruption harder.
> > With MTE it will only make it harder provided that the attacker is able to
> > predict allocation tags.
> >
> > kasan.mode=full has 40% performance and 30% memory impact over
> > kasan.mode=prod. Both come from alloc/free stack collection.

FTR, this only accounts for slab memory overhead that comes from
redzones that store stack ids. There's also page_alloc overhead from
the stacks themselves, which I didn't measure yet.

> >
> > === Questions
> >
> > Any concerns about the boot parameters?
>
> For boot parameters I think we are now "safe" in the sense that we
> provide maximum possible flexibility and can defer any actual
> decisions.

Perfect!

I realized that I actually forgot to think about the default values
when no boot params are specified, I'll fix this in the next version.

> > Should we try to deal with CONFIG_SLAB_MERGE_DEFAULT-like behavor mentioned
> > above?
>
> How hard it is to allow KASAN with CONFIG_SLAB_MERGE_DEFAULT? Are
> there any principal conflicts?

I'll explore this.

> The numbers you provided look quite substantial (on a par of what MTE
> itself may introduce). So I would assume if a vendor does not have
> CONFIG_SLAB_MERGE_DEFAULT disabled, it may not want to disable it
> because of MTE (effectively doubles overhead).

Sounds reasonable.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxEQ2krRDrPPFmOvp-pR%2BjR179VDg1iwd%2BmB0hVZ9rsgg%40mail.gmail.com.
