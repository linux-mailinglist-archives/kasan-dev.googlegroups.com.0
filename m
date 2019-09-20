Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5DSTWAKGQEUTSVB4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BC1EB96BD
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 19:51:09 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id b2sf1605235oie.21
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 10:51:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569001868; cv=pass;
        d=google.com; s=arc-20160816;
        b=xU8H8oduVi1/sv8+WDq/t3EZoRUV5c44IdDn+mAmVotrRnB+I0ZIaOLS2cIcYBYaqE
         zbozTIxLGSD2HIT9Wuxh3SM/p0OeHMV6ySNIJggqowHeJ0JTzDi/CGr9EmnqEdVzKnS9
         GpvR7k7V5TxgA4eaFJbW6WY3JUFYbctxczoss77O3etVxaXIF5EzbZJw+QwcApPxGzeZ
         ydW55DMdvsXssu9grKiDtkMEz8T1m2huFU6RXCZLeWC1nBppQh/PBgo+GTW4l+r/zF61
         gn/qh4BPfn9YBWJ7N5DS3MKMB2+qSrgyU89xP2JDws7LLtLwWf8ZZtB+gqLT0XPkVIrT
         UVcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=deCX1VTqJIKeCSvVZq97gmf3M8wdaVimb0YCzFlqwiA=;
        b=BkpD1lnzvOEincrmnucNMmAvVRQDAQ2UBicSG4k+Tx6YHvyxzXLbHOtjrS6dhVjq5Y
         FTCAZ7wGXKvZ66OCtcqt85EOP1s3MQLQtfzS4sL9u6AOihdiGX+9daLlO4octXqEOsLR
         KN4ZJHmyZTz8JKTENthOE3OCiX6PNTImm20qukXuTX1DzwobsUQk1ITH13wMHviOI25O
         SeyiQKZWZcNR+G6cnMVIP9DDJVczX4+a0Dyxm0iwNC0nenvNF5I/YxybXVl8YjH3IJrX
         ltiBRwgH1mGCHDfj/5kCo1M5iHPFdBSASKC780/Lqs33CleaTaHaZHpo1W32xCk7P50e
         dkMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GcxR+Hvz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deCX1VTqJIKeCSvVZq97gmf3M8wdaVimb0YCzFlqwiA=;
        b=b4LTYKBEoFOPYcQ45xMlVCv6diE2gaUeY5zlWiGGxxuPSkWqRrQqjiSjntedfR+3cF
         3o88twhmHphM3zfr98ldJ6ewOAKPDTUi+mqiKa+Qo/sbpPzhhkDnPHK4VAYXOfBGxGDf
         3wLZz4/02JY5yGfr7v1nt1SL5IHpT4nQ5wQnd2K1XyROozaY1DzTFoU/PRlGlrxgdONy
         QKOHIkmZnD6EkPq0OjbuOL9K4uXdOv2t706zV25vRFDJ6580b9M8UGmeJLvMDJ9Fiswy
         SkbKcHbnbr+ifhvADGVA4tQEVhUCnAEO4RCL9a0ASlqTTlDsg4Tqb8XJ1iXB6OnXjexS
         vw3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deCX1VTqJIKeCSvVZq97gmf3M8wdaVimb0YCzFlqwiA=;
        b=NtlR6SkkYV2msxwvrMcTCXGQ6anfB+Dsh8BlHfOBpQ971XNw5QqAL9BoYhJIC41cH6
         YiJM1PFAVAgZ2iaCBNXvdKN+o7ODr94nBsT46kzzr1//+1mMUWhg49J2EXsUwgZe1kpM
         /0Me5wSBgVPOWLfjRT0YOlpBqljdZ4gZMo7qMBKTJzIgFGRDnI4jT002pasne5jae3f2
         m71YapZm9KnRchxyQfQ4vnr8MOCJ3rSmiuFiSkWoLcCheM395c8D7a/jwJ+KH86Sw8rD
         YJOtYw8PfTWgcnOQItIRb1gemHpt/D58iIhHgiDhHUSWuU6bOxTSj51EP+AMhEsFZQP9
         dCOA==
X-Gm-Message-State: APjAAAVSXz7HkSAPtzuggDG5M2U5xxl79BJrEpabtUfVY1fWxym/R6zc
	C5tTLYYqzyTZ1mhVi7kSuAc=
X-Google-Smtp-Source: APXvYqz2F42yf/Z/tj/BlLQgBuLzkqT+ynqOebn5nI03S1vyqQQ46AkTmhPMIzvHZ6GTm1zM2bWqLA==
X-Received: by 2002:a05:6830:1bf2:: with SMTP id k18mr2410502otb.259.1569001867996;
        Fri, 20 Sep 2019 10:51:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4fcd:: with SMTP id d196ls593962oib.16.gmail; Fri, 20
 Sep 2019 10:51:07 -0700 (PDT)
X-Received: by 2002:aca:ed0a:: with SMTP id l10mr4017948oih.83.1569001867724;
        Fri, 20 Sep 2019 10:51:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569001867; cv=none;
        d=google.com; s=arc-20160816;
        b=lAgi+0huv/q/pnWhkEvqZ2VTdZaxANxMfxLzGjUxVT7moJa9iT6j/CmQSjNS7MoX8/
         ajudgflKS/aX/Lw7x6b6uX7g9AnwuVAcWkpVXvkdrURQFYQeEJwukeeBs8WQ7JSMm4Rc
         eqEdYdbcdSWDZ0HBVmzm4GQSDDIkdz/+Fh9e4GumKIUdDtzXwqKOvK0hvwhEbQMur5D3
         gCj9eC6BhfswKCTacSKzZ3MmawNR/LVM0z1cABHqaPsxg58vsZ0DD37yLmuatVc7nYCt
         BgJOfeT6BMf1mdpHfiAF3+fP9eIjlA1mOXzeAnJaBBp6bXFuMOfMsE++klrD96ioVCl+
         5ZUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=EvpPydj1iU8UnRZJqqbCnDu9C5EKJs0suXbTn88VB04=;
        b=GCBzfIXPwaIXNvol/p8MiQnWRso0lXKvSE7SL+QpT2TKh+Oec3cO5fpTvY2IMqwIrz
         GFUJDLdemK0lFHzZEWXkEb/aToAwCg8Xrf8J+frztaggPiPEk04t8cTDq36W/4qzSoWs
         GVpdqSirvBVDjuNODjKS1ieizpAD2vl29l2u0L4wDPQfVeeQ2zay6YGZXPX02MIQvE73
         ARTU30jsCy5oe5IswqdnFP8mBSl5W28njxBOc0E8sbHRJ8ZzcCwTENmmZIrz00PK5SWQ
         KyC8dsTAuvzuUwj6HBi7MHB0IamH3A6or+MyKu6GLIEYMsQBy9qBviVW6be3+ODs6eE2
         omYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GcxR+Hvz;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id a22si199953otf.3.2019.09.20.10.51.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2019 10:51:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id k32so6912187otc.4
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2019 10:51:07 -0700 (PDT)
X-Received: by 2002:a9d:68d7:: with SMTP id i23mr5023651oto.23.1569001867060;
 Fri, 20 Sep 2019 10:51:07 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
In-Reply-To: <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Sep 2019 19:50:55 +0200
Message-ID: <CANpmjNMfredJzrmjV7Vm_VAeL_O=_mWWKXAMoGoPH=U8VhkS=A@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Will Deacon <will@kernel.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, stern@rowland.harvard.edu, akiyks@gmail.com, 
	npiggin@gmail.com, boqun.feng@gmail.com, dlustig@nvidia.com, 
	j.alglave@ucl.ac.uk, luc.maranget@inria.fr
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GcxR+Hvz;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Fri, 20 Sep 2019 at 17:54, Will Deacon <will@kernel.org> wrote:
>
> Hi Marco,
>
> On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > We would like to share a new data-race detector for the Linux kernel:
> > Kernel Concurrency Sanitizer (KCSAN) --
> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> >
> > To those of you who we mentioned at LPC that we're working on a
> > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > renamed it to KCSAN to avoid confusion with KTSAN).
> > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
>
> Oh, spiffy!
>
> > In the coming weeks we're planning to:
> > * Set up a syzkaller instance.
> > * Share the dashboard so that you can see the races that are found.
> > * Attempt to send fixes for some races upstream (if you find that the
> > kcsan-with-fixes branch contains an important fix, please feel free to
> > point it out and we'll prioritize that).
>
> Curious: do you take into account things like alignment and/or access size
> when looking at READ_ONCE/WRITE_ONCE? Perhaps you could initially prune
> naturally aligned accesses for which __native_word() is true?

Nothing special (other than the normal check if accesses overlap) done
with size in READ_ONCE/WRITE_ONCE.

When you say prune naturally aligned && __native_word() accesses, I
assume you mean _plain_ naturally aligned && __native_word(), right? I
think this is a slippery slope, because if we start pretending that
such plain accesses should be treated as atomics, then we will also
miss e.g. races where the accesses should actually have been protected
by a mutex.

> > There are a few open questions:
> > * The big one: most of the reported races are due to unmarked
> > accesses; prioritization or pruning of races to focus initial efforts
> > to fix races might be required. Comments on how best to proceed are
> > welcome. We're aware that these are issues that have recently received
> > attention in the context of the LKMM
> > (https://lwn.net/Articles/793253/).
>
> This one is tricky. What I think we need to avoid is an onslaught of
> patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> code being modified. My worry is that Joe Developer is eager to get their
> first patch into the kernel, so runs this tool and starts spamming
> maintainers with these things to the point that they start ignoring KCSAN
> reports altogether because of the time they take up.
>
> I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> to have a comment describing the racy access, a bit like we do for memory
> barriers. Another possibility would be to use atomic_t more widely if
> there is genuine concurrency involved.

Our plan here is to use some of the options in Kconfig.kcsan to limit
reported volume of races initially, at least for syzbot instances. But
of course, this will not make the real issue go away, and eventually
we'll have to deal with all reported races somehow.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMfredJzrmjV7Vm_VAeL_O%3D_mWWKXAMoGoPH%3DU8VhkS%3DA%40mail.gmail.com.
