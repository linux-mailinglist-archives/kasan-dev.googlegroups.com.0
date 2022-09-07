Return-Path: <kasan-dev+bncBC7OBJGL2MHBBI4J4SMAMGQETB5FBMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id D9C7A5B0E9D
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 22:52:52 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 62-20020a250341000000b006a93b57e2dasf6522669ybd.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 13:52:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662583971; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3mc1kI5e70YI93xepjDAlR6bEufmuwtcyY/1zMMls6/l9d43IlT2T5Vl+pSr8l87U
         65qP3tVTDtjrSF4si+s6jV0hilOm1MIJzuVcfKDZLZcTiMnpMLKbBv+3uJNj31Zv7uDK
         nTvKcv43RvRAJD2ZmBPV7/8RHbcmhIShWefQgctieoRKEB691cNLnBJiUDlVcrPQ7pTS
         /ZxF+XTvAaXhQJ9iy8luhRgEAycPI205Ty1jbzQm8bU1dkeYHM0AGJTfzjiE85cXzIGp
         TQTCZ+lbn0afA1iz2FEfhJZAzFiD/89WpCorSlmWHCmy6YEm0sbza8+nS+FvojmpZ/V0
         k8Qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5rxbkWZhJXI6LaIQONsVpn4iJ62wTE7XRXpMlHl59xY=;
        b=b3gjPWUNKf38p+Iqh++c7rvLh1uxTJxmI00SY4VnLdscyXATgcBJv1L4HX4GNhJdQI
         dpg/kqOCOOCtqd5ricD3p3bbvZHrk1+XeYgAWhgZuHKbokq2KRkU8gLr5Zngyn1Vhkxm
         cFo9meN3ZlSRfSG0dH8Q5QqvKeCNC5lKawKTL69mcQwTT6/9pmt8pG+1E85bFRa3iMCl
         x2bIcLJh/PDRDX1B6u0vztRXiLmTmJB1m+q4OVOMUPKZfs0G8D0stN2Up4TZQvqDEced
         NcpJTd//OWKXRDgLhwh0shmujd/IowlKhwMh7cMp1MilHdwxZBkj+9S2s34uTnNGkaEx
         Zw2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="W/rcNroN";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=5rxbkWZhJXI6LaIQONsVpn4iJ62wTE7XRXpMlHl59xY=;
        b=g7aAvgFB9tgbJJgz/t0WiT04u4EzxfnLbAkkSLFxHCOSZXw4pQx6lwiRyVVEtrO6pG
         XUzw8jVOl2kqLOqF6QRtnHRNxmHtmrrQWVOKvJWdocCjuqySxBqS/9rJQKT/YR2VRLqO
         0N/qo/mZrnNprUj49z9pJpF/44n989hEGFMfXpzCQTRg2Mgvy2+PnsP8CiyuuO7hp7pY
         y9zbUdMkYF5CNoJuWQ1f1+vYQwqjYwrQVWc+QtxIzt5VFLYqDOMTBILqHO4OKcdK2mYG
         P4XmuLnoAYv0d/aLBdk/u25kQSIk0TkmE65hn/K5+dF2ALCxUmLzeJkEeW+zAT86DEJZ
         iCHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=5rxbkWZhJXI6LaIQONsVpn4iJ62wTE7XRXpMlHl59xY=;
        b=Jihra19Z73jiRaZRjOr/h+7cNJmUAUeTuliwYrc7C4MEZme5vFxIzr1aMk18PjtJ6p
         cAoOGujeptccOqV1sFhEFAEPK6uiKUxEubz0c3ZlTMZz1J6U7is1dmlUVFvNiDnEmo6D
         vSKTmkDaF/APHS/SXUXacUbsoK+hDjEZLTGK3AQ+2MP8wyqfHbT4jnRh6mfiSe+v+ES9
         OoJqPeoysItpubYmvD/oIDjjYWk4lnstylfXMoahiOsyNJgyyt/p7SuB3ai2s8ci759w
         hQ8ccj2CTw+p4bIGdR2hEcnhkJR/8MU74lrvUDjtvjV2baUc65YAwOZGbCSCVMeJmP+9
         ceXg==
X-Gm-Message-State: ACgBeo3uRu8YsKiAXSlkKTVRfJYJEe1ZnFpABUYaNBOMLUYXQdRXlKiY
	1FK7n8spDoJggNVEljFWXmw=
X-Google-Smtp-Source: AA6agR6sEC/7ra2WOPOI1CVXIUmaeC7y81MU2q0Yk67WAajPUj+hcDr12tOSxEuPZ+57RNhlEdEO2w==
X-Received: by 2002:a25:8547:0:b0:672:ca9c:d33f with SMTP id f7-20020a258547000000b00672ca9cd33fmr4452153ybn.270.1662583971677;
        Wed, 07 Sep 2022 13:52:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ad9f:0:b0:6a9:1fe7:a717 with SMTP id z31-20020a25ad9f000000b006a91fe7a717ls27316ybi.2.-pod-prod-gmail;
 Wed, 07 Sep 2022 13:52:51 -0700 (PDT)
X-Received: by 2002:a25:2f13:0:b0:6a8:e0f1:3288 with SMTP id v19-20020a252f13000000b006a8e0f13288mr4156875ybv.449.1662583971067;
        Wed, 07 Sep 2022 13:52:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662583971; cv=none;
        d=google.com; s=arc-20160816;
        b=mPckdpYjyVtOd8XgIJiliK3ryaEvwo7l8YMFQzdHpchZ+REn05GDc/2A+y9PFNTiGA
         XxMPLzgYWoyumOLvxm4DdXjmRnMpKdnz5loWBnYEoDUm68SN6rd0L8nrcvqAiS8p15Ev
         PaUo58bG3aPToK+biNq3Q12BFSkMviI7XE2dxYU4KFqvYvvuE8qnzuh0tQ9Rt8MTxJG+
         aN7KE7xpUU2Z1OiMRajUUtbS/J/FLCe9PLsKTtsQqZWHzY739Rco0uPUw3eeOrHO1k+d
         +YkcxC/RjPs4Ey7m0ER7wI2wxBOdyE2SaDRN7yDRDLlRcN86m03q9rxt0OUTyAqJm6Tv
         egjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eSmjHP3psGeOMr+WEOk0DOTV5ssd7/gZzN1bjJygBoE=;
        b=TZ3U2BWlHB7fsSG2YHZ5kPK+GVhCCYOkP5nzY6DlMpial5ZBz2T+UlQojvm9sNRd9c
         Id6NEwS5Q7byw1yPT54GvAAXo8a9CcRMgLty0wwx+5j3rsQtymLHqKb+3vsFy9xYIEox
         jSY9RSE6BhHDahWlA8oGMSVAlmJKyJ8Ck5fH1A4XjiD1CEi7B9BL4+KDyI9xAYgrXG42
         saVVCTUlxh9fqIfTA7jxhxW6OG0VWSzSO2kKVH+NYNYC2OWiwtaa9aUK+uid3emRcRKC
         UP1CzXRxGWRfca1GkeXVkxCUgxMitzozYLJVLurqC7JyxD4AistdbitSaEGwl4/xvM8h
         kLKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="W/rcNroN";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id l64-20020a25cc43000000b006a790068256si1636994ybf.1.2022.09.07.13.52.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Sep 2022 13:52:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id b136so2640322yba.2
        for <kasan-dev@googlegroups.com>; Wed, 07 Sep 2022 13:52:51 -0700 (PDT)
X-Received: by 2002:a25:1e86:0:b0:68d:549a:e4c2 with SMTP id
 e128-20020a251e86000000b0068d549ae4c2mr4320074ybe.93.1662583970644; Wed, 07
 Sep 2022 13:52:50 -0700 (PDT)
MIME-Version: 1.0
References: <20220907173903.2268161-1-elver@google.com> <Yxjf2GtNbr8Ra5VL@boqun-archlinux>
In-Reply-To: <Yxjf2GtNbr8Ra5VL@boqun-archlinux>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 Sep 2022 22:52:13 +0200
Message-ID: <CANpmjNMNpFUN3mvpAfdgf2NRcrOjMKdnF09UcbPSvAi8+==Byw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kcsan: Instrument memcpy/memset/memmove with newer Clang
To: Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, llvm@lists.linux.dev, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="W/rcNroN";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Wed, 7 Sept 2022 at 20:17, Boqun Feng <boqun.feng@gmail.com> wrote:
>
> On Wed, Sep 07, 2022 at 07:39:02PM +0200, Marco Elver wrote:
> > With Clang version 16+, -fsanitize=thread will turn
> > memcpy/memset/memmove calls in instrumented functions into
> > __tsan_memcpy/__tsan_memset/__tsan_memmove calls respectively.
> >
> > Add these functions to the core KCSAN runtime, so that we (a) catch data
> > races with mem* functions, and (b) won't run into linker errors with
> > such newer compilers.
> >
> > Cc: stable@vger.kernel.org # v5.10+
>
> For (b) I think this is Ok, but for (a), what the atomic guarantee of
> our mem* functions? Per-byte atomic or something more complicated (for
> example, providing best effort atomic if a memory location in the range
> is naturally-aligned to a machine word)?

There should be no atomicity guarantee of mem*() functions, anything
else would never be safe, given compilers love to optimize all of them
(replacing the calls with inline versions etc.).

> If it's a per-byte atomicity, then maybe another KCSAN_ACCESS_* flags is
> needed, otherwise memset(0x8, 0, 0x2) is considered as atomic if
> ASSUME_PLAIN_WRITES_ATOMIC=y. Unless I'm missing something.
>
> Anyway, this may be worth another patch and some discussion/doc, because
> it just improve the accuracy of the tool. In other words, this patch and
> the "stable" tag look good to me.

Right, this will treat write accesses done by mem*() functions with a
size less than or equal to word size as atomic if that option is on.
However, I feel the more interesting cases will be
memcpy/memset/memmove with much larger sizes. That being said, note
that even though we pretend smaller than word size writes might be
atomic, for no data race to be detected, both accesses need to be
atomic.

If that behaviour should be changed for mem*() functions in the
default non-strict config is, like you say, something to ponder. In
general, I find the ASSUME_PLAIN_WRITES_ATOMIC=y a pretty bad default,
and I'd rather just change that default. But unfortunately, I think
the kernel isn't ready for that, given opinions on this still diverge.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMNpFUN3mvpAfdgf2NRcrOjMKdnF09UcbPSvAi8%2B%3D%3DByw%40mail.gmail.com.
