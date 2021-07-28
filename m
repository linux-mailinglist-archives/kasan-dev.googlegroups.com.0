Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFCQWEAMGQE75SQIAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FE9B3D8E14
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 14:43:54 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id h12-20020a17090a2eccb02901762a8fbff0sf5344833pjs.1
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Jul 2021 05:43:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627476233; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+p7xXDtn0r2DVuBmhsg5bANvfWaZgUmEGek3vCFxEj/rVVLRxP5QpIUK2ZEUr+vqV
         pRHnUufJHtjPWtMeH56PPmS0gDQ/aIda2FCdHuOI+JQ1kLCuFMmpGwEwY6bYK3+wtnAc
         hg8rlzRhoUjC9eoExnPywdZOKHFPXWAFvJHPld9z5Yqhh563dEAc4auJT6+iqrpiHSo6
         rUHPh8Pry0wXwpI0F70EtgoiTSMfoYlPEPMyNVPYaHldP+sJvbIwXR9dt19oB6gvfVCK
         E1r+Il2mHG+2UPkBFYCuIbnHcAEO/Csbtck2dtdXaj7ZH7kZ/oNbwI0UcEI5WOYwyzHl
         dXvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JgPY8z7BQcFjnIhELiTPHQW+qtAwz6iTemnBZu3Ost0=;
        b=ius78JfCq+hv6TOOp+DGT3CzuIgmfSpjTUQpzCxedmj3SdqI6LD0pFiklhkxN3BI3g
         XlAItFFZiWEkQtWOC5fTS5571oPbqJrmyl3stDTMRib7NzRhh3ch7sb6zg2YhPsDmNPA
         pXhUUB+Ru2yCGppbi+qAcZnzNYfJ5hyTWNBFWC/gQstJDCXoy/EMYqN1GuZ3KuOsLuH+
         7U/JwQrzjhhg7X9jiPax7NiLmxGcdYd7+zz2pq9jFnCesjhEp0vJDPLyATos0LInBxG5
         bbZwxFLtgslDawZkBJ3VIVSRPOn7kAag3S7R2xciXskfl4ar1WHdRfHOA+f0YXY7emdE
         D4rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hHX52BoT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgPY8z7BQcFjnIhELiTPHQW+qtAwz6iTemnBZu3Ost0=;
        b=fb3sqoyMv5R7SXntPM4b+1cyzab6lUnWFJ66RmzLJ6oAiUPt5fMGi7SDiLD9x9GYAX
         /fJSpS3eRmdtGgY8+L/1EIHCdQKc1l+3myvjwJil888DomgjUncAGkm3bOWD4ImY2yVT
         PpfeCByD8o0chUAnf8LCCIqJxTdLulsO8vzyxO5iq5njlxGOba2JE07Bh9DWRO35DgLG
         3z4mUfIahAmmqM1hxohtSxLH1PQwVr5P8C6FDJHCJYdrBfKvNI1x9TUbEbLsJdCCVccz
         reypBjMcqXF96/Zxy5YRfLlVoLWloL8lOzxtCtWhLJ99+HWnqA5PcJ8hAXV0g1RU5p/p
         uVgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JgPY8z7BQcFjnIhELiTPHQW+qtAwz6iTemnBZu3Ost0=;
        b=cmT7QQqgQHhEc7mEh2OnRHVzUkH2CIiaqhClkHXDYQuSum5lWEouCb6l3jb23eTzm4
         ij/3uCtVG+ZEdIme7QAx2nTQ41HHO0/d3Gmn2kicoVCc5yWCHZwsOkj1OB1xRv4dl8xh
         yVPClstf3iyssNU4m+yJUMn3OuU+PKLWlUG532s6OEzlwyM+dfQaoivluKndchU8TjTD
         5FUgWe0xxMoghHX6Mln+tprPQiRyEhjSlNLvr5TXR/J7L9AMbl/I5UmeoLmReb069saX
         6cvaD3CBxhgpar5u2o5l45LjhSqkCYJCcAcPI3cL3MlkbupPqFSjd66asf6XBYyoE0tG
         9Ngw==
X-Gm-Message-State: AOAM531a4s7it0DbIRBv9ULlx2AZ3PeYmGRzyS9qdP9ZXQhjIufbYLgc
	d8PBnyxRKAmVo5dIv0StoI4=
X-Google-Smtp-Source: ABdhPJyHcawynI7G0WT5Tbl3U7MPMK9U8KqsLDnVExPxSYXmgO+HKPY55LVKQigeZpk2zfqTUblMdg==
X-Received: by 2002:a63:3f42:: with SMTP id m63mr28955030pga.33.1627476232889;
        Wed, 28 Jul 2021 05:43:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:a1a:: with SMTP id p26ls927505pfh.9.gmail; Wed, 28
 Jul 2021 05:43:52 -0700 (PDT)
X-Received: by 2002:aa7:9517:0:b029:35e:63f3:64a2 with SMTP id b23-20020aa795170000b029035e63f364a2mr28614483pfp.74.1627476232259;
        Wed, 28 Jul 2021 05:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627476232; cv=none;
        d=google.com; s=arc-20160816;
        b=LRc06B0Btcc+2247hnl9ia5IF1I/akfi/BPevi0T+/A7PFdZH4miV+NvGzKZoBTkJg
         16PXUDSbX8mp2SexiN529Xx4FmyepvweRziirz6vqMrzJl9IOMt8t31mkMJ4I2cRcAeC
         4kX67fOIrrmO3ILQ9hY4TljMeMLLVubq5o+GnyA/b84hDrjZkFJvyAXMtZl0iaFFXlHK
         vSICZdj11dIucFrj/6M1IHIAR5a1vGLmuXE5GgTg0sKWomkYEWpwsoypFZp/KS/HBHsa
         ClR2w71jdQZ8feSCZoozeOcS/5h34ymRgXiDwc3/r5yflHKtHQQZyPT1LmD85CJtOqFG
         iTAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=z8JopdaUBmz7iXRtArgg3xHwWvgUd1IpWAikP8/7uLI=;
        b=nd6pekGEiGpq4zmZAyiNMflWitohw8NPVKf2a8JUlYXmQPJsGFSkwZC57XoxCr0qhQ
         AvRgvGtYo9ug0MH66/uRLuWQ+sxydLZ+eCao81CUDZM0t7CWpAl/eG7etbva6gPvxgrn
         XDASb0sThur9AYD5uxKQRXIFsWaciWJma4vRl7NSOf4R7rkQ1ykhDdVrKHYuiQ+GSWUo
         0WuzJt8Pyr/PESsbMRTiJWQZ7yM1oHA0azXmqw2gvNNbGP3m25rOWDUmMdx38z2mFtV9
         Bq9+iWewEDTXWz/ZUQ19t8nHiix6Af1LQtkhn0F94XINri50AsrAI2JNhrqNOmwzKR0J
         fMrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hHX52BoT;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id y6si388801pgb.3.2021.07.28.05.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Jul 2021 05:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id c2-20020a0568303482b029048bcf4c6bd9so1905681otu.8
        for <kasan-dev@googlegroups.com>; Wed, 28 Jul 2021 05:43:52 -0700 (PDT)
X-Received: by 2002:a9d:650e:: with SMTP id i14mr19173472otl.233.1627476231336;
 Wed, 28 Jul 2021 05:43:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com> <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
 <20210727192217.GV13920@arm.com> <29f4844b1af163b0ec463fccbc9b902b3150f5c1.camel@mediatek.com>
In-Reply-To: <29f4844b1af163b0ec463fccbc9b902b3150f5c1.camel@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Jul 2021 14:43:39 +0200
Message-ID: <CANpmjNNhSauZEp9W48WcrjK3w5-3cV5Rk4oc=Ci+h04+T2jsAA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Nicholas Tang <nicholas.tang@mediatek.com>, 
	Andrew Yang <andrew.yang@mediatek.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Chinwen Chang <chinwen.chang@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hHX52BoT;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Wed, 28 Jul 2021 at 13:05, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
>
> On Tue, 2021-07-27 at 20:22 +0100, Catalin Marinas wrote:
> > On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> > > On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > > > +Cc Catalin
> > > >
> > > > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > > > Kuan-Ying.Lee@mediatek.com> wrote:
> > > > >
> > > > > Hardware tag-based KASAN doesn't use compiler instrumentation,
> > > > > we
> > > > > can not use kasan_disable_current() to ignore tag check.
> > > > >
> > > > > Thus, we need to reset tags when accessing metadata.
> > > > >
> > > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > >
> > > > This looks reasonable, but the patch title is not saying this is
> > > > kmemleak, nor does the description say what the problem is. What
> > > > problem did you encounter? Was it a false positive?
> > >
> > > kmemleak would scan kernel memory to check memory leak.
> > > When it scans on the invalid slab and dereference, the issue
> > > will occur like below.
> > >
> > > So I think we should reset the tag before scanning.
> > >
> > > # echo scan > /sys/kernel/debug/kmemleak
> > > [  151.905804]
> > > ==================================================================
> > > [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> > > [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> > > [  151.909656] Pointer tag: [f7], memory tag: [fe]
> >
> > It would be interesting to find out why the tag doesn't match.
> > Kmemleak
> > should in principle only scan valid objects that have been allocated
> > and
> > the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID, so
> > it
> > either goes past the size of the object (into the red zone) or it
> > still
> > accesses the object after it was marked as freed but before being
> > released from kmemleak.
> >
> > With slab, looking at __cache_free(), it calls kasan_slab_free()
> > before
> > ___cache_free() -> kmemleak_free_recursive(), so the second scenario
> > is
> > possible. With slub, however, slab_free_hook() first releases the
> > object
> > from kmemleak before poisoning it. Based on the stack dump, you are
> > using slub, so it may be that kmemleak goes into the object red
> > zones.
> >
> > I'd like this clarified before blindly resetting the tag.
>
> This kasan issue only happened on hardware tag-based kasan mode.
> Because kasan_disable_current() works for generic and sw tag-based
> kasan.
>
> HW tag-based kasan depends on slub so slab will not hit this
> issue.
> I think we can just check if HW tag-based kasan is enabled or not
> and decide to reset the tag as below.
>
> if (kasan_has_integrated_init()) // slub case, hw-tag kasan
>         pointer = *(unsigned long *)kasan_reset_tag((void *)ptr);
> else
>         pointer = *ptr; // slab

This is redundant. kasan_reset_tag() is a noop if
!IS_ENABLED(CONFIG_KASAN_HW_TAGS).

> Is this better or any other suggestions?
> Any suggestion is appreciated.

The current version is fine. But I think Catalin's point about why
kmemleak accesses the data in the first place still deserves some
investigation. Could it be a race between free and kmemleak scan?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNhSauZEp9W48WcrjK3w5-3cV5Rk4oc%3DCi%2Bh04%2BT2jsAA%40mail.gmail.com.
