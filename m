Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXXX4HWQKGQE6RJJ6ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 979CEE8EA7
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 18:50:23 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id s1sf8667293oth.15
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 10:50:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572371422; cv=pass;
        d=google.com; s=arc-20160816;
        b=noSZ7Hdk/nP/w7Lv8PEcpka8LeVQeMa0ObDCjCwgsSttZYNj1o6uH8oQhmfg6snKIa
         ric7nmnEB9z+Q017DrDRjcd9JfGSYkzyLOJq53bEDSuQgJKoDChIsXE12a/XnQ8OCvCZ
         WYQ8oJevt9WVhS+e0vLbN9iSwnfVQSwCNGvvWEftbVfZZo0uZI3GLUc3FYwG06zblK31
         ai2RULOPCvcPlPZ6aonotUcNTyJXYdjbnJJyfouYFakmNOV45Y6DXSA9dO2BBNqU/sOI
         HIi7kUjNQi9pn8El/VM1OfOACyxfMKIGiPALL6g1TmwcHe3pTdh2WBQN2/6deFyuwCBQ
         HsnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8waumSUkHCASpdZ2Uqa+i+dQVhmGAyMaXlc9ctlGhYQ=;
        b=uM/xZUeEyeIUluMIopKDCbP4UIZE/dJbo/aHMgDIrxU3uWdfGRmNWt69RjpeW+N+vg
         IJQCqtA3hKD6dPR74rLrdj8gQldrK2DyJlFovUjbmNnpNzLk2YP3XKMOXVnrLYVdvj5y
         Af1I7+SqwnGbDmXUFwJ7kENek02GdXEx1BcOnHvUlK2j9mhl+T30Jag/rHB9ZNRht6wM
         oN6VmCaZi9Cjk6xMXSlKAGjdspXx/3vHfl7W0iosvTY74u7mTSXssZEkF+uesY7bhhoT
         mN4UWTGSKmxCPNRvbZw64dsFi0qr7RzIuy9IX+7m2u3wKtcpR84L5QRuM2iao6nimXd3
         F33w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ejqJimG8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8waumSUkHCASpdZ2Uqa+i+dQVhmGAyMaXlc9ctlGhYQ=;
        b=XSMgW3ZRoyNecpAgtOlRZfFnH3stojjfq4RBRRlRC3NwlwHUVpqkNnIgvC2Jrc+P6M
         H78aVLxOOOvn6AbIBb4tuhXQiJ3c1PfB6l0nlDbCEl/i8Jz0tFl7LZYtVkQwwdT8OA/k
         aXlRTwrNtIfp9MfS+B8bRUEwUZhWH5T+OmxYAhb0IIBpREW0IGaTWJrJ2qurvNF9HWdF
         Mqv45wSa0+h0/ZkhKl0ARYiGuJayGbJq637Q9BsiS1kTPVb6F/aLCf5DkCgX24Gv5pll
         eStsvXkU1+mWbkmB7nHdhIe9MRpWxO+6Rrx0P3pWEMllMVnqkotBxfHWiOtoNNaMaIg0
         R7Jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8waumSUkHCASpdZ2Uqa+i+dQVhmGAyMaXlc9ctlGhYQ=;
        b=DuDfSQ4v0NkVYtCO7CDX61sLb7hrchKWs4iVDw1kslKMuDd4nc2AINsBLtMtSlZI9W
         n98XUZrUThqha2TZalsB1G7qgT2gYvObN2h//RfXxQUahqfc4NapINHUbVN6OLrwl3Wv
         kTqfDZ3D0vzVzEarBvzb0paGCavzudyU8Ny5sgm5CnP0Yj6qXHZeiE+LcewsrUQnkErl
         gqLYoPOjWdtC8hGLI1lE/ethlUhq9c7iGP4MO4GY+HJDTGb2LbAlSFyefxeyfmwpMZT0
         A0yYD1GQing8fjI+uaxI0m0iOjqPcrg6hyeNw+WBpNybTTr4TvWjhXdyMd7lPrsyCrh1
         45qg==
X-Gm-Message-State: APjAAAV1w8OG4Nh81atfzSZ8zPF3KFZcU45X7cHkqPfs9PF+/ycwjXRL
	LPS1J59OhzxDdXNe+9SsWCY=
X-Google-Smtp-Source: APXvYqwRFqaPqtcz77c9fCU05yey6q+pX4mpCFuJ9AakyaWoLOGe4G/F7QsvMkYPiv0zaAA+2NcyyA==
X-Received: by 2002:aca:602:: with SMTP id 2mr5171866oig.19.1572371422535;
        Tue, 29 Oct 2019 10:50:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5f56:: with SMTP id t83ls4552154oib.5.gmail; Tue, 29 Oct
 2019 10:50:22 -0700 (PDT)
X-Received: by 2002:aca:c003:: with SMTP id q3mr5281845oif.177.1572371422191;
        Tue, 29 Oct 2019 10:50:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572371422; cv=none;
        d=google.com; s=arc-20160816;
        b=guXZSyabBV2b6TL0qCNonF1dmzlkl2f5uan68aDQ2dTxAd9r9x07u8s+dVxYr27ZY7
         /zK3eYWtdN9ndqMyXWn/azmoeghi45mBB+4x5M/HFMaYZMhLIQkeHrtfFUfsg+Z+M4c6
         2yvxOOqlkLrand81qniVvac4P/f+gFQhvyxMgKy5RCepVnv/qsgAtkOCvjbBgtJAh+7/
         hNgxa/Ey/J5NhphK+uEs5KUkK5aLAf860yhuRDa1sJkigYDRiXpkxG0M3PG3jd+voz4E
         wzC5KnRp81i3p40h2lqGTIc3ClMP5aTnTNU3Bqr33gdexHhHO6tgGJj6qH4tKVdznqxj
         UB0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fmMddgqe/zb0sEYHSbXlOXxTKS7tgsQKFOtlLEuJ5V0=;
        b=SwPECoesRkLUWZQe8gLV0liARqdRdzADACXTGJKtYion1XfCLx9Mno8gkjkrfkNqmX
         pD2mij3B57zfIaivgfaSz3ZLWXhGmKLZRiMvQv1J5gTVjDkkEjUpKh1pKW0pYy18D5T+
         cpQRNUrjLCAckocHusSGSWGZcA8zqf6f+sjplWVZpmBrM4cDJh1tihnxIEO+Dye56OAO
         sWyr8PpTw8IPDD5RuDud+qxAYLq6kwcZIxSsKxrxY+6e+Sgkzj6NQby6uwhcE7kDvypW
         CZN4echlG50LLW0lYTzuj++yr84UV5szpsvPN5krWU/7SWZgIXIDwJIAqsXfnn1sQKtA
         Inrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ejqJimG8;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id n63si770850oib.3.2019.10.29.10.50.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Oct 2019 10:50:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id q26so6456010pfn.11
        for <kasan-dev@googlegroups.com>; Tue, 29 Oct 2019 10:50:22 -0700 (PDT)
X-Received: by 2002:a63:541e:: with SMTP id i30mr28747681pgb.130.1572371420847;
 Tue, 29 Oct 2019 10:50:20 -0700 (PDT)
MIME-Version: 1.0
References: <15b7c818-1080-c093-1f41-abd5d78a8013@arm.com> <CAAeHK+zbMhErcEo66w6ZH45A3XUH_joUmimOa2RL1t1Q6AV_PQ@mail.gmail.com>
 <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com>
In-Reply-To: <6f9fdf16-33fc-3423-555b-56059925c2b6@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Oct 2019 18:50:09 +0100
Message-ID: <CAAeHK+yP2vK06tnx2p=NT8cD_qz_gV_xkuPZ40b2OAe+zxM-EA@mail.gmail.com>
Subject: Re: Makefile kernel address tag sanitizer.
To: Matthew Malcomson <Matthew.Malcomson@arm.com>
Cc: "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, nd <nd@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ejqJimG8;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
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

On Tue, Oct 29, 2019 at 6:45 PM Matthew Malcomson
<Matthew.Malcomson@arm.com> wrote:
>
> Hi Andrey,

Hi Matthew,

>
> Thanks for the clarification on that bit, could I ask another question?
>
> I seem to have non-stack compiling with GCC running ok, but would like
> to have some better testing than I've managed so far.

Great! =)

>
> I'm running on an instrumented kernel, but haven't seen a crash yet.
>
> Is there a KASAN testsuite to run somewhere so I can proove that bad
> accesses would be caught?

Kind of. There's CONFIG_TEST_KASAN which produces lib/test_kasan.ko,
which you can insmod and it will do all kinds of bad accesses.
Unfortunately there's no automated checker for it, so you'll need to
look through the reports manually and check if they make sense.

Thanks!

>
> Cheers,
> Matthew
>
> On 16/10/19 14:47, Andrey Konovalov wrote:
> > On Wed, Oct 16, 2019 at 3:12 PM Matthew Malcomson
> > <Matthew.Malcomson@arm.com> wrote:
> >>
> >> Hello,
> >>
> >> If this is the wrong list & person to ask I'd appreciate being shown who
> >> to ask.
> >>
> >> I'm working on implementing hwasan (software tagging address sanitizer)
> >> for GCC (most recent upstream version here
> >> https://gcc.gnu.org/ml/gcc-patches/2019-09/msg00387.html).
> >>
> >> I have a working implementation of hwasan for userspace and am now
> >> looking at trying CONFIG_KASAN_SW_TAGS compiled with gcc (only with
> >> CONFIG_KASAN_OUTLINE for now).
> >>
> >> I notice the current scripts/Makefile.kasan hard-codes the parameter
> >> `-mllvm -hwasan-instrument-stack=0` to avoid instrumenting stack
> >> variables, and found an email mentioning that stack instrumentation is
> >> not yet supported.
> >> https://lore.kernel.org/linux-arm-kernel/cover.1544099024.git.andreyknvl@google.com/
> >>
> >>
> >> What is the support that to be added for stack instrumentation?
> >
> > Hi Matthew,
> >
> > The plan was to upstream tag-based KASAN without stack instrumentation
> > first, and then enable stack instrumentation as a separate effort. I
> > didn't yet get to this last part. I remember when I tried enabling
> > stack instrumentation I was getting what looked like false-positive
> > reports coming from the printk related code. I didn't investigate them
> > though. It's possible that some tweaks to the runtime implementation
> > will be required.
> >
> > Thanks!
> >
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByP2vK06tnx2p%3DNT8cD_qz_gV_xkuPZ40b2OAe%2BzxM-EA%40mail.gmail.com.
