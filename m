Return-Path: <kasan-dev+bncBC7OBJGL2MHBB47CX3XAKGQEBQF3HBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 122A1FEB3D
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 09:21:09 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id w9sf5604854otj.22
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Nov 2019 00:21:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573892467; cv=pass;
        d=google.com; s=arc-20160816;
        b=vI127inFhAT7sAT0fRh3eTX4isbf7gBBAbAS7lKv5x+qt37HCXxQYMxNt0yrSud7kt
         fonTURBOSh2R9THP1KzsF4ahOKOEuhlAOJv3DdaAPaM/K8oi69pK5Jl7/wR1mfwYf3Vh
         Lme2qELSwTe+1C2k7RQCu/vKxl7mSvVLHDKeYGNbiveqSzO7IjY4zhFiKGMUVKv7n/ik
         ifcXsurKO8rtsrx5AlmEKDwBJPlP3goi413WGQ2a8wW7nynuOIlzHHXZHd5dF3pF8noD
         QjJaOheMpQzFB3tRtiRCX1QYwhGB4+TZorQV9+/AFMdGz8v50IzqxgZYLm+yvKw/QJF8
         xvcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iRY7sWgM+K9nngwH3XIAfeNOhrIG0wKkGN2t7ZPco7s=;
        b=e8oB1uVO3BXU2fnzrz8WfiFgSkdDDCmLyJ9XwccEFFYKWliNpwuVQD36oJn5ipYaX3
         NEDUsDED+l7NTAXNpdw0w5T2lG8FpkPQkQdNqJrmN4OTh2uwI62MviFbDOaJY0L1mGrC
         TH1wKDC9yCV4Fvi974c9/aFMoyLd5H4HlWObckjRSy7Gw9KCY2Cv3zFwCDkOOxvFJJhA
         orurGxMfAu+vO0K8OU+kW1bCHszi87R+Z+99CoBDySBgFnYsRpMq/q+J1W0yb4uSpFQb
         dH67ORw7YsPY++vpxJnXL5NY9eHtbVrYrhNyRtCcyhrYDU8wWa8IkvMOXc1WK9ogF27p
         pLeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XWnuclkq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iRY7sWgM+K9nngwH3XIAfeNOhrIG0wKkGN2t7ZPco7s=;
        b=LIqXPfI2hBR5WRI6LblfROqExb5GSveCrZXietQwdfKA+0bpF0X4rY056R/KlF4trG
         3woCqTSZqvZBRq8ppn/W5kXMFo04+n6Xvq0yXRXjMAvQlEwdc75kY3rsRAQc7sZ3Vs6c
         t4FFNFdB6iXfNf3SPyYE0LQep0NBbwP1AZaFuqhSxglmDRtiNgYa0PP23PdYdEwgEmGL
         8v+Lb8WvZh5fsW/u01xELtDcNSdZRhwTjlPv8S+Ik8xtslGCoIK15voFvOiDTinzdybo
         bJWzrAxem7koULQ/B0VNTLfYewhnHwVRA3MHHdaviv/8q2e4Ywp4CdSczDSamYoA/HZg
         TT8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iRY7sWgM+K9nngwH3XIAfeNOhrIG0wKkGN2t7ZPco7s=;
        b=QRJPndkUlIz1f7jWW4iR/Bgp7gEt2lMMK+odcJXAw1LKN2rk2FRosXIMyGUHXLOKYO
         mHRKT3juVJjOsLjl3qtPjFJj0B/3yf1EAS787/jyhSG44/eAaAGPV3YFMq3i6Z2ZuzY7
         N6lNWw94JcxLluyb/WlHeQ6zm+LRxKmHGLJ7Oc/hV+yKg8oghqsAwBdGLHqMfo9/MRCc
         ujoIWPvsCfazplmNRCiJZH3tQzuxvXD916JVJRjZ3Ke/rIy4sL6aArRi/2Jb8Gd5jcvT
         sP3S5610aejQyU8KPaci1sCe2ZTl1TAjCSA5h0+/BvsTEA4HDJTwR6qkcnFIEYpTzqn9
         u8LQ==
X-Gm-Message-State: APjAAAX+D7SCg9pzVvsgiV1V1LAaS9mBFLDlocujzSo1D766KWJJGdnE
	s7yjc8FAglgpSMDvu4rfNEE=
X-Google-Smtp-Source: APXvYqxotpLQzwA3vLB7WfI5jg1urPRyg+qHhsWXYriOlhyGor16LGiLpz9FjulsrqDmiKXPOpRAQQ==
X-Received: by 2002:a54:4783:: with SMTP id o3mr4907513oic.33.1573892467357;
        Sat, 16 Nov 2019 00:21:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:410f:: with SMTP id l15ls3523756oic.4.gmail; Sat, 16 Nov
 2019 00:21:07 -0800 (PST)
X-Received: by 2002:aca:f0c1:: with SMTP id o184mr11612767oih.2.1573892466968;
        Sat, 16 Nov 2019 00:21:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573892466; cv=none;
        d=google.com; s=arc-20160816;
        b=r4wbt9PHwnDf/LruU2dqjcGk9AWWVY4W+y8qtmjjkuC/qppsABmZ3/Vj+tMNnXprQ8
         EgaJks/OY3aBB6rY2KbRQGHots4IEybf5+xdr8l00NMHhkrViH+HtYq4UDkWbrdrnvpF
         5GtPOZImE1EaNJQ1vk7YhIIGoXuM9l8AOgSaAJaPJ+tE6Zv4hcTBDgBjCk3BenUowKp+
         J7Sdq4JeWhn+Q8JRn+TLu9+vV1luFM3XAjsGjS7dYgdWDNx5UZTaKDCuxAsS3mNGKRk1
         VNedaCWYKfG50nTiqIvcqAprLXjFotDdJiNGVGhP7NCkYnMVoSktXosMFUSyJmaOd0Bg
         DKdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IAbPck/tyWYpcH6q1DqU0wF9VrcqMWHjsvfsasMdJQ8=;
        b=afv36+EEoByFpQLib0+NOlLEJvJ5M/FmxbVPPzsnRROyOyQopyOpiwTb9Cn2P1mm3E
         jZ+xaGqSCfS+M3SXkDodvGD/Qu5qqUhHsooJ9OesVHgXhXZGyr1x8diq2IKHteh8gLgR
         z7t5b+zTwLTGmAiULX51+9yHRwqi63i5ILoJnRdsIDc+zpMVSpDT5c+1kEvD+nriwDmU
         ir75rVR85t3/K/94VdO7J5n1XwmFO0E/H1URINHUj6c/4OxrWgw1r0skOxtZZJ8C70BQ
         lQWuyrJgAhaXQ3qv70T/boxKGONjR+JBoKqeQn+++78bibgac3h4vUEQt8W+ugdTiA6I
         ZNfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XWnuclkq;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id p16si814275ota.3.2019.11.16.00.21.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Nov 2019 00:21:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id m15so10113562otq.7
        for <kasan-dev@googlegroups.com>; Sat, 16 Nov 2019 00:21:06 -0800 (PST)
X-Received: by 2002:a9d:3d76:: with SMTP id a109mr14975357otc.233.1573892466111;
 Sat, 16 Nov 2019 00:21:06 -0800 (PST)
MIME-Version: 1.0
References: <20191114180303.66955-1-elver@google.com> <20191114195046.GP2865@paulmck-ThinkPad-P72>
 <20191114213303.GA237245@google.com> <20191114221559.GS2865@paulmck-ThinkPad-P72>
 <CANpmjNPxAOUAxXHd9tka5gCjR_rNKmBk+k5UzRsXT0a0CtNorw@mail.gmail.com>
 <20191115164159.GU2865@paulmck-ThinkPad-P72> <CANpmjNPy2RDBUhV-j-APzwYr-_x2V9QwgPTYZph36rCpEVqZSQ@mail.gmail.com>
 <20191115204321.GX2865@paulmck-ThinkPad-P72>
In-Reply-To: <20191115204321.GX2865@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 16 Nov 2019 09:20:54 +0100
Message-ID: <CANpmjNN0JCgEOC=AhKN7pH9OpmzbNB94mioP0FN9ueCQUfKzBQ@mail.gmail.com>
Subject: Re: [PATCH v4 00/10] Add Kernel Concurrency Sanitizer (KCSAN)
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Alexander Potapenko <glider@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, Arnd Bergmann <arnd@arndb.de>, 
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>, 
	Daniel Lustig <dlustig@nvidia.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	David Howells <dhowells@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Luc Maranget <luc.maranget@inria.fr>, 
	Mark Rutland <mark.rutland@arm.com>, Nicholas Piggin <npiggin@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XWnuclkq;       spf=pass
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

On Fri, 15 Nov 2019 at 21:43, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Fri, Nov 15, 2019 at 06:14:46PM +0100, Marco Elver wrote:
> > On Fri, 15 Nov 2019 at 17:42, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Fri, Nov 15, 2019 at 01:02:08PM +0100, Marco Elver wrote:
> > > > On Thu, 14 Nov 2019 at 23:16, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > On Thu, Nov 14, 2019 at 10:33:03PM +0100, Marco Elver wrote:
> > > > > > On Thu, 14 Nov 2019, Paul E. McKenney wrote:
> > > > > >
> > > > > > > On Thu, Nov 14, 2019 at 07:02:53PM +0100, Marco Elver wrote:
> > > > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > > > KCSAN is a sampling watchpoint-based *data race detector*. More details
> > > > > > > > are included in **Documentation/dev-tools/kcsan.rst**. This patch-series
> > > > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > > > architectures is relatively straightforward (we are aware of
> > > > > > > > experimental ARM64 and POWER support).
> > > > > > > >
> > > > > > > > To gather early feedback, we announced KCSAN back in September, and have
> > > > > > > > integrated the feedback where possible:
> > > > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > > > >
> > > > > > > > The current list of known upstream fixes for data races found by KCSAN
> > > > > > > > can be found here:
> > > > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > > > > >
> > > > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > > > including several articles that motivate why data races are dangerous
> > > > > > > > [1, 2], justifying a data race detector such as KCSAN.
> > > > > > > >
> > > > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > > > [2] https://lwn.net/Articles/799218/
> > > > > > >
> > > > > > > I queued this and ran a quick rcutorture on it, which completed
> > > > > > > successfully with quite a few reports.
> > > > > >
> > > > > > Great. Many thanks for queuing this in -rcu. And regarding merge window
> > > > > > you mentioned, we're fine with your assumption to targeting the next
> > > > > > (v5.6) merge window.
> > > > > >
> > > > > > I've just had a look at linux-next to check what a future rebase
> > > > > > requires:
> > > > > >
> > > > > > - There is a change in lib/Kconfig.debug and moving KCSAN to the
> > > > > >   "Generic Kernel Debugging Instruments" section seems appropriate.
> > > > > > - bitops-instrumented.h was removed and split into 3 files, and needs
> > > > > >   re-inserting the instrumentation into the right places.
> > > > > >
> > > > > > Otherwise there are no issues. Let me know what you recommend.
> > > > >
> > > > > Sounds good!
> > > > >
> > > > > I will be rebasing onto v5.5-rc1 shortly after it comes out.  My usual
> > > > > approach is to fix any conflicts during that rebasing operation.
> > > > > Does that make sense, or would you prefer to send me a rebased stack at
> > > > > that point?  Either way is fine for me.
> > > >
> > > > That's fine with me, thanks!  To avoid too much additional churn on
> > > > your end, I just replied to the bitops patch with a version that will
> > > > apply with the change to bitops-instrumented infrastructure.
> > >
> > > My first thought was to replace 8/10 of the previous version of your
> > > patch in -rcu (047ca266cfab "asm-generic, kcsan: Add KCSAN instrumentation
> > > for bitops"), but this does not apply.  So I am guessing that I instead
> > > do this substitution when a rebase onto -rc1..
> > >
> > > Except...
> > >
> > > > Also considering the merge window, we had a discussion and there are
> > > > some arguments for targeting the v5.5 merge window:
> > > > - we'd unblock ARM and POWER ports;
> > > > - we'd unblock people wanting to use the data_race macro;
> > > > - we'd unblock syzbot just tracking upstream;
> > > > Unless there are strong reasons to not target v5.5, I leave it to you
> > > > if you think it's appropriate.
> > >
> > > My normal process is to send the pull request shortly after -rc5 comes
> > > out, but you do call out some benefits of getting it in sooner, so...
> > >
> > > What I will do is to rebase your series onto (say) -rc7, test it, and
> > > see about an RFC pull request.
> > >
> > > One possible complication is the new 8/10 patch.  But maybe it will
> > > apply against -rc7?
> > >
> > > Another possible complication is this:
> > >
> > > scripts/kconfig/conf  --syncconfig Kconfig
> > > *
> > > * Restart config...
> > > *
> > > *
> > > * KCSAN: watchpoint-based dynamic data race detector
> > > *
> > > KCSAN: watchpoint-based dynamic data race detector (KCSAN) [N/y/?] (NEW)
> > >
> > > Might be OK in this case because it is quite obvious what it is doing.
> > > (Avoiding pain from this is the reason that CONFIG_RCU_EXPERT exists.)
> > >
> > > But I will just mention this in the pull request.
> > >
> > > If there is a -rc8, there is of course a higher probability of making it
> > > into the next merge window.
> > >
> > > Fair enough?
> >
> > Totally fine with that, sounds like a good plan, thanks!
> >
> > If it helps, in theory we can also drop and delay the bitops
> > instrumentation patch until the new bitops instrumentation
> > infrastructure is in 5.5-rc1. There won't be any false positives if
> > this is missing, we might just miss a few data races until we have it.
>
> That sounds advisable for an attempt to hit this coming merge window.
>
> So just to make sure I understand, I drop 8/10 and keep the rest during
> a rebase to 5.4-rc7, correct?

Yes, that's right.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN0JCgEOC%3DAhKN7pH9OpmzbNB94mioP0FN9ueCQUfKzBQ%40mail.gmail.com.
