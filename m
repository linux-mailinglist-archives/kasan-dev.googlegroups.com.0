Return-Path: <kasan-dev+bncBCMIZB7QWENRBEUFSTWAKGQEFV2DBMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AA36B95F1
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 18:47:16 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id i28sf5061214pfq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 09:47:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568998034; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ds2DrHZ/naQbmMIzuaO/eSAuEYLZ2VAYGoCKp8ilKg+R73cXr2CwqV8Y4ElPwoNfRJ
         hFkTn9wVm69enaakP476QP9L6Pmt6DUdBwvEVBxPPK5VDHAJ9iggLm9lwBp6QOiYsbfR
         qrS36/zbr3jGXSNib2Fd5IJYEhtyuAIUChKvcJFOO8YQwvmrr9Jaf0cAmo4ibtH6VvMD
         QPNVElzKRuJzB2uLKH7GDYvMXXNAs/XZs5TIhauLuEm6xZjg3kJZ22o4+lRuaAPOcywb
         JSuni3mYSJgJKZc7sTIldoeJFv3Owf8IktnK8W1A743ixzXcBHHcPfMFhCW7kwHhodOV
         qpdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=o26O/UgYuEBNqoHEFa4KwhHR+4j2JadFYId5NS2/RO0=;
        b=Tzq/Er8imok4oGLaRY9ICbMW7bI91+b4yUMo2O8coiaNe7o3nDwDllf0AwHiFtYR2J
         Mmw2a9HXN0+ScPSfEw+nhSFGa0DO+1k8Iec1m0EXcgV7JA4u/T7h+KQuOcEEviCYzcgT
         PXpd4SbCJqVj9dmaOkFncZyzk9eQqkuCqlagjMn78WUZE6dfKlYAy72J+9066h4Tq2uw
         gPQv1Ln5q8QjnwIlAi23b3t4nL7W5WPM+dmpvELvP1jV8Rd+ixypmFz6vHn5Iv5bxkC0
         u0OmEJQTiiaRzJGMCZ9WYhRQs6tqfysjaj2tC1CksOHjuYzf9AI7zIawmD44tHHS0aT9
         c+vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kTf1z///";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o26O/UgYuEBNqoHEFa4KwhHR+4j2JadFYId5NS2/RO0=;
        b=hn4HgtM06Bfx2rQUkvyaF6eS85nWMZ865B6kCkQ9uQzIYYcmuDhH2rHFr3cQc4IE44
         DzzkbtaWbfVbyFrU7G6ocja3luyDdt3MuTK5vwdJ4LhNEgWoHFdJ4r+3B74ktp8KdgRT
         oGPjNIU9tWAQqjEua5gv8ahuabY4coJMNUpYhwpucUCMoHnpGFomajYEZo4POc5FQQSU
         2O8r48dz7kX7dXHC/WBaI0/ErRCuIrJlZVZSWn9Bf6bFCTHqmGCwwQLKYKeMzBFvMJoR
         0JZPIZRP0N/UcmhNth/6yx1r7g7GC3ace/r2Q723waLKw+DEBSuGcou28HBLHCD3t9zZ
         w7/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o26O/UgYuEBNqoHEFa4KwhHR+4j2JadFYId5NS2/RO0=;
        b=f+u8tE4CxSYRVXxqa0nhlrE+znzzBPBeUEm3Ou4QHb9R7kGmF64UOYfEgHPw2jxePb
         ZJkRsHcDb/gj0TuuGNa0DhLjR4442ddXsQQzQo5rEziC4BwwVYZ2XoumiGwgnwQpIJGz
         QJQKxXDoCwPVG5BfDTgFvZRMEynwaW5VFb57O0SYMF+pp75xP0tD+5CrmubheZarQz3R
         YwS/tKTGQB4shUHIAq++x4pbvDTB0SV8tGv+faX/k6BHEdzAq8/ly8m42WeKhd+ubReu
         /P/CBxESUeCBPozBz25wK0hCwBv0lSyGQVeJ6ljYmXyefXemvfi+pSBeMslwoVFWiE86
         SNSg==
X-Gm-Message-State: APjAAAUYRf7tuEJFXpgn3m7WXtAJzUMutoCg1tsrT71jzATxFQ2T4Fw0
	PlogkE/aDf/I1ivLunqGwV4=
X-Google-Smtp-Source: APXvYqymS5UEsuRUAd5tJN/XdqFg/a4ponG+wtexhVE5umn8hT7INM4+cLuw2dMpDtltFiZ37pLtIA==
X-Received: by 2002:a17:90a:c218:: with SMTP id e24mr5673922pjt.97.1568998034591;
        Fri, 20 Sep 2019 09:47:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a8c:: with SMTP id x12ls778051pjn.5.gmail; Fri, 20
 Sep 2019 09:47:14 -0700 (PDT)
X-Received: by 2002:a17:90a:cf93:: with SMTP id i19mr5975096pju.72.1568998034260;
        Fri, 20 Sep 2019 09:47:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568998034; cv=none;
        d=google.com; s=arc-20160816;
        b=fHnm2JfFb+JoK96a0R+NV1ihPOViShV1uc2ugr9CwdkUy1gROH7m3EJcx38AarP0AC
         iOgyNz6epjYSNq//bb8jHBGg2OiX2J9tUO24+Qeg+2QHgw8it3Tm+1yKljQtXOVNExc4
         9JuOdiHzo/M3T+OmFf31t3XjyKwNlHkRHUqdEy+env8v5EOdO/SUE1P4TxDSy6FiP6zb
         3fvNt3SQVbHLVE8+ejzzuhXYg7BoeTsCEzbMdwuxpSaQs/wyJgCBo0murkCVBblwDroN
         IRuDBJkgP3BSBB1RVlZjBFuh7NxFQiBwTEkJDX31hhdeRmo4SKaCOrGfKpkPNNqFhETa
         8Jjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c57hxFA67fRRdSaSzWfUzlK33jYXyRtls9vYGbs8yPA=;
        b=oC9uVlYkVmj5WhwKFEt7zfwoddkctFpRgKNCV8fRVEgH/4etuwchA8c8ToANv8ljIP
         py/h5l2WpLNA15FennhCSIlVaRgZZVuVpLpPF7mH6yBnX2CNhlAmByZZhbsI+QqH50kL
         bbLvQJmjKkdNUyD3vqbjz34dx/1oScmx0glFfZxkHo3u6Gtak2dnM+Pr4it6Cq8i51ks
         H3CETd+9R/p+g83xvNqCGZFny+jvC0qESwmQEq5iYjE+TihzNmgBbTMpWO+SD9kk6Y56
         60Vy8jfmwPhlaGwNuqKKg/1cpXi8mFVh0awXsG53JpfUD5EAV/93yCbXs+u+7L8DUNNf
         yUGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kTf1z///";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id t22si108838pjy.1.2019.09.20.09.47.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2019 09:47:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id u40so9364067qth.11
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2019 09:47:14 -0700 (PDT)
X-Received: by 2002:ac8:7646:: with SMTP id i6mr4420523qtr.50.1568998033153;
 Fri, 20 Sep 2019 09:47:13 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920163123.GC55224@lakrids.cambridge.arm.com>
In-Reply-To: <20190920163123.GC55224@lakrids.cambridge.arm.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Sep 2019 18:46:53 +0200
Message-ID: <CACT4Y+ZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Mark Rutland <mark.rutland@arm.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="kTf1z///";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Sep 20, 2019 at 6:31 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > Hi all,
>
> Hi,
>
> > We would like to share a new data-race detector for the Linux kernel:
> > Kernel Concurrency Sanitizer (KCSAN) --
> > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
>
> Nice!
>
> BTW kcsan_atomic_next() is missing a stub definition in <linux/kcsan.h>
> when !CONFIG_KCSAN:
>
> https://github.com/google/ktsan/commit/a22a093a0f0d0b582c82cdbac4f133a3f61d207c#diff-19d7c475b4b92aab8ba440415ab786ec
>
> ... and I think the kcsan_{begin,end}_atomic() stubs need to be static
> inline too.
>
> It looks like this is easy enough to enable on arm64, with the only real
> special case being secondary_start_kernel() which we might want to
> refactor to allow some portions to be instrumented.
>
> I pushed the trivial patches I needed to get arm64 booting to my arm64/kcsan
> branch:
>
>   git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan
>
> We have some interesting splats at boot time in stop_machine, which
> don't seem to have been hit/fixed on x86 yet in the kcsan-with-fixes
> branch, e.g.
>
> [    0.237939] ==================================================================
> [    0.239431] BUG: KCSAN: data-race in multi_cpu_stop+0xa8/0x198 and set_state+0x80/0xb0
> [    0.241189]
> [    0.241606] write to 0xffff00001003bd00 of 4 bytes by task 24 on cpu 3:
> [    0.243435]  set_state+0x80/0xb0
> [    0.244328]  multi_cpu_stop+0x16c/0x198
> [    0.245406]  cpu_stopper_thread+0x170/0x298
> [    0.246565]  smpboot_thread_fn+0x40c/0x560
> [    0.247696]  kthread+0x1a8/0x1b0
> [    0.248586]  ret_from_fork+0x10/0x18
> [    0.249589]
> [    0.250006] read to 0xffff00001003bd00 of 4 bytes by task 14 on cpu 1:
> [    0.251804]  multi_cpu_stop+0xa8/0x198
> [    0.252851]  cpu_stopper_thread+0x170/0x298
> [    0.254008]  smpboot_thread_fn+0x40c/0x560
> [    0.255135]  kthread+0x1a8/0x1b0
> [    0.256027]  ret_from_fork+0x10/0x18
> [    0.257036]
> [    0.257449] Reported by Kernel Concurrency Sanitizer on:
> [    0.258918] CPU: 1 PID: 14 Comm: migration/1 Not tainted 5.3.0-00007-g67ab35a199f4-dirty #3
> [    0.261241] Hardware name: linux,dummy-virt (DT)
> [    0.262517] ==================================================================
>
> > To those of you who we mentioned at LPC that we're working on a
> > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > renamed it to KCSAN to avoid confusion with KTSAN).
> > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> >
> > In the coming weeks we're planning to:
> > * Set up a syzkaller instance.
> > * Share the dashboard so that you can see the races that are found.
> > * Attempt to send fixes for some races upstream (if you find that the
> > kcsan-with-fixes branch contains an important fix, please feel free to
> > point it out and we'll prioritize that).
> >
> > There are a few open questions:
> > * The big one: most of the reported races are due to unmarked
> > accesses; prioritization or pruning of races to focus initial efforts
> > to fix races might be required. Comments on how best to proceed are
> > welcome. We're aware that these are issues that have recently received
> > attention in the context of the LKMM
> > (https://lwn.net/Articles/793253/).
>
> I think the big risk here is drive-by "fixes" masking the warnings
> rather than fixing the actual issue. It's easy for people to suppress a
> warning with {READ,WRITE}_ONCE(), so they're liable to do that even the
> resulting race isn't benign.
>
> I don't have a clue how to prevent that, though.

I think this is mostly orthogonal problem. E.g. for some syzbot bugs I
see fixes that also try to simply "shut up" the immediate
manifestation with whatever means, e.g. sprinkling some slinlocks. So
(1) it's not unique to atomics, (2) presence of READ/WRITE_ONCE will
make the reader aware of the fact that this runs concurrently with
something else, and then they may ask themselves why this runs
concurrently with something when the object is supposed to be private
to the thread, and then maybe they re-fix it properly. Whereas if it's
completely unmarked, nobody will even notice that this code accesses
the object concurrently with other code. So even if READ/WRITE_ONCE
was a wrong fix, it's still better to have it rather than not.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA%40mail.gmail.com.
