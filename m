Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFNDSTWAKGQENVS5THI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 694AEB96BF
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 19:51:18 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id z13sf5186221pfr.15
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2019 10:51:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569001877; cv=pass;
        d=google.com; s=arc-20160816;
        b=0L3M6fU230dMW4+UH3aKyjBfStoMcgs0F/JsTFzrpqr8TBmwuQTJgKxUQjeh+ZhxBz
         z3cn8gPgT5Z59usWK9ZpCugA3TFFsqPANn7w8CQR/m1uN7+MAsNj3bmrOnoyISZL+lkN
         +NZE+CnIFLlYBQNi8bIO3zvCECrQwpSIDRPFeKpg6Tst65Mmb4Zr7gxN3imhBJs/u2cT
         wmMsXip+zQDEt8PenkFkarePDMS8KdPMsby7Kf1V7PF4tPRvbRn7PiBELNiE3FtZ0lEH
         hRTt+DK+cNNzay8KNXd5ykGGqDQb8O0+RJf3uGJGUmaMd5T/EOoq1jwuE5avpGSv4GPC
         rwhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/5v4/0ZB3K0ANB77NYPSKsxuTurMgI8YQUNwfzzWKWE=;
        b=JU2/0gwaSiNHVvwAUOBrfoA5WJe0nwy8WjlNyS4t32VOWPVNmsQRfNh8ej23GcvEFX
         DP94O87ZcI1rxGaO4Csdf05VUiN4j/6U5kptp3aE3RTLMYELMFQbnt1RzQvX+ImDJhuH
         gKTpmOJtXpUuruUG/zXjlxeITGBUaUhGgOLtJrjIOG1cqFfA11JWFWqRrAX5cQCyTs6U
         pBvmkHuqBa1gEcVYjAjMs9/EyRG2mDxv01nPOyg7gagbVTnrn4bhBhQuf8Y3JhaeePwJ
         3/wta4avgF2sSUEHwnoFLYp29PyU01xi7gg2p6ag/IAqoMAa1QMte6YVcanXaBYwkIxA
         qywQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UEgIQlBP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/5v4/0ZB3K0ANB77NYPSKsxuTurMgI8YQUNwfzzWKWE=;
        b=QNxgV3chmfrXMdwlNXYIiqPKNp1FyxmJLWWmIU5i47X8vcM0xiddJTNP8HFAg46ii/
         98ScSUIJZ0h05fBoxHdM0n9sM9actzx94wIulH/mOCNzfVMk8u7hK2HURbNq31gmyDc5
         grwJTYeLtqBsSydrSBwzXsFhWQsuzsdK0un0OrK7SRaxMuRpCY0QybMt6SjNmLi22NHA
         KamOLGoeMo36M/XWy0r9OKuRa1VNQxsrkB+u7dCZnYwMsU7gn+uq7PTvK46XFMmzQ4v0
         /HNYgtyxyclri+IlNvewBbsFDnlYOorUfrTRGHy7EGM/UOve2mLyG5W2yjTU7V/qnkQN
         UgBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/5v4/0ZB3K0ANB77NYPSKsxuTurMgI8YQUNwfzzWKWE=;
        b=eclzW7LLokmXcBD7oh5Bk++Gq8WBjczmncdG3Fnto21iRT7+QPz1Gem+XX0dm7+oMS
         0BJreNyYuwOyAM5Dv4kUj+9HrsiQN7D9krHziJFHfv7WruACeXXFzbOtqUZM9+5cia+h
         ZbUcUSBLn3rZldRq+nlmDQ0ihuXbSLMRsGfGElN9VoNU8ConTk0mxaTGdMxGfWao2rLo
         vIWremEuTmHGmGtmeDspfatWM9rZOUpo3qf/hogw3eqqoqN4CcTJhkjeqgsUDgWyokHn
         Ch3Rdov7SEp8hAQkTB4w1BZQcJDTJTkv/lrEej8UpYeFDBzCO33IFDtXivmm3Uv8IeRj
         ovnw==
X-Gm-Message-State: APjAAAWaJBdlT80SPkf9f533l0ymU5p9+EfSqmKQgoO2twmIERfNrg+1
	s7q4WAt1no0B4r+XylZhnRs=
X-Google-Smtp-Source: APXvYqwQrV0EhTd7MIsSKEC9qYyu+RVJXt8rl8kV1OAGd0m1oLnebLb7s3MIdqilT1glsaiyVn3FQQ==
X-Received: by 2002:a62:32c5:: with SMTP id y188mr18400289pfy.97.1569001877093;
        Fri, 20 Sep 2019 10:51:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls2190380pfb.2.gmail; Fri, 20 Sep
 2019 10:51:16 -0700 (PDT)
X-Received: by 2002:a62:fb06:: with SMTP id x6mr11466738pfm.186.1569001876725;
        Fri, 20 Sep 2019 10:51:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569001876; cv=none;
        d=google.com; s=arc-20160816;
        b=g9gIgWS09a9PS4viUy6DXu2dYvrX/AUKh985eum66tS3V5zRLhSQcvNlSVIP++7n4/
         29T7l3/a6f3+V6+HE+yIhr17C9OqRHnnHvv+Ddcoe9R2CCDIpta4DAP9vOxBLuGB+4nW
         wsid96XMr+FFKUmdwwNYdLv7b4I9J8QCYp7bZ5wNjNBJ54oqQfcZOuNsvvyXrZcUBKtE
         IdwALZymU85duH5vVCv6lmO+GssHb2WVohVXHFvolVM9QXSn/HHA8RlIWglJlKnH3ZG4
         cGIzRcE5e/smRWfIPHp4riew1RmXYBtCiagUpepVg1fEZKKebLIoiI+RojxkXGbjk7u5
         5vgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eTz6yzxiFyHtcxZo7L97GNHOGY6QY7O6TNCJQilZlzU=;
        b=NqZkWoiyVZlaXJ8B2G+//yXhfYtfES+pQfNmsef0/ORQAu3lbDgqUPGoC6TGRKucif
         LDDrqKr+ZtmWFC5xNnSnl6tiSjrFvZVEuyoMBOHfjB+zHNvB5d3ASb4Riow4FglaCfCa
         DCY2ZWC7tk4wyeustV5SnJ+yOYXfZk4URBzMsfNbp10mT4BA9ygg5zxGNjo/FHxcgSp+
         XFwDeEDfAvct65MTimgugxA6wk2uyFCAaURMxfEcd5yfTFJGbPmFzv8dPg13h4qNDeVL
         Vj3NleBY2g9wT5wjDEy6yGULdD2zoDZ6J0kzcZTUL9EMQvUCsY7bKb5xFoqxJ6YMtfiN
         B8KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UEgIQlBP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id d8si193724pjv.1.2019.09.20.10.51.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 20 Sep 2019 10:51:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id w6so2456439oie.11
        for <kasan-dev@googlegroups.com>; Fri, 20 Sep 2019 10:51:16 -0700 (PDT)
X-Received: by 2002:aca:5510:: with SMTP id j16mr4095393oib.121.1569001876015;
 Fri, 20 Sep 2019 10:51:16 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920163123.GC55224@lakrids.cambridge.arm.com> <CACT4Y+ZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA@mail.gmail.com>
In-Reply-To: <CACT4Y+ZwyBhR8pB7jON8eVObCGbJ54L8Sbz6Wfmy3foHkPb_fA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 20 Sep 2019 19:51:04 +0200
Message-ID: <CANpmjNM+aEzySwuMDkEvsVaeTooxExuTRAv-nzjhp7npT8a3ag@mail.gmail.com>
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, "Paul E. McKenney" <paulmck@linux.ibm.com>, Paul Turner <pjt@google.com>, 
	Daniel Axtens <dja@axtens.net>, Anatol Pomazau <anatol@google.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Daniel Lustig <dlustig@nvidia.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
	Luc Maranget <luc.maranget@inria.fr>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UEgIQlBP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Fri, 20 Sep 2019 at 18:47, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Sep 20, 2019 at 6:31 PM Mark Rutland <mark.rutland@arm.com> wrote:
> >
> > On Fri, Sep 20, 2019 at 04:18:57PM +0200, Marco Elver wrote:
> > > We would like to share a new data-race detector for the Linux kernel:
> > > Kernel Concurrency Sanitizer (KCSAN) --
> > > https://github.com/google/ktsan/wiki/KCSAN  (Details:
> > > https://github.com/google/ktsan/blob/kcsan/Documentation/dev-tools/kcsan.rst)
> >
> > Nice!
> >
> > BTW kcsan_atomic_next() is missing a stub definition in <linux/kcsan.h>
> > when !CONFIG_KCSAN:
> >
> > https://github.com/google/ktsan/commit/a22a093a0f0d0b582c82cdbac4f133a3f61d207c#diff-19d7c475b4b92aab8ba440415ab786ec
> >
> > ... and I think the kcsan_{begin,end}_atomic() stubs need to be static
> > inline too.

Thanks for catching, fixed and pushed. Feel free to rebase your arm64 branch.

> > It looks like this is easy enough to enable on arm64, with the only real
> > special case being secondary_start_kernel() which we might want to
> > refactor to allow some portions to be instrumented.
> >
> > I pushed the trivial patches I needed to get arm64 booting to my arm64/kcsan
> > branch:
> >
> >   git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan

Cool, thanks for testing!

> > We have some interesting splats at boot time in stop_machine, which
> > don't seem to have been hit/fixed on x86 yet in the kcsan-with-fixes
> > branch, e.g.
> >
> > [    0.237939] ==================================================================
> > [    0.239431] BUG: KCSAN: data-race in multi_cpu_stop+0xa8/0x198 and set_state+0x80/0xb0
> > [    0.241189]
> > [    0.241606] write to 0xffff00001003bd00 of 4 bytes by task 24 on cpu 3:
> > [    0.243435]  set_state+0x80/0xb0
> > [    0.244328]  multi_cpu_stop+0x16c/0x198
> > [    0.245406]  cpu_stopper_thread+0x170/0x298
> > [    0.246565]  smpboot_thread_fn+0x40c/0x560
> > [    0.247696]  kthread+0x1a8/0x1b0
> > [    0.248586]  ret_from_fork+0x10/0x18
> > [    0.249589]
> > [    0.250006] read to 0xffff00001003bd00 of 4 bytes by task 14 on cpu 1:
> > [    0.251804]  multi_cpu_stop+0xa8/0x198
> > [    0.252851]  cpu_stopper_thread+0x170/0x298
> > [    0.254008]  smpboot_thread_fn+0x40c/0x560
> > [    0.255135]  kthread+0x1a8/0x1b0
> > [    0.256027]  ret_from_fork+0x10/0x18
> > [    0.257036]
> > [    0.257449] Reported by Kernel Concurrency Sanitizer on:
> > [    0.258918] CPU: 1 PID: 14 Comm: migration/1 Not tainted 5.3.0-00007-g67ab35a199f4-dirty #3
> > [    0.261241] Hardware name: linux,dummy-virt (DT)
> > [    0.262517] ==================================================================>

Thanks, the fixes in -with-fixes were ones I only encountered with
Syzkaller, where I disable KCSAN during boot. I've just added a fix
for this race and pushed to kcsan-with-fixes.

> > > To those of you who we mentioned at LPC that we're working on a
> > > watchpoint-based KTSAN inspired by DataCollider [1], this is it (we
> > > renamed it to KCSAN to avoid confusion with KTSAN).
> > > [1] http://usenix.org/legacy/events/osdi10/tech/full_papers/Erickson.pdf
> > >
> > > In the coming weeks we're planning to:
> > > * Set up a syzkaller instance.
> > > * Share the dashboard so that you can see the races that are found.
> > > * Attempt to send fixes for some races upstream (if you find that the
> > > kcsan-with-fixes branch contains an important fix, please feel free to
> > > point it out and we'll prioritize that).
> > >
> > > There are a few open questions:
> > > * The big one: most of the reported races are due to unmarked
> > > accesses; prioritization or pruning of races to focus initial efforts
> > > to fix races might be required. Comments on how best to proceed are
> > > welcome. We're aware that these are issues that have recently received
> > > attention in the context of the LKMM
> > > (https://lwn.net/Articles/793253/).
> >
> > I think the big risk here is drive-by "fixes" masking the warnings
> > rather than fixing the actual issue. It's easy for people to suppress a
> > warning with {READ,WRITE}_ONCE(), so they're liable to do that even the
> > resulting race isn't benign.
> >
> > I don't have a clue how to prevent that, though.
>
> I think this is mostly orthogonal problem. E.g. for some syzbot bugs I
> see fixes that also try to simply "shut up" the immediate
> manifestation with whatever means, e.g. sprinkling some slinlocks. So
> (1) it's not unique to atomics, (2) presence of READ/WRITE_ONCE will
> make the reader aware of the fact that this runs concurrently with
> something else, and then they may ask themselves why this runs
> concurrently with something when the object is supposed to be private
> to the thread, and then maybe they re-fix it properly. Whereas if it's
> completely unmarked, nobody will even notice that this code accesses
> the object concurrently with other code. So even if READ/WRITE_ONCE
> was a wrong fix, it's still better to have it rather than not.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM%2BaEzySwuMDkEvsVaeTooxExuTRAv-nzjhp7npT8a3ag%40mail.gmail.com.
