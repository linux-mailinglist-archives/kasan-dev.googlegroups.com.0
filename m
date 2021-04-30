Return-Path: <kasan-dev+bncBC7OBJGL2MHBBYVKWGCAMGQECE42AKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC29370100
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 21:07:14 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id o14-20020a5d474e0000b029010298882dadsf25913050wrs.2
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 12:07:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619809634; cv=pass;
        d=google.com; s=arc-20160816;
        b=vXlYa/tiEHVcfMqEE6cCok9oRl0te4hfR6ZerpYFwMBHYzLb9Iz1nQjgPdhyEKSO2A
         YWg87eHny60e6KIdGfFIoS2l02EdE8EC9k5STbnPKntrSB8XapkbJHWymW2HCP+xEs+p
         lSsJwgRXF+qUVA69zt4a8Q0SZzN9jQK3q4vtpTNPQK+RYFeBchv8oDQWTXftI5hlWODD
         ztzy2RAdAjPFZK40f1GpR+v/cejvc+a01bPoqCvjlfUZbeHBKVElGH7vRgfpnSe8JJvV
         lvlPq50navbXHmeAcYvbl2Q5mBTJzVmolbDfV8F0Wzp62qhaB8C5NsEKLEzK+mVb1KwG
         jPpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UplZcKMwAC69iKq9vwHFwzHDNP6kTgF0dRidKRdkvMY=;
        b=s130FU27evrUxhjPRhrY2oLYC9wohWq0cb22b7hvBe/XLNvKj11Xq0HF45eWrr7Jh+
         wDKC8gbKAGmwBi+K8ji3K8z5MPX4ADZNbqwp3H9cthh63JFEIHRPinoCvpZvK5fIaEnq
         ntwOiWN+sy1xfCORM1M+a6VPznsM3PdmHCiJJbloz+TPM6Od9mrSap23fMowS7o0q18D
         hpxjKmDJ60962a4h2OBJTFSbcSkj6eFZNO/r1ccMGnUP/jdn8TO2x2tHbqGYMidrFRFE
         FzaKe7cVWSUWHKv0ImMeZBrhWwaMO8HYqvt0riJSQrBw6A8vAnwUP1P/tgwX6UiUk33G
         LAGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=feNJVQ1R;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UplZcKMwAC69iKq9vwHFwzHDNP6kTgF0dRidKRdkvMY=;
        b=OStCxeWe5rnbwjuAT/vg38J42pFBOzH/fNRjHWe0ajt3jjZ9h49Q4pSsibvfIZ88Dh
         d5o/IJ72xY85n9GGA7qYos/B4FNMMKdjWsa+ZyXPI+6a/75MZUXSs7JDVra3s5EgH2pz
         0LDMKFexA3tjOfmP9qS5XZnQ8zQq8en8N7v+k3j46nqMMft5fGpmH5lJ3PgjOIz9kUTG
         E2/x63WFehhPK4cYLPuT7dTzq3VS/tlOM7Ke2bsaTSYHxbq6bNRHQ1ksJkAf/WSHwurE
         MFY7MDvdoHLJx/4jXhTTWBEjLPPztPqoQYRVsBVbV0ykwKlExCPY26lSqbrFk+POIV/3
         NBpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UplZcKMwAC69iKq9vwHFwzHDNP6kTgF0dRidKRdkvMY=;
        b=GXKcKu9MmTRN6gzB9qoevdbekMPeVfEaSMW25qX2bmu1ozqhcnSUNAd2MXt3vQp6Xz
         O9Ag4YkhNxf90P2qyj4c0LkZdpINTjLWMfsGnrU4w8Ie1p/K5W1jMbgCAlIUgz99KU43
         tOmfRCOmzk/iqHICADYdOA2jTRUkXirTkU570YrjbYaJkOYOJuX/s42G/FBLycvkalzf
         0k9IRSDpZ1Uz0YOt5UONTb5GC3OltMPci+BQ3Qrnxn6K3PxZINIpOtCTj3iBTshPEZ7p
         13e2R/XvPZCTP04oCD7gdZj1VKCMfJBIA3OBk7pGOVJho2XJ48iLT1bazmrkgKRoYqNT
         NORA==
X-Gm-Message-State: AOAM530rojlAPqIbexcM3jOBM6AuN11ZQvkwcdgSIulfP2aOKnIz2ysc
	bAhyjI5FBPw66qnwAUEpgeQ=
X-Google-Smtp-Source: ABdhPJwrKazXMlAD3qPiyvGd2YFmD4FwFX2XegLLlc5ycix+FxIj4O8CNIWqCTXh1wCrwYaq3Y5pMw==
X-Received: by 2002:a5d:6d41:: with SMTP id k1mr9364487wri.66.1619809634615;
        Fri, 30 Apr 2021 12:07:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:24d4:: with SMTP id k203ls6386863wmk.0.canary-gmail;
 Fri, 30 Apr 2021 12:07:13 -0700 (PDT)
X-Received: by 2002:a7b:c0d7:: with SMTP id s23mr7708913wmh.115.1619809633573;
        Fri, 30 Apr 2021 12:07:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619809633; cv=none;
        d=google.com; s=arc-20160816;
        b=otySQkCY1gHB4uHOCSNFlL9z4QDU72n2Oj7zKzRp0zn6BSg6QzFWJlpf9yd+pZJUta
         ysXIzeY1r4hopagIT3kxLNrsS4Zyh5LtLR2EMmoC6yiNNUJ3iOEbXWcstPESwLyd/j8p
         NoMSXSIqsrAuBTcIxwpIqK51dseptIWdCXkVQ38j/uOntveIOxa3oqaZxE4h1e8Wzepx
         11V6cgH8zIPxTh7KasFtUuzqdnHV3fMpRsW3OmFjE2JhWuVCSaKcGW3WIcu0xovVZ69j
         U9N6G5hMsG+GBIA+10D2PcEUJm9QO0D82bgqFBfiS+8yd2RSKrCn/RvM/wgAnju+NBOK
         1OXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QsIOjRVDObuzB3TAj/QUXyHP2hTbDXsiJXpMnud8bTw=;
        b=FpN3wqtM8gYKlZ9bqeKCUxtusY49S77v/RMB1rACs4CQ98iLJDGAQ7AxUxDMHgh62F
         mjDV+gcCNe0a15VZzquTOVoFGwQ4fl/2MzDRTcNvrtsfzQwhq+4fo4ZROESZ3iILOe42
         pGXHY+ftGWY6PoAO7XOZA8zx/mFwwKyQ9zucTAskEj32PrCA2unqW3RJGHWUHaH6G8BM
         uY9jJ1HWHCsNztL8Tq/48YdxsiEwtyN+KyFFyPTT3mEG1xa4+DcB4W38pxgAnKHJ2J88
         o5W0vbY1t77+ZQ1I/27BA0au5uZTfvEaDjrVvnRu3i+DMjdiS4Rkf/yQFAG0d36iDuWf
         /Rdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=feNJVQ1R;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id p65si681295wmp.0.2021.04.30.12.07.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Apr 2021 12:07:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id m5so11622420wmf.1
        for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 12:07:13 -0700 (PDT)
X-Received: by 2002:a1c:545c:: with SMTP id p28mr18332214wmi.118.1619809633033;
        Fri, 30 Apr 2021 12:07:13 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:8eae:7187:8db5:a3e])
        by smtp.gmail.com with ESMTPSA id a9sm3801655wmj.1.2021.04.30.12.07.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 12:07:12 -0700 (PDT)
Date: Fri, 30 Apr 2021 21:07:06 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
Message-ID: <YIxVWkT03TqcJLY3@elver.google.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
 <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <m15z031z0a.fsf@fess.ebiederm.org>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=feNJVQ1R;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32c as
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

On Fri, Apr 30, 2021 at 12:08PM -0500, Eric W. Biederman wrote:
> Arnd Bergmann <arnd@arndb.de> writes:
[...] 
> >> I did a quick search and the architectures that define __ARCH_SI_TRAPNO
> >> are sparc, mips, and alpha.  All have 64bit implementations.  A further
> >> quick search shows that none of those architectures have faults that
> >> use BUS_MCEERR_AR, BUS_MCEERR_AO, SEGV_BNDERR, SEGV_PKUERR, nor do
> >> they appear to use mm/memory-failure.c
> >>
> >> So it doesn't look like we have an ABI regression to fix.
> >
> > Even better!
> >
> > So if sparc is the only user of _trapno and it uses none of the later
> > fields in _sigfault, I wonder if we could take even more liberty at
> > trying to have a slightly saner definition. Can you think of anything that
> > might break if we put _trapno inside of the union along with _perf
> > and _addr_lsb?
> 
> On sparc si_trapno is only set when SIGILL ILL_TRP is set.  So we can
> limit si_trapno to that combination, and it should not be a problem for
> a new signal/si_code pair to use that storage.  Precisely because it is
> new.
> 
> Similarly on alpha si_trapno is only set for:
> 
> SIGFPE {FPE_INTOVF, FPE_INTDIV, FPE_FLTOVF, FPE_FLTDIV, FPE_FLTUND,
> FPE_FLTINV, FPE_FLTRES, FPE_FLTUNK} and SIGTRAP {TRAP_UNK}.
> 
> Placing si_trapno into the union would also make the problem that the
> union is pointer aligned a non-problem as then the union immediate
> follows a pointer.
> 
> I hadn't had a chance to look before but we must deal with this.  The
> definition of perf_sigtrap in 42dec9a936e7696bea1f27d3c5a0068cd9aa95fd
> is broken on sparc, alpha, and ia64 as it bypasses the code in
> kernel/signal.c that ensures the si_trapno or the ia64 special fields
> are set.
> 
> Not to mention that perf_sigtrap appears to abuse si_errno.

There are a few other places in the kernel that repurpose si_errno
similarly, e.g. arch/arm64/kernel/ptrace.c, kernel/seccomp.c -- it was
either that or introduce another field or not have it. It is likely we
could do without, but if there are different event types the user would
have to sacrifice a few bits of si_perf to encode the event type, and
I'd rather keep those bits for something else. Thus the decision fell to
use si_errno.

Given it'd be wasted space otherwise, and we define the semantics of
whatever is stored in siginfo on the new signal, it'd be good to keep.

> The code is only safe if the analysis that says we can move si_trapno
> and perhaps the ia64 fields into the union is correct.  It looks like
> ia64 much more actively uses it's signal extension fields including for
> SIGTRAP, so I am not at all certain the generic definition of
> perf_sigtrap is safe on ia64.

Trying to understand the requirements of si_trapno myself: safe here
would mean that si_trapno is not required if we fire our SIGTRAP /
TRAP_PERF.

As far as I can tell that is the case -- see below.

> > I suppose in theory sparc64 or alpha might start using the other
> > fields in the future, and an application might be compiled against
> > mismatched headers, but that is unlikely and is already broken
> > with the current headers.
> 
> If we localize the use of si_trapno to just a few special cases on alpha
> and sparc I think we don't even need to worry about breaking userspace
> on any architecture.  It will complicate siginfo_layout, but it is a
> complication that reflects reality.
> 
> I don't have a clue how any of this affects ia64.  Does perf work on
> ia64?  Does perf work on sparc, and alpha?
> 
> If perf works on ia64 we need to take a hard look at what is going on
> there as well.

No perf on ia64, but it seems alpha and sparc have perf:

	$ git grep 'select.*HAVE_PERF_EVENTS$' -- arch/
	arch/alpha/Kconfig:	select HAVE_PERF_EVENTS    <--
	arch/arc/Kconfig:	select HAVE_PERF_EVENTS
	arch/arm/Kconfig:	select HAVE_PERF_EVENTS
	arch/arm64/Kconfig:	select HAVE_PERF_EVENTS
	arch/csky/Kconfig:	select HAVE_PERF_EVENTS
	arch/hexagon/Kconfig:	select HAVE_PERF_EVENTS
	arch/mips/Kconfig:	select HAVE_PERF_EVENTS
	arch/nds32/Kconfig:	select HAVE_PERF_EVENTS
	arch/parisc/Kconfig:	select HAVE_PERF_EVENTS
	arch/powerpc/Kconfig:	select HAVE_PERF_EVENTS
	arch/riscv/Kconfig:	select HAVE_PERF_EVENTS
	arch/s390/Kconfig:	select HAVE_PERF_EVENTS
	arch/sh/Kconfig:	select HAVE_PERF_EVENTS
	arch/sparc/Kconfig:	select HAVE_PERF_EVENTS    <--
	arch/x86/Kconfig:	select HAVE_PERF_EVENTS
	arch/xtensa/Kconfig:	select HAVE_PERF_EVENTS

Now, given ia64 is not an issue, I wanted to understand the semantics of
si_trapno. Per https://man7.org/linux/man-pages/man2/sigaction.2.html, I
see:

	int si_trapno;    /* Trap number that caused
			     hardware-generated signal
			     (unused on most architectures) */

... its intended semantics seem to suggest it would only be used by some
architecture-specific signal like you identified above. So if the
semantics is some code of a hardware trap/fault, then we're fine and do
not need to set it.

Also bearing in mind we define the semantics any new signal, and given
most architectures do not have si_trapno, definitions of new generic
signals should probably not include odd architecture specific details
related to old architectures.

From all this, my understanding now is that we can move si_trapno into
the union, correct? What else did you have in mind?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YIxVWkT03TqcJLY3%40elver.google.com.
