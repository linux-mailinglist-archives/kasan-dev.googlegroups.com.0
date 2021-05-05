Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWNLZOCAMGQEP6MGSKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id E276037437E
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 19:28:58 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id c2-20020a1709027242b02900e9636a90acsf1029046pll.12
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 10:28:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620235737; cv=pass;
        d=google.com; s=arc-20160816;
        b=SephvsJaQv+SYDJTg4VaKuyG8pU5DnTi3wq8tQUQR7NkkPFddY9EAL1tyegx+KrvmE
         NLwCHCr1PYZxBRNxB+bRZw/PpBKSXJaElz9mRqSvfTcQWS11mBWG3E95fRwWo4hUvbko
         XeQ2qXIWh2VOtzfxCxIqeR9QEtj31yvFqdHYJKn9vU/zdvSJ04xN6gfVx/kG3TGWCjdr
         ShuN+21rIQxCepg+8IzCggc20ktD9GtLqWNh2MzNVTxuMyMmXayf0ODC2JTXS+HKz4iy
         tZi455xzC9Uy0xFw6qxNGEfL5c61tn+SI98cF70tehtSlDmM4Pj5uUpMxTZOnxnM1zSx
         U1Fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IwlTCjT8tRiwLemB38L64juP7SDv3Ymma8/4LWCn5e8=;
        b=ulEWUbLwLo4eOpq8hM3Nuj0kUblB5Wh1Y+PDLrMDYl/iSXdwUgpFBdiOtsn9sEagfS
         9g0nBpilmI4YJ3ekaPlVCRWJzs2Y15V/+tSZOUZ+Iev7Ut8nzvT/23OJDb1kzUW19bOv
         Dowx/VGFxddCpM84eTqBDkM4VP4DIOp4On7zyS2xoIIWGbT9TIaJoWMzVd5Rk3L14ocu
         t0rCcyv1G2ypOXRg8F3yoFpvTJgo+dsYI80Dv7pcmf3ZkvlR2Q7cH+CrcShr+Lr1bfIV
         U2pPa3NHSfqQkyVIZIqX0Es4X6gsAt4rA+dueaLHyUEfAVkYEZAqyyqZcT6phTYT2ITj
         kDhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ci17lKNM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwlTCjT8tRiwLemB38L64juP7SDv3Ymma8/4LWCn5e8=;
        b=iaZniaWLOkI7EBc3CDayRRAZBIU5u3CINJC+gSGK4aatd5bFWUbEyVulLtrRdCVaUc
         nqAC/KKg18kO1el9WWRpen+Y+6P0FCd+HdpjADtHh7IoQogr6w50/nQEfrYcofCw6ywB
         1eic1UCXQY78E+81E7ED1uZuBIPbk5WqJWuXT+ba+0rBdks3ZiqNd9EvKSk+lzl4dXAF
         MRvpReChQvyxjcBGOkKiF0pekbsUqiQLbKhLnViG/F0DPJa23bNdBtlj5qYrx+whRJg4
         cQmfgxsnKA2EN0HSCUDtnrRFuyjrsN73KiIwHfQBAFO633FJ6lHANld7fLxyy7GIk4gR
         hAkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwlTCjT8tRiwLemB38L64juP7SDv3Ymma8/4LWCn5e8=;
        b=amz4Fwr2BmOp5fn1C8EPTF8QF5w6GcWUDEfVHVM6dK6UbckqJfSVvQj+svfPxHZPdF
         2XGwUyXAMtkrfb9u4fUlPlrt4dnsYtehYO+YodbK3N5rEwCAgbF4fVbOlAkMON6GxH7h
         xIuG8kd2C8DSv0EQNLLY2Pcb+DAkAu9zxmj20xjfhC7/qipBbk/g3nmQgvn1GpK2o7gH
         dqRrF18VX2C7jl/m5yecmIVdnEjRpxDdeuRfiNvdPVWVBlRr1Vk6HgUnrk7jDfa/HwcE
         AAq6FdLrgM+G5Z8jhqyYGm8/PiE1VHjcb7TGCP67KptmZgYYXDAbwlye2cjs1mAP0mZi
         ttfg==
X-Gm-Message-State: AOAM533c8eFS02S3T8CRcF+WyzDx0BtDEfnmXIuQylWPulocvYECemIq
	9kcdn1r4PBKWcXkp8NA0eew=
X-Google-Smtp-Source: ABdhPJxGtxwI2qoTk+Yp9Cz18LCOpX6PNTivHVHBrd4Seu6EC23JPUqSx3w7iXcOYJOFDVw4IR4AnQ==
X-Received: by 2002:a17:90a:b001:: with SMTP id x1mr37155267pjq.122.1620235737674;
        Wed, 05 May 2021 10:28:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea8d:: with SMTP id x13ls4712147plb.2.gmail; Wed, 05
 May 2021 10:28:57 -0700 (PDT)
X-Received: by 2002:a17:902:b487:b029:ee:d04b:741e with SMTP id y7-20020a170902b487b02900eed04b741emr18735270plr.45.1620235737024;
        Wed, 05 May 2021 10:28:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620235737; cv=none;
        d=google.com; s=arc-20160816;
        b=DDngYYz8VAoeRJ5Ar23X9zb4PFpFU/8szMs+zR8YLR9v9Az7AfC1sZTRavlcJpp/gm
         bSwGVzmCxE0x1Dfs3cgUPcw1D5K/Hsbz7zJu74BsK1SSfHpQzO3fvbMJfX8rUA7Hdqof
         zBEk8ccgE7bKFuqzQ8dH/DmCC59BrPo/9rH1hyeBuOkCm+HM0fcO05HufU6lgVbeOmko
         ElFV6BtVI9OWWzoNF9iElGh4dxbzTrb80QkYfko/oz3HUGrGteCPIBHnVHstaKqsZMy4
         Z+BfKQuVy4Pp5wqQdLINRiuUHLZz+58S2Jg4BbE4ioY9tp4UAaBAdX7+rMBsTFqokHeX
         6d6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=g4X2E1XRo1phsTQg3EtaDOCHvhUj1Tt6jnzKJ2/36r4=;
        b=uhzkCPfzZ46YtHfx71ADWi69sxPkgcdTt/izQAnw1mPqwGhpE65dDsGoheG0gR7FAi
         cNESR6jDRuRO7pYDFNI834mjimqWGgIx/IHr/RlFXq2GsbLSI0pQH7kCm2J016XwqY9a
         KNWrMgcxy46/7tOQEjJI6rbzHGzm2fwjH95SVH7SqTtCdHdeXem+NjGf+atbCBZjMkpt
         esrJd6R93X1BFiSTAQAcxScqOhKaDC0TkzWwr97PFE+wXlT8GGjFIjFvqmgtv1sAtVcH
         hs1f5esqqQ+vwtpEMDVUiaq/v3sH0Ou5Zx/3JlfnUUvse36f403yDjZylqES+BxUb8E5
         ztuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ci17lKNM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id x3si1000898pjo.3.2021.05.05.10.28.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 May 2021 10:28:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id r26-20020a056830121ab02902a5ff1c9b81so2377646otp.11
        for <kasan-dev@googlegroups.com>; Wed, 05 May 2021 10:28:56 -0700 (PDT)
X-Received: by 2002:a9d:60c8:: with SMTP id b8mr24974375otk.17.1620235736198;
 Wed, 05 May 2021 10:28:56 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <m1r1irpc5v.fsf@fess.ebiederm.org>
 <CANpmjNNfiSgntiOzgMc5Y41KVAV_3VexdXCMADekbQEqSP3vqQ@mail.gmail.com>
 <m1czuapjpx.fsf@fess.ebiederm.org> <CANpmjNNyifBNdpejc6ofT6+n6FtUw-Cap_z9Z9YCevd7Wf3JYQ@mail.gmail.com>
 <m14kfjh8et.fsf_-_@fess.ebiederm.org> <m1tuni8ano.fsf_-_@fess.ebiederm.org>
In-Reply-To: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 5 May 2021 19:28:00 +0200
Message-ID: <CANpmjNMLbc_8HtUVB2fOu3eV7vO2rMdZAZ4BZ02hndeXu3hUoA@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] signal: sort out si_trapno and si_perf
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ci17lKNM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Tue, 4 May 2021 at 23:13, Eric W. Biederman <ebiederm@xmission.com> wrote:
> This set of changes sorts out the ABI issues with SIGTRAP TRAP_PERF, and
> hopefully will can get merged before any userspace code starts using the
> new ABI.
>
> The big ideas are:
> - Placing the asserts first to prevent unexpected ABI changes
> - si_trapno becomming ordinary fault subfield.
> - struct signalfd_siginfo is almost full
>
> This set of changes starts out with Marco's static_assert changes and
> additional one of my own that enforces the fact that the alignment of
> siginfo_t is also part of the ABI.  Together these build time
> checks verify there are no unexpected ABI changes in the changes
> that follow.
>
> The field si_trapno is changed to become an ordinary extension of the
> _sigfault member of siginfo.
>
> The code is refactored a bit and then si_perf_type is added along side
> si_perf_data in the _perf subfield of _sigfault of siginfo_t.
>
> Finally the signalfd_siginfo fields are removed as they appear to be
> filling up the structure without userspace actually being able to use
> them.
>
> v2: https://lkml.kernel.org/r/m14kfjh8et.fsf_-_@fess.ebiederm.org
> v1: https://lkml.kernel.org/r/m1zgxfs7zq.fsf_-_@fess.ebiederm.org
>
> Eric W. Biederman (9):
>       signal: Verify the alignment and size of siginfo_t
>       siginfo: Move si_trapno inside the union inside _si_fault
>       signal: Implement SIL_FAULT_TRAPNO
>       signal: Use dedicated helpers to send signals with si_trapno set
>       signal: Remove __ARCH_SI_TRAPNO
>       signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency
>       signal: Factor force_sig_perf out of perf_sigtrap
>       signal: Deliver all of the siginfo perf data in _perf
>       signalfd: Remove SIL_FAULT_PERF_EVENT fields from signalfd_siginfo
>
> Marco Elver (3):
>       sparc64: Add compile-time asserts for siginfo_t offsets
>       arm: Add compile-time asserts for siginfo_t offsets
>       arm64: Add compile-time asserts for siginfo_t offsets
>
>  arch/alpha/include/uapi/asm/siginfo.h              |   2 -
>  arch/alpha/kernel/osf_sys.c                        |   2 +-
>  arch/alpha/kernel/signal.c                         |   4 +-
>  arch/alpha/kernel/traps.c                          |  24 ++---
>  arch/alpha/mm/fault.c                              |   4 +-
>  arch/arm/kernel/signal.c                           |  39 +++++++
>  arch/arm64/kernel/signal.c                         |  39 +++++++
>  arch/arm64/kernel/signal32.c                       |  39 +++++++
>  arch/mips/include/uapi/asm/siginfo.h               |   2 -
>  arch/sparc/include/uapi/asm/siginfo.h              |   3 -
>  arch/sparc/kernel/process_64.c                     |   2 +-
>  arch/sparc/kernel/signal32.c                       |  37 +++++++
>  arch/sparc/kernel/signal_64.c                      |  36 +++++++
>  arch/sparc/kernel/sys_sparc_32.c                   |   2 +-
>  arch/sparc/kernel/sys_sparc_64.c                   |   2 +-
>  arch/sparc/kernel/traps_32.c                       |  22 ++--
>  arch/sparc/kernel/traps_64.c                       |  44 ++++----
>  arch/sparc/kernel/unaligned_32.c                   |   2 +-
>  arch/sparc/mm/fault_32.c                           |   2 +-
>  arch/sparc/mm/fault_64.c                           |   2 +-
>  arch/x86/kernel/signal_compat.c                    |  15 ++-
>  fs/signalfd.c                                      |  23 ++---
>  include/linux/compat.h                             |  10 +-
>  include/linux/sched/signal.h                       |  13 +--
>  include/linux/signal.h                             |   3 +-
>  include/uapi/asm-generic/siginfo.h                 |  20 ++--
>  include/uapi/linux/signalfd.h                      |   4 +-
>  kernel/events/core.c                               |  11 +-
>  kernel/signal.c                                    | 113 +++++++++++++--------
>  .../selftests/perf_events/sigtrap_threads.c        |  12 +--
>  30 files changed, 373 insertions(+), 160 deletions(-)

Looks good, thanks a lot! I ran selftests/perf_events on x86-64, and
build-tested x86-32, arm, arm64, sparc, alpha.

I added my Reviewed/Acked-by to the various patches.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMLbc_8HtUVB2fOu3eV7vO2rMdZAZ4BZ02hndeXu3hUoA%40mail.gmail.com.
