Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFRQXXAKGQEUGO3JEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 08C6FEFC12
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 12:11:10 +0100 (CET)
Received: by mail-yw1-xc3d.google.com with SMTP id b19sf16043363ywn.19
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 03:11:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572952269; cv=pass;
        d=google.com; s=arc-20160816;
        b=irSAAkREi5xtT3mwF+Q9hNHi+O5DnwG3azHfVXBLCGCtWhIIhDi/hNm/eSoowm5QHW
         zqAeG9YSa5Y7j0xW3zWJ4LVFdCLP4NuGZM7XLuEOSfhX+OJvjWjG16xmF4TmnuFGeAGb
         qgzNkVZ/+R4JWrWsii0r+T3UzvVilaSyy/uu1u0+HvjnyDRI+kdqCYx8ua1o0pM2kxA7
         7lZEsRSC/xSble7/wZH0Cpy2ovo/ONDu23DXuzoEAVgu1HUCFSrlM+js2izmK7tURXu1
         YyLvaop5v5YiCTPgZXTDKKFoqO0N29hAB89jG+5AqqBd7zXTDZ6JemavzzXM/14LQuRM
         MERg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=re4ueN3/UkRrzkhquJQf1C1DsaGrEkpchJI0K+sfPwA=;
        b=ZmMo4Zi4DaSdm4aaIArUtnfWp4ZC0Tm6OI51UOHTvfozpaz/RAUZnV8fk9lgBJPhyK
         ZgvZzCDQkg4Hogk9sdQMd4cyoUGgwj7hf26P/90IJ9gmppEXKvtk7xHqKC+QOUAr02WD
         f40ZaoQSEMe8PNRUsTlo5mVX+CNFXCc0dI1Qw+cgDWptA8+svpAlZ0Bd+60+zABo6wpN
         SnIzHGPtp6I/pmaYeYb5BGGvZ0hPmKrnoSrPiaeGpd14SriOtCMe1iSUHJzkvsbxKAlO
         7sRR6qsSRBPuUhswvhjQAuHbcj5/JsDJUBMtm+M2FuQx9L3AIeDENfFktBgDt29uhpjb
         SZLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UdD+cwSe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=re4ueN3/UkRrzkhquJQf1C1DsaGrEkpchJI0K+sfPwA=;
        b=KDCdg5Z6IUL+fO2nH3fOeuWWK/Oah2fkkkpAOdyCWQzQE3omjAuaAPrt4LsME4Mmx6
         52elnSWmNgr7w0J8hnPUK0PvN9X2ynGo9wAeDmlduOKIfCsAs3m5LFpX72KeefkiXOXz
         nUdIAcIPe1KPaG/BNTH9OIaTIIX7nM9+GFshxw7k3mXYugZmuMeBvNEt3xFpR1mRY0YO
         9Ja/2DIF7tro2RE6N5e/3iVmX/ep2bnzldSALV7r5PuCE/Ljev3SZF7PSXWqM2ZNqmt7
         uTTeQ/Qx52hs0XFucUalTzao4IB+EfwNFX4znOnRdnlDUpcy4L9b/cxU4snS8kK60rKm
         r4iA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=re4ueN3/UkRrzkhquJQf1C1DsaGrEkpchJI0K+sfPwA=;
        b=okGuOLdxXyeIbxO0mYj2bT8YffvJALLhHKZ/EhB0wnzjHcYh04zsyPLb7hQZBTp7Ae
         FTI6qEW7UwiOa3FbUDSBosws7hOvFXgmqFbR6oUKiUysn1ja6GziPq+m0bQ02JnK5INS
         asCedPg/PPa59vFz+i3b+EboQYKPmqEOWub+qMLNSp2wdQ6rqbVgfherJXpzbNW8CQa3
         Oa+GT0TWeZ9f9s82aOogglTGQlkBKvf7vUmZTCgOgswb4X/crkYJM5/pYnGftCSOfP4S
         q3O6vRanpMxROhr15+VRQ2N7nDFeJ0nsbXSNMvFCp15C1FBF2vrUhE4pb1+2r4dN4BOf
         te/w==
X-Gm-Message-State: APjAAAVeoGcub5GhRb6clPLmIwPs9hMU6KZcYCCSccZ8Wvsge7/ZCGS9
	e3UsOgo4/WRYmLpV0KJA7m4=
X-Google-Smtp-Source: APXvYqzQ+NfFVYV9iqYkzHBRwbmMvZhryVeUex+DAyWx4iSwmdjzUGGY4J5wmm+5jWhu8K+E2D8EBg==
X-Received: by 2002:a81:3650:: with SMTP id d77mr9210720ywa.397.1572952268916;
        Tue, 05 Nov 2019 03:11:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:ea09:: with SMTP id t9ls2810263ywe.3.gmail; Tue, 05 Nov
 2019 03:11:08 -0800 (PST)
X-Received: by 2002:a81:1ac4:: with SMTP id a187mr882280ywa.5.1572952268507;
        Tue, 05 Nov 2019 03:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572952268; cv=none;
        d=google.com; s=arc-20160816;
        b=Odl9y4eb6c/UVyTEIuWUbjlRjMubIay44ZigFGMsQ7DiP2zW9ywlwi2+wM/r1pecAT
         B9+0PYbxO/cqiVV1IqBOHAQbuC7we2QViz+HqJR7dGFDZOw+cwlICYYHf/rqy3rd5hrz
         rHFye6W/Eqlc5TEaPmoQfeMC/X1/b4qRXQV80e9ffNXC33I1M6wZEGDphZZR8+0MvscX
         n6sOedqMgwqTMw1gs7NQjAMQzzAkT3vZ6JNp7luSKhG/l/psBK1QULvzFdP6Tan+2RBR
         Bt62HEz5lvEeRCjYVdrVNg7I4gYVbfCserBbn1NRKHpXwRWoNwju8wkIYKwg9tmsc2Ch
         B2VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5B6n8kH55VbZzEY+wjyqB8FdxqyxjbBetSMGjeJd+Zc=;
        b=1Fp+vKOXo2aE/ESOxHXraHqdazcEau7xGXWgeh+QsTovHuG9quKrNvAYYuygmh+B/g
         w77U0WMAYyBzaOOQpcSbfIDErLU0guJr7hP6mJOX7Vrg/8pRc+qSQ6bYPbuf3Yp5xtRQ
         IDofInZi5V1eUFKzRuBc3WNSyw4bVndbZJz7s3cBgHvMSDNPYdEhOKzAIK38JewTyIAu
         rQupocWQsvPEHdLVH7KATQaa0ECMKXXvtDR27+a9ZkGVDP8z2lIsvC4dNst4DQNfKpm4
         QpVCeEcF3Gmm6gKs6gexHeR6aHcn1XhxgWb8wf6oFOnoyE1uO92Rf0sPzfF/KmGo9nlO
         cdww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UdD+cwSe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v135si1145432ywa.0.2019.11.05.03.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2019 03:11:08 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id z6so17286000otb.2
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2019 03:11:08 -0800 (PST)
X-Received: by 2002:a9d:82e:: with SMTP id 43mr22800110oty.23.1572952267599;
 Tue, 05 Nov 2019 03:11:07 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-1-elver@google.com> <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com> <20191104194658.GK20975@paulmck-ThinkPad-P72>
In-Reply-To: <20191104194658.GK20975@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2019 12:10:56 +0100
Message-ID: <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
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
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, linux-efi@vger.kernel.org, 
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UdD+cwSe;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Mon, 4 Nov 2019 at 20:47, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Nov 04, 2019 at 07:41:30PM +0100, Marco Elver wrote:
> > On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > KCSAN is a sampling watchpoint-based data-race detector. More details
> > > > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > > > only enables KCSAN for x86, but we expect adding support for other
> > > > architectures is relatively straightforward (we are aware of
> > > > experimental ARM64 and POWER support).
> > > >
> > > > To gather early feedback, we announced KCSAN back in September, and
> > > > have integrated the feedback where possible:
> > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > >
> > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > including several articles that motivate why data-races are dangerous
> > > > [1, 2], justifying a data-race detector such as KCSAN.
> > > > [1] https://lwn.net/Articles/793253/
> > > > [2] https://lwn.net/Articles/799218/
> > > >
> > > > The current list of known upstream fixes for data-races found by KCSAN
> > > > can be found here:
> > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > >
> > > Making this more accessible to more people seems like a good thing.
> > > So, for the series:
> > >
> > > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> >
> > Much appreciated. Thanks, Paul!
> >
> > Any suggestions which tree this could eventually land in?
>
> I would guess that Dmitry might have some suggestions.

I checked and we're both unclear what the most obvious tree to land in
is (the other sanitizers are mm related, which KCSAN is not).

One suggestion that comes to my mind is for KCSAN to go through the
same tree (rcu?) as the LKMM due to their inherent relationship. Would
that make most sense?

Thanks,
-- Marco

> >
> > > > Changelog
> > > > ---------
> > > > v3:
> > > > * Major changes:
> > > >  - Add microbenchmark.
> > > >  - Add instruction watchpoint skip randomization.
> > > >  - Refactor API and core runtime fast-path and slow-path. Compared to
> > > >    the previous version, with a default config and benchmarked using the
> > > >    added microbenchmark, this version is 3.8x faster.
> > > >  - Make __tsan_unaligned __alias of generic accesses.
> > > >  - Rename kcsan_{begin,end}_atomic ->
> > > >    kcsan_{nestable,flat}_atomic_{begin,end}
> > > >  - For filter list in debugfs.c use kmalloc+krealloc instead of
> > > >    kvmalloc.
> > > >  - Split Documentation into separate patch.
> > > >
> > > > v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> > > > * Major changes:
> > > >  - Replace kcsan_check_access(.., {true, false}) with
> > > >    kcsan_check_{read,write}.
> > > >  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
> > > >  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> > > >    contexts.
> > > >
> > > > v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> > > >
> > > > Marco Elver (9):
> > > >   kcsan: Add Kernel Concurrency Sanitizer infrastructure
> > > >   kcsan: Add Documentation entry in dev-tools
> > > >   objtool, kcsan: Add KCSAN runtime functions to whitelist
> > > >   build, kcsan: Add KCSAN build exceptions
> > > >   seqlock, kcsan: Add annotations for KCSAN
> > > >   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
> > > >   asm-generic, kcsan: Add KCSAN instrumentation for bitops
> > > >   locking/atomics, kcsan: Add KCSAN instrumentation
> > > >   x86, kcsan: Enable KCSAN for x86
> > > >
> > > >  Documentation/dev-tools/index.rst         |   1 +
> > > >  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
> > > >  MAINTAINERS                               |  11 +
> > > >  Makefile                                  |   3 +-
> > > >  arch/x86/Kconfig                          |   1 +
> > > >  arch/x86/boot/Makefile                    |   2 +
> > > >  arch/x86/boot/compressed/Makefile         |   2 +
> > > >  arch/x86/entry/vdso/Makefile              |   3 +
> > > >  arch/x86/include/asm/bitops.h             |   6 +-
> > > >  arch/x86/kernel/Makefile                  |   7 +
> > > >  arch/x86/kernel/cpu/Makefile              |   3 +
> > > >  arch/x86/lib/Makefile                     |   4 +
> > > >  arch/x86/mm/Makefile                      |   3 +
> > > >  arch/x86/purgatory/Makefile               |   2 +
> > > >  arch/x86/realmode/Makefile                |   3 +
> > > >  arch/x86/realmode/rm/Makefile             |   3 +
> > > >  drivers/firmware/efi/libstub/Makefile     |   2 +
> > > >  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
> > > >  include/asm-generic/bitops-instrumented.h |  18 +
> > > >  include/linux/compiler-clang.h            |   9 +
> > > >  include/linux/compiler-gcc.h              |   7 +
> > > >  include/linux/compiler.h                  |  35 +-
> > > >  include/linux/kcsan-checks.h              |  97 ++++
> > > >  include/linux/kcsan.h                     | 115 +++++
> > > >  include/linux/sched.h                     |   4 +
> > > >  include/linux/seqlock.h                   |  51 +-
> > > >  init/init_task.c                          |   8 +
> > > >  init/main.c                               |   2 +
> > > >  kernel/Makefile                           |   6 +
> > > >  kernel/kcsan/Makefile                     |  11 +
> > > >  kernel/kcsan/atomic.h                     |  27 ++
> > > >  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
> > > >  kernel/kcsan/debugfs.c                    | 275 +++++++++++
> > > >  kernel/kcsan/encoding.h                   |  94 ++++
> > > >  kernel/kcsan/kcsan.h                      | 131 +++++
> > > >  kernel/kcsan/report.c                     | 306 ++++++++++++
> > > >  kernel/kcsan/test.c                       | 121 +++++
> > > >  kernel/sched/Makefile                     |   6 +
> > > >  lib/Kconfig.debug                         |   2 +
> > > >  lib/Kconfig.kcsan                         | 119 +++++
> > > >  lib/Makefile                              |   3 +
> > > >  mm/Makefile                               |   8 +
> > > >  scripts/Makefile.kcsan                    |   6 +
> > > >  scripts/Makefile.lib                      |  10 +
> > > >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> > > >  tools/objtool/check.c                     |  18 +
> > > >  46 files changed, 2526 insertions(+), 206 deletions(-)
> > > >  create mode 100644 Documentation/dev-tools/kcsan.rst
> > > >  create mode 100644 include/linux/kcsan-checks.h
> > > >  create mode 100644 include/linux/kcsan.h
> > > >  create mode 100644 kernel/kcsan/Makefile
> > > >  create mode 100644 kernel/kcsan/atomic.h
> > > >  create mode 100644 kernel/kcsan/core.c
> > > >  create mode 100644 kernel/kcsan/debugfs.c
> > > >  create mode 100644 kernel/kcsan/encoding.h
> > > >  create mode 100644 kernel/kcsan/kcsan.h
> > > >  create mode 100644 kernel/kcsan/report.c
> > > >  create mode 100644 kernel/kcsan/test.c
> > > >  create mode 100644 lib/Kconfig.kcsan
> > > >  create mode 100644 scripts/Makefile.kcsan
> > > >
> > > > --
> > > > 2.24.0.rc1.363.gb1bccd3e3d-goog
> > > >
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104194658.GK20975%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno%2Bo-Fe%2B7OYKmPvCboQ%40mail.gmail.com.
