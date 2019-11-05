Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2FIQ3XAKGQEDFCRJKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C69FEF0147
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2019 16:25:29 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id u20sf15396326pga.4
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Nov 2019 07:25:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572967528; cv=pass;
        d=google.com; s=arc-20160816;
        b=oWvGJoRqA0huIbh7mZVLiGI33wHv52Usd5RWm3J/RKoqQybUulEt5nKPSS4kQ1QMlp
         D7HbD1BHirMyeqFmaiGlsDCm7B7mxeCDv93dqmAOvwRpYqyRNR7qYVmMdUH50DQOXJoq
         A+UurZUlRkV25TnygzwvF3RYK2Kwx8hpYLMrDAUXn1BnJhNNiZGuXqGZBJ8crTPpMiS6
         drJY+DsylKGVsX8j725LRsZAcs5/LDURqgS3FMGw6mJf+AXzliMDGQlAgKWbtInaIC+l
         LZRdilTttPDUWL03GbNtSlMoN1O/tFHwSJjOEbr7c1yjTxSYmj1fk/2y90e22Q1FIE2Z
         c8JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=0ys0zBkXk6b6/IVJAy+/u+QyYpJ4OpUQA72FDxjjxxM=;
        b=AnZFVk05/VPUrqirc6fXfZTeQaD/L1R6B3nerDmuW2UElr7Dv+3+9N3e8/+UvKYmI5
         PNPxy9MIDXf3u+zBx6FGJ4VMrdWmfO2I9OT6BmSelC18XIrV2d07JsdXsiYByllWlAqz
         aiDuTp3EXLe1/N9qzN8INcwHIFqiS2VAvBdrV6XHrPHjbZDnjcU3Lve6cGWN+rck8ID0
         HWX7OlcgHrDF7hGPE808WSqqq0IIfo1NcOgJ2lxJkSj05btKUeR3LFOjFGpwzB2O5ur3
         FelQrAE7NESX0xuHW6aJKGdj+CkcI+MFDwacApxAtXprnz8BNQBFUl0pwVvySibZ9r6c
         2Vuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u71G5vAu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0ys0zBkXk6b6/IVJAy+/u+QyYpJ4OpUQA72FDxjjxxM=;
        b=HlsOxVRhipNlYVfrpkcfG0gqkQjJZLSfmr8rQl7j3OViKC3pKDcvCGGaefz50KkD7/
         zmHzKrZBAuS2jd0GQlZ0anqS5m3xpJm3Y2YwUyPccKzHz2vIHuBkhhYVnxBvY1Ymqx2B
         3vG1np76wrm4MSfYkin+3KMRieiLSUjanUcPvZ6nDEUwOr0Xh/o39KI/voHu8TU1VUww
         4xFCQhRa7rf4eWbab6SUjxtPykSPTNAFq6eme++qFstJSfWfNEKFXv+H2aCrbLwf9W7w
         jElZjunAr8CzxqXZ37n3WKL4S0rxlVESLujWbeK91bXLbv+SZTfkDe0EVgIULnqZPe0o
         6axg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0ys0zBkXk6b6/IVJAy+/u+QyYpJ4OpUQA72FDxjjxxM=;
        b=PLR8mp35VHfheQy+Y27miZuVz7qHVGmMfd99Div3gXYGLSVxSI8OA3tm+0x6KkGFJu
         F6OfIH0GqINu8luliZjlxVznDWGmgjBhL88QUDZGp+FnnvqrObiYtti8K7+15XiZMeBR
         dZLOeTtFteTOcnnHaK9GQ5GCMhFHxr+4zBp91rQ4BmfHM0qmCrOQcJSK2+3ybFdtl89k
         2dbz3F46gQV0CLRrgY2JAx7Uj3Qb/DQJXGdVsm874eawj4ebAbcNnUJ3T8IPaziuuTGn
         rVx56G9ZFm6aIC/ZFf6g6ah1YCCxshRQ7YhIRCl04NBCHuyq7l9z/gR8ufLgvImL1oh7
         A2pw==
X-Gm-Message-State: APjAAAWJ5n/95Zm2oPTLF4gu2hlpya4EtxUMhSS1rqxLPBUx1R0iQ24W
	kZz+DEcDF5blcQXDvnIqgyg=
X-Google-Smtp-Source: APXvYqymeMEPyNggsTD9RNVJyarT03G+PHk5LAUjelOlBUehMqqjfoDhDjUYrBvLnS/TWzrhzBPDUA==
X-Received: by 2002:aa7:982c:: with SMTP id q12mr39215508pfl.83.1572967528433;
        Tue, 05 Nov 2019 07:25:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:20a2:: with SMTP id f31ls950808pjg.0.gmail; Tue, 05
 Nov 2019 07:25:27 -0800 (PST)
X-Received: by 2002:a17:902:6bc8:: with SMTP id m8mr33228071plt.49.1572967527833;
        Tue, 05 Nov 2019 07:25:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572967527; cv=none;
        d=google.com; s=arc-20160816;
        b=dYBPVJkTQlciivQr0IMBQSlw2pkw3LDHAs5D+z7rny+OS6fn8I183usAPt5Jt/trkQ
         vv3euekBXNKkHBrKNu/x/mNDL6tGC5ULEmdiZ2FHWcHv0mJtwn4EtTAi1EtuTXbP+RK5
         1PjN/UpbKaUpvZGogdO7dYXmIkK23UoFxpXnDdkjIQwaK/Cql8prlkpqi46yKBC4H3tI
         sSh6bD50n8/c2nDhXUZUUTtocWBYxBomStMa0+X8VN7KhrrP8CB/bUFmDO8mJuaGJaYK
         XsnIr0wA9zaMvzM/7bRuGGs9X5e93sKRQklLqY2N4vVTx3aiZsDgvHK9Q8P91FClLDvX
         dwWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=F+CYhJdTSBVhddLA7SYp46bo6WQRi/eEfG9ft70Vz4c=;
        b=HXp6x5Js8r+aQN8UfU03djHc4OnyRBjfMiLTFe4V8a25F/hJIyXYaaGqKEdSnHeoY3
         0qe0IGPC2iXWzSulziNQw5Td5All2uRQfuVXZ9mijGrjbSHHyVjcVW0mErJ07b5TpyiI
         tUzqw3S1J2CvLO6B+bvaZEvk5fjC0H59S7xIMf8zsmETgFilrmOsuqjkzIYPcGZ+6SYY
         V0xjI5PJ9+LQ4tIsxcVPEGFDFOgwnHUsI+OE3mq6V/78/Hbl0Z04VAMVEeshcBuoWmMk
         OywCFu1H1IMvSlXqqT6PX4sykcjVNSPgnZZ9JcTMWnSnau/F6w5qRzhx6a2cpB3n+NDI
         jrrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u71G5vAu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id d9si902279pfr.3.2019.11.05.07.25.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Nov 2019 07:25:27 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id l202so17868561oig.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Nov 2019 07:25:27 -0800 (PST)
X-Received: by 2002:aca:f046:: with SMTP id o67mr1917381oih.155.1572967526641;
 Tue, 05 Nov 2019 07:25:26 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-1-elver@google.com> <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
 <20191104194658.GK20975@paulmck-ThinkPad-P72> <CANpmjNPpVCRhgVgfaApZJCnMKHsGxVUno+o-Fe+7OYKmPvCboQ@mail.gmail.com>
 <20191105142035.GR20975@paulmck-ThinkPad-P72>
In-Reply-To: <20191105142035.GR20975@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Nov 2019 16:25:14 +0100
Message-ID: <CANpmjNPEukbQtD5BGpHdxqMvnq7Uyqr9o3QCByjCKxtPboEJtA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=u71G5vAu;       spf=pass
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

On Tue, 5 Nov 2019 at 15:20, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Tue, Nov 05, 2019 at 12:10:56PM +0100, Marco Elver wrote:
> > On Mon, 4 Nov 2019 at 20:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > On Mon, Nov 04, 2019 at 07:41:30PM +0100, Marco Elver wrote:
> > > > On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > >
> > > > > On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > > > > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > > > > KCSAN is a sampling watchpoint-based data-race detector. More details
> > > > > > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > > > > > only enables KCSAN for x86, but we expect adding support for other
> > > > > > architectures is relatively straightforward (we are aware of
> > > > > > experimental ARM64 and POWER support).
> > > > > >
> > > > > > To gather early feedback, we announced KCSAN back in September, and
> > > > > > have integrated the feedback where possible:
> > > > > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > > > > >
> > > > > > We want to point out and acknowledge the work surrounding the LKMM,
> > > > > > including several articles that motivate why data-races are dangerous
> > > > > > [1, 2], justifying a data-race detector such as KCSAN.
> > > > > > [1] https://lwn.net/Articles/793253/
> > > > > > [2] https://lwn.net/Articles/799218/
> > > > > >
> > > > > > The current list of known upstream fixes for data-races found by KCSAN
> > > > > > can be found here:
> > > > > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> > > > >
> > > > > Making this more accessible to more people seems like a good thing.
> > > > > So, for the series:
> > > > >
> > > > > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> > > >
> > > > Much appreciated. Thanks, Paul!
> > > >
> > > > Any suggestions which tree this could eventually land in?
> > >
> > > I would guess that Dmitry might have some suggestions.
> >
> > I checked and we're both unclear what the most obvious tree to land in
> > is (the other sanitizers are mm related, which KCSAN is not).
> >
> > One suggestion that comes to my mind is for KCSAN to go through the
> > same tree (rcu?) as the LKMM due to their inherent relationship. Would
> > that make most sense?
>
> It works for me, though you guys have to continue to be the main
> developers.  ;-)

Great, thanks. We did add an entry to MAINTAINERS, so yes of course. :-)

> I will go through the patches more carefully, and please look into the
> kbuild test robot complaint.

I just responded to that, it seems to be a sparse problem.

Thanks,
-- Marco

>                                                         Thanx, Paul
>
> > Thanks,
> > -- Marco
> >
> > > >
> > > > > > Changelog
> > > > > > ---------
> > > > > > v3:
> > > > > > * Major changes:
> > > > > >  - Add microbenchmark.
> > > > > >  - Add instruction watchpoint skip randomization.
> > > > > >  - Refactor API and core runtime fast-path and slow-path. Compared to
> > > > > >    the previous version, with a default config and benchmarked using the
> > > > > >    added microbenchmark, this version is 3.8x faster.
> > > > > >  - Make __tsan_unaligned __alias of generic accesses.
> > > > > >  - Rename kcsan_{begin,end}_atomic ->
> > > > > >    kcsan_{nestable,flat}_atomic_{begin,end}
> > > > > >  - For filter list in debugfs.c use kmalloc+krealloc instead of
> > > > > >    kvmalloc.
> > > > > >  - Split Documentation into separate patch.
> > > > > >
> > > > > > v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> > > > > > * Major changes:
> > > > > >  - Replace kcsan_check_access(.., {true, false}) with
> > > > > >    kcsan_check_{read,write}.
> > > > > >  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
> > > > > >  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> > > > > >    contexts.
> > > > > >
> > > > > > v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> > > > > >
> > > > > > Marco Elver (9):
> > > > > >   kcsan: Add Kernel Concurrency Sanitizer infrastructure
> > > > > >   kcsan: Add Documentation entry in dev-tools
> > > > > >   objtool, kcsan: Add KCSAN runtime functions to whitelist
> > > > > >   build, kcsan: Add KCSAN build exceptions
> > > > > >   seqlock, kcsan: Add annotations for KCSAN
> > > > > >   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
> > > > > >   asm-generic, kcsan: Add KCSAN instrumentation for bitops
> > > > > >   locking/atomics, kcsan: Add KCSAN instrumentation
> > > > > >   x86, kcsan: Enable KCSAN for x86
> > > > > >
> > > > > >  Documentation/dev-tools/index.rst         |   1 +
> > > > > >  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
> > > > > >  MAINTAINERS                               |  11 +
> > > > > >  Makefile                                  |   3 +-
> > > > > >  arch/x86/Kconfig                          |   1 +
> > > > > >  arch/x86/boot/Makefile                    |   2 +
> > > > > >  arch/x86/boot/compressed/Makefile         |   2 +
> > > > > >  arch/x86/entry/vdso/Makefile              |   3 +
> > > > > >  arch/x86/include/asm/bitops.h             |   6 +-
> > > > > >  arch/x86/kernel/Makefile                  |   7 +
> > > > > >  arch/x86/kernel/cpu/Makefile              |   3 +
> > > > > >  arch/x86/lib/Makefile                     |   4 +
> > > > > >  arch/x86/mm/Makefile                      |   3 +
> > > > > >  arch/x86/purgatory/Makefile               |   2 +
> > > > > >  arch/x86/realmode/Makefile                |   3 +
> > > > > >  arch/x86/realmode/rm/Makefile             |   3 +
> > > > > >  drivers/firmware/efi/libstub/Makefile     |   2 +
> > > > > >  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
> > > > > >  include/asm-generic/bitops-instrumented.h |  18 +
> > > > > >  include/linux/compiler-clang.h            |   9 +
> > > > > >  include/linux/compiler-gcc.h              |   7 +
> > > > > >  include/linux/compiler.h                  |  35 +-
> > > > > >  include/linux/kcsan-checks.h              |  97 ++++
> > > > > >  include/linux/kcsan.h                     | 115 +++++
> > > > > >  include/linux/sched.h                     |   4 +
> > > > > >  include/linux/seqlock.h                   |  51 +-
> > > > > >  init/init_task.c                          |   8 +
> > > > > >  init/main.c                               |   2 +
> > > > > >  kernel/Makefile                           |   6 +
> > > > > >  kernel/kcsan/Makefile                     |  11 +
> > > > > >  kernel/kcsan/atomic.h                     |  27 ++
> > > > > >  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
> > > > > >  kernel/kcsan/debugfs.c                    | 275 +++++++++++
> > > > > >  kernel/kcsan/encoding.h                   |  94 ++++
> > > > > >  kernel/kcsan/kcsan.h                      | 131 +++++
> > > > > >  kernel/kcsan/report.c                     | 306 ++++++++++++
> > > > > >  kernel/kcsan/test.c                       | 121 +++++
> > > > > >  kernel/sched/Makefile                     |   6 +
> > > > > >  lib/Kconfig.debug                         |   2 +
> > > > > >  lib/Kconfig.kcsan                         | 119 +++++
> > > > > >  lib/Makefile                              |   3 +
> > > > > >  mm/Makefile                               |   8 +
> > > > > >  scripts/Makefile.kcsan                    |   6 +
> > > > > >  scripts/Makefile.lib                      |  10 +
> > > > > >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> > > > > >  tools/objtool/check.c                     |  18 +
> > > > > >  46 files changed, 2526 insertions(+), 206 deletions(-)
> > > > > >  create mode 100644 Documentation/dev-tools/kcsan.rst
> > > > > >  create mode 100644 include/linux/kcsan-checks.h
> > > > > >  create mode 100644 include/linux/kcsan.h
> > > > > >  create mode 100644 kernel/kcsan/Makefile
> > > > > >  create mode 100644 kernel/kcsan/atomic.h
> > > > > >  create mode 100644 kernel/kcsan/core.c
> > > > > >  create mode 100644 kernel/kcsan/debugfs.c
> > > > > >  create mode 100644 kernel/kcsan/encoding.h
> > > > > >  create mode 100644 kernel/kcsan/kcsan.h
> > > > > >  create mode 100644 kernel/kcsan/report.c
> > > > > >  create mode 100644 kernel/kcsan/test.c
> > > > > >  create mode 100644 lib/Kconfig.kcsan
> > > > > >  create mode 100644 scripts/Makefile.kcsan
> > > > > >
> > > > > > --
> > > > > > 2.24.0.rc1.363.gb1bccd3e3d-goog
> > > > > >
> > > > >
> > > > > --
> > > > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.
> > >
> > > --
> > > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104194658.GK20975%40paulmck-ThinkPad-P72.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191105142035.GR20975%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEukbQtD5BGpHdxqMvnq7Uyqr9o3QCByjCKxtPboEJtA%40mail.gmail.com.
