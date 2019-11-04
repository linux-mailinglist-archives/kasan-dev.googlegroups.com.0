Return-Path: <kasan-dev+bncBAABBNUAQLXAKGQEQHNOMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B4EE1EE8E9
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 20:47:03 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id y127sf1246472yba.19
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 11:47:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572896822; cv=pass;
        d=google.com; s=arc-20160816;
        b=sVsU7nmdwPLceRvnAKZQ2xzD7wbGZbs42oq2HhEOgm0oEoNswfCxJhqOjCL46n8KEu
         Yj+ArV0nF8hDSxSbgKcitU5COVfwWCRj3jBAIjfSKvWrLZyvlw8Tr5Nn9IZZhkRPb7Mq
         UQin9C6SOwGEXEgA342f/rWmAE2Txg6l99RM36nWIO25i9nBka93XA7a3hIPdXI1jFnh
         a8x+wuJXGbP2yBag1viA95r8rGav2uKKVfCvockZ19OQ+y27GOrV3ZsG6weE2aI9iXxI
         ro6p/Ygp1FVbbGj6EjR76FYAIDsAdOiI0y4x2I8VoetUiqIwoN5MvYj8iPnxwC9AogNy
         mRHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=sjCEI850GAb/Td7PW5Ub+n78eHgrEosA9jdLEXNeSls=;
        b=dMCsnZXFANuo9Br6hQMxfhW/bPKogiLQQ8AZTDZgyc94Uq5fSdSubSyo65XY4iWg0c
         SFyxcdkDJCb6jryYBx6puaQ+pfY3XSYdcxvHXGYRMbxTZ5AaNWVrz2DL0nlU6HX50JmW
         l0tUuGuyLBSj/ZqXLhosiWGU0IaxrpkM/tGCvV6VpS8jb04iM7gcHKzG6PHtz4Qbr/og
         K6C0CJ3nIoUsZlRCrPCcGpbmnftbRUTREa8b3dJu9wpl/Col5P3a4RKAOuKYAJHDXe4Y
         uQl3wEYS1vNjgIC7W67b7jkyGFCB3oarePnexCK7dJEOA85t6hCk6e3SqG/WYz/yiyeZ
         jGHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ONuLiO7M;
       spf=pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sjCEI850GAb/Td7PW5Ub+n78eHgrEosA9jdLEXNeSls=;
        b=AW3li575ubOByPqa+eW5hh4GoxwSKavJyN+JvGjKPEA32WtZhLzL8B8CSxr8CVWWpQ
         yE+11qxrLnodK8HGBZefnI3mT5Jje3KOJhhDILiX+u2FE0rCLHeSRDABT6XJFkM8qGIl
         lTolFbN0qZFcHzrTv4XIJQufHVtsCNLHyKUhM/fzKVMwCpZQfsRvJ+jjiH/eBpSTiCpH
         iAnV4d0lXwlzaqy+fckkjhHTjL5UFlS295soQ1DEZ0JPuEYDHgMt05gffpCPtOpafHwb
         Dyop9cUY1VZsc5235U1IfB3ySQTsKz0upu4hUvGNRR1Rgkh9meWIASaOoEprIDNKJ5JP
         0ZyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sjCEI850GAb/Td7PW5Ub+n78eHgrEosA9jdLEXNeSls=;
        b=TSZZDSxOgkAO70aTWvWAvevca4D1y1G0JzC++KRUMPNwxhMKllArt8ZkjAt9gRoVku
         9FKu/iuDC2ECJuKutF/uf4c0UmfTavdt5stY1Cz9hLcsJoY2mf6AEq04Rsu4ZkD9rh8k
         nXdpfE4IDrIvsik1hzw+tbWgBA9i2mGUx4UJNaGntdxrppKwg80yiQtIXL7pi7ZZ4FgQ
         /3P7keB8RsfeCldxnK5vULhD7TdJ/bbwM3gNOPpmKP9/q9oMyI2VmTTNwgujD884D62r
         sIyi/ipzTgk00nEz8pc8sCHCxFDIKPJO25xUGeWINTQpI4AgyQb0QP78yM8CVlgUwQZ+
         QKIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXKjqoVaqVyOBLGNfSlXZ8MR8qKicuvomwtyuYfySfdSL0FiONK
	2ymLtKuyxyEb/iizpqBgQKo=
X-Google-Smtp-Source: APXvYqxh4oFt4rC1v/m43Je3Zs2JM7HOX+7BrtUZ0eRQynvyexEW8mkchYwIP9+a6nx5c+xqqGq9aA==
X-Received: by 2002:a25:d14f:: with SMTP id i76mr10755152ybg.247.1572896822683;
        Mon, 04 Nov 2019 11:47:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:cb92:: with SMTP id n140ls2340636ywd.15.gmail; Mon, 04
 Nov 2019 11:47:02 -0800 (PST)
X-Received: by 2002:a81:6fd6:: with SMTP id k205mr22304302ywc.401.1572896822325;
        Mon, 04 Nov 2019 11:47:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572896822; cv=none;
        d=google.com; s=arc-20160816;
        b=iVVfyZPLl/ugO7DCT61Ecz2i3YpN4rs1Ae8oFhVzdm2gsx6hd1WO4ZBemC6hkkfJD6
         Lh/hVjmlSmGzLovzju631LRU4CxFUBpcu2NOwGpAQhJFPJYu82HazTn8YEyntbLVK9gz
         6xiTaBP6VG7rN/TJyMOhicBo0fWPYNJl0IG4T7zvR4+Jo4B+C6u7QuNY/XFdeRzjJtZV
         Z4/yueGbFeA963jzddeTiXtzgpLZVbRTCUL4AO9BUIYdy+CCH4HU5/ZK8eFIi8+3UUyK
         7ShK5aruDCOBzjtKRWVfVQaN5gqH13MwxCHsKorSduLvNdT5ElBfDGO4L+pyIh5UaOYK
         wn+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=wQEtpOYIPgZFKluhvVUQ/RvIT0w1rFxOEMtLPcGnGSg=;
        b=J+sEOreSKLDwzRF0O3TR1ApBE5A59X7oq5cH44rXZuWqUfggiCVXmuy8M/p0mwp+CM
         9i67lHq1Dce8Q3ej8zdP0yamjAbGN8p4Z7LF+Hm+urWtuxXmGQX/I3sB9jZ48JN0oUfA
         Y24p3LHnEZMZtd7fmTERhIuqGantuMO4hgri7mRPOCesMZGZXYHbaXp1P2jbpO7qicdX
         SxDrYrk/0VdOoQYLDo9Uv0jDnVwkZ/2Mm559wF39t37Y0dtAcq+fiLhg/iwDbelu9+HX
         YPzS+yRdr0NnyZXYiVz9+Ww4pMFfYjp7LDxsaZ/xzVRr2OL0eJfiJrx5csDsxruV2UPD
         BxZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ONuLiO7M;
       spf=pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x1si365003ybs.0.2019.11.04.11.47.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 04 Nov 2019 11:47:02 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (28.234-255-62.static.virginmediabusiness.co.uk [62.255.234.28])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D3417206BA;
	Mon,  4 Nov 2019 19:47:00 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 1FD783520B56; Mon,  4 Nov 2019 11:46:58 -0800 (PST)
Date: Mon, 4 Nov 2019 11:46:58 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>,
	Alan Stern <stern@rowland.harvard.edu>,
	Alexander Potapenko <glider@google.com>,
	Andrea Parri <parri.andrea@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Arnd Bergmann <arnd@arndb.de>, Boqun Feng <boqun.feng@gmail.com>,
	Borislav Petkov <bp@alien8.de>, Daniel Axtens <dja@axtens.net>,
	Daniel Lustig <dlustig@nvidia.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Howells <dhowells@redhat.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	Jade Alglave <j.alglave@ucl.ac.uk>,
	Joel Fernandes <joel@joelfernandes.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Poimboeuf <jpoimboe@redhat.com>,
	Luc Maranget <luc.maranget@inria.fr>,
	Mark Rutland <mark.rutland@arm.com>,
	Nicholas Piggin <npiggin@gmail.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	linux-arch <linux-arch@vger.kernel.org>,
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>,
	linux-efi@vger.kernel.org,
	Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
Message-ID: <20191104194658.GK20975@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191104142745.14722-1-elver@google.com>
 <20191104164717.GE20975@paulmck-ThinkPad-P72>
 <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ONuLiO7M;       spf=pass
 (google.com: domain of srs0=hufz=y4=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=hufz=Y4=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Nov 04, 2019 at 07:41:30PM +0100, Marco Elver wrote:
> On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > > KCSAN is a sampling watchpoint-based data-race detector. More details
> > > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > > only enables KCSAN for x86, but we expect adding support for other
> > > architectures is relatively straightforward (we are aware of
> > > experimental ARM64 and POWER support).
> > >
> > > To gather early feedback, we announced KCSAN back in September, and
> > > have integrated the feedback where possible:
> > > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> > >
> > > We want to point out and acknowledge the work surrounding the LKMM,
> > > including several articles that motivate why data-races are dangerous
> > > [1, 2], justifying a data-race detector such as KCSAN.
> > > [1] https://lwn.net/Articles/793253/
> > > [2] https://lwn.net/Articles/799218/
> > >
> > > The current list of known upstream fixes for data-races found by KCSAN
> > > can be found here:
> > > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
> >
> > Making this more accessible to more people seems like a good thing.
> > So, for the series:
> >
> > Acked-by: Paul E. McKenney <paulmck@kernel.org>
> 
> Much appreciated. Thanks, Paul!
> 
> Any suggestions which tree this could eventually land in?

I would guess that Dmitry might have some suggestions.

							Thanx, Paul

> Thanks,
> -- Marco
> 
> > > Changelog
> > > ---------
> > > v3:
> > > * Major changes:
> > >  - Add microbenchmark.
> > >  - Add instruction watchpoint skip randomization.
> > >  - Refactor API and core runtime fast-path and slow-path. Compared to
> > >    the previous version, with a default config and benchmarked using the
> > >    added microbenchmark, this version is 3.8x faster.
> > >  - Make __tsan_unaligned __alias of generic accesses.
> > >  - Rename kcsan_{begin,end}_atomic ->
> > >    kcsan_{nestable,flat}_atomic_{begin,end}
> > >  - For filter list in debugfs.c use kmalloc+krealloc instead of
> > >    kvmalloc.
> > >  - Split Documentation into separate patch.
> > >
> > > v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> > > * Major changes:
> > >  - Replace kcsan_check_access(.., {true, false}) with
> > >    kcsan_check_{read,write}.
> > >  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
> > >  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> > >    contexts.
> > >
> > > v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> > >
> > > Marco Elver (9):
> > >   kcsan: Add Kernel Concurrency Sanitizer infrastructure
> > >   kcsan: Add Documentation entry in dev-tools
> > >   objtool, kcsan: Add KCSAN runtime functions to whitelist
> > >   build, kcsan: Add KCSAN build exceptions
> > >   seqlock, kcsan: Add annotations for KCSAN
> > >   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
> > >   asm-generic, kcsan: Add KCSAN instrumentation for bitops
> > >   locking/atomics, kcsan: Add KCSAN instrumentation
> > >   x86, kcsan: Enable KCSAN for x86
> > >
> > >  Documentation/dev-tools/index.rst         |   1 +
> > >  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
> > >  MAINTAINERS                               |  11 +
> > >  Makefile                                  |   3 +-
> > >  arch/x86/Kconfig                          |   1 +
> > >  arch/x86/boot/Makefile                    |   2 +
> > >  arch/x86/boot/compressed/Makefile         |   2 +
> > >  arch/x86/entry/vdso/Makefile              |   3 +
> > >  arch/x86/include/asm/bitops.h             |   6 +-
> > >  arch/x86/kernel/Makefile                  |   7 +
> > >  arch/x86/kernel/cpu/Makefile              |   3 +
> > >  arch/x86/lib/Makefile                     |   4 +
> > >  arch/x86/mm/Makefile                      |   3 +
> > >  arch/x86/purgatory/Makefile               |   2 +
> > >  arch/x86/realmode/Makefile                |   3 +
> > >  arch/x86/realmode/rm/Makefile             |   3 +
> > >  drivers/firmware/efi/libstub/Makefile     |   2 +
> > >  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
> > >  include/asm-generic/bitops-instrumented.h |  18 +
> > >  include/linux/compiler-clang.h            |   9 +
> > >  include/linux/compiler-gcc.h              |   7 +
> > >  include/linux/compiler.h                  |  35 +-
> > >  include/linux/kcsan-checks.h              |  97 ++++
> > >  include/linux/kcsan.h                     | 115 +++++
> > >  include/linux/sched.h                     |   4 +
> > >  include/linux/seqlock.h                   |  51 +-
> > >  init/init_task.c                          |   8 +
> > >  init/main.c                               |   2 +
> > >  kernel/Makefile                           |   6 +
> > >  kernel/kcsan/Makefile                     |  11 +
> > >  kernel/kcsan/atomic.h                     |  27 ++
> > >  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
> > >  kernel/kcsan/debugfs.c                    | 275 +++++++++++
> > >  kernel/kcsan/encoding.h                   |  94 ++++
> > >  kernel/kcsan/kcsan.h                      | 131 +++++
> > >  kernel/kcsan/report.c                     | 306 ++++++++++++
> > >  kernel/kcsan/test.c                       | 121 +++++
> > >  kernel/sched/Makefile                     |   6 +
> > >  lib/Kconfig.debug                         |   2 +
> > >  lib/Kconfig.kcsan                         | 119 +++++
> > >  lib/Makefile                              |   3 +
> > >  mm/Makefile                               |   8 +
> > >  scripts/Makefile.kcsan                    |   6 +
> > >  scripts/Makefile.lib                      |  10 +
> > >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> > >  tools/objtool/check.c                     |  18 +
> > >  46 files changed, 2526 insertions(+), 206 deletions(-)
> > >  create mode 100644 Documentation/dev-tools/kcsan.rst
> > >  create mode 100644 include/linux/kcsan-checks.h
> > >  create mode 100644 include/linux/kcsan.h
> > >  create mode 100644 kernel/kcsan/Makefile
> > >  create mode 100644 kernel/kcsan/atomic.h
> > >  create mode 100644 kernel/kcsan/core.c
> > >  create mode 100644 kernel/kcsan/debugfs.c
> > >  create mode 100644 kernel/kcsan/encoding.h
> > >  create mode 100644 kernel/kcsan/kcsan.h
> > >  create mode 100644 kernel/kcsan/report.c
> > >  create mode 100644 kernel/kcsan/test.c
> > >  create mode 100644 lib/Kconfig.kcsan
> > >  create mode 100644 scripts/Makefile.kcsan
> > >
> > > --
> > > 2.24.0.rc1.363.gb1bccd3e3d-goog
> > >
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104194658.GK20975%40paulmck-ThinkPad-P72.
