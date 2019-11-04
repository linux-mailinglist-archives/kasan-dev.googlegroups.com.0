Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HBQHXAKGQE2XGOO7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5432EEE77D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 19:41:45 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id t67sf7162525ill.21
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 10:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572892904; cv=pass;
        d=google.com; s=arc-20160816;
        b=LTanIZYUvyJK/xI1As33VWossGydD1i0cuHR6dAjSOsAu8EH7PxLNtBkvpnRJ3Wo/d
         6a28Ts5O39uywhKxmP/peVvqzYdlmQIT49ibKozNd+AiMU/JNhpLcJK9tGIexFbkjo0D
         diaETnwMNtwfTngqbcS8qd7Zb4snGaJQSoU2QGfB7DJQ163NwTd22Hi5TRkYPQrjnVGR
         0QEHpWS2Gm6n0FwDbvPkp+3ZKo9RzEsX8tO1SUoA9y31xDnhRs8G7Lq6EAGn5jfi6/aP
         Q/39wIfVcYjnCHQpJDeOCubO7rX9eDcLPlK4kTfPmI6a6L+2mDXjw4nkO8HMNyHqSKgo
         B4nQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fNQNGArXNUwkRUt+sRMWt6yrFpy/Cn4en4vb9VnWYvA=;
        b=RzzoQeFmiaAQdpFmCOkIG/ivbiU2CbfUvQWlOtUZ+LdUaC1NZcGq5rSlB+pe4Q2IZ6
         flGLe7ftLkZ5Jipyv1vSqwdifGPYI6aaqGM905WKDAMCYND+XpfAQN2+aaW20jHcH8M0
         x25aHLH0Fj6DiCiHeB9M3vkS4/TpG3lOifZuZ4LLikGpX20X6/3doMRsrUi5tS1L1S4O
         5H19O+JDn1aEolN49wvgu/70Vi96HwRmmKRliWSQ9uKxUvW5FuSf3R9I7lulihOojvYb
         TH+zdCV36L6VbIe+zo+Y1DtGs7048dXgCqOtaTTQ9mnynX82fJi+KSKyLTlPx3a3md3V
         GGpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JAbFW9ec;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fNQNGArXNUwkRUt+sRMWt6yrFpy/Cn4en4vb9VnWYvA=;
        b=tVKq+63dMEfQoQJnWvcY/0oxqWuvG/uwkGUgStqkk2Jx1Z7wRthsFyHCfuix04cGP+
         TP40dwWlVtEwXCntGlJRMSExKSJjd3uiGuFJ+3WrlX9WLkFQA8yW/zrhUznhVKhRXZcR
         uCVBniy2FOt8pfO8g1T5eHHyYcxS5Gk7jN1KrFPokGL2xpe3O5S2vXEsJ3nzM6unXgUT
         dCdqvts5ECZFF+kTOms9h3gu0ZijOkCgqZhw0VAxAyAcazRsukQUckU1n+Qv5kS9PrqB
         kgJQFo0BhXMOUpi7zUZeQJg2roLqQfN14kZOlG4tHjzd6fJ4D2FyiHoRxSTzqdNswtqQ
         Ohig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fNQNGArXNUwkRUt+sRMWt6yrFpy/Cn4en4vb9VnWYvA=;
        b=GD95cQA7ckay8US2XQSv9AnMtZYXQ1QAe/anbBdLfp4scln39F+MVf98yRoG560T2y
         fwulC2jSw5FjtWKm+shndRlLb5Up0I8AlrxHNMO/raOwdbEexD4KjkchHpHMf135eyp9
         BzV6e+HrRG0mGNHn8/0EvG766u5TUTuAIYXz7E4Dsliy5e94MdH4wtf6xAHZ4I+7FCdk
         /0xA8fndLGGXB85Rb0Qbn1pFw+nEersJ7rBosrL3f0CJGYPSc6NlDriK1JR4oZqkKyJT
         95PAvMg54Y7J2BXAA9XAxT8L+NwMBks68y1hgNy+jcELe1mHthZjEJKauAeeCcSJ1aN2
         k19A==
X-Gm-Message-State: APjAAAXefTsLSrQUc2UMhndgzo5XIQhYMJNO5Cyme/bz+EbMhE2hkqtR
	1M5tPlb1swSG5CTh4pyrwpE=
X-Google-Smtp-Source: APXvYqwvm6mum98bX7TEgK7mBUZp1TlWW5FOufWruUJPzwd3m08chS28QM1AV4Zsf7WhKaA7gcCb+g==
X-Received: by 2002:a6b:6909:: with SMTP id e9mr5000486ioc.124.1572892904214;
        Mon, 04 Nov 2019 10:41:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8149:: with SMTP id e70ls3158488ild.7.gmail; Mon, 04 Nov
 2019 10:41:43 -0800 (PST)
X-Received: by 2002:a92:360b:: with SMTP id d11mr29200311ila.249.1572892903812;
        Mon, 04 Nov 2019 10:41:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572892903; cv=none;
        d=google.com; s=arc-20160816;
        b=SbikTuWs+TUY8hjreyfBVulkWnOuoZC7exCRrJrsoYhAZ4Ev1CMxBtSDToI1azjbZI
         T1+obcv6E01uZa2qiObahKqGASVH1IXgUWFaW1Q0PLhR6dd1MrjCIzlrnpaJ0Y/cZ3Cn
         CWynr4cwJ6c93u3OH5ShmE0TwkuseAWotzOddIu881siew+6Edwam1EYCk7Ou6gW1vFb
         SwXq2LCanyhKk42Rhjn4aEfbIwtbHzlZnxiEkpW86sFNV1TQiX/FrTs7TZDEDStIV8+w
         LU+YFY7LXt81gT5OgcDXmC0x9GT71T0BtHsqzKbKRbfPxzj35PePcHhDV1wUDt9isW6I
         SqBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ph+IqdOgslNSLP+IIBkbCH/w84oSj6hoU4Op/Hgua2Y=;
        b=KYoRWuqfkd1OWryE30/13Msbia6IpchG5Iio1opNDKgjvHqcNqAi1oSKBQu5oLiURB
         KM1FdsacvIXkHwCYGDrWvpMMXkF1LmvWNYHfG8DLetmI0Il/E1x/q5ViFXISBW060qc2
         HRDsA5wHcflTnAiDFRnqIHtcPkg4W8x0R9Coi4fpEPzh2LdXLYBa0cVP024YDeKWR18n
         Tg7xyaIKZ2NLKkkO8Onoq3XhUu31+9NhI/JnX8C1dEVBGi1ed72tvDCztDRvgiuNTvDx
         XUs/rZ/oMv8lBOMkxOqszkp7WZf1nLO6rp/XSoQSVdS3bRWCrtjgUgdTkhOBZrGbiDmZ
         F0cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JAbFW9ec;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id x18si1087178ill.2.2019.11.04.10.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 10:41:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id l14so974085oti.10
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 10:41:43 -0800 (PST)
X-Received: by 2002:a9d:7308:: with SMTP id e8mr119704otk.17.1572892902802;
 Mon, 04 Nov 2019 10:41:42 -0800 (PST)
MIME-Version: 1.0
References: <20191104142745.14722-1-elver@google.com> <20191104164717.GE20975@paulmck-ThinkPad-P72>
In-Reply-To: <20191104164717.GE20975@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Nov 2019 19:41:30 +0100
Message-ID: <CANpmjNOtR6NEsXGo=M1o26d8vUyF7gwj=gew+LAeE_D+qfbEmQ@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=JAbFW9ec;       spf=pass
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

On Mon, 4 Nov 2019 at 17:47, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Mon, Nov 04, 2019 at 03:27:36PM +0100, Marco Elver wrote:
> > This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
> > KCSAN is a sampling watchpoint-based data-race detector. More details
> > are included in Documentation/dev-tools/kcsan.rst. This patch-series
> > only enables KCSAN for x86, but we expect adding support for other
> > architectures is relatively straightforward (we are aware of
> > experimental ARM64 and POWER support).
> >
> > To gather early feedback, we announced KCSAN back in September, and
> > have integrated the feedback where possible:
> > http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com
> >
> > We want to point out and acknowledge the work surrounding the LKMM,
> > including several articles that motivate why data-races are dangerous
> > [1, 2], justifying a data-race detector such as KCSAN.
> > [1] https://lwn.net/Articles/793253/
> > [2] https://lwn.net/Articles/799218/
> >
> > The current list of known upstream fixes for data-races found by KCSAN
> > can be found here:
> > https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan
>
> Making this more accessible to more people seems like a good thing.
> So, for the series:
>
> Acked-by: Paul E. McKenney <paulmck@kernel.org>

Much appreciated. Thanks, Paul!

Any suggestions which tree this could eventually land in?

Thanks,
-- Marco

> > Changelog
> > ---------
> > v3:
> > * Major changes:
> >  - Add microbenchmark.
> >  - Add instruction watchpoint skip randomization.
> >  - Refactor API and core runtime fast-path and slow-path. Compared to
> >    the previous version, with a default config and benchmarked using the
> >    added microbenchmark, this version is 3.8x faster.
> >  - Make __tsan_unaligned __alias of generic accesses.
> >  - Rename kcsan_{begin,end}_atomic ->
> >    kcsan_{nestable,flat}_atomic_{begin,end}
> >  - For filter list in debugfs.c use kmalloc+krealloc instead of
> >    kvmalloc.
> >  - Split Documentation into separate patch.
> >
> > v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
> > * Major changes:
> >  - Replace kcsan_check_access(.., {true, false}) with
> >    kcsan_check_{read,write}.
> >  - Change atomic-instrumented.h to use __atomic_check_{read,write}.
> >  - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
> >    contexts.
> >
> > v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com
> >
> > Marco Elver (9):
> >   kcsan: Add Kernel Concurrency Sanitizer infrastructure
> >   kcsan: Add Documentation entry in dev-tools
> >   objtool, kcsan: Add KCSAN runtime functions to whitelist
> >   build, kcsan: Add KCSAN build exceptions
> >   seqlock, kcsan: Add annotations for KCSAN
> >   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
> >   asm-generic, kcsan: Add KCSAN instrumentation for bitops
> >   locking/atomics, kcsan: Add KCSAN instrumentation
> >   x86, kcsan: Enable KCSAN for x86
> >
> >  Documentation/dev-tools/index.rst         |   1 +
> >  Documentation/dev-tools/kcsan.rst         | 217 +++++++++
> >  MAINTAINERS                               |  11 +
> >  Makefile                                  |   3 +-
> >  arch/x86/Kconfig                          |   1 +
> >  arch/x86/boot/Makefile                    |   2 +
> >  arch/x86/boot/compressed/Makefile         |   2 +
> >  arch/x86/entry/vdso/Makefile              |   3 +
> >  arch/x86/include/asm/bitops.h             |   6 +-
> >  arch/x86/kernel/Makefile                  |   7 +
> >  arch/x86/kernel/cpu/Makefile              |   3 +
> >  arch/x86/lib/Makefile                     |   4 +
> >  arch/x86/mm/Makefile                      |   3 +
> >  arch/x86/purgatory/Makefile               |   2 +
> >  arch/x86/realmode/Makefile                |   3 +
> >  arch/x86/realmode/rm/Makefile             |   3 +
> >  drivers/firmware/efi/libstub/Makefile     |   2 +
> >  include/asm-generic/atomic-instrumented.h | 393 +++++++--------
> >  include/asm-generic/bitops-instrumented.h |  18 +
> >  include/linux/compiler-clang.h            |   9 +
> >  include/linux/compiler-gcc.h              |   7 +
> >  include/linux/compiler.h                  |  35 +-
> >  include/linux/kcsan-checks.h              |  97 ++++
> >  include/linux/kcsan.h                     | 115 +++++
> >  include/linux/sched.h                     |   4 +
> >  include/linux/seqlock.h                   |  51 +-
> >  init/init_task.c                          |   8 +
> >  init/main.c                               |   2 +
> >  kernel/Makefile                           |   6 +
> >  kernel/kcsan/Makefile                     |  11 +
> >  kernel/kcsan/atomic.h                     |  27 ++
> >  kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
> >  kernel/kcsan/debugfs.c                    | 275 +++++++++++
> >  kernel/kcsan/encoding.h                   |  94 ++++
> >  kernel/kcsan/kcsan.h                      | 131 +++++
> >  kernel/kcsan/report.c                     | 306 ++++++++++++
> >  kernel/kcsan/test.c                       | 121 +++++
> >  kernel/sched/Makefile                     |   6 +
> >  lib/Kconfig.debug                         |   2 +
> >  lib/Kconfig.kcsan                         | 119 +++++
> >  lib/Makefile                              |   3 +
> >  mm/Makefile                               |   8 +
> >  scripts/Makefile.kcsan                    |   6 +
> >  scripts/Makefile.lib                      |  10 +
> >  scripts/atomic/gen-atomic-instrumented.sh |  17 +-
> >  tools/objtool/check.c                     |  18 +
> >  46 files changed, 2526 insertions(+), 206 deletions(-)
> >  create mode 100644 Documentation/dev-tools/kcsan.rst
> >  create mode 100644 include/linux/kcsan-checks.h
> >  create mode 100644 include/linux/kcsan.h
> >  create mode 100644 kernel/kcsan/Makefile
> >  create mode 100644 kernel/kcsan/atomic.h
> >  create mode 100644 kernel/kcsan/core.c
> >  create mode 100644 kernel/kcsan/debugfs.c
> >  create mode 100644 kernel/kcsan/encoding.h
> >  create mode 100644 kernel/kcsan/kcsan.h
> >  create mode 100644 kernel/kcsan/report.c
> >  create mode 100644 kernel/kcsan/test.c
> >  create mode 100644 lib/Kconfig.kcsan
> >  create mode 100644 scripts/Makefile.kcsan
> >
> > --
> > 2.24.0.rc1.363.gb1bccd3e3d-goog
> >
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104164717.GE20975%40paulmck-ThinkPad-P72.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOtR6NEsXGo%3DM1o26d8vUyF7gwj%3Dgew%2BLAeE_D%2BqfbEmQ%40mail.gmail.com.
