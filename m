Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7OUHWQKGQEF2FPMQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id AE5C4DAF4F
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:28 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id a5sf1845936ybq.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321607; cv=pass;
        d=google.com; s=arc-20160816;
        b=NExLPXNtgu9uAKpXvoiZG8CIrfiGgb0Qq7vC6Tja/EfBK25jozUZYH57HFZrYNvkSD
         kEdGzt5sAhL/p/IMg5UaB6nrVM+VViTEOr3IFdpB2/oggq1zg7VgthZr14JGD10DkqbJ
         TEIiTQwhHJEArWAQRTrEtTtA4RIeWSv6rdoIAcuUGb0gjvfavqBLMHZoNUa/V0gWe2Sy
         CqFTJNsxfRJQ80+fM2URRejDN7SjVyde872X4uCAdc/2kXTPluVluRo2CrySbKX1jQBQ
         UPUSbljoxHt4HmXmSmQze9WurWWXshuycJ/uAK2otEH7a5zYASoin/nPNSg3bx4oSUtx
         e+Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=KdYx4j7s5nHA3P+1n1Z7bYBSPOrUVLI+II/R9Sz3b3w=;
        b=uRNzkSe83S6wp6My0fHynLkOgpREdlkLXYOH/w2RH295KIj7sYJIqTmcRmkK27KEe1
         KWz6zhY8E5K0xNCJkhao9MDMNWEYlQXGwVbDEULAcnaKnOkcJEXX3nilivLLMlAhJaEG
         rA3F4uKMYbmQ1i2iVGbmjgMXVw59J/2W3QgiCjnkEqM+Z4Jufvm4TgUywWAx443ILu7t
         alX0OEMmao05VOQkdvRtBvnQBIZMCc0PlVQ0c0/jne7BBAmMXLJ9ZF8NYEtfiGAyWo5B
         RjTGK7wpHzeBamf+n7UW+V6/NZFc1UIYuv8M6coZBDSKF2YpNLbqbuHTCUi5YnSAjtTN
         aESA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E3NOAAWo;
       spf=pass (google.com: domain of 3bxeoxqukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BXeoXQUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=KdYx4j7s5nHA3P+1n1Z7bYBSPOrUVLI+II/R9Sz3b3w=;
        b=ikU4JV83P2ySwNR+lq5ga9V3KdCyXM85FXTXh31Hn1+YO+PVP7AfvbQhQ5RJY+jQOB
         fuweJXbX2P3eXRvH6XBOXb6V4xxIPHQCvVYX6Obci0hyATTzqXoFXadUTOx7Pt4NFO0Y
         8kK+zu8UHCsznsWL7EhPn3wMw/BMAfVnePt4tSthmssTk0mV1BClvGSDUeN34GZxMvMB
         wdZk511NoJe+SR35bIctgKuBywYNCJWrEBa5qJ1anExnMZ/o2tvHgaJNNlarDxJJrSOW
         9/l6LP8/em6rtwHlzJIUzOy0icBAXWwTq1sSLC4T5BpK2bHLTbDxsXicxjckLfGDt9hQ
         AovQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KdYx4j7s5nHA3P+1n1Z7bYBSPOrUVLI+II/R9Sz3b3w=;
        b=hD3TExU0Yri1iH3gfrN0VIDfphN54R6i/+Ui+ymRKcRjbJrcisgv2asr8eksvO8vxx
         RCNG1BcKT08Mncm4ojaTOmyGtknUlW5VmudEM3N5vW0IEiu7W1UYada6GbkpVFI7+w6P
         wVXHmOhLhNli+rJHb3GOdgPOmrUUeTogYTXcuPXRaxApvia6mZYN6/WzgEIZpjgsHki8
         fkOhMb1+yPnWrqrdGmT1z//jRKz3kik1YPOoxz1JAkdVceuX9l/Kcwhzjub/TFyjztA6
         gUQORp75SnWSACftsXjR2TN6PGJvAqxIbdJa1YnQz4pvxckSkOfkkMUzb2yGylBcDpp9
         28dA==
X-Gm-Message-State: APjAAAUaREUi8kovIh1sAjD/SVhvOZYhUIl9Nlsec+YU58s4K+pAUbul
	xDrmNA9yFGDwYitqSSn1s4E=
X-Google-Smtp-Source: APXvYqwqQmuVvZ/lJMtAmRkVdC4wnX5Y/V/szu+g2VCwyiPUwBw3pjmg3jvwctlxHQHZgPJ75TEX6g==
X-Received: by 2002:a81:7004:: with SMTP id l4mr2963329ywc.462.1571321607265;
        Thu, 17 Oct 2019 07:13:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:db4d:: with SMTP id b13ls413366ywn.4.gmail; Thu, 17 Oct
 2019 07:13:26 -0700 (PDT)
X-Received: by 2002:a81:9486:: with SMTP id l128mr3053426ywg.334.1571321606657;
        Thu, 17 Oct 2019 07:13:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321606; cv=none;
        d=google.com; s=arc-20160816;
        b=qC5/VIG6RJO6E+R7oLuK11fIeAfvXUlCOVcqFMiGQL90vpP2H7HENB81gHxYq+FPAk
         7BhmG8k7FFh9SieQH2NA+7zwbD/haK2xas3Qk62n5jFZhQOJ4y0WlZ4My+5ykxzbefmq
         A1mVhRs4pkgA6C096jtgaOXiR8anwOi9vkxBPxt6AwPT68Hw0sm+Q/C+E0/45Zz4b49G
         Oq9LSCWQUGnpJWCJCvkvD22PPW+y1u8nxE7laPnvD8fKjWP3BYrOSTVJopP0clS2NEmb
         Hp+MnH6h35PCyvApuGLTGkHWE1yXXppuLgKZRoLQRZlFgn+woiBivKfgjvfJik/W13BB
         YgpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ahMy3naCKZUNeyQrUsfvkWdO2IwHI3ehg2cI/CL0H68=;
        b=W8QTamDc4FI5PMCbVyigJnpZ3eGIk0fI54dnWzy88mur+84NQzAqx6x0KqTVdtlA0z
         aqYbu9cLpBLLerBDW1s1wMWz5bhf+H1CY5HVGts7AJ67CQKL/67+ky+v+F1It5X33Mg3
         fn5eHHQdr3UspXdZZE8z9iZ5hWqZmvabpNzFXCdHhhkRPL7CECeNqtvwZgsM9RLCB3jH
         raxfxVZq2lHxBa4tEoO0fRcZvxLhgxIyWyNxpk5ab3eOwELYed7t+srON4Sv6x9RvUyR
         7QfKpREuQJETvuoooCzAP4as8ELc8ALdmIenMxO8YqCb2HfzGKLeh/WnzsXh3YFXJRGh
         0XlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=E3NOAAWo;
       spf=pass (google.com: domain of 3bxeoxqukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BXeoXQUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id r9si117641ybc.0.2019.10.17.07.13.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bxeoxqukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id o26so2398483qtj.17
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:26 -0700 (PDT)
X-Received: by 2002:ac8:1903:: with SMTP id t3mr4137772qtj.344.1571321605784;
 Thu, 17 Oct 2019 07:13:25 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:12:57 +0200
Message-Id: <20191017141305.146193-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 0/8] Add Kernel Concurrency Sanitizer (KCSAN)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=E3NOAAWo;       spf=pass
 (google.com: domain of 3bxeoxqukcygqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3BXeoXQUKCYgqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).
KCSAN is a sampling watchpoint-based data-race detector. More details
are included in Documentation/dev-tools/kcsan.rst. This patch-series
only enables KCSAN for x86, but we expect adding support for other
architectures is relatively straightforward (we are aware of
experimental ARM64 and POWER support).

To gather early feedback, we announced KCSAN back in September, and
have integrated the feedback where possible:
http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com

We want to point out and acknowledge the work surrounding the LKMM,
including several articles that motivate why data-races are dangerous
[1, 2], justifying a data-race detector such as KCSAN.
[1] https://lwn.net/Articles/793253/
[2] https://lwn.net/Articles/799218/

The current list of known upstream fixes for data-races found by KCSAN
can be found here:
https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-found-by-kcsan

Changelog
---------
v2:
* Elaborate comment about instrumentation calls emitted by compilers.
* Replace kcsan_check_access(.., {true, false}) with
  kcsan_check_{read,write} for improved readability.
* Introduce __atomic_check_{read,write} in atomic-instrumented.h [Suggested by
  Mark Rutland].
* Change bug title of race of unknown origin to just say "data-race in".
* Refine "Key Properties" in kcsan.rst, and mention observed slow-down.
* Add comment about safety of find_watchpoint without user_access_save.
* Remove unnecessary preempt_disable/enable and elaborate on comment why
  we want to disable interrupts and preemptions.
* Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
  contexts [Suggested by Mark Rutland].
* Document x86 build exceptions where no previous above comment
  explained why we cannot instrument.

v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com


Marco Elver (8):
  kcsan: Add Kernel Concurrency Sanitizer infrastructure
  objtool, kcsan: Add KCSAN runtime functions to whitelist
  build, kcsan: Add KCSAN build exceptions
  seqlock, kcsan: Add annotations for KCSAN
  seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
  asm-generic, kcsan: Add KCSAN instrumentation for bitops
  locking/atomics, kcsan: Add KCSAN instrumentation
  x86, kcsan: Enable KCSAN for x86

 Documentation/dev-tools/kcsan.rst         | 203 ++++++++++
 MAINTAINERS                               |  11 +
 Makefile                                  |   3 +-
 arch/x86/Kconfig                          |   1 +
 arch/x86/boot/Makefile                    |   2 +
 arch/x86/boot/compressed/Makefile         |   2 +
 arch/x86/entry/vdso/Makefile              |   3 +
 arch/x86/include/asm/bitops.h             |   6 +-
 arch/x86/kernel/Makefile                  |   7 +
 arch/x86/kernel/cpu/Makefile              |   3 +
 arch/x86/lib/Makefile                     |   4 +
 arch/x86/mm/Makefile                      |   3 +
 arch/x86/purgatory/Makefile               |   2 +
 arch/x86/realmode/Makefile                |   3 +
 arch/x86/realmode/rm/Makefile             |   3 +
 drivers/firmware/efi/libstub/Makefile     |   2 +
 include/asm-generic/atomic-instrumented.h | 393 ++++++++++----------
 include/asm-generic/bitops-instrumented.h |  18 +
 include/linux/compiler-clang.h            |   9 +
 include/linux/compiler-gcc.h              |   7 +
 include/linux/compiler.h                  |  35 +-
 include/linux/kcsan-checks.h              | 147 ++++++++
 include/linux/kcsan.h                     | 108 ++++++
 include/linux/sched.h                     |   4 +
 include/linux/seqlock.h                   |  51 ++-
 init/init_task.c                          |   8 +
 init/main.c                               |   2 +
 kernel/Makefile                           |   6 +
 kernel/kcsan/Makefile                     |  14 +
 kernel/kcsan/atomic.c                     |  21 ++
 kernel/kcsan/core.c                       | 428 ++++++++++++++++++++++
 kernel/kcsan/debugfs.c                    | 225 ++++++++++++
 kernel/kcsan/encoding.h                   |  94 +++++
 kernel/kcsan/kcsan.c                      |  86 +++++
 kernel/kcsan/kcsan.h                      | 140 +++++++
 kernel/kcsan/report.c                     | 306 ++++++++++++++++
 kernel/kcsan/test.c                       | 117 ++++++
 kernel/sched/Makefile                     |   6 +
 lib/Kconfig.debug                         |   2 +
 lib/Kconfig.kcsan                         |  88 +++++
 lib/Makefile                              |   3 +
 mm/Makefile                               |   8 +
 scripts/Makefile.kcsan                    |   6 +
 scripts/Makefile.lib                      |  10 +
 scripts/atomic/gen-atomic-instrumented.sh |  17 +-
 tools/objtool/check.c                     |  17 +
 46 files changed, 2428 insertions(+), 206 deletions(-)
 create mode 100644 Documentation/dev-tools/kcsan.rst
 create mode 100644 include/linux/kcsan-checks.h
 create mode 100644 include/linux/kcsan.h
 create mode 100644 kernel/kcsan/Makefile
 create mode 100644 kernel/kcsan/atomic.c
 create mode 100644 kernel/kcsan/core.c
 create mode 100644 kernel/kcsan/debugfs.c
 create mode 100644 kernel/kcsan/encoding.h
 create mode 100644 kernel/kcsan/kcsan.c
 create mode 100644 kernel/kcsan/kcsan.h
 create mode 100644 kernel/kcsan/report.c
 create mode 100644 kernel/kcsan/test.c
 create mode 100644 lib/Kconfig.kcsan
 create mode 100644 scripts/Makefile.kcsan

-- 
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-1-elver%40google.com.
