Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIPLQDXAKGQEDBVUI7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 291FBEE24A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:28:51 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id g8sf13462561ybc.6
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:28:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877730; cv=pass;
        d=google.com; s=arc-20160816;
        b=nMSdKyr/F7ou+HvNdT/8UKrr5zovuHng9dotevibPdRSHpcaLfWLZAsBon8U8EB4Hy
         t3CPQ0bgodiZXxijv9Habi/SVzkCCYfDRhmRHa9fSkUZVKq65+AuVbQ94vTZuXVQx5Jf
         yR3W1QOKVTwGWU1EIvqgMNsBDV/IjdjkIIiajWHcJwoq+0ztvvcc4lcZBLhsgwhWtvhc
         NYkcfBKTNvh6NUduk1JYBNXyqZzjNrcspjzmJWInaZWWdOMA1Bj03tS90+gS+G89jxuz
         xrBh8WGeJcNAsbxpmFNGt7QP1Y1HzvWNM8wvdlMd1a9cp+bR2VCvCRzy0RBswehC4CKY
         fcSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=XD2fM1v8SPkOuu1EpoiA+FClq8A6zZOq9f6Sr8tqNgU=;
        b=vatVGMet30khtAfMUoA27gUCP0rsU9d87QsWbo+JVarEa9+Rp46YX1hzhwX/TDKR6Q
         99N1FMxXsFL9/fCcOl9moNQGC2MjNYU+TH0PLFN37oVCYkUNEgh6+hH/RKrrtRABxSpZ
         X9Y2Hjp/n4BBtTC5q2Pq7QKq/tHPnZyHbCaJwbfhoL3jSEP990PBQFpb27vEOpcElQx0
         guM/3zlp38eT2ahRKospROeY9iaEfRGMOFHuYNLmEYrYkLzYVTBazKg3SQItwUNkQOA1
         2BNWnxYUdYYvvC0RvY9aFLRVGU2Zb9ZFgDtflEzU/ffZo1pWS68yYC1+jV8Sf/cMlNdG
         evXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iYeCrSfz;
       spf=pass (google.com: domain of 3odxaxqukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3oDXAXQUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=XD2fM1v8SPkOuu1EpoiA+FClq8A6zZOq9f6Sr8tqNgU=;
        b=L8KLw0p2/H1E3VxpSqjJ+wQV5TiPp+IqaAvDEdffj3jKvSMQIgXawxwjF8WEFgM0H9
         EBjwLTk3AmCmP5YYR9fgvSC8N57/tgPNg+t4EitU0f4J0KhC0WCUIHVmo2nD0JOCLtIB
         dcL53KRDeL6aB5O8k215HPgDsx8BDDPk5dQogLdampXZot6N/8LLyEbqEa+MgiZH31qw
         zYV//V14w3SLpqHx/1IEY1Vi4iWkkLYI1fk6cEuK4byLoVm3yAlkLAlwRLkA5ypRAxyC
         TeaGhSbu7s6o6q1JBjZHqqSLbKxdt8sxynnv3jl3iqnq7OEXwHEpQEZOiUEn7RnIiPkc
         5lpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XD2fM1v8SPkOuu1EpoiA+FClq8A6zZOq9f6Sr8tqNgU=;
        b=gXUEEGrlCsibvfT0fIrrzclbKOknb7LSqx3How++iKOUblCS7N5Og/iA9ItyxSOBEb
         dYmlG8gFwflqpZEj8fgNhDXo63dLe6v8vbFA9jdIu3wSXlxq8RB0CzfBKlYdevo3tmUp
         dGiTbHHkBR5wtow+HRBj+6RDuKyDN+OTbDynCsC93+cUtU6/XQH0yUC6xerKqGkrQF7a
         prxQiRbKiAX6mA9jHAHFUoiQLjq8Rlk2skLnu6s2Rt75C9SI4ZBNycYlsqBbnHF76/5w
         KEzSZiRHfidpYpzYryzcoXWuwnmdFMl7nqJFKkmTECvkmxJE16t6SaMCdEzJdyRbI3bJ
         ymUA==
X-Gm-Message-State: APjAAAXjVKEq3+TPoAXK+gnOw9Aij1XnUCBGBtI74mq8ZXXqIpje2/SU
	MRAG/184mKEQKiRg8NY3QFw=
X-Google-Smtp-Source: APXvYqx3DveGiPBS/OiEgFdho6vSePsZAIffY3nXgtyJG8ZMhSjovtn2yi8y3851V1hqmozk31A+9Q==
X-Received: by 2002:a25:9a48:: with SMTP id r8mr6390528ybo.514.1572877729983;
        Mon, 04 Nov 2019 06:28:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:adcd:: with SMTP id d13ls2404475ybe.10.gmail; Mon, 04
 Nov 2019 06:28:49 -0800 (PST)
X-Received: by 2002:a25:4292:: with SMTP id p140mr8021299yba.455.1572877729484;
        Mon, 04 Nov 2019 06:28:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877729; cv=none;
        d=google.com; s=arc-20160816;
        b=eyaDR+1taHpQvhVHb+13P6yCwJo8/+MKP7MYuJ3JMIljx5BM449Hl6jSTccRKhB9pp
         fxl/Ngg7uo0jWaiotfUvNzutSfIoV+9KucHJS/qoOj8Xn78Bb87bqai5yEsJ3Hf6uxvx
         4IhldjvE7U/E/VOtSOJWHM1gFoNiyHEnPg1K1zvaZ8AUbiyi4gPapHwx3g+0+52a/u5D
         UFcsl07jfI9hdyjI8IvAH7e3E5AT10kV1Nl+ArmY+YeZVldFlT2lTSMCn2TisFhmk0gV
         2S+s3gJr84afqjztMa6MNEqtq4KhwEAwiAp+7XnY7AcMT17stOivyniHMB8NObvf2Hg1
         T2UA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=gOZJXriFYaJqnLiXWIeTvOu6TRK/57oj4m43E1U5Ltw=;
        b=fA5R/0qp/0noMKWMB8/94MjXhv89ryNFPqyneF4GM1iKrAV6mQV3R+f8dBt+aAFw48
         STJPAg7b6j51Q/H7YaXjZN5+lLt65u2lPR53D6gqP6R/m62mZe/Mokew9YBA3RRJ6stT
         JKoJvDl/idUOER3I7wo7GV8FIytUm9rUNr48/bqyZzY9RQ2IPYqYoznyOwZ2Yq63cKAa
         n6Jqdz2B29ZsoW8Fp3BaI6NQ5UuSNvrL9yuA2PSYl6AFvBTdrH2WuxCWO0GZg7pKIOYW
         5JG479t8GfTHNxg0y0lPu0hFrL0CT6Uzlze5vEZEckV6kj/tos5WIIt4N7SFkJwqsmN2
         ZmvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iYeCrSfz;
       spf=pass (google.com: domain of 3odxaxqukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3oDXAXQUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x94a.google.com (mail-ua1-x94a.google.com. [2607:f8b0:4864:20::94a])
        by gmr-mx.google.com with ESMTPS id c5si997120ywn.5.2019.11.04.06.28.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:28:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3odxaxqukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::94a as permitted sender) client-ip=2607:f8b0:4864:20::94a;
Received: by mail-ua1-x94a.google.com with SMTP id b19so1068627uak.5
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:28:49 -0800 (PST)
X-Received: by 2002:a67:fbd9:: with SMTP id o25mr5000794vsr.70.1572877728570;
 Mon, 04 Nov 2019 06:28:48 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:36 +0100
Message-Id: <20191104142745.14722-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 0/9] Add Kernel Concurrency Sanitizer (KCSAN)
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iYeCrSfz;       spf=pass
 (google.com: domain of 3odxaxqukcqefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::94a as permitted sender) smtp.mailfrom=3oDXAXQUKCQEfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
v3:
* Major changes:
 - Add microbenchmark.
 - Add instruction watchpoint skip randomization.
 - Refactor API and core runtime fast-path and slow-path. Compared to
   the previous version, with a default config and benchmarked using the
   added microbenchmark, this version is 3.8x faster.
 - Make __tsan_unaligned __alias of generic accesses.
 - Rename kcsan_{begin,end}_atomic ->
   kcsan_{nestable,flat}_atomic_{begin,end}
 - For filter list in debugfs.c use kmalloc+krealloc instead of
   kvmalloc.
 - Split Documentation into separate patch.

v2: http://lkml.kernel.org/r/20191017141305.146193-1-elver@google.com
* Major changes:
 - Replace kcsan_check_access(.., {true, false}) with
   kcsan_check_{read,write}.
 - Change atomic-instrumented.h to use __atomic_check_{read,write}.
 - Use common struct kcsan_ctx in task_struct and for per-CPU interrupt
   contexts.

v1: http://lkml.kernel.org/r/20191016083959.186860-1-elver@google.com

Marco Elver (9):
  kcsan: Add Kernel Concurrency Sanitizer infrastructure
  kcsan: Add Documentation entry in dev-tools
  objtool, kcsan: Add KCSAN runtime functions to whitelist
  build, kcsan: Add KCSAN build exceptions
  seqlock, kcsan: Add annotations for KCSAN
  seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
  asm-generic, kcsan: Add KCSAN instrumentation for bitops
  locking/atomics, kcsan: Add KCSAN instrumentation
  x86, kcsan: Enable KCSAN for x86

 Documentation/dev-tools/index.rst         |   1 +
 Documentation/dev-tools/kcsan.rst         | 217 +++++++++
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
 include/asm-generic/atomic-instrumented.h | 393 +++++++--------
 include/asm-generic/bitops-instrumented.h |  18 +
 include/linux/compiler-clang.h            |   9 +
 include/linux/compiler-gcc.h              |   7 +
 include/linux/compiler.h                  |  35 +-
 include/linux/kcsan-checks.h              |  97 ++++
 include/linux/kcsan.h                     | 115 +++++
 include/linux/sched.h                     |   4 +
 include/linux/seqlock.h                   |  51 +-
 init/init_task.c                          |   8 +
 init/main.c                               |   2 +
 kernel/Makefile                           |   6 +
 kernel/kcsan/Makefile                     |  11 +
 kernel/kcsan/atomic.h                     |  27 ++
 kernel/kcsan/core.c                       | 560 ++++++++++++++++++++++
 kernel/kcsan/debugfs.c                    | 275 +++++++++++
 kernel/kcsan/encoding.h                   |  94 ++++
 kernel/kcsan/kcsan.h                      | 131 +++++
 kernel/kcsan/report.c                     | 306 ++++++++++++
 kernel/kcsan/test.c                       | 121 +++++
 kernel/sched/Makefile                     |   6 +
 lib/Kconfig.debug                         |   2 +
 lib/Kconfig.kcsan                         | 119 +++++
 lib/Makefile                              |   3 +
 mm/Makefile                               |   8 +
 scripts/Makefile.kcsan                    |   6 +
 scripts/Makefile.lib                      |  10 +
 scripts/atomic/gen-atomic-instrumented.sh |  17 +-
 tools/objtool/check.c                     |  18 +
 46 files changed, 2526 insertions(+), 206 deletions(-)
 create mode 100644 Documentation/dev-tools/kcsan.rst
 create mode 100644 include/linux/kcsan-checks.h
 create mode 100644 include/linux/kcsan.h
 create mode 100644 kernel/kcsan/Makefile
 create mode 100644 kernel/kcsan/atomic.h
 create mode 100644 kernel/kcsan/core.c
 create mode 100644 kernel/kcsan/debugfs.c
 create mode 100644 kernel/kcsan/encoding.h
 create mode 100644 kernel/kcsan/kcsan.h
 create mode 100644 kernel/kcsan/report.c
 create mode 100644 kernel/kcsan/test.c
 create mode 100644 lib/Kconfig.kcsan
 create mode 100644 scripts/Makefile.kcsan

-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-1-elver%40google.com.
