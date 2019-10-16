Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJNPTPWQKGQE2TOAMDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id F0556D8B42
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:11 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id o128sf2042804wmo.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215270; cv=pass;
        d=google.com; s=arc-20160816;
        b=xEKHPQGitP48Krm1VD7FbNJT3j9bDBKu9/9Xe4Zlm73Zej6338BWVvCA3uVcGyF5ii
         4QAomedQJy7FzuM5xtSzza8eSFptf7GccHb9HMtEUlSHMto3qvraRWxkkx5K9tU4knF7
         KWnDO6U5Wzjkior8vKdOJ0zvdOgQg/dNV02whOMAYTdLacLRXS5UOMUMjvUQW2GFI0B1
         cgoBK55gDuLQ2s2RYKvOghw5Akh0/pzIsHHyrd8soyg8o5IDrQnWsfefWNMTAVRlQ6ZN
         2FOEIH9E9Uj977U+yoJDBR+20hbm0XuyOVPfaBm6K9nrg9eF3MfiJ0fVuUbV9pRgB503
         awiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pWR8Q9OZDljKGhIVAV5rKywshsby46LOeuh+wH+v8iU=;
        b=yRUxBXvqdqgh5mEVvyTNr7PhG5TRldlox9XgUdDwjhn+bZ89iaWiMop/5LYo76iEZb
         Pf2nEHFvvcMwXyZHJoywoq2zCSm5BpYKUJbvaNitPEyBR1n9tRpHSQNsgAgyHAmqQPIn
         KFTcltga97x/Lv5JhT97dAWpZpAFcMM3EUMct05Gywba16/PqcvIUvV+4DiZlhXGlL8k
         XvDAGI9lwrhELvZey83aN9fDVtHlC4ZJgkFN9sWd/PSizg1h8zkoNzr7VeBkt5b+Z75e
         +0XIhtio8W9emdCZL3am9MeZjFtc6hL8PetezkXvNepnFd3QiR9aZcqiMxoykJPzFNxx
         PpJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvnoMqX1;
       spf=pass (google.com: domain of 3o9emxqukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o9emXQUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pWR8Q9OZDljKGhIVAV5rKywshsby46LOeuh+wH+v8iU=;
        b=ADnXS1rmDR7g3nV+9hBbfh1S62evDIEueHHgQ6BCjWfHV2ONJOAVdoaJ2Xgw+yv7JK
         lN/wlW1dCkUHisDeFNhsTxq5l6JP6PUlYRcR8nA4fuhmmk2CWGvJ2jbiOFXR57A3l82c
         yrP22SAzcNecDdaPxVHoC7oTV+QA0itQBckGXflnxJR8ODFpfL7s23Yz/YvzmJ12bIe7
         K2HCczcm1vmXH8GqJfpNDgxhEsGRpT8vzUhSY2D1zK8DJ4kEZuyEthDt+cggSDRKhHOq
         m4P7wlKEEZ/RIvX3aXd13soCa0H+lUpfJJiAeQrzwOn01Uz69iWj+3mTG+MSGXQ5t86z
         5Ubg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pWR8Q9OZDljKGhIVAV5rKywshsby46LOeuh+wH+v8iU=;
        b=OOy+JQE8NoupxHDXp3WWa67A+BnacxnypTHTQAGmAc4Iv9NVv4mc2kTjkyhobUetXB
         Ok/TCclrEz0atB79C5nYHv6IhI77ntCLI7u7+mc7CyGEfa+32X4qpSA9UHQfJ7kpJc80
         lRsU5U341i32Q9kdz+DgWvEsUyr4vr3kJ5os1FlUYZQzzJbW1T+wKr84wAeQ0om353sE
         q+4LL/AEBSpggkorhcd8CVeN/EF4znPKr26wzWA6e9Bx4QDW3nRqHnr9Pv2hAhVMJU7C
         JwPWAFKGdFd+sxFw3qvFP8vfoel4V6vw5FoGagmff6zykgtlbsOuodY4I1o6fJ9G5yCY
         kJTQ==
X-Gm-Message-State: APjAAAVpPRzO9TrU1Zj4Pi9jw2YUYUQ0f4DpBs4NI4hQ/bmSK5sUABri
	aM8GNDY9KydrlVLowgzG0kE=
X-Google-Smtp-Source: APXvYqxdg+dXc7hFBAp2x7qrPoKqz9AXKd43B4TcQDHbQcnsi1wkm7EljlfWJTEDA8YBcO/f1TBb+Q==
X-Received: by 2002:a05:600c:205:: with SMTP id 5mr2343191wmi.19.1571215269650;
        Wed, 16 Oct 2019 01:41:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:f707:: with SMTP id v7ls845807wmh.4.gmail; Wed, 16 Oct
 2019 01:41:08 -0700 (PDT)
X-Received: by 2002:a1c:7313:: with SMTP id d19mr2381328wmb.16.1571215268846;
        Wed, 16 Oct 2019 01:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215268; cv=none;
        d=google.com; s=arc-20160816;
        b=S0qGpBVwlCvf/vRqsn9VNceGpsUrhbyQyOTYPfpGp+l2+/1cVVL5hiMH+vOL9hh5dh
         3k/hg6Stt2FwTsEL5sl3hSGirPhVIGm2MLVaP9ZigjqH0Hj9YDZ/wwhqfMhZnbEAKFC+
         lgkUP63inZi5Ds7o7PLc9KmIa0h6whhRJi4XSJ0P419Oq/Q8NT7DjiHrkENgUUa1TzPb
         LAmxTOts+VcGH+iSBYnlusXLY6D+A22JumZD8EQcVz2rLxVM1mgv5J4DmYfQtHi65EFW
         LTCMnFukwDPK6SK1PwmYCoayn9csgXtAXbmHFpcNKGfUs6f+87ZWg3aJrw20iNz2/Esg
         I/Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=IToO3TxaVYb6aPcdpP1nSr/83vwykcAUYMHrIbrPyZM=;
        b=CUTaR0U7y6VbDl+TbwSMy6GsUEmtIWRwZSHKGCQTXornPmhJEzaNgr8npWkqV7W+8T
         pO9hmOmZXkVr87lDlT7l8V5cNLyRVTYWnkLeeeOrVbFj5F1CCk78yUW3mzUcUMHToyxk
         YrFTNSK2/2bcIpNy13JnqTyrfjluFThxNSzwpoBy4FWcSF37iXlTK4XbYU+9SnTlxYzA
         daZeFBl9pRB9RIlYuL0zH3b3HUx2CIDyLE/BHoMI/ta5M7Id/KouyufcbwAL92+8wfkS
         oQmoacVxcLX8ao8zfLs0khHh1IXGwctvV5nk4gwNSdl6v4dYJVX8f5H2l1UU8nWRtsvZ
         39sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bvnoMqX1;
       spf=pass (google.com: domain of 3o9emxqukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o9emXQUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e17si240941wre.3.2019.10.16.01.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o9emxqukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id p8so7079775wrj.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:08 -0700 (PDT)
X-Received: by 2002:adf:fecd:: with SMTP id q13mr1712303wrs.224.1571215267988;
 Wed, 16 Oct 2019 01:41:07 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:51 +0200
Message-Id: <20191016083959.186860-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 0/8] Add Kernel Concurrency Sanitizer (KCSAN)
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
 header.i=@google.com header.s=20161025 header.b=bvnoMqX1;       spf=pass
 (google.com: domain of 3o9emxqukceagnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3o9emXQUKCeAGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

Marco Elver (8):
  kcsan: Add Kernel Concurrency Sanitizer infrastructure
  objtool, kcsan: Add KCSAN runtime functions to whitelist
  build, kcsan: Add KCSAN build exceptions
  seqlock, kcsan: Add annotations for KCSAN
  seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
  asm-generic, kcsan: Add KCSAN instrumentation for bitops
  locking/atomics, kcsan: Add KCSAN instrumentation
  x86, kcsan: Enable KCSAN for x86

 Documentation/dev-tools/kcsan.rst         | 202 ++++++++++
 MAINTAINERS                               |  11 +
 Makefile                                  |   3 +-
 arch/x86/Kconfig                          |   1 +
 arch/x86/boot/Makefile                    |   1 +
 arch/x86/boot/compressed/Makefile         |   1 +
 arch/x86/entry/vdso/Makefile              |   1 +
 arch/x86/include/asm/bitops.h             |   2 +-
 arch/x86/kernel/Makefile                  |   6 +
 arch/x86/kernel/cpu/Makefile              |   3 +
 arch/x86/lib/Makefile                     |   2 +
 arch/x86/mm/Makefile                      |   3 +
 arch/x86/purgatory/Makefile               |   1 +
 arch/x86/realmode/Makefile                |   1 +
 arch/x86/realmode/rm/Makefile             |   1 +
 drivers/firmware/efi/libstub/Makefile     |   1 +
 include/asm-generic/atomic-instrumented.h | 192 ++++++++-
 include/asm-generic/bitops-instrumented.h |  18 +
 include/linux/compiler-clang.h            |   9 +
 include/linux/compiler-gcc.h              |   7 +
 include/linux/compiler.h                  |  35 +-
 include/linux/kcsan-checks.h              | 116 ++++++
 include/linux/kcsan.h                     |  85 ++++
 include/linux/sched.h                     |   7 +
 include/linux/seqlock.h                   |  51 ++-
 init/init_task.c                          |   6 +
 init/main.c                               |   2 +
 kernel/Makefile                           |   6 +
 kernel/kcsan/Makefile                     |  14 +
 kernel/kcsan/atomic.c                     |  21 +
 kernel/kcsan/core.c                       | 458 ++++++++++++++++++++++
 kernel/kcsan/debugfs.c                    | 225 +++++++++++
 kernel/kcsan/encoding.h                   |  94 +++++
 kernel/kcsan/kcsan.c                      |  81 ++++
 kernel/kcsan/kcsan.h                      | 140 +++++++
 kernel/kcsan/report.c                     | 307 +++++++++++++++
 kernel/kcsan/test.c                       | 117 ++++++
 kernel/sched/Makefile                     |   6 +
 lib/Kconfig.debug                         |   2 +
 lib/Kconfig.kcsan                         |  88 +++++
 lib/Makefile                              |   3 +
 mm/Makefile                               |   8 +
 scripts/Makefile.kcsan                    |   6 +
 scripts/Makefile.lib                      |  10 +
 scripts/atomic/gen-atomic-instrumented.sh |   9 +-
 tools/objtool/check.c                     |  17 +
 46 files changed, 2364 insertions(+), 16 deletions(-)
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
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-1-elver%40google.com.
