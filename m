Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUVRVXCAMGQEO2PTHHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 34ACEB1709A
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 13:51:48 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3a50049f8eesf170578f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 04:51:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753962707; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZvbQYbmXi8McUpWGuluVpizocQKFp6f26mPt+J/IJ9NCT6ptNdXWNsj3lh0Yo0mVg8
         feIeYAVTaNCdTls+gs77+jXOxSWAzuwIMr4NOj/xIBT3PbQRvWd6WM+fiRfsL2wJVYpj
         oZIEtsWvjwNWpC0aP16paPySQjZa5H0GKqLEE09uL8Jl9bHBACB8CVYOnTlinxzUZCoW
         WCmfVSepJlCJa74Q/AKkBwjNlFw9RbYtT9N75NZ6zUOmLSW/Y/G7ExBhTD2su9bN/uGL
         BI7L4w67d+hVBS2IAJcdAG4AUIOcfLTt0nsTZib3LmYuXfMwlvW5zOEI7dsnawE53gR1
         0RvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=5gZwGmN2Pq/0MLwRZxP4FI8mTqMdc9pAbcBvNgnITjg=;
        fh=h22Xd/vuGjc5yN0ME4bKaqGZ+XEUfpKLiX0uUp+k74c=;
        b=W5h7yyKF+dWfpU179rtLQN23mb+LwTT/f5hMU1IOnEF6r03GX8V3WSC7f8xAd5AH0U
         jEq9Rm1wjhD0HvVy719+VvBs4fqwlv56T3nZVeFfUkIng/d+LZG5FAqPG9mRuP1WsfCL
         2g05p/iIEYdbn+0abLQICid4PStjLwHDiby4xkh2DiuYAp8pmi749LJbnuUdcEE1PCkP
         KHwLT9Yar1PrgXGeiv/P+ndk2CBclkHPtzPq04UlgrVmNRaIEwQv6AWNfZYheUDIVX1Y
         kNf8QpTKV3UQqjpFEHadf3xGXckc5Um0cEDNSMnlPidSiwQQOBpMgfBR4SB11Jwif0pb
         GLeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gYFBTD2j;
       spf=pass (google.com: domain of 30filaaykcfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30FiLaAYKCfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753962707; x=1754567507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5gZwGmN2Pq/0MLwRZxP4FI8mTqMdc9pAbcBvNgnITjg=;
        b=Ea9zHegf0fhsgQNZDTXrflHXWSqEAW9cq7oNxAb9bLZgdD9T7n7ivnUskXU/XZaNvd
         tOtPVi6DQt/roE9f8PO9vE5mqve3jJBpQxKxNyalD/9avAH8BrDtqUOTAJ3Vs15Az5J9
         Y0MOxFRoO3pyEp/lbnYxpvHaDLmeXgKrIkVS51Ndp7tncCPLqusf9bSzQzWbGkPHBP48
         ZqDzyS78p6UUPFvDBBE1JeaiSvY3lizCDMZw90rbA4sezQIbVz2ye7Oq+f4X3giJ2jkA
         MS7G0N++5yAzYJcOomzlF0Mf5mI+f74AZ2TTulvoqFfuewq6aQUh9hLlDfC65cwehW0p
         Ah7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753962707; x=1754567507;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5gZwGmN2Pq/0MLwRZxP4FI8mTqMdc9pAbcBvNgnITjg=;
        b=m4b4dQkNJDQY1jE5YN0sPvOIzUvfm2pZM8fztmPkOkOSv+FwfDpTIBDUywrzfnEZY6
         HQweoCJMUzxkHCMEVTySLYeiDwTWr/06vN67lCQn7bToIeG5/qczuwd1fcECehcIIU5I
         sWiaZuflkje6NKtW2sCbXoCgslCcOxr8aH/cFWnHx6BfYuI7lWsNwoFWcrnTuT8MwVMR
         jvMTfhsmMLwThAjcQ+ABqp0QFyfePC1iEOlQT9vnWz1rmRFHdTF7QXixENUegbEMrsDA
         gTNz1bAcgddVPk3ZuHRTpBSDBNXjNhfhmdq3Lvat+lvB0vf4NdT/SUZPcDV3eJVlzKsS
         KCtw==
X-Forwarded-Encrypted: i=2; AJvYcCUzGkZmRuws8AeLclWZE43lpC9VphiNLAbswCuan9efCfvc8Vwkle0akUj7vKVGhwAxlVRtxw==@lfdr.de
X-Gm-Message-State: AOJu0YzgMBy77ExLc22wLdtea7NhnvKqFD2JNr5eqCmtKSl4INBMcg8Q
	ZnRJvJM8ZompvpjbY2gyXTQT1wN+S6qI0CheDJYL1DAO8bHxFbA/1da6
X-Google-Smtp-Source: AGHT+IGm37MDA+6G7a091WzGl+BzC3z6P5fQAOV+x59uc+syYTOZQDLj4uafqcHPnl0aJ7PHulvN2g==
X-Received: by 2002:a05:6000:2dca:b0:3b7:9bd2:7ae7 with SMTP id ffacd0b85a97d-3b79bd27d89mr2114612f8f.57.1753962707137;
        Thu, 31 Jul 2025 04:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfe2MCDSenKQBSco7GimAcsNeeaQQ6wfMTmFmjSQg8TRw==
Received: by 2002:a05:6000:40cd:b0:3b7:8c4e:b7bd with SMTP id
 ffacd0b85a97d-3b79c3dd694ls385149f8f.2.-pod-prod-04-eu; Thu, 31 Jul 2025
 04:51:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUrSGPMS6fyL2/djxdAEgij4ugJmzvrXFJFmT2UibEsH/nWsw1UQbo8IUWSJBrNUnOEJKm/kd4oi/o=@googlegroups.com
X-Received: by 2002:a05:6000:2501:b0:3b7:974d:533f with SMTP id ffacd0b85a97d-3b7974d58a4mr3830467f8f.34.1753962704510;
        Thu, 31 Jul 2025 04:51:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753962704; cv=none;
        d=google.com; s=arc-20240605;
        b=OHb2GUmawIpChZEcLV7V5nTuK8YkJQw5V+MqSh3kxp5VnvaT0ejV3VbtS4kYtJJZEo
         siS8ffrRbIwahKkuPYyPp4rxRAm20/2eDT6b22vsr4eQ1oOAx8CvNYmYJpikXWaP/PSp
         OtNjcYceuSnJ1k1uf6D4bNxCcJ4SOyV0zJ5DNy9up3Uo8q4mgG+gwTTjlFuA5x15ml8T
         2rHX5SfR+AlOAKUN4MEUNDlGmWUxtw0hdDwb6hRupRPbdONW43kMNF/NI6WFzdQICIJs
         47XMYgG6HMqSYhi1u+VpuaISl0yqoRO3lo20A5YgMVLBmH8y8+/WlX1K5Y+LNHu//CFj
         UsOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=cckhx9CXRNcAY8FjYomyKrgfIuhjcELUGfeGvXt5wWc=;
        fh=vIJgjwa2JCVCHpxe8GQqgJHeE+r9lETfq3qVag6Zg4s=;
        b=ZZW1BL3vu3Z+OVOkQfkaJRnLbDOhaCtaSIANALAd+rPNRK9wefM3kb4N1T4yhp/2I5
         dVRwfhj0jKra1xB6FXig5BMUmZfzTdDhFviS13L5kKk9Cony046uzmjWTDQoJkAe5+6e
         qWa5qp4FO0NFyB5+JI4hFqd0mtqZ0bi9epOkdav0XFAJKIlYl9uCMbbCf3O5cfvmcfdU
         36T2pDorAnaW77PwI5lK/niRDHWx/Cu4lD9iWIRwbieFIEWhtVp5bOB/fRLjxHNkXpKN
         FIh7iBD5cbDzlquuLwOOvDPDc3W0rOwPQflpHrAkPsPUZ3SkZyfdl4Qe0f1h6KnYnmzf
         hYCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=gYFBTD2j;
       spf=pass (google.com: domain of 30filaaykcfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30FiLaAYKCfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c46a1f6si40629f8f.5.2025.07.31.04.51.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Jul 2025 04:51:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30filaaykcfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3b7882c0992so511368f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 31 Jul 2025 04:51:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVliQnrmNvvDvlNdvfJb7fecuiOiW7tfwYSUXfNku/cKUU2z7x3bsu3rdrXmbG5YHEvGZ1pbZu16W8=@googlegroups.com
X-Received: from wrus5.prod.google.com ([2002:a5d:6a85:0:b0:3b7:95af:cd73])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2889:b0:3b6:cf8:64b3
 with SMTP id ffacd0b85a97d-3b794ffcfcamr5188031f8f.34.1753962704086; Thu, 31
 Jul 2025 04:51:44 -0700 (PDT)
Date: Thu, 31 Jul 2025 13:51:29 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250731115139.3035888-1-glider@google.com>
Subject: [PATCH v4 00/10] Coverage deduplication for KCOV
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=gYFBTD2j;       spf=pass
 (google.com: domain of 30filaaykcfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30FiLaAYKCfkhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

As mentioned by Joey Jiao in [1], the current kcov implementation may
suffer from certain syscalls overflowing the userspace coverage buffer.

According to our measurements, among 24 syzkaller instances running
upstream Linux, 5 had a coverage overflow in at least 50% of executed
programs. The median percentage of programs with overflows across those 24
instances was 8.8%.

One way to mitigate this problem is to increase the size of the kcov buffer
in the userspace application using kcov. But right now syzkaller already
uses 4Mb per each of up to 32 threads to store the coverage, and increasing
it further would result in reduction in the number of executors on a single
machine.  Replaying the same program with an increased buffer size in the
case of overflow would also lead to fewer executions being possible.

When executing a single system call, excessive coverage usually stems from
loops, which write the same PCs into the output buffer repeatedly. Although
collecting precise traces may give us some insights into e.g. the number of
loop iterations and the branches being taken, the fuzzing engine does not
take advantage of these signals, and recording only unique PCs should be
just as practical.

In [1] Joey Jiao suggested using a hash table to deduplicate the coverage
signal on the kernel side. While being universally applicable to all types
of data collected by kcov, this approach adds another layer of complexity,
requiring dynamically growing the map. Another problem is potential hash
collisions, which can as well lead to lost coverage. Hash maps are also
unavoidably sparse, which potentially requires more memory.

The approach proposed in this patch series is to assign a unique (and
almost) sequential ID to each of the coverage callbacks in the kernel. Then
we carve out a fixed-sized bitmap from the userspace trace buffer, and on
every callback invocation we:

- obtain the callback_ID;
- if bitmap[callback_ID] is set, append the PC to the trace buffer;
- set bitmap[callback_ID] to true.

LLVM's -fsanitize-coverage=trace-pc-guard replaces every coverage callback
in the kernel with a call to
__sanitizer_cov_trace_pc_guard(&guard_variable) , where guard_variable is a
4-byte global that is unique for the callsite.

This allows us to lazily allocate sequential numbers just for the callbacks
that have actually been executed, using a lock-free algorithm.

This patch series implements a new config, CONFIG_KCOV_ENABLE_GUARDS, which
utilizes the mentioned LLVM flag for coverage instrumentation. In addition
to the existing coverage collection modes, it introduces
ioctl(KCOV_UNIQUE_ENABLE), which splits the existing kcov buffer into the
bitmap and the trace part for a particular fuzzing session, and collects
only unique coverage in the trace buffer.

To reset the coverage between runs, it is now necessary to set trace[0] to
0 AND clear the entire bitmap. This is still considered feasible, based on
the experimental results below.

Alternatively, users can call ioctl(KCOV_RESET_TRACE) to reset the coverage.
This makes it possible to make the coverage buffer read-only, so that it
is harder to corrupt.

The current design does not address the deduplication of KCOV_TRACE_CMP
comparisons; however, the number of kcov overflows during the hints
collection process is insignificant compared to the overflows of
KCOV_TRACE_PC.

In addition to the mentioned changes, this patch series implements
a selftest in tools/testing/selftests/kcov/kcov_test. This will help
check the variety of different coverage collection modes.

Experimental results.

We've conducted an experiment running syz-testbed [3] on 10 syzkaller
instances for 24 hours.  Out of those 10 instances, 5 were enabling the
kcov_deduplicate flag from [4], which makes use of the KCOV_UNIQUE_ENABLE
ioctl, reserving 4096 words (262144 bits) for the bitmap and leaving 520192
words for the trace collection.

Below are the average stats from the runs.

kcov_deduplicate=false:
  corpus: 52176
  coverage: 302658
  cover overflows: 225288
  comps overflows: 491
  exec total: 1417829
  max signal: 318894

kcov_deduplicate=true:
  corpus: 52581
  coverage: 304344
  cover overflows: 986
  comps overflows: 626
  exec total: 1484841
  max signal: 322455

[1] https://lore.kernel.org/linux-arm-kernel/20250114-kcov-v1-5-004294b931a2@quicinc.com/T/
[2] https://clang.llvm.org/docs/SanitizerCoverage.html
[3] https://github.com/google/syzkaller/tree/master/tools/syz-testbed
[4] https://github.com/ramosian-glider/syzkaller/tree/kcov_dedup-new

v4:
 - fix a compilation error detected by the kernel test robot <lkp@intel.com>
 - add CONFIG_KCOV_UNIQUE=y as a prerequisite for kcov_test
 - Reviewed-by: tags

v3:
 - drop "kcov: apply clang-format to kcov code"
 - address reviewers' comments
 - merge __sancov_guards into .bss
 - proper testing of unique coverage in kcov_test
 - fix a warning detected by the kernel test robot <lkp@intel.com>
 - better comments

v2:
 - assorted cleanups (enum kcov_mode, docs)
 - address reviewers' comments
 - drop R_X86_64_REX_GOTPCRELX support
 - implement ioctl(KCOV_RESET_TRACE)
 - add a userspace selftest

Alexander Potapenko (10):
  x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
  kcov: elaborate on using the shared buffer
  kcov: factor out struct kcov_state
  mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
  kcov: x86: introduce CONFIG_KCOV_UNIQUE
  kcov: add trace and trace_size to struct kcov_state
  kcov: add ioctl(KCOV_UNIQUE_ENABLE)
  kcov: add ioctl(KCOV_RESET_TRACE)
  kcov: selftests: add kcov_test
  kcov: use enum kcov_mode in kcov_mode_enabled()

 Documentation/dev-tools/kcov.rst         | 124 +++++++
 MAINTAINERS                              |   3 +
 arch/x86/Kconfig                         |   1 +
 arch/x86/kernel/Makefile                 |   2 +
 arch/x86/kernel/vmlinux.lds.S            |   1 +
 include/asm-generic/vmlinux.lds.h        |  13 +-
 include/linux/kcov.h                     |   6 +-
 include/linux/kcov_types.h               |  37 +++
 include/linux/sched.h                    |  13 +-
 include/uapi/linux/kcov.h                |   2 +
 kernel/kcov.c                            | 368 ++++++++++++++-------
 lib/Kconfig.debug                        |  26 ++
 mm/kasan/generic.c                       |  24 ++
 mm/kasan/kasan.h                         |   2 +
 scripts/Makefile.kcov                    |   7 +
 scripts/module.lds.S                     |  35 ++
 tools/objtool/check.c                    |   3 +-
 tools/testing/selftests/kcov/Makefile    |   6 +
 tools/testing/selftests/kcov/config      |   2 +
 tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
 20 files changed, 949 insertions(+), 127 deletions(-)
 create mode 100644 include/linux/kcov_types.h
 create mode 100644 tools/testing/selftests/kcov/Makefile
 create mode 100644 tools/testing/selftests/kcov/config
 create mode 100644 tools/testing/selftests/kcov/kcov_test.c

-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731115139.3035888-1-glider%40google.com.
