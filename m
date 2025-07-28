Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCFNT3CAMGQEEAUBDDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B1BCB13E33
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 17:26:01 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id ffacd0b85a97d-3a6d1394b07sf2713951f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 08:26:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753716361; cv=pass;
        d=google.com; s=arc-20240605;
        b=b2WE0PFF8J+vb/ZEnTVajnJG+7u8oDvMLailNkVJDtEMB0bQQgnagDbo6mcpdV9qJr
         2Bfbr2Ppopu6oCQvx4nPdxuMsCZpdYPKUAhLXYCWhNHiBxqR9mokzryqAxGxb4CND3PF
         dMYJRDOgff7ydcZjz7YQKx/cPla3D8H1uvaZhYkB45cVqoI7eWZxOwhgWSqvZk/MGWoZ
         7ochfmiRVwhkcXDPIGnnM48K4H+QAvKZNfp+oy4Qteemd+vW7d+B4Iiefy+pYnv90EMT
         720tKafOTJolv13d4m8JRp4ckv4CUsIbksWFQ/vCxwZr7k0QbsYGxq+xyXMtphqHvbzt
         Sw9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=nKtj5CZEEtd9CzHPsLd8GMZ+9BV3uAObpLhPGlBqldQ=;
        fh=HZHNkRR8qszYoMETJgUxDKQcRXcE4xjRtht4NaBRjSQ=;
        b=BSLrQ1PXbrlG6RMDOT6ghwjdR/q7ZBC1eASkqv+MFZ9HhshrqoLteX4BOWaxnw4VwZ
         oi3Vh76O5EAH0Sd+MdD5f4Hdkytf1ZxJa7UL6BEGZdYXLDCR+Ml9pQOD5QA+mHXFjlHJ
         Z9xgM5d1W1eWKN2TIIqeJ9UC/9In+LCXmtQfPx+I8VZ8vhFPdFk3Ir+MFZ7TDSHSXwO9
         QQCUMvCGnFy1qdVex1HHuThAbYBlxLq4rZ84BVQjHrdW8KRXmyaS55usI2vzlWV1wD9L
         xch9YhOoAgZDjhLuaYoSrzpTCpD77XAdX22YtB8iicKfoKM1XUc9moyG0/6fJsi/fuA1
         EEjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KVV4RzSU;
       spf=pass (google.com: domain of 3hzahaaykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hZaHaAYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753716361; x=1754321161; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nKtj5CZEEtd9CzHPsLd8GMZ+9BV3uAObpLhPGlBqldQ=;
        b=t/eIZfFbBctm6W6wTZjNard+O/hjeGOF9np6brDWw5G04WcLvapjUnk0C34UmcuXxi
         PIorck7jF8gVIKucA6cE0r6I6rRN01yc0BfPCmBLEUdebmiM8WX171yHMLX/3GEYOaMM
         VsrVXoR/pqQXVTWieVgSDdGgAWXYTacmz5o4XAI9R/1RKTntVSckGmFoSQooYGkSiMmv
         WpsWruAMlsv9VM7d8cliZEoVewvAH+iI5QAuUNG4NxaGMC7nSy2Nyy1PEC63qS252w5A
         Z3aiURx1DDtm9MFtZJ1CH4CbZDcaoOwBjwAHU621JGfIwL8uiFjmeDCc5lVqnwJpsZDs
         hQ+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753716361; x=1754321161;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nKtj5CZEEtd9CzHPsLd8GMZ+9BV3uAObpLhPGlBqldQ=;
        b=LQreLSDno13kEsGgjN3yeqnGBlN98cF3NQDyNhXwkTDYaiiDupEeenbc78WTqiqSw4
         1wvbVPw49BBzGxs63rNLsQkialp13d2ffAfdxRQAUqTHUCmpVmHeHS+0gnMJGXiEFt6q
         g2lu5oe6rSWrOPEd7nVqPGHwwCoPolUkTpAY203dGaCMZ3Bzx+p9ibogeGgPM2QvC8CD
         wGGWfIsBMglWxKGfTlBFA7yMQaWfUFGSg2gzr/ohmzf6OAp4KCYQkSLWUyog/3xtjfyu
         3csJbqkBFn93z4xDuOwQC4MGQRC4ZKrn24CrXVi+FOJ+zD7Z7nlAG3o+gezXs3ytFl3e
         gXkw==
X-Forwarded-Encrypted: i=2; AJvYcCWXY7k4wHMpCsymEG6TYYRhXYoiTTYgxKbN9ekwgavr5gQ1QqK9H4A8dbP1uqtrPuAsq8lcNQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz3Cv6AIElrXBSaxGJ75z/WudcYlaSGSGeuYJGxaKbDdeTeM5HK
	KnWS1il69xyvz0suFLZKqDn4mbsBNwyaK3VElkUdm8Ahux7CbxqV17d1
X-Google-Smtp-Source: AGHT+IGfGe+n4tEtciMtBoFnYezc5A0d7caPuTuRjKfOaWw2fGACzSIJxTOuv9pOkSk7Lkg+gvuokQ==
X-Received: by 2002:a05:6000:2209:b0:3a5:8cc2:10aa with SMTP id ffacd0b85a97d-3b7766451f7mr9030668f8f.32.1753716360600;
        Mon, 28 Jul 2025 08:26:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcTe7B/Qkko/VE+euGFoB1dfBvG6ta0jQSVzg4zCEFb3w==
Received: by 2002:a05:600c:1c29:b0:456:107b:aa63 with SMTP id
 5b1f17b1804b1-4586e5c3ff6ls23536135e9.0.-pod-prod-02-eu; Mon, 28 Jul 2025
 08:25:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwLUTGJmSCJ2V5LFgGUbf7r3yKD7mDkO0RfeXwzlX5TZ5GbiJh6F/daxIkoEPdBZYCFAx6QXz2Ns0=@googlegroups.com
X-Received: by 2002:a05:6000:26d2:b0:3b7:6429:da6 with SMTP id ffacd0b85a97d-3b7766684c2mr8289241f8f.42.1753716357949;
        Mon, 28 Jul 2025 08:25:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753716357; cv=none;
        d=google.com; s=arc-20240605;
        b=JbceKpVcVh/52YDLKfRQ8xB3gi4JIuAyx9iNcRRLpjoNFrOXsCC30fJtyC2CEUUKtY
         WWgv4buG/PJ9aaT5h4fRXdE9nb5fGv/CJSZzt8mt2aUXVUpYWKC6ocE8jsNzf4pzCC2Y
         r5r0GIpFo1gp/HolCIWXRETB5nd8LDzP9otbz1mK3CXe77nrLX+eVZKQ8FZe2jIpO94w
         e7vhgLYhGKtsCiyYNoqgKyPSj9OFPpqPkN/diHCJlXIvLk7CA/QlW16dPNuSjxb3uGcz
         yvKVomG3Et7+RLe7VyvmWhh40rOSiC62o5+W+Ojgh5WE2bmahmCMmG9Pz4KbZfzgUP7K
         Vbmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=aTNXrPEm9i79aGsWLTCVivE2wW9JNpqR5y4vNeS9jdc=;
        fh=00J/LxggCCzbW9TvKLD6CFBOQhUPqS3p28P6Rdlp69g=;
        b=OFMPhKl5GX1XbaEDp8UCZYu8IZKR0fkw6CuJM69jLO2kJJ9rGXYfx8jN8g9pAPDvlI
         m5akN5QGPxjW5RT33Z/1LtKqedkZzsQOserSHxdBXkv2JMsY16dzDi71n6Q5aCLXqQZ4
         TKRoAOm4JL4+p8s+q3Im5X2BVbX4ZNvppiru+xh8J/M6Pi2yt4qxy+wb6k4ISyOsXdEz
         Bo4BXPIgqni9KVhv7KWpcnJk7XYGU/tAMvwqoFRcwjmf7g8jnfnVhqEpHyQ629vnLh2g
         6h2ELAzjodcrmAbWSwRgxBHRkcTq828JmTnKJ1jMvfRfYkymIn3tS+2G/wUXb2k6VJ2X
         y94Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=KVV4RzSU;
       spf=pass (google.com: domain of 3hzahaaykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hZaHaAYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45870550a87si3541485e9.1.2025.07.28.08.25.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 08:25:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hzahaaykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-3b7806a620cso983174f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 08:25:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVERv0xcOCNDEiBNtSs3+Og3AFNi00A2CcY00/4v3ZJVQK316UHhvXwD4DRswjpa9WPJMqLmPIrGHo=@googlegroups.com
X-Received: from wrbfq12.prod.google.com ([2002:a05:6000:2a0c:b0:3b7:76ce:137e])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:584a:0:b0:3a5:8a68:b82d
 with SMTP id ffacd0b85a97d-3b7767642f0mr8876288f8f.43.1753716357406; Mon, 28
 Jul 2025 08:25:57 -0700 (PDT)
Date: Mon, 28 Jul 2025 17:25:38 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.1.470.g6ba607880d-goog
Message-ID: <20250728152548.3969143-1-glider@google.com>
Subject: [PATCH v3 00/10] Coverage deduplication for KCOV
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
 header.i=@google.com header.s=20230601 header.b=KVV4RzSU;       spf=pass
 (google.com: domain of 3hzahaaykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3hZaHaAYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
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
 mm/kasan/generic.c                       |  18 +
 mm/kasan/kasan.h                         |   2 +
 scripts/Makefile.kcov                    |   7 +
 scripts/module.lds.S                     |  35 ++
 tools/objtool/check.c                    |   3 +-
 tools/testing/selftests/kcov/Makefile    |   6 +
 tools/testing/selftests/kcov/config      |   1 +
 tools/testing/selftests/kcov/kcov_test.c | 401 +++++++++++++++++++++++
 20 files changed, 942 insertions(+), 127 deletions(-)
 create mode 100644 include/linux/kcov_types.h
 create mode 100644 tools/testing/selftests/kcov/Makefile
 create mode 100644 tools/testing/selftests/kcov/config
 create mode 100644 tools/testing/selftests/kcov/kcov_test.c

-- 
2.50.1.470.g6ba607880d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250728152548.3969143-1-glider%40google.com.
