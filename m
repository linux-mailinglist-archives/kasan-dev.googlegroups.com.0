Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY7A7W7QMGQEDRBW4ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 244B7A8B470
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 10:55:02 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-30bfc0f5599sf28300721fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Apr 2025 01:55:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744793701; cv=pass;
        d=google.com; s=arc-20240605;
        b=DzZJuQoLm+ExvBMFdQuh48wMOvAQtBoOZwL8+4J1wD1nTEt1WJgU1gOJpS+dvku6zK
         pQ9hf4Wneozxs3CleQHmlszrZwljeOQtRMV2jc6PTnDGzDBr3Hrwbl9nijTNiyyTKdTb
         a7ZOhaLlBR3AsHrI4WMBhubwHod4RStiaivhC+vRZetpSVZdOvi6UPf805xpJBheaL5b
         o03acVmUa17IlY98RysyF3B91805b0cvAAGYXSjikN4laWQvj0jvvbmbqYcoQ1xrT4IK
         lnnM1y6tGpZO+UmXsoJcB++5D7fK+jafkTqx7pYfrTvlXNI4fSMdTPFqxElMFCCg7087
         f+eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=keP8un/ZkSgrpJF7fPRoO4CPmFSL0yNq5oyIPAHRlIY=;
        fh=J3DmmXGKNJfGp7AOh4DGsezffNO97eWeB5qkbw2U51Q=;
        b=IMaPE98X5toPwDIelb+Sy5X07ba8y4pq0zbO7tKP+ZhXMZuIhFd5x7/CS884PJv3m7
         ibtpHxvEt64xOdmgKYdhdC8Kb/Pwx4zoY57OIhYGgVG4QT+/A9GVRuMhCKukcn5EpfQt
         1kG4rK8FLlMeHjYCoGnRvWUaZr2W4P8hmdLwwyhbeF2+grefrgRfPRkH+54QQeU+S58L
         escqSD1eThus6RJ/9Z/EuSDP7GLGLIxkj5T5lBDqSjIa0wAzUKvlJ/vskzyYbpMFebVd
         16qb3dKZ1pzAFCYDCTKW0fd6OuN0TjqfQIrqo8F9bJWIvbxHa/qhivAk+9pQG6Ne6GjN
         jAnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mEQZPYnT;
       spf=pass (google.com: domain of 3yhd_zwykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3YHD_ZwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744793701; x=1745398501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=keP8un/ZkSgrpJF7fPRoO4CPmFSL0yNq5oyIPAHRlIY=;
        b=L5ri38rw2shlhg/761fpTqV4KEi/cVZnsupjnaCIUvjOpK1cYZSWIooiTUW4vCcvRC
         4PWzvJeBpwFIXkFOnQ4rpkvPUoe/oGH/R2csxfg2ytNLRl3cSz9zd1XH7pblzgnaoO4q
         5JVeo3uKv0DHZ4pSNPykvCINeNrt4nbaI29RXsa7HJKbrQhxDru+C+1L90Bgchc/IrIt
         YMRQr/qDrrmW6yEgscldYeUhfwCvkdk2JEkYqLo4bifLuYdUV42KDocl+e97K6xq8WPM
         MOIPssI/WclW4NPc+6zjhbTBdnU1lLDM1lKwWrBWJ/ztATyL6IEQgl5fgGAjObwKyJ8A
         Gx3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744793701; x=1745398501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=keP8un/ZkSgrpJF7fPRoO4CPmFSL0yNq5oyIPAHRlIY=;
        b=D81vOUsFGcD+mfC4peJeqjTRncppbDrN6ErlmwJyJrpOFTDXs6RtuUBar+JeVMnmuB
         2iwp5O/gCGGLk6R+p8Ne+bK+PYI/rVrpF4oH73eB1NiEHxi5UdiZ7dq3Fit7BDYdSIr/
         KaiqEk1g8gJkHF4lIRQR3W5y3xw8Mi8YlOtH4BoHksPKgDcSTHduqQWc7iC3BnL5clXY
         AOzlMP4DVwvP7C07Ce+/cduZAdbLenIKCcN1nBpMZeFlugBsyxniO9o2Q0FVmRQkWcRj
         oBSq0SV4fLI9rKmeasqJK7ZK1l2cDn8hraYgsKqdeHzOOfzZIe0Np22eWcoPq+K1tC8k
         xPJw==
X-Forwarded-Encrypted: i=2; AJvYcCX55n8ZVMn6fi6APd8VS/jy1zeWX493TR7yr541DSIIB2G82TOS6Zc1nwBt+zvrsNQr9/ut7w==@lfdr.de
X-Gm-Message-State: AOJu0YyUQJbsS5Du8qEXO+c44tXTDgcvPyl/WO252kLx4lKilaJLnbHx
	LarkXyhMC3Kja9kEMWYQKuedL99fXAqPxbe+DLdhdtS1LyJEUB9r
X-Google-Smtp-Source: AGHT+IET5NeQn/SRQxIti744CB1IWighhXoe+R8C/TlEHsiWV3gIWWtz+uyo75REM0XFLLOxEaCHbA==
X-Received: by 2002:a05:651c:2209:b0:308:e8d3:7578 with SMTP id 38308e7fff4ca-3107f73921emr3426191fa.35.1744793700228;
        Wed, 16 Apr 2025 01:55:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALton4h2X7FB2P4IJAvKhgNKgxa9ejb6dJauyrLDZiJGA==
Received: by 2002:a2e:94c4:0:b0:30b:cd63:6fc1 with SMTP id 38308e7fff4ca-30f4c976bb7ls794351fa.2.-pod-prod-04-eu;
 Wed, 16 Apr 2025 01:54:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXp4XaIbuEZMAdHoloYxspVUKBkBh0k3f4utJvK5Nui7UDvQ04ARTqnQZEAdjSRTXsxMWEgEHwI4M=@googlegroups.com
X-Received: by 2002:a05:651c:158d:b0:30b:f924:3554 with SMTP id 38308e7fff4ca-3107f6ceb59mr3905031fa.21.1744793697258;
        Wed, 16 Apr 2025 01:54:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744793697; cv=none;
        d=google.com; s=arc-20240605;
        b=QjdxbZIgcZM181amDeYiLUo4rP7RXJLOp82j3YDcOLSq0TlCdCHCY60mJTJK8ewWpL
         6nzOETBikKb0A+mciOHI2mTbaoaPjan70VBRu8dO3rp3aezHBWgwyEIMuMventJU2hG3
         L0+Cbq3Y0HLUJkPyqE8nSvzaPytNO1fV3L6Ui4tpl1P/zb4sSfTwLRsvFZgHTHQiFg1Z
         7zgh1Q+iF4VobhTZZgf27sIbiBm4w4TOgWl13StZ9TvMDCLZ9J3KBr0vHExGBfqA3Lcg
         ci9AtRrLpMoKCseU2yf0+7yLG4IjO8EG4OVqLWo3nExsH6C0l7Bnn+aiwsDw/DBEBHFs
         W0pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Q4V5sKaO6KF+CpbL0Hc6XBejXO7C4P5Jvce3Dn0tr8s=;
        fh=F/Fvy8b35MtJ6gmjIn6i9DLyIMechJpVbPhjwWl3ICQ=;
        b=gLeH3awIfjmugCQ5B9RggCTni1zaogzNNtHMrU5OD7OdI0CnT4l0xHyeoaTP/PUVy7
         FP+6/i+5J9EweYA9RU21d0X4cebwgnyQlRQtsWXr5Y2X5ahzXjucEhuVQYlnL5ZJ9NlL
         VMEn+k2q5fW7g4g9QUBPorBgDE5Hz7mGPPLuNVyKWdnNMIgkbCvmn3un3XNZ0YAh+89V
         BZ7okXXaOL4RALuXPMkAPW5XmJJo90HcmlRz6wHP1UgqvyDvy1JIfmff2dTrbyA9tTQN
         hOfjOaz95EN7ZvBZjROnlaJ/7YXAjpOPFtGrWxK1wA7KBcA9xu/9g9nbGzm9W6FoxlwH
         b6bg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=mEQZPYnT;
       spf=pass (google.com: domain of 3yhd_zwykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3YHD_ZwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30f465d6583si2453601fa.6.2025.04.16.01.54.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Apr 2025 01:54:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yhd_zwykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e5cd9f3f7aso6283380a12.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Apr 2025 01:54:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXdl2/xfdSPFuLElyiJh000eovEd/fnIURGsTOyhc3yyG7ibppeF+4LoSWD85MNsa4B/OswPUaa6aM=@googlegroups.com
X-Received: from ejbo18.prod.google.com ([2002:a17:906:3592:b0:ac2:9a4c:6337])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:9721:b0:acb:1184:cc29
 with SMTP id a640c23a62f3a-acb42d39990mr80502766b.59.1744793696746; Wed, 16
 Apr 2025 01:54:56 -0700 (PDT)
Date: Wed, 16 Apr 2025 10:54:38 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.604.gff1f9ca942-goog
Message-ID: <20250416085446.480069-1-glider@google.com>
Subject: [PATCH 0/7] RFC: coverage deduplication for KCOV
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
 header.i=@google.com header.s=20230601 header.b=mEQZPYnT;       spf=pass
 (google.com: domain of 3yhd_zwykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3YHD_ZwYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
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

The current design does not address the deduplication of KCOV_TRACE_CMP
comparisons; however, the number of kcov overflows during the hints
collection process is insignificant compared to the overflows of
KCOV_TRACE_PC.

In addition to the mentioned changes, this patch adds support for
R_X86_64_REX_GOTPCRELX to objtool and arch/x86/kernel/module.c.  It turned
out that Clang leaves such relocations in the linked modules for the
__start___sancov_guards and __stop___sancov_guards symbols. Because
resolving them does not require a .got section, it can be done at module
load time.

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
[4] https://github.com/ramosian-glider/linux/pull/7 


Alexander Potapenko (7):
  kcov: apply clang-format to kcov code
  kcov: factor out struct kcov_state
  kcov: x86: introduce CONFIG_KCOV_ENABLE_GUARDS
  kcov: add `trace` and `trace_size` to `struct kcov_state`
  kcov: add ioctl(KCOV_UNIQUE_ENABLE)
  x86: objtool: add support for R_X86_64_REX_GOTPCRELX
  mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init

 Documentation/dev-tools/kcov.rst  |  43 +++
 MAINTAINERS                       |   1 +
 arch/x86/include/asm/elf.h        |   1 +
 arch/x86/kernel/module.c          |   8 +
 arch/x86/kernel/vmlinux.lds.S     |   1 +
 arch/x86/um/asm/elf.h             |   1 +
 include/asm-generic/vmlinux.lds.h |  14 +-
 include/linux/kcov-state.h        |  46 +++
 include/linux/kcov.h              |  60 ++--
 include/linux/sched.h             |  16 +-
 include/uapi/linux/kcov.h         |   1 +
 kernel/kcov.c                     | 453 +++++++++++++++++++-----------
 lib/Kconfig.debug                 |  16 ++
 mm/kasan/generic.c                |  18 ++
 mm/kasan/kasan.h                  |   2 +
 scripts/Makefile.kcov             |   4 +
 scripts/module.lds.S              |  23 ++
 tools/objtool/arch/x86/decode.c   |   1 +
 tools/objtool/check.c             |   1 +
 19 files changed, 508 insertions(+), 202 deletions(-)
 create mode 100644 include/linux/kcov-state.h

-- 
2.49.0.604.gff1f9ca942-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250416085446.480069-1-glider%40google.com.
