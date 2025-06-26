Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLU46XBAMGQEMAXNV4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id CD6ECAE9F29
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:09 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-450d64026basf5114435e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945327; cv=pass;
        d=google.com; s=arc-20240605;
        b=HJhMFkLy0WtpvJlkJ96w1jznsMTh292gD9vJ4rJX1qD6CACRxcdIAvVGHNqdJGutPN
         85bQxkoEnccUNgVisXGUsQq4Bp/0X7u1aVOaAK2f5KMtHdisQS5IO1kq3XZP+t09sFbY
         zHFUNwArksciTl7/FrbHkgO7N8rRzxUvgXa9eJo7PfcuReoAv3SDHG/suhKt/5zTH4yW
         ZqBY8pCJQDV+k100VK8eJwPKC8G/Cclib69G/RGUENSu9bE/Vx5UtF/+CNq8lBAOFAFk
         UyXfQoIrAsjUrR0VI4uLmLlZ0jtBPTLV8dYAVUm69KPugOjKBsBG1LrNhW1VS/sE8bbh
         z98A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=77VfkPlI9aWlIuhwpZ23XFM69hronvTnx/hrXLwkPds=;
        fh=OvHVbR5v24BVuME1pI/ccea2/S2KAXwnHO+E9nLellA=;
        b=L3zwS1Q1lfHN/PJ35afmyEWpnhRk1m6iMTPrsp+BisV1wgLwRiDy8rh5FiaQv/ANtP
         zR1EoyRfR3Wfdyc7tb7TnyNvdPxw/mwUD1ark8ZGeB4C0Kl4R/vqPjAkhwu7sCazK5gz
         RWdXibqBZ0nOt3k1Z7lL7Hh25LEKM3DJ7t85A0iKaWhIS6nPkkd8hnthiTmjFHb6CQYq
         RpDRD1cwN4dffWR+1ffcrI/AJ6tO7k0ONdgM9xbtKFDzyBOMDpBYRFr5KDnSpKw5gO0Q
         6kwrDkOSzpgKwZLT8h6T+UWMCF+1n7xUC5iMIoqMSchcK/LNlA9kjS46c+IfGA5w9v6g
         enhg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=llbcL+Me;
       spf=pass (google.com: domain of 3k05daaykcyyqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K05daAYKCYYqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945327; x=1751550127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=77VfkPlI9aWlIuhwpZ23XFM69hronvTnx/hrXLwkPds=;
        b=n3KF/oct8CaWYAx1qwh86CGZW510Frv3WD7ChDtn+wr/GiTPSkpVA2PLhjXDbN3rby
         ERFzf4y0Vk9P8vOa24Lod38TcjdpYToUa0+1qTf3k64HSOwHMnYGBefqpnEJ8fk8G5VU
         b6ud39RN4pbwrkhCy31RUf0kSxJMsiyjcT41bGsElkdkI/uanUV2qjmNjTAs1RrntkJk
         q2K3ZKio1pWtdGYB/UenQUTwfoMR91xtyUP+fdtpqkA/ydu7dQD25zUPPdFRmslaPe9/
         kiMvulXQVeQ226yzYT9KPPsGn0F+xIIt9EwVemIbNqWSGq/4bE46kHmbyhs5vBrJ9xqY
         tj/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945327; x=1751550127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=77VfkPlI9aWlIuhwpZ23XFM69hronvTnx/hrXLwkPds=;
        b=sUuuuntmUuOBWaWXxyOTh61LaerXilPEt/euM/XzihLlSju4o7mpcr+VqiQDZKT7fh
         VFMzZHX9BZ9IDS8lpjvkPM3dV32hXZctKlHJLgJrifBwmxHIJ+dd6HkuyGv181HGy3rz
         ImtgK4V0OJTt6N3HeT/dZmc5ecU9z+JPmlFVnvcck5eTyayldDXZ0PVg3WAzFDgQqpuR
         2YVV7EgufLPBe/Uf12PazhtGvphV/q5Y8tU2audlRR/wGbL02Gzoa9wdyekpcWLu8jiy
         6uYzTPUrWNkg3AFs2P3/BbPWncxIDw+pt+xm38SXpKriFmAXiPqzbXCUaiHXObwaQuDw
         Mwlg==
X-Forwarded-Encrypted: i=2; AJvYcCWflRXrmfIGR8Dbyq/SVGg0mR6QgAQ5qiLNKRrpdX+Frp6+PWKXxH/fRV+37NCa2jkxTywuOQ==@lfdr.de
X-Gm-Message-State: AOJu0YxJBKD9r7e0kraeSeyan3rJuHG51v4w7xVtAqONbJZxnudnfpfP
	NWbGtYhwLrFYdVS52gy7oWDiH4KPf6HY5ZCkXPG5ktz3A6brsk4+UJso
X-Google-Smtp-Source: AGHT+IEbbOT3NldXtmngcH8V2PJqrLPK5z62LlgWL2SGUZfJWy35lWcudQYWlTrLsboE5xJx+fejtg==
X-Received: by 2002:a05:600c:64cf:b0:43d:fa58:700e with SMTP id 5b1f17b1804b1-45381af6af8mr59604015e9.33.1750945326710;
        Thu, 26 Jun 2025 06:42:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+VN29CkqHEoIK0mvmPhQVZSO9TUYWwEmF02KDDHfHcw==
Received: by 2002:a05:600c:6285:b0:453:5a2:ef4b with SMTP id
 5b1f17b1804b1-4538b2dc659ls3954465e9.0.-pod-prod-03-eu; Thu, 26 Jun 2025
 06:42:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVc/kbCwbId267D/LnG7JkA6RcF/RdtWxLQs/Ab7AWaneRS3LWA0cPmoW4fCbts8SBJ7DOwm3mlbOQ=@googlegroups.com
X-Received: by 2002:a05:6000:2890:b0:3a6:c923:bc5f with SMTP id ffacd0b85a97d-3a6ed62e897mr6597500f8f.17.1750945324271;
        Thu, 26 Jun 2025 06:42:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945324; cv=none;
        d=google.com; s=arc-20240605;
        b=ainue0nQ8i9CsWy3FpdWVw/nTEqJ8gDj2h0bUNU9WwB3pLetUffbozKEHAJps/B8Iw
         apUzOTf4LWH4dGXtemJE+Ak2zJtSEgVeAxKQaoMjmsy1G9Gq5sqgIBpOSoRcdNkfMeEh
         XA2KaAiOYgxbTMYM03i+Kt1Ih8Xj2K8rSuQXR9eq6ktIjgy4ZEZT0alliy3bvvuSCVcD
         8XhXguLtdBRWZ7XGjfknoMxMLDlZ19EfPg1WKBvfw5xnMZXfdxRZClM3FZHkMyaXUgd3
         n70rPL6bg0IEVd7tV23AGFTwq1ImDgzbVVu/7bpKYqasIL5xOfVlsJ7QbgoWI1ZCMMgK
         xawQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=vrPr1zxHZfkYQVjw4j3e6ELu8cbOu5H7i9dTktErl1A=;
        fh=fd2IlQswGE/0rmp1gBxQySw8IuVA75t08YpEcLOv458=;
        b=bwgDRepCoAnSqdUWQt48PY6rGwrA2tGDJ+F3TRVqO38jY50RZIok7VW1EWfCpRjK8b
         0nn475IaKSOa254x2TtUOybVFStxeu2pUCITRdiun/BaG4zGJ+yW5sRLcW47zxYa2Y2L
         5a5EwxEQ7undRyyXctbiS+4kB+a6Sl3JkN0zA5WSbsi6RLmuDvHJBpxrUPle4UjjJRch
         cNKESmE/Dx3sD703QRSG7YNrMsXagixnPKwKYTOHRXizK/6rTZbt5dpZBN9hbCbEuiox
         lveusMKqQWFuhyxdcWEXrbVh+K149aP55Dd1om3E6SH1US2JVIA+/L3tmNxvFaFNLjCE
         3WSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=llbcL+Me;
       spf=pass (google.com: domain of 3k05daaykcyyqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K05daAYKCYYqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a99f3si1642015e9.1.2025.06.26.06.42.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3k05daaykcyyqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45359bfe631so5239945e9.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXtpGigbEJ703SpJxfzGmwgWOw5DOX+RrNGkNDpTzKqtZRHeUmyklRHPVaYQSwimhwFC5X6k/xeW5o=@googlegroups.com
X-Received: from wmqb8.prod.google.com ([2002:a05:600c:4e08:b0:451:d5b6:1214])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:a00d:b0:453:23fe:ca86
 with SMTP id 5b1f17b1804b1-453873da0f4mr45260965e9.4.1750945323898; Thu, 26
 Jun 2025 06:42:03 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:47 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-1-glider@google.com>
Subject: [PATCH v2 00/11] Coverage deduplication for KCOV
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
 header.i=@google.com header.s=20230601 header.b=llbcL+Me;       spf=pass
 (google.com: domain of 3k05daaykcyyqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3K05daAYKCYYqvsno1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--glider.bounces.google.com;
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

v2:
 - assorted cleanups (enum kcov_mode, docs)
 - address reviewers' comments
 - drop R_X86_64_REX_GOTPCRELX support
 - implement ioctl(KCOV_RESET_TRACE)
 - add a userspace selftest

Alexander Potapenko (11):
  x86: kcov: disable instrumentation of arch/x86/kernel/tsc.c
  kcov: apply clang-format to kcov code
  kcov: elaborate on using the shared buffer
  kcov: factor out struct kcov_state
  mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
  kcov: x86: introduce CONFIG_KCOV_UNIQUE
  kcov: add trace and trace_size to struct kcov_state
  kcov: add ioctl(KCOV_UNIQUE_ENABLE)
  kcov: add ioctl(KCOV_RESET_TRACE)
  kcov: selftests: add kcov_test
  kcov: use enum kcov_mode in kcov_mode_enabled()

 Documentation/dev-tools/kcov.rst         | 124 ++++++
 MAINTAINERS                              |   3 +
 arch/x86/Kconfig                         |   1 +
 arch/x86/kernel/Makefile                 |   2 +
 arch/x86/kernel/vmlinux.lds.S            |   1 +
 include/asm-generic/vmlinux.lds.h        |  14 +-
 include/linux/kcov.h                     |  60 ++-
 include/linux/kcov_types.h               |  37 ++
 include/linux/sched.h                    |  13 +-
 include/uapi/linux/kcov.h                |   2 +
 kernel/kcov.c                            | 480 +++++++++++++++--------
 lib/Kconfig.debug                        |  24 ++
 mm/kasan/generic.c                       |  18 +
 mm/kasan/kasan.h                         |   2 +
 scripts/Makefile.kcov                    |   4 +
 scripts/module.lds.S                     |  23 ++
 tools/objtool/check.c                    |   1 +
 tools/testing/selftests/kcov/Makefile    |   6 +
 tools/testing/selftests/kcov/kcov_test.c | 364 +++++++++++++++++
 19 files changed, 981 insertions(+), 198 deletions(-)
 create mode 100644 include/linux/kcov_types.h
 create mode 100644 tools/testing/selftests/kcov/Makefile
 create mode 100644 tools/testing/selftests/kcov/kcov_test.c

-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-1-glider%40google.com.
