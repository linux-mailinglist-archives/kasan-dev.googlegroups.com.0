Return-Path: <kasan-dev+bncBCMIFTP47IJBB5MN3S4AMGQER7EZJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A9199A95C7
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:20 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-7d4dee4dfdcsf4418581a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562358; cv=pass;
        d=google.com; s=arc-20240605;
        b=CRCQI83kGiVFa/yHXsGb95+6U+U6Mm+GvZ2OrFUvRlNqtDLWwFkBp0lgLC1jra2fmx
         yTePjFXyTgYbrEoE4oa52YC08CqjxFtS1aVOFINsLQWKsYjK56+ak/kPYryhRhhCjR1N
         exeiMU7ILC+DGd0DLD016IK2fOxCERw8NgPt3kuzQRVLfo2mXNZHYcasl5Z3oSPHOIv5
         ScCRFWQCTIDwBImON+UGUrXO3cDgrosIREivoFw85nJEJfw4UlQe4xQenFQGqQvJwutZ
         JHit0JskCaaDZ5qIa9diW1whA+DWIwHbw2pTi/vhgOmkIz2VILZJB+l0Q1AwqIRFyt93
         t7WQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DE+owL6GNo7kNLIHL3F/avGRKpmT+NtYX8TmHF88OPM=;
        fh=GO9HzMj3j70PfB8araxPXiM28TgfOvQGvZxORkPKTI0=;
        b=MwuyKVR63cGHoKLs67j7rOfC+i4+/8Vq50F/AgWbDDKJV4qdXPG6GwHbZMhuuMNJ0O
         jreGj2s2G/VJER+n39hyreRsdxhd/MhsaK2qJgHUKzDdROU0OJ3q1o67PBSUIsa1FUdT
         eP6cTUVenPlo8uEUQ8amq6/t3KCIBBIOdvo3htdwgfauIVMBYOSHC5xo4F4qyf4GIyM9
         U9lwLt+fDh39Vb7hZhL4CiBPCIi+lJo+RC9gdHyCiNcpoiMd3EEF1LS2JEwyUD93SlSc
         WlN80eiBBGO1il4a8wdbBYA3a1+9SKNK+ZWyu517SX2J2f6K9Zh4Gwhd85Fhr9Klc8rU
         60Tg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=AA+X0LQF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562358; x=1730167158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=DE+owL6GNo7kNLIHL3F/avGRKpmT+NtYX8TmHF88OPM=;
        b=o4DVKhX3tieTYHyIWHxhF5GRYkPpFi4twSnaS2AmnOwlv/3rvANU2/CYBPFufOfobm
         ai9xK6TIXSXfmGeqA2cc0XaCjehO1ASfD6mSaUvt7jARL5nU6CruI5Wh8mhlyx9jQbTV
         m68iBRpIiNoK/I3uQuGP/bjPLHRFrnfhgKwPywbiDx3mdIyLZhQ5S3Jmg5fnUe6UoH0O
         yXtdhuteYyOmxIQl/HXjuZRN6jmOD7+HQ6jFhXQp+GJgi/anQQIsXe4pPeUB5RKVMH+W
         7INhToZNcD6hLcKlwJEBtb93idc8O0AkYYROW+zWqbs0aS0pgFtLDarXT+3FxjksriUY
         bnkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562358; x=1730167158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DE+owL6GNo7kNLIHL3F/avGRKpmT+NtYX8TmHF88OPM=;
        b=ik0u2l1K4Yp/7SR+7xYQPmbToGaJQ8cnmSWW59q2gMuuLiOZVGATb6jsYVjz67wQZ+
         g2eT8a+UNxHBXs8W+DhvmmbWt61LPORouKEC1C95Z9HfqvYNOOEdmLPWvpAzaTf8uqLb
         /42GWQ7koGBVOAT7UCM0Tt+Movdz0G/mUYCbPWJ6MFDoPcZS6lQQg3sVibE5AVhO5uAY
         8/3aoQlc+Hl/zHXl7uucjvPkUbtA+5jL8wf+YPZiC410m/3cnyNf1y+72YQ2fk61CELd
         Z3UciV1s6y5YY0jfvyAQnKLYTgGiewxInGNPvWx8p4KkezVLnoTvau3Z/PEBEg/tgu5m
         qRNA==
X-Forwarded-Encrypted: i=2; AJvYcCUaQg8QCCFp1/hfwQDG94nNf5WtxPkZetCS0CLoBx3gZ9uQQ10+dNCAHMdCmq8ER6QP5KuJpw==@lfdr.de
X-Gm-Message-State: AOJu0Yxz3v219JZNM1yL8gC3P9IpOSZMXC93p+g3PhqYs/RPzI74xGxK
	cCv1JXwoQ0KJv6aG4q1iolqbWM+j+tDxGpZWibdnegmcT85Wqyfo
X-Google-Smtp-Source: AGHT+IG4p+WMa2EPy3NpUylFx/N8X1u3+eo+fOJ6v+smMs/ZXEPmyw5qa0GAgOwGzpcFqNqd3Qq/2A==
X-Received: by 2002:a05:6a20:43a4:b0:1d9:4837:ad7c with SMTP id adf61e73a8af0-1d96b6b6e2bmr2796559637.12.1729562358036;
        Mon, 21 Oct 2024 18:59:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:7102:b0:2e0:79a0:bd97 with SMTP id
 98e67ed59e1d1-2e3dbf34ff3ls3235166a91.0.-pod-prod-01-us; Mon, 21 Oct 2024
 18:59:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVoiVx6BBFW/2WVPz9yCTjNm3b3Wgr1b9mwyPPIh1kKqhMSCSse8bub9PkIij/RPYzu1xWEYj843ZA=@googlegroups.com
X-Received: by 2002:a17:90a:a888:b0:2e0:853a:af47 with SMTP id 98e67ed59e1d1-2e5da931fcemr2224037a91.33.1729562356873;
        Mon, 21 Oct 2024 18:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562356; cv=none;
        d=google.com; s=arc-20240605;
        b=V9enIsyLioBxNwQoD12rePjFu+ZeidwetUrbNt4J5d5fSyPHjAmQnVWgFXXBd5XZiC
         UVlrzGD3pnnW9F3Y9efTpTqT/NY27US7/R+NRWJIsi+evzcGhDXiPneUlnhbWsuspcQ0
         eeafCBzFMcbaSsJ1mJhsL3mnJBhx8dLHVh8WtpiXyiB96Ls9XX9Voh7gP3XSrxqcV0Pd
         OactdR/V3wlhxSUG1IKP9WXqkZzFUR2ynJjVXSft9IuvnzBNK49WwI8JpNRTIBqov6IG
         FYIomtol+zJQuzUK+bmPVgnIj5lqYl8ex3J/ETqd9lcBNbkm3tHFH1ERzYbTepDUR7fm
         wuHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=e65ANAnizaofFjgpIDXOaUasil0HVOGTLixFGnIEx4s=;
        fh=9z5M3NO90YPdJNbuMjqGKFORAzOhAxEbvUYGwr8HEwc=;
        b=Hgdg9QSg88sZkELJuiks4UQMp55h/xwngeDKtdQcjXkj72qcnDb9qEy7TjkQtzKt4l
         BfNdcxkIedtwjA9VEF/C1p6Sejc/z/asrDT5cdyN2owDLmSkAbO0om6uxR6gRT94aRh4
         tK67Z2AjrdjmL7rBzIb5/skHVxb/U7WH4xX5sYraXM0MyI0JQVohZlNPo7pBsg4jqqZf
         QBLq+V7FjreXKpOoWGRZ6x1x4/TEM/Fq2i5uNcpF3mMOTSB4gYY5P1m6RKr+bYOKzWBj
         pk3D2/rxjcxR9K1GjvTqXUqk98F17DSHvy9toy4s6wDKaIcyJPld9w8YuLxYiAJoTwWC
         2jWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=AA+X0LQF;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e5df3fc4bfsi35442a91.0.2024.10.21.18.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id d9443c01a7336-20c77459558so43757655ad.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU9ZsEzhacsVlq/59bexbuVc2sVidbQP6mo/HDcclZjQOP3TNCQkplCCGoL/1yQssIvAeCJsDUeWDg=@googlegroups.com
X-Received: by 2002:a05:6a20:d81b:b0:1d9:20cf:2c24 with SMTP id adf61e73a8af0-1d96b71566fmr2363833637.29.1729562356331;
        Mon, 21 Oct 2024 18:59:16 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:15 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 0/9] kasan: RISC-V support for KASAN_SW_TAGS using pointer masking
Date: Mon, 21 Oct 2024 18:57:08 -0700
Message-ID: <20241022015913.3524425-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=AA+X0LQF;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

This series implements support for software tag-based KASAN using the
RISC-V pointer masking extension[1], which supports 7 and/or 16-bit
tags. This implementation uses 7-bit tags, so it is compatible with
either hardware mode. Patch 4 adds supports for KASAN_SW_TAGS with tag
widths other than 8 bits.

Pointer masking is an optional ISA extension, and it must be enabled
using an SBI call to firmware on each CPU. If the SBI call fails on the
boot CPU, KASAN is globally disabled. Patch 2 adds support for boot-time
disabling of KASAN_SW_TAGS, and patch 3 adds support for runtime control
of stack tagging.

Patch 1 is an optimization that could be applied separately. It is
included here because it affects the selection of KASAN_SHADOW_OFFSET.

This implementation currently passes the KASAN KUnit test suite:

  # kasan: pass:64 fail:0 skip:9 total:73
  # Totals: pass:64 fail:0 skip:9 total:73
  ok 1 kasan

One workaround is required to pass the vmalloc_percpu test. I have to
shrink the initial percpu area to force the use of a KASAN-tagged percpu
area in the test (depending on .config, this workaround is also needed
on arm64 without this series applied, so it is not a new issue):

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index b6321fc49159..26b97c79ad7c 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -43,7 +43,7 @@
 #ifdef CONFIG_RANDOM_KMALLOC_CACHES
 #define PERCPU_DYNAMIC_SIZE_SHIFT      12
 #else
-#define PERCPU_DYNAMIC_SIZE_SHIFT      10
+#define PERCPU_DYNAMIC_SIZE_SHIFT      8
 #endif

When running with hardware or firmware that doesn't support pointer
masking, the kernel still boots successfully:

  kasan: test: Can't run KASAN tests with KASAN disabled
      # kasan:     # failed to initialize (-1)
  not ok 1 kasan

This series can be tested by applying patch series to LLVM[2] and
QEMU[3], and using the master branch of OpenSBI[4].

[1]: https://github.com/riscv/riscv-j-extension/raw/d70011dde6c2/zjpm-spec.=
pdf
[2]: https://github.com/SiFiveHolland/llvm-project/commits/up/riscv64-kerne=
l-hwasan
[3]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliver=
smonkey.space/
[4]: https://github.com/riscv-software-src/opensbi/commit/1cb234b1c9ed

Changes in v2:
 - Improve the explanation for how KASAN_SHADOW_END is derived
 - Update the range check in kasan_non_canonical_hook()
 - Split the generic and RISC-V parts of stack tag generation control
   to avoid breaking bisectability
 - Add a patch to call kasan_non_canonical_hook() on riscv
 - Fix build error with KASAN_GENERIC
 - Use symbolic definitons for SBI firmware features call
 - Update indentation in scripts/Makefile.kasan
 - Use kasan_params to set hwasan-generate-tags-with-calls=3D1

Cl=C3=A9ment L=C3=A9ger (1):
  riscv: Add SBI Firmware Features extension definitions

Samuel Holland (8):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Check kasan_flag_enabled at runtime
  kasan: sw_tags: Support outline stack tag generation
  kasan: sw_tags: Support tag widths less than 8 bits
  riscv: mm: Log potential KASAN shadow alias
  riscv: Do not rely on KASAN to define the memory layout
  riscv: Align the sv39 linear map to 16 GiB
  riscv: Implement KASAN_SW_TAGS

 Documentation/arch/riscv/vm-layout.rst | 10 ++---
 Documentation/dev-tools/kasan.rst      | 14 +++---
 arch/arm64/Kconfig                     | 10 ++---
 arch/arm64/include/asm/kasan.h         |  6 ++-
 arch/arm64/include/asm/memory.h        | 17 ++++++-
 arch/arm64/include/asm/uaccess.h       |  1 +
 arch/arm64/mm/kasan_init.c             |  7 ++-
 arch/riscv/Kconfig                     |  4 +-
 arch/riscv/include/asm/cache.h         |  4 ++
 arch/riscv/include/asm/kasan.h         | 29 +++++++++++-
 arch/riscv/include/asm/page.h          | 21 +++++++--
 arch/riscv/include/asm/pgtable.h       |  6 +++
 arch/riscv/include/asm/sbi.h           | 28 ++++++++++++
 arch/riscv/include/asm/tlbflush.h      |  4 +-
 arch/riscv/kernel/setup.c              |  6 +++
 arch/riscv/kernel/smpboot.c            |  8 +++-
 arch/riscv/lib/Makefile                |  2 +
 arch/riscv/lib/kasan_sw_tags.S         | 61 ++++++++++++++++++++++++++
 arch/riscv/mm/fault.c                  |  3 ++
 arch/riscv/mm/init.c                   |  2 +-
 arch/riscv/mm/kasan_init.c             | 32 +++++++++++++-
 arch/riscv/mm/physaddr.c               |  4 ++
 include/linux/kasan-enabled.h          | 15 +++----
 include/linux/kasan-tags.h             | 13 +++---
 include/linux/kasan.h                  | 10 ++++-
 mm/kasan/hw_tags.c                     | 10 -----
 mm/kasan/kasan.h                       |  2 +
 mm/kasan/report.c                      | 22 ++++++++--
 mm/kasan/sw_tags.c                     |  9 ++++
 mm/kasan/tags.c                        | 10 +++++
 scripts/Makefile.kasan                 |  5 +++
 scripts/gdb/linux/mm.py                |  5 ++-
 32 files changed, 313 insertions(+), 67 deletions(-)
 create mode 100644 arch/riscv/lib/kasan_sw_tags.S

--=20
2.45.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20241022015913.3524425-1-samuel.holland%40sifive.com.
