Return-Path: <kasan-dev+bncBCMIFTP47IJBBNXC6G2QMGQEQJDBQSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CCBA95171D
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:24 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-39b15a6bb6dsf7965465ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625782; cv=pass;
        d=google.com; s=arc-20160816;
        b=piVQhQjs/SgRPjveGb6nxA6iHAhBlafWgp5T4QN/h+y6rZy1wYlJwIfipAI0i7U0ur
         mpdVtfS3P/jDcjAYn0illfJmZIzZQ3SYoINC/C8IN+gwMIyc45ZUzJ6o383mkCih5oF5
         J1h6+Y5QEmheCDQSDKHS6jYcaJfqhJVViw+wd6DRab2k96WBXZb/H8FYwQukEliu0NZ+
         w4Q6aIFXOenb5hXg4bJKN1mqiHL24MbHoJeR6F/tcyunu/OArQdWV+vQCw9JXePsoH8I
         K1EhndkddJ/hYDvy7OsRi1uHy206fxGJaooPC84zY08wHz/9MnV5FMcjttVkASz6dfTT
         DZdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=k0nfY1tbLR0CAryBHiOZxxtXv0pJKdGIuSTgLVlxemU=;
        fh=M/L6BR9CI10XsSYvOeg4aNzFjY+lqmiE3sn0wHwh9Ls=;
        b=YuGGRmsFAUvBpAHWKBAY1gjz+iKx/JJf2DMGO340D8A4TlakEELw7KLCgGAcjNimTk
         qQeZ6scMu0Rwe01vHmcdE8AwTH1KPvrDzmUQGABEHTMdKBpouvxZzFZjEEqAdQUKcmjC
         PYk0WARKjfBDSaR3qqOr2gkF/xtk03R5E0Rry2EBWD6Y1NvtyVor8heAUewpX0Eln8Bd
         z3t8svRpTpM9IAx9h14SnaZOZwI9qbz/ToFT6MG4eJsc/VfERovcYUGDOtaVE/iGVRj6
         nToCaMIpxObqeP3tUOaf4dNv7iJvtipyQpgQ+XKLAzXS3/16txoij3Sq0u6W+5i1X0dJ
         ao1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KXn1Mtgs;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625782; x=1724230582; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k0nfY1tbLR0CAryBHiOZxxtXv0pJKdGIuSTgLVlxemU=;
        b=VFVY3bDNfovqagDMpvSJOV8EtUnd0NKJOJft5vD/QsVlA4L4NwoC5zY02LHg+JaB3x
         neUnnnrqW7SGuZLAqGZiKYQKBNid4S6rKTw5wdpbpzvCAkBaq5sFDK1/539TCNB6Hlaq
         IbGqMDqOvzS4u1j0LGEKuxDTDu6brcUO4SAYIjGaHNSxH5Oxlq/OFI+yUxZNzrQs9yQI
         VTEN8qmTnhd4+uihsUUqrjl95LoRA8gy1/4fqsYr4wuuEGYaZ5YnO6N+KyQCklzRnzZF
         2cT7uEWBO4LI+jHHWS8aXH7cDYswceCbuhHK0vW/CwX3s/S4c1jlmbc0SVOtaiwmsbrt
         PddA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625782; x=1724230582;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k0nfY1tbLR0CAryBHiOZxxtXv0pJKdGIuSTgLVlxemU=;
        b=S7MFN5lS/C90FViuUfwYVJ90KV8450Kzwg4XZOidOMVOuXv35RU97IZCA4NCq7JRb+
         8VjD1kuf6laY0vmtCOd1i9D0rJZnywl92JcBQsZ4hvi7kmHdHdbROffGk688GPOtieF0
         3UkyaLXGyOzHeJQmlY12Nk2lCsZwsSi7PGtB8mfJsIwlmtyj2oglsTg35uT+1UIZj5/g
         bOeqB9tO98wLTGrS09hq885lk6rxQn3jYC5xgxDeOgRRfzD90My3Yb8e0wwzdbMlmCQD
         1vLSjSyFS33P139heth8iH5Ff/Tri46KT3bhyLO9w4J48cjFBmC6LVixWL22but4Qh8C
         bI6w==
X-Forwarded-Encrypted: i=2; AJvYcCUvVV1IkjuHBY8ImH3DqkzV+j12tKzc79nAust5neSz3QkaVi0AFOd8nFi2DIFBHp4rFI+PTNfuJnbYFerNpPYbCHuA5MzUvQ==
X-Gm-Message-State: AOJu0YzeqhUq88gKeKXDznTl3mb8uQGM25M6JNBQtaaypOILXdQPoOUp
	YTYxHVpyefWg+40P/IKH5frUfM3O/9xDfvYfXqmyud3i3Btesf60
X-Google-Smtp-Source: AGHT+IGYLinz3Em4Ogeb2UP11YAohaJjUq4M9OMjn3WbbysJvbcwR5PC7YxcB5aVw6b+BbxrMU0Hiw==
X-Received: by 2002:a05:6e02:1fec:b0:379:494f:57e2 with SMTP id e9e14a558f8ab-39c48c3b383mr44410055ab.5.1723625782241;
        Wed, 14 Aug 2024 01:56:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:6a08:0:b0:39a:edb3:76d9 with SMTP id e9e14a558f8ab-39b5c9882dels636855ab.1.-pod-prod-00-us;
 Wed, 14 Aug 2024 01:56:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRP5MNxzNDI8stIY1tqrQUr8xQUyPqn2564/JwfqlQZl4ShppKobNtdGGwMAngT4w8kv6cOSc20Afm6lp7/+z66UxDfgtqe39PVQ==
X-Received: by 2002:a05:6602:6306:b0:7f6:8489:2679 with SMTP id ca18e2360f4ac-824de1bb443mr99043639f.8.1723625781389;
        Wed, 14 Aug 2024 01:56:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625781; cv=none;
        d=google.com; s=arc-20160816;
        b=T8veG3brOCtI6efYK8hyFxkYVziEUY/j0vr8HBIyNkvJcADKbjrAHh26rekAa1Xxjx
         pfSNvlpbimy9Pc6W6rueGirYpjmRXIE2ORYEi0Tf9mqtGewybbxHha46xXGD1+oNu5BH
         6SHfFg0ZOJznaD2uT28WR7LadjUHIDlAZHBMzyDoU7urlwju4iIHGurZ3YW2SOL/dHDf
         zoxzT/9TzM3cVD09xD7bY2LFGEcrkHJiSZZwOFIBXYFb3t6wfEYEjC27jZK3GbMsXWor
         6iKR8gFTE8mLepetmn4drNx05w30Zf5kS6b77tST2HUwhDG72wmC0OSmcZsKHqZzB73p
         Rqsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lmaS/ucUO4ax4xArhdHVTXE+tGzy8O1URFQiuKQW0B8=;
        fh=ljOqiiTEhF17brpf9EVBL+bHgVRR08XrLzxZlyTQ/+I=;
        b=NfZb73M7qKr0SZaC6IPjvejiRF+msTCnsYsZLlLs0zPQGsZsgTrehwSMSHdCC8nTCI
         sDoUHyaxYbu7zZU/WOGQDf96GrS6ACNQC2t0OkqoIlG1mRtbJ9oUkFrNIwimOsuNRkYV
         LQvqDNMT3MNq2rZW3bchpeVa5xUwuXTay1itQeAp9H99kkJ3SFJiijJ22P0ou7TSQDwe
         rBolgQUn/cP1InySYdoeupeOmOOLiMCpT8GdPMmt/DM8zF7c7YRg5OS7JmHJcbq16IYs
         aLwGpB7cb2atgHRqjWLW4scgePz7a+Yns4XecyP24cU2E95fnjnVgUn5wFeEBQKTPZ8v
         ZPnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KXn1Mtgs;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-82266f51491si31666339f.0.2024.08.14.01.56.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1fc56fd4de1so5203305ad.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXxYE7Oo1maayTZO23nsQwahCZRpEakxtBxkYpjXdBOyoORWgmLC4ChuYjNKBG2/i7S4JLu5wHh5nFZ4mJkuHH8Z2q6AcVZSrI+vg==
X-Received: by 2002:a17:902:da86:b0:1fd:8b77:998e with SMTP id d9443c01a7336-201d9a28d73mr22221125ad.29.1723625780442;
        Wed, 14 Aug 2024 01:56:20 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:20 -0700 (PDT)
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
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 0/7] kasan: RISC-V support for KASAN_SW_TAGS using pointer masking
Date: Wed, 14 Aug 2024 01:55:28 -0700
Message-ID: <20240814085618.968833-1-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=KXn1Mtgs;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
Content-Type: text/plain; charset="UTF-8"
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
either hardware mode. Patch 3 adds supports for KASAN_SW_TAGS with tag
widths other than 8 bits.

Pointer masking is an optional ISA extension, and it must be enabled
using an SBI call to firmware on each CPU. If the SBI call fails on the
boot CPU, KASAN is globally disabled. Patch 2 adds support for boot-time
disabling of KASAN_SW_TAGS.

The SBI call is part of the upcoming SBI Firmware Features (FWFT)
extension[2][3]. Since generic FWFT support is not yet merged to Linux,
I open-coded the sbi_ecall() in this RFC to keep this series focused.

With my RISC-V KASAN fixes series[4] applied, this implementation passes
all but one of the KASAN KUnit tests. It fails vmalloc_percpu(), which
also fails on arm64:

      ...
      ok 65 vmalloc_oob
      ok 66 vmap_tags
      ok 67 vm_map_ram_tags
      # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
      Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
          (u8)((u8)((u64)(c_ptr) >> 57)) == 127 (0x7f)
          (u8)0x7f == 127 (0x7f)
      # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
      Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
          (u8)((u8)((u64)(c_ptr) >> 57)) == 127 (0x7f)
          (u8)0x7f == 127 (0x7f)
      # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
      Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
          (u8)((u8)((u64)(c_ptr) >> 57)) == 127 (0x7f)
          (u8)0x7f == 127 (0x7f)
      # vmalloc_percpu: EXPECTATION FAILED at mm/kasan/kasan_test.c:1785
      Expected (u8)((u8)((u64)(c_ptr) >> 57)) < (u8)0x7f, but
          (u8)((u8)((u64)(c_ptr) >> 57)) == 127 (0x7f)
          (u8)0x7f == 127 (0x7f)
      not ok 68 vmalloc_percpu
      ok 69 match_all_not_assigned
      ok 70 match_all_ptr_tag
      ...
  # kasan: pass:62 fail:1 skip:8 total:71
  # Totals: pass:62 fail:1 skip:8 total:71

I'm not sure how I'm supposed to hook in to the percpu allocator.

When running with hardware or firmware that doesn't support pointer
masking, the kernel still boots successfully:

  kasan: test: Can't run KASAN tests with KASAN disabled
      # kasan:     # failed to initialize (-1)
  not ok 1 kasan

If stack tagging is enabled but pointer masking is unsupported, an extra
change (patch 7) is required so all pointers to stack variables are
tagged with KASAN_TAG_KERENL and can be dereferenced. I'm not sure if
this change should be RISC-V specific or made more generic.

This series can be tested by applying patch series to LLVM[5], QEMU[6],
and OpenSBI[7].

[1]: https://github.com/riscv/riscv-j-extension/releases/download/pointer-masking-v1.0.0-rc2/pointer-masking-v1.0.0-rc2.pdf
[2]: https://github.com/riscv-non-isa/riscv-sbi-doc/blob/master/src/ext-firmware-features.adoc
[3]: https://github.com/riscv-non-isa/riscv-sbi-doc/pull/161
[4]: https://lore.kernel.org/linux-riscv/20240801033725.28816-1-samuel.holland@sifive.com/
[5]: https://github.com/SiFiveHolland/llvm-project/commits/up/riscv64-kernel-hwasan
[6]: https://lore.kernel.org/qemu-devel/20240511101053.1875596-1-me@deliversmonkey.space/
[7]: https://lists.infradead.org/pipermail/opensbi/2024-August/007244.html


Samuel Holland (7):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Check kasan_flag_enabled at runtime
  kasan: sw_tags: Support tag widths less than 8 bits
  riscv: Do not rely on KASAN to define the memory layout
  riscv: Align the sv39 linear map to 16 GiB
  riscv: Implement KASAN_SW_TAGS
  kasan: sw_tags: Support runtime stack tagging control for RISC-V

 Documentation/arch/riscv/vm-layout.rst | 10 ++---
 Documentation/dev-tools/kasan.rst      | 14 +++---
 arch/arm64/Kconfig                     | 10 ++---
 arch/arm64/include/asm/kasan.h         |  6 ++-
 arch/arm64/include/asm/memory.h        |  8 ++++
 arch/arm64/include/asm/uaccess.h       |  1 +
 arch/arm64/mm/kasan_init.c             |  7 ++-
 arch/riscv/Kconfig                     |  4 +-
 arch/riscv/include/asm/cache.h         |  4 ++
 arch/riscv/include/asm/kasan.h         | 29 +++++++++++-
 arch/riscv/include/asm/page.h          | 21 +++++++--
 arch/riscv/include/asm/pgtable.h       |  6 +++
 arch/riscv/include/asm/tlbflush.h      |  4 +-
 arch/riscv/kernel/setup.c              |  6 +++
 arch/riscv/kernel/smpboot.c            |  8 +++-
 arch/riscv/lib/Makefile                |  2 +
 arch/riscv/lib/kasan_sw_tags.S         | 61 ++++++++++++++++++++++++++
 arch/riscv/mm/init.c                   |  2 +-
 arch/riscv/mm/kasan_init.c             | 30 ++++++++++++-
 arch/riscv/mm/physaddr.c               |  4 ++
 include/linux/kasan-enabled.h          | 15 +++----
 include/linux/kasan-tags.h             | 13 +++---
 include/linux/kasan.h                  | 10 ++++-
 mm/kasan/hw_tags.c                     | 10 -----
 mm/kasan/kasan.h                       |  2 +
 mm/kasan/sw_tags.c                     |  9 ++++
 mm/kasan/tags.c                        | 10 +++++
 scripts/Makefile.kasan                 |  5 +++
 scripts/gdb/linux/mm.py                |  5 ++-
 29 files changed, 255 insertions(+), 61 deletions(-)
 create mode 100644 arch/riscv/lib/kasan_sw_tags.S

-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-1-samuel.holland%40sifive.com.
