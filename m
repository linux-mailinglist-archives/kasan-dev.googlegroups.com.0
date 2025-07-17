Return-Path: <kasan-dev+bncBDCPL7WX3MKBBYMM43BQMGQEVH6EVJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 07C2BB0973C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jul 2025 01:25:35 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-6fb3bb94b5csf21584566d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:25:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752794722; cv=pass;
        d=google.com; s=arc-20240605;
        b=DJXHqBfKGnsS+J5E/nOQ9afEym9mMEIxtlA6jFzp7T4dzzsCizxhTojUGFtq5WqTOS
         I1w2ftrDVFKfLnnZXWaba7jiijPHlzkmtx0vpxk9rmOdZMllZwS/MuuxyhWYGaFEooX1
         C8Fpluv5LgefvAFNcP2DSDnT/TDIVeV13f3X0NYOljUGOl0vaq3KTBp7mKzsStDtL33m
         uJpaAGiXNzxtAq4LD+gkMFcJDB7brNLoNKfw+mUV4vWeHgSgHmIUrkBpIO9l8oqYEFto
         S2ttgFc896DZAkXlIr2awmhwK0otWkUg5yPp+w+d/oWrfov/02dQw55mJn4xFNxPJGch
         aqaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=NncEvDDMWDWKgV2nNSU35UQ3xDbWCk7YhQImpc1Cb7s=;
        fh=7SR5Vk7as786nn9MrgoZO1g+lpvA0C4v/Tb444/AClc=;
        b=cP9ZEs0mikIhTkRL8hMMGG6qVxulU2pMzYH2Morm+Nd9cddPaIoSKIBIKZWd9zwTsx
         LFcY4sO7q25ufMeGFsStJ7QtvwgjCg0cc/BZJxBszHoHBAurmqpKyc+uewm+axawODQ+
         YZCeDXG7ZK5POfURMK/kaQMcbpLlnO01YV3DIKZ8bZf0KZAYNZgws4pT8sxfJvMP0CWh
         WEpe5Z/dc/Ra87NoFBhHxjlKWCoeZLIp1/fSQGIA87EPpP8ggWdlcyaFynLj5UUZ5qKv
         oAlv6P2E580a5sqU8mxDJMhODxz77u0kUHucomnark1+JFL5jQQ9xsPAZgp9DKmyh3LM
         IoUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Gn7vBNA8;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752794722; x=1753399522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NncEvDDMWDWKgV2nNSU35UQ3xDbWCk7YhQImpc1Cb7s=;
        b=Dmtay+9hH9GIjnZKx6ikzqmvNrpuxLqR6ZAwY/aFK5ICdd0t3LD2TPKipS8/Wcuun0
         AD4ih+Fu9YVrDk12pDY5YP3szSYX+Alb9CJb5sf0rS/CcAtzYZ5i8DBNOBfblliIzSXD
         yRBue/mh72yWOFSnmqRiUdah9GG3WjY/N4N1O5Dqepep0WA/TV7czfb4uaniaaArz+uz
         YWFvCMw7Eu+aC59W1Mum4BUjWuqhLC0BYEsGZ+rs/CYKX+mQaM+1s6eadOLg3FagMW5y
         UyturADBTyHsiEagP+JYadtse7W9iq2FnSn/tVbeXqQWKtqvNIhqpKw4nF/IrLrilPS4
         ND4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752794722; x=1753399522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NncEvDDMWDWKgV2nNSU35UQ3xDbWCk7YhQImpc1Cb7s=;
        b=AGKa7Y6OjgmOulmH3e0eZ9kA26LGVZ8d5mvaqTJfJtFF8fzFdcsBp9dyGRmqjrnWu6
         PVeuRGtpfeGexDe74RUzEUZ7+Y7hVE+BX1ALKPi93AzRpZ+O4v0bwIkwg8BoeDG93uin
         J9Mb1q1TaRv4haWdzXa4gyGwbWvWY6vgIwQTOZQjMkXCNaF45XNeoxMkzmnJ5u3sq6yz
         4illw5H85yIPipZUcXXEzP1NONR33CHhFI/fg1J1e9Lz83O14/9IBhZfjcbR0SXGVkt4
         gPZATn29L3ysxKfL8OKk1JQrXnbWrjeXGxv7HBM2+BOfW6TjMXEnGnJTQNSPXqrzID+/
         d/ng==
X-Forwarded-Encrypted: i=2; AJvYcCWAi8s+S7QQ5pq1yHV7/oS743ilvMML7wt8oA+wAgscQZzknN6Pc+jyc0zoo0c/XNB1hRYQ3g==@lfdr.de
X-Gm-Message-State: AOJu0YzEtx7gF3I+nr330MShgfCIcdPX6JJt4NeHAiQY0LwDleMvB+OV
	jOkJ6WA1tlXUP/6QL9MB+BJIIz/VZCt7L6Sd6VJ5y5wTtIFjlItBczIK
X-Google-Smtp-Source: AGHT+IFCYpMfp4365+iinHwq+c5l0d24BoYNUVro2fWOrivwQu6BtKEdh5cS97ZxtcKptay1tSywZA==
X-Received: by 2002:a05:6214:4611:b0:704:9275:a7c7 with SMTP id 6a1803df08f44-704f47fa191mr141735236d6.2.1752794722050;
        Thu, 17 Jul 2025 16:25:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+WITPnpgDw7UW02ZVVNoF4FZsSEaD5is/7Io8k7B7wg==
Received: by 2002:a05:6214:caf:b0:6fa:bd14:59a0 with SMTP id
 6a1803df08f44-70504ac48e8ls21364266d6.0.-pod-prod-01-us; Thu, 17 Jul 2025
 16:25:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVowJVXL6mSlwPn1lkpo6+USg+PUqIJXbbUIIZFOLgStLVkrE4Nt6/fJhLQsBrP7KD/W0wnevx0Ofc=@googlegroups.com
X-Received: by 2002:a05:6214:54c2:b0:6f8:e66b:578e with SMTP id 6a1803df08f44-704f4ae20a2mr174321166d6.32.1752794721020;
        Thu, 17 Jul 2025 16:25:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752794721; cv=none;
        d=google.com; s=arc-20240605;
        b=hacr2Ztqw/v9OWn6DRsXt21RgsNnN+QLuxaiTcBxZK+uzEGCYjE5KbaF/H6sx4TB6X
         mgYKMr7ZEdW6LoL7q9hopd3AuIB/kzpXEDDtV7ZSiWSE4e0QaCju1XuC7TlwzGsI9GpI
         SBK960hJ8k1IPLMItRwXqj2rdb20kEnytmQ3WLsLbQPkbclkGlIg6eaONgm9qXmghVLO
         UR7ehNvlqdXAvFuLZ5V+i/Ew1lKsIaitFQhJSbGV+3d+0u3liQPpu1E4AqEJg3E9+2mE
         yucbSNphBwuBv1vC6iiijvP4P4cWGLKK2xfzXhUsHj/aAgchbnCAuS8JelzsWNRTanT5
         YllA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=EYgAYwsBBvJfM8LX3r7dwr8+iapgS1Bh05pfLczFKL8=;
        fh=QGkC0XXYFVR44rRsApAzBCz8GYyMQkb/Xk/qpxP69oA=;
        b=TWzzxvY4a/rsPR2GXCfliOKtkVOfEtYNR7+P2oJ5fNH4YCv649lGn8jInxj7oLEsCs
         kCbfRm3zGvjsHlykAbFtfE4q4i2h5fOH29SNRgNKtv+R6M+kwTo9OwOgH+AA1Laa10zI
         YgtaVXCZAGKQHQi6OmhK5/GEqOnHcUfX+NX9kCQxKFzPUoTaIlkTGC0hIze9CL+6Hd+O
         SbErTdU+Xd2Odv70d9wakQDiCB3zABN9TbxjcI5YvswfVt5RFaqYBanLPfoPXyAoIMa+
         GoCieSHt7HV8MGBNVnfaCdxFgD2coYiyA3HptjoUNBJ9H4vJwOaupjP2GFzVbuTt3wCB
         7WDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Gn7vBNA8;
       spf=pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-7051ba7cc2dsi140646d6.8.2025.07.17.16.25.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 16:25:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 899365C6CAD;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29831C4CEEB;
	Thu, 17 Jul 2025 23:25:20 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Ingo Molnar <mingo@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	linux-kernel@vger.kernel.org,
	x86@kernel.org,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kvmarm@lists.linux.dev,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-security-module@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	sparclinux@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v3 00/13] stackleak: Support Clang stack depth tracking
Date: Thu, 17 Jul 2025 16:25:05 -0700
Message-Id: <20250717231756.make.423-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=5918; i=kees@kernel.org; h=from:subject:message-id; bh=ix3ybSX3HXyR5ul7nVKO/r/KYy1s5o0+DAZiEgLkmcM=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmVbZHJG+bN3K/qtDByvmFFwWZOiegr7v9P8cdPbSg4o 3Zj+4WOjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIkYBjMyfNv4wNam5MZaxztb DVV2bLscf+z93ddLbf58MJq2fUdLOyfDP/uXom2zOn6oGNnZ+vY/6tuxYr3x7FmnbTaV1Sr/nay 2lB0A
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Gn7vBNA8;       spf=pass
 (google.com: domain of kees@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

 v3:
  - split up and drop __init vs inline patches that went via arch trees
  - apply feedback about preferring __init to __always_inline
  - incorporate Ritesh Harjani's patch for __init cleanups in powerpc
  - wider build testing on older compilers
 v2: https://lore.kernel.org/lkml/20250523043251.it.550-kees@kernel.org/
 v1: https://lore.kernel.org/lkml/20250507180852.work.231-kees@kernel.org/

Hi,

As part of looking at what GCC plugins could be replaced with Clang
implementations, this series uses the recently landed stack depth tracking
callback in Clang[1] to implement the stackleak feature. Since the Clang
feature is now landed, I'm moving this out of RFC to a v1.

Since this touches a lot of arch-specific Makefiles, I tried to trim
the CC list down to just mailing lists in those cases, otherwise the CC
was giant.

Thanks!

-Kees

[1] https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth

Kees Cook (12):
  stackleak: Rename STACKLEAK to KSTACK_ERASE
  stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
  stackleak: Split KSTACK_ERASE_CFLAGS from GCC_PLUGINS_CFLAGS
  x86: Handle KCOV __init vs inline mismatches
  arm: Handle KCOV __init vs inline mismatches
  arm64: Handle KCOV __init vs inline mismatches
  s390: Handle KCOV __init vs inline mismatches
  mips: Handle KCOV __init vs inline mismatch
  init.h: Disable sanitizer coverage for __init and __head
  kstack_erase: Support Clang stack depth tracking
  configs/hardening: Enable CONFIG_KSTACK_ERASE
  configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON

Ritesh Harjani (IBM) (1):
  powerpc/mm/book3s64: Move kfence and debug_pagealloc related calls to
    __init section

 arch/Kconfig                                  |  4 +-
 arch/arm/Kconfig                              |  2 +-
 arch/arm64/Kconfig                            |  2 +-
 arch/riscv/Kconfig                            |  2 +-
 arch/s390/Kconfig                             |  2 +-
 arch/x86/Kconfig                              |  2 +-
 security/Kconfig.hardening                    | 45 +++++++++-------
 Makefile                                      |  1 +
 arch/arm/boot/compressed/Makefile             |  2 +-
 arch/arm/vdso/Makefile                        |  2 +-
 arch/arm64/kernel/pi/Makefile                 |  2 +-
 arch/arm64/kernel/vdso/Makefile               |  3 +-
 arch/arm64/kvm/hyp/nvhe/Makefile              |  2 +-
 arch/riscv/kernel/pi/Makefile                 |  2 +-
 arch/riscv/purgatory/Makefile                 |  2 +-
 arch/sparc/vdso/Makefile                      |  3 +-
 arch/x86/entry/vdso/Makefile                  |  3 +-
 arch/x86/purgatory/Makefile                   |  2 +-
 drivers/firmware/efi/libstub/Makefile         |  8 +--
 drivers/misc/lkdtm/Makefile                   |  2 +-
 kernel/Makefile                               | 10 ++--
 lib/Makefile                                  |  2 +-
 scripts/Makefile.gcc-plugins                  | 16 +-----
 scripts/Makefile.kstack_erase                 | 21 ++++++++
 scripts/gcc-plugins/stackleak_plugin.c        | 52 +++++++++----------
 Documentation/admin-guide/sysctl/kernel.rst   |  4 +-
 Documentation/arch/x86/x86_64/mm.rst          |  2 +-
 Documentation/security/self-protection.rst    |  2 +-
 .../zh_CN/security/self-protection.rst        |  2 +-
 arch/arm64/include/asm/acpi.h                 |  2 +-
 arch/mips/include/asm/time.h                  |  2 +-
 arch/s390/hypfs/hypfs.h                       |  2 +-
 arch/s390/hypfs/hypfs_diag.h                  |  2 +-
 arch/x86/entry/calling.h                      |  4 +-
 arch/x86/include/asm/acpi.h                   |  4 +-
 arch/x86/include/asm/init.h                   |  2 +-
 arch/x86/include/asm/realmode.h               |  2 +-
 include/linux/acpi.h                          |  4 +-
 include/linux/bootconfig.h                    |  2 +-
 include/linux/efi.h                           |  2 +-
 include/linux/init.h                          |  4 +-
 include/linux/{stackleak.h => kstack_erase.h} | 20 +++----
 include/linux/memblock.h                      |  2 +-
 include/linux/mfd/dbx500-prcmu.h              |  2 +-
 include/linux/sched.h                         |  4 +-
 include/linux/smp.h                           |  2 +-
 arch/arm/kernel/entry-common.S                |  2 +-
 arch/arm64/kernel/entry.S                     |  2 +-
 arch/riscv/kernel/entry.S                     |  2 +-
 arch/s390/kernel/entry.S                      |  2 +-
 arch/arm/mm/cache-feroceon-l2.c               |  2 +-
 arch/arm/mm/cache-tauros2.c                   |  2 +-
 arch/powerpc/mm/book3s64/hash_utils.c         |  6 +--
 arch/powerpc/mm/book3s64/radix_pgtable.c      |  4 +-
 arch/s390/mm/init.c                           |  2 +-
 arch/x86/kernel/kvm.c                         |  2 +-
 arch/x86/mm/init_64.c                         |  2 +-
 drivers/clocksource/timer-orion.c             |  2 +-
 .../lkdtm/{stackleak.c => kstack_erase.c}     | 26 +++++-----
 drivers/soc/ti/pm33xx.c                       |  2 +-
 fs/proc/base.c                                |  6 +--
 kernel/fork.c                                 |  2 +-
 kernel/kexec_handover.c                       |  4 +-
 kernel/{stackleak.c => kstack_erase.c}        | 22 ++++----
 tools/objtool/check.c                         |  4 +-
 tools/testing/selftests/lkdtm/config          |  2 +-
 MAINTAINERS                                   |  6 ++-
 kernel/configs/hardening.config               |  6 +++
 68 files changed, 204 insertions(+), 172 deletions(-)
 create mode 100644 scripts/Makefile.kstack_erase
 rename include/linux/{stackleak.h => kstack_erase.h} (81%)
 rename drivers/misc/lkdtm/{stackleak.c => kstack_erase.c} (89%)
 rename kernel/{stackleak.c => kstack_erase.c} (87%)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717231756.make.423-kees%40kernel.org.
