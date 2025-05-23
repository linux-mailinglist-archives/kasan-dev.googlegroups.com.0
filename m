Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDHYX7AQMGQEGK2GJXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id EB352AC1B01
	for <lists+kasan-dev@lfdr.de>; Fri, 23 May 2025 06:39:41 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-70e1d134c0dsf3350457b3.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 May 2025 21:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747975180; cv=pass;
        d=google.com; s=arc-20240605;
        b=JPbDa6HHz6XpTnqLNI5PRSh6e/rph6zvhh66BSiHv5c88duSdwCDvLPokNrOZQZmjW
         ynsQCwiJAYMMyZhkT71s2032ndbWTwz09wvg6nU9866AEqkZDXHgJNM0exg7/7We3aaX
         5MndHCZNdSaX0bhaFWAi4aNv8+1uO918rruNTGh028edHDFEuKcKVjHp+L59evC2aJOj
         +DCMDyvEAv161pi+m/kZXQgso2/cCCh0GdbUuSN5Fw8BT46bbbiY0uUZRGbpfeJ1xKhZ
         KJgtCZalKDjhr7Yda9OieaaZhQvqECpd6js4jPV8G22mPlB2WRz/b29OmXIIXA2J3P2y
         GbGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=d8NVK7wCb+XMZ54pONYR6DtkH+RMPx/dokp+XZkd4+M=;
        fh=MxEiGhpqIhYsbapxJ9j+7EYmq/PNgkdcq8sZFh90ryo=;
        b=kquPY02v0qzH4Xi6NJ4Sp6+1LgelV7oaDMb1Z3LqewZ3YThUgsj0xuGKLwBWJryrB3
         Tg+YArqftVBbB68u55b/adnQAOPQKZgFZt/OYswKr5rw0RWxbzojJqT9MQDQ+LUTqZ4L
         ZrsIQT2svIZxtwfY2WTxl0nzFvUPVbC4oszJZJvHQIXBk9sBkA6/b7cPRgTlOZZJvEKq
         LlS0kP20JDhJCE1kH4jey9dUMFcgoa1viy+P5Glu+vYrZJT2shrOagv7aBRGxNlq6n3v
         AlH+jza+K/RCx1c5ROvkpiHRtpikkBVHV6nxu3ywGoG4LhYjpQbSx8fWlTF6A0ZOaKcJ
         VggA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KqTkaNur;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747975180; x=1748579980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d8NVK7wCb+XMZ54pONYR6DtkH+RMPx/dokp+XZkd4+M=;
        b=JA6IxL0knuDQo60ff3Fz9BE20VX6xMrAYYhJPPBIIajuJWlVQZyAXgbCgPT9IRoLI1
         WgejxL+50Kn+A9UEYs5i1GCRTiyX0PZRzy+z3ImvDcnmFUZyHfzPw/JEnfTL7U8NNDAY
         7R//ZuQLFSL1Ft33F2Gdn4y0PIKuKRcQRwne5pcN0XCqDJgHRdHLFq2/xW+bhX7WEh+7
         /58g5z9BbaxNaZGwZ6dykJRP/2FkjYRZ1AHIuHJlaBjrJ3tj1JDpzEuhTP4MW0KDW6Rr
         G3hU3DyN1peMRizD3MfuFwnf1ZI8usTgwtLE20ia2EljhymlinrRDOWVWC8OK8g7ikJF
         gZ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747975180; x=1748579980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=d8NVK7wCb+XMZ54pONYR6DtkH+RMPx/dokp+XZkd4+M=;
        b=sAW38q+Qwn4FsVuAXQFXjDATOnP+IjXK3TkayYwk6X1urCWUYRf8JaJp3kxQkYflyp
         sqgldhQTkFp/Wrc5osivOSy2uyYo75a+gA5eVowmJksM7Vlr6R5CC2TxHP2Wc1MZ8D26
         8ZO92COieNajWQs/kgg6UnxJYD19FMca1umzg5deiX/025zKQkPLvErRoO1bJI8+tW4D
         TiitWb3cZAc5Gs+0A3yn13JXE2uJmARMwyqxVUZclMkGdlKvG7pjl/NaejQSIA2gGIfo
         wpqD05AoR0xBoKqS5hoCGT23Wbwhzh8AORPMUTqk0qI5ZrG5MvRQGxQ++F8sELENuAvL
         VjgA==
X-Forwarded-Encrypted: i=2; AJvYcCWHrkUbE6N8zccZ2JWInNHx0Av8j+ui7ZKvv0EYUXKRqVGQFHNZWNIhWPyJU5l2dvaPs2byhA==@lfdr.de
X-Gm-Message-State: AOJu0YyFohqdCrvvYiEXB4fzC65AtOawH2RjXLIB7jPZEZUlAswt2B02
	KSHOWG/IU+28A4qTwqHqgDnMLqQs6ZUHFrLFRMw5iLB1inG4iDWFRjgd
X-Google-Smtp-Source: AGHT+IG8/STsHV6A8QNk6PB9ODTbbq6QG9hOvTtwitvXU141IIBY4bH9GsEWsS5vqnTdFYp4MhbwOg==
X-Received: by 2002:a05:6902:70d:b0:e7d:5a3e:8a9c with SMTP id 3f1490d57ef6-e7d5a3e8dd8mr11930912276.24.1747975180232;
        Thu, 22 May 2025 21:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFIETOakH7qyUad47xsV2YcH38BmGQXp4CsJaKd0phwfQ==
Received: by 2002:a05:6902:2685:b0:e7d:82d4:2546 with SMTP id
 3f1490d57ef6-e7d82d426f1ls64077276.1.-pod-prod-06-us; Thu, 22 May 2025
 21:39:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1+vbogOqyuW+BF+vpiyxEppszI5UBca6cW6jL7MEf47Eotzxp9fZP+HOFoHx1G4aKwc3R9CCoEMY=@googlegroups.com
X-Received: by 2002:a05:6902:727:b0:e7d:3f32:6fe1 with SMTP id 3f1490d57ef6-e7d3f3270bfmr20274249276.9.1747975179310;
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747975179; cv=none;
        d=google.com; s=arc-20240605;
        b=Lt4jUBLYT+DpFgHjikIpxvPJ4wpD8oaBVUXSi7QiF6Rrj7/uwgkxn2ofW28AyO2MZT
         DMI3HgXNio+xMy7U93yFPGbANlfN6Df2mTrgblakBQngtcsQkTAWEi74Q8Tsl4Qi6qj9
         CUdTgN+rB2HMBoWMA84pMtZi7s1QTGMaPCoG+bF2tZOA+5NVpYDJkCsskDbhRMdtXnot
         Xix1vSAu9rVRFp3/3ndxak8zAaKfr9nTYphCUqwl75qX4Rxn0gJClcDQmw9xeQXh+79U
         bHk+ijIktiEYn7MkkT6xjZX1S/0uEfgehm6tRMwul0injjk7nLf0qbO6FFn6ipoqpx1s
         Y8sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NFkMhwNuEQwB51aj6fmgJxI31pAOIBg0Fai80ZSggSI=;
        fh=zycgEl+1nSr/uEFwJ9RlK4/BTsqgjrj7fd+U8rQE3i0=;
        b=dx4jZwOYwzRxQJGo93mNhNV7rF2YxqxL4gnjQFp6xvAKj0wOtBCCbPE/M3dCxf0PvN
         z+Fxv2hqw39Q2UYN7ErTAKgFWrAD4sSZOppyF8kvWaMzqnilA6ZNpftQKrhuvTSf/Jef
         xbu8wNEzerZEqCFnDoQ/DHGBiRI822JFmQkbAXP0DLxuvhN6/C9o6mw8iFkXwpBuOcVo
         j3TAMDdD5/xdrpVVvbDdztx3eSDIOhzpwuCTprb6R4HOYEFWzoXMZ5M1virmEKphikg6
         FKYh649J1m43eYdR73YcT+U+YJFuPqugx6ufjy+nRVpU5kmIi32/jSxGKT1g2Ju4ROgx
         IVqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KqTkaNur;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e7d5aee425bsi286202276.0.2025.05.22.21.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 May 2025 21:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A879D5C6D20;
	Fri, 23 May 2025 04:37:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66D66C4AF09;
	Fri, 23 May 2025 04:39:38 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Christoph Hellwig <hch@lst.de>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v2 00/14] stackleak: Support Clang stack depth tracking
Date: Thu, 22 May 2025 21:39:10 -0700
Message-Id: <20250523043251.it.550-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=5806; i=kees@kernel.org; h=from:subject:message-id; bh=XVwkrc3glEUjTIVHxhgADYvS6InRhqZwcVUoNmb8gLs=; b=owGbwMvMwCVmps19z/KJym7G02pJDBn6v7/zd349lB4js43v/P8PVhOrZ671qt7bkPjchC/4n VqhgOyjjlIWBjEuBlkxRZYgO/c4F4+37eHucxVh5rAygQxh4OIUgIm8qWdkeLn+6AuHlaaR0h8X HD0uxWndd9xPfAPD46tHXz3TfCnRVcDwTy94qstMZtfd7Myfr9qe83KzmFlVcIJ9CYvupkfljK9 kmQE=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KqTkaNur;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

 v2:
  - rename stackleak to kstack_erase (mingo)
  - address __init vs inline with KCOV changes
 v1:  https://lore.kernel.org/lkml/20250507180852.work.231-kees@kernel.org/
 RFC: https://lore.kernel.org/lkml/20250502185834.work.560-kees@kernel.org/

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

Kees Cook (14):
  stackleak: Rename STACKLEAK to KSTACK_ERASE
  stackleak: Rename stackleak_track_stack to __sanitizer_cov_stack_depth
  stackleak: Split KSTACK_ERASE_CFLAGS from GCC_PLUGINS_CFLAGS
  x86: Handle KCOV __init vs inline mismatches
  arm: Handle KCOV __init vs inline mismatches
  arm64: Handle KCOV __init vs inline mismatches
  s390: Handle KCOV __init vs inline mismatches
  powerpc: Handle KCOV __init vs inline mismatches
  mips: Handle KCOV __init vs inline mismatches
  loongarch: Handle KCOV __init vs inline mismatches
  init.h: Disable sanitizer coverage for __init and __head
  kstack_erase: Support Clang stack depth tracking
  configs/hardening: Enable CONFIG_KSTACK_ERASE
  configs/hardening: Enable CONFIG_INIT_ON_FREE_DEFAULT_ON

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
 arch/loongarch/include/asm/smp.h              |  2 +-
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
 arch/arm/kernel/entry-common.S                |  2 +-
 arch/arm64/kernel/entry.S                     |  2 +-
 arch/riscv/kernel/entry.S                     |  2 +-
 arch/s390/kernel/entry.S                      |  2 +-
 arch/arm/mm/cache-feroceon-l2.c               |  2 +-
 arch/arm/mm/cache-tauros2.c                   |  2 +-
 arch/loongarch/kernel/time.c                  |  2 +-
 arch/loongarch/mm/ioremap.c                   |  4 +-
 arch/powerpc/mm/book3s64/hash_utils.c         |  2 +-
 arch/powerpc/mm/book3s64/radix_pgtable.c      |  2 +-
 arch/s390/mm/init.c                           |  2 +-
 arch/x86/kernel/kvm.c                         |  2 +-
 drivers/clocksource/timer-orion.c             |  2 +-
 .../lkdtm/{stackleak.c => kstack_erase.c}     | 26 +++++-----
 drivers/platform/x86/thinkpad_acpi.c          |  4 +-
 drivers/soc/ti/pm33xx.c                       |  2 +-
 fs/proc/base.c                                |  6 +--
 kernel/fork.c                                 |  2 +-
 kernel/{stackleak.c => kstack_erase.c}        | 22 ++++----
 tools/objtool/check.c                         |  4 +-
 tools/testing/selftests/lkdtm/config          |  2 +-
 MAINTAINERS                                   |  6 ++-
 kernel/configs/hardening.config               |  6 +++
 69 files changed, 203 insertions(+), 171 deletions(-)
 create mode 100644 scripts/Makefile.kstack_erase
 rename include/linux/{stackleak.h => kstack_erase.h} (81%)
 rename drivers/misc/lkdtm/{stackleak.c => kstack_erase.c} (89%)
 rename kernel/{stackleak.c => kstack_erase.c} (87%)

-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250523043251.it.550-kees%40kernel.org.
