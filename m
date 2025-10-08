Return-Path: <kasan-dev+bncBDXZ5J7IUEIBB4NHTPDQMGQEW23YZKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id C1274BC6A70
	for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 23:13:22 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-4de36c623f6sf8071441cf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Oct 2025 14:13:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759958001; cv=pass;
        d=google.com; s=arc-20240605;
        b=LqtcOCpnVfAeARHUMnTmDPwNBUfaPOkDSOwSTl+lU/SrTlAJHRG+NO9hrEvMIZfGfa
         Pdp8uezYNz+/C64IOChRlymfBCILAuPeUiYo8Zl+ttvjYwHb3r/czZWNuBeFGEwkxhRR
         VLrnQg9XJFTl099AibFpD36BhJXPnpgseXr31OU+rsiCUJWbE9/7vY9JF34bip78tELY
         kan/2EPeXMYdG1kFB3TT4zJ741YaExXx0pc/qstxy/kUzEWyEXyXmvErDhFF5YHb8OEN
         B0iDG0Ifda5ngMX9kYNEwdJbjH6A7xRVvXW9q/0dzEfvaXnLmgZ3oQHCyAlMWHbVXk/T
         GeCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=p8j8vrEvKHU6T4P22nzXJKyRr8Ze50dMOP0FxsmRmhc=;
        fh=WFQ9fm1v5IKQ9syHnOYdTQ9voOwM2URc5KGmTvkJEWk=;
        b=aABN5BnJm3Re7x/L8aasLx5cwe0kEQmouGm3jcX29jml5Cg12GlVjr21usbVyPMm87
         laX/VwN8JsX1iTGvJk7jTfu/yM32wxGacd+/ozZ8zil3rn9WvjK7HkWqLFjGqHhyPcoC
         ofaBY+HXWTlqvl6NOlNcqt8OFkwehoHZxRGR7Ph1ICd3KErJFTibvU9poRba4xFvMaJo
         6Crxbucftiezv97XlPt5PrAKIcmQPau6AV6NP2ExsQvOnTUdJDrC50wj8GlrTf5KvafB
         GwyNbIYcC3YzhrfDJrDkJPRGMjqXErgCcc93Fyp4Q2iGRnZ2Y+WigRpoaBOmFQ56IUcg
         iHXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.177 as permitted sender) smtp.mailfrom=yskelg@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759958001; x=1760562801; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p8j8vrEvKHU6T4P22nzXJKyRr8Ze50dMOP0FxsmRmhc=;
        b=mcQ9UEyycirrwywd7sSuZ2dVs6YNgob3l1cXzTeVPm82uOOq24Xuzib3X+sMuzjANe
         i7k60h2jxlfMtGTr5rNPhOQ2iJt/3bDoVt9r/bF1ky8gXLvd8YDlh2jmRWusNfng2pJg
         w7JxXgvPUw8CXMNflcPyY/EHyqxAFs/Fs9+2kDZu9rgPB87dVwu9OfSBQOoqP6mz/uit
         a+PJLbXxzzDSnWlH/kYAidry8sswElPbZwtA56qXcwpdGYYVQmZANo6a0PjuGO2tLUSO
         jL+MOIDXZA+OiRlv/dcdXL2W9VZr9jdu6yyqz4Xw+EnsZUg0uyNhDn2/ikF6f7IKB/OI
         2PDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759958001; x=1760562801;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=p8j8vrEvKHU6T4P22nzXJKyRr8Ze50dMOP0FxsmRmhc=;
        b=m24hubjn+6rQ07G0Z3hKbYUCIugVUh4QerF1DBqslxraz0F1N/k5eealIpO9Fucd+c
         eDyKwyP1S+d9lYYNMEcDIJY0M9tswrqhm1WGZ5c0vTJKMyIe4wTDoiieJ3T0aG1k8DZv
         UG+3T0rIEJpwRNHO+TkOfih7Z966sXHmnzAtIJhW75cvxqR6x8uJIZ+0TslgoXnV24J6
         ZpTY/sX37eKxne+1L7RbWnLdvjqHRIfrsNZ6ioG7Bq74gLAhK9p4E1bgxGFXhown4/mP
         ig9LJaYzjmQx0STPhGyBQ43V6Qrh4yHxkNwuafZfLXzVSrZYn/+69g3aUZoDoj+YhThg
         WlCQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVTwxpc7JJnZKfQ6o8uFSOkT9nLeM1NlPmWppB32jdqkilVeS1/xtNAiKUvN4dLY0xDegHjdQ==@lfdr.de
X-Gm-Message-State: AOJu0YwNSTJsDQY3DQl/At8IkoQT2dRJXqA9ckuUxHsD8cQUHWYz8aCs
	aFFcNBVE+fdCUx2KiWAQ9EXeeKLReQr1ekGTREtWmZXaXl1+4zgMP3G5
X-Google-Smtp-Source: AGHT+IGOS4dlDOqfXH5pPcwlCFNHyUJm+NNkWtaeQFLpociX53PDHaT4WiLJVMdqKoYtzqNdEZ39aA==
X-Received: by 2002:a05:622a:18a7:b0:4b5:e83f:70b0 with SMTP id d75a77b69052e-4e6ead7f92bmr65772011cf.83.1759958001350;
        Wed, 08 Oct 2025 14:13:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6YEge8WUd6E2WOJ4TimyAUya/Q6kYy0smDZHZmA5Ctiw=="
Received: by 2002:a05:622a:a6c6:b0:4d0:cdd7:addc with SMTP id
 d75a77b69052e-4e6f8bbc572ls5495851cf.2.-pod-prod-09-us; Wed, 08 Oct 2025
 14:13:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW7RMHgYl8+U/pFR0XQU/u3nSPFV4o3woSG1Hq67Y6noOUpB3SdUIelznGQKB8Oav0sI9VJTF8+17Q=@googlegroups.com
X-Received: by 2002:a05:622a:118f:b0:4cf:dc5c:8c79 with SMTP id d75a77b69052e-4e6ead62e51mr61630401cf.60.1759958000071;
        Wed, 08 Oct 2025 14:13:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759958000; cv=none;
        d=google.com; s=arc-20240605;
        b=CWRGxk3t1xPJQq9iCR6B1boA8BN1sl3Y+jcxo2UmVlgKq0neUeRk7lV5p02Rb/DZnK
         wjNy9yRQ7DpC12g0y8LncfjXzOpWmhqWq64kRIfazcNnbMe0H/obmDrzPmLftXQ4xpvv
         sonEFc1kXhpp4xZT7GVY7JX8nH12F/L2nllBH31Tr5oDCOgc927L/b2bRrXlE6+CwZyf
         CBZih0sHfL0108p2ti3QQmPXG4WhdDtWmqFIlwNemxURdIDBbWnIcHY3U/heE27u8Zvu
         /mBqpMmRdZR/iVKUyU76BgdCEXJ+QUZFd8aGRCF8nKS4FTZ5kfiBIRqvj2JbAASHpuIm
         l7UQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=qLh4JfqdToTCSFHPlw/HO3cQZJoXYFuBoaG7iGYgs6U=;
        fh=VNC6wTnoWVgH4TXgfVtJhamDLiJFcd/ZW7WQVSI7xf4=;
        b=BLglVj5aEA/jq57i5JelNYUOj0aWNZIlh5O8eB6ZPCiDeZMToBe1TyO5dVjcJJZvHO
         y16le5lDLlgRT3zzhqRDwM83SMQyUJt3+PYZm63xYB/JyGxm8rwxuUIYMEK+4RpEJ6MK
         q0LrVXqrFe7krHiPIgN4nGC5i6NoJdloxsGbTFKW7vibiBgHvvG6jBE2HxroW581Kw7T
         cWRIOUHfRLWP1GDNzKCko6BxtDsMqgEjF9JIl4NmuXKwa1iknFFDiaXoJZI6vMfbmgxR
         HIyHHgWWnL9RP0WWCdTU1ohfj4SOMn3bGf6Nhnv2LNuzz4lIqCb5+BGZh/Hh9wIVwYyz
         84Mw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yskelg@gmail.com designates 209.85.210.177 as permitted sender) smtp.mailfrom=yskelg@gmail.com
Received: from mail-pf1-f177.google.com (mail-pf1-f177.google.com. [209.85.210.177])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4e6f953723asi292941cf.1.2025.10.08.14.13.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Oct 2025 14:13:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of yskelg@gmail.com designates 209.85.210.177 as permitted sender) client-ip=209.85.210.177;
Received: by mail-pf1-f177.google.com with SMTP id d2e1a72fcca58-78afd21cfd4so25316b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 08 Oct 2025 14:13:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFyQRse5IwgJWY1lfDT2DRNPy7aJ8AHWQ1l2QH0PKF8/ChpHfjBKfmSmX2TNKMDRuuGMvoIsJk0K4=@googlegroups.com
X-Gm-Gg: ASbGnctga1G38oBgcHJufcnCwtiXg6HBl42LMZKbizVxH96UmZbjmbdTcZfLgf5rGTE
	9CRM9PbCV5ratN0PAB6gxczhpLcdbL1rDWRvknj23USJTU7jOm5gZb9EWct67CZoK+ZfqIL5Ksr
	bMZP/adiqrbEsC1bJwhGbpNxf7RTM9A3lxnUzytg5Tb4l5AmbKPo4dvqWuxhzP0YlOusbXa9dkZ
	nc2qAdbGwB0sVA5z9EQCfyF/wuyUgMmoNgR4eq1kqctUWNbK6NStc01kSs42Zt9uKXHkLcursrw
	VU31+ABJss2zGQg8KyP6PPiAvzLqYh/8EHxoBafDLEHqOivKKwKfC9afPbK6UTIVH+0gse5ZBGE
	aWqbth6c5ICyXvVLGRED9Zmjurf4qA0KwnZlx0n9ctpL1wNn2HJ7hK6zBIQ/VXvaDKd5DU22cCE
	O2L6QeCOB64I9Y/SpU6W4YvGg=
X-Received: by 2002:a05:6a00:a589:b0:781:21db:4e06 with SMTP id d2e1a72fcca58-79382794da2mr3112777b3a.0.1759957998850;
        Wed, 08 Oct 2025 14:13:18 -0700 (PDT)
Received: from localhost ([218.152.98.97])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-794e33efc46sm666364b3a.74.2025.10.08.14.13.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Oct 2025 14:13:18 -0700 (PDT)
From: Yunseong Kim <ysk@kzalloc.com>
To: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	James Morse <james.morse@arm.com>,
	Yeoreum Yun <yeoreum.yun@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Marc Zyngier <maz@kernel.org>,
	Mark Brown <broonie@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yunseong Kim <ysk@kzalloc.com>
Subject: [PATCH] arm64: cpufeature: Don't cpu_enable_mte() when KASAN_GENERIC is active
Date: Wed,  8 Oct 2025 21:04:27 +0000
Message-ID: <20251008210425.125021-3-ysk@kzalloc.com>
X-Mailer: git-send-email 2.51.0
MIME-Version: 1.0
X-Original-Sender: yskelg@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yskelg@gmail.com designates 209.85.210.177 as
 permitted sender) smtp.mailfrom=yskelg@gmail.com
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

When a kernel built with CONFIG_KASAN_GENERIC=y is booted on MTE-capable
hardware, a kernel panic occurs early in the boot process. The crash
happens when the CPU feature detection logic attempts to enable the Memory
Tagging Extension (MTE) via cpu_enable_mte().

Because the kernel is instrumented by the software-only Generic KASAN,
the code within cpu_enable_mte() itself is instrumented. This leads to
a fatal memory access fault within KASAN's shadow memory region when
the MTE initialization is attempted. Currently, the only workaround is
to boot with the "arm64.nomte" kernel parameter.

This bug was discovered during work on supporting the Debian debug kernel
on the Arm v9.2 RADXA Orion O6 board:

 https://salsa.debian.org/kernel-team/linux/-/merge_requests/1670

Related kernel configs:

 CONFIG_ARM64_AS_HAS_MTE=y
 CONFIG_ARM64_MTE=y

 CONFIG_KASAN_SHADOW_OFFSET=0xdfff800000000000
 CONFIG_HAVE_ARCH_KASAN=y
 CONFIG_HAVE_ARCH_KASAN_SW_TAGS=y
 CONFIG_HAVE_ARCH_KASAN_HW_TAGS=y
 CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
 CONFIG_CC_HAS_KASAN_GENERIC=y
 CONFIG_CC_HAS_KASAN_SW_TAGS=y

 CONFIG_KASAN=y
 CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX=y
 CONFIG_KASAN_GENERIC=y

The panic log clearly shows the conflict:

[    0.000000] kasan: KernelAddressSanitizer initialized (generic)
[    0.000000] psci: probing for conduit method from ACPI.
[    0.000000] psci: PSCIv1.1 detected in firmware.
[    0.000000] psci: Using standard PSCI v0.2 function IDs
[    0.000000] psci: Trusted OS migration not required
[    0.000000] psci: SMC Calling Convention v1.2
[    0.000000] percpu: Embedded 486 pages/cpu s1950104 r8192 d32360 u1990656
[    0.000000] pcpu-alloc: s1950104 r8192 d32360 u1990656 alloc=486*4096
[    0.000000] pcpu-alloc: [0] 00 [0] 01 [0] 02 [0] 03 [0] 04 [0] 05 [0] 06 [0] 07
[    0.000000] pcpu-alloc: [0] 08 [0] 09 [0] 10 [0] 11
[    0.000000] Detected PIPT I-cache on CPU0
[    0.000000] CPU features: detected: Address authentication (architected QARMA3 algorithm)
[    0.000000] CPU features: detected: GICv3 CPU interface
[    0.000000] CPU features: detected: HCRX_EL2 register
[    0.000000] CPU features: detected: Virtualization Host Extensions
[    0.000000] CPU features: detected: Memory Tagging Extension
[    0.000000] CPU features: detected: Asymmetric MTE Tag Check Fault
[    0.000000] CPU features: detected: Spectre-v4
[    0.000000] CPU features: detected: Spectre-BHB
[    0.000000] CPU features: detected: SSBS not fully self-synchronizing
[    0.000000] Unable to handle kernel paging request at virtual address dfff800000000005
[    0.000000] KASAN: null-ptr-deref in range [0x0000000000000028-0x000000000000002f]
[    0.000000] Mem abort info:
[    0.000000]   ESR = 0x0000000096000005
[    0.000000]   EC = 0x25: DABT (current EL), IL = 32 bits
[    0.000000]   SET = 0, FnV = 0
[    0.000000]   EA = 0, S1PTW = 0
[    0.000000]   FSC = 0x05: level 1 translation fault
[    0.000000] Data abort info:
[    0.000000]   ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000
[    0.000000]   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
[    0.000000]   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
[    0.000000] [dfff800000000005] address between user and kernel address ranges
[    0.000000] Internal error: Oops: 0000000096000005 [#1]  SMP
[    0.000000] Modules linked in:
[    0.000000] CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.17+unreleased-debug-arm64 #1 PREEMPTLAZY  Debian 6.17-1~exp1
[    0.000000] pstate: 800000c9 (Nzcv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
[    0.000000] pc : cpu_enable_mte+0x104/0x440
[    0.000000] lr : cpu_enable_mte+0xf4/0x440
[    0.000000] sp : ffff800084f67d80
[    0.000000] x29: ffff800084f67d80 x28: 0000000000000043 x27: 0000000000000001
[    0.000000] x26: 0000000000000001 x25: ffff800084204008 x24: ffff800084203da8
[    0.000000] x23: ffff800084204000 x22: ffff800084203000 x21: ffff8000865a8000
[    0.000000] x20: fffffffffffffffe x19: fffffdffddaa6a00 x18: 0000000000000011
[    0.000000] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[    0.000000] x14: 0000000000000000 x13: 0000000000000001 x12: ffff700010a04829
[    0.000000] x11: 1ffff00010a04828 x10: ffff700010a04828 x9 : dfff800000000000
[    0.000000] x8 : ffff800085024143 x7 : 0000000000000001 x6 : ffff700010a04828
[    0.000000] x5 : ffff800084f9d200 x4 : 0000000000000000 x3 : ffff8000800794ac
[    0.000000] x2 : 0000000000000005 x1 : dfff800000000000 x0 : 000000000000002e
[    0.000000] Call trace:
[    0.000000]  cpu_enable_mte+0x104/0x440 (P)
[    0.000000]  enable_cpu_capabilities+0x188/0x208
[    0.000000]  setup_boot_cpu_features+0x44/0x60
[    0.000000]  smp_prepare_boot_cpu+0x9c/0xb8
[    0.000000]  start_kernel+0xc8/0x528
[    0.000000]  __primary_switched+0x8c/0xa0
[    0.000000] Code: 9100c280 d2d00001 f2fbffe1 d343fc02 (38e16841)
[    0.000000] ---[ end trace 0000000000000000 ]---
[    0.000000] Kernel panic - not syncing: Attempted to kill the idle task!
[    0.000000] ---[ end Kernel panic - not syncing: Attempted to kill the idle task! ]---

Signed-off-by: Yunseong Kim <ysk@kzalloc.com>
---
 arch/arm64/kernel/cpufeature.c | 26 ++++++++++++++++++++++----
 1 file changed, 22 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 5ed401ff79e3..a0a9fa1b376d 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -2340,6 +2340,24 @@ static void cpu_enable_mte(struct arm64_cpu_capabilities const *cap)
 
 	kasan_init_hw_tags_cpu();
 }
+
+static bool has_usable_mte(const struct arm64_cpu_capabilities *entry, int scope)
+{
+	if (!has_cpuid_feature(entry, scope))
+		return false;
+
+	/*
+	 * MTE and Generic KASAN are mutually exclusive. Generic KASAN is a
+	 * software-only mode that is incompatible with the MTE hardware.
+	 * Do not enable MTE if Generic KASAN is active.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC) && kasan_enabled()) {
+		pr_warn_once("MTE capability disabled due to Generic KASAN conflict\n");
+		return false;
+	}
+
+	return true;
+}
 #endif /* CONFIG_ARM64_MTE */
 
 static void user_feature_fixup(void)
@@ -2850,7 +2868,7 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.desc = "Memory Tagging Extension",
 		.capability = ARM64_MTE,
 		.type = ARM64_CPUCAP_STRICT_BOOT_CPU_FEATURE,
-		.matches = has_cpuid_feature,
+		.matches = has_usable_mte,
 		.cpu_enable = cpu_enable_mte,
 		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE2)
 	},
@@ -2858,21 +2876,21 @@ static const struct arm64_cpu_capabilities arm64_features[] = {
 		.desc = "Asymmetric MTE Tag Check Fault",
 		.capability = ARM64_MTE_ASYMM,
 		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
-		.matches = has_cpuid_feature,
+		.matches = has_usable_mte,
 		ARM64_CPUID_FIELDS(ID_AA64PFR1_EL1, MTE, MTE3)
 	},
 	{
 		.desc = "FAR on MTE Tag Check Fault",
 		.capability = ARM64_MTE_FAR,
 		.type = ARM64_CPUCAP_SYSTEM_FEATURE,
-		.matches = has_cpuid_feature,
+		.matches = has_usable_mte,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTEFAR, IMP)
 	},
 	{
 		.desc = "Store Only MTE Tag Check",
 		.capability = ARM64_MTE_STORE_ONLY,
 		.type = ARM64_CPUCAP_BOOT_CPU_FEATURE,
-		.matches = has_cpuid_feature,
+		.matches = has_usable_mte,
 		ARM64_CPUID_FIELDS(ID_AA64PFR2_EL1, MTESTOREONLY, IMP)
 	},
 #endif /* CONFIG_ARM64_MTE */
-- 
2.51.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251008210425.125021-3-ysk%40kzalloc.com.
