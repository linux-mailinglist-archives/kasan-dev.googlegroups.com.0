Return-Path: <kasan-dev+bncBDCPL7WX3MKBBDVN2TAAMGQEQO3UKSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 3473AAA79C3
	for <lists+kasan-dev@lfdr.de>; Fri,  2 May 2025 21:01:36 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3d81820d5b3sf42603885ab.3
        for <lists+kasan-dev@lfdr.de>; Fri, 02 May 2025 12:01:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746212494; cv=pass;
        d=google.com; s=arc-20240605;
        b=VZma9+C/pIU3erNUDf1RmKOiHAMQw8P401tvRvE/djLN2UgRFfYCP3lDqKjMKgKArg
         QGqz462spvB/p8ysLbt8F53wSCCY/hdELbu9S7gm/d6Fkhj3U6U6WxjuLfmLCkvdNwCc
         Mxo6+xNMskGRg5QwUwrYOlMQJaB79LZ0JqUcb4BMe7E+wuCAw7cSXZOF3QUU5KPqqkcv
         a7qXnwxHT+/9t9XQm0i7slAMSmVbpXCqKc+27zA/551iBdbAOLKm28u/z0jETMSzIiqS
         BXL7kU23Wg4chkLsa+9YKYVgOpyMLbcuclMQ9egP+9GjZccBVH3Gv7/NZxcVGTrzRDHQ
         Qg2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=GxdZIejeKuDFtPbFQnAEmx6CJCZfmVnAbyfS8zDlm0g=;
        fh=CrEOd9eE9Tgxb9XJqNrgoASvHXFUZHQsrW8nVEVcrNQ=;
        b=M5vc0efTO+7Vx87a5f+SuCf36n+OOEwRtnD7I+jNAWzA7EQod9l6bYZe951JN2gu/x
         xZB3j+yLufF3DFqNn2pWERqy++hhP0kij+6TCFYb4g4GZw2iTX0zHR+tWrmntiHrBNxV
         ZAaR/9kvjfcj6AaeuBOzve4NBF4BgEXG87OtzFe7oLteTuhK3+yFvQ0uwXpnGyu8KE8e
         2mxE8ZDBkrvSE/Cp7zA7p884ZaUXffqNHyyETsaiCdFrOAzbFc0peWAPQW2QNK748i5n
         uzFaebAzTtB3GWVC5VRp3tUncE0O7IpQx+UfWpoySqxcwBH6QGaHj1ubCJMSSSv5MZq/
         0BeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o2GJQzXK;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746212494; x=1746817294; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=GxdZIejeKuDFtPbFQnAEmx6CJCZfmVnAbyfS8zDlm0g=;
        b=bI4VePx0VVNk783B/uj5VLJWLQlxWCtnQFlwT7iHTr+zYmfHs5o9BiQgSzPDRjE/b1
         ACrsdKDflrYzOzT2EemUjjaqCBoqTJsuk6XUVYOxgxSY2EoXvMHP8iMcO/cqN7Gqe7lL
         PiFIjJz4YiDn+r0ggOSvSBsSmCK95QAkEm37DRikddLrrfXN3WXAtYCt64Y0+HaFl7f9
         X6NQ48aQQ1L2hsvcYoZb/h8V7KUwFgq08MOll6CjXb8FQ2kCSKkAGdX70vMykTB7rea4
         7luKIGCCDtThh4qcGRTYHZQfr7HU37D/jpBE873v2d6Y7ZJjfIgLE45NQYe99orfizt4
         Vnvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746212494; x=1746817294;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=GxdZIejeKuDFtPbFQnAEmx6CJCZfmVnAbyfS8zDlm0g=;
        b=k6vFDkjLDNY4PIaXL+PVquusm/RxsAMbj0pWKAGFjbc7P0zFuQgqox7HvtSORUtNoZ
         ulII71am2gGWJUD9dGmHRsBMnSSnfv+lOL4EiB3x1negIBji3xr9peUSK2Kpx+RBvGrF
         rl+Z9XiomPTuEB1eaH+Pp99GRO1jHlMCT9PC6Hlck/bkT0I/bv4dnR9tYZ0kYpPqIh2q
         axXDhyZQylmGwa70r8eh2UpoA1lUh2s6b16IJyMhwrp6KVteD3M+vuDYU+AkbuT/e+uE
         wGzIe6/mvf9zBagxuUqkatncHYmct0foXxRCptzljAGrhn1pJn67/cTDqBj1m9Me5iY0
         bTog==
X-Forwarded-Encrypted: i=2; AJvYcCXD9ObqipDZbp8gs7bwpOvs342db+tkHkL+X+hpj/KFCdhKTzrsl7QNpdvTHi+HtE9Sdflxkw==@lfdr.de
X-Gm-Message-State: AOJu0YyHVQzihFBTKxfwF7t9bzI7YW5UD3oZedO8jkoB7n7ecdcpGBFq
	lRSMImCdssRkJiwUP8HveGiwFSijrctlm01WD9RB9UkaWJQahGGt
X-Google-Smtp-Source: AGHT+IFSONxCefsCe5ylwrzA9chpJFpXoocJvEXJI1ImXZZbzl2AKat16P4NI+MNlg827OpeTvGp+w==
X-Received: by 2002:a05:6e02:178f:b0:3d5:8103:1a77 with SMTP id e9e14a558f8ab-3d97c158b39mr46789355ab.1.1746212494477;
        Fri, 02 May 2025 12:01:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFoaf3TjvGTF0jKSn2pMrtVZJGd02NlSOLceyu+BFcQuQ==
Received: by 2002:a92:c6ce:0:b0:3d2:ab3a:2d23 with SMTP id e9e14a558f8ab-3d96e8184cdls2284585ab.2.-pod-prod-01-us;
 Fri, 02 May 2025 12:01:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAy0Qxh6GsygyQ4/ECq7UBUqDoyIvTm61Agu7r4BeqYE0l0Kto5s+5HMjDudg16SQWU9F4BwnqIv8=@googlegroups.com
X-Received: by 2002:a05:6e02:188e:b0:3d9:6485:3a03 with SMTP id e9e14a558f8ab-3d97c155cbemr44289235ab.4.1746212493622;
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746212493; cv=none;
        d=google.com; s=arc-20240605;
        b=KrZUDoF8nR3lKSedKa8cchLmjlwtZQUzqXA1Ak8Z7R0jSCSd497IbSc4OrBw6fsjfh
         1eh9cvr/fvkDsqA5U/nn5WKU0Bil5t+l/QgSjDraiUq45iL0T9SplYqkg6kRvUkxfA7K
         j7SzavnJqtVXbFyT1OTj9bB//j5Kfb8CgzsJAzRFAGtp2s678I3AS73ryf0X0RKml1o7
         yFm+nRZZ6gsphKNXavCuc+h18S2OEx/UU/ntWXeqCowWh32S78FYLNNI6EKYGSHQb+JD
         jTQMFsDnGUuo93Ci7gaNy4G3RnWXD+jzshgHiMkRwO3knBkcL87zEsoS4yRyyg0mS9Av
         DHbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NG/rF3bvTsluKUSY/5qFQcGuNB6yJPMQ7BdMPhUhXd0=;
        fh=jJ1rFvFPQEpajCJXRAc7IbaWemPQruxfIs0JuE9xRfk=;
        b=QLSRXUk2zrznGo7ycyffLeVr28dNBIA0RtfIv9UraiN69IocGPY5NPn7/25zagvX3U
         xBt/bBT92xejHLDPvG1pNWa1vtPC+9MaxzPd/aRSdFsgCTPwCR4PL9ATQYNRtvSwXTRQ
         O2ENt3x/4ijU9XVgmfZUmFwbQ1YV/lYiRxN8BnAhDMbPxEcx2AuWz0YiqSf0UoowvAX4
         trOmESeQ8draJMkEKHlw3t6oKl1LGVdINJGFKTf28ifBP8A72posHoDqaU693HztMSIv
         mdbtFPHDjRvrUiG5+/U7vkk+XrsILonnqYxBfSK5wbjTxefF3S/3cFf85JS/lDVHtxeK
         NNVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o2GJQzXK;
       spf=pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f88a731e3dsi171246173.0.2025.05.02.12.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 02 May 2025 12:01:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id CA22E5C589A;
	Fri,  2 May 2025 18:59:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 969D0C4CEE9;
	Fri,  2 May 2025 19:01:32 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	x86@kernel.org,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
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
	linux-kernel@vger.kernel.org,
	sparclinux@vger.kernel.org,
	kasan-dev@googlegroups.com,
	llvm@lists.linux.dev
Subject: [PATCH RFC 1/4] stackleak: Rename CONFIG_GCC_PLUGIN_STACKLEAK to CONFIG_STACKLEAK
Date: Fri,  2 May 2025 12:01:24 -0700
Message-Id: <20250502190129.246328-1-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250502185834.work.560-kees@kernel.org>
References: <20250502185834.work.560-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=17888; i=kees@kernel.org; h=from:subject; bh=hbyQsZ/6y5+e9RQDQHbSQJPPcxxu+z1a8WXI/ozgaEE=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmiYq2+zXc+bn0vVlUVuWC6jfAv3vSSYvsZGZ7OepZW0 SWT10/oKGVhEONikBVTZAmyc49z8XjbHu4+VxFmDisTyBAGLk4BmIjqDkaGh5Yx4gdsp1ar3JI7 2r0vPm/Z15Yje1iY3N+GPNhzatOaAob/oV/bGjZ/3+t+u8b16/qJrN2WXmkCoa8XO5pbrbn28U4 IAwA=
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=o2GJQzXK;       spf=pass
 (google.com: domain of kees@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

In preparation for adding Clang sanitizer coverage stack depth
tracking that can support stack depth callbacks, remove "GCC_PLUGIN"
from "CONFIG_GCC_PLUGIN_STACKLEAK" and remove "PLUGIN" from
"DISABLE_STACKLEAK_PLUGIN". Rearrange the Kconfig to have a top-level
CONFIG_STACKLEAK that will depend on either GCC plugins or Clang soon.

While here, also split "prev_lowest_stack" into CONFIG_STACKLEAK_METRICS,
since that's the only place it is referenced from.

Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: <x86@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-doc@vger.kernel.org>
Cc: <linux-arm-kernel@lists.infradead.org>
Cc: <kvmarm@lists.linux.dev>
Cc: <linux-riscv@lists.infradead.org>
Cc: <linux-s390@vger.kernel.org>
Cc: <linux-efi@vger.kernel.org>
Cc: <linux-hardening@vger.kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <linux-security-module@vger.kernel.org>
Cc: <linux-kselftest@vger.kernel.org>
---
 Documentation/admin-guide/sysctl/kernel.rst |  2 +-
 Documentation/security/self-protection.rst  |  2 +-
 arch/arm/boot/compressed/Makefile           |  2 +-
 arch/arm/kernel/entry-common.S              |  2 +-
 arch/arm64/kernel/entry.S                   |  2 +-
 arch/arm64/kernel/pi/Makefile               |  2 +-
 arch/arm64/kvm/hyp/nvhe/Makefile            |  2 +-
 arch/riscv/kernel/entry.S                   |  2 +-
 arch/riscv/kernel/pi/Makefile               |  2 +-
 arch/riscv/purgatory/Makefile               |  2 +-
 arch/s390/kernel/entry.S                    |  2 +-
 arch/x86/entry/calling.h                    |  4 ++--
 arch/x86/purgatory/Makefile                 |  2 +-
 drivers/firmware/efi/libstub/Makefile       |  6 +++---
 drivers/misc/lkdtm/stackleak.c              |  8 ++++----
 include/linux/sched.h                       |  4 +++-
 include/linux/stackleak.h                   |  4 ++--
 kernel/Makefile                             |  4 ++--
 lib/Makefile                                |  2 +-
 scripts/Makefile.gcc-plugins                |  4 ++--
 security/Kconfig.hardening                  | 18 +++++++++++-------
 tools/testing/selftests/lkdtm/config        |  2 +-
 22 files changed, 43 insertions(+), 37 deletions(-)

diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
index dd49a89a62d3..c94475661a80 100644
--- a/Documentation/admin-guide/sysctl/kernel.rst
+++ b/Documentation/admin-guide/sysctl/kernel.rst
@@ -1465,7 +1465,7 @@ stack_erasing
 =============
 
 This parameter can be used to control kernel stack erasing at the end
-of syscalls for kernels built with ``CONFIG_GCC_PLUGIN_STACKLEAK``.
+of syscalls for kernels built with ``CONFIG_STACKLEAK``.
 
 That erasing reduces the information which kernel stack leak bugs
 can reveal and blocks some uninitialized stack variable attacks.
diff --git a/Documentation/security/self-protection.rst b/Documentation/security/self-protection.rst
index 910668e665cb..67a266d38172 100644
--- a/Documentation/security/self-protection.rst
+++ b/Documentation/security/self-protection.rst
@@ -303,7 +303,7 @@ Memory poisoning
 
 When releasing memory, it is best to poison the contents, to avoid reuse
 attacks that rely on the old contents of memory. E.g., clear stack on a
-syscall return (``CONFIG_GCC_PLUGIN_STACKLEAK``), wipe heap memory on a
+syscall return (``CONFIG_STACKLEAK``), wipe heap memory on a
 free. This frustrates many uninitialized variable attacks, stack content
 exposures, heap content exposures, and use-after-free attacks.
 
diff --git a/arch/arm/boot/compressed/Makefile b/arch/arm/boot/compressed/Makefile
index 945b5975fce2..2da39e41e5c0 100644
--- a/arch/arm/boot/compressed/Makefile
+++ b/arch/arm/boot/compressed/Makefile
@@ -9,7 +9,7 @@ OBJS		=
 
 HEAD	= head.o
 OBJS	+= misc.o decompress.o
-CFLAGS_decompress.o += $(DISABLE_STACKLEAK_PLUGIN)
+CFLAGS_decompress.o += $(DISABLE_STACKLEAK)
 ifeq ($(CONFIG_DEBUG_UNCOMPRESS),y)
 OBJS	+= debug.o
 AFLAGS_head.o += -DDEBUG
diff --git a/arch/arm/kernel/entry-common.S b/arch/arm/kernel/entry-common.S
index f379c852dcb7..9921898d29a1 100644
--- a/arch/arm/kernel/entry-common.S
+++ b/arch/arm/kernel/entry-common.S
@@ -119,7 +119,7 @@ no_work_pending:
 
 	ct_user_enter save = 0
 
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	bl	stackleak_erase_on_task_stack
 #endif
 	restore_user_regs fast = 0, offset = 0
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index 5ae2a34b50bd..c5456ff920d3 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -614,7 +614,7 @@ SYM_CODE_END(ret_to_kernel)
 SYM_CODE_START_LOCAL(ret_to_user)
 	ldr	x19, [tsk, #TSK_TI_FLAGS]	// re-check for single-step
 	enable_step_tsk x19, x2
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	bl	stackleak_erase_on_task_stack
 #endif
 	kernel_exit 0
diff --git a/arch/arm64/kernel/pi/Makefile b/arch/arm64/kernel/pi/Makefile
index 4d11a8c29181..77159298f3c6 100644
--- a/arch/arm64/kernel/pi/Makefile
+++ b/arch/arm64/kernel/pi/Makefile
@@ -2,7 +2,7 @@
 # Copyright 2022 Google LLC
 
 KBUILD_CFLAGS	:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) -fpie \
-		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK_PLUGIN) \
+		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK) \
 		   $(DISABLE_LATENT_ENTROPY_PLUGIN) \
 		   $(call cc-option,-mbranch-protection=none) \
 		   -I$(srctree)/scripts/dtc/libfdt -fno-stack-protector \
diff --git a/arch/arm64/kvm/hyp/nvhe/Makefile b/arch/arm64/kvm/hyp/nvhe/Makefile
index b43426a493df..4e00a2a8ad0c 100644
--- a/arch/arm64/kvm/hyp/nvhe/Makefile
+++ b/arch/arm64/kvm/hyp/nvhe/Makefile
@@ -12,7 +12,7 @@ asflags-y := -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPORTS
 ccflags-y := -D__KVM_NVHE_HYPERVISOR__ -D__DISABLE_EXPORTS -D__DISABLE_TRACE_MMIO__
 ccflags-y += -fno-stack-protector	\
 	     -DDISABLE_BRANCH_PROFILING	\
-	     $(DISABLE_STACKLEAK_PLUGIN)
+	     $(DISABLE_STACKLEAK)
 
 hostprogs := gen-hyprel
 HOST_EXTRACFLAGS += -I$(objtree)/include
diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index 33a5a9f2a0d4..d6e9903817f7 100644
--- a/arch/riscv/kernel/entry.S
+++ b/arch/riscv/kernel/entry.S
@@ -220,7 +220,7 @@ SYM_CODE_START_NOALIGN(ret_from_exception)
 #endif
 	bnez s0, 1f
 
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	call	stackleak_erase_on_task_stack
 #endif
 
diff --git a/arch/riscv/kernel/pi/Makefile b/arch/riscv/kernel/pi/Makefile
index 81d69d45c06c..40238ed13ea1 100644
--- a/arch/riscv/kernel/pi/Makefile
+++ b/arch/riscv/kernel/pi/Makefile
@@ -2,7 +2,7 @@
 # This file was copied from arm64/kernel/pi/Makefile.
 
 KBUILD_CFLAGS	:= $(subst $(CC_FLAGS_FTRACE),,$(KBUILD_CFLAGS)) -fpie \
-		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK_PLUGIN) \
+		   -Os -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK) \
 		   $(call cc-option,-mbranch-protection=none) \
 		   -I$(srctree)/scripts/dtc/libfdt -fno-stack-protector \
 		   -include $(srctree)/include/linux/hidden.h \
diff --git a/arch/riscv/purgatory/Makefile b/arch/riscv/purgatory/Makefile
index fb9c917c9b45..af8fa4aded5c 100644
--- a/arch/riscv/purgatory/Makefile
+++ b/arch/riscv/purgatory/Makefile
@@ -53,7 +53,7 @@ targets += purgatory.ro purgatory.chk
 
 PURGATORY_CFLAGS_REMOVE := -mcmodel=kernel
 PURGATORY_CFLAGS := -mcmodel=medany -ffreestanding -fno-zero-initialized-in-bss
-PURGATORY_CFLAGS += $(DISABLE_STACKLEAK_PLUGIN) -DDISABLE_BRANCH_PROFILING
+PURGATORY_CFLAGS += $(DISABLE_STACKLEAK) -DDISABLE_BRANCH_PROFILING
 PURGATORY_CFLAGS += -fno-stack-protector -g0
 
 # Default KBUILD_CFLAGS can have -pg option set when FTRACE is enabled. That
diff --git a/arch/s390/kernel/entry.S b/arch/s390/kernel/entry.S
index dd291c9ad6a6..6b43318dc0cc 100644
--- a/arch/s390/kernel/entry.S
+++ b/arch/s390/kernel/entry.S
@@ -124,7 +124,7 @@ _LPP_OFFSET	= __LC_LPP
 #endif
 
 	.macro STACKLEAK_ERASE
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	brasl	%r14,stackleak_erase_on_task_stack
 #endif
 	.endm
diff --git a/arch/x86/entry/calling.h b/arch/x86/entry/calling.h
index d83236b96f22..790e63df94a2 100644
--- a/arch/x86/entry/calling.h
+++ b/arch/x86/entry/calling.h
@@ -369,7 +369,7 @@ For 32-bit we have the following conventions - kernel is built with
 .endm
 
 .macro STACKLEAK_ERASE_NOCLOBBER
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	PUSH_AND_CLEAR_REGS
 	call stackleak_erase
 	POP_REGS
@@ -388,7 +388,7 @@ For 32-bit we have the following conventions - kernel is built with
 #endif /* !CONFIG_X86_64 */
 
 .macro STACKLEAK_ERASE
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	call stackleak_erase
 #endif
 .endm
diff --git a/arch/x86/purgatory/Makefile b/arch/x86/purgatory/Makefile
index ebdfd7b84feb..5450d5f7fd88 100644
--- a/arch/x86/purgatory/Makefile
+++ b/arch/x86/purgatory/Makefile
@@ -35,7 +35,7 @@ targets += purgatory.ro purgatory.chk
 PURGATORY_CFLAGS_REMOVE := -mcmodel=kernel
 PURGATORY_CFLAGS := -mcmodel=small -ffreestanding -fno-zero-initialized-in-bss -g0
 PURGATORY_CFLAGS += -fpic -fvisibility=hidden
-PURGATORY_CFLAGS += $(DISABLE_STACKLEAK_PLUGIN) -DDISABLE_BRANCH_PROFILING
+PURGATORY_CFLAGS += $(DISABLE_STACKLEAK) -DDISABLE_BRANCH_PROFILING
 PURGATORY_CFLAGS += -fno-stack-protector
 
 # Default KBUILD_CFLAGS can have -pg option set when FTRACE is enabled. That
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index d23a1b9fed75..1cfdde43da02 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -22,15 +22,15 @@ cflags-$(CONFIG_X86)		+= -m$(BITS) -D__KERNEL__ -std=gnu11 \
 
 # arm64 uses the full KBUILD_CFLAGS so it's necessary to explicitly
 # disable the stackleak plugin
-cflags-$(CONFIG_ARM64)		+= -fpie $(DISABLE_STACKLEAK_PLUGIN) \
+cflags-$(CONFIG_ARM64)		+= -fpie $(DISABLE_STACKLEAK) \
 				   -fno-unwind-tables -fno-asynchronous-unwind-tables
 cflags-$(CONFIG_ARM)		+= -DEFI_HAVE_STRLEN -DEFI_HAVE_STRNLEN \
 				   -DEFI_HAVE_MEMCHR -DEFI_HAVE_STRRCHR \
 				   -DEFI_HAVE_STRCMP -fno-builtin -fpic \
 				   $(call cc-option,-mno-single-pic-base) \
-				   $(DISABLE_STACKLEAK_PLUGIN)
+				   $(DISABLE_STACKLEAK)
 cflags-$(CONFIG_RISCV)		+= -fpic -DNO_ALTERNATIVE -mno-relax \
-				   $(DISABLE_STACKLEAK_PLUGIN)
+				   $(DISABLE_STACKLEAK)
 cflags-$(CONFIG_LOONGARCH)	+= -fpie
 
 cflags-$(CONFIG_EFI_PARAMS_FROM_FDT)	+= -I$(srctree)/scripts/dtc/libfdt
diff --git a/drivers/misc/lkdtm/stackleak.c b/drivers/misc/lkdtm/stackleak.c
index f1d022160913..ab8c690a039a 100644
--- a/drivers/misc/lkdtm/stackleak.c
+++ b/drivers/misc/lkdtm/stackleak.c
@@ -11,7 +11,7 @@
 #include "lkdtm.h"
 #include <linux/stackleak.h>
 
-#if defined(CONFIG_GCC_PLUGIN_STACKLEAK)
+#if defined(CONFIG_STACKLEAK)
 /*
  * Check that stackleak tracks the lowest stack pointer and erases the stack
  * below this as expected.
@@ -129,16 +129,16 @@ static void lkdtm_STACKLEAK_ERASING(void)
 	check_stackleak_irqoff();
 	local_irq_restore(flags);
 }
-#else /* defined(CONFIG_GCC_PLUGIN_STACKLEAK) */
+#else /* defined(CONFIG_STACKLEAK) */
 static void lkdtm_STACKLEAK_ERASING(void)
 {
 	if (IS_ENABLED(CONFIG_HAVE_ARCH_STACKLEAK)) {
-		pr_err("XFAIL: stackleak is not enabled (CONFIG_GCC_PLUGIN_STACKLEAK=n)\n");
+		pr_err("XFAIL: stackleak is not enabled (CONFIG_STACKLEAK=n)\n");
 	} else {
 		pr_err("XFAIL: stackleak is not supported on this arch (HAVE_ARCH_STACKLEAK=n)\n");
 	}
 }
-#endif /* defined(CONFIG_GCC_PLUGIN_STACKLEAK) */
+#endif /* defined(CONFIG_STACKLEAK) */
 
 static struct crashtype crashtypes[] = {
 	CRASHTYPE(STACKLEAK_ERASING),
diff --git a/include/linux/sched.h b/include/linux/sched.h
index f96ac1982893..f323a4d9f0ef 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1599,8 +1599,10 @@ struct task_struct {
 	/* Used by BPF for per-TASK xdp storage */
 	struct bpf_net_context		*bpf_net_context;
 
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 	unsigned long			lowest_stack;
+#endif
+#ifdef CONFIG_STACKLEAK_METRICS
 	unsigned long			prev_lowest_stack;
 #endif
 
diff --git a/include/linux/stackleak.h b/include/linux/stackleak.h
index 3be2cb564710..71e8242fd8f2 100644
--- a/include/linux/stackleak.h
+++ b/include/linux/stackleak.h
@@ -12,7 +12,7 @@
 #define STACKLEAK_POISON -0xBEEF
 #define STACKLEAK_SEARCH_DEPTH 128
 
-#ifdef CONFIG_GCC_PLUGIN_STACKLEAK
+#ifdef CONFIG_STACKLEAK
 #include <asm/stacktrace.h>
 #include <linux/linkage.h>
 
@@ -82,7 +82,7 @@ asmlinkage void noinstr stackleak_erase_on_task_stack(void);
 asmlinkage void noinstr stackleak_erase_off_task_stack(void);
 void __no_caller_saved_registers noinstr stackleak_track_stack(void);
 
-#else /* !CONFIG_GCC_PLUGIN_STACKLEAK */
+#else /* !CONFIG_STACKLEAK */
 static inline void stackleak_task_init(struct task_struct *t) { }
 #endif
 
diff --git a/kernel/Makefile b/kernel/Makefile
index 434929de17ef..79583e3501b4 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -137,8 +137,8 @@ obj-$(CONFIG_WATCH_QUEUE) += watch_queue.o
 obj-$(CONFIG_RESOURCE_KUNIT_TEST) += resource_kunit.o
 obj-$(CONFIG_SYSCTL_KUNIT_TEST) += sysctl-test.o
 
-CFLAGS_stackleak.o += $(DISABLE_STACKLEAK_PLUGIN)
-obj-$(CONFIG_GCC_PLUGIN_STACKLEAK) += stackleak.o
+CFLAGS_stackleak.o += $(DISABLE_STACKLEAK)
+obj-$(CONFIG_STACKLEAK) += stackleak.o
 KASAN_SANITIZE_stackleak.o := n
 KCSAN_SANITIZE_stackleak.o := n
 KCOV_INSTRUMENT_stackleak.o := n
diff --git a/lib/Makefile b/lib/Makefile
index f07b24ce1b3f..720c4846d255 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -338,7 +338,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
 UBSAN_SANITIZE_ubsan.o := n
 KASAN_SANITIZE_ubsan.o := n
 KCSAN_SANITIZE_ubsan.o := n
-CFLAGS_ubsan.o := -fno-stack-protector $(DISABLE_STACKLEAK_PLUGIN)
+CFLAGS_ubsan.o := -fno-stack-protector $(DISABLE_STACKLEAK)
 
 obj-$(CONFIG_SBITMAP) += sbitmap.o
 
diff --git a/scripts/Makefile.gcc-plugins b/scripts/Makefile.gcc-plugins
index e4deaf5fa571..e3ed92e20d16 100644
--- a/scripts/Makefile.gcc-plugins
+++ b/scripts/Makefile.gcc-plugins
@@ -32,9 +32,9 @@ gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK)		\
 gcc-plugin-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE)	\
 		+= -fplugin-arg-stackleak_plugin-verbose
 ifdef CONFIG_GCC_PLUGIN_STACKLEAK
-    DISABLE_STACKLEAK_PLUGIN += -fplugin-arg-stackleak_plugin-disable
+    DISABLE_STACKLEAK += -fplugin-arg-stackleak_plugin-disable
 endif
-export DISABLE_STACKLEAK_PLUGIN
+export DISABLE_STACKLEAK
 
 gcc-plugin-$(CONFIG_GCC_PLUGIN_ARM_SSP_PER_TASK) += arm_ssp_per_task_plugin.so
 ifdef CONFIG_GCC_PLUGIN_ARM_SSP_PER_TASK
diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index 3fe9d7b945c4..8aa5c1d4794d 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -158,10 +158,10 @@ config GCC_PLUGIN_STRUCTLEAK_VERBOSE
 	  initialized. Since not all existing initializers are detected
 	  by the plugin, this can produce false positive warnings.
 
-config GCC_PLUGIN_STACKLEAK
+config STACKLEAK
 	bool "Poison kernel stack before returning from syscalls"
-	depends on GCC_PLUGINS
 	depends on HAVE_ARCH_STACKLEAK
+	depends on GCC_PLUGINS
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
@@ -179,6 +179,10 @@ config GCC_PLUGIN_STACKLEAK
 	  are advised to test this feature on your expected workload before
 	  deploying it.
 
+config GCC_PLUGIN_STACKLEAK
+	def_bool STACKLEAK
+	depends on GCC_PLUGINS
+	help
 	  This plugin was ported from grsecurity/PaX. More information at:
 	   * https://grsecurity.net/
 	   * https://pax.grsecurity.net/
@@ -197,9 +201,9 @@ config STACKLEAK_TRACK_MIN_SIZE
 	int "Minimum stack frame size of functions tracked by STACKLEAK"
 	default 100
 	range 0 4096
-	depends on GCC_PLUGIN_STACKLEAK
+	depends on STACKLEAK
 	help
-	  The STACKLEAK gcc plugin instruments the kernel code for tracking
+	  The STACKLEAK options instruments the kernel code for tracking
 	  the lowest border of the kernel stack (and for some other purposes).
 	  It inserts the stackleak_track_stack() call for the functions with
 	  a stack frame size greater than or equal to this parameter.
@@ -207,7 +211,7 @@ config STACKLEAK_TRACK_MIN_SIZE
 
 config STACKLEAK_METRICS
 	bool "Show STACKLEAK metrics in the /proc file system"
-	depends on GCC_PLUGIN_STACKLEAK
+	depends on STACKLEAK
 	depends on PROC_FS
 	help
 	  If this is set, STACKLEAK metrics for every task are available in
@@ -219,11 +223,11 @@ config STACKLEAK_METRICS
 
 config STACKLEAK_RUNTIME_DISABLE
 	bool "Allow runtime disabling of kernel stack erasing"
-	depends on GCC_PLUGIN_STACKLEAK
+	depends on STACKLEAK
 	help
 	  This option provides 'stack_erasing' sysctl, which can be used in
 	  runtime to control kernel stack erasing for kernels built with
-	  CONFIG_GCC_PLUGIN_STACKLEAK.
+	  CONFIG_STACKLEAK.
 
 config INIT_ON_ALLOC_DEFAULT_ON
 	bool "Enable heap memory zeroing on allocation by default"
diff --git a/tools/testing/selftests/lkdtm/config b/tools/testing/selftests/lkdtm/config
index 7afe05e8c4d7..b9b1275c07e8 100644
--- a/tools/testing/selftests/lkdtm/config
+++ b/tools/testing/selftests/lkdtm/config
@@ -2,7 +2,7 @@ CONFIG_LKDTM=y
 CONFIG_DEBUG_LIST=y
 CONFIG_SLAB_FREELIST_HARDENED=y
 CONFIG_FORTIFY_SOURCE=y
-CONFIG_GCC_PLUGIN_STACKLEAK=y
+CONFIG_STACKLEAK=y
 CONFIG_HARDENED_USERCOPY=y
 CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT=y
 CONFIG_INIT_ON_FREE_DEFAULT_ON=y
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250502190129.246328-1-kees%40kernel.org.
