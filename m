Return-Path: <kasan-dev+bncBD4NDKWHQYDRBV4L66WAMGQEOWMO7YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 67F19828F87
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:16:57 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6dddb4e9f4esf1898670a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:16:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704838616; cv=pass;
        d=google.com; s=arc-20160816;
        b=FjuzFJrXlBO+BNkXDJ+hMOaGaQEXzgamppQB0vfjKE/B3jPTKOKTVfNTHSsXnDviVk
         rGgpcKJpGp20GXZ96mIwTTwcO0mmqTtlj4FYP7ktrCyqjpVtslf/5yt6ENBk83ZGOr/c
         /vIvHPkX8gL5BU/Oz5bF7HND8sTZNDFpxlpuwvfwUC8A622FwS1hiwSVJXHuBaGW3q2J
         ljUwnLX1J1f3z45i7GnuGSiJrYPZB0aImRumVbTkTR4QGpnjZxWFmbKoREReTLjJRXI5
         +0ybtekkN6hp1678YiALVWXAcA3YEeILODL0Jj/6GSPVGigiMmppWh4aFhFNex9ldwVv
         Q+GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=nl0EmfycZTGifoqieMvwKJdAC+ffnW6yh7fE862Cbxs=;
        fh=U610rwpBWzjqqwzWB+qVKy6HwACT/aT32/o8U6KTT3E=;
        b=KyIVnBMXlVkWo5Zs3cgf1dlsOWpnkP8Y25Ew3Rc8hFZKDQJwb89vD2AOWBW/J/hbxR
         Ma8IcD7ifyOB6uNY+BIJABve+ipYb4deMp3zrUbG7VaV4Yi9kGQ8pyxMZirlj9sr2UJp
         oyGBkgJFdHg9l4iwsMcNPMkPNue5eQxx7on54PWEVmYVkb77oYI80RELpz8TxKC+4EXY
         thtvjW/YrDTxQaSWkyxxIkKTaZ1OF//jIFhpq/EzxBEp3PYRtKM7OhFXPLHw2GyuGb4c
         AKhZfZ/Tbb69naYYGETvG4NJn4K7bydgOvp9+0yVM6AWfWXUcRWdYcpji83satUumO6x
         PeaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zq8ocN8G;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704838616; x=1705443416; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nl0EmfycZTGifoqieMvwKJdAC+ffnW6yh7fE862Cbxs=;
        b=ahgbX87tLXn00vLsQwPztw5kGVtEwBxogRCvRAjzae/2CqpdL0Ix5PS02aAiNlyr+3
         yzDDsTKKEmlRJgHvryll8V3PcHAR8UiSJ8v/f04QPK0PD2CouHnz3NiHlkh4Dnpv9wqS
         3msgTbLgdktiEnuDknCsyxSDiXCnCT2DzNijdn0zCfAP+c4sinnbY4ct3NAO0WklbVGc
         qF24Trqt+XGO+aZYUAFWqXIFeZzEQQQJp2SYhRlqowZLNrN7LKYumOflOrqQWKxrhlSM
         8Tgu/duIGyBs/Woe4stKf2DPVNy+xNPsgrQ7lbCVaWx+Mdfj7Hn/p6ur/MTHkg0xIY8x
         k5cA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704838616; x=1705443416;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nl0EmfycZTGifoqieMvwKJdAC+ffnW6yh7fE862Cbxs=;
        b=HOnvE9YzGj6rISF2CvOO6gVroaNLr7QM8eBWNvASZSI5wza+OBft/1gN0UiI+Pe3hd
         w3O6hB4bUD5uH9hUM97Shlobum/+3pqKWYyfrzGCLTVhq629SdTaFRiumS1h7k1QIIuc
         wo7tiURg5z19/lIoozwGrt1QD9J1hVuuCRQXXetgTwGAKuYnvyRORDngSNAWRPtDjrwQ
         0O1s6RJGGk7/vKNm5Vpw7lfpxE2J8cIb/FILPDRG1yvxcpOEwC9D+WDgkfsKN7QMDGj1
         5soHsIeFr2bOHETue+AlWYq43TQM9Fy8ciQvxzFnyZhWTksqPFD7SWfDcJNNtomyo3G7
         QXvg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxd+q7g0tMRrSv5w14I7CxQP+NDyQOI5D+yMQP8wA3SMxm50j1i
	e7b6sGYbDqNl8p7RPMKglRs=
X-Google-Smtp-Source: AGHT+IG4wGYaGmhdtHzSbvGHXewXDwlXhP+BYC4N2FN/EK3A2Y7cvu0bEQwoxiwqsYSbBbeCZ+wCNQ==
X-Received: by 2002:a05:6830:3298:b0:6dd:df3b:f4e0 with SMTP id m24-20020a056830329800b006dddf3bf4e0mr37849ott.51.1704838616032;
        Tue, 09 Jan 2024 14:16:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2290:b0:596:19d7:6e16 with SMTP id
 ck16-20020a056820229000b0059619d76e16ls1082724oob.2.-pod-prod-03-us; Tue, 09
 Jan 2024 14:16:55 -0800 (PST)
X-Received: by 2002:a9d:7d0d:0:b0:6dd:e0d0:cabc with SMTP id v13-20020a9d7d0d000000b006dde0d0cabcmr49875otn.8.1704838615314;
        Tue, 09 Jan 2024 14:16:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704838615; cv=none;
        d=google.com; s=arc-20160816;
        b=fROQjLYn99mQ/YX9qpxAdIu4UFkMXLevbDJiAE3AMq07JV6jESswXBX/BSYozNTkDY
         YoTAJ3xJvdRcR7Sb561W8qmPHh03Lm7mp5XHpx1fuIn6NVCbzK6rfq1XUTh0dkCBnN96
         Rm1pFa0+H4PafByka95ig46B522tLRLj22w21e55+P8rwLr31A5om9+ZcawqZao0PFmq
         5XvAGViF1mYN+RWTqA010ad6/3pC7yJwKKh0ZDbYf6Fo5TRrVQcBUbKmXn9h0S4vk8Ib
         H6yQnY1++8fexl7PeRulehs/ZRhTx2xHocg4waYPIe6yEgPZy6mUYNusIeZUaVzaR8XR
         kJYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=NPQlNW6AIpj2THHiIngJe+lsrXoJ3MnTkEIzhUpB1nE=;
        fh=U610rwpBWzjqqwzWB+qVKy6HwACT/aT32/o8U6KTT3E=;
        b=w4GAIwutuWTP7HM/5pXeI8weEfi0XcDEBl9zJP8zxz6MmBZwu2EalIH+xFIcG+Rds4
         Dy4IU7fFoZ3ZJ0p9BTdUaTe94p5XKtbVYQoCA9vIaKtdGIVaMaHDSWJCsj6wya5Ed+5p
         i/rkkuC2hvikMJJCxOKjNzqb1FH6EUmkeBQ+ZP9E4DAwSAHk4kZlDoaWvl8rcJzLXI+3
         fIe/rpQYZPuZcpKlz3FtSmlwRaTLnPi5OkVzYkjGJhg7Bf11133+wlcBtfbNJQn7KaQ/
         UTm1HqDx7ncT1TNH7o/rP8Eqy49vx7QypwYdIZeAm80YWhF2gsgXXhVNNSh2scDbTUcb
         55Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Zq8ocN8G;
       spf=pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id r16-20020a0de810000000b005eed61daa67si262758ywe.2.2024.01.09.14.16.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Jan 2024 14:16:55 -0800 (PST)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DD333615A4;
	Tue,  9 Jan 2024 22:16:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7695CC4163A;
	Tue,  9 Jan 2024 22:16:53 +0000 (UTC)
From: Nathan Chancellor <nathan@kernel.org>
Date: Tue, 09 Jan 2024 15:16:31 -0700
Subject: [PATCH 3/3] treewide: Update LLVM Bugzilla links
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240109-update-llvm-links-v1-3-eb09b59db071@kernel.org>
References: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
In-Reply-To: <20240109-update-llvm-links-v1-0-eb09b59db071@kernel.org>
To: akpm@linux-foundation.org
Cc: llvm@lists.linux.dev, patches@lists.linux.dev, 
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linuxppc-dev@lists.ozlabs.org, kvm@vger.kernel.org, 
 linux-riscv@lists.infradead.org, linux-trace-kernel@vger.kernel.org, 
 linux-s390@vger.kernel.org, linux-pm@vger.kernel.org, 
 linux-crypto@vger.kernel.org, linux-efi@vger.kernel.org, 
 amd-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
 linux-media@vger.kernel.org, linux-arch@vger.kernel.org, 
 kasan-dev@googlegroups.com, linux-mm@kvack.org, bridge@lists.linux.dev, 
 netdev@vger.kernel.org, linux-security-module@vger.kernel.org, 
 linux-kselftest@vger.kernel.org, Nathan Chancellor <nathan@kernel.org>
X-Mailer: b4 0.13-dev
X-Developer-Signature: v=1; a=openpgp-sha256; l=11357; i=nathan@kernel.org;
 h=from:subject:message-id; bh=WEn5lTrzAXiM29oFJTOtG7WGsQHyaE8VVcpnTQ825es=;
 b=owGbwMvMwCUmm602sfCA1DTG02pJDKlzj16w1Pj8I8RGNGpqStpeL/2Ss7Fckxj+MQn8ummhc
 f/e3puMHaUsDGJcDLJiiizVj1WPGxrOOct449QkmDmsTCBDGLg4BWAipzgZ/mcpXDN6n369Z2Vr
 7IPwnTz2R5dYJN5v++9iM3XOfBYtOU5GhuM55jNe+5/7H/HicGe1b2CLnMlqaZtVrzg+6Dfn1Hg
 YcwMA
X-Developer-Key: i=nathan@kernel.org; a=openpgp;
 fpr=2437CB76E544CB6AB3D9DFD399739260CB6CB716
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Zq8ocN8G;       spf=pass
 (google.com: domain of nathan@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

LLVM moved their issue tracker from their own Bugzilla instance to
GitHub issues. While all of the links are still valid, they may not
necessarily show the most up to date information around the issues, as
all updates will occur on GitHub, not Bugzilla.

Another complication is that the Bugzilla issue number is not always the
same as the GitHub issue number. Thankfully, LLVM maintains this mapping
through two shortlinks:

  https://llvm.org/bz<num> -> https://bugs.llvm.org/show_bug.cgi?id=<num>
  https://llvm.org/pr<num> -> https://github.com/llvm/llvm-project/issues/<mapped_num>

Switch all "https://bugs.llvm.org/show_bug.cgi?id=<num>" links to the
"https://llvm.org/pr<num>" shortlink so that the links show the most up
to date information. Each migrated issue links back to the Bugzilla
entry, so there should be no loss of fidelity of information here.

Signed-off-by: Nathan Chancellor <nathan@kernel.org>
---
 arch/powerpc/Makefile                           | 4 ++--
 arch/powerpc/kvm/book3s_hv_nested.c             | 2 +-
 arch/s390/include/asm/ftrace.h                  | 2 +-
 arch/x86/power/Makefile                         | 2 +-
 crypto/blake2b_generic.c                        | 2 +-
 drivers/firmware/efi/libstub/Makefile           | 2 +-
 drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c        | 2 +-
 drivers/media/test-drivers/vicodec/codec-fwht.c | 2 +-
 drivers/regulator/Kconfig                       | 2 +-
 include/asm-generic/vmlinux.lds.h               | 2 +-
 lib/Kconfig.kasan                               | 2 +-
 lib/raid6/Makefile                              | 2 +-
 lib/stackinit_kunit.c                           | 2 +-
 mm/slab_common.c                                | 2 +-
 net/bridge/br_multicast.c                       | 2 +-
 security/Kconfig                                | 2 +-
 16 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
index f19dbaa1d541..cd6aaa45f355 100644
--- a/arch/powerpc/Makefile
+++ b/arch/powerpc/Makefile
@@ -133,11 +133,11 @@ CFLAGS-$(CONFIG_PPC64)	+= $(call cc-option,-mno-pointers-to-nested-functions)
 CFLAGS-$(CONFIG_PPC64)	+= $(call cc-option,-mlong-double-128)
 
 # Clang unconditionally reserves r2 on ppc32 and does not support the flag
-# https://bugs.llvm.org/show_bug.cgi?id=39555
+# https://llvm.org/pr39555
 CFLAGS-$(CONFIG_PPC32)	:= $(call cc-option, -ffixed-r2)
 
 # Clang doesn't support -mmultiple / -mno-multiple
-# https://bugs.llvm.org/show_bug.cgi?id=39556
+# https://llvm.org/pr39556
 CFLAGS-$(CONFIG_PPC32)	+= $(call cc-option, $(MULTIPLEWORD))
 
 CFLAGS-$(CONFIG_PPC32)	+= $(call cc-option,-mno-readonly-in-sdata)
diff --git a/arch/powerpc/kvm/book3s_hv_nested.c b/arch/powerpc/kvm/book3s_hv_nested.c
index 3b658b8696bc..3f5970f74c6b 100644
--- a/arch/powerpc/kvm/book3s_hv_nested.c
+++ b/arch/powerpc/kvm/book3s_hv_nested.c
@@ -55,7 +55,7 @@ void kvmhv_save_hv_regs(struct kvm_vcpu *vcpu, struct hv_guest_state *hr)
 	hr->dawrx1 = vcpu->arch.dawrx1;
 }
 
-/* Use noinline_for_stack due to https://bugs.llvm.org/show_bug.cgi?id=49610 */
+/* Use noinline_for_stack due to https://llvm.org/pr49610 */
 static noinline_for_stack void byteswap_pt_regs(struct pt_regs *regs)
 {
 	unsigned long *addr = (unsigned long *) regs;
diff --git a/arch/s390/include/asm/ftrace.h b/arch/s390/include/asm/ftrace.h
index 5a82b08f03cd..621f23d5ae30 100644
--- a/arch/s390/include/asm/ftrace.h
+++ b/arch/s390/include/asm/ftrace.h
@@ -9,7 +9,7 @@
 #ifndef __ASSEMBLY__
 
 #ifdef CONFIG_CC_IS_CLANG
-/* https://bugs.llvm.org/show_bug.cgi?id=41424 */
+/* https://llvm.org/pr41424 */
 #define ftrace_return_address(n) 0UL
 #else
 #define ftrace_return_address(n) __builtin_return_address(n)
diff --git a/arch/x86/power/Makefile b/arch/x86/power/Makefile
index 379777572bc9..e0cd7afd5302 100644
--- a/arch/x86/power/Makefile
+++ b/arch/x86/power/Makefile
@@ -5,7 +5,7 @@
 CFLAGS_cpu.o	:= -fno-stack-protector
 
 # Clang may incorrectly inline functions with stack protector enabled into
-# __restore_processor_state(): https://bugs.llvm.org/show_bug.cgi?id=47479
+# __restore_processor_state(): https://llvm.org/pr47479
 CFLAGS_REMOVE_cpu.o := $(CC_FLAGS_LTO)
 
 obj-$(CONFIG_PM_SLEEP)		+= cpu.o
diff --git a/crypto/blake2b_generic.c b/crypto/blake2b_generic.c
index 6704c0355889..32e380b714b6 100644
--- a/crypto/blake2b_generic.c
+++ b/crypto/blake2b_generic.c
@@ -102,7 +102,7 @@ static void blake2b_compress_one_generic(struct blake2b_state *S,
 	ROUND(10);
 	ROUND(11);
 #ifdef CONFIG_CC_IS_CLANG
-#pragma nounroll /* https://bugs.llvm.org/show_bug.cgi?id=45803 */
+#pragma nounroll /* https://llvm.org/pr45803 */
 #endif
 	for (i = 0; i < 8; ++i)
 		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
index 06964a3c130f..a223bd10564b 100644
--- a/drivers/firmware/efi/libstub/Makefile
+++ b/drivers/firmware/efi/libstub/Makefile
@@ -105,7 +105,7 @@ lib-y				:= $(patsubst %.o,%.stub.o,$(lib-y))
 # Even when -mbranch-protection=none is set, Clang will generate a
 # .note.gnu.property for code-less object files (like lib/ctype.c),
 # so work around this by explicitly removing the unwanted section.
-# https://bugs.llvm.org/show_bug.cgi?id=46480
+# https://llvm.org/pr46480
 STUBCOPY_FLAGS-y		+= --remove-section=.note.gnu.property
 
 STUBCOPY_RELOC-$(CONFIG_X86_32)	:= R_386_32
diff --git a/drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c b/drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c
index 0f24af6f2810..265fa028b121 100644
--- a/drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c
+++ b/drivers/gpu/drm/amd/amdgpu/sdma_v4_4_2.c
@@ -610,7 +610,7 @@ static uint32_t sdma_v4_4_2_rb_cntl(struct amdgpu_ring *ring, uint32_t rb_cntl)
 	/* Set ring buffer size in dwords */
 	uint32_t rb_bufsz = order_base_2(ring->ring_size / 4);
 
-	barrier(); /* work around https://bugs.llvm.org/show_bug.cgi?id=42576 */
+	barrier(); /* work around https://llvm.org/pr42576 */
 	rb_cntl = REG_SET_FIELD(rb_cntl, SDMA_GFX_RB_CNTL, RB_SIZE, rb_bufsz);
 #ifdef __BIG_ENDIAN
 	rb_cntl = REG_SET_FIELD(rb_cntl, SDMA_GFX_RB_CNTL, RB_SWAP_ENABLE, 1);
diff --git a/drivers/media/test-drivers/vicodec/codec-fwht.c b/drivers/media/test-drivers/vicodec/codec-fwht.c
index 1ce682e1b85c..fd75457d03b2 100644
--- a/drivers/media/test-drivers/vicodec/codec-fwht.c
+++ b/drivers/media/test-drivers/vicodec/codec-fwht.c
@@ -49,7 +49,7 @@ static const uint8_t zigzag[64] = {
 
 /*
  * noinline_for_stack to work around
- * https://bugs.llvm.org/show_bug.cgi?id=38809
+ * https://llvm.org/pr38809
  */
 static int noinline_for_stack
 rlc(const s16 *in, __be16 *output, int blocktype)
diff --git a/drivers/regulator/Kconfig b/drivers/regulator/Kconfig
index f3ec24691378..f537e78478ef 100644
--- a/drivers/regulator/Kconfig
+++ b/drivers/regulator/Kconfig
@@ -278,7 +278,7 @@ config REGULATOR_CROS_EC
 config REGULATOR_DA903X
 	tristate "Dialog Semiconductor DA9030/DA9034 regulators"
 	depends on PMIC_DA903X
-	depends on !CC_IS_CLANG # https://bugs.llvm.org/show_bug.cgi?id=38789
+	depends on !CC_IS_CLANG # https://llvm.org/pr38789
 	help
 	  Say y here to support the BUCKs and LDOs regulators found on
 	  Dialog Semiconductor DA9030/DA9034 PMIC.
diff --git a/include/asm-generic/vmlinux.lds.h b/include/asm-generic/vmlinux.lds.h
index bae0fe4d499b..c425a1e2edee 100644
--- a/include/asm-generic/vmlinux.lds.h
+++ b/include/asm-generic/vmlinux.lds.h
@@ -977,7 +977,7 @@
  * -fsanitize=thread produce unwanted sections (.eh_frame
  * and .init_array.*), but CONFIG_CONSTRUCTORS wants to
  * keep any .init_array.* sections.
- * https://bugs.llvm.org/show_bug.cgi?id=46478
+ * https://llvm.org/pr46478
  */
 #ifdef CONFIG_UNWIND_TABLES
 #define DISCARD_EH_FRAME
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..de3e9e4803af 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -163,7 +163,7 @@ config KASAN_STACK
 	  out-of-bounds bugs in stack variables.
 
 	  With Clang, stack instrumentation has a problem that causes excessive
-	  stack usage, see https://bugs.llvm.org/show_bug.cgi?id=38809. Thus,
+	  stack usage, see https://llvm.org/pr38809. Thus,
 	  with Clang, this option is deemed unsafe.
 
 	  This option is always disabled when compile-testing with Clang to
diff --git a/lib/raid6/Makefile b/lib/raid6/Makefile
index 1c5420ff254e..385a94aa0b99 100644
--- a/lib/raid6/Makefile
+++ b/lib/raid6/Makefile
@@ -21,7 +21,7 @@ altivec_flags += -isystem $(shell $(CC) -print-file-name=include)
 ifdef CONFIG_CC_IS_CLANG
 # clang ppc port does not yet support -maltivec when -msoft-float is
 # enabled. A future release of clang will resolve this
-# https://bugs.llvm.org/show_bug.cgi?id=31177
+# https://llvm.org/pr31177
 CFLAGS_REMOVE_altivec1.o  += -msoft-float
 CFLAGS_REMOVE_altivec2.o  += -msoft-float
 CFLAGS_REMOVE_altivec4.o  += -msoft-float
diff --git a/lib/stackinit_kunit.c b/lib/stackinit_kunit.c
index 05947a2feb93..7a10e1d17258 100644
--- a/lib/stackinit_kunit.c
+++ b/lib/stackinit_kunit.c
@@ -404,7 +404,7 @@ static noinline int leaf_switch_2_none(unsigned long sp, bool fill,
  * These are expected to fail for most configurations because neither
  * GCC nor Clang have a way to perform initialization of variables in
  * non-code areas (i.e. in a switch statement before the first "case").
- * https://bugs.llvm.org/show_bug.cgi?id=44916
+ * https://llvm.org/pr44916
  */
 DEFINE_TEST_DRIVER(switch_1_none, uint64_t, SCALAR, ALWAYS_FAIL);
 DEFINE_TEST_DRIVER(switch_2_none, uint64_t, SCALAR, ALWAYS_FAIL);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 8d431193c273..105ba974854c 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -656,7 +656,7 @@ static struct kmem_cache *__init create_kmalloc_cache(const char *name,
 
 struct kmem_cache *
 kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1] __ro_after_init =
-{ /* initialization for https://bugs.llvm.org/show_bug.cgi?id=42570 */ };
+{ /* initialization for https://llvm.org/pr42570 */ };
 EXPORT_SYMBOL(kmalloc_caches);
 
 #ifdef CONFIG_RANDOM_KMALLOC_CACHES
diff --git a/net/bridge/br_multicast.c b/net/bridge/br_multicast.c
index d7d021af1029..523f72ac9633 100644
--- a/net/bridge/br_multicast.c
+++ b/net/bridge/br_multicast.c
@@ -5043,7 +5043,7 @@ void br_multicast_uninit_stats(struct net_bridge *br)
 	free_percpu(br->mcast_stats);
 }
 
-/* noinline for https://bugs.llvm.org/show_bug.cgi?id=45802#c9 */
+/* noinline for https://llvm.org/pr45802#c9 */
 static noinline_for_stack void mcast_stats_add_dir(u64 *dst, u64 *src)
 {
 	dst[BR_MCAST_DIR_RX] += src[BR_MCAST_DIR_RX];
diff --git a/security/Kconfig b/security/Kconfig
index 52c9af08ad35..606a87c29a01 100644
--- a/security/Kconfig
+++ b/security/Kconfig
@@ -142,7 +142,7 @@ config HARDENED_USERCOPY
 config FORTIFY_SOURCE
 	bool "Harden common str/mem functions against buffer overflows"
 	depends on ARCH_HAS_FORTIFY_SOURCE
-	# https://bugs.llvm.org/show_bug.cgi?id=41459
+	# https://llvm.org/pr41459
 	depends on !CC_IS_CLANG || CLANG_VERSION >= 120001
 	# https://github.com/llvm/llvm-project/issues/53645
 	depends on !CC_IS_CLANG || !X86_32

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240109-update-llvm-links-v1-3-eb09b59db071%40kernel.org.
