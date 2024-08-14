Return-Path: <kasan-dev+bncBCMIFTP47IJBB56O6G2QMGQE4ES2PGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id A128995164A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:14:48 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-6acf8ac7569sf10491637b3.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:14:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723623287; cv=pass;
        d=google.com; s=arc-20160816;
        b=p9H1HNVNFH12MbOhQ5oHX+OqXcubN+aO1v0J/SvjQxIdfZ7uaGahA8fEn4UuBRAnC3
         06RG93RFi/jqHoJ14ldmrAiHioDxoMPEHj2cfJuA/uSFwV6qeIu/QCpRT3d1ypX0ypEf
         aN9aeRlnOl0x/1jcqsEpcpPgvJO0WLdYt5UE8AAskT/wkvd5Rx/3iy6gWPPU2f/Dksiq
         aFUPwVgtSIP13NmNUJRcFvLDuT1GPLdGL/d0AiAn3zYLs7XUU6WckK19+pJVbr1+vJfr
         DCTsu5dSQ0GBFr2lW9jAS8KkcKZTyIBUzJfsF8UOT6ckAww02Yt0tRN99mgM7Gcy1zfD
         T49g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=32k55KIpI/CgfbEuHzdxESmGyYZXSopH4d2qWASqcI8=;
        fh=cVV6xkMyTLOqH4EYNaxbcTsyR3icJYirAFTKNBa36Sk=;
        b=vqPSwjYSk7cOMnu2ku/HOUPXI3W+ow6PpGonFQ9xicM1xJ0tuSXBZj/0SV8nZvtILF
         /mLvYn70Kl8gs4MMR0dm0ZoAEgFcO7MRVsa8yh7x4cvb8Sjt0kf+EVEO5ixwpRVTDxge
         mFaeukZjyzI5MRvw5iwa2O3AXLIONg7gZ/u6rIHnLIzPbxDAQmFxZ7aJsTtVMTBJWZTu
         YgVqUMLiVwOYgmYXkESGyJLLq9zC7pusAVEOdjBjc/BxXkQm7uCYgsTnKyqo7DXKtsol
         85Pk/spswYTF1eOLbivVjHvSvGxtjA1aWEqCC0u5MesiKmERd1AxRI3ph8rFqfPRs2ZB
         i7og==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="dd9X/0nj";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723623287; x=1724228087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=32k55KIpI/CgfbEuHzdxESmGyYZXSopH4d2qWASqcI8=;
        b=DRAfunvt32R45kFW3uv5ezSxDIPlEd3yRzGD4TahAAzdEuEcHYMPobyYSfs20fjoHw
         GhfEyLFe88LrpwmzPGZwgQN/OIfqUBx8jwH3Cj0PHxviMooJd/PObwIaMwjB++HNBn7e
         iJryL+yBMKqQVPQ7PVEzF702V5TpEoY9zrEzFfTBSA5i9fccG67I6eplxkzevYiZSGiE
         OcK7fNXNT/3u0Uji97pLRG4012b3XO84bAj5dxQPDzMXM3XaGP7ZnZKZFQ7F72dKhJsz
         I/xrZuNx6dhVowh6a2z5XdOWqHUalcKEaKPokKMMHowmoymXBeBp3paJrpIpagYJqxtv
         jIGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723623287; x=1724228087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=32k55KIpI/CgfbEuHzdxESmGyYZXSopH4d2qWASqcI8=;
        b=KSgzs4II1DwxwS3kSwqchOgHFYZuMrtKh2BrRBrn9VaPVG7al2pF295FNCSCmbba8c
         JNnQefcXW+kNe//IOg5Ao+Iq76bMriGE+QfQ2kwYJIX2tas0nTt0w30L/RnSpGezDPsK
         n3WoXcSuJI4qfBOCZq+XTre7qrTxggsgHRiZRHLC6eV43unGK0cjyZSMFghacecKzYU3
         mOVZ/HFgWqKX5BHIY4emzhisO0UCsOAaUwUeCv0X2PrLjUddFlD5ZPEU97Ao6DixdqmY
         jjghv+24/SOI5kTsVW4SBdvLe20IhnPOMQ0co6EdOaiA8fJx3ue3vlud/2aKQ7q90en1
         iqNw==
X-Forwarded-Encrypted: i=2; AJvYcCVKsEiDXQ0dlTWAqHrIu/HknHB4ZClP3//6TEoW8EuJV50lbv0S5/Dmz+aIft2MU7J6QRiWMQ==@lfdr.de
X-Gm-Message-State: AOJu0YymdxI+JbIpbgFrqKbPlmh7fPWoGnSCbVJKkEW6XZOYwloz8uJS
	1p5+OIEuCyB9iAU3e5lpULVRoAcdwVv9dzUmUR9gxhEO2gACJWVZ
X-Google-Smtp-Source: AGHT+IFJ48NSCPU7T6G7QS9Ylu1KkmP6tXLVpzqUSaeadYWI/qHhCloyTiP4MI5pz1S44OF3aLhhhw==
X-Received: by 2002:a05:6902:1708:b0:e0b:e28c:b4f4 with SMTP id 3f1490d57ef6-e1155bb3d5bmr2589528276.38.1723623287220;
        Wed, 14 Aug 2024 01:14:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4987:0:b0:e0e:cec7:7a05 with SMTP id 3f1490d57ef6-e0ecec79901ls2156969276.1.-pod-prod-01-us;
 Wed, 14 Aug 2024 01:14:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoPZA0XQnD9hC5bgOIJFKV1bXGI3PWKKq2CWb+mLmLpAvWluZXuZT9r2K1o4cFYWwXnIoLzSn/wOw=@googlegroups.com
X-Received: by 2002:a05:6902:a90:b0:e08:551f:c90f with SMTP id 3f1490d57ef6-e1155a4ad28mr2391044276.7.1723623286487;
        Wed, 14 Aug 2024 01:14:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723623286; cv=none;
        d=google.com; s=arc-20160816;
        b=pFVfop5b8nualKXCHF8MyNSaTIjJ9xINBPUCfhd/HvBiBmnZLFZlnClr2Yn9VbJ7wZ
         l7qyhx2h/2IKZ84mr7JM8Mrst8od2lZhbEb++zQl4P7mWFoU0kqlf353T2SbSB2ZygUt
         rWf3lbL6ycYWarqsUJ+nBlUwVTZNm85ic5Nv0dTPVBGoN9UDO8AHZrixySlKGhf4A+Iu
         B8rByy1MZ2Wca9oBjI6b2B4Ld/KCkjbAAmdS6A14mD5XPGyuS9qMXCHlWA0Yrm+p7Ymf
         CqZNlGRarYweuowxw7fMf6tKvsTZ0uaFurc6fixbZTFuPIBvHwvAgx/DSBskA4rLCea/
         BsDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FGFNLFqSjlWe1rFESyvT8Bv10SEVbMi3uLZQLxiHpKM=;
        fh=Fs1sOAaQOPbP5efEURNnrhSou4nZqpCxjwRwxGHrvPk=;
        b=uaQTD5PWVirXWvHA999IA7Wi2vdimArz3qSdLvw4lsLtF06rA7Tpl9kjtvBwjlZO7u
         GSBMw6iJ/3+8YVUjZCMUfrzfJ7oZ41+XU3icOwHqWeADakQd8cnavyK7mZoJD7OCvxWG
         DxGhp7qg9Yro2aVUIzxp+eeqoAIhvu4HK5AG1nQPnW5j+fo4xKhmhhlwtU/uiGi8oIyA
         LzJQWLd7Fz/00ZVtLKhq5t1pfsZcL/7zopG96f9fFPRQJSJtg3RLL2w1sNsw4Bj7y9Tu
         UjuaZsC7SORx1DCwGAOjrJrLfJ4H5vsTTdvpmqG5CAETMJFIo2RpjDG3tZdVBXBUchwl
         wJfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="dd9X/0nj";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x630.google.com (mail-pl1-x630.google.com. [2607:f8b0:4864:20::630])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bd82f8400fsi3878576d6.8.2024.08.14.01.14.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:14:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::630 as permitted sender) client-ip=2607:f8b0:4864:20::630;
Received: by mail-pl1-x630.google.com with SMTP id d9443c01a7336-1fc566ac769so56903575ad.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:14:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUnl0saaznbZnQLCeIvNDOOcSe/Qe41fQMmWsoEoSZ32krIIdGUVxs2ie+CW6F6OOCHyWTuI6MxRTc=@googlegroups.com
X-Received: by 2002:a17:902:e5ce:b0:1fd:a769:fcaf with SMTP id d9443c01a7336-201d6592fcdmr22165255ad.61.1723623285971;
        Wed, 14 Aug 2024 01:14:45 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd147ec4sm24868335ad.85.2024.08.14.01.14.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:14:45 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Atish Patra <atishp@atishpatra.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v3 04/10] riscv: Add support for userspace pointer masking
Date: Wed, 14 Aug 2024 01:13:31 -0700
Message-ID: <20240814081437.956855-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814081437.956855-1-samuel.holland@sifive.com>
References: <20240814081437.956855-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="dd9X/0nj";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::630 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

RISC-V supports pointer masking with a variable number of tag bits
(which is called "PMLEN" in the specification) and which is configured
at the next higher privilege level.

Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
so userspace can request a lower bound on the number of tag bits and
determine the actual number of tag bits. As with arm64's
PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
thread-scoped, inherited on clone() and fork() and cleared on execve().

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v3:
 - Rename CONFIG_RISCV_ISA_POINTER_MASKING to CONFIG_RISCV_ISA_SUPM,
   since it only controls the userspace part of pointer masking
 - Use IS_ENABLED instead of #ifdef when possible
 - Use an enum for the supported PMLEN values
 - Simplify the logic in set_tagged_addr_ctrl()

Changes in v2:
 - Rebase on riscv/linux.git for-next
 - Add and use the envcfg_update_bits() helper function
 - Inline flush_tagged_addr_state()

 arch/riscv/Kconfig                 | 11 ++++
 arch/riscv/include/asm/processor.h |  8 +++
 arch/riscv/include/asm/switch_to.h | 11 ++++
 arch/riscv/kernel/process.c        | 90 ++++++++++++++++++++++++++++++
 include/uapi/linux/prctl.h         |  3 +
 5 files changed, 123 insertions(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 0f3cd7c3a436..817437157138 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -512,6 +512,17 @@ config RISCV_ISA_C
 
 	  If you don't know what to do here, say Y.
 
+config RISCV_ISA_SUPM
+	bool "Supm extension for userspace pointer masking"
+	depends on 64BIT
+	default y
+	help
+	  Add support for pointer masking in userspace (Supm) when the
+	  underlying hardware extension (Smnpm or Ssnpm) is detected at boot.
+
+	  If this option is disabled, userspace will be unable to use
+	  the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
+
 config RISCV_ISA_SVNAPOT
 	bool "Svnapot extension support for supervisor mode NAPOT pages"
 	depends on 64BIT && MMU
diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
index 586e4ab701c4..5c4d4fb97314 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -200,6 +200,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
 #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)	riscv_set_icache_flush_ctx(arg1, arg2)
 extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long per_thread);
 
+#ifdef CONFIG_RISCV_ISA_SUPM
+/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
+long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
+long get_tagged_addr_ctrl(struct task_struct *task);
+#define SET_TAGGED_ADDR_CTRL(arg)	set_tagged_addr_ctrl(current, arg)
+#define GET_TAGGED_ADDR_CTRL()		get_tagged_addr_ctrl(current)
+#endif
+
 #endif /* __ASSEMBLY__ */
 
 #endif /* _ASM_RISCV_PROCESSOR_H */
diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
index 9685cd85e57c..94e33216b2d9 100644
--- a/arch/riscv/include/asm/switch_to.h
+++ b/arch/riscv/include/asm/switch_to.h
@@ -70,6 +70,17 @@ static __always_inline bool has_fpu(void) { return false; }
 #define __switch_to_fpu(__prev, __next) do { } while (0)
 #endif
 
+static inline void envcfg_update_bits(struct task_struct *task,
+				      unsigned long mask, unsigned long val)
+{
+	unsigned long envcfg;
+
+	envcfg = (task->thread.envcfg & ~mask) | val;
+	task->thread.envcfg = envcfg;
+	if (task == current)
+		csr_write(CSR_ENVCFG, envcfg);
+}
+
 static inline void __switch_to_envcfg(struct task_struct *next)
 {
 	asm volatile (ALTERNATIVE("nop", "csrw " __stringify(CSR_ENVCFG) ", %0",
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index e4bc61c4e58a..1280a7c4a412 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -7,6 +7,7 @@
  * Copyright (C) 2017 SiFive
  */
 
+#include <linux/bitfield.h>
 #include <linux/cpu.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
@@ -171,6 +172,9 @@ void flush_thread(void)
 	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
 	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
 #endif
+	if (IS_ENABLED(CONFIG_RISCV_ISA_SUPM) &&
+	    riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
 }
 
 void arch_release_task_struct(struct task_struct *tsk)
@@ -233,3 +237,89 @@ void __init arch_task_cache_init(void)
 {
 	riscv_v_setup_ctx_cache();
 }
+
+#ifdef CONFIG_RISCV_ISA_SUPM
+enum {
+	PMLEN_0 = 0,
+	PMLEN_7 = 7,
+	PMLEN_16 = 16,
+};
+
+static bool have_user_pmlen_7;
+static bool have_user_pmlen_16;
+
+long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
+{
+	unsigned long valid_mask = PR_PMLEN_MASK;
+	struct thread_info *ti = task_thread_info(task);
+	unsigned long pmm;
+	u8 pmlen;
+
+	if (is_compat_thread(ti))
+		return -EINVAL;
+
+	if (arg & ~valid_mask)
+		return -EINVAL;
+
+	/*
+	 * Prefer the smallest PMLEN that satisfies the user's request,
+	 * in case choosing a larger PMLEN has a performance impact.
+	 */
+	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
+	if (pmlen == PMLEN_0)
+		pmm = ENVCFG_PMM_PMLEN_0;
+	else if (pmlen <= PMLEN_7 && have_user_pmlen_7)
+		pmm = ENVCFG_PMM_PMLEN_7;
+	else if (pmlen <= PMLEN_16 && have_user_pmlen_16)
+		pmm = ENVCFG_PMM_PMLEN_16;
+	else
+		return -EINVAL;
+
+	envcfg_update_bits(task, ENVCFG_PMM, pmm);
+
+	return 0;
+}
+
+long get_tagged_addr_ctrl(struct task_struct *task)
+{
+	struct thread_info *ti = task_thread_info(task);
+	long ret = 0;
+
+	if (is_compat_thread(ti))
+		return -EINVAL;
+
+	switch (task->thread.envcfg & ENVCFG_PMM) {
+	case ENVCFG_PMM_PMLEN_7:
+		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_7);
+		break;
+	case ENVCFG_PMM_PMLEN_16:
+		ret = FIELD_PREP(PR_PMLEN_MASK, PMLEN_16);
+		break;
+	}
+
+	return ret;
+}
+
+static bool try_to_set_pmm(unsigned long value)
+{
+	csr_set(CSR_ENVCFG, value);
+	return (csr_read_clear(CSR_ENVCFG, ENVCFG_PMM) & ENVCFG_PMM) == value;
+}
+
+static int __init tagged_addr_init(void)
+{
+	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+		return 0;
+
+	/*
+	 * envcfg.PMM is a WARL field. Detect which values are supported.
+	 * Assume the supported PMLEN values are the same on all harts.
+	 */
+	csr_clear(CSR_ENVCFG, ENVCFG_PMM);
+	have_user_pmlen_7 = try_to_set_pmm(ENVCFG_PMM_PMLEN_7);
+	have_user_pmlen_16 = try_to_set_pmm(ENVCFG_PMM_PMLEN_16);
+
+	return 0;
+}
+core_initcall(tagged_addr_init);
+#endif	/* CONFIG_RISCV_ISA_SUPM */
diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
index 35791791a879..6e84c827869b 100644
--- a/include/uapi/linux/prctl.h
+++ b/include/uapi/linux/prctl.h
@@ -244,6 +244,9 @@ struct prctl_mm_map {
 # define PR_MTE_TAG_MASK		(0xffffUL << PR_MTE_TAG_SHIFT)
 /* Unused; kept only for source compatibility */
 # define PR_MTE_TCF_SHIFT		1
+/* RISC-V pointer masking tag length */
+# define PR_PMLEN_SHIFT			24
+# define PR_PMLEN_MASK			(0x7fUL << PR_PMLEN_SHIFT)
 
 /* Control reclaim behavior when allocating memory */
 #define PR_SET_IO_FLUSHER		57
-- 
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814081437.956855-5-samuel.holland%40sifive.com.
