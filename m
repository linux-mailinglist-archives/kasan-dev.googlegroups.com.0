Return-Path: <kasan-dev+bncBCMIFTP47IJBBCURX63AMGQEEQQWTOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C584963730
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2024 03:02:03 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-39d52097234sf697355ab.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2024 18:02:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724893322; cv=pass;
        d=google.com; s=arc-20240605;
        b=hXEEbh0U1sZZQ9dAyOjmg/K4nm3iwyEzqgSBvw3Obg8ZSFQDEMqtwB3LFtMFizV+Mp
         EYv4eBlAaSo6lZ5th8C3zd/8iIjZRdzCVDOddAqGCbaLc+4NfJboLK5XHNI5vDbdCZ0d
         T/M3U/ZCV2b8XkHklualK75rxyjkhTy36ezvyfufWDkA2BnNIrnndFXbXptnBk9jJEH5
         cJt6XF7sfamJK8XHVpTwKInub+XGVpVW59QARQJRlwCbf0gWM0u+LW1hs4LU5wl5U6Xf
         8JtCf2eV4JRRESNes6BUQO+Ty2rJOpdD5TynnfnAzavg2RTHF7zfvpLM/yiyi5YKb0hx
         ctSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=z6n34ij1cKgEXf7lKiVP/g/Q7och63IZdHSjG62zB6U=;
        fh=9oAzPeQtYMGD8+90xmQmJSoLIxKiHzFsOCOluF6wNUE=;
        b=SzpCmeqTgq/mrFFQqu+uXSrLCOd3LkbQvjyt8F4Cy6UpyadeasxDRSpb8ASFvMeDyn
         6mRHFUx97Pkx/j5PW9iYEo37PoAXNye4N1vVl0fQr8gdCts2qJjNAe8JB751RXiHNJ5F
         NnJGHI+yV99a6hKC+hh89dUEykW1CJwSy5G0UFw4OIy3gqx84/SCf1SIX7QDg1tLkFr4
         Onpg+HtDXTSNV3G5z14hSN2zKfJFU+0NSSmEJGq9vYi2/N+pHSPNrEqtT4V2J4Atih3n
         ocJ2Gcv9wB7czglKBu+HVIWvMPMB/DD5/hydmlO4objuBFSsPrcJrIigllY4ijiLkzU1
         qtYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TzqEFm4t;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724893322; x=1725498122; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z6n34ij1cKgEXf7lKiVP/g/Q7och63IZdHSjG62zB6U=;
        b=ToxQyrOict3xDjjPJ0K6QDofPq3XH0vA9IN9hHj93d5n/0J3U/24dgN/YGLspd7xnw
         gGSkrnEmk6kr5SRzXODgo15Z3w7xcyy23/5R8ppozaJlib6eznzq+57GuZpPjCTWVLu5
         3EQ9BCku0BNjIn7uH1NUyukp+XU+GmGZvznnTkV50kaXU0ktXQjv4UI64dnMBYD4OE9K
         SdwSmnrdROC7N1kXDuzbmIvwOygpClZROv+SrfCbPVa2+fuBL5/2pSfLlH0Bs5YZoT0B
         tC8pgdxdslWPwtHW8Y30wD7sAI1hica+p7HlD0tE3q/SPxYkmkd2l4UBlE20xUhCFyua
         YcZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724893322; x=1725498122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=z6n34ij1cKgEXf7lKiVP/g/Q7och63IZdHSjG62zB6U=;
        b=p83KyDeBhjjhjl/8efumar2k0J0kDwGRBtl8hvf3Tr0D+6kk5MMtJlYHUHuWnJTxux
         9UZF9dwvqmsswTLdqN5ChjleNiNFponT6YxS9mDreiKnK2SIdgg6K+0S9SWxPneFV2GN
         T38ZWc1oeazUsD5udng1mR+GNwEL/rT96WEC/ozCyT7VgTr/jZnYnDEGrU1J17mtf+4S
         a7KqDMhDdz2kLDnIVR3krQk+bfuodSEdkPWEdzu9Fr6OPVojiLMlZDFBhV4YrGwyVra4
         hTlglT46wwpf/dufkG65lCYXJf6DroTn305yX+e7/vAWYZuefjlohZHGnVs27uiM3Nv0
         TFIQ==
X-Forwarded-Encrypted: i=2; AJvYcCWT2ZCaZwZninEpGXdNc+ax4M5v1J7Qmz5tyJMS+RRIP5uWo5wb81F6lzv+I52Vx9tNqFHR0A==@lfdr.de
X-Gm-Message-State: AOJu0YzBoGGYVouLFywXKS0Ang2xQBp7pAqZqWaBNSpjnXBG5mcKqdrt
	eOFDnHuFuJ6zBpU9QrLQ1wFLW1Ino7DmAFmrEE7LlZFgn/B9J9CD
X-Google-Smtp-Source: AGHT+IETQArTrNhabFtSqLO1/8OCgXWNJ4EzTeNfrJIooglTgsgX0qChTGgnFrEgajy29wgHgb0X1w==
X-Received: by 2002:a05:6e02:20e6:b0:39d:1ca5:3904 with SMTP id e9e14a558f8ab-39f3793205dmr14020085ab.14.1724893322290;
        Wed, 28 Aug 2024 18:02:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1547:b0:39d:28a3:8030 with SMTP id
 e9e14a558f8ab-39f377940afls3544475ab.0.-pod-prod-09-us; Wed, 28 Aug 2024
 18:02:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUzO11Nx61xMjM9S2ZjisU74Q2pRSEhhQ1nRUoKDhyiuDFRfckN3PEuGIKkWYzGMzgkDceozNpz0o4=@googlegroups.com
X-Received: by 2002:a05:6e02:13a6:b0:397:95c7:6f5d with SMTP id e9e14a558f8ab-39f379068bfmr17368845ab.11.1724893321219;
        Wed, 28 Aug 2024 18:02:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724893321; cv=none;
        d=google.com; s=arc-20240605;
        b=I1/ypqvP6oBCfsTHlSqOPgCjzGD5eUJ77LGzy+dn/39SVo8GcywQGuWnhxdq6fz6YB
         9ekzP9KWG6/mAISMuPWMV07OBj37YwXhspbSrwJ4FPxOsvVNSAN3Kt9Azp4eU4YdFNTJ
         2vROM/T66lIJvw5NMPQPH/4r7l13ZK2HpPu+8n1FbrT3Q1VYkr2pbSVj1H9+ReVSlBBr
         uFk4Y+k1hNtWya/n9qiDKAll3mA0amIrVKuOh37ZbyHNZDiThAwSp8za3RpQayDJfK7O
         IC6kFVDSDQEchYPTsRC+Xp7PmDTBxMhjkcvXa0C3AAMptkFcApBVJteZs0JKzp/awT8m
         ms7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=C3qDkoS5rxZK3Tpvbz7Odl2ZyEBU08AZZIxTPut6X68=;
        fh=7lmo58SuVCwc3uLkByluBn1oH+Bvl5ja4A1az4vEruc=;
        b=dfhcuSUU4MST2sfgncz9DaSvcBq3ndtBoDTNHowwS5uBozuKTVYZ6l3im3oeAUZwvs
         JZym0EJA5vZ6Z5Bvxq3nroN7cMQRC1xxy46vMF1XsqWBIIpq/nR7++oKNbasrf1jRls8
         CHAlMV74HWa4lHzBiU7xKvm/zk/G64pHuLrg/TrsOfIWecede7ipm3l1SgRgud2Qqh0A
         pBhXLlCGySnWrInYVfyD28nwU2amGaYI3MgLCFD9U2axRPkGwVRoPHJFiJka47eJNVJq
         OCnVlAMiGox3Alv9rjqmpHVqg7Pf9HI9MYZp7IklOanzpjNtkgGLtAdJj2qK3JS5KeKE
         JGyg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TzqEFm4t;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-39f3b195d6dsi12815ab.5.2024.08.28.18.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Aug 2024 18:02:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-71433cba1b7so85338b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Aug 2024 18:02:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUgf0HESNppKUGgVqoI5vvdmMf87Kdgo8O3PnidPIS1LETdrcmep41CCNBgTLgulvI87fKvznm7Vao=@googlegroups.com
X-Received: by 2002:a05:6a21:178a:b0:1cc:a104:c9f0 with SMTP id adf61e73a8af0-1cce102cfcemr1093597637.31.1724893320369;
        Wed, 28 Aug 2024 18:02:00 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-715e5576a4dsm89670b3a.17.2024.08.28.18.01.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 28 Aug 2024 18:01:59 -0700 (PDT)
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
Subject: [PATCH v4 04/10] riscv: Add support for userspace pointer masking
Date: Wed, 28 Aug 2024 18:01:26 -0700
Message-ID: <20240829010151.2813377-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240829010151.2813377-1-samuel.holland@sifive.com>
References: <20240829010151.2813377-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=TzqEFm4t;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Changes in v4:
 - Switch IS_ENABLED back to #ifdef to fix riscv32 build

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
 arch/riscv/kernel/process.c        | 91 ++++++++++++++++++++++++++++++
 include/uapi/linux/prctl.h         |  3 +
 5 files changed, 124 insertions(+)

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
index e4bc61c4e58a..f39221ab5ddd 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -7,6 +7,7 @@
  * Copyright (C) 2017 SiFive
  */
 
+#include <linux/bitfield.h>
 #include <linux/cpu.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
@@ -171,6 +172,10 @@ void flush_thread(void)
 	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
 	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
 #endif
+#ifdef CONFIG_RISCV_ISA_SUPM
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
+#endif
 }
 
 void arch_release_task_struct(struct task_struct *tsk)
@@ -233,3 +238,89 @@ void __init arch_task_cache_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240829010151.2813377-5-samuel.holland%40sifive.com.
