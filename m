Return-Path: <kasan-dev+bncBCMIFTP47IJBBPMV5CXQMGQESNZNQGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F8E3880701
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 22:59:27 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42f138874e7sf77591cf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 14:59:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710885566; cv=pass;
        d=google.com; s=arc-20160816;
        b=lFWEs4AuJXTOcV0UUM6FmZyH5IBxX7ae5+SfEjdk18h3TV/jzart0P2GmMHUMe0vnT
         uL71T6jDmd2q8JA0CcaL+cauqJrEgOovLFENiTYsdMWQc/ENn5Xv7S0IXkPeFB7iYa50
         lgRNLBncgMsXHsfc4yHaJZ0JG8PBWNyR9Y6gQfeQpmgKb+uFIjPQOdN0gqT8gId54k9c
         p3+YPw1ZJ9jCmpgIAT75Dk0hj6IQ3oFdd9HaWStnqVd45MRZVmpDAaIIg533XumFdcnF
         wp3deLo+7r7TpMsePPqw1efRlRiYqjDZ0Z81xuRMADplCRwhsDHrXcpJ/XyuhSGhfDVH
         WP7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=dDEkSAyTjx46vTH6idr8nJQzxbbnRUVBvnSNadJ3iwI=;
        fh=Cipjwyc6DLmq4+MKuuI99kyBDGbRxO7mi08z0j3Mvvw=;
        b=h2n2txxACQ7WydcCGwDgRwZEHs3kEhBM7lglU2PktLdlF1TnlSrlqUYnhGX+stxByg
         f+zXTkd3FNX2dJ9QCPIun3MGqpIYoVU1xBLrhMQaspt3r7TNbfD0fOWnBK3yTslHe3Wy
         Y61yY+0GT32YR3me2HbfhOomLYiPbJ0Ummv+rHcESNXGXCzfXMt0ienXSXG292I8RaKU
         Qckva0XcuvYoghYiqEYIqZvylpIb2MP1kqMqdkoeP59/ElRIXlvCc+oozQPmsvNUxDXn
         ut9KXYOpeMJGymf716Bz9kgFScPvlbQ1q7wnNJNLnUzkLY7BFmQKbFzj6Wxb+gme7QrO
         nTVA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=MDVSXtlS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710885566; x=1711490366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=dDEkSAyTjx46vTH6idr8nJQzxbbnRUVBvnSNadJ3iwI=;
        b=nvNNkrd6U2dBe3QYLe7TnlenxENOkL3INpbQQlEfXh54iVDovSAw4WblPjvUkDvhIH
         osPI+2DKDdIkdCipHwoNDYa9wjxY1ikGlRPSoFia8lY8IOdT6KOTX9+XmCnnBiiVGL9o
         njb//CMR2kEHZF6AKy9HqGTB8UUvyzVkBK/U2zsWNb0qU7GQq80A9niANjZcVqO/YO2u
         TvcxUfa9zrLj6YqpFapn4FJL60Maq7lfAGYuhE+VAhOqBoVy0Re5F3EH5G9kG4rYgR1f
         Q6yNi6NpIQ6JvqrqDMoAdnLGIujo4eZfXzJfl/O3RPyKW5Tq4PQiqQ3pHYVKsBapiH7c
         Wtbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710885566; x=1711490366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=dDEkSAyTjx46vTH6idr8nJQzxbbnRUVBvnSNadJ3iwI=;
        b=X8TDem+Sm4pLenRHvyqEbQU63lVBQ11qYfQT5WwO3T0Y4GnThGayW55GjFqO0bWcsL
         2Mb1ItMYDyA3uHrJ+Ri1ICi/iJ5nXc08N1ii4byhrAS2YEFBZV4/f0Dn7/wMGqAJnp1y
         sTLK4pMXQhPKkdK7dSDLg463qZbHgb90hrQDFSL1snUmsJsPvg3/PGzuMhTyN5Wmzyun
         fVycgHmNzqY2rn0Hc00V9DRgYKiEmk3+kffk2GijYPIrxi6C5vJ6NwjCC7eFJNtwjD3U
         VVLNv63JAyZCS+QEb0CdOxkWovIXm6pSoXN7mrYvMxio49kOYJDmiwFnCvyUms7A7qwu
         j22Q==
X-Forwarded-Encrypted: i=2; AJvYcCV5LwYnunAqFN8rARPQJZtO7ju+k0GRpSB2oJa9VHtJGH+04tdd0g+Jz7DrqZwDXWPIQpMsmkrkqOnQZlVVGTAyeDvmrj0kHw==
X-Gm-Message-State: AOJu0Yzx4NbqgZ0HRuW/WavsSZfGvINsyLwWkFXTNyF+UKT65But3Gkv
	cqq9jFgD79dePEnT9OgHR0VYecXJ3j88JxdLZ0E7tDfkocaO7ALM
X-Google-Smtp-Source: AGHT+IG5eMiaMPqTSDTGmn7zUz1MZflhHjWCZVwz18TNFf6ptZsTrVDteLjXu8461MdBn1FutIjNSQ==
X-Received: by 2002:ac8:7dcc:0:b0:430:ad98:cc44 with SMTP id c12-20020ac87dcc000000b00430ad98cc44mr124679qte.12.1710885566028;
        Tue, 19 Mar 2024 14:59:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5e4e:0:b0:42e:f7cd:b912 with SMTP id i14-20020ac85e4e000000b0042ef7cdb912ls1843404qtx.0.-pod-prod-08-us;
 Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUyZiPa8S8q8wCO5KLKFbGEQ5xz4azUzIMe1LS5N7jQDEwc0TI+Dj7GabfO7jOoTcBAbwXZdeO9FiGw4hA4h5GQP1hLHWXEcwxh5Q==
X-Received: by 2002:a05:620a:211a:b0:789:e842:a04e with SMTP id l26-20020a05620a211a00b00789e842a04emr4218933qkl.39.1710885565307;
        Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710885565; cv=none;
        d=google.com; s=arc-20160816;
        b=sbzNkg4kjYDUq8Ju3DUEGVvfBwZetV2kTMjx5omMVftL2Aj0hooGu0Rk0jllGkohgv
         U0Jb1oFL8x80Ayn+RdnH8NC+/fSnNshNDoU+Ao13BV9qtVmJTRZhy0fCTxnz/jMRVvfI
         ogzcKVSquBqte6XaZc9NQCum1zYuyuiMWEAU2FMB5mCQM6ZhN7iX+3ZLCmfNXJXW0upb
         dTOG46S1dFcmWJjPgLQs24/c20WhE+u+fP+NmPWkO/qbTUvT20k3c/wR1K/E/VGfuMfZ
         diu4tvw7ZDG4S3q4xsNVG2c5fqmTp9LeaQ9vQoNuHm/k68lpZsgk1f9gVTPdl379GtpB
         t6CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=L9YnfDFlIzM6IgPNouej5vSECO3AYIq38694OD5b58U=;
        fh=/ABaD4FzEk4Tqjmg5KsJCmoyrJm7uZohNnLzcq17Ymw=;
        b=oZMIDHTQfVCF5apHt9DH36HRHuT5zum0ZYatRbRlO8vFb4lmNj+NOjvvTiok43zmlL
         MF+LemC6uNFjKcphEZf5yqCnWkr1ec3ySVPxsrr0x5Hlre3DlsebSERh2StigWqgDVIn
         gK/Xo9DSbT4gzNJDqMP8zckvZvHvEBfGefWOm/ZHpnqJBP61otQSSMJ4kggPPBE9EqmO
         6ews0bc4Tv5QuRzYZS8NH38unyG4XPvWb0lHtIYOI2gPbq1OwcPiZ0PNBxdruMWAafFX
         LIeG6P5V1ZB0TPXJPP4kZq/tRA2PFU12hI42T2w2ufZfHD+D3rikm/OmxSZsFYniLDSi
         F3zA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=MDVSXtlS;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pg1-x532.google.com (mail-pg1-x532.google.com. [2607:f8b0:4864:20::532])
        by gmr-mx.google.com with ESMTPS id qz21-20020a05620a8c1500b00789e8ea597csi754704qkn.3.2024.03.19.14.59.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::532 as permitted sender) client-ip=2607:f8b0:4864:20::532;
Received: by mail-pg1-x532.google.com with SMTP id 41be03b00d2f7-5d3907ff128so4647236a12.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 14:59:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVSSP8v+9oBtrHoTsDTi0l6HcJBb6LV/3ycz0JxeEe1QCZTHg+ZbsnXDoq8SG7g9dGy8ZmmG+pn4vpiwoqcZSxJt14YW3VvEtkV8A==
X-Received: by 2002:a05:6a21:350d:b0:1a3:7efc:81f4 with SMTP id zc13-20020a056a21350d00b001a37efc81f4mr1954693pzb.16.1710885564420;
        Tue, 19 Mar 2024 14:59:24 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id z25-20020aa785d9000000b006e6c61b264bsm10273892pfn.32.2024.03.19.14.59.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Mar 2024 14:59:24 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: devicetree@vger.kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	tech-j-ext@lists.risc-v.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Rob Herring <robh+dt@kernel.org>,
	Samuel Holland <samuel.holland@sifive.com>,
	Guo Ren <guoren@kernel.org>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Stefan Roesch <shr@devkernel.io>
Subject: [RFC PATCH 6/9] riscv: Add support for userspace pointer masking
Date: Tue, 19 Mar 2024 14:58:32 -0700
Message-ID: <20240319215915.832127-7-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.43.1
In-Reply-To: <20240319215915.832127-1-samuel.holland@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=MDVSXtlS;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::532 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
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
("PMLEN") and which is configured at the next higher privilege level.

Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
so userspace can request a minimum number of tag bits and determine the
actual number of tag bits. As with PR_TAGGED_ADDR_ENABLE, the pointer
masking configuration is thread-scoped, inherited on clone() and fork()
and cleared on exec().

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/riscv/Kconfig                 |   8 +++
 arch/riscv/include/asm/processor.h |   8 +++
 arch/riscv/kernel/process.c        | 107 +++++++++++++++++++++++++++++
 include/uapi/linux/prctl.h         |   3 +
 4 files changed, 126 insertions(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index e3142ce531a0..a1a1585120f0 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -479,6 +479,14 @@ config RISCV_ISA_C
 
 	  If you don't know what to do here, say Y.
 
+config RISCV_ISA_POINTER_MASKING
+	bool "Smmpm, Smnpm, and Ssnpm extensions for pointer masking"
+	depends on 64BIT
+	default y
+	help
+	  Add support to dynamically detect the presence of the Smmpm, Smnpm,
+	  and Ssnpm extensions (pointer masking) and enable their usage.
+
 config RISCV_ISA_SVNAPOT
 	bool "Svnapot extension support for supervisor mode NAPOT pages"
 	depends on 64BIT && MMU
diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
index 06b87402a4d8..64b34e839802 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -185,6 +185,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
 #define GET_UNALIGN_CTL(tsk, addr)	get_unalign_ctl((tsk), (addr))
 #define SET_UNALIGN_CTL(tsk, val)	set_unalign_ctl((tsk), (val))
 
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+/* PR_{SET,GET}_TAGGED_ADDR_CTRL prctl */
+long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg);
+long get_tagged_addr_ctrl(struct task_struct *task);
+#define SET_TAGGED_ADDR_CTRL(arg)	set_tagged_addr_ctrl(current, arg)
+#define GET_TAGGED_ADDR_CTRL()		get_tagged_addr_ctrl(current)
+#endif
+
 #endif /* __ASSEMBLY__ */
 
 #endif /* _ASM_RISCV_PROCESSOR_H */
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index 92922dbd5b5c..3578e75f4aa4 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -7,6 +7,7 @@
  * Copyright (C) 2017 SiFive
  */
 
+#include <linux/bitfield.h>
 #include <linux/cpu.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
@@ -154,6 +155,18 @@ void start_thread(struct pt_regs *regs, unsigned long pc,
 #endif
 }
 
+static void flush_tagged_addr_state(void)
+{
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SxNPM))
+		return;
+
+	current->thread.envcfg &= ~ENVCFG_PMM;
+
+	sync_envcfg(current);
+#endif
+}
+
 void flush_thread(void)
 {
 #ifdef CONFIG_FPU
@@ -173,6 +186,7 @@ void flush_thread(void)
 	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
 	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
 #endif
+	flush_tagged_addr_state();
 }
 
 void arch_release_task_struct(struct task_struct *tsk)
@@ -236,3 +250,96 @@ void __init arch_task_cache_init(void)
 {
 	riscv_v_setup_ctx_cache();
 }
+
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+static bool have_user_pmlen_7;
+static bool have_user_pmlen_16;
+
+long set_tagged_addr_ctrl(struct task_struct *task, unsigned long arg)
+{
+	unsigned long valid_mask = PR_PMLEN_MASK;
+	struct thread_info *ti = task_thread_info(task);
+	u8 pmlen;
+
+	if (is_compat_thread(ti))
+		return -EINVAL;
+
+	if (arg & ~valid_mask)
+		return -EINVAL;
+
+	pmlen = FIELD_GET(PR_PMLEN_MASK, arg);
+	if (pmlen > 16) {
+		return -EINVAL;
+	} else if (pmlen > 7) {
+		if (have_user_pmlen_16)
+			pmlen = 16;
+		else
+			return -EINVAL;
+	} else if (pmlen > 0) {
+		/*
+		 * Prefer the smallest PMLEN that satisfies the user's request,
+		 * in case choosing a larger PMLEN has a performance impact.
+		 */
+		if (have_user_pmlen_7)
+			pmlen = 7;
+		else if (have_user_pmlen_16)
+			pmlen = 16;
+		else
+			return -EINVAL;
+	}
+
+	task->thread.envcfg &= ~ENVCFG_PMM;
+	if (pmlen == 7)
+		task->thread.envcfg |= ENVCFG_PMM_PMLEN_7;
+	else if (pmlen == 16)
+		task->thread.envcfg |= ENVCFG_PMM_PMLEN_16;
+
+	if (task == current)
+		sync_envcfg(current);
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
+		ret |= FIELD_PREP(PR_PMLEN_MASK, 7);
+		break;
+	case ENVCFG_PMM_PMLEN_16:
+		ret |= FIELD_PREP(PR_PMLEN_MASK, 16);
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
+	if (!riscv_has_extension_unlikely(RISCV_ISA_EXT_SxNPM))
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
+#endif	/* CONFIG_RISCV_ISA_POINTER_MASKING */
diff --git a/include/uapi/linux/prctl.h b/include/uapi/linux/prctl.h
index 370ed14b1ae0..488b0d8e8495 100644
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
2.43.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240319215915.832127-7-samuel.holland%40sifive.com.
