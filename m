Return-Path: <kasan-dev+bncBCMIFTP47IJBBGHE5SZQMGQESSHTWFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id C89839172F5
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 23:09:45 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-5c19ee51349sf9195198eaf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jun 2024 14:09:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719349784; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQO52PkctnvR7smuu0PQUuVyjw2AL//RscVXCJJbW6n9E2RZtPF+dwu1wVpa/O7UJa
         8ZYkVrbxj5VPFuMoLxJvN7xm8ovshEa129rhzoInuHS8YqfY2BKwqYLBJ7nmupx7d+mq
         WlgvFCQ4oVRuyIR5K9l8aosgGRrYsaNpr9KxMhNUXyPtlJ/N4evWQoTwKeM4iiBqunTW
         MLk+YRkC+HP5mr00mj97BVTMskO0zpCeRJjczDDb0ywg+K9vrxigZzn82KkNqb1povbx
         4EQPdd9K61uKPCKQoKvYrIl68YRLrmRl5gOEysPIoTBGh/ia/aWoM5MSaL2bk7EiR9Xm
         jhVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=M9+pLTBTdFZQKnsda9EGKlRNhCE1B/t0g94tPz0VzHM=;
        fh=SP7vOd6mS4HsX9UfEybakTSqT4B3MGV4JBnHFaIb3W0=;
        b=CJ6Hw4fPT4SA2fLs8GEvlMpIYnNgnOjGm3QE5r9nI/HPIrZh60bR6Q8vRV5teMItji
         SrbpYxxRgPp9XCLquUyMiX2aqA0kUQZMZEfZ0q9zl42iBPAlET02TqeDgalPre/pFe2n
         EXPZWmotqmWNKsGORhpM/rsW+SX9AKCgS3jpwwOX6dsIBWALd1DGmZjL2t4n0HhDupev
         2jig9eO7j2dtIqYiSOgPNmbyHwZs/OUrhblREl9+E9x/6EehgPkA13NYKoeXnFoYDr0C
         30tpspl5aGuMgyC3W7X0voOD47bB5Fd6xgzI62cofacB1VxosNPrmLu9d6yVEejV+AUP
         BXAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=l1uKzMi0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719349784; x=1719954584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=M9+pLTBTdFZQKnsda9EGKlRNhCE1B/t0g94tPz0VzHM=;
        b=Q4dcJE4LjlbxSHhra5hF9GbIlVDT7zlWhvqbSDQyk5evqfD9miao9osYGGI0ZnvlWk
         cH5Xkyn+iBH1waTvFXnExHhAXmBqCFfb50ooM+5PzHKU/vuH9TxFW9xBvUtBCBTCF7Il
         uNgYPA9NKHggDx3qXmPxzOd8E1wK8OMtuF30mnThHjXkJntmWxKI4Ucp/QHduCV4CCtN
         3mLU6C8rRSUsGTVTh2GYuZcPsOMFjYAyIJuJI3eleMe50EUCU/BFS0ymSkzsy1F9ihRR
         NexMTcYctO7d5wCGIFI6Awl9U3SbOxDCoIrfUWLnVflu10KiqBdZcrnemMI7xJppmCGz
         k68Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719349784; x=1719954584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=M9+pLTBTdFZQKnsda9EGKlRNhCE1B/t0g94tPz0VzHM=;
        b=NQMbA6++4wHSkJV9693DNTaL7wAlUPu+bMaq7zpoxCYIVmhG3Rb7W9J6+6lJWu1ogX
         swAWtW0WX1KIzRsLM9C+AVI+FaH2yPIyNWpNj1x4QUY4HIt+n0adcqNyM9HSZKKUlBOM
         XdsT82IaWs2DgLxw44gGISssYyKzfU6pBKQ+yzWv0Hu0yie2SK+dj1YWkjfJ+naXNI1L
         uq6iQ3SsgeVc9q4CnyfcYQ175A5NpvKBQ9rvvBmYCm1n5yKjYW9cKNTTY8P8IxNTco9d
         3Vs7Zz7SaCHFN9LusaIvCRyaogZDjC9e257A/+YmRe0aTHOJWN/lpiUArZVN9KPVeFao
         GWew==
X-Forwarded-Encrypted: i=2; AJvYcCVjmDQCfPppCSv3hQ2I6Hr1nOiDP6QpkwlM3V0fPLTLi1gMYtIwY4fqYL6kTE+4yzlea6COYhvdirAUXhOpc5P2YeZCrMkK4g==
X-Gm-Message-State: AOJu0YyyOHniuQFD/np9wVY/V8YJEUxZD+lmF9IBjragtg/HgFODkSrj
	QAnHM3uiJg+6LsU8z19gKxpI6QWLKswHcOEgehexSAAbn6GGumTG
X-Google-Smtp-Source: AGHT+IGG7XernBGXrXhO3JX/WGIw9T4i8PSr9QzA8prUFspW7PmIK14/3gv/2nSxpS0Z8DS3WMkK8A==
X-Received: by 2002:a4a:d096:0:b0:5c2:1885:f770 with SMTP id 006d021491bc7-5c21885f82amr2156807eaf.8.1719349784501;
        Tue, 25 Jun 2024 14:09:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:6c11:0:b0:5bb:19da:9170 with SMTP id 006d021491bc7-5c1bff41bd5ls5390225eaf.2.-pod-prod-07-us;
 Tue, 25 Jun 2024 14:09:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWNnodQHf5+oYr1ubA7DwPq1R7aVrKk/Q7PLys2Ab80musktm14hKDnlhcE5v9r/NYzJq6kgKlTNX7o3vNdQhJUCFm0EZqXCbG3jQ==
X-Received: by 2002:a05:6830:10ce:b0:6f9:5bfc:81f0 with SMTP id 46e09a7af769-700b12a87b2mr8212030a34.31.1719349783703;
        Tue, 25 Jun 2024 14:09:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719349783; cv=none;
        d=google.com; s=arc-20160816;
        b=R1nzX19Vp3ZM1yk8qVSenuVfPW9xCEJJ3gjhYoout/XrMLgAbEBeMQzEhhM2CCjmCQ
         3uADX3MSfpdvER7mRNGZ5SEsAXfY/6atP8IcfMFU75htS2Gxhvv+hkzVVzv/efEGPBKt
         04sW1XDQq/XAmL5lD6kI3eYanVbrwsRB5sb78JZ7zLDZmUz/P5i/LIQWxrVPXQPzqXq8
         OGomfvdA37mmCexiYBP4ODHTh9zEDj7xTYjNoR8zA0IC2DDLkG92l16vCJipxV/ca7EJ
         ga3aKkrk2MkDHxIO9YLwvijbNdCXr6EyrlMy1xeFYKu+iKKc0AJWbqmMRjiawiVNhOau
         oUKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9RHKmejM9a0vevYfMOXCLHoYWj48ZdPOlbThmmBhK0Q=;
        fh=0VgBNyLRrdmKpfQ4Qh5/QIgtQL4Iw9xPbrhpn9hWavw=;
        b=CZcvw2JUBsH3Gn0wJhZvQn1eAE8ccNESmUwUwVebT+q7Y7mXi5YVnmuvJluzgWttaA
         zjMzW9HT0HJiIPP4kdS9on0Q80klUEiPaTgAyIzM3+EtzoJ4L4tdH/BpdrE88uAcWvBJ
         vpOWB9tFMFX+2i0IJ1YnLIrOY/LZNocjQCEtEfzd+wlvV270v2l2F+OT55jw1KJ4yzna
         ZkWC+ODBa6ZVWwsPVTDdJYjKwZVufbRrBDQpoFQdlGui8LxoURCKNF0UMjwRdZ0K+mkJ
         Y5tcoEX9bptOYPSayJKyrdk47G6uhjPJjWxd11BObQa6OyzsGkr5ju9SsXHEXaM6LY7m
         M6sw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=l1uKzMi0;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-700cce04b6esi43932a34.4.2024.06.25.14.09.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Jun 2024 14:09:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1f480624d0fso47410935ad.1
        for <kasan-dev@googlegroups.com>; Tue, 25 Jun 2024 14:09:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWfRReCuDxeAh8xO0Ssb62Vmmfb/axuSmgdU6HnOA6XUSOCDu42aie+W9VVCNoq/dE4HVff7uKzs2E9rV0XnyZddZKWD17h5pupNQ==
X-Received: by 2002:a17:902:c943:b0:1fa:2210:4562 with SMTP id d9443c01a7336-1fa23fd8a00mr103679455ad.29.1719349782852;
        Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1f9eb328f57sm85873455ad.110.2024.06.25.14.09.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Jun 2024 14:09:42 -0700 (PDT)
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
Subject: [PATCH v2 04/10] riscv: Add support for userspace pointer masking
Date: Tue, 25 Jun 2024 14:09:15 -0700
Message-ID: <20240625210933.1620802-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.44.1
In-Reply-To: <20240625210933.1620802-1-samuel.holland@sifive.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=l1uKzMi0;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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
(which is called "PMLEN" in the specification) and which is configured
at the next higher privilege level.

Wire up the PR_SET_TAGGED_ADDR_CTRL and PR_GET_TAGGED_ADDR_CTRL prctls
so userspace can request a lower bound on the  number of tag bits and
determine the actual number of tag bits. As with arm64's
PR_TAGGED_ADDR_ENABLE, the pointer masking configuration is
thread-scoped, inherited on clone() and fork() and cleared on execve().

Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v2:
 - Rebase on riscv/linux.git for-next
 - Add and use the envcfg_update_bits() helper function
 - Inline flush_tagged_addr_state()

 arch/riscv/Kconfig                 | 11 ++++
 arch/riscv/include/asm/processor.h |  8 +++
 arch/riscv/include/asm/switch_to.h | 11 ++++
 arch/riscv/kernel/process.c        | 99 ++++++++++++++++++++++++++++++
 include/uapi/linux/prctl.h         |  3 +
 5 files changed, 132 insertions(+)

diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index b94176e25be1..8f9980f81ea5 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -505,6 +505,17 @@ config RISCV_ISA_C
 
 	  If you don't know what to do here, say Y.
 
+config RISCV_ISA_POINTER_MASKING
+	bool "Smmpm, Smnpm, and Ssnpm extensions for pointer masking"
+	depends on 64BIT
+	default y
+	help
+	  Add support for the pointer masking extensions (Smmpm, Smnpm,
+	  and Ssnpm) when they are detected at boot.
+
+	  If this option is disabled, userspace will be unable to use
+	  the prctl(PR_{SET,GET}_TAGGED_ADDR_CTRL) API.
+
 config RISCV_ISA_SVNAPOT
 	bool "Svnapot extension support for supervisor mode NAPOT pages"
 	depends on 64BIT && MMU
diff --git a/arch/riscv/include/asm/processor.h b/arch/riscv/include/asm/processor.h
index 0838922bd1c8..4f99c85d29ae 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -194,6 +194,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
 #define RISCV_SET_ICACHE_FLUSH_CTX(arg1, arg2)	riscv_set_icache_flush_ctx(arg1, arg2)
 extern int riscv_set_icache_flush_ctx(unsigned long ctx, unsigned long per_thread);
 
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
index e4bc61c4e58a..dec5ccc44697 100644
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
+#ifdef CONFIG_RISCV_ISA_POINTER_MASKING
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
+#endif
 }
 
 void arch_release_task_struct(struct task_struct *tsk)
@@ -233,3 +238,97 @@ void __init arch_task_cache_init(void)
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
+	unsigned long pmm;
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
+	if (pmlen == 7)
+		pmm = ENVCFG_PMM_PMLEN_7;
+	else if (pmlen == 16)
+		pmm = ENVCFG_PMM_PMLEN_16;
+	else
+		pmm = ENVCFG_PMM_PMLEN_0;
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
+#endif	/* CONFIG_RISCV_ISA_POINTER_MASKING */
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
2.44.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240625210933.1620802-5-samuel.holland%40sifive.com.
