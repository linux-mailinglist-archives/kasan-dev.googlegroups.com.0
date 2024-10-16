Return-Path: <kasan-dev+bncBCMIFTP47IJBB2ODYC4AMGQECOS2UPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 55F339A13C6
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 22:28:27 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-7b11467e528sf31355985a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 13:28:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729110506; cv=pass;
        d=google.com; s=arc-20240605;
        b=YUwAmnZETQ4WHcw+qftV/lJWaL4ezS7EtM+zGTGIeRSzZEDKcbwG1X0bVcIFwD2q/K
         DzI1Ns5BzP2c2XwpNIqQ9xktPfjoXeD6h0Sdf6iUqeOWYd/C/FZUfk/hFoGo/YOZeiDz
         5bn+YTlH+Nlf/VUozzQQlkonnP/SJcZIN8FksSAiW7kP6ZiMRasdXQgm0IK21CxtrDin
         5tzNH4sB2sQQ3by547RG7AJy4Pzy5DDqApixwWYcsnhh/keTcuoWKTgqVicMEEMgjPzA
         pruRqcwnyOWOljV1yqRg2lY4/HxHn8ysl91yZGrvF7w4AYh0ok/DJyZNT3z2mkJgDsPR
         459g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=To8w3S0QNHORhFwdeIROket3O7wS+KYXRP5rSkSYIFc=;
        fh=EzNFAL22lfsAfi4HVdo6kvEuXI83PCEt6vJee5yNeKc=;
        b=GrCD+lVX1th/AQROdJUhg3PgdivNbB86oD3yJvW5DArTzp3k47pYZW6wXAo2AaT+EG
         Othc+AbWoqYiMbRQDftq02xpVvyLoU/5VKByy0EJYtqjuuNgW94jHqn+/VkJE+sTnYuZ
         pgk9zBh2vGyt4Qc+GoOXfX5ux/cEifW3w1iHw415wocUgvRXB1st/dinRu+rThj4gx3D
         7Y7kRuCSjiDkFyO/sO0ms1XKNV/HHyE1XUBC3KBG1rvzzld64lB+T+vZ0ICjEMgew+FX
         F63ldz3I90xkst12q7z/ej/LYaMZ9YsSXQvXM18GYxInoR3/PF/WOHeGPnUVVKHHcuMw
         nOGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=E8duDTSQ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729110506; x=1729715306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=To8w3S0QNHORhFwdeIROket3O7wS+KYXRP5rSkSYIFc=;
        b=OvCq+TFnmiDTuiytUdLpMUpipZhczLJZA0MIU2RqlBkyX88Qa7rb+E+SrHSLhfed76
         eZhq0+KzTArt/weqx+I5C8R6T8XfFzZjXDPwgXwOSPvEp7GwAghYwIQRrqiEibWZEPh9
         nREMSFoYK/2TDppG8CZZG9foBIvi+U1xQ4mLDNgAvYRANGaCPN9topM+93+ogfwRvl0J
         EqVEj1Tqe157rKwfHTdNB905eFh3w7Hnt29qzQYUzEfxvGfje5WXXL2JmBPAMkpBhp+F
         uBhWmtEZ5EFEXa+zbSv0o7rQX4ro2/zs8k2DC6+eU73TOm3I0jTN5JJkdeE/1PaBH6ea
         wVvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729110506; x=1729715306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=To8w3S0QNHORhFwdeIROket3O7wS+KYXRP5rSkSYIFc=;
        b=hfMpgo4x2iT8dRhyfsZAVlTfuRDegOLK1AxwpS762rSs8V5TS1jWUkYWylEWCPl7Vz
         OFt+bz714/TLC3W7sdEc9TpkeQOYymdixLqhYlfc1Fb28+LiEn1TtkCY1V/FoYACoW/4
         ZFzSze8QW7Yk/WOY6QF5ahElM06ie5deb+MJg9gnSY96e6uLGig6ZI7zoYABi/idvoqU
         L5vza1g8LXJHzwKBM+n/iSaaQWn3z29KRqj1722GGsXQyBeGkhk0KF0ONsBs8i68NB0c
         sahgWZoCKNCu5m6MkAmihIjzeCVX/9DjAks7PySzB7peLAwaFXJ3rQj3KF5PvRDbtYjX
         o5Zg==
X-Forwarded-Encrypted: i=2; AJvYcCUSoZ44peyoQjHMrUlPW4++Y1F9+y7+EDQ50pc0HLUrpenCzyCrsEZdiQzfc/GzMDnqeRr2gQ==@lfdr.de
X-Gm-Message-State: AOJu0YyTvewLAcw61LwNLbN5mt7+4H1H2R/qtdmPluX0IChyAlDTryeo
	BOfUnfG6z96JqLvkjCehHDdJipi9MZ2RlQvmFRYkgZZTOo5xjLug
X-Google-Smtp-Source: AGHT+IFzBKT5xw3IdU18CDWcNmXL2eFO88Ym+ALFAeCDqvPYYVMgcNkVz/2kXDy5psh+uIGfPvj4AA==
X-Received: by 2002:a05:6214:428a:b0:6cb:ee7b:7ac4 with SMTP id 6a1803df08f44-6cc2b8bc9d5mr72405766d6.3.1729110506026;
        Wed, 16 Oct 2024 13:28:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:260c:b0:6b7:96a6:c5e7 with SMTP id
 6a1803df08f44-6cc36f692f8ls4177066d6.0.-pod-prod-08-us; Wed, 16 Oct 2024
 13:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPWqrWda0YQBwDCrXLfc7b7sBmBnJWf9Rlm3YZwPm5BjqqDaKeDcoW52mwUgXyDTdPl9hjpvJHboM=@googlegroups.com
X-Received: by 2002:a05:6214:3d99:b0:6cb:2ab7:56df with SMTP id 6a1803df08f44-6cc2b91f490mr89137046d6.49.1729110505381;
        Wed, 16 Oct 2024 13:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729110505; cv=none;
        d=google.com; s=arc-20240605;
        b=KA2QgT05zO40shcy/DDCtVYxE3xOcKzzh9b1KKT4bHYwQIub1lEr45Kt8Q3ebumFES
         KVEhcdJPHAkKInTfMtAE+fxSpOxzNI7xeMlaI+T5rbaoc1GfjSm6GedPV6A+ylf7pp0T
         1s4odIrSe+JnYUX4ge4WECsb6a7kBxNDA3QIy/gsb++xlIzDZTP5uKbxtM4FnlRN6LRh
         iuc3Qw2QUPJtZLKih+K4vMMnEVrmpl3yln0cVdiJA91DcZc6y1htd72SwTmBokPiHolL
         +joyu7auf5Hdh0aLaUk1etYM41x9rSPKHybmwhEdH2ytsNwFr6t2TMHCBwM+ubMaAkLz
         HLcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eo/JV88hOL+S2Nr/0pjLrqapJLfVH6+MO5UxiP8a69U=;
        fh=BS2QsrF+SS4QaLOKwK+1V38oRy1VDi9dwUU4Q/n7Bvc=;
        b=Q8qRTulI2lckzIsIcA/InJJ/KL56jfFi/InljrF7AfphCsTUYlPTi1X/k/cSWWSnUf
         0yuhb5xIAqD8lttflOZsXPG4S+9bMaIAQghTa+pcXi1hqX2YIu2J4n+mZUczV3hL1e41
         io5cy4uz4Ew9W5G7WY4TF7X7QlE1IwchssPb+/Kgt3IruX6NWOhmYb3ai3JXrIkPD79U
         qTZAodqk3KkP5DUXqZrnABeZlbUeND33pZz5Ds2aSj94t7/NJRqYat6OOgDRx4nHFfW8
         77+HWlymxIx5HUvzDnI4Myk5C/56fNsvXsAIfAlPOokfxMxg7eiqLgkIxyK6I3wHM+45
         9d4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=E8duDTSQ;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cc229e4b18si1913566d6.3.2024.10.16.13.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2024 13:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2e34a089cd3so173253a91.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 13:28:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKx5osF2GjivOW4K7RtAKCq30gEgcj52RNlY8SYbIQwnFcSmRN94LI7Itln7zWo2nGaueFro7foQg=@googlegroups.com
X-Received: by 2002:a17:90b:881:b0:2e2:a097:bb02 with SMTP id 98e67ed59e1d1-2e3ab7f85a6mr6439669a91.11.1729110504350;
        Wed, 16 Oct 2024 13:28:24 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e3e08f8f89sm228613a91.38.2024.10.16.13.28.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 13:28:23 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Atish Patra <atishp@atishpatra.org>,
	linux-kselftest@vger.kernel.org,
	Rob Herring <robh+dt@kernel.org>,
	"Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>,
	Shuah Khan <shuah@kernel.org>,
	devicetree@vger.kernel.org,
	Anup Patel <anup@brainfault.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	kvm-riscv@lists.infradead.org,
	Conor Dooley <conor@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	Evgenii Stepanov <eugenis@google.com>,
	Charlie Jenkins <charlie@rivosinc.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v5 04/10] riscv: Add support for userspace pointer masking
Date: Wed, 16 Oct 2024 13:27:45 -0700
Message-ID: <20241016202814.4061541-5-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241016202814.4061541-1-samuel.holland@sifive.com>
References: <20241016202814.4061541-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=E8duDTSQ;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Reviewed-by: Charlie Jenkins <charlie@rivosinc.com>
Tested-by: Charlie Jenkins <charlie@rivosinc.com>
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

Changes in v5:
 - Document how PR_[SG]ET_TAGGED_ADDR_CTRL are used on RISC-V

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

 Documentation/arch/riscv/uabi.rst  | 12 ++++
 arch/riscv/Kconfig                 | 11 ++++
 arch/riscv/include/asm/processor.h |  8 +++
 arch/riscv/include/asm/switch_to.h | 11 ++++
 arch/riscv/kernel/process.c        | 91 ++++++++++++++++++++++++++++++
 include/uapi/linux/prctl.h         |  5 +-
 6 files changed, 137 insertions(+), 1 deletion(-)

diff --git a/Documentation/arch/riscv/uabi.rst b/Documentation/arch/riscv/uabi.rst
index 2b420bab0527..ddb8359a46ed 100644
--- a/Documentation/arch/riscv/uabi.rst
+++ b/Documentation/arch/riscv/uabi.rst
@@ -68,3 +68,15 @@ Misaligned accesses
 Misaligned scalar accesses are supported in userspace, but they may perform
 poorly.  Misaligned vector accesses are only supported if the Zicclsm extension
 is supported.
+
+Pointer masking
+---------------
+
+Support for pointer masking in userspace (the Supm extension) is provided via
+the ``PR_SET_TAGGED_ADDR_CTRL`` and ``PR_GET_TAGGED_ADDR_CTRL`` ``prctl()``
+operations. Pointer masking is disabled by default. To enable it, userspace
+must call ``PR_SET_TAGGED_ADDR_CTRL`` with the ``PR_PMLEN`` field set to the
+number of mask/tag bits needed by the application. ``PR_PMLEN`` is interpreted
+as a lower bound; if the kernel is unable to satisfy the request, the
+``PR_SET_TAGGED_ADDR_CTRL`` operation will fail. The actual number of tag bits
+is returned in ``PR_PMLEN`` by the ``PR_GET_TAGGED_ADDR_CTRL`` operation.
diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
index 22dc5ea4196c..0ef449465378 100644
--- a/arch/riscv/Kconfig
+++ b/arch/riscv/Kconfig
@@ -531,6 +531,17 @@ config RISCV_ISA_C
 
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
index c1a492508835..5f56eb9d114a 100644
--- a/arch/riscv/include/asm/processor.h
+++ b/arch/riscv/include/asm/processor.h
@@ -178,6 +178,14 @@ extern int set_unalign_ctl(struct task_struct *tsk, unsigned int val);
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
index e3142d8a6e28..200d2ed64dfe 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -7,6 +7,7 @@
  * Copyright (C) 2017 SiFive
  */
 
+#include <linux/bitfield.h>
 #include <linux/cpu.h>
 #include <linux/kernel.h>
 #include <linux/sched.h>
@@ -180,6 +181,10 @@ void flush_thread(void)
 	memset(&current->thread.vstate, 0, sizeof(struct __riscv_v_ext_state));
 	clear_tsk_thread_flag(current, TIF_RISCV_V_DEFER_RESTORE);
 #endif
+#ifdef CONFIG_RISCV_ISA_SUPM
+	if (riscv_has_extension_unlikely(RISCV_ISA_EXT_SUPM))
+		envcfg_update_bits(current, ENVCFG_PMM, ENVCFG_PMM_PMLEN_0);
+#endif
 }
 
 void arch_release_task_struct(struct task_struct *tsk)
@@ -242,3 +247,89 @@ void __init arch_task_cache_init(void)
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
index 35791791a879..cefd656ebf43 100644
--- a/include/uapi/linux/prctl.h
+++ b/include/uapi/linux/prctl.h
@@ -230,7 +230,7 @@ struct prctl_mm_map {
 # define PR_PAC_APDBKEY			(1UL << 3)
 # define PR_PAC_APGAKEY			(1UL << 4)
 
-/* Tagged user address controls for arm64 */
+/* Tagged user address controls for arm64 and RISC-V */
 #define PR_SET_TAGGED_ADDR_CTRL		55
 #define PR_GET_TAGGED_ADDR_CTRL		56
 # define PR_TAGGED_ADDR_ENABLE		(1UL << 0)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016202814.4061541-5-samuel.holland%40sifive.com.
