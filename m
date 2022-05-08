Return-Path: <kasan-dev+bncBAABB26Z36JQMGQEVVASAII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E86451EEE5
	for <lists+kasan-dev@lfdr.de>; Sun,  8 May 2022 18:16:45 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-e853229b21sf5362475fac.2
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 09:16:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652026604; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q0FLc2MeRWcCaIPNTwAFJ62pMiKd55PNmPckA24dCqWLUEyg2Nh6c5C+ujZTM3JpWY
         sWry10N9yPmYeX2gRLzL6lfrtd+lP6IJKkQ4ZnKI3CNJSBdJedocYS85Fn/dGQhVqZrf
         pxbGVgOW9CX8uML9qKGqoaJbEBBEh3ix10DlBkvRBGRrfU4J+FG2iPj1lQy/pWKBDnLZ
         AZXIHDKGJdR46YpQS9F2al6Y0bjo4J8BoI/3H2HULtz5gmEnA9XZKt2x4PcbVkHmgbbw
         iS/Y0LnJ/GqUp3m08dCYRPSFfNLr1XVaATPZJMs48/aHDVHYUcssxqCSNdy/R4Dxc6q6
         YsJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=blI20TuxdksYhUvzU4dXdCMZFIOvcD3pHOsd6KXIZXs=;
        b=dVZlG3eNcyqQcScZOMLhI6ceR45V4Dtrupj0HryX37NujYOPJceZDLMPkuHR6lyI7Q
         zOVAXhso4wFns2qGm2C2K0nImCMu1Yy2nlUMcUvoOAyBt8TjJQRWnH+09i8I9Leh27le
         huOQgSI0CvKzC3U9KtvO8UAGWpp6FWuPExpXcqJGTGHMSzVTEh16aSQ7WX4tH9aUhOWb
         YAToXb2TsSkUPgUNkYuDifRvDqd6nXE7zmQyvNAOvnIPze/uU6UhZsJb2nSw3Sjv+V+3
         sUHZdHk8luyN/bawjWpRQYIL/rKzrP/P6jLdX3/cuOFVuLUjLVt41I3RmQQ3mFxBxyLu
         6NJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wp0TGBxI;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blI20TuxdksYhUvzU4dXdCMZFIOvcD3pHOsd6KXIZXs=;
        b=YoIsE1PcJ6iSczbNLkGPZyBK9LFGkzY2xUusk3vkLPFJQYajUfYNdXceBL716Ea9VO
         nGf5HR+hnHBz+UqX0D8C+nkKsHeri747BRkQK8gS7rzJUnIPvevW/I1mnpXHHBEeYlp7
         yVOJKwGUCX9WoxmnvGXM1sDSmvEcvgp90cdsBY8AcX8MbYCwEh2MC/9YqK1RctgZA9Dj
         j+hIO/+1tcbXCyITSxkbWYUJxtM/GKiwRBDgchYui6uyzKTLyAjZHfQhvpUAo5sh+xpD
         hsj/ku2ClMygqFcpOVaAPHjrwTRBRpNKgu8thJd9zvxW09mmwaBuL7V1riexaHOs/LIZ
         Egew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blI20TuxdksYhUvzU4dXdCMZFIOvcD3pHOsd6KXIZXs=;
        b=xaugs55rKMPy0T7fNpYBRm4sTa3lr3Fd9/hshBc/LnQFYmiHfmcF+5FVFQHRC9Z/AJ
         EeXjeqNEmd9T4PKjd0Kxk9TLj7eYxbsQurn61FKZQKfVg1XyFX4iM2pfi7yujKABDX0O
         kiM8eCTOXX63aE9psXqlLGOsD+/FUJfUL1iDlsk1iDcM+qd8432UDU1gIBigJ17uCg8F
         5QP6luBc7Iu8PwalKjCRSRtHtw9fwUXV+OXmEaE/IySbnAURDGlSo+NS6n+stON+tLdq
         KCdtbfgZp4RqiSizooMTMffj5j/LiMGclT8Vs0EVoHJIWK2v7I5p6uJfT5yIcheghg/n
         hwCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305qO31ABfTkytDhaBal/ihOPY4TmDa/U0KcpwhAZBSECtyP2WF
	MlBKlankzwZVjQxGKWHHdX8=
X-Google-Smtp-Source: ABdhPJxK1RkqMv9A23EnFlTvMWX6LUK92/oGyriQ2wqecuMAmay39JpmWR6CM7KEUxEYTGda7o9dKw==
X-Received: by 2002:aca:7c1:0:b0:324:fe9a:9856 with SMTP id 184-20020aca07c1000000b00324fe9a9856mr9017402oih.293.1652026603826;
        Sun, 08 May 2022 09:16:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1508:b0:606:1375:a4a6 with SMTP id
 k8-20020a056830150800b006061375a4a6ls2780817otp.11.gmail; Sun, 08 May 2022
 09:16:43 -0700 (PDT)
X-Received: by 2002:a9d:2f61:0:b0:5e9:4bfb:61cc with SMTP id h88-20020a9d2f61000000b005e94bfb61ccmr4379502otb.355.1652026603480;
        Sun, 08 May 2022 09:16:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652026603; cv=none;
        d=google.com; s=arc-20160816;
        b=Jel5JRTa4psgooADqUpc53Bqi+zmRLFxesJYJ9XHmAUCa3kIpI0fn5foqo7+O7Z3Az
         DRbw3owGln1ZjUwOIfXjwEYwSj/XaXbY8Ask+pQu46EhO7HN8AcjR/dG8nEvY8+lhBIQ
         /bEpOWodergSr1ZepQXwU9vpGdLBc9rh+C9/6OBAZEwN9B0vRdDVYm1ASneVcdsksNR8
         H0oCH5r07Jnm2cs18hOXYt61WqUTwsCcVqbGVoZJcdGZwf1ssAPCjirHW+IEq9wPH+0G
         r7qWyhrKNB/BP2HzkVifxJdqNHXjZ+ASod4etFTxFcjkjdRfcZSZbncKo9CHdy+CezL5
         kxag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ntHhccAlt0sMpDhlurzdabOIyQ7/g2/eZwyBg52NyaA=;
        b=MauaSPH2IPljn259sN9Ph+wd/p/FkEbvS8hefSO/gZo8UCg7U8pBb0vMbJ6nB6v9S9
         E3Odn/AQ3yP3mvG74a+3y6ws5TiKwUcmonzJO1mRZrE31v2dMImqyue+q5ZqhKN3rxkf
         5hZwvvWHj86a9/c7328Qt5USgsmVEt7VodnQ+2cv28wtrqlTH+OR3IXr9O6Qq4siDXA/
         u8M/SY3rgr0FNDWUquMGiMiEwDo+gi0z+7m2NNerb+epqQm+tJhBsL76S1jT0ykpgj4M
         dhipRzLB4VbFW5M4Z4YQ925+NAyiL3kI1Qv81CMdjF6hDrgYPANWmLbh3gAL/gDyaogz
         Xs3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Wp0TGBxI;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 4-20020aca1204000000b00325eb87c2a3si547831ois.5.2022.05.08.09.16.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 May 2022 09:16:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4AC4B60F60;
	Sun,  8 May 2022 16:16:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2514C385AC;
	Sun,  8 May 2022 16:16:35 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v2 3/4] riscv: replace has_fpu() with system_supports_fpu()
Date: Mon,  9 May 2022 00:07:48 +0800
Message-Id: <20220508160749.984-4-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220508160749.984-1-jszhang@kernel.org>
References: <20220508160749.984-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Wp0TGBxI;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

This is to use the unified cpus_have_{final|const}_cap() instead of
putting static key related here and there.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/cpufeature.h | 5 +++++
 arch/riscv/include/asm/switch_to.h  | 9 ++-------
 arch/riscv/kernel/cpufeature.c      | 8 ++------
 arch/riscv/kernel/process.c         | 2 +-
 arch/riscv/kernel/signal.c          | 4 ++--
 5 files changed, 12 insertions(+), 16 deletions(-)

diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
index d80ddd2f3b49..634a653c7fa2 100644
--- a/arch/riscv/include/asm/cpufeature.h
+++ b/arch/riscv/include/asm/cpufeature.h
@@ -91,4 +91,9 @@ static inline void cpus_set_cap(unsigned int num)
 	}
 }
 
+static inline bool system_supports_fpu(void)
+{
+	return IS_ENABLED(CONFIG_FPU) && !cpus_have_final_cap(RISCV_HAS_NO_FPU);
+}
+
 #endif
diff --git a/arch/riscv/include/asm/switch_to.h b/arch/riscv/include/asm/switch_to.h
index 0a3f4f95c555..362cb18d12d5 100644
--- a/arch/riscv/include/asm/switch_to.h
+++ b/arch/riscv/include/asm/switch_to.h
@@ -8,6 +8,7 @@
 
 #include <linux/jump_label.h>
 #include <linux/sched/task_stack.h>
+#include <asm/cpufeature.h>
 #include <asm/processor.h>
 #include <asm/ptrace.h>
 #include <asm/csr.h>
@@ -56,13 +57,7 @@ static inline void __switch_to_aux(struct task_struct *prev,
 	fstate_restore(next, task_pt_regs(next));
 }
 
-extern struct static_key_false cpu_hwcap_fpu;
-static __always_inline bool has_fpu(void)
-{
-	return static_branch_likely(&cpu_hwcap_fpu);
-}
 #else
-static __always_inline bool has_fpu(void) { return false; }
 #define fstate_save(task, regs) do { } while (0)
 #define fstate_restore(task, regs) do { } while (0)
 #define __switch_to_aux(__prev, __next) do { } while (0)
@@ -75,7 +70,7 @@ extern struct task_struct *__switch_to(struct task_struct *,
 do {							\
 	struct task_struct *__prev = (prev);		\
 	struct task_struct *__next = (next);		\
-	if (has_fpu())					\
+	if (system_supports_fpu())					\
 		__switch_to_aux(__prev, __next);	\
 	((last) = __switch_to(__prev, __next));		\
 } while (0)
diff --git a/arch/riscv/kernel/cpufeature.c b/arch/riscv/kernel/cpufeature.c
index e6c72cad0c1c..1edf3c3f8f62 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -22,10 +22,6 @@ unsigned long elf_hwcap __read_mostly;
 /* Host ISA bitmap */
 static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
 
-#ifdef CONFIG_FPU
-__ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
-#endif
-
 DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
 EXPORT_SYMBOL(cpu_hwcaps);
 
@@ -254,8 +250,8 @@ void __init riscv_fill_hwcap(void)
 	pr_info("riscv: ELF capabilities %s\n", print_str);
 
 #ifdef CONFIG_FPU
-	if (elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D))
-		static_branch_enable(&cpu_hwcap_fpu);
+	if (!(elf_hwcap & (COMPAT_HWCAP_ISA_F | COMPAT_HWCAP_ISA_D)))
+		cpus_set_cap(RISCV_HAS_NO_FPU);
 #endif
 	enable_cpu_capabilities();
 	static_branch_enable(&riscv_const_caps_ready);
diff --git a/arch/riscv/kernel/process.c b/arch/riscv/kernel/process.c
index 504b496787aa..c9cd0b42299e 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -88,7 +88,7 @@ void start_thread(struct pt_regs *regs, unsigned long pc,
 	unsigned long sp)
 {
 	regs->status = SR_PIE;
-	if (has_fpu()) {
+	if (system_supports_fpu()) {
 		regs->status |= SR_FS_INITIAL;
 		/*
 		 * Restore the initial value to the FP register
diff --git a/arch/riscv/kernel/signal.c b/arch/riscv/kernel/signal.c
index 9f4e59f80551..96aa593a989e 100644
--- a/arch/riscv/kernel/signal.c
+++ b/arch/riscv/kernel/signal.c
@@ -90,7 +90,7 @@ static long restore_sigcontext(struct pt_regs *regs,
 	/* sc_regs is structured the same as the start of pt_regs */
 	err = __copy_from_user(regs, &sc->sc_regs, sizeof(sc->sc_regs));
 	/* Restore the floating-point state. */
-	if (has_fpu())
+	if (system_supports_fpu())
 		err |= restore_fp_state(regs, &sc->sc_fpregs);
 	return err;
 }
@@ -143,7 +143,7 @@ static long setup_sigcontext(struct rt_sigframe __user *frame,
 	/* sc_regs is structured the same as the start of pt_regs */
 	err = __copy_to_user(&sc->sc_regs, regs, sizeof(sc->sc_regs));
 	/* Save the floating-point state. */
-	if (has_fpu())
+	if (system_supports_fpu())
 		err |= save_fp_state(regs, &sc->sc_fpregs);
 	return err;
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220508160749.984-4-jszhang%40kernel.org.
