Return-Path: <kasan-dev+bncBAABBLGYYCHQMGQEETGYOIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A753E49B962
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 17:58:22 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id a7-20020a05651c210700b0023223408119sf2849717ljq.4
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 08:58:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643129902; cv=pass;
        d=google.com; s=arc-20160816;
        b=JabD0owNoRSm9sztkZFGtXCCKmg9Mk8PPk54HlDDVGPvBxOpmtc2JxNlsBIJTGJTM3
         17yFgUEwL6LHozIeqOXnTi38wLQ0pWDKKBQVqGH83PhGj4lRFPt8Rblw2XSVjFZr5t9I
         mwuh7UtA21j4900y+Z8BwweRjpCBhp7Ufk9YgRCEchPD/pI4XNrqk8+4rwyL3HWIADZN
         cWVmW1g3tK8JGkKPainZOJuI062hzXN6XbD8gKn/R0eUIvxfhrHxVmkgYBo3jNITrziN
         43B+ttaUHxNclsM5YpusbX63aTy/SSAW9kHUiZ0CLOx4gT8nH8v5lZwiZ3yeACzOcU5X
         Yy3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Rgeb0Aabhc9KIZ2Qg79T2WvRiyU3cIDNOMwm3XmYo6A=;
        b=atWyc8vZom32j/If75+/8/TmzYymBqgrMtmbHlGzblMihRq5HgzTL1atXpXuMuTTQi
         g+hUlkCOeAijfn6YtljBC/5dI0G9pMJW8Y3bR2Be6M1WPr4DMYvfEdGJYfV+QDs8Kq+5
         x7eGto8p/TT/aFr2l/H9CbKRrZBOXWZl8QWUhkoRSq2+cOhsKApy87KTjRu5jw6vnaI7
         JeSdV4rIASF0YWS0cqQnNCoZwfZ+GMA4TV/TehHRdeXxN7FpRSrn9jHoKys3L3q7H9kk
         P8JcMZ2X+4EdmgUQXRE5sbch8/W1utiKRcX5kEVnLiAo5wUwVqNWHvSYuVYOKiGux/d9
         MBsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fimlBcBb;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rgeb0Aabhc9KIZ2Qg79T2WvRiyU3cIDNOMwm3XmYo6A=;
        b=Sa72K3fEh86GjJPGLesNHHedrlwXr9NE1/WBvXxY/9NZUeKdUq+QJjhLKLA0SK50V5
         mD28naHXXt1viG0f71toidclU4xNEo3Kdl12juDhancSCb+zkhu7fzMDufmZZS4SOvxP
         oz35OXcBQL6V74JE4ApCDy75EiZAeExuoV7PXPjK21a9bSkVaCExdC+nvETT72CWBj6N
         6Z0ZYoMxZXSW5l2sGu78emGifqZWkqsBC9wCf1Oa3kjfAKhykf5JDbNeOiynAfFBhNj5
         olzNov/c/0U2VZsgoklGCdGZW6juA1tZLHjaYmI3oKrDeMSoncvzlKSqDf3qMpQBsgRr
         TOIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Rgeb0Aabhc9KIZ2Qg79T2WvRiyU3cIDNOMwm3XmYo6A=;
        b=v5tVtnkU5BRJK2pgS4GaWW24zbducmwOvuYDw2Lswl6NBN9Dx1g2xctJPKOg+U0ODR
         eK4QPGp8hC0HvBzVNu6x/S9VukIrjsf+A+1LT7EG+JkM46HtgseoKoxk/NaBWQ4+PJA6
         g+FeAME9VfLj5wCY2JyrgNXj0t4debESZ9PsS6DTfsp/MYNrPLSx1yDL0xTEvni+2wa5
         WMRANE0ip8//ki1blcPVVgflMTkRKP8vU6x8wfWP8yinVZajww0Q33/wPRd+/b4gbix2
         9WE6kmH69yRuTf/wCF/yXawWXuUjMaEOGDtOGtBnKUsALjIUphYQ/PhGLsKfCavO8+H7
         sAqw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Z2Dw7wUVE0diMOHdQT+ExJJuTmqGWqFl/jKEAsgAwIRpaFKXM
	y3USXPTcLUA1FAeNIgGjxeI=
X-Google-Smtp-Source: ABdhPJx/DlIei8pSQo6ZybB5pZTQYz6K9vEhCKbwaIbGSJmO8qSiQf/Hxrar06qNHs1+Rg2KDOyo7w==
X-Received: by 2002:a05:651c:1404:: with SMTP id u4mr9574007lje.291.1643129900749;
        Tue, 25 Jan 2022 08:58:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1a2a:: with SMTP id by42ls3043398ljb.4.gmail; Tue,
 25 Jan 2022 08:58:20 -0800 (PST)
X-Received: by 2002:a2e:9cd4:: with SMTP id g20mr2523089ljj.2.1643129899930;
        Tue, 25 Jan 2022 08:58:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643129899; cv=none;
        d=google.com; s=arc-20160816;
        b=Wf3bQ1oYZW4dmCVNf3rvQIRV7XMlQwCDcOpChCTnkpg0RgjGfyZstsi8WV6hyCzp9p
         HmwBnMClcxb448/Ikn55Vw3gsARsBGtvbvcAP25l30vJCHd60jPZpJiRrlhFw3JWeN4u
         lSHHwH92rmusDBVLbi2PUXWhAN0I+wS65EBHmXYOxFYsS+LvpoGvdz32KohSsv2jv8/i
         Hsqco20djGhSrfNAUaKQbSD/G5dhKvo4oNdioWZIR6qA4klmuyaewPlowQzMgco2z8be
         qFug/8N25/NlaDy9IDDlD67621V18fat7BXz+lZTUFBUV8EHpRCBaVQVy7BfB1gvJj2e
         j3zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=m8Dfv93J8Kk1ZQHSMIfywODJNZyurYYF/TfoeUxsjNs=;
        b=kNWlvLzUna5lm6EVMv7AdWN78Vx+dl7tznbzboshY8jjp12Fr6gGmCH4jSx6Eih/VL
         CV7uzjsSyBN7pG+jQaw4S3wMxchcdWwg4xSWr/x30/sJGb0JXc5vkO+0Nu1Gn5JLF4jP
         6UtRwrKooYhfHpSeKaO0p2cAdL5Si717xtHQOwNMCdXfjRQwHqAgCnoa1k2N3+Fgg/vp
         4KspU1Rl9ChNFM6qPQAmJd+X/BQlYaFgBum01FUy9OYdLsbveB+z/yfLtpKoAIaf0hlN
         izFwfxX6SLlPKaVEf0BcfgzhTl+vj1U3fMwmIWQ1xFs1r9FqtwhP1/JQoq+SiQnWlaPm
         7TvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fimlBcBb;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id z19si624756ljo.2.2022.01.25.08.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jan 2022 08:58:19 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 8779960F03;
	Tue, 25 Jan 2022 16:58:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 03D8AC340E8;
	Tue, 25 Jan 2022 16:58:14 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 2/3] riscv: replace has_fpu() with system_supports_fpu()
Date: Wed, 26 Jan 2022 00:50:35 +0800
Message-Id: <20220125165036.987-3-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220125165036.987-1-jszhang@kernel.org>
References: <20220125165036.987-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fimlBcBb;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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
index 09331abfa70c..da272b399af6 100644
--- a/arch/riscv/kernel/cpufeature.c
+++ b/arch/riscv/kernel/cpufeature.c
@@ -19,10 +19,6 @@ unsigned long elf_hwcap __read_mostly;
 /* Host ISA bitmap */
 static DECLARE_BITMAP(riscv_isa, RISCV_ISA_EXT_MAX) __read_mostly;
 
-#ifdef CONFIG_FPU
-__ro_after_init DEFINE_STATIC_KEY_FALSE(cpu_hwcap_fpu);
-#endif
-
 DECLARE_BITMAP(cpu_hwcaps, RISCV_NCAPS);
 EXPORT_SYMBOL(cpu_hwcaps);
 
@@ -166,8 +162,8 @@ void __init riscv_fill_hwcap(void)
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
index 03ac3aa611f5..ece62392b79f 100644
--- a/arch/riscv/kernel/process.c
+++ b/arch/riscv/kernel/process.c
@@ -87,7 +87,7 @@ void start_thread(struct pt_regs *regs, unsigned long pc,
 	unsigned long sp)
 {
 	regs->status = SR_PIE;
-	if (has_fpu()) {
+	if (system_supports_fpu()) {
 		regs->status |= SR_FS_INITIAL;
 		/*
 		 * Restore the initial value to the FP register
diff --git a/arch/riscv/kernel/signal.c b/arch/riscv/kernel/signal.c
index c2d5ecbe5526..c236eb777fbc 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220125165036.987-3-jszhang%40kernel.org.
