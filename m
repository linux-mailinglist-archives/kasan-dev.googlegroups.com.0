Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBPW2QWAQMGQE3DNZ37A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84D4F313A2B
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:31 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id v16sf2038238oos.1
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803390; cv=pass;
        d=google.com; s=arc-20160816;
        b=EgXKjX6EI24ZeSHYny+JEKRl+hvOjrRF+a0gC+Rhy6b+6l+Uc3L10RYcfM7K+w9CFY
         Nogx4EKnQFv/TTZEUZjKpYzR+ivNpLy9xDW2JHDl0iwAr0ft+zMTk0UqimOSsBw36vwo
         XKxn+QQCb9qXSX7rFMjY1q/JW95QdSmnZlKEbiZHXaegIorwZdoN6g66pjxuIEmjY7E7
         JrZVqKqKF7wkaCaRX6iiGyjbNO2HvYINgW3HwJmkA4lghriilLTpZSSHqC9R4WRvvkrV
         XmGrGIJYSIG6HDH+3mo/hngNjJTdGYKwBUL5EXTy+8Ut4ddBJfKshTWBl7dOpob+u+wR
         sttw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ell0saZ4m+W71oBIxcQRq5M8HdfHKjtqdoj0du1q6R4=;
        b=ylvJO/lROV+TY96t8OZ2y+GfWDHsUnTV/AuWnowwB1s5r9jL5b5Le1lT7G6bBxGUc/
         ySXfnmTPjsYN5MafsAbAxRbZ7Ebjc2flhJZIPmHfsPsgmvRa60a5OW7BSP+UlDzHraMx
         i242FhnbonwXFbwT/sm9GgnaPzVMrr4uFujWMJKahhjOqc36T40W9ak56R7UuzyUUvUh
         4ZxyWySwBYUOEUaNWvZ6oE2uRnGBtuscdRVLKK3H6RAyHW82cgB3K7n5lIC2kPlFaBKx
         DCm0VP7oerJ+ZNFiOgphK+2wiCzvRybGiGHZUj7FXUnEjam49g7UHbMKZrNF3uijwv+C
         snGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ell0saZ4m+W71oBIxcQRq5M8HdfHKjtqdoj0du1q6R4=;
        b=qKp62ILUWulDqO6Rs+Zz8i9dz2P+omSQyOD4bIJA5I0fhxmznEgn5bs02efD7Y+RTk
         molzUKISKxE45gcb4V/JBPx3q8+9SmPddogfODO5Qa0Qluhen5JH8xrv+0+gtTfQPUYj
         f1VeOybraZaYXAm1GSRs5vfu38PYGMS6IOc/CzPSRTJx8Y01onHg5zayq3TXlcT2n6Fg
         3lGYsrgUIqo3t1KVB38XrEjUp8suiy4RKNRHQvgJx3rwTc1NW29nWYA6E8VT/LVE1Dlr
         xti4s7BgM+823pQ7k9Z/QttkkvaEE+ozAcxYAdz65UGj/36cz2l5gLtO8S1NKO32XaF6
         WsdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ell0saZ4m+W71oBIxcQRq5M8HdfHKjtqdoj0du1q6R4=;
        b=A3jGf2Fl5gDghyMniMqMU09V/CJLfVwzrFYp7gJuHSqGkwJ22uvxf1sRQKXIwDKf2y
         u445T2a9rP9cOUKFRQDOClPtOZPBKwA53I4BkbMZZyVRYYLwZi4sdtnLpGIvoeufKHQp
         hw3A3y6iG2Qrj1PzDSHQ9LFS9oDSJLOdIVQSUG8eHzlDQgAnqNgtYY+2jqVj7FuqTD2M
         PIpx/TmI0B2pNI+eZfTyOyslwuWRK35or+YX6quik/xR2XUylT58I2Qk5JnYx7PdLqaV
         zBmaQ5W9HW8RDo76wVemohRHrxbAfQt/dRajGjaJuG72IbCLn6wi6KwbZqliOdQnlzVG
         A9ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ct4K5DKr982sXV38gmeRASeGlXGSNZ1Ve4LsiT5qbUzYaZd8G
	QX2eZ6B8n7HoEdHuOeO6RVQ=
X-Google-Smtp-Source: ABdhPJy7Q8Rt7GRhPh0DU4ouIahNVtvEKQI07m2rvM6Wpnlj+3MyPBtNqWuupjsPhCfiPI4opuokYg==
X-Received: by 2002:aca:dd08:: with SMTP id u8mr12219985oig.55.1612803390368;
        Mon, 08 Feb 2021 08:56:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:552:: with SMTP id n18ls1084242ooj.2.gmail; Mon, 08
 Feb 2021 08:56:30 -0800 (PST)
X-Received: by 2002:a4a:e383:: with SMTP id l3mr5380793oov.66.1612803389926;
        Mon, 08 Feb 2021 08:56:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803389; cv=none;
        d=google.com; s=arc-20160816;
        b=K5y/jPIxwoN7Y6YLiVx/u+d7thP/Vd3s9LLNpWJ67/Aj0G6ndnkK0YBrvH9PWqEU9Z
         NgDQQLh+6L2FkVdzxvaakoM9JBwFcGW2ysFsSaw5AU6rZdl0rYwQ/7Jc6zbJGkq/u1HY
         89I42HYQQ5UTeQZ9Av6anRONXWBcLohzQZVvI7LM67VWwX+An/if6WdzXV4cEj8JSUpJ
         GGKpJYIMfZXR7gKuEqZOEjZtspTOpjLifKOOxWaTzu10rUE3iRVP1FXfnfDN6/DIdW7h
         ayQq4R1ILIjQfy8MqejKfwfaYJq6JvjSedSpfcgeaFT82qfJHGTyaXLn1xOj7BQz8Qjn
         QLVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=lJNNTKwVaY2Bs8RnkOuqo6eHWcn0Ec+G85xmkJMwvsA=;
        b=uPT5Bt2VHJImzhAYsjMDIMmu/NBrsVTcto6+I+Yc0H/+kZ261XE1u8M3PMaZ8E8MRe
         1uYtJ1KLgrmtgoJpUgJJzUKO40WboIKB6ICby1WSvx2psjNA6AcvW4mp0ID6i4gLHm+9
         EjoVh4RVw+TaTcRoXKWlazPXKUWP5VXqnvLwrWflIaU/A0ykAiuMGUx5xsL4/Oa98tR4
         uPkNERxICYl4pv4reJdoSL/6E7DYjwzD2tgh+Z1TZkneYPjIqYcblxvGS+yO/QxjnKYs
         H+ZJxcVBy6OucBtJa2WJj82fRutUah6Ruv3ZoxNiYjo4Z9jf/yqos4IxyCQlrnBvCXpo
         W9Kg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m26si1119719otk.1.2021.02.08.08.56.29
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:29 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9D36AED1;
	Mon,  8 Feb 2021 08:56:29 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BB8B83F719;
	Mon,  8 Feb 2021 08:56:27 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v12 1/7] arm64: mte: Add asynchronous mode support
Date: Mon,  8 Feb 2021 16:56:11 +0000
Message-Id: <20210208165617.9977-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210208165617.9977-1-vincenzo.frascino@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel after the asynchronous tag
check fault has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.
The code that verifies the status of TFSR_EL1 will be added with a
future patch.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index c759faf7a1ff..91515383d763 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -243,7 +243,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 3748d5bb88c0..8ad981069afb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 void mte_set_report_once(bool state);
@@ -55,7 +56,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_async(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index c63b3d7a3cd9..92078e1eb627 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,11 +153,23 @@ void mte_init_tags(u64 max_tag)
 	write_sysreg_s(SYS_GCR_EL1_RRND | gcr_kernel_excl, SYS_GCR_EL1);
 }
 
-void mte_enable_kernel(void)
+static inline void __mte_enable_kernel(const char *mode, unsigned long tcf)
 {
 	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, tcf);
 	isb();
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", mode);
+}
+
+void mte_enable_kernel_sync(void)
+{
+	__mte_enable_kernel("synchronous", SCTLR_ELx_TCF_SYNC);
+}
+
+void mte_enable_kernel_async(void)
+{
+	__mte_enable_kernel("asynchronous", SCTLR_ELx_TCF_ASYNC);
 }
 
 void mte_set_report_once(bool state)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-2-vincenzo.frascino%40arm.com.
