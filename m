Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBWVHS6AAMGQEMEPO7BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D3B42FA8D7
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:51 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id t206sf8879613oib.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994650; cv=pass;
        d=google.com; s=arc-20160816;
        b=WK3VpqdKJ4KH/SW5Xpk38ixcZBp4hPCJK6yHT15s4i62P8pJt47lYkDOtTyzevCFvI
         brL0mY1nFjLi05juWrjHNLZ8IcpLSiljQsLjwcrZBPHP/RZQW/eb+et+1bck0iVtL7mw
         damrcl6WFlAp4AXsoqfVZY8bztxLc7gedN5LLn5J0Tsgh3StGXkNFhomQmzizkjTCEj0
         oM+RozUerJfs+BKHRdyQZPAPRU5C8V4w7zQoKZlgBgcrN/Xa/qMhxQ5ZD4qV/JxFavD6
         F3ISKYVkwdiqQYSY+jDl8UP4lpkLA/xqlI4gJqvHzEIw52ZogxHYC4bSO8kIqsMzeL3q
         t/Xg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=7kFKHMtYfzvs/6kilv7VlWm6YpU2MLxjI9mlXM4IEBU=;
        b=i/YU68Vd2FISck63A42hOXo4cWPIzPhCUpDRvZBLfpepc/4O6ovLs9CAmKWoKaPK2E
         s0dSik5ghjSN2ab5hHv92/ZaOFF2ovezb6w1AzfkUrOKQyOMJPhC10hgbLMzyqk8WdMp
         T/n9GjMQCz99yomD//4VYcwu6x3hWU4x5wZV9kiCuW5vDxkIh0e66bBMEwoM/1kmSwEk
         c9X3lakvRoC5WlgpvMf4dp/AKVDG78DXEab9jGU3+pOL2xRKFWg1yaeXGqY4oEfhBujA
         EVU3pSR2tvJFdtp9dKspwmQJSM3LGufQSxxBJ5brZ6OYyQnFlIsazuv5phJtgVYhWN4V
         DXBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kFKHMtYfzvs/6kilv7VlWm6YpU2MLxjI9mlXM4IEBU=;
        b=BACJo9Lv1J14zKQ49SC/Ij5SBmtVr/OzSp70L2++XwO486K4T+SJByuWb4pKmAk6BT
         +EdQB1w+WqlBt7ei9vieaK0QHlHw7EOebLKgphnz70edL/MBF6QQJn2iNhqClt8FGBTG
         6N362osChLxUe8vjfGKhqRQGr+4Pyz4VgBlevF0V49ksO1MEJud5RLC5fdHcEReJZ5z/
         9Bi+EugtpfWRd+YX0ebc+Jj/JjtctFsFs9W4KxmuHHIxpHLhUFDxtI71gikY7FpYLde3
         KsEgcO4/d/RtuQKsq8K9jxHyTp192K0cyZowAtDM8PZXzlH8CxsZrPSR0R4a4GRMVUm4
         vqAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kFKHMtYfzvs/6kilv7VlWm6YpU2MLxjI9mlXM4IEBU=;
        b=F1SYzjM4fiUhEISqLditKS6LhqxNtjkn9OPsSGGtaJtOZKyJefKGQflBF/Y3LlqK9t
         vyKuCSJVyx8XXSUvHq1mxXckrw4MUBUF/dl+z/8+3smZCyj5iBrhBCzYKJJ1WsA2QPjM
         yqN2ZH/Xjy/6N6OjxexoadDXLd9hPwvDpIwM1zIoVBkr3oBirTelVDAO+LR+pU4Z9mXo
         OwFXhRI3tNN+73niGNKgcigpQdCS/Is+dSKI9ykk1YMyb3z591DlPCf45qVkJjSRspjG
         /89eIqGCp3PJxmttKP5JPpptrscKtPeNvEIGeXj+H0IEr9Ah9wqH8i4aubnKYmNlMuWZ
         Y75A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OnCzoVd5utGYOzRdk3dQ/Txy4+8vndoKpBo3mlcBAqBRkSrb4
	WfwiISoJQzRli+p2PZ7kgdw=
X-Google-Smtp-Source: ABdhPJzhgUUje7WCVNZMoffLHwBAANQMzglk9avk0tC51Q1DjTZanajP2oRkniae+6fpMbQI5hMZVw==
X-Received: by 2002:aca:4cc4:: with SMTP id z187mr413897oia.116.1610994650598;
        Mon, 18 Jan 2021 10:30:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cc51:: with SMTP id c78ls789167oig.5.gmail; Mon, 18 Jan
 2021 10:30:50 -0800 (PST)
X-Received: by 2002:aca:478e:: with SMTP id u136mr394557oia.165.1610994650243;
        Mon, 18 Jan 2021 10:30:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994650; cv=none;
        d=google.com; s=arc-20160816;
        b=z4rkSEK54FOmuVWl55zXLh7H4c8VzBAQxujOhWqFxZRcvHKNunjNcF6iwFkxA2VERy
         0Ti4dEAV6L8mpJsvQ7wxAfxSipaHAV4HA+63i/nW9oQuMag7+2BhtXLJ50/yCApMSaVU
         hwBwmTSTcrnqMOSwiHWOcFCErl3Lfiyk41HTLoISdZH1lE3c2UdZYaQz0y5w7kYcoyvd
         5FH3YTNQJQ8iTp3k9tdvlB9wsc+pgvAlh/Vr1QIZEdRKQ0ktR9Emc+EAqUDKV6w8N/X0
         YsNrqNQBk5sYQ4R/WR+C8aNqxEQcPWBZZ5YWyiTLCRglRkrJCqVi7UbZtL2BQf+3khxo
         SarA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Z9g5G1mzqtlhefxhoroS0Xv/bUYuuVGr4CwsrP+MTT4=;
        b=KsrXMciqQZgpA3vpvsCKM+0R+TTQujNZl2e0fYGziVH7RBccWWO1kTX8Q2pt3V/wBX
         FwDiTZSvr7GsP3cHO7MbLP8QtcwYjBqVxlocjS+pzv8hMqtIWca2vVHTefDyAR4+QqD8
         JKYeief9JKPSKsO4FMsb092/Rr1B0RMsvPoaiVSlNxeCL672KzzuhZ2ENAtos1FMgrw3
         VjrpUwJgF32n6H3yWBxrGD3Jw+hDo3fWrbpOPSXmnNsj3wvs7Ob2g/2LLkfptIotApg7
         CRCuhkcs/bBIEKYxlPT2LlATjvGydUuNZf18uYGyoOEtPkoF3tg+eholQdHkpK+nhSG1
         C2+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r8si1910127otp.4.2021.01.18.10.30.50
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:50 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F420CD6E;
	Mon, 18 Jan 2021 10:30:49 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5564D3F719;
	Mon, 18 Jan 2021 10:30:48 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 1/5] arm64: mte: Add asynchronous mode support
Date: Mon, 18 Jan 2021 18:30:29 +0000
Message-Id: <20210118183033.41764-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210118183033.41764-1-vincenzo.frascino@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
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
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h    |  3 ++-
 arch/arm64/include/asm/mte-kasan.h |  9 +++++++--
 arch/arm64/kernel/mte.c            | 16 ++++++++++++++--
 3 files changed, 23 insertions(+), 5 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..233d9feec45c 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -231,7 +231,8 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging()			mte_enable_kernel()
+#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
+#define arch_enable_tagging_async()		mte_enable_kernel_async()
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 26349a4b5e2e..9a5e30dbe12a 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -29,7 +29,8 @@ u8 mte_get_mem_tag(void *addr);
 u8 mte_get_random_tag(void);
 void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 
-void mte_enable_kernel(void);
+void mte_enable_kernel_sync(void);
+void mte_enable_kernel_async(void);
 void mte_init_tags(u64 max_tag);
 
 #else /* CONFIG_ARM64_MTE */
@@ -52,7 +53,11 @@ static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	return addr;
 }
 
-static inline void mte_enable_kernel(void)
+static inline void mte_enable_kernel_sync(void)
+{
+}
+
+static inline void mte_enable_kernel_sync(void)
 {
 }
 
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index dc9ada64feed..78fc079a3b1e 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -151,11 +151,23 @@ void mte_init_tags(u64 max_tag)
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
 
 static void update_sctlr_el1_tcf0(u64 tcf0)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-2-vincenzo.frascino%40arm.com.
