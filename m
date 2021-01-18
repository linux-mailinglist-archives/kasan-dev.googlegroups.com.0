Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYVHS6AAMGQEOYQRE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A451E2FA8DB
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:59 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id y1sf14266781ybe.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994658; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRMeoUGPthcGc9YLu5/W8so0KMtpFVHq434vk6FNjVgqnPoSHynvf30083K1/XUN6o
         VU4bDWQAqMqihABpXAMIF5THbur271jvzjjIbnfzQm7faTPNt9uvs5whDYKeUB4qF+BZ
         LLf5mkfHTsd5XbQdA+jjJS/tQ8mCs1QVPptQpMAZqgs29grB7y85eK8gRV0kT+V+144L
         zL7kF8tslFnGDwJLBfCmXMHhiy5V7eauwsl3KZ0ul4tpSQqEOeyhVcvzSDRocefZ3C66
         BGP4kRcOwuIhjMcFErY/E0c0FfoXhvik3bjCd1Z0qjnzLqu+tzrwzRoawa1dPQCc55WQ
         A6qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tOF8qha+CA6gxfByt0JcG4gyOH/uI4NrTZpEfD23Q6k=;
        b=ZyDeUs6b5aaKfsf209X5ge77dhZYSreXeLAAHvapd2JtBY6uczbewV8X2zp5klwdUT
         YqVpQdfWXYIZugIy1ZUGQxOXYk0j3U8PeJRnzUNg8TfI2PjemejsikvYQiK3DMXRg5z4
         aDB/PRKQd+RGMJod5JridiiiPTv2ERCEGVLwN4vFm47m2InuYpj+qU94tK7nxQxyEanL
         cq8UcsE2x5XNbkaC2bnm2fSKx7pyvgSLzkeKIMXPYhX93lSbtKQOrkp7a/05VkyCgIP8
         I2z1tfWmk6YbLUOkGsIxI73qkDCXD3lV6gbgv1nAmTUwYKdsVjkFp7S56if4bU5cMOS4
         Ds8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOF8qha+CA6gxfByt0JcG4gyOH/uI4NrTZpEfD23Q6k=;
        b=K0BFv4KAcFB+FyljoksgfsCe6dNg/Ca6HSXisGi2DfvZ7M9isrAqURXN3s63pIfT0J
         ViDeaVzVmZK89hWqmNmDwYmsgQPYnvpi731E763QxnFx+OKdkDqEsUzkO0kTAcmGhZxf
         cK5iTA2txOCLSoxxXR3prQEyFygDAn/AnyVbY8AlQe8iSKajawIkSsNjn8bj7C4owC50
         Ee11YdbCSLkndiRfe373wad7lcuABtauAXy3hakDWIWYbTufMO2oepnF610aKZeqMdxf
         XDgv8xBkDfQEb3ASGpY38ILdXxecj2JO2dYpxeHPB5YzWE7lrdA3T74OJpb5uVbdIqPx
         DTGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tOF8qha+CA6gxfByt0JcG4gyOH/uI4NrTZpEfD23Q6k=;
        b=IyzrnWjvVuBa7pxF/5XLSRaIz0kOq9nRlemBsMpffqGxR8K0qLWHhqgliX2nRFw6EB
         udBfv590j8BrCzVNVRMhXJEkl4mA+e9njsSTIn/0Yq6d3kF1CQOEB21oM1pUPtMjBshz
         FgFKBHIzv+j9X+mqcfBh8cqYT+5P2n9n1FXZjif5ZaXmPfFmv6gS5KMLRipHXucAgu0H
         CupOVl2mudRJZDGfpj0Ci61kVwrpVjVlP4M8ti0kf647Ua8x4rNrvuPudUyJsC5ldrVL
         yy6Wa3KVNjXgL1BwM5g0KnANOBlhzWvCIx9PZ4cJSBnpjG7xrZuNNJWdFnxKYT1uv4wc
         FQEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530moFhWpgoKL8dzZpSTwBX6juhgtZQxo7/OwsbSOJMP3KNxRMXT
	+gYe8dDxcHXgf2ujTfELCDQ=
X-Google-Smtp-Source: ABdhPJx9wrzZT2yyA4npcUu39g7OYyC5VPmlcnr93TmEeneW8/IRPojJRpIfh5w7G8rFqq/oCTRr3g==
X-Received: by 2002:a25:6b04:: with SMTP id g4mr602356ybc.169.1610994658548;
        Mon, 18 Jan 2021 10:30:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:946:: with SMTP id u6ls9028575ybm.1.gmail; Mon, 18 Jan
 2021 10:30:58 -0800 (PST)
X-Received: by 2002:a25:e90a:: with SMTP id n10mr666000ybd.296.1610994658051;
        Mon, 18 Jan 2021 10:30:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994658; cv=none;
        d=google.com; s=arc-20160816;
        b=g4L4ajhkKptpuELW1tHtGUIf1v0rNTL4tZpgFakG8WyCnpiCJfsAl083xUbaen+HrV
         TY+tQM6RqZTggHHmuCDJ0l6o3bWnPSiP/o87hcogeWPVSkO5CUAbcaBq6tmy4vHhCv+9
         kfy0YW/7mvWIEDaQpcFfET7llsQuRGygFYvdyEb2fLBMXmKEJcXCzsgL7PwFxRIIJvzF
         hVx/mRlqMZQRxKeLyNMwuL1l0Q1Pf8/7MDk/abxidlXTb6yQPQqbAVBS9ct6f4/SQXEB
         flxSpfis0ItPeF8nBNb6o23/DZYMVVTwoKwiGvZI40LQX0IAQpcDNm8fSTSBvhWyxDBg
         S4jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=0GynTCjGmgRfp5GMExFipnsaDpFCmJq4NMhd8UvxnZo=;
        b=ZFtzzoN0ZhPuYMq9//uUfXU6NhoUE5ms+Xe+bRInD4G4son8xAZevwYOYV6l4Yiifi
         qFKOYt+GW3tueIBcSC1i8OWomQOWgPYwNXouyYfXD8t7SR2GqDPfrbGvvJad8j28gNgm
         hTGxuxz+Q9qZFw5iFqXDBgf0z1lbn2+M8oqoJHtpm/moEt312bxWWG1Lf0whWI8Nqskm
         +oFLow5MA48Qcs2l/mPUU2dDIy7CEGL83IpYVrNiHlj42pYyhkezkC7THiqtCSHIS9de
         Ev+hCNIj/SKt0D0w9OusgrMJbeSLR5c4DKDnfofeYuBXE8ZtBv55zUzWL/EA1m6OZraA
         WjdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id s187si1735131ybc.2.2021.01.18.10.30.57
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 790AE106F;
	Mon, 18 Jan 2021 10:30:57 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CCD8F3F719;
	Mon, 18 Jan 2021 10:30:55 -0800 (PST)
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
Subject: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
Date: Mon, 18 Jan 2021 18:30:33 +0000
Message-Id: <20210118183033.41764-6-vincenzo.frascino@arm.com>
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

mte_assign_mem_tag_range() is called on production KASAN HW hot
paths. It makes sense to inline it in an attempt to reduce the
overhead.

Inline mte_assign_mem_tag_range() based on the indications provided at
[1].

[1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
 arch/arm64/lib/mte.S         | 15 ---------------
 2 files changed, 25 insertions(+), 16 deletions(-)

diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 237bb2f7309d..1a6fd53f82c3 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
 int mte_ptrace_copy_tags(struct task_struct *child, long request,
 			 unsigned long addr, unsigned long data);
 
-void mte_assign_mem_tag_range(void *addr, size_t size);
+static inline void mte_assign_mem_tag_range(void *addr, size_t size)
+{
+	u64 _addr = (u64)addr;
+	u64 _end = _addr + size;
+
+	/*
+	 * This function must be invoked from an MTE enabled context.
+	 *
+	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
+	 */
+	do {
+		/*
+		 * 'asm volatile' is required to prevent the compiler to move
+		 * the statement outside of the loop.
+		 */
+		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
+			     :
+			     : "r" (_addr)
+			     : "memory");
+
+		_addr += MTE_GRANULE_SIZE;
+	} while (_addr != _end);
+}
+
 
 #else /* CONFIG_ARM64_MTE */
 
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 9e1a12e10053..a0a650451510 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -150,18 +150,3 @@ SYM_FUNC_START(mte_restore_page_tags)
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
 
-/*
- * Assign allocation tags for a region of memory based on the pointer tag
- *   x0 - source pointer
- *   x1 - size
- *
- * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
- * size must be non-zero and MTE_GRANULE_SIZE aligned.
- */
-SYM_FUNC_START(mte_assign_mem_tag_range)
-1:	stg	x0, [x0]
-	add	x0, x0, #MTE_GRANULE_SIZE
-	subs	x1, x1, #MTE_GRANULE_SIZE
-	b.gt	1b
-	ret
-SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-6-vincenzo.frascino%40arm.com.
