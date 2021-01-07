Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBOEK3X7QKGQEQTJQEEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id B16FE2ED5A7
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:30:33 +0100 (CET)
Received: by mail-vs1-xe39.google.com with SMTP id a5sf1939481vsa.23
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:30:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040632; cv=pass;
        d=google.com; s=arc-20160816;
        b=K8cWZm0jTWokDCMY2tMVdzDA9O4NbPDVZrngTm9oeSl+WfbzQuc7Ws+BZdvE3woK8k
         YcJBk/t4w0G1Jdv4Xzl324iA7qaLTa6XmDufDAQo5ZvK7ywwluLwU/2qwElY0cD+ssgK
         DXxgxp4Y1WuYihAy4cd0K2HGLJt3X9SGmZlrZgEaQHOur/H4ezOYSHrEDSIImOTbz81b
         OacBa/nPT/qfZOZLeA5yR7IjGDKi+efSc5LrN3O/HA/Kr5vK0l42gd+VXKPpBQzFXL/k
         5Nv3VdsbdS9MScBVEa/xltsRTPNa7Ac9J6Oc+OTonJzQkm7QN6qX74r12EB3eHCC8VrC
         uUwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pKn6ONc0AUVabaWsHPsO/iAi2xDjhoGx8Vlaii4mlo8=;
        b=coIvcq4MWGkt7yFlQmn71pL0J9F1oDPz4+4ZTUu6pJhiJ8rvUB8h/H2aMRxmUyr9L2
         E8PZxbe7BfuZ3S/kw5L7foQ53SbS0S47FFta+Isq5sFjYaSP3+cHyF9QOq+58YFc8gZc
         /d+6Z1sF/8KHBSzAv9kuosa+2DmrqT4ON5K/r1MGBN6a3p9dBzaDVWlNgF1qaDO5eaE4
         jS39JHrkUI7wUeznu4zSWY6nCZ+PWms+xUWPv0kEr8Ss2tQt+4o5KZlsjG4t/wLy6Pou
         27ZebeQYTfKfmRz1jvUnVPkW5sX6hS7fNBDw3XceXBFTp+uBFOtmxUIwIcJTI2qE7zps
         d7ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKn6ONc0AUVabaWsHPsO/iAi2xDjhoGx8Vlaii4mlo8=;
        b=n0iGtghHfvuta1vsw3aobgBBZGymKgrYUdGKdsxbxQMRWjqomNPtnrOxHcRZtSTaUE
         ezttz77jDfhgf3i5zHgpcZXvFGKbmWaGOHFNvWbWNg69WL0EIe4WVVivEIRDJ/qoEzFp
         hEmMU+6pl8VRKAIPNd7VfYdGq4wd7fhH0jzan7zK1XDKCFdTZds0KMlAHk2QfhP4dPSm
         K8TIMwmEVw4GThb5IFYTktJJAeLNaUJCvs+deDnsyuj86xh7H/kjdSTlwJnHxiZ2Eiy9
         P8k5hYsv3YG99tL2DcKss2dPds0M0KVWe0U5v216Mpcwvgmne+KTVBajyxFksNQln7Uz
         Z/VQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKn6ONc0AUVabaWsHPsO/iAi2xDjhoGx8Vlaii4mlo8=;
        b=RKl+ZHn+RelH5OEgKhsNJjIpo/48BywM66ilm3PStqt/4sKLqh//a63jlv7PnYdS5Y
         uHuutvIUKxvb9mDe0oZpY6kbMEk2XAHNXtPE+x5jeRBOFru7LA4wTJSA6j2GgHIy+jnM
         3w2AFScJhQpxbEsd2KkWA7MLLMK2mJn6mqfYWVudXmTioUtIsjuv/Wzo4JF/5Lad84bB
         YIdbiP8E6YIujkbAha+tXVjyLzI9vAHKm9TdWPVo8Xk2v6gQ1wD4EssfnV0OFGIQM9a5
         Wjjh9ozPZigMSMTIc11j90UJ8QT20rWGYd4Jtf8yZY313YSYVkFI2kwgaHaVD1gpbhQs
         L37w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bXxqYRk4R611S0oXO27LonCg7VG1u/paETPbMwLlYxKtQ8qvw
	qAlFMrY6netW3Q7Cz5Gw1Vw=
X-Google-Smtp-Source: ABdhPJzRsTuFgYjShMSa9a/l7igFsrd5TdggmQ/A/3WpUiHEV60wLpU88tPdr6ykJ8Zn/Agkm7Umxw==
X-Received: by 2002:a1f:a697:: with SMTP id p145mr2662901vke.23.1610040632761;
        Thu, 07 Jan 2021 09:30:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:382:: with SMTP id m2ls1072878vsq.8.gmail; Thu, 07
 Jan 2021 09:30:29 -0800 (PST)
X-Received: by 2002:a67:bd0a:: with SMTP id y10mr7908221vsq.28.1610040628981;
        Thu, 07 Jan 2021 09:30:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040628; cv=none;
        d=google.com; s=arc-20160816;
        b=Ouorlnb9WCvqTKwkLyXHxr/cL8StNjNSlXQibSFece33yEuwvxDDt/foxV10HIj7dS
         DM1HbOr6x8fGcYimq/vf7we+eBbXDVN6V9QEsT6z29VQx++XILVcdDKHirOTkaKMeHYL
         INnPnvUeV4QpI6gu+iLAiyvGUNkU6A3TDOv+nW/JN38kRw1s1xMYfRbp5UEDiE0wJvbU
         lVgHfKdp6I1arLWx1YJ2qNdxogEngkQfkcTP/Q3bohPHbCRGjZp0KWbq5lUkrxgCmXws
         cIb3vC/XNrpdAyy+StDM0VcPHSZirgbfZ0Kj/eerIkMeJP7ixOJtDnschAsW7np7SLxY
         EKdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=If7juAe6lMw6TuMFSj939RtZ5idQEdkv+QhpwFdZ/g0=;
        b=ISSZCGnAyx+WXaQ4t2u3YYDU+T16WiBz9XTQlGaupk39/kz4F4zVB5S6Q/iIN2nR5G
         jmRPuFeG5I0PLEjfeC5IBanH/xsvPi8mFl1xugm8AvqYIhk4iqQ2JDTHdWqMQK3ipMQb
         maLtw57am8Ij6q159YEELsLK6AjQAbeJ/eFwCuqk0FavmnsaLetbNWCEZLYahY+Dsryi
         rSnHPiiahMdshKoPDwsY3W6vZATid/BmBQApTieZwV2iBEnVAeGcbI1koioJm2zY7OZv
         ZLMzGnJ53nVOt15zj5BdQHNexirheKZE+VVqC4yEqOOooI4YZxQBnwZsB9hrvdoQo9rf
         9GWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v23si705427uap.1.2021.01.07.09.30.28
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:30:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3544911FB;
	Thu,  7 Jan 2021 09:30:28 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8A4E63F719;
	Thu,  7 Jan 2021 09:30:26 -0800 (PST)
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
Subject: [PATCH v2 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
Date: Thu,  7 Jan 2021 17:29:08 +0000
Message-Id: <20210107172908.42686-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210107172908.42686-1-vincenzo.frascino@arm.com>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
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
paths. It makes sense to optimize it in an attempt to reduce the
overhead.

Optimize mte_assign_mem_tag_range() based on the indications provided at
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
index a60d3718baae..c341ce6b9779 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -50,7 +50,31 @@ long get_mte_ctrl(struct task_struct *task);
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
+	} while (_addr < _end);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107172908.42686-5-vincenzo.frascino%40arm.com.
