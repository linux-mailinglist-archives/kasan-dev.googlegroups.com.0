Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB7MHQ2AAMGQE6AJFRGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D4E72F7828
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:01:03 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id a1sf14156203ios.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:01:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610712062; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWw9BIpn0Wn8FoRHKLsDE0sI0HZ86QMRoWHEjNUco/C3QvOCmIIJCkrxenwZBSXoPw
         kuTPBgc4xvM8olWhSvTWTUJNCvTPVSz1cw1rJKJlTIJkpRyKn0s8CppMJpNuhZk52Tcp
         vTOvaqzq5lJDIJGjilr6Flp/vKTTL5koNL9A47W0XrXxY+/GAbT5EqHbPFRroa1QyKZJ
         VkSQBl8FzFIfuVXBkT780SQhd4LABdJNICbyDtX1SMF3ZJUXL0NALN47mzXCYurO6wtk
         3DDPe5blqvoLydfQS5wFLbXSLv7yLI0RSA+ZQAnu/DF7cbvRJs/vWDcFKgpD0d4HNpFE
         WQdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=0yslhQpRCo9UjxfsCyhariTMlZ3Z51fWiE2/1ETYiHA=;
        b=dDQqbBUGl9u7VhxFapJYLYnlOVNdTw3snQLcWs+DE7vj/XIoly4w+SuvdWc7Iak5Oo
         P4EU6zfgEzJCwKPDpw0Y3cqS2CpDXbWfiRmME+2eI3dcBX/Wiw+MHM0QpWptSgkIskin
         7UyJKVtbZiMxorUFe5ybWF3Lk7v/RGt4MxxO0PhfJVTHe+toNadUi+/7GkxYHE1bIiS0
         LGKbyl4zp7TG7veo2MXEmWtRQm9lurxld1U8xyrlpfUzIxmf8qr5Pc8Oi7OLWOmA9U96
         wqAua6RXmBBh91r04BvNeWMCymWMAMHFIpmGhOhRvepFA67OmB2xojYSyAZy6ijQTT5d
         JPWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0yslhQpRCo9UjxfsCyhariTMlZ3Z51fWiE2/1ETYiHA=;
        b=T6jye81g0VAsrdAcvwbi+NmK+WnlN9e3lTM5WRXqt6k/5euQM6+CRz9DFPVYKBGNeh
         ZP37FZYpIVYrP/voNHldqkwIYNrSbGLKdTUHo7g7fTKD0SQF9xj6BCZZzJzychB55jMK
         VdRiwyfRl7DtbLPzOBvvSUxfIp0wkEAB0g/X9EYRZECccqVl8zNqfPSKC7KE4sqkQAG5
         PYhx1cFJvWCTK7vVIv5rbTUOyXeNXMF6nHk1Qnh3dFOdYgJdfHfflx9GOWSGSvJtjzlg
         XynsS/j3PJMughmz74js4O2ohY3jUcFFEcaD1bL9fhf7KBNWLYC5svKgRl7+AtI0g03J
         Vs9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0yslhQpRCo9UjxfsCyhariTMlZ3Z51fWiE2/1ETYiHA=;
        b=UkVdv7oDxCj4ZdcQrCfajYQSMpFN5e1Zw2qbzJJl+cUynSkjh1g0yE+CX+ME/0UhJZ
         Yu4+u3W5f3jrx8XUjXnleAjxUothoGqV1pbJ5x1e80IJqU6U2CkeT7xTnjzz0Dp1INtP
         rpL3cbrztMddn9Lj/M79yHmNWI4FEF+87R88n1PeNfRmrH7tJi2wQNj7+BLAwZWvCY51
         IiW1LHokD5bJ5WN+Nf+oru2kMeC3apFKdephuRjpJUiLMjEOEuHmYxavE2vi+/DtPDev
         9P4glX6O/VTIfcD4Gz30qK/jnoKEo8ROypoFab1mVcSbRp6W/sXD9i4Tc4yT1X8kIylk
         XI0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533xtEfsT7Ur/EfXj2I1PqKo3cFBzA1Ixh71kbwqvm61os8tuYkx
	JAGbKrYg2+r6eCwoDSPBrt8=
X-Google-Smtp-Source: ABdhPJy/eo5uh5FGK7ZphUCKF5bJnmn9p9bbpeAoFj6A8UyM7Q62MCxbXYgDYz2h5rs8Z0GiHMMHsw==
X-Received: by 2002:a05:6e02:1a0f:: with SMTP id s15mr10933455ild.244.1610712061983;
        Fri, 15 Jan 2021 04:01:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls2489416ill.9.gmail; Fri,
 15 Jan 2021 04:01:01 -0800 (PST)
X-Received: by 2002:a92:bbc1:: with SMTP id x62mr10595500ilk.73.1610712061571;
        Fri, 15 Jan 2021 04:01:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610712061; cv=none;
        d=google.com; s=arc-20160816;
        b=Eq0eAe+Ux6+/DUwQhAChdfor7YK9eYem2gacktfA91WO+IDpmNSu2ebUs5hM5b8bik
         ncVGCdBxnak8UoBTk1VA2mZyyvZJjzEvmqAXXshl7csTyDAlPX1sFn+/siklj7PVc6M2
         dZqGLv44rSLB5TE43uYTgWzdHeyD277Yin96cFdjI3CvFMIaSgq2/s6Z3yyasAkqteeT
         ISB48UKH56yQesJ0Vqa/hG0GVhjCfseFYAdLwI8nDlOR9f3igYpngqNEaAHjpAaz4+Dz
         pIEv1uuTLFplWIBYmego+GMm3JJThvMicg80/yNVHNv93oDaxBWTFc2a9h+f/M11VbYD
         HxGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=vBqBBylpgYRkd+8HRVzzvkccjvjwAwELTow+ckZtvKo=;
        b=kr19ootuTsAC4LT5LxzWsNN1+uUfGsqb/c64tEPP3mXynEzV4immbXVh2lq8Wg1i8b
         a9tEU0uz9UUTnKXJBLjNl7rWGaXRxMWirsC8aJ/cl/s0o7DsFeGEm6ERTouA83d6R+jv
         B0Zfql6JAldqqhWGP+RExMU5J3LyvHMJd84fszw2UR4cWNkyKekrlL+TxYnDhti/UxsC
         9vQ0lsWLAilN5KnlnBoymAubR9ER8XmLy17+Bhdw7CtUFRDyWF6MVtCslhqtR5v6gWk5
         tzf7+hQcbe5utVPjOLejxTFIUi+0VW5Rb9wOm6mhkhwzSbMmFBa+sqhM7Ag21DeI4tR7
         do/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c14si921299ilk.5.2021.01.15.04.01.01
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 04:01:01 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EBA281396;
	Fri, 15 Jan 2021 04:01:00 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4CC683F70D;
	Fri, 15 Jan 2021 04:00:59 -0800 (PST)
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
Subject: [PATCH v3 4/4] arm64: mte: Optimize mte_assign_mem_tag_range()
Date: Fri, 15 Jan 2021 12:00:43 +0000
Message-Id: <20210115120043.50023-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210115120043.50023-1-vincenzo.frascino@arm.com>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
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
index 1a715963d909..9730f2b07b79 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115120043.50023-5-vincenzo.frascino%40arm.com.
