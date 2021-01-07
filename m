Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMMK3X7QKGQE75FSCUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA92D2ED5A5
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 18:30:26 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id t14sf4391008plr.15
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 09:30:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610040625; cv=pass;
        d=google.com; s=arc-20160816;
        b=QPLhpSF+KsG42QP3vS05aHH8/oazqdGOX8pY7OXAm3hjq6E44ynXn+OJwxlWFz8+22
         O76aIaAjOH4e9Tt+t7+f/dKhsK55aBPQ6qLWUscMnxyg1gbkTFf9SpNh80a0zC9VvY+w
         DdJSnd7TOW+YmBK0hKhm3JxhsOPj2y3nJl4OQcAZRrdfxR9a5T9ldT5Em2tJYVjgXdqC
         SUU9ZIHAb6hDDVJ7o+AYNtkNT9WQA7Tz5oi4Deq8j1zora/iFzLW1VbriOnZM/9kBe4e
         iWbWGEeTUsbheATrtZtt26Z6YMsYULVFnm0i33d7AW7lqYmYzlzrs/oSzSRgXzWvOOI4
         NbbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=v2sZG5YicpDHdGigu+TKKxxFJVmrhOWELUzlLH7Rkio=;
        b=igkesIiG3b5la1aytNOzZ/GJWZMKt4EAvlruf2uYC7iZcW/Vt8U395OOhYx8WCcnZd
         TWER4WOrBl3h3B4CWhjumBeZxnUTWC5YzI/3NPrY3mlDKzDWyP1x7LJJuoop+Jpih0az
         ndZY+3fEugb5qway7llYrQ5ZGJv8QZuwBRA4A4lkclPcM3vkF0BKdB4OLAYIhV65acB1
         1U7yvJvmDvCvGiaOfsWTCglyCpdOHMtZAdC5DQrI1re+UacFx2hQDWyuk2F2PZ/V4AdV
         op1g7cVau72x+Vqt32d2o1YUB7+m2Bu1crH8TcRGB0C55fRKSQFDuAmYHZwOiWC+WX0v
         h4cA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2sZG5YicpDHdGigu+TKKxxFJVmrhOWELUzlLH7Rkio=;
        b=NtVS4IhSuu7roRU+jXFdHbUyNdiNeWsidx9P0KUwM3wCYDdipKAubW3SSug3kJCdd6
         uEhg/pBTY/EOjWbBZA+OsHa9ryDzdyk15iuQFdxUTXualyluBkSe4UuuQ2hzOvlUNzYf
         6So1uXRtTjx+rhHbzOgmzzwCJQn+vyHQAP3qPw8GXYRq1IusqgRbPFjvjYwDnNLyENzU
         2S0L3nTLvEpxaA1fR8Ybv/KuXPde0XazT+VfcHhzZbdIoI3LOyQ9UW8cCwtj0CuA5xDa
         iABSThrGcb8NlfrKmtcPCfSf4N1v0EowwXYyH2jiBB1Qywd0mmBG3mkbIG8MK4x4qg+6
         u2yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v2sZG5YicpDHdGigu+TKKxxFJVmrhOWELUzlLH7Rkio=;
        b=A7PeMmoXTvul2AnS4dp+RWDVYUIU3lbv/Zs+n49+5DAW8LHX9X/P/X4zIt5vLi19Rc
         BklfyLC3+fVt/X/Bsh9IHvr5iYE/hHu6XzkVmTVcbGkaPOtnyQLKGOPcqSN+gAJBQ0fL
         X9bUZjqKPKW/TOOUAS1H0n3XhFTZVrMMPwRnxV235OXSIbgH6K2OzBtGX3kGWsfxltzh
         FbYlkKfKgU3AyvciRHuU06H9Jw9ilZe18FmPqYcl1DDjR79g39VsoKv0LR/AAXJ0YNCo
         S5a6jH6rKb1daUNYGWb+qr8xuArrmO0yXQi4ghClDUEg9WHSIBxlfqo18eIye0ru6oAU
         +GtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531O3eZtl96A3NRbj6GMTTDfeN1399Jk5NNtIHEkZirYnwiKyxae
	LaX82UkaqG34e61yLANnUAc=
X-Google-Smtp-Source: ABdhPJxnb0u0zScQch5Zfn/rQA7RGSUU7Mng6nW9IPaqECvxCtrfxxhFtp6Poxb2aHghqLpM+PELfg==
X-Received: by 2002:a17:90a:ce0c:: with SMTP id f12mr10451400pju.89.1610040625708;
        Thu, 07 Jan 2021 09:30:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:b893:: with SMTP id o19ls3572077pjr.2.canary-gmail;
 Thu, 07 Jan 2021 09:30:25 -0800 (PST)
X-Received: by 2002:a17:902:6a83:b029:dc:2a2c:6b91 with SMTP id n3-20020a1709026a83b02900dc2a2c6b91mr3091192plk.8.1610040625159;
        Thu, 07 Jan 2021 09:30:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610040625; cv=none;
        d=google.com; s=arc-20160816;
        b=AlcaD6rad5efz1bUseqexOXqCvKcX3nO7u6VaiD81jIAfRg7KEQGjNfL+OqhZGgwzK
         Tt76rLQMUVHvFIZnDZBzmxpwStCettKHkrzIbw6pb6txQmd+z45CqXWTN960+Y4FH1du
         Osg90TN1XHdlkUbRIBdjMRLDaoqhac2agPFoi8uNoyRokv+vDC3T8QOQLD7eg3x2Hxo6
         +IY6BNvUsYLGVkCBePnzgZ+ix/Z4KUc8qh/LE5+jnaRTBnhus334ZDkSb10VhhvE6PBM
         fF6tMMa1lxyK3rsDiq2juAeX5Ilf1m7rXCE2r7cFIojL6r385bkcwrCsGjarcLZo9pBk
         ioIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=01ehw1Ofk0BY4CAL27La4GHE2RjftcptrR3YX6Ao4D4=;
        b=kVeO4R5ivU+EGZmQdSnVNLYAySOtTQ5HFKIg5eXc2rZmKN5GWV49hk1RHUpi+WLxiM
         m+qLdTKF1pjdXTmSJYNiwutvpbwsPJ4UnZQALsPx4wUuUUNdhpasWQxFURlFuyfq8s2i
         uZH9geLZ5qGcI6aQDy3m0ck/B/AqW4SUzJtoE8TY4+d+FSUba9UJ5IanxWZerMpju8rs
         dXvt1KRINDbP5+8sBnSoX5t5crtUpWJeaPHz5bgjWDHxWAVTrwI13jtkerPY6WFaYwvK
         Hik3SBFXlhnuqko3rF2iZSO56SwFnFXTIou/e1nGEZFGZtlqlyONBwCxcIXBV2+LCScR
         XGBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id q32si240935pja.2.2021.01.07.09.30.25
        for <kasan-dev@googlegroups.com>;
        Thu, 07 Jan 2021 09:30:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7B05F106F;
	Thu,  7 Jan 2021 09:30:24 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CA71E3F719;
	Thu,  7 Jan 2021 09:30:22 -0800 (PST)
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
Subject: [PATCH v2 2/4] arm64: mte: Add asynchronous mode support
Date: Thu,  7 Jan 2021 17:29:06 +0000
Message-Id: <20210107172908.42686-3-vincenzo.frascino@arm.com>
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

MTE provides an asynchronous mode for detecting tag exceptions. In
particular instead of triggering a fault the arm64 core updates a
register which is checked by the kernel at the first entry after the tag
exception has occurred.

Add support for MTE asynchronous mode.

The exception handling mechanism will be added with a future patch.

Note: KASAN HW activates async mode via kasan.mode kernel parameter.
The default mode is set to synchronous.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/kernel/mte.c | 31 +++++++++++++++++++++++++++++--
 1 file changed, 29 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 24a273d47df1..5d992e16b420 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
 
 void mte_enable_kernel(enum kasan_arg_mode mode)
 {
-	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	const char *m;
+
+	/* Preset parameter values based on the mode. */
+	switch (mode) {
+	case KASAN_ARG_MODE_OFF:
+		return;
+	case KASAN_ARG_MODE_LIGHT:
+		/* Enable MTE Async Mode for EL1. */
+		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
+		m = "asynchronous";
+		break;
+	case KASAN_ARG_MODE_DEFAULT:
+	case KASAN_ARG_MODE_PROD:
+	case KASAN_ARG_MODE_FULL:
+		/* Enable MTE Sync Mode for EL1. */
+		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+		m = "synchronous";
+		break;
+	default:
+		/*
+		 * kasan mode should be always set hence we should
+		 * not reach this condition.
+		 */
+		WARN_ON_ONCE(1);
+		return;
+	}
+
+	pr_info_once("MTE: enabled in %s mode at EL1\n", m);
+
 	isb();
 }
 
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210107172908.42686-3-vincenzo.frascino%40arm.com.
