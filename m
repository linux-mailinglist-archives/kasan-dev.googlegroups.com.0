Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB6UHQ2AAMGQEVIVEXCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id BE9BF2F7826
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 13:00:59 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id x64sf5878259yba.23
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 04:00:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610712058; cv=pass;
        d=google.com; s=arc-20160816;
        b=PQ58lxvE/rikue90VvSitNU1Xzh+QSBCbKkLzo1qzCnVo0izPd6Jlmo/h7lhk4ALkU
         LdJijcDLVuTCy2upRXb2CCLdiBjUnIULiHHdPR16eW/xAgCFLx0Y9xfIJ8E0Fm1eKtH9
         ZPEKp1CMzzi5c53ny6N2fzG2Iwbqh6wOy0ksQ+SxhjbPR55YKjeriB5JTkeGhikRDKEz
         TdY/h260v1+xwrG3E6RxnHJX/QHoWtmx8xYQfr619/c2RNS0PdPhP5ZZHgHLquy4um2O
         Nn8f0lnXPAgEQdL6B50VTY3S7vsriEX5HWAJ0+kkPz3ZK0OR6VqDHEzbPhqOZxXwmXnw
         3iUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZlBtX2clLauefKeCnbMCmsIi0UeGee6kfU4Ad0IRLL4=;
        b=RTev9cmXLWKKmFD18T0mo0egO4QHV0CVa7ld7n+qlvHqN8SieAPFy/IO8KXIl5SSjc
         xl8nyMd2Nb2SB7+4///EIsqsstC/aq2f9KfrRyc8cphTimiXaoJ1AK0WhArNTmLsYl2a
         NnE4Is/1OLnrpaFZKZWKBNdmVzW+sfoJvkvBUlXzD0sUHcKVz1nKaEn38VRmlBKnzKac
         Wpj/9ozqs5lOL1/hnaetqUYGbdMIx8D1NsDUthr7UMi3QxLOl6itPsW1XbztJNHrl70l
         J7daPRH7fx9oYnAV4aqKVBK4aSYJMjHMVDD2z/HJb3FGUnzLFakeKxe/iAUsEaY1qBDI
         nIog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZlBtX2clLauefKeCnbMCmsIi0UeGee6kfU4Ad0IRLL4=;
        b=OOI4xQ0667AUTN8ublA2EMGJ3Ek5ipYO1GbIIa9csVwUSVkjJfzcxhk9iqxETtpjJk
         oWDEJSGyWLQDzAmF2yzx9YZlaJoGvZ0nAiAeikgLCLMRWUiohoGOtGTUtbTirbgnwsAu
         RDRuht3z1lpx6f2gFUNYZV04XDXdA45oyA28DJygjdV5HI0T8d5DqvV2cAY4Ou49QYRf
         B6c0zLEwJXVp5NQ96VFSdlrLlU+cklEQ8PxOvTdH33uXr6R/SsTHArjAnK5d8ghvRpX9
         KYevNP55hz5JXrdzwjoutOMnIj5X8FLnqWvS3Di7Gm64GRmVaYdy9ZziiRLCame/Tktw
         DygA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZlBtX2clLauefKeCnbMCmsIi0UeGee6kfU4Ad0IRLL4=;
        b=pcRpCcpMt8R/5FUUG6ADoQUR/QUdyfTORB0BjVXU5eXQ+dhK8fIwvwwLQL+J1Lc9v3
         vc+RZCdy7q5XPwihVSpNzShB2jOEXy3w6R0ftg/M9KaWQp3n4VJilTLo8Vo5wbOw23Cr
         RksHH9tkVx4ozS1NSj8hjIUQpOqpGwk55y5S34U1H9cIyg5tey6pa2+0accFy/WXJ649
         f04BuQh/g/gSb2P/Sj/cI41OVP3/2oQD74ArYspX03OK0pHQNA1kWBLwSbK28w400Med
         CGE91DJQi5HX1KL8irNIH9Nc5RZazzf2xYui3n6mNYDTS7YQ+Pz7JE4kJzG/mFFswVRY
         ky/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HcACnaRpX2eabj08pFI2oV7+lbX+Oy6xRLHUXDtNmdxwv72hU
	cx6OJw9K46VRfmqk27lDphg=
X-Google-Smtp-Source: ABdhPJy85LiDG3IMKkaaWWGhyDay05Ge4qQfNGuSXOCMmYD8qOGWPsqisnAcsUdqphyBoC21X3YaXQ==
X-Received: by 2002:a25:bc51:: with SMTP id d17mr5324566ybk.72.1610712058194;
        Fri, 15 Jan 2021 04:00:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:f80c:: with SMTP id u12ls4336755ybd.4.gmail; Fri, 15 Jan
 2021 04:00:57 -0800 (PST)
X-Received: by 2002:a25:bdc6:: with SMTP id g6mr10058342ybk.337.1610712057718;
        Fri, 15 Jan 2021 04:00:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610712057; cv=none;
        d=google.com; s=arc-20160816;
        b=OwVIuOUIS1REDpoR55HGg/6XNPpM442bnetE7BUWNUrJHrF2hyWeXUFxedaskZD/8X
         uOdr+HnS//Ez3fe9JRwImnVev/omvoWSW/DLutU1wB8HhLyAyrNEjv5mWS0vt3Tf5l+W
         O7q4TTPeTjELc69ObaL6qo8+k/iZvL4yA13nl9Q+vAfp3K/tJUCoU2NooY0IdNHqdn/N
         2lqK3RP8kIYA2DSGi/Q5w0Pup8loCXCShLeCpaNggKCjaxqHY8QK9/BA6VIRlTBtoH2a
         qYK8GYz2HlzdYn4dw59QzwcF5CDcSYQpWdZXe6Vs/KVnjivaUbQhC6N8U2xfkReMtf2M
         qndw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=e7ELhc0T2enATmJukMyHdmYj688F0Fum10YA+AQbAL8=;
        b=dIiJMYA7rzvo/i26b5cKw3RQqEdn0vU5698T0MwKy4KA94D6trksTrpFTxntNSi1Ri
         mM0KDOPvLeB3HDU8pPloScPrhrkyDjEVfxLXwJXPrrUBBdAld4RHla88xNaGGCXUzjed
         iEV7DVC/5ILygGHPZlSae7WAg+Oa6DgHNsHUzRksaBhyh36WJIfeCzxs8hFRjwFhEtj2
         0Ew0ynIOfRvg9fjjEWC61mRvgS/ixQsdS4NNZYvgwASo8B837hyxz4SOmpilumtyP1Ap
         KbnXa3MC68Fv4OU+b3SQrT/pCWBDwgjXwCZbQvicxffbkrFadWsb0BTtNVjzBijJiDVs
         6miQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i70si653128ybg.1.2021.01.15.04.00.57
        for <kasan-dev@googlegroups.com>;
        Fri, 15 Jan 2021 04:00:57 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 380D311FB;
	Fri, 15 Jan 2021 04:00:57 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8C7413F70D;
	Fri, 15 Jan 2021 04:00:55 -0800 (PST)
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
Subject: [PATCH v3 2/4] arm64: mte: Add asynchronous mode support
Date: Fri, 15 Jan 2021 12:00:41 +0000
Message-Id: <20210115120043.50023-3-vincenzo.frascino@arm.com>
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
 arch/arm64/kernel/mte.c | 26 ++++++++++++++++++++++++--
 1 file changed, 24 insertions(+), 2 deletions(-)

diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 53a6d734e29b..df7a1ae26d7c 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -153,8 +153,30 @@ void mte_init_tags(u64 max_tag)
 
 void mte_enable_kernel(enum kasan_hw_tags_mode mode)
 {
-	/* Enable MTE Sync Mode for EL1. */
-	sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
+	const char *m;
+
+	/* Preset parameter values based on the mode. */
+	switch (mode) {
+	case KASAN_HW_TAGS_ASYNC:
+		/* Enable MTE Async Mode for EL1. */
+		sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
+		m = "asynchronous";
+		break;
+	case KASAN_HW_TAGS_SYNC:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115120043.50023-3-vincenzo.frascino%40arm.com.
