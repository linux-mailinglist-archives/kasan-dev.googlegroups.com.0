Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB66K237QKGQE5N36Q7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id A5C502EBD5A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jan 2021 12:56:44 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id y16sf1396111vke.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jan 2021 03:56:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609934203; cv=pass;
        d=google.com; s=arc-20160816;
        b=0SsCbq93p1Y4Cgsv3Y3g8y3NQnnjreQTH4RsX6qd2K99AOONVcrM5s6FHiiVdb5HXe
         qyLnK5STLa2CXtENeDzTTow+UwwYOtfOlC/tfhVmjHSRfnAjyeKvitQlB5wH1pOnBpdj
         RAESLFnWEwwZDUEgbFAUOcfENnIy7CMHAJrbTrk68Aacwk0TIWJMiHOXsUBeL0tRqhKZ
         WDg4fBht8CcfEaBnOX6gO7vF5X5gXGQ6n0DwBKzIRlBwUO2JZytnt4JbQtczccwxrIoW
         o01jas/th8lpxtLjVusykTuv/U9ypWIiFHLf+edUFo9AkdpiZFo/zi5W/H/TjAde2Yry
         FgEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EctuBUw2nMQ7k5PanvSpeB8DLlJu1ERHXMxJTZ2T4OA=;
        b=NhDW6jjEYNt1cKjHz1o5DBGMe9EEAtWHJB4cc4ZkNRQPXydUJ8UMTFJ5GpGLZ/hAp2
         /ZTrx+I1pGdc0FcDCtN2KPrcvBpkU4mAXmLTyZwK+yL3VKMBr7BM6HEUz8CZdqzqmeqc
         +IWTqZx3B933K0xPBIVwkXYHF8GDfdVJFaWPnKrbELr9ZLw6V7F4ZQPs8SHrN0CapZK6
         uJ8RY/sZFWkljn834egaQ0Sb1YpIG0aSLGhPeJ9WjCdJz8CUCTbA7czRFOAr+lTyUUx8
         XWEev+djEU56HpCuIN1WKKARK+/ee30AYIGrJo+SJ/QCX0Fk7U/MXBc35pC8qqbArIP5
         jP5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EctuBUw2nMQ7k5PanvSpeB8DLlJu1ERHXMxJTZ2T4OA=;
        b=FwyEZO1idZX0lC6Qtco5ee+bNfs23JaD4CP1J0CwliHocbGI0gRlFcro0rPbRvPYBd
         sbM7DT8DAlLyFY7m+BbjgPB/uPaPVOFL1Lct1Gro4aZw15d7NLy7pPgBoE7nJNy3x9je
         XQCMjDKhqk5DGlkCrPHThoNRTUoAqb4qIruga5/Vij/RBjAHmRBxFNfqQO28EIcor2x5
         0WWAOUqMbkqW/5ljq9wp65fwI+PVh/LTQY81wJQe5z0S3ApLTMQBLuzN+qdlxGyQxwUn
         /GuO5OJXRS4pfedWSv9C0t+ho8jIqJI+ticZIBwk6Df+IfQ4VZHMYJjBW6ZzgH7bQ/Dw
         JFgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EctuBUw2nMQ7k5PanvSpeB8DLlJu1ERHXMxJTZ2T4OA=;
        b=A39Y8LRchPLFpEcgJyGWSoqeU2vDVW0YURvGOvMT81eO+wOAk+bgcFCxVyiz0gXGli
         zu6/kvhZVxm0Yl14heEwueYJzR4mBwqY4xVyuZEQKAtDZVusbg9BGTRRLSvvlZ4UGzAk
         XsKDpcUPsXyMWedVRGnya/sNFP6tbtPb5Edgt2+PdVhEeZJEwVD6KlrbyraEqqs9DHTL
         3vlUiPvZAESQE4McsWD+yjKf82XSGff7eAYfEpPXiGZhJaqu3792quQ650XPGcMTGeDi
         6kZMda8dKgNOx/L/1o3d3pAla+n3WcfVvDlovOvD0aq5rOWTekOShOVNChIZPa5RqEah
         7A2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302XPjaaOwLAQkMBMRINq7VgAR+J/k0DXcHfhkmotamJrUXkiO4
	7j6CWMondrcCvhF9SygPCxg=
X-Google-Smtp-Source: ABdhPJzKwtO53DeNhh9iQnqhR8t9/ARHeZG1VfjmvadcCuq/fttWb+AlepaFcH7YhFWN2dD6QfCjUw==
X-Received: by 2002:a1f:a796:: with SMTP id q144mr2997910vke.19.1609934203750;
        Wed, 06 Jan 2021 03:56:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c902:: with SMTP id t2ls129477vkl.11.gmail; Wed, 06 Jan
 2021 03:56:43 -0800 (PST)
X-Received: by 2002:a1f:9c42:: with SMTP id f63mr3219318vke.10.1609934203234;
        Wed, 06 Jan 2021 03:56:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609934203; cv=none;
        d=google.com; s=arc-20160816;
        b=HzRw1Nl4gFNUBXX2x512Z+gCgZWq+XQImqrD+ZmXL949fBJheslfqzf3YbAy3mIcZ/
         /bUFzZ8gCERYHN4MBVCtDwQJ2Yx4Tng+OzeUADVEQb/TGeOdctFNiB13vEWIeOpYmbsB
         2iaGZnFxav8vaZwOtsChXw6C+LiHyTHNrCXT1PV76JCF9vSXppZqr/bahusJMJZ0ZbXb
         DCxW0h8kwYfB5Xf143AhPXdyei9++zTlWeHamYTy7YRePmTXzzCNuLvpTEPXIfzXHlsT
         v1WLFBB8WDbJ3Wm4ESut80yTCyavjJUag+ibSnJ60R+i6ws3gsVg6dMGBZWhQak8+Fep
         IVhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=XlmroV/vhAwnLKyyy8esKuqejxi3ukZs7nTe2j4Lj+0=;
        b=qdY2GCV4TgoHyKnDDJ7Cdz0VKIWPPKoarl/fybONlGNHnVvU8kwZVl7wK7cdSn8oqe
         n3MC0E7Zw3h1Gm04eLL9kZ3sp5wSkZL0Qps1et6XFrUFaKbE4wW52wTKAsy+By7v1r7X
         BxmU6bmSjJHG0H1E46RicXvL1wB3Q/KAskPHsjmKxSp3HzWUo0Q16vOuApV9jaXNdMYc
         pKuFEUVncwWdpSXFzyuaczBvPuDhuqGHOujnQW6WNZqy3zOYREZO15lEpLxCrhf+BOw7
         C+UsT9tsUcXCbHo0P7w8QgX3qx5S31bSl6o/GCM7q+jjDWTH6A0k0mJhLw7RzmZJnMNA
         NaqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n3si154641uad.0.2021.01.06.03.56.43
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Jan 2021 03:56:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9119211B3;
	Wed,  6 Jan 2021 03:56:42 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E5D573F70D;
	Wed,  6 Jan 2021 03:56:40 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 2/4] arm64: mte: Add asynchronous mode support
Date: Wed,  6 Jan 2021 11:55:17 +0000
Message-Id: <20210106115519.32222-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.29.2
In-Reply-To: <20210106115519.32222-1-vincenzo.frascino@arm.com>
References: <20210106115519.32222-1-vincenzo.frascino@arm.com>
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
Cc: Will Deacon <will.deacon@arm.com>
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
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210106115519.32222-3-vincenzo.frascino%40arm.com.
