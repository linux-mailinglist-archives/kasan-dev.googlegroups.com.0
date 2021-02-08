Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBQW2QWAQMGQE4ATG5DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 33C2B313A2D
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 17:56:36 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id s4sf12871403ilv.23
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 08:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612803395; cv=pass;
        d=google.com; s=arc-20160816;
        b=nuAbSCMhOPKNlJB3oJK8+wB7qo8PNdQtcbFUMEnPh/dOmVwQrN/+AQx0n0PjVk2/4D
         ZiwekKXPm4Td9dfOMGS9ZUE1sWxZ0PZBsuUDtBFsfQZQaTpJUFh8keRiJo+e+8MdkPo7
         bPtxf34lwcaS0s507hq+FBnXua1pPal7SQGl8qY+SyR+RAOEmuLCPWuYvS4BadhsuD9M
         UeC8LV1Gbw8IEyINjxAiHyUDSDy93xeOL95dq/SRFEaXwVHQBZScBuThWVehoJQ3GLhg
         PC7E2PiW94sdFgcOlbloaOYtIOEi+Shmoqdctf+ArwLpUbNYePfXC4h1Mm3aoUhyNLj7
         BLTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FTtMyDDVCXiEBGInYxvsZIr2vnYICSRnYcQ4+lGkHyM=;
        b=jfLH/KbQ1GR6gfOzFv9YKL5J+0N44OtF0qVrME/s+zDwjcjFLAvuMRsMxNWn0YgI51
         /PEq5RqaqihB9/vOxlvGaIxaQR6B/ovBLpjOAgjyJqEMFTCxQuHUdQSjT3l0ASwAO4IA
         aT3tVlqNiM4ZyuojMDOuNoOpgAewhNGcn49q9IBSnUQWe5CGfE8yjDEmsEP8iGkH0bk1
         fO5ffgQBJ3fvXsRHzklM3S4vPkuAgNMp3PqdAbhF4VJ7qn0HN7ox/5nbpIWlFqZufJhf
         kmtg2DybaoiZCVQKUUEiGGzyd+hxQTH3TjXXlBULSvb5oisTPWyXNwBARvTcOg9ZtxE7
         pydg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FTtMyDDVCXiEBGInYxvsZIr2vnYICSRnYcQ4+lGkHyM=;
        b=fSBm7K/R7fyh9x3fqxlccZ0HSNW1JcGPbZAToNgEW1YOHrNtMB9/bJT+esqVmqUUXq
         NadPyZ1fsnohLBg9kPpr+3Mnk3uB2Sg9SU5Hey+0jPaH3vucT4FqrQ5iAqEALIKX2Oyo
         FyltahIu7tQF4c/BPZmc/o9L6cmumvNSV8nrPt8cN1JJF39sPPIrs4XpEaP+WDKYLqKL
         KluYXdfRSgwnefn8aBn6W0q4kA4SKhVj+KxXPCu3dbmNc7CeyRwW7qm7Q4XCjhQ9lvG/
         GgyhpgCPldcml/LWT0IPfx2mcJy2rcV8KqjccPMXFAsPkE/Z45uKHHFs1QjmZvmrW68T
         DiFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FTtMyDDVCXiEBGInYxvsZIr2vnYICSRnYcQ4+lGkHyM=;
        b=k82yY5VMF0zDBZms6hNVQRiOgl3bZpvO+pDkVEhrDpOs5BWjiDuL3HlRX9IqC0R4Kt
         oCP1+I6KNDnOrE/AEPKN6zNExO5Np/5XXvI3fQ/9ChqDWly+eIAz+e9SJE69RblBqZaA
         TjWpw6Qb7WglFg+07E5aZ8PDWSUdRsFfwyKJDH6uBLpN8HBJTbE136/nEfpV1j8vu4l5
         hJ1M3eoGi+95vnvI/btBrAx/lPiboklQo4hCnDye9d/tfiK+q6fgjYj66Vvt0HM/h+PP
         gf4ItAEk+gmLjUTw5SxeAQY/f2QNF4MVY/GNo9eG8w2JLlWIXZbCkvCoqG5P7NkZbPO0
         KUlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZeyM52UaOrdGq7kwfM+C9ct+RZpYOH8S66MYbmR5IQG5oylit
	wyZ/D/NUZ7zVLHJHly3RXZw=
X-Google-Smtp-Source: ABdhPJxPlue4T6P/O1TSiaE5BBUoRppUNVoy9+FFdU4WoTjHedr5bBzVkonjvqZZP5IBnaIrcujOWQ==
X-Received: by 2002:a92:dccc:: with SMTP id b12mr16077360ilr.86.1612803394841;
        Mon, 08 Feb 2021 08:56:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2195:: with SMTP id j21ls4197112ila.4.gmail; Mon,
 08 Feb 2021 08:56:34 -0800 (PST)
X-Received: by 2002:a05:6e02:dc8:: with SMTP id l8mr16694238ilj.174.1612803394432;
        Mon, 08 Feb 2021 08:56:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612803394; cv=none;
        d=google.com; s=arc-20160816;
        b=DzhF7vMFKAVuYDReLB2s/nf7cM/pNcqhwr1TVcweYqBtSCNAqM2vN3otzEM6FqTIKS
         kGFU7j85N7/O3hj78Gt3KQ8fNEOP8XeyjeVnR4HpjpQ6KNfNumTCmyEGmU2ug7ia1ADC
         IAh1y0GC/UNCm/bim7RFGdzErdmGbuPbGJ5BUqsDPYfCcwylDuWcqBqA/NUb2TIYrRyA
         Aem1ornNV0SBwCMw8MXNPV2IuFqaZm9I78BZ2YZrSE1c7Ddnt10MK+GXVN6Q/70MEz2p
         o6VBAKXjO4CAYZPn4ZpvxLoy1x4srl/oUeXWOeaskEvCkhIPppqI9+ZPYPxynfRUKVi1
         lA3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=aCRe42nt/ymd1Lh+WKNt4INcVf/2fK5xQuuwV/2WwAU=;
        b=yYyew0nHjAPybY8rkgTxWWQSmccJA6t1+0xk/PZWm3d1ahj00A6266DJqPNOmUQXPx
         my15MTpsWbDob9DS1EgGEqcxZEHz5dOmqlgtwbDpOLn8m9YjLSpErigQmjW4XJxs58aF
         /ut5WD3Dcuoq4T4RksJ6QngtbFbGBnffYpPwOmlthDkHdQ75EEVIrD0Iz3Aj5SDCCabC
         T8j7+3clTqfXortsCPwBSDiYdEtw3qWCtrgSfW5UNevJlfDT0QfBIgC7rx47u+xH2SM1
         3ON749l6ba6EKcM7gcSO9RIB0xUwVOTgEsWjJqPdCnDMtJixPpH4aBWyjlMfD32VPgBv
         fsuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o7si768864ilu.0.2021.02.08.08.56.34
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Feb 2021 08:56:34 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id CB6871042;
	Mon,  8 Feb 2021 08:56:33 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E7CA63F774;
	Mon,  8 Feb 2021 08:56:31 -0800 (PST)
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
Subject: [PATCH v12 3/7] kasan: Add report for async mode
Date: Mon,  8 Feb 2021 16:56:13 +0000
Message-Id: <20210208165617.9977-4-vincenzo.frascino@arm.com>
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/report.c     | 17 ++++++++++++++++-
 2 files changed, 22 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1011e4f30284..6d8f3227c264 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -367,6 +367,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+void kasan_report_async(void);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 87b271206163..f147633f1f2b 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -87,7 +87,8 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+	if (!kasan_flag_async)
+		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
@@ -360,6 +361,20 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags, (unsigned long)object);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	pr_err("\n");
+	dump_stack();
+	end_report(&flags, 0);
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208165617.9977-4-vincenzo.frascino%40arm.com.
