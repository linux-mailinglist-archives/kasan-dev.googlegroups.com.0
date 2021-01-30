Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBYE522AAMGQEEI6XAJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA0353096E9
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:49 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id q7sf5758520qkn.7
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025569; cv=pass;
        d=google.com; s=arc-20160816;
        b=SQ76xdo0QjNn5yTE5lAM23QFPEt+iI+HMDRwSEVnWFjvaq9kU4+s48uCexjwL/YpM6
         32MA78qtiWzWZH+UR5Y5KfR/RCtJHE5uyayOMTGtvFs1n0lGuE4HFI63wPl0N5aw/gHK
         TSaSurTFpbMWFbS0DHQGJ52nbbPB3QJ6mg34VDuC76DuHr/cvp9+JLF0WYVbJ/u4p3Pm
         nq1qKZJ9rnpyN7qKjy196ncQfnLmMUU3nVjWKPiwo42Gi5H2BhSeuEKSrBhHITp9/vcj
         WNQLu3mse0rPvtYv3qNkAt0c+seEQFfsVD98OYc/QmmZe2gF6S7rEyAfA7VomQC5VzSv
         Wicg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+xtUKdAKxxu9+OE/aJ4AXKadHJyD7wM3qEZS7YT8q8k=;
        b=NK6PcoLQkYkf5SlfxivHX3NAR40AwuLs+WMtcMwuZTYEYybkDyzb6gUoHAvAb63RBr
         MXeb9k0Leo1TEAnn3xH+H+3ZvJbgQyC/6q9Ge+KXxL/8sYkgLhJFm9+BDyJKxEIT2h0l
         vR+PRDxaMBmkvYlLVEbn/Muo+rYwtiUC4GIdQ59fT5yR1E3BCSzhQPO3S5Lv65pzn/so
         f9O9nBQVcKxj4xKVwz7/13S0LaacNy11KsEjfmP94kftgVAyUOl5Ar9rUJq3dUBohlPe
         2GFXDQdZGBDfYmK4hwLjZrw6boVg3zq7jSoqeuS2FDrZSn3E/5qJbZd8Meq8/1EVfp3g
         jrsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+xtUKdAKxxu9+OE/aJ4AXKadHJyD7wM3qEZS7YT8q8k=;
        b=EdhBxC+DF0HSzTk/MiScMAdnPnopUdz437gDjiuUfut/yT1jojNX1WYRNIIABdh5Um
         V+ZOYz+gUbP89m7w/YES9kPgwgxUFJDz4rFRhjNIqVm4FViwtGOjPOalvPLTX/04vs8T
         ZowkZP1k3zFk+3F+5BjCCc2aUv9fjI2vyIg/4ZLdelbV/E1m8Js+pDgCNqL/cccu/1vv
         caNU+E+Pei0wGblR0uqxAOnMeKlNYQrVEr/Xq+0YZ14Bn+dwox81xPDkQrDz8yaydMJc
         Y2xTUDBPDFGFsl7zvHwXdGYtax1y1Po3LucJhwKOIySlJVoOZtgZgiQ4Lw6IagUYuMjL
         vPuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+xtUKdAKxxu9+OE/aJ4AXKadHJyD7wM3qEZS7YT8q8k=;
        b=gspIwPe+sSvjsJk2nfOf8h7P4ptxnLGxdM7uxWk8eurWee6gA1RH06P+7atb/+q8I1
         ESETydwIBc7SAq2UtUtNBULqJZK+mWT4zwTc8KauLojvJ8hc7+BG0EwGD8nUD6v8SMKL
         dT6ZQCA8LN57okTR20g8tmOIpzXtnBbbjrvDyDCvLmZ0xJBMrSjl5t1uG9hFRtK1V0Iq
         4EIxA7vguInyduUudk7lEcJGYw7iJTAvD42cQrdnNkYNJNEO//uU+ikUM1vTup15oWbI
         fOpKHUPamSt1pIQ8D6lGKU4qHZgvWaqPeKF7c/di1cfN65QlwCeMidn982HUyz9QUacg
         2jIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IIZE7+BEAFObADA4Z8geEpwxQ1Vp558DAhl8ebr3xzoZYKZA+
	bB4LmnmcHBaEbDtQk9NAUFU=
X-Google-Smtp-Source: ABdhPJzhHx0jNyPsRyUBsLZDb8DJBNhIU/jLAgmj+eAPmOqtjU6P2o6Xea68U322EOk67jmYiJFAAQ==
X-Received: by 2002:a37:d2c7:: with SMTP id f190mr9088251qkj.95.1612025568959;
        Sat, 30 Jan 2021 08:52:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:a19:: with SMTP id i25ls5654492qka.2.gmail; Sat, 30
 Jan 2021 08:52:48 -0800 (PST)
X-Received: by 2002:a37:9bcb:: with SMTP id d194mr9266568qke.217.1612025568644;
        Sat, 30 Jan 2021 08:52:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025568; cv=none;
        d=google.com; s=arc-20160816;
        b=wqC73Kamp+8NVeDGnpSeg6oxi3EyMDojLuvNyiDRkvPRLNeb4gGC1iXeqPPmSWzR0o
         zudtI5+rv3Qdsc3ZJZZuzPbjUvrDc3ua76pjnvaBGVW9as9Tl8DUyr/whU24KQsfLQUa
         KtSgA53SP3Fh5W7hndY0i4iTt1Az8izYoZo9m2gPhy0ckbNOu/YafRHe0boLmbFTMaEb
         QzkC9senM4RvMj1aWnhxs89j0WoT63yZDsxM+f2AfqZHkJHoAW3SrR6aYZTRFS6AVPTs
         xIVBRYiPHYSqBhHRPfRu2OveLEnbDtqKC7cqdrWGxB2J81Lvj+OW7PUlfhwEQTA+XxeU
         KQ5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=aCRe42nt/ymd1Lh+WKNt4INcVf/2fK5xQuuwV/2WwAU=;
        b=lUTpFV22SBfEVGeHwpmMDVSvHUy789keN1TjbyihJE5NZN4UL0Dxw16dwfobNGXCr+
         hNjX3PVADYJftXPwCN0SWFo/3BQ7lJiM179btN1ggNQoBdexxIvjmfglRLuP/c7yjlTi
         S7Agb7ip5kTMpmo4mWzZnilq1bB+x4ELEFwbiiQIi0iBPo+G9VvZepsBoVQGKAKhKvWn
         BimfgMSk9bfnnO9So5l8XIumzBLcWt/NYrUoev1/DyATWrFhpTDo/HBI3uTHy3LYMa6I
         Yy3sYH6bqzvy+rOLVN68EKvjI8C0HRfalJEbd+at+IocVSebW9zcD/6nY92DMRTEu0tr
         l1ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f10si414413qko.5.2021.01.30.08.52.48
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:48 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A88C9147A;
	Sat, 30 Jan 2021 08:52:47 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BBD053F73D;
	Sat, 30 Jan 2021 08:52:45 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v11 3/5] kasan: Add report for async mode
Date: Sat, 30 Jan 2021 16:52:23 +0000
Message-Id: <20210130165225.54047-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-4-vincenzo.frascino%40arm.com.
