Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5M4SWAQMGQE62T5CIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 10F63318EB4
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 16:34:15 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id h17sf6322414ila.12
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Feb 2021 07:34:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613057654; cv=pass;
        d=google.com; s=arc-20160816;
        b=amgjQxck1l+cRAkk+1WhHov/pn+6yNC60rfFPiR4Eo5L+ea7j3zU1hTAGJLynUTJd6
         ry3g7AWv2lOPg5RZ5JazVi2hBZySHeu/QrMDUkoERmTySIu7Yo8fsEGVpm45nbyM29sj
         4vJ7pkQ2I+vJIya2vnUXTd/v5gXoPFrRGP7HNxV943aI/hnoJqdxxu2URFGn2sW3j7i3
         0YzeZIhWjeEbPPu2Oc9S5g5eF5Ng/ienX+y5h8eOPoWanj7tp56mC+8QCQ3w4PX0ceTS
         DsEMECYVvMF8cz4IbBegCitCQXUPSuUBJ44bkvzQnzZ/2QVIU1xgfzXrnFe2UgNAU7tb
         afig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ArLcLBselRkb8srcUe0VSB/FgiaSuUrqpfJtgVxOhTo=;
        b=OBwJ1t5DYS5BWH5eNFh2BndX/Pl6LKCtBIbHVqWvEFerOCqRTibyHrede5Z4BKCmo3
         cB0m0Ineo1aeKQVwXjQndqHuJVkpfhkDuEUBAeR2Em/qJOSU//mKgFPJZjfk8YSTDLpE
         jkId3x+21VteX/PdWsyrX5O+imxy3JNkRDN9y56egZ1AZb872JQrbwdH7eoxZUVfVR3Q
         svtBLjiVwmWdP6/GAgtwZs1HTYm46WBJN/+TOjxI1vHMxcGY8pcT66sQM1PuOmgQwRmi
         vDIVkU7lx6/zRIXRvkrl8zCw0y7TovVyHuI6OD05lsYn6whcF2xwhpn011A0ybtkzV/b
         SF/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ArLcLBselRkb8srcUe0VSB/FgiaSuUrqpfJtgVxOhTo=;
        b=QtmMEHQjDsNiTnUELccGYsQD4l+DSp3M2T/Ig3DuZ1+L1rnXPK+hffT+LBmYcN7Rp7
         NbCQBEV36jnzmrbhkdbCM+Ho5S4sgnShqVLPBaAKt1FeIcA1QfKSuZ9b2g0gNnK0wFS1
         rrpBQc7ucblyAYetmZDtQSmVNFLXSCAHDEeOwwdChzYvagsJgLoAKPn8Y8dqBrtmfig1
         9hGWzPGuYu2sOwbeqnQYTbKwj6DhIggtXLCxRBlN8gMfAQErmhRcuamysxjhbxjgudB0
         mtdUNrcEksjqrSGaVvi6Odizdmr4lT276cMixK8EaSih/zNwm4p43CM6cHtzjke/YvVA
         x8+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ArLcLBselRkb8srcUe0VSB/FgiaSuUrqpfJtgVxOhTo=;
        b=JNsXLQVWmNmRFGRg9xwuC/rP3OyWrQgcpxd206eeo51lc1bZi4/M7ftJH1BO3jgTue
         CpM2HQtmMmYv7ZXBzdzZz36BdKwEqQ+ociaDJs03iD0KqrxSAOZzEQyj1vA60O1lQRpz
         JytjFXXtwAj6+/9UYtxWy7dsM6YOWEZG6ShK6rDX6LA2BUlAQRAN914fq/Effb0uqsli
         H4ibOxuzIxyuBGpGUjicXexxV9fJJoA1HxkwwvsHF/Xm6XLr7YD+K9DURxQkzocVbo1U
         aqzCeZ2mtQwslrgs59iBuVnz8CcyudVpZgwKsbTq4MYVWWmI8R81Ez750205HVdqfQGC
         YzPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UqGH4gdgAgRTKNP+9NUh4G7t2UN/a8Ef2YvVFE937uD3snksR
	NJ/7X6Jf74/uwa5OdlRCAKg=
X-Google-Smtp-Source: ABdhPJwGfILCwgVmcEu4nWAvbtmUN9b1wfbybXN1+IFa3AoT3QindWiTYyYcf9hCn/lvRgKKnyosCQ==
X-Received: by 2002:a92:c7b0:: with SMTP id f16mr6135619ilk.162.1613057654082;
        Thu, 11 Feb 2021 07:34:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1687:: with SMTP id f7ls852087jat.11.gmail; Thu, 11
 Feb 2021 07:34:13 -0800 (PST)
X-Received: by 2002:a02:b70d:: with SMTP id g13mr9218801jam.61.1613057653524;
        Thu, 11 Feb 2021 07:34:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613057653; cv=none;
        d=google.com; s=arc-20160816;
        b=Bhnu0arykQIWY8zFNlbbAO3dQf2Z8wXaS7D4dFTZ9Jr75Uz1XHI3ZJ1laO7Bhlu2dg
         SOvzVKt5mwJDxZ8wpQ1ajeKjVkizpRSZyvK6gtEEasYuTSIfY3A7Vk01/y0Zs/hXpviT
         cBG5cm6pM+GIa8lc37ZBRUZHFmL16C7J1Eu+LWq3q17z/LAUpOHeceGVinZl7eKTFY8s
         UsB+sizL8aPEOZ+2t2UM4FvlPnXMgspE9MUNE5/1s61tAy+Z+7nYMOOHQrknaIRxrCuS
         298wkh7+qtUW7BBT+LdZi1FleVIQ5hmv8ymqlTUA692sgXNo5AjJGYuZohJacOrLLxrh
         yNWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=NQROjo202rhYJoAIPOihP/5EOJxg81PnNRiEQw053Bs=;
        b=LrEWjAmWSn3yQYCCfq+VHLFO6sa6D2IlOlIc12TM2F8UyDzpifUJ/QYOv8rUOkOrFd
         lFha0iFf7BNLG66HR0ZLN7gS8GcTmyqwyptpEzJKs4EUFG0MAJe85G5y/1YAm6WvUcWZ
         zQdYVtpel3O56+/XSmnb6Pa6L8y+f1EIcpfviA68wklP2NWoQJgYhauH2RhYsblZNyil
         tqvEFpclLJs+T4v1jTMv1GI5TCSN0Eg4F+2lJCJgO/8BcpY8qyUaL+O7Xf4U6L+hT2+Y
         sK25xOGhJm6hLvDa/TAQuz4yUFdfYTi74fD1CemaMC9B/cHlOAk6lVrvMqlHt5/VWRXP
         X5UQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f11si352359iov.1.2021.02.11.07.34.13
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Feb 2021 07:34:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E177B139F;
	Thu, 11 Feb 2021 07:34:12 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id F36DA3F73D;
	Thu, 11 Feb 2021 07:34:10 -0800 (PST)
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
Subject: [PATCH v13 3/7] kasan: Add report for async mode
Date: Thu, 11 Feb 2021 15:33:49 +0000
Message-Id: <20210211153353.29094-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210211153353.29094-1-vincenzo.frascino@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
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
index 14f72ec96492..d53ea3c047bc 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -376,6 +376,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210211153353.29094-4-vincenzo.frascino%40arm.com.
