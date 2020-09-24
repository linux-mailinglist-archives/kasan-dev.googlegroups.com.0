Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFWGWT5QKGQEZ645M6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DF1277BF0
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:07 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id w22sf55377lfl.13
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987927; cv=pass;
        d=google.com; s=arc-20160816;
        b=vIot/eNlqP91XwxqPiSgZdk4/J8yGeWxuX26MAwAow9WVyx5j9ThoazY51cOqxE/uX
         GBUqWA78Eg+kyhU6XDRP8TQ4aHUmz9ANkgLAdBWiEYkLxGjIv+/Ob+MuyTyRSm1rWZRr
         hXZDKijgqXVCfzXn3UXDtcmCN/Ixuh8xXUxW7NyaZxwOJMHIGa5N3PlMWFmcpNWHfdhF
         xOpQQxPD5Ankrf/eTwPrq/fwXfzo88c3TvTNp9Fq/acNEyHBBcim6KJacB6IARfE98Zj
         al2obmNplObVpPzCk3EAisCDh9MlbDkC/3NIInJJWddGIzBlKULYH9DuPiHnwl1BsTws
         kd8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=HW9ox1Sy7PmkVKvwUp0zc0NeaQjhetNbAooVQgI3bNY=;
        b=viz6WT39w+kAsKX5RRtpdC84P0pzyICp3LjHNZQRySRcggDDt8fBVNNDcQIVnCCpxF
         QLwKYBuHcQUdqfHMUxo6yVHFxB56XiUDs4y6C7dubdEQETckcD1NKCcxw8XInmbbwwUy
         +gO0cPyBszqJriE5xI0eNveMs2XYnGc/US3U3qx+/8K/mvSbCsIST5tmjm0WHAXyqPR4
         oLm1FjOFiTx4lDc6dVlZ92Se7HkFfaqhogTCSk+M76Ux3FC0Sf5p6myazy6Rq3ESY5YX
         j25YRO3Bw8lfooWz9JC1H+qCVpdqyYce5AzGdyRwfHIjqEyne1gzTDbIEUkOSUsO/0cl
         EErw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aE6bW7ZD;
       spf=pass (google.com: domain of 3fsntxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FSNtXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HW9ox1Sy7PmkVKvwUp0zc0NeaQjhetNbAooVQgI3bNY=;
        b=tHuoY7nz0D4qggG8PMh/34yyC8B9EU51maZpY3lagqCE77dK74j69dPpaUS/8rQTVV
         CVvh3S3FhK3gUEydlp3IN5CXOWrz//OGaJT8j/VJQHqqGk324L3IZE31vsugWiFs8Hnv
         Wjt2xZj1k4Pp8Vxr867xNZ1/3XXfk9xE9Ne5lMDJlf2TU2dBY6HFmJSp9hnvKRoyUXuB
         v1OOLUtnGE4i1Gh5WPPBvm/wyMThWfK6zYm2EQDl34jrsbc9T1Oza4/glA+tBc57OjjR
         ToarO/ySATyn0HxX9QeEV1vz8cMi+Cal7pIE+2eSZZgxHtuU9s/6v9is4uQTN31mVoEs
         cEPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HW9ox1Sy7PmkVKvwUp0zc0NeaQjhetNbAooVQgI3bNY=;
        b=QNyAqWLGx0qlfpVuGN9wFUXebLrWQaMB0yX6MUknqS4x9J2RsBCPR/I2xfLvWi3kKf
         a+GbREzZNeX/RooLV2JOVYOrHEdel/Y8D9/aL6Dir7uTgCphXeWLrm/t39sK64IH3cws
         L/6PNUS51ThEzZqmQTWP3mdmr3zvDwicMtdICBw53v6L72agQvINtQhmX0Y/I8n7f8ov
         djUIX4+zndFPqNXb3pGSmhq84E/fEXDY7maRrTIXP+zZ33V6p0Pi43yjZnhQYiLQVrcN
         4Wg/TPNn8L8wY5TmL1R2q3QkWyx0KcX5UjCFn8AxVcryM8FSTj0tcRls7txTK9WaSjA0
         DJjw==
X-Gm-Message-State: AOAM5325Q/GQ4sqVxuLAkhm87eCg2TpUehPveHbhORc9Mc/hnPEGr07g
	2meCxOfWNrLZmDvjgtf8uz0=
X-Google-Smtp-Source: ABdhPJzRRfL2mgCrvzK0Pa4tCoQO2S35oFxXKYMZm2hYTJqXSdgZMdvJ4s8UwLaN/SeNnG8kMAJ+kQ==
X-Received: by 2002:a05:651c:104:: with SMTP id a4mr403125ljb.273.1600987926919;
        Thu, 24 Sep 2020 15:52:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:c7c8:: with SMTP id x191ls256768lff.0.gmail; Thu, 24 Sep
 2020 15:52:06 -0700 (PDT)
X-Received: by 2002:ac2:5de8:: with SMTP id z8mr383284lfq.204.1600987926049;
        Thu, 24 Sep 2020 15:52:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987926; cv=none;
        d=google.com; s=arc-20160816;
        b=Wi5c+6P12Lo/dPtobjQ0nK8dpGxRwXlK3whv3ibT38BEWC3mUoacl4gSQ9QvNFC4J1
         koOUpEaI38G5G1ssDFbRRe8aPY++AQvviBan6cgD9O16GunyrlAqtNB7czy6EZxNNOx4
         tRIi5s2kmroMh/2XpYSELJrUz100YLXjluIEE3NustzCiD2J/sb7gj8CiY1A+kSzKlOV
         o9Gb0LdtO+cF6F1C8yV6sCmyy5ivsNYwpdBhemauvU3kvLuNGRmiFXkoRNF0NlUZEH9Q
         BfRpnTtm69rgSDHbSAoe3s9qAz/kmF6DgEYHBtWkkzedA8WecnRXAE2Y2F8vp0IXADhW
         4MPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ISpXqi6MEt5kdGDveTeyFeZjiJg33x31XXLtNJOX90w=;
        b=pjZfjVoUbhXRUTZqDJ2t59uBw7+O9RFIAaK+SSDNdZD3es5QnQTgfRW4UEqn4ulJY3
         ikzHf66rDxvjbRPXeaK/GIPtJh7iJgVqYptKSFFLMVVvSWCjJ4067olylE4ZMq6mHWTK
         H1wxEaeP0sMpdrgEigOPda2qAvX9ckYyQw+3c7RnCD5APB7VQeE1ymmg2PY9HMzrEasn
         +/soTIf++UBtKXsRCTxF1KuqaesF0rtlIa56yGlRivyGk0QNqxnd5CvZr/LXokkVIiaY
         WFalopubcoQz3gpuEP8lMYEwpDThPG7SedjdQYg5tqqplbR2bZ0lDFtuE8b/BkD4c6RX
         asUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aE6bW7ZD;
       spf=pass (google.com: domain of 3fsntxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FSNtXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 11si19768lfl.4.2020.09.24.15.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fsntxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id y18so276250wma.4
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:06 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:4d0c:: with SMTP id
 o12mr202wmh.0.1600987925110; Thu, 24 Sep 2020 15:52:05 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:37 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <733e94d7368b54473b242bb6a38e421cf459c9ad.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 30/39] arm64: kasan: Enable TBI EL1
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aE6bW7ZD;       spf=pass
 (google.com: domain of 3fsntxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3FSNtXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) that is
built on top of the Top Byte Ignore (TBI) feature.

Enable in-kernel TBI when CONFIG_KASAN_HW_TAGS is turned on by enabling
the TCR_TBI1 bit in proc.S.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
Change-Id: I91944903bc9c9c9044f0d50e74bcd6b9971d21ff
---
 arch/arm64/mm/proc.S | 13 ++++++++++---
 1 file changed, 10 insertions(+), 3 deletions(-)

diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 12ba98bc3b3f..dce06e553c7c 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -40,9 +40,13 @@
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
 #ifdef CONFIG_KASAN_SW_TAGS
-#define TCR_KASAN_FLAGS TCR_TBI1
+#define TCR_KASAN_SW_FLAGS TCR_TBI1
 #else
-#define TCR_KASAN_FLAGS 0
+#define TCR_KASAN_SW_FLAGS 0
+#endif
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define TCR_KASAN_HW_FLAGS TCR_TBI1
 #endif
 
 /*
@@ -454,6 +458,9 @@ SYM_FUNC_START(__cpu_setup)
 
 	/* set the TCR_EL1 bits */
 	orr	mte_tcr, mte_tcr, #SYS_TCR_EL1_TCMA1
+#ifdef CONFIG_KASAN_HW_TAGS
+	orr	mte_tcr, mte_tcr, #TCR_KASAN_HW_FLAGS
+#endif
 1:
 #endif
 	msr	mair_el1, x5
@@ -463,7 +470,7 @@ SYM_FUNC_START(__cpu_setup)
 	 */
 	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
 			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
-			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
+			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
 #ifdef CONFIG_ARM64_MTE
 	orr	x10, x10, mte_tcr
 	.unreq	mte_tcr
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/733e94d7368b54473b242bb6a38e421cf459c9ad.1600987622.git.andreyknvl%40google.com.
