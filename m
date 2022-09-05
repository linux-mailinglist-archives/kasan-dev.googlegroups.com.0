Return-Path: <kasan-dev+bncBAABB6WL3GMAMGQEL35XQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1050F5ADAC4
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:11:23 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id q32-20020a05640224a000b004462f105fa9sf6289657eda.4
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:11:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412282; cv=pass;
        d=google.com; s=arc-20160816;
        b=HOrqldt5FQm26BYKeBWnP8RVtFdWoVfMGONeNzopSsle89SoCdPuWoeFMVsIGQdTEF
         5KXAcd3mdvmVQFL48Tzpk+JT0BIEtFCccLmN5MMLddZRON43iX+mzh2wrbtzaoppVdBL
         cEekeq9aYHkPx54GclcxOhh/LTSl/NF94Nn74HaHGCyzd6ORVW2eMMnOU2luKRTGHOCk
         sxDJxW9gE4VJTnOfbHrXN5qg8HoNeW781wHmlwN3HkIPM1FulyWVkP2Usg/4AtkI28F5
         +y3AtakNAvj953NUrcepmJQ/pYb+aDvTdVgJcUQyn+bJ0VNRGInybRzC2VqWG3drCKRf
         bhSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r0+/45HbdO1LcHp/V6+WWNv5IZlIJvRQTX628dR4kw8=;
        b=DLZiH+jfyI2+APzD7A/sqsFsr8r45ry4NVYyOJ34Kk7kfofWx5bzFg687vS8UR5YXN
         zTroCK1i53V3oINc9VVc3/c5XLfHX5OwD4M9J/sIOnZEL5qasremIhDXjyYPn+5ybpmI
         CW3tKMsE7aUN33xS+cVEHS+Q26oUZySXiKtguwEMkKV6XEU/1riScDr7qAf9t/syLRuf
         icm7ARndJg3RvNbhx/VMvNnju/o4z1glmV4oewNEyOHXhbGEeysmICDRJzWEVAldX2LS
         Ni8QUvGjmfZeOkoCu91icn4TykhDaFJKM4l+Pn4H6T/RkjNwJt7K40WmT9iYmcTWI/uk
         aMZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZeoiyJr1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=r0+/45HbdO1LcHp/V6+WWNv5IZlIJvRQTX628dR4kw8=;
        b=WVpYAKkgg5edSz12meV9xutmcTKM7AGGs1g8u3w3wYu1HsjazntC6o8DKoJAsyKEcH
         SxVbwD/q7oU+zDgWlCnPuDStn9/z+oycfGnCy5otJaRDRV2LOBS8nCzkoLsk/wtKEzJA
         Oph/KBozK/ulskf/HX9DNh5G5QO8khaQHd8nQu8vXj7dfkDJCGeX3OmnqUFb15mJonOh
         JiJPa3LehfF7L7mgJWFXIul+M8nmVZhzj3cb87XGFWqMXI2cf4eOMCzA1Xt6YUhCgHVD
         7nXUFFLid7TYYxWchCdgRVnNAwZ5P7lFr8v7QZpTOTe4JxFsOvPzOnTOi5vbGXW49S9W
         dL8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=r0+/45HbdO1LcHp/V6+WWNv5IZlIJvRQTX628dR4kw8=;
        b=HNDNU1uOGYr1o+zW9nbDvwelcFuHHXAfWIrLh0MQPU9t28knIm5rrFuOOamFETXOHZ
         RqC8+kRgNohWSrd/Ag0OoHuoIZz9pe+sDJINIJ26riFNxOOvgTp1qw4FjTulhZhuVePk
         u6BquKAAUPLXqsbxwPue/7+3yTgT80TXdo9bf0FSQwqkey5t5B35Lzr6fsapBnjGmcS/
         l1eaju+JUJ1F3XZhkDuU8YdhD1k8TJJxS3gE25FFBY03ffkFLwEo92AV/VftJ4IJWcIA
         Xymo9kXoF2eDUFpP8jxnXGlcJYYuuxX1PpUgwVX03BJEBDB4LUjgDNs6i/3YYpF0QeW+
         ubRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3UxyzrYobeOBtrFyhcZJi84aJtkim1eC5/RQDe2Fvzj6805gsu
	pJZQayxbCZO1Noy7Q+dqcWw=
X-Google-Smtp-Source: AA6agR5CrH/2e6BNwl/zib1RbWQ0HwUYS/1g7YHb7XRAcDfFj/RSBcdYcghKB13nl6mJB6NbZ0DGvg==
X-Received: by 2002:a05:6402:240a:b0:446:39d9:95d7 with SMTP id t10-20020a056402240a00b0044639d995d7mr45854524eda.253.1662412282745;
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:880f:b0:73d:afe3:ffd9 with SMTP id
 zh15-20020a170906880f00b0073dafe3ffd9ls3995247ejb.10.-pod-prod-gmail; Mon, 05
 Sep 2022 14:11:22 -0700 (PDT)
X-Received: by 2002:a17:906:cc12:b0:741:64ed:125a with SMTP id ml18-20020a170906cc1200b0074164ed125amr28784657ejb.713.1662412282024;
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412282; cv=none;
        d=google.com; s=arc-20160816;
        b=eeVx39teMA+bP0+nkJ+wdAsmdKK5AJ4jhyhvRFSgIhwoJoxNZ1+zb1IqDnyq9aZU+V
         QRBBMrdKMzjRtClUpOaekk00RiyTee6YdYbd7domn06FUrC135VtXWg0qDKdZ2ObcU8c
         KVs+q4ZHuUNINrWbPCuCxsASA17EMA/5OPwFL69QGD98dZZO0CJs1oCQ9Wu4ruwS9k8r
         Yzawko+EJSwqym4+ajsRv5AES0di0AeHUNeHlQgHB+Z+Sys8mXkwqLB6ANnnBkkNKjQK
         ZhDeq7nxmo4Ra9MGQz1sMP3EsBj2pmAEAHqEK4rLbt+51M3YtK5AK/Luz1dWLP6jG3Jl
         +zpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=T0DFoi3F6F/yHkLbxOafy4/ej0Np4BxwTKaKbEY2PpY=;
        b=r8afyk4s8mrirfra3ARyF9NY9v3192IO4l++SXoSICAv5ursN5FULrRO8w8Gm0/veA
         29xwgTlmvHyAY9z6RqGYEpxQrwAiucw1unaNlyKij8hzVBbXF+MfJ1LgM+ymStGgji++
         52vNEBXefh0h4E4fVfw4gPGyduOOF4IkOvKSTZ5fBNj1Q6iWFB1vk8OPC2NPAjrCD/Mk
         SjlYYT/I8MEceAE4fom1lRzaY/5R1388Rkz1u6LcrBmw8A8/3cGpnHgx1FokeD3Nunl8
         lmut48HYwizu3Nz0CqeBbAIdsRaVo64Der4jkPRiaWLaqT6ZV80Q96mIHfoE1K1HK8sE
         XLEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZeoiyJr1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id og36-20020a1709071de400b007415240d93dsi449765ejc.2.2022.09.05.14.11.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:11:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 33/34] kasan: better identify bug types for tag-based modes
Date: Mon,  5 Sep 2022 23:05:48 +0200
Message-Id: <13ce7fa07d9d995caedd1439dfae4d51401842f2.1662411800.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZeoiyJr1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Identify the bug type for the tag-based modes based on the stack trace
entries found in the stack ring.

If a free entry is found first (meaning that it was added last), mark the
bug as use-after-free. If an alloc entry is found first, mark the bug as
slab-out-of-bounds. Otherwise, assign the common bug type.

This change returns the functionalify of the previously dropped
CONFIG_KASAN_TAGS_IDENTIFY.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report_tags.c | 25 +++++++++++++++++++++----
 1 file changed, 21 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 57f7355377f1..d3510424d29b 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -10,7 +10,7 @@
 
 extern struct kasan_stack_ring stack_ring;
 
-static const char *get_bug_type(struct kasan_report_info *info)
+static const char *get_common_bug_type(struct kasan_report_info *info)
 {
 	/*
 	 * If access_size is a negative number, then it has reason to be
@@ -37,9 +37,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 	bool is_free;
 	bool alloc_found = false, free_found = false;
 
-	info->bug_type = get_bug_type(info);
-
-	if (!info->cache || !info->object)
+	if (!info->cache || !info->object) {
+		info->bug_type = get_common_bug_type(info);
 		return;
 	}
 
@@ -84,6 +83,13 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->free_track.pid = pid;
 			info->free_track.stack = stack;
 			free_found = true;
+
+			/*
+			 * If a free entry is found first, the bug is likely
+			 * a use-after-free.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "use-after-free";
 		} else {
 			/* Second alloc of the same object. Give up. */
 			if (alloc_found)
@@ -92,8 +98,19 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 			info->alloc_track.pid = pid;
 			info->alloc_track.stack = stack;
 			alloc_found = true;
+
+			/*
+			 * If an alloc entry is found first, the bug is likely
+			 * an out-of-bounds.
+			 */
+			if (!info->bug_type)
+				info->bug_type = "slab-out-of-bounds";
 		}
 	}
 
 	write_unlock_irqrestore(&stack_ring.lock, flags);
+
+	/* Assign the common bug type if no entries were found. */
+	if (!info->bug_type)
+		info->bug_type = get_common_bug_type(info);
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/13ce7fa07d9d995caedd1439dfae4d51401842f2.1662411800.git.andreyknvl%40google.com.
