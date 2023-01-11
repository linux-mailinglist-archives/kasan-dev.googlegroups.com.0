Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZEZ7KOQMGQEPYPZQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A595F6658CB
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 11:18:13 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id i13-20020a056512340d00b004b8825890a1sf5437151lfr.1
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Jan 2023 02:18:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673432293; cv=pass;
        d=google.com; s=arc-20160816;
        b=B2IU8ZJdfvU/c6XdYDF4+oyzBv4EDAK0fZLJmivtFxCyIFKCESqIVDY10uGWp9gk0q
         3mvEctZ6DAOu1Iyk+g7IDEsGhx/txigDPVQMziEAx7bl1p23KHK+8qBEOyqcsMbWMwn+
         QqYurIq8y7FsDEhQmaI4/ItvhiV1HmZ9ePVoID12YbjlYQl8AL8WcOitb4CNt//r1UNI
         2w8iDk7/t31keDWeaXUSux54DXizwgRorIjZkbCsu6vzhAqjvVW+9k8iQvABEWBf8m1X
         wwiHREWQKNA6aO3wgAspJGLXzbaVbcnJoGpl0kmqjPnJ5cnsOs++rLrOmwUbcDVoFAlb
         wB9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=WjXJ88qCvxPRkJrEFU6CSltkSCGQ1vrg7osgy2bkFNs=;
        b=MQpNumr6S0LSUHAW3kblIE/SjrkISIqWTBpjf9/5s16ayl+geooO9Xh8Dj61iYPyUg
         oOL3hK2AhcifBuBjd31gQyyRmJZEP0pHDbJbCMLE3jNGQQuDtmOvuFE9sVmpvHWYwS6y
         zqfwL/aAOZSTFKXoWdBS9zUPbClYVPYAu1XguK0tB2eXtUS8Nt+IoyEQ+ZzreEpBajcz
         njncb2AT084Pq/r7izcL4lqUZSe2awiymlm/fRPQ9qCsiB+10mK3Biy80xNDHVETFoNW
         MDspqDz6moYO1+AWsnQ7oJvqE2JRosCtctKDK6fVovevMQmwRTrJY3U0RCRfBwIGHiyp
         +qAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bqqcT2FV;
       spf=pass (google.com: domain of 344y-ywykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=344y-YwYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WjXJ88qCvxPRkJrEFU6CSltkSCGQ1vrg7osgy2bkFNs=;
        b=WcZEXaCwopkV6jLQq1XjkKcr5D621X9upGRvR4Jz5zOfirzHmaMUEGZcRcVrSCHrMc
         plw8nA6S9eZ+5nZiaHDM1aYNbjMVC/EtmZaN+x7Dzq3RatYeUZvOyK6zUotsPhi5wz4o
         UWHxonG6zue/3unPCBImGdO4TkvtT/JZr5QW1U+cMedwD5YBoOMBZWb4U0UBJ6ah6aRE
         V/BJify1pVMFsIakbvOuSodKGdEKqutez3K/OjPsMgz+nFzfyWESaF9FDjjjVm0LKAaQ
         zGepdGaE+QbLR+rckRsF50svbuSxetY0HADQ9anrLkH5FeO4CA5VJ46H0h9KSU/78oeO
         S6jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WjXJ88qCvxPRkJrEFU6CSltkSCGQ1vrg7osgy2bkFNs=;
        b=K57fCMJmZ9H8EJeqdEnKtejJ9/kaqp6LbmyjDHhL1TeRyMNUiK8pfjZuT2h2mB8Hpp
         90YaQchssp6AtLcrzynVqn3T491I76hTJvHypnU75s7exF98It9r0B5mPflPS8Bz3ujv
         y/nqA8LxHRskS4Hjo8Ync3yRUMGXJUOMajMEAmhz5w9iwqvxKC/Z1B11VQCyRQfy2s8D
         81paiKwjf1iE/FnaxofHrqgu77gMu68kziuUz8VYigArc4tQS7O9473GCTYdbMidgU5Y
         OQpY5jjNotlmgKHDHe//uQo2qxnSJ1dofomd88HwPJv2vaJQQmrODXwRf6mF/YtsUzdp
         R9GA==
X-Gm-Message-State: AFqh2kr2bFpSstNCcRDAUBxR7aQOiCyeTwlVBqnxXB93t2LKlqiAi6pB
	86wwkVKKnVBLTbemy7RMzf8=
X-Google-Smtp-Source: AMrXdXsEgICttZKor5PA4wWm/abHyttReBDJO+Wha0tGhDDifWbMxTA1Dd6JPKvf/Zppb37xPi6Qtg==
X-Received: by 2002:ac2:5612:0:b0:4cc:727b:e830 with SMTP id v18-20020ac25612000000b004cc727be830mr1248626lfd.355.1673432292786;
        Wed, 11 Jan 2023 02:18:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3609:0:b0:27a:3eb5:4759 with SMTP id d9-20020a2e3609000000b0027a3eb54759ls2131454lja.0.-pod-prod-gmail;
 Wed, 11 Jan 2023 02:18:11 -0800 (PST)
X-Received: by 2002:a2e:9d45:0:b0:27f:e221:2930 with SMTP id y5-20020a2e9d45000000b0027fe2212930mr9678485ljj.35.1673432291529;
        Wed, 11 Jan 2023 02:18:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673432291; cv=none;
        d=google.com; s=arc-20160816;
        b=NLdEWJbvRCBU55LvSoSl1s5Oa43r2DtiQFnOMpRUtWZOhWm4OlcER+mnYg6cbilsRF
         GpLEMcNG2JlIJS3V+olP9d/XGFW/4kuEiYsr8rf9qS/ogaJGnT2umUng3KxxB+HjmN7O
         t8dNuFAJ/v4VwSMBzUlVub5D3OrGuR1HndS3JLXRiRKsWhHMrKKgqhhotLfMJRP0iagH
         QGhFqtqLiisud/CkCdajoEpjLwl4E1ukpL3UDbdA8iotXCDhmyCwIlMIFzpCrLgrMIcj
         G2qpJc7+PFaYucdwEjZCzIeGum0L10SRXvceXMf89EM+PSUFKbIm7ybqNwH67PZ3e4Wt
         4mTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=PBX6ktcO3Ge095CwaOXemPHb5zPjrq8Ho5XrQZ9Bxvg=;
        b=XNbXWXaacXw8x/JURzt5y1CwCnAPDSKajDLvgy0603ZMaEChkvEBo7Kugn+TsocOIz
         1ls6lCBNfazCMjWn+tAdhbTsdn4BwjqYz4ptcMIlMRIjmyBaqYoH7NbmrIA3ku/HZb6S
         r/MS3NIeM8ZwNxtpoVsUbMKtqKN9UjJ0Cm8EsyTNOZiORiv3XFZi3D2N9PouI683HuH+
         Vp+NRC/1O9cFKAGOD7uMFdfH9OYDeNd1++03nE4lE5913rgHFW7z5VDmZDzI1wGwCijU
         fC+jgnNWsqRuhdxsYsjyw5NCZdVfaYtYBPmhfzPctR2geO65d7NDiyXFBp3EMCojCZQ7
         ObTg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=bqqcT2FV;
       spf=pass (google.com: domain of 344y-ywykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=344y-YwYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id g28-20020a2eb5dc000000b0027a2a767052si607075ljn.3.2023.01.11.02.18.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Jan 2023 02:18:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 344y-ywykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id b11-20020a05651c0b0b00b0028248aa29a5so3540352ljr.19
        for <kasan-dev@googlegroups.com>; Wed, 11 Jan 2023 02:18:11 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:c1cc:851a:3d0:4d31])
 (user=glider job=sendgmr) by 2002:a05:6512:3b07:b0:4b6:f1af:4263 with SMTP id
 f7-20020a0565123b0700b004b6f1af4263mr3407142lfv.114.1673432291206; Wed, 11
 Jan 2023 02:18:11 -0800 (PST)
Date: Wed, 11 Jan 2023 11:18:06 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.39.0.314.g84b9a713c41-goog
Message-ID: <20230111101806.3236991-1-glider@google.com>
Subject: [PATCH] Revert "x86: kmsan: sync metadata pages on page fault"
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, akpm@linux-foundation.org, 
	peterz@infradead.org, mingo@redhat.com, elver@google.com, dvyukov@google.com, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, luto@kernel.org, 
	tglx@linutronix.de, x86@kernel.org, Qun-Wei Lin <qun-wei.lin@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=bqqcT2FV;       spf=pass
 (google.com: domain of 344y-ywykcrw8da56j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=344y-YwYKCRw8DA56J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

This reverts commit 3f1e2c7a9099c1ed32c67f12cdf432ba782cf51f.

As noticed by Qun-Wei Lin, arch_sync_kernel_mappings() in
arch/x86/mm/fault.c is only used with CONFIG_X86_32, whereas KMSAN is
only supported on x86_64, where this code is not compiled.

The patch in question dates back to downstream KMSAN branch based on
v5.8-rc5, it sneaked into upstream unnoticed in v6.1.

Reported-by: Qun-Wei Lin <qun-wei.lin@mediatek.com>
Link: https://github.com/google/kmsan/issues/91
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 arch/x86/mm/fault.c | 23 +----------------------
 1 file changed, 1 insertion(+), 22 deletions(-)

diff --git a/arch/x86/mm/fault.c b/arch/x86/mm/fault.c
index 7b0d4ab894c8b..a498ae1fbe665 100644
--- a/arch/x86/mm/fault.c
+++ b/arch/x86/mm/fault.c
@@ -260,7 +260,7 @@ static noinline int vmalloc_fault(unsigned long address)
 }
 NOKPROBE_SYMBOL(vmalloc_fault);
 
-static void __arch_sync_kernel_mappings(unsigned long start, unsigned long end)
+void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 {
 	unsigned long addr;
 
@@ -284,27 +284,6 @@ static void __arch_sync_kernel_mappings(unsigned long start, unsigned long end)
 	}
 }
 
-void arch_sync_kernel_mappings(unsigned long start, unsigned long end)
-{
-	__arch_sync_kernel_mappings(start, end);
-#ifdef CONFIG_KMSAN
-	/*
-	 * KMSAN maintains two additional metadata page mappings for the
-	 * [VMALLOC_START, VMALLOC_END) range. These mappings start at
-	 * KMSAN_VMALLOC_SHADOW_START and KMSAN_VMALLOC_ORIGIN_START and
-	 * have to be synced together with the vmalloc memory mapping.
-	 */
-	if (start >= VMALLOC_START && end < VMALLOC_END) {
-		__arch_sync_kernel_mappings(
-			start - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START,
-			end - VMALLOC_START + KMSAN_VMALLOC_SHADOW_START);
-		__arch_sync_kernel_mappings(
-			start - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START,
-			end - VMALLOC_START + KMSAN_VMALLOC_ORIGIN_START);
-	}
-#endif
-}
-
 static bool low_pfn(unsigned long pfn)
 {
 	return pfn < max_low_pfn;
-- 
2.39.0.314.g84b9a713c41-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230111101806.3236991-1-glider%40google.com.
