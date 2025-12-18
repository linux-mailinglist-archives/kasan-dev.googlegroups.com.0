Return-Path: <kasan-dev+bncBAABB257RXFAMGQETRGO74Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DCCDCCA06F
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 02:59:09 +0100 (CET)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-3ec31d72794sf2431281fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Dec 2025 17:59:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766023148; cv=pass;
        d=google.com; s=arc-20240605;
        b=e6qzz1S4KUN86ENfHdT4EIUTs3biN0eTwnUeSX87lr86nHWx6tB4G6djGhRhrUmTuM
         plNGpV6lAprz+CrGKVjdq6OGKByzV1u+xE44N8XaTXIusJySiTMjgiCWSOjgNCLUBCOu
         SGryEQt+oJcR2dKq903mQmA4lhkjlyijrYfP+69Qda5lS4vX9qP1kUxYbHBStADPZ7EJ
         LhLv0nB2BSRMB/XWPz6iDmCmIEOqsl+6xykZB+S4mK1fYkgvqfSlWlVBVMrfkDRDpCV1
         hzYFxPMep64owa6tE0fvIZEL64JdnPfwGuRxUCMY0PWXdk+mzMwf9Zy6Yw6EzAuhFMM4
         vIeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bbUIalsOQcHRPDWXQZ8hf8jQEV9AxB8AdQ280v+09nQ=;
        fh=DPE1NwhFXrFA34sVFTPnSGB9jB+s/nXY+s23L9bu9qE=;
        b=HnEESkd3CQyWZQC41szwkx17ZT+fOXw10ycakAE1Vz9j5p/Ngu/3r2epx6t5Z6eMKH
         YLokiNaurlaztQlV39FJocdKwE9GOV8QtOvf5D7JBSin96uGUw7ix3wzJpdLmmGotPbU
         Z/2Mk8ShpldGSkjiwp5Ny7ZWBStn1ihbY6RANiPB5LHDNNc8pwEcJdFVq+YY/AixmXjb
         6vyB4AFxB/sHMpjnbvO2NDnvK26NmjXk8+wiVBzVlUO5fN13T7uaHV1+Mp/9YWdL3m2a
         MEuXuGHF4WPM4IKYsllLQt38Lq89hvM2t2JD/uRN2chgbt5DWlZANMx/FEil5klBZTNV
         L7/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766023148; x=1766627948; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bbUIalsOQcHRPDWXQZ8hf8jQEV9AxB8AdQ280v+09nQ=;
        b=tIa7Bfb2vvwuJHAMmhoiK+s/SjHzTKmRncO5DysQYhf+bk7NikkSAHxWQzqmFHpQn1
         y4GemaStoONpbjGltyF/VjX2yw3WlEwL92Qdfm8f3D2Wn045JyxOl7/6AhxFiAIe+4Yh
         HTy4m2RiX47FM00GNqt/+IxrPIGJ/SBQptYAZip97Vi01ur5Q8h/59GAKmASyvDZDo5P
         brtO2h6swpxXZVm9eDngZmBK4ZtYzeM1sOp/noqpYOXuA0pVqOgWGNsqMJlEjfr/g58F
         ighjaOK1pl+fY+8wkssj0ObM7zIzGiZ/2zZ6OUQFR67ESqpIVW+S6nPpBzae6DPh8Y69
         V/sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766023148; x=1766627948;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bbUIalsOQcHRPDWXQZ8hf8jQEV9AxB8AdQ280v+09nQ=;
        b=uF40CpwEkMdqKIZMKYvjjebbutknx988ncIem8cdVVe7AAZsgVkeX0d/1Gs9yujHyp
         LeWL6u1xz+3fY+82EoHmABpN17/GOpA7jRmnqK31R7G5iyu0nUvKPKMEavc2xs59mY3K
         xUNcjWU+97pt9bY05+yovljC2Q5mqns+XHEAliNdrW1YoMPAxKmNIHjG+YfXJRyOmq4B
         /bO7mNmnfAMsDkPtb3r/avJQTiPTZ7qCPsgkRZbWdQUDTJMQbPwjvWkKM5dOzFJvykKz
         XF4xda+5hExHdlpl6nX7eexw0Qweb2pD7JJmO9f05G1YKY5wIQKzj+rW/fL0pLRUTjhS
         n0uA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAVeKH7aMYcldE2i/tTo27ic2apFTJ1qlKgbOfhQcsO9aPYO6OsDmvusxp2LhyC22pI7yK0A==@lfdr.de
X-Gm-Message-State: AOJu0YzVxCzrCKfBfucKZdLjzRBpFz7+0QfLvsK1Glq/aNBHibIaSYih
	r5R7OWUf1GcU4mHIgrmq9ElmmhRiZkZLPBZpevv5pDu1Y/GiHWos+GlI
X-Google-Smtp-Source: AGHT+IF2t75h/GbNvCtin4pUAY7IRjvYwlwRpxVBlE8PQ+buBcP4g7r0SaSMXEGyHfWZCxGAayNSXQ==
X-Received: by 2002:a05:6870:a709:b0:3f5:b7e0:8680 with SMTP id 586e51a60fabf-3fa168cd79cmr674127fac.1.1766023147745;
        Wed, 17 Dec 2025 17:59:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbjJ4HNAxz42TuT2zfUrtWUf+jqcV7KH4Glym+Mv+KnWw=="
Received: by 2002:a05:6871:4f12:b0:3ec:31da:bbc4 with SMTP id
 586e51a60fabf-3f5f83f63f5ls705478fac.0.-pod-prod-00-us-canary; Wed, 17 Dec
 2025 17:59:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX0tG20GrJekLjMQkeA6luPVJlu71COTdAI5X2LNTvVv1MXMsD8RrNOXMI+zPzjgIhZIaaPPFufWRw=@googlegroups.com
X-Received: by 2002:a05:6808:1591:b0:450:aef0:ffd2 with SMTP id 5614622812f47-457a286f930mr733851b6e.5.1766023146984;
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766023146; cv=none;
        d=google.com; s=arc-20240605;
        b=cwuDcaHUrwNyZk65Jo9Bk96OwBthvypDxcC2huNqFP5XwFFWg4YY76c4LKEc8xSsqZ
         ctm/Ot2KwLbDMCZOtjYyKIfe0IYZOde/QD1SU4XX/VvOwPNMIti6LQ3ozdO3UGk/NCGt
         AW+VOzx5muADqUTmRrMq4hET3xS41ZMfh12k9wcN3AfkZsiZEPQNUsmcjZmg73ShD8sA
         Q6udoNgpNeT528MgBbWfMwvYi9JkoocUjeMInL1bi4leQT/6MrPOnWguy+mQ+Vl7Zu/R
         lGsC1+0GyQ+YuAV+x0xWVUAozmonPCaQZjlqAtef2XgMYNgR0ndchexynjlaE0JI+p4K
         YhLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=1SXi61QKvEmzRMEh+1xzYP0Tb6bWdmBrzPKuMyImTpg=;
        fh=tXyokhajkC3Hwq5fulW7liM7gDFGcDjcIYOJPNGPN8w=;
        b=dpdOVlkAcZE4wF18E7TckqrKXhDqtgKpQkIpGnajttsyw2pbB4kzrlYAotnhNaZLUR
         8GtdyhE1B5FDpmhYHe02p1gMZ5HjN/TumQ5hlVLxCQfm3BYqqLW535KwXuMlFm0qdna9
         6Q+ASLxzaTKqMjreJbVIj2w+AX9Q6LPegWWBNpBrrg31/D6B6LsOW/WXuTxS7wItCVSi
         sOoAaVTSNVVj/znAlv/Qu+b/09+IsfMlA2x8mIlrr4Ez3W04z0aSGT1PCHGnO6OeYDT6
         Q6z3Cv3HDL03ArGF+MeohqdqaOt3HZqWThueJbZwreRZNpxRJ/hBLIynNnqxQB/clwhU
         5k8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) smtp.mailfrom=yuanlinyu@honor.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=honor.com
Received: from mta20.hihonor.com (mta20.hihonor.com. [81.70.206.69])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-457a44b6a60si33482b6e.4.2025.12.17.17.59.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Dec 2025 17:59:06 -0800 (PST)
Received-SPF: pass (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as permitted sender) client-ip=81.70.206.69;
Received: from w002.hihonor.com (unknown [10.68.28.120])
	by mta20.hihonor.com (SkyGuard) with ESMTPS id 4dWv0X2l0vzYqZWX;
	Thu, 18 Dec 2025 09:56:28 +0800 (CST)
Received: from w025.hihonor.com (10.68.28.69) by w002.hihonor.com
 (10.68.28.120) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:02 +0800
Received: from localhost.localdomain (10.144.17.252) by w025.hihonor.com
 (10.68.28.69) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.2562.27; Thu, 18 Dec
 2025 09:59:01 +0800
From: yuan linyu <yuanlinyu@honor.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Huacai Chen <chenhuacai@kernel.org>, WANG Xuerui
	<kernel@xen0n.name>, <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<loongarch@lists.linux.dev>
CC: <linux-kernel@vger.kernel.org>, yuan linyu <yuanlinyu@honor.com>
Subject: [PATCH 1/3] LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
Date: Thu, 18 Dec 2025 09:58:47 +0800
Message-ID: <20251218015849.1414609-2-yuanlinyu@honor.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20251218015849.1414609-1-yuanlinyu@honor.com>
References: <20251218015849.1414609-1-yuanlinyu@honor.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.144.17.252]
X-ClientProxiedBy: w012.hihonor.com (10.68.27.189) To w025.hihonor.com
 (10.68.28.69)
X-Original-Sender: yuanlinyu@honor.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yuanlinyu@honor.com designates 81.70.206.69 as
 permitted sender) smtp.mailfrom=yuanlinyu@honor.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=honor.com
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

use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE definition

Signed-off-by: yuan linyu <yuanlinyu@honor.com>
---
 arch/loongarch/include/asm/pgtable.h | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/include/asm/pgtable.h
index f41a648a3d9e..e9966c9f844f 100644
--- a/arch/loongarch/include/asm/pgtable.h
+++ b/arch/loongarch/include/asm/pgtable.h
@@ -10,6 +10,7 @@
 #define _ASM_PGTABLE_H
 
 #include <linux/compiler.h>
+#include <linux/kfence.h>
 #include <asm/addrspace.h>
 #include <asm/asm.h>
 #include <asm/page.h>
@@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE / sizeof(unsigned long)];
 #define MODULES_END	(MODULES_VADDR + SZ_256M)
 
 #ifdef CONFIG_KFENCE
-#define KFENCE_AREA_SIZE	(((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2) * PAGE_SIZE)
+#define KFENCE_AREA_SIZE	(KFENCE_POOL_SIZE + (2 * PAGE_SIZE))
 #else
 #define KFENCE_AREA_SIZE	0
 #endif
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251218015849.1414609-2-yuanlinyu%40honor.com.
