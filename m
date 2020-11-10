Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBFAVT6QKGQE23AGEOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E6042AE2A9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:17 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id o1sf2144285qtp.7
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046276; cv=pass;
        d=google.com; s=arc-20160816;
        b=AI4FMdiaB4B0J8b9MwN2d388NuDTtQT3LUZcUoOtpwMpkXsVCqiERWaXeU3bXKKqbp
         ZrbThxxkoTc1f6MTM1IHALe08bB54F+tNUvqwGFqk5NaaOdwGHh4yT9M8gDO7dR3QPfr
         mpZkp96pTTtvb6ksOlut6xYD2GeL3bv/rrbF61B/CiABxS6Ckk13se2WbW2Mv7YEaY1r
         1FIUvJKVijCpKPntazExHdiK6YoVTpTCkJQZ/AU5fUG8SB+5AlJh3ixFxJyv8wiwCl0l
         8iMtGaeWoG5Bzso8MHb6/+5bJWlgH9Mf7odl1fD/LK3ASX0CPCN8dwQPH5koSJq0OZZl
         A3Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=d+ITwgJ7oTJTdeWVmNiZJ255JNazLEm1U5aleEX/3Fw=;
        b=B7VBN7nqrmXeKS4O4gWeiI3EAd04EMUftfj48CMy/HZFCVOZQ8AkTzzFSwrL1f5SMU
         msH1a9dnysRSHHaUi7EiEAWTjwwBQpk6nxrnwMojNtwJbuNiiadEqDmn3clzzyFK1+Jb
         NYyrt552jVnBwS8ppOxi+XjN4bI3rVxP0fQhAmtDS17CdKDBEfJCsqAy8gAUzFi8nHCG
         np7llCQZpiw+/p2rotNNVZhMWjBJGnv0XJyzLl538VmR46+KUi9pG8F3AK8XoMEGOhKy
         YPgSJavhLeKgUj3u3o+b+lyCiAImQaMo/qVNYJGhefNh7niqaO72OLfrwKz8dgcQG/xg
         0X6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=khJY5VLW;
       spf=pass (google.com: domain of 3axcrxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3AxCrXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d+ITwgJ7oTJTdeWVmNiZJ255JNazLEm1U5aleEX/3Fw=;
        b=mImLqYxkvPvWHOzqKZe+EocAPRGVZUmggNjo/D12ccF26PisV+OiOCR7Ya6p39A1tP
         crba591VJH8ES6i+dgjAIzCLq4SPE24897SPu31yHeUkut88J9grV5sYHBZ1w+tNQ+Lu
         EGYmTIDIw8XF/NhBmG+z0h7jWkqyzwUpOWTTNpC2tqfrDFV/wFWAIEQ5OqxLhgjpXH42
         A5XYuD75hZ2t7M7yQfSnKB1v+tRt9UAtGF595/dzhYG1WlQOMWrWMKMLqefRwrX+Zs9G
         Uq4gMNuZDcAOLqBdFGfut8GfxPVDO8TPcrbxp4HPDZFn2DcJva4puUX81qaK8053n126
         TORg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d+ITwgJ7oTJTdeWVmNiZJ255JNazLEm1U5aleEX/3Fw=;
        b=OZhJOoldYLNbf9/fRjreot8qA7/YTJjD7/sOSbB5XKSnUgmHHLiNiSXLwDuJfSmCAX
         XdOk+Y2gP/JRPlwyQK6S29A3s9iXeAuFv+95pCNBjCK8qA0wqAeOMC7vEUSeJuSOYG4j
         JNfqdPstTZP13VxEbBUstZNk+URDVHX8aW/G628XjeDiU7w5ezS4NqiKawmriW3oVBR5
         HtcONmGf7bwATPgj2tQ5PniVLFpaKodmw/T9TpMo+3xvhIgtHXKXxYiUSXX0+qUrj/oO
         mVwNSpoMQUc2EB/jHr5916Zrm+eAyZHpMdUTkPWuzMo+5vYvHZMQ7K/c6GfrR8JaGVNm
         9TOA==
X-Gm-Message-State: AOAM532dIk5fDiJJHpFQq5Epj12mXdR8n6BztQcpnWNp76tnTx/+KyUL
	NDUTufD9ARlS6ks0TseQI+M=
X-Google-Smtp-Source: ABdhPJwjqaAYK3NdwAfqFDVFIt7CaEja0RCxIevPQNw8MzWgrnTP7NmboNHj8pf2eqiMzvWpCOJCAA==
X-Received: by 2002:a05:622a:8d:: with SMTP id o13mr20469670qtw.146.1605046276103;
        Tue, 10 Nov 2020 14:11:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4b69:: with SMTP id g9ls3115683qts.11.gmail; Tue, 10 Nov
 2020 14:11:15 -0800 (PST)
X-Received: by 2002:ac8:4884:: with SMTP id i4mr20810126qtq.300.1605046275634;
        Tue, 10 Nov 2020 14:11:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046275; cv=none;
        d=google.com; s=arc-20160816;
        b=CmNl9mtvWPIveKBABPpNfHptvDVxLcH/33WhPNiBmWA7/EPKHL4I+xiK5YIiZ+i/b/
         MOj7nRFbaqghnf/UNjDAL9azZV1me/rALSfr/SmTO343Dejljaeauzie463bQZaY1HyA
         GR0nFtcfYsp3qUHxMsMDdfV7NCrVJ78pcNdHv0xn3qbM6PmxErsvddTVUnb0UneOt0ft
         Q3hktaKg4Gr0nr9Ez348qsF2y93xS6UFN+lgdvbizg9VBTZuqpe9MdayrpDBn6Znz8zw
         9eMlbnFR+xyxEUYWqq0A7Qn9arFBXhTyoNssA59qnsVQCSgY2lrOSRxvh8FuXNGA9Fwj
         Kz6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=aIsdSQcI18Vrv4rqf7/CpzDYxbaOkJ5FCCTIj5rnv9M=;
        b=oqYM0+NYsry7M0GBdRAnyb8Xr6kNls23/yWx6i4cjzZ3UscVHUE1ZgEhK8mYaayqD+
         Liz52OVb+aZ13REWT8zt2j8SnHeKrflQjCWkepWaYUN2E3P9jUbabd6qK4Z06NmFRXcw
         JkjnFp+tY8kTFJfzW+RqowHiYhTdEPPUmC0vhANXty6fISuNjRLACZl3ksGy/Tj4tjts
         2vixMp39N29KMLI5IZo1MBHox8fypyg9JCXCyilo3TVim7etkH1/CZzaa6o5q3sq4JhS
         ZscljxxOgm8lb0Xo1U8WxWDYroosNj8w9JENDdMcZON5S18EnU6KuJwriv99yfhNpxgg
         sXnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=khJY5VLW;
       spf=pass (google.com: domain of 3axcrxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3AxCrXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id g19si14776qtm.2.2020.11.10.14.11.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3axcrxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id c2so8515642qtx.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5691:: with SMTP id
 bc17mr12182478qvb.30.1605046275279; Tue, 10 Nov 2020 14:11:15 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:01 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <34c72d612b6b06393ef455520c70f37c8b7a2c6f.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 04/44] s390/kasan: include asm/page.h from asm/kasan.h
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=khJY5VLW;       spf=pass
 (google.com: domain of 3axcrxwokcdiyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3AxCrXwoKCdIyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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

asm/kasan.h relies on pgd_t and _REGION1_SHIFT definitions and therefore
requires asm/pgtable.h include. Include asm/pgtable.h from asm/kasan.h.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Vasily Gorbik <gor@linux.ibm.com>
---
Change-Id: I369a8f9beb442b9d05733892232345c3f4120e0a
---
 arch/s390/include/asm/kasan.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/s390/include/asm/kasan.h b/arch/s390/include/asm/kasan.h
index e9bf486de136..4753ad0c3cba 100644
--- a/arch/s390/include/asm/kasan.h
+++ b/arch/s390/include/asm/kasan.h
@@ -2,6 +2,8 @@
 #ifndef __ASM_KASAN_H
 #define __ASM_KASAN_H
 
+#include <asm/pgtable.h>
+
 #ifdef CONFIG_KASAN
 
 #define KASAN_SHADOW_SCALE_SHIFT 3
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/34c72d612b6b06393ef455520c70f37c8b7a2c6f.1605046192.git.andreyknvl%40google.com.
