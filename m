Return-Path: <kasan-dev+bncBAABB2HVUWKAMGQEEJFABWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 87F3F52FFDA
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 01:51:05 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id bt27-20020a056512261b00b004779fd292b1sf6101983lfb.4
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 16:51:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653177065; cv=pass;
        d=google.com; s=arc-20160816;
        b=eijiOByN/rpUNeIdFYH8IAKAqelmPeXgHCioYjnZD9sXPDhZyoamtWhdKuskreh9qx
         m0IOge2tRC/YhQ/Th6pCrSXG6OOMtROBzqxR+j8dt8Y0fpMsVa9CCxrUUBNtqxye4GDo
         Nq8iNhxDz9OnbTdjdmtNgCo056R4BUvfJkRUEXnA2F7iqJxW/eBscj6vB86y7neXrK0j
         TWDuVjRIt4kG2GRaxf2fFW1rBVzUR9qkDcsvtkqYALhAJMF+/UVqxxiWEEKR6ZhZKSic
         Q9FVwAFkEGs2BWl/Q9FkYiudJCrkgUB9SHr+rI9wtSLv420vG16YvMTgeYV0XvGJ2n5T
         I/lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=8Sxfnhxn9BL8L2Z39z3GmHKq6k5ickF6od/P9Gttlj4=;
        b=XQ/4Fvsjfsn2+Eo7EJpGVsgSODC+X0Sj0L/T6djNGNThyv0U1AnXE+/s4BkwBHa0fH
         yxL0iprsyVat/Ldqzppky5lv+he9h7nVa0Oy53Ljn9VRXYT6QFckVpSoI6u2SF9amIr+
         2sPdaWzWrm7ZQzJH+ONZkUL1pA+ZyPCRT70CKNwLUwepx6rguKNbuPL0U8lLGmZ9/N56
         E2pxoCIRq0MAMckW5yiOi9V/3cCrDMnxDSI6UZ5OXct66sK/jyDNBWkHhPJHt1ermNBM
         7n1gL0TfDPJnxndzEawJeKMCpCFG/0/SvF4HmepDZnEV47RSqMsT7YMW3Hm3NVskAvXA
         sVtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jh+koRmI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Sxfnhxn9BL8L2Z39z3GmHKq6k5ickF6od/P9Gttlj4=;
        b=UZ0WJde1JO2mg/wpIqeuX/NX0CFXPn9kthMT2DYFkmYqE6IUvkaVOiYeKFlxBI/ihU
         RDpjPJWmco6u10GYXiPvZj4GDlIehTQc632TRSJyENO62ZBVVq1lT/qK64Chcwtp7s+P
         4VDSR7YeEYBKBKvQ+xvRIH1JmSDTyxPjmobRQ3k7lST9orK0m7mipE6JjPpOaUU9uBdp
         ZKfUrM9qhoTemtClSvCDhYHzgqGGnj4q8gwm19o82l5v0BPk1ZyKHix09KOsQNZnhJtg
         3gdfWSGi4Dskqv19PIyoV2Mf/U7MSyPdmj/WQbq+GXc6TGODDsj0NRSfVc22O6UhSR6k
         sfzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Sxfnhxn9BL8L2Z39z3GmHKq6k5ickF6od/P9Gttlj4=;
        b=NuopAudYrmKSOdYqxN9tpVqE2TTWC33o66yjfYnmA1cD5IHsXA1NHmemz7HzX7Ip0G
         eUkyzQ46r3atxy2GLTGwrhby3mVjtmCIYCuURN4kg2XADfAs2G+mUf5hmjqeVDStQckT
         k7AzAfNWjB4kW17E/RtGk62QTwsiMQSOybWotrNNh7hcHveaD/kpcXofixYkKYEQNVVA
         uFAZdzwQv/2ZySlsDUNMY/1oFQ48k+HWJpInAvyucQXIR1Ugkvm2+7ni80Xhc1E9zgpT
         hEbwcBvEy4NQsjfSNh82brb3PcvkSMsJiyOHYgPU68322l/eQ0BcqtoCWdAp2dfIzp8I
         ckBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532nsCld2PsBAWMH0WcgDL12vBFeqENEbb/faKzTVokysWcvgydu
	R+jWXr4W8WK6iy9qDSoDVfQ=
X-Google-Smtp-Source: ABdhPJySij9csPgPmGSzYZIVD+9wXS4NAxRsiIuQOhQHixWysN+BV8sE3pBT+5J/rlxtqkjxcqFI1Q==
X-Received: by 2002:a2e:6e02:0:b0:253:d7da:ef27 with SMTP id j2-20020a2e6e02000000b00253d7daef27mr7973967ljc.105.1653177064868;
        Sat, 21 May 2022 16:51:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3f16:b0:449:f5bf:6f6a with SMTP id
 y22-20020a0565123f1600b00449f5bf6f6als4204833lfa.2.gmail; Sat, 21 May 2022
 16:51:03 -0700 (PDT)
X-Received: by 2002:a05:6512:2806:b0:478:54db:fa23 with SMTP id cf6-20020a056512280600b0047854dbfa23mr6717384lfb.253.1653177063881;
        Sat, 21 May 2022 16:51:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653177063; cv=none;
        d=google.com; s=arc-20160816;
        b=ygIXjArN1sPBBu1aUJIc2vZG5Gw+KwSc4KA8Jg7rJe+kRNujLzB+F0krhHAe5zG67u
         bpOfus5xJRg/B6Zxv0fWzMESRxH+OROrIK3mEvveclTKu9kZ2Vx0TrSoDecY/GbCsKYN
         4vqBw4LcHffg2d/7KH08m+Tv6Pp4n/e4us2gsjp6VPDEVqLB9sx7pk82ABa6ieD5DR9p
         9UxLF7pdFrxLcD2BE02JVO82NpWkbJeHL42Y1/gGD1ZpmgchL7Uk8cguiuLvkdLW6l40
         GXFCkFUJoh9/nRSMXjLl4OURJNcYfBSedNOjPRVURACJFi0pu9gk1PgV9Z6Qj2t0y3fq
         6sPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=117xuqHBOdhuOAsmwIJGI3P4mj0w/efp2m2gROWKZlA=;
        b=AW14b8xQlC/IRY7d0tiO1c093Ox/JzKPuSJmirV6x3Y1/PSGRQnVurwb5OsDBkMy8v
         0naU8kPyLCyWLMPzwt2AofI8hSscIk0HdTBLpTxFRze588LzgsersPqJdZQt8Sy+rm+7
         c8DeUMh7ZWIhuc7Nl+vli/wSregmYTiyv2Y2S3grq+8JWIluJrI+iy8UM+2iJZju6zAK
         E+f/TR0rII7tUh7MKZBK86wBGn8UXUOlInRtZMmYBF6Nq9ODNz9f0g8s3iDJFEeIDPub
         OD9U1zt5Tmq6pHaKqF2JbjNXZxriKG0uUoZ3Urc7QLnXYc40tn09kFfsDSzub9palb1P
         Cu/g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Jh+koRmI;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id j7-20020a2e8507000000b00253da2da6d9si265229lji.6.2022.05.21.16.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 21 May 2022 16:51:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 2/2] arm64: stacktrace: use non-atomic __set_bit
Date: Sun, 22 May 2022 01:50:59 +0200
Message-Id: <a584e95f613d59c7ff45686c2805deb63bd61442.1653177005.git.andreyknvl@google.com>
In-Reply-To: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
References: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Jh+koRmI;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Use the non-atomic version of set_bit() in arch/arm64/kernel/stacktrace.c,
as there is no concurrent accesses to frame->prev_type.

This speeds up stack trace collection and improves the boot time of
Generic KASAN by 2-5%.

Suggested-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/kernel/stacktrace.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
index 33e96ae4b15f..03593d451b0a 100644
--- a/arch/arm64/kernel/stacktrace.c
+++ b/arch/arm64/kernel/stacktrace.c
@@ -103,7 +103,7 @@ static int notrace unwind_frame(struct task_struct *tsk,
 		if (fp <= frame->prev_fp)
 			return -EINVAL;
 	} else {
-		set_bit(frame->prev_type, frame->stacks_done);
+		__set_bit(frame->prev_type, frame->stacks_done);
 	}
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a584e95f613d59c7ff45686c2805deb63bd61442.1653177005.git.andreyknvl%40google.com.
