Return-Path: <kasan-dev+bncBCXO5E6EQQFBBS6FVWPQMGQE6JRYDOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 335E56960C0
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 11:30:37 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id ks3-20020a056214310300b0056bec2871e8sf8384592qvb.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 02:30:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676370636; cv=pass;
        d=google.com; s=arc-20160816;
        b=kXT7lG79sFwd6Zrgkm6fxHd8T4smsgFirpa5PCUAzYe+qFPMWtwgtHfH4/FSlJYeBn
         JWgDqdm/ABpjqSpw/7DxvSNk3KByLBDb+srAhKC1NHIWklVIbm17f1gC1Va38X+Jpi6I
         QpROzCbUMkniw7W5SLxR/Vo3mg0MRmKMxJjGO9fefQpqUUvsu1GJm60ZCwR2brzV0TB5
         /+qpTWYLCnvn1BwwZSnczVfDuye5mLWeTKHYdhaNDb5sN+TfLWsY28AW01PPJ56/e1qx
         51oQX7ghzDByiMtiRVQQ+r7ps1cLuhoA+smQQ/mpzNoM8lk6UMtBb+l2oqdqca9k3jC3
         TSyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=3NjIJrAVqk/hjFKUb0lzgZKghTrdQ4wWAJjID4DUcuo=;
        b=VIpPaisboZ4haJkkb0ybcZzRs44JzQyQjttdsxhhDYUyWwZpwQKbTSlrOFTcHF1DnQ
         bh2H8uZIwGB3GzMP7BtYOEZH8ALyINMxjUKslY214DMWGih+D4yGtZ1uUuL4xQ140mBb
         urFfZUXmtV4K4yEIiKYtlBYHkX71yqLmiThNPZPfs61EZCWe7ojXDyjGhOH4E0K0ZX3+
         eHwQsZ902CCJY21hn/cogoinvsudXha6SYNZ4aAU7uBEmCznAUG9u7sbjOdgIhyZBrPW
         BjxS2VsSBWXJKCbuhcpHRT+bsnrUPGFVkhtVs4sjA/hsqNErXRUrzoXkKMhud506rNEM
         1dcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FRujVgQd;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3NjIJrAVqk/hjFKUb0lzgZKghTrdQ4wWAJjID4DUcuo=;
        b=nabkZKcBYw/2ubaS31nRgcpDgbp54efwqH6NgG/3T5eIAm8b9WuD18KkFd15pdLM/7
         aHSzILKjnQX1e1xSQg0+GEFjsUu0N7+q+08lURT9KRra1Ebhngwl8QDLzmq/OvrpdnLG
         0T8xAahVzk75u7ni0gCT6/2y6pRHoGddNzIq3JkF22tck2F7c2DGQW4Epiob0YPMtoeq
         RVdhk7OB4qzH/BmKZ2z/kE2tjwkrA+ZVGdi2jAFXNxQrHaodfMmOfjrajTpHVoPHMG9a
         zWTTy1BDm/W0RoyoFA5U5EQ3oW48B8zPPlajKnvRoyShWRaz3xDE2QqGuK8gFcYlSqhq
         /Itw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=3NjIJrAVqk/hjFKUb0lzgZKghTrdQ4wWAJjID4DUcuo=;
        b=JDuk5xRA65z0WZFBpvBABGVa27WiHxQhJGhHddDtTnTCroJqsNppBkRo3A0XId4h6c
         2MHy5XD2oRRzhXuSn7LAJdmp9JICamiLhhgkQlERuFsVMtpvymTmOTc6PweYF7WxFYXl
         VhmlupdnjRsUO1srxHw9xS5odWudEK59ateD01VfGR4jRblcH04DthPjI7rJ3V4BPKFp
         KRIai3OKqgqJkilTEHlWZWvLjSuy87txufSURh6SeE/7IgnWA2Bln+41u7I+nMMst8Bh
         ohNC2vvthuDQEQS671J2vLJ07VUexmSxbnxhUWJWr0gr+QtLvteKn4W2g3+cF7LdZlOf
         7gTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKV+Vo+js2l7w1ngDbmTWADEjLsKBvoikTAtKkk+gOWRfYD1iTV0
	q2YufubJXedUHF481jGyngA=
X-Google-Smtp-Source: AK7set9x4VS1MAZu248oWZ6DXL3CJWH+OdMO0iOfY7Z+aqon8YPpe4YsERsLnJXS4bKyQ5aC9/aGFA==
X-Received: by 2002:a37:b046:0:b0:733:fe2f:98f3 with SMTP id z67-20020a37b046000000b00733fe2f98f3mr119044qke.258.1676370635824;
        Tue, 14 Feb 2023 02:30:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:68b:0:b0:3b8:130d:4473 with SMTP id f11-20020ac8068b000000b003b8130d4473ls16233286qth.10.-pod-prod-gmail;
 Tue, 14 Feb 2023 02:30:35 -0800 (PST)
X-Received: by 2002:a05:622a:406:b0:3bc:e796:8630 with SMTP id n6-20020a05622a040600b003bce7968630mr3093724qtx.23.1676370635336;
        Tue, 14 Feb 2023 02:30:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676370635; cv=none;
        d=google.com; s=arc-20160816;
        b=CzWcaTUwINKUmQq7H2ISF7i+dvA0a/NpZMubAWs6mfPbiA7VVZ1OhlDUFLhvQIivuk
         w3ZAOaXJ2L3OeFmC4U5m/tvIbmZ2iWgJb4paIMixuRiIFX0CYQfAk4re48kQ2NDcXGPq
         kX9fQsaEo49YCb4ruzuzyjH17IOU+1eDGPpU7yy9Pe2oT3j5tF6Cckbr+qfbhc94hDQe
         Qsz1kXmmdQ2uc+Gckk06W9s6tzhrsHrKfxmlGImm5qvqYi1LvH73bfySUMtI1DBvTS3J
         N2KT4dAGXX+nH6Z1o4PZZ1me0TrVIGg5A2f9OKyf1McsCZCSiodYMn70rmIbxlQ/YMVC
         dsnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=iO2oNcvyj+5oQXBNXKeF8zvrEC8UyLgmscT1pfcl3Oc=;
        b=kF2eQeEWCLf/lqv5RcfJKDVRw7NYOgMO7w4bp15Xa6lbPnQW+ApKJiPIODKh+g25zC
         5gvi67OfxmzCoAyjkuXzcUTv1tkTU/v2btxZWP8WMJ2/xLwSZjz5yc8W7HiGSpdMTPYW
         4ebRNT4bNw0mpXP9s6RAAod2dbAsnNQaVlYQKsZY9cYvxNgXDYbrRprIaatbi5ove51g
         LiDss1c/ItV2ZEplykSq1wtsCSUC9uCgi5bIoqej0+q7Cx6MNBP4L64R02w35bBlUC7+
         PlWVVpN5UBrdZOm9M7vgO4cUknzLVvbnP0soRdlvm/D3Co2fxjJ8PUEtxLO3qi2gj6xp
         RIHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FRujVgQd;
       spf=pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id b3-20020a05620a270300b0071da5397385si1202158qkp.4.2023.02.14.02.30.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Feb 2023 02:30:35 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E65C761509;
	Tue, 14 Feb 2023 10:30:34 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B7E7BC433EF;
	Tue, 14 Feb 2023 10:30:31 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Vernon Yang <vernon2gm@gmail.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] [RFC] maple_tree: reduce stack usage with gcc-9 and earlier
Date: Tue, 14 Feb 2023 11:30:24 +0100
Message-Id: <20230214103030.1051950-1-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FRujVgQd;       spf=pass
 (google.com: domain of arnd@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

gcc-10 changed the way inlining works to be less aggressive, but
older versions run into an oversized stack frame warning whenever
CONFIG_KASAN_STACK is enabled, as that forces variables from
inlined callees to be non-overlapping:

lib/maple_tree.c: In function 'mas_wr_bnode':
lib/maple_tree.c:4320:1: error: the frame size of 1424 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]

Change the annotations on mas_store_b_node() and mas_commit_b_node()
to explicitly forbid inlining in this configuration, which is
the same behavior that newer versions already have.

Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: kasan-dev@googlegroups.com
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 lib/maple_tree.c | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/lib/maple_tree.c b/lib/maple_tree.c
index 5e9703189259..646297cae5d1 100644
--- a/lib/maple_tree.c
+++ b/lib/maple_tree.c
@@ -146,6 +146,13 @@ struct maple_subtree_state {
 	struct maple_big_node *bn;
 };
 
+#ifdef CONFIG_KASAN_STACK
+/* Prevent mas_wr_bnode() from exceeding the stack frame limit */
+#define noinline_for_kasan noinline_for_stack
+#else
+#define noinline_for_kasan inline
+#endif
+
 /* Functions */
 static inline struct maple_node *mt_alloc_one(gfp_t gfp)
 {
@@ -2107,7 +2114,7 @@ static inline void mas_bulk_rebalance(struct ma_state *mas, unsigned char end,
  *
  * Return: The actual end of the data stored in @b_node
  */
-static inline void mas_store_b_node(struct ma_wr_state *wr_mas,
+static noinline_for_kasan void mas_store_b_node(struct ma_wr_state *wr_mas,
 		struct maple_big_node *b_node, unsigned char offset_end)
 {
 	unsigned char slot;
@@ -3579,7 +3586,7 @@ static inline bool mas_reuse_node(struct ma_wr_state *wr_mas,
  * @b_node: The maple big node
  * @end: The end of the data.
  */
-static inline int mas_commit_b_node(struct ma_wr_state *wr_mas,
+static noinline_for_kasan int mas_commit_b_node(struct ma_wr_state *wr_mas,
 			    struct maple_big_node *b_node, unsigned char end)
 {
 	struct maple_node *node;
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230214103030.1051950-1-arnd%40kernel.org.
