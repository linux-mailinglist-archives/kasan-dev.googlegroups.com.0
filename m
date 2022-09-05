Return-Path: <kasan-dev+bncBAABBN6L3GMAMGQE6CMGSOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 655865ADABA
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:10:16 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id j19-20020a05600c1c1300b003ab73e4c45dsf5543638wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:10:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412216; cv=pass;
        d=google.com; s=arc-20160816;
        b=cB55tdOIh1NE6ZPBF+Hn+OXWtIZMpwllUhr8nnJYZL7vq8QAzmRUgupbmmuTT6ge5u
         FL9DO8p+tXbelSyHc1rzWFPL0KqziBKeskgArQgP6OKvq0qj4MYxBjMW/mwGQyP2TmyV
         MJJ/KxV04xpVrkE+/QvaTUrJP0QHlPf2hbR6XuWNf+vglJYpOOb1twjPzT8T/nSs/6ym
         ZnEVcKCH5DYtyQnBa272mu/jX9JIK6Od2lLENJLCLTzaJXD3AHT5F9Dpk1yMZgZDSCfc
         EsZ9ggT9w6hox6+PCi/JwDT5qKn91RzUEZ+QgORo7kh2j4GDvpK/S+dsO8/NeMo3h8U/
         OCeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bQNEkX14TrgxDNpf9DXYivIF2PD4itNupxv18/asZtc=;
        b=igs/jKjVbS9sCLGZqs+fTD9QvVC9gpw+ZAQgmtXZiV3DdUbil7iJCxeIOKlvw2nosw
         xDmeNSLFotU3mfpi0lYl7HUzLeOIW7YIHCz2/UL1K/50+JIYNgiVJUx/X/zMwlvb6K2x
         dayND7G8/dZzElhBaZoQBcntH04YgQJ+9/nIPRC+NbFR30MlMjojFpXVwQ7r4axl8LdW
         aB/ZBicFqzXBdwE+yIzfqq6p1X4LpKYaUUff4Jalw8fyh3S1LBm/e7O6ZxpW+6DpYnlX
         hoqZUuFMIos0l29Lcz+xutvtVfxr2vyu2thxG/VplMln0n4qv6iXPnFLMK+vqUZdAgNw
         D3xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hjZEe66l;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=bQNEkX14TrgxDNpf9DXYivIF2PD4itNupxv18/asZtc=;
        b=O760F+ChrM873g6MS5M1N6NBzfPv6/f5eTsefs1LixOAgUXcwMwEDsDhMtsY1pHMMo
         JnxSG35fkaydQfI+jjqUYzCWsLzTdfiOAF0wwWsOBN8iVb7k0cCYkxb9AZPLiMTnLONO
         /L/Zl2gTOgiBXwdE2vFx2lHSPZxJHTtDaPjOylseliu1TlqHGcR/e0vqcLL938HOJIcl
         GM/7gwTw1gIINNAkPIeCVsv6x2CVkO8Dh8VhRXBbDebb9Igb3TakR+KxaYwqKpf5ght2
         B8Do1dSqo//kISdgjiACf/FLR2eZVNdwcIakCHJ326CVT3zWWQhGi2vTz6z3UBVNAZZK
         Ze5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=bQNEkX14TrgxDNpf9DXYivIF2PD4itNupxv18/asZtc=;
        b=oqNiA+mfsKsAFGFEbsh9pK6FVXZ7Ka3NwinUAeStsH03vlsNVPzgicBJcpw5dr9tLe
         0ATG2Az30ujOA95W3InwSYUnyGY0wNiCSzKztvuU6GL+YSNOSeI33vi/hqWJW94TbZrB
         KFFIcEwAs+NxBXc9v1Vd+E3mJkng578rVWW44bnWLRlYAGHy2F6ePPFurpPpRevH7WHC
         TeSbJ6z5iZfoXG5iV3d1UI/mg6mLFWDxhqFdPjsXVhk4fyuZETGQ7WhcZ7sWRaR3GYOH
         0uJ4c2KEHjNxcu6ENOoHlwe0E8tB23657x1ko9mGgTW554PL0hqnGutAVACtPVhwkxv3
         BkcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2vggLcKzI7X2piiuH4w0wEavPG16xXMlmWgcL0Aay7MvXJ06R7
	f6MHwu0TGB9ASnftKlJkUx0=
X-Google-Smtp-Source: AA6agR7OzXApNflwwZmbTT2pDVm5wvfWKF3b1XXyODzqLU7cstSq9Xmy8ZBhNADXw3V+sgtMQvhCZg==
X-Received: by 2002:a05:6000:2ad:b0:228:cf8f:fe85 with SMTP id l13-20020a05600002ad00b00228cf8ffe85mr1520594wry.94.1662412216016;
        Mon, 05 Sep 2022 14:10:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c059:0:b0:3a6:6268:8eae with SMTP id u25-20020a7bc059000000b003a662688eaels4150938wmc.0.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:10:15 -0700 (PDT)
X-Received: by 2002:a05:600c:4fcb:b0:3a5:f2cc:2f19 with SMTP id o11-20020a05600c4fcb00b003a5f2cc2f19mr11491034wmq.142.1662412215333;
        Mon, 05 Sep 2022 14:10:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412215; cv=none;
        d=google.com; s=arc-20160816;
        b=XGVDHGDsOp/Pv2ldmhuOTI25cTFZtWc5o76BFKxTS2ldrPojhwAG2r47Abxj09SbCP
         7ojJl1X7JvFyygQZrOBNMF0dVHs+RjOXZChpIiPIqS0z50G+o2qhSkYeSuBPAUs7Qow1
         525gJG0KFCdxLLXT7HF8utJUDYBSqn+dJtCE9o4J1ozJapWd017/G47kdGRZ5ySE0z2B
         Oam45vQx5R5c5VVw4eoXnpGbQ+1r5jcK28YTdeP3P52OtCQ1+HWLINg0+fr8S5q3IA3M
         EgjzjbV0hIJTXNbFnQvNttrcSbinx3DG5ILcN4W9+srDGpP5xafS5W1n3hfNiE8WtENL
         jWtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HG8amreOT6Boo2OYpfsAisJYLLHPkbhrfrZ7vEhyKIU=;
        b=BgU2UFmjVUHERgsk3VRXE3rHx580Gta2JBEhk4lBM1zyA0mIFMgPXJmG+WGn/7TixN
         eS98aWILaePVqTvA8O7R1xf74qqnXz2AbLJ5inAOAb2Tzf5dZlDRiy9bdYvffMnTH/8b
         LFZo1op8ndMFN5r+5px5zGlSVZtH4/zphWDHptbICR7GAojLcMFqof2snm1s641ohDHA
         AgHDkgbqxDY+/t48dXOoUGoHAg5rkP6xEx7fMFsvW7s8VGZAm1NA15BOs6c73PzRmkvD
         tFC9nr9/hizTHMbjA7PxJ0M3StQUVPQXV+rMNiUGC4116r1v4/6VvGQbw5kpmK5s9JUI
         gj4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hjZEe66l;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id 185-20020a1c19c2000000b003a66dd18895si912300wmz.4.2022.09.05.14.10.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:10:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v3 25/34] kasan: simplify print_report
Date: Mon,  5 Sep 2022 23:05:40 +0200
Message-Id: <f64f5f1093b3c06896bf0f850c5d9e661313fcb2.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hjZEe66l;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

To simplify reading the implementation of print_report(), remove the
tagged_addr variable and rename untagged_addr to addr.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 11 +++++------
 1 file changed, 5 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index ac526c10ebff..dc38ada86f85 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -397,17 +397,16 @@ static void print_memory_metadata(const void *addr)
 
 static void print_report(struct kasan_report_info *info)
 {
-	void *tagged_addr = info->access_addr;
-	void *untagged_addr = kasan_reset_tag(tagged_addr);
-	u8 tag = get_tag(tagged_addr);
+	void *addr = kasan_reset_tag(info->access_addr);
+	u8 tag = get_tag(info->access_addr);
 
 	print_error_description(info);
-	if (addr_has_metadata(untagged_addr))
+	if (addr_has_metadata(addr))
 		kasan_print_tags(tag, info->first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_metadata(untagged_addr)) {
-		print_address_description(untagged_addr, tag);
+	if (addr_has_metadata(addr)) {
+		print_address_description(addr, tag);
 		print_memory_metadata(info->first_bad_addr);
 	} else {
 		dump_stack_lvl(KERN_ERR);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f64f5f1093b3c06896bf0f850c5d9e661313fcb2.1662411799.git.andreyknvl%40google.com.
