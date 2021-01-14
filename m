Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWF2QKAAMGQEQRKQ7XA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B55A2F6B1E
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:57 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id e12sf3057998wrp.10
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653017; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGxs/eEko2an6pu4cXDT6/cEiaIcV1qqtZgXC5tjTMwwVt0B/QdMoXSUe6RLrzQV9t
         vKlS+CweHoYlO2kQ336RoWImLeHplbUcuB0nPRAUrB3u/WG6wi+7aPkUaG3lWgimv0sH
         CPturnWJc41wA7cvzmrpcKnkRB21svUqyPCvkp5DeCYBUS9gMu1YZaxIHtzvLttJW+ue
         bwoWXOyUEWAqxKPatVIWDolp+7tkU0o+nvqikpEkYvUT9YXBxoEV4VoMcizPjjZzzle0
         Y52/jX+BGL2nhyOUsCGzLxeX+4J56p6tSqLDYQWoGMwH8XQtSxTGwX99vXmuxvYc04Et
         NzXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=iYLmiIYF6yDWKBOLDXAIn2htXHqlYCI+E+LM4xYGxoc=;
        b=Y/PyV+cVExi/Jc7hBudvH88hiayxMtRebHHnkHIThp+XQMXvMaBHJoO2LEwVyvMhDr
         +1zAUMax2Qfh56WsKWc8l+KeSUFDig31XaDfgsydoz8WLBmG9tlnF2PR7yF43JG1fDoU
         YTsoSLfISlovUB3HRQ4jOroWXEq4Y1hUhp4HFAre7D0qfxchymnjDrFw92TUm+ljDXfj
         LJ793wZb+1uvrWSGlqJHyd2Af4d8DkxORYyNYo6/lkEA6QiSPCkKSCCOcGhHJv/CqEgZ
         YdO+3SV2Ivn0psi/FFzj2L+f7i2bRBl4BFyqEu+IOMOY9i0tdont3gpqSg9s2IoIPRsf
         gxfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rTUv5m0z;
       spf=pass (google.com: domain of 3v50ayaokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3V50AYAoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iYLmiIYF6yDWKBOLDXAIn2htXHqlYCI+E+LM4xYGxoc=;
        b=qP9QH6qjY75tUeitIctuRjr2BRQpqz7XVEsItFWHbNHAxscws91eBCV8+PyoslMBVk
         evvQklKClSG5xSnoJvF/u6/z4JfSMMeSVfAzFlrKPVtpj3Ozwv+SIqUJXZWJI56eUalu
         5kJgzdA7JQUw/L1FLyqWUqSz91lEQmKCkxuqrH0WcJK86Qgid3Bwc7xPDSXdGwpDTGbI
         U7pHRBWxKeToYlQhG8dghFtK/76VlPFgtEgGWfq4K8Jpuzq1MERuDN5lpuuo5ATKFkO7
         x8tLr1VU5KtcbQl1rSkOqIGgbBdGtYVA029sx8qO2s+YnwcnGXKjHLal23y+8V+yoWKb
         +DZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYLmiIYF6yDWKBOLDXAIn2htXHqlYCI+E+LM4xYGxoc=;
        b=PWT9CRvSphhEn+0IzGCfSM1q0ml5ryp/rSdvIOKwlPx6V/84LvQPS4TR7lR9BqHGQA
         k6R3hzhHRKSYLsr6bBTvSm1xFAbKkmBYd5uAAuS6KFL+gE25GM/FAt+96efdy9iJ4/gr
         YqR38qypIwsIJFIvpFkiRHO7y9RJLUlwcIY/88tFecggfo7t8dc6bCbauzdvO+7eb91G
         RJh883WddmWH+kl8lqlXYgBn3a0L+xbvm47O7Zo8444eSYgFG9tltgWZXEPGmQZz0LbY
         YkFpTFxRCzBS0YFGOyM1YaRPjrLtvUeWMw/UIMJ9GrLBbZA5KnFAhniTWzakEbrjem1D
         FRGw==
X-Gm-Message-State: AOAM531/seYeQSeJWC9maTZnnyO8p/3fJKDBobsfPj+lM3e6bhs9ZUW6
	w2hCeomlcLAHeRwnUIy506A=
X-Google-Smtp-Source: ABdhPJw7Zwhk+IK7ouP44DYeNn3Ybg6W6YRNskntiSMqdqo8aQpAFdFYgfptME8UDWyLY7DH6h07NA==
X-Received: by 2002:a05:600c:2042:: with SMTP id p2mr5513618wmg.152.1610653017050;
        Thu, 14 Jan 2021 11:36:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5543:: with SMTP id g3ls6481366wrw.0.gmail; Thu, 14 Jan
 2021 11:36:56 -0800 (PST)
X-Received: by 2002:adf:fdcc:: with SMTP id i12mr9444598wrs.317.1610653015895;
        Thu, 14 Jan 2021 11:36:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653015; cv=none;
        d=google.com; s=arc-20160816;
        b=y15G5Z7zs/l3le3S8D2n4LBSlL6+KKFgPtIvEcCxK0oDiuKW++WhKSJ/jYm4K79n8u
         89u2qg43jIx/0wBh4ACmXSBy0cWzhsNJ4i21+r7csM4a03xnDIFibhobBw98tpQiLPaD
         1pXqf4T61GGio2XfimW0+ZZJr5M6nyuC3UpubzochG9bkHKXZiLxhVQX84TSvWsLjoJJ
         ry8yrDTeQQjtiAl0DOYAyqPq8IXHEa0YSj3KNlHcc2T3NJ7GaxGHSkVzTpjnJ+z6PH+u
         RFHNmwnLaGMFH33FJDuUgsjRvANR0RiLhD8gJZbSsGhFcnF45QVRbQ08EgE+9dlBYNSq
         Xndg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=BYOOBCCudRU7Lchp5NpxZrw19s2hqbj4Q5eYKa3nns4=;
        b=rSWn7qeEisxZ1tVwlCvkRL0+jTTVM8R8syHLddJateXt2WYOwjcz9R4DjxjVt8anna
         KZ9KsUMHTPflAtquy2MAJgU9xLxRysIOMTaadkHLuIaqlOYLHyoiivEegnkuqIbi2Vmw
         zRUaVaqJ9HnzBrLpK2nZwO/m27B7Z2hXLF/8AKLYfFZg8YjnDgXwGTwt7JPjzzziRqiI
         pBJuX7d25TgsGM0YQu2/rZGsw7EZzfK81kMksqFkwURpbCtPKfkk38eA8FVlQEM4pCm/
         UyrYQsCFSo3082OPaie3JPC6f7raCl/mXd3uzly60zW/uOhOIztOrrnylLV/644WyMIB
         QftA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rTUv5m0z;
       spf=pass (google.com: domain of 3v50ayaokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3V50AYAoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id e16si347402wrn.1.2021.01.14.11.36.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v50ayaokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id r5so2263486wma.2
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:55 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2905:: with SMTP id
 i5mr5291713wmd.28.1610653015397; Thu, 14 Jan 2021 11:36:55 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:25 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <62a4d6dba701ad4747d836fb08c20fdfffc701f8.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 09/15] kasan: adapt kmalloc_uaf2 test to HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rTUv5m0z;       spf=pass
 (google.com: domain of 3v50ayaokczo4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3V50AYAoKCZo4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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

In the kmalloc_uaf2() test, the pointers to the two allocated memory
blocks might happen to be the same, and the test will fail. With the
software tag-based mode, the probability of the that is 1/254, so it's
hard to observe the failure. For the hardware tag-based mode though,
the probablity is 1/14, which is quite noticable.

Allow up to 16 attempts at generating different tags for the tag-based
modes.

Link: https://linux-review.googlesource.com/id/Ibfa458ef2804ff465d8eb07434a300bf36388d55
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 2419e36e117b..0cda4a1ff394 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -382,7 +382,9 @@ static void kmalloc_uaf2(struct kunit *test)
 {
 	char *ptr1, *ptr2;
 	size_t size = 43;
+	int counter = 0;
 
+again:
 	ptr1 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
@@ -391,6 +393,15 @@ static void kmalloc_uaf2(struct kunit *test)
 	ptr2 = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr2);
 
+	/*
+	 * For tag-based KASAN ptr1 and ptr2 tags might happen to be the same.
+	 * Allow up to 16 attempts at generating different tags.
+	 */
+	if (!IS_ENABLED(CONFIG_KASAN_GENERIC) && ptr1 == ptr2 && counter++ < 16) {
+		kfree(ptr2);
+		goto again;
+	}
+
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr1[40] = 'x');
 	KUNIT_EXPECT_PTR_NE(test, ptr1, ptr2);
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/62a4d6dba701ad4747d836fb08c20fdfffc701f8.1610652890.git.andreyknvl%40google.com.
