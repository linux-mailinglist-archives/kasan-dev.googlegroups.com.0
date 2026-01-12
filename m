Return-Path: <kasan-dev+bncBCCMH5WKTMGRBDEVSTFQMGQE2PXBOZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id F29B9D134EC
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 15:51:58 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-43065ad16a8sf3649005f8f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 06:51:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768229518; cv=pass;
        d=google.com; s=arc-20240605;
        b=AlZ64S1WPposoXtYnqEG3fy26AnaIP//Q9DjFpSRD1Keo20VSJ2WTaGkJLkPDxdtwk
         NSZ5xz1EJrh6xc1ImIK7ZFoYzx2mSYh2TbZD6v+wIuttXT95DnzgQoWcJUEHieLYyD7z
         xG1FslJ7RC1KbVCk8OLpFXV++23BcLRdjAK/pEab3FBCbJD6HmfImjIKq61UMwfFyD7H
         BPYm97Bp+KVsiJA6Jscp863OWShQLuvYAp7rZcQVb5ayHEtNcLoYIyPQiAofLuT35VyC
         6sUCtoN4ByzviuqI4Eqt5JeG1zZO8nyVIqC6Bgm/ROwHopea+3IED7oN4euqbvN8dasb
         WfKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=NJBDcujz9NHlsLLpMnf0Z0p1Limd1SBi18b/+msCjG4=;
        fh=ZNdNr6kur1XN5zMPcj+AvudcXKg3QYVvozY/PtocZXA=;
        b=NtBdKNfZFlPFVGjIQ1CFwuu6jJDGbS+/npIC7UCbBx0B29AotJ39LJXtk9mZNoSbPJ
         v4h4JpLWA8UG7BZm4ztcwhvC/KlB6dOfFwRYZasUCKP5jTvrNejiUxUuEun/1YWwUDTl
         qtN6lEGkrfvG+MLRAWGjsC8pzN/itbDU734l9/WhzcRjmZr1SKsBCzwiX9IkHWIP6On2
         2OaLqsXVRPYx1niSETioD2HY7DvU+2q0V407kIdigX/J8nKoWr3lPXvcFW8+V/sAKgL2
         RvdHJ/ggIW4ZuUoEO+sDwrIIEfpndfs5zz56zgCQV+djdAR6LIXIdyy/awi3H56QYhSE
         mkMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vIOq+yOE;
       spf=pass (google.com: domain of 3igplaqykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3igplaQYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768229518; x=1768834318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NJBDcujz9NHlsLLpMnf0Z0p1Limd1SBi18b/+msCjG4=;
        b=k/gmHlKPY/OWehCweH0xpD+q0aw0fJHXRrnEHowTR1oIDn2GdIhwyPVsrQDHU6RylM
         +8z0dmQ3w/MjXFLoMCUNodm1FgmdpmqMGCsF+OFNrO9BJjUEWsSbzn4I/jESOd268Ven
         fT96CfR4Fqha5I6jpdgKpPv8JeFSszDfeuioyPew0oArjZb463vIptISH8dUtbFZBaAK
         ZTpCPpnIACJa0fMMp5iy+mMmHID6hyVlIbZeUFPSkDb5RHKM1wCM2HoP+nE+43d+32Cz
         7H+12bPkPPcfFo0nuvnkkqEqbDODvCiB9oZUwGdzILO40UJ14mnqyGu3AA3Nwjj7gwVO
         IyOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768229518; x=1768834318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NJBDcujz9NHlsLLpMnf0Z0p1Limd1SBi18b/+msCjG4=;
        b=kcKf4azfIg2kp/85uMZ2+0LJi46sovyHcNgSP5Usjg26Kt66cBj73SbfcG0d9R3m2I
         Eb2xBWMCnUhnJc6JJ/7tyD8vxXvtJ8A+hilJkPUL2uIzKWf/EfZOYz1nHc3Ker9ZRkIC
         eeihyHYDNAm2CEME7B+Ekbx/tGNWWQD5rpYu534UrU7cjPG4sXDamR/RiLdhl2wiCfxx
         d3eA/WMe69HYnOe7R0t/CogZGuObvVEtArv0SCktYbg7cAvII7OkPMbv/4u0WTkawQlc
         +gAZmXtAPeoZY+Rlk2AeVNF4SJvsCint+jnGaP9gL5L1Y09XIyxNBH9h0CxwTDHJRMuk
         Xmgg==
X-Forwarded-Encrypted: i=2; AJvYcCW20Iaov3hQvE9F1kU0VNuXsXAyzgrqyPt0WvPG7XtL5eQY+vAP/h78x7ANY1it8pjcZ9iz7w==@lfdr.de
X-Gm-Message-State: AOJu0YxN7DLmzt8KG2cLQuMStDGZeHc6BMH+BKeViPEiIW5ZiCE1zEfe
	pNkyez6erTOlrEzTSQL6GyprGysFdhOOmsMt0k37HC8zFZpz+RISdO7N
X-Google-Smtp-Source: AGHT+IGdoLBjCNA6sQ/EPIsUe5P3Hh3rYNgBP9bLqrx4GyNs+mHcaWQKTTgeFobvfFwhPDpLwU9Cjg==
X-Received: by 2002:a5d:66cc:0:b0:431:384:15d2 with SMTP id ffacd0b85a97d-432c3760d13mr17787658f8f.53.1768229517472;
        Mon, 12 Jan 2026 06:51:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H/FbItMaw9iubObMzkgG2l6yS4tyFV09CD5fQz+1Rygw=="
Received: by 2002:a5d:5f43:0:b0:432:84f4:e9e2 with SMTP id ffacd0b85a97d-432bc91e333ls4415059f8f.1.-pod-prod-03-eu;
 Mon, 12 Jan 2026 06:51:55 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVTXkdQ3B/u0sPrHs6q6a/rQ0KcAKCcD6azy61dGCQvMTA35Hqpfc0lfrGsJ8Stqz9ZQzoM37gnW2k=@googlegroups.com
X-Received: by 2002:a05:6000:2689:b0:432:8697:be04 with SMTP id ffacd0b85a97d-432c3632927mr21577912f8f.20.1768229515086;
        Mon, 12 Jan 2026 06:51:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768229515; cv=none;
        d=google.com; s=arc-20240605;
        b=gk8ydKRDK6dDVibv8s1757aUwY0At4q83wF2tc95ehrAjMKyK5GJmCIG2dVtnV3i8k
         CRIfyPL9ihNjPZr+UecxVZhxKsbQJsARwC6bltyAksWIWbCRTLWe1jG1IVOUNwv0pQNh
         xy9+Sdu/5IA1OYRs/Z5wGm0DG2x42BT43c23rOxXBqmmNb5wkllQV6icGIImrPGTjwrD
         Qpxinx0TCh4AwZVJ3kTh/zWTTCAUpV2RLXScGInzzi04c1Xkjz9RsrdDOOWq9PYrTL9D
         7Z7w4oZZXFj2YWS8AJiBWqWzgGGGrr5Nv2pbw5NfA7fA9xwwuAYBJ2mk+RQsadHG2Gro
         3s7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=zb8lxCUKflLPJGxewVRt/oFLWki5YH9LqEd9Zx/sLAc=;
        fh=GK05Mb77QoV77CTlgda87uJwrF8jfSLZnxnt9URMNUs=;
        b=CkNX6dtk+zFP7SG9u74bKS2W/rZCnyywmDa076cheBgUh2aoToHx+p3zYtvfj5YLkX
         S5HnZTexyHTEQMOXQTMqAe/0spaYL1hawJZLUelq+wYQ4XzmrCp2HOL/NyO2ata9pALQ
         6OiaalNJcHS3Ue7gU+hIDlFso3JwQ87ta664BhEBkiU7ibft5aoWmxIbJEaOfIpDAMTJ
         Pef6m/EIUVkbSAyX3imfQgwZ6+I0s/dX95zL253XjyGE94BEee6vQf3ij6yxGt6w4IDZ
         UVW7ZpdqZfcSp6PfvYO4y3IZXCis/KuVjR0TBTSwp3KjXZgdfRLaI2AxErYlvubRf26N
         LRDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vIOq+yOE;
       spf=pass (google.com: domain of 3igplaqykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3igplaQYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be4fd1a4si371402f8f.6.2026.01.12.06.51.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 06:51:55 -0800 (PST)
Received-SPF: pass (google.com: domain of 3igplaqykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-6509eb7c54dso7441229a12.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 06:51:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU4PT15UB0llnV8l8hBzHQwZVMPXXXB1tAOc0/DOiE0kLJAdW0r1fBLWZYdeA/ZdxGVvTdXLi21NWc=@googlegroups.com
X-Received: from edbbq21.prod.google.com ([2002:a05:6402:2155:b0:641:6f6c:f930])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:3fa3:b0:b87:253a:dd39
 with SMTP id a640c23a62f3a-b87253ae4a3mr232543166b.26.1768229514739; Mon, 12
 Jan 2026 06:51:54 -0800 (PST)
Date: Mon, 12 Jan 2026 15:51:50 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260112145150.3259084-1-glider@google.com>
Subject: [PATCH v1] mm: kmsan: add tests for high-order page freeing
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, ryan.roberts@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vIOq+yOE;       spf=pass
 (google.com: domain of 3igplaqykcyupurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3igplaQYKCYUpurmn0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add regression tests to verify that KMSAN correctly poisons the full memory
range when freeing pages.

Specifically, verify that accessing the tail pages of a high-order
non-compound allocation triggers a use-after-free report. This ensures
that the fix "mm: kmsan: Fix poisoning of high-order non-compound pages"
is working as expected.

Also add a test for standard order-0 pages for completeness.

Link: https://lore.kernel.org/all/20260104134348.3544298-1-ryan.roberts@arm.com/
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 48 ++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 47 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 902ec48b1e3e6..25cfba0db2cfb 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -361,7 +361,7 @@ static void test_init_vmalloc(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
-/* Test case: ensure that use-after-free reporting works. */
+/* Test case: ensure that use-after-free reporting works for kmalloc. */
 static void test_uaf(struct kunit *test)
 {
 	EXPECTATION_USE_AFTER_FREE(expect);
@@ -378,6 +378,50 @@ static void test_uaf(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/* Test case: ensure that use-after-free reporting works for freed pages. */
+static void test_uaf_pages(struct kunit *test)
+{
+	EXPECTATION_USE_AFTER_FREE(expect);
+	const int order = 0;
+	volatile char value;
+	struct page *page;
+	volatile char *var;
+
+	kunit_info(test, "use-after-free on a freed page (UMR report)\n");
+
+	/* Memory is initialized up until __free_pages() thanks to __GFP_ZERO. */
+	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
+	var = page_address(page);
+	__free_pages(page, order);
+
+	/* Copy the invalid value before checking it. */
+	value = var[3];
+	USE(value);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that use-after-free reporting works for alloc_pages. */
+static void test_uaf_high_order_pages(struct kunit *test)
+{
+	EXPECTATION_USE_AFTER_FREE(expect);
+	const int order = 1;
+	volatile char value;
+	struct page *page;
+	volatile char *var;
+
+	kunit_info(test,
+		   "use-after-free on a freed high-order page (UMR report)\n");
+
+	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
+	var = page_address(page) + PAGE_SIZE;
+	__free_pages(page, order);
+
+	/* Copy the invalid value before checking it. */
+	value = var[3];
+	USE(value);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 /*
  * Test case: ensure that uninitialized values are propagated through per-CPU
  * memory.
@@ -683,6 +727,8 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_init_kmsan_vmap_vunmap),
 	KUNIT_CASE(test_init_vmalloc),
 	KUNIT_CASE(test_uaf),
+	KUNIT_CASE(test_uaf_pages),
+	KUNIT_CASE(test_uaf_high_order_pages),
 	KUNIT_CASE(test_percpu_propagate),
 	KUNIT_CASE(test_printk),
 	KUNIT_CASE(test_init_memcpy),
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112145150.3259084-1-glider%40google.com.
