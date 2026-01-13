Return-Path: <kasan-dev+bncBCCMH5WKTMGRBY4YTDFQMGQESOSEBPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6780BD17864
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 10:12:04 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-430f8866932sf6198637f8f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 01:12:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768295524; cv=pass;
        d=google.com; s=arc-20240605;
        b=H6ZEekJUZo+sfR1dNJpzePbVEbuxvAdIBUISPP0ZSaaXzku2fMPg7YfaP2XRv3V+rF
         KNbIDLiv+6NmOGKTvmMbrgLypCnBgtSNNPvbXR4hrZJnQUwZ1wwgk1SQe2RWkavUdIfW
         FU+GNI8LoBPYS/7jbX87bz0+9aswug/d6YbXr3MsucQL6V9x6ymWgQdVLID0/GYGLGMj
         w0nq8I/Gcd/G00sXYPWFrHiWEcFQKGzYuZmOjYhXLOCukTrdC/bEWubr2mtivHs3NutH
         xZCPkSi4r7GVoYtnsYjXIIJqfPk5sM6bjiBFZGNBcoW6vOAwxBlyUY3UADhAF+L86/CN
         K1pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=jX8LNOUV2yzDw/zdaiIruYv7dJgMm/K2pGEC2twJVrk=;
        fh=lH3ELY5iwYUhn2Cvjzi4bldYsWyy6jZvuYBKnAhHerw=;
        b=IUs3fHll+0jUhG3XSrN11eynTyiT6Sd6MOrDPLd4AcQOnhKGW3X9CQcLe/Ye5rVOrN
         Gn3Z0RAkiHkjtKj/G5qo3DKBjF9cRjJUng/3aaoNRcq6UVWFhJE0vb7MJe67TAZMnAj+
         +MxllqceCKhZjTWuzNcB85SJokrfXWmKrCRwJ788vwKmiIT3UbkD19fDK209awS7gf6+
         UIDJgGh1hHLbWddy/tkhFS2O9yKcPp5heRyTGKKyt8VlxJ/zqfkUD8byPDmgmy3U1+8P
         5li6+YmE7UzHPMkIqfZ/8C5CyW9wtH6mWrPfHP+yCk+Y7Ks1ByisHNywXyG8QufJnIlY
         17uQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bw56M0/s";
       spf=pass (google.com: domain of 3yaxmaqykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YAxmaQYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768295524; x=1768900324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jX8LNOUV2yzDw/zdaiIruYv7dJgMm/K2pGEC2twJVrk=;
        b=tNGOZrUpqzTnZRPEDnQT4j05GoyOENNchGw2ZiYGdzHBvvQ2zKoGsVZggDyq1d/kyF
         0jMFka+39s4gw7LQRQwW5zep5gbfuoRmaIk+ROGE6lFJKWs1REjkga+WfLjKVDo9ZxTw
         gC11AZOLB2bT71i2U89HaR1UQlNWjH+tOu6T52VV16PVC9BAc0RbdKMcxnZKiqbCH9H7
         QrqeUyyzauA7echcuynwtQ2znIXcxSBBtq4oQGgD5iF+nJOvFmSF0nhNTVLVz5TKrNg6
         rDs0BOZT1gyxehLnTn8HYMcde2ykCbtUEYvkTgPLlny7nOEq/zOZ86XyiFq3+z9WvXCd
         dyhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768295524; x=1768900324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jX8LNOUV2yzDw/zdaiIruYv7dJgMm/K2pGEC2twJVrk=;
        b=uAvV5e3TB35a2Mr7UIInh7Sib9c08hzYAHeCISRFItSoe4yFYvLkwk0f3emhgMJ5Ef
         XMHAglkx6il99fdHwH6zxfW74PvEwXIUJHuDTTI0SjFKQ8+cJX11tmg0dVwESshX2RmT
         FHdm8GR3UuHt0AjYAcYS4Im+GPRycZuZ7s5yYUIdITruCz5qsqlzABI2TTpggoecb6/5
         gaeePHSExttbbbmsJm/g91h7t+h7LWnOwqyKa8MlFv2rPWJsA19upNj+G03ejEWRaW7M
         h5QzddA5AWehUN1TM2Nrj02CW/MsbykzR/w+EGN4fzQY8J+hhp8S7NRAPXivvJgrCWPr
         RTrw==
X-Forwarded-Encrypted: i=2; AJvYcCUCgXkEAn0cVflI4ED8I+1YsZSw9EnpgCNePzJgikJg9h0GuyqAIbCQtBY6OE+G+t9Ih3rsXw==@lfdr.de
X-Gm-Message-State: AOJu0YwdB9pbUW9xOJFdE3pWmlDIXzrPyg4xIrXE4Cg7xW3UxAZ9GXd3
	ZNmKkivCghgufVZ3/+FYzQ+WVOHIRVZwksS7SNR/xp1Fu+/p56hCVt6W
X-Google-Smtp-Source: AGHT+IHDF71sG7oXnBCG/omhJf8vu51BsoAzbFhw3aA0gA1NuXdYjvsWuo5R1n9kuQD8uoU6G2G7SA==
X-Received: by 2002:a05:6000:290e:b0:430:f704:4da with SMTP id ffacd0b85a97d-432c37a74dfmr22053587f8f.58.1768295523484;
        Tue, 13 Jan 2026 01:12:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G5ZN62Hy5wIEk1UUQ77g+oRIZgvgoGATOed3lW+xfgOA=="
Received: by 2002:a05:6000:400e:b0:432:88bb:9f8e with SMTP id
 ffacd0b85a97d-432bc93a6bels4552044f8f.2.-pod-prod-09-eu; Tue, 13 Jan 2026
 01:12:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUrnAANVJVnPc3VRa7L2pLbTAJHidZmHepWPSN8Pmk6Efdsl4twZLHcNhoR9GC2IXTZPYITp7H52Zk=@googlegroups.com
X-Received: by 2002:a05:6000:2c0f:b0:431:16d:63a3 with SMTP id ffacd0b85a97d-432c379f205mr25121293f8f.46.1768295521135;
        Tue, 13 Jan 2026 01:12:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768295521; cv=none;
        d=google.com; s=arc-20240605;
        b=Lyn20Q8B1pcCmw4I72hb2tTNu938cEpLfKYaXFUYrf9eCsSIVPPHC3glgIxvMBRkcL
         gUXgDaw7Ho/HW3G82I4B+x9ZD5ra6AqNsMFzqsB/Q0ZgqoxS8To9gxu4UdbhYuQkKsAo
         db2Zdrf7GpqdBu1ylBU2RmfU/hvdlhjDB4VGzuoFe/P5mgBAqFN2JmCZxGpl0eK4odqR
         xOf87pkR4P8FpmlEi0HV7jX2KxbcZW8/SI1HJK4RoUNnPcXzfwJyvc4Vu8Ck1RVGB/Fk
         xtqhZTEto/TQhW70kAmg6rRXsJAxSW4IZW2n6IcoBz0NMQUiqzFGpIzST/F4nmYuyRFM
         cTBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=F46n0Clt9F/caqPQqDQW8qBOZa0FnmposgAtMZSYCf8=;
        fh=pPQLyO3iWJe0p/WTYBIWAdW1HsfVsXzKFtEugGxEyfk=;
        b=YFkXGdMNeN01ItpFqSHLtSS7pF26WLCXCCfY+ku+BcNHuuPmB/UQ688dsAj8FVyqc5
         ZZZYurKf3Q3gGvTvqqsCzHOYHPzplNy9zz0RODBRazmsx3YDufXrYXz7+0zYvpknoYqY
         A6LAfXAQ7YqqtQlvv8rXsJ4TLVuh8P2D3W5K9pbWmKFZXWlKnv49ToUcv+/cTAEiHp1t
         qXN9dIIXXQkVpvE0B2Yv1u5gD4VZC32C2eCrYBN4p0HEkWWtAXPLsGf3B+7CGtZ2nx3y
         0f50KKqSOapFSoIoTRxaMqBQhpnzgbJx3TyPpW8ZhokkH9Fjgk66Uzq9xKSbDWnVcvK3
         +sDA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="bw56M0/s";
       spf=pass (google.com: domain of 3yaxmaqykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YAxmaQYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be4fd1a4si423701f8f.6.2026.01.13.01.12.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 01:12:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yaxmaqykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-43101a351c7so5992430f8f.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 01:12:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVggYEJjux7yaf0RAkg4VvhDJk+86A5Euw65ohscyqCbnWEqJmtz4m0mKIkKReKgvmULLrcZG3BgoU=@googlegroups.com
X-Received: from wrbgk6.prod.google.com ([2002:a05:6000:3106:b0:42f:c9b0:e5f4])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:24c2:b0:431:c73:48a8
 with SMTP id ffacd0b85a97d-432c37c8796mr25385140f8f.29.1768295520722; Tue, 13
 Jan 2026 01:12:00 -0800 (PST)
Date: Tue, 13 Jan 2026 10:11:50 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260113091151.4035013-1-glider@google.com>
Subject: [PATCH v2 1/2] mm: kmsan: add tests for high-order page freeing
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: akpm@linux-foundation.org, ryan.roberts@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="bw56M0/s";       spf=pass
 (google.com: domain of 3yaxmaqykcwmhmjefshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3YAxmaQYKCWMHMJEFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--glider.bounces.google.com;
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
Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>

---
 v2: factored out the common part of the two tests
---
 mm/kmsan/kmsan_test.c | 49 ++++++++++++++++++++++++++++++++++++++++++-
 1 file changed, 48 insertions(+), 1 deletion(-)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 902ec48b1e3e6..ba44bf2072bbe 100644
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
@@ -378,6 +378,51 @@ static void test_uaf(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+static volatile char *test_uaf_pages_helper(int order, int offset)
+{
+	struct page *page;
+	volatile char *var;
+
+	/* Memory is initialized up until __free_pages() thanks to __GFP_ZERO. */
+	page = alloc_pages(GFP_KERNEL | __GFP_ZERO, order);
+	var = page_address(page) + offset;
+	__free_pages(page, order);
+
+	return var;
+}
+
+/* Test case: ensure that use-after-free reporting works for a freed page. */
+static void test_uaf_pages(struct kunit *test)
+{
+	EXPECTATION_USE_AFTER_FREE(expect);
+	volatile char value;
+
+	kunit_info(test, "use-after-free on a freed page (UMR report)\n");
+	/* Allocate a single page, free it, then try to access it. */
+	value = *test_uaf_pages_helper(0, 3);
+	USE(value);
+
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
+/* Test case: ensure that UAF reporting works for high order pages. */
+static void test_uaf_high_order_pages(struct kunit *test)
+{
+	EXPECTATION_USE_AFTER_FREE(expect);
+	volatile char value;
+
+	kunit_info(test,
+		   "use-after-free on a freed high-order page (UMR report)\n");
+	/*
+	 * Create a high-order non-compound page, free it, then try to access
+	 * its tail page.
+	 */
+	value = *test_uaf_pages_helper(1, PAGE_SIZE + 3);
+	USE(value);
+
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 /*
  * Test case: ensure that uninitialized values are propagated through per-CPU
  * memory.
@@ -683,6 +728,8 @@ static struct kunit_case kmsan_test_cases[] = {
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113091151.4035013-1-glider%40google.com.
