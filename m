Return-Path: <kasan-dev+bncBAABBAXM2SEAMGQECMKPGYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B1433EA6DF
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:54 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id u25-20020ac251d90000b02903c64ed27829sf1932776lfm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780034; cv=pass;
        d=google.com; s=arc-20160816;
        b=wnHRfpjiE8T71d67F4jl6O3IT//yfIr2xSuMtgbnrTscLIW0YuClhehxb5Bq1WEQS1
         gEv0eVkb+DuzSr015tYq3BPAIWO2GVA7oZqJll2pROQmGUGzcpAi3NMWPFJQohQuDA1V
         NlA8kLbLAvHBTAwFlzyyIxroVrPasLfGbatiRnBTVEu2VQ1x/UVyShFB1iiWPu6YSUHo
         j3uSGsLqv3hU6sYAp7rB42ouqfbRRkv6Tqy+emvjoBwK38YbZ3HGZ1dQMVgaTfWmLbqX
         +wX9MLKeUsFYBDyGNBOiwGCVJRjyVH/Q+3ED/dlD+lwcSldnjqvmiAVhCgd9H7c4ctvt
         PsYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UGZpxcemDmqnJ3r63pJLxwq79aGWURxV/7Q+sbLf+/A=;
        b=GcuV4gyVLopC9w0pt5KObBqoTAHOhMB5Ag+Ud9lM/EyctoFvrUkgfREv/+Tdn+y8xA
         wY6/zSxHHfDH9IMVoA1+G6RxJY0vXiDDBrK7lTDwLO2KO5qntuS8t9HsFOGz9eANBWh0
         ujXAdS93Jtp72TMJa2UtnckXhQal3hNr6tyWxWI4m0sMYt7jJKSYFHi0xQOk/Nul/pf1
         gofzD0o1vZEmehbPNeByGVM/JaKccHyeBz0v3tB3EHgNAxXeQopcX028zOoUNq1Rc+3n
         USPdHxn5UDEvvlswyArSXaJySg1C/XgSRNwyybIR+HfPs8ypyDfPDpf6rziOV8OnOPEg
         484w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AZHYWSAY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UGZpxcemDmqnJ3r63pJLxwq79aGWURxV/7Q+sbLf+/A=;
        b=oepIQfPisqW55oTdD7lo+qKBSD9oroEM1AuZ9VPO28NOgiBvbElz+UrpgpTfTn+kMI
         JKnUuRYgVb0rTjoruqJNAMQ43YcySE3DQSqZBs7J2ZlEUlAKj+7WNdIxly2KA6R2BUZL
         wwi9u2/+zlS9ivRrYjKHVlNamy6nSdtObXWRGRnZgmwACF8LR3UGzasDdzL5pd+VPgbL
         0VARt4GVJBcqYt/sxTP+YAkrb5KO6Hvec4qLkcrl/VqKbOhrTL96ybf95HoLv1zOMUHw
         y8y19htH77PjrsTWRs+r13X7sHkoCYX7GpbS4m95ALCktgezT0fU8EIU2YUYQ3pPb4OO
         PoIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UGZpxcemDmqnJ3r63pJLxwq79aGWURxV/7Q+sbLf+/A=;
        b=nBD7p2+ntx4lIuhec6PUI+/opqhM2tMS0qmAxEO1WnTafnUAMD8sTrt2oHHuVTQq8g
         dT9HW6D22ZvSKDiXuWR2gqjq1IeU4uap8m8DzKJXc1hRJlwxRMyCXwRgfS8sQGqFoI1Q
         /0h0GVYFI8/QlKNV0TpDiTG0YksRv9vNDHKwVn2vOeCm9JT3OWxh5WM1IKX+5stDUFKG
         vG5xeIXRNz89U14LUw3JNUlIUqQhC8Q6yPRznVGy2FHw/Wc//09rCP7rlPzAHrVifhN3
         3um4B5OiHcnmmG/0NSQleaEXMYS5TmHXT07GTdQVuL+/5qgsE1cGWbqHJV17eglpVxt1
         +i9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530F3onJK2rdcDHKeyupI/l1kjQs+S3SAHsSRsWAnb+fvjBsDDZ+
	GPJcAso2TtxKjdkGHdpLY4E=
X-Google-Smtp-Source: ABdhPJzVvC+ldAHV+V5+eJUMouqSU4XmvbuaVljrMwXvHMP2+lEsh9G6RnzRZLMx33vsBDlikWu/SQ==
X-Received: by 2002:ac2:5e8f:: with SMTP id b15mr2713818lfq.651.1628780034244;
        Thu, 12 Aug 2021 07:53:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4146:: with SMTP id c6ls726578lfi.2.gmail; Thu, 12 Aug
 2021 07:53:53 -0700 (PDT)
X-Received: by 2002:a05:6512:1105:: with SMTP id l5mr2796807lfg.351.1628780033374;
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780033; cv=none;
        d=google.com; s=arc-20160816;
        b=0uHn+uX9F1AfPN4sD3BCXZmYqKjPabphJYSD8AvdEjIwO8G9sth2cTcIWDF70SlmUL
         iWmFDHLWG7QIO2vjuAxxQmD6EPfUZHn/Z2B2812gbMGvG8rOK1FXlcbVSRItkh6B5aev
         PW1XwOFQfHf5X/X+wcY5ZuxaoUMDV59PK6Jfc2Yhq0gn3GcGBAZwLqGF34IgS28S/tTB
         AYztq35hTnPgS7HRSfMq5yHUBVu4m/iOjdy2D7mXdCnWuAhhte97osRDLMcYicc+eEez
         FCmHZEQOE8wfUnm2w22LbdUgVUeXUO6LyyODHzTtBHSMcr0eLtel58JyYsAOm67uFjfi
         MeNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rCxgc2eXwoBM9Jq6kKWMWlEDWeYYkjt8bVAWDL+S3zY=;
        b=qf8TwGrpYHAwS7PHWSfhHHRTud+wGmeWDgVHdmxfI19UFGhZ3gG1fp7c9KCTSrKOk4
         PN+JopupbAeXeDZ28fsbLf7SYbkPSNnebT46gKr4+rGpPyjIj0xuGJELJU0WInosq+0b
         TP6PzeggH6nW6O4ApZtPsKMlsHzexQPPXIKFIh0yUjCPk/pI1g28k8kTb7i1EAT+myiL
         iBOvrJRyonem08iItauM4VnlDDnb3Xg0oAgGgq7gVKwx+j8sUvLG6kKhNXOl1in5khCA
         sFP97lADcIqKJVp5Ydo6ecWixydmrEuLEx53Q7V8roHuu6MZk13ThJsg1AwhVnWaYnpV
         oO9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AZHYWSAY;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id q8si191565ljm.2.2021.08.12.07.53.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 3/8] kasan: test: avoid corrupting memory via memset
Date: Thu, 12 Aug 2021 16:53:30 +0200
Message-Id: <64fd457668a16e7b58d094f14a165f9d5170c5a9.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AZHYWSAY;       spf=pass
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

From: Andrey Konovalov <andreyknvl@gmail.com>

kmalloc_oob_memset_*() tests do writes past the allocated objects.
As the result, they corrupt memory, which might lead to crashes with the
HW_TAGS mode, as it neither uses quarantine nor redzones.

Adjust the tests to only write memory within the aligned kmalloc objects.

Also add a comment mentioning that memset tests are designed to touch
both valid and invalid memory.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 28 +++++++++++++++++-----------
 1 file changed, 17 insertions(+), 11 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index c82a82eb5393..db73bc9e3fa2 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -428,64 +428,70 @@ static void kmalloc_uaf_16(struct kunit *test)
 	kfree(ptr1);
 }
 
+/*
+ * Note: in the memset tests below, the written range touches both valid and
+ * invalid memory. This makes sure that the instrumentation does not only check
+ * the starting address but the whole range.
+ */
+
 static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 7 + OOB_TAG_OFF, 0, 2));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 5 + OOB_TAG_OFF, 0, 4));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
 	kfree(ptr);
 }
 
-
 static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 8;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 8));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 16;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + 1 + OOB_TAG_OFF, 0, 16));
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
 	kfree(ptr);
 }
 
 static void kmalloc_oob_in_memset(struct kunit *test)
 {
 	char *ptr;
-	size_t size = 666;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr, 0, size + 5 + OOB_TAG_OFF));
+	KUNIT_EXPECT_KASAN_FAIL(test,
+				memset(ptr, 0, size + KASAN_GRANULE_SIZE));
 	kfree(ptr);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/64fd457668a16e7b58d094f14a165f9d5170c5a9.1628779805.git.andreyknvl%40gmail.com.
