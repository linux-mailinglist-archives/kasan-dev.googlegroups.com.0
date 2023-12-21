Return-Path: <kasan-dev+bncBAABBL5VSKWAMGQEFLQ3UYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 5037E81BF5D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 21:06:08 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-548e2b9fc55sf3873a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Dec 2023 12:06:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703189168; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y9leLRs9Z7fdgo5R+a5I5V7LvnHGoOhJA0iVSNleQxy/DvzHWZrXuLIp2VJuHOmhsF
         UKNYd3LxhSFu4j2MObhochnTks1SoZv2BOjlpOnlq/BNwI6mkzMO/3iRacRSBCMREDaJ
         B2w7YjDDWanhrvQbOE26yjtMDXAiCzs5ZQVEX6tbRmi1fng6cvkOTHCzYWBDUTug7+2N
         Smkg2nKMiI46DOHY1sKJjtivMJd/Cb8GkNOXKZhTVoZPPLQHbdNbOT1EAFJeqYZUfuQo
         r3dSbbEl0zzbNGKiQKO1dNI6Fukva8Z5adW5YSgvvrukkudS45p07zk8DYoQyI5pr0Bh
         6zXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=susd2FUc/Gj5CbBxK6Hwq/+0VnRzw3CVTLl7cMzkBAw=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=wDJ/YigfIe6nrISuvb5O9aiCcFGmGOPiAy47HiyNXRywHXexfILWUy76Fe2D4Mgwyr
         phsiV5KWIzS9JG0/f8XsfDwGzwpq1yVNIdxztnUmlLgANusKMCO1Fe1hWqxsgERM4zYB
         kBApewTKlqosLUHyeIhOzLdEaxxEz72GbEoY5AOn6kpr3dSACYrpc25ssTs6VIzGtC6x
         yy/Xy9+3CSpy13ntumz9li1qxNB5Kg7KW4LdTQD2SJ9cZY2nc6j1xIX86AJ5054H3GUb
         6UI7Ps45MaI8SqJabyUZeiAowaZ4cE6/DDSnmf085D5y4BjLBBb0u6ngXz0o8ohEJ3V2
         Njxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=USMsmCfc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703189168; x=1703793968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=susd2FUc/Gj5CbBxK6Hwq/+0VnRzw3CVTLl7cMzkBAw=;
        b=AT5IrsGpsgeUH9Xbz0udDw8vlikVkpX+fRCR+SkxuDCqrMPyfg005d7mZOg4AtP81O
         LktNXukkVXkuHMabU/0Lcl3qF0haEyqyVQS+d53P3dmLAO48iCBR5Dh1vnznLWeMSy4A
         zKhZ5GhKcK3EuyRQ1+nk4iEmAn2Z4hbPcmcXj9Yb3w3KKjg7Xl5RAHwDq/Cv4D0vMnRA
         jcJQ/hZcVCDnYAUU537usATcHIbpoo4GhCuJ1EeypxWrO8eCuWVQqRbV09sD2kW+xL89
         /xXCUkVLX7FCPrim5Wl+0ZdxxUbfqTNbjQwGF/9W4NvFq8YBmkmRiyPY9I2jnS9bisBL
         AQoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703189168; x=1703793968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=susd2FUc/Gj5CbBxK6Hwq/+0VnRzw3CVTLl7cMzkBAw=;
        b=KxuyfrMIhvkzquN/kaySWBr4eBr0mZ9fTbHe/PqOVedv8UyrkVd+25z20jQ4+2/+rc
         v6DGpAzACp3jbTfg42Hkitg5kijj+1hjw/a8EKOAlg9Voa9WZUie07na6jxa7nnE7AdP
         tLzKZ6n3vrU2CZmSZ7IUDizttnp+rfhsnnBAeoM3rN112vI3XgkR0Gkl0K6KuGWDYp+7
         EkYeYPCgbf5Y/QQ24cuwymfmO+UA7mWi5O5vpzqzkJtN1/7TCzQOLbd6W0J2f6ur81L8
         YLe4XVX3nyZSwpOPLgPpn6Y8vu/1FoIfRinqnSAwitJ32FefWVLeO/fkNhHXRdG26xn/
         VRxQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxUwqI41e6I0MRga8HDOo7v46zJTKShB+O8L1vM8E7LXcKisd2G
	JisQcuwKT2pCs9cLtwnou4g=
X-Google-Smtp-Source: AGHT+IFrsrg+CYOrKbDf5dgrAbmZiTHXeVEAqiBPIOtTWtJLyc6zGeoDG8TSX5HAwG1pAeqttaZwQw==
X-Received: by 2002:a50:ba8e:0:b0:554:228f:4b8e with SMTP id x14-20020a50ba8e000000b00554228f4b8emr26491ede.2.1703189167649;
        Thu, 21 Dec 2023 12:06:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c12:b0:40b:3148:1b7e with SMTP id
 j18-20020a05600c1c1200b0040b31481b7els672930wms.2.-pod-prod-03-eu; Thu, 21
 Dec 2023 12:06:06 -0800 (PST)
X-Received: by 2002:a05:600c:520c:b0:40b:5e21:cc29 with SMTP id fb12-20020a05600c520c00b0040b5e21cc29mr148701wmb.84.1703189166186;
        Thu, 21 Dec 2023 12:06:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703189166; cv=none;
        d=google.com; s=arc-20160816;
        b=yFb1/XgqKDWxgffFY707vtm9VHUMN/VngsZjuNGhFRvToomd2km1qw2OT8tbFDKI2r
         KK48eE6TbsioQrwRWMtk9tBWhsKO0FhsBq2RxnB4BMxnoIu943az/G9dmdSDvY5ngH6j
         /RYqXQdvgePG+DWtHGTpiE1oNHVF3nu83jHDzMPadcP9fmcfypjyd2lZwUtpIGF3ghHa
         KKgrpXPG5fTUiAG06tgKD9Woiz16/4pkwWq+TWmZmwdcKn4bpaM02r4U7i1UXyElo9Mq
         v99RnbDHYnojVJzX5BXrmCG7hmw2LjGL/86G2sRHwJG+w85mopjjTIyoyoJWdOQvJWX7
         4GTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ColijDwhDovJxdnzDPHxNzx5OycMVFqUSNs1GHs5mVk=;
        fh=GyTEpUCUNPwsl1pqA0jDPXgvja+iZTM9USlQd9sQtQg=;
        b=Speh36H5wsm6LX0K3WEC3hYPuMM+qJthI8EaRCWJGP71Kikeg99rs0h4ukRr0C19E6
         49nNQr64f9xWe4Mud0jYK0gpgv4Y76g1jSQc7lWpwQIx+rJ9ix/KtKZtnoJRB2m02yOp
         tj6aiJnXUQcKOxtmQvkh0Q32vH3yMWT0cbatdaq+AwMMPsG4etxvQj6re73kgue10U+7
         94Ks7dCK4SrSOBuKfNisuy8UeV+CHRTxBFDROWcnVAEPMbKDqmXhooyYw2dS6b29Ass8
         kj8Wm5CbLyocrJ7Rf3tPl2rY79OSEVOeUb9DJQWDeYy2gXlq2N8nOG/d7vmTpX0/405n
         dYwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=USMsmCfc;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta0.migadu.com (out-189.mta0.migadu.com. [2001:41d0:1004:224b::bd])
        by gmr-mx.google.com with ESMTPS id n40-20020a05600c3ba800b0040d3ff92a4bsi68758wms.0.2023.12.21.12.06.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Dec 2023 12:06:06 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::bd as permitted sender) client-ip=2001:41d0:1004:224b::bd;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 08/11] kasan: check kasan_vmalloc_enabled in vmalloc tests
Date: Thu, 21 Dec 2023 21:04:50 +0100
Message-Id: <954456e50ac98519910c3e24a479a18eae62f8dd.1703188911.git.andreyknvl@google.com>
In-Reply-To: <cover.1703188911.git.andreyknvl@google.com>
References: <cover.1703188911.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=USMsmCfc;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::bd as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Check that vmalloc poisoning is not disabled via command line when
running the vmalloc-related KASAN tests. Skip the tests otherwise.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/hw_tags.c    |  1 +
 mm/kasan/kasan.h      |  5 +++++
 mm/kasan/kasan_test.c | 11 ++++++++++-
 3 files changed, 16 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 80f11a3eccd5..2b994092a2d4 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -62,6 +62,7 @@ DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 #else
 DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 #endif
+EXPORT_SYMBOL_GPL(kasan_flag_vmalloc);
 
 #define PAGE_ALLOC_SAMPLE_DEFAULT	1
 #define PAGE_ALLOC_SAMPLE_ORDER_DEFAULT	3
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index dee105ba32dd..acc1a9410f0d 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -83,6 +83,11 @@ static inline bool kasan_sample_page_alloc(unsigned int order)
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
+static inline bool kasan_vmalloc_enabled(void)
+{
+	return IS_ENABLED(CONFIG_KASAN_VMALLOC);
+}
+
 static inline bool kasan_async_fault_possible(void)
 {
 	return false;
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 1c77c73ff287..496154e38965 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1540,6 +1540,9 @@ static void vmalloc_helpers_tags(struct kunit *test)
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
+	if (!kasan_vmalloc_enabled())
+		kunit_skip(test, "Test requires kasan.vmalloc=on");
+
 	ptr = vmalloc(PAGE_SIZE);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
@@ -1574,6 +1577,9 @@ static void vmalloc_oob(struct kunit *test)
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
+	if (!kasan_vmalloc_enabled())
+		kunit_skip(test, "Test requires kasan.vmalloc=on");
+
 	v_ptr = vmalloc(size);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
@@ -1627,6 +1633,9 @@ static void vmap_tags(struct kunit *test)
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
+	if (!kasan_vmalloc_enabled())
+		kunit_skip(test, "Test requires kasan.vmalloc=on");
+
 	p_page = alloc_pages(GFP_KERNEL, 1);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_page);
 	p_ptr = page_address(p_page);
@@ -1745,7 +1754,7 @@ static void match_all_not_assigned(struct kunit *test)
 		free_pages((unsigned long)ptr, order);
 	}
 
-	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC))
+	if (!kasan_vmalloc_enabled())
 		return;
 
 	for (i = 0; i < 256; i++) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/954456e50ac98519910c3e24a479a18eae62f8dd.1703188911.git.andreyknvl%40google.com.
