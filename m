Return-Path: <kasan-dev+bncBDN7L7O25EIBBOHZQS3QMGQEVFWL4VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id B5A48974A8E
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:46:17 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6c360967e53sf90549796d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:46:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037176; cv=pass;
        d=google.com; s=arc-20240605;
        b=aAZu25Oi8QP/3QfgkECOFr1z6pIsRGNrOdde1F3bWrIk2jwdk0mgIlLQicQvB7peGT
         lZQjSiW9ejo4W1dfhNsHhWmm6G0+2o9ZrYW4BCItzvZ0CUwXEVN2RprDNljHWBCo01co
         oP81l5wHmHy+F4fu7yB7+dkjlcWCDCRznBZmD3srlItk+KIJ2HYH4TMNpVtSvJLWO053
         HIsjSQzRoZHTVbn95HngvXSPXbHh5geYiDc42HbFfSBYxIPsKqcH4uxNvYGVP6K/riZ3
         yWmspIe5l7gL369nWL/yNS4F3DbmSJMra+bXnG8GoDq5JTVxHhn0j7OnjKcCdpRszni/
         TW5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pJVEIA8TfwINhG+YCRoDH/QMzf6eCtoKwbrc2HSv+a0=;
        fh=kObs/9eBbHp0rz08HdiNrUERTPn93lcz7r7YgmAKEMc=;
        b=Br2PrM2v3hwapYW4k479c8E88R1i9qOlEdXZWsQ/ZHKiet1jon13+mr8koQ7YcpT3r
         hhmu8hIF/wb9hqGwE0PyZydHwh+yuhXlFnTym1jqQeulPOakcggv06Vhfv6KP8LvYZPE
         0BUSjSX+9WxYCInGCU6EoivhJpvwK0NXqOEGumLEKaVPeKMI+pvbBnbBLpQjRfaGa/Hg
         VH9OtowYX5c7fsd4Lpcd+M/yTZIBBO72+YKPwfJBYAdWobeJa+3HKSRXIw0ddW/Vus8j
         SfMVm/IrXGGq0VdD0OgV1EtC9Rcf6r/x3zGb5rrcd/boFsAZpm1uSjAJh9RiCvdErsrF
         ocvA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jYACyB8Y;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037176; x=1726641976; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pJVEIA8TfwINhG+YCRoDH/QMzf6eCtoKwbrc2HSv+a0=;
        b=kHP3BPk/TJG8ZeXImyHQY77eR9TRRtQxjBZ7tLyhIl6H2n8K4csNT55ngwehsoTYVO
         oAwo8UnApNKY8RlESHXax66V/Krpr+MS5xbCg5CxBtSE9EJpjHXst5bfojqt8eaQ5gir
         iGwInuD9DC+df4bCd/kZd95CXAyiIYxsl9A0CBpR/AwcvnZygi6z03Tp545eqiiFEZSz
         PqKpnCXxs5Oo6+wNpEBPR22PFmwtI2uxtMx8xv598Spk2XoMgiIS+GkTfwdqYWZBXwdG
         HeJTRAqFYTMpXifYhfvnaQZqbB8gB55Bw9HhKfSCGrGeowplEA+ZIC+h5P5yB4N1sPIj
         /ZRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037176; x=1726641976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pJVEIA8TfwINhG+YCRoDH/QMzf6eCtoKwbrc2HSv+a0=;
        b=Z5YRPpqYM5ib34kkYmSLF423ne93Afcb2pIJNOQH1C1i8zZpyxLALIus9g19cKRF6w
         AmMLzzCOCscRG8TzBKDHFYfQU00coWxVxQErXIXoNksE0v1Z/yabbMQSSxslueD1MvnT
         nZNo1nEziGNfpJlEeK+1Yx84UalIl4uouYLg+siNb9/f4ivefTiVB5M/S/CqOwf8KVo9
         TVs/nTgWFkJ/doVrGXQOt1WPJKoGrprFYhzZ2FPt6EYQKE5656UA5NOUjpQBX6vx1vln
         OWoG7Dswjrbboc+NIBZegzICd3fWPFsVI42KYtRnMLCX+oUN7bcxfsf8/0FzRbigqIt0
         kEyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW8AzT9m09jcNa6j8FG13H6eO/khFvwVPf+4unUdKX7LMBDyN3Z5wtfGt/7DXsb01j3Fpvy1Q==@lfdr.de
X-Gm-Message-State: AOJu0Ywo6T+2yU7NhyDdn7xGRWUYXwY0Zz2rWWU7BPG9dFmwQzBHGwct
	7fRIzUol2K24wkc0//RJjx1pMetEQ7AUcSiF5khenTHa+MRCh++B
X-Google-Smtp-Source: AGHT+IGnfDG227KaFU/xwNOkNLbIFr0IaHooZF6BNJ0DK/1mDhwQy+LGtX3qrqFQOSTJIWiUbUtwlA==
X-Received: by 2002:a05:6214:5406:b0:6c3:6de4:be0d with SMTP id 6a1803df08f44-6c528508c45mr223260976d6.40.1726037176459;
        Tue, 10 Sep 2024 23:46:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1312:b0:6bd:735f:a70e with SMTP id
 6a1803df08f44-6c5279b1a7cls33993126d6.0.-pod-prod-06-us; Tue, 10 Sep 2024
 23:46:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUwh+2NpMtElAahCt62YvRwamHLrrqtfEkwxsWpKN3fSm1nwQ6JhjbjuH/HiR7Rwz1eWRLg1+nTs7A=@googlegroups.com
X-Received: by 2002:a05:6102:38d3:b0:49c:e92:7f3d with SMTP id ada2fe7eead31-49c0e928052mr6301495137.16.1726037175708;
        Tue, 10 Sep 2024 23:46:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037175; cv=none;
        d=google.com; s=arc-20240605;
        b=NL8yLwh+ckvl+oTTWfRoRuYn920sp6c73tS3cOO5mVKoAX9TsneXcQZeWf/IORXSdB
         yPUt+WSDQ99TUjgS8vj9TPO0Zw2R2ZgOjlVBai/ZA17HfOSXACr5SYQBxQyzj63F+bCS
         xjk0suIGnO11+mns0nrL+qOiyrmMOGdYUkoNR1NGC3yh4TCY2/FktY2Gj+WmDRtKH24f
         Xmsk2Y3fEamE6e2NgrBdk0ct261ICBvcQdX2czyqDsisNHoeeOvvFblqzjWa+ki9a6ze
         iRLC5UYw2jaBDU9pd9DK3fc38V/mxfio45fkFMwMB5gBEh6YYiXinQIKZjHBg+bvF43T
         7+EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1BHG+Zromux7mCdATmh4gGmA49XGYtvRJwCiGSv6jro=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=JS+Qt/1TwOlrYzASjvDTVwRLIqsrQZ6Myo15qHvOKtOx5vKdu+LjTz2Q79x+LtEAnA
         3StMU01a/cX4Pp6zeesah7LmfqEhMxvQTBF6+b9a2TIUtjtZh1F6EalSWLoe+6ux+dww
         pSTwIMP2URxTOd2tr0ZGBjhAKmoIVDEsF2IfiXLS31lvDdzKyBXaW5BElPTuiFj0LBUg
         GXU4zQgCrD/qJt0QzVDkTVL6jP7DPZF8WNkMmFJEvGmBwy3ppg9SOUxH4YQiN6oNor8l
         5y+EuYg9+oiEsnHwOslV4nJiAoMiNpbNfw5TSwBZiGRrWBRAOsJbIWmhn8gV7aRtTa0r
         feAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jYACyB8Y;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-8489ace45e2si354069241.1.2024.09.10.23.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: uO3YH2jCQY2MEyv/fxZk/w==
X-CSE-MsgGUID: vO4CPRxNQuC4Z9XfPhQbpQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36173048"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36173048"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:46:12 -0700
X-CSE-ConnectionGUID: tvwWZ/Y9QRKy+QIHoKa/xw==
X-CSE-MsgGUID: V2Tkj4x9QrGrTc/GWUmeNQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771512"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:46:05 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v2 5/5] mm/slub, kunit: Add testcase for krealloc redzone and zeroing
Date: Wed, 11 Sep 2024 14:45:35 +0800
Message-Id: <20240911064535.557650-6-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jYACyB8Y;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

Danilo Krummrich raised issue about krealloc+GFP_ZERO [1], and Vlastimil
suggested to add some test case which can sanity test the kmalloc-redzone
and zeroing by utilizing the kmalloc's 'orig_size' debug feature.

It covers the grow and shrink case of krealloc() re-using current kmalloc
object, and the case of re-allocating a new bigger object.

[1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
Reviewed-by: Danilo Krummrich <dakr@kernel.org>
---
Hi Danilo,

I keep your Reviewed-By tag, as I think this v2 mostly changes what kmalloc
slab to be used. Let me know if you want it dropped, thanks.

 lib/slub_kunit.c | 42 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 42 insertions(+)

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index 6e3a1e5a7142..b3d158f38b98 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -186,6 +186,47 @@ static void test_leak_destroy(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 1, slab_errors);
 }
 
+static void test_krealloc_redzone_zeroing(struct kunit *test)
+{
+	u8 *p;
+	int i;
+	struct kmem_cache *s = test_kmem_cache_create("TestSlub_krealloc", 64,
+				SLAB_KMALLOC|SLAB_STORE_USER|SLAB_RED_ZONE);
+
+	p = __kmalloc_cache_noprof(s, GFP_KERNEL, 48);
+	memset(p, 0xff, 48);
+
+	kasan_disable_current();
+	OPTIMIZER_HIDE_VAR(p);
+
+	/* Test shrink */
+	p = krealloc(p, 40, GFP_KERNEL | __GFP_ZERO);
+	for (i = 40; i < 64; i++)
+		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
+
+	/* Test grow within the same 64B kmalloc object */
+	p = krealloc(p, 56, GFP_KERNEL | __GFP_ZERO);
+	for (i = 40; i < 56; i++)
+		KUNIT_EXPECT_EQ(test, p[i], 0);
+	for (i = 56; i < 64; i++)
+		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
+
+	validate_slab_cache(s);
+	KUNIT_EXPECT_EQ(test, 0, slab_errors);
+
+	memset(p, 0xff, 56);
+	/* Test grow with allocating a bigger 128B object */
+	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);
+	for (i = 0; i < 56; i++)
+		KUNIT_EXPECT_EQ(test, p[i], 0xff);
+	for (i = 56; i < 112; i++)
+		KUNIT_EXPECT_EQ(test, p[i], 0);
+
+	kfree(p);
+	kasan_enable_current();
+	kmem_cache_destroy(s);
+}
+
 static int test_init(struct kunit *test)
 {
 	slab_errors = 0;
@@ -208,6 +249,7 @@ static struct kunit_case test_cases[] = {
 	KUNIT_CASE(test_kmalloc_redzone_access),
 	KUNIT_CASE(test_kfree_rcu),
 	KUNIT_CASE(test_leak_destroy),
+	KUNIT_CASE(test_krealloc_redzone_zeroing),
 	{}
 };
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-6-feng.tang%40intel.com.
