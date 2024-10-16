Return-Path: <kasan-dev+bncBDN7L7O25EIBBUV5X64AMGQECEF54UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 640809A0EB7
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:42:11 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cc01327930sf61194866d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:42:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729093330; cv=pass;
        d=google.com; s=arc-20240605;
        b=AUhHqbKpu/lUh3kVChUAd3O0I1FUCRqtrwUsdH3/WhzKq1aN5yiVqAb3HU9q8n7OPx
         bmR8xjXBvw5109STGyZPjhe1+aqOmdkYPNxt+oJtD+/ZcYT8JDjFe7nfW5cC0Oap4Gxc
         WidJS+qXy2VpJZ3iCa+0wR3zQZXkLAHI3KRHJ+/WBWCvXjYBb6CCisEIdVTiITOXoKtS
         2mbmCuziMr7VJIpXSyUcC9pFQLCNyfQA9g33dYAbBFDCSvCWcnfO9xOp+UTTiP+nxpQE
         AAJW6dZUV9V7U11n3uddkOVmybH08/2tcOmXWxH2MBIwIthhTT0tbBo4/Eo1YcpdxXYu
         PvlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BYch4nzHR/5ot0JaNzWQ6SyFsa75mre+kFkzf7t4YSY=;
        fh=rhP4r3StIQLkTTVix2TCZko5MJQn8yhwBCmbohNVysM=;
        b=Ctt7aq6IphlUqU/RM7rGQg1LZWyU6r4LP0b4iv8dz5rlb66yYvyod7jg+neojh7HQl
         U1/XIm5pqkeM8U+AC96ThajOBcQvFRPHPL0qn7V9RZH5m0FPoCThC15nHAX5LeNGbj6u
         258kRVX+9LxDSurl4rdCVzM8mJNYJlMuMtFqkrs/plNySxh/lwjfqwOqFSUTn/HpakXa
         EYYA52Q5XsNIQ7YBFqu+2+Cro+Xjy2BgDtpv4CKv/WhRSvyarx+qyKOr+HGGGNX/ZpNV
         emdBvAn7JMsCTFg3rWC08anADBDh8V4EcR8mPCdgbJvwRMZeA7fDFHrw89uP9iOC9IUO
         Hl+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K25Pibhp;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729093330; x=1729698130; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BYch4nzHR/5ot0JaNzWQ6SyFsa75mre+kFkzf7t4YSY=;
        b=Lni4qP+QGnYVjLlwgaIe6os9Wcl2zUo6UfvlvMeeplr87SlmeJ63dVXW0m2Q0YwfFn
         GS63n6Xry5yLKGes2zNJISkkXAzVxgBPH9atVf1sJScttJr8yZDwIUuij4NUkw+KVy7Y
         73A/qADrUrZO61V1E2nRD945RkNclkEBUbrtf03T3C797Y4YljzcXG6b20/o1J/fVsZX
         mxFkokuMPl9C5VqW5WBdtF/SrW6xy7BW6hlICPhD88n7LVFVf0+5MltRZ2DCt7jFGEI/
         raiqiIXZnXza3qjl8PYlmiu2JB0OWowSKpbMPIblIG8D1ZptdeRvOQ4dlVt79Xe59FPd
         ECbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729093330; x=1729698130;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BYch4nzHR/5ot0JaNzWQ6SyFsa75mre+kFkzf7t4YSY=;
        b=Wz6wmcCPWC/V4In4tdV9Qsepmn01L8dMxsJY05yGQ/HIKLIXi44URn8EIi+5rYIvAv
         1tBhei/3d39zkGsSgBib9/nTDcOcLuyt6czxa5BncRrwqjTzRmRRVgZD76Khwtq7Nwcp
         NKwLl2LPklzV4bJYf609+DIXJ/rHXWfbVJ4tyxpXrcC7f+oexcwEj3JidgbZ85ZkjGFM
         fDIMQAzRmLfHW97z7M/uknqFcqySKkqwgu2kmmIcqgC6crJbxV/gHubLdZjE64FIR6vw
         4Yyi5F5wAmDKLDGT7z8sXAt7PeEK/Qb+pAlYsZcHG8up52HXh1x5zaV9+WELa/pHzAEE
         kbZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXAbNo8HxoOh6ZTNoaIiuyDJTZxRv+4UgMhZqeyymp6D2qqg1/y801AaaYVCAi21hBXE42h8w==@lfdr.de
X-Gm-Message-State: AOJu0YznQfir0g8Wpqwz7S2LQmBnk97Do/H49vKuAfHXLrzx4hBXCkOW
	vgylo7TXBW8oz7p5jAY3dhJafbG3RU/7D9oqVIFmUs4o/q4wH4+I
X-Google-Smtp-Source: AGHT+IEtii52eDqlKF3k+WYEfvZDDb3M8ppwIQ38iv/Mr2LNjsD+bUH6XHt6r9eLiadV/GvtrcQVaA==
X-Received: by 2002:a05:6214:2f13:b0:6cb:5f28:6b73 with SMTP id 6a1803df08f44-6cbf000026dmr252244056d6.9.1729093330291;
        Wed, 16 Oct 2024 08:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c44:0:b0:6cb:d0a5:f12 with SMTP id 6a1803df08f44-6cc36f68b8bls829436d6.0.-pod-prod-01-us;
 Wed, 16 Oct 2024 08:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzaR4/GspRdBQVfm8sDWE4JpWm1MT7JePhOjxtEIAi9OGVPLlwbMfO2Qlx9eAfCo5sH0VtgdBQ5H4=@googlegroups.com
X-Received: by 2002:a05:6102:3749:b0:4a4:938e:222c with SMTP id ada2fe7eead31-4a4938e23a9mr10583181137.17.1729093329695;
        Wed, 16 Oct 2024 08:42:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729093329; cv=none;
        d=google.com; s=arc-20240605;
        b=R+7MzSkiRmgD1lKIG1SnAFu62ayBJwvmBkqXezOTCw7SQpB+PjrcUoEM7K/Wb6cJtu
         6GGi5WacvCVVQNefYK8IYy7OiY9EnSYt/5hibR6wPDSkTBtB6a61sn+YnByexRVVKPg1
         vPTI7sPAPq4WPS6eiN67WU+ljP4iM7dYj8gjnDZx7lCJbD7BM4kfbKUg43n1IECaJ9pW
         kZgISYdxCELhd3nOks0buiu89YMWfBdl7NodSxbjDx2KYHGX40WzDYvDF1QO8jyjMbRM
         E9ftr/AULDCXHElDiw4pIwgERuWP706WFGhqyzaW8LInljpow3aEtmnmNLlysKxWlyvF
         mA2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2hm99wYh6qNVY2KuNWC++KmNGsWyV5y7wgmQq9+ww+Y=;
        fh=7lbPjXPBrR8dSgG7ysvKWnMIE29dr8yWrocKYwe0ENg=;
        b=hMdZCImaOIVYZYsYj3xZA3u6CUIu9ofaemvWmYBTEoQJhneJIohLYxv8pjLpC/uIUx
         2QFOVjP0MYlkFkdJetMH+8L/vgmUORQClu/bSzmzUZa+ct7LpIoDVTSW0IF5Yur74DU8
         9XMnMV7BUJeaLZNPpgORubV1Wrc0Hhfl4kimPxeCqaU/ttzh8BSxPE7/TfAHhMigQEaz
         9hd+idmMqH3963j2G26NXZ6vbIFzUISvjx21/0PZcynKOpW4bRXrhoaueELdw0G+FN2+
         Jic35AU89G1ac61bsTaQkINj/qsUM+UUglw2nGI+dmf0O8+ez1GIMdKKtiM3J1ADwYv9
         a+tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=K25Pibhp;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a5acc321fbsi175313137.2.2024.10.16.08.42.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Oct 2024 08:42:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: zSaQyOssQNaUZr24GyW4xg==
X-CSE-MsgGUID: 0CXGlRlHR9CyL3tSUhXNUQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="46021379"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="46021379"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Oct 2024 08:42:09 -0700
X-CSE-ConnectionGUID: r7upwpckRCmJoHJMMwP35w==
X-CSE-MsgGUID: iXHmcnIjQDGr0gnwyXsyLQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,208,1725346800"; 
   d="scan'208";a="109018940"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by fmviesa001.fm.intel.com with ESMTP; 16 Oct 2024 08:42:05 -0700
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
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Narasimhan.V@amd.com
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v3 3/3] mm/slub, kunit: Add testcase for krealloc redzone and zeroing
Date: Wed, 16 Oct 2024 23:41:52 +0800
Message-Id: <20241016154152.1376492-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241016154152.1376492-1-feng.tang@intel.com>
References: <20241016154152.1376492-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=K25Pibhp;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as
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
---
 lib/slub_kunit.c | 42 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 42 insertions(+)

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index 80e39f003344..3cd1cc667988 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -192,6 +192,47 @@ static void test_leak_destroy(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 2, slab_errors);
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
@@ -214,6 +255,7 @@ static struct kunit_case test_cases[] = {
 	KUNIT_CASE(test_kmalloc_redzone_access),
 	KUNIT_CASE(test_kfree_rcu),
 	KUNIT_CASE(test_leak_destroy),
+	KUNIT_CASE(test_krealloc_redzone_zeroing),
 	{}
 };
 
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016154152.1376492-4-feng.tang%40intel.com.
