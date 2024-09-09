Return-Path: <kasan-dev+bncBDN7L7O25EIBBME77G3AMGQENAP2XJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E513970B37
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:26 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-45677d056c3sf54254111cf.3
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845425; cv=pass;
        d=google.com; s=arc-20240605;
        b=RXYjdFjHKoNvvaBk8v4ivbr+s+18gGE2kmT3PQULH2KzAmez2NXkPOX1Ewp/RYNwuP
         TubA2xWM0vB2bSF39lbSw3KF6GzzloQPocBYpTejlGzxwTvNZffwQx+zSn4/rfdsm4d+
         Z23MwBGZtgEktGm0mrh1hujq4yyIUHAvB7wWOd3EyYdHYJdsWMcdViNGl0l4hb5ubjKQ
         ajbOhjCbfzndq0icv2Iy9O3OzZl2OOII6B8sDS10RlBD9CJTlR6/qzm7PIJSG78Cn3Vj
         /lmI56DDaSDYlhh2S+/oQmG9iDUYlXvRyxT1Fhw7GqnamjZWSFQ8SIk3H2WikTkgVgvH
         5k1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lWQiGYesbDoTyjoF+BsxoBmLiPasFm1gcZtetBH6x04=;
        fh=nhlDvx9suR2948rkRqzdLo74mDWzZ8eg7ArR3/YDq7E=;
        b=XWIlT5u6D9i7RCQpNAIDqOXowV/dmF4Z6DpCoZYixAHfIstoIO3sdpNeZ7aNLOI6Mn
         haBuIfKgOxmq9teWi7Me86tnThNO50ay3Ic+wY0kOtAWRPlexZnBm3d8mZIysGcsvb0g
         slQSSdWB04yscbOfKZ8S4ye8ZLHPfY4FarlrGcIghA1z1X+4zPjxvLUf+WLw1N9NpNIi
         PBkGz2e3SSJeh0CNrZhmqZT5/yo4inSmiAH5AxgXj//JQR3HsRHqbtaN3UOXengFPWQ9
         PgJD7/UIoX+pzERVduzarqKHjv/VW4ebLBfFIzykptrAxdbARNvF7amX4mFhZ12XJ3D6
         ypJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MLiaaWnj;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845425; x=1726450225; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lWQiGYesbDoTyjoF+BsxoBmLiPasFm1gcZtetBH6x04=;
        b=qjtoh/eyKefCD8mj6etyclQUqdj4ILJDvVxX5dilvmigRl1AT60ttvoMzMAz0G5jlN
         Vr62/JMlnLhGj9WzJE4krepcqSvJhXmxWUDBFZkYiTDxSNwVsCUG50/4FW75886ykuVJ
         lXd7oq1VoAJfVlQZjJ7oLmDufltmlGMrUnmJJ7ynHCc0DeDPTQpVp2yyJbBNcw+/JjFi
         kGSm79D4A+2OTCFBGMHCVhaKIpo3vbuTLLr0jIgA/m5h94b6UW6wpC5rN7gztenImYzz
         8eKI/5n3H+Vr36CyZr6iO0OMP1soxnhR/X5lHcuqTpoHUifwms5ZtpfYjxGmLiwPCIvt
         jKuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845425; x=1726450225;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lWQiGYesbDoTyjoF+BsxoBmLiPasFm1gcZtetBH6x04=;
        b=Sn/t6aKkc3un14AEP0fVSCWKiqM5UFKAxOkkecglPQYF2kWVBqT36ZpqHBn6Q5eIqf
         pOuidHJzKpNcHLpPAo8l4lqSgC7fS85D1Ym3vDCCQWLGSuuAD2J4wbPn7rQPRK2YE4AY
         tc+2lzPfHeBFQ7RhUmRn1cGjfHWJRERGF6GLqTf26ty5/0NusZjWY0JMECf5pahDL+tO
         K5LgvpItp/xZdk5RHUtKevvZ5toNk3ZfgBAXWyfmsbjQciy9DXT7JD/zD8NABhmqam4v
         oGJMaAJFFLSF0q8E8ytxEcEj4iXa2WYPsQOuGjYJQZQXql+/lBUpuSIzzAHF04nsBhH8
         giQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtylV211l229STcEquobe+bzs2tFOjG22+5PwJI9RJz9Gq8N8dk4K1hoKmKOBT0axIEWJoBQ==@lfdr.de
X-Gm-Message-State: AOJu0YyL7M+whnrmOKlAC1sVCLdtFvVWrm+9xVgCOHh2lCcREyBYFAEP
	IxhucA4wpW7J8NodmZ7ecx+rbG4ZQhAHi4raHbxF9KZQjsItCgNo
X-Google-Smtp-Source: AGHT+IH2MBwp867Y/32GHcXX5egmX/e+6RiPKlvVKm0Qk1ZHr2YOwuEd7tTkJ3mK82sYxvQ5tpEuww==
X-Received: by 2002:a05:622a:351:b0:457:ca34:58da with SMTP id d75a77b69052e-4580c76f0b0mr96490061cf.54.1725845425011;
        Sun, 08 Sep 2024 18:30:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1994:b0:447:f206:4e7c with SMTP id
 d75a77b69052e-4582dd10d31ls9093671cf.2.-pod-prod-07-us; Sun, 08 Sep 2024
 18:30:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUeRoy3k3CFRS7+9eGLNUydwXkSIfsCC2LJ/Skeh8UJ//cNFdq/yjla2APKdL6uAufbo9UyqBI/+WA=@googlegroups.com
X-Received: by 2002:a05:620a:40a:b0:7a9:9f5e:26b6 with SMTP id af79cd13be357-7a99f5e279bmr760487285a.19.1725845424364;
        Sun, 08 Sep 2024 18:30:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845424; cv=none;
        d=google.com; s=arc-20240605;
        b=NWZEKEQt5K/zwcK+ae1OpNCThOU3GrA5kn1mMjslvUjxeP8VriGklKTEfqT5smm/5w
         I+zWW90EF4EyWYaunjD97XEEr8yxfM8hSH0aoO+YjGTe7XkawLkTFsssJQQSjzAJftBI
         ftL3Jzmir3XyC01W11/eRXec+aErG8c9W//Jg2ivlou558MKhVbIHIQvyjSzWR4H7Kvb
         1dTVSN6Q0CGgOakX6PYCRXzwgKvK/cNkA3HUI40ItYFEnaztksPZ9Qs9tmKtgt3Mq24I
         XporfDbs0GRMKH63B6/3KPL8WqTtqmTzdJM9X1hdRShEbPxgpJXa5nXuuL3jffY7xHLr
         Pkkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TdrgPZ3kYW9y9DC7KkVYudRyE6G4mFvxFIKatTay83o=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=eAnzEZbnEWjNLaNu5HuiQ6G6R2Ru0O9d2PKkd333QTStw5OI/Jt3FK0D3b03s6ZuRx
         Ak51l5xBtlUwHXhBHqV1ZYr4p8A3Mgnnjgu8GEJj9tz7UCcdajh4JIqpI/OFt65ozlx7
         L1fSA6GdVNAll2VONWtp7KJmS2R3KItgRDUo1/f7ONXH1bBJC51D5HkDUiOynO5qH0Fp
         l+LuRl5zvyK3DtJQNHzI2N67/NxEvk4xK+9W1cADZBbEvMCLN95ZWPIExFsox5vgPhYg
         +SEGCwTPciJu4VQxrqjknpDdJ2ZPw5BodNYvriJ5UlZowqt2sABBawuKIPs3SFH6OSah
         hqTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=MLiaaWnj;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: bT4i3RSQTj6AphNIiFdPRA==
X-CSE-MsgGUID: w4CpZ+MbRhasudvVRo+wCw==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258159"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258159"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:24 -0700
X-CSE-ConnectionGUID: ROdRq+r4T9WF2KAQcT/Xlg==
X-CSE-MsgGUID: DV/YFBNgQQa1SpiY83zezA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486541"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:30:19 -0700
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
	Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH 5/5] mm/slub, kunit: Add testcase for krealloc redzone and zeroing
Date: Mon,  9 Sep 2024 09:29:58 +0800
Message-Id: <20240909012958.913438-6-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=MLiaaWnj;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as
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

User can add "slub_debug" kernel cmdline parameter to test it.

[1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 lib/slub_kunit.c | 46 ++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 46 insertions(+)

diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
index 6e3a1e5a7142..03e0089149ad 100644
--- a/lib/slub_kunit.c
+++ b/lib/slub_kunit.c
@@ -186,6 +186,51 @@ static void test_leak_destroy(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 1, slab_errors);
 }
 
+static void test_krealloc_redzone_zeroing(struct kunit *test)
+{
+	char *p;
+	int i;
+
+	KUNIT_TEST_REQUIRES(test, __slub_debug_enabled());
+
+	/* Allocate a 64B kmalloc object */
+	p = kzalloc(48, GFP_KERNEL);
+	if (unlikely(is_kfence_address(p))) {
+		kfree(p);
+		return;
+	}
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
+	/* Test grow with allocating a bigger 128B object */
+	p = krealloc(p, 112, GFP_KERNEL | __GFP_ZERO);
+	if (unlikely(is_kfence_address(p)))
+		goto exit;
+
+	for (i = 56; i < 112; i++)
+		KUNIT_EXPECT_EQ(test, p[i], 0);
+	for (i = 112; i < 128; i++)
+		KUNIT_EXPECT_EQ(test, p[i], SLUB_RED_ACTIVE);
+
+exit:
+	kfree(p);
+	kasan_enable_current();
+}
+
 static int test_init(struct kunit *test)
 {
 	slab_errors = 0;
@@ -196,6 +241,7 @@ static int test_init(struct kunit *test)
 }
 
 static struct kunit_case test_cases[] = {
+	KUNIT_CASE(test_krealloc_redzone_zeroing),
 	KUNIT_CASE(test_clobber_zone),
 
 #ifndef CONFIG_KASAN
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-6-feng.tang%40intel.com.
