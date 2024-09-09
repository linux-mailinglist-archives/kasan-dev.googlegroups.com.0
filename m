Return-Path: <kasan-dev+bncBDN7L7O25EIBBLE77G3AMGQEDSE6I2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C560970B36
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:22 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e1ceef1b984sf9211351276.2
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845421; cv=pass;
        d=google.com; s=arc-20240605;
        b=QmNWhIZ2oFCKITXkG0vjU6i4cbb+GboRnc4bLNsfDswJGcFUAQ5pCzYUuRjFu+TGJH
         TGzRjqI4pVzho2vExlIILL979s+y1eUNMcuwIouEfFD+DSmvn5g0UJDOpm993lQtQ2DC
         yrOCXAcEoyJaddWmKvXDzL2Ln75uY6Poz5g4Oc1Mhqt3ss5g+I6OOucQZdrTgogLMsTJ
         7UVuhAs8sAQHebnt08V33zSlO/OK5oxbd2zNbseoPYpWcvzCQ7PwyTN1nbMHzm7Vdzv7
         glfSUsbbS8G1l8D1JsZdQuG6keNloolbFWtZG49rq8Lw0ZYkO6+cr/WU1j5e7/kYGx4o
         9jzQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wZuyKlpgYJQNEskLUpB9Ni1mLlKwL9GWHYudA9HH1ME=;
        fh=DTEGeF8OEvH575XWZrnthk25I8Hqn4N1t2I8ttgrKiw=;
        b=M6O62Az2CiA3mXWj2ZFJ2UdQEYjmbPFrwMdoRWlq0OPupNHkcPbLdVhYndR75L2TU0
         zx/bP2xuxTcUJ+qVI9gQKIbPqGVrxzUtTLPSTtJRiv27naI+Xe+WYrgCor2w2jbxLLR9
         vBY4sw/3h/hQLiR/X164uqiw1HYTDyaBqTOay16//CIfvfOJyptE8KsY0TCW33VXrYex
         L1UPh3m0hZr4iODVEgrX2JORdC2Ns300XGENH+Vhr2hoOLd9KXpVvO0NQP1bbGBySX5H
         It8aXigRB/4PfOnCX+OIdb+8Gc5ubaJTyr8Ar7QnNTBOKHAu61gNk6r49zoB+Cq5I1Oh
         mfwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Nq8Qelke;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845421; x=1726450221; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=wZuyKlpgYJQNEskLUpB9Ni1mLlKwL9GWHYudA9HH1ME=;
        b=oHE96fiUPvpOLAwgZEEVnycjQBqVZOJ9iwCVO8IocyK0GzMYDZfR+DRNRSR5HpfW67
         KaBUiby+cFkruA9RyuZ3yZYKYGQl9dCmJz9GkwmaBzqmcpHWRi/MoUWkT4IgF9I2SXz1
         5/Xjq3GcQzDJGdTQvJxGrw2fLYhKny1G1z0PEpKX9NHnpatYQZnwHjUuXdrK4OEu/LHH
         9qVscwY5HWWUtxXRmi3SqVMaNxkLkiGQf8h0Gk8ZyzI+zWGvllhsG5ioUbC20QK1b912
         r8C+eVbMXu+OVfDYoC/KehmoVzRNL2AJZ5wISuwxASH9fCtjNDnIY+eYq7Ft+c7fy7WR
         /zLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845421; x=1726450221;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wZuyKlpgYJQNEskLUpB9Ni1mLlKwL9GWHYudA9HH1ME=;
        b=ZOdAFnk8GgpoQZIlbrgHFaQDI4xTvaaJ+4baRNswQpgWGG1bOvzaVeNmUZ6IEML88t
         YRfth9Stlb/D/v1uFhl0Fr06JMh0WJDjHihe+QjPbf26Fu7EsA531kSTtAxVR5JE4QuQ
         BXVGFb3bOvHtA7fO+tUU0Sl4SEWWA07TqHOtl5u10qJ/ofDQkSFP0pJ5L4H4vqMdts1Y
         eLJwGxMXdV7ww/sCekQDZuvKfnNTQZFzhWS2KEDnNzsHvpmvRFN3bYmL1tkQZUOeK/ut
         aOFAU5fgDCguQ8JsBL8doGZ2K5ckCGNJj/xdhfP7IixOoKhFWsVDlPFq/d5GfLZ7TcXS
         LbCw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsL8sG5Vdcxg0VluF3gYyUk0DvEw8w8RmI2jyHzuMqZ1tBK3VHAR7P6NYrzbKkMbmhkXn/gQ==@lfdr.de
X-Gm-Message-State: AOJu0YyTEWEFgj6J/lcJg3WL5MVJkWf3tuhS6BQQMQAep3i0Ku8AYYgl
	8GTrLvBn6YvQv/07Zh7hWWvC4aM6XNDMi7bBGFeEvSE0Gw1Q4zW8
X-Google-Smtp-Source: AGHT+IG33TfeSrx/X9TMEXY7HSdEi0debuL2p1z/TLhKYetoEFn2i4TwwTnBEBJ+ka6Q4UDAx5EvoA==
X-Received: by 2002:a05:6902:1b93:b0:e1a:72e9:b243 with SMTP id 3f1490d57ef6-e1d34875d03mr9691218276.9.1725845421044;
        Sun, 08 Sep 2024 18:30:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7e8d:0:b0:458:355c:362b with SMTP id d75a77b69052e-458355c37f7ls1112111cf.0.-pod-prod-06-us;
 Sun, 08 Sep 2024 18:30:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXDcM5ZcYn4LDXlCbpXLZJtQViY3hzd/kyS+1gr95jtGlijmnOiiOx1DQvjBahhK7dA9Zv2p04gMqU=@googlegroups.com
X-Received: by 2002:a05:620a:1a03:b0:7a9:b7fe:68f5 with SMTP id af79cd13be357-7a9b7fe6c86mr247224885a.61.1725845420326;
        Sun, 08 Sep 2024 18:30:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845420; cv=none;
        d=google.com; s=arc-20240605;
        b=EcBtap/S7hXO2eMGRy+Kd729OVXDZplOKgufpcrko9qFcTwzRknDLnjYw6sy7oOXNU
         IoFgfkdtUudEEnsrKS5dnODxaSIWZEGi2OHa9jM3mhwPhBkny1mPQccST6QmqF6CZ+vY
         JSAxZyUGmTD4bYmdclOb63SVK/h71jQs5ww0UbyYdngM6GxFhetOEs2ErZ1wKVXo1ljP
         djd+xuvCsxqV+7MhTlc6m/zAqZxCjdEJf3UAT4gMYq2hC331LvTIIntsiangFIAA04o4
         gpW9xbSN1BQAUlZdL/oSN+u+4KpSjUwCihPP5AgPDxnWclKUqjPyHC7ZxobfXuG76+zW
         RK8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7vVZ50kdJDNFI19gsV94XEZMSmlP1RCFkWL2RtPs6kk=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=YMG5OI3ju59WKlN0hPzOIifT+12TnU1DfnrCatk4m5MYVhOUbfNPrcqk1/8Bsj8SNk
         u5JWwv8jo0PnJx00AqhfqtKDV2e1WbiIBYmZ1GAu9aHpS1FnOiavPPcPv5kNyIzMTH8X
         tf2Opk+oQsstXwPjONCS7tQkwRPo2ilm1xJlQdxiu9fhB5t2G7qgQFAcWQHyg52oXh/K
         y7keoGPCd2Q44naheRVlUOxzUdrW1kKFUfU0GBNWcPbUsu+cpKYGVe0sSr0bvFTplFTx
         KInSfHejbaoFkD8/OOWp3fB3l8Va0hFWPwg4z0Qe0+7qCsiGs9yTwKlS1QXsEZ63okoJ
         kdZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Nq8Qelke;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: 5kQraL03R0OP1yC0Y/cg5g==
X-CSE-MsgGUID: ou+eVFCoQBinQPA+wDNocw==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258144"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258144"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:20 -0700
X-CSE-ConnectionGUID: WDU907LnRC+3vfLghWzWkw==
X-CSE-MsgGUID: 4FEk/tfqQaKVE8AxVIBYaQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486499"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:30:15 -0700
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
Subject: [PATCH 4/5] kunit: kfence: Make KFENCE_TEST_REQUIRES macro available for all kunit case
Date: Mon,  9 Sep 2024 09:29:57 +0800
Message-Id: <20240909012958.913438-5-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Nq8Qelke;       spf=pass
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

KFENCE_TEST_REQUIRES macro is convenient for judging if a prerequisite of a
test case exists. Lift it into kunit/test.h so that all kunit test cases
can benefit from it.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 include/kunit/test.h    | 6 ++++++
 mm/kfence/kfence_test.c | 9 ++-------
 2 files changed, 8 insertions(+), 7 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 5ac237c949a0..8a8027e10b89 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -643,6 +643,12 @@ void __printf(2, 3) kunit_log_append(struct string_stream *log, const char *fmt,
 	WRITE_ONCE(test->last_seen.line, __LINE__);			       \
 } while (0)
 
+#define KUNIT_TEST_REQUIRES(test, cond) do {			\
+	if (!(cond))						\
+		kunit_skip((test), "Test requires: " #cond);	\
+} while (0)
+
+
 /**
  * KUNIT_SUCCEED() - A no-op expectation. Only exists for code clarity.
  * @test: The test context object.
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 00fd17285285..5dbb22c8c44f 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -32,11 +32,6 @@
 #define arch_kfence_test_address(addr) (addr)
 #endif
 
-#define KFENCE_TEST_REQUIRES(test, cond) do {			\
-	if (!(cond))						\
-		kunit_skip((test), "Test requires: " #cond);	\
-} while (0)
-
 /* Report as observed from console. */
 static struct {
 	spinlock_t lock;
@@ -561,7 +556,7 @@ static void test_init_on_free(struct kunit *test)
 	};
 	int i;
 
-	KFENCE_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
+	KUNIT_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
 	/* Assume it hasn't been disabled on command line. */
 
 	setup_test_cache(test, size, 0, NULL);
@@ -609,7 +604,7 @@ static void test_gfpzero(struct kunit *test)
 	int i;
 
 	/* Skip if we think it'd take too long. */
-	KFENCE_TEST_REQUIRES(test, kfence_sample_interval <= 100);
+	KUNIT_TEST_REQUIRES(test, kfence_sample_interval <= 100);
 
 	setup_test_cache(test, size, 0, NULL);
 	buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-5-feng.tang%40intel.com.
