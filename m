Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNBYSEAMGQEWMQNIDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F0F03E44BB
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:42 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id k6-20020a6b3c060000b0290568c2302268sf12306521iob.16
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508341; cv=pass;
        d=google.com; s=arc-20160816;
        b=gat2Bwhi8unwgEmTDveR1jY0DJklRvwXMzMDv60tK1aJpZRSHMtj5VrCpYaC8F1gID
         eu83iqMgaIPdCBCulbWmKLeGt4kah5YCGtqd+fDyeBtc0XjNkbwWwA+/PePOenCc+Zwn
         zSFdgvld6Fy5tH/izunSOO6MZPKMbyIoACa4wMAGoLWvI+vRxgz/1h0K6N9QARryXMUq
         owsBNAoOew6po5eoZ67f0BQ2izHsLRDuDq6JZ8BX+OpjR6caRhSuzIRi83ShcEZFc4gY
         5Nlj8STQnwUc4p1bkWc6ddEMafsF1o7mMZe8uYlBe4tFM6/rBFI8sd86d/K3vV/DKMgt
         AcFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=GHDBCrxZKeFcNcOdoLd1CrTuAbUcOBjKZZ4mANJR7SY=;
        b=gNgDtddDcxebOTcpvSj2lNMMfz5nYgpCGSdFgK1zupH6PlmNT8TtTHJ7odGlP3sV3c
         xetopIDwR4naHJbg04ZUNVMZbBBV7BbQjLCBbi0T6m439zpjx/PFkcGr9p45BeH7foFm
         3vngxXvRB3rztrMiu9qk89lYe9iW/kc2NudYQdW/8Dx8ACqXiIP1pqr7OeVfRT5khj4V
         TjkSbZ52poHv4NDm3xKz1bRd8OkqYLpTKP6ICzXLWQgLot/Pd92uxKL3xo8LuEuuomEw
         bAYfPdD0l2QBd1JfKYntcC8qsWVGJE/XbTey6ZfAPjBCBmkVy0uHZDYscEKta5ES6Z06
         J4cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxmkxAUi;
       spf=pass (google.com: domain of 3tbaryqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3tBARYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GHDBCrxZKeFcNcOdoLd1CrTuAbUcOBjKZZ4mANJR7SY=;
        b=qm05TmGHVyEO13pS/TaCgj+rLAosqJBlVmUPtYEwQNgKnWTqZsvbXKUHDGV3TPw+KM
         uWdzsrA5i6EEXV2wpW4zyAvXSw0PWou2hPR25ZuimP98HULv8yzRaOEee1kC3nxVQOEN
         xdBBw0Q3mfW8gJD8fhw/nQs98wK4/AR2+9CUbw2cbJSREo8//vgIA53WVzfJ8aPd75dN
         0GkieuGCbxfFYwHZ9SpsBpixiMTf6mwYUcqXuKyM32rePtzAgwMypQlXXygSatUsmn2f
         +eg/QAhE08eIGosCq6aspT5RC82Fw+/+yiURlx/TaE1xYUHi4ToxGofIQj5jt9kmvMhk
         5cYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GHDBCrxZKeFcNcOdoLd1CrTuAbUcOBjKZZ4mANJR7SY=;
        b=eNO7h6VlcpkplwwFW4A+GIcu/cMw88gNexBjPGn43BLw8yf2tU3wg9GhnofvmQMliw
         1Hnnr7oeUNvqr2A5sSb8dwO1kizTc9vIjQ2OUzqO4G/09sESTIvB0AR1wFJVQo+yYyjh
         I46sRMMhJZSL7K8C6Cpj9OyUpZ2GtMrnuPMR/fgdDLYfbCVwchzekbB1MK3/7+yiUjY4
         O/obXs5GEfqPKLmE9sU0mPtHDZpI0ZdHRO4Ll+l56S3Ji4ut9wUH3qZswUzc0LZy1ogp
         GxgwuBHGIX11QWErSz5CZfZZmRm92Ik9NPzGFFwBGWV3tcgAx9GnP+UZeZMMLN+TDGl/
         11nQ==
X-Gm-Message-State: AOAM532S1joWaCsFHTuKD9HrRI/xkp08eP2MPcG2euR54i2dvu2hISz3
	RJ+MK0dsPRoh1Je2cSsGOxg=
X-Google-Smtp-Source: ABdhPJyvg+I5KVEPANMGa4N8HYyTtoqeMEFoJl0JrQ3odYeDGi5EFjF2H54CxaCl2DcC2mz+C7gBlA==
X-Received: by 2002:a5d:9ac1:: with SMTP id x1mr167276ion.191.1628508341204;
        Mon, 09 Aug 2021 04:25:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:354b:: with SMTP id y11ls2052831jae.10.gmail; Mon, 09
 Aug 2021 04:25:40 -0700 (PDT)
X-Received: by 2002:a05:6638:306:: with SMTP id w6mr21975252jap.132.1628508340903;
        Mon, 09 Aug 2021 04:25:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508340; cv=none;
        d=google.com; s=arc-20160816;
        b=K1x9CteYHvZNzCFmeGNiHXSQzLjP7LZDzm74x0uAV1QxPVW/pPfO1800ksPat0DG3N
         Rzsvtx4DleXY87CLoS/Fx32xzNLQ/7QanknriYx44jkwglFOh+6ethP/WP8OZoC9EtIi
         4sjGXRJJ7dcsUmjp9TlDxuli0O5acjJBvRr8gA9vNiOLTTLdUGbEHAoJeAKl9Btu2cbf
         C1uOfV0Ek7vjjZFqexB6fWr+AYPjd0lnr9PuzrfUkX06UIsjLJE5KwDXRP+LO5Kra2yh
         0HrDjxRX5xn7b6oM/PweDnul69D+Thq32i/YL1AA8LzbDqZOE5GowbUA+0Mp6heF78q5
         +2PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ETG24eNjcLOqgZgZJOfludY7in3fTtyTQv+qiRTb/Zk=;
        b=K4D0CwregXzt1+GGDdbe8s8ga/PF3pDNFIKqF4SCDFF/47XZXjXbfvSw1j4HA9D8N1
         uOedyNHTKUXuFXQgEgPtvF1myiu+gDmprbBFDBsfG2qXKGsGs2iPKM9CR9YqCEiHO606
         imP6FpxmUw3b8l++2qs1+ToC4L8t5O8OQBK5WbZHQohfjl68idXhem5I2G9ZIGow61vs
         mSjUn2T5Fnmvx2EKZ+wmDF+wwj8DjYDeK2/6lshoSdwsYKW1s/9t7PN9vAVWcpzdXq4l
         F8wq16vThaZTaqrE55in3Jkl2UqaV57Wbbwx5+pSneVAUBY/ptDpThXoSvfDZVDZkvoe
         Ydlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxmkxAUi;
       spf=pass (google.com: domain of 3tbaryqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3tBARYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e16si772662ilm.3.2021.08.09.04.25.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tbaryqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id b19-20020ac84f130000b0290291372a1d17so2852342qte.9
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:40 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:ad4:4e50:: with SMTP id eb16mr9341163qvb.14.1628508340651;
 Mon, 09 Aug 2021 04:25:40 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:10 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-3-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 2/8] kcsan: test: Use kunit_skip() to skip tests
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lxmkxAUi;       spf=pass
 (google.com: domain of 3tbaryqukcskjqajwlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3tBARYQUKCSkJQaJWLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the new kunit_skip() to skip tests if requirements were not met.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 11 +++++++----
 1 file changed, 7 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index df041bdb6088..d93f226327af 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -29,6 +29,11 @@
 #include <linux/types.h>
 #include <trace/events/printk.h>
 
+#define KCSAN_TEST_REQUIRES(test, cond) do {			\
+	if (!(cond))						\
+		kunit_skip((test), "Test requires: " #cond);	\
+} while (0)
+
 #ifdef CONFIG_CC_HAS_TSAN_COMPOUND_READ_BEFORE_WRITE
 #define __KCSAN_ACCESS_RW(alt) (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_WRITE)
 #else
@@ -642,8 +647,7 @@ static void test_read_plain_atomic_write(struct kunit *test)
 	};
 	bool match_expect = false;
 
-	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
-		return;
+	KCSAN_TEST_REQUIRES(test, !IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS));
 
 	begin_test_checks(test_kernel_read, test_kernel_write_atomic);
 	do {
@@ -665,8 +669,7 @@ static void test_read_plain_atomic_rmw(struct kunit *test)
 	};
 	bool match_expect = false;
 
-	if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS))
-		return;
+	KCSAN_TEST_REQUIRES(test, !IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS));
 
 	begin_test_checks(test_kernel_read, test_kernel_atomic_rmw);
 	do {
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-3-elver%40google.com.
