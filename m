Return-Path: <kasan-dev+bncBAABB6PQRKIAMGQEWYNSK7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E6DF4AE0F3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 19:37:46 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id w25-20020a05651234d900b0044023ac3f64sf896699lfr.0
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 10:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644345465; cv=pass;
        d=google.com; s=arc-20160816;
        b=eub2FlRX3w2W8vfHV35JOWeCGU82vzJeVohFe9Kmn21dFHZ9xQe1jVe5jN2R5Jf94o
         htRN+yX41Z95WNavpP3V+6DBcW6APiE+OklxZ2+ek36BGxX1M7I64+1jgm12JjEBvNQY
         cTnItSDUjop9tQOawk59aLxZ8Df6exoipoOoV89v3EfG2zrC4Mqz/BHP5AaOHcetTg3M
         8rYSGSY8rqRkxWZVOmCqYhmNzjAFtfc7pi3Z0O2r/htwVOTEYeunfedUuFbvIsMoEMJr
         G0dW/f2xkEUoXYUhp4GmQj48urKVRoPmjJMj2VKbixZA5cvBhbkAXA9NHS1WghFAeZDK
         CuEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bIvidT3KIZIBTKwcheoNzarviY38p8QYvfP5rtEFcQc=;
        b=q4CICZD0xrSAsH/pmKPfCb469M0ApCGkpZNqk+1GnNWc8RJcz+fE18oPV/U2yE5qrU
         B510LkpYp82iv5JfNSyQkB+qeRXZN6ryckj9l0YVDVJAaAtQq2dFuB64PNmZgBOeMchP
         5w66aKGpjQTjESyvq53K+83TZrqBemK7pjHcWBLke9vTEw68K9RHKJ0vtvqy0VqRqZ4+
         4BP/va9riG293ytjuDKzu+2W8j5sehAIXOZNFevJfUn4Um5to9knBqZLqc+ASUDAhYiT
         jO4KIGxRhdV6YZyWvbSzH+1vAZ6Zyioi+Ba09uT33G8x1YjazV6dGbEBhA9xcSwvaBwf
         Cb8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZUjyopAN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIvidT3KIZIBTKwcheoNzarviY38p8QYvfP5rtEFcQc=;
        b=pS9updJdHbhG5O8Jw7EO0jh9lkOp4BQ7xtg0O1ryqArJ0BksicWqItEfRS0YvHCGzX
         rsYRBS7SnOCVnV3+W7ahX2bXH1NxUYI7d2cNGuY7l4sO74t3ptdGyhez+uREsL86+a+E
         AY+Ingx8bgiyuWUlpw1Lx9Bpmq6K6l+gfmWsiInB19Y1g9cCLC9G14r63vcWB+GFZsJO
         pmxVL9ZSByYDeyGSENgJGRrs7OWoCmvOtRzoniuFgRHmWoHV6vsNDahfihVvriHlmPWZ
         zivjxH6PzCELycphaYVDB1kUph/vTELMJq3cDLSCX8eaurrw/i46mlvT2wGVtmXjCOhr
         SP8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bIvidT3KIZIBTKwcheoNzarviY38p8QYvfP5rtEFcQc=;
        b=DpTwRAfvTxs+0srJqsZwOPaYRLv4fkvD7GaCNQchqz4Qr5mI7+S/xRcI/jwhbAcRC5
         7NYE56Sm9hxSu5rudf42UwI8OBCrQGAfJHQBTSUOThEff5igCvYKnhmk4xC9vcxEidxA
         XPI+iS7wdfsDPxcn1EWb3q6oz0knyOEhcY6ES7KaTcyLSei0BUoN9uHLWVfznerZGNwp
         ypcgnYmhFE+raqogMnSVckQ9ExuWwcZku+wBWKG/bt6H7ujElHCcCJEP7exEgb/OpA5W
         2q00VxhwJ8jYI3A7Tn1POscxkorHGYuTi8RWimm9kUyChdAePiimophn5IrPeDsJRrVz
         AFLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5313U7DMoppRcgePo5D+Q0uhIQkuqsydgnyZZeNC7TPZDLmT9C9y
	metp2hPeVPA3gFQuyimkIrc=
X-Google-Smtp-Source: ABdhPJzLhrCsGMkiVRfTrX9VJIKJ7YFowSwWlKogJE+gyvqbzMB8XHp7A12c2aF70LsZA/eggkSr6Q==
X-Received: by 2002:a05:6512:308e:: with SMTP id z14mr3742055lfd.104.1644345465640;
        Tue, 08 Feb 2022 10:37:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1599:: with SMTP id bp25ls8610925lfb.0.gmail; Tue,
 08 Feb 2022 10:37:44 -0800 (PST)
X-Received: by 2002:a05:6512:3e19:: with SMTP id i25mr3911720lfv.351.1644345464811;
        Tue, 08 Feb 2022 10:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644345464; cv=none;
        d=google.com; s=arc-20160816;
        b=AknNvifaNhs9IukdcnbspTDrk1tCPiJqx+Qos+QObzFv9IcvTKZCfN/7w9ZFyDGfsP
         NKg/RAcSyk86+m6uV6xIhUqq1cwJc+tvhHFrdIM9mq+cWAOigtU9S5Z7G9cDOmOaaFeY
         5DC9WWg4Y6B8kwdLneV1ZPM/Glq0FsUdraaqJyk/xAAJ3nb7e8qp7Oduz+7m3cLfUNSr
         dJHKxy34bG1BnO2fYd47NVhZ5vNaPbigyj2Ll69ImMd0aPJmarSnC4pqOASK03xF98Nv
         KfYkr0/IT4oalCIdCs+1RIRJm2l9GH+sIRWiI6txb9I1aOD2YYkkfz5ur1m+84klAwDJ
         rHMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=NRVXz6k5qYgOdp2xZIUPWtH2m6FyLOF3PXWsoqOGl2A=;
        b=g1y+oi8SATfJHiHrTWKvI1KT6b9ytpDbdPJf9h8OrkS99BzTqdf1Ox3nwOVF3AHCmC
         3mVldUP1knbrbL4UxgJIFgZIFEi99J0GvGqmv/lS3y/y/Ok58pNZY2fhd10FOD1tXEZW
         6SP2V+x5NcWNrW9dGNvd/142hq0illrWa7msNKx6shEXrnCIWWDR7QDWZTU60uLTtrEx
         ryw+xwaVFHS+5dLW3+THzRGWesSP9Kcj6gvSdtSBR65j+Hm9GYUt520/KVT9My/b6ubJ
         7c1NGAXv3hWUE9W2OdAEbCosxtRzI6lJCFofiK5J8X0aNrRo0RpddRSdWh6zCBKtpEVZ
         ZYEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZUjyopAN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id k18si457275lfe.8.2022.02.08.10.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 08 Feb 2022 10:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: test: prevent cache merging in kmem_cache_double_destroy
Date: Tue,  8 Feb 2022 19:37:36 +0100
Message-Id: <748bd5e0bad5266a4cac52ff25232bbc314b24f5.1644345308.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZUjyopAN;       spf=pass
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

From: Andrey Konovalov <andreyknvl@google.com>

With HW_TAGS KASAN and kasan.stacktrace=off, the cache created in the
kmem_cache_double_destroy() test might get merged with an existing one.
Thus, the first kmem_cache_destroy() call won't actually destroy it
but will only descrease the refcount. This causes the test to fail.

Provide an empty contructor for the created cache to prevent the cache
from getting merged.

Fixes: f98f966cd750 ("kasan: test: add test case for double-kmem_cache_destroy()")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..3b413f8c8a71 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -869,11 +869,14 @@ static void kmem_cache_invalid_free(struct kunit *test)
 	kmem_cache_destroy(cache);
 }
 
+static void empty_cache_ctor(void *object) { }
+
 static void kmem_cache_double_destroy(struct kunit *test)
 {
 	struct kmem_cache *cache;
 
-	cache = kmem_cache_create("test_cache", 200, 0, 0, NULL);
+	/* Provide a constructor to prevent cache merging. */
+	cache = kmem_cache_create("test_cache", 200, 0, 0, empty_cache_ctor);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, cache);
 	kmem_cache_destroy(cache);
 	KUNIT_EXPECT_KASAN_FAIL(test, kmem_cache_destroy(cache));
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/748bd5e0bad5266a4cac52ff25232bbc314b24f5.1644345308.git.andreyknvl%40google.com.
