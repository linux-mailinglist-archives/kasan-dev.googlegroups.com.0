Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEFNQ6AAMGQEF6UXYWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FB122F82F9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:21 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id g15sf3383288ljl.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733200; cv=pass;
        d=google.com; s=arc-20160816;
        b=GeIUEQ7bgjZkC0UrAK62ar1f2ob6ZdeDd1g5jLLSBUqtMCHL/XUkzJZSttI9fEu09U
         dwRE1kH2WaTUFt9L7zWkuV1l2yp21OuKp217JwsTf7KdZR5cARzJKQy/yIGaSLrpiLcM
         EULvEhyusk9Smt+3+Ua2laOI6M/cnrvvARu3BQXyJFkwKD8wPV109FqDy4eCXw9qXFqp
         /M6VtHnwqn/THYNvP/DJT6iRGukMuoUhhewyM3GyQBttzR87NLCDvoN3nozbROvteVnq
         AGyGOIcXzXAkTdMTrriMrSFb3wq6P5Ph9jIxcYVibzvT884uYLOMlTFMtPt5KZaSuOB7
         liyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3x/m1c+T0mVjd3FZG/myMucFHiRBDA60Qopj73cYuPQ=;
        b=UMN9ffyF5o8jxwrXC1MyWFYmb1giRE2wGk45GbBwqhwP9lngm6h4C96B+wzfFrdKgA
         J5ftt0We6F5AJlPiNFoZBRyU4r/RhxIaGluSsC3b/clf1qrDG1Aa4/+SUz2Qi/MfSB9I
         ZqrjxK77y6F1K8A9ZjgcwdT58E/svVyN9NHHa5lgtRg9Z4vHG17LsJQEwcgUuVMOfgT7
         DhzXu7agqh5JHmyvD/pdZQYCiYpdsemkieAKKpc/C69INMeVxdvcCdaq9UrHrFWlDXzT
         0L9YR+33VX7YpRbASM+YlLfydzChGwjhR3djh4mtCW2heyQ+CPnhm37Crvfn60CZ5Nna
         Bkqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyTBPemy;
       spf=pass (google.com: domain of 3jtybyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jtYBYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3x/m1c+T0mVjd3FZG/myMucFHiRBDA60Qopj73cYuPQ=;
        b=Qm1/GDJcKvAk7vOFK2Q3R7xeczU3VPoqYkLLCVPUg3Y811B4jKRvaWqgLTg6+BVAsh
         22OgiSnQbEXZ8sLnbsGaJU8ifot56iwG1CjkDhwYl+yinhc0IWC2vzSXL4CH5LM9uBNi
         yAUMrJIVZuKqU5TNAEfqkVgaFiauo2rAB4tKvjBTN0qkzXTMjpqGHFBw5KOLYMzP35kH
         5j70emACa+0KWTPKgc7d9DYq4DjWQx6YNO6iWIHfwyuw4CAAw88UQuD6QCtrUJITyv6O
         CgPlntIopzHrGB+T2/7ZfplNxalKw0srU8zeN75uUayeYrVlhounnA11qAscvTpKuixs
         WEag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3x/m1c+T0mVjd3FZG/myMucFHiRBDA60Qopj73cYuPQ=;
        b=XUt2+cUUmpbuZyPkB2KYyF3xZUPiqvzpChBTzEm6PT5d7AjBvRDJI7dQR0Lbt+FS+3
         HV5DRHqtFS1odpJ9V7sm8VmRhtg9l0wc7mXiE5iVu52kKqJoKqqRnG3+CkOqyGtmlNet
         I89rLxP/GRgSxiBuy7Pq6O0Ft0eERkIn8JfRrTbapgWDXoDaev+JCDlK3tVnJXXby09e
         3dr/39QJcNb0ucQGMrJaNB4np9Vs53wq57lTPE3CzODkw5m5nviJaTVgZuZy1jYiqbkz
         Ea/yNZN7Hri66ztoMeddlxGE9Q55dC2Dr1ktbutJUxXnxtwoIhFMqtVciOYHpJwrwj7u
         AF7A==
X-Gm-Message-State: AOAM5324k0KqtngPpG26/tOK49XqNWd4GpVnJbtaXt1ighB0N8JOfsWO
	vLolmN25/InsLA5unSryTD8=
X-Google-Smtp-Source: ABdhPJwY9JCsP5UC8UAiY+2Ew4OyLVCGUUHIpYdiRyM/GwEx6IXaDpHc/1hfeDqNWba2e11Je/GTqg==
X-Received: by 2002:a2e:8148:: with SMTP id t8mr5579162ljg.203.1610733200783;
        Fri, 15 Jan 2021 09:53:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7806:: with SMTP id t6ls1702861ljc.8.gmail; Fri, 15 Jan
 2021 09:53:19 -0800 (PST)
X-Received: by 2002:a2e:9dd4:: with SMTP id x20mr5593645ljj.37.1610733199762;
        Fri, 15 Jan 2021 09:53:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733199; cv=none;
        d=google.com; s=arc-20160816;
        b=H8r/+MfYo+jrOBVyY1UxGzkQ1qv2pRwkhWosl4ySdnJ0ww/ZOyWs8FLonQqj3skFLw
         VTQnMb/h2Ebq6Gm/24OBqcWvYaU+RgXh2rNvPbVWC78tiKZ1DMh5R43YD0BGs3u2Ffa+
         USuSnI+hJua+LrikIrZaMhEyRA0y5am9SASkDMSzaMUwOho6tI0bZB5nPZke3AZNDgl7
         MgPqYqBiIysDZXRjoRe2RaxXaWERA+eYEE3PK3tx14/2XvYg4ptRmUJ2jT5VZz1MJsBq
         MdsHBGGLPT1pcA/6pBIl9v5t7dOT0v5seK4vWn6Kc9IEwNBKvudExwIG6uNCYlOttryW
         WVWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ncx/ADq8yORoljqCdVSCBm5uc5T6Epz7JI4WnQIQm9Y=;
        b=ryML1V/2W+yn1XZiwJ1vEvednBP3Qcu9oS9M+mmBiCRsAUr+o2Nsy3qOt1bjEMamnE
         Et97/ZLnImJ2Rb9aCC/ESl8O64LzoT7RONz8z5lqWc9rCVnhv4suGMy1vH+2znK8VZuc
         h56U7cugLC8YN2u5HrD5t2LbIn0M5n43o4iKqhV5Far4vqYLVgL5jONyYOTDips7X+pT
         z43yLcpwMe7qY0Fcx1iURA2vthdPj9I7BFNa2OBzorU4AEr1hIgxsq87MDyuyUgvbemx
         Q3Vyp9yZTW9a7MbcsQxXtV4a21otd4qGbFWjjmnbd5rYTC+VcdJ9nFiGC6jUJiW1Zhc3
         SLng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JyTBPemy;
       spf=pass (google.com: domain of 3jtybyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jtYBYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id r12si345048ljm.1.2021.01.15.09.53.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jtybyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id j16so3372033ljb.9
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:19 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a19:40d7:: with SMTP id
 n206mr5901814lfa.27.1610733198842; Fri, 15 Jan 2021 09:53:18 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:45 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <6f11596f367d8ae8f71d800351e9a5d91eda19f6.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 08/15] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JyTBPemy;       spf=pass
 (google.com: domain of 3jtybyaokcuklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3jtYBYAoKCUklyo2p9vy6wrzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

It might not be obvious to the compiler that the expression must be
executed between writing and reading to fail_data. In this case, the
compiler might reorder or optimize away some of the accesses, and
the tests will fail.

Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL
and use READ/WRITE_ONCE() for accessing fail_data fields.

Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c  | 17 ++++++++++++-----
 mm/kasan/report.c |  2 +-
 2 files changed, 13 insertions(+), 6 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index ef663bcf83e5..2419e36e117b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -68,23 +68,30 @@ static void kasan_test_exit(struct kunit *test)
  * normally auto-disabled. When this happens, this test handler reenables
  * tag checking. As tag checking can be only disabled or enabled per CPU, this
  * handler disables migration (preemption).
+ *
+ * Since the compiler doesn't see that the expression can change the fail_data
+ * fields, it can reorder or optimize away the accesses to those fields.
+ * Use READ/WRITE_ONCE() for the accesses and compiler barriers around the
+ * expression to prevent that.
  */
 #define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
 		migrate_disable();				\
-	fail_data.report_expected = true;			\
-	fail_data.report_found = false;				\
+	WRITE_ONCE(fail_data.report_expected, true);		\
+	WRITE_ONCE(fail_data.report_found, false);		\
 	kunit_add_named_resource(test,				\
 				NULL,				\
 				NULL,				\
 				&resource,			\
 				"kasan_data", &fail_data);	\
+	barrier();						\
 	expression;						\
+	barrier();						\
 	KUNIT_EXPECT_EQ(test,					\
-			fail_data.report_expected,		\
-			fail_data.report_found);		\
+			READ_ONCE(fail_data.report_expected),	\
+			READ_ONCE(fail_data.report_found));	\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
-		if (fail_data.report_found)			\
+		if (READ_ONCE(fail_data.report_found))		\
 			hw_enable_tagging();			\
 		migrate_enable();				\
 	}							\
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e93d7973792e..234f35a84f19 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -331,7 +331,7 @@ static void kasan_update_kunit_status(struct kunit *cur_test)
 	}
 
 	kasan_data = (struct kunit_kasan_expectation *)resource->data;
-	kasan_data->report_found = true;
+	WRITE_ONCE(kasan_data->report_found, true);
 	kunit_put_resource(resource);
 }
 #endif /* IS_ENABLED(CONFIG_KUNIT) */
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f11596f367d8ae8f71d800351e9a5d91eda19f6.1610733117.git.andreyknvl%40google.com.
