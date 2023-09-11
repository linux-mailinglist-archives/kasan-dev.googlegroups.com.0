Return-Path: <kasan-dev+bncBCCMH5WKTMGRBU6V7STQMGQEQGB3UOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 378B279A933
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 16:57:25 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-1c8c1f5717asf5471060fac.3
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Sep 2023 07:57:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694444244; cv=pass;
        d=google.com; s=arc-20160816;
        b=gfZOLjP1l/jLY8+YTIFqBhh8jTEHsTeFM7zbvLMl9CjR9CFHNilMCjSoxZvcRfeHuX
         tpABbuoMvnKDmALyIsXa5ntn8yuA841XlmGSwNQOgjK98JxKK1Vah4GI+ofjpBCZr61w
         6pF9yUFOpF/v/r0QM91luP6qhhHA/fEn6a5xLLZMXCOstnhU4SKBMrWHjbDrPL5IXYTh
         hrAJwjdSuUpb9OwXgsGi+3wYE68fYoB9Wwn6d5+O+CBpMuwVAU+IvLlYSckTXebRjrMC
         rLwkwS7mBzET7ibJVJsrJAhNZfmT54AyZ05NQ06Kn9/Wjr3d85+kRuTMtZNOEGY+WebA
         DMZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ANDf1ZLc2d4vMVdw+2j17Aeq2ZcxF+2BwcJ5Ammirkc=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=uZPP4eH/N+oaS7Gbjnoh9k9GmVPZ5OEE7izhgS2z/OApcyQBryfu+WKB62EqdATrFD
         H7a1trD1GEUbllPtemmn+uswzMYmh59MVDJ3pLk7F7J7llwiSponHiIU2qdvBafKfWUZ
         vaHA2+LSxDQ2iXfGoLBFyc3y9ngkxLaTGVuvDpg17tHHTCykAgzZWgGHmTaMp9xhfVAS
         sm/RXRt1NsEQhto0EQTCcHPVIr+Rll9w3XwvstMD2RCac/oAkxFpMODMuzMHL8GOwd/T
         lbZ6jdIi9yHkjCKMgZk6ogLaZFRa5fZr+19kHzyKDlYbhk70esSfcBT5+hThuQUkMIao
         qPZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=k0t05XgJ;
       spf=pass (google.com: domain of 30ir_zaykcvm163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30ir_ZAYKCVM163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694444244; x=1695049044; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ANDf1ZLc2d4vMVdw+2j17Aeq2ZcxF+2BwcJ5Ammirkc=;
        b=s2n/WxtC/k3jHHZbpvKl9ojqqcpBJp4mltOBpsb6mpFgf68Ng4+tNfp4nC6V9AzSgb
         ly8/T2OUHnH/uOKtVKCgMwZP50CXVaQuHeuFv7Oe36OQYt9Sx6MWEJolknHanSqXwRUg
         NhaW7XKOjJ6FbRnTfbD0pTczHyHR7csBjjA4Yu+BvYlwdNx04APHw5FBR7WDvCZWUjF0
         vcyrqU0THIvJVZBob4yYC2VF1WDL43+TPJAS1WLd5sd5Ya9xtnRMYZXWfZpqHHT424kj
         BvxTYvXk1SvXr4HtHsjGZwrqg4YnynMK7ClqZFcfRMk2iIpC0Si2nbUMM7ee2M9ZWme4
         ue8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694444244; x=1695049044;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ANDf1ZLc2d4vMVdw+2j17Aeq2ZcxF+2BwcJ5Ammirkc=;
        b=h89BLJJnpxkTZ1EAF3uKN2gemFVTg0RZd5AIs1gMExIob0V2xtiaYtYZQ6i4hIYLIm
         +IPC1rpM48s91HtLpJfj4Tz2C6sPVbPj431qUs+UIYtYI0lrW5c+zW9ajmmQqeKJKFJe
         VTTH5F5d1dQ+3MkYcoI19n5R+Pc7g0Qua68f+Mnh0sH2FHy+uiJe+3h+i785mHakon/s
         9bNsQA+eJs3icIO2eOmgCY/Rf+4ktac7P6sIpFnCd8PLLBHeqg3+dpdeJUeXR8S8lzme
         RQaL2U8ngIp2Hh3VfPs2YaAWF/VtrHmGqSTIM3yEpvQCK3qxLiBlNDDHBQmAsfZzPMdr
         XRgQ==
X-Gm-Message-State: AOJu0Yz3xiV9KnOf3PXH/n3YJPukCFMWvX0XQrVE09L1LQqOp6ZC7NB3
	qwfWJQvpieDD2Z23/Ia+YM8=
X-Google-Smtp-Source: AGHT+IHlwqgXDlEzJfpN9BGU5XzsSPzqbQ2ctM+q50YriBgD+3V7F1hTjnz27RY6bzRuXdnBo1jXbg==
X-Received: by 2002:a05:6870:c5a8:b0:1bf:2ad9:8dae with SMTP id ba40-20020a056870c5a800b001bf2ad98daemr13102870oab.45.1694444243545;
        Mon, 11 Sep 2023 07:57:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3313:b0:1d0:e2e8:7edf with SMTP id
 x19-20020a056870331300b001d0e2e87edfls2621473oae.1.-pod-prod-05-us; Mon, 11
 Sep 2023 07:57:23 -0700 (PDT)
X-Received: by 2002:a05:6870:4584:b0:1b0:60ff:b73f with SMTP id y4-20020a056870458400b001b060ffb73fmr13499724oao.8.1694444243009;
        Mon, 11 Sep 2023 07:57:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694444242; cv=none;
        d=google.com; s=arc-20160816;
        b=JmKlO52dAFwZqmvjzR5Siux2GVwTyFmluj2w8zQKm5/18qSiXL+XD4Xj2Zp4ziyaYm
         kP15TDuP237lzMBKHywfS47rbkFYzYtnLvojiB+q979hTYYVeOgvQ/fS9GbBH2ISNXis
         Z1EoQ9yxD+8F7Kwraeh85po3X8GBGEqNrNEmuskKZ1O6NQxJNve6MDEF90SItNHCL7/B
         YWRbMCaiMAIz9pP/Qd+ZIx6t93LKA4pcp1fNY0lUeeUv4DNCP3YJM7B01Q3eHJVI9Lxd
         mhSDFieSgFu3Ra6CHAi0EPcx7lY6+FA3O2HPGXLCaRzDmF9BwGq6Go3C77t3m325x+fg
         G/3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=J1LA3n6XS+9W5aKwW+ISlF8R6L/zQAaDfcEugGZs2mo=;
        fh=x/Eq99+ICi7e9grjZNFq4mA7WJOkDm5ZB5wM283JjUk=;
        b=qjpYfIegUGw3UoFW8pryXw1PYLALFLzd+3B8L/e96ORV+IfWFuYvAWuTgYguJxg0ZM
         SEUinaJh2yo868IefkpfHVOwpBuBM3kMwqejJTDLyJGZq1tCvLpzrLamUmzSjb0fdPox
         O1o2Vo9CKirk5qNlkN2DqLrCYJOvknDP0xnoL4mO280f/XVNRxz7CdF7wPHyaxePcNjC
         MaaaheZK5QV9oL1qBC/n+NAslTCB/IErLCToMimZ3mxracGW9GWOJMgBwsYNGFR5a9H0
         X3d6QeIvMtz8viynsxcYLCIpb3vs5lJzNvWt5MvMFgwCGNqKYCyH7matds6sJ6otgUva
         272g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=k0t05XgJ;
       spf=pass (google.com: domain of 30ir_zaykcvm163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30ir_ZAYKCVM163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id v36-20020a05687070a400b001bad45ecee4si1331052oae.5.2023.09.11.07.57.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Sep 2023 07:57:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30ir_zaykcvm163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 3f1490d57ef6-d7fd4c23315so3908629276.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Sep 2023 07:57:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:62e7:6658:cb4:b858])
 (user=glider job=sendgmr) by 2002:a05:6902:68e:b0:d7e:add7:4de6 with SMTP id
 i14-20020a056902068e00b00d7eadd74de6mr237093ybt.4.1694444242566; Mon, 11 Sep
 2023 07:57:22 -0700 (PDT)
Date: Mon, 11 Sep 2023 16:57:02 +0200
In-Reply-To: <20230911145702.2663753-1-glider@google.com>
Mime-Version: 1.0
References: <20230911145702.2663753-1-glider@google.com>
X-Mailer: git-send-email 2.42.0.283.g2d96d420d3-goog
Message-ID: <20230911145702.2663753-4-glider@google.com>
Subject: [PATCH v2 4/4] kmsan: introduce test_memcpy_initialized_gap()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com, dvyukov@google.com, elver@google.com, 
	akpm@linux-foundation.org, linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=k0t05XgJ;       spf=pass
 (google.com: domain of 30ir_zaykcvm163yzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=30ir_ZAYKCVM163yzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

Add a regression test for the special case where memcpy() previously
failed to correctly set the origins: if upon memcpy() four aligned
initialized bytes with a zero origin value ended up split between two
aligned four-byte chunks, one of those chunks could've received the zero
origin value even despite it contained uninitialized bytes from other
writes.

Signed-off-by: Alexander Potapenko <glider@google.com>
Suggested-by: Marco Elver <elver@google.com>
---
 mm/kmsan/kmsan_test.c | 53 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 53 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 6eb1e1a4d08f9..07d3a3a5a9c52 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -486,6 +486,58 @@ static void test_memcpy_aligned_to_unaligned(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Test case: ensure that origin slots do not accidentally get overwritten with
+ * zeroes during memcpy().
+ *
+ * Previously, when copying memory from an aligned buffer to an unaligned one,
+ * if there were zero origins corresponding to zero shadow values in the source
+ * buffer, they could have ended up being copied to nonzero shadow values in the
+ * destination buffer:
+ *
+ *  memcpy(0xffff888080a00000, 0xffff888080900002, 8)
+ *
+ *  src (0xffff888080900002): ..xx .... xx..
+ *  src origins:              o111 0000 o222
+ *  dst (0xffff888080a00000): xx.. ..xx
+ *  dst origins:              o111 0000
+ *                        (or 0000 o222)
+ *
+ * (here . stands for an initialized byte, and x for an uninitialized one.
+ *
+ * Ensure that this does not happen anymore, and for both destination bytes
+ * the origin is nonzero (i.e. KMSAN reports an error).
+ */
+static void test_memcpy_initialized_gap(struct kunit *test)
+{
+	EXPECTATION_UNINIT_VALUE_FN(expect, "test_memcpy_initialized_gap");
+	volatile char uninit_src[12];
+	volatile char dst[8] = { 0 };
+
+	kunit_info(
+		test,
+		"unaligned 4-byte initialized value gets a nonzero origin after memcpy() - (2 UMR reports)\n");
+
+	uninit_src[0] = 42;
+	uninit_src[1] = 42;
+	uninit_src[4] = 42;
+	uninit_src[5] = 42;
+	uninit_src[6] = 42;
+	uninit_src[7] = 42;
+	uninit_src[10] = 42;
+	uninit_src[11] = 42;
+	memcpy_noinline((void *)&dst[0], (void *)&uninit_src[2], 8);
+
+	kmsan_check_memory((void *)&dst[0], 4);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+	report_reset();
+	kmsan_check_memory((void *)&dst[2], 4);
+	KUNIT_EXPECT_FALSE(test, report_matches(&expect));
+	report_reset();
+	kmsan_check_memory((void *)&dst[4], 4);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 /* Generate test cases for memset16(), memset32(), memset64(). */
 #define DEFINE_TEST_MEMSETXX(size)                                          \
 	static void test_memset##size(struct kunit *test)                   \
@@ -579,6 +631,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_init_memcpy),
 	KUNIT_CASE(test_memcpy_aligned_to_aligned),
 	KUNIT_CASE(test_memcpy_aligned_to_unaligned),
+	KUNIT_CASE(test_memcpy_initialized_gap),
 	KUNIT_CASE(test_memset16),
 	KUNIT_CASE(test_memset32),
 	KUNIT_CASE(test_memset64),
-- 
2.42.0.283.g2d96d420d3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230911145702.2663753-4-glider%40google.com.
