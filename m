Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB752OGAMGQEWGSGRRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id F1E654546DC
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 14:07:19 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id w18-20020a056402071200b003e61cbafdb4sf2085257edx.4
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 05:07:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637154439; cv=pass;
        d=google.com; s=arc-20160816;
        b=No6HT1pVSNCS+a047LS0/pAVSXrlz78Tx7RpQaI16xENu4afEdqMi2Kr24DzECm29G
         T2SI8z2GT3RWctBnZ/I4rFqtedk8ovjLmsstfj1Pn0X3vh/7a0NHQvrQMFSyc5axA/rL
         /YqYrN2vF8osXb9DZZDBcIlOiIcMb3L0gGN6LBPiMU1Jl0JzZ5pcYAbNJe+ESyNO2WrF
         Cfv1X5g26tY8fkTwNtkHtm35H68LD6g896RV+Uu/NeQuxqKB7o6qbQN+vgRSu29hE8TR
         DK63IFikBJWz60MCRF3yAGeHuWE0DB6TWmImGCJwKqXpNWh/jXgbpA49wSATDiAFzOJ5
         ckxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=kCnGEW99wrsSc4m595t4+MV/ybfgA9ssKz10cyLCrWc=;
        b=PXC7r5hbcI/ypIdQyGW/zCHNmJQXXEg/G4r35y65qNP9k/tZKNJpmEchbxiLqU+gPd
         KiZodnZ9fagxAT8n5hTeOf0XfiQHI2GkhLG/b0Fsz8iT6VFXlpMh1bViKb66j0ddnuQP
         BL6/8HP9HY2bINAwG1Uy+SVfsd2iJHIYUHaZVDS9Y6yuslkPcsHKcHfRTZGaLfam0R1z
         udJJbHScRN6PWsKeqTneb+O3DbSe3jfpS8ZKuJ7ZlA91OxpFsIgHYLQHA+t5x/I4LgQ3
         /oogrBL7taBiI4nauNbsBKsnqSqcxp4sa8oKUipA1xUYxJc63w29Zmc7L2eS5nlHsNOY
         KO/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ndheOzfs;
       spf=pass (google.com: domain of 3hv6uyqukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hv6UYQUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=kCnGEW99wrsSc4m595t4+MV/ybfgA9ssKz10cyLCrWc=;
        b=Ko0MWFkzmmeICe0+hI4WSOK6It5MnmCysDGOP5IH2NNGGVl9ZPWa2L9dBR6R7BqUqR
         LOfzw0jmq4LGM9vVhihs6h27WKfG2+M5UmlD6cxJ7lLv2rGIOxEAHFaS9xvjXLyTeggt
         whei2FQWif1qlhse5K8HcnID1QSTb9P+BbRZQZ9deVe/qDvb7dMu17klW2jk5dTn1XSH
         20NauncPtN4EVsZNULhrg8UtiEL5emPx71w/5EWYdttz9oqhc786yikOZlkEnlV/W6rq
         EIgJdZAMFRyo94zNFh0FiQkw4aPRbBlDtCSlGCQ4JcUh5SYNlxd7LOzxmM7PK4k49qqp
         Eo8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kCnGEW99wrsSc4m595t4+MV/ybfgA9ssKz10cyLCrWc=;
        b=Pw56lWuEbkECi1QZksZcWr9+jqQDc4E5/wKD3dmxTNkw9OmU3AGfgeEsGi0H3qih80
         dssER/QrUCBUBWUKo1nWvnYyDAyAiKNjce9uqpH6G1kuaeZcGtI4sC4m+VU4BQxAMWS8
         LgJSiAsVPvI1Zg5MQvJbqAYwYw1nyrO4vkG0GDRecJU+3NR2cSFkiBz3q1AHfYaxQ/PA
         oE261H5/w1O5X3nnEEQwz8Vt6vXsxgUi1p0MSqJr0QxMG8ourpFx/h3ljUHNygcF21rf
         mAxPVN3NkDlkStjHvmyc8IN8KDqioiZvZFWxGev/HXJLb9sV4rIkKkYOsBzqNgw/NYoB
         BvPw==
X-Gm-Message-State: AOAM533ESe6fzcJCmmISBVCI05ApoTmqC+ZXz8KaVzCxqfe40VOXStpp
	E3o8ThMhOw7wjBCvW6Ga55E=
X-Google-Smtp-Source: ABdhPJwSomYrY6WZ+Zs10+o9yXZaTPLqmkx5/P+aCpstedoEhO0dhiDjGgHM6OHTt58kVfrrC0+9EQ==
X-Received: by 2002:a50:d883:: with SMTP id p3mr21704724edj.94.1637154439632;
        Wed, 17 Nov 2021 05:07:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e93:: with SMTP id qb19ls6795953ejc.4.gmail; Wed,
 17 Nov 2021 05:07:18 -0800 (PST)
X-Received: by 2002:a17:906:314e:: with SMTP id e14mr21853443eje.165.1637154438532;
        Wed, 17 Nov 2021 05:07:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637154438; cv=none;
        d=google.com; s=arc-20160816;
        b=TzSsXXQCwyJxXPzq4OHp62Ehn4csAwSloK7pXq+jMyTrVkRQDuzZNoK91xvuC0ybJa
         /UfPH8+KOAWYGEH/HtBQ2HiqSXAXggucGnhbfvu2w1sTKsij/FwwIeAs6rR/1DgBCCAs
         Lf6imqKYF+FG6yuyR4+8OPQVBs3/otrctQAzy9dinekNaGOi0TKeJRfvBnJbwHZqzYsB
         br6lWdj7k3wL3yRHTGpBV9FbqfBuFtrTSmEbYKe4ixrxqnm3t2BOT8rEF87G7x9JZxFM
         aaP/F2ZsyaOWUQ82TdS/nU9NsXPuAU/49miHfeFJbauK8koil23uCrsvXb+WjWsnVfK2
         zSRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=tN9I+pAFJlbUYxyB1icCBjOYc97BjdaVLmTiDNjOPV8=;
        b=zay3c3+LKbYIcSzELFcHdv1o0vJPFZtL4Tch/aDW0z+OfIfivhg0ZWKvbPClk2sIXC
         a/Uyubb5KKRhDWQz97UxSWjQn7ag81VjL3J10bYAfaVFvhkPQkWOLnfZ5VsS8Z3SSQvy
         SPynyPeCGrRQFHXFjzlJp0VUX5CxF5QKcV9uChDc9qCWQlNsxnN/twjInmLyfjzMY2pn
         O+UIvVU+b1DPAwD6vD2GV0mcJvYZESx/uEIv6AWi45dn+EpDui1KxaFFmoaWq95i141l
         5Kdh1VN3PBnkFrbr2xRS/w1LVMUzhvivP+MUwlGPVNUi0VFpDAC0K4MhcHSMNtqpufCd
         7INA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ndheOzfs;
       spf=pass (google.com: domain of 3hv6uyqukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hv6UYQUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o19si404399edz.5.2021.11.17.05.07.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Nov 2021 05:07:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hv6uyqukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id v1-20020aa7cd41000000b003e80973378aso531441edw.14
        for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 05:07:18 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:80aa:59e4:a6a7:e11e])
 (user=elver job=sendgmr) by 2002:a17:907:1c97:: with SMTP id
 nb23mr21669634ejc.488.1637154438173; Wed, 17 Nov 2021 05:07:18 -0800 (PST)
Date: Wed, 17 Nov 2021 14:07:14 +0100
Message-Id: <20211117130714.135656-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2] kasan: test: add globals left-out-of-bounds test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ndheOzfs;       spf=pass
 (google.com: domain of 3hv6uyqukcekpwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3hv6UYQUKCekPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

Add a test checking that KASAN generic can also detect out-of-bounds
accesses to the left of globals.

Unfortunately it seems that GCC doesn't catch this (tested GCC 10, 11).
The main difference between GCC's globals redzoning and Clang's is that
GCC relies on using increased alignment to producing padding, where
Clang's redzoning implementation actually adds real data after the
global and doesn't rely on alignment to produce padding. I believe this
is the main reason why GCC can't reliably catch globals out-of-bounds in
this case.

Given this is now a known issue, to avoid failing the whole test suite,
skip this test case with GCC.

Reported-by: Kaiwan N Billimoria <kaiwan.billimoria@gmail.com>
Signed-off-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
---
v2:
* Add bugzilla link.
---
 lib/test_kasan.c | 19 +++++++++++++++++--
 1 file changed, 17 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 67ed689a0b1b..40f7274297c1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -700,7 +700,7 @@ static void kmem_cache_bulk(struct kunit *test)
 
 static char global_array[10];
 
-static void kasan_global_oob(struct kunit *test)
+static void kasan_global_oob_right(struct kunit *test)
 {
 	/*
 	 * Deliberate out-of-bounds access. To prevent CONFIG_UBSAN_LOCAL_BOUNDS
@@ -723,6 +723,20 @@ static void kasan_global_oob(struct kunit *test)
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
 }
 
+static void kasan_global_oob_left(struct kunit *test)
+{
+	char *volatile array = global_array;
+	char *p = array - 3;
+
+	/*
+	 * GCC is known to fail this test, skip it.
+	 * See https://bugzilla.kernel.org/show_bug.cgi?id=215051.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_CC_IS_CLANG);
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)p);
+}
+
 /* Check that ksize() makes the whole object accessible. */
 static void ksize_unpoisons_memory(struct kunit *test)
 {
@@ -1160,7 +1174,8 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmem_cache_oob),
 	KUNIT_CASE(kmem_cache_accounted),
 	KUNIT_CASE(kmem_cache_bulk),
-	KUNIT_CASE(kasan_global_oob),
+	KUNIT_CASE(kasan_global_oob_right),
+	KUNIT_CASE(kasan_global_oob_left),
 	KUNIT_CASE(kasan_stack_oob),
 	KUNIT_CASE(kasan_alloca_oob_left),
 	KUNIT_CASE(kasan_alloca_oob_right),
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211117130714.135656-1-elver%40google.com.
