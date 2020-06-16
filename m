Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3XZUL3QKGQEBEB45BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BED41FB0E0
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 14:37:04 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id c17sf24577414ybf.7
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Jun 2020 05:37:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592311023; cv=pass;
        d=google.com; s=arc-20160816;
        b=k29vnEIlpyvD28WtQgbgNwWCPZPDlpSx7S891SoCzziDl+n4Y6PrJI5uXoPcNb/61s
         UQLXncrzLxPSoRLV4xUEIh8TgTCKt3Nhd9vnk0VMgIJOomcfJfGvQEKuh46k4TbaMcE3
         dE3OGEfeunhhmtRqMR4QKx6FWo1bUV+yaTWUf1EJS13whAOvvXtZBKWbmHp2UPHPkVHy
         zd/pmN+j4wVXgjhnfDx8QhG+BfcjphQ0rQ1zQxyFmWmDRdTN+rP7AuySmjvCdcOsRHVx
         Uw9avunZg9d9PvFu2ysO2sX/iJEPoEzUV9zE9cwjhTJ5kNIEWadP5oqUvOzxf2G/KhEz
         dm1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HHU8zgE/K0+B+4sDyP5t2QMjk3zeo9Kv1og5/X+kevE=;
        b=Ip3BYupTOHZnWel7fjRMR1ntqblwHJjMLTMewXVp0pctJ9inS4Iv5gy0JSSW6/AYP1
         mIE4PndISXB1IBMC6eGKVHbiVdsKTXxTt92lZJLLZz1KO0DTiCDxe+ZkKpTHTJVC+FU9
         mhpkwnaoYc7ik1iw3C7x16kqsziSiMsFYPFdioMZIoNGKMATBmKunEZp0ezKne7xSIEq
         HZ7UqL/wemxN/I4JNq4Uf9r6AOguHsqUKN9OZ2/SsgFZRLtSR5J0HMKqkxIEF4lXaShk
         V0OcMKV7rwe5xaPv/wwuXrh0ESYEJlWNXqWU1dkBZ+QpmO9yNlTRUVnUyWqPGnIgzJe1
         XY7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CncR2ckP;
       spf=pass (google.com: domain of 37rzoxgukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37rzoXgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HHU8zgE/K0+B+4sDyP5t2QMjk3zeo9Kv1og5/X+kevE=;
        b=i2XL/fM61I05Nx9aVv9EOLtp277esuC6QgN3PRLV3qY/hIwMYZfvJPqB2M97oslrPD
         HIIQh1p9dxzpym1HrBc1KNhC7dXVwPoVrIYk5WdFJCKWkkPKg0t4Ul5Y78Z/38l7KL6e
         55a2uAjHG5a3mGthVctxXUz1n8HSuR4nVKsJTLcqGltp+VFVXDQip8LHW/z2TbrWsIIM
         GS9ckNE8KfHrMxsPYKzKDslgKtCVZHtlcGomYozv9JBBWTvCAUdVQo1OgMWc47j0HJt2
         oPYev7MBZNBMfcxBfhUMRlSYZmpyaSR3InszVnBzUosh3T25a5JbUg96rTk2TlwsoAUP
         kUBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HHU8zgE/K0+B+4sDyP5t2QMjk3zeo9Kv1og5/X+kevE=;
        b=TWoZs9iOazCrapkz6rAQmugcTXa2zEQ2fUy0XIfR763xoUt9pQ4yfS1+N/gCSk3gaY
         sl4DPEaacIE3WxdY5db9WVr6lbJchrGwic6L1AzXjzcHSQR9Kn3QHxD/XqqQYLn50W0K
         rWrAp5sUMyxkTPTmnxHqGRF1mfhsS/ig+6ziFWBogtKEv+5BcuDB+K6EJV0zsIiJD4Pa
         yifUovJlYNHHwLYfv5NTdsHvYNeX9QyS9tbZGMJtTcW2Ux9oTViC/XJh52sku8tKXM4R
         alLb3wAID307JSCUd4Qz//j7kNe/8GXUysvDCk402PfZo52fSbciWAqqqmaebsORnv1b
         8xjQ==
X-Gm-Message-State: AOAM532vw3vHeDL6u910S5iTaAVkyf90f4n1mgFl6gMlZYi9K1DTiD/L
	7KbuCrUGscRAvOTIZGrLxV0=
X-Google-Smtp-Source: ABdhPJy72pNq1GsA2qVQcx42TxJBbFGMW2c/hRGSg5PwKy7NcmQDg+BJuEVpe0DXSslo7jBsng9ttA==
X-Received: by 2002:a25:d451:: with SMTP id m78mr3211625ybf.402.1592311022966;
        Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:cb07:: with SMTP id b7ls7293813ybg.1.gmail; Tue, 16 Jun
 2020 05:37:02 -0700 (PDT)
X-Received: by 2002:a5b:a89:: with SMTP id h9mr3957369ybq.93.1592311022658;
        Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592311022; cv=none;
        d=google.com; s=arc-20160816;
        b=eiGgC+wVVNBShvWpEQSOds+ODNEn1tXTumuTYK28Y6+IaMTC9Bmwvb/Tnz+rYasFah
         643mpi6RW9+LI/lfE150w3jjw91p+R+kjxrqrplki13D0zrAn7PDF3PZcS14Jd60v/yM
         NQ08gN5EQAn51z4lBqh8KCtlk0B6LOMx0pzfyCNdpGm2So+uG+L6xXX0uo+e9e84WiLH
         7Oi26pEMzvSSXDYbDf00l0gDl88fgA9djuBpXNcfIQwnap9T0T3l2MnZInn89rhqtsHG
         C2eJ890eZgIpA3FudN2HvXrBv9U43nw1vwZF/S/1/1xIvJ4BRY+kB4F27BfVtkbba9HU
         GQfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=1xZsTLo/mLSdGNuFOenJEIpuLskAW05lb+ykXWbx68A=;
        b=nVLa3HNNzxftHEwYFKnprCYoRpS9yziZUPxbAkU+ZVnuURrUxIV+rBqcC3BD7YfOpE
         7zqWp8EGaBEGB+v+C5cKKGViwU9tfS0qFtDk5Abyqihofs9scX69llvEDtnqhamivxIM
         8qbPzh5tQtRCKgUXuKOrSMGf1bdlfL8y/Rccc1TwnarWElq1o/SW9cgE2AF3yLuvw49m
         U2wAxXyRJPf/avAfrUCNbXo9uZCxaep3oFyAKToAtN3XGRWzaz3lDCPOAFfFOLvfmCl1
         g6g/xcT7VnkwxdlQWBC2Dvg9Dym1whM6WOexP4rd5ucwDdIeKiyrSDJzI3D4mqVdZTW/
         00HQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CncR2ckP;
       spf=pass (google.com: domain of 37rzoxgukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37rzoXgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id n63si1061953ybb.1.2020.06.16.05.37.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37rzoxgukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id l19so16569411qtp.12
        for <kasan-dev@googlegroups.com>; Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
X-Received: by 2002:a05:6214:14a6:: with SMTP id bo6mr1988177qvb.244.1592311022252;
 Tue, 16 Jun 2020 05:37:02 -0700 (PDT)
Date: Tue, 16 Jun 2020 14:36:25 +0200
In-Reply-To: <20200616123625.188905-1-elver@google.com>
Message-Id: <20200616123625.188905-5-elver@google.com>
Mime-Version: 1.0
References: <20200616123625.188905-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.290.gba653c62da-goog
Subject: [PATCH 4/4] kcsan: Add jiffies test to test suite
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CncR2ckP;       spf=pass
 (google.com: domain of 37rzoxgukcqknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=37rzoXgUKCQknu4n0pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--elver.bounces.google.com;
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

Add a test that KCSAN nor the compiler gets confused about accesses to
jiffies on different architectures.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan-test.c | 23 +++++++++++++++++++++++
 1 file changed, 23 insertions(+)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index 3af420ad6ee7..fed6fcb5768c 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -366,6 +366,11 @@ static noinline void test_kernel_read_struct_zero_size(void)
 	kcsan_check_read(&test_struct.val[3], 0);
 }
 
+static noinline void test_kernel_jiffies_reader(void)
+{
+	sink_value((long)jiffies);
+}
+
 static noinline void test_kernel_seqlock_reader(void)
 {
 	unsigned int seq;
@@ -817,6 +822,23 @@ static void test_assert_exclusive_access_scoped(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, match_expect_inscope);
 }
 
+/*
+ * jiffies is special (declared to be volatile) and its accesses are typically
+ * not marked; this test ensures that the compiler nor KCSAN gets confused about
+ * jiffies's declaration on different architectures.
+ */
+__no_kcsan
+static void test_jiffies_noreport(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_jiffies_reader, test_kernel_jiffies_reader);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
 /* Test that racing accesses in seqlock critical sections are not reported. */
 __no_kcsan
 static void test_seqlock_noreport(struct kunit *test)
@@ -867,6 +889,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_assert_exclusive_bits_nochange),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_writer_scoped),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
+	KCSAN_KUNIT_CASE(test_jiffies_noreport),
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
 	{},
 };
-- 
2.27.0.290.gba653c62da-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200616123625.188905-5-elver%40google.com.
