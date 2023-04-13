Return-Path: <kasan-dev+bncBDFONCOA3EERBVFJ36QQMGQEL4A6X5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 921DF6E0B09
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 12:09:25 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id cd18-20020a056808319200b0038bef54e329sf1583212oib.17
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 03:09:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681380564; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zknr/y/wJdKpgBfGdXzQbriNebFsMZEj+H/E2qfFYbm8n9DiXU5Vk2bWVaVxq18xsS
         AA2XTR23IKxy4RcZwmwn/tMKjYcg5vcHVJNL7OproOwWOiVg9H9ZANOUM/3BPZUy9aU0
         UPNkU8fx+Lotd9fjQGoIlfu7DRLm5hk1hMX0606h6swsRQcFtiwGewlQ/TI20FB7nkbu
         TYFmNIKUYHwyCc8iJ+fak3zln3EBweM/t9wLxvJdUjUbgkH0/VSnjE4txZco7SjPU9w3
         A1/X7hMah7LnKnNtOEFHplppzCwL7vbb9aU/EpflacU9AC3cIPcuQjrjO9MjtjPtnpdi
         aOyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cCdnyHwNh8B7MUra62bGEzfugZY3LWbujVa7BdzL3U8=;
        b=O5rjqrFJ/1UeGtyUr4Vul1FwJEHLf0eu84+yklcpEkFLFyRDadNbBbThsO+aOCVDdk
         o8BkZtp4L6Cgv2T9ENpKz2mMjkKstB45bSeDvwJzI28HA+FmOirddp+bAcuFPfrHxmVp
         LKdc8w7x/n/Yun+EPbEdw6ZBxKmRVWVCVWgKvbgkohS1ZQqMdRfi78BRVi9XzZdApj2j
         pa4FYHsUkQ68kUg75aPQw9WUESGHP4lXaoSX5AYC47zCN7qwPk/aJRMX2lMlB0l242LJ
         FTiljd2l05L+MeHvf9bQRAKu78p0CitaocFTle7yxMVGrHQ02nufQKi6oSDbDf8wqO5m
         OaaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=F0Ml3lRr;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681380564; x=1683972564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cCdnyHwNh8B7MUra62bGEzfugZY3LWbujVa7BdzL3U8=;
        b=hurVVWzUnDK0iFjUYw5fr3m0/BP+yk5uRFcMM9D92oPB/3riLLFGOWvyKZIAUG59KL
         UYrBfGnl4ySxy3WTO2sf8OwYEsunb12oKxqKEfzMVe7FPioN5FXMq7mzA6SK8yKMSAhG
         kp67HTx4I2bCPRa+CbDDIiHRGRMnME/tHQuqmwj4i2tSCyBWboVEJe5eiHqblL3ji1Fw
         C6+8GncTmS1nYv+MOzf/a+ZpTbk46N+g0p1ZS69mLzur8G5u++DsTE8OHLrYRWyQ74gx
         FvmcnIwUaBdOnDxnXsitr8IKNmXeUvvjSt4LtXjnzk0TqNnZZqQLG9YEUiMb0XZo/I8I
         rlsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681380564; x=1683972564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cCdnyHwNh8B7MUra62bGEzfugZY3LWbujVa7BdzL3U8=;
        b=Rg+Oyc9zTwPUHjg42KIRP/PwWt7BYywwznQ5ZZt3udjMogfw5/40Sy039MGQfAWfFA
         g1i/6W+FQuCtOpw5cjaHAiwIWJPxYaCYnVqHzddGKNu/Y+9Xfye93zBhz3BaHF0wn0sm
         pgNOOKJEaDY9stKhafX5+Oi04B8EfrQyqkwKNERTG4V6uTqsig/IjRwTnH9XARZt9MFT
         C9QKzNt4FN/r4XXM9FDrDO/gS9+nHIw/CDshEkHoKs/GEnik3d/w4Clg/O0c6WirNhqq
         s06hk8LqkK1Q2/Et65GGr2eKgPUc5H+6AZQEFtdLlVoK0iLSu10DYl0dsG7JwY4EBkY6
         2JUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9d35/gBNqa1Ad/ANzX151i3stCQesvID5obwLl38wcTFhQ8hkpe
	XiefH6zxbBZDtijxgOCRcE0=
X-Google-Smtp-Source: AKy350aXGy8FT7KgiXpdYu3u8kaN1zrG2r5xxMpIiXM96r5Xss1vrYCq768nlcjV3Tefh1BWcokS0Q==
X-Received: by 2002:a4a:dec1:0:b0:542:3986:53bc with SMTP id w1-20020a4adec1000000b00542398653bcmr46376oou.1.1681380564219;
        Thu, 13 Apr 2023 03:09:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:631b:b0:69f:7d7b:d8f6 with SMTP id
 cg27-20020a056830631b00b0069f7d7bd8f6ls7187202otb.4.-pod-prod-gmail; Thu, 13
 Apr 2023 03:09:23 -0700 (PDT)
X-Received: by 2002:a9d:628d:0:b0:69f:8a30:3993 with SMTP id x13-20020a9d628d000000b0069f8a303993mr666783otk.26.1681380563718;
        Thu, 13 Apr 2023 03:09:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681380563; cv=none;
        d=google.com; s=arc-20160816;
        b=xGjikhQz0C28L0Ay6Ep4dZHAsEx2hVs24UOtpv2i3Bi/VPSVkTB58TCR5XQDoh/TLF
         ZgpQr9qmRyNxpwNQc1V8+k3vD11jdQdgw2xAUOTrfyvm4NYTs67uSIDrylFvauFnVfwY
         I7jW5A+H/8uYv/T29YjufS8t4j1thD1CAFxqQuvnoiuKwJdvGh9HpXqUAZlcDVu9B75i
         HkonGJi6XO/VNqLr/Tsb0qbbDptdDqdwRqsf4ks8fOpq8GJjTji7GnOUVfB0z9v/O2wJ
         zFG1EZs8ZDZrQeBibBZfrFw9sMlBTYdkPBGtMi7VSGs0CSX0xIkE2zpDVKt2CbflhPyg
         QEDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=VXmvsb+hnxaTo9wc9S7lxkclisncj9vjgTNoeT5eZbg=;
        b=qdIhz3JTbhHxiR9CSk7PKc6OoMWkKx7HWElXWl1YqkWii6nw+y0HDm1953xtCq/os4
         1kEMBv7/ABaHMgOeR1ID/KLJB/uGCVtx7FppBs1EWmnN59T6iWnlcF/psjGxBFxDxSuL
         QdXw4ALLogUus9dn/pXqQ5VSJ1jWEMYKUz71DXSxlScxXJCz1A6/yzO1f+GLtMwpgEBW
         +uju+kL/CxPxNprderAA3la7vPV1Hh9Lvhy35DNkX5EI2rWkaKDg9hzZuUl/I95ZdUSu
         uSWZVYUThSv0n3Yin+D+e9Om/qXe86yagYfqPfsPxf13sfGJxHeIKyySJXnmIlpSqNbp
         pRWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=F0Ml3lRr;
       spf=pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id bk19-20020a056830369300b006a12b6325c7si125466otb.4.2023.04.13.03.09.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Apr 2023 03:09:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279869.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.17.1.19/8.17.1.19) with ESMTP id 33D8Q7BQ003975;
	Thu, 13 Apr 2023 10:09:17 GMT
Received: from nalasppmta04.qualcomm.com (Global_NAT1.qualcomm.com [129.46.96.20])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 3px5pks4h5-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Apr 2023 10:09:17 +0000
Received: from nalasex01a.na.qualcomm.com (nalasex01a.na.qualcomm.com [10.47.209.196])
	by NALASPPMTA04.qualcomm.com (8.17.1.5/8.17.1.5) with ESMTPS id 33DA9FrV020429
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 13 Apr 2023 10:09:15 GMT
Received: from quicinc.com (10.80.80.8) by nalasex01a.na.qualcomm.com
 (10.47.209.196) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.986.42; Thu, 13 Apr
 2023 03:09:10 -0700
From: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        "Petr
 Mladek" <pmladek@suse.com>,
        Sergey Senozhatsky <senozhatsky@chromium.org>,
        Steven Rostedt <rostedt@goodmis.org>,
        John Ogness
	<john.ogness@linutronix.de>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov
	<andreyknvl@gmail.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        "Andrew Morton" <akpm@linux-foundation.org>
CC: <kasan-dev@googlegroups.com>, <linux-kernel@vger.kernel.org>,
        <linux-mm@kvack.org>, Pavankumar Kondeti <quic_pkondeti@quicinc.com>
Subject: [PATCH] printk: Export console trace point for kcsan/kasan/kfence/kmsan
Date: Thu, 13 Apr 2023 15:38:59 +0530
Message-ID: <20230413100859.1492323-1-quic_pkondeti@quicinc.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-ORIG-GUID: t97JO5bgO05dqWQcoE3wtonyMnjCzuS8
X-Proofpoint-GUID: t97JO5bgO05dqWQcoE3wtonyMnjCzuS8
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.254,Aquarius:18.0.942,Hydra:6.0.573,FMLib:17.11.170.22
 definitions=2023-04-13_06,2023-04-12_01,2023-02-09_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 phishscore=0 adultscore=0
 malwarescore=0 impostorscore=0 mlxscore=0 suspectscore=0
 lowpriorityscore=0 clxscore=1011 mlxlogscore=944 bulkscore=0
 priorityscore=1501 spamscore=0 classifier=spam adjust=0 reason=mlx
 scancount=1 engine=8.12.0-2303200000 definitions=main-2304130091
X-Original-Sender: quic_pkondeti@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=F0Ml3lRr;       spf=pass
 (google.com: domain of quic_pkondeti@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_pkondeti@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

The console tracepoint is used by kcsan/kasan/kfence/kmsan test
modules. Since this tracepoint is not exported, these modules iterate
over all available tracepoints to find the console trace point.
Export the trace point so that it can be directly used.

Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
---
 kernel/kcsan/kcsan_test.c | 20 ++++++--------------
 kernel/printk/printk.c    |  2 ++
 mm/kasan/kasan_test.c     | 22 ++--------------------
 mm/kfence/kfence_test.c   | 22 ++--------------------
 mm/kmsan/kmsan_test.c     | 22 ++--------------------
 5 files changed, 14 insertions(+), 74 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index a60c561724be..0ddbdab5903d 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1572,34 +1572,26 @@ static void test_exit(struct kunit *test)
 }
 
 __no_kcsan
-static void register_tracepoints(struct tracepoint *tp, void *ignore)
+static void register_tracepoints(void)
 {
-	check_trace_callback_type_console(probe_console);
-	if (!strcmp(tp->name, "console"))
-		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
+	register_trace_console(probe_console, NULL);
 }
 
 __no_kcsan
-static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
+static void unregister_tracepoints(void)
 {
-	if (!strcmp(tp->name, "console"))
-		tracepoint_probe_unregister(tp, probe_console, NULL);
+	unregister_trace_console(probe_console, NULL);
 }
 
 static int kcsan_suite_init(struct kunit_suite *suite)
 {
-	/*
-	 * Because we want to be able to build the test as a module, we need to
-	 * iterate through all known tracepoints, since the static registration
-	 * won't work here.
-	 */
-	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	register_tracepoints();
 	return 0;
 }
 
 static void kcsan_suite_exit(struct kunit_suite *suite)
 {
-	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	unregister_tracepoints();
 	tracepoint_synchronize_unregister();
 }
 
diff --git a/kernel/printk/printk.c b/kernel/printk/printk.c
index a5ed2e53547c..8bb9e8752d65 100644
--- a/kernel/printk/printk.c
+++ b/kernel/printk/printk.c
@@ -71,6 +71,8 @@ EXPORT_SYMBOL_GPL(console_printk);
 atomic_t ignore_console_lock_warning __read_mostly = ATOMIC_INIT(0);
 EXPORT_SYMBOL(ignore_console_lock_warning);
 
+EXPORT_TRACEPOINT_SYMBOL_GPL(console);
+
 /*
  * Low level drivers may need that to know if they can schedule in
  * their unblank() callback or not. So let's export it.
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 74cd80c12b25..edf3158fc075 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -56,19 +56,6 @@ static void probe_console(void *ignore, const char *buf, size_t len)
 		WRITE_ONCE(test_status.async_fault, true);
 }
 
-static void register_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	check_trace_callback_type_console(probe_console);
-	if (!strcmp(tp->name, "console"))
-		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
-}
-
-static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	if (!strcmp(tp->name, "console"))
-		tracepoint_probe_unregister(tp, probe_console, NULL);
-}
-
 static int kasan_suite_init(struct kunit_suite *suite)
 {
 	if (!kasan_enabled()) {
@@ -86,12 +73,7 @@ static int kasan_suite_init(struct kunit_suite *suite)
 	 */
 	multishot = kasan_save_enable_multi_shot();
 
-	/*
-	 * Because we want to be able to build the test as a module, we need to
-	 * iterate through all known tracepoints, since the static registration
-	 * won't work here.
-	 */
-	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	register_trace_console(probe_console, NULL);
 	return 0;
 }
 
@@ -99,7 +81,7 @@ static void kasan_suite_exit(struct kunit_suite *suite)
 {
 	kasan_kunit_test_suite_end();
 	kasan_restore_multi_shot(multishot);
-	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
 }
 
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index b5d66a69200d..6aee19a79236 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -825,33 +825,15 @@ static void test_exit(struct kunit *test)
 	test_cache_destroy();
 }
 
-static void register_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	check_trace_callback_type_console(probe_console);
-	if (!strcmp(tp->name, "console"))
-		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
-}
-
-static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	if (!strcmp(tp->name, "console"))
-		tracepoint_probe_unregister(tp, probe_console, NULL);
-}
-
 static int kfence_suite_init(struct kunit_suite *suite)
 {
-	/*
-	 * Because we want to be able to build the test as a module, we need to
-	 * iterate through all known tracepoints, since the static registration
-	 * won't work here.
-	 */
-	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	register_trace_console(probe_console, NULL);
 	return 0;
 }
 
 static void kfence_suite_exit(struct kunit_suite *suite)
 {
-	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
 }
 
diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 088e21a48dc4..06e18f76c641 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -541,33 +541,15 @@ static void test_exit(struct kunit *test)
 {
 }
 
-static void register_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	check_trace_callback_type_console(probe_console);
-	if (!strcmp(tp->name, "console"))
-		WARN_ON(tracepoint_probe_register(tp, probe_console, NULL));
-}
-
-static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
-{
-	if (!strcmp(tp->name, "console"))
-		tracepoint_probe_unregister(tp, probe_console, NULL);
-}
-
 static int kmsan_suite_init(struct kunit_suite *suite)
 {
-	/*
-	 * Because we want to be able to build the test as a module, we need to
-	 * iterate through all known tracepoints, since the static registration
-	 * won't work here.
-	 */
-	for_each_kernel_tracepoint(register_tracepoints, NULL);
+	register_trace_console(probe_console, NULL);
 	return 0;
 }
 
 static void kmsan_suite_exit(struct kunit_suite *suite)
 {
-	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
+	unregister_trace_console(probe_console, NULL);
 	tracepoint_synchronize_unregister();
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413100859.1492323-1-quic_pkondeti%40quicinc.com.
