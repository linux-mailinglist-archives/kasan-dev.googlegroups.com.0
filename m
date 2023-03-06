Return-Path: <kasan-dev+bncBCCMH5WKTMGRBWUVS6QAMGQEA5574ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 460C26ABDEC
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Mar 2023 12:13:31 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id r7-20020a05600c35c700b003eb3f2c4fb4sf3600809wmq.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Mar 2023 03:13:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678101211; cv=pass;
        d=google.com; s=arc-20160816;
        b=L/374u7akmqR/XkJ7p9EWj+yuruuafhccW6vrurxXX34r0S/3l8XcSzMb6CPfoRj9a
         hZ0Y/S9S07zGTO+J/mkvh3BJI++DL2P/XICYwZB+wmyNz+GQGIT//zaee3ELJl2vQFwm
         jxEQI/G0X4T6PgVWNaZJ+7+PVvkzZB2MD1bNLO/B+qyQlUcoz6CAc4prVPlmS9vVUZSD
         FYcBX0Cc/7bJKTtc47wgYq5HN7sDvEnF4psZ+I/vPJeN6bocgJl39GY2dl2oP8wd2PRR
         XFveWmA1NJs7EaIQJIk/Tk92MUd0eass+3wl+aQn7UskhpAH4Pjbc0RB9f8TLcUcDSZ1
         tD5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QufwqgImBs0x1M05RwkPcLGKviZJAXwqfLGkxFmHPm4=;
        b=nKC5O8LqzHqf1raILZnsISEpeFKfl9mOMc2PlTAV2tWnrhu7ZUbqCfkHNEt78+FKUJ
         oG5ncuMsemxwAPAyIJwh28t2i0q/3teXAtcHGP1xY/C4NuWNSvBkQTqJvsMm8YQ8maCy
         KEtdF+FalIstRA8s9SQZds2hSqkyJrUrGKpV6fSpNcz1RJRfNJIfFeXSyk0+RskrZQPI
         ob1cwiA+KENitmuFdZANncuOlOPONdO/WmHJjXp3slog6r9r6PN7cdONcO/VvMGmBDb7
         Ay5Ag5nTwmn6TXV10JPRRchoQkingh078TPkv0PyIblBYHXR+K5NcIFT3e6uoNrUiSC+
         94AQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P5DhRm6l;
       spf=pass (google.com: domain of 32cofzaykcawsxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32coFZAYKCawSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678101211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QufwqgImBs0x1M05RwkPcLGKviZJAXwqfLGkxFmHPm4=;
        b=Xw77qA6WF2iYdihYXcknJOMkj2hwV3CZ8dLJMT0rQKBzHnRljIOuAZo8uX2wnhT8PB
         RLL3QoGV3/RwLugHlMPWIxOX5qA81ffsKXX5QWNR2PnRQc2MXqDA63kTzN5uJ72TujMn
         QXFUuIAhUs4+MJedZp2N3gORi6Rfsr6mawvX4r+SvmMAqvdgDl5+XUvXRXHoior6RWQ0
         H/jThf/SxEh22aqSlsIdYMENGYhdctDg0N1ZetuXLs3HXwbLnRTuZ3em6JzCFxibW9yT
         fLAZXi2Q/gPs0e/0lg0rlhpQABFuYFotKwMwUef2SwZ3OIVsxUhu01YPNLytyGek2YIU
         IhEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678101211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=QufwqgImBs0x1M05RwkPcLGKviZJAXwqfLGkxFmHPm4=;
        b=Yx1YaWm+4U9rpaNyqbyu5FzHHi5FqkFlcgafp7eQ4VLbn6v0oWzZcKkyNVBePTnO18
         sNjkQ8+hXCk1iN1aCHOeyscDYPJ/z3rEdSmq9w3jZLc3XnZU16DJ3segp/8oMbRee89j
         4dx3Z13ZAdWKhTb4BaLizR3rR9+Jmh4lp9p2CvIbRLQVoHukrYQuvLYeOXk+gTF8/n7O
         dftwVpmi8KaS+UayHoKxerp2eXrQMGnwfPVFE+JdJhqKdswfR/WfAk81wbSMe9EneEJ0
         rCkF2fOYD3A1dWWkdt1tx+dSreHxjMMoup7KEAi/aLeBXnbpM6muNcMnd9JVwWoF46Zb
         cHMA==
X-Gm-Message-State: AO0yUKU4ykk930pQS9TPsHrVtXhcH4qRKOCr27PIOSysmhrBcoqwxzCj
	ZvrEI2eQxla4YNZ/GGqcdDQ=
X-Google-Smtp-Source: AK7set/7widFaVZY1QuCDrxtfvUnL2SzffVTTF2QaUQVxeHssQePkHJydF6WaG+rk/SgUmKL2P1n+Q==
X-Received: by 2002:adf:f006:0:b0:2c4:80a:e849 with SMTP id j6-20020adff006000000b002c4080ae849mr2242764wro.1.1678101210638;
        Mon, 06 Mar 2023 03:13:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba7:b0:3e2:19b0:7006 with SMTP id
 n39-20020a05600c3ba700b003e219b07006ls5045527wms.3.-pod-control-gmail; Mon,
 06 Mar 2023 03:13:29 -0800 (PST)
X-Received: by 2002:a05:600c:3c85:b0:3ea:f05b:50cc with SMTP id bg5-20020a05600c3c8500b003eaf05b50ccmr9597680wmb.8.1678101209446;
        Mon, 06 Mar 2023 03:13:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678101209; cv=none;
        d=google.com; s=arc-20160816;
        b=0OBx/DO5jhH0MAgM4KczSQJDuew+n+Ot+rhxP2lIBoZg+SJQ2xTuxP0KBHzFmNQIyr
         nx53lghYjqcV/JeIDkxMMQgA2WXw4/ds51BVJ1+F5yZE6jWF8KzanC5BvCI3720Zd4LS
         1gpNTWKHmw9saVcNIXX60QxMYed9Kogn3w8j+k9dOvdr4FNNW2ZZVLy4lRlT0eN8MEbl
         rDxFgHQi54Ze9ugTdI8RRlFzJK2Ba1JqJAW1HCtlYXbs+cFOVX1H6+bPSOZSolMKq4Xa
         uL0c5xfwsAqrVGNqlPzGywdFDa39M85clheEXjWQ3ix56XDwnLqqP3uZQlzdG0663N0w
         Pi2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=i1L+pZCwrwV8WFeqR7MKglAsPEnoOPqo6PmA3RfPAYI=;
        b=DEJkHpzGi+zArwSu6sTnbSemcJ443uxSGKCbA2EV519VF5GHsGi+3btmIc6u1AIUJu
         8Kju5sR1W8zN5znxF1HBB4ZzJGFNTSmYlhGfRdTf0Lj6QUlOaAPfgMeQ3oWb09DRr7a+
         vWY4H1i6dvQa4G9hZUiu7Keokjoo51LGgwKJfbiQ++f+OqjIVDahoThp9VWOg7+reaBn
         ovWYvGnsI1A+Dbnq8pUs7xoYnY1077n6BJDg/L1JlRtyGtJd5XndO5gpe9gseItTOcos
         dBodxRsyeV6vvRxyaK393Uj1u9guFrN+EAYlksZrdL3SQlgIXJtCMcV1wWXY8ug/C/rp
         q2qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P5DhRm6l;
       spf=pass (google.com: domain of 32cofzaykcawsxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32coFZAYKCawSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m19-20020a05600c4f5300b003dc537184cfsi622581wmq.1.2023.03.06.03.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Mar 2023 03:13:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 32cofzaykcawsxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id w7-20020a056402268700b004bbcdf3751bso13197163edd.1
        for <kasan-dev@googlegroups.com>; Mon, 06 Mar 2023 03:13:29 -0800 (PST)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:b93a:5d85:6f2c:517d])
 (user=glider job=sendgmr) by 2002:a17:906:4f94:b0:8b1:7de9:b39b with SMTP id
 o20-20020a1709064f9400b008b17de9b39bmr5034537eju.1.1678101209226; Mon, 06 Mar
 2023 03:13:29 -0800 (PST)
Date: Mon,  6 Mar 2023 12:13:22 +0100
In-Reply-To: <20230306111322.205724-1-glider@google.com>
Mime-Version: 1.0
References: <20230306111322.205724-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.rc0.216.gc4246ad0f0-goog
Message-ID: <20230306111322.205724-2-glider@google.com>
Subject: [PATCH 2/2] kmsan: add test_stackdepot_roundtrip
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	akpm@linux-foundation.org, elver@google.com, dvyukov@google.com, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=P5DhRm6l;       spf=pass
 (google.com: domain of 32cofzaykcawsxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=32coFZAYKCawSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
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

Ensure that KMSAN does not report false positives in instrumented callers
of stack_depot_save(), stack_depot_print(), and stack_depot_fetch().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/kmsan_test.c | 31 +++++++++++++++++++++++++++++++
 1 file changed, 31 insertions(+)

diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
index 7095d3fbb23ac..d9eb141c27aa4 100644
--- a/mm/kmsan/kmsan_test.c
+++ b/mm/kmsan/kmsan_test.c
@@ -551,6 +551,36 @@ static void test_long_origin_chain(struct kunit *test)
 	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
 }
 
+/*
+ * Test case: ensure that saving/restoring/printing stacks to/from stackdepot
+ * does not trigger errors.
+ *
+ * KMSAN uses stackdepot to store origin stack traces, that's why we do not
+ * instrument lib/stackdepot.c. Yet it must properly mark its outputs as
+ * initialized because other kernel features (e.g. netdev tracker) may also
+ * access stackdepot from instrumented code.
+ */
+static void test_stackdepot_roundtrip(struct kunit *test)
+{
+	unsigned long src_entries[16], *dst_entries;
+	unsigned int src_nentries, dst_nentries;
+	EXPECTATION_NO_REPORT(expect);
+	depot_stack_handle_t handle;
+
+	kunit_info(test, "testing stackdepot roundtrip (no reports)\n");
+
+	src_nentries =
+		stack_trace_save(src_entries, ARRAY_SIZE(src_entries), 1);
+	handle = stack_depot_save(src_entries, src_nentries, GFP_KERNEL);
+	stack_depot_print(handle);
+	dst_nentries = stack_depot_fetch(handle, &dst_entries);
+	KUNIT_EXPECT_TRUE(test, src_nentries == dst_nentries);
+
+	kmsan_check_memory((void *)dst_entries,
+			   sizeof(*dst_entries) * dst_nentries);
+	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
+}
+
 static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_uninit_kmalloc),
 	KUNIT_CASE(test_init_kmalloc),
@@ -573,6 +603,7 @@ static struct kunit_case kmsan_test_cases[] = {
 	KUNIT_CASE(test_memset32),
 	KUNIT_CASE(test_memset64),
 	KUNIT_CASE(test_long_origin_chain),
+	KUNIT_CASE(test_stackdepot_roundtrip),
 	{},
 };
 
-- 
2.40.0.rc0.216.gc4246ad0f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230306111322.205724-2-glider%40google.com.
