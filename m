Return-Path: <kasan-dev+bncBDYZHQ6J7ENRB4XB5SVQMGQE3AHGWPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id EA6CD81369B
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 17:44:36 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-28b0d8841e7sf472821a91.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Dec 2023 08:44:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702572275; cv=pass;
        d=google.com; s=arc-20160816;
        b=fFM4Qig4zHw8AnsffmWZ4mDLVi+KZXbjl0zVok57DZ4DPB33S5/+IORS9W205xN/KY
         W5LoYkcvVuqCnHPXfhzr/yOdXmidio0W2G5DEhL0oNjUE5X7YijwlP/PUCYzq/3tGWYo
         13MuSLBR7hm83STbrB8bngWEY+6bLBEkqNe8O6rfbwpdSo2PhnJDnO96dvjnsjlnzv/a
         dRFhBjdBRs4CS/Fl6GyvIA7F5Zs6syr+09X16El2xvOonlSIupH9VTENG2uT/kOlkI+N
         VeT0wOoU5C1dGVkTPPvDlRI7wnhdOmbOhnYzvMwSsrRQlLzgpcMLyRczNcjzpQ6qJ0f8
         qf4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xkbitQ1maQRTGIDvXyxdRzpeenMPGBstmo0vfSnf6d8=;
        fh=t4pyiPcCBIC9Y+5xkCTP+ifpPVuOKc4r2DwOkdw1hDY=;
        b=eBtAEtBRAcUa7MnSwo/RIFoCk+BukulCBD/BefhGcZTHMubnsvaM68gOk7HckIhu9o
         eChMLVU/DE2m1vuctOdq9KSBvFMqYISIiqT7aSbmCjXwSWCRzznG4gYUvSJR04r96+tR
         q1fbTiIDfUQVF4mugig5KmHihv4PnOJLtWH/0nVEzgc7dI4xZP3495IN7yWtCFH4bAVf
         gqD72ClgyAqN7ej7x+0DqHwyK7ibvFlu7UcRs5XyNDSPPs4q2OrRHwm0VRukEJzYwOF9
         RVD9wM5QFLezC3iLb0QRjY7zwPkY+HqZ6m6Mb+Hdo271OxiE6qaRkGsdXek8Y1gchRRn
         ZwYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f6pGycap;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702572275; x=1703177075; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xkbitQ1maQRTGIDvXyxdRzpeenMPGBstmo0vfSnf6d8=;
        b=iswzuOf92GZwC4qvx0K4UGyKbf6wdNioh1YxzAPTMVTmfzwRbtQzx+l2dLejZQ9rfn
         2lldbwXQJoJaDzUvVjd2tu1Pczd13nI4AhOWK5Ugt0E8VDkuMcOunvhAHxhlvqyYtgpr
         it2owaaD2Rop5dQeNUnldp3FDekko0M/kbNrtaoy4HUMZpn07B/cHm45gRmPF0cZWdGu
         HfmP/bGPUdVN6IsH6QMA4/Uh6AKWUcuJ1xSY8lEf2ONNQU7ZwLxPpZVw1KfRecWMDAjv
         QmJILITd7ZNdwL4M6AZBOJX+HpwTIM+Rs+mkoOFJ1NUbZRQYMx9Mw74iTc9xN7JSWSNs
         Hxog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702572275; x=1703177075;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xkbitQ1maQRTGIDvXyxdRzpeenMPGBstmo0vfSnf6d8=;
        b=mcYXFM7bsjc9neM6m/hmjv80vQL/u9HfIIfUjfJaWfGk1kwHKoEkhUomTKT9RVudS+
         Aq8mk9LNDNimDvXx4i6haU1k8L0qcVdvCYFSSaHww1kkIBT2X/KNIhKTSemxNIHJvWlp
         Dmgxwwjhd3MuJIa4QJEZrfH4GPRp9Cc7WaZRWQL7svMM/YXXDn3LaVBCbrm+StKS7NLs
         KI/uZojjLDnGeJourfDPFVrsqW85CDONXQ/Fg06m2/a2AtJkbbxmjK69HMybRIoFnJx1
         sMD9HqHo/6Ymxv4oi8J3gEJGG4Q3WJ5UmlEXJ29B6k3/EYmTKHlDVtF+hQxkmgM4/OGc
         zyIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YweIKIMMr7F/FI0z6VrmT+dGSLVWcBMIzH22u/LFwPnuzAiSLs0
	KTAMKjsnv4AjnX5f+YlZbdY=
X-Google-Smtp-Source: AGHT+IF42zLNdYvOSN4gQP38vv1D/rpSmqxlKwNxCyAC2oxMMTl74rM6j/5AhpzuXSNMpGYQ1+XATA==
X-Received: by 2002:a17:90a:af98:b0:286:96c0:ba37 with SMTP id w24-20020a17090aaf9800b0028696c0ba37mr3905970pjq.96.1702572275059;
        Thu, 14 Dec 2023 08:44:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9a5:b0:28b:1871:9d6d with SMTP id
 34-20020a17090a09a500b0028b18719d6dls356573pjo.2.-pod-prod-02-us; Thu, 14 Dec
 2023 08:44:34 -0800 (PST)
X-Received: by 2002:a05:6a20:29a5:b0:190:3d8d:a0ba with SMTP id f37-20020a056a2029a500b001903d8da0bamr3962130pzh.18.1702572273984;
        Thu, 14 Dec 2023 08:44:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702572273; cv=none;
        d=google.com; s=arc-20160816;
        b=DliAKkrMPOAO+Cs0+th9Ppp2pOPT0NAkfZfBCzEVxBadBzT+hTh8uQrse68L84M52d
         Y0DMr9+CuU8ayHi0WuUg359Fe6TqGKyfKUyZZYjMP2/fZTk+3JJBUL13fM6JKMZ/VVxw
         9tPsVH00Y2vElfE50optFu9IC2hYQIteTWX31gQCNuUaPnLwOKF2Z2R70JV9TpsPBtyA
         c0pGL8vf/jITpm6mU6yc1l5R3MS6p6zT5QKYOqMIQpBBcSpiN2terXdsUXU7gFa4hRUZ
         qJW5p9w3cSBgwKuXyiseRTsqTyYbpdr0UwqVWY/i49Rl/jVCEEyJ1/aSd6JK/nqHQyKK
         cEBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=w7n7C7cUVujGrFjhyS4KsTPPgLzIdfsh/gqlYQrUTfI=;
        fh=t4pyiPcCBIC9Y+5xkCTP+ifpPVuOKc4r2DwOkdw1hDY=;
        b=Z7uPWwN2XNf/9qdbVXwlBpHL72Sld2ZVV3AMiTtCazBHth2JqdcYinDDQVWPVruOuH
         gx1CV9++nTKw2yY/c4KkcbzVuff8qJw3TqZIKkrzt/7V5//miF9nrpne8fT9X78y7SJ5
         riT2zcUfr0sZ1tY3Znokf+ekjkh4fVuBkwePEgGHSTqEEbjGf/tV3kpX4G5qipeiU01P
         P9cGuFgvHLq8UnsVlm7vTYwcU7iv1V0udD9Jn7xT1iROiMh8HzEARl7F/4REF38ePSdh
         DXJld/OHwlqnnsJ8dOHMv0pMZKUm5RelJks+jqcPR0NHbELIoAJLtwO/s/qdr9pSb0lX
         Z5RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=f6pGycap;
       spf=pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id z8-20020aa78888000000b006ce99cc58afsi964916pfe.3.2023.12.14.08.44.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Dec 2023 08:44:33 -0800 (PST)
Received-SPF: pass (google.com: domain of npache@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mx-ext.redhat.com [66.187.233.73])
 by relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-212-7MArNrfxMKKcVf6uYur6ow-1; Thu,
 14 Dec 2023 11:44:27 -0500
X-MC-Unique: 7MArNrfxMKKcVf6uYur6ow-1
Received: from smtp.corp.redhat.com (int-mx09.intmail.prod.int.rdu2.redhat.com [10.11.54.9])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id 7D7D91C0514E;
	Thu, 14 Dec 2023 16:44:26 +0000 (UTC)
Received: from localhost.localdomain.com (unknown [10.22.33.120])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 28381492BC6;
	Thu, 14 Dec 2023 16:44:25 +0000 (UTC)
From: Nico Pache <npache@redhat.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: akpm@linux-foundation.org,
	vincenzo.frascino@arm.com,
	dvyukov@google.com,
	andreyknvl@gmail.com,
	glider@google.com,
	ryabinin.a.a@gmail.com
Subject: [PATCH v2] kunit: kasan_test: disable fortify string checker on kmalloc_oob_memset
Date: Thu, 14 Dec 2023 09:44:23 -0700
Message-ID: <20231214164423.6202-1-npache@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.11.54.9
X-Original-Sender: npache@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=f6pGycap;
       spf=pass (google.com: domain of npache@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=npache@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
FORTIFY_SOURCE") the kernel is panicing in kmalloc_oob_memset_*.

This is due to the `ptr` not being hidden from the optimizer which would
disable the runtime fortify string checker.

kernel BUG at lib/string_helpers.c:1048!
Call Trace:
[<00000000272502e2>] fortify_panic+0x2a/0x30
([<00000000272502de>] fortify_panic+0x26/0x30)
[<001bffff817045c4>] kmalloc_oob_memset_2+0x22c/0x230 [kasan_test]

Hide the `ptr` variable from the optimizer to fix the kernel panic.
Also define a memset_size variable and hide that as well. This cleans up
the code and follows the same convention as other tests.

Signed-off-by: Nico Pache <npache@redhat.com>
---
 mm/kasan/kasan_test.c | 20 ++++++++++++++++----
 1 file changed, 16 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..34515a106ca5 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -493,14 +493,17 @@ static void kmalloc_oob_memset_2(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t memset_size = 2;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, 2));
+	OPTIMIZER_HIDE_VAR(memset_size);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 1, 0, memset_size));
 	kfree(ptr);
 }
 
@@ -508,14 +511,17 @@ static void kmalloc_oob_memset_4(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t memset_size = 4;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, 4));
+	OPTIMIZER_HIDE_VAR(memset_size);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 3, 0, memset_size));
 	kfree(ptr);
 }
 
@@ -523,14 +529,17 @@ static void kmalloc_oob_memset_8(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t memset_size = 8;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, 8));
+	OPTIMIZER_HIDE_VAR(memset_size);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 7, 0, memset_size));
 	kfree(ptr);
 }
 
@@ -538,14 +547,17 @@ static void kmalloc_oob_memset_16(struct kunit *test)
 {
 	char *ptr;
 	size_t size = 128 - KASAN_GRANULE_SIZE;
+	size_t memset_size = 16;
 
 	KASAN_TEST_NEEDS_CHECKED_MEMINTRINSICS(test);
 
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
+	OPTIMIZER_HIDE_VAR(ptr);
 	OPTIMIZER_HIDE_VAR(size);
-	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, 16));
+	OPTIMIZER_HIDE_VAR(memset_size);
+	KUNIT_EXPECT_KASAN_FAIL(test, memset(ptr + size - 15, 0, memset_size));
 	kfree(ptr);
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231214164423.6202-1-npache%40redhat.com.
