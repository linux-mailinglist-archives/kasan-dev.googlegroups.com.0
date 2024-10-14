Return-Path: <kasan-dev+bncBCMPTDOCVYOBB555WK4AMGQEXLSAMEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB98499BF2B
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 06:32:56 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4601a473e90sf58224031cf.2
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 21:32:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728880375; cv=pass;
        d=google.com; s=arc-20240605;
        b=LT4ljFUgrmDKXcLGfV57cVhFxWozyTzDDJMO4XkvpETiNZgZhOk/OfKZhpYd5k7NtS
         sjW27Z7PRrVleuoAjwks3RbAaR/RTgGU2t6ZYqjJjzelIDoNjS0WsduDSI1AVXuDjiE9
         TCSWqGe9tiwrMZg9Oz2301J9BQz+f6prMCG8wSbXCCeQj3IRMloNJhtC1XCQqpU8QY5t
         QdPsWNL56SfKLjm85joKg0ASAWr94fbWb0yuC9LVDkxOgMrj4EifzaKjlKxzd3a61wrr
         Zf7fAkDAYPJIIzmuabmddE/pfKh+uj6kRgUjOUBYVzJ1LvJUJXHb6NXyFZyxRj1LVE90
         bIyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=nLBFFDmd/eDb/Q3OefSmXpxkPFqdM1D0bI3Bp+5ZZ0M=;
        fh=/TMHbBDSPJjoca77OxtAnCM7u5RWH9iH+IH7nbdRdCE=;
        b=VTgG6J0jc4k31WfJcLVweaLis9WmPKgmZrBiRhGGeg5KRfwzjvbSE1/m+MU+zKeJYz
         OMi+yJE9/To/71bTKSj63YeJ/d3DGBJbV/WftuiFAZUolV4EBCP8QGUuXvP4gFghEBT0
         /cXMQropC4VosOJd2KSf0c4QDaIKOtOckBKoZq39ZdWu4HlATvYUoeTlGfq2UINhrQl+
         lqKbkpfo0uvJlQg3HPpTda1FetsEhuGQbsI8D3fo/ixBq38lQLc1FfsRU27INX8DNj+9
         DKRMQtKAgGXIQV1aPnsHqmvmoO0KyCMLydkmuAfLgbP+wXNQG+QmrfkeXw0ldL/k/AIe
         ukYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UPpJtTuc;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728880375; x=1729485175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nLBFFDmd/eDb/Q3OefSmXpxkPFqdM1D0bI3Bp+5ZZ0M=;
        b=ZvXBMzYk5YwP7HGOUVJ8T5DDGw2jTYTLsMEx06ACRqw+XKuU8htFoKzDMkJhcbYBKo
         rpYteDU1l8vZTo3OgPJCi2KZSKGuNCl9xGvkpdO8T/cALfh6wpw7ttgaPduj2NBo5S9j
         pMjhALYU+TkK1VEZS45BfSH5bqfu38mvwb4CZvFuLvaD/v7T0vIsF1lBzDoXAG9ifRFt
         mLxDgZrf8+68AdQiiIOwgArO/nYV3NRlcS6lPU14d02KGGsI7+E0sK8jxSo4ty/RMaY6
         aJReDguY0ZYDal70HKSrEGprJF+hYOkN5RROpvc9i/hBwa+ra+kVhfcSmzbvL1A2Bn78
         RzdQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728880375; x=1729485175; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nLBFFDmd/eDb/Q3OefSmXpxkPFqdM1D0bI3Bp+5ZZ0M=;
        b=G6NlMG9dcy+R+dmrk7KqDKhsSoDGFAGVsiwO+iXBo9UaD+bdrTMQv5+17OT//EAj/m
         s3N1ZwsDOr2tsm8jfACbZ1AQwBqtzH3odpfSy6Lv7iIFo63tkkIvBydjFT9vVwOYq/LX
         /y4wt+9nGzwHfqPJgpQRA/QZTmvdWBK2ecOnqlufKHfX0XtA3bCwoywD2tfDY5T+uoob
         ES1cHt6bfJkT8q0XSOW0hr52BFY2AC1WfHkLGpqT8ML2An9ATqjhRaKqLdj8w5xdEAP8
         ZdwMTP5hE1cbv+Z5EgaL33XYjWB3GBSGSr0jFeKEUHOohGeurBsn2gM3Gi6t25yUHpD6
         /VWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728880375; x=1729485175;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nLBFFDmd/eDb/Q3OefSmXpxkPFqdM1D0bI3Bp+5ZZ0M=;
        b=pUWBBumwW3UXAC0eA56pCHig4OlIlv3xS8PZWZqhZvnBEvrOuHRih7mMC2nzlivytX
         ynXIUkv6jJMIruRHPu3kekdC49F6vviH5Ryy17Faw4u+GJfFxppKTmBGly7+7pKmfBiS
         w43CA56Q56s6GvaIC+lSQwdhQDCXqP5OrLxcW70M/b7pSZjrk7hByJhpTN6PdoJUSRpS
         dB2DgeD6kMIx76kFi3wj8NE/L0FAZL+NNM4Etv/XK5j17YKOXDXnYnqHK/efZkQQj8hD
         Xs4AOuxPnujEQCf3W0OX5096fbcKdk6y4By4VW4fVh923eeGP7fJaZbXgOa169oQaLt/
         Ikiw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUOSH4+wDJ01XySkhVrQHpkKcGV3UuuNzEXLxiKabdH0Jxa0Hi1Q9TS/DQuIKk51PSUU4zn+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzXRwDawCsjMeuTBrW2TyBQz4ESu1LAVedwT7AgyneVGe1yNpKj
	xuqNE+XGAFVTK45l/asHfM3q1YgBAwzr9Dzi23CpmvUjPeb/OCE5
X-Google-Smtp-Source: AGHT+IFU1/qzS3izyztHTdzKGIjp1EjsnbWirbXSC3dWRAyKBpyiwB/paM5l6Co5XNiKAI5Hl2V2BA==
X-Received: by 2002:a05:622a:13ce:b0:456:89a6:ec00 with SMTP id d75a77b69052e-4604bc39217mr171428731cf.39.1728880375200;
        Sun, 13 Oct 2024 21:32:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5e4b:0:b0:446:4642:4f5e with SMTP id d75a77b69052e-4603fd7199dls69774371cf.2.-pod-prod-08-us;
 Sun, 13 Oct 2024 21:32:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHKxZtjg2B7vE7aOAQzKzPstmD8PwMcig0LVhCCB2Ppt5knrmby3NfB4gYsK0N7AajGCtuKEmRI3A=@googlegroups.com
X-Received: by 2002:a05:620a:3f85:b0:7a9:bd5b:eb61 with SMTP id af79cd13be357-7b11a36c6ccmr1726441385a.27.1728880374487;
        Sun, 13 Oct 2024 21:32:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728880374; cv=none;
        d=google.com; s=arc-20240605;
        b=GzDt+WaHpxsBgMmHgnvo43iKsYMuW+8xRXOncCo753GckIQkzL9QurMZ3uqvy4hSnc
         HxOrBLuGOh6L1GiufSyr33rFNWTqmOH3vDv367wWeM+b0B1FBBIQQ+1xYyoPRUqmBwMk
         3EGNwacNnAL5LlCgrU3oZbB76xSbL0rjMDKH6I2BCW/q01nRW+vXMl3kPbp9bxL7veg6
         n9ENcJW43VbNamL0pKPALenobm/hN2Bk5FtnOBOOn52j6EHZsHM+FQWM238XteuVt78a
         73krBBbz+qUorTsTw3exdKFFH5uA3VtdnNsDZHJtEZvfNDFPTYCgLztlo/LDcLACpydj
         n49Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=3pUgdOnTMHFVpme+dAscM8QajZI3+HzzTGGVOmH4CSw=;
        fh=JYXlu84YHGoHKe4sD7YOSeG+dCbS6jgaPQzdgvaVfAQ=;
        b=DJ1aFbaXOXD0Ijo28My825q5YH11yy2IDVtAFO53o2eAHKgsHxeO3BD69ME5Lnx3JW
         HNIyeOerhox06EMejhZ1zaMWhNe/htBeWD7GAXOLrzCfc2wbyLxSODUjctE4LTKYPtnI
         /IK7TLCahGwpC2TQ12amWP/y7QnN3SIp1TNsD+IeGRb0X4lZgI46PcN0/PN61woWojS3
         0tcyW/nKYhnonW46mDcC8I6pjpa5pnc7uYQ5e1ZwJCs48o3fl/2ALuwHA83hws84KtNy
         ltyFKzEsHPJhQpOPq8pF7UVF/6MQck61ysq2DHocHUHiHhVfmmRQuPls4n3MemwKLiJ3
         j5tw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UPpJtTuc;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7b1148e493csi33036185a.1.2024.10.13.21.32.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 21:32:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id 98e67ed59e1d1-2e2d83f15f3so711282a91.0
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 21:32:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVcmS7SC3tPliSmxy8WvJ+/dtq3dyJh5wH9lnAD2cP7LBegSdHcE0vJ01fYIfkfIJPpuFJjQApAPDo=@googlegroups.com
X-Received: by 2002:a17:90a:c7c4:b0:2e2:a60f:289e with SMTP id 98e67ed59e1d1-2e2f0811b98mr5091735a91.0.1728880373672;
        Sun, 13 Oct 2024 21:32:53 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id 98e67ed59e1d1-2e2d5eeb082sm7700190a91.21.2024.10.13.21.32.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 21:32:53 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH v2] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
Date: Mon, 14 Oct 2024 09:41:36 +0530
Message-Id: <20241014041130.1768674-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UPpJtTuc;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

The Kunit tests for kmalloc_track_caller and kmalloc_node_track_caller
were missing in kasan_test_c.c, which check that these functions poison
the memory properly.

Add a Kunit test:
-> kmalloc_tracker_caller_oob_right(): This includes out-of-bounds
   access test for kmalloc_track_caller and kmalloc_node_track_caller.

Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=216509
---
v1->v2: Simplified the three separate out-of-bounds tests to a single test for
kmalloc_track_caller.

Link to v1: https://lore.kernel.org/all/20241013172912.1047136-1-niharchaithanya@gmail.com/

 mm/kasan/kasan_test_c.c | 32 ++++++++++++++++++++++++++++++++
 1 file changed, 32 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..62efc1ee9612 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -213,6 +213,37 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
+static void kmalloc_track_caller_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
+
+	/*
+	 * Check that KASAN detects out-of-bounds access for object allocated via
+	 * kmalloc_track_caller().
+	 */
+	ptr = kmalloc_track_caller(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'y');
+
+	kfree(ptr);
+
+	/*
+	 * Check that KASAN detects out-of-bounds access for object allocated via
+	 * kmalloc_node_track_caller().
+	 */
+	size = 4096;
+	ptr = kmalloc_node_track_caller(size, GFP_KERNEL, 0);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'y');
+
+	kfree(ptr);
+}
+
 /*
  * Check that KASAN detects an out-of-bounds access for a big object allocated
  * via kmalloc(). But not as big as to trigger the page_alloc fallback.
@@ -1958,6 +1989,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
 	KUNIT_CASE(kmalloc_oob_right),
 	KUNIT_CASE(kmalloc_oob_left),
 	KUNIT_CASE(kmalloc_node_oob_right),
+	KUNIT_CASE(kmalloc_track_caller_oob_right),
 	KUNIT_CASE(kmalloc_big_oob_right),
 	KUNIT_CASE(kmalloc_large_oob_right),
 	KUNIT_CASE(kmalloc_large_uaf),
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014041130.1768674-1-niharchaithanya%40gmail.com.
