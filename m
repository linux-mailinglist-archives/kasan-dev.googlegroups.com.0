Return-Path: <kasan-dev+bncBCMPTDOCVYOBBSOYWW4AMGQECLCFA4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5D399D704
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 21:08:59 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-6e3245ed6b8sf66706187b3.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 12:08:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728932938; cv=pass;
        d=google.com; s=arc-20240605;
        b=T0OuIMoT90w5nQxv+1vVUHjwgt0LyFXvxIfm5t6smApBKyNsr/gixoRN5rTD38jHFq
         mucxZY1+9KqtJIioXIYadHo0BUgp6J6b8XVrvcChn1ysmuB958FtYp8NoHTGu5D1MBiI
         UXHVQ+SO6Vdo+e34rjHh7dVItyvYjU0oi+PZiKOkDWk4hy3tJkJt7MI0E013KlN4A4tP
         ayJhHPlbyAQhJLPZljdPFpMehDX8vQdjbenI8VZnaIw2A/vcwatr1xz0omY4RNzmiC9p
         yEZupH8S9ISgr+L91v30LelPytYMSnyAy7bTWnooNAjGy6rEdqtikmBY6OuPjEqCb1yS
         MqHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=flbIyS5HxzXyPO0ab4wxL/nSKSe+JrVs8lrVy4ZiALo=;
        fh=67BCyYGbXgsdXpL1T102LbzWndBNQ/ctLMwrip/5gss=;
        b=OypOlaTtHEp4UGiY3MhQTtHbrqP8+KhFFgK0MCrHCKo4WrWda1Mz3jBP+eEgVKd9YC
         kzryhIkIeB/o1IPby4N2NzFukA2zP7ufxXoWIX8kwHdt3kLkeTYhnONAoVKoNVPs6/l+
         dON7FoIW4uFU/lMSgkxmjR12FpL5jIo81hhYgzKiUulKPdBYxcZqr3oZDX5u77+75oR/
         +FLcR6q8R72WkjenxY6Msns+V7KLTJ8/6P69uwIlwMS+8tnN688Tva+++550+Ix5h0j1
         aJ8PlPL86tPdpX0YUztvTZv4k/EGujOaEX5iXYUHDvOte0DetEw60mwoy97sbJGmIs5c
         Uu9w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTnaOL0e;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728932938; x=1729537738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=flbIyS5HxzXyPO0ab4wxL/nSKSe+JrVs8lrVy4ZiALo=;
        b=XbTV2XpEne4vrUhA5KZTgpD5dR5jar2vA9CGfwRDNbE0Hdkp30HuQOLAGIgm2y8cAc
         xmSEl1pR1PXfPO9E2xbbgz0aqQEEXdiHQhGspJwoJsN0zBGxKExjgzqcwzvXiFgZFA09
         dV2Hbs2sW0gUbIQ+/ujFGgJ7J0Mjd+cSrhM2O3iNN7PM8xDSg1MC/RB2KWQvAaxr9ij2
         zNio6suiqVm8bgz7kYIt93EJpAyv7bffIWMYO2L0tBYUreRF72RscRo7nhX6j1dL7ZDJ
         vs08IEftpXi4Swm3tDCDerFFJN/9yrL2Cd1OWW1EaUt4cUWNRzUL5LrZsWbZZoXZ6iHO
         z0XA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728932938; x=1729537738; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=flbIyS5HxzXyPO0ab4wxL/nSKSe+JrVs8lrVy4ZiALo=;
        b=iTLPdGMvdMPuam0OqG4j36uZdnb2GOAvTCum0vOtSw50nJHZDQoM5+qpydaZHMXxMa
         rPfeOhUp7fz4B/415FAtLlYrh3wh/YFdU4AjLUStPV5MOOfOGI5VJCNi+vRc8d/f/ZGm
         gC/M+/c5hq4K7Vkfc44jYYwXm7tT9zuoksAWoWLsAtd1VcM+JjHZdVR4KCSW34T+8Zxj
         i7Vb/mlqRIH4LqgOpNeYU5IGfwMrjdJSuRDXNG9aYLyBsrMQp1B69FQKNHh3HoChLjhQ
         dl1NmjVeKJSoIbkCZK+fFIJ161hRgY7J9rt8hj+adcQ0b7qBddrIpqN6/WZTeNxwYGBC
         joyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728932938; x=1729537738;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=flbIyS5HxzXyPO0ab4wxL/nSKSe+JrVs8lrVy4ZiALo=;
        b=JxPrdOgex2t7AziKSRGFXZWpCmvHp7WGGpH2wIjGEb5AMOQBr6IolnlYvRquKY0XNS
         71wa7vInrk7jA2v7Bdmyu6RQbUrogM1Aqpf9Mjepr5DT5kVm00IBte0eJJ/VvjziUPCd
         8X0qbOYJQvrXbXYm5qQLZKjcWfNuA9O8fV/6Z/nTmStSUWxKBDD/agZtWQo7EyKbzd2b
         0V8vxr/4OCY8jgr9qMEC8az3sA97R22FHTuD5/qAE+rF/HktO6cZVQXb0tknunfzWu37
         nt86D1l3tSohUUaCUNcSOs2sKd+2ysYzPU1dfJzMq8viqxakMqUhi1JCaD/nBkTB5PRd
         ULlw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkDbpO7zxy1YeQbKgUDOvo1dbsqw8pwxTiWG7NRPlEIOhHRWe/naVh8/0mISNuU+uwaEF2Mw==@lfdr.de
X-Gm-Message-State: AOJu0YzH9f1iJ3Lrx6nqPW4HXk9mGqjQJmMDFf/wuzELmzSWlmaBP/xU
	rtDuTnaDFWbB42cbedoxxlFKBPQZ7BJkS4WLmWBFu0S63BCaYpV6
X-Google-Smtp-Source: AGHT+IEUpTk/zO4A69PZhPfhGkMPyKGEVCMH1TOlDqF6fe8fM32BVI5B0898xYdQ3I6MraE4jojhSg==
X-Received: by 2002:a05:6902:250c:b0:e29:2465:f23a with SMTP id 3f1490d57ef6-e2931b007d0mr6388647276.6.1728932937804;
        Mon, 14 Oct 2024 12:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1003:b0:e28:67be:7472 with SMTP id
 3f1490d57ef6-e290bb88fe7ls1528944276.1.-pod-prod-05-us; Mon, 14 Oct 2024
 12:08:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDsO+/PQ95V2KRs5rolIqfka5StZdsnPMxS0fKWjZn59M8kqkuR2TOkKkDWcDI77OGscqPLVURyG4=@googlegroups.com
X-Received: by 2002:a05:6902:f81:b0:e1d:2639:66be with SMTP id 3f1490d57ef6-e2931bd76f1mr6664561276.43.1728932937017;
        Mon, 14 Oct 2024 12:08:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728932936; cv=none;
        d=google.com; s=arc-20240605;
        b=H8xz8P4w+bwlFDGm1kr8n0Aq2mfvMWYOD+OiZoLxshYkh9DbXlfde5bYKJrJHhyqWw
         dYPJ7yzDNCKsD46ZzY/jpzCHNOyb3aB1+KYaadvRCkYRzVTv6blTP7v96PuIy1+Khfny
         M9HmfAUGwKfgY+HKAjkuLPLhRQRQz72/+lA6H/P1GUNSsYtcIk3gZjKYx7Gvh0IPNZF1
         gg3XM8O/J0HBppMxdApQnbfDnT62LLEufLgHzPxjglfK5SbZm5r1Pc+sQsrsia7D7Uwe
         zbwkaQxVlKC+OUtz8ANQ467AgchncJfL3nIuO2Q3W5a9FH4zk/Acl6E47XkBfcAlm5TS
         0Ldg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=GwggpQA75Ji4L7zAdfPb87y+vAtwZU5Fx5cuVPrXzvI=;
        fh=W2bAJl3AyQvFaWscM6HvXQRdg56itzLwu/ek5Ad5x9Q=;
        b=BcofsqxR7WpAbr4Yk7OnrX5kZp8jGc6eHSKQW8EloSlwZKtx3r00+yKZRiOqizlEos
         jrseHczu7k5p2X22mbxsQemGkKPq1R9Lz1RD+KPdX9np1LVOYurjCWvKwav1ecAfuvlb
         vk8x6QFQFGlyIYlWdItFwYtiIpt+OxzpgS93FnsYeQrgEhVpKkKFlpyMGuBBCeNHiS5r
         dcIG62OjN5XzPemnmYm4pHh8c4o2UgqpQG959pb/G849rz3fSIBFzXo5P/RFtMTz364r
         U23KDPJzOP3szUIXOrGgPWGT3iJ8j7t0UXWb3cej7iUs3pLu9EjpYzrBjhOpRWlk0vDd
         Q4RA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aTnaOL0e;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e290ede9769si554412276.1.2024.10.14.12.08.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 12:08:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-7c3d8105646so341015a12.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 12:08:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWYpiUtv9UhScw9Tap4I+1YOoCF01vw2pebJq/toKL5xfoDUNwRXxXVQKmNGpVqqYUllcqqDvcsB3g=@googlegroups.com
X-Received: by 2002:a05:6a21:9998:b0:1cf:5471:bbe1 with SMTP id adf61e73a8af0-1d8bd017b40mr8872998637.8.1728932935999;
        Mon, 14 Oct 2024 12:08:55 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-7ea775bf3easm2895833a12.94.2024.10.14.12.08.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 12:08:55 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH v3] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
Date: Tue, 15 Oct 2024 00:31:30 +0530
Message-Id: <20241014190128.442059-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aTnaOL0e;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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
v1->v2: Simplified the three separate out-of-bounds tests to a single
test for kmalloc_track_caller.

v2->v3: Used the same size for both the test cases.

Link to v1: https://lore.kernel.org/all/20241013172912.1047136-1-niharchaithanya@gmail.com/
Link to v2: https://lore.kernel.org/all/20241014041130.1768674-1-niharchaithanya@gmail.com/

 mm/kasan/kasan_test_c.c | 31 +++++++++++++++++++++++++++++++
 1 file changed, 31 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..7e7076e71de0 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -213,6 +213,36 @@ static void kmalloc_node_oob_right(struct kunit *test)
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
@@ -1958,6 +1988,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014190128.442059-1-niharchaithanya%40gmail.com.
