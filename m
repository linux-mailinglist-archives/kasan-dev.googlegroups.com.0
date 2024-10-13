Return-Path: <kasan-dev+bncBCMPTDOCVYOBBHMIWC4AMGQEXAPTJHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D8A599BA8D
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 19:32:15 +0200 (CEST)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-6e38fabff35sf6021697b3.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 10:32:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728840734; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vl5pXRS2reyNdywyCGpTWMqGKV3pWnplk3QMquEytYLgLha+56Atwvn5OmrYPTw6AN
         rZGYO7d4B0k90pjcm5mUvLTriPWQZ7niYtyzyzCsLo/LQHUfVmlF0S9vCpFJyFsDZUlp
         kV7FHaTv4OnS/fn5xJwR7VfwONMpy6rf9zlsMlItrSIIS0lzAUzKxALKvVNddpb8NiSM
         /N2t3dJXWjjpD4PPcKa2WiVEHwantGqizLZDtEzCil3bYq55SByfmJbsCVE5WoJCiNdU
         hqczRp9E5y2rb80nwVucTYUn+p7X0Pbp4KdNwxtt8Cn+S8OX2asC1VPxAfCIYWWIY4x8
         7zaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=5UYY8HbWlGvRwvxilpcP7baJC/oGEwJdmvkQQXpO/jA=;
        fh=euSm+6S4YNnfYf2Xvjuz0zOPb4ORnH0hdT8u+dZyD6g=;
        b=HePnxqWQnHkBKAYmhkTSIpRV9f7K2iiM2TNaHBsBvl/AgX9gVPvRpTF9C314IIVuTf
         0MFzvo8WigXUT30kIUN41lYWW4GLD814iQFWh/FboPlnKKa5pA84+x6M3l3G5ZphxgDP
         oyk8OOBUpSfpNs56RMqqEFNamU2plyaZcdyR0aNd9QEHO7NsWX5aBoK9YD92fPB6Q5FG
         F0e4FER8cDXorHLngL9oDu8qrdYAq7mvcAH8orbNJG9qMfUnVCbD3/NkimxxgvPqtgBt
         SVX3Bs1go8o89cHn8UU2YYFNYGPS+loQB46jlswKS//U28pabwsViBG126cgCjgVlfnf
         mYDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EAMjQOxa;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728840734; x=1729445534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5UYY8HbWlGvRwvxilpcP7baJC/oGEwJdmvkQQXpO/jA=;
        b=KSBqsgpbhuv9kfGnyR/BRo60kfI9oPkBQCwU2D3oO3WASa48mEGyrJDfKoQ+iza9gF
         98tAl4wTNvrTe0YMBymCZupN0XZwvMRyABGDFSI2vYGqRkBJ0MICyKQZ3W89TsKa+iA6
         dH1aX70HLCMajx+eFAV+JgQdJbvp3hzN4GJAmoMDZPimtdpOLH92UUSLojekZE2aFloZ
         CpMgqE53ykgPXdIOK7teW2Bdnko7mpqMZ8gDuRqkeVEMOq12tRE7ZputFXs547iORlVh
         AUc+KG6uUz44HxU+4cEgA1nP6AhSzMmYqkC7K5EF1plbUqNVpUbSsRfgjbWlRg17d45G
         dMjw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728840734; x=1729445534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5UYY8HbWlGvRwvxilpcP7baJC/oGEwJdmvkQQXpO/jA=;
        b=DmK9hNHzwysYYZSJDuxdfKZmwSLSBwExmqEZmgn3yOOE+ohxg6pnGYy30TUT9xBePe
         4JOPACemB/riou+pRHh8IM/EXTI0FDuDSen1GKBDylPKqT/j52LgNMU+FizE/VJslO5L
         gOENTGiYE6K/CM5VHcMwhrUK+7qFQ74tEGrjmBQ+mBaFyUakcl1S8uRgEYD8ttb1J+nq
         5uM4HwN7C4ibdg0BNnEou7P8cgI/gJ4+l+ugM8JeHb+G6SQOH6X0IP+B2pmhzUTA6aCs
         /9SZa2+Mn5OVLSGz7snlMudNZfJiDuEjw/TNdxfRdQBsfIGztQYyoalzHzOXOG64m2TB
         CGJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728840734; x=1729445534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5UYY8HbWlGvRwvxilpcP7baJC/oGEwJdmvkQQXpO/jA=;
        b=LIQcxJoi7JcRiv4M/8XfaCuwZOqsz1qM2OG6Rf0ENPihKPm3qsmM4pdwUEXQWTYhXl
         +exu68IavkXyE4w9sI309HriL0TwJSKLv4t+JBfb53UFOyazzy0a0NxnXMtgq1NtY0sS
         lAFpfNxrzBYIA5LSKOkR1rWI4goN6LhYeMIoSp3vklMgWZVv6VndaCXxcyo1oHzEP/5o
         wJ6LwrYvq2sSngQX6elqfJnRQY0Qjh7ZdfA7/8Haxn7NiuMyLUnUigqzyVMsDm9EZC4K
         lZ5RvbdtdMKZe9TfCE0rey1YEE4fvH6R1t9DH+x2fIcEVoZN3JZxH9n/mfAW6zWIbHJv
         rtHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfOTYpKXanLAr1vAqK+NXfF+F7TdJNQiVLQBxVjEq1VETX3ECOCneuAdmmCO2oYEKiVauEMg==@lfdr.de
X-Gm-Message-State: AOJu0YzaYpprpaHi7bGI1u/bYSel7peib475cD1BvGGM3LSZ9v8vrs1Q
	r8hXg0GiHsypv78folZnQbLZbNBVFMaZwzlLKGr7xBRNPhrLnJ9j
X-Google-Smtp-Source: AGHT+IEmwUrYHtSAo9o7tYZoMIk8z3ShK2HYDP8gQhwq3CsgRm7J2ZmkWjvXj2dnbBx5zP+zEaeBgg==
X-Received: by 2002:a05:6902:2789:b0:e28:fd73:4d3f with SMTP id 3f1490d57ef6-e2919d81a52mr7338611276.14.1728840733809;
        Sun, 13 Oct 2024 10:32:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:942:0:b0:e29:1ffa:37db with SMTP id 3f1490d57ef6-e291ffa3a4bls654951276.0.-pod-prod-09-us;
 Sun, 13 Oct 2024 10:32:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgcVdRFfNxFVTTHFZrtzRrdSax87dOQC93H2hkjIxwn3OXnaj53p1weUcgH+EU0yNIquAVQ+CoM1g=@googlegroups.com
X-Received: by 2002:a05:6902:2804:b0:e29:236:fe46 with SMTP id 3f1490d57ef6-e2919da10f3mr6227035276.26.1728840733039;
        Sun, 13 Oct 2024 10:32:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728840733; cv=none;
        d=google.com; s=arc-20240605;
        b=bIf4HcOtc4EfvuyYjEypb6is1TFTJQZT3wcC5NGpqC6uoIVM8VElQxKuFR8zryTlXi
         Dtv59p/wtADF3gigIwbUgP6xUwzumu1XzkFAu+HNHLeRXrDGkP8R5OWgLNvprm+I/1ko
         Sqy+RJLxdU/tGs0IkmJKlawkCFWK0Q0lHrGlBTBldW/BHG0IS+8Vxqtlbnm7x5ZIG5IB
         L8Nr/WtAKfVDJ/vyapopPwuQY7mml/EYvSMFsJa6vBS3EGsjNzMM5DwDQ/T8Il/YjQOR
         E0mYOQOyRNUaF+Yrvpx4/76dKfyU+XA7NMj0/uTOgpHmIjWdvDqhWh8Nruve326dOl+M
         eeUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=wxwHOtTydZ5pI077ASwiQ1w7C2c7W/JrF5E7on+jchM=;
        fh=nxwnAYzO30O2DN6xiQEWMZe+nndtUNGyPLTen+rClYE=;
        b=jLdL2zKq0Pka0vCqbdvTz2K9EB/ben+S8xhaY56XxHSbyB4tEluud5tdlnZ14vB4H9
         g29UhE6q8KaQ0K4sIyCzekVXygJrt4MYy8HC6mSTrbquMSKZor56BYnfWNk52h2dendA
         XvDI76RpAUQJ0B9ms6bNxzPkLVXVg2a1jaDrtTWMPMKNjneVQEvcqK3AsQQXIxsSiTGk
         ZVvAGkVSFdkdFs4Yy7f46UVmFdkFsadwafYTMPZnF2TzlVGUk28xnsu6ZXMp948JRP06
         ZBwnF1ZqCu+tVLADIlYaK6tYhjhuUl2F25tKMuWjs1VQUPlSJbK2viFLjHqVWLw/NbGx
         Creg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EAMjQOxa;
       spf=pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e290ede9769si434169276.1.2024.10.13.10.32.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 13 Oct 2024 10:32:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of niharchaithanya@gmail.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2e2af4dca5cso708475a91.3
        for <kasan-dev@googlegroups.com>; Sun, 13 Oct 2024 10:32:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXiKmGkOVIaJFyFsBpTon8mcytSUNhUtiERrSdoHB+QbBzE6NAR/kWW5Ekj+GexUU0qck1ojIeKpbY=@googlegroups.com
X-Received: by 2002:a05:6a20:3d89:b0:1cf:4845:67f with SMTP id adf61e73a8af0-1d8bd014f12mr6349940637.9.1728840732003;
        Sun, 13 Oct 2024 10:32:12 -0700 (PDT)
Received: from ice.. ([171.76.87.218])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-7ea6bc08282sm2240999a12.49.2024.10.13.10.32.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 13 Oct 2024 10:32:11 -0700 (PDT)
From: Nihar Chaithanya <niharchaithanya@gmail.com>
To: ryabinin.a.a@gmail.com
Cc: andreyknvl@gmail.com,
	dvyukov@google.com,
	skhan@linuxfoundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Nihar Chaithanya <niharchaithanya@gmail.com>
Subject: [PATCH] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
Date: Sun, 13 Oct 2024 22:59:13 +0530
Message-Id: <20241013172912.1047136-1-niharchaithanya@gmail.com>
X-Mailer: git-send-email 2.34.1
MIME-Version: 1.0
X-Original-Sender: niharchaithanya@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EAMjQOxa;       spf=pass
 (google.com: domain of niharchaithanya@gmail.com designates
 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=niharchaithanya@gmail.com;
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
are missing in kasan_test_c.c, which check that these functions poison
the memory properly.

Add a Kunit test:
-> kmalloc_tracker_caller_oob_right(): This includes unaligned, aligned and
   beyond-aligned out-of-bounds access test for kmalloc_track_caller and
   out-of-bounds access test for kmalloc_node_track_caller.

Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
---
 mm/kasan/kasan_test_c.c | 34 ++++++++++++++++++++++++++++++++++
 1 file changed, 34 insertions(+)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index a181e4780d9d..b418bdff5bdb 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -213,6 +213,39 @@ static void kmalloc_node_oob_right(struct kunit *test)
 	kfree(ptr);
 }
 
+static void kmalloc_track_caller_oob_right(struct kunit *test)
+{
+	char *ptr;
+	size_t size = 128 - KASAN_GRANULE_SIZE - 5;
+
+	/*
+	 * Check that KASAN detects out-of-bounds access for object allocated via
+	 * kmalloc_track_caller().
+	 */
+	ptr = kmalloc_track_caller(size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
+
+	OPTIMIZER_HIDE_VAR(ptr);
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] = 'x');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[size + 5] = 'y');
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] =
+					ptr[size + KASAN_GRANULE_SIZE + 5]);
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
+	KUNIT_EXPECT_KASAN_FAIL(test, ptr[0] = ptr[size]);
+	kfree(ptr);
+}
+
 /*
  * Check that KASAN detects an out-of-bounds access for a big object allocated
  * via kmalloc(). But not as big as to trigger the page_alloc fallback.
@@ -1958,6 +1991,7 @@ static struct kunit_case kasan_kunit_test_cases[] = {
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241013172912.1047136-1-niharchaithanya%40gmail.com.
