Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWV2QKAAMGQEWJXV6PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id AF95F2F6B20
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:59 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id b123sf2901034ybh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653018; cv=pass;
        d=google.com; s=arc-20160816;
        b=yVoMpS2gNJHdBcYkSVT25i7yUdsnpzGGZkuYS+bUtIHW97S5ykMojkOw+MlAmeAO8O
         SV96EfyshNnRNGlQtX4qEJeGDF9u0JNs1RU0MkKc9ttox8Sb3gWSEb/qOR7NAL7Uj0zy
         ozswjDqUwmzZi/le9b6UQ/9ol9fvfNm99tUwNrZUn/2jm1MWgEqfvEtV6ldVLfrbsn1U
         jPxZO0TWsXyAIy/8UbAdwnWPwQoZyxkgaD03k6Tz+7010oWk5GFJXOWCZM+BX6Y0Ywo8
         F+Vykp1iFujsvvItWA6utdf5mB9FbvfsQ5S5W5XuS5Moo0Np85O45bqnNCD/lpS0T19p
         7BKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pv48xXeBffSCm9hTudNPiPXcZiO1dBiIRKngL3Is4wg=;
        b=IQ79pQy5yqLk1hdcVnET9aMjh47omERAQcxlNmzc1LX5LEPUQRnE3uiXIaqMUgck/0
         HUoFC04WEQi07xkUEsmT/dR8z/a5C1CKpkDVruM6y5jyAI3LPuHSUp/WQ6goHZjRwsdS
         hAnaSikaccpdnKayyLEJytTGhtfTbwsNo5ikxJA6LPuREGjecGlmPPcY0VGF9j9uJKe7
         KJwVrBtxdecLq0bxY9EAAIosc/W3VmR45pwLCIH9x9MWiYEb72uKDE7v0i1m4AgGL5RQ
         TCR5VLO8KIi4fH0XtRq7TZzzKwFnA4fpOt9HpaeTunqrj4ldhnU02CCl1ICECFgwsou1
         FvwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=svvurHrH;
       spf=pass (google.com: domain of 3wz0ayaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WZ0AYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pv48xXeBffSCm9hTudNPiPXcZiO1dBiIRKngL3Is4wg=;
        b=SV5GyOoLwMt73D55M4XyeXrOlEDpH5rZg8/gXr8up+yR+qXs5uceNOCgGaBbi5jv92
         rW5GD2TmS8T4xhYilS+rXgAwn5dESqBuFIjDFqShMSwU1CV2R3YKr+LDBORiKNIGsYYm
         EnrfI9SMPNNgS/7aeNo57oIpQkkiHNapr7cza9Don1NVdPlXSRPhX5tk5UI/qL1OZNxK
         b8thBlMuMJfyfKuPcbxXPuTrhkqW//uC+OLILCKyLYbcCOKmTgIVrlUnC/+wMkZFs18S
         fWNoJZx0PKbekhut/Z4wYqJzwmxus+UE+9cNVwp+ig/L1eIUwKCmlQ76f1UqwT6DYH+B
         f64A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pv48xXeBffSCm9hTudNPiPXcZiO1dBiIRKngL3Is4wg=;
        b=pAQygH+4fgXXfbn2SN8KmXKGPbR04SfRJ1QiMmoXHKd75pWRzQEQ8TDKCFTZRm1zUS
         0ry09YMVjNaD9OXyVNH8bccdfLcUYPlKW5QYr4xt9ewJej9ffa/sempY6gx8cfIMkxuQ
         j4646jp2wy+6OYiNF/KwSSqg3FiUsoE2MmxGoN6SEH7XrP5q5IKrDOU5rUZwNs5Ktzjk
         M3Vmd+0sbzlnK+vy8MMX0Ews6KIkTDMUKalKwzpqo/r2u0SXp8lAC2TE/fsp7UW0sQ35
         q3neiUPM2s6XuoKdHnzr3VzPh0lUX0u9d7xP8V1uPR2+viD2gpvGyyglQi75TqIyNAnY
         LyYw==
X-Gm-Message-State: AOAM532EZpwDaqJvMIJn60yv1si/8l/SQL3G1ueUlQLd35pIhzQPl3IG
	ozJKMgNDAwaooS/dNyJl5Qc=
X-Google-Smtp-Source: ABdhPJzYHvLpSe2VL4IfPzNVxZlMAvNlLDog3sxX5KMBI0bTM0xKdm5kmoDM3U7oa/mGDOzZZF8zrA==
X-Received: by 2002:a25:488a:: with SMTP id v132mr5603905yba.28.1610653018750;
        Thu, 14 Jan 2021 11:36:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c594:: with SMTP id v142ls3210048ybe.9.gmail; Thu, 14
 Jan 2021 11:36:58 -0800 (PST)
X-Received: by 2002:a25:5f49:: with SMTP id h9mr12759250ybm.99.1610653018287;
        Thu, 14 Jan 2021 11:36:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653018; cv=none;
        d=google.com; s=arc-20160816;
        b=iE8VjULuB7mN5uDlczqPAOUT8p69iHAekwJHTexkweM5looZFnhy/8HnIAS9E8s/wa
         VSLge8z1L1Hzg+OORNQqc9pYdMT0i802urHMeQyYk5eLEQGMeehRG/wukXqTuwc88BsS
         +BlQIBUxg1Iwy7LOZneiLvPMDL6/nRRBHj6/VxpydGWmKxB/WpGkAxwWJR6O0Rx79waj
         XwAVfHduSmjLkcJWtQenc03sZefT6v+2Z5wSsR/kAX2TGlVHgv/0798P1OGIN46AYTaW
         xUjjrywy8jfTUFwqT/0QcaLx2g0e5WuFTEOpyV5N9aLVDgBo8URQSg18yQKiWRVNWt+r
         HHjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ifrv61nnbwuahZCEiwjCwkZVX2MKhkqH/HoLspc9PnM=;
        b=q+hlFYz6Jx/faDQvXRWRzrX5qYBkKCn5OGazxQCGFk0CoY7LUzEtdbulMONQUYOTOX
         WPNhao1x6KtBJkFNHbjpiBqMcoQfsHdJH69dMBTvVJzvq3xV4/db+/DdkKrUq3SbZuX4
         gSuEpccrYfud3Ql8v/rSJHphAvv8W/pGwEdhHJHe1C322B6srhuxG+Y5bw6kJYc6ax9w
         oeydoExLRi3ammuZpoRKz/y0sKmXC5zW7nI5UE4N2bv1HPl0ZbcAvzNB3FzIhn5wMQyx
         WPANLM8Hh8MrfnHEnWk9rDnWSDu4lblGPhsttQBaa49x1RF8UyzAURSnkW5StHI3KIjJ
         juyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=svvurHrH;
       spf=pass (google.com: domain of 3wz0ayaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WZ0AYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id r12si505010ybc.3.2021.01.14.11.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wz0ayaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i13so5325729qtp.10
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4c44:: with SMTP id
 cs4mr8625788qvb.25.1610653017877; Thu, 14 Jan 2021 11:36:57 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:26 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <5232775c82fe249ef3ec0a1e8470ec54eceb5002.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 10/15] kasan: fix memory corruption in kasan_bitops_tags test
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
 header.i=@google.com header.s=20161025 header.b=svvurHrH;       spf=pass
 (google.com: domain of 3wz0ayaokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3WZ0AYAoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

Since the hardware tag-based KASAN mode might not have a redzone that
comes after an allocated object (when kasan.mode=prod is enabled), the
kasan_bitops_tags() test ends up corrupting the next object in memory.

Change the test so it always accesses the redzone that lies within the
allocated object's boundaries.

Link: https://linux-review.googlesource.com/id/I67f51d1ee48f0a8d0fe2658c2a39e4879fe0832a
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 0cda4a1ff394..a06e7946f581 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -749,13 +749,13 @@ static void kasan_bitops_tags(struct kunit *test)
 	/* This test is specifically crafted for tag-based modes. */
 	KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_GENERIC);
 
-	/* Allocation size will be rounded to up granule size, which is 16. */
-	bits = kzalloc(sizeof(*bits), GFP_KERNEL);
+	/* kmalloc-64 cache will be used and the last 16 bytes will be the redzone. */
+	bits = kzalloc(48, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, bits);
 
-	/* Do the accesses past the 16 allocated bytes. */
-	kasan_bitops_modify(test, BITS_PER_LONG, &bits[1]);
-	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, &bits[1]);
+	/* Do the accesses past the 48 allocated bytes, but within the redone. */
+	kasan_bitops_modify(test, BITS_PER_LONG, (void *)bits + 48);
+	kasan_bitops_test_and_modify(test, BITS_PER_LONG + BITS_PER_BYTE, (void *)bits + 48);
 
 	kfree(bits);
 }
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5232775c82fe249ef3ec0a1e8470ec54eceb5002.1610652890.git.andreyknvl%40google.com.
