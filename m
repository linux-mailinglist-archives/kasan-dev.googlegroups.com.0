Return-Path: <kasan-dev+bncBCSL7B6LWYHBB5VTTLFQMGQEC5VADSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F9B4D1AFDF
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 20:16:08 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-477563e531csf54764295e9.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 11:16:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768331767; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q6zLK/o8l2Age8ytF0LoKIRKbcJEPA8HdCiODyitN8KpheLPes8E8EB52fMg3ARYvU
         0Zr0q7/avpjXJZ2XvzSvXwGJRqCc3JAaV1LlOR0g+y64TBf1Cv8OErmJgFGfMq8g5AEw
         oGha2SbuXcpkdB+Lxm+VaS9RmPARI8SDiRqI2ZnAxk78lbpsx24MhgtBYrD+fahedPgp
         YbJJstO/eQM9Zx3aqSJz+cAmdMtJWZYUsKrcOn2bI/V4M9zasoNBZKuUnWjqHp53/HBc
         SvMOIl+TJXJR+ulNZHQu5zBk/JOGUz5x3T+4aZk6MDgbBgno08SDskzxq6dDKu46vhFZ
         PwpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=u5IxrRs7t+oQlvPWvzWNXVYlXiaMjmTlfR4lp4g9REc=;
        fh=/2IjmHlLDfabDyE0YJt0dzIDyTaxODo6pAZP6nvOQ28=;
        b=EIJhJyMBzz5ei2QlC4D9y1StAqf0FrKCSBEWKl7w60dGCZm3c60rNHlSo3lowCE+3S
         KcKg+Dg2Tgh6TRiXtNZfxx+SPxfYuwrqltFUUI8ku51zBDJAztK/n7OIS6wCqfNgKbju
         Pkv8KYheARTXrRfzYkLMwgzEtid4BAKH8dy5JlZoORgadY/0/I7iMuVakFcI5+AYRbwb
         VXbpWIC72p/jw2RqANDLPaCLAfPoRKKzdlgDqCqSOZ7UlPXRL/Bg8LMZyF8sJTzVNua1
         JBP6LaSPKrrpY7u/kFoc8dZ4pCOmRwhGaXdcNIMcN9DmBb5fUrKk1VOu0EJuIjWtHrtO
         vqQg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NEIhX5ce;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768331767; x=1768936567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u5IxrRs7t+oQlvPWvzWNXVYlXiaMjmTlfR4lp4g9REc=;
        b=Y0r2XF6IuY6RhGF6ABqHduN84/aHbGuJeObTiE71FZrTh2uoJSrlMHYC8y3LuSH6wM
         DD31lAd9ss0SsDgZcU5o1OEiPVp7xI8vE4/HN7foZhnNkXO8RSdYmjiQJpPPqC+AGbNq
         K+lZTrN2JexkPbnHAe18n+0YoFl0ZLGuZgc/Jsuc3pSIvmRQSfAX4oaXju6sgHs4JkGT
         7BH29vx1HuPKl4UHHgHVIUe42q1LeqQJybNsbExKyT2haghkWPSCXc2h1a2d+uzFAzEJ
         1Q8ia6doPYd5KFiWHn3pYb4v753XNNXFq3054SCfPgz2CDNXriBwil+8vUEclUcBbof2
         pN2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768331767; x=1768936567; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=u5IxrRs7t+oQlvPWvzWNXVYlXiaMjmTlfR4lp4g9REc=;
        b=XXSS+VLrvR/XuOsEMQpMZht4xDEqHdM2mi1iufuRzpOHLEvXby2IUh7N58f0P2J8mk
         fcjeryGM1skLRVLV6twB5fbOTU2KsplRqy3vurR2PCWiAW/8EJ3g1tSggC6G74MNo4nW
         AgoMWIBute4Sv7ECCusItva4XYvj+wsv/8woxccxEz3Pb9N3OKT7ZJvN3U33PMVi6XSO
         SBA+RvUVVLENbiCWZNOywPTImcQ9kmWkI3PZ8AEhFWlxEJLCKNBh/mNkmvG0aVqjdrRG
         qi2Mgod1x31o5EjgGnw8esVFxQL/HapX968Andjakl4E5IP7y2M84UT8hkBYDFIWrydp
         sExQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768331767; x=1768936567;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=u5IxrRs7t+oQlvPWvzWNXVYlXiaMjmTlfR4lp4g9REc=;
        b=NMJqSz07f2D0xciwkYksyLms4YmuzTeeFfdb6lFscg4ZXxU0tEvD5OeikR918FTuCr
         tbja0lYsC6pKajKaCRsnAyi1NQJVmtUm1R5QIaVPJY0vMlNsX5Xu29bqsKtsSukC4gCE
         0lyrqOF+5YcyudxuvQgT/JTd2fvyXKLJWEoCd6v383kHMUfgvdxFGn3bvOKtxeWbkwyj
         YQFAEatG8k6fEYKU/0v2Wasj+HKmACH+ze/y1xdUFVZfcbEuXtdN3PFSC/5qOI2nfejU
         bW12akir02rJEv9i1doKLJAnQTSEoyGEsIqAYKeViAjrKgDXPd2geO/H1mvya9Vb2vVy
         F2+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmUzD9dMA/4xUwv3oQhDR5ThJSLS8hEwpLMb7TA2DzlWzOJzSTnm7ltS1U56YITNa2fw0BHQ==@lfdr.de
X-Gm-Message-State: AOJu0YyJTSoRrZ0Ijd3hAbeR8vwYXfZe2znxnoEbzmHMNg9j5B7m7voc
	2jd679sOKoo91FqkVngWOtZhRHtd3Jmlno3ZpazGfIZI2T1QflhYjzrt
X-Received: by 2002:a05:600c:34cd:b0:477:55ce:f3c2 with SMTP id 5b1f17b1804b1-47ee32fcad5mr3161735e9.14.1768331767282;
        Tue, 13 Jan 2026 11:16:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hnl4pU2wICp5SIYO2SIrVSSefRwx5Nt5FtNM3gaIe/fQ=="
Received: by 2002:a05:600c:4703:b0:477:a293:e143 with SMTP id
 5b1f17b1804b1-47d7eb13bb3ls58550635e9.1.-pod-prod-06-eu; Tue, 13 Jan 2026
 11:16:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV2Z7738+cC/gh0JIZLwYgzA7bVtL45+Unj3xJHqOPwHgMGajtMssbYhkEQmF8OStlHTSU0J5+iKBk=@googlegroups.com
X-Received: by 2002:a05:600c:3484:b0:459:db7b:988e with SMTP id 5b1f17b1804b1-47ee3305a23mr3244015e9.13.1768331764883;
        Tue, 13 Jan 2026 11:16:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768331764; cv=none;
        d=google.com; s=arc-20240605;
        b=U0OeIQ8HsQnec5CPhbe6tBajounCeQMgaNWN0JoxIqWxZBGQVI3LmJVKuPvYXcV8lk
         weHCD/sBxj1W0SO2+PJVZbA5ZNwSiX+lunHBm83KCfP1Bqqx3LUj+FC9GJR2fSOAw4M1
         vrmkN+AUkSW3kTfzks2L9L4cvQKuXJcyimriJTx65q4PwMP9URbABTjoArMyCfNEZ7+z
         5Yw8Vwr8lXb6lz+AJ1QcM0Gu8GFks+boKZmqYno2apFixkog2fEYUoVMJNgfOE/MnqIH
         RgaWbRsVU7NF77mTMpfuTTr31lmsP6ssQ0h/dg2ffFsYpLrhyo/q7TG1KvQLGVCZJ3aI
         soOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ScbrhvmjweTqkN3+3yPcwAeK769lF/fHEHFkP4nsS9c=;
        fh=EEShVsjxizEu0z1+7DH9HXQbYsvy8vRTChBbXyvv0Qw=;
        b=X4h7R1oqP2aMomksfJrMojfDe2UoVFI0OeVOH1AfW1QFIMssJGMZydQp19DZEstxFq
         eHFHO/xlnfQpFsXEAkXQgk8/fb13RnwBiW2LA9+QGniyYkQS6DAXmKPAeXogBeMBX/b4
         McgEyYk+RNBA3zWUvwhKqeaQdkFQ3agjq5P4r0YE0SbPwG84pkdS1eiNC9/g6iJ5kCvb
         MAOeM8basMQfm+GNX8pvUacv/k4gaCjwvEr8LvCJXkfy6tbqznjgbq0lFBc/3Arfnfpf
         NbgAQRjgunAP90LO9tnPtUFOFrMBMb+/RLjkH3hTpif+iQqMEGACObrfcn6zE0kP4enk
         bPIQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=NEIhX5ce;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x129.google.com (mail-lf1-x129.google.com. [2a00:1450:4864:20::129])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47ee272aed9si59185e9.1.2026.01.13.11.16.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 11:16:04 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129 as permitted sender) client-ip=2a00:1450:4864:20::129;
Received: by mail-lf1-x129.google.com with SMTP id 2adb3069b0e04-59b6d59340aso493784e87.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 11:16:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUonKTokgeVF52m2kptRqKIN7w5ckxksswyatqkJqM58UT4A7BWRBx6uJq6pL7jvkD9n89nJdivSkI=@googlegroups.com
X-Gm-Gg: AY/fxX6jpSioyp54i6VOje5F++to1b3G6vxaBnPr5cQbcJlHosrcPzw4GX1vof2Xb5u
	/yhpZNOsXGbVl19ZIpAmOGCUekDh/8UlZgHl6aLAZXtU6eRITBp4T/Jewbq+1Yrtuydie/t/QmO
	z/GodyCpkT4Mxo+nbybb8TPtEBN9d2rwIaa7q/8d5ghURoW8qOqKuhbnGnfwxvTCgoD2FOGA2Y+
	/nniO4FHAq6uOegzdWZckABSrF7h1VyUsF2+l17vvn/OjuLV6B/j6jQuRpAUhbDjPYAwJDOJ9+c
	Vaw7UeduHPKtuwgwXu1FWD1DA9fW3y11UHt/QAsvlnpsNl6lKLYAC+FtVqqlrvxUV5rhOl5ywBH
	Mnjjzk8GDznlODzajNP35nrU8JFD/U/cA6ocGjr1LIDEe2FrjH055fB/LoQhIN7JoFoS5foo6Uk
	bwX/8Gwayzqo4c5M4z0gwUS55StuM6cVNbzw==
X-Received: by 2002:a05:6512:3b83:b0:59b:7869:b9d0 with SMTP id 2adb3069b0e04-59b7869bad0mr3414712e87.3.1768331763812;
        Tue, 13 Jan 2026 11:16:03 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59b6a97e94csm5568773e87.91.2026.01.13.11.16.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 11:16:02 -0800 (PST)
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: =?UTF-8?q?Maciej=20=C5=BBenczykowski?= <maze@google.com>,
	Maciej Wieczor-Retman <m.wieczorretman@pm.me>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Uladzislau Rezki <urezki@gmail.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: [PATCH 2/2] mm/kasan/kunit: extend vmalloc OOB tests to cover vrealloc()
Date: Tue, 13 Jan 2026 20:15:16 +0100
Message-ID: <20260113191516.31015-2-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <20260113191516.31015-1-ryabinin.a.a@gmail.com>
References: <CANP3RGeuRW53vukDy7WDO3FiVgu34-xVJYkfpm08oLO3odYFrA@mail.gmail.com>
 <20260113191516.31015-1-ryabinin.a.a@gmail.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=NEIhX5ce;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::129
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Extend the vmalloc_oob() test to validate OOB detection after
resizing vmalloc allocations with vrealloc().

The test now verifies that KASAN correctly poisons and unpoisons vmalloc
memory when allocations are shrunk and expanded, ensuring OOB accesses
are reliably detected after each resize.

Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
 mm/kasan/kasan_test_c.c | 50 ++++++++++++++++++++++++++++-------------
 1 file changed, 35 insertions(+), 15 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index 2cafca31b092..cc8fc479e13a 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1840,6 +1840,29 @@ static void vmalloc_helpers_tags(struct kunit *test)
 	vfree(ptr);
 }
 
+static void vmalloc_oob_helper(struct kunit *test, char *v_ptr, size_t size)
+{
+	/*
+	 * We have to be careful not to hit the guard page in vmalloc tests.
+	 * The MMU will catch that and crash us.
+	 */
+
+	/* Make sure in-bounds accesses are valid. */
+	v_ptr[0] = 0;
+	v_ptr[size - 1] = 0;
+
+	/*
+	 * An unaligned access past the requested vmalloc size.
+	 * Only generic KASAN can precisely detect these.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
+
+	/* An aligned access into the first out-of-bounds granule. */
+	size = round_up(size, KASAN_GRANULE_SIZE);
+	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size]);
+}
+
 static void vmalloc_oob(struct kunit *test)
 {
 	char *v_ptr, *p_ptr;
@@ -1856,24 +1879,21 @@ static void vmalloc_oob(struct kunit *test)
 
 	OPTIMIZER_HIDE_VAR(v_ptr);
 
-	/*
-	 * We have to be careful not to hit the guard page in vmalloc tests.
-	 * The MMU will catch that and crash us.
-	 */
+	vmalloc_oob_helper(test, v_ptr, size);
 
-	/* Make sure in-bounds accesses are valid. */
-	v_ptr[0] = 0;
-	v_ptr[size - 1] = 0;
+	size--;
+	v_ptr = vrealloc(v_ptr, size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
-	/*
-	 * An unaligned access past the requested vmalloc size.
-	 * Only generic KASAN can precisely detect these.
-	 */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)v_ptr)[size]);
+	OPTIMIZER_HIDE_VAR(v_ptr);
 
-	/* An aligned access into the first out-of-bounds granule. */
-	KUNIT_EXPECT_KASAN_FAIL_READ(test, ((volatile char *)v_ptr)[size + 5]);
+	vmalloc_oob_helper(test, v_ptr, size);
+
+	size += 2;
+	v_ptr = vrealloc(v_ptr, size, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
+
+	vmalloc_oob_helper(test, v_ptr, size);
 
 	/* Check that in-bounds accesses to the physical page are valid. */
 	page = vmalloc_to_page(v_ptr);
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260113191516.31015-2-ryabinin.a.a%40gmail.com.
