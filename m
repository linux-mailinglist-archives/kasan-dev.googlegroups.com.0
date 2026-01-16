Return-Path: <kasan-dev+bncBCSL7B6LWYHBBUP2VDFQMGQEXXEY3LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C3D7D31D54
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 14:29:55 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-38300efef65sf8874991fa.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 05:29:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768570194; cv=pass;
        d=google.com; s=arc-20240605;
        b=BVpQca/Hl6VyRBF2xo4ego4JFSMhBbxH6kJ4cnlY+iPh5GPJ3zIdaZcLO/+65nwvgI
         kuaNUfSF6NvrXAcyi69B4vPFF6dvlFHBBx7mJGFFXgYoC9M332TGY3xk8nc2wUlDxR//
         1IMCpWYLSG1xBM+LRCpwoEFCOAIi2jCMnLt1fSOZlGclllmNr+q28Oe8/cManA/UI+zR
         SugjKDkJT77U6dDyGI0lV2Xs3WvXqCvp8Tkdo9NCGztB5e1CgSZ1oYWKIJuV4UZG9zAq
         3Zh+3fW10rcFNWWrlvVTctPnXKmh9Gp2nwVR/oA3F3ameKrG+UImgujgnf0ea5hwAK5I
         BG1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=vItPGGOtCBg4iamZSsGu9iXXBgjzDoju6TLQuLYAyDQ=;
        fh=N4UCJzAgTlrL+OI23EW8rA1phVC9UKovUUVK5OWlT5I=;
        b=P3IDJkuv2OYwSlVa3zDRh+Vuxeeb2pjo5/3NYZjtyybkTHe/QiO6UfqDPwvLd6YArA
         JT4WUiuD3OOUSJyyD8DzI1eia0OgdfkIacrDRBH/cyuD82wNOpMRk2tlppmE1rLm6S7F
         0/LEB/dgyUBVLgMTzOijmzod69TU2Qw2H0haWNr8H5SMdP/sDjYb/Bw5DYNAMdaxbnW+
         t0LFvJ9NO+8VB1vGbqjFZI7V53icwfVg6VLRfkDxJCWEzRWC6QiTQC4njCyJKM2bk8CO
         dI877XsCQAinOpuGUrUWr93pzBaTJbdjQazRLsgS4ffCGOQdcp0A1fibdOt9F/g6Jf2O
         mIpw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y45a2tKl;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768570194; x=1769174994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vItPGGOtCBg4iamZSsGu9iXXBgjzDoju6TLQuLYAyDQ=;
        b=l0359QQHISmVPCvDf/8y9Rzcr54P33znQsBORkvDfqot1nCiWbs4p7fDlcNCPrXtyG
         PGhZJPMke0VUG3KuAZFZGAeL15N3Ea0Hi1eUu9xTS0h1omjimsj0PEYxh+gsCxE8FKtf
         qGZoRvnV+aUOWJ+nGXT6MrOV3FpEYI9QyqyizkP6kJkrugnyas+R4cZZ0is+G0HpsfB7
         k3y7xwO9TMKnZPkWdiuBXZxPIIFc0FfoZrj6LXNviQm7hMYUC2bge8bdcSRdAFghtLCB
         OB5JAPuNWs23WLdbz/LBhSpWRL9yjypx2d5h2wpHiH6IDRt0URjAPiX2lagHfJhOULmS
         wJFg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768570194; x=1769174994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=vItPGGOtCBg4iamZSsGu9iXXBgjzDoju6TLQuLYAyDQ=;
        b=Qhw1Z4TgAKK/jtgjECgmcbDhG5gUHWBVCP0yJxo2ywXrYv9LGM9cVCDQbEvDm2Zx/A
         j+sk0eFHXkHySndGPigCRHNSjsxlLMeTFeQPdIuPxCs6L9JLeQYXGeHh5JKqWPFNXZjS
         mjdv46bNAwr7PQshML5fvm5EE5hMmEXPPEvrYCeU45uHsdCJzCJKmq3tWGhUpurUzx/a
         Q/1H9g7FOEJt5DqV5BWqPub8bL+mOiT1QwElAYgRVHX2zziYTligm7zpQnuotAkYyOxi
         oc9NDqfArWUhKv49nrb7QhR01aWXDo916kaloZplzLvMzAc96c7jqEC/c2G/rrmUyLND
         V2Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768570194; x=1769174994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vItPGGOtCBg4iamZSsGu9iXXBgjzDoju6TLQuLYAyDQ=;
        b=cmBflauYV2/0aCftrYOWLYEf15JkAq9KXghMGCaLZ5XwNNw8MmFgWKqFN87q3XZ/ZR
         lB78i3duteEazfpP/vi1AZi5VfVV2QnI0L51eBsv4rr4u6XRkjrmilW9qLEAZbecuC4i
         tuIaF2MzNteQERuro9EQy89lvHdAk8EpasjyI4SVTH01B8vXsU7xdC5WvA3H/UJgE8bA
         Cmjr9AkO4lnGaNCZjghx5XMp0BEj/qNznUutWsnBRv8ge20VfD3q7jaD4q4EL6qA5Eyp
         BOdmwok3t82+lQh2RfuS19DMA0idNHV7Qq64z4llod+X2xlz0RalJ1WqJU1DZIiLqpy0
         JNXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWZ8OSgUMgopwA6iJqmTZZsDbhhBkIyHwUK6vXlxJXY4c4DP26NkpwSgRi794XvwPYbU+2pDQ==@lfdr.de
X-Gm-Message-State: AOJu0YyiQwmTuJsTN2HcbqIzV/F7TbDW/NlSOTsIEmFkWMYlshh4znnT
	2xieeKFhlmGkovauFkbBT6u5WcydfBBzHjoO87VJ3/tUedMRnEDemSZM
X-Received: by 2002:a05:6512:3792:10b0:59b:afb7:ed60 with SMTP id 2adb3069b0e04-59bafb7ee41mr605030e87.0.1768570194078;
        Fri, 16 Jan 2026 05:29:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gt4iGqYY6yZbcfPYSelDQ0Z2eUmCatNOq/t4HQZM4jjQ=="
Received: by 2002:a05:6512:31c3:b0:59b:6d6d:c with SMTP id 2adb3069b0e04-59ba6b4b2edls882174e87.2.-pod-prod-09-eu;
 Fri, 16 Jan 2026 05:29:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVafGtjYY3ev6DfpG0AT0Syx6k6LrfGOfRH1c6OHfAE2ITNIhwYRCLfJYKFG6hFnzTnZBOqpMn4BSQ=@googlegroups.com
X-Received: by 2002:ac2:51d0:0:b0:591:ec0f:fa92 with SMTP id 2adb3069b0e04-59baee8f1bemr1149484e87.3.1768570190876;
        Fri, 16 Jan 2026 05:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768570190; cv=none;
        d=google.com; s=arc-20240605;
        b=Uo1ASDASi81iACFQeNn3Gg6QMs8Vxj5pqOfWpq2NITvGB+CvFiyf34hRJnX6y1wXsC
         Q3EBmHab8Qv5JmZ8urP3xztyz3pbwUeEzG3cslwKDqBEfJKVYBMAkoU1/cMk1lbUhpz3
         zhWD8pjCAqDZCGvuyvATYMWgmSNTV5tcEEarSxCl4BSXWVGAkzPfsc0MOOBoMsyddhCb
         nelTB98IixFfaLxWRv9OuVhPMRCDZq66R6fTAg+AQOAQ6PRXXhIV24Hcvc2LgjA1XuQ0
         URu9XNeReFs4GyJ/Lo4pAgaECBemkYd1m/utCWv3Sdh3MzvMw3eAi7J1okQ1Lb9yUvf3
         sQPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=V1EOYdbPMccS+aeufmTW2gbnPDhaXxuCCgvNnc3/C2U=;
        fh=d+CEdj6v8eHkpaqJmf2tCN1xqN+Iq8GU1Ox3VsVBPVY=;
        b=UeMjtPpNrmdPPTFNS83SMShh9M18rj0O6atEJnLREpb7FhuSKHl04RgMKcxGxXy4iJ
         Gzc5Bx0yWcuOFQzL36v55u2ccP10RGvFUp1qw38bXfN216XxGwT8HwfOwWBAqc5Skr3Y
         GtpJ7b4EMnHqJC6dKuUMI0usj9kZ84yWVQQu/QpQnB61uRZAIZwKiJrvI3eyrwKxr7NR
         pbbnGQU3z/JaueSuFCpGRhfRedB7zmcpLD8rywmlrNAvmIcYqm7KEsGvIV/zkB8S2Hsw
         V3r1SE7sjSZXEVzZFq2gdWOYo1fNlf+mHbMlGXW8/yCsluvJYLFPwLeE8Q8/Tpp674IA
         tD8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Y45a2tKl;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf341ef5si54838e87.1.2026.01.16.05.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 05:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-59b6d59340aso178190e87.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 05:29:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW5zQU3SM4ahEyGM38OzIqBqw1BuWZtS2M8c9FOu8bj6BOakjmXZVez/r2fuhonQEJLF26KZNp3ldA=@googlegroups.com
X-Gm-Gg: AY/fxX4LroTzaMpOWGjOozsPj4UQbCpLtLoklDrnIrUw7WnC/4pHvkHuQu8aSKSubd5
	c3BWD7gZdNKRuQ9/9cUNT26AK/da3AOyxcCB+wFy9ZEogbmNYEop8OrbBIesv6P0dgpc3foqXBt
	CWYwytglf+V5CoFjltfvg4XmGmdc56A9G3ENCsPiaQUBjBoi/5vf4iVC3LUhwu7nYZwfztjLaty
	KTqFhyfp+HtoI/lH1QzgKkDsYRQ6mq+jLuhgr2e18bJOlN1OnZw/3xi6YTb+j/Kco7FMCjaeJGw
	Wlhf5BHIYVrNZfLPOUDhz7bMBtaYT6jQ0z0wg0fTBiLyqoX3hfWSYQBel5WbmuHeflYQYBA/q0W
	JdDNwv1P9nS7+UEzF8jdsm9zDNpp4fxMPC6GnFswUB/Sb6lIWwYXxC4hUsT9CXrSZY9hhI36qIp
	BnWjsPMMbyiOn17lX1mfTJG9zd8vzDpKqlOQ==
X-Received: by 2002:a05:6512:6182:b0:59b:729e:680c with SMTP id 2adb3069b0e04-59baef04d3cmr537410e87.5.1768570190107;
        Fri, 16 Jan 2026 05:29:50 -0800 (PST)
Received: from dellarbn.yandex.net ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf3a2aafsm785875e87.98.2026.01.16.05.29.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 05:29:49 -0800 (PST)
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
Subject: [PATCH] mm-kasan-kunit-extend-vmalloc-oob-tests-to-cover-vrealloc-fix
Date: Fri, 16 Jan 2026 14:28:22 +0100
Message-ID: <20260116132822.22227-1-ryabinin.a.a@gmail.com>
X-Mailer: git-send-email 2.52.0
In-Reply-To: <CA+fCnZeHdUiQ-k=Cy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw@mail.gmail.com>
References: <CA+fCnZeHdUiQ-k=Cy4bY-DKa7pFow6GfkTsCa2rsYTJNSXYGhw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Y45a2tKl;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e
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

Adjust vrealloc() size to verify full-granule poisoning/unpoisoning
in tag-based modes.

Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kasan/kasan_test_c.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
index cc8fc479e13a..b4d157962121 100644
--- a/mm/kasan/kasan_test_c.c
+++ b/mm/kasan/kasan_test_c.c
@@ -1881,7 +1881,7 @@ static void vmalloc_oob(struct kunit *test)
 
 	vmalloc_oob_helper(test, v_ptr, size);
 
-	size--;
+	size -= KASAN_GRANULE_SIZE + 1;
 	v_ptr = vrealloc(v_ptr, size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
@@ -1889,7 +1889,7 @@ static void vmalloc_oob(struct kunit *test)
 
 	vmalloc_oob_helper(test, v_ptr, size);
 
-	size += 2;
+	size += 2 * KASAN_GRANULE_SIZE + 2;
 	v_ptr = vrealloc(v_ptr, size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116132822.22227-1-ryabinin.a.a%40gmail.com.
