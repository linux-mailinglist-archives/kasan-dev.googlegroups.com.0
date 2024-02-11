Return-Path: <kasan-dev+bncBAABBSNBUKXAMGQEKZRCTKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 931D2850849
	for <lists+kasan-dev@lfdr.de>; Sun, 11 Feb 2024 10:18:02 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2d0bbd45288sf11902431fa.1
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Feb 2024 01:18:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707643082; cv=pass;
        d=google.com; s=arc-20160816;
        b=RXygvRn9VQnuNgj5o5wgXJppSj1x/G20BFQ2hGHTsy15R8sJEfLz6q4jEMDALr9O5G
         lqEYqj4FMU1x5TEtDx7EybhKBCHnlI9Q5Vx1nxJ7lIYhvrnejUUw13fy4qZokadJOkqV
         icDD2RanVlV2pWQKDc4WyaqaBAs5lM2V6wVa7Rwipk11Fj4sbkZs5nraUcbl9W2grA8L
         qdg44Mvmif8uK8fv/8tIgeV5koHM4l0opWCTKKZeYPCOGiiqrginl6PhvnTc5AzYj0kR
         4aUQoWfqmE4doEMBfL1qmVGT3xIXnrQeDwecPldHWlnUIPUBP2edtGAHrqncwPUfxxL5
         0gFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:sender:dkim-signature;
        bh=LAL/p0B32iHk6wHdXQS9okNmfRXNWD9v42W/i7A18rQ=;
        fh=PErjkZWpFUUtP86AbnmkAd0BqoByBE2D83qdndE9gNc=;
        b=u9A5nA5IxzvcIm0bWQmB3tQ0d0ROXA1XzN40Dre4xpMxkDIeT5bJ9fvEXP+MRUNa5s
         cYTE+UbVW5bqNstFmcd8IOj4WNqtU5WMdYDxpd2qGzneGIfak38dR/DTrewb5t15Bm4v
         xctlkoBRXlv7MW6S4fO1bNuNEr0p3xIWlRD5xdzDFgp6mjNetLFBioM3apPnD9eUzkRJ
         Z3SAHHlEla+SPMb8z2dxPs+T5RwG8iKFB46RPjzTqpfe9P17xB4KU+i6CGjC6+ibWD7a
         T8Zcjt5SD4vdwonr5vd4bunmtQ97/nVbTWR/M+jGjBsQA+sxhMrrt/pJNYkFJx0E2kmF
         gnpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=fXFBmetf;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707643082; x=1708247882; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LAL/p0B32iHk6wHdXQS9okNmfRXNWD9v42W/i7A18rQ=;
        b=MH2mGvi5RccT0uq7HIr1TsHYM6Qww6pvZa6sqDmE09QkugUMAE6zDKZzqPene2D0SG
         a+sZsG1Q7nSuzH17TmGJNHWUZTe7iSYpmGPluZa+usbHgPgTJKu+CY8PAOS7ujiKhDTP
         rFFfkxgsm5B1r0rcANK13uFD8FT8QAI0vcp4noFrsVTqCSH+01Q39YCFD6kpnLZ6OJyj
         ez/iwj0Hz0gHJHTxO/YoTGXVticMFoF3VZtViLGKkdxvY8mlPb2eCR5v2R/gRwaw1/4g
         6CvwZqTavw5AdaBjaFn5kHP8sEE4PUEWt67c4UnSZqCycEuEJyBjmq5tZlfbaezvUi7K
         Kj5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707643082; x=1708247882;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LAL/p0B32iHk6wHdXQS9okNmfRXNWD9v42W/i7A18rQ=;
        b=ZeUbGqbYVsIskYXF4N76JDlutSAwDa9rVK+Frgvf/gvgJCiqMPwkHSzapEfqg3VlUY
         zrt/7dYUaOYFDKTHTEXsFrewJnkoWlxoQzjqp7WtCLpk1rqfUmTg7mNrWk3lR046bUa2
         9it5TUABWfFKn8rKqRbp2s5W0vJQYkfor/5AElHepMCogHEe3bmKrgMxHPspfHDrxbdJ
         uklRUuNs02OsxdP9IFGjdM3i+x+R4RQQPVkPoDWY2+oE7GCLGepG+pYpcq8INbAHG1n9
         d2pvivE45UWvuRy8clNWsxJfe4YwjhS6MnBoujnEZaesS/wWrUdQfap9J49zG+giIAmq
         LMOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yzme0jtNjZIB8aA371CmQBs7qylRTbTBQjxqHEZPoX5jgYwyl/S
	KktJjXWqMv/uJMmW3vf25i94+fGVyzSKl98s6o0PL0cHsbhjuWBP
X-Google-Smtp-Source: AGHT+IFodOhHJ4StmzdwHgouSx+uhf9QFYpxzo0AaxrZKFYZZuO42rfU5A4qDYMuopqOV19QGyY0Ig==
X-Received: by 2002:a2e:9991:0:b0:2cf:4625:c1a9 with SMTP id w17-20020a2e9991000000b002cf4625c1a9mr1903175lji.23.1707643081420;
        Sun, 11 Feb 2024 01:18:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a26c:0:b0:2d0:a0fd:c342 with SMTP id k12-20020a2ea26c000000b002d0a0fdc342ls743297ljm.1.-pod-prod-00-eu;
 Sun, 11 Feb 2024 01:18:00 -0800 (PST)
X-Received: by 2002:a2e:908e:0:b0:2d0:8e95:612e with SMTP id l14-20020a2e908e000000b002d08e95612emr1104849ljg.16.1707643079802;
        Sun, 11 Feb 2024 01:17:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707643079; cv=none;
        d=google.com; s=arc-20160816;
        b=fA2ppUmKMRZTwYjbuKOhCLADQb1cLNqcUeunWcTNd9uiO2JWbOUjBm93uyIK7NmTDF
         CP2/JZHjJoTZXJCkGC8u7IQ5vgk/mtOWgBY+5JBB1hlaFpmGd/zqtQYUJ3SzTUbjPZKT
         nh6dULwWIiewkqGS7uuTlpHk3S5DoAEkMkfrrJ1wd9gB0zbtzSodh4k3Awid1So+QkgE
         8eetht8mJxbcK0EGEwNRleFCE+vmJnfcwyt0XLlA8Zh0r3grZ3EeROGakD4zGm8yyPrU
         CwhNMMX50iemeett8USTmoBLy5vul4WpyzqIzRPlgBxaCYpKaH1Pr5YM13DkghetmjLi
         aV+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nyUqcldidtnXWwbTceXwthhkZZm9TNzWOm9++Z2b+gM=;
        fh=PErjkZWpFUUtP86AbnmkAd0BqoByBE2D83qdndE9gNc=;
        b=anrQX3OTnXjGLUe2zp1jvmfTE7wB9tZz9juj+qO/rQFa+XKdmpLkOF7BPjfTH6wqyl
         31aIbQfZ7scIBO4py7dWS/Rk6vO2SdVhhAnZm0m8MXojAZJ7nF8dNw+FtdEjVMg2gyeP
         +3xrVmXZ4eioroAqHgRf012fz67+ZHB090RycNGFYZUc0E3RTWLz83MSS8vtdUO0tLgV
         voCg2wzD/cBrZ9TxN/Ii2F962mHXVvjH74z2z+Budsi3K1w4l1N2ifktsw2+SGG2IFLq
         08SrBVFXFk05xa1N5Sg8YcZvhfc3lkp1Otr7vZPsC8FslkaDAkCWGjcEhapSEis7hLlr
         Yp/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=fXFBmetf;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
X-Forwarded-Encrypted: i=1; AJvYcCXZZB+BlHFNFpNYbJizjIudcoMw2h/mMjSf7surjeiv4KL6b1iNI2rTefZRFdX9TZBWJa4Isz5eoU9tRoa8PhSR55E/hovA4N86Rw==
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id i24-20020a2e8658000000b002d0ac7feef0si357913ljj.5.2024.02.11.01.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 11 Feb 2024 01:17:59 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4TXhny4cG0zySP;
	Sun, 11 Feb 2024 10:17:58 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs51.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.88
X-Spam-Level: 
X-Spam-Status: No, score=-2.88 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_CT_PLAIN_UTF8=0.001, LRZ_DATE_TZ_0000=0.001, LRZ_DMARC_FAIL=0.001,
	LRZ_DMARC_FAIL_NONE=0.001, LRZ_DMARC_POLICY=0.001,
	LRZ_DMARC_TUM_FAIL=0.001, LRZ_DMARC_TUM_REJECT=3.5,
	LRZ_DMARC_TUM_REJECT_PO=-3.5, LRZ_ENVFROM_FROM_MATCH=0.001,
	LRZ_ENVFROM_TUM_S=0.001, LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001,
	LRZ_FROM_HAS_A=0.001, LRZ_FROM_HAS_AAAA=0.001,
	LRZ_FROM_HAS_MDOM=0.001, LRZ_FROM_HAS_MX=0.001,
	LRZ_FROM_HOSTED_DOMAIN=0.001, LRZ_FROM_NAME_IN_ADDR=0.001,
	LRZ_FROM_PHRASE=0.001, LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001,
	LRZ_HAS_IN_REPLY_TO=0.001, LRZ_HAS_MIME_VERSION=0.001,
	LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001, LRZ_TO_EQ_FROM=0.001,
	LRZ_TO_SHORT=0.001, LRZ_URL_HTTP_SINGLE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, LRZ_URL_SINGLE_UTF8=0.001,
	T_SCC_BODY_TEXT_LINE=-0.01] autolearn=no autolearn_force=no
Received: from postout1.mail.lrz.de ([127.0.0.1])
	by lxmhs51.srv.lrz.de (lxmhs51.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id voYhHrpRVFxn; Sun, 11 Feb 2024 10:17:57 +0100 (CET)
Received: from sienna.fritz.box (ppp-93-104-92-100.dynamic.mnet-online.de [93.104.92.100])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4TXhnx1Vk2zySF;
	Sun, 11 Feb 2024 10:17:57 +0100 (CET)
From: =?UTF-8?q?Paul=20Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: paul.heidekrueger@tum.de
Cc: akpm@linux-foundation.org,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	ryabinin.a.a@gmail.com,
	vincenzo.frascino@arm.com,
	Mark Rutland <mark.rutland@arm.com>
Subject: [PATCH v2] kasan: add atomic tests
Date: Sun, 11 Feb 2024 09:17:20 +0000
Message-Id: <20240211091720.145235-1-paul.heidekrueger@tum.de>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
References: <20240202113259.3045705-1-paul.heidekrueger@tum.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=fXFBmetf;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

Test that KASan can detect some unsafe atomic accesses.

As discussed in the linked thread below, these tests attempt to cover
the most common uses of atomics and, therefore, aren't exhaustive.

CC: Marco Elver <elver@google.com>
CC: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger=
@tum.de/T/#u
Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D214055
Reviewed-by: Marco Elver <elver@google.com>
Tested-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul Heidekr=C3=BCger <paul.heidekrueger@tum.de>
---
Changes PATCH v1 -> PATCH v2:
* Make explicit cast implicit as per Mark's feedback
* Increase the size of the "a2" allocation as per Andrey's feedback
* Add tags=20

Changes PATCH RFC v2 -> PATCH v1:
* Remove casts to void*
* Remove i_safe variable
* Add atomic_long_* test cases
* Carry over comment from kasan_bitops_tags()

Changes PATCH RFC v1 -> PATCH RFC v2:
* Adjust size of allocations to make kasan_atomics() work with all KASan mo=
des
* Remove comments and move tests closer to the bitops tests
* For functions taking two addresses as an input, test each address in a se=
parate function call.
* Rename variables for clarity
* Add tests for READ_ONCE(), WRITE_ONCE(), smp_load_acquire() and smp_store=
_release()

 mm/kasan/kasan_test.c | 79 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 79 insertions(+)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 8281eb42464b..7bf09699b145 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -1150,6 +1150,84 @@ static void kasan_bitops_tags(struct kunit *test)
 	kfree(bits);
 }
=20
+static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *s=
afe)
+{
+	int *i_unsafe =3D unsafe;
+
+	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
+
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
+	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
+}
+
+static void kasan_atomics(struct kunit *test)
+{
+	void *a1, *a2;
+
+	/*
+	 * Just as with kasan_bitops_tags(), we allocate 48 bytes of memory such
+	 * that the following 16 bytes will make up the redzone.
+	 */
+	a1 =3D kzalloc(48, GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+	a2 =3D kzalloc(sizeof(atomic_long_t), GFP_KERNEL);
+	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
+
+	/* Use atomics to access the redzone. */
+	kasan_atomics_helper(test, a1 + 48, a2);
+
+	kfree(a1);
+	kfree(a2);
+}
+
 static void kmalloc_double_kzfree(struct kunit *test)
 {
 	char *ptr;
@@ -1553,6 +1631,7 @@ static struct kunit_case kasan_kunit_test_cases[] =3D=
 {
 	KUNIT_CASE(kasan_strings),
 	KUNIT_CASE(kasan_bitops_generic),
 	KUNIT_CASE(kasan_bitops_tags),
+	KUNIT_CASE(kasan_atomics),
 	KUNIT_CASE(kmalloc_double_kzfree),
 	KUNIT_CASE(rcu_uaf),
 	KUNIT_CASE(workqueue_uaf),
--=20
2.40.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240211091720.145235-1-paul.heidekrueger%40tum.de.
