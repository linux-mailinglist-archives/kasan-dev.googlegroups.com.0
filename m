Return-Path: <kasan-dev+bncBDHK3V5WYIERBW66TCIAMGQEFCBXBWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 14BBD4B2243
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 10:41:48 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id p9-20020a2ea409000000b0023ced6b0f51sf3821806ljn.19
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 01:41:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644572507; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZzQoL9lv/hZehssCfp+iI7Du3On4fnHCvmjbPyt5LqRo2pOOciPIodZBiNNyK9bywW
         C49eKrcGa69a5JkgkVefd79OdR4rlnjTS6d1dCmLp/OHxX7cJWrISwiRaiPKNmLQyNC3
         8HrEy1qO5cIrpTooHLRHKQ6GuYMqIyHapBkaBb4PrMwnVmH1MORz2cslpFyKAHDV3oH9
         OzEAWXMN1UGKRpNm96QT/dJ8tJfGsaLA9haC0Lbeq4xPG6XKk1oF7i7HobolRc4eJcnN
         yMaBdH2NHkEe7vkO7PfGi2MiE6lxvoarHMLP+dcB4yW5PXWETS3y758pvByIJhFb7GO8
         v+Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=nF8VqRnM8XHxbUJIC8WffMo0EggfkBCa6/0Cdyo87q8=;
        b=Kc2KwHoGMmju6p3C0sJvUn4Flge/wgOtVPeRQEDjR8yTpP1lLQiR7z/Suk+VsA+S1X
         MEjU2CsNEgRTsOhC2iq/RwgErG/zAuylplP6vHxRz5eWe6hCWlWguOQ546Akg0YUOxFy
         Wt4q5V/aH4+mm0Q+9KAnXzZb69yPSqWgesvzTFJD8RMgsMkQoScudoLYEvMGYdh5M1Vj
         QlM31kpwN1ykhjUjyPVxG78g78+Pjfe5Quj65EX/BsMEO/AXz4SIQqxXuXTQckV4eRFu
         GUqlXgMR8zFdiioJAjr5p67DB+o5Jj/F1ueqTiQ15wRdUSzWxZt5C5mlytpto270ChgE
         ucyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="P+snyK/K";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nF8VqRnM8XHxbUJIC8WffMo0EggfkBCa6/0Cdyo87q8=;
        b=ocnVs1KoDKeMug4ypCcTM2WsfxFWgFAd9kXcL7kCMSDurtQHvsj479S+rj9PRdNODv
         dAlxN4uJPV9udIxeA2BkJb+WOhmkaoM1pBPi5o6/5V8sIazNExuc/DtNVHKA+SQvU5v1
         GITnxLlhWpDlRehmnPM9DXKQbI0yFx5/OhlT4k4yxRw9txzxkzBJtY04XSwYbMMBrER7
         v+Ik6JanzbjMkmuc1Vg3w6FXiBGY/IjD3JhVSRiunbLWr/eN5tzze3dFcNKGIZ9AuOs2
         LeC+iupO47I0E4klFa964AYWOOPLeZdEhsYAyVjUfaS+9+MsX+3VnGVsfMYl/MG+ehjV
         qE2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nF8VqRnM8XHxbUJIC8WffMo0EggfkBCa6/0Cdyo87q8=;
        b=ndGsLNXh0xcsy5d5DrMiXrjKnUPNHEfhSNCV6iRzGJHo7q88mtYN/ru6rL1T8h4knE
         JeYw3tfZvTDKwOGDIAazbGAx7kr7xSiQm969/rwmnbZopijdmPHVwWrIDuBYpfAJ+Ked
         XaYdxUDYS5ZE4jNDnDKS/tG4pb6Qo9DIKzAZxWWAlXormTpL4zE2MZrYH9rEs4hKVNpg
         wqzbuWwU+Q4Ei4BF3UnYnpFugfVgYasWeyws3UUk7nd4fwwQwj55T6VfdcNUFZa9v/Et
         5Do5zmCjtWAby0CpQLWvJ65AxOKZ0rhm4LaLPePyD4NupqZU0i0tjlXyMGEJWLdFA7LG
         utjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5334yX8gABg9cIOxBrDLmoG+TJzqbwT12ojMbB/YY8Ytw/5PQbRT
	k5BbeNS3MB5+vz7Fh+ET5oY=
X-Google-Smtp-Source: ABdhPJwC3qgZFcuwU2mHxB5zkdWhA5FAqE4+25xpYhqQ0hyPjTuPATtWvEGKnCOpFAmnXsvEKVGW9Q==
X-Received: by 2002:ac2:5144:: with SMTP id q4mr661176lfd.206.1644572507497;
        Fri, 11 Feb 2022 01:41:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:: with SMTP id f14ls5037469lfv.0.gmail; Fri,
 11 Feb 2022 01:41:46 -0800 (PST)
X-Received: by 2002:a05:6512:6d3:: with SMTP id u19mr619288lff.434.1644572506446;
        Fri, 11 Feb 2022 01:41:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644572506; cv=none;
        d=google.com; s=arc-20160816;
        b=NQgjczmDBIq4Y9q4Tz/mDupE8T/E2jYzw96FvhVNDrOJ5bH8oqqz+WjVIYk3kLmJL1
         dKthmxl5w4EJMUvznrT5TmgcmbgdYE7EvSMIKIlv+mm/OHf4MpaDIkkaVpMDlrxRLSzE
         TepCkezqwxQOEw9mvTfAyI48GSqx2tpsewSK+oVDJTcL/Lxrr+K1uUYzZezLeOMyBzuB
         umpgroxfxq+MbfWN0A6OJ0SjQE6XgnGKGPG5AsEwXaTJwM4repuBK7Pfpmd4rpTBdzXT
         yWfeDdUbKf4I/9m0HAqQVuFJ8fVrj+kXuXkpQ2TZ81q+ovwfZ1B0UNSuSS4fg8OQjEj6
         BJdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rYp/F1vbxbLivUF65w2maaWuA20v5CCQAIJDPT6o8JY=;
        b=TxuO1ta6gEXPfc4XA8rWUDV/IpBrY8pG4+gVQSWkJHbtrvan0Eqsb57fQppYH8Z37o
         DlDuxfXNZnpILIhBFJbgpNyC9ZniWRojalAAUMhp8NvpfH5zI57cepeMO43RPb0guhmz
         x5ToUf9RX3HaX6/ca7qso0vXtDtG72RT7iA1UBGWS1yLmE0qsfuAmv+wgSTgfCic2dx2
         Wn0Z+tnpVC85ekOWtjYCK19EauMvubV9lzXWOs6UoE/zMClnrcW0Uh4lN2DY4P3fF2Rw
         ngxniEXvVcRLz/E4qeH1obzdufncMjKf+FF161fQb1ASfNktggHSlpQlKypfvfVr+M7M
         NUzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="P+snyK/K";
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id v26si311224lfo.10.2022.02.11.01.41.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 01:41:46 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id p15so21594972ejc.7
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 01:41:46 -0800 (PST)
X-Received: by 2002:a17:907:6d88:: with SMTP id sb8mr639925ejc.25.1644572506148;
        Fri, 11 Feb 2022 01:41:46 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:83e3:abbd:d188:2cc5])
        by smtp.gmail.com with ESMTPSA id e8sm603196ejl.68.2022.02.11.01.41.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 01:41:45 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v5 6/6] apparmor: test: Use NULL macros
Date: Fri, 11 Feb 2022 10:41:33 +0100
Message-Id: <20220211094133.265066-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211094133.265066-1-ribalda@chromium.org>
References: <20220211094133.265066-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="P+snyK/K";       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629
 as permitted sender) smtp.mailfrom=ribalda@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Replace the PTR_EQ NULL checks with the more idiomatic and specific NULL
macros.

Acked-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 security/apparmor/policy_unpack_test.c | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/security/apparmor/policy_unpack_test.c b/security/apparmor/policy_unpack_test.c
index 533137f45361..5c18d2f19862 100644
--- a/security/apparmor/policy_unpack_test.c
+++ b/security/apparmor/policy_unpack_test.c
@@ -313,7 +313,7 @@ static void policy_unpack_test_unpack_strdup_out_of_bounds(struct kunit *test)
 	size = unpack_strdup(puf->e, &string, TEST_STRING_NAME);
 
 	KUNIT_EXPECT_EQ(test, size, 0);
-	KUNIT_EXPECT_PTR_EQ(test, string, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, string);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, start);
 }
 
@@ -409,7 +409,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_1(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->end - 1);
 }
 
@@ -431,7 +431,7 @@ static void policy_unpack_test_unpack_u16_chunk_out_of_bounds_2(
 	size = unpack_u16_chunk(puf->e, &chunk);
 
 	KUNIT_EXPECT_EQ(test, size, (size_t)0);
-	KUNIT_EXPECT_PTR_EQ(test, chunk, (char *)NULL);
+	KUNIT_EXPECT_NULL(test, chunk);
 	KUNIT_EXPECT_PTR_EQ(test, puf->e->pos, puf->e->start + TEST_U16_OFFSET);
 }
 
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211094133.265066-6-ribalda%40chromium.org.
