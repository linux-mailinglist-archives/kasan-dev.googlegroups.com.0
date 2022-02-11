Return-Path: <kasan-dev+bncBDHK3V5WYIERBWG6TCIAMGQEWES5IGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AC2FB4B2241
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 10:41:45 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id t24-20020a199118000000b0043874ba4b56sf2006523lfd.8
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Feb 2022 01:41:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644572505; cv=pass;
        d=google.com; s=arc-20160816;
        b=aEusIhmYLiTYPg2fPchHI52KlWDf/9CpqJpQNSGbjVdK+2bl+3PRjA2UFHv9Xm5srC
         eePH1ZIwHhG1edTwxHPYK9qvwgePGyCTMlFQWFDmI6mGASQcuXYZvPCGHANcZnQ2xzI0
         uBNHymqgs2tvwed5Qug7FavuBHFcbSfeAooc3rzubRc2E4SlUmdaFth8sEDyTnV+xzkB
         mYGjSnv2OJ+r77TEUP6DtR234J+CuoHLnTStCz2S9kuljtS9hDmoWQ1R3ddu7ngfMDvt
         9ejiTw/25GiL2xAd3vH0niEjvVOpRbIJsSVshwVGVC4bv5ug37nf+ATJ8ME/CAGHIRDH
         kjGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OAnFi5AOb3uu6gMRLTr9CsFJKbgBJPux/PFoyHZiYys=;
        b=VSPzmlp4VBzsNPcjC+LYTZUjlv1kp/XTTXCTRE0ijgn+6VVmoiy8CYd4uEAwuSv/dS
         UH8hjjZV8QJz6cQ/Y7HvZZQV0ESD/yoMyvk8pM+beIGij3cna+ncjiiQju2pcLTJnMKM
         dRUQ3CuwmSWiYeUDHJun11kQbFiJfswOWgZvmuLk49r4MrmPpCBbrF1ORpo1DP75L7fq
         gdpn23mf3FWNDR0AUo9+8vK7n46uwLWTEfEAA1CmDQkbQyNGPwbGK0JEpbsFUqmCOmo8
         vBMs0hG085lubVe654lv7r1iu2BBeN3+1ZAWe3y0Ye0cQlDxSZb8mfh8vUCu5XhDb3SP
         59Qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bMKbgW7a;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OAnFi5AOb3uu6gMRLTr9CsFJKbgBJPux/PFoyHZiYys=;
        b=gqvBEp9Cy43UInvhOKdXknSZbQJd8lY8Vq4k5nKwwWcjQKeaRoPBjkFiryht7cZ0Hb
         z+trAGpNCEB/EZOlyLoSuWMHLD2yCBmcJ7aWG/d4jmvN41EL084lFE2wxz2aqX7Nw7x+
         /xwQM7ZX/16DqtA2P72OVN+TU2Syl2LUJ/j35NsgSijbl5ayOOZteNst1sHqLSDroQTK
         oh6U3YYiGylfq2pwg6vz5scDZEbFW1z5ZzxMGcgakfkKrT+WT9RG00VNOnqA4WNdExrM
         fHq199a24jCIIKvK5LqANDgP59RdYNuUbEbs05OSY5PlVvr4G4wqGhbvHWWQfJHkc0J5
         gyYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OAnFi5AOb3uu6gMRLTr9CsFJKbgBJPux/PFoyHZiYys=;
        b=k/tixofVAVjUZeepdg/NycMKW+7ZXcLtyjhttfYeD/zGtd3nllyIgD/nvF47DHzj+m
         vz3UhMR5wGu1X0RrFBghjEsXI4vNIQPd6N4G9WKz7GktcWt93zm5PbsKzvxGShXhPnCL
         9EVpHMJ6TIfxGQarov7muyVyMpYt9XSZV6Kx0pww+hGEqSY9AHKmq5iJhLIGXZn1SUjH
         whrltCaHMFg/qBycE9oreDIPwz45hctvTDarDegoekXvEVexEU5rBP3UaJ/MUVTLn8yQ
         8zObME2VMCCtwIR/Ef982wqavxfy70EI3BMwUb89A12LbMECXsTR+ej1TXIC7f0zYyFj
         FzOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PilcBjvPQbEUqDxMVNgTyeSreeaW620ZmSyvrIGrXQQoC0gsD
	ekQPHPRcnrIywRKfOnwf+mM=
X-Google-Smtp-Source: ABdhPJyZxhw9ZtR4BlT+yOHfhakeSG2Px5dJupYAEDlFDqllTK3W1/reTwKXVwbU2obpzrUlVOkxGA==
X-Received: by 2002:a05:6512:32c8:: with SMTP id f8mr626988lfg.222.1644572505098;
        Fri, 11 Feb 2022 01:41:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:22d1:: with SMTP id g17ls5031708lfu.2.gmail; Fri,
 11 Feb 2022 01:41:44 -0800 (PST)
X-Received: by 2002:a05:6512:15a9:: with SMTP id bp41mr690288lfb.374.1644572503998;
        Fri, 11 Feb 2022 01:41:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644572503; cv=none;
        d=google.com; s=arc-20160816;
        b=gjjBxpBqdBEP7PcynqMtY9iokUd8vd/6vaSbxyluXEQuzp61mAxqOx191R+/lLfsbY
         SaltmREhU9Sf9WvIxEo1KRVtba3CCabEEkxGjYjxGkeJY5yAw7xlpIuYj+NfitA3Y4+j
         pqXG7bJDpjV3/YH1gLHXhP63hRvMbTDkfqiKaDBW8s5hATeHsIczPFwLiVqkq7I0u3+/
         a1HJlwfMo2l4rO+Vx6FkWxnvBm3ns6Q8N0pKO3n3sHeteiEGad87k7cNLhepW1asz78l
         YGOJZUrjeymkvii+wCrwsRL7HO17w92oL+/cFnMdQ4NyLNajqp91WEFgxFeRgCx+rvFV
         Nf+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Yxy7zthPRWHub+MPiGJfuPkSoZH4U5JEJa8lsfSBR/o=;
        b=qKjiOxySl/d2NJ8Ia0E+H94nvFi4Dko3HFT+pPIyahhEpNxGQAkzyYSK/68RP6lci+
         1FJooTreWXrXybQS42CGEZVc3bjB73LROvNIFcQPhl2YuK4Qs0FUmhsYm2ONW/IpDk/4
         t+OLmjOtBs/L9a7xIxJb2XxBMNuo7FAiyJ1mKjnVKPikuzN0P6nS894RlMRVsB2DT/HC
         20dBH3jUHN/OklT3zGjezH/V3p3L9waM7bJK3U6sBu8z5GQIEvWfWYt2Ae78qZmma09J
         FdCRKLWMeYp1p3b+YZ6pLmJQOedJkVblAVKWn3bR8PxzLzkojrMgxutD/egLY30XStTR
         ZRBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=bMKbgW7a;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id v26si311224lfo.10.2022.02.11.01.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Feb 2022 01:41:43 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id p15so21594972ejc.7
        for <kasan-dev@googlegroups.com>; Fri, 11 Feb 2022 01:41:43 -0800 (PST)
X-Received: by 2002:a17:907:d0f:: with SMTP id gn15mr660915ejc.195.1644572503756;
        Fri, 11 Feb 2022 01:41:43 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:83e3:abbd:d188:2cc5])
        by smtp.gmail.com with ESMTPSA id e8sm603196ejl.68.2022.02.11.01.41.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Feb 2022 01:41:43 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v5 4/6] kasan: test: Use NULL macros
Date: Fri, 11 Feb 2022 10:41:31 +0100
Message-Id: <20220211094133.265066-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.1.265.g69c8d7142f-goog
In-Reply-To: <20220211094133.265066-1-ribalda@chromium.org>
References: <20220211094133.265066-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=bMKbgW7a;       spf=pass
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

Replace PTR_EQ checks with the more idiomatic and specific NULL macros.

Acked-by: Daniel Latypov <dlatypov@google.com>
Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 847cdbefab46..d680f46740b8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -385,7 +385,7 @@ static void krealloc_uaf(struct kunit *test)
 	kfree(ptr1);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ptr2 = krealloc(ptr1, size2, GFP_KERNEL));
-	KUNIT_ASSERT_PTR_EQ(test, (void *)ptr2, NULL);
+	KUNIT_ASSERT_NULL(test, ptr2);
 	KUNIT_EXPECT_KASAN_FAIL(test, *(volatile char *)ptr1);
 }
 
-- 
2.35.1.265.g69c8d7142f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220211094133.265066-4-ribalda%40chromium.org.
