Return-Path: <kasan-dev+bncBDHK3V5WYIERB2WLQWIAMGQE7GBPURI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC3784AC89D
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:14 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id k22-20020a2e8896000000b0023f97d5d855sf4809418lji.12
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258794; cv=pass;
        d=google.com; s=arc-20160816;
        b=w8FsAvDf+oJ99Dm2MQyeSv5phQbZhCUrhrbkg3jhV8kB/Sq0sidyZIvPqEj8kA/dQQ
         hlBrFMAGLStE5snoNn3/GzFjdjNpqn31pXyKg6xRWBgygltHmhUxzTHp0MhKnrSkaB4l
         K2A1NVarJTdLypZlcdfockbmlUP4PX8QIjdnyjF3fwk2c8vcn0tv610BsV0fyby6n6Ef
         NbsRix1kUsQ9dkIFdPhwf6RrRC/Mh1Ue7i9N/PiUzARIwvjos4nhw7tKTZQzOkDlLaim
         hqpArphUss6deglL7IIxITt09yu8ur4U5OKh9X4bAbLTlJd+R74WpgnoGL4g9hKnTo/i
         bb8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=feVuFbFnce2KiguG0JYtyah8BEX1JZNA0Dbo0YM1P3g=;
        b=h5Tk0giy3d69Guimf1a6p7dA+0e2D5M/Mqeru8mDM1wlYsKCYlCParG3DBp+Ye8nM6
         Ge5wlKsltRgz5CVfq7H/rLtXoy5Sxuvk8uGg/LjlwMxq3l4UvSmDl56EZlntoriUWOv+
         bhTHLqFIRfENtb6WBFmUNc50bhxf3nC2oKjgtYQnvkX7ooOWNIeNcy9KSC5wyuh4jVYK
         BWb00k5brUeGJc87g1WGtAwLJSkkSI7X1qjimigBj+CCJdL5vBdNAii1B8dCoeNYV+li
         PbObV7ipBkiX4+wF02njMaXG2ORmCrWGHmHeSaruj9XH6zLLUTzIDe8YgSN39GgSp+xT
         Z48A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ib7OInvn;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=feVuFbFnce2KiguG0JYtyah8BEX1JZNA0Dbo0YM1P3g=;
        b=iY0u56jM2PBMWPF5W4mYo92M2wUN58Pkukumdtt9/wpUOuyA1Gr1coeDJEjIJa6VdJ
         k7K24Y1C9Hu8l7jTB/x3w/kx8rIg7t64bbrfxboIiVpT1JvZXaeFgCFr9+rV2sfT+plS
         zsPKyFEjws7y9LAFjUXiE6FxWiqng5uxkzCH0PIHsh7RLuWzFHD9pa4nkdvGW81fWp2V
         KfFRSioMGHnd0iHldRavELbxAFq8rtEKlqf6tFjRaJ0sJNZHDp+9VgoT1Qmi1Lysx2rD
         leN7fS/usOPBokXxI9ig1yjdTPr2yhH/3nb/ZsnTViImRszLr5bwAaz5fnytDsKcMbuy
         thYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=feVuFbFnce2KiguG0JYtyah8BEX1JZNA0Dbo0YM1P3g=;
        b=oDSHe8VSJ/f4KftnBxsjNA4P/LaULnyX5KfNNdUfFex7Ynec36NT4jtXxRGzywdRll
         56h6TkJR+ioAe19SMnr2s0J52cnjAtDrXhwWp2z3tdjrye2khHTTgVnRfEohsICCJ0Zi
         mp9KcFfZS+Pu0m4zHY3TxGYWeVtAE778RYpt0WAOH0lEwM9EgCzgG6V7l5L227cxlNVQ
         6VIwRUTnNe8wU7eO9tffZkHS46WMUYsDFXfzuCG3lXKL9bZV37W/JWyPouRKmPRCmcEQ
         pJdFt0cdAJjDSFAJP/u9qmnN2W14avGs2OtaoPcmC05CTeTdIRFuyxmIZy1VZDuquHwo
         1ECw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531czf6HdkmO4Scqd38jNIaRraY+NpKmZIdBKoEVpNJIYeifEgN0
	VaARuwx4PkyTzQsbyGW9GL0=
X-Google-Smtp-Source: ABdhPJwBvSeu8NJO+nWwpGYRyTfMWuJbKEz4kfV91Ux4UOk9DnpCYdLBGKINmeNlApl6huecwaMFeQ==
X-Received: by 2002:a2e:7f10:: with SMTP id a16mr496096ljd.48.1644258794466;
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls6217747lfr.1.gmail; Mon, 07 Feb
 2022 10:33:13 -0800 (PST)
X-Received: by 2002:ac2:46ce:: with SMTP id p14mr540100lfo.496.1644258793507;
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258793; cv=none;
        d=google.com; s=arc-20160816;
        b=zgcpd4GHML9TpsuhqNiepbyHHGmohHkXmSD939cw8+nbRIf9GWo9SyWAlU3opcWBGG
         tSLIxzB+/c+jgq4H8ZgQnkShcChhpowI0bODoJv5kOkmYCgNBCXo/NZ7t7BQcr1nnmjS
         vsQHBjBDWHDl3pnWuUoDsS09XE4uXHtbulOGI6GHwms65iNkYq0fkZe+LEDKRX5N07PD
         yQjGvlgsB7KZpy8E0RfNGH3lyyOd5Lyh4n5CXBAcYsRqchlXimINpWz7VcW4HS+4eIlu
         f5nNxB2zZIXMoZ1aMeams3Wt9KLl452dioWBBSehXE2Dkp999cBrjWWKNKjDNq0l8CQf
         23AQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=elxmE3zs5g2Y4x1nlwNY1X/XBfQO0VsIOMiC0QvhdRs=;
        b=sYkt2kzpdkTXN+jLSKSuBphwd8lb7kJuUNzcxk/fmcc+SGZ39kKbv5zxL2KKKRdbyk
         uSCODh1pzRqsmCf1Vgus8zhYz+Bp4Cf9xNJ1g2iQynabVM5PH1c6/9VKjmzf+yw5IOFM
         q87z7m4C3P9Mf608UOqKLZl6Ck9TpxyMi5TBdDA0cwjHO+xVCQDJFhNwjJbywiFAmfkR
         iDLBAPIHI+fScLY0x0VJtFEnhcuTnYucLcPWqHks2qEHJ495SyDdDETZibD6HE+TQ5NL
         yMr8+L1Hw8LBHGbCMvSPf0hzSyWcYPJ89GDto+40Eip/C5ly8yQqL9vNQexejz/oRaZ4
         lhmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ib7OInvn;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id a6si547681lji.0.2022.02.07.10.33.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id ka4so44589758ejc.11
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:13 -0800 (PST)
X-Received: by 2002:a17:906:9756:: with SMTP id o22mr807187ejy.448.1644258793323;
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:13 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 4/6] kasan: test: Use NULL macros
Date: Mon,  7 Feb 2022 19:33:06 +0100
Message-Id: <20220207183308.1829495-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
References: <20220207183308.1829495-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ib7OInvn;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634
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

Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 26a5c9007653..ae15f7bf7313 100644
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
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-4-ribalda%40chromium.org.
