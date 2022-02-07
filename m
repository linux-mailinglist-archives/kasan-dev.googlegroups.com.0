Return-Path: <kasan-dev+bncBDHK3V5WYIERBFMWQ2IAMGQEOG4WXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5641A4ACAF5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:11:50 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id u4-20020a2e8544000000b0023aeea9107dsf5003873ljj.21
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:11:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644268310; cv=pass;
        d=google.com; s=arc-20160816;
        b=aLIIt0jfOHOgFhx89fKndSSPc7VGjA3jS5SlwgjLz/ToacEgpdqZWVdsL+55/zIRWd
         e8fneAjS0ljqE2XlQ0OO4Pg5DEBQ/zMbyGeqWvVA5cp2luAB8WwBJJqdgmNhtAWLCRIq
         Z2rZ0GzPOoPJn2ER4xFXc3DqUIm8LNDYWvu3E0nHCw9yGFPVYKJXE24Gs4V4I2Gzr8Pl
         xAzyZj1bt/J+R30evsT7cJ+lTcvSj6XQd+fvjnuU3tgpvKmp/6X8vtF2kGz9YUxj6Nzj
         T1YA/s+uUOQMUtvI+Yeb1tiJ9cPLcvWqcGfyrR255iJrzkSUu4/QrWtVyVqmGO2gQc1m
         xXKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=L3+hu0bTYPH0PtFIYPwgCokXi51QvSyZcC4Gg8QGRPs=;
        b=iaGlVO+ben/sYZKsm3Ca2J6dEwwu6oJL4TgfKAXvwKxs0ItWZj3wyVbvRTcUVYvPdR
         AznKGq5tHdy9bpEvTQ7ytblUDDb7P4wI+T0X3Tgg/HFLOu7rAZ3eM9WbPLzGE9ofHUla
         qTKFY7kgb4WP1u4809CXBCTBY7eLF0Tk0qT79kpzY+VO27HAZnhsAj5mD1i3MmdLBVM8
         oqflCTcc31GUyGzI85yPMspzwp3BCa3bqpMSHrELZEay7Si1BiAquoOOyIx+nsK7RMIf
         5YIfMDB+O4oQlr/Ji+l1exQsM0lAk9K/wywBdReT5x+2t0koosErQfIWCc8dQny7EcAL
         sBjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=H6UeLb8y;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L3+hu0bTYPH0PtFIYPwgCokXi51QvSyZcC4Gg8QGRPs=;
        b=d48tt9dlXUPr9SKM1UN+kBweRPwyKqFNuLO4XITlTJJzxnSpA7+quoMuCzfzF+gv2y
         mfcOjhQEjT2NN4jhGTNwiTX5kEWwW42zE0v13nZhoo1gGYPj64Cne08kt5bh15w5yTJA
         W3tib/o1+WD2u/kWR8IfjqFAvKSs6TmfavmawC7BHBrgIdlcaj3sF2inrFOqyKkjP1WL
         9oQjv0Y44vwZMgIRs2+WgKmffqHla07vumtg9YeR3du58hTjbbXvv23WJSxYElrox+Wr
         EOcavdXg0TqBOvCJ4z4hC0SEAxUDf123Q1+NDZ4Kx1YeG/G/bc1/4rafqUJfqLB4Imu4
         t5iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L3+hu0bTYPH0PtFIYPwgCokXi51QvSyZcC4Gg8QGRPs=;
        b=DOZTu8W8kvve1yVLq5432J1UhmT5B8MeUc5wv1uXqq7DlS/lktj75E6y6x67eoZbpE
         GSpXl0YzFYcwPe6axGDdwaRgy4tgLz6kSy0Sdzqovf3VtCoFtO30mlPuDuFwl99vNMbY
         19PmWurKI4bRJp0ET8bZV/zmA6LQ+nM+2tO95b5rX8X77YYftA3NBOLHEeeQjolQ18Ku
         R0AWUed8qs3H8TMsECsTKCeTjayBwO9MLFlFQhxImggRBusPewsC2SLw9mNv/FcNaTCN
         innLO/qEmQbCvOMQgZXwhqKHt+xsZkU8C+2pAcraF5OcqOE95DDHXVg80g+qmPiKkk4N
         aTNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532fMlezXV1v1M1WH54+6idwvV2wpNIhPveXxljUuPW2J4QC+JRO
	Bhm73OqEIQ1fstLJh1GT8jc=
X-Google-Smtp-Source: ABdhPJzwh9sv2Ocx6XTubIkua3GBDOU6QeU0LqFYT5rh/EUhrz6UJtJzSG79OB0yVuSUDZuLoQFvEg==
X-Received: by 2002:a2e:a58a:: with SMTP id m10mr848504ljp.451.1644268309916;
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3ba6:: with SMTP id g38ls6465148lfv.3.gmail; Mon,
 07 Feb 2022 13:11:49 -0800 (PST)
X-Received: by 2002:a05:6512:150b:: with SMTP id bq11mr912468lfb.590.1644268309108;
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644268309; cv=none;
        d=google.com; s=arc-20160816;
        b=AyPbz79OxY5tkEGs/HX8eKapMaS9qBzLqMJybCMx2A4ViI6aIzww0NkMYNy0DJptdh
         qt3KFrrA48DpYYG8zhMyNixxy1X8rebO7la9TWzEHUtOeAeixcJ/MdbXcGEpHrte6DKW
         irE5nwXnwVwzZZ4ikEGszWBrGQryaK31D3D2seNELcXdIffglUUSt7VY0Bnm0cO070wA
         qosuyD/dU9r5K6CnK8RF66XUupPq2BF331DAwTulTiZEgCPAmHhffMh5u4Ga12Dx8gPe
         5LuzRthVzEmvRvqeiwc7vs2EkoAfcumZRFIaUHjvZg3QV5wJQCpUaJudUYOdPMzjyt3I
         Iscw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KXm+9Zz7kQqt2EFBwAfIC5XooSw7CB+RPRatZ+DKukY=;
        b=qC2N5np3/Vhby3Pl+o2iLOyAHFGSGxua7ze/TVOm7nLl5c3XZ20dUJnP3qu/AeISwd
         eVKIQGG1JL3vLaVvD4kcBJMEOEQ5kQsAz516welja9WsX9alpV3x8uSiRGI85LFgXKRP
         UhB1K/GStuEABINXXmtUxcTQQsMt4iWntQoblKJTLeMKCnp+chAkJBlEf/BRZSvdHllZ
         8MW/NNkf+O0vwKlDDv6bOVyeM0vxvidrM3DyMgL0+cciIrSivAb0dPOOtFp88T+Jarcw
         MEE1VrtV3bt+ZauXHK8/8WTgrVSFkwUub9nUqFMGal4zhJBNKHRaaZcvFU2XsptzPK1B
         uphA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=H6UeLb8y;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id z2si395591ljh.2.2022.02.07.13.11.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:11:49 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id s13so45824852ejy.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:11:49 -0800 (PST)
X-Received: by 2002:a17:907:3d92:: with SMTP id he18mr1176037ejc.597.1644268308882;
        Mon, 07 Feb 2022 13:11:48 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id z4sm4047239ejd.39.2022.02.07.13.11.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 13:11:48 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v3 4/6] kasan: test: Use NULL macros
Date: Mon,  7 Feb 2022 22:11:42 +0100
Message-Id: <20220207211144.1948690-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207211144.1948690-1-ribalda@chromium.org>
References: <20220207211144.1948690-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=H6UeLb8y;       spf=pass
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
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207211144.1948690-4-ribalda%40chromium.org.
