Return-Path: <kasan-dev+bncBAABBXOKQCUQMGQE7NMXHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C50A7BBB9F
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:55 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-40667ced6aesf180925e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605535; cv=pass;
        d=google.com; s=arc-20160816;
        b=0yISnItHLKkc8FEwTEKD4md9T3AFVThXfzPFfX4aCOGYnDuGlkkaEKkIHw62viFkoz
         6yUyDpHac/qU26sFUSfvqv6rAgyUfqU/5VF/FMH4HxZf+6UpaheYPbBKzGUoSQjyUmDK
         5x4v8iQ5Rx13nH8gxYZ4tWvKZgx3RAknYwZ0lAG7sXdR+0MHYUkFCawNvKTYz1RXbFdd
         h4ucPA91LcvsfvsNQBx/SbmfhFuNP1LMIHOwxDHW35NQ8/x3+aFGZZXZ8f+iMRQLHXMh
         +0oWau/O8jmQ7qgn95uT2xwALYiBOmSHgR/RN/HazJytPBN3O0SXLaEcB/iZ3Y4X6FzB
         6Gdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SzyTr6I5DqYHYH89D/aIZlHd+atPL8RNYLSfpKgGM5s=;
        fh=lnWC2s3YVhkirWx8kTqFekoOxXJ3q/uSKdwZdkIV6qE=;
        b=PvAvzudYt1oE0XeAjfOT51ODEiSo5FnKWejRQEKkBCUmGysVgZeRO23ZGQjz5e9UWx
         gLERdR7aiyKP4NN9183YbqwyljQiZawD4ImkYVXhFVjijDIr9dDLoYBVFVeZbwJHevau
         BrBtayG6bcoWG3tigLfSVl/xBCa3MskEAFehCjPVLMbUo41TQgGMUrBBO5am53GUKesa
         3quLgZ5i0inCMh/KrfLNOtIF1/kBjKEeyUHbLvJZFG80izGGP+89fYTAQ9Tv57FvGOzB
         veez4Xh5YBdfcJjfiZ6+H72xfLJdHsieHaZyGv6yREp5LVS5wkn5WMUgHsySNSESQv45
         uHAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L7U+Ncze;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605535; x=1697210335; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SzyTr6I5DqYHYH89D/aIZlHd+atPL8RNYLSfpKgGM5s=;
        b=Qm7pgDRPh/X9UWGZkw4dBjq49l12rhogXGEenX14NJCwBN6MQ4ONdrpdsRW1p9KOOp
         J6EkCsenZ/asUKChG1GYpD7Skw4JkAO3B/AmZEhYxS9LYnIi0aJbpzsGtoQaMMT93YsS
         w+j59umr1q8tAGVMdKlUQwDV9cO457W12XNi3yatSnKmTu2h/SVYs1uERM4/xU5bGNP2
         e15Vz4E0Wst4d7qPm1s8NY2IVKE4YhxoP9hEHC22kBPNmyIIvlixSj5SUNmcUU0s24Ko
         07+eEIhPI1U2AfLPHoRXalicKVA8VNGOkvgAbQAnG5Xg0g7vBRB1o2o15BpceqCgt6eZ
         mvxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605535; x=1697210335;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SzyTr6I5DqYHYH89D/aIZlHd+atPL8RNYLSfpKgGM5s=;
        b=cRy7DCNcLagGeBwDzP0LN8ThIimVa3t5G0w2QcVW8ya1q39YbsmnPX29FEMlFbsDLr
         ax5fgmeV55nnCNRc2udP/MXSdqHAsHdr+XQR5wADd2cfQi0mdJMzEwFUNdv/MCtoWmMq
         GqQX0ixFr82bLBhGae6eZj12/t9yIreWXrKKSIalo2wP7tctL9Pw2F4Yec7sZq8Q6gEA
         xfhSXh8adTY4V+ZyNmy+3gKihchyg2NW5PoY9sBN3vVMlOvizJ1GQV+0SwJYCUwPvnxN
         hQYTda+J4MzFVtGySVuVJiDCFhXNzg+JG3pSR41m/z4Vo2/0htwS4mP5uR8RXz/HnRSF
         umHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy5gEREHW6PjG7/bs52t2TvmH605shrFhrQ9xGqip4slu0D2BS1
	iqy9BJvleQq+lNDbdD8azLU=
X-Google-Smtp-Source: AGHT+IHgfFHw+rO9M9zHTEwEh6aurn0D95a4eU+e1l4qbgnYGPI0dhUD84ZF4RLiENuD5ytZmc/++g==
X-Received: by 2002:a05:600c:2182:b0:404:7462:1f87 with SMTP id e2-20020a05600c218200b0040474621f87mr175667wme.6.1696605533768;
        Fri, 06 Oct 2023 08:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5129:b0:3fe:e525:caee with SMTP id
 o41-20020a05600c512900b003fee525caeels42402wms.0.-pod-prod-04-eu; Fri, 06 Oct
 2023 08:18:52 -0700 (PDT)
X-Received: by 2002:a7b:c3d2:0:b0:405:75f0:fd31 with SMTP id t18-20020a7bc3d2000000b0040575f0fd31mr7270601wmj.31.1696605532348;
        Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605532; cv=none;
        d=google.com; s=arc-20160816;
        b=TDB7iRevZgpywRBmPe5e+Y3zV/WwqDmDnCNqfl28DZHiZ9aXavs5xMMLHp+ulYNirz
         SDGgPztkEY++rsicZsaxDOjGeo3t6Ncc2CNHyJ2bhYnkwExud4feeBFtVuysK26aJADA
         S5DU4dy+f6PAaQgom1aIqWsXC0mPlqfmR7cApkgmAqM0YBBklHHhjOE6TeCHy4t1itTQ
         kY7kZLiPOeL2nffhOsDMd7axUKlURNnUAcKoOnPjXVenDoRp3PWZkTbvZm3JprroecMR
         ZG36FZlMymJc131RRfc02H8hwpBGie+ly0fzdWXlO2+M0l+t+ZD8G2V/iZYoaaQKOpnq
         UNeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EIqAxPuP24RonUYv8PBGZm7b4Pl2lfOTG5ClA7Kyoqk=;
        fh=lnWC2s3YVhkirWx8kTqFekoOxXJ3q/uSKdwZdkIV6qE=;
        b=EoKb3uEmwLgYxETdbEnYHU1LLiLAcCw3bXZdaO+ux6zQL+g2G0SyvZCXR4gbv/T6Dg
         gIGPZlDPOvjLkvRH4+GcATjSdwjd2uruQEs1Fyqt+LGJMFssWz4xjVGEEYsOesRpVLm3
         Gq4I6J6fT8vWyoVPGDN4J98ghtViaBbZNErvFJYjcfXABIPzzZSgprlMKwJZf1tjLPk+
         uSBoyuoowdioLyxfIilcTGEgoMvXH1kcywq1vWq4e4+hi2IcqPD4hRdXINtuLWz1sbPG
         u7q+M0xx0h6rbh8Nw8vifznSlyhBVpD25fvWsIffOvuWbcLAfDhmeverYOuSZR5rl3e8
         1uVw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L7U+Ncze;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-202.mta0.migadu.com (out-202.mta0.migadu.com. [91.218.175.202])
        by gmr-mx.google.com with ESMTPS id bp30-20020a5d5a9e000000b003263a6f9a2csi81290wrb.8.2023.10.06.08.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202 as permitted sender) client-ip=91.218.175.202;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH 4/5] kasan: fix and update KUNIT_EXPECT_KASAN_FAIL comment
Date: Fri,  6 Oct 2023 17:18:45 +0200
Message-Id: <6fad6661e72c407450ae4b385c71bc4a7e1579cd.1696605143.git.andreyknvl@google.com>
In-Reply-To: <cover.1696605143.git.andreyknvl@google.com>
References: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L7U+Ncze;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.202
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Update the comment for KUNIT_EXPECT_KASAN_FAIL to describe the parameters
this macro accepts.

Also drop the mention of the "kasan_status" KUnit resource, as it no
longer exists.

Reported-by: kernel test robot <lkp@intel.com>
Closes: https://lore.kernel.org/oe-kbuild-all/202308171757.7V5YUcje-lkp@intel.com/
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan_test.c | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index c707d6c6e019..2030c7ff7de9 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -91,10 +91,11 @@ static void kasan_test_exit(struct kunit *test)
 }
 
 /**
- * KUNIT_EXPECT_KASAN_FAIL() - check that the executed expression produces a
- * KASAN report; causes a test failure otherwise. This relies on a KUnit
- * resource named "kasan_status". Do not use this name for KUnit resources
- * outside of KASAN tests.
+ * KUNIT_EXPECT_KASAN_FAIL - check that the executed expression produces a
+ * KASAN report; causes a KUnit test failure otherwise.
+ *
+ * @test: Currently executing KUnit test.
+ * @expression: Expression that must produce a KASAN report.
  *
  * For hardware tag-based KASAN, when a synchronous tag fault happens, tag
  * checking is auto-disabled. When this happens, this test handler reenables
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6fad6661e72c407450ae4b385c71bc4a7e1579cd.1696605143.git.andreyknvl%40google.com.
