Return-Path: <kasan-dev+bncBDHK3V5WYIERB26LQWIAMGQEE66NO6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3932F4AC89F
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 19:33:16 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id i8-20020a1c3b08000000b0037bb9f6feeesf3668196wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 10:33:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644258796; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dc6rwv38JKSfDCkUaiB6V/FwbR8oSD4srpwzbvOMHQJQ5aVYvrwJqjaVeLeqcuVLdh
         D3HlzFXUX8czcFYsMlFG4gWfEhWx3aXmvhjgwEGd6jQ4qyXFWcoGPO8EpXKenCeJUE4K
         OACyWxOOjoyJp+VOG1+4xkCGQzJekQlU3xPcVGtUtsj3lUgbGJeNTXW8nj/HSNAqWaXk
         6NnvuRkLOqjPrTsWPp1HdWOfXWPjdr8AN1WwY0P5F/WVbJz8QA4kOMtX7o6u4jvpFqG3
         se9j19M4PMXMoi+dM0Bjf4+Gvmx25Ej8BODmPxuxSKJbay/7+qvc2EjSd66F2/2SotPB
         YZhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GmxEpKXuc+AyZqOQazHEWTjhbW9I4Gryqmlb3BH0KBI=;
        b=Ebgsg7UQOXnsGMQj8xsse64OuiWFpho8MhzAd7mGxPaW3c4tX6NP85HcoD+t8wp+hC
         hd/GYtbJMseh54MZ6CqZ/V6P+oaheERcB0NPtGR1LC2RnLntcahSLi878/9SZNvgjtQY
         ctNV2DEGibyvHUUGhvMO+I7nXGZIGY3ZLrUjriAFB8KaczyGbpXOKoaeydwJXADGC1cZ
         5i3HH9e+9fXD4LNybax5jvAzTHmZf7gc/Vg3HSqLX0/nxq4fq2SRBwBEU/DQj5KkzUbj
         u+kEY+P9SENvMqeybNETWfHstcYYK1BmrcPCNmtd6P/yfTm4ICPbHt6YdLooGIayXsor
         4TGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=l4qyatFZ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GmxEpKXuc+AyZqOQazHEWTjhbW9I4Gryqmlb3BH0KBI=;
        b=ZmWh3WvQsT4fUdcYDu3ZkofOHJlHQEk6+z4RD+bbzqBTPOhFxoM7Q0NwSv2Kz/Eigv
         4/MrMM8tm254OADEHJZ0mZ8nOW5fP+NotkLHHaC8+dPyo5im+pEH0UcZsovk2VGVKNUY
         WnydgsoLo2Q//Bim2zPZ97yVb+DwCqqPdviS1JELmVMIaV01o6IqDoiptKRrp4hrx9nx
         DsUgjGH+WBIJBxnsu1xjXUj26bDqmnpusDn1asTGnpNYQTO2xWzLhyPKmUtDv96B/cjj
         PquBy0BeHrCfKmx7K1hWR9rHcP4GJ1Uc5uPoHaGYtdoMExiZ9D/l71a6zLMw8mkvyMzB
         kXCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GmxEpKXuc+AyZqOQazHEWTjhbW9I4Gryqmlb3BH0KBI=;
        b=QUG07KyrB1LKri1ommLsc8Sq31CJxXswBTxD4O9QYDHojnvuwYkgAgR6WPWuqYI+bQ
         lcd5R89K/NRdJGyRRBGsyWMG9fYaAPo04F3ksM/xVH+eQOVnxETrQvQvZm5ntImIL4iJ
         urlO3SeXy8Z12oz6jYoQG2kLl+vEOm0PaPdb7mwuvod8ib1qCbnQQbA7q8dTU2himZ31
         SywEl33r6kp0MzyvrPQkAj7InQ+K+mM4X3168SxDgS6lvDzNqRml+nU9zRYBDUQHVcSA
         cZDeyfutow8pcqSAG2zPEihSF66xd9DJLRLsMcRVVMyvsQCFEm1Wg9Ez15D8zdhvfKvO
         pAaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533XLkpIdRN7NRxOYWgkMNUhKRQu8bBjTnFd8rhj9xyCIrL5xi4b
	4ORb65CiH9Ikg0q6JU0X5+U=
X-Google-Smtp-Source: ABdhPJwSj1S8sAuP4hjlxGKJ/DviZTKk65OD5W1z4d+q/h+mL5HMXCZvI3VIoMlHqHJ5fM+J8T4LOA==
X-Received: by 2002:a1c:4641:: with SMTP id t62mr202509wma.12.1644258795931;
        Mon, 07 Feb 2022 10:33:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:9793:: with SMTP id s19ls1509wrb.2.gmail; Mon, 07 Feb
 2022 10:33:14 -0800 (PST)
X-Received: by 2002:adf:a49b:: with SMTP id g27mr164691wrb.20.1644258794793;
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644258794; cv=none;
        d=google.com; s=arc-20160816;
        b=Z+4lr7mOU1cFE4DsohbDaMQ09PRxZDDb4JLWt3GzBRoOndro+bRGrt5TX5Lodrs0wb
         UV/R5Q2NFn+X7tM8csPNNWjgXpsPK6CZVC4ClvaRSphMFfvaJ71Z5wzgyx5mchdRJfWx
         nO4jK8U2QaSM2S7nmchVuuNoeBcoVUj+DYSlvmUwCckDPQZ/Vq/UzGc9oP9rnkActhac
         R9gZQv14VnBZsFPQoKrwzrJYT6Evi8jkL3F41Zl9YgTy+oiDricXEHONhDcEU+JBPDYE
         huFRJVtk0EBMXA5+onqTkyqQMtQ3hQ4T0bcbBSRpH+l6bczwg6u2e3+nIFA+FJMQg5Pu
         NCMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sQV3FF5mFgBVe7Tg/aDZitfy1ByGgWInZOonbxaNvNg=;
        b=QAdCrO+9EPcEz8JYyGwB2d9cGA/QeoH8eFN3gHkFVxu9vBu1Ov6QP++ajI5cE15hop
         VguYjU2a0BP/Vzu13mx759AulajGQ92pzswd2qiwKHd1oBeG2Ro6ajZrb5OY+5MT4k8t
         SLgGRnadHHyyzZG+IdfDAmNP7O6nbzcM8+cCc0tVy2bPmdfnAP2pkcUPGg5wJMBErAYL
         g9BsWVt/mvZByD8wWpPt329ftYk/c53HMKFPtuts7DVmxc1QHbPSk/bZUSmicESap8w2
         aEAtNXtRw30PxsotHRQjvc5uW0b1uFmHFFGreZW2Fs5jCFnJyi0yNSDRFzNFpNi0c7bE
         1sDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=l4qyatFZ;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x633.google.com (mail-ej1-x633.google.com. [2a00:1450:4864:20::633])
        by gmr-mx.google.com with ESMTPS id az22si466918wrb.5.2022.02.07.10.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633 as permitted sender) client-ip=2a00:1450:4864:20::633;
Received: by mail-ej1-x633.google.com with SMTP id s21so16513530ejx.12
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 10:33:14 -0800 (PST)
X-Received: by 2002:a17:906:5a5c:: with SMTP id my28mr775731ejc.54.1644258794460;
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
Received: from alco.lan (80.71.134.83.ipv4.parknet.dk. [80.71.134.83])
        by smtp.gmail.com with ESMTPSA id k15sm3045173eji.64.2022.02.07.10.33.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Feb 2022 10:33:14 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH 6/6] apparmor: test: Use NULL macros
Date: Mon,  7 Feb 2022 19:33:08 +0100
Message-Id: <20220207183308.1829495-6-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220207183308.1829495-1-ribalda@chromium.org>
References: <20220207183308.1829495-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=l4qyatFZ;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::633
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
2.35.0.263.gb82422642f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220207183308.1829495-6-ribalda%40chromium.org.
