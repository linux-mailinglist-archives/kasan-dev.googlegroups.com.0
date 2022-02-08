Return-Path: <kasan-dev+bncBDHK3V5WYIERB3FPRGIAMGQENHIIE7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5708D4AD7BB
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 12:45:49 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id o3-20020a2ebd83000000b002446a7310a1sf518107ljq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 03:45:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644320749; cv=pass;
        d=google.com; s=arc-20160816;
        b=K2Tmb8vc1s6QJ5E6T2bZui1UBqHnaBPosCYq5Qjg7aKi7/vq8Njen/kysEy24hFUsg
         lk4m3dbYq7HEmFLBZWky9kWH5IP9ncR3VkYQwEtqsuVWvlCAqBnxnMnBNkBKnyor8NYl
         CePGbpqhDmmMBmm/Vd+aU68s5k+FHsUr3+0S09dkCHsdGRjaLVAvYkliH6SWCV57VTRE
         SyN38Cp2GaYVBCXnLeNgWK0f8aRMw7I51EOa77Z0qb7WYTX3B0tmNZ8+TXu+85qbFGv6
         wjReFebOvdTXE3D/2c8JjncUQEWk8Sy48UWzr7PCQwoEwgmMNDC6EAueFf3jVnN8cgf8
         +giQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uwX6UTlqKK+PQuEKrjc92Uu298shcu+9okQG4hZ7KAE=;
        b=RGvVBKjycD/l/7uppIukD3afBgqSVgY6SLTFQdKM9d3FqKWkI4v14T0bZWtcJXL9gw
         9MuhhLOOujVFbL7dd6aDsarehN2sKxJIsuF66ZDlbuFdQUTEulQuTN+X5gWtdY1HkOGg
         XL5lYafhQKZNhzR5v9VLsL4uLmWH8c3+hSuJsFMfKrZj40Ack/fAkGbuCY2Ce4BKJw6W
         8LBMTxfr2TriG1meDbp4HcSGxS0RiWZ7hvMi05HFfg8Kc6ivD+M50o1Fx0F3GC4/521S
         ZYayZZPgp61W67hbaQiwbrsZjyA6H8RAVKU+fMEboIO2CcHZQb01k5kr+U9NrQyPPMmP
         f9qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mBet+b8u;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uwX6UTlqKK+PQuEKrjc92Uu298shcu+9okQG4hZ7KAE=;
        b=YeUdnoWMwytis7WTT9+U5d/2iTQbeKqQqMdiq9jW5alahfdJuiQccxh4/mY+q+Qas1
         68RqNwTdDPbkpqFZVWBAZ7JfwDfWJLMzJxMYiJzGOvDyBAVMKZUVkAJALlQDjnVitXjw
         fLM0U/aWT0ijXhyt6mLRzedX0AFjlCHcjT/mbQeAf9uls+7sasagP8mBtNeMsCut+pf6
         gRT6UGC8Ca6giRSaAF3DL5AHyt2o/f23XI8wWHpOy3iYFVB99dhPyXpUTEYt9oQPhoam
         LkfjPhzT5Sf+M5tWNNsOgY9c14RbyHBnq9uhdYEgmP0+a/S5BPurBA49HOZeGr/TA3nG
         jsLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uwX6UTlqKK+PQuEKrjc92Uu298shcu+9okQG4hZ7KAE=;
        b=fqOWr3MFDvOHNUbbIHsRRrUNt0HhtTh3URdRxMhWxFDgQo9PYLVF8S8mzT2pUG5mHW
         OdMKguBBt+mFH3DtJd1BJebAyZZkC8TlHAp4aKBttocy8gD5WFN3ip1gUE9EyCgixxoc
         88LwNGVCY6QgScCT58aCnhXz9e/TiSd0w4ZVzvwctn5mFFFhZaLXzkwduVemYimenPmS
         +uKm+v8e+4cJfCXHDSw9EbbmaB0hWopSrKHpsDM5VqUI14JJztzaAt/qteRNXouNw5nb
         HVOjSFqqM0UKkL+8HJYA2L2d7KcfY9DvdOD3thNqDmOUBnAL3blANzU3wFYptpzvZ5N8
         RAYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530joKUmUP3D75C71mYAQgIewcWtMH61A0QSwm98rp2oHIGvx86g
	hGp1HBf5KKJZs+UNyb2KoA0=
X-Google-Smtp-Source: ABdhPJyKDDLwWPK/7Lw1wy8Mc+/44Cm/4xBQiENIpi6PStf7tfypXw5rRYd2A0CDqU94B51qrTYPWA==
X-Received: by 2002:a2e:bc09:: with SMTP id b9mr2617811ljf.24.1644320748769;
        Tue, 08 Feb 2022 03:45:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1599:: with SMTP id bp25ls7710478lfb.0.gmail; Tue,
 08 Feb 2022 03:45:47 -0800 (PST)
X-Received: by 2002:a05:6512:3fa0:: with SMTP id x32mr229215lfa.681.1644320747739;
        Tue, 08 Feb 2022 03:45:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644320747; cv=none;
        d=google.com; s=arc-20160816;
        b=WI5v563t5+dLzeq6MFJdfL8tsJLTQJ0ndKNCR6B71VQd+kekjfeQYdlHWHlap7PlGA
         ZmhZZhc57+xj73YFkH79YhhggjMAwC7g6IT6FHdeEyM07gZCTwps0Za8rYzUfTnNQnx/
         +r2qME+VtSSHdma79gTik0HxEj5iL+ykOh/jlzI4je/2MQUPd/Gr9UyMCp2VguOT79JK
         +5hjr6RKC8uiU54Dd4oiWbGyUxVQ50ophIf0dnKipM44qHz7ftE9ZyLRjwbThDk4hajb
         M6+3UYps0kvUUAZPwfqi8C/ffCm8YatyQen79TElT5ES2yjMLj9lt9mid8xhhVctGO6F
         It0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ora2gAZjzTFWwGBCGckRLz708H124CL8azMV0mFmXpM=;
        b=wxfgzyuwIP7Y8tAuQ+4zQhf/+68uou4pED+e2nE0J51hWMlODMsDIKLPoPXySN6HSv
         RT32wa1zLPKxtOV53O02kNpG+W1xPBwbnBJ5au+ySxZD+I/z9GFJk1+4APAJpdbGtwq/
         CYz7orzWE3ef8JYa7edDK7Go2WR3JAWpPr4vTno7pze8I/4EgDsC2UVjE0mXPr8jEzY4
         xo8WUDTAtF0vnRYYOVP3XYmctfMhRMehhNodoBU6RJfAmXRsf5KZ+Kd50Jw7RcxgSusH
         m0Po+q5LquaScRnDt1ZbFIjhBRfEf2GDmwra861Ktf5OgtyHsjZmOUOp96Q1LoiLLBYE
         QqzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=mBet+b8u;
       spf=pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=ribalda@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id n28si61463lfq.9.2022.02.08.03.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Feb 2022 03:45:47 -0800 (PST)
Received-SPF: pass (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id d10so51547207eje.10
        for <kasan-dev@googlegroups.com>; Tue, 08 Feb 2022 03:45:47 -0800 (PST)
X-Received: by 2002:a17:907:7212:: with SMTP id dr18mr3513058ejc.187.1644320747443;
        Tue, 08 Feb 2022 03:45:47 -0800 (PST)
Received: from alco.corp.google.com ([2620:0:1059:10:5d0f:d242:ddbf:a8a6])
        by smtp.gmail.com with ESMTPSA id y2sm4151902edt.54.2022.02.08.03.45.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Feb 2022 03:45:47 -0800 (PST)
From: Ricardo Ribalda <ribalda@chromium.org>
To: kunit-dev@googlegroups.com,
	kasan-dev@googlegroups.com,
	linux-kselftest@vger.kernel.org,
	Brendan Higgins <brendanhiggins@google.com>,
	Mika Westerberg <mika.westerberg@linux.intel.com>,
	Daniel Latypov <dlatypov@google.com>
Cc: Ricardo Ribalda <ribalda@chromium.org>
Subject: [PATCH v4 4/6] kasan: test: Use NULL macros
Date: Tue,  8 Feb 2022 12:45:39 +0100
Message-Id: <20220208114541.2046909-4-ribalda@chromium.org>
X-Mailer: git-send-email 2.35.0.263.gb82422642f-goog
In-Reply-To: <20220208114541.2046909-1-ribalda@chromium.org>
References: <20220208114541.2046909-1-ribalda@chromium.org>
MIME-Version: 1.0
X-Original-Sender: ribalda@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=mBet+b8u;       spf=pass
 (google.com: domain of ribalda@chromium.org designates 2a00:1450:4864:20::636
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

Reviewed-by: Daniel Latypov <dlatypov@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220208114541.2046909-4-ribalda%40chromium.org.
