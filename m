Return-Path: <kasan-dev+bncBAABBLPN2SEAMGQE27YQW7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 263413EA6F1
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:56:46 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id l12-20020a2e834c0000b02901b3aafdf5eesf2070497ljh.17
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:56:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780205; cv=pass;
        d=google.com; s=arc-20160816;
        b=cee8x0hNwFurYP092VIAuuhDbkBxYDAQOchSEuoWlouxA7U9r0BsjfEgLDzVHFp+lQ
         CBf9LPDwSvHc6+6bN37u2a5mFdRg5WLiuh9QbKkF2Rmo4EsUQ7GIexBpbbrd39u6mrbB
         BMKADcRU2I4QUBo3LKItNTJYHCyLhAYp5iWqEp3wjjiagbL3FEGg5DVPO08XB8hvzmWq
         gZYcCOEtjVn9viAAfdfAKd11HCTEQl7rZLMuLo6l6uupEiBxqEuSseNGmj+pYXc3AHaQ
         RF2e8Znh6vOIOoZ1pjK+QB8UDqhyY1M4nw0BhyL4v6T5Y3FqZF4ttI3qvVWeLMi48tQX
         84/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rT3zjfa5DEkzqj1qt88cIdPWe2K2qrjh349wGkhYH84=;
        b=vpndA65ahyWPDOfUMgHbfofjkP5uIaV6QeiHxGB7Ac5xztb9Y+dIqo27XfGBvx+hgH
         JlxrDliqQaobWSf12hcMyAIEPm8npEJI51H19LAU/fwT52A984mdK8dwkmxIw5VZb8kJ
         6ejqN6GBggc85Vh16nwEnvx0ucn+9KKB790WSj3uWskajZ2zIvn5jXPfWckcZ0yMPSVA
         MZTqH2ZUnCQF4HoQNg+alAI6VUWdWLb5OPKLOIN8IiRbDjinL6FSnIGGSFKAIYFDCFKN
         mG+3RNhBuJ+WnPaj8QwUtmBNyGUfTakKzV8q38qEdU6/FWv/7j+mlphj5MzgI8vetlKf
         8ibQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="qyNj2/4L";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rT3zjfa5DEkzqj1qt88cIdPWe2K2qrjh349wGkhYH84=;
        b=UbKE4crNA6G08h19oqPM2WS1BRZPORqBlKTtFRZhKYENyRTVPXUljR9pQGN+A+i01f
         9VOOFEqEQJXryyzXQSnRvwlpqpK+RmZNjZPDhKGB+MZoNGSXTlv+XbalyO2+P6Skf1cM
         BB8bhZza/JcVmsdtN4o7SKPS1OI6Javo+KdMNyUrgqiLxu6Cb6uTjRFadCedd99VGquw
         v7uEM1nYeuXovT7Q4XzxCCki+x47Mjz7VLksaWwks+QP1sLCUAqNHI9ZhtbDmlZwKvmY
         nE+bwI9RrQRdyLCJbqCXL//L97P6rEaFC9K9Fve8jKD1LxrkSrf0SyEHPAG0YkFr/z+s
         6Gdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rT3zjfa5DEkzqj1qt88cIdPWe2K2qrjh349wGkhYH84=;
        b=N3tUoyEMpxij2fAclZXH9bFaePdOQbf3gJ8FwUn3Tc+7vwYkJT7u8f8zFckV5vdR6B
         obcSDVM0sYYZbMLmSTx2AWXMuupiJnHgj1sY03jyR7D8Cvql11XmGpgv2Gl9hus9JBZ2
         Cqb5ZWkz1ldIiqS3ddbDWLbx/ckpRZna1XsqJjT7E5Ms25uvcxok1uT6DUdZVwpLVZgw
         67Q1wVReyNovkkU1pzPZGSl2TfOwvagBq4ylORkFakA0jOoXlvK48JOSMvsZso8fiB/6
         R4GW3LklIy3WdtUv+PAfPDqVHmXO1n8BRqWtjlRDgWUptMkDOXy+Hjqojgl1hLc1g94K
         9a4A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ekM0SaDmihWP39SBNS4omtWrLTYs0DkqFnFuZKYx5Af3iqwqC
	eKc8j3fmy6mcSJCYPWq5nZU=
X-Google-Smtp-Source: ABdhPJzF+4ma+TRzjDVeJcHKvOjJQV+YeTOD6EkzhvGPPYyFfdWgSzEbgpmX8anOwNMBSii8Nk9iyQ==
X-Received: by 2002:a19:e214:: with SMTP id z20mr2850708lfg.37.1628780205750;
        Thu, 12 Aug 2021 07:56:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3210:: with SMTP id y16ls1043199ljy.7.gmail; Thu, 12 Aug
 2021 07:56:44 -0700 (PDT)
X-Received: by 2002:a2e:9d84:: with SMTP id c4mr3062087ljj.465.1628780204750;
        Thu, 12 Aug 2021 07:56:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780204; cv=none;
        d=google.com; s=arc-20160816;
        b=CGwSV33zY85yOkgjY/GS7tnRPZp5Y6YFH4AnCpTUvZFyzmzneHdQ98DKd/BZjjms7e
         q2MkjPPqhOVbQUJduAfOOuvmQfpEjJU8EDh8F94T8frj1+guYzks5nCQ2Lb5Wv8iZdVZ
         XrIIDS7G8i9MtnEaMbZPKedw2p5KB0RYrt44uloYdnjIFuZQ0AqGuUH2fyUetn5KBcCn
         uzGlJLvTWxPywNEGwlFIIrqFstf0U4NDr9YgZ/bqH/n29Eqp+laWYEfE2dZ1pRa0iFmz
         801o6rMBRt0infP591qKm7T8GXhENmMD7e02IY8x6T5c4rfUuyFTlD5eAsPYq+aXiVx0
         qdUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wLYmxDSn8yRlvCuXwA7dhNRH5OHfdPThVfS1yzZfw8s=;
        b=fVSCOmtPM4Vag3TIO1RYINhuTp8+F2VlIU/nVrNWKM/yMa2eY1nWVWEKGtokdVzNYc
         61apcGuhG9kLLO6OpEljIpEsaDteQirQUL7gJLGwqWjBsnGRPwlANkR/AztxVeBm/jou
         WUOs5GnUc1wwEc/NwWgahz5mhg7BpMvvBKUJjC8jtMtsAsG2FV943zIsinBNZkd+BQh9
         cS5x4gnGBPX/AR/X3IXZjfWvhz/T9N//g4NJ1xOGK7hhI9f6cA7+pp9Kg2L6HVJsZc80
         roDuDGxwkHIxT2o+2aZ9uzj/IKWiAdk4UdI2/5X3kXXDTawlUAfDvfVKexnIJzajbpJr
         UBbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="qyNj2/4L";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id g15si127485lfu.1.2021.08.12.07.56.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:56:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 6/8] kasan: test: clean up ksize_uaf
Date: Thu, 12 Aug 2021 16:56:41 +0200
Message-Id: <a1fc34faca4650f4a6e4dfb3f8d8d82c82eb953a.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="qyNj2/4L";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@gmail.com>

Some KASAN tests use global variables to store function returns values
so that the compiler doesn't optimize away these functions.

ksize_uaf() doesn't call any functions, so it doesn't need to use
kasan_int_result. Use volatile accesses instead, to be consistent with
other similar tests.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 1dcba6dbfc97..30f2cde96e81 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -737,8 +737,8 @@ static void ksize_uaf(struct kunit *test)
 	kfree(ptr);
 
 	KUNIT_EXPECT_KASAN_FAIL(test, ksize(ptr));
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *ptr);
-	KUNIT_EXPECT_KASAN_FAIL(test, kasan_int_result = *(ptr + size));
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[0]);
+	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[size]);
 }
 
 static void kasan_stack_oob(struct kunit *test)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a1fc34faca4650f4a6e4dfb3f8d8d82c82eb953a.1628779805.git.andreyknvl%40gmail.com.
