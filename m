Return-Path: <kasan-dev+bncBAABBX5XT2KQMGQETUL7FYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BDD7549EE1
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 22:19:44 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id a4-20020a056402168400b0042dc5b94da6sf4637708edv.10
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Jun 2022 13:19:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655151584; cv=pass;
        d=google.com; s=arc-20160816;
        b=FXbyfClPvBgC+yP5xVbecHldhOmwyHzwYytpJumA8YHL69ZdVoLydW2A9c00LbuG2x
         bFP6i8LKTTr++rF02cBmppSz2XbgXfZ325U/Ga3x2o9xXucSmK4Px1i7lr+p5mT2YMiL
         faU6FklY7vW42VrlXJ7hAVDrgxyV/RevvxWAICDgJfv6PxqF2hk1de52EeTImJNXjpWI
         qs/qdy3CiH68NAn0PhkD447vTwPcAo272srjUKQGus/WRayKWGRdyoO5jBfG1d1hFROO
         GEYExSYm5xE2Xgx1pXMsZbquL4lVcxiRktIPuMiQaKqmur0pohEcO3UeKUWiyTNKxowk
         VK4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xkT4RUBWCMRZvX+7XPMEPH3+uBfxoCzNl/hRoHgn4cU=;
        b=m6ME3q4CnUcBTbikTAMLTn2NiDnMKeRtoUnJmGy4FwkYhL4PiZwTnGv35rUMislk9G
         +7U97KFcf4fI3YqCZcOGrEfCd8RTh/ofegqWykDVZyOCEb236lIJ5RpLgGCDqzxaX3Qf
         cUaE6XOTmaXs02t7ypJo410xDQe6iqNU9S8MAuhoGtgLuRUmH4yRL/7W+hykbI/7Rev/
         H1Grc4LKGviBgtN+GJoqZk3aNRAzdwE81udla8gmCus5Q9g5jnoV1rfho/RFtX3+JmLb
         lgDR0HS5dBzrPS/NUg+RAIVmZhg9QJlHNtpp1RI3noDWlj5672hcdN7qB367xJakmY/w
         OZhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tNdYTuep;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xkT4RUBWCMRZvX+7XPMEPH3+uBfxoCzNl/hRoHgn4cU=;
        b=DABPBlUsiecry7euvTFFZy4srkMM8D45qKvlrSepwTNJjFskJm/wnv8yyIc4K74Jq+
         YjrWquSRr9hh1242fVfMVjx5TqNfPF+2IvSJIEy9OOKDQy6uiD7TfkU2Bz+K95kIxq7g
         RAKL9zr1uRG6qmvTFbkTkhpwoEHgvqJK494fhrKcyUx5wn2xhBKUI2BuGdvKVdovRZP5
         CBHrZsQ23CGS00pSUl4mExfwAGAvI9Kr/BWq4/1cPa2baoKBkQ17m19r+TPtuObKtuAc
         C8i0g6YwIW7vAUZdo1XvcOT00wwNyLcmoZj03d8C+eA1ns8CyeG3uADaELLisllRK8Sw
         B0Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xkT4RUBWCMRZvX+7XPMEPH3+uBfxoCzNl/hRoHgn4cU=;
        b=GUMglIK5BlirLDldk3yvwbYJ7trsF4c1Y5UaLCmrFePwXqfsWptNBqL1tHCyWXX+Om
         c4hSA8bBMH3oB6RNmfdBgPRefaSL7dtqjgJyn/ABHlwUDAKGIWCv+x5bn9Xuvl6aGkmv
         OBo20g04MEre/P93heAvZ5JBYG5hnkGVqHJ/2DKHeh5IkuUXlaliIrSW3emzvdt32W4S
         3oggVGLeLuWx1s/Yv4ef6/eNnXzRhwALK0YG6g+qe8BbUHxhQYELvzRurGfUH06CFN1K
         mgkwGbtr29NA6/zmJITYhHJ8B0TSQXDNTBwn4cSM27TBIn4YLj4gFYd25XYqj0IrhYsT
         Z4kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/mfLIuSZ+L5yRr3hZU5QlCrzdN/J1jxCP3TBuMd1KTE9wKKBt1
	doF6llSNwcCHIQEZapYtz50=
X-Google-Smtp-Source: ABdhPJwPT/fPyAZ5bU7AfrwK+9OG2YS3nSUVH0rRw4HzW6wHYTrkZLPzzfnxnSluOQ+Q6oIvvibGVw==
X-Received: by 2002:a05:6402:350b:b0:42f:d079:647f with SMTP id b11-20020a056402350b00b0042fd079647fmr1684376edd.321.1655151584095;
        Mon, 13 Jun 2022 13:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:c19:b0:704:582e:9858 with SMTP id
 ga25-20020a1709070c1900b00704582e9858ls146567ejc.1.gmail; Mon, 13 Jun 2022
 13:19:43 -0700 (PDT)
X-Received: by 2002:a17:906:530b:b0:718:c256:3933 with SMTP id h11-20020a170906530b00b00718c2563933mr1365159ejo.142.1655151583496;
        Mon, 13 Jun 2022 13:19:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655151583; cv=none;
        d=google.com; s=arc-20160816;
        b=bfVU/Rl8KHOBluHEK6i3WaNkbUKZ5g1nYfzG6AlVmSglwkuvFQT2t1BTtDUwM43ovt
         bRtzmXnsf0/3ILUzTVVcdwL7AebMNRy9P7VX8ufPeJLrsz3Mp5K/dD7O6KkfK2c7p4DH
         25STboyWA10YmU8m2raIldB/2doBiu7n3A8o69YV7p7cQMLIlFTQgmCSWMam+UNz+sSp
         vq+6s6DNfPrhjqibAcyljtZ/O98nxfjbW5MRqgf7MxmXgSroFe0S32ij+f6AmgAmY3ls
         OIEKfoLQKx8xCU876XDOZbs0RuiUpK26XXnpvTJ+ofk348svWcARtRsRBjB80/y9RtKk
         TKdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=i8Ujjn8ODA+o6f5+82XskCVtNKiV5I0P+bzfQLYNt08=;
        b=TLig2/cq7FIawm+qMdsBed+PdHPF0/unyzk8mGFwGNgXZPgiGHD0qwpo80LLZx3VEL
         Uo/QXJYKFaqxpTZPvOwkoX/D+7G24aCP7ze/qvhQoUPJ+INaITlGHkG/TO/9lrUKo3q5
         n0hpUeOLqzsaoUUkT1zUgXHEgYn/vfw3A6YoPcuhf6fOAdVMvAxFPlhXfFM6MJVDk+oC
         D75rj7KuWfgCTeWXAKyUdGMnmHIxz6Zi9aAnjKd9P6Txsi2lj5kGNlrdXlCjlnw5TgD6
         c8rUMBao50C2bTQPtc2MQN6GnzQe/Rp6Hq7p0cB0Vgctk1reMDfuJ8ZqH2D6b6gqFk7+
         7r8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tNdYTuep;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id g22-20020a056402321600b0042b8a96e45asi258632eda.1.2022.06.13.13.19.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Jun 2022 13:19:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 24/32] kasan: move kasan_addr_to_slab to common.c
Date: Mon, 13 Jun 2022 22:14:15 +0200
Message-Id: <5ea6f55fb645405bb52cb15b8d30544ba3f189b0.1655150842.git.andreyknvl@google.com>
In-Reply-To: <cover.1655150842.git.andreyknvl@google.com>
References: <cover.1655150842.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tNdYTuep;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Move the definition of kasan_addr_to_slab() to the common KASAN code,
as this function is not only used by the reporting code.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 7 +++++++
 mm/kasan/report.c | 7 -------
 2 files changed, 7 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 519fd0b3040b..5d5b4cfae503 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -30,6 +30,13 @@
 #include "kasan.h"
 #include "../slab.h"
 
+struct slab *kasan_addr_to_slab(const void *addr)
+{
+	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
+		return virt_to_slab(addr);
+	return NULL;
+}
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 1dd6fc8a678f..ed8234516bab 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -207,13 +207,6 @@ struct page *kasan_addr_to_page(const void *addr)
 	return NULL;
 }
 
-struct slab *kasan_addr_to_slab(const void *addr)
-{
-	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
-		return virt_to_slab(addr);
-	return NULL;
-}
-
 static void describe_object_addr(struct kmem_cache *cache, void *object,
 				const void *addr)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5ea6f55fb645405bb52cb15b8d30544ba3f189b0.1655150842.git.andreyknvl%40google.com.
