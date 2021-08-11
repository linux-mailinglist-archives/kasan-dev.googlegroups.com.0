Return-Path: <kasan-dev+bncBAABBQOK2CEAMGQEVM3Y3NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 187ED3E98C4
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:30:10 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id e21-20020a05600c4b95b029025b007a168dsf2396372wmp.4
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:30:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628710209; cv=pass;
        d=google.com; s=arc-20160816;
        b=q52v+Il+TbDty7N1C1lbtPOXUAHrY0BEa8wsAFdJ43L01CSPUAN640A5ocpL1f/xel
         KgAfbmQ5JDwYPTSUu+Lq46x8+8L2+hrtF8eT+S7w5h63fOhzGjMuIkXRhNK7BbgxBwSR
         y+tmePekyQIb6xTfpRMJV/dza2rNdpRQZWmH8BbM/S3CXjGVU89I2NFapAhYPF6DG0d4
         6ExS6S6aGxR0yJSgchp0Al9LkA9YeIi9abHz158Asyld/NZze5PS0KqL0m28MxoB1HtA
         TvoVqA535DPHILYo7MPPQe4EXMyVsyBdoir1cfuvYQ5/oOl7gRzKzWsK6qzfrgkt2OUI
         bfLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=m7uuQQw8NWSSKZkSQ+lTIiSNQybXqXXRkZ8LlctNOdQ=;
        b=SgueMe3Z45hrNn8TK7tW37ic+2xBP9jux/8PjK4PXHnPrUhnzF7XJqaOl0G7zf8ES5
         DhTJXslpKexd8iQxQgkQBMsx9aKIGoPENGG6gbV5vB/rk938Hxq/3UUYEDSx1YxmYf+q
         X82xmta2HaH1YRLXfmfJtJ2hyOWItWPWUXId7yRoLivOMjY83YdYoHSDQsg2/wu5on/l
         /rldrgCVLwBqyEc0hs8nf1V9EKz1Bb8ndcXqJOUTtp9/pByW7MwG0VAufibzzCbWweBd
         JN5rruqpuC0uKmTFAdnPOBO6bNWJRGR86sJj4qonpL3gX1rDNrDlYqtCbXTrJTOyzdME
         4tLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pSu9Edxg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7uuQQw8NWSSKZkSQ+lTIiSNQybXqXXRkZ8LlctNOdQ=;
        b=rS87OLgmIAwUX5qgwiZmdLWUbdcKshiB0kf9g2rlMfSqFovWIx68HSAMcX7eN5/oEI
         6s5vJ1wMBNhRU8iUbHUOqHcHVowManqLQbIPliL/85t0Ro9KzFxBgfg+73l04XOweTpe
         mSONCJ/uqRnm7acTPplSJaj80kqS18iS/p+aStJwa2xvBjmA2BMC7yA5LCmjP53FplpD
         n7kB5APZQA6D1ECVz6W1XcyIwHqYTzT3qItRj806fxsAf+jiQKt99qK3sR6nYWChiKXD
         VKQnPJYseAXlE0quVsIACJyoJGcNZU5uWde9zBDxOReFG1cpnhkbGqDvFwVWfyCIsv7Q
         JbLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7uuQQw8NWSSKZkSQ+lTIiSNQybXqXXRkZ8LlctNOdQ=;
        b=ZBReI/IC9XVSvenefysHZD9+7nvrdb1XSkUCU4ojXttihV1vkhWe/nVerb0DyOjWLS
         gcdqp9LwF/c66pIHkwVKQppaSMX1ruPvH3lLDNmE9nG0r/JrDuhDa0o3psg5xwrH45Er
         grYMaGJ07sWBEuslwZu+WOgZuSeEm08BydJALnZjpTh/CbLCHFUXs+kIALj0RNzNWE02
         IrE+mCTXHhW56GoRvxusgbMOzbJoQjzDD/EoEVVfX5GWL1XczidFq51WWDGILPCkGqFN
         zfKOCcQjzYtdZX3phsWwuwEY7UtAUwBKdf945SM40XLMD5ol/9rS1iHIh3JwXtpcbwHP
         rMWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DNF/BbRAHBzPtimaA4NoaZPv4I2B0Y9CZTbYWK7lGYsM3FFt2
	W1z86Sy+cciu1J7qE+GwqeM=
X-Google-Smtp-Source: ABdhPJxJaJDa0oKR9rPAj+KCkN+M5SjxuVfNSmuCiq+NVicoH9Ez5h/hiPeviUCdreakjmwFa6ipwQ==
X-Received: by 2002:adf:9c8b:: with SMTP id d11mr55992wre.43.1628710209902;
        Wed, 11 Aug 2021 12:30:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6251:: with SMTP id m17ls2036056wrv.1.gmail; Wed, 11 Aug
 2021 12:30:09 -0700 (PDT)
X-Received: by 2002:a05:6000:120d:: with SMTP id e13mr89389wrx.6.1628710209170;
        Wed, 11 Aug 2021 12:30:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628710209; cv=none;
        d=google.com; s=arc-20160816;
        b=SVccQd2tYtttGhuJGuWeHB8Ih76s3sr9CBqero/7Vy66PJoSVNd0qrLEa0/H2WZ/eN
         mIua6ARrhknqYMXevo1k9GouptKyf6xHw4/4xcDndcOXsEAKixKvlBweqykVjHI/fXoG
         kkPW/GXcLTkLaDip3i5qvs0+wCjAwQMHedmb7Ti888KteWijCna4b3pVuMUeK2TU/iUf
         1qN+ds3GBC3Dmk/frPikww7wYyl/OY+4GQ803prr7bduXi96JDkVVCrx0rjuLlhTr1lB
         ROLrwmAorD0Gyvd9B0ftLiW3OoOiBJrLmxlt3xi06J8m0HvuY3FZ0rBxoxNsukjVcBkN
         FYxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gpLXpLqEdWJax+H+vzAJpIoO8hEwkusrWIf9JpaCtao=;
        b=rv2Aq3far3X+T1copY65uJm/mr/qxX4Le7KXsxTf2S5uPydbVd4mIl/n4hIpXfuzA0
         HvLg8XGEAE9+9+o9rlbmwP+v/X7QFDRCi18xvwSyQusp/sVPcrhYjToqIU8VTBXkZdOs
         dSb+41U+0bxAq/0HWErvl0S8+kZStJcBXKC49IQ18O8joDRavs7mlIvYif63Bzrwmk7h
         f0ZDww4tU1wwTErePUuaMWkZrGb2uCFuxTn0WMcsp7oolUz3esFEaApaUC3o2t0zPu0k
         7f/MJc7hKQBU3lkbip6RYO6U+zLFYuikfS6Zfb2ITjDTql1/J+qz9uxiqr78W+MVrf7r
         ZJjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pSu9Edxg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id z70si564802wmc.0.2021.08.11.12.30.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:30:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH 7/8] kasan: test: avoid corrupting memory in copy_user_test
Date: Wed, 11 Aug 2021 21:30:06 +0200
Message-Id: <17b812a3c28024acfca9b1a9e45c8235b35efa32.1628709663.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628709663.git.andreyknvl@gmail.com>
References: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pSu9Edxg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

copy_user_test() does writes past the allocated object. As the result,
it corrupts kernel memory, which might lead to crashes with the HW_TAGS
mode, as it neither uses quarantine nor redzones.

(Technically, this test can't yet be enabled with the HW_TAGS mode, but
this will be implemented in the future.)

Adjust the test to only write memory within the aligned kmalloc object.

Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 lib/test_kasan_module.c | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
index f1017f345d6c..fa73b9df0be4 100644
--- a/lib/test_kasan_module.c
+++ b/lib/test_kasan_module.c
@@ -15,13 +15,11 @@
 
 #include "../mm/kasan/kasan.h"
 
-#define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_GRANULE_SIZE)
-
 static noinline void __init copy_user_test(void)
 {
 	char *kmem;
 	char __user *usermem;
-	size_t size = 10;
+	size_t size = 128 - KASAN_GRANULE_SIZE;
 	int __maybe_unused unused;
 
 	kmem = kmalloc(size, GFP_KERNEL);
@@ -38,25 +36,25 @@ static noinline void __init copy_user_test(void)
 	}
 
 	pr_info("out-of-bounds in copy_from_user()\n");
-	unused = copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in copy_to_user()\n");
-	unused = copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user()\n");
-	unused = __copy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user()\n");
-	unused = __copy_to_user(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in __copy_from_user_inatomic()\n");
-	unused = __copy_from_user_inatomic(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_from_user_inatomic(kmem, usermem, size + 1);
 
 	pr_info("out-of-bounds in __copy_to_user_inatomic()\n");
-	unused = __copy_to_user_inatomic(usermem, kmem, size + 1 + OOB_TAG_OFF);
+	unused = __copy_to_user_inatomic(usermem, kmem, size + 1);
 
 	pr_info("out-of-bounds in strncpy_from_user()\n");
-	unused = strncpy_from_user(kmem, usermem, size + 1 + OOB_TAG_OFF);
+	unused = strncpy_from_user(kmem, usermem, size + 1);
 
 	vm_munmap((unsigned long)usermem, PAGE_SIZE);
 	kfree(kmem);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17b812a3c28024acfca9b1a9e45c8235b35efa32.1628709663.git.andreyknvl%40gmail.com.
