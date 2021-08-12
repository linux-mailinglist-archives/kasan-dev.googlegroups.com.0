Return-Path: <kasan-dev+bncBAABBCHP2SEAMGQETVGSL3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 021D63EA704
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 17:00:25 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id u25-20020ac251d90000b02903c64ed27829sf1938756lfm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 08:00:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780424; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjrsUQOLhBCdBatfccj+iynU7C/OvD9NDIC+JGKx8faS8lmUtO5NY/VRdv+rhgpw6s
         VVTOkhJ9CXx/BjyoedPomou/D8EpNzAyrsVFnQ0JTJ/1goB8o4g8+3b2+jA9NiCQ98Zv
         K3gJVnkNV0F5GEXiriM4N9JeYMrAW5BlipgHkLHyz6AIdAzSsVfP96fHP0x2XiAG4QeF
         ZFjwj5npn77OA3hfL5P/R5aX6P86/J7uVYXPzCfACie6X+saMlwrHgdy0xkhpPBOTGKw
         L/XFN6Naf7oEAGq+y1bhF5Cy+ajuJ2+DNBz1pe2kdIG3CXpudOIfLlRiaVCCXT3gkgXI
         i+FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gCBHgDmA77fnOzzuEqTFhMURk5DMaf8w9p4OgopeYiU=;
        b=fGC9bkIre9zhTjdoI9tdKVAhIfhyKTaH40TJ1JIXPfgu27MtMnENHyLmZtpx+q4Hle
         iQYKFbklyicRSWPmmxsMrb8GeX1x0V/Q/FLo0Rhph91cKc5WxnYJL2Jra//t5c5yPTIJ
         0ncgzu33Yz1NNFk0RFB9cQLfxP6PS5NhLH1vU4sBifIGjwo/2EQv7Yxo/HsfyrSst/4l
         dRx0N5SWKrffuYKG8Ogahb2jMDLCgQmRknQkuavUFNqMgKiMeH0Nnmmribx6HZpXsaz5
         OV2cBOoEkuRkZ9eMG9ljZ1xEFEyvhZk6vLQKlLneJ6sndK4DHWO0NgxO3KHP6dXuK2Ni
         pdsA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pYy6jrZ0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCBHgDmA77fnOzzuEqTFhMURk5DMaf8w9p4OgopeYiU=;
        b=ADa5o3Ai09OUv5CRTzLVhsbkcWyTo/M8/iKNY4iCbwj7WnrPclUgIvRvk+gVvhy0B2
         KfzVNpoy7+fJjuTZHdYn8c/VUPlZHh0mOx16SZwsZWw0W3h6zilgwHB9ktOFMX+ypXgR
         c4iAqZm8JMutG/WAWB9+o301/Uen5FjI+HQ4xvAN1EZO5akzB/LEM1lZCTSjI2+acqtY
         ZIxM1dKwTDXc8AxSKW2PvAgs8hsq4Uo1kruU/7gdLgQCdo8J7IcDnQU0m06VVU6zoLlQ
         SiL1cNk4rjdyV3x7mPxmQqgnmrjWeb6IS7O9btTFtwZUCE0l5g5Y5KsJ0DkupMIw0Nor
         fQMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gCBHgDmA77fnOzzuEqTFhMURk5DMaf8w9p4OgopeYiU=;
        b=CIpJEvat/EGNHBxl86pfU6Sv+8Qv4rPmuKBCtKUsU7jBgUfza/0OhOxa+jjxLkaMJ+
         CbExbz/+/JlilCyo2vR6VyuqdvGebLAo8QcIbDF4v4qVa4wvSZQKrPUcrOXQABQin6sx
         1bhSvenc5NH+K991XIjP/7TE/GspGsGpxo8k9AJklOmpWgDl3MNswu9sLZcNurrwHRus
         X/sPe24ghLPbMApGGGI+adC6ACWqrGGKo8vJNEQgcE4CSx1KZHDveuuMoOU8tZ30tcMJ
         LAbEbozhW+aQKCco5jAaHwY30QBEkZUcARC/CuXzW4t3aaWSmzqzXe+Dajc7YOEZjTRU
         b+hg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531yGQbZb90B46QPENPha8ZvUc5jHat1JtT7/N3Ntrk1RvuN4BQT
	eM1JUapGqFXM6HNt3ssX79Q=
X-Google-Smtp-Source: ABdhPJwwnt7vhqJ6ilSyRuay90SNfmLXSXTFCgpI2uNPdXbzQQIJJ/QP3LwR6t059rYaR3oxuPptog==
X-Received: by 2002:a2e:580c:: with SMTP id m12mr3283145ljb.316.1628780424512;
        Thu, 12 Aug 2021 08:00:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5395:: with SMTP id g21ls741104lfh.1.gmail; Thu, 12 Aug
 2021 08:00:23 -0700 (PDT)
X-Received: by 2002:ac2:4350:: with SMTP id o16mr3010047lfl.184.1628780423782;
        Thu, 12 Aug 2021 08:00:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780423; cv=none;
        d=google.com; s=arc-20160816;
        b=UuVFhpqjSYfdHw5plWk+WLE4stEpRgmPMgX8c9LUITIcnxT9Z6X2upNv4QJB6btC3Y
         N8rjeEkBi3Cjttzx6LsnXhixwN2eL6CE+f1P7J6G4vYR8QWB1xAepS/NXMRG1rmGY8hp
         tAHLuYeuBygrSiZLi/P9sHNPpxj+JzwfawGbAt721lbmkdLxB2zR05GNRZPuF26mH8nP
         /X7C07/dn7mIwiz3QdukKW6xoKK50cJJMSJ4DuE6YABhRRj8ToD6tF94paPM8nlmMSty
         Owe+Th7ghzQe+1Q00kOMSFOHO/+Ewkju+FYnkTEG4ye08BwHLbhZ7ARjf/kNfwlHt9kJ
         oG6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gpLXpLqEdWJax+H+vzAJpIoO8hEwkusrWIf9JpaCtao=;
        b=q0DpWr3DnAhCKmMZL7qj7ZxOd5ei6iCec6gM3x0Zf4lca9S2TD2ceET9rIWyqzMdc/
         6WOszbLax4ciS8/VsI22aVVem9H0Jjz1+UNvQiwgp/jJZA/T4++2GpdPfFvMz3U1dprI
         j+AEgin7sWG6e73fvX1Jy3Cc+kaLu2S8YR2rb0feY7dbOuuw1AJk3IOngyIoFm/9s+QC
         LN4z4/Joshva1HBso1PQzhS2vihqFpIPjy9pCD6VpCY3gLEpktrBDR+jYn+0pDDd717g
         RcVMCHsqnB7HzPIczTkBfCpqkd9/okF+O/dMsg1yz9w41/SQ6oHBV9/FFufPPxFDwSTp
         Z3sA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pYy6jrZ0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id j7si210419ljc.1.2021.08.12.08.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 08:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH v2 7/8] kasan: test: avoid corrupting memory in copy_user_test
Date: Thu, 12 Aug 2021 17:00:21 +0200
Message-Id: <19bf3a5112ee65b7db88dc731643b657b816c5e8.1628779805.git.andreyknvl@gmail.com>
In-Reply-To: <cover.1628779805.git.andreyknvl@gmail.com>
References: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pYy6jrZ0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/19bf3a5112ee65b7db88dc731643b657b816c5e8.1628779805.git.andreyknvl%40gmail.com.
