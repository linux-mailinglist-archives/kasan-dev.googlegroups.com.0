Return-Path: <kasan-dev+bncBAABBUND2OOQMGQE7VLI4CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C26165CB37
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 02:09:38 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id z3-20020a05640235c300b0048ed61c1394sf1812459edc.18
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Jan 2023 17:09:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672794577; cv=pass;
        d=google.com; s=arc-20160816;
        b=cyAEKiC3tmz4+kEwefIKHiOoDad+AGXJRYVvEu5S9n25HT7wr6cD92yrDHy5SyOViE
         +IMcjKFAQ4kpPiPJi5dFn2cjdgoSAnVYKdq2uLVQCmldjUYQYSZOW0zYykYF9lP69Ie5
         Vh/ccxxcXrUkQ6cHht9wbKXNPiRYI6YUr7kj8VDfxue9s/GL/Gl0/D+xy4W2tCKNmLJX
         v+wHLghmPCf54mpgWN/JWT8K07tp8672JB7z3aF2xCMMGl+LMbsV7H/lhL0K+uNC2g5h
         wzcofQUOvSpeyLCBMXOLrsDj4XltzMFJqNSmzC94fsXy+v74GxFhGKkkijxo5zCHkwlQ
         vJEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=g7bJFNdVjBbC1bpJcxakCFqgp3BPf4ouPJsgQzrXJPQ=;
        b=b25O9k3TC7zom08rwcyLxd8oXfwBNXXfY+hy++03o0PjzgTBO7+IRVjrm72JA/4XIU
         zkV46jcOHF1tAlOk1Az5lEMBFc+zoU9OZIce/VBJB61JzW9cj/CNMj7JUihwnqPePMh6
         vnNJI8gXtsnbnn4KqCVznLvGie4CN0L+5qg5X9tEt9JO9/RSdSHQ8P9rZxlSI1REcbCz
         2iF656hnlXf2i7i0WqnxZBguUX7hT2dPj8PyAFH/Foxu2Het35+3S9KN6U6Pwcr+HwEp
         LXCv8INnoI3C4Vk5cPUS+hMrCQU8LP7jMbpXvTiMfNwpOcHkHbS1LFlHbQgkJW1iLF+o
         /u9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VzH6fyc+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=g7bJFNdVjBbC1bpJcxakCFqgp3BPf4ouPJsgQzrXJPQ=;
        b=Qc7ukfHsW8R44ZUunCmiMWC+66uzBRQDkMpaWwjDsj1TmmHGoNUWXdqE8whrux7Yd5
         ulVAye2RlevpBO4rWbUVFajoj2a5U3ZoX/p6hS8Qo7ESO0cNvm3ALHm9ihSp6glyy++h
         IqiMrNFZ9Dlq6wqD+NQckkNleXWvhUKAxtkKXOt2BXR2LgYFUhjLENSw6Q5088ZU0kOS
         ax2lWSVD2PAXtqgFXo8YrjMqtA7yySj6c1HIoAQZ4Mmp7o3rfRB+yV/smJ+R2eT09VfD
         vusJEKIMIuq4xMdGwoEQ7fy3SVrRN66rOTh2fWkXauy4s9U3pU7TrWolBuUqX8wzx4y0
         boEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=g7bJFNdVjBbC1bpJcxakCFqgp3BPf4ouPJsgQzrXJPQ=;
        b=2N3kuIG6EA6bwuVzkxZKpshVBb2AtYSw2vUqV4VkQa2VIXZ+rhvLYH0Pi8RsNl/NS1
         Q3coECFBaY7uLoASppWkRwRgNNM8ctTyLvjXdWy/eozzX0ehHWiHZMgSXZDZ97EH/w67
         XNwnNsszXyc8BUOE/r+r2IppRiwBmdL3FcIQUue9HdZQdHnx1nAfsmyE684b6KLQW+ir
         96LdY/lkRT2MPKnLeMpeyBC2d0kmKAEQ4BdEabHrP6p/Yo8ps3u4GtRKHdSJg0S3gq76
         1zT9ozrPgtd0VCFLt5Rc21Jo9lswI5USjDDfE3BJFqmdrZv8LTT6f5K5/JQY+SIljGjO
         CA2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kqeXhwm1GOdl4ITlS3Hszp1F0Shm+uBJ0Wc+7MdjK3v0+dGzCdi
	gEEZWZwy5s7ZVmlBWqem0P4=
X-Google-Smtp-Source: AMrXdXsgtgf7tmlXXIEUMubGWjbFyW/X61RZHnzikUr/dUjrCdi0piN/qB534cG1/3iXZlQwOblXIA==
X-Received: by 2002:a17:906:aac7:b0:78d:a136:7332 with SMTP id kt7-20020a170906aac700b0078da1367332mr3573767ejb.355.1672794577514;
        Tue, 03 Jan 2023 17:09:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34c9:b0:488:1679:c417 with SMTP id
 w9-20020a05640234c900b004881679c417ls4587282edc.1.-pod-prod-gmail; Tue, 03
 Jan 2023 17:09:36 -0800 (PST)
X-Received: by 2002:a05:6402:d5f:b0:48e:c8c9:700a with SMTP id ec31-20020a0564020d5f00b0048ec8c9700amr3095858edb.9.1672794576772;
        Tue, 03 Jan 2023 17:09:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672794576; cv=none;
        d=google.com; s=arc-20160816;
        b=STgFub5fVVQewuxxZG3gB/mT6H57skPpsADl/uGie23gbQWnGCyCLhmUrhhXjGlLRJ
         RzmSfezFsJ86QYAXByGtLaQSXoyJ2cocBumkzS93vrwTyBxHwMQqdEjF3YX45EwYz+rG
         Hpt9x/w163RPfFIRaWzp6+2zWku5J28TGZXVBuAU87j+qv2HUaQFmHwJ3WGid9Z9JKAz
         aTsIbYvfvbWBEQ8EKwQZq+wZ0lplAelW3BQdhD8q8hhd0IORISXbvo8+nio7yRRunxpI
         GAYzCQgBYqXRdaCDDo0Nd7fd8VvNxNoTQhD1Nn13YHuKImoOsVMPv9c3G5SVPG5B833F
         TUSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=PC26Ho/6RwxF3gMRadK0bIZPfa+DG2oG9ZOGTDXD7m0=;
        b=Avp0t1bb47s+48fEdeFTiR0G+dS1Xk36QkqrBXwn8SHEyi3Z8Iu+GMOQ04jMrwS2Xw
         xEXEcPYVWvhURTazyfdDjyxRNN8qGXsAIHL3F7rikTxAFNJ+K4iKSYej0asqfccFLuOk
         7r0QL6pYVMU0/FvuBmb/uRcKNRFlVy3zVXuntZL/CZ8jnx2VyV3CDgLbnLiuhOnPVT94
         tXVpMdpe5ITNUjb8+nc0Q1pl3z2LxIZsffSq2SJQncSwdc7J/I76NjORv3yj7FjCR3Ir
         l+6BQu0vjebVmsFUvGIt0moisGe+/FXPqUHQeCrQXmK1CcDeQEOnxZjvhaXDmMjU8hd1
         anNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VzH6fyc+;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-201.mta0.migadu.com (out-201.mta0.migadu.com. [2001:41d0:1004:224b::c9])
        by gmr-mx.google.com with ESMTPS id l23-20020aa7c3d7000000b0047014e8771fsi1180775edr.3.2023.01.03.17.09.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Jan 2023 17:09:36 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c9 as permitted sender) client-ip=2001:41d0:1004:224b::c9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH] kasan: mark kasan_kunit_executing as static
Date: Wed,  4 Jan 2023 02:09:33 +0100
Message-Id: <f64778a4683b16a73bba72576f73bf4a2b45a82f.1672794398.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VzH6fyc+;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::c9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Mark kasan_kunit_executing as static, as it is only used within
mm/kasan/report.c.

Fixes: c8c7016f50c8 ("kasan: fail non-kasan KUnit tests on KASAN reports")
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 1d02757e90a3..22598b20c7b7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -119,7 +119,7 @@ EXPORT_SYMBOL_GPL(kasan_restore_multi_shot);
  * Whether the KASAN KUnit test suite is currently being executed.
  * Updated in kasan_test.c.
  */
-bool kasan_kunit_executing;
+static bool kasan_kunit_executing;
 
 void kasan_kunit_test_suite_start(void)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f64778a4683b16a73bba72576f73bf4a2b45a82f.1672794398.git.andreyknvl%40google.com.
