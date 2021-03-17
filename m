Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMUEY6BAMGQE3BMTCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C18E33EBCF
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 09:47:47 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id bi17sf18920285edb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 01:47:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615970867; cv=pass;
        d=google.com; s=arc-20160816;
        b=PrgmoPgObMFvqNlvmhU4ufBr/QcjO8fco1QuuwXy5rUVvSew6vHwQSuZ2m6rJBxSnF
         K8A3Tje4WRwqDonyhXHZlVBk8yfvY5wxku2spuWhc9cO4VDGDkld7exoRpRjjghSrn4G
         rB4BijVK9cE7CEhR6nM+pOlKYNpS5vqB3F4urH5mvzudW3XlYSG9Fjl3rJ27k+7vA/LD
         mHWUE6KJWSsVY7G/kh+iR1A731WXY+3TBpdbW4/2f5EEIlZtZsxWaBHE5peQHSPjEw+W
         pr+mq+gWYmvdUgdEdqCQOcVf+H5wzdCufxE+wOFJtuiExQM40KVD7moR47/RO0D5P+xk
         IAeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=X6vKKagwLWi96dmjB/QtohCWOKzfrdSb1nPRR0sevmg=;
        b=M4hRKq1br0g7WYizecK5N1t68cZoA8mOgszKnhvWg09N0SziL+5FYO9iGRG4Q3QGvV
         dNyuoN+opXxUVhLab2KcxZ4p+F6hQoHKtmlbzidRgJNgqsHzn88hGIKw0QcthyaN3ZWX
         adjN9aI2mNYCIf3NUmeIfzPCABFW8bhAmVQ7TuDC0TdVEDRpQ0hBfw5XFiBqLSgOAtlh
         icsUnCZD8egifkFroLkj2+sVxnJHjy4KQHB2pki74llbNJMbvVgfQ4XoroSVTWFBjxp9
         /CuAY352rkguxBtj0hfMmxPS4SPwex2V7+Yg7aw3R0JBT0ESdMWv7CiO2XX3L+lkKFEt
         G0ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PqGjPWsZ;
       spf=pass (google.com: domain of 3mcjryaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3McJRYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=X6vKKagwLWi96dmjB/QtohCWOKzfrdSb1nPRR0sevmg=;
        b=HjdVjd56TzKD09jWe7cOVbqtneUzBvVlm/y1Zvu0/kVMqLDdYBvLmlzC0ubVkxFjgR
         YtH2fIeFd6nRVTH1vFjP7qGKx2ZVJ6lSDFLNLTuZwJNzKiHF9Q2I9xSlnxSQYQWxw0H3
         2Hkx+tvv81fzYrlIGtr/CETXoDkz5ISLXhodhudrmzdpa6ReF6izWFVbJlZh56ro7lFN
         VoCFPTob8L7/ExZ2RSUPvz33zT2kXX1kVhLNck3yVCaH/jApRDRMkWYJ+kPECP2ko3hi
         vdnKh54a6mn1sQ+EYTnSHHHhzDkx7v+w2ajKt4IQSkYA1hVd/q24NMR/llm7xpLG6ERE
         GqCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=X6vKKagwLWi96dmjB/QtohCWOKzfrdSb1nPRR0sevmg=;
        b=YIszy5735KtKb+y8Wqj6euQy/YpAOc3rpuWzUNkWt3a/OvLAMI6QniEZu+3ThuBYR1
         CRV7xhE8li/tPEds102cTbFtyIpZVe9+XaC4XDvv0dt53nELMxSVSeFPn4FA1N7Amj2G
         1gf2N56FgdQjdAW4x+vDvdmAniCAKZ5HAKfjimbsnNlk3wcvu73BjSvJVfi9quaYhKhL
         rBjJJpZhT/91+gZfsAoF6M9/FwI+QuUSnpCprfp7zk/7Rkfdz/opxdxCgbCzqoOr8WM2
         rnw5ksk2xcljeZHyLLcdItzq7ogQ/6muZbma7x+LQUB6Y+WC2GzfFPEmQB2xrI+CRWfi
         YZ1g==
X-Gm-Message-State: AOAM532QlzizQMveISSHVTP5Zbt4a8JUyjKEFa6etL2E4AqsOluUtFYm
	KLZfy6xKRI6AqFTtptH8aVM=
X-Google-Smtp-Source: ABdhPJzOoUWvXxf63qY06gJSKGgzJTIyEnpIXgB/2RPiXBUly33w+PhX3+qzfqT4uAYPbjmP46z/xw==
X-Received: by 2002:a17:906:9714:: with SMTP id k20mr33886614ejx.519.1615970866927;
        Wed, 17 Mar 2021 01:47:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:50cd:: with SMTP id h13ls197482edb.3.gmail; Wed, 17
 Mar 2021 01:47:46 -0700 (PDT)
X-Received: by 2002:a05:6402:38f:: with SMTP id o15mr40181139edv.361.1615970865993;
        Wed, 17 Mar 2021 01:47:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615970865; cv=none;
        d=google.com; s=arc-20160816;
        b=RVd+j3dpiboYSUuwZUP0H5JzXBSjnui0dI16itNYOMvqJb83ZyUa/JdgYRXjbbxWTe
         NHr0DkEwUtgX0wBtVmxeKeZ4m1fJ17Kat5UkqlMAZ5RXxqYNQbxKpr4xpRkRKEnxhwxL
         PQBoY1kz6vW3OgbFnu3Oc+0eq206T85726Hb6DvP5SHPLqsXcLE67CuYmdkacSzZxcZN
         u80u2+NMPrJ5fxjKKw+m0KUgd82Tks7oZ9RWjYvQG1klZRL7YI+WUK3+jHtiVO1EJcs6
         p9tYjQGNJQH0rlLVFiQkmb6nlJvYd9fs/UXZ7spH82A6n/kAgqk7L14wxBw8XAbTUQLz
         MpEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=mQ9lVwNHA8xNGK/XyR+U8c7RoXUhm2JAea9oSpZR7Gk=;
        b=oAUOWAcabAAhntjAQlUSK4zqPqYmGDjL6v6F6dWW1fLosUpfw5ZUbZfbThyKhxN178
         xAaxjU68bEGUlzE1hWLPxvNT8h0wsjhaNgQmnSOrgJmk6nJRIxfIYjjFI7mtUCiEMGmb
         UQ3EofbsAqFfU1f/u7K/Cy7obAAWdC2p9wIYclfTPMqY6rrZp2sHdr5KlSP22SbUhr6d
         wS7y6mI+EBBeZH2to/xO9Kp3gJsxF0TiAEdwClQnrVEpR3CyXSPDZN1FpAbOIHd49Nh9
         RrzznegUY2mKahdnHM+3rKMmM3/6w7V+y8njlqSVTWeDQJ6KwNARQ/vPGidy+HCETuDZ
         rYoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PqGjPWsZ;
       spf=pass (google.com: domain of 3mcjryaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3McJRYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id f25si735647edx.4.2021.03.17.01.47.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Mar 2021 01:47:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mcjryaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id t14so675948wrx.12
        for <kasan-dev@googlegroups.com>; Wed, 17 Mar 2021 01:47:45 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1d09:9676:5eaa:550])
 (user=elver job=sendgmr) by 2002:a7b:c047:: with SMTP id u7mr2656333wmc.98.1615970865676;
 Wed, 17 Mar 2021 01:47:45 -0700 (PDT)
Date: Wed, 17 Mar 2021 09:47:40 +0100
Message-Id: <20210317084740.3099921-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH mm] kfence: make compatible with kmemleak
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Luis Henriques <lhenriques@suse.de>, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PqGjPWsZ;       spf=pass
 (google.com: domain of 3mcjryaukcqykr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3McJRYAUKCQYkr1kxmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Because memblock allocations are registered with kmemleak, the KFENCE
pool was seen by kmemleak as one large object. Later allocations through
kfence_alloc() that were registered with kmemleak via
slab_post_alloc_hook() would then overlap and trigger a warning.
Therefore, once the pool is initialized, we can remove (free) it from
kmemleak again, since it should be treated as allocator-internal and be
seen as "free memory".

The second problem is that kmemleak is passed the rounded size, and not
the originally requested size, which is also the size of KFENCE objects.
To avoid kmemleak scanning past the end of an object and trigger a
KFENCE out-of-bounds error, fix the size if it is a KFENCE object.

For simplicity, to avoid a call to kfence_ksize() in
slab_post_alloc_hook() (and avoid new IS_ENABLED(CONFIG_DEBUG_KMEMLEAK)
guard), just call kfence_ksize() in mm/kmemleak.c:create_object().

Reported-by: Luis Henriques <lhenriques@suse.de>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 9 +++++++++
 mm/kmemleak.c    | 3 ++-
 2 files changed, 11 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index f7106f28443d..768dbd58170d 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -12,6 +12,7 @@
 #include <linux/debugfs.h>
 #include <linux/kcsan-checks.h>
 #include <linux/kfence.h>
+#include <linux/kmemleak.h>
 #include <linux/list.h>
 #include <linux/lockdep.h>
 #include <linux/memblock.h>
@@ -481,6 +482,14 @@ static bool __init kfence_init_pool(void)
 		addr += 2 * PAGE_SIZE;
 	}
 
+	/*
+	 * The pool is live and will never be deallocated from this point on.
+	 * Remove the pool object from the kmemleak object tree, as it would
+	 * otherwise overlap with allocations returned by kfence_alloc(), which
+	 * are registered with kmemleak through the slab post-alloc hook.
+	 */
+	kmemleak_free(__kfence_pool);
+
 	return true;
 
 err:
diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index c0014d3b91c1..fe6e3ae8e8c6 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -589,7 +590,7 @@ static struct kmemleak_object *create_object(unsigned long ptr, size_t size,
 	atomic_set(&object->use_count, 1);
 	object->flags = OBJECT_ALLOCATED;
 	object->pointer = ptr;
-	object->size = size;
+	object->size = kfence_ksize((void *)ptr) ?: size;
 	object->excess_ref = 0;
 	object->min_count = min_count;
 	object->count = 0;			/* white color initially */
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210317084740.3099921-1-elver%40google.com.
