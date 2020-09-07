Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB7R3D5AKGQETRYCL3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E40F25FB92
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 15:41:28 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 23sf2854978wmk.8
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 06:41:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599486088; cv=pass;
        d=google.com; s=arc-20160816;
        b=BstRkKq5HdqeHjYKgQFFdWkOQKBQVE3uSBQ7l5inyjr8XFBxy6RBAHJpZf3cfORgWu
         0lcumI8m8GDErrxioIqzb4L0luUttf7+zNoPJgV/ogNiAq2FR5YM7rHGr4BqRVhNv5lx
         Ln+LS8gTaqWDOWPAEc7ICJ1VSPVW5HVYgV5LlVrmElr9xoqy5m5xIGHcUzL2ZKhly06A
         mf7+bSu3o0q+HZ6VVnEOOsS91u2kIlYI1IcXrjaIjjxEzogbS7hkrew6EgR9W4cxcxPd
         tgIarsr6Pqe8WR2QSkS3DX6GAkxoXC+8jPJ9aYZYK9dG0BEmrDMl/GncnnyWHK22P+5O
         PDNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=vHvTUS0KR8mlXO2DaFLHvw+nz9lrtMA4MUOlBH4WsjE=;
        b=Uh3AmtK6OOskzaF5nkVixHj46SFMdxECTm81Hhegx8tNwe2yk1vPzC7xbv71zM1wTW
         t7x3ba6ZpCKnXMXKh2/o4B1t+NijiBbR3pBuzylFHdJ4eXTeSBEwGHXtakgpFDYcW4Cp
         cYrtyUEMO0GV+OETqRLlp1svzz+lu7bSOZPpRl7cOlRrXRXnVu+OpHQrBy5lgBl+4DSq
         X9s1pzhDgGTKh9B/+XOldIEntdH08WyDYi2WdvDYmnJOWAM/iNAmxoMpkWl5eNF6QERW
         mHDgVO5APo7NsJSNojRN71czYNXopL8dR3QZXcW8J+pBDoVO/SD+bjNVlq83S3f0PrN3
         mteA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJMepwpD;
       spf=pass (google.com: domain of 3hjhwxwukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3hjhWXwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=vHvTUS0KR8mlXO2DaFLHvw+nz9lrtMA4MUOlBH4WsjE=;
        b=m8p+t2ih26tHcr5snqDWtH/ZNkTPxRwHvEHlI878iE/KW0vwW99Rs6vS1HHVztHn5D
         0CrML7PnCLsX9tBynYV/aum6GjTblDWquRYUtN9P5SPetlaMd659GAUfr952l+JMbjYv
         cTKNozzjecVb4mZ/3EJZ9yn/34kibuaHGyVyZf+CUzqiqlh1lO0jwZru8gY5PeGGQlbL
         pGZL4iP7w95GhTP15m6H3c8669Y7yQQHxKoSDUQJ0RCdRh8hYHq3NNps9RmLKBw6LScE
         nz0o0iaCFSdYFovTO/ph+em1qhV68znOjd7QhXlWORwxN1iOtOOy4N4f02T9g3GfXH5g
         4iXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vHvTUS0KR8mlXO2DaFLHvw+nz9lrtMA4MUOlBH4WsjE=;
        b=eqkPkEjSJhCWFGrqi2e18WaTfKEWnj5yiYxMw1c/FagkiR0REGeceZzCH7DbgX14qC
         P2yCPFKLm4wLVyAFyRk1yt4xMP64vVMpqi3bHZ7GgoQaYN9CBLJtVJ9zNYjJWTOlDTbT
         XR1Kp2QrX/yJqAMadVSlML+FQk8W2FVh7fJg0EXgQKXNXfxKexTEa4Wiv+/33I8xmsK7
         3HWY9AUvA/tTQUoMQfrF2ZBUQe+JXPYzT/fNK+0TTCkZuHw76CRkaOkCwkzCISPGiEMG
         xmIB6s/T9aUziaVVuJ7F+vQmQgJ4Ce9J6eMlFfTwa836qog4A/ExZZmFPdkpEioKA+np
         ij1w==
X-Gm-Message-State: AOAM53388sI45zulfztCdsj2wW6OhA/pmjECcItp7kUc30+yTBgdVq+H
	jNd8lhtokHCE/slsT8i1DiE=
X-Google-Smtp-Source: ABdhPJyF4cgTtOyDOsbBH2+jZ0ae67xIef7ep7++n82OFtYr7dDS6EO/CDjGI2gqarQNEkk1jHhRnw==
X-Received: by 2002:a1c:3505:: with SMTP id c5mr22016173wma.65.1599486088025;
        Mon, 07 Sep 2020 06:41:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:80d7:: with SMTP id b206ls4451207wmd.1.canary-gmail;
 Mon, 07 Sep 2020 06:41:27 -0700 (PDT)
X-Received: by 2002:a1c:28c1:: with SMTP id o184mr21725252wmo.91.1599486087295;
        Mon, 07 Sep 2020 06:41:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599486087; cv=none;
        d=google.com; s=arc-20160816;
        b=IPbjzgfC3h+ZMO92DBNHTAqWlAO6FuCACAOtvptCzhF+SVrZBFP1FcTsYkgOaudhkM
         Enz0HdvyDpfQELtP6MfBPySgzOb67kNsD4dQzgxs5RVegyX6xP/1JMRiszbND7DB7yPk
         0IjmRUPuprFcWsg3QG6yGrvPscOluFQw3qmX3iJboYj3fqOuC3X38l1wbR0orxgibje0
         dh33/FG1xoG0KP+kdKHblxxgGw2G6UooZhyIQiMm9Hx0nKDmeiURq8uRoGDUrgC3EcrD
         q7lMd0p8YcEpdQ1BjVVgzbr/XInKQge3QI7IZulnqp6F12kAXyojkPXbhaILygYkKdyE
         wwtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=6l8eSHfBJbgjXLH4YKy244cAN4v6gWSGUkqWIYWs5l8=;
        b=l5i7qvSM7iR7qIZe+VzuOkklR/Etvpz5UrL4FKZKKE+6twlcBsC5yA4kGgoU7hrREw
         2/qni82wBSCSmdkQi5LZJIYZG20ltBVh2jRBZLp1QTqEOZQqDVFMKVtJ05mjsmEHIFpK
         SH8EhcPoH6Fmo/0GpDgUdB2GvM2iWrdr2FlrvS+m8TCSfCvkYNQ56sT4xNjqgcGwLa7c
         /oyU8KpPIMRjG8BpB4NmM0HyemRjztwKhqj7mZPqQDh7EZR7ZXywC8LFvZY7UrIZJ+BO
         kGva057K3fUHJcHlgUjfw0UyhG9ccqu17xOTJz75gxFHrTEMhxwoCc+wZQIOF2NEr9Ma
         tFwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gJMepwpD;
       spf=pass (google.com: domain of 3hjhwxwukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3hjhWXwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id z17si450668wrm.2.2020.09.07.06.41.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 06:41:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hjhwxwukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id m24so5601481ejr.9
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 06:41:27 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a50:be82:: with SMTP id b2mr22342862edk.303.1599486086811;
 Mon, 07 Sep 2020 06:41:26 -0700 (PDT)
Date: Mon,  7 Sep 2020 15:40:52 +0200
In-Reply-To: <20200907134055.2878499-1-elver@google.com>
Message-Id: <20200907134055.2878499-8-elver@google.com>
Mime-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH RFC 07/10] kfence, kmemleak: make KFENCE compatible with KMEMLEAK
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, glider@google.com, akpm@linux-foundation.org, 
	catalin.marinas@arm.com, cl@linux.com, rientjes@google.com, 
	iamjoonsoo.kim@lge.com, mark.rutland@arm.com, penberg@kernel.org
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	dave.hansen@linux.intel.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, mingo@redhat.com, jannh@google.com, 
	corbet@lwn.net, keescook@chromium.org, peterz@infradead.org, cai@lca.pw, 
	tglx@linutronix.de, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gJMepwpD;       spf=pass
 (google.com: domain of 3hjhwxwukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3hjhWXwUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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

From: Alexander Potapenko <glider@google.com>

Add compatibility with KMEMLEAK, by making KMEMLEAK aware of the KFENCE
memory pool. This allows building debug kernels with both enabled, which
also helped in debugging KFENCE.

Co-developed-by: Marco Elver <elver@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmemleak.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index 5e252d91eb14..2809c25c0a88 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -1946,8 +1947,18 @@ void __init kmemleak_init(void)
 	/* register the data/bss sections */
 	create_object((unsigned long)_sdata, _edata - _sdata,
 		      KMEMLEAK_GREY, GFP_ATOMIC);
+#if defined(CONFIG_KFENCE) && defined(CONFIG_HAVE_ARCH_KFENCE_STATIC_POOL)
+	/* KFENCE objects are located in .bss, which may confuse kmemleak. Skip them. */
+	create_object((unsigned long)__bss_start, __kfence_pool - __bss_start,
+		      KMEMLEAK_GREY, GFP_ATOMIC);
+	create_object((unsigned long)__kfence_pool + KFENCE_POOL_SIZE,
+		      __bss_stop - (__kfence_pool + KFENCE_POOL_SIZE),
+		      KMEMLEAK_GREY, GFP_ATOMIC);
+#else
 	create_object((unsigned long)__bss_start, __bss_stop - __bss_start,
 		      KMEMLEAK_GREY, GFP_ATOMIC);
+#endif
+
 	/* only register .data..ro_after_init if not within .data */
 	if (&__start_ro_after_init < &_sdata || &__end_ro_after_init > &_edata)
 		create_object((unsigned long)__start_ro_after_init,
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200907134055.2878499-8-elver%40google.com.
