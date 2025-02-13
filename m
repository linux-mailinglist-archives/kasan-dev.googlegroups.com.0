Return-Path: <kasan-dev+bncBCPILY4NUAFBB3M7XG6QMGQELJPXKFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF5FEA34EEA
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:02:54 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3cfba354f79sf26186995ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:02:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739476973; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZfRXwhva0gvwkns5cfGErRdnWkfBXY0k/7DVASEMAtajrSFHeB2MxihlvDk4nuUfxZ
         nhkDRCe8wvp8x0Jl6ZzXKqwic0V9pEwyTA6+NGkeb6BZlneCVun8jBEdCm8upZjnp1Yd
         C6I5JSS3sKizxcVJQ2xLpHBOt4Jv37U2H4uD0lAL40BlEughDsjLxdHTpwrDNE+PRFIo
         Lw7c49cdxfyXYCULJpeHBf1H2nbsmusvJDGpEDj3nqaoOFlOMXHbk4I4i/lJ4iziM7NU
         8j/vGY7SwNvyP7OasB9tKXughBcYMOYKS/anBoeQ8fM9xgsIHWGVc2KAiMqcaMQ1xNM/
         tRYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9CQaoIi+EPcZprInw+o48pcwaQd4o0XYLCQNW1/zhGo=;
        fh=1KWGn1rSW+qJuzlX3HyJSGMOktyNuqsu01nbNgP1c7s=;
        b=Zmkre9eF0Q256rG2xGvrvR4epCyhhOzRyKVqmxg6HD7A0njweOYgrwY+4LyHD4qz7R
         7lURiULMu3wu40mfCN/2kj8UEOWUCRCbN4liCOvn5581JAt0Zs3fjlimNXzMytt7hjKe
         ZXhwTJBQdehMUy9oJmkD4mQwcNPO+yTK3dLvyje+WTZAa2waTi6QN+q3dHfVvYnFtRD/
         /mTaY7JYGcB3/+5HxKJfr9Lb4e0icjxmvrENHiD1DMEqJpBbS0YQjJQUp2rpy0wTuT+I
         P7AN52ACdcdRNP2b0oMDkQxXX/tcM4dYcHKhqyT7TD++czoc86Lt+viovPRJoUVRktmh
         +ikQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ebsMz1H/";
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739476973; x=1740081773; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=9CQaoIi+EPcZprInw+o48pcwaQd4o0XYLCQNW1/zhGo=;
        b=bxqsVMiCGgPsjbVqemrXTjpJZCCBsNxOYwEur8rsn95BEVHMbvi+4DjOFYpGqCxMcm
         DQ0PhJBQb6Ax3ZrCoGdrBd7WCL4SPhSjkBQxqLTZmWirxsouZygTnVk4hlb87qDI2TtK
         ggkIRsfX+ceOogame1VMftPIfqg1U5lJ7bs3WECzOVMb4xDzJrTIG1+Ix2Xt+U7l/Nz6
         r45oBBMDbIDlY6GgElRU0barl/vFLXlgfEG/Wi87H2LD2ZFRH7nA7/RITVJYoSgIMR4c
         v8+TSfDR+Jf9yx+pI/tOk1n9I8FK+03U4qmD+dBvyJa162cogizAhrUw7uBl2MeezoPM
         5aSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739476973; x=1740081773;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9CQaoIi+EPcZprInw+o48pcwaQd4o0XYLCQNW1/zhGo=;
        b=nDdWpErCQYEGB+wWigQ1ts2Hz8CHe4TWNhb+OCnqfcSR9e2Ge97zRLijrjDzNg1taJ
         2ufctNxwsPnECe93ubLkG5fPVax1ekpT8feq5UEq/a6nZkTuupIHB4LpJIHsVqbuQ9/d
         KOFti5rruIqgJvJx8i7O+r1bVZVIqxi2Bvc61tdoVWbGpWvw2yr2mxIIYQfZ5WPLzi50
         8xEYVDQA9q6s/pH9SBht8hr3CcY33Iehre0KvNA+phMOlXkGx2BTWFEUwPLA5BbEeFjG
         4R+1EYWOPL7/+AHGfGoqpihN9ovQSIOIsDOHT2C7VFKmBkEKOnBEQY044V5EYI5WcZIA
         HUiw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUdfb1AYvHopx/RTNLpP4rUx4LSjsll+i2AVEab2RBcyofxMzyHg7zmmeL+RcuneLQNz8FIzQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywm4rz8LACBZvKZ3WT1oOoOs/u2zSI7btcTy6GutCulg2rm8cxi
	RHBth59LNeJfZ7d+rM9QHbMgeIy8WSCyO68HaUpJTNOMtt5PkNEK
X-Google-Smtp-Source: AGHT+IEQ/R0KhLBh4mLZZY5wqTxg31YjK6HXJIKwkZaR54A0g7tHQdUcHFDkpHl8/tQujF7hn8OYFQ==
X-Received: by 2002:a05:6e02:2145:b0:3d0:21f0:98f3 with SMTP id e9e14a558f8ab-3d17bff8a03mr89122315ab.21.1739476973378;
        Thu, 13 Feb 2025 12:02:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHBNPOpuyLDkm1xWLxKiZsdr7Fe2ktUQjRam4p3ZiB2eQ==
Received: by 2002:a92:d092:0:b0:3cf:cf0f:7dad with SMTP id e9e14a558f8ab-3d18c393010ls4298455ab.2.-pod-prod-02-us;
 Thu, 13 Feb 2025 12:02:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUp9ScbEtbRlYxcv3252N01YCFSx8K2ux8fPb21Y6pDeMhFHKcGIwVMGx8T/VmXe8SorYy6O78hD1A=@googlegroups.com
X-Received: by 2002:a05:6e02:1fe8:b0:3cf:bb3e:884c with SMTP id e9e14a558f8ab-3d17bfddbd5mr77249135ab.16.1739476972407;
        Thu, 13 Feb 2025 12:02:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739476972; cv=none;
        d=google.com; s=arc-20240605;
        b=frRmF0Rp3hvIO68g7x/AktqC3sTTxRxzkeM7tDVac5Blh/JsjoWGhZpRW0PnIX6N4D
         4yqBmfFhlFW5Et9YMLBKplY52Jmu6bhVPUmyynKCMVunv1QXfMM0nXyZEsOZfJY/X0HF
         zwY8sYU3L7USQ+Fs7SEW2J7Oc671lVaj6WWkCf2MTZelGo4wcRyWKs0/Vf+mQQ7tjxsX
         Yop9EJdzI+5gDSSr4QPcwW/rv4Rmzr7OkW+ski45Qc9dLuZS6lNTUz4R4Czdaqd8l9WJ
         fjxVqSeItODsBsM5cY8pSaN55bFPcKjXJtdf15U+HWB79faG4YpthBMPLUYIp3RmHeOq
         vqHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jCz7+XdNeTmg0ywryfA79K8sDfbhrWMKHNAgiZbFNpE=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=PoNoOTgAGhe/2w2MGUvafGqBJlWot0uvLRa68qyTF7lb/XfH13he5sZ8aQd0CULe1e
         /fvIz8xL2P1DjdrIomAPxoa2Kah2v2LL8O6dYe4WxFHO+91UBCJ3MZZm/Obd90x4iHei
         UL4zu4hAJ//X9dW+4LJZtOpUXOzWXYTC6ygl4JIDCJld+evJm2LA7miQ2UQYX1+sDEBE
         dQe4aHXeK+z0S+mB4qY2Pv0minsazez69FkSSrv8gsQMNZwEUhb/SLfwCnqvPseYCuWL
         Ov1iIfUHs46oP/uMQ/84llIkwn90JTMlC729wVrYDuY4tbpqEXvbRju/7/v/kQjFnRA6
         GxQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="ebsMz1H/";
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ed28257a84si69976173.4.2025.02.13.12.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:02:52 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-433-SsxhO4IwMmWfG-T4-krdSQ-1; Thu,
 13 Feb 2025 15:02:47 -0500
X-MC-Unique: SsxhO4IwMmWfG-T4-krdSQ-1
X-Mimecast-MFC-AGG-ID: SsxhO4IwMmWfG-T4-krdSQ
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AB17619560BC;
	Thu, 13 Feb 2025 20:02:45 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.174])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 70E361800872;
	Thu, 13 Feb 2025 20:02:42 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 2/4] locking/lock_events: Add locking events for lockdep
Date: Thu, 13 Feb 2025 15:02:26 -0500
Message-ID: <20250213200228.1993588-3-longman@redhat.com>
In-Reply-To: <20250213200228.1993588-1-longman@redhat.com>
References: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="ebsMz1H/";
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

Add some lock events to the lockdep for profiling its behavior.

Signed-off-by: Waiman Long <longman@redhat.com>
---
 kernel/locking/lock_events_list.h | 7 +++++++
 kernel/locking/lockdep.c          | 8 +++++++-
 2 files changed, 14 insertions(+), 1 deletion(-)

diff --git a/kernel/locking/lock_events_list.h b/kernel/locking/lock_events_list.h
index 80b11f194c9f..9ef9850aeebe 100644
--- a/kernel/locking/lock_events_list.h
+++ b/kernel/locking/lock_events_list.h
@@ -88,3 +88,10 @@ LOCK_EVENT(rtmutex_slow_acq3)	/* # of locks acquired in *block()	*/
 LOCK_EVENT(rtmutex_slow_sleep)	/* # of sleeps				*/
 LOCK_EVENT(rtmutex_slow_wake)	/* # of wakeup's			*/
 LOCK_EVENT(rtmutex_deadlock)	/* # of rt_mutex_handle_deadlock()'s	*/
+
+/*
+ * Locking events for lockdep
+ */
+LOCK_EVENT(lockdep_acquire)
+LOCK_EVENT(lockdep_lock)
+LOCK_EVENT(lockdep_nocheck)
diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 4470680f0226..8436f017c74d 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -61,6 +61,7 @@
 #include <asm/sections.h>
 
 #include "lockdep_internals.h"
+#include "lock_events.h"
 
 #include <trace/events/lock.h>
 
@@ -170,6 +171,7 @@ static struct task_struct *lockdep_selftest_task_struct;
 static int graph_lock(void)
 {
 	lockdep_lock();
+	lockevent_inc(lockdep_lock);
 	/*
 	 * Make sure that if another CPU detected a bug while
 	 * walking the graph we dont change it (while the other
@@ -5091,8 +5093,12 @@ static int __lock_acquire(struct lockdep_map *lock, unsigned int subclass,
 	if (unlikely(lock->key == &__lockdep_no_track__))
 		return 0;
 
-	if (!prove_locking || lock->key == &__lockdep_no_validate__)
+	lockevent_inc(lockdep_acquire);
+
+	if (!prove_locking || lock->key == &__lockdep_no_validate__) {
 		check = 0;
+		lockevent_inc(lockdep_nocheck);
+	}
 
 	if (subclass < NR_LOCKDEP_CACHING_CLASSES)
 		class = lock->class_cache[subclass];
-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-3-longman%40redhat.com.
