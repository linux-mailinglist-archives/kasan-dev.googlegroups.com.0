Return-Path: <kasan-dev+bncBCS37NMQ3YHBBEVU2X4QKGQECGRFQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 586AA243C5C
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 17:19:47 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id z19sf2129071edr.10
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 08:19:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597331987; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wvtg+v5/stHH+tEktuTFwHldtdRXGfuhnPFF3OMQ8iiAuScRIQJU4r7FksXGyyVP/B
         p0Tvt2jwyGmR6vyNtYF7a3CG2SyQ2YNKfT7vcNPYZiKhK1Y+BT4fYvpdusE2s03HwHtT
         g84s2pf3kYGt729Wo1k87Dw9zPC7AYMUd+XLrv3pa6t9IPVdjNAREdLj8KVxgqhmIT/Y
         9KBTcy08rtDWD1eVFurLpPSzSD2+0ZtsUqUsxdRduaidyWqN67RCS9ZGDyy5W2w2QLli
         +obKhHzaAUQywzxZ2Hp3bINomgwSho5xifFEpfW/dbAqjBsAob1J0Xbhh3hDwMPiKsuV
         eaaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wxrC2l2Y8RdtlUVm0fRAU+uJ8E79JpJV5C/B6b9H4Ik=;
        b=N8ldrHDZ77LlxNIcc3NyJ1fhXIAIyFeDetz5T3eALoWNuhUoPjDbtJBc5SMq3G9lBZ
         Q9kLg4Xf20WGw0Grew0Mzf5hoWvZWloBdtRoYnrsvWMHg16AlTksIRL4PjZOVqhGPm+g
         5aK4B6AITW+9fUhXT5x2w9pHAUMPYogJ6AMGVUfYfWXpSOscDVhW6zP4l8Sc7SYLLJ06
         2KWi6IymERHT7mT5zEst69q8xDXWJZ/x9nBjnSxmcOtANMa1tUvxr5/+J0HYXlrRBU9F
         OCoIlpMEKCLtUkMa0a5B+e/5xR3J7DU7w700vLP57ckm5EksNsHBNqPA/AlAycc85vfZ
         +2Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxrC2l2Y8RdtlUVm0fRAU+uJ8E79JpJV5C/B6b9H4Ik=;
        b=koRJ3UCnfom/Rd4ugBVQoZQTAslH/vUsknKVDneob9a2NlEVamo7wS6Go6fptiUm2a
         jpXlvtBWZi0/2ZaFApFM4/sAGoucht6K+7kFT12OErhellpZasVFgVlL7Czy3DbBqYl5
         RPPFn7E6vhwBlCP5jfftXZLmJfq2kjaRf1Dw3gxeH/ufAdUxq60lOI8vrok5qAw2XntT
         N4Ps1xCxk+j4VNK23qzjzoGzipVWmKL3k5zNbyHHTEcgtNIZB0Gy3WZzm+fzcJoYftvX
         WGICA17/j0ETKO4fL8SgeHa/qFAi470uRu46NPR29itDPZn1YB2i191WOjTIpKbPLuw9
         pAhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wxrC2l2Y8RdtlUVm0fRAU+uJ8E79JpJV5C/B6b9H4Ik=;
        b=LSVWWM2O5kLgn879kE2on25EiO7qRrULUh54Em97R/QnTKZoQ9J8+IteXUv0zl6SVb
         whi2d1reWdguGfhwiMAUUI+ghetbiJdCDeH+Vl121DwhxR9cd0T/hlf4ohDC5fGrjG5P
         RFWvixz0wjJo5rmcsyupM6qMwtX9u7t1hGaAvJOPrJmkf99qnTypsEK7sQKSPi5Vm6kd
         EB0/bSBO2UXrYyQjJRrOljKuaZsEMvzMtywhb2XOn7F/z1+2qAfQOGuL7Ea6M3rJ2Ser
         GaNbPXzFi5z6070WeUqFrqBgQi5rR4sWD9xJdlc9x4pvmnDVkkzVuW8VRBldKCw86KoH
         XQGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530uSmZZz4/xDS5wCXFoWs29m1bgLVVsicoakQH1g9bi6KNjyWe5
	wQf+pEWdc39hz1XZGU/9QiY=
X-Google-Smtp-Source: ABdhPJyq8YaceFTh47Kux28rgYjFoN+l4jqeGDVwCE7Vlw5KInKmmHQ8YVY/E6hmvP4auMXAL5bgfw==
X-Received: by 2002:aa7:dd91:: with SMTP id g17mr5411228edv.186.1597331987044;
        Thu, 13 Aug 2020 08:19:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:baa2:: with SMTP id x31ls6202800ede.0.gmail; Thu, 13 Aug
 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:a50:e087:: with SMTP id f7mr5413870edl.174.1597331986592;
        Thu, 13 Aug 2020 08:19:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597331986; cv=none;
        d=google.com; s=arc-20160816;
        b=hA5V6CldcMj11Xief5OpJ7SCmeKRJGaKF5ejFeC+0eYtAb5uuj5sXRVfcCyjyb+pT5
         lZuJDIOrhL+jtpX3DIrTv+vKkIRd+oZ/yOVPKT/SVojIyE7CEIUSlAwTQCGrHW/Hr/o2
         F7bXqd2ZMwyFftN1RH+0Rr1UyEes77kfht2JcKlF2dhj4zJU+N92F7zIVEvIbCPM3Mro
         Sk8lxjNNJkQ/Rgmhyx0wGF85iVKAM3a3+/oFebbnLCzxw4J4W+k9Ka7VeoAlqkVvyMGD
         YxhH2C+hzpgLBpTe6szjADZsWdvrdooTqqp4HMRuZB2od2hJ3V2KqjaMp6BRMbMJNTjr
         kffQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=sWVYbnLUoQh2/bQ8PJoxS/2ocrG/gYbDVzBuksdzAMQ=;
        b=VpjvAUeqHIS7vwD5qmgokuuRZxCw1FlhHW0ILuN7cJ383rSYupjPOokNCw+iZBjpTR
         mahR/X6xJ31z3W14M8NYIyblOY4GSrisKgOefprW4oC1ImRLu84SgFoKrS/OzW3CZ+Xi
         1UmbQYrisTPL4z1N9jKAT7X8oBoR17aMqg2JxDDID5FdYaeF4K5PEwPG97uM8Y4ZV1hh
         NwWbJlJnDm5KPMI3sraosPwagin4kKiu3Hyy8UgN2XOih91jzBA8SI0VHf5lTHiIeV44
         O4DiAb8DaXhlrQR+T9BEoueBMfuDdt1NYWacwUTbQwSj4WqIim5Xi9cj4chQn9a68fNZ
         bgiQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wm1-f66.google.com (mail-wm1-f66.google.com. [209.85.128.66])
        by gmr-mx.google.com with ESMTPS id b5si285773edx.4.2020.08.13.08.19.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Aug 2020 08:19:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as permitted sender) client-ip=209.85.128.66;
Received: by mail-wm1-f66.google.com with SMTP id g75so5380630wme.4
        for <kasan-dev@googlegroups.com>; Thu, 13 Aug 2020 08:19:46 -0700 (PDT)
X-Received: by 2002:a1c:de88:: with SMTP id v130mr4675656wmg.98.1597331986347;
        Thu, 13 Aug 2020 08:19:46 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id d23sm10394044wmd.27.2020.08.13.08.19.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2020 08:19:45 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC 2/2] lkdtm: Add heap spraying test
Date: Thu, 13 Aug 2020 18:19:22 +0300
Message-Id: <20200813151922.1093791-3-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200813151922.1093791-1-alex.popov@linux.com>
References: <20200813151922.1093791-1-alex.popov@linux.com>
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.128.66 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Add a simple test for CONFIG_SLAB_QUARANTINE.

It performs heap spraying that aims to reallocate the recently freed heap
object. This technique is used for exploiting use-after-free
vulnerabilities in the kernel code.

This test shows that CONFIG_SLAB_QUARANTINE breaks heap spraying
exploitation technique.

Signed-off-by: Alexander Popov <alex.popov@linux.com>
---
 drivers/misc/lkdtm/core.c  |  1 +
 drivers/misc/lkdtm/heap.c  | 40 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/lkdtm.h |  1 +
 3 files changed, 42 insertions(+)

diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
index a5e344df9166..78b7669c35eb 100644
--- a/drivers/misc/lkdtm/core.c
+++ b/drivers/misc/lkdtm/core.c
@@ -126,6 +126,7 @@ static const struct crashtype crashtypes[] = {
 	CRASHTYPE(SLAB_FREE_DOUBLE),
 	CRASHTYPE(SLAB_FREE_CROSS),
 	CRASHTYPE(SLAB_FREE_PAGE),
+	CRASHTYPE(HEAP_SPRAY),
 	CRASHTYPE(SOFTLOCKUP),
 	CRASHTYPE(HARDLOCKUP),
 	CRASHTYPE(SPINLOCKUP),
diff --git a/drivers/misc/lkdtm/heap.c b/drivers/misc/lkdtm/heap.c
index 1323bc16f113..a72a241e314a 100644
--- a/drivers/misc/lkdtm/heap.c
+++ b/drivers/misc/lkdtm/heap.c
@@ -205,6 +205,46 @@ static void ctor_a(void *region)
 static void ctor_b(void *region)
 { }
 
+#define HEAP_SPRAY_SIZE 128
+
+void lkdtm_HEAP_SPRAY(void)
+{
+	int *addr;
+	int *spray_addrs[HEAP_SPRAY_SIZE] = { 0 };
+	unsigned long i = 0;
+
+	addr = kmem_cache_alloc(a_cache, GFP_KERNEL);
+	if (!addr) {
+		pr_info("Unable to allocate memory in lkdtm-heap-a cache\n");
+		return;
+	}
+
+	*addr = 0x31337;
+	kmem_cache_free(a_cache, addr);
+
+	pr_info("Performing heap spraying...\n");
+	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
+		spray_addrs[i] = kmem_cache_alloc(a_cache, GFP_KERNEL);
+		*spray_addrs[i] = 0x31337;
+		pr_info("attempt %lu: spray alloc addr %p vs freed addr %p\n",
+						i, spray_addrs[i], addr);
+		if (spray_addrs[i] == addr) {
+			pr_info("freed addr is reallocated!\n");
+			break;
+		}
+	}
+
+	if (i < HEAP_SPRAY_SIZE)
+		pr_info("FAIL! Heap spraying succeed :(\n");
+	else
+		pr_info("OK! Heap spraying hasn't succeed :)\n");
+
+	for (i = 0; i < HEAP_SPRAY_SIZE; i++) {
+		if (spray_addrs[i])
+			kmem_cache_free(a_cache, spray_addrs[i]);
+	}
+}
+
 void __init lkdtm_heap_init(void)
 {
 	double_free_cache = kmem_cache_create("lkdtm-heap-double_free",
diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
index 8878538b2c13..dfafb4ae6f3a 100644
--- a/drivers/misc/lkdtm/lkdtm.h
+++ b/drivers/misc/lkdtm/lkdtm.h
@@ -45,6 +45,7 @@ void lkdtm_READ_BUDDY_AFTER_FREE(void);
 void lkdtm_SLAB_FREE_DOUBLE(void);
 void lkdtm_SLAB_FREE_CROSS(void);
 void lkdtm_SLAB_FREE_PAGE(void);
+void lkdtm_HEAP_SPRAY(void);
 
 /* lkdtm_perms.c */
 void __init lkdtm_perms_init(void);
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200813151922.1093791-3-alex.popov%40linux.com.
