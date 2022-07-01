Return-Path: <kasan-dev+bncBCCMH5WKTMGRBB4H7SKQMGQE4H2DNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E072856351F
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 16:24:07 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id c185-20020a1c35c2000000b0039db3e56c39sf3114339wma.5
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 07:24:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656685447; cv=pass;
        d=google.com; s=arc-20160816;
        b=s4HF79ISL7kfEn3MuX6cRTqY6USbx3gWnzAlEwpeizYhnjGfHpoMA+bdMlsEFy9zCK
         m2k07JeZfT8dLzPpLNf9S1KQMjlfNRkQ+wzi4z5iMIkUIrAQersf7nn9POL0eDeSwyPX
         neZySWQFlbp0xnRtnDGCXLUPGRWFu2hErquF3Lo7XC15TFGIHgSWBFf87XmC1DWkhPt1
         MTGnMqKqgpzOthxj3u9eJDhRgZwARtJQpWd+ogWC9OaZew+hSvn1RXuOyBOP7cJKnQlF
         XMVaWF8xSLpl2M8B4b8pZ8tI4MAMG1V7amsiM7G7TJH/uwDawCBGfIwFUbm2Hv0Ln0j2
         dwLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Z660kR0GpR463BIg1xZsrdgrtvXO0epHYXdKXpGQECE=;
        b=Q5/zSb59RxNYmWAAUiC/rx7GrPQk8tMLHRP73RtAM0/L7g4a4yz6/7fDG2LeO7tV5w
         Xmivsld0C2oiObVc1T6BdKjffNZ47iNkVGyDw+GR4rxPE2ElSjD6C+Arzb7/x21lULmL
         Mr0r/o8XiMQ4PZk3RM7qiGOJ3RIgLXmlJo+9LEvrk/Nz9YzMtYLXHqRJ8CPppMpoa5KC
         V53a+pRj4Y9xKX3zGMRUTYJX380atk5FX4jamyaTztYAh1Spbuv/6r3RIh+UufPJi1kR
         35u6ROQ9G4RqRYmzWW1ldvU9wXvjpoeETi5730e5n/JHc7SMjxF+x+KM7vEEivaSVVY1
         n54Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nuIy5sPY;
       spf=pass (google.com: domain of 3hqo_ygykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3hQO_YgYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z660kR0GpR463BIg1xZsrdgrtvXO0epHYXdKXpGQECE=;
        b=CLP8Gp+khYYc2/Mg/zFcT9Fs/4P4TfXIt6h+Zf1zFs9EhQ+43RXHbpLkraHIkNw5io
         VU8cqdPfNIBe4wJJpKVmr/XOeSPvV1sijeMvxFOjUCgUlYEnVvVXVldp6DpGrhag8P03
         L8GJSYHK8eizJ/YNK1M5URwewZLn4FrKIIpYxrmXlIHcnoGkFk+rIN9pHbTIjXFmjHxW
         /5t3Zl9129lAiBR+mt8oPC6P2BNReFxey3GcFg+7cURPamnu6eDhCjNw0BSMXf12uD6R
         3HxQCSvrzL26xGZAiBnVlsxdZJNj2xqHRxzVBS79OxDMoIx33B9P2YlZiLNWE0G/F8Za
         AAPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z660kR0GpR463BIg1xZsrdgrtvXO0epHYXdKXpGQECE=;
        b=ZErfkPBn7YXTn7jrva0t1YbCzbE4MgO/WYS+pV6SQjtq5KTJJD7xP94JkVLS6nx4cJ
         Pkl9JzfMi2PzsaYIgPo9fInRR8Osts8/pZB2E/efyBqwU0MYlypmVEGCTgb7gU4mnBmf
         07vGS2tzYMTm/SjNuE+mRjjbrEWeKAHVf9Isw5VCbweWZ7oun3VgHe3LYHveWSuS3nrn
         8SecdvRATypRK017YK45uX5qIv3A5NhyLNeRTSgNVfWlS+qY84523K2AzIUBmvCBZisV
         aJGCLsUr9U48UgPs4un4jn0wp+nUfwxM9R6BfcYIW0v2p+VG5hyi7D+6lE2ZlDFDgDEl
         9HqQ==
X-Gm-Message-State: AJIora/BcHwOFGKDiluEVEfz3OjpOwzDUEG2v21sc9WZFkxWM1in4ECv
	oaCNx+6HNLlEN44JfV1BFgo=
X-Google-Smtp-Source: AGRyM1u0Oco8kIHQVt/NVsbx1eIabxMQQQvemJYv4ivxSBrngI5XKk0Ex+83onpD/weY4VONsNbYtg==
X-Received: by 2002:a05:600c:5007:b0:3a1:7c44:44f5 with SMTP id n7-20020a05600c500700b003a17c4444f5mr11124153wmr.106.1656685447666;
        Fri, 01 Jul 2022 07:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls11354255wri.1.gmail; Fri, 01 Jul 2022
 07:24:06 -0700 (PDT)
X-Received: by 2002:a05:6000:1844:b0:21b:b06c:3ab2 with SMTP id c4-20020a056000184400b0021bb06c3ab2mr14514626wri.618.1656685446646;
        Fri, 01 Jul 2022 07:24:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656685446; cv=none;
        d=google.com; s=arc-20160816;
        b=rTnUcKzrcwJamskcnTLVcCIt1nuqeqNKoCuBBwaUffa/UsUOpiI40Mdf+r/61eY3OS
         DLF1OCBYNRBGOhIxLrOgrULI9c6sl5Fr8PLl8VuO7Pyj9nFBaBFOx6e8RFeK5frXAPkR
         qw0VtqQA5T3AUj256ES1oGTAU8zxwT+3cnrQWa3oXcL4nt3n6TaVEtw/jOj+pMq3JJo6
         fgiIJWOU6aWi/CLEX7hvhiXxf3lEBlYILEcswRhedxQHQusBVXBM+0fUfSpY8Z0DJZJx
         vY/Tm+9edDOAQ0vW1CLOB5b4CgLG6NWR/bwONW3yqcXULsi60UB22QZtDqhXqlaJGHQq
         Rp9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=qRpA/KHLRYdo76YWwE6d04+ye7UN8yXoHeTH9XEwQK0=;
        b=vZLxfWlGn5GoS0DmTaBxTlvw6VgrgJj3DOrQqdpjEpzl/1hjwMj2GfBURp+k6YG84g
         NgMn7KhncbWHO5FGmaaeTeIrEIQLai+rFMRrmJCpNl0rvvIl1clnvHBZzXNj9lIoxgvZ
         1khmrtlnX5reOK5eY3FRejWnIfz518FKkfzHVytpeVRHzCqFMct8OIjpwT41u1Gt94qJ
         lsbvy3u9w7Sfv6WPUYXsR7hgy+wL2T5rbApBKbw2jz4t6dKDkR74N5SmIv92P+G50yWZ
         H/qjbv5Rd/5UAyWbzHzqu3XELg76z20oful+aGtWLE3w9vVAHlcNDTj/GCu5vPXm/sty
         LlOw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nuIy5sPY;
       spf=pass (google.com: domain of 3hqo_ygykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3hQO_YgYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id az15-20020a05600c600f00b0039c903985c6si215394wmb.2.2022.07.01.07.24.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Jul 2022 07:24:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hqo_ygykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id x7-20020a05651c024700b002594efe50f0so506766ljn.21
        for <kasan-dev@googlegroups.com>; Fri, 01 Jul 2022 07:24:06 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:a6f5:f713:759c:abb6])
 (user=glider job=sendgmr) by 2002:a05:6512:b9b:b0:47f:6aae:ecc5 with SMTP id
 b27-20020a0565120b9b00b0047f6aaeecc5mr9169900lfv.412.1656685445833; Fri, 01
 Jul 2022 07:24:05 -0700 (PDT)
Date: Fri,  1 Jul 2022 16:22:43 +0200
In-Reply-To: <20220701142310.2188015-1-glider@google.com>
Message-Id: <20220701142310.2188015-19-glider@google.com>
Mime-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v4 18/45] instrumented.h: add KMSAN support
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Marco Elver <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, 
	Matthew Wilcox <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nuIy5sPY;       spf=pass
 (google.com: domain of 3hqo_ygykcaqkpmhivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3hQO_YgYKCaQKPMHIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

To avoid false positives, KMSAN needs to unpoison the data copied from
the userspace. To detect infoleaks - check the memory buffer passed to
copy_to_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v2:
 -- move implementation of kmsan_copy_to_user() here

Link: https://linux-review.googlesource.com/id/I43e93b9c02709e6be8d222342f1b044ac8bdbaaf
---
 include/linux/instrumented.h |  5 ++++-
 include/linux/kmsan-checks.h | 19 ++++++++++++++++++
 mm/kmsan/hooks.c             | 38 ++++++++++++++++++++++++++++++++++++
 3 files changed, 61 insertions(+), 1 deletion(-)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index ee8f7d17d34f5..c73c1b19e9227 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -2,7 +2,7 @@
 
 /*
  * This header provides generic wrappers for memory access instrumentation that
- * the compiler cannot emit for: KASAN, KCSAN.
+ * the compiler cannot emit for: KASAN, KCSAN, KMSAN.
  */
 #ifndef _LINUX_INSTRUMENTED_H
 #define _LINUX_INSTRUMENTED_H
@@ -10,6 +10,7 @@
 #include <linux/compiler.h>
 #include <linux/kasan-checks.h>
 #include <linux/kcsan-checks.h>
+#include <linux/kmsan-checks.h>
 #include <linux/types.h>
 
 /**
@@ -117,6 +118,7 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
 {
 	kasan_check_read(from, n);
 	kcsan_check_read(from, n);
+	kmsan_copy_to_user(to, from, n, 0);
 }
 
 /**
@@ -151,6 +153,7 @@ static __always_inline void
 instrument_copy_from_user_after(const void *to, const void __user *from,
 				unsigned long n, unsigned long left)
 {
+	kmsan_unpoison_memory(to, n - left);
 }
 
 #endif /* _LINUX_INSTRUMENTED_H */
diff --git a/include/linux/kmsan-checks.h b/include/linux/kmsan-checks.h
index a6522a0c28df9..c4cae333deec5 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -46,6 +46,21 @@ void kmsan_unpoison_memory(const void *address, size_t size);
  */
 void kmsan_check_memory(const void *address, size_t size);
 
+/**
+ * kmsan_copy_to_user() - Notify KMSAN about a data transfer to userspace.
+ * @to:      destination address in the userspace.
+ * @from:    source address in the kernel.
+ * @to_copy: number of bytes to copy.
+ * @left:    number of bytes not copied.
+ *
+ * If this is a real userspace data transfer, KMSAN checks the bytes that were
+ * actually copied to ensure there was no information leak. If @to belongs to
+ * the kernel space (which is possible for compat syscalls), KMSAN just copies
+ * the metadata.
+ */
+void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
+			size_t left);
+
 #else
 
 static inline void kmsan_poison_memory(const void *address, size_t size,
@@ -58,6 +73,10 @@ static inline void kmsan_unpoison_memory(const void *address, size_t size)
 static inline void kmsan_check_memory(const void *address, size_t size)
 {
 }
+static inline void kmsan_copy_to_user(void __user *to, const void *from,
+				      size_t to_copy, size_t left)
+{
+}
 
 #endif
 
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 43a529569053d..1cdb4420977f1 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -212,6 +212,44 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
 }
 EXPORT_SYMBOL(kmsan_iounmap_page_range);
 
+void kmsan_copy_to_user(void __user *to, const void *from, size_t to_copy,
+			size_t left)
+{
+	unsigned long ua_flags;
+
+	if (!kmsan_enabled || kmsan_in_runtime())
+		return;
+	/*
+	 * At this point we've copied the memory already. It's hard to check it
+	 * before copying, as the size of actually copied buffer is unknown.
+	 */
+
+	/* copy_to_user() may copy zero bytes. No need to check. */
+	if (!to_copy)
+		return;
+	/* Or maybe copy_to_user() failed to copy anything. */
+	if (to_copy <= left)
+		return;
+
+	ua_flags = user_access_save();
+	if ((u64)to < TASK_SIZE) {
+		/* This is a user memory access, check it. */
+		kmsan_internal_check_memory((void *)from, to_copy - left, to,
+					    REASON_COPY_TO_USER);
+		user_access_restore(ua_flags);
+		return;
+	}
+	/* Otherwise this is a kernel memory access. This happens when a compat
+	 * syscall passes an argument allocated on the kernel stack to a real
+	 * syscall.
+	 * Don't check anything, just copy the shadow of the copied bytes.
+	 */
+	kmsan_internal_memmove_metadata((void *)to, (void *)from,
+					to_copy - left);
+	user_access_restore(ua_flags);
+}
+EXPORT_SYMBOL(kmsan_copy_to_user);
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220701142310.2188015-19-glider%40google.com.
