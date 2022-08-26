Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD6EUOMAMGQE7YBQBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 47A435A2A6C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:09:05 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-337ed9110c2sf29581187b3.15
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:09:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526544; cv=pass;
        d=google.com; s=arc-20160816;
        b=z/lzfyQTR3GZFn7EscZ16IpXjjcG/hFgQvljE7MRCCxUSGoJld8JvhvOC7U0dds9i3
         cgeL2B0KgnWLW9bwhp3+UREq51DowKDuxdezxu+/JG1EJyMbu/jrkb6D74TnVjmcQD8x
         em3PBl59bTfgkIX+4l7ft3DimSIB1ipwcv74SYe6nfoFmnhrCWdyKdbcJjK4WJ907daA
         9nH1WJssoUcDtSXyhhYlKMwHx2oxGcX6STroMfjUIm+tXLx9Mkb0XeMbTLruE9ILas6Z
         nU5ESCQgvtuEnuSOhpkeP8U3SSnoiFPJJWTxRkcYyixiiHR802lsg2v6mlNAx/cNwFEE
         bVRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=kxNKagAkiiqsbx2dyUbU8nEDl+7vbycldi8yiRkmsHs=;
        b=E3yxIh8S3H/Hy5X6PL2SlrqkRnN1AOoVIqgBBCq7vREjn2LlFaoqXs3b5svWOo9MhX
         9bWiqn0piIa5IOr+3IBgUU37wF1pJUbse3wu5fBpaD03LBlP2Fb26dbizpl2XvBecEB5
         XqmcDZ3FO40a8lRxRvBx4unAm/huyCVT2mr3UxFdFWHb0seK42xHRgQGyNm+Xu1Ye7jk
         9CUCBpAV22t/zdrXs+9Y4meqbTLAtqC4b5gOH+DaBmTQ1taOJMRuC/OURAXwZEd/xn3s
         R9Gur6L2D5s1es/26/ZTMdT/HG4uZHONZ6cXQzKa19jQg+l0bpL8O4mA7kyUZWiN1cGF
         L6Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JXeupyYJ;
       spf=pass (google.com: domain of 3d-iiywykcry274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3D-IIYwYKCRY274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=kxNKagAkiiqsbx2dyUbU8nEDl+7vbycldi8yiRkmsHs=;
        b=LftS+D6gljtdYd5H34SsnG3ZWLPCMN6b6udoIsOsS2TRFgEObbv4SaA7qxOWQD9PIM
         29AWeuc07IPMXEuOqzgZbly+LVIgrZNTkMwX6n7b+mTR+Idhm9xSAAQ3HpQXq9y5+m/f
         s7IIrsGiXgRtdtAUrB8RnsXuxVByhOTl/EXWfEu9mJ3+vWEJd0LkRgvEuNn0CQb8mVUo
         CYgiUAtnUnRi9su2D0RLEy9vDF603lySZSGFro5KqOc6HrOzfnaZa6CPIgbowIhgGiHh
         7R8t/CMG+HDZjeB1/YK8hOhDHeZO8lZMJy0nlxwYhHEBbaW21sW+7hwLFWaqNjYELL/T
         k+qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=kxNKagAkiiqsbx2dyUbU8nEDl+7vbycldi8yiRkmsHs=;
        b=WFJRR/g6+8q50RPrAk+sd6IfrFqbF20xfitcPSYUVlwODAoAkYiY3aDok7nDpKcP1S
         ADeJKmb9y00m+/Gt3pG79jdtw/6wo3ZQFFdxPLtkf/zDzCWjTRrkUl3buYFZJgCdbk4G
         aTjVRSsf/cmBMV+Svb7WoRiVz+/nGqJrZ8Ig3MilDbrE3LnQbJY37XyMhXamLRAwXaIy
         hky18zCho6awwGDkwzB5eN0dpUKRCCNNUR4L0wHQMquKQXJvRf0bgK2GH+Z/Tl3X8Jdm
         UUQQygAMYMbQBYH+9wgCVsHM7KRk5ISdjLibeDGEePn9Z9NMFWxflDL8S+wDNa93UkIh
         yFnw==
X-Gm-Message-State: ACgBeo2CxvTKWs4TQySOCJzBiPwetzCYc8+oWlyaLJehc+5EprjkKIbC
	H8CntUZfqpcDlFfi5mojZbg=
X-Google-Smtp-Source: AA6agR40kvwpw0XM+XgoKMmTBhuHE23hJwZhcr4R0xuao4um7t/IuOwSwtNebKUuYT2I5eKM4c0EOg==
X-Received: by 2002:a81:460a:0:b0:32f:f024:c169 with SMTP id t10-20020a81460a000000b0032ff024c169mr96561ywa.53.1661526544056;
        Fri, 26 Aug 2022 08:09:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:268b:0:b0:695:9cee:e88a with SMTP id m133-20020a25268b000000b006959ceee88als2799483ybm.6.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:09:03 -0700 (PDT)
X-Received: by 2002:a25:f512:0:b0:68e:d3da:5e24 with SMTP id a18-20020a25f512000000b0068ed3da5e24mr130253ybe.2.1661526543536;
        Fri, 26 Aug 2022 08:09:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526543; cv=none;
        d=google.com; s=arc-20160816;
        b=V+mZj1/+wW64KthAz9DKRw/YRR3qY+xTmHwRDv4EZnfGDQp1rADPMNS2bM5a1rLqxj
         0rcjo+snmqxDBflU8ZIN+B5BUA1dDllaqLD3ONkhZVSHX1NEdeC9mt+1clGLEcOvhe/d
         cW+zfe0/E+D1xyrLQi6rDLVRihKO/iyCNwR92bwLg/EegTBHMUV965TQ1iAxlgJv7Iwg
         +auimPHNtsS2soEzg/UlXc+R2ER3VWzomXVOgypU20hQhgac9wYDAzvXBd2Kz2m7MgfR
         BJVzBUyPmWczwDZnEbK7qZ8hmUWcwWm8ii8HMu1W7ukZ6U9ALEtCKf1M9HWnl4/QE8rR
         w0qg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=pkHi/aIOhGHio3xjvQCqySH1KrxER9e0jmCiCnEZ6lc=;
        b=VDj9sRehbEf50nSUNsfYd9TQ4WhVTJ6wrVj/RadQQvgPpeIQ07Ey3GcgBLeTAoU9f+
         ljnwBwPoIucdcNLHRkZOw6TXQcCI9T9jr2pn88hW1KuATqJBOPmElIQzdyS+RDUAgDMR
         eDt8jsqL4Tt5rUe1TDFh19r0+mNbD7g/Tz7864awscUrjHeuxAGQw+zUGfSRJrNyKyR6
         mrQzxqI7oRgULeazIP5W+C6HNkWht0X8/NbYISjd1QryEkwyOx33kukOmNLyVhdGLwMw
         LJOsWQwwU+vOBd61qAeQUKEzkIVVutCjpAZ02DMde2C+X/aW7KK0lWfYZH1AYMBtuE4o
         vW1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JXeupyYJ;
       spf=pass (google.com: domain of 3d-iiywykcry274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3D-IIYwYKCRY274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id q3-20020a815c03000000b0033dca312115si2605ywb.4.2022.08.26.08.09.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:09:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d-iiywykcry274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-33f8988daecso21031917b3.12
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:09:03 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a81:d0d:0:b0:333:99b1:44f1 with SMTP id
 13-20020a810d0d000000b0033399b144f1mr119968ywn.288.1661526543285; Fri, 26 Aug
 2022 08:09:03 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:41 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-19-glider@google.com>
Subject: [PATCH v5 18/44] instrumented.h: add KMSAN support
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
 header.i=@google.com header.s=20210112 header.b=JXeupyYJ;       spf=pass
 (google.com: domain of 3d-iiywykcry274z0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--glider.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3D-IIYwYKCRY274z0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--glider.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>

---
v2:
 -- move implementation of kmsan_copy_to_user() here

v5:
 -- simplify kmsan_copy_to_user()
 -- provide instrument_get_user() and instrument_put_user()

Link: https://linux-review.googlesource.com/id/I43e93b9c02709e6be8d222342f1b044ac8bdbaaf
---
 include/linux/instrumented.h | 17 +++++++++++++++-
 include/linux/kmsan-checks.h | 19 ++++++++++++++++++
 mm/kmsan/hooks.c             | 38 ++++++++++++++++++++++++++++++++++++
 3 files changed, 73 insertions(+), 1 deletion(-)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index ee8f7d17d34f5..5f0525d95026a 100644
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
@@ -151,6 +153,19 @@ static __always_inline void
 instrument_copy_from_user_after(const void *to, const void __user *from,
 				unsigned long n, unsigned long left)
 {
+	kmsan_unpoison_memory(to, n - left);
 }
 
+#define instrument_get_user(to)				\
+({							\
+	u64 __tmp = (u64)(to);				\
+	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
+	to = __tmp;					\
+})
+
+#define instrument_put_user(from, ptr, size)			\
+({								\
+	kmsan_copy_to_user(ptr, &from, sizeof(from), 0);	\
+})
+
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
index 4ab8c629acd0c..a8a03f079a8a5 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -204,6 +204,44 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
 	kmsan_leave_runtime();
 }
 
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
+	} else {
+		/* Otherwise this is a kernel memory access. This happens when a
+		 * compat syscall passes an argument allocated on the kernel
+		 * stack to a real syscall.
+		 * Don't check anything, just copy the shadow of the copied
+		 * bytes.
+		 */
+		kmsan_internal_memmove_metadata((void *)to, (void *)from,
+						to_copy - left);
+	}
+	user_access_restore(ua_flags);
+}
+EXPORT_SYMBOL(kmsan_copy_to_user);
+
 /* Functions from kmsan-checks.h follow. */
 void kmsan_poison_memory(const void *address, size_t size, gfp_t flags)
 {
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-19-glider%40google.com.
