Return-Path: <kasan-dev+bncBCCMH5WKTMGRBGODUCJQMGQE3LEVBOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1130A5103F5
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:14 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id cw28-20020a056402229c00b00425dda4b67dsf3947135edb.10
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991513; cv=pass;
        d=google.com; s=arc-20160816;
        b=O71m7SDdN2qZLjZ0386FwXplToo/uxvcFRRxYaI4sjZuR9rZq+bRsYDOMUrIJTGEi9
         PgXfNGWKJ8q9ukb61hEwabcGxGSl8OXMDouw4Z4+7W65+4xpkYid0JPXtckBK7q31xPf
         G1RgqulG8CCynr2Mg1oTHqs99Zradij4abqTAj8DQfQjy5i5NvZXKN2kU6In7MQXmTVM
         qbahNSZNzhWUTIz17B9kf8i4E8kfyiBgK0espDckm9SHVfj48TWZtXdIOoSMntuit/8c
         XBHnqyQJp3VvchQ9ClukgmoAfdeu+BjP9/m2vBatpRn1jXmW+7Rqj1pJJefKhnmXp6oy
         vxLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=m5h04m0rvfQl+yZEHBNgyCt43rmbIftAwHe+O7i8b5I=;
        b=O+LerIa85ZBPjHpMJPys31vYKuuwZBGvqSfyJh2J1vLFFsac/aONdW/kY89OSdQ6ds
         HWOYQneUhldllZcASAZH/FvadCQe1B4H5UnghRDC+Tk/MjTSP9XUm3O5asbteft6tFM3
         cnk/hMoEUyfg24ee2p/QNIoEMkzOONzhBb4GsgKV9ONXg0KTBeJOAI1uuoX/pFirEuGs
         4I8YxuRW3LU0k2FuI8t9G+K/NbYaHz9UdgVETZPhpKgBCiz03nGD9bWf6thdBh9mRZBN
         yQXmleV/BQ1ilSuTW4ZdzGWjac3Ky9JKLV8dRctrrAlnnFVM4aEoaJ7MHWCybU7ujmWw
         xmBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UzHbOhn2;
       spf=pass (google.com: domain of 3mcfoygykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mCFoYgYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m5h04m0rvfQl+yZEHBNgyCt43rmbIftAwHe+O7i8b5I=;
        b=KHI/LPe18F4BN1TH/RHzncTNUhX8fYphY5a6R+TaRfp9LOC6mMmIdbFKNmvyBFdQa2
         Vw1C9CafsvKJ+NcshnvL28rFSXK5AzsgMtkkKzLawYRSW0ihYksXOE6/x5idXLv8C7EN
         y4SKETapjR+cFLDxY5ZIZggJLL4m3+y+TUef/tzFubIHClV2tHzksW/3fdg7OcLWI1V6
         UXbb744nJBcdhQzz0CNo8/ZhzHuZ60iUIV8tdtUxihp9z2GGGhaRCA7ZdzrnRFdtna22
         lBYm4JZkI9T5f0/aUS35JkRcqUsSQUCkmCJfcEhNkp5j8sv/vedrQC51YNn3ar4jelUq
         sojw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m5h04m0rvfQl+yZEHBNgyCt43rmbIftAwHe+O7i8b5I=;
        b=z1D3RY0TdeoO0T0PhN2cb7nx6+JBGcw72p13jormFUCsIz5RlsUHTWdrgruz5byBmP
         23M0Xg8csPBrJsze5xIGlL82JEHKXVMAZ5o6ehI4Mx+fSIrVcpxwY8qKDIvquPR+K5j2
         +w8y/vHLetPEcFfltHl0IqfjVaueeE3rsflv9/H5RkDVpsXs7Ay94y/vMSQKaN0qQvLD
         Hl9oWQmkBdsCB+r+TIUPK0sBYpnGbGZY711lAmMNz7fs4GKydpsfkCu9rLkAR2DOWaCI
         AHVuGhA6oYg88xiykrFzu/joMB34pOx+jT305ZglPaw7NLVz+XrkDiSwXh+Pt8Tg2M0s
         yqeA==
X-Gm-Message-State: AOAM533vKOTmCCOOajUuw0XwBZTxRHLZ3/nZHmXONZm7ECG/zgyDs/iw
	0SNBDfcGBPZq3ONWuzrkgEE=
X-Google-Smtp-Source: ABdhPJweZjxcqUgR1TW3TSutDXoiLGVX686XyaZg5Mp1pg9YeqzH4A/Izv9nSyhMxMI+oxcdieUwsw==
X-Received: by 2002:a17:907:c18:b0:6f3:9c23:20fd with SMTP id ga24-20020a1709070c1800b006f39c2320fdmr8986475ejc.740.1650991513767;
        Tue, 26 Apr 2022 09:45:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:478d:b0:6e8:95ff:b734 with SMTP id
 cw13-20020a170906478d00b006e895ffb734ls5358397ejc.5.gmail; Tue, 26 Apr 2022
 09:45:12 -0700 (PDT)
X-Received: by 2002:a17:907:1625:b0:6f0:28f2:f0f with SMTP id hb37-20020a170907162500b006f028f20f0fmr22101939ejc.330.1650991512870;
        Tue, 26 Apr 2022 09:45:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991512; cv=none;
        d=google.com; s=arc-20160816;
        b=mhfoqbo+f3GS+v0W2g2CSsWTAfs38Ru58aJFuKo1sKvmiX6sIe84jIPrmEJ4EOooYB
         lIInDFrkahF+MJh1ajrt3KX/QMYaLrdUpaV4sTJJu9ZnQQe+nxj3iHZ//th/xqUG4xgc
         Lcbd2OVGhjWSnR9WgeJ95su5tJ683N6rhnw7ZRoBqEn6we01sRY4OyH0zLDldJiizTe3
         BNosIHi64j5yK9ubT1BM52JcdfJodX5zuc8ON/OFQwatIqCGl2iaKixd0690bXHFAfqE
         /gBNrqSWEJ0bwsjHnPYXrsz7mCRpvuMJ9Evgpk4C7ePYNs2RaNLNytbYgvX2fgOOsQ6G
         1w7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PbBXRuKFLbtHp5AyM4yBRHn0ZnsWI8OdvT0jRFW7dGk=;
        b=0bpIC6T5yopZUs+FHKIWUsJ4xKinoNFxj/LdzOGHTLdAi+FWXoLp+SlDcPZlW+VnAj
         uEyNAHE7y2fjv4TASj5/vLMZ7xEK4Z/claYsaxeAOFgw0dFW8wgo4tnMdMlFWhglsJkE
         N3VWRMvPLSSu+zBNc//4Ljx7IBzfUmPVs03aEMkA9FY49CTO9r1mIoQjEMaqbVXXV3V8
         /qhD32Bfiupugo3wBYXx5fW3Ok4nN+k3I8vMWtkJ+1dv839yohGVR6I6HcH32fHn0lsc
         fGIOmv8wLoFhLNp8NSgspsHUgluwatXNMJV90bMXiyPGcEBDcNCb9o2QBmjqDTBN4lOO
         Qx3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UzHbOhn2;
       spf=pass (google.com: domain of 3mcfoygykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mCFoYgYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m10-20020a17090679ca00b006e4026d0ab7si809763ejo.0.2022.04.26.09.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mcfoygykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id n4-20020a5099c4000000b00418ed58d92fso10617774edb.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:12 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:400b:b0:425:f59a:c221 with SMTP id
 d11-20020a056402400b00b00425f59ac221mr7821838eda.307.1650991512487; Tue, 26
 Apr 2022 09:45:12 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:49 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-21-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 20/46] instrumented.h: add KMSAN support
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UzHbOhn2;       spf=pass
 (google.com: domain of 3mcfoygykczu5a723g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3mCFoYgYKCZU5A723G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--glider.bounces.google.com;
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
index ecd8336190fc0..aabaf1ba7c251 100644
--- a/include/linux/kmsan-checks.h
+++ b/include/linux/kmsan-checks.h
@@ -84,6 +84,21 @@ void kmsan_unpoison_memory(const void *address, size_t size);
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
 
 #define kmsan_init(value) (value)
@@ -98,6 +113,10 @@ static inline void kmsan_unpoison_memory(const void *address, size_t size)
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-21-glider%40google.com.
