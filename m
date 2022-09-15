Return-Path: <kasan-dev+bncBCCMH5WKTMGRBOP6RSMQMGQE657RU7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D9B7D5B9E13
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:05:29 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 62-20020a1c0241000000b003b4922046e5sf5572694wmc.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:05:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254329; cv=pass;
        d=google.com; s=arc-20160816;
        b=eJp8CfX0bspbe1/MAvr+aK35kYWyCrZBehHZXaxRpxJ97HZjCqwtHgX3RZV1bC8Qe7
         GyKMHZUJU3cdl74B+WJgv36/c2N1A3QFndiHN/K4GUR1cPNaSRTeCfcg7W5TNTL45ea1
         Y1NBheP5MLIQp6g5tVDRp8MKYjfDnWmWbGJG1A1XOKqNLT2uZCMZ0zKQB+nMmd3Da5A/
         i7e2/OGrSUx10b/VGZOAhJTEgJefEW7OVDyG6nkWMx/GVniZZaB1mz4awVfYM4C0QBJJ
         E81JD9VcfFeFWBL71d9mv8zdL80mlH9iKNcTr9tqby+hUkqQ1odADN+ErvqqpKtGokzB
         es/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=cTIMqNqGxn8SyTfuRgVm6Hg6eCD38aSKxmdjDpoN4l0=;
        b=n66jvy4mw8pvnOYpJhC8kehjsV+ksry6+4VGwLgGoq7+8XAf5Mw0fmxzMWK5s4fW0G
         utFLEPkzYa3lm9v2J1D2z1hh9q2uYKTGRBmwYLi21TE3Q0EGBBxFmJnwASN2LPLwsyNr
         3d7VnuFOww8Y+DKu8g9dTNttZh9IeyVEbL3K1AN/nF25FIGcK+9x6VHxEDRppkIzywXl
         pliToD6Kda/P1BLUWDhH851ou+FtfjOqu7JqVCHz7cFprE/XL0cgv0ayoDeq+r1t21Kf
         58hfqoyFVVM+baAUPeBb1rqKbIYCaAAZMBxC7oAixTS2KAsbM2ubWrA05qljL5FiZfle
         lmag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rks9uNCm;
       spf=pass (google.com: domain of 3nz8jywykcwiglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Nz8jYwYKCWIGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=cTIMqNqGxn8SyTfuRgVm6Hg6eCD38aSKxmdjDpoN4l0=;
        b=T121CFyhfDD8ekoK+7JVnB8blc+3fnBhUh5V5V0E2ToomOPGABfVO+zL4vkUO09b/D
         WfHSO0ZTSLZxeVChLglJn70djEgecPoPjJr6saIS0dGw1oytXw4XNtlFvUMvAaDqQURv
         o7doOkik3Xbwt7i4MacyM5YZPg/OEuXlaU8/xgWluUNbxzNeyT7/ZN4v1rW186nj4NYf
         0gO6HbgUperYSTNtvoJj5aUc6E4JwtV7Z+jDYbGwtGHlIZOdZhgIGwNIsafs+Zs9fWhr
         sF4WnsMgxcWU52zwR/GyZsCu9ILuYaZqwH5r5UCL0zM9HyF9rWV5QhtA9ks10N5FVDod
         PqzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=cTIMqNqGxn8SyTfuRgVm6Hg6eCD38aSKxmdjDpoN4l0=;
        b=cfUw1IMjoLhpfzaeIIpwxmHc1iecF+ggMxCAagt+Hn3+TrFHHzAoZJBcyB3VKrHRU8
         MmFBXa/5+kakGl+RwRPES/9Scys8JO0mg68rGK64ypFNRIUFBsk6c1XnFl7w2GcvBxym
         gn4IqAVMenwgzE8OAmx+312FeSR1aYB1mGOtGQ1kMhT1jALsZO5FKHKWS7uJaw0ktbhy
         xH6Zv68XQ4RFIEQPL39oH6ah4HLtWdAMmYoc2tCP11qKwSMn9qV5hA+/Io3dd4dqFZbz
         YDdJGHoq1OsT969P2wTqCTbz3lqq+4aLztRGg9xrzhg8uqVHL20lGAr8V4szy3KTTy0h
         HBkQ==
X-Gm-Message-State: ACrzQf1gA7OSlL8ecqqgQifdd+7JBdUGe8FXNxzoRQj1UIjyr05RExzJ
	FzKwv5NSnbfrXSlhyTgb0/8=
X-Google-Smtp-Source: AMsMyM7Lf5LC0lc6FOa8HtTr8cQbLh524xTY8vl0qch8vEbHT3Lj15Hdyxo50X5cVRtkONyZl8du/A==
X-Received: by 2002:adf:ef52:0:b0:22a:6ec5:a0fd with SMTP id c18-20020adfef52000000b0022a6ec5a0fdmr86125wrp.190.1663254329475;
        Thu, 15 Sep 2022 08:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4cf:0:b0:3b4:a307:9032 with SMTP id g15-20020a7bc4cf000000b003b4a3079032ls1783651wmk.2.-pod-control-gmail;
 Thu, 15 Sep 2022 08:05:28 -0700 (PDT)
X-Received: by 2002:a05:600c:4e94:b0:3b4:b416:46c3 with SMTP id f20-20020a05600c4e9400b003b4b41646c3mr160958wmq.149.1663254328269;
        Thu, 15 Sep 2022 08:05:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254328; cv=none;
        d=google.com; s=arc-20160816;
        b=0WYbWjz5RdoFiWdx3XE5e5kt1e+cNDFhcqmjXC3QjVE54qaC8gdCKhR/C2R8KBUaCu
         bRNb4nuKlTFwjDeP4swAx2CIoVKD0Y9kPvjBHL5fEpyfw1ujH585PWFE0Wr+jVAdaha5
         TDCIl0slIzspbEqbtPHtqEhquNPplBIETYaxsmWdPyW1BHpCaAj7ISGFIB5/UWzJvZZe
         iqMWJB4ErtPrJxX6PPPj2NBlh/itkhWEtpsQW59oMVgruyUYyRUSBH3qGSMkY/KqWusR
         1s+P49q8W+w5SwaPfu5aTO7EZGJ45wtYczdHia2Fq5GODAZ4XRp2wqUTM7Hh/Tt83wm8
         93mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=78o9fcmZe1rakLyEcoaxPY9Q3UwZCgWFE2+savdbFCc=;
        b=eM/vVoWTAV1pKNTZ8P7K588WiI3w8NXiMFPQreAJePLbkPTCE7ESwAlenpBEEf5VBt
         F3ljXpsVY4/ScD/3hxAXYMP6fw/xmJaTeEhO4s0Vnq51qGWDqbffJqjmCdYm21UiHUFA
         QW6t5FiJPmLOhN9/NW/mLP6yxEOLI8pwdPunUlpZ2p9nM4m7+rQ+TWRi/mJ0q8k3QH0Z
         65z5E4GFrcBtI+jnlci4HqX9CG2YBlwJRAfM88kNfq5JD5GL+XvxyW/wB4w6bCnhoCXH
         QGW+T7t0GN8Eak+0gpcPWzNcBfNz5gff5Ut5cte8h0SLX6dfJ4a4J2YzcfeYcEvPU8jS
         kMFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=rks9uNCm;
       spf=pass (google.com: domain of 3nz8jywykcwiglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Nz8jYwYKCWIGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 65-20020a1c1944000000b003a5a534292csi44755wmz.3.2022.09.15.08.05.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:05:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nz8jywykcwiglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id y9-20020a056402270900b00451dfbbc9b2so8664034edd.12
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:05:28 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:aa7:d8ce:0:b0:44e:8895:89c2 with SMTP id
 k14-20020aa7d8ce000000b0044e889589c2mr272708eds.382.1663254327816; Thu, 15
 Sep 2022 08:05:27 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:52 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-19-glider@google.com>
Subject: [PATCH v7 18/43] instrumented.h: add KMSAN support
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Biggers <ebiggers@kernel.org>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, 
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=rks9uNCm;       spf=pass
 (google.com: domain of 3nz8jywykcwiglidergoogle.comkasan-devgooglegroups.com@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3Nz8jYwYKCWIGLIDERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--glider.bounces.google.com;
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

v6:
 -- rebase after changing "x86: asm: instrument usercopy in get_user()
    and put_user()"

Link: https://linux-review.googlesource.com/id/I43e93b9c02709e6be8d222342f1b044ac8bdbaaf
---
 include/linux/instrumented.h | 18 ++++++++++++-----
 include/linux/kmsan-checks.h | 19 ++++++++++++++++++
 mm/kmsan/hooks.c             | 38 ++++++++++++++++++++++++++++++++++++
 3 files changed, 70 insertions(+), 5 deletions(-)

diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 9f1dba8f717b0..501fa84867494 100644
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
 
 /**
@@ -162,10 +165,14 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
  *
  * @to destination variable, may not be address-taken
  */
-#define instrument_get_user(to)                         \
-({                                                      \
+#define instrument_get_user(to)				\
+({							\
+	u64 __tmp = (u64)(to);				\
+	kmsan_unpoison_memory(&__tmp, sizeof(__tmp));	\
+	to = __tmp;					\
 })
 
+
 /**
  * instrument_put_user() - add instrumentation to put_user()-like macros
  *
@@ -177,8 +184,9 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
  * @ptr userspace pointer to copy to
  * @size number of bytes to copy
  */
-#define instrument_put_user(from, ptr, size)                    \
-({                                                              \
+#define instrument_put_user(from, ptr, size)			\
+({								\
+	kmsan_copy_to_user(ptr, &from, sizeof(from), 0);	\
 })
 
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
index 6f3e64b0b61f8..5c0eb25d984d7 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -205,6 +205,44 @@ void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
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
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-19-glider%40google.com.
