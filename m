Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEX6RSMQMGQEJE5MBWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E46E5B9DFE
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 17:04:51 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id s7-20020a2e9c07000000b0026c1202d438sf3911426lji.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Sep 2022 08:04:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663254291; cv=pass;
        d=google.com; s=arc-20160816;
        b=ActGNzWjyq4QhrRBwL6YqHGUgW2YVkLUvQ2WtHGvgF2SXVqkhvpHPbxK04lXHVEboj
         FZNj5gmz9R9Mnd+bobPxqYNnX1UOz30VuKR4znPrSKQmOpd7FGY0lTblUPKdRMrM3qY/
         CsiMvGdO00+vh8nwkfjQaYsT38NQLYV46UkcfMZgPcafWFHloV4gij0aUzkgEOxJN0z9
         yhElZ7RUQw+B/CTWrAd8JVmbT8/zBkaxf+rEL/JMA/rqrJtyrAVBmmqOWU394D4DOLTI
         sWkJbXd8KB5I8+n3uiI856jfJxJvHVQbDLVFRIzcWbkNwsIa86BeethcyRhqKjN0LdbR
         DW/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VJmLuzpNoCDlgeT/Oyxp+g5SP6hqIzeTzK006t7I6GI=;
        b=NwvGrmSxKxz/4Pe9GG3IYl+HmN8c3ThcGf1hVX0NN+3UAZGVolgG5r8u5XB8KvPfOB
         2QEMN8knN4OM9qnpVDqPKl4I1LsUSc8QmQpeC4uSWfvYMRq85/fsXHeqQQjA4jrOfcsm
         tN43ai8XABA2qGeDHDbBZWJHeVvd7B4HA/KFSs6pyE5/se6mLpaBhWz3a0gVfKhXuMi+
         7aRvcu9pWGwM5kvt9VbJCHvbst/8C9mnutTZN1Al0dHaZ9JyWKKo+eDCeXTERFPBwzOW
         D+T/csfDKlUm8tl5yIXXLu1sltIzRMbOwu3TFuy/4BMztWZKIqhA2bGwgygzCV1R9wOS
         Lb5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EznsgfSi;
       spf=pass (google.com: domain of 3et8jywykctwejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ET8jYwYKCTwejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date;
        bh=VJmLuzpNoCDlgeT/Oyxp+g5SP6hqIzeTzK006t7I6GI=;
        b=Rm43zaQNa1NafnteQMgQxCVmo1WFL/TbIK+fGY2c6ROYs/MYYbr4fjusaKjMf5yjc0
         u2pzx+2uS6Tg7S2b7hUQ1XVr8WSernNENkqVU+ILSLHzYVUy/v/vHqDD09Hsfp6vuZTB
         46n0IZddFlTlZeSmjd3P/0z15qLAHRp/td1hJDTlI0LyE3HwNAZiynqvPLH3CrUYNJvb
         8SkdiXBjc6OE+vU2OWpnz0rgHVDW/7/8k/qMwIpe1j5i87tp6FMHcbU/uoAph6KuqVHD
         ySfgzjTueDm41j9aFsUbcP6Tspj4nPEoe29nHaDZGjfrV/6pOuwZPQEKARuojtATVwKk
         v0ZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc:subject:date;
        bh=VJmLuzpNoCDlgeT/Oyxp+g5SP6hqIzeTzK006t7I6GI=;
        b=IOnRxCwp0DrPM0Jee5lG5YfrYUmjCp2nQMFUzsfC3NREfJ2Wlc5u7q+JhdjEy1Xdor
         uVqxpRT2CQNNtpFGLAoBlhN07mIwrnzDUvBQJ3bSpS8W+WoEbc1jkIDJXMTFGhBtYgY5
         VdAlRLCrQD8JcezajKWVlH18aaaDL1AgbOh+pqJinaKjbXreVi5mbwhZhX0Q7uW3B2q6
         3iO4Yg8rLe00Z2VUkdoe/QWJQ6Zaw7HYjaOV44tQYqLt4DvurfZiBHLMzVuf7COttSLA
         ILu/SiVWLooGBmKENV7PY3wEcGySluiDjJfrsUe38MZAzfz0Y9g5CpYt3BFhsYb7plPR
         5MyQ==
X-Gm-Message-State: ACrzQf3KaBUaMRFUFGXT/IZEQMSqQ1H29q3F3mcVQ0x3CzD06IAgYJX1
	5IW37zHA5C9nogCWDBT8qz0=
X-Google-Smtp-Source: AMsMyM5RH8tiqM2kmx8JeXuTKXCCCAerZG6xl2lXFBxcRIhn9H2v2HsI6qYMlFxBhdZJERsA5cYQKQ==
X-Received: by 2002:a2e:b88d:0:b0:25f:f179:3837 with SMTP id r13-20020a2eb88d000000b0025ff1793837mr50318ljp.357.1663254291093;
        Thu, 15 Sep 2022 08:04:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:808f:0:b0:26b:db66:8dd4 with SMTP id i15-20020a2e808f000000b0026bdb668dd4ls2132753ljg.8.-pod-prod-gmail;
 Thu, 15 Sep 2022 08:04:49 -0700 (PDT)
X-Received: by 2002:a2e:940f:0:b0:261:b9ca:6207 with SMTP id i15-20020a2e940f000000b00261b9ca6207mr65139ljh.192.1663254289761;
        Thu, 15 Sep 2022 08:04:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663254289; cv=none;
        d=google.com; s=arc-20160816;
        b=kU8IT5fB9PEK0pQ1yzLb2lKkuQEONjOTpI/UVZn2NHWNZJSfheTpQkcrFglOwpHWNV
         v5xIwUEqlIv8NasVVrI9waVqrUq9BVx2hBDpNLiDBYjrYcFsQpcyncS58LsVzcul6s1F
         jICoY0nj4Rz7/+npO3xmyDk4cOgZk8DLvvY4zxFhK49m0jpFuK3cQ9yPmm8U5LkSQK4h
         3qeO2nRawP2M0hRnAeZuDdeD4RSkKtc0wBhLhpktxrPjAYt9MsF75ROk5UkI84GMo/s2
         Ez1/24lrITtHhw+/hlGUMjrOQ3oIT5iUvQ9qGQ3YiurQNzN4ok1QgcmQ/MaqxPCZzFMK
         +iTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=gSZzwrXvhkj2wpolUx3YVTouxdXHw9PaTEDZ4n2e3I0=;
        b=z2yjF2JRsYaQtarU+WXDMu5qKSOErEpNBH148TtMz6ds0Y4vxPNMXjLqxSyGqOi1zf
         o3ezTylu2M4FoBNoNAYL5CqnTeM9KEF7OSEw5NMoGHlPKuLF+gpeJ6+vdpAgfI2+IMuQ
         l0yK6okrYn6rBMd/gUcQuI9sBddAfgUbPkLUuvJfim+8Gd9TKzNeENjLVfGsr2y+YnOb
         dUfbR/wACuJ0MaPkTL4KdTapcOHyc8Kn9q2igSrfUx0gSnVhTCX6302N9tHrhxLF4HQY
         hUQtkDja/RBpBv+5ZxmS79MiBcWVepf7s7V6WwfkSwa7P5c4rX/faFaogKcCXA+ZImQE
         eWpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EznsgfSi;
       spf=pass (google.com: domain of 3et8jywykctwejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ET8jYwYKCTwejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id b15-20020a056512070f00b0049c8ac119casi244013lfs.5.2022.09.15.08.04.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Sep 2022 08:04:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3et8jywykctwejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id m13-20020a056402510d00b004519332f0b1so9674372edd.7
        for <kasan-dev@googlegroups.com>; Thu, 15 Sep 2022 08:04:49 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:686d:27b5:495:85b7])
 (user=glider job=sendgmr) by 2002:a05:6402:c8a:b0:44e:81b3:4b7e with SMTP id
 cm10-20020a0564020c8a00b0044e81b34b7emr256022edb.181.1663254289168; Thu, 15
 Sep 2022 08:04:49 -0700 (PDT)
Date: Thu, 15 Sep 2022 17:03:38 +0200
In-Reply-To: <20220915150417.722975-1-glider@google.com>
Mime-Version: 1.0
References: <20220915150417.722975-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.789.g6183377224-goog
Message-ID: <20220915150417.722975-5-glider@google.com>
Subject: [PATCH v7 04/43] x86: asm: instrument usercopy in get_user() and put_user()
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
 header.i=@google.com header.s=20210112 header.b=EznsgfSi;       spf=pass
 (google.com: domain of 3et8jywykctwejgbcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3ET8jYwYKCTwejgbcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--glider.bounces.google.com;
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

Use hooks from instrumented.h to notify bug detection tools about
usercopy events in variations of get_user() and put_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
---
v5:
 -- handle put_user(), make sure to not evaluate pointer/value twice

v6:
 -- add missing empty definitions of instrument_get_user() and
    instrument_put_user()

Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1859fdf5cc485a2fce
---
 arch/x86/include/asm/uaccess.h | 22 +++++++++++++++-------
 include/linux/instrumented.h   | 28 ++++++++++++++++++++++++++++
 2 files changed, 43 insertions(+), 7 deletions(-)

diff --git a/arch/x86/include/asm/uaccess.h b/arch/x86/include/asm/uaccess.h
index 913e593a3b45f..c1b8982899eca 100644
--- a/arch/x86/include/asm/uaccess.h
+++ b/arch/x86/include/asm/uaccess.h
@@ -5,6 +5,7 @@
  * User space memory access functions
  */
 #include <linux/compiler.h>
+#include <linux/instrumented.h>
 #include <linux/kasan-checks.h>
 #include <linux/string.h>
 #include <asm/asm.h>
@@ -103,6 +104,7 @@ extern int __get_user_bad(void);
 		     : "=a" (__ret_gu), "=r" (__val_gu),		\
 			ASM_CALL_CONSTRAINT				\
 		     : "0" (ptr), "i" (sizeof(*(ptr))));		\
+	instrument_get_user(__val_gu);					\
 	(x) = (__force __typeof__(*(ptr))) __val_gu;			\
 	__builtin_expect(__ret_gu, 0);					\
 })
@@ -192,9 +194,11 @@ extern void __put_user_nocheck_8(void);
 	int __ret_pu;							\
 	void __user *__ptr_pu;						\
 	register __typeof__(*(ptr)) __val_pu asm("%"_ASM_AX);		\
-	__chk_user_ptr(ptr);						\
-	__ptr_pu = (ptr);						\
-	__val_pu = (x);							\
+	__typeof__(*(ptr)) __x = (x); /* eval x once */			\
+	__typeof__(ptr) __ptr = (ptr); /* eval ptr once */		\
+	__chk_user_ptr(__ptr);						\
+	__ptr_pu = __ptr;						\
+	__val_pu = __x;							\
 	asm volatile("call __" #fn "_%P[size]"				\
 		     : "=c" (__ret_pu),					\
 			ASM_CALL_CONSTRAINT				\
@@ -202,6 +206,7 @@ extern void __put_user_nocheck_8(void);
 		       "r" (__val_pu),					\
 		       [size] "i" (sizeof(*(ptr)))			\
 		     :"ebx");						\
+	instrument_put_user(__x, __ptr, sizeof(*(ptr)));		\
 	__builtin_expect(__ret_pu, 0);					\
 })
 
@@ -248,23 +253,25 @@ extern void __put_user_nocheck_8(void);
 
 #define __put_user_size(x, ptr, size, label)				\
 do {									\
+	__typeof__(*(ptr)) __x = (x); /* eval x once */			\
 	__chk_user_ptr(ptr);						\
 	switch (size) {							\
 	case 1:								\
-		__put_user_goto(x, ptr, "b", "iq", label);		\
+		__put_user_goto(__x, ptr, "b", "iq", label);		\
 		break;							\
 	case 2:								\
-		__put_user_goto(x, ptr, "w", "ir", label);		\
+		__put_user_goto(__x, ptr, "w", "ir", label);		\
 		break;							\
 	case 4:								\
-		__put_user_goto(x, ptr, "l", "ir", label);		\
+		__put_user_goto(__x, ptr, "l", "ir", label);		\
 		break;							\
 	case 8:								\
-		__put_user_goto_u64(x, ptr, label);			\
+		__put_user_goto_u64(__x, ptr, label);			\
 		break;							\
 	default:							\
 		__put_user_bad();					\
 	}								\
+	instrument_put_user(__x, ptr, size);				\
 } while (0)
 
 #ifdef CONFIG_CC_HAS_ASM_GOTO_OUTPUT
@@ -305,6 +312,7 @@ do {									\
 	default:							\
 		(x) = __get_user_bad();					\
 	}								\
+	instrument_get_user(x);						\
 } while (0)
 
 #define __get_user_asm(x, addr, itype, ltype, label)			\
diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index ee8f7d17d34f5..9f1dba8f717b0 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -153,4 +153,32 @@ instrument_copy_from_user_after(const void *to, const void __user *from,
 {
 }
 
+/**
+ * instrument_get_user() - add instrumentation to get_user()-like macros
+ *
+ * get_user() and friends are fragile, so it may depend on the implementation
+ * whether the instrumentation happens before or after the data is copied from
+ * the userspace.
+ *
+ * @to destination variable, may not be address-taken
+ */
+#define instrument_get_user(to)                         \
+({                                                      \
+})
+
+/**
+ * instrument_put_user() - add instrumentation to put_user()-like macros
+ *
+ * put_user() and friends are fragile, so it may depend on the implementation
+ * whether the instrumentation happens before or after the data is copied from
+ * the userspace.
+ *
+ * @from source address
+ * @ptr userspace pointer to copy to
+ * @size number of bytes to copy
+ */
+#define instrument_put_user(from, ptr, size)                    \
+({                                                              \
+})
+
 #endif /* _LINUX_INSTRUMENTED_H */
-- 
2.37.2.789.g6183377224-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220915150417.722975-5-glider%40google.com.
