Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZ6DUOMAMGQEUNVKRAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6ACFF5A2A5C
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:24 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id z7-20020a2ebe07000000b0025e5c7d6a2esf654355ljq.20
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526504; cv=pass;
        d=google.com; s=arc-20160816;
        b=fRQtCD26S4pxntOtIBe8qFjsL51CDQIOxn21zPPEKOULhGl/9Ca996U+L7YoVH2SPA
         /R6NEH/Yh2s1kiYgQN9zqJd5EHbEbO8m9G50wzzJXV/h/4m1XiMkjjWLjbYJOnD+lOZg
         o3piWk1oYRTjNC0fS4+xeub1qLPyoAxUkTP/ACdEz72ixaua0CvhF7e7w8zP1/wKEL/D
         XEhjVqcrpVLKMVptwN8trwPDVY7rM1FL87e0W8E5qAnZiwzUES50lf+lL0EhkzauaB5k
         +2vzRXUo56dAUEbA1HDRpHmwNBinfDTp2krJ7+EpZ7MY+JvCCIB98GdBBXQOXfL0U1t2
         ZcHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/BFlr4hB65pj7Q3hwtIBSvY9IhskYiGpyAiqTx0z+SI=;
        b=lMia8Lz+X2zdQtI5kerIiuQ7wwrV3uyX1JHlXI0gO/oeW2AgYcWLdsCJZaBKCjDfAS
         0tBl9/NHz0QGEMIVzReYkCJp3Ds8XZX0xSd5Ly6TrF7PFDnDdieQicKBa48Yxlrl13zf
         DAJT74iikmQ6xIE1K9bJISjQDo3bMwN0elcEthtQR5lN0rpPniXmJtt244aHF7tR/+HR
         oOtxRuorNj/IAiu7ANMGNlxD6ruN7+DhB04GvRjQo4FWB7XeFDwVV/e5V5z3bjB6XnvQ
         jpSrDNpInzqSiHIR0Jd5ToLpwqo6CvwZdQBDiI2rGWTMtBIuB9RrROiQt+6v8IEnKnkn
         9bzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jCaizTYg;
       spf=pass (google.com: domain of 35eeiywykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35eEIYwYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=/BFlr4hB65pj7Q3hwtIBSvY9IhskYiGpyAiqTx0z+SI=;
        b=mi1XEYLzYEbZJ298RLwbjofFW4qdW6ZIhLIJx//n1LhlBm8ZSjEyWp7t+zDyvi5qR8
         MixZjSng00B6xD8aK+/uVCIrKT/5I+qaksqFKoottUOm1HCXaFt9Mu9WqnTgRJBNqe1N
         RaDx1iy4el1i5UaF9/uH2KRsEKD6Lp9mVD7X07jQCznCf9wsH0H7nfKxM7MRQyOINc3D
         3jn8JLgtUevsQ0VlXEEPWoJF8WAfLG5nmJGuPjSO+vzpuhOgbBzU687WRfaF/fCKFQ/w
         Aot/llH7P1+RBP8YR1+VXQMOXR67k7Yk6yPuJgTYq5uWkBFQf3zIZdRiIDiPTQsFRlJ0
         ve/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=/BFlr4hB65pj7Q3hwtIBSvY9IhskYiGpyAiqTx0z+SI=;
        b=w4xI9sOoaYMSNuLZv0e1RBXmM1brIysMpY+4BLOI+OUWQTgAFj5IPMW80hgBO5R8qn
         PpmIU5m49OATlToRzLv9xWRbxgYHN5/HaZZIVJJHtntDnktroBJ/UjWkj/uV2XqUTr9u
         rci3Q6rR/N/8XYKFiLuD/ILyAcwzfpGTLi0LwyU6uE3ZNvBFvC+pXUbLxP64Tbga5FuV
         n7YMmHHTWhC+LNnLYXasaUZ6jFMjlj9QpfUKW1lwBxeQMLppJFbxRudtgQBOXHcreOn8
         RDS3j7GnwH+s5RqTvS6RlpH4P/L6LrC9rxmsaWfXpO0L0ucViHtwAsa9zfA6FhY6ZZ/A
         V8gA==
X-Gm-Message-State: ACgBeo3LiLFAv3QPrYjoK49Eru36OiN85G8YFCKkGzxTZ3V8Xk74uD9+
	gG7DpRZTdxAQe1Qpl4+cLns=
X-Google-Smtp-Source: AA6agR6FC9SZJNhBXoGKK8LwSf66zIPs1jfvV3eBlOEgrNhx6gtD7nTuXmh/Q/E/BPdcDNZv4As6+Q==
X-Received: by 2002:a05:6512:39cf:b0:492:dbf8:990 with SMTP id k15-20020a05651239cf00b00492dbf80990mr2864604lfu.39.1661526503903;
        Fri, 26 Aug 2022 08:08:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:995:b0:261:b5e5:82b6 with SMTP id
 b21-20020a05651c099500b00261b5e582b6ls707550ljq.9.-pod-prod-gmail; Fri, 26
 Aug 2022 08:08:22 -0700 (PDT)
X-Received: by 2002:a05:651c:4cb:b0:261:ca07:dc5e with SMTP id e11-20020a05651c04cb00b00261ca07dc5emr2677731lji.325.1661526502374;
        Fri, 26 Aug 2022 08:08:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526502; cv=none;
        d=google.com; s=arc-20160816;
        b=sZNIBSxIq1E3BG8Z6kzqivdNBBODQDlg6aPtEHgq9RYhv52z/LMtt+Chwc1tqXkSbF
         P5iT3bAB16+TXqDsqdo0OBLkevD3nGBCxvN63UJu3yZR/NK+7iAD/WQjgMJS5Qrq+S6W
         obOYEP2mja3T6cgCJXTPU02ZwwzWjLKltNUMG3jhk4EaQPB3TnFz8jp+MPyFqQChz0Nv
         Nsx7W2TkT2ird34TKA0yqAahb6ag+I24+5+IeCewokVajj6SKEKSsW/l6sWkBZYGruIk
         wwsrqYbkEaQ+8I6uZtEQI99dOCQLyL46yJ33l2YXP3IX3x0eD/01N+ZCSrcxBTYh9nLR
         oy9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=BPAgteciaEShNCu1utOx4VHGX1XRyq5ObvUAakfxq7k=;
        b=uLZBvpg01f6j/45+rNAH0uJvjAxivAS429NNLRpwxpKmyfsuYikMV4SGO+DISrdDTJ
         b94tBj0jfbs3b71EcP8w2L+DghmJHqDIBNtkVxE61G0ghtIuiMGbSvgp2JjRSLCvjwaS
         H4a5tjvZ/VcfDZiaLawoo5DU+2btboUbm/oXzrBQpxrsQTaaFBjpYEzDjr2HRe/QabWe
         +Uz5OIhyZwG9JdNREwscABCm5GDmauMeLmaV6ZyMAtGWJnMUcCy3KR6yx+AvhOoGMBjL
         WpO+f+772Xmt38M/vDqb5DkAZ3BW21x6qVq4qO78UAKF2nkHpU1OTVcbPDzCAYoEX18s
         XPIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jCaizTYg;
       spf=pass (google.com: domain of 35eeiywykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35eEIYwYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id n23-20020a05651203f700b0048b2a291222si62514lfq.6.2022.08.26.08.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35eeiywykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id y11-20020a056402270b00b00446a7e4f1bcso1253702edd.1
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:22 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:da0:b0:730:d0ba:7b13 with SMTP id
 go32-20020a1709070da000b00730d0ba7b13mr6038874ejc.332.1661526501538; Fri, 26
 Aug 2022 08:08:21 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:26 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-4-glider@google.com>
Subject: [PATCH v5 03/44] instrumented.h: allow instrumenting both sides of copy_from_user()
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
 header.i=@google.com header.s=20210112 header.b=jCaizTYg;       spf=pass
 (google.com: domain of 35eeiywykceosxupqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=35eEIYwYKCeoSXUPQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--glider.bounces.google.com;
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

Introduce instrument_copy_from_user_before() and
instrument_copy_from_user_after() hooks to be invoked before and after
the call to copy_from_user().

KASAN and KCSAN will be only using instrument_copy_from_user_before(),
but for KMSAN we'll need to insert code after copy_from_user().

Signed-off-by: Alexander Potapenko <glider@google.com>
Reviewed-by: Marco Elver <elver@google.com>

---
v4:
 -- fix _copy_from_user_key() in arch/s390/lib/uaccess.c (Reported-by:
    kernel test robot <lkp@intel.com>)

Link: https://linux-review.googlesource.com/id/I855034578f0b0f126734cbd734fb4ae1d3a6af99
---
 arch/s390/lib/uaccess.c      |  3 ++-
 include/linux/instrumented.h | 21 +++++++++++++++++++--
 include/linux/uaccess.h      | 19 ++++++++++++++-----
 lib/iov_iter.c               |  9 ++++++---
 lib/usercopy.c               |  3 ++-
 5 files changed, 43 insertions(+), 12 deletions(-)

diff --git a/arch/s390/lib/uaccess.c b/arch/s390/lib/uaccess.c
index d7b3b193d1088..58033dfcb6d45 100644
--- a/arch/s390/lib/uaccess.c
+++ b/arch/s390/lib/uaccess.c
@@ -81,8 +81,9 @@ unsigned long _copy_from_user_key(void *to, const void __user *from,
 
 	might_fault();
 	if (!should_fail_usercopy()) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user_key(to, from, n, key);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
index 42faebbaa202a..ee8f7d17d34f5 100644
--- a/include/linux/instrumented.h
+++ b/include/linux/instrumented.h
@@ -120,7 +120,7 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
 }
 
 /**
- * instrument_copy_from_user - instrument writes of copy_from_user
+ * instrument_copy_from_user_before - add instrumentation before copy_from_user
  *
  * Instrument writes to kernel memory, that are due to copy_from_user (and
  * variants). The instrumentation should be inserted before the accesses.
@@ -130,10 +130,27 @@ instrument_copy_to_user(void __user *to, const void *from, unsigned long n)
  * @n number of bytes to copy
  */
 static __always_inline void
-instrument_copy_from_user(const void *to, const void __user *from, unsigned long n)
+instrument_copy_from_user_before(const void *to, const void __user *from, unsigned long n)
 {
 	kasan_check_write(to, n);
 	kcsan_check_write(to, n);
 }
 
+/**
+ * instrument_copy_from_user_after - add instrumentation after copy_from_user
+ *
+ * Instrument writes to kernel memory, that are due to copy_from_user (and
+ * variants). The instrumentation should be inserted after the accesses.
+ *
+ * @to destination address
+ * @from source address
+ * @n number of bytes to copy
+ * @left number of bytes not copied (as returned by copy_from_user)
+ */
+static __always_inline void
+instrument_copy_from_user_after(const void *to, const void __user *from,
+				unsigned long n, unsigned long left)
+{
+}
+
 #endif /* _LINUX_INSTRUMENTED_H */
diff --git a/include/linux/uaccess.h b/include/linux/uaccess.h
index 47e5d374c7ebe..afb18f198843b 100644
--- a/include/linux/uaccess.h
+++ b/include/linux/uaccess.h
@@ -58,20 +58,28 @@
 static __always_inline __must_check unsigned long
 __copy_from_user_inatomic(void *to, const void __user *from, unsigned long n)
 {
-	instrument_copy_from_user(to, from, n);
+	unsigned long res;
+
+	instrument_copy_from_user_before(to, from, n);
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_after(to, from, n, res);
+	return res;
 }
 
 static __always_inline __must_check unsigned long
 __copy_from_user(void *to, const void __user *from, unsigned long n)
 {
+	unsigned long res;
+
 	might_fault();
+	instrument_copy_from_user_before(to, from, n);
 	if (should_fail_usercopy())
 		return n;
-	instrument_copy_from_user(to, from, n);
 	check_object_size(to, n, false);
-	return raw_copy_from_user(to, from, n);
+	res = raw_copy_from_user(to, from, n);
+	instrument_copy_from_user_after(to, from, n, res);
+	return res;
 }
 
 /**
@@ -115,8 +123,9 @@ _copy_from_user(void *to, const void __user *from, unsigned long n)
 	unsigned long res = n;
 	might_fault();
 	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
diff --git a/lib/iov_iter.c b/lib/iov_iter.c
index 4b7fce72e3e52..c3ca28ca68a65 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -174,13 +174,16 @@ static int copyout(void __user *to, const void *from, size_t n)
 
 static int copyin(void *to, const void __user *from, size_t n)
 {
+	size_t res = n;
+
 	if (should_fail_usercopy())
 		return n;
 	if (access_ok(from, n)) {
-		instrument_copy_from_user(to, from, n);
-		n = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
+		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
-	return n;
+	return res;
 }
 
 static inline struct pipe_buffer *pipe_buf(const struct pipe_inode_info *pipe,
diff --git a/lib/usercopy.c b/lib/usercopy.c
index 7413dd300516e..1505a52f23a01 100644
--- a/lib/usercopy.c
+++ b/lib/usercopy.c
@@ -12,8 +12,9 @@ unsigned long _copy_from_user(void *to, const void __user *from, unsigned long n
 	unsigned long res = n;
 	might_fault();
 	if (!should_fail_usercopy() && likely(access_ok(from, n))) {
-		instrument_copy_from_user(to, from, n);
+		instrument_copy_from_user_before(to, from, n);
 		res = raw_copy_from_user(to, from, n);
+		instrument_copy_from_user_after(to, from, n, res);
 	}
 	if (unlikely(res))
 		memset(to + (n - res), 0, res);
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-4-glider%40google.com.
