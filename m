Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4GCUCJQMGQEKTEECHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id E63105103DD
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:44:32 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id i21-20020a056512319500b0047223ce278dsf336323lfe.18
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:44:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991472; cv=pass;
        d=google.com; s=arc-20160816;
        b=WHigfLuRmKV95yfp8YtQqrhvWCp+nRAPXDo3uAOQcmg7VFGxXtNaBxE3q28p/sxkxK
         XdOUI/3UBKDrprMcyWmPFerT97x80jIKyjo8JP7CWfeJyY2p9OQCtH/N2NGAYy+WmxHG
         LaffyzokofO5xbH4ZtZ//WQYvwDPh1SiwUgy14SsjBFm28WqSoU0yQ6f5EFg+cMaMM+1
         g80faW9hnCTHeyby3+lFSn12PoMonxTtu7tJ6knIJpdzz7R8NIurQXJlTCOOXuLjdROS
         N55DboXcDGJoN5Yx8tpS7bANNvUMl8su29Aq2re+vphJ8Q+C/f+1TIEfCoRquTxH3zbv
         rKFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=yeM0KVCEB/fOOBgIxm28XHOQo5/hAXkXy+T8QPssts8=;
        b=eMK1Pj6wd5oeGJWVUB5wocV0V/hYxjDSYMj77TZecoRw6jWagW7fQNkgzmwupQ6WUz
         2zFgDpBZVwi25QyNyrkEgQrDL5CwHtLuNnrB5EQ7NMxxy5XS+GxDWRhD9fje60Pxr4GJ
         zHKKrHfwEy1/zn3TbMb5LK06HwbgitZzeTPaknHPZqia8JEneM8eIjW0OSBD0EjFp1ET
         z5lP5pLEBA1ScQnay61au91SIcIA7Kl6ro3XR1xkLLItm1Ea1Oqr8CJZSZsNjSSD4pFh
         utqt0VCHJyiv8pjVse+QYpl3dT8AiMbukT7H4KcZ0gvWbo3uRbTs9v7pv2cn4LBpoEsm
         YHng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="socyW/SW";
       spf=pass (google.com: domain of 3bifoygykcwspurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3biFoYgYKCWsPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yeM0KVCEB/fOOBgIxm28XHOQo5/hAXkXy+T8QPssts8=;
        b=bSRuYh2aUT8nbz/2g+bsnU1oth5Dxi67euOg5KFAt1NRVv5TzDMI58VsKNU60itshQ
         8ce2BbcHw7m0QTkz90SdVh1dp4UoOD9FaDJ4el8zr3hYD5g5SBUAIvXoPMpgrFYUUqFa
         Mc/LYfSCbLiKHU+05bt5mRLnKvMqQ4mbcDnLX9mAhKcsbecEvlY7v5l9LcvBjK/WhQ75
         LhM7pd766FEy5XsRS2NWYcKigQUzJom+BNWMjEIKwO/3A66Em0xGhzgDBKU9G/3NgROi
         re6bo5pxnrCyWiz0nnLxhfx714ZKbjpqI8jaxzICe3xV2loFyjoQ3X1R0eyWvO/HI0cA
         /bhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yeM0KVCEB/fOOBgIxm28XHOQo5/hAXkXy+T8QPssts8=;
        b=AczeQWl6i8g+CJo/1RDtn5W6WoVFYIcConIq/d8U5Exjb+js7z74OMVbvx8kT6hHNK
         lYI6BlJ0PP3yLXEz+3gAQMrY8vyU2q6fZkVcqnM71tkUKPovqz8DsMpdBzjAW0gkyxW8
         v0nQDKuEZn+ZfgGJa3Xc9tvpX1FGdCvrbfKXnxl8IZxPbmbweDlqHpk/V+5nIGkqYKja
         gHE8+8bsWKdASktaFzLDo8ZUl3++0BqkXP1QcseeiNDgRhSwacamR8xCauMhVlOdRM61
         Clef/BStlT/GfuB3f2Lvd+l7fdMwc7qy/C3cc51/9US/u8Kuu6dkoB4Cvxz0HfL4+s54
         9vjg==
X-Gm-Message-State: AOAM532+fpPNa0uVi1Q6yfDjfgqHVVXX/50wS377+9Ls+T6fVWyIDSAw
	/vTSs7FVaWA0TEGz/Axup3o=
X-Google-Smtp-Source: ABdhPJwPpgAnvSMiopevSnsYveyW1ozuZNTq1L29BOC5Ai8vCiKKvoSwqjhf55giHmuQrAqfyD4e4w==
X-Received: by 2002:a05:651c:10b:b0:24f:24a3:9dec with SMTP id a11-20020a05651c010b00b0024f24a39decmr1409405ljb.144.1650991472518;
        Tue, 26 Apr 2022 09:44:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls2080163lfb.1.gmail; Tue, 26 Apr 2022
 09:44:31 -0700 (PDT)
X-Received: by 2002:ac2:4d32:0:b0:471:fa43:ad01 with SMTP id h18-20020ac24d32000000b00471fa43ad01mr11027469lfk.276.1650991471365;
        Tue, 26 Apr 2022 09:44:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991471; cv=none;
        d=google.com; s=arc-20160816;
        b=OkbJm8kuqiLdeupX+B5+IjbTtvRw4D+gnxNbXUftZypMBiNl6M3033LwAwIus9HeEX
         vkrmsVvoWj6EKdG/RwEKt5jx514uj2hzyxOfKLNhPAJ/H0FUTha10i49ogxqZVxD0yKc
         WjpfgFlqiutcyuDpsFAmsMtJyc9tKJc+e2wldS0xX9N6uF2fjCziXoXCOw9DpjJwFRZD
         pZexKB6XtG15/Zj/BwvGEkkoC7cIE6LwOkNrfo7f0JVijs1XoQCrgeGCJwNImRu1mEVI
         iDj0RLFNe4TrY/jMRrtWxVfegRvmP1/wSaUnhxDYtLTynicZG9uchIl0KM/STwNuVkhA
         XGVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=jT7N8sHbqw5Bt63XokggrytDJOztxBUcMGiWNZUZnNs=;
        b=pl83Q75yhWrMQzq+gK+OLt9QzL3RuPT+8ulr0yDG0wIFt7drHP3BYmdym3DCgBmxzi
         tMtaq2xWJi9KsAOaD8SvYZq985VbbcarjRPRgZnuP0S8uevKW7iT+ZnKpCP9m6aBkvK7
         O4AuGLYtRdbyBh0k5fwps0rDJ00B7zzpocgmheoYBILn6I/M34MAHOpp46XULJbnMWjn
         EW4kkwbXdeALq7pS2ct2rC4ZKqaGLk0+x2gW3LDnAu73dMmUIEtihFn9BFFCqQuuwsEt
         mBuuWLKtI4p6KZS8wd7fatx36JeayyCaBy2vfEW2RS5y9Hl4GSlTiW8vpFkqyc4MsNLO
         osgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="socyW/SW";
       spf=pass (google.com: domain of 3bifoygykcwspurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3biFoYgYKCWsPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id e9-20020a2e8189000000b0024eee872899si542605ljg.0.2022.04.26.09.44.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:44:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bifoygykcwspurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id dt18-20020a170907729200b006f377ebe5cbso4558016ejc.22
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:44:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:3593:b0:425:dfd4:2947 with SMTP id
 y19-20020a056402359300b00425dfd42947mr14309082edc.137.1650991470646; Tue, 26
 Apr 2022 09:44:30 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:33 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-5-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 04/46] instrumented.h: allow instrumenting both sides of copy_from_user()
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
 header.i=@google.com header.s=20210112 header.b="socyW/SW";       spf=pass
 (google.com: domain of 3bifoygykcwspurmnapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3biFoYgYKCWsPURMNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--glider.bounces.google.com;
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
---
Link: https://linux-review.googlesource.com/id/I855034578f0b0f126734cbd734fb4ae1d3a6af99
---
 include/linux/instrumented.h | 21 +++++++++++++++++++--
 include/linux/uaccess.h      | 19 ++++++++++++++-----
 lib/iov_iter.c               |  9 ++++++---
 lib/usercopy.c               |  3 ++-
 4 files changed, 41 insertions(+), 11 deletions(-)

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
index 546179418ffa2..079bdea3b9dcd 100644
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
index 6dd5330f7a995..fb19401c29c4f 100644
--- a/lib/iov_iter.c
+++ b/lib/iov_iter.c
@@ -159,13 +159,16 @@ static int copyout(void __user *to, const void *from, size_t n)
 
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
 
 static size_t copy_page_to_iter_iovec(struct page *page, size_t offset, size_t bytes,
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
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-5-glider%40google.com.
