Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOUUL5QKGQEFBG2F2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A0527256D
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 15:27:03 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id w32sf8754690qvw.8
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 06:27:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600694822; cv=pass;
        d=google.com; s=arc-20160816;
        b=0dsuhU3TBj1v4K6s7yPYG1JTjyrdidSaoFWgHWJd9KDuvO6MQEybpu14fetz2v+A1U
         b2PHobdPe71vlElc0E7V+GGB4Gx+iukQHCWJtOcTx9PBF9stW5z67xoDg0BTJ2KkYEHu
         ap3+hCSduCUqoXBPFDuvxNjICUSn2lMNaBZY7qD3gOr5jZcRORMOxu0t9CmpwR8Y2fDa
         qfVaQPrTv/3feUsVEpDrPZsdOS97YWnj0AIexwLUAgEFoUr7fN1plyR4UX9O8ALPY+ZU
         nnKCBBwqlZvrfU+Wg74Q/SWzJFOzbR0hzLcrrHGWFOZRJZf5UlUgGFoKq4p+rfDkEuhu
         auZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=hfWkFDtOwGF/UbC/a8lq9w8/hL83J5OvKW3FOgkIB10=;
        b=TYjxG3rh9s3X44k3YiQPdKkMgDWlj4mlVzkR3b3e/BAQHufRV98yCJ2yJCufn9qGpN
         qJvh+EDUNr1Rhinh7BpzsSSxlQWuq3pncNU0cBiFFcN1BKFRm/bkaZhwfp6ZS9CyujF6
         g9JEmYzbHozcEymgjaKN9R0sTWoGgSUh4+PTWqqrBanxUTJSz/h5XYAVZqgO3Y1rbVKb
         2eQeEkQNzuga3eC1vY1X+gzvZ2nVsc/M4N+5TqLS1geme6+PQbtJy2LzvN+J9oURkr2P
         oRtrfbDIUuyBZiXBRb7zR4nlqEZlVQ/5Vhe+t4GArMzZe5uCMHU3FEgfbTx7N0gPqBpV
         r69Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwQ3SH4R;
       spf=pass (google.com: domain of 3ikpoxwukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IKpoXwUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hfWkFDtOwGF/UbC/a8lq9w8/hL83J5OvKW3FOgkIB10=;
        b=AICBx+hB8tFgfnbYjQAgIVRRwiMCdh/bR/f349cSfuN7wf5iUyfO8S0xqZ9Tk9XYqz
         juPU9jb4+IwYjMepYvn/5j2TTJSy0VL+m3LsyHS5JVrgD7mBQeqRd4EeRU7LDZO1LQWj
         ZgSgpCDlqYkfGVY8+DjHaGryTzqdw3wiRiD+t/QmB4mK1u+NfXbwpoz+cW2p45uDcRmu
         BkFq4o0uBEaZ+9+KW0jXwUqqxaI3U3A/l2GWorjCvA+MUvce3WF7Bex+WRhAbKM6QJYX
         8LOG0skZ8Jy7a9YeEslNvrDBZjvpeYD34dxzeuU3TgFnGGyBlXIqIbeifj2W4rrY8vv7
         76lw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hfWkFDtOwGF/UbC/a8lq9w8/hL83J5OvKW3FOgkIB10=;
        b=YUPUPtfX3BBO5WdxUTFtEg5NZvPqgwnNTmm4P8bAK9j9T5LtPhoQyQoyjkane0+wfn
         lMqc0LtsEoGtJ4AhlIxlP7tlO4ohlW773NQwKyHNUNzZQZqz/IgGwMSYaD48a2ssUVi5
         9NnI2/z0TH9x12fjhF9NJJ8AQZqzN5XcGJPpH93RbzrdVCXWHXdo6Z0LUCRPG6jLTjfE
         1JlDMJ39uTMM0TLWMFkG9o+FXa3e70cmIDib6r2Z2cQDPEU6Ytpa1A4j3d4oKh49Vzjb
         miPvQOfBSXxtUEIWOMYMZeR3rsLN0RdqBOJ2hXA/yRAo0afB8MswO6nPtQIJ8EL7uBJP
         Jgdg==
X-Gm-Message-State: AOAM533VSTWy+hwLv/dipEA4bXEn2MF1uhv4l5JK7waXjdmkpcY/+WBO
	cVb+8yNRSAC5JzAz10iwoTc=
X-Google-Smtp-Source: ABdhPJwtWf/Wiw6s2ddVxKV4UfM30TR7Dnun8C5eI9w+6BDTQssZHrtACcjji5A7j68k2Ok89JgFwA==
X-Received: by 2002:ac8:46c7:: with SMTP id h7mr45986086qto.69.1600694819301;
        Mon, 21 Sep 2020 06:26:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:f50b:: with SMTP id l11ls6355447qkk.6.gmail; Mon, 21 Sep
 2020 06:26:56 -0700 (PDT)
X-Received: by 2002:a05:620a:4d9:: with SMTP id 25mr46442036qks.285.1600694816904;
        Mon, 21 Sep 2020 06:26:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600694816; cv=none;
        d=google.com; s=arc-20160816;
        b=KVG1XQvmW80209uSzG5nJz2y6TwBoJcHH6QGhx6Po2W3Qk5h/jhceKeXb0mxva+3CO
         nq4oz7V1Xk8EVNxkpmGFmwLlpw27cAPpPgnChamScaZLRkZnuSuYiN3/taZ9VnDbXbg9
         0aOzZwfBRNno3nf6euhQfMrhuJM36oXkNkfOfhHx4Y23KicGyWeldHbo/UZaoN5P12UR
         iMzyssq4nl3T6uqx/DTq1vAbmkMMTdWdeur/yZSgU/kTef5pDkapUouYGcIzfs/2znyA
         dkXeQLXzVLSmAIT/RbqK33grk3fntzgVD0ZlTZHYlH2vFPYryYyF53wMF75fbTkiuofA
         tz/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+R3FkgLg/uUxAfttfYVSjxdiI+HJZltSBRxJWgKHPWI=;
        b=ypY3Fx9Rfkze8p+D92Q5V+ZtFrisgiNr+bWM22uagIKmhm+SNV9DKlR/llyFf/t7l7
         mLmH9E8Orj5Udxb+rl0xrzBT/hRrk59V8G1s1UWBIjnKaFGZdBN3tD/62m/CIWZuWwn8
         nLFbd6DERFc6WoeH8+3uHOUtAJqgeOSR05qLYboOyiA/VHFR9LbQTy/Y8+Yb2khI/xzF
         XJl5KvArvBuRq8nkKwzC5PqFaPB7Io5W31IyhuR+mnnEXKn5ZXrofLZtEKOxacnZKOqt
         nEIhXDUs1bO7JWOqbTdg58ihoCpixufQPS2D/xLQoFKRe2czaSIVWa3Z43fcVBfPd0Go
         AihQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AwQ3SH4R;
       spf=pass (google.com: domain of 3ikpoxwukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IKpoXwUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id x13si612201qtp.0.2020.09.21.06.26.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 06:26:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ikpoxwukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id t7so8908111qvz.5
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 06:26:56 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:c709:: with SMTP id w9mr46105935qvi.26.1600694816482;
 Mon, 21 Sep 2020 06:26:56 -0700 (PDT)
Date: Mon, 21 Sep 2020 15:26:09 +0200
In-Reply-To: <20200921132611.1700350-1-elver@google.com>
Message-Id: <20200921132611.1700350-9-elver@google.com>
Mime-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 08/10] kfence, lockdep: make KFENCE compatible with lockdep
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, keescook@chromium.org, mark.rutland@arm.com, 
	penberg@kernel.org, peterz@infradead.org, sjpark@amazon.com, 
	tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AwQ3SH4R;       spf=pass
 (google.com: domain of 3ikpoxwukcrk3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3IKpoXwUKCRk3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

Lockdep checks that dynamic key registration is only performed on keys
that are not static objects. With KFENCE, it is possible that such a
dynamically allocated key is a KFENCE object which may, however, be
allocated from a static memory pool (if HAVE_ARCH_KFENCE_STATIC_POOL).

Therefore, ignore KFENCE-allocated objects in static_obj().

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/locking/lockdep.c | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/kernel/locking/lockdep.c b/kernel/locking/lockdep.c
index 54b74fabf40c..0cf5d5ecbd31 100644
--- a/kernel/locking/lockdep.c
+++ b/kernel/locking/lockdep.c
@@ -38,6 +38,7 @@
 #include <linux/seq_file.h>
 #include <linux/spinlock.h>
 #include <linux/kallsyms.h>
+#include <linux/kfence.h>
 #include <linux/interrupt.h>
 #include <linux/stacktrace.h>
 #include <linux/debug_locks.h>
@@ -755,6 +756,13 @@ static int static_obj(const void *obj)
 	if (arch_is_kernel_initmem_freed(addr))
 		return 0;
 
+	/*
+	 * KFENCE objects may be allocated from a static memory pool, but are
+	 * not actually static objects.
+	 */
+	if (is_kfence_address(obj))
+		return 0;
+
 	/*
 	 * static variable?
 	 */
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200921132611.1700350-9-elver%40google.com.
