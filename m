Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEODTH3AKGQEKF73KNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25E1C1DCBC3
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:10 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 63sf1783082oid.15
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059409; cv=pass;
        d=google.com; s=arc-20160816;
        b=MNlbPcaHw3egr4COyjwFATlCBEpDqryzdS2X4Fc79Inqnu4cpqkdZ7N07X7STWKG3/
         sRJ6TXa0JjA0iMRY+AWD/axupeSKGvnt4Z3Evfgb4bx14vRrbHz6trSv7Jh3nuaART0O
         mUkbRj5kFSNqvGrmDqVAL8DAe11VRhw9WnkvP9ygohq/FX2hu6beJqFlk9ImfecW1NF7
         42aJY968+gO54NhjwhuPdQIMebafiJf0XiWNCp1C2XmX1Ta70YnlFlNzaq8Uiz2fGUL9
         lhWkwTJvTv2NbvXNd5Z5HaFx67lysUg8lBkiohb/AsBFgRQEptdueC3FbASBiLsvylTq
         +RGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zGIyL5Z8uZ+cu+PMBl2KlwfIpAn03EpHFXpE81Gidbw=;
        b=m+u7bUhqLfDnPrwTPvYlvUl86xObU0/yxGzPpkTTXxhjGgtGjtTvc7LCVOk+J87LbM
         UqHbCREJCKPLYbOMOVhG9XUjUu1BaogTgjrCyQ/ox1UWDvTkDdK2DGtMpGRyEeYM/5um
         4LJcFSk9MSwgyWArT+rsodWVEWpSkGAVtWW5BA7RNhNcQZAOeV64fYuHxqdpFz47XeiP
         AgcbAt61d3I3twZCm50ZgLsKyjamEhHDiH2dYgDWsGkYCUIWE5lTnUhvWGoP7iYc57gM
         nSkkxktSp8BHqVl3zp0rFKbxasvEXDromDjCryAnKZW1yldvgCeFT9Uili++W+Yc6eiH
         tjhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FdoZFAIo;
       spf=pass (google.com: domain of 3kghgxgukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kGHGXgUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zGIyL5Z8uZ+cu+PMBl2KlwfIpAn03EpHFXpE81Gidbw=;
        b=ShtrhlHy1rlgg7iBgIB5jJbmSHDgdRr0mqOlkhS7oOkB9YCkft2+IRF/q0mME5K6J6
         S6cKLoc70Tbxoh0q2CgDvrsoThi5CnXtVKPcTJGLG7obHp0moxIeksGf6XQaPUjOkjsW
         3ZiVao/ASOtNjjhqWvULz/esqqCHTfgB3vOcGl2XHT7UIJLbt+0NyU4Hx0rmCVfxEcW9
         RIDIvRGD+7I7FgS5DafCpmdEp0PX7w/AnAknd1AAVI20GtVhRDC4dmvAlpR2JmtNbVoc
         /fHYGlsTBYRMu2FyvqrAZiZtxaQG/FtT+ERhi5TPi3bUflAJTaiaFY0HdEAvjyL5YM4v
         V8jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zGIyL5Z8uZ+cu+PMBl2KlwfIpAn03EpHFXpE81Gidbw=;
        b=nBUMIteY7NA2fectXqTWURzzGOIVyhKky5mv2FSrZ3aUwQgivbWPuR4D+H+WUm0FN+
         v8GOVbJgFIuhtSlm5QYE5LIChFc+u1AcN5IcWnsSba8RxrdsiW9ExwRtHf7EGHw0uX4s
         HmyQLWX/Xqgg5nsNOrtu5Ug5mucRjwv57bC1TgfqZucE0WPzH+LNgfVnE5GYzn0WTjbH
         IAMBh1pj67epWCXVqEV0HBEuIEpmKJa9aVApS1wgSZcFIqgJFVbslyxeq/ZzJGptsWTB
         5Nx7qNGWDMNCuhciovctahz1jpp08H0a0Yx3/lvR7XzUTj2QM38TNe4ATTOVRt49N41J
         oKxw==
X-Gm-Message-State: AOAM5320TH5sfkDgBFBy9XY7Z+wwJ3sPlPSxBWNfOp4O2+Q6zi0FTBOG
	ZofJ/uihTwKmGd+mbaAqNow=
X-Google-Smtp-Source: ABdhPJwiklJIvVXtO1h/L+edF49m2W2135wuHQ4GaXcHYrtb5J+QO7Ub+Q+ncdMLhOP7M9GimBJpzA==
X-Received: by 2002:a4a:49ce:: with SMTP id z197mr6949528ooa.74.1590059409151;
        Thu, 21 May 2020 04:10:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a6ca:: with SMTP id i10ls101444oom.10.gmail; Thu, 21 May
 2020 04:10:08 -0700 (PDT)
X-Received: by 2002:a4a:e759:: with SMTP id n25mr6847227oov.75.1590059408860;
        Thu, 21 May 2020 04:10:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059408; cv=none;
        d=google.com; s=arc-20160816;
        b=vNwGxcNFIZ/+RPk+vVmsJkXpNjUQ1hcZ3xo5v3V+d3MUNGMLz+Wl6ED0/irvXvI0P/
         9ZWbHBHH5BsyFXhtMqzgiqK3PDP3xYJqr11FASvssjVGbntlab7B8hJEd/DoE+jWHjQC
         wwW/YjJwxSFgz0K4sgwfj8hFG6dkzLJicbT5XM9iVbI7BcDmiEpvjNYK3jPoGym9nBF3
         CF9xTBI8qPNbDh1QS5wI9bYs/ab2Qx4znYM42EGPpkY2BAdu6WuXrv+HH+aEivky3BQz
         kLaVPG75csdGVAvSvqEgFke+xTOg2PsVPFZ9jN7F+4iZ8eprB3+KoTl3plvR84I5Ez27
         UuTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=yPM4FruOpCgqlY8Fa/KGpo+V+oloeiebiyu3mkE+4Yw=;
        b=XAj43D94A3uOjFfN6wUnYDe7HlzW2hlSaT/lasWOYqJjNhndrIPvqda+Td8OC5t7vZ
         1dCGgFoqSTEUurSr6oS7ZHx9muiT/GEfgPryxRB1NiYocT0aP1gFo8fS6e+zQrDG+qG/
         KUla1B+DGb4Hxe4yJUND28wt1xoLxv4bVgTFMycI8neK6p/9G/JtyfV86T2n2nVrWiww
         UJ9qA2YCot6/RkMaoMdMzkxPRYzXAepfdfMgWoU00+BOVjmnBhr7PKX7rNykUI/6ncXE
         B9vPOkxXJRhM9SBpc+1evhxN8H9KhrCLaFDgZP/EWtOVIgY2S/CCySmQSpqGM3xd9tAG
         c5qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FdoZFAIo;
       spf=pass (google.com: domain of 3kghgxgukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kGHGXgUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e20si416409oie.4.2020.05.21.04.10.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kghgxgukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k15so4933064ybt.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:08 -0700 (PDT)
X-Received: by 2002:a5b:58a:: with SMTP id l10mr14644958ybp.483.1590059408475;
 Thu, 21 May 2020 04:10:08 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:51 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-9-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 08/11] READ_ONCE, WRITE_ONCE: Remove data_race() and
 unnecessary checks
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FdoZFAIo;       spf=pass
 (google.com: domain of 3kghgxgukcwklsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3kGHGXgUKCWkLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
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

The volatile accesses no longer need to be wrapped in data_race(),
because we require compilers that emit instrumentation distinguishing
volatile accesses. Consequently, we also no longer require the explicit
kcsan_check_atomic*(), since the compiler emits instrumentation
distinguishing the volatile accesses. Finally, simplify
__READ_ONCE_SCALAR and remove __WRITE_ONCE_SCALAR.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove unnecessary kcsan_check_atomic*() in *_ONCE.
* Simplify __READ_ONCE_SCALAR and remove __WRITE_ONCE_SCALAR. This
  effectively restores Will Deacon's pre-KCSAN version:
  https://git.kernel.org/pub/scm/linux/kernel/git/will/linux.git/tree/include/linux/compiler.h?h=rwonce/cleanup#n202
---
 include/linux/compiler.h | 13 ++-----------
 1 file changed, 2 insertions(+), 11 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 17c98b215572..7444f026eead 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -228,9 +228,7 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 
 #define __READ_ONCE_SCALAR(x)						\
 ({									\
-	typeof(x) *__xp = &(x);						\
-	__unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));	\
-	kcsan_check_atomic_read(__xp, sizeof(*__xp));			\
+	__unqual_scalar_typeof(x) __x = __READ_ONCE(x);			\
 	smp_read_barrier_depends();					\
 	(typeof(x))__x;							\
 })
@@ -246,17 +244,10 @@ do {									\
 	*(volatile typeof(x) *)&(x) = (val);				\
 } while (0)
 
-#define __WRITE_ONCE_SCALAR(x, val)					\
-do {									\
-	typeof(x) *__xp = &(x);						\
-	kcsan_check_atomic_write(__xp, sizeof(*__xp));			\
-	data_race(({ __WRITE_ONCE(*__xp, val); 0; }));			\
-} while (0)
-
 #define WRITE_ONCE(x, val)						\
 do {									\
 	compiletime_assert_rwonce_type(x);				\
-	__WRITE_ONCE_SCALAR(x, val);					\
+	__WRITE_ONCE(x, val);						\
 } while (0)
 
 #ifdef CONFIG_KASAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-9-elver%40google.com.
