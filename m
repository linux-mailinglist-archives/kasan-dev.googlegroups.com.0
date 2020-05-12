Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRW25P2QKGQENVSA5LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F5E61CFD6C
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 20:39:03 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id r189sf10181704qkc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 11:39:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589308742; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ee2Oli/oQJqaRn4Tru6dzoQpfCjBr1C6wB6e30M6ZlOTFZs30IkiLjy9lquDZkUBlB
         M1ioUvPv6b+1ILolKjVgHFgCzKKgu2wAQrvFlT8/DWlxdBXSmNupFF53KJ2RnZ+AR/5W
         z02yZfJsX3PC1lDrtRbxb2a1gfIzx6q07nRmx7fj+bQXzw6OmQPbzSSz7l2AChCn9b1N
         KjyV6uVQySBFyUdXPBmA5UiPM6Dm6SJW4KHYdhuT/7Cc22FtnghNXdEw4kyqF+hgk3qH
         Yfduwvx1OwGleJM+m34F9Mq74LNRf9l9zx/oBkeHf+iuwiSH0OrzEDT9oNz9H4iRTCvp
         unqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=x3w7HfaEo5bMQHkADuV3VNihvrMynrnJVufZ3HrgAoM=;
        b=StYyB8ZnzOoI5pmoCTcjRswfTXe75URQT2PInWbdYZypqkIGP7vN5Qzs2mS5DVzDJ6
         7vV+dHqlyWyUR7XTzC/lOZ2+mEg13TEtSqZfvpQUD1FCmL9aVhHEpr2M6sTpKGsA6A9Y
         QxsTfIufQoCTSYPCaM8k9ECvHR8+QMn0uGDhuaBwL7C8ebax5w096NOSICrt5M+ReTp8
         x7hBBw345C5SPoICX7CnnC1yERp49gttQF6r7/KjKIgx4auy3hd320h7SLeBmqR4wv1X
         5dbgBDU8S6f/QkU/h08KmDHN87ejuSiiqWluw7vSc8PaeZm6bWxKjyg1lE+VZ2F97dpd
         wbZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I0P6mE6Y;
       spf=pass (google.com: domain of 3re26xgukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Re26XgUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=x3w7HfaEo5bMQHkADuV3VNihvrMynrnJVufZ3HrgAoM=;
        b=odQsceOdSA2fkk9KsBIF2sCkIJX6UEw1s7fJy4LZZjitAUvBXw6vKaEG76koSuvDg0
         akQtse0T7WVYmlUApjNiiJSokaD7o2YbCc2cPe90igQPmgBta24P8O5xTCjAz9EnVcME
         aC+/51yblaZZi+EsygiE0yuUoeLzLC2uW/d5mQwdBHQV1bdwCWTsY7MNg/syQBWQfsMA
         bA4juInXE4FUWiZNXsOjB5ZumJx08nzHPdcc1e1kikEp7bBNjbp+s4QHPqqRfL8q4T1p
         VVRs+XTLaCJFUpGu0QTbi08bpDbI4FKMbExPO4E0KWQ96b8jYaPn+Qk3ofbXKZ+HvL8u
         wmjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=x3w7HfaEo5bMQHkADuV3VNihvrMynrnJVufZ3HrgAoM=;
        b=Phb/mswEMlXhYYs5vRd5DZjKCtAjv5xy+vB8QU7qUE1xwrWmOusR0y7b95p8Nzoez2
         jtJhnp2dhDmxiCvuy+nkrtOmSfdGV9Dwasa8h2uzijHVDkzBTo5AW85f8KQMJcxq+DEN
         Zi6MUQ/qq9p/sKtsGz6wdF83oMTT1UC4GqD8opYL+sf/sGuoU5nMwfrzT5i73t1xosSH
         pSe/LOQfKE8M7VL5kN7qet8S8QXOsDY4+Z5rFK/x+2ZUGi8v2MBd2YxScZIWnE7MKCUD
         o//Y7wgH3ytNZFRBnlo0Sw06Urv/A7kQ4Yu5ZgPDuznRrWcigSaZnsB5v6hOgSOcVjx3
         GFXw==
X-Gm-Message-State: AGi0PuZXX1SMDqj6KsJHOsF6slSGrUxzHOaaBPCaUSUkr9m3OJHX0+BH
	1x/g4gDl/oxZQNlWN2qxE4A=
X-Google-Smtp-Source: APiQypJZPlvzXMQxUE6bnIGma0wxjctrRHIQnIsRytFO8ayPYl+X3VPzQ4/uNjqilhG2JmHPoHreCA==
X-Received: by 2002:a37:640b:: with SMTP id y11mr22599796qkb.266.1589308742159;
        Tue, 12 May 2020 11:39:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2d62:: with SMTP id h89ls749557qtd.0.gmail; Tue, 12 May
 2020 11:39:01 -0700 (PDT)
X-Received: by 2002:ac8:524c:: with SMTP id y12mr20385304qtn.350.1589308741761;
        Tue, 12 May 2020 11:39:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589308741; cv=none;
        d=google.com; s=arc-20160816;
        b=pF4zSrJn3UxBqkEueJq7LD6CrsaQv+SuRbfoCurGY6Zhm/kPaVywuxpnMcaCAEv9z7
         YUALygtgdovHZ+AN8NzKiqWNviFgoo1MGVWNPxR/283N3tMzEj4dGAZRe9r4eNc5HHeu
         xeL8X9xWYslmZEip/QfAUXJIOhXKTcd6i/GOkpBRyn9uCAetMBiPRvXqo1jm8aFywXJ7
         9l2+UKSz3d8sFWnr1q9ReCFaR5CSqLpyeOcCpvnKM3Z7jZdnlAQR3stp+jaCxaumzPof
         C+INUtiaQqlPNISW068WN0bVOkU9y5xqkF2/psNxEN63IwVyP5tnAXfPYkPoq80UgsJy
         dD0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Ps+E68vTZBQzCMKZDqxPDdmjNakB1JNehAqdvEI79/o=;
        b=Eyd6gGNl8eCWoUH0K3K1n6iRMcyIR5IqDvWkjnpBeG5IcadNALaNWhDdP6B+j/81hd
         bV/448fmmuF6UfcudVjm26P2GtWgqfSG2oFqHrGqmjgimR7WjFOS+Ob3NefnTsPstjoT
         R36qwBfVbdgs/Hv/eXzALH5rYzLxl47zQMkhmZHiCMYkt6BO5WS01aXTCywSkrW3OhtY
         5y08FcC0teEdo5J+7Uj+3ae81USpDLzZyHU9O6YMWDEZLf7TUYS/UD/3Y0UqZxyUr7M0
         B7wCNxWnFAwweKVOnmKlqr/BpdBfPdMK4GTYlk/8nPAo2ZSqJiQVKinUqHAxhmssylnP
         pMWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=I0P6mE6Y;
       spf=pass (google.com: domain of 3re26xgukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Re26XgUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id q4si659666qtn.5.2020.05.12.11.39.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 11:39:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3re26xgukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id l17so8465741qvm.12
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 11:39:01 -0700 (PDT)
X-Received: by 2002:a0c:ec4c:: with SMTP id n12mr11416847qvq.190.1589308741420;
 Tue, 12 May 2020 11:39:01 -0700 (PDT)
Date: Tue, 12 May 2020 20:38:39 +0200
Message-Id: <20200512183839.2373-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.645.ge9eca65c58-goog
Subject: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=I0P6mE6Y;       spf=pass
 (google.com: domain of 3re26xgukcqgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Re26XgUKCQgmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

If left plain, using __READ_ONCE and __WRITE_ONCE will result in many
false positives with KCSAN due to being instrumented normally. To fix,
we should move the kcsan_check and data_race into __*_ONCE.

Cc: Will Deacon <will@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Ingo Molnar <mingo@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
A proposal to fix the problem with __READ_ONCE/__WRITE_ONCE and KCSAN
false positives.

Will, please feel free to take this patch and fiddle with it until it
looks like what you want if this is completely off.

Note: Currently __WRITE_ONCE_SCALAR seems to serve no real purpose. Do
we still need it?
---
 include/linux/compiler.h | 15 +++++++++------
 1 file changed, 9 insertions(+), 6 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 741c93c62ecf..e902ca5de811 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -224,13 +224,16 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
  * atomicity or dependency ordering guarantees. Note that this may result
  * in tears!
  */
-#define __READ_ONCE(x)	(*(const volatile __unqual_scalar_typeof(x) *)&(x))
+#define __READ_ONCE(x)							\
+({									\
+	kcsan_check_atomic_read(&(x), sizeof(x));			\
+	data_race((*(const volatile __unqual_scalar_typeof(x) *)&(x))); \
+})
 
 #define __READ_ONCE_SCALAR(x)						\
 ({									\
 	typeof(x) *__xp = &(x);						\
-	__unqual_scalar_typeof(x) __x = data_race(__READ_ONCE(*__xp));	\
-	kcsan_check_atomic_read(__xp, sizeof(*__xp));			\
+	__unqual_scalar_typeof(x) __x = __READ_ONCE(*__xp);		\
 	smp_read_barrier_depends();					\
 	(typeof(x))__x;							\
 })
@@ -243,14 +246,14 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 
 #define __WRITE_ONCE(x, val)						\
 do {									\
-	*(volatile typeof(x) *)&(x) = (val);				\
+	kcsan_check_atomic_write(&(x), sizeof(x));			\
+	data_race(*(volatile typeof(x) *)&(x) = (val));			\
 } while (0)
 
 #define __WRITE_ONCE_SCALAR(x, val)					\
 do {									\
 	typeof(x) *__xp = &(x);						\
-	kcsan_check_atomic_write(__xp, sizeof(*__xp));			\
-	data_race(({ __WRITE_ONCE(*__xp, val); 0; }));			\
+	__WRITE_ONCE(*__xp, val);					\
 } while (0)
 
 #define WRITE_ONCE(x, val)						\
-- 
2.26.2.645.ge9eca65c58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512183839.2373-1-elver%40google.com.
