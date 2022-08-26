Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2ODUOMAMGQEM3F6Y3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id AAEBC5A2A5E
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 17:08:31 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id c25-20020a05600c0ad900b003a5ebad295asf615270wmr.5
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 08:08:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661526506; cv=pass;
        d=google.com; s=arc-20160816;
        b=gYfNOX+y6xjSWlvbvaaxBPnlNLwFMVfDwukd5ISmZKWX4jXq4WK4y4Tul9KeY2Bgvt
         bP0b3F3Zl+vwDtrkOSMCniBXBFw23TlD8jx1s1uXCFjtX9ihWyoBmB+PljikepCwtU9a
         J/I15ntwsCxuF82iqF80E1ce/E3Ar9tPFqw3Imsmxlde0Wu+jVKv0MV+Rv7WfUpPY7Bc
         gdde2LxJssJ45zez8JZlpbKmZwSrvg/OOZYU3/puSksFPzA2ke9JW3tlkRZMC13xM033
         pLfZPpuAhH1M8GDXtMRlp6ls3qJDpLSfFRsXUYGoR9WC1+0pS5D8UZVh6ijkHbBgzP2i
         qQfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=v7MY2xraN0Z4tXw1a0SFkVqUspUaOohTImHuF+sW9nk=;
        b=QRRjxMCN9MBlh21er8xldYH1Abb9FndeX4GJalgW6BthnJN9Sr7S+E9XXSlSGNI7Jk
         jm0H/H7g6+Ob1dqjgLHahRjOkRz68AurkAvgbscB4zihDMf21Q3MEnno4txutMVVnZLM
         li2oLEOU8KDGnr1Pq3bN5p7cVVdvIdX9VXovS1QPhZ/Lg4wpU/uq9BqS+UD/eYUJA5Q9
         qgdKAYMl1e+bbaTISPhPnE6LAZJp3ClLHBdJ2tYrABYZi5EBJLBgoMCTb7AXE4qmTyNq
         7i5uWTj4gqI+RV0utKJ4Dkzp1jUQNf+338pvoCtU9qoXjq3Njh/bZlbmuP6au9TVm9LX
         QGXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lGhpRwPT;
       spf=pass (google.com: domain of 36oeiywykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36OEIYwYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=v7MY2xraN0Z4tXw1a0SFkVqUspUaOohTImHuF+sW9nk=;
        b=mKWaBWMr/cMiqmD0SUO/ofacRnyyLNPHtlIbL8EFihPZqZBDQUy8ksTjHbFeydL3Yn
         oRG1uoKxhohWOw3lW3Joepxts0ad0MSJ1xIq8SNH2gaTHdRAMAEf/QuMV+eWiDMU1npX
         du837DleqzIY0eDV+sz6dGmRraFePvgz5Cc1DJ7k+xgKzTMIZ3lgBUy2CSUIx5aZ8fiK
         c0JNiZaGUiHW/Jh+QvcocmTadJ/5YfIU/ZTcNiKRSSpF1etPsII9pyR3BWt1nbE8GqW1
         C3ChBZMFFxWNQgW3ezybI3VJvsOhatdQiWNEBO7LpCl3D9BHLcMMSibcuOu01PBZCQCe
         xUuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=v7MY2xraN0Z4tXw1a0SFkVqUspUaOohTImHuF+sW9nk=;
        b=btZrng4jL+MtnToYfbhOI859FCR0kY5i4lstTO6CMqJQgXqdn5H3Ylyt7Sjk8K8uCs
         1HXNVQLLAZr750XIACK4AZvd9rkR6mbyLv0ZXYEEcPhGzRgwk/07gOY3LGTqDMpaYO5o
         nvvdY5I5LBtRoxT4yMtremE9ZWK1rT6zNGARKoU5W67zz4/DU3uiFVE9OgnIpwxaKYUE
         yl1C+lpcFFHH0gakf4ALTaGJ2uFxDMH1y9dvk5ccp8+iNIg583SXqWeTASbG3Mx8EnUJ
         knSoeZlyZtJfZHMeXdTAoPwt1fqDwPJro60UzcTTtMqdosj58K2jzRoyJCRKYD7lrUle
         kfAA==
X-Gm-Message-State: ACgBeo33wgbnCGxoMpYfREppeb8VjHg0XZwHEJy/ovsPCEbiq6aBFsPJ
	OkEu8GgfeBKsybLoAiIaqCk=
X-Google-Smtp-Source: AA6agR5GPfoyHOYJ1ShT1WbEkQ2u5q1dQOIexLuMcxnjlnGxnSAckuwxCEUdBqzAGOrKmwoiHlivGA==
X-Received: by 2002:a5d:47ca:0:b0:220:5cbc:1c59 with SMTP id o10-20020a5d47ca000000b002205cbc1c59mr59799wrc.662.1661526505999;
        Fri, 26 Aug 2022 08:08:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc5:0:b0:3a5:abc9:1b3b with SMTP id n5-20020a7bcbc5000000b003a5abc91b3bls25809wmi.1.-pod-prod-gmail;
 Fri, 26 Aug 2022 08:08:25 -0700 (PDT)
X-Received: by 2002:a05:600c:4e92:b0:3a5:fd90:24e3 with SMTP id f18-20020a05600c4e9200b003a5fd9024e3mr5650wmq.59.1661526504979;
        Fri, 26 Aug 2022 08:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661526504; cv=none;
        d=google.com; s=arc-20160816;
        b=fAowORqwu5R3qw9mN0aa8j72Ayk9O3etd/0IFxyYelb9MCyxfkagpvTaPL4e6PE0cm
         whmTdJfjO9UArQNo2eUR4xT7+AFk+fPbRUPxkiaEBzKze0b1AgWQK//KI8jejuI8G3ia
         MAKobm/upamZxsbCp2II/C15G7/pAFyfpPFzjrVENemxoPdiDRJRAYmWtiVPqAQ8Vu9a
         zweQW6lBDqYYnTBKhItiEZz8b/6M+UqTpg11RA+GQ/H7Cvn0vU0aEDMFw6UIAge/hp17
         kDb8E4vngXfR22q2RKwmVvaGgH8IdpWQpTdPuzXiNTci3mwY1LhzVbcNzZ+syDG3EBZH
         rmSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=H9Td7/TMrTAtAVeUrHIrhZSexZsjcdbUinsVZHg+GW4=;
        b=Q8Lpjn/li9BrIbd2QsIq+G+TNfqJJUj9S88NM/2zZJJZGRFJvi9ykkLpwioaB64b+g
         l++ADV5pWmdQDvTw8Mf4v3h2BMmYmwFL90ZTNdV13AZsvfX1+cDT0V4UHY1q7WM/X6+G
         BGuvOkbN1/SkGK4qHgKK1hYu6IedM4RltwSJk3uJ7haQ56eSd0LDJfbvD9lGpyvah8/v
         e9Sexzuu+4ezDzJp2YVg74j4StxzDqmc3vZPBY8d7EN+/lsFaC448MUREpbzy5DlTzle
         L1PDBrx7SOk+z4hJKcSvAkJL1vgrDYPNWerCBDx7Bl8SOihjbNEvpKgTwPH7GIAxAQYW
         T/OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lGhpRwPT;
       spf=pass (google.com: domain of 36oeiywykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36OEIYwYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id bj16-20020a0560001e1000b00225378eb94asi1003wrb.7.2022.08.26.08.08.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 26 Aug 2022 08:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36oeiywykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id sc3-20020a1709078a0300b0073d77f805b3so730950ejc.22
        for <kasan-dev@googlegroups.com>; Fri, 26 Aug 2022 08:08:24 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:5207:ac36:fdd3:502d])
 (user=glider job=sendgmr) by 2002:a17:907:7fa5:b0:730:5d54:4c24 with SMTP id
 qk37-20020a1709077fa500b007305d544c24mr5759332ejc.641.1661526504373; Fri, 26
 Aug 2022 08:08:24 -0700 (PDT)
Date: Fri, 26 Aug 2022 17:07:27 +0200
In-Reply-To: <20220826150807.723137-1-glider@google.com>
Mime-Version: 1.0
References: <20220826150807.723137-1-glider@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220826150807.723137-5-glider@google.com>
Subject: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user() and put_user()
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
 header.i=@google.com header.s=20210112 header.b=lGhpRwPT;       spf=pass
 (google.com: domain of 36oeiywykce0vaxstgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=36OEIYwYKCe0VaXSTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--glider.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Ia9f12bfe5832623250e20f1859fdf5cc485a2fce
---
 arch/x86/include/asm/uaccess.h | 22 +++++++++++++++-------
 1 file changed, 15 insertions(+), 7 deletions(-)

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
-- 
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826150807.723137-5-glider%40google.com.
