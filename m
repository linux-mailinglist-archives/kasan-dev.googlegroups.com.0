Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIXA6CFAMGQEO4FKOYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A101422407
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 12:59:47 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id ef19-20020a0562140a7300b00382729caa76sf20843145qvb.15
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 03:59:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431586; cv=pass;
        d=google.com; s=arc-20160816;
        b=oEJKBRgJgK9QGOO9UEx0/RCmFIziIRCxoljXlEu4k4SxyNyaxsoFNH2Hxp9JxR2Y8w
         k9QAbBnlhHoKwNaPPOwhtCeM1xPjYYUPKiYAhtXFs6uBa8H/j5ufohdiBmLDq8uvpJ2n
         qGyzq+lmNTnVCuSR5IcvnRkDpIsnZi+QRrdHkmQIVQh/3kfzxDJdCdNd2pEWcqB3ClrA
         EOxct9kl9S5NHhh/Yy4WDTtErXp5B8un0l69NQIFi2lWs9ecBSdYApYTZ8gjZpKtzcxx
         YwWkdg1RUSrgxY2I/ypCEjF8c0jjpr9XLLFVgBq7zPRNH0wYaRicAqyR0i5h9awEZpAm
         JJEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=R/V3n5FSlYzD03lGcp1WfYC0w70gAhX4nytDRjHoDgI=;
        b=UvyN7yZBaZtiJhi6RBjv9h065DyJTYaLstGt7t+0Sn0ZjPY1V1qSkqnr1oPp5mxZoU
         hNOJMUo4uCXhCLhibp5D81t/ZioBLlLatxzfONxItaZQfxSuFSuN+DSymGNIpWjcogx5
         U76UhXtIdtzZ7jh87wQVALmOuJLVGBS5WLR2uD2nA4JfPMcuJrILqObAHT+Utmi9QS0N
         VY5FFC/acEvV/29f8mFcuc2wQzoQwhc1SX+vGH602PunIAFWcBiqSschNMjOKNWXcaoO
         kdosppvWnDCxWeydzbHCW9ByF8fP7eyP9Vwlb3+/iPCEW9E+H5Ygfb0l9EPZEx4ymtXY
         dBEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZQrlEFr3;
       spf=pass (google.com: domain of 3itbcyqukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ITBcYQUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R/V3n5FSlYzD03lGcp1WfYC0w70gAhX4nytDRjHoDgI=;
        b=C8ADMWLhQ6V3+H/4yx3UruyisUusg6uPQL4MPxgdKWbS7vlx0cQvGHfgdz24HHcD/W
         UCPi4TzPtQkaN1sqsYgTYA7g2BULoBvhQUx/0CTlXUiVKoaC+IQdJRlW5hmSkrVxwVf3
         UUqZv90nt8RMOwPXmcrHARTBVSnXTWcLu2AN7N2n3aByX0L+YBxilaTAOhwVPB/CFtYy
         g1L8SpMi/9sVIuHnTXaRQH9MrlZMBm5H6UedW8P44+lKH8C788fzME7gTUzdN/qx829A
         8Heqp+0L1YNQBbGUxJJJ555n3AI639iUtETVcgy4J7q9ARqQIy/6Y07KXcCt8suCEK5s
         v3Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=R/V3n5FSlYzD03lGcp1WfYC0w70gAhX4nytDRjHoDgI=;
        b=phWiFdZYNOWUcKJ2yP+Y2JoAh1ksCSmCy2NJglJ2AJFDkjRnvHNgfQDYSPp7k2TGUQ
         LWjMgRLFPs0CEO7Pxn8JEezA8SHuA/TiYd3Pu7jMi6eMr8LP/gYAsYFshx/jRlz76vIK
         LcHJicRN2V4ZuGVvSUz4YEtJBG1GY5d0mDgQ7Y1/dCnqQvZ+DUGBtkxLK2XlIqQBXhlX
         t4UcZD1RsNuajHh+zdCEDaFy9iP1KevCMf7XoYrKCpqBSFJzf0WyKvB5ZV/GSOuRavxv
         JZmLKvkQ16EN/XjN565zIwv4cURFDdEGP4h6OnhqUdMOnAVdfvf1xJVA1b63kffu/itP
         LT1A==
X-Gm-Message-State: AOAM5304J7WFXW1Pavk3i2OiMxvXuT48w+Q9MeD1o7wYFWH5uNgRrzXd
	N6kj8MONYJ7EXvHsauXV6iI=
X-Google-Smtp-Source: ABdhPJzuysZODyYxZVWYS8G363t126nTHBQwOIy3b16bjlEKtyLw2WZxtgpsi97O+ONZGlwbxNBYqg==
X-Received: by 2002:ac8:183:: with SMTP id x3mr7224819qtf.270.1633431586139;
        Tue, 05 Oct 2021 03:59:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ab1c:: with SMTP id h28ls1400231qvb.2.gmail; Tue, 05 Oct
 2021 03:59:45 -0700 (PDT)
X-Received: by 2002:a05:6214:12ad:: with SMTP id w13mr21795874qvu.8.1633431585706;
        Tue, 05 Oct 2021 03:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431585; cv=none;
        d=google.com; s=arc-20160816;
        b=R19fkO3tlNeZtvHkJbLQ0IYvWQAMT3LrpeM26Kpm3qQSSNFKQIoyeG/ww/qq7Du9Cs
         rpldLtPWH84PCb04n4NDs7n24X0v6Ser7gY2Em8M5SnJWNi9iPN45QXaY+vS/h/fC6uj
         zvPA+cMLrI3jiHBCtBAJYsXd5gMZBRsrqasnyp65vTmwhV7Q7LsZCPsMiydfL9Q5uU2s
         rCkoAOpxhebzGsfDrWy/3HOHdBdCtYFVr4YjU5IPbVfvAn3EcYl6SQ3IAKXaJn6NONmY
         0S+XKonE3tRa5KWOuHO6S99mPiurPUV4tlt+3sBG7fflCuD6zjYa4tlXX+F1nTqb+7Vd
         cefw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=AjGY1e3Ekh8sgb5t91HD4gatgCiWO+4KwBntiL6GjSk=;
        b=YZrvapSEOQTtZNhguPoyJt8e07zEt1QkD1G4LFoys3ccvxU6PySpH07DjieCppdO/s
         cqxbukbLo5cM57J6GhOr41dpam8P45Dz0cDI323Zq3fyIwz4jQvToAzGAkqkH4HOWtAR
         sreDf2X0LN22rQH5ULyIL8hRMf/wbge5EU5emcn7oD9h46eBAZPc7VdViix9x0Eu7VgA
         2K1rocXEyIDsqVCUrnvgukdVHL9kK0pu5wR+Or6S5i+OzLb1SuzVeV1OKv0+gDIrMRrK
         WWanEpP7j0b1mJoBkKya4lIoz6/8mR879GY0NR5wPUX25Tt4UzRlw+8MHgoPlV7YxlWh
         tSpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ZQrlEFr3;
       spf=pass (google.com: domain of 3itbcyqukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ITBcYQUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id 126si956171qko.4.2021.10.05.03.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 03:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3itbcyqukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id 100-20020aed30ed000000b002a6b3dc6465so22788331qtf.13
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 03:59:45 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:a4d:: with SMTP id
 ee13mr23024272qvb.6.1633431585442; Tue, 05 Oct 2021 03:59:45 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:43 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-2-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 01/23] kcsan: Refactor reading of instrumented memory
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ZQrlEFr3;       spf=pass
 (google.com: domain of 3itbcyqukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ITBcYQUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Factor out the switch statement reading instrumented memory into a
helper read_instrumented_memory().

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 51 +++++++++++++++------------------------------
 1 file changed, 17 insertions(+), 34 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4b84c8e7884b..6bfd3040f46b 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -325,6 +325,21 @@ static void delay_access(int type)
 	udelay(delay);
 }
 
+/*
+ * Reads the instrumented memory for value change detection; value change
+ * detection is currently done for accesses up to a size of 8 bytes.
+ */
+static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
+{
+	switch (size) {
+	case 1:  return READ_ONCE(*(const u8 *)ptr);
+	case 2:  return READ_ONCE(*(const u16 *)ptr);
+	case 4:  return READ_ONCE(*(const u32 *)ptr);
+	case 8:  return READ_ONCE(*(const u64 *)ptr);
+	default: return 0; /* Ignore; we do not diff the values. */
+	}
+}
+
 void kcsan_save_irqtrace(struct task_struct *task)
 {
 #ifdef CONFIG_TRACE_IRQFLAGS
@@ -482,23 +497,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	old = 0;
-	switch (size) {
-	case 1:
-		old = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		old = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		old = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		old = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	old = read_instrumented_memory(ptr, size);
 
 	/*
 	 * Delay this thread, to increase probability of observing a racy
@@ -511,23 +510,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * racy access.
 	 */
 	access_mask = ctx->access_mask;
-	new = 0;
-	switch (size) {
-	case 1:
-		new = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		new = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		new = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		new = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	new = read_instrumented_memory(ptr, size);
 
 	diff = old ^ new;
 	if (access_mask)
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-2-elver%40google.com.
