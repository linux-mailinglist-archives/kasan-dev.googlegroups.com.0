Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQM5TCGQMGQEJJAZOWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E91C4632B9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:06 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714sf10282335wme.6
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272706; cv=pass;
        d=google.com; s=arc-20160816;
        b=AAzt6tL7V587nghB+oBKj7/b90xahgvMUinamc1/jIN3e5Ii5Y3aa6x68PD+TifVB8
         8wvLtcckDFjjOSvkMMXwtuVw3ujOXRFg64J7/FsqpemFhoMFxL1AVn92+cqz9VzOP0zW
         r6XiLfI1BgY/pGKS9MIfeQAR73siBMfYb9Ob0mgKFRyYggsVvD4aD4CWRVhXJ9O71Qg2
         8Toc+VOIjFNydw5/ds9VGey98IEcyNzz6suiulRzwpLbGmD9iF9nkDFipJUnzJ+GpDHB
         ZxpD/8mBNKYPGg0+yU8hs/emQPg0R2AYA8nSPFOoLR/2i69Yx8jeIC5k08Mx5KojprAe
         fjrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=xMPFHMvVr858ltNm1Fq+0nhzRNfIQkvd5T8RDQwisz4=;
        b=VY0pvXyizbRLOxSHGmKb+9wWaUXWCQvbyFDb4hkDQoj80MNFbiTesGbZDHTPEqft+v
         Ip/bgFB/PhpzR6i4+FjHlpb8+E2T7pfJyhxzFqqwyjwad0XwRH5V/IJm7YMrJIibVwBY
         kDqMNovtY4LIjxoqvNDBpNZWBplKkikpDLNvZuhC5s972ub2zYhY4+u03fcMcyHFL0+d
         wzegBpCURQDEnx6zhDwJOPk4hoFWmHjhANUMKCpp0YzCTkpqp1cz0SwJlLTAzt9Q8JNY
         jkHGRs0PAGUh4Fx0tQyOUmaoKGtYY4IAwJcrYkucNZh76951YLJou82UF8sdaehHMK4/
         1vgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xy0Q+YI5;
       spf=pass (google.com: domain of 3wa6myqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wA6mYQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xMPFHMvVr858ltNm1Fq+0nhzRNfIQkvd5T8RDQwisz4=;
        b=Ux/pAMpsaYiNMevQfDOhj2b8hiseROL4MvKl5fRrh6ys4sdjSGl+DOZ4aB1N0KMbOI
         HPYaHGm6YoavRf4zG6x3BMttLDCHv+Ex78De/EvaO6ol4WvpYeB15BgOaqtS4xs+PDn7
         j8NnCYFVZqKGf1mk/zPXNssIzAw7p2aMrojPDkg+LZeIhELXr1Pk9aRxSMMCE98Ry92I
         m2bm3TNee9NP2YqB5p3fzXROVGwICJvbqCi5j2CEYTQz/WNdyfvopDSWc8Pcr8bDyqP2
         Mnf6bFvIlZqeklTsz7u6F2A6cFh9rv8bFZUA63k1OmVJiPAwNpfkKGQbx3hWhcptSMg1
         e4yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xMPFHMvVr858ltNm1Fq+0nhzRNfIQkvd5T8RDQwisz4=;
        b=OzzThro1sc+J6tYcnDgDRCSaRivgnisad1grfMPohhW5sm3YAlCZZCfjdVkT9eCG3I
         WrNaNXyUIYYO58Q539L3PQx/jgUaxZ0/yIbwwEMkqZ0VCjYYyzSm9RSwXTSyMULhYtVb
         HzohtpXhzmkhPaAscXMdsN52pMW7Wba5FjzBaBttbTgS05QK1Rddy935RQ2I345zw8rO
         1IlzUMdzwV76XSQS3iwfCiHAPBCBwx8lwphmyJCZZvEkJMW5koYuWNydjj2lox69798Q
         qLy8sXCOEiRfBpfrG8Ear5q+jMCSkKsDFb05BiPxbUAzcx5uYOqi5HjDoB9w53ztu+DB
         fpNw==
X-Gm-Message-State: AOAM533HdCrmrwXCEWRTfo7eKxSvHD1qfBDWUm6aWzjGzXPR591DstlV
	NGVVZU1oW3NMvLT6JbZjZ3s=
X-Google-Smtp-Source: ABdhPJx+OuSI2XxXQULWmKWnSVL8kcH4hTb+Hp37Fzj694XYBcnJApi4qrrlGkVHEPdc6obkBdwxMQ==
X-Received: by 2002:adf:e286:: with SMTP id v6mr39834010wri.565.1638272705988;
        Tue, 30 Nov 2021 03:45:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls13078242wrp.1.gmail; Tue, 30
 Nov 2021 03:45:05 -0800 (PST)
X-Received: by 2002:adf:f209:: with SMTP id p9mr39056221wro.191.1638272705049;
        Tue, 30 Nov 2021 03:45:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272705; cv=none;
        d=google.com; s=arc-20160816;
        b=M3VJ7nT73XP0EJOoWFZzckZ47z+7Z0A0saOwPLBdtCVFBpLeu2qgmk5Ja6OREV2Apr
         M/9fn2G14HOnJ3MC+cIBx325NqcTL8w8qgneNX/JM2peyBvUs2y4x/1SXuS0fCz7+u7h
         cAIbZCUvJuLud8NuGtapeYZCuEhTJvK2s9Hhx9MrvQUoL7ji1qEAmhhQtcrlerjziwMT
         XA5HvedGpv4ip8A170qXr7uiaYVywZa9SDnmiNX4CIGbODbspIzjCfRkOGTkzkY/qlVA
         N52pSu+vU4tbSGIgkMjVY7Wb7pJd/DVn0UdLfs++WnQw7dIlxHTpvPVeXJSKeLRn3QDa
         Tw/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=xU7oMqGuZSzuwQqlTLWl5HT2gcOlUZd23bSn8B82hrg=;
        b=Vd+KAdQeH8YvSwwPNq0/utktwjcIPMG0LIgj7yfRe94f5bEpkjyDv3Vq4NFtD5UTv8
         HPh4Rsphg1IwxJBhnnNkdu9UL7Jd5I7WnnSRddzTbvIS1X371/5KU2rWdjT74HWQMDaU
         NXAjqTSwngc3kJ0OMDnFOKodSU4DIXXWwyLuh4XJbgm1d7/aj12xMyV1bgPUX8kz1iyQ
         qVEHvnTkH/KNJ/grJBnvIj0j7cwHNmrq/w/YXgODTjiuyLqLqsddmk8Co0CK4A3bTc9C
         1mxV7PrZDRo5ot4G51KGtTQEXi22nQwQhjDxLM59+9tta1Pt7uiQZffN+mSEW6nlhHXf
         rhDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xy0Q+YI5;
       spf=pass (google.com: domain of 3wa6myqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wA6mYQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id p5si1188898wru.1.2021.11.30.03.45.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:05 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wa6myqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03aso13596821wme.8
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:05 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f87:: with SMTP id
 n7mr4359911wmq.63.1638272704753; Tue, 30 Nov 2021 03:45:04 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:09 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-2-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 01/25] kcsan: Refactor reading of instrumented memory
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xy0Q+YI5;       spf=pass
 (google.com: domain of 3wa6myqukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3wA6mYQUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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
Acked-by: Mark Rutland <mark.rutland@arm.com>
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
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-2-elver%40google.com.
