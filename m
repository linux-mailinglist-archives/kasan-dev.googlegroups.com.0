Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCELY7UQKGQEMA64CYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BB756E65B
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Jul 2019 15:28:41 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y66sf18713637pfb.21
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Jul 2019 06:28:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1563542920; cv=pass;
        d=google.com; s=arc-20160816;
        b=0+CuQmobG/eCM7EYlNsKDOfyrXmYljfcA8unGkRU/kFCNgOinEZpmVQTpFSUZKdRDG
         znDvCzmt/2OygOEKOclDKgCy6q09y3aXUEZG0AjtthMIre/keLANyiNoxyV++Y/xznPv
         4xE2yV4r46yyYp5a0gmPafK2boXgA1caQy7+NUbTK1RmGSocqlzqGzWBglKdu+Fuv4WX
         gUZWsgVQraWfm+5HxNY5DBs7NVMy4GswaFp5mua5qgk4m46PBdblSgG28tfMLmwd7Y+K
         w6p5Mpv4nrari6kjGPKEaTnLm8pFkHuM6+Zmf0WF/tppcEZX7jEmWIQdv8L8UV705zjA
         AwAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=m8bVVnWGYustcC7vw7/Joy6CERrL09qmBBPchmh5ih0=;
        b=RfKvo3HIv6znVCtpmTofHdZYnwxVui2PDAMjJoNgtwb7JzUe60ijw/V/xdAyxEMpeU
         UnmmJ8mbs8T1lJ58d+1H1V85rUFKl13bBUo2xPsUS9FeVw71/VwlGHPXTe0arQNxnrjo
         I0EtrxsJGW64PIrvqbHz7HUvY5LTxgLMqxepllcFVZUJenFGbWUhxAIAAzgbimb2SipU
         M8V2l9vs1H3OkoPTyIf+JkUKGgxls2cR13IpTActkrct8xstoWTLf6LPyIaVA1NuCPQg
         ZCTBNCOoO12JOBzSSt7PwoKL808ah/UieYontn2bjcJVZtwhhwm97zdygXpGL9/t9Swp
         coBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pdZXIxj3;
       spf=pass (google.com: domain of 3hsuxxqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3hsUxXQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8bVVnWGYustcC7vw7/Joy6CERrL09qmBBPchmh5ih0=;
        b=o2btzY2hJ68c0T5ngEW5BBniSK875fzr2URjGI7Mu6KJgLgvf5JDbg5Fk/vi6NhD/Z
         dttYOlAL2P4GBqJpoI905kE69bNNBrG3SRyyQ/tD4zaFDnlXG6MKJJ50BzZ/HyGj1M3h
         683qlAY2bVdac+TE97ZaG1p1NYvBWAvDurS74Yh1TkHI4SVOEK9RjS9eHMJiPpmPqWF7
         ifRNcbBVCA6jiLJQze5afVRVROiuT+kM3GrIBBSRUhqXFXsUZQ0RjyX/pl0nt7zDPP9E
         P0GoJTTlbFgEgjbL8Kg4KSw0rBoLeBgDA/RkzUBPcNSalqCzB0SvYUyNxAr9ixKM9wFA
         IdiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m8bVVnWGYustcC7vw7/Joy6CERrL09qmBBPchmh5ih0=;
        b=pUAfvog0m34UJJ8FMJkU4Wc2STLWfeqjt4A+sdpxIkZDGeLDDOb5heg+QrED4C5i3p
         Zj6qQd9vuiAT+LRO24oOcAtMk+Y0IIFuptJa6RQTgaQ6Tqoh9/hQ3nwDdqeiHMzvpiG9
         6cTy4Vwaj0TIZY1WHzo0sbqEL0hLBUD69kgMt6LR8QgTqUeuxowZXYq5yKF5hKQ5JtDK
         MKll4JZ8uJgER6KPh7a46sv6VD4tHi+hTHpzsmNCnmr5b+VEZAkEvReotaLjlFkt1uzM
         uSXyuHLlGUPsIyWhs2Fgyyvm9yFaeDGoRYkQIKdausMWDuBz0DVCdrbyuEr6FWvyhK65
         e3bA==
X-Gm-Message-State: APjAAAVr1t/rbIV7qL0VKx5C+f1PUKZOkk9VIJs2yXBPx8h/L5TB+ker
	JJT7YOTVZB5WOCEy4VxAly4=
X-Google-Smtp-Source: APXvYqyOPGa8SntgUN7Rj9YM5xDcgRJqy2BG1Z+Q/UtYp8+f56sjgtCWlOchT2GvT4Dn/WcT1YRdLA==
X-Received: by 2002:a17:902:82c4:: with SMTP id u4mr56970211plz.196.1563542920158;
        Fri, 19 Jul 2019 06:28:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0b:: with SMTP id u11ls5414126pfh.15.gmail; Fri, 19
 Jul 2019 06:28:39 -0700 (PDT)
X-Received: by 2002:a63:7d49:: with SMTP id m9mr43864322pgn.161.1563542919769;
        Fri, 19 Jul 2019 06:28:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1563542919; cv=none;
        d=google.com; s=arc-20160816;
        b=oRK+XC1ZwboP3KiNiyUgHXpuH6z2XFqKddUCbp6nN1ogn/sHArziNjFNqDSAGF5IHh
         RxzjREnk+cNqBiekfA7heaee+7yoB9OX0crkc5sZNwhPtXa0u2aIOM6RM8dbDm0pb/fM
         +bSerRsK0TYhxH5RIEoNifpkszSPKFbbCk3PoxIxan/woMD8BW7CcnNbch6uZLpAi5oH
         XiejJ9n8U6EtXAe0FEvN2Ic0MWoN2V6TwpE+lm2R8IXtm3WOk1r3tQSe3sJMTwToBemU
         TSVhpy6rGIXOzO484Jg11//xiXrxdVrgNepw7MGDDqhky2qnc9IElS9sVmAQ8ICdL9j3
         AMhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=CieYDgU1j7WHeryDkyQpHsfZB1hSZxkxH69srwlIIMw=;
        b=qU/pwzLcXy8ixSHEpu5f2qJMGrqgjFtR87SHnvOBIbHyMVXzIazocq4L7MTQ5gh+fe
         koWhx0Dufiw1i7KkKikT68IpZXgNni+gzNU5htfy1mFC8DEx5HGGq0exzeO68ESN+NJe
         h6gTsbWvjMOQSOu8V8U+Lk7b6apR0qyEfIpXJBMBDGuYYFGiqKNfW3gtGID9YJFRlufn
         jQP9LJfR8jTdcuWROjV3jOjtT9QIbXNidLtW4eakpGO0UVMRIfOh77FK26v4DDVYqUKS
         PP0+r7mMMLMxoWpIk0wq4BRuRqEVL65C2cVtCnqP0gCrFWTVMMUNjTD5R5Breq+Hza7a
         MZaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pdZXIxj3;
       spf=pass (google.com: domain of 3hsuxxqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3hsUxXQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id cm10si1346596plb.0.2019.07.19.06.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Jul 2019 06:28:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hsuxxqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 63so22162301ybl.12
        for <kasan-dev@googlegroups.com>; Fri, 19 Jul 2019 06:28:39 -0700 (PDT)
X-Received: by 2002:a81:a155:: with SMTP id y82mr31345602ywg.80.1563542918815;
 Fri, 19 Jul 2019 06:28:38 -0700 (PDT)
Date: Fri, 19 Jul 2019 15:28:18 +0200
In-Reply-To: <20190719132818.40258-1-elver@google.com>
Message-Id: <20190719132818.40258-2-elver@google.com>
Mime-Version: 1.0
References: <20190719132818.40258-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.657.g960e92d24f-goog
Subject: [PATCH 2/2] lib/test_kasan: Add stack overflow test
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, x86@kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pdZXIxj3;       spf=pass
 (google.com: domain of 3hsuxxqukcccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3hsUxXQUKCccry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

Adds a simple stack overflow test, to check the error being reported on
an overflow. Without CONFIG_STACK_GUARD_PAGE, the result is typically
some seemingly unrelated KASAN error message due to accessing random
other memory.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Borislav Petkov <bp@alien8.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: x86@kernel.org
Cc: linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
---
 lib/test_kasan.c | 36 ++++++++++++++++++++++++++++++++++++
 1 file changed, 36 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index b63b367a94e8..3092ec01189d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -15,6 +15,7 @@
 #include <linux/mman.h>
 #include <linux/module.h>
 #include <linux/printk.h>
+#include <linux/sched/task_stack.h>
 #include <linux/slab.h>
 #include <linux/string.h>
 #include <linux/uaccess.h>
@@ -709,6 +710,32 @@ static noinline void __init kmalloc_double_kzfree(void)
 	kzfree(ptr);
 }
 
+#ifdef CONFIG_STACK_GUARD_PAGE
+static noinline void __init stack_overflow_via_recursion(void)
+{
+	volatile int n = 512;
+
+	BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROWSUP));
+
+	/* About to overflow: overflow via alloca'd array and try to write. */
+	if (!object_is_on_stack((void *)&n - n)) {
+		volatile char overflow[n];
+
+		overflow[0] = overflow[0];
+		return;
+	}
+
+	stack_overflow_via_recursion();
+}
+
+static noinline void __init kasan_stack_overflow(void)
+{
+	pr_info("stack overflow begin\n");
+	stack_overflow_via_recursion();
+	pr_info("stack overflow end\n");
+}
+#endif
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -753,6 +780,15 @@ static int __init kmalloc_tests_init(void)
 	kasan_bitops();
 	kmalloc_double_kzfree();
 
+#ifdef CONFIG_STACK_GUARD_PAGE
+	/*
+	 * Only test with CONFIG_STACK_GUARD_PAGE, as without we get other
+	 * random KASAN violations, due to accessing other random memory (we
+	 * want to avoid actually corrupting memory in these tests).
+	 */
+	kasan_stack_overflow();
+#endif
+
 	kasan_restore_multi_shot(multishot);
 
 	return -EAGAIN;
-- 
2.22.0.657.g960e92d24f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190719132818.40258-2-elver%40google.com.
