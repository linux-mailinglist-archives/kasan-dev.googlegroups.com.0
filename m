Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR45TCGQMGQESEKPTII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3FAA54632C1
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:12 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s16-20020a2ea710000000b0021b674e9347sf7529465lje.8
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272711; cv=pass;
        d=google.com; s=arc-20160816;
        b=L5TAtfcRzulTNXxo4KL3Ef0gYs+Btvt08amesi4w8GdNrM6GxnLo9KclaOMFDp/0M5
         wKJVuyNaRKQG8g2oYRRcou++dXtaViWeKdhTmTfGXQ06fEz/Mkm+YFHFGSX7lmFWamn2
         jz7nqqBBhgGfhVEK33TSHNbYPgCNS3M3dJLrzwQw+EvkUi+gVz4TKmyWWKdfBPRzQIID
         LBqdzwoziDSI41ROFU2tgEZP6Tu3fvmEX3nDxm+q8c9762Mx25no7HtjUkG1ToDtKbuV
         cU7spCkAOIt2ofiUEbU2Pr6eH7RrOJ3fV/yTZy5SRPGJCbWOsl+C+AyqgxmIdhlpL3Uo
         k20A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HQl1wagcKrCF9vlgWEwHZAuHz2T04p/ScsrDj/WLNkM=;
        b=MG8CeB18M2UTTdwVIj5pyDqVb8GxiJX8YQUtx1zfQZdmanLElRjR1H6Mk1V3hh7GyM
         XnGKh6nSNKr+9JmrAcXygoTm/yz1RW4fA3IFWN+Ps+XCirgOgdH65nqYW4zEhs2gAxoQ
         +vl4JtZOtGoFfCV7t5gnL8pzm5CMqm/z6j0FnGO3GU4tp52HM4bDz/qJUqjLHprn+MaQ
         l4vSeElzNfqALcCiPkrzroxxjx0pQKq0LxSr3U8DVI+R7f56a4qnr9nenxa7zUn/AaWL
         BII6aJpMxCVHEePyoAixNPQ7mXDPXrNvGKaWenQhkRWR6srJX0PwHs6HVshijMqfVRB5
         MfLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cKjMDTXM;
       spf=pass (google.com: domain of 3xq6myqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xQ6mYQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HQl1wagcKrCF9vlgWEwHZAuHz2T04p/ScsrDj/WLNkM=;
        b=BbuMfWJJhLjBbfBtMfALanfYugDVEOG3c1+GghENgcoePSOJq63/MYDvCboqegdSux
         i2Sg5LfR5K7qWU5MH+9z1Xsn+cVjHXCo3wdevraLb+uNtP16nix5EiUe3hwYWiKDPGVn
         MQDXesM7Ga9W0fjv6y7ZgUsMfKTf2Z+AnvJdRRfVINe/K0/ASZUrPXZuH2KxUg3gWGt1
         FVKDXJ2bktr776JSuYkoEBh1siDmEJHDFeZgvC9wE+zG7whRei1749p7KmEaEt292+ZQ
         fPrJAxCS6wgImtw4dRKSDKw2GjSIqd/i5AC5vGa45MLb2MftkBR9NMQNqs/tC1ezE51P
         BJHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HQl1wagcKrCF9vlgWEwHZAuHz2T04p/ScsrDj/WLNkM=;
        b=p0PjgKQrR5N4wmi3iSUX9XoyEcSGITfvtVfGcjwp76zwpQY1mr/Vimhv4jvmvw2qrj
         ChzejdAvEjG5I1lgHYwtn/YWVyHUiHIvz9FiJ0aa7e430mXcLNAAdrNLzGFG/JyMsP8o
         dvUXMzcKoQdqmyN80GcQq6uY6prE3fHaH7n9WrxN/ELOvCTgr9uILTqv+LQFMkQHWY3v
         1bVLTvYzj5+ayfufLXvcWk2DCrrCDOUwPibygOjfh4nibG+e4S0O1bUD6VMHKwqcOgor
         Aa0Yb7SjMvllUDlfeKlJLVxUNdoxoD+uVVi6wxvg/CgsE3RxNExwVeaWbPLXUhOpbt9i
         v0Lw==
X-Gm-Message-State: AOAM531qPVROb2YEKhuiatIdC7e+XzsMMLVNrDtmaAzLneJGTU8xNAB6
	LaM4pVVkS/lkett7cd3/3+M=
X-Google-Smtp-Source: ABdhPJx48z9o1/xwUfnLAU2Yd25XdONAmhUW7C8+vqUQCxZ7HbsnE9o7EUd5utnDQfoPVQZONYq8xw==
X-Received: by 2002:a2e:5c46:: with SMTP id q67mr30321346ljb.271.1638272711858;
        Tue, 30 Nov 2021 03:45:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a4c2:: with SMTP id p2ls2450402ljm.4.gmail; Tue, 30 Nov
 2021 03:45:10 -0800 (PST)
X-Received: by 2002:a2e:8350:: with SMTP id l16mr52555570ljh.428.1638272710765;
        Tue, 30 Nov 2021 03:45:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272710; cv=none;
        d=google.com; s=arc-20160816;
        b=Dvcmq95nQTjwn6VoOvrbhtLyvsiGf++MbPUcjaK6lQAaXf1/ElRdzFc6LjBIG/NtUz
         FyOqUXzSF5jV8g1OGVj1Jf9SgfO17FsxyhJwNRG8Cg2CuXcwPDAV5YARMfoKZtIWHQMo
         LCaSIEgE7cIKbwChODYSNSYlrNL5vuI4PrKZFF4bhtD7r1ViKCFU9jqQR3B17wMYh7ck
         tXGB/0jk64r9JnwXFckyGLLeiN8jObde4gPq2lx+yD6YqpxN+Ejg0vrhseFSnJRqVWnr
         TOaRA586ZAUDOPtn1wOQ5kkBygEagT+EtjIfCYmPMIa5RN9qIVqkmO/8OHZZeQfnR6J0
         U5/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cCyxJnES0DWyrpQ2J5vRoZu9DlHTb3+fL88VjiCWbjg=;
        b=nMeglu9wdmLv/3kNOngNb/IedzAWL4VjmppDpQeTQZIlObN7GVVKMJqccXyjrPztlT
         s5me/1qYrRN9yPKl13ZoFmJ4WCrH0kxpemNJBBDASXKlbpL7X7KlB6aCyxkcUHlH/tVp
         5bGl0wPt4WMvB7ROq76i54rK+GfT9VAKFVjX8uiZUVHWQLaIf9UMworBI5q+qI4ws6A5
         ZZkBv3BJKkBZHs2MlMHNjfP1iMCP6w8aLRx3wCQzANADNBy9m//el4fUuOvDE2e7nDDY
         bkBX4x0mcu+7GVfW4L1ZwEOFfHUk9/RL+izzHFFhk0S3bRO1+p2O22Z8yka+jOtZfaqw
         11aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cKjMDTXM;
       spf=pass (google.com: domain of 3xq6myqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xQ6mYQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id c12si1371168ljf.4.2021.11.30.03.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xq6myqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v62-20020a1cac41000000b0033719a1a714so10282431wme.6
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:10 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:1d1b:: with SMTP id
 l27mr623895wms.1.1638272709978; Tue, 30 Nov 2021 03:45:09 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:11 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-4-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 03/25] kcsan: Avoid checking scoped accesses from nested contexts
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
 header.i=@google.com header.s=20210112 header.b=cKjMDTXM;       spf=pass
 (google.com: domain of 3xq6myqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xQ6mYQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Avoid checking scoped accesses from nested contexts (such as nested
interrupts or in scheduler code) which share the same kcsan_ctx.

This is to avoid detecting false positive races of accesses in the same
thread with currently scoped accesses: consider setting up a watchpoint
for a non-scoped (normal) access that also "conflicts" with a current
scoped access. In a nested interrupt (or in the scheduler), which shares
the same kcsan_ctx, we cannot check scoped accesses set up in the parent
context -- simply ignore them in this case.

With the introduction of kcsan_ctx::disable_scoped, we can also clean up
kcsan_check_scoped_accesses()'s recursion guard, and do not need to
modify the list's prev pointer.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan.h |  1 +
 kernel/kcsan/core.c   | 18 +++++++++++++++---
 2 files changed, 16 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index fc266ecb2a4d..13cef3458fed 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -21,6 +21,7 @@
  */
 struct kcsan_ctx {
 	int disable_count; /* disable counter */
+	int disable_scoped; /* disable scoped access counter */
 	int atomic_next; /* number of following atomic ops */
 
 	/*
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e34a1710b7bc..bd359f8ee63a 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -204,15 +204,17 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);
 static noinline void kcsan_check_scoped_accesses(void)
 {
 	struct kcsan_ctx *ctx = get_ctx();
-	struct list_head *prev_save = ctx->scoped_accesses.prev;
 	struct kcsan_scoped_access *scoped_access;
 
-	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
+	if (ctx->disable_scoped)
+		return;
+
+	ctx->disable_scoped++;
 	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
 		check_access(scoped_access->ptr, scoped_access->size,
 			     scoped_access->type, scoped_access->ip);
 	}
-	ctx->scoped_accesses.prev = prev_save;
+	ctx->disable_scoped--;
 }
 
 /* Rules for generic atomic accesses. Called from fast-path. */
@@ -465,6 +467,15 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 		goto out;
 	}
 
+	/*
+	 * Avoid races of scoped accesses from nested interrupts (or scheduler).
+	 * Assume setting up a watchpoint for a non-scoped (normal) access that
+	 * also conflicts with a current scoped access. In a nested interrupt,
+	 * which shares the context, it would check a conflicting scoped access.
+	 * To avoid, disable scoped access checking.
+	 */
+	ctx->disable_scoped++;
+
 	/*
 	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
 	 * runtime is entered for every memory access, and potentially useful
@@ -578,6 +589,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	if (!kcsan_interrupt_watcher)
 		local_irq_restore(irq_flags);
 	kcsan_restore_irqtrace(current);
+	ctx->disable_scoped--;
 out:
 	user_access_restore(ua_flags);
 }
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-4-elver%40google.com.
