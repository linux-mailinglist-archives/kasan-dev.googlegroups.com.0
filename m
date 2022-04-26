Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLWDUCJQMGQEK6YDOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id E50D95103FE
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 18:45:34 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id k29-20020adfb35d000000b0020adc94662dsf2001343wrd.12
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Apr 2022 09:45:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650991534; cv=pass;
        d=google.com; s=arc-20160816;
        b=j5wBsyTrwwkP1NeywCPXS/PH5CVZuE45kaa2RcaNvb3Bfzxv9Hr56uNrBy6ii3iUyi
         jDHBTWGu3aw/ZBD7UCfgnU/lmCPHIEH2oAASnKIzqA9mqtasIykAeQrLV6HraU4T/jL8
         bzbU8mMpXLboNuTVOIPTFfSHCMYTWfNUQYQofBZA4BS6DFd2qSDbbCAoKYUBArGX3cc+
         qAzzCce4MOFDscWqXMiWetkjwkrb5S6nElOy2Jiok3Mc1e+lhrqkzZDXdv2vnhhjAoGm
         FO4ZyO1zvK1V2agifrDpa/qAtTwZNuxEQBKSJvIar+R2gMF9I7f9zB1jUrwtk6fOjYno
         ELcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Cvpnf+3xiRIUoVZlEK1xr0MbdoqTpodjsuCuGYLr99g=;
        b=hRIBQv682Z+iDzM9h2fHi7IsBBjJ8gbTUjW4n1jKfY+teCJgmExGZabOPgS3p4DK/b
         29U75NKNdyG3uDEj3gj5sHEllfeTplFHLUNfZQDUOYygk3Moo5UIZN8YTX+XfpJJY5Il
         4oiTnY81f5y4mKWYETKJUD8Cctk/F8UAy8NjQsYkKr//bHe7kRoTN1WLzBnje+4LUNn2
         vb4n4uef14PupvHmnAS3NuMUAqoWtitjg2YO9mPspmgi3spRK9kue/5FsJHPNWJhQ3JD
         IJna3o5KfLAPT085WphNZwUbjzFvtqlvzGIe7dcujmoX6SkivQ7QAwlv7BmMmsSaIF4K
         lwZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q5MasDLt;
       spf=pass (google.com: domain of 3rsfoygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rSFoYgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cvpnf+3xiRIUoVZlEK1xr0MbdoqTpodjsuCuGYLr99g=;
        b=MSIBTG6pLMgJ0dBXEsuvy1egppSCYK69sVM5xkM4BFjImziSlbKqx1WlQtYNHY9TXi
         adVjbZ7mUWkkOr4Fg+a3lvhw1yUkUEZOSGoR3enNV5AC5oqkKnThVLqh5hPGQAm9S8pc
         JTb6CM13cHCaRp2kXNva+/6mtT5IowyMXfZY0wvoeBk1NzcUU1dS7vXnc5xdpUhJBHmQ
         Rgd55y92XtEnHbUzXB2ybm7/DhI5u2woA6YUHke55ysNaFhroHdr5D1MQgjZYZnW6Ee7
         ce+zU1hQpjkIFBmbLf1vAYLB3W6sA4eDR72Q+eXcDDFp+2qYRyVVUk0hG4pZNQpQiQiU
         6WRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Cvpnf+3xiRIUoVZlEK1xr0MbdoqTpodjsuCuGYLr99g=;
        b=tC75EoHQxRAuOnc4suhhlIuILv6fnDqdTAoiT3QBrXYLuQ+MjHVPxURVWGazd/kwXU
         /SfMbXZu/lmNIJhLDG0DPYNB3nfwQowXfSiqNIM+RphW4Fi3MFQov57wqYZ0c7hx7WUy
         Wc3AdDTu91GnCLgxeIgIneZ3qUXzmW318JN4xKC28Yxs7WQp6dn9stQjSdwjW6XB6Y/K
         ni9byK44HUsfocanVToVo0urjH13WRkAgfpqM4ZrWYJXUwkbjNyb1J4t7lnxHLRjSR6x
         EWL8xP/Uld2dfpmk2rKaj9SLdahTonwtonK4s7wMiZfxNlk7XApZCy7Aa+5rg4th2V8+
         0Dug==
X-Gm-Message-State: AOAM5311FzZBZ38b71ZfaNYwjrGa9FeRzc/WgB7REPNXnfAPqg2VHBP/
	rO6c7+K+UH8yGb2sNU1Hz90=
X-Google-Smtp-Source: ABdhPJyowU3XUEnOfnmA2o3AqaI9JF+W2aIHBFvnCtCHEVVHud+B2EIs03xam6UJA6+51dcGI0YtSQ==
X-Received: by 2002:a05:600c:1e89:b0:390:ba57:81c6 with SMTP id be9-20020a05600c1e8900b00390ba5781c6mr22714571wmb.29.1650991534656;
        Tue, 26 Apr 2022 09:45:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34ce:b0:393:e84e:a015 with SMTP id
 d14-20020a05600c34ce00b00393e84ea015ls3807465wmq.0.canary-gmail; Tue, 26 Apr
 2022 09:45:33 -0700 (PDT)
X-Received: by 2002:a7b:c30e:0:b0:37f:a63d:3d1f with SMTP id k14-20020a7bc30e000000b0037fa63d3d1fmr21725567wmj.178.1650991533765;
        Tue, 26 Apr 2022 09:45:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650991533; cv=none;
        d=google.com; s=arc-20160816;
        b=FB+I+lEX+UqWz7fDKLm594EJv5mxOH1XM6XlM5X1c3Zy9G3cB6R8No2y4ptPFQ0ds+
         6OnUmWrk5HOKLbW7G+3OYpxWx53lI2Nf1BgPwywEGP24OpgKwRq243x+KoTlF8FsDjqH
         tuQNlBNYtyCG8EZJTQIyBM3xUhlQWxXW1lAhqxruUbCCWxpKixaN9JCRP1VecuZyhS+F
         qwc9D19kO/j7lbzcRL7v67GiBRDuYZP/1hkPQpursEyzqUQXjheO6yVbqRW2xZQiWxhs
         EeFOcqVcbop1GHfvjoSOoyj6qUrAwQYOTgvRLtMXJmzbbeSpyzRtWXmP6V19ZOgUiyWl
         EcJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=7rWXomHmmGtw2qSW/Jql3Xky6Nc8Jl3o+xpl6HNe0X8=;
        b=k8tdQZ6OquyGFJzSVjW6bmt19IKYLslz6BYVFoO/6tr+OPjYP/vnhrb2uwDJlnOVXG
         CcmGSht/U6wQl+vtoYKUBVkZDDxsvqQ9Y/k6VzVWu4DkAnarrQInILc3NJie7vxDWMdK
         5zG6iconR3TvuXewxDTwQyLM7bF4kVqTEKqmx4PuaQNhSRaVgKblCi/vQQGNli53ObcT
         TmeqthfX1RqK7LvcG29+MMch1XlPpazNN/GjaDfPw97MfmlvOX7gQJLix1Jyw7gmFiyi
         kdvMtnXSeBwjC9qpXapnzBOzzfi42HsY/qXyItvklAe1I6F3td+ytEMRroeduDqifOWy
         Vs3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=q5MasDLt;
       spf=pass (google.com: domain of 3rsfoygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rSFoYgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id d23-20020a1c7317000000b0038ebc691b17si215091wmb.2.2022.04.26.09.45.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Apr 2022 09:45:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rsfoygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id hr35-20020a1709073fa300b006f3647cd980so5654180ejc.5
        for <kasan-dev@googlegroups.com>; Tue, 26 Apr 2022 09:45:33 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:15:13:d580:abeb:bf6d:5726])
 (user=glider job=sendgmr) by 2002:a05:6402:27d1:b0:425:f92f:aac0 with SMTP id
 c17-20020a05640227d100b00425f92faac0mr5194069ede.409.1650991533278; Tue, 26
 Apr 2022 09:45:33 -0700 (PDT)
Date: Tue, 26 Apr 2022 18:42:57 +0200
In-Reply-To: <20220426164315.625149-1-glider@google.com>
Message-Id: <20220426164315.625149-29-glider@google.com>
Mime-Version: 1.0
References: <20220426164315.625149-1-glider@google.com>
X-Mailer: git-send-email 2.36.0.rc2.479.g8af0fa9b8e-goog
Subject: [PATCH v3 28/46] kmsan: entry: handle register passing from
 uninstrumented code
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
 header.i=@google.com header.s=20210112 header.b=q5MasDLt;       spf=pass
 (google.com: domain of 3rsfoygykcaoqvsnobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3rSFoYgYKCaoQVSNObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--glider.bounces.google.com;
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

Replace instrumentation_begin()	with instrumentation_begin_with_regs()
to let KMSAN handle the non-instrumented code and unpoison pt_regs
passed from the instrumented part.

Signed-off-by: Alexander Potapenko <glider@google.com>
---
Link: https://linux-review.googlesource.com/id/I7f0a9809b66bd85faae43142971d0095771b7a42
---
 kernel/entry/common.c | 22 +++++++++++-----------
 1 file changed, 11 insertions(+), 11 deletions(-)

diff --git a/kernel/entry/common.c b/kernel/entry/common.c
index 93c3b86e781c1..ce2324374882c 100644
--- a/kernel/entry/common.c
+++ b/kernel/entry/common.c
@@ -23,7 +23,7 @@ static __always_inline void __enter_from_user_mode(struct pt_regs *regs)
 	CT_WARN_ON(ct_state() != CONTEXT_USER);
 	user_exit_irqoff();
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	trace_hardirqs_off_finish();
 	instrumentation_end();
 }
@@ -105,7 +105,7 @@ noinstr long syscall_enter_from_user_mode(struct pt_regs *regs, long syscall)
 
 	__enter_from_user_mode(regs);
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	local_irq_enable();
 	ret = __syscall_enter_from_user_work(regs, syscall);
 	instrumentation_end();
@@ -116,7 +116,7 @@ noinstr long syscall_enter_from_user_mode(struct pt_regs *regs, long syscall)
 noinstr void syscall_enter_from_user_mode_prepare(struct pt_regs *regs)
 {
 	__enter_from_user_mode(regs);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	local_irq_enable();
 	instrumentation_end();
 }
@@ -290,7 +290,7 @@ void syscall_exit_to_user_mode_work(struct pt_regs *regs)
 
 __visible noinstr void syscall_exit_to_user_mode(struct pt_regs *regs)
 {
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	__syscall_exit_to_user_mode_work(regs);
 	instrumentation_end();
 	__exit_to_user_mode();
@@ -303,7 +303,7 @@ noinstr void irqentry_enter_from_user_mode(struct pt_regs *regs)
 
 noinstr void irqentry_exit_to_user_mode(struct pt_regs *regs)
 {
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	exit_to_user_mode_prepare(regs);
 	instrumentation_end();
 	__exit_to_user_mode();
@@ -351,7 +351,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 		 */
 		lockdep_hardirqs_off(CALLER_ADDR0);
 		rcu_irq_enter();
-		instrumentation_begin();
+		instrumentation_begin_with_regs(regs);
 		trace_hardirqs_off_finish();
 		instrumentation_end();
 
@@ -366,7 +366,7 @@ noinstr irqentry_state_t irqentry_enter(struct pt_regs *regs)
 	 * in having another one here.
 	 */
 	lockdep_hardirqs_off(CALLER_ADDR0);
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	rcu_irq_enter_check_tick();
 	trace_hardirqs_off_finish();
 	instrumentation_end();
@@ -413,7 +413,7 @@ noinstr void irqentry_exit(struct pt_regs *regs, irqentry_state_t state)
 		 * and RCU as the return to user mode path.
 		 */
 		if (state.exit_rcu) {
-			instrumentation_begin();
+			instrumentation_begin_with_regs(regs);
 			/* Tell the tracer that IRET will enable interrupts */
 			trace_hardirqs_on_prepare();
 			lockdep_hardirqs_on_prepare(CALLER_ADDR0);
@@ -423,7 +423,7 @@ noinstr void irqentry_exit(struct pt_regs *regs, irqentry_state_t state)
 			return;
 		}
 
-		instrumentation_begin();
+		instrumentation_begin_with_regs(regs);
 		if (IS_ENABLED(CONFIG_PREEMPTION))
 			irqentry_exit_cond_resched();
 
@@ -451,7 +451,7 @@ irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs)
 	lockdep_hardirq_enter();
 	rcu_nmi_enter();
 
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	trace_hardirqs_off_finish();
 	ftrace_nmi_enter();
 	instrumentation_end();
@@ -461,7 +461,7 @@ irqentry_state_t noinstr irqentry_nmi_enter(struct pt_regs *regs)
 
 void noinstr irqentry_nmi_exit(struct pt_regs *regs, irqentry_state_t irq_state)
 {
-	instrumentation_begin();
+	instrumentation_begin_with_regs(regs);
 	ftrace_nmi_exit();
 	if (irq_state.lockdep) {
 		trace_hardirqs_on_prepare();
-- 
2.36.0.rc2.479.g8af0fa9b8e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220426164315.625149-29-glider%40google.com.
