Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJMZ333AKGQEZVDZC4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A4071ECEA9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:31 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id p20sf1240495ili.16
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=A3mIAtT6FBxvhqDCQGDUVcUIUih99E+pg14DppBFMssjlgNT/q48ufxJcvZFZ4ARPG
         RhKSV0hnz6qwyK+MB+LcBXz1VkDlEqtEnbIzUbHsF1SlJrxgWcitRCTILp+3iwUuDr8L
         wo8UiiCJMqJv6rPK60fjLNnXzXhQbqiNNhZUWrQjD5sodBpHIiPKQw2LMocQ3A1ymb5S
         q4AOew4aCJzCcyKl7S+igKheVYf091v6XkLfKANIZSp8y8XKydo6gjGJZExsWsVPp4x2
         Q+neTafTWkuHVL6M697PpS2aKiNslBjWR9DRIJHCKAra84TO6QPB9azp2wI7NIrLZJQV
         PtvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=833c380zyF/kAW4kkpWe8vLxZAJXLHjavJmOurrDw7k=;
        b=oOk+/zqmFrAXaLihszQFiY6/46cS7vkMjPbVEgviHWVSqcDg3QOvlchuDAlP3f9hsI
         SyV6pens4UWwbDm4fprXd/DFGUU6FOmCg0DaI0OslL/mOFufOWDJCK+a+JDDhlejzhRB
         w5B4qaEWbDpxhwqbBMSvapIm2CjvaPT0QssFF+0xcU9LLw97Cf25II5SBY4V7zmFmEC0
         r7nvmh2O3noDYQzjeM03NudnQUQ+soOdhRn5aDu2E4MpQB0MorQ33LNjRspb2cwToUR3
         +YStaNl+kVzBkJ6BohwbNtYm9+eqz6AYW744bsSAQnQJQlm2vW2NBfsrryKEYdSGumrQ
         /hdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=E3gzSfAM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=833c380zyF/kAW4kkpWe8vLxZAJXLHjavJmOurrDw7k=;
        b=CXcEWUaJvlR7ZGukWKMdbuuaAQd0PHXTg192mZJa1Mno/v2TB7HbgV424txji4CPE/
         p2KayDaH0EDWjpbQjgGkpFYykDwCalTkehDUDC2IInwTamanCdW0zPiCzsFlXM4z6PB4
         Bp+IP2MUvYl0lk/wW4TSg6VnLp4ghGZc7fKh3xY7PNntblXEQ4BBJtBDdBtQu1DsDOIE
         T6kBpRZe/lApCfzcFvkA0cfFQZjZVaB395S+u+mw5ks4hXULCKrOH3ri4qQfIKXMUHRD
         GNBXIQT43F//CS2deXgWML2GNokzt9y0qDb1jdqifhdnVyQ2ZrnILE0JZk8hPmQbzC44
         qyOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=833c380zyF/kAW4kkpWe8vLxZAJXLHjavJmOurrDw7k=;
        b=Gpe0MZQGz8Pca031w6My16+5FcYxkq5pp5P443GZ/6y804cDErWjxl8mF6KD+LnCMQ
         sKrAOI+eUBAIBgSOMMKyJjbIrWEU08dmTb8wDA/G1MO5+OEyuCUqCMHPotWjeU2C2LUj
         elPICko+PhGY2vjfxjkpEWvUSeRmWgUI49BCK483k9DkMCjqnH7m3K4y72fByKiTv94L
         zBmiZPmpr/KYCGgjyyS374SGr9LuEY2TuAJEV7RTIxL944udOY5P0PfRuUbmLbHGnWXf
         tQNwZbKzouQJRA9Az7kNjnMklDjKVAhCTjxOEEcqm73UKLjsNmTEYVLI79W+q3rSswam
         YjKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wosxiKa0lBuMOexFzU9/jdgrrwWt6Ziq+RmFyLsu2eYPUIsXv
	B9xxw7kWW/iPxD6dZ4DG0ZU=
X-Google-Smtp-Source: ABdhPJyzsTSu4aaMVWg7am9CmwslgbLw4VMMSPQKY3pWFhlrrhDZh2sj1oTjdqtPVklcxFzc0smkaA==
X-Received: by 2002:a92:400e:: with SMTP id n14mr3435511ila.300.1591184550048;
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:9345:: with SMTP id e5ls267656jah.0.gmail; Wed, 03 Jun
 2020 04:42:29 -0700 (PDT)
X-Received: by 2002:a02:c985:: with SMTP id b5mr28457973jap.22.1591184549667;
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184549; cv=none;
        d=google.com; s=arc-20160816;
        b=i0IUFByG2j1+fJCAO37kGXmpZckMl5yzMVKLiOpQqA2bmSOb2TCygzNYWarBqSSqcn
         kaOxG8OM1k88dX8eoC7EpjH10iFj2KYBLLRxadNLxl+b2E2/1KXT97gRu0PuxhkvpEeO
         Or4GeUXCtz2Ehaunq1xY+5ZfnSLhEURjFUJpNCK7rLbD1Ve4EretLOmpUlDaRzZExVn/
         IUF8M7l3BN89qpYxmLEDNHZty0xo9RsUXMq2x7kPKE2lH73r9M7rKj2qHN8Vee50Da0P
         ydTjnTyUceURIGBFQW80bPT1Je5g9vMGeFLMbxuw4lkTpCXqaNF9XlxKBgMJyTe0QHdT
         i6tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=7IW00XHgXSVe0eWN0HTd2HDxOWygvcOr4u+CUzB/SvI=;
        b=m7GEaL97cchg6m6hMlBHljYDdjqAz+FDjncwDIiAnxEcYxgLWSesmnu6e7XGn87AVE
         E/+KfqBClqsA+y+Ojmi6o8ByjO+3yuDho2tEJVV8I5b0DNPoLh580N3dgmZ27KKpGYBi
         a8SN3sOpbNCBfunwewH+ICxCnmxXWvZu6zuxfKFCX+K5i2aecxFfQ4q0DMH3iPVUtMf/
         Wrx/gctxWzN2pR+AJo3RM5awAvGQ2iBCE8bVEVhFPEi7YkwLsVCJ3bDh37UxGWjRgHl3
         8Q6+AghFMC436HmiBGtK6E6WCRaT6XQjh66xMwphGwLcrUQB9oy40eFm97yevZID13bv
         6dDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=E3gzSfAM;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v16si74442ilj.1.2020.06.03.04.42.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:29 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRms-0005of-U0; Wed, 03 Jun 2020 11:42:27 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 0E03D306E6D;
	Wed,  3 Jun 2020 13:42:24 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id BEF6D209DB0D4; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.243227806@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:22 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org,
 will@kernel.org,
 dvyukov@google.com,
 glider@google.com,
 andreyknvl@google.com
Subject: [PATCH 8/9] x86/entry: __always_inline CR2 for noinstr
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=E3gzSfAM;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

vmlinux.o: warning: objtool: exc_page_fault()+0x9: call to read_cr2() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_page_fault()+0x24: call to prefetchw() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_page_fault()+0x21: call to kvm_handle_async_pf.isra.0() leaves .noinstr.text section
vmlinux.o: warning: objtool: exc_nmi()+0x1cc: call to write_cr2() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/kvm_para.h      |    2 +-
 arch/x86/include/asm/processor.h     |    2 +-
 arch/x86/include/asm/special_insns.h |    8 ++++----
 3 files changed, 6 insertions(+), 6 deletions(-)

--- a/arch/x86/include/asm/kvm_para.h
+++ b/arch/x86/include/asm/kvm_para.h
@@ -141,7 +141,7 @@ static inline void kvm_disable_steal_tim
 	return;
 }
 
-static inline bool kvm_handle_async_pf(struct pt_regs *regs, u32 token)
+static __always_inline bool kvm_handle_async_pf(struct pt_regs *regs, u32 token)
 {
 	return false;
 }
--- a/arch/x86/include/asm/processor.h
+++ b/arch/x86/include/asm/processor.h
@@ -823,7 +823,7 @@ static inline void prefetch(const void *
  * Useful for spinlocks to avoid one state transition in the
  * cache coherency protocol:
  */
-static inline void prefetchw(const void *x)
+static __always_inline void prefetchw(const void *x)
 {
 	alternative_input(BASE_PREFETCH, "prefetchw %P1",
 			  X86_FEATURE_3DNOWPREFETCH,
--- a/arch/x86/include/asm/special_insns.h
+++ b/arch/x86/include/asm/special_insns.h
@@ -28,14 +28,14 @@ static inline unsigned long native_read_
 	return val;
 }
 
-static inline unsigned long native_read_cr2(void)
+static __always_inline unsigned long native_read_cr2(void)
 {
 	unsigned long val;
 	asm volatile("mov %%cr2,%0\n\t" : "=r" (val), "=m" (__force_order));
 	return val;
 }
 
-static inline void native_write_cr2(unsigned long val)
+static __always_inline void native_write_cr2(unsigned long val)
 {
 	asm volatile("mov %0,%%cr2": : "r" (val), "m" (__force_order));
 }
@@ -160,12 +160,12 @@ static inline void write_cr0(unsigned lo
 	native_write_cr0(x);
 }
 
-static inline unsigned long read_cr2(void)
+static __always_inline unsigned long read_cr2(void)
 {
 	return native_read_cr2();
 }
 
-static inline void write_cr2(unsigned long x)
+static __always_inline void write_cr2(unsigned long x)
 {
 	native_write_cr2(x);
 }


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.243227806%40infradead.org.
