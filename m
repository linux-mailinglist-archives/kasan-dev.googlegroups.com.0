Return-Path: <kasan-dev+bncBCV5TUXXRUIBBJUZ333AKGQE3CYXAJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E32531ECEAB
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 13:42:31 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id x123sf134581pfc.13
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 04:42:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591184550; cv=pass;
        d=google.com; s=arc-20160816;
        b=CSj6E/8/HEQTB+v5U8ayPiwmU8qOwX7sCcBsaqX6AYAua19m1GN4zaaOM0i3BIr262
         k5K5j+kZ7cPEMYkiSQr/tiWnZkRPiX+0n4TqnUOoEVq93/1iX6Op2xlB5SB13FALnoJ4
         h5Kj1ajENDCQi/d5ZZnL923QHHKhoToxnLgzAHvXI3fKEucFPf4LH4yr6t78IS9jsGPw
         e3seR2t5i3cooNTTt6wd0jbQaGkI+PYaiAB4i4wUl3OfGPXpeR6C2OvxCvrSPjo9xJx8
         QPupp7rTOp7lHktO6nmqdIJFiyclGdQe7hWZemHvobQSMxesj6/pyeB5EnRkpXRmXvkZ
         TLVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=I6M7HjxWB4QfRS4GmviNyJ2kFom8PWLQtx4JeS+CGMY=;
        b=JXdD3HtDChMZP6gtU3XcWSbU9n2OHi72qNr8WeB7gkwIlCwUEauR4M76u1ZUme0ccB
         B5Km/6EoW4E/Vts99TcoH9gZqgIEpebnTpvWQd55Y+AvSOY/DE0o+OdRDXYR05c5tMCM
         WDtpfvu0q9hSI5+KIcP2cyaL1plSsCqbvOkPj3Azbvy4dfwTHmX5m7YTeYNe7gO3tdRJ
         ZXgyKL8jhNRicXYpZRiWNIPgk8zEwGFb3sRL7s9f4SCE+jkWeOqQjPLljNAxSBltfI3D
         Ofd1bDNVTs56+jIpEI5nEb5MJQL/4Ta306vR9wZJARQH5VduSnJyFP8D81qkHGhCdFyi
         i4BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=nd5NSFf1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I6M7HjxWB4QfRS4GmviNyJ2kFom8PWLQtx4JeS+CGMY=;
        b=mh/jQRvN6f2BBblN8EuWfoE7d6rkJ++RptESsi6gLx4by/Xr9Xn2AXZT4ucX3n+nU5
         TUDOAMPrBs84g7kSsfeELtgREL6gzt5CInhyKn7bxQ2gE+goi3Kzxl1PEFBpQEpeLaaV
         QNFjAroR9RXq5q5ImTHoftUytS36RkGT5g78aF6j1LaD2fK/R72aJoxTWCbPGPA68OtQ
         oEfvCEfntehkTX/PUx63Ml1qNlVxfcmJOLsSH4CwYhnHLBL5cXqTXDJ8BYKs3636vpJq
         NRS32LizDI1qLhTE+lllO9XYV6E52QS2gSSZREEBXc2n/i2/ByrCNWzJ/6vkqrwNN6DZ
         UpZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I6M7HjxWB4QfRS4GmviNyJ2kFom8PWLQtx4JeS+CGMY=;
        b=f2ZnrLVbfVQNaLm/bkEkoT/40Dp/cfGjIehRmnjDuc1wt1AevGoJdbC6DVtMJ7Iw57
         bryo9xBU46K4m39LHUEvLW6ReVCXD/M/YnjS3OOouOQ0knGRaz/Cw3geBzs+BJr88D+p
         U7WThPA1+ysExyMozTBK/0xbBXnckICaTSORtU4Zs8VoeZ+ME/L8qdPYjgKMo3vl7s0Q
         OyfKFoiTg8E7kpKh4QxI1ZyO9bCXkNI8nPuWEb7IpnWk2hue/CoTZeRqrzVF+JPx6JUC
         0kgcOPGA976WpOFB+dZ6/8squFZcnHfLMP5QytNInZNxBxGc4bunU+1IpChsdniwYlD6
         kFNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530gUJ4Il5ixos71iRrre4N1mhkgR26HFKm+ALTg8Uqu6feAO0lo
	GXyy9S2GMUI+kyKy23eY1bs=
X-Google-Smtp-Source: ABdhPJxOIhjOj7drXRAL1W7p4PbuQV2gj3U8W5vodm5UjUiZJ4oKFBUIKNEyuUfCuBRxqJlaGGRldQ==
X-Received: by 2002:a17:90a:f184:: with SMTP id bv4mr2372597pjb.57.1591184550669;
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d349:: with SMTP id i9ls1462569pjx.3.gmail; Wed, 03
 Jun 2020 04:42:30 -0700 (PDT)
X-Received: by 2002:a17:90a:ce17:: with SMTP id f23mr5594174pju.51.1591184550291;
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591184550; cv=none;
        d=google.com; s=arc-20160816;
        b=Ac5ZyDRpgcPLM8q26j/LoznXkan5WRkg9LrCRuCkr6mruqxEJfaDE5gSKwWE02WFlS
         eNwlih8nCIpYpqRQS3npZAEN6TPhuCO/nkek1Ntnr9g87xNLD61y0GpJll+A3uhWGYGa
         GwgZle/omPA1/ebhDXmgcMmzDISVDtOMoS8hsRRENMkFuVYOF0acsYwz2/vBhUNu3XBG
         LOnn5W9p40SFtBDeZHcK8iKGxTjpoDQGfPvYwHG5WQ2RNKQgJsUr1KCmc+b7F/QKoG2E
         T0aOsvon+kNIQkzW73RAEbQXitRHfzcmSxiNFIy6zsRFR/NOnACzLOTwUxGiPdwJr9xB
         ITxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=/2QXn+atrvGmy2WDbzn5KMB/u9lheYoEWUB6ctzoU3g=;
        b=b0s1jZZ98Cj310IVulAlxdrs+AXJ21GdY2DKYam9JnMBRcXMfKfOzCBtfvzDcU7jc1
         auVg4cbS8fHcTU06K/GJ/bnjI4FFTeXIz2+xtTpJNiFQSAXsLGCq2Klpxp6ORtxFrXs5
         x/Wjz8o1WuCdC0okMQL8bFejh4pAUo+9e/6LeRL3s4+0HcGdgqbf6yv5eTE0Hl8MbeyQ
         xs+O/q8kfqzf0Lwc1snY00GjkwO5L8oUsh5fE/iDtiJVgJ+pMQ1iO1Ca89/ti2HxR6g8
         jG7ApQPF50iCF8XeX7DIIxoc+TlvACiQBYM5WLVCApCCWd40rhmJSgWh1NpJMEcVzG/M
         PLyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=nd5NSFf1;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id r17si79203pgu.4.2020.06.03.04.42.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Jun 2020 04:42:30 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgRmr-0005oW-FJ; Wed, 03 Jun 2020 11:42:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id F266B306D6D;
	Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id B4319209DB0D0; Wed,  3 Jun 2020 13:42:23 +0200 (CEST)
Message-ID: <20200603114052.070166551@infradead.org>
User-Agent: quilt/0.66
Date: Wed, 03 Jun 2020 13:40:19 +0200
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
Subject: [PATCH 5/9] x86/entry: __always_inline arch_atomic_* for noinstr
References: <20200603114014.152292216@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=nd5NSFf1;
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

vmlinux.o: warning: objtool: rcu_dynticks_eqs_exit()+0x33: call to arch_atomic_and.constprop.0() leaves .noinstr.text section

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 arch/x86/include/asm/atomic.h |   14 +++++++-------
 1 file changed, 7 insertions(+), 7 deletions(-)

--- a/arch/x86/include/asm/atomic.h
+++ b/arch/x86/include/asm/atomic.h
@@ -205,13 +205,13 @@ static __always_inline bool arch_atomic_
 }
 #define arch_atomic_try_cmpxchg arch_atomic_try_cmpxchg
 
-static inline int arch_atomic_xchg(atomic_t *v, int new)
+static __always_inline int arch_atomic_xchg(atomic_t *v, int new)
 {
 	return arch_xchg(&v->counter, new);
 }
 #define arch_atomic_xchg arch_atomic_xchg
 
-static inline void arch_atomic_and(int i, atomic_t *v)
+static __always_inline void arch_atomic_and(int i, atomic_t *v)
 {
 	asm volatile(LOCK_PREFIX "andl %1,%0"
 			: "+m" (v->counter)
@@ -219,7 +219,7 @@ static inline void arch_atomic_and(int i
 			: "memory");
 }
 
-static inline int arch_atomic_fetch_and(int i, atomic_t *v)
+static __always_inline int arch_atomic_fetch_and(int i, atomic_t *v)
 {
 	int val = arch_atomic_read(v);
 
@@ -229,7 +229,7 @@ static inline int arch_atomic_fetch_and(
 }
 #define arch_atomic_fetch_and arch_atomic_fetch_and
 
-static inline void arch_atomic_or(int i, atomic_t *v)
+static __always_inline void arch_atomic_or(int i, atomic_t *v)
 {
 	asm volatile(LOCK_PREFIX "orl %1,%0"
 			: "+m" (v->counter)
@@ -237,7 +237,7 @@ static inline void arch_atomic_or(int i,
 			: "memory");
 }
 
-static inline int arch_atomic_fetch_or(int i, atomic_t *v)
+static __always_inline int arch_atomic_fetch_or(int i, atomic_t *v)
 {
 	int val = arch_atomic_read(v);
 
@@ -247,7 +247,7 @@ static inline int arch_atomic_fetch_or(i
 }
 #define arch_atomic_fetch_or arch_atomic_fetch_or
 
-static inline void arch_atomic_xor(int i, atomic_t *v)
+static __always_inline void arch_atomic_xor(int i, atomic_t *v)
 {
 	asm volatile(LOCK_PREFIX "xorl %1,%0"
 			: "+m" (v->counter)
@@ -255,7 +255,7 @@ static inline void arch_atomic_xor(int i
 			: "memory");
 }
 
-static inline int arch_atomic_fetch_xor(int i, atomic_t *v)
+static __always_inline int arch_atomic_fetch_xor(int i, atomic_t *v)
 {
 	int val = arch_atomic_read(v);
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200603114052.070166551%40infradead.org.
