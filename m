Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNE33L3AKGQEP2SFYBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE9FF1EC0FF
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:34:45 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id o12sf1984248ilf.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:34:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591119284; cv=pass;
        d=google.com; s=arc-20160816;
        b=x+tSKdaC9o07fWsA14dubXKWx2g/prhpMu+tt1H5F/PDsYN9mEPoxWToAaN7X+sz1H
         by93gfOWKUm3TTbVTHrnHguuDfQhHjCB/XHAZdyNAd02c1pD6cqJ/Ek7Sr5CkIUTGs32
         ZFYCWHifbfPm+P+NQkZ/KR5Cw4mdtlLfAs0hYKlQVCFQiWlCe7mcfCvKq07idohhZua5
         F8WmyiByNyj+sXXh+DO5ZDDLVfUCc/6ndMzNe7K3vsw2/XplA3CqKCiQYC0HMXHBkEle
         QyKDJ1DRc+4QfYG74/l8LbQuG77VG1NUKoki0wUXCIm8vkMG1VXvadc8ZQawxHn/CDqI
         cBxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=ojfK9nMcLpK9K185fjnq5BmiEsUagpcCCWw2IFqg1Cc=;
        b=P6dERyY+fvgdprp6xGxkHk4GXbNsqks0Da48GmHctI9/WqlrN6UwGJU8DzZdDMrS4D
         OxONNenBZALf+loBfdT7f1hL3j2VHXY2NVCZlYRThYn1HyMPdt8KkiWWfOjc1Po30Z4t
         Hb80JGCptI0ImVDr3QJitNflumEDXnSGL8IntsqTPT3ay1WhUJUm9fivpqlC4EHtWGOx
         +6Gf13JPlkxXdFL19G+FMpmtaqtMXlCWtztwAXdhh8PcdKo4/4o0A4C8ImIaR3JsoOyk
         DcX6Mn8Eshh+WgHjaRRGdZctr/WNB66Prdj5Dz7GAm1og00TOEOFV/v92mKLGKbm5WQp
         +I2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bcScTCo5;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:user-agent:date:from:to:cc:subject:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ojfK9nMcLpK9K185fjnq5BmiEsUagpcCCWw2IFqg1Cc=;
        b=dJtmlmAM7/ULNUxt8bYdmdeAFeFyg4oHR/JvEmGbUaJ8j757u8RW3s3JDfQdtvlB+C
         UlhSjdFjx54tYptBtIp7Jz3XXCm7UDs+BVdZtFlcWH+Vpp4KRYQXvVfmm2OpW2YEzUl9
         qh65CzQnp6VGFvVcklHzH/QxZSRyXefNlTqmcNCGUiBRfncAItceNKECgrXSNAQwwtzf
         mrhezRHj6V8J7Z67oHo7OkfW+g/JHuRFESgAmeI189EnRXaC1+9790yMAhjfL+tk+19L
         nyTx4EVqAcgyu7GmVbKg20UNYyJ8/TCU2vbxcidwBvDHljk1tZC3o2vW6Wgw6iiFO2gC
         aY/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:user-agent:date:from:to:cc
         :subject:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ojfK9nMcLpK9K185fjnq5BmiEsUagpcCCWw2IFqg1Cc=;
        b=oLEiLq4I2jnQnU0Q6qumXrYZVeRB2HrSjKQfR/qyK9m95QWNU7ep89ZxoCR9LXl7S9
         TDeqz+TbNykxInXzi1ToDkNPj9JlwpXaaMNn99LZ10ij1ecz/WJixeXZBB0W/pRe826B
         U+muufcw48Y9AjzhJJ/uGkWkXsUyykDn41PELOuxL+NuXgw/myR6M4xVpb3J/9gVYwIR
         Xo9Xi8PzJdvoIbds50wYu1g2cSkHgPl9Zw6Yv0h7ixWUTGhJ1i8AiqO0nSSJGsI8flCX
         wYx3qmNondiIicvIbc9k71wqQHZ2o9tdToUKF8yP+2cPHK/V9MrJ2CMSrtSD8+b4++14
         pRdg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532UC6/rVpp0V6+pHUDO6uaAaS1dut3X4u3xz/esCsF/d+04dTN2
	JHL0uCfXdFwGPJHXeKY9wgA=
X-Google-Smtp-Source: ABdhPJyuBCNDW4ZIq6V5tKrqJCvi/paX0KePX/twELbc87Y6BkZ3+EzIgZKiU/+z49jrzHU9+pAJwQ==
X-Received: by 2002:a02:cce1:: with SMTP id l1mr25091162jaq.89.1591119284613;
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:84c6:: with SMTP id y67ls4708209ilk.10.gmail; Tue, 02
 Jun 2020 10:34:44 -0700 (PDT)
X-Received: by 2002:a92:6d03:: with SMTP id i3mr432708ilc.103.1591119284330;
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591119284; cv=none;
        d=google.com; s=arc-20160816;
        b=ft8VXqPeewnJrbnqV2DNXOh1pGE8yPkNb2noNzO7MCNq0gGKdVXFXh1mmZHfm2cKle
         Dqaa8TXlgnirC10GYa9yzoFMtbpqzxqbsgxQc53RO8He456jBb2ZCHQcKcb41tfqJJJv
         REvhoJp26o0yjXwphGuTuQqw1fGHY3zXI21c/Rp06NyyQKh95gIvJdAf/lsY9RN4vM1x
         rxyFY7yKEOPDFT3ozQA9kdBrNvePTbzObjeDmkT3h6mRRFr2ry2Sr6u4KUvX/eqFMUj1
         Hahk9+UIB4AtQvRe0oqjoFilovcp2UIchFT4IzShsvlwaoT83xXy6IUa0QaZGnXZZ7yD
         FahQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=qEEnCRuSkGqY17m970ZD2QMrdQ942DugTV6zA6aC45U=;
        b=meJvJvDSaPDPNAvUZcDPFYxH0wJzWE55Rhn32dRdiK+qksEylW4OQYfDHg3DqpC9m8
         4lEar2ZFWjgHB5gi9rLY+sknCs1sHnFlZ0IksCw91ZnATcaZVHgvWsVUizLNPnx1meqy
         5byAyhg30e2dL4EGegfGIRXw0saukBfNMLPoHvK5wcjVcnrzYj4VE6s6KlEcfA563gUw
         XEHkXggNzOFooRXDk4yvADOpzUsbIyIcuXJlNxuQ30Cett0uHafzB+a+3eO7cmrFSvuR
         d5qCCwIfeiqGZeesDwDLdvW+BnmWoVbGc+/GTDJG1jEDZk3+x0uxe7ER7HMi3U/+tQFV
         kBbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bcScTCo5;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id k16si45691iov.2.2020.06.02.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgAoC-0000Q6-Pz; Tue, 02 Jun 2020 17:34:40 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 3DA7B304BDF;
	Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 0A338201B7B84; Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Message-ID: <20200602173348.458385730@infradead.org>
User-Agent: quilt/0.66
Date: Tue, 02 Jun 2020 19:31:06 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org
Subject: [PATCH 3/3] x86, kcsan: Add __no_kcsan to noinstr
References: <20200602173103.931412766@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=bcScTCo5;
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

The 'noinstr' function attribute means no-instrumentation, this should
very much include *SAN. Because lots of that is broken at present,
only include KCSAN for now, as that is limited to clang11, which has
sane function attribute behaviour.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 include/linux/compiler_types.h |    8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -118,10 +118,6 @@ struct ftrace_likely_data {
 #define notrace			__attribute__((__no_instrument_function__))
 #endif
 
-/* Section for code which can't be instrumented at all */
-#define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text")))
-
 /*
  * it doesn't make sense on ARM (currently the only user of __naked)
  * to trace naked functions because then mcount is called without
@@ -200,6 +196,10 @@ struct ftrace_likely_data {
 #define __no_sanitize_or_inline __always_inline
 #endif
 
+/* Section for code which can't be instrumented at all */
+#define noinstr								\
+	noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
+
 #endif /* __KERNEL__ */
 
 #endif /* __ASSEMBLY__ */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602173348.458385730%40infradead.org.
