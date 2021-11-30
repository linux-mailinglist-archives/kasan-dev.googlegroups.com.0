Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3E5TCGQMGQEY5ZKUTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E35FF4632F2
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:48 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id i6-20020a0565123e0600b00417d29eede4sf3386846lfv.12
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272748; cv=pass;
        d=google.com; s=arc-20160816;
        b=XBfpREyS9x7J+qyRpks9IMl+3vMkEktv00Ww3Qu39yRgm3q750eS6Mp/ODAiBNrZ5B
         dd6lOYhUQxgYckyRbjXZDOSCXo6mmGtJ1CJFtvQ79etgrDFs2K2lduEf6OnxhKMkIJR1
         gsx+DaLZIpqackMuyqBfSyB5IoZvotvUTrUtvheKIg5w2ytd26Q5QGdhLcQVrW36rySZ
         tY7HDbcn7U2O2lvRyrKK8G1XHO0Q6+/rixUP3Zdsl/lFuwybsJ4SaJrjNeF4h5lHFr+v
         KjgwPaAoZWhXn44UbLijf/v4yyUPDyaWzUV+OrUNsMTo6dHtQZNEAOgIZGiTGLsQcOeE
         JKyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+D5HOO6OIj0WqhEDwPfsEbNcLNV2TvHKNHrwykXlpkI=;
        b=q2rlG/waVBiZcuoE3cT7pMLrkshjgQQXvg3GMsbhqPhvpOpp2NAcvUP/AlLmD930Qe
         EK+DWFBvHaxw1f80sNZaeJXiUrog++nxbEyVgoQ3B3APn/IC2iiPbGHEEpVJBD4kz45E
         xP0IGKuXKMArx58nsJQc+MKYuys/YvulQCLBVCZ7vqnsaglKnSXO3q8DGt7ow3vJFjYq
         u9X+cTbKW1jWV3xBKkOoyNlMKsmE9l6fHeKbIydCU/9wOeBC5k4WHauAL5k1Av5yO10E
         GTcLMLW+Txg5LqhwRka5QGp1WzZPlg+ZqCXeMLb1eoStZl2lzZfH5o1GeHtLXb6DBwd6
         ODfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IuT8ETl+;
       spf=pass (google.com: domain of 36g6myqukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36g6mYQUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+D5HOO6OIj0WqhEDwPfsEbNcLNV2TvHKNHrwykXlpkI=;
        b=maUjNLJKOP8ZtfjA3JrkPcDD1pFtHJqQM1OjMb8Hck3kglpWnXE5/NJql3++OA57vS
         JRbUSEHpYrZBzV2aEIFziAbqHukr3h6Cg43bbhj5oMgM13VHIksu4vVwmim8gzvYWE/Q
         47T/MrRBSBFPepbSfkweDNXFAQY5tmJx/kqd1SvS2C2z76rIwFODs/LeSksSiW9f7ceh
         ff9UBze7heT9rF1smppg/gx/G9LIVvN/tiDoRLEMZMCmwI4nOrVJNXb1+CV4DL74G3Cd
         ja2s2B9wkzVvAdrLVTY6RgDr1DdGdYdYPo05LybwfLmriE1rOoazzFFElZjU+kn00bp1
         VAXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+D5HOO6OIj0WqhEDwPfsEbNcLNV2TvHKNHrwykXlpkI=;
        b=Ygmwh1ECuzXL50h6cnaz+yzBgOPceAW/n2koalv0VS19knUIUlbdCVbsrckTZr8+vl
         8OcaG/DaxGdPSrMPuwQxNUfBk/Q+w3fune3prCtJ6UKeq2R37XGEu+FRlUVHZp67gDHL
         Xa/0rmokGgigkzbb9whFUDPW1DeX7fXQ32tUieLpKubauy3rOiHt+2ln1C9tEiqYwdz3
         pGRmbeMXQdJ0O39HBxQ4lBHblPLfAFgZk/aUn0FxnrAcBDnzDXMbJ+/dpfJHxWAsBAik
         XITsqxdmQTuiMzvYMkGmMopaHRYS9TVeL/XiusRqbLRwc+XscZjcMPifHsmwQpw5FnH3
         pvuw==
X-Gm-Message-State: AOAM533AO1KYWuCv2QY0J28P7K/4BBo2jJ8Gwp0vOpBdQDznHdRKlDQA
	3xDF5jcLmaEQX5iQ/6/w70g=
X-Google-Smtp-Source: ABdhPJxOUGsNPuvWO1aRNl45TN7Rp42Dj4+3tfiU7//PVHD5Jfh5eAFtaEvRB7qrsUod+K5nVJP+qw==
X-Received: by 2002:a05:6512:3e09:: with SMTP id i9mr55116850lfv.239.1638272748554;
        Tue, 30 Nov 2021 03:45:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c4:: with SMTP id x4ls2442512ljp.8.gmail; Tue, 30 Nov
 2021 03:45:47 -0800 (PST)
X-Received: by 2002:a2e:b816:: with SMTP id u22mr34951101ljo.51.1638272747471;
        Tue, 30 Nov 2021 03:45:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272747; cv=none;
        d=google.com; s=arc-20160816;
        b=VKNW1zJ9nJWZ3yzQk5XLGurPHBh2AQftKj4PvUdfWyYDWseFo4V5If6NT3zDBpw1go
         SbANw5J3VrFL9BYaBgIu8AwV5HMmHlSxa0n9TA+KUI8p7MDj42CSUm6Ed5guE6BM+oIQ
         T5hkYqoyg4gDQNKNM9S5DZbuEnEOd9g+/84/A+9A9GwZKkdYM23Q0wr25JxXtG2moSOQ
         vENpSLmLd48csjSANzzP8nf3pdds8eEWQYwgJ/zhQ+iDxwrUgDTrlRppTgzjhLSSN3Ql
         ZuQDkV703dh0iXc4hiTP6SqyRhjf1RqpioLA0Zmy9lupbFbehRNvC1+0PSJ1HcGywwjf
         /odw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=FxnGx7glVXa5fb5vt97IxdOcLQo6ydeIuX4RCBDcgdw=;
        b=oxCoc84LZTA0u7s29rLZSgH8L0/jCl1b1n8T0bqOBnNCHSPjdPA/vjmfn7ey1SQ/7q
         xAEaJEg1RqEYguFsRmBor5/CsE+ZCAUL3/W+IwZh8h113ir8rl556Wpo3s1lMGP0I7Sz
         5flWwnZxsiOzzVUHz6iq+ts8sFeWHcorJx0myJXiyCH8iJSRySH7mpmJYoEXKppwbTlJ
         mQsPdrcACVBoIGjAjQ4AhbHG4lD8lsbZ/UM+NYloTbXhbgG0srKUgwaKQ9pOwJckTFOH
         4U69VAVf2+XmVxoKQqwH2NHlIR6euChQd0mTcfepOtkfWKAvejCX6t5YY3CjOFx6sNk2
         1vbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IuT8ETl+;
       spf=pass (google.com: domain of 36g6myqukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36g6mYQUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id e19si1711934lfr.9.2021.11.30.03.45.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:47 -0800 (PST)
Received-SPF: pass (google.com: domain of 36g6myqukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id t9-20020aa7d709000000b003e83403a5cbso16713660edq.19
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:47 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a17:907:9720:: with SMTP id
 jg32mr69349183ejc.304.1638272746945; Tue, 30 Nov 2021 03:45:46 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:26 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-19-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 18/25] x86/barriers, kcsan: Use generic instrumentation for
 non-smp barriers
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
 header.i=@google.com header.s=20210112 header.b=IuT8ETl+;       spf=pass
 (google.com: domain of 36g6myqukcbmxeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=36g6mYQUKCbMXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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

Prefix all barriers with __, now that asm-generic/barriers.h supports
defining the final instrumented version of these barriers. The change is
limited to barriers used by x86-64.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/x86/include/asm/barrier.h | 10 +++++-----
 1 file changed, 5 insertions(+), 5 deletions(-)

diff --git a/arch/x86/include/asm/barrier.h b/arch/x86/include/asm/barrier.h
index 3ba772a69cc8..35389b2af88e 100644
--- a/arch/x86/include/asm/barrier.h
+++ b/arch/x86/include/asm/barrier.h
@@ -19,9 +19,9 @@
 #define wmb() asm volatile(ALTERNATIVE("lock; addl $0,-4(%%esp)", "sfence", \
 				       X86_FEATURE_XMM2) ::: "memory", "cc")
 #else
-#define mb() 	asm volatile("mfence":::"memory")
-#define rmb()	asm volatile("lfence":::"memory")
-#define wmb()	asm volatile("sfence" ::: "memory")
+#define __mb()	asm volatile("mfence":::"memory")
+#define __rmb()	asm volatile("lfence":::"memory")
+#define __wmb()	asm volatile("sfence" ::: "memory")
 #endif
 
 /**
@@ -51,8 +51,8 @@ static inline unsigned long array_index_mask_nospec(unsigned long index,
 /* Prevent speculative execution past this barrier. */
 #define barrier_nospec() alternative("", "lfence", X86_FEATURE_LFENCE_RDTSC)
 
-#define dma_rmb()	barrier()
-#define dma_wmb()	barrier()
+#define __dma_rmb()	barrier()
+#define __dma_wmb()	barrier()
 
 #define __smp_mb()	asm volatile("lock; addl $0,-4(%%" _ASM_SP ")" ::: "memory", "cc")
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-19-elver%40google.com.
