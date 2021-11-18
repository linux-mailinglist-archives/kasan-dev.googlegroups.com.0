Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP4V3CGAMGQE7NCIXEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 752D4455684
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:43 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id bx28-20020a0564020b5c00b003e7c42443dbsf4529610edb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223103; cv=pass;
        d=google.com; s=arc-20160816;
        b=ES7W14M3olgZzeaaKcplvSRzSj3rScg3kPh9vZ34flXdSt+bh0tH3gG5SG7DCrNXLS
         KO/WxUiq5B/hp1xY7U3NV0W77cCoL635O7Rq6k0GbRYBRgLDBVb3VyM9qYjth+yclUzZ
         wcMalqNmyN/kPYLmbD8bGiE3pYPWACQ34GgI4FEpH5lEquOQa+uBA6nRXIF1jobYZHnY
         lJFS9Kwwdg1irpIQb+7e10ND7a6ka6uq6SMFXpf26Jq1OEgVeB6ObuI+d+1ImKjXqVFp
         q7SUa3NNbTSsdfMCvd7nKumY6JYCxmladeMmkd1D+PEoGiZIA/F1thil6J+Am2OBiV20
         RDuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=au+jvd1CMU6ElVwxn5VZ+9BTPiog9mVaeF/nddjSmag=;
        b=Gv3xKhFHsCYKZtsMSZtwqHPKcfsrAc/0SakIX+3NFyjWrUYwx1jMNLUUCOxXdXrNK1
         mYF2MNDopCfbajBmCrQ2916eyNPnk019vNu046ook7ojtwJBzSq41JzSDB6IpQWG0VKA
         LHaeOHJq16bpb1xDWGVrHVdnIYKBVOO0S64CS6Za5YRE4UuVpe/Xci+XhOzthDz71uhK
         mKZaC6GvRYY6La1rdUCWL8E6XPvZn/w1mRoBOllVWXVgsRBacahPqUe6O929TKHPcYsN
         sNuD4vTdSfN/7nD3DT/batDdkLu+ledFJ51A6GKWee/gM9e4tlN7y6KBb4r9gNxU4WtW
         MWMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JzkdiCAf;
       spf=pass (google.com: domain of 3vgqwyqukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vgqWYQUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=au+jvd1CMU6ElVwxn5VZ+9BTPiog9mVaeF/nddjSmag=;
        b=YoYqdbI/ZYtnkGgEp2gIe+KMxIZUa7Gj8Cx1ADS7GyT6TyuojuDTfMTAXW6+UlxvZk
         kYVbHsN50t1TeAYcddbsqnDF+6fYb7H01ZHH1bLF0eHCwQjmxUXCPZUuBy9wMcztsmh8
         jnVTxPuDVKSx9Vhe0NMuhffgnHcMhp8JjvuBfRX3KzQLrbd12rGnlASHQN1OYIUNSxSI
         nlXdYZM1lKA+0AkZvFdJk4mu70SChUBsLJhBaDhn1Xppa2OuCBERMDSEcCTULjWwV7cr
         5gBFUYQQy0bczkImPbWVC4o4N9663Inu7J1WDP4ihz4Z6p8aPIFIMSXK5YqzBPmh9b7A
         JXDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=au+jvd1CMU6ElVwxn5VZ+9BTPiog9mVaeF/nddjSmag=;
        b=YrBxP7oDzTN8WcnN3VCgBJPbKHGmkFLA1Ain62eUxwrn2mdY3MOR5WaUba+XJIhe7x
         ToL2dBIvic4yysxkdG9cNDc21xARVIy//FZhuaD3JhLOiP29V89Rsiv1AUO6TXfo8BdL
         CdZExXpdrhl36Ng2YHwulgoUHZRiXmGjBGo6BKk3nHwK5JQiW9lNLTM634pe2e8O4HWs
         SBLeVCYmvGqlZpvIYiuqhmfS96/F6c2a2xG5Hnw8ptQHm5DmBte9NAoB3jZFvDvIQ7Cr
         5PluJC8HSU/NgstGCU3SfLbDLElxUmoSlZwMepIsVC9frZ4A20CjyC4xOJwlEDWjWY1z
         oFWw==
X-Gm-Message-State: AOAM5318nx2r9gYYlgs2IRAfemm0JOi1dx4wnfBH1s5QubIju24NXT8Y
	wZwNzHHMGHxcLK27nNwcHlY=
X-Google-Smtp-Source: ABdhPJyPLvY+yMKhvQLzpSbRX4ex5wXCk4d/3zzbGK9JRrye3CHi9Z+WAriYDeezJosY/83wMtMLgw==
X-Received: by 2002:a17:907:96a9:: with SMTP id hd41mr31459815ejc.413.1637223103263;
        Thu, 18 Nov 2021 00:11:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e93:: with SMTP id qb19ls1078853ejc.4.gmail; Thu,
 18 Nov 2021 00:11:42 -0800 (PST)
X-Received: by 2002:a17:906:dc93:: with SMTP id cs19mr31178315ejc.21.1637223102301;
        Thu, 18 Nov 2021 00:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223102; cv=none;
        d=google.com; s=arc-20160816;
        b=tj34im260ivTlfS2Kv71Ymky1xwQeQ6L8OoTD1d+QqdcooqsCDe54Cp+Xqmv/eSzaz
         U3xPW2cLrBvJbleRSnMKA0y5rSeeXmPFR3JTihZNhW1P9AziQs7IdEceykg1uDNAn9Ap
         pyLRxNMD+kt1INdGuZzoYwZxRAc2d7mREJnSq5bcJ/qeSsKiNHSG6WVmjCipc6sgIemS
         uWyGsf25X0T0oZAmncg+sVoV88c5PozNY+c3megvMUa56HJHKXLVEkHCXXVUGdhL8pVU
         3H3dxiOBRziM97MQhscTfrBXCjZPt6vlyV8AqF4n0raWrBgdM+dPbbw+K6Cj4c9rf7QD
         45DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=FxnGx7glVXa5fb5vt97IxdOcLQo6ydeIuX4RCBDcgdw=;
        b=D1VU+FLPrFeQ0bHW9oddbWMd4wv8RJ0/fswhKhKe6sZh/dscs8CabfdpC7J8GU/6BX
         6M08B6ouYoPFaqm2szyBb6H16z3Kk4pdhfWYI+fDnTxYXTInS3Q8ox3hp5Wl/RJNa+GH
         qgtcs97cFEf/gIZafKNAq3TzVs+L+vzOA7YeoZF8dGOGLVbAUfw5Q96VVOr7i1t5ylBo
         QmHcYq5cWAFbqviB+YAhvLv+KwItHU7Q28mhg0/b+YY/hlz6/qJMpsYfRq0Pb6h1r97c
         xppUgk/04SIzfYPtwNggNQv5bNNHUhWv7gwZuBj8o8BWlAQmbsFlbFKkMCfhEBNiDBKJ
         dBvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=JzkdiCAf;
       spf=pass (google.com: domain of 3vgqwyqukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vgqWYQUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id fl21si175672ejc.0.2021.11.18.00.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vgqwyqukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 145-20020a1c0197000000b0032efc3eb9bcso4006387wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:42 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:1d01:: with SMTP id
 l1mr7928633wms.44.1637223102036; Thu, 18 Nov 2021 00:11:42 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:22 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-19-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 18/23] x86/barriers, kcsan: Use generic instrumentation for
 non-smp barriers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=JzkdiCAf;       spf=pass
 (google.com: domain of 3vgqwyqukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3vgqWYQUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-19-elver%40google.com.
