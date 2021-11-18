Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKEV3CGAMGQE2VQKRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 4147445566A
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:21 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id m2-20020a056512014200b0041042b64791sf3440487lfo.6
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223080; cv=pass;
        d=google.com; s=arc-20160816;
        b=SOY/IXPWR7MlpqX2q4lGTFyegFRLzepo+qK1TyEEuZDv0G8nQcsTCvm+yGq+uZG8B0
         2GRjXM1pRAbHdG+QFkGzZgG3CKX7d89gd1lK25IHE4kHug42YWGvMuU82TqrUhqUcvGP
         9tIJP+t/i1UAI7Rn81KU74n40k9/0X1u+7b427nKPbbRCe9IpLMUB9IJnc237a182ozG
         Hh1MmVxXKjPcEXAe7Qk5KCzPIHDWz0/WCW5MMEdaVO1xhSI7LMQwaaw5hiSYkugpXiUV
         Qwbsdy79YWA9mh1/kmmUUiADtvw0UeXMF8oOpMRAp6jAV480OEYFa7PwpQ4n153OWN9b
         Rx1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZbNKI6KUAoeG2NXfqFuYCUtOXPx0Wt6tCTwuJMrHxGY=;
        b=YK8X1M4ET4pYo4OANhnQDUUsRRqejDpf8e9cqbXfbnsJxJnlDKdzl9lNpJb1pbEj7c
         67avF4PFlnAKf9FJPsTKL3/s4h1N4tRMP8UF2QrNo9xWlWIKlxfQViQQCUcLAfUd3Oab
         tmUxn5zAlMXJ9u3/6hdZBPWYqAHnr2AqAcJugTDVFjGLejm8e8fsDol8owmLYm4LbjYM
         6IacG+yYdf23c6wttK/6T1lf26QtjW3/Yjn2BFIOc+EPh7nnUX+viVK78TtnjCjq4diS
         whd6O//HruFVG5fIOT6ojTEWtykV+vCBU3qzLu6n6OiGtoiXUMox+u3oh0w4q6TJ1ehi
         j1/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=obL9Yv7I;
       spf=pass (google.com: domain of 3pwqwyqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pwqWYQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZbNKI6KUAoeG2NXfqFuYCUtOXPx0Wt6tCTwuJMrHxGY=;
        b=cRvwVdVZTTKACK+xqC5bwsSI8BzUz4yapnYiNvTrq/SD4LbCtRXRTI1zW+GlHtTu8D
         SDQDSuduPb0Q50hWpoGGmLKnefG/xX9aL43fw5QSRxGU5XSycttqZKm18gVnXBBEWkhu
         tHs0U6hbV3K0tuHYr7Q+Ytbr6hKX18P/196Jr26KVLYPvHsfAA8XPasWYbhstmvWqk93
         Mqrp/HXYy++4SXMBkVDfGdg0SjAcEqLBpQdyv1vgL2mz43OP54TQI2xdCnTrobE9Y+Xs
         UEs5pJQ5xKYkHEc3jnZAx0HVeWx8fzkwtVaYvQZsjya6kJIkygWjXpB0bSz3UNweQHQA
         idmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZbNKI6KUAoeG2NXfqFuYCUtOXPx0Wt6tCTwuJMrHxGY=;
        b=GCsLHAahNwU9Uq+Vi7qdy/ZJPh2lzH0q8rJHFYfyJ1ccfmhBZuot+EkZC7cJ/3pMDx
         Qugvkmuxuj904JccgS1dIhmICEBMuWLUVDpgsfuv0+cW7kik2PUB4AmBN6SEys+38P2n
         qepoAMecOU8x9dTvn93EA3AxFTxx4q8jn1ZxzFD53Adoh5wLxoNk2JDWzLR1tfGUGeIH
         Xhx6pKe9vviGCfmuoTPtoB4iRfIbmZ/KAia1y+uQRqno1uLydqpvXiMp55Lk7FMc8PWx
         WrWIzzvXAjpuBgQ50w0quTvxbrXRac+aXXd0XmQjHukrwcfalYx3pv0YTncOnJ+h8ySQ
         Satg==
X-Gm-Message-State: AOAM530uFbgAHyf51WWM6gOfjby/VNu639opNPov8/8CDAzm70CZabDr
	pJhyESLSngMf/5/WhRPF4N4=
X-Google-Smtp-Source: ABdhPJzZBhxO01iPbPVaf1vdDZazWy7PO6D8AAygDWCOCgTRTkQhu+O1Qy1umUUnli6nGziaPzdWhQ==
X-Received: by 2002:a2e:99cf:: with SMTP id l15mr15336999ljj.111.1637223080802;
        Thu, 18 Nov 2021 00:11:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8611:: with SMTP id a17ls403724lji.1.gmail; Thu, 18 Nov
 2021 00:11:19 -0800 (PST)
X-Received: by 2002:a05:651c:50c:: with SMTP id o12mr15224188ljp.438.1637223079721;
        Thu, 18 Nov 2021 00:11:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223079; cv=none;
        d=google.com; s=arc-20160816;
        b=tEeu2dZwMsb025mGBxssEeNz72XWSatzDrfC+i6VwXAl+I1yT0EdkFqjk55zhu02w3
         bMdl+7jCjcZWvNph8TL3OUCbbObF5p09BKls8O9qCg342GylMN8VYR+ms21Zh14pI9GC
         1ciJcnW6+M0TY2pH/tq0DwGhY8vVY71e0R318RZtBYsA+CWUcWDgkAR0kXXBdAfdu2Wa
         PI78BOgdawLhVRRFuNtPOPTXXdX1rG9zBDUk+fLMnjZlw3NmdHcILJPET8edy1ien1G5
         M2e4n/zIbawk2ip/G0b34zqK1tLJVjUfF1cX8Qgm68VjNIaVJk84Xo/V3oMbnC0KGUXW
         JqQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rG1xNdPiM+b/19SfERFIEiLMABj+g1AA81VAk56ezfY=;
        b=jy2Q5i/egsFj51FuCZFXo0zsUNBexmh6OcjyoFnzXhzGe2iibWO9UqVmXfNl8n75iV
         8q1pdCwa+y6pZNoWtag8PB4offYIRopnKJQlX5HjNDtSRR3D/7RCLdf/OYKD5LdLQXMr
         9GvqUzJjM8ETneSPzWTWMSyQFfweTb9WQ5oYHstmMyImWJgB3W0IHtyFkmS7T9svOhBA
         K6GZJCasDQT2mqGkADH7lNehBeZh47pFdnBNrluDGBWPg0FWGZkUBbIHWSyc4A4bRhni
         ZY0FiNtRRQH03Z67pny7gaMFVvEp9mHJnXmsHSYRWS+7LNtOI9OMvlhyYmTwV6Qt+sQS
         90LQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=obL9Yv7I;
       spf=pass (google.com: domain of 3pwqwyqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pwqWYQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id h12si154325lfv.4.2021.11.18.00.11.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pwqwyqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id g81-20020a1c9d54000000b003330e488323so2009851wme.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:19 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a7b:cc8f:: with SMTP id p15mr8092401wma.158.1637223079061;
 Thu, 18 Nov 2021 00:11:19 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:13 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-10-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 09/23] kcsan: Document modeling of weak memory
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
 header.i=@google.com header.s=20210112 header.b=obL9Yv7I;       spf=pass
 (google.com: domain of 3pwqwyqukcsgipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3pwqWYQUKCSgIPZIVKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--elver.bounces.google.com;
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

Document how KCSAN models a subset of weak memory and the subset of
missing memory barriers it can detect as a result.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Note the reason that address or control dependencies do not require
  special handling.
---
 Documentation/dev-tools/kcsan.rst | 76 +++++++++++++++++++++++++------
 1 file changed, 63 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 7db43c7c09b8..3ae866dcc924 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -204,17 +204,17 @@ Ultimately this allows to determine the possible executions of concurrent code,
 and if that code is free from data races.
 
 KCSAN is aware of *marked atomic operations* (``READ_ONCE``, ``WRITE_ONCE``,
-``atomic_*``, etc.), but is oblivious of any ordering guarantees and simply
-assumes that memory barriers are placed correctly. In other words, KCSAN
-assumes that as long as a plain access is not observed to race with another
-conflicting access, memory operations are correctly ordered.
-
-This means that KCSAN will not report *potential* data races due to missing
-memory ordering. Developers should therefore carefully consider the required
-memory ordering requirements that remain unchecked. If, however, missing
-memory ordering (that is observable with a particular compiler and
-architecture) leads to an observable data race (e.g. entering a critical
-section erroneously), KCSAN would report the resulting data race.
+``atomic_*``, etc.), and a subset of ordering guarantees implied by memory
+barriers. With ``CONFIG_KCSAN_WEAK_MEMORY=y``, KCSAN models load or store
+buffering, and can detect missing ``smp_mb()``, ``smp_wmb()``, ``smp_rmb()``,
+``smp_store_release()``, and all ``atomic_*`` operations with equivalent
+implied barriers.
+
+Note, KCSAN will not report all data races due to missing memory ordering,
+specifically where a memory barrier would be required to prohibit subsequent
+memory operation from reordering before the barrier. Developers should
+therefore carefully consider the required memory ordering requirements that
+remain unchecked.
 
 Race Detection Beyond Data Races
 --------------------------------
@@ -268,6 +268,56 @@ marked operations, if all accesses to a variable that is accessed concurrently
 are properly marked, KCSAN will never trigger a watchpoint and therefore never
 report the accesses.
 
+Modeling Weak Memory
+~~~~~~~~~~~~~~~~~~~~
+
+KCSAN's approach to detecting data races due to missing memory barriers is
+based on modeling access reordering (with ``CONFIG_KCSAN_WEAK_MEMORY=y``).
+Each plain memory access for which a watchpoint is set up, is also selected for
+simulated reordering within the scope of its function (at most 1 in-flight
+access).
+
+Once an access has been selected for reordering, it is checked along every
+other access until the end of the function scope. If an appropriate memory
+barrier is encountered, the access will no longer be considered for simulated
+reordering.
+
+When the result of a memory operation should be ordered by a barrier, KCSAN can
+then detect data races where the conflict only occurs as a result of a missing
+barrier. Consider the example::
+
+    int x, flag;
+    void T1(void)
+    {
+        x = 1;                  // data race!
+        WRITE_ONCE(flag, 1);    // correct: smp_store_release(&flag, 1)
+    }
+    void T2(void)
+    {
+        while (!READ_ONCE(flag));   // correct: smp_load_acquire(&flag)
+        ... = x;                    // data race!
+    }
+
+When weak memory modeling is enabled, KCSAN can consider ``x`` in ``T1`` for
+simulated reordering. After the write of ``flag``, ``x`` is again checked for
+concurrent accesses: because ``T2`` is able to proceed after the write of
+``flag``, a data race is detected. With the correct barriers in place, ``x``
+would not be considered for reordering after the proper release of ``flag``,
+and no data race would be detected.
+
+Deliberate trade-offs in complexity but also practical limitations mean only a
+subset of data races due to missing memory barriers can be detected. With
+currently available compiler support, the implementation is limited to modeling
+the effects of "buffering" (delaying accesses), since the runtime cannot
+"prefetch" accesses. Also recall that watchpoints are only set up for plain
+accesses, and the only access type for which KCSAN simulates reordering. This
+means reordering of marked accesses is not modeled.
+
+A consequence of the above is that acquire operations do not require barrier
+instrumentation (no prefetching). Furthermore, marked accesses introducing
+address or control dependencies do not require special handling (the marked
+access cannot be reordered, later dependent accesses cannot be prefetched).
+
 Key Properties
 ~~~~~~~~~~~~~~
 
@@ -290,8 +340,8 @@ Key Properties
 4. **Detects Racy Writes from Devices:** Due to checking data values upon
    setting up watchpoints, racy writes from devices can also be detected.
 
-5. **Memory Ordering:** KCSAN is *not* explicitly aware of the LKMM's ordering
-   rules; this may result in missed data races (false negatives).
+5. **Memory Ordering:** KCSAN is aware of only a subset of LKMM ordering rules;
+   this may result in missed data races (false negatives).
 
 6. **Analysis Accuracy:** For observed executions, due to using a sampling
    strategy, the analysis is *unsound* (false negatives possible), but aims to
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-10-elver%40google.com.
