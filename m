Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVU5TCGQMGQECNAGXVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F06D4632D8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:27 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id q19-20020a05651c055300b0021a259ae8bbsf7492477ljp.4
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272726; cv=pass;
        d=google.com; s=arc-20160816;
        b=Uf515eLBf6UITRCVdLdxRkKodLV7kYqpF0qi/w7eD27aKvmJd04SkwfuYL9nYE3fUr
         NAkRRpMAZiyGL8xjbPmj8zZN8+pSz7VUhBI2QXS4wYOAwPChy3NiEwXj+hRYIQSTOR/A
         o7uLmFJuIm8AF/x7WRkEBzPtDezF/TUt17wWzNop6PfGprm4p0KALBd0RM8g2Nq0xfzI
         8aH/6GzZEY2UdZcxFAZmCF6/Ltss9nZiii8z9gVw6MwZ0Gpgu/GLd76VpQiAPqCe8Hb3
         xiv6Xw2iLSJpkmsbMZxlvffGWJuZgAfGbkHIoM5KJ9i9iKd1BZkjVVr7gJKH5C7hqYBV
         4ztw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=9MF2kYe9KOHO2XHIN9Bp39jCNJPO9U02Mle8z51DLmY=;
        b=dAxq5ViM2t5j/Iyo0X1ZnrbvhLJsTiiRr5jjayKNylgCdtPLcM40/Kq3KqotVsm9Kw
         zGlG6v30SZ0iKW+cfLf/dh2YG+iQS47c39JYzTpFnb7A9luGYvhN+cdpinzDszbdINlW
         bZPJYfY0k/jCjmfwNF/YeGnt2NeT0IiYBQhgYAA4bWxldjBmyQgJ4h6oStg6QtXd4BrZ
         oJXyn3jYxhHqJuzxS0Q4exUfTJmgX1nk+KS7Wk5MfaapemrGH4eeyiwmkGxJWr0XzPuW
         j1li3gxdNykk9yeyX/bNs3gN/0MM+w0V14fChKM8H5aifyGoFioqEniRG3UO30SRRM8r
         AAcA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P81cETHj;
       spf=pass (google.com: domain of 31q6myqukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31Q6mYQUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MF2kYe9KOHO2XHIN9Bp39jCNJPO9U02Mle8z51DLmY=;
        b=gr7tDH7UAEqz9SEx5veXmjE1+4GxkpKrJQ9wPmJJHXS5+vNi/qZt0gwaytbflk4i5d
         V83ZT6IkCmxt5rS6h/If9my/26T7z8+LxZGYb+LZTgMHXgE/cn/KH8UHWoPGqh15K3jI
         MC1HvjPpX1dKvrnN+H2J8cDEq/g4r3RCIbLi2xl3XGz0PqvT6IOcsbTvBJyhi7tq8Vep
         zz8wxSmNYi1NOyV5kAHs4fg5zSLieLAXwhaaSEKlwkBQCHgRH9/XxknkbhKiD2Z69/GX
         uDFK50N3R50VHLr2825jNLi6Q2hRfUiI5Cqm1Wfw9VsQBl48rTV2n5g7f+YbjzRucxtF
         uadw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9MF2kYe9KOHO2XHIN9Bp39jCNJPO9U02Mle8z51DLmY=;
        b=sqLShckTbdCqsZfWXexKI9+VS8w0DsKkl8eyEji7D2I0ULOBIbYui2fWiL2IwWBJUx
         /n2lu4PzEJpQICkWRmkwhgScmZbWtruNEGkqSMIrCKiCJVI+gw9PipSChAvPoKpmPFTs
         OTQP4Lz4qI/zHDlEHWUDnKEIfgw13se3rGRy1JgvdEyl9VX1GWvi70Iup/oG6PJIRQ2p
         FLUdOus+6PQXP3i05M9TWQmM/dWFWED2SD1YPLmAvZ2iP2NDc7boqVWBapEDCu+Yk6ws
         6kvhkxKBHAbD6dLSQpyAYtd8R9PryLixoAt9k3nP6UVFxkn5Ie+4HmndGufUWUz9S3lY
         sMVg==
X-Gm-Message-State: AOAM532u2972lRI5R9cnLvoms09G3C8CSsH9iI7ndBMLG2wklWy3cJbl
	Fkcwbk3h2638ypC7vhjnXaA=
X-Google-Smtp-Source: ABdhPJx/uriRmTuRk7rnY0M7XJHFiO67qdmwzsZ1+Es9v2G5ReksAtP4aQs21WqTf5/mMPzLEvqMyA==
X-Received: by 2002:a05:651c:308:: with SMTP id a8mr56931784ljp.149.1638272726688;
        Tue, 30 Nov 2021 03:45:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls452928lfu.0.gmail; Tue, 30
 Nov 2021 03:45:25 -0800 (PST)
X-Received: by 2002:a05:6512:487:: with SMTP id v7mr54120179lfq.386.1638272725628;
        Tue, 30 Nov 2021 03:45:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272725; cv=none;
        d=google.com; s=arc-20160816;
        b=mmIuoV9WEfmk2JoTpx7yj56l4Q+Lb61FZ+9z2qvS8KdzKbYMrr9neAkLo9qOd1X1T8
         /hKJVrPt8yOQoDzDJyFRTu9Tc01XYck13RNiUUQk6j0IolWB3/HUik7ybhAxw9U2TM5r
         hAy36XoAYaWlYyBCYPzGH9vxdJZb8qAnA6VzBjlIem3KoqVX4KSWTSGOSMejX3lk6hC8
         f6hvbwgsjehuvZm84nkzKJ4mJd1KYp8XZyYr6uF/lv+Yk0+oDkY+PAcnU/FKGo1wC4xv
         rXkxGJ8dPmgVDOHJKI+x/G5kr6JPGwy9rzDQfQvIuUWsZGVYj3knK31nvKMgBoldy/sY
         nMrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rG1xNdPiM+b/19SfERFIEiLMABj+g1AA81VAk56ezfY=;
        b=IFIjNhVu/GCNp08WcNYOCkwLz+qTjIer5s5AMPKh+a+iEKi3ZvkmjfXQCNODtu4KGF
         5iDCPaBGIsSfUwSrpoX019kyMg2ZeZf/Qa016JAPi1LJgGE5rC6+nWuzDBLWCT/cyRRf
         +d4X9MesH6SezkN8PDRqZL0UlN7F/oepezBOjgGzeIzu3JUiK1uNrjUgZV2G4Y7EU0Aj
         jtks/KPKKq2Hc/rwZmvZ79ESI05Yr+R8Xw73MWzzFi9WyuhZcwttwznOYRWfNB4bqqlw
         8uESrL0bXzGcHaYQYFd4hzo+IAHQWgJMnsRpuB3Xh3KbvQ6j03hRElpOah0OBymD87ED
         ahfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P81cETHj;
       spf=pass (google.com: domain of 31q6myqukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31Q6mYQUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id l13si1214738lfg.1.2021.11.30.03.45.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:25 -0800 (PST)
Received-SPF: pass (google.com: domain of 31q6myqukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 138-20020a1c0090000000b00338bb803204so10300810wma.1
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:25 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:adf:f0c8:: with SMTP id x8mr41133135wro.290.1638272725050;
 Tue, 30 Nov 2021 03:45:25 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:17 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-10-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 09/25] kcsan: Document modeling of weak memory
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
 header.i=@google.com header.s=20210112 header.b=P81cETHj;       spf=pass
 (google.com: domain of 31q6myqukcz4cjtcpemmejc.amki8q8l-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=31Q6mYQUKCZ4CJTCPEMMEJC.AMKI8Q8L-BCTEMMEJCEPMSNQ.AMK@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-10-elver%40google.com.
