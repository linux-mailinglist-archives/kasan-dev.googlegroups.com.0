Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7A6CFAMGQEQUH47DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D22F422425
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Oct 2021 13:00:09 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id a12-20020a17090aa50cb0290178fef5c227sf1239668pjq.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Oct 2021 04:00:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633431607; cv=pass;
        d=google.com; s=arc-20160816;
        b=nYgtwZdx9oxbgv7PkehpI2hMZUt+S3GYPWw7SHSLnfAd/cJ1wdMXOjZ/SF+OZgFLV/
         n0V4hGvpfv1az4nCl/YGc5uBH28+crpBZueg/ZbCDKXb3Ae0dJAfhr142lTt9DHKUrhW
         1im9rqdzFAPIc0doQn1dowTavUDaUkx17cVjUOBx2nLHQd5z8vMtkDtreREd0+3H9DX/
         dXGEVnzwWCBq3ZVzGpX38e4PWxMmY1Xb0M3aW3ftf773qCw5mCasIzpdqq3nWPWj5Ziq
         uolI/nFlFtbZTQTgFI5X/QBNAiikk4IT4T8jwP04I+NP4kV/K3ONtAGrW0AN0LcKytyz
         OYhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=GS1akSI0MY2/Qf6cl3WlWd/AGkUAgTXctLS7YPM2QUY=;
        b=G/1sf92KcfO5tiVKvQAd7KQUw2he9Y5+bZOac4gIIBvS5jp7Lj00qAur8A9C2W9SqO
         vLVw4OSt7u+kH5PTfhYkMMigZdq3Hp6UkFQEjKZlq7Xot8ST04BYEm7u0SyrPA2KGsfn
         wkzimwwF/BjTCi1xX50LmlAIuAqN/r2rFb5klD9rGsu65t9wMZ7ImQLhJriclDBEzSB6
         1yJ+/eh1doRGQh7wov147PnLdWViisLi2Zqi9GR99z57zeUNKK9msl627Je5l1tq9WaF
         nJBFZOcSXjMzt+qYmVUAkkQWlb79M81rGpNNm5QQ4wa62vsYCTJo7NgcRXB75GMZE4Zo
         OSdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OOmVz5m9;
       spf=pass (google.com: domain of 3ndbcyqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3NDBcYQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GS1akSI0MY2/Qf6cl3WlWd/AGkUAgTXctLS7YPM2QUY=;
        b=lYO7UKuf2FMU7Bg7V9NL5nzr35mlEkfJbJqHw78XKooSB5tnAfsCV9ORp6dwT4+lHL
         pSXOQJgiNiRSTLG0VyxdoclNDkuc+AnSiqeEt7aCVC71U9W7wDwzyM4afIf7/pfEkxgk
         Ac01ps6CsnkS6ZNNzTydVR7xlQBkx1QPzlnySnokr0dgM1IDJhy33jk+JAqPhsGD8UQ5
         xyTnbzmmvOR1Bhi41eXIRpMeOCi+6qgQ2J8gloRADnZysv0rw1bCB2GD77uBF5QYBBfk
         gRBiLqAjlrt5y/e/R+t5USzk1Su6rLLRwQ8mAwWIfdvU5rkdQtJuQQN7ehMmyE1yQjkF
         9OQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GS1akSI0MY2/Qf6cl3WlWd/AGkUAgTXctLS7YPM2QUY=;
        b=fgX86ARFf7/UFfOwc1ldCtmb4xO2eqC5Kk+PphZubFZCxYRNNCaynIth9lQUowFkfN
         azhRHlnLq38Cb9hWNAmrKhsu6Ioz39UDwKJOiSzPninj5j1koGroM+V3kLWnIrid59ir
         hs7n0KTbDfl7K3FmEwkqY6ZnQRX0VcHBtn3+n/HFP60g0QxI2AfN8Obf+wzHigHC6CkB
         VJtPT9QyU0Y4ki/IagdbxCYklCrbh/uh9u7e608CRfR3D9/4cH2qGYy6Nf6kj/V4gHm2
         Rs8u4iL0weQdQZFeUwsi5xLouOBgmffaE+ALz7ZDCvUTCpDUZM1tz2tkD8Q+sK1bSujs
         DbZA==
X-Gm-Message-State: AOAM530A7IN8AjbiI8pjprDNBDUTjI2KAdEWOB3gMXq9zMYOwld++J5W
	cSJ+g7b7j20nSC+IxbzhYdE=
X-Google-Smtp-Source: ABdhPJz+N4DWHI6dksS8j8IEmDO61BO9LnrDMfeBwQTZbWxpHvud3XCW8eF+eJ0yHQme9lWSfCkHoA==
X-Received: by 2002:a17:902:bb94:b0:13c:9113:5652 with SMTP id m20-20020a170902bb9400b0013c91135652mr4733283pls.70.1633431607551;
        Tue, 05 Oct 2021 04:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d206:: with SMTP id o6ls1019620pju.2.canary-gmail;
 Tue, 05 Oct 2021 04:00:05 -0700 (PDT)
X-Received: by 2002:a17:903:31ca:b0:13e:daf1:6a3a with SMTP id v10-20020a17090331ca00b0013edaf16a3amr4686640ple.76.1633431604915;
        Tue, 05 Oct 2021 04:00:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633431604; cv=none;
        d=google.com; s=arc-20160816;
        b=bZE/pOvHiQ9MBUylvzWpAD8Ep05/y2rMToEhISq09il0DumBG47lSkH6m/SazuA1Dw
         e/7D0d/2pK4U4kMDUYpF6UYJNSTmNecLkVtosseQwoy0P3WieT10jYZIlKTYLgnMAAW6
         Fcs/uamTATSBXRV4i5DCM1LNTth7LIcba2u80fgv/wlxeXe6vOxrvt7UliW4uQ7Orn4s
         spt5JAzVULgaKKjqInz/mQ4Pkougnn3MTGWhJhpvvffnqr/Hq5gIWAUWlf8F3cGl5lOa
         oyKblaFqXnOVJ0VZcdQ4pkhPCUP7+XWUoEk9Sx56rLj+DqcjJ2iTJ2CJvI6cj1BG+wcq
         QqtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=VR1v+uOEj5JHWgZG/AjKjsmQRdRMH76n4CGK16N25tc=;
        b=p/+8C4pSDVzKuCf98sOrRJLKQLfyvUrDc95jf2r6WI8oE0YedZjCyymBiDFEBCLZoc
         hhk1KsZwkN0EOcH+IBqne6CvgqUT1ECzmVkbeO2O8NiiYGf3gIZytyjauReK18qGoC44
         s9/vCub4nqTIjTNHFNQ1lXZOoxbWLT+jKCEfATqsPSSnSoFzwjoQYnuF5kp/DER4Tx5t
         oXRZvAOSGlT8Hcshc/5XQpiGPcLfZQ0Y7LtPbxeOoonHqM37PzLDzYPpZ4Lbc47x0f/8
         hM3OOjuoSG3P6Y0lns4y7fzWuLsoglzUlSZeH1rYmWk7CkHkjg/RdtvjXTdLIIbczW/Q
         hMsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=OOmVz5m9;
       spf=pass (google.com: domain of 3ndbcyqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3NDBcYQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id u5si158454pji.0.2021.10.05.04.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Oct 2021 04:00:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ndbcyqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id v14-20020a05620a0f0e00b0043355ed67d1so26539137qkl.7
        for <kasan-dev@googlegroups.com>; Tue, 05 Oct 2021 04:00:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e44f:5054:55f8:fcb8])
 (user=elver job=sendgmr) by 2002:a05:6214:1022:: with SMTP id
 k2mr27293030qvr.53.1633431604158; Tue, 05 Oct 2021 04:00:04 -0700 (PDT)
Date: Tue,  5 Oct 2021 12:58:51 +0200
In-Reply-To: <20211005105905.1994700-1-elver@google.com>
Message-Id: <20211005105905.1994700-10-elver@google.com>
Mime-Version: 1.0
References: <20211005105905.1994700-1-elver@google.com>
X-Mailer: git-send-email 2.33.0.800.g4c38ced690-goog
Subject: [PATCH -rcu/kcsan 09/23] kcsan: Document modeling of weak memory
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E . McKenney" <paulmck@kernel.org>
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
 header.i=@google.com header.s=20210112 header.b=OOmVz5m9;       spf=pass
 (google.com: domain of 3ndbcyqukcrc18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3NDBcYQUKCRc18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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
 Documentation/dev-tools/kcsan.rst | 72 +++++++++++++++++++++++++------
 1 file changed, 59 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 7db43c7c09b8..4fc3773fead9 100644
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
@@ -268,6 +268,52 @@ marked operations, if all accesses to a variable that is accessed concurrently
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
+subset of data races due to missing memory barriers can be detected. Recall
+that watchpoints are only set up for plain accesses, and the only access type
+for which KCSAN simulates reordering. This means reordering of marked accesses
+is not modeled. Furthermore, with the currently available compiler support, the
+implementation is limited to modeling the effects of "buffering" (delaying
+accesses), since the runtime cannot "prefetch" accesses. One implication of
+this is that acquire operations do not require barrier instrumentation.
+
 Key Properties
 ~~~~~~~~~~~~~~
 
@@ -290,8 +336,8 @@ Key Properties
 4. **Detects Racy Writes from Devices:** Due to checking data values upon
    setting up watchpoints, racy writes from devices can also be detected.
 
-5. **Memory Ordering:** KCSAN is *not* explicitly aware of the LKMM's ordering
-   rules; this may result in missed data races (false negatives).
+5. **Memory Ordering:** KCSAN is aware of only a subset of LKMM ordering rules;
+   this may result in missed data races (false negatives).
 
 6. **Analysis Accuracy:** For observed executions, due to using a sampling
    strategy, the analysis is *unsound* (false negatives possible), but aims to
-- 
2.33.0.800.g4c38ced690-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211005105905.1994700-10-elver%40google.com.
