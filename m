Return-Path: <kasan-dev+bncBCS4VDMYRUNBB75J4SGQMGQE3NDIFKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 09752474D97
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:49 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id q6-20020a056e0220e600b002aacc181abasf6587737ilv.13
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519488; cv=pass;
        d=google.com; s=arc-20160816;
        b=R3eiLqj74OHvbioAASEQfWXXcntZtgNfRc2FK1omDtEeglu9rmpoY3a6mu1fkwsJJG
         xrzZWtmtk0qb4jgyxwMf2sJq2yDc0xSXNvtkMQ9jm3JTnZbn5+wGmCe9HNh/kKp/bE6I
         p0+WE+AuLhX1touu7/wK+m8cf3L2ELCKir4LWWNJoCDF2+nig8PMT7CpH7yJ8f2ag8SC
         bAi7ltXIEe9CvcvtNejQRODuUnbY4Pr8jw+jYX1ESkcOjKOYfNWjlinTcuaYmfqnBond
         mc9vk3o4MtDyei+X7JLe0Tb8XmcQffWT6qj5Pz95ftR36rA9x1zLWkCrP6zd+A68Gtoe
         +f8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=BzuwVeXN6xAhs83NUU7usIqHJHm3qEaN136zPoKCKy4=;
        b=nMjmHG1JI4WLQ9dxN7Q1wPFHo5fEeZtsiJJxTLpSFuZrUJceuZHvZYJDlTtk+4Eq8b
         M79moPEjTxNKjnCIHaI5gFSV1A+3+gRqy/APmU/senFCkqHORBxloT6kNj43wsmhUdnN
         GFYUEvsq3VKJSE7vUjYCt9OEod5xN8TZB9JplhbxOJkC4SSJf/ng3z5rpCtQRxCFHrkQ
         idb3X+WRWK6FxjBVkuV3XrViiZKbMP34nuVrAe8wmnGcaBrTQmnnzKa1cJUm7obgUiDl
         OCCcfzqC2fZXp5Diun+Zse+VlDdIWQ6Y6n5tqxVV1yfpSxp4lZZC/hoVNlZGE+ggE+ar
         NJLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fsgP1WHm;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BzuwVeXN6xAhs83NUU7usIqHJHm3qEaN136zPoKCKy4=;
        b=QrrbCP2b77j2G2YRNj2KYeeyMwrzbNGkMLnysGJChBF4H7TSPH8X9AunLTs/oCcKl/
         DH31RkbIOblsCapaTFw/rWI4kQX2/Y9fsxkFZXR05BaxbnNUANx6s14MwZSQw+FiZ8wX
         phnEKNOqa5TOH0uBKYBCLIlu9MohDvu22HnmsXcAIhin+xgA1faHdG0aRLWbmgzhNnq4
         JgJB7W5NkjvF9mdXaKznL3S4KXOvhpu3xDH/PeEw8xT7vwskqLFqhsqhQz/XsTM5GAtX
         DAOquF1BOHZivXnVllrNm9Lu2JBXTcdAAkDymmUx0SIc2U3IyWMCEwQ7Tug7d/8LzzSt
         uSPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BzuwVeXN6xAhs83NUU7usIqHJHm3qEaN136zPoKCKy4=;
        b=GMSoOD65Yru9IyV3aFBl41wd31cYs+TN/oJeO946FJMNvW8uT527TvJvL8KqhbK2/M
         lPsJPMpGijXvJqV9e75Y5L/ajZRpqYnIWrAN5nK069BmJDqE6GEaUk5ALjW0LX7gWxLO
         AOJDCihZQtTOR5w/zvhlANYoLP878Bp4OLNSkwVR8T6QIEZbDPh44fL8F50AYZSXCFJL
         XMe8WiD1gvq+55Jal6Rhp0YvipoXLGCC2ygKlB5kQLr4MzwoZd79hgOMMhqSxU1cinvx
         q0gJKIdHoz08j3YKSfigfBMR3GrJRFElE+3Rm66Xpd6/2lQE4Erta5PaV2ZUHI47Dzg/
         2/aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531uIkqu8KoysWdEt3D66PJYLkQjZCgiPtH/RlmeE8A3YyRpTQ8L
	NZmOWhPN1RWt7RDgCbcRgC0=
X-Google-Smtp-Source: ABdhPJwNdT4TOztUwv4QZ6xvughFI4be5l+NMwbeh3Z9c5oUcbX8whrIyIRF0oePSgnbu91ra5lrEg==
X-Received: by 2002:a05:6e02:1a47:: with SMTP id u7mr5197466ilv.258.1639519488028;
        Tue, 14 Dec 2021 14:04:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:cf81:: with SMTP id w1ls39494jar.9.gmail; Tue, 14 Dec
 2021 14:04:47 -0800 (PST)
X-Received: by 2002:a02:7b25:: with SMTP id q37mr4356697jac.666.1639519487689;
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519487; cv=none;
        d=google.com; s=arc-20160816;
        b=DbtSOhza0+8GEW9V55y2iaTuUUGBWUAY0aSlejgwnG0wmfHljlpe9QOBTCT1vuM2m+
         lGVJasDTrsCnU7LKnVeGW9rGp70gZh+RiYK9PmEdfdo3VzgCJItTq4N3rf9vbFcmA04l
         Oe/Sriou+Hb+2wGL/VJ8H9ZHI0xjadl54Ho7C2pElGSLa9Zwhr/NbFCcMRIhNZh/3kdX
         HZW+l5maW7Pw7AS529ipkA/0y5MI6bXSd22TSdIfKM60KdC+1lU1k5Xsm397BSqqOInO
         HWhFgLFUIgPx4DJ4xDDDmBDyCBGoMcXb94WTppUEW0J158XteikDw4tYecNzOMloPKma
         jY3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VA01UUT7ogvMt5xvNXMtorIGXwz8x4yXdwBkAh4le0U=;
        b=TM8NfRmeOA/p/ulkAbrGgrz+hySekYxWus8TUma1yTpyUxzUfQF6Ti/02Bs4YPFEb2
         frOnbKzcqRUBSnP/4cVephiV/bPUBRSzIKtvnDps17K/EHYEHIw67PIU0fP3o37w4dH6
         vnFe9oeOOatszBOUzaiXkgOKylxypvSpLfSiGkgU7YElrcnZPuk8gu/S6DSTwLC4e/Xk
         h5fmk5pmHhU4T3RPhv43uVOnfypLGknhMLmofuHC0zgnN+DnB1x/Jgd5wnR3BMwQO0w8
         wRV5bwy7QMxRnddjsXt3xN6FwaKYIQiyOQGgexYDOdXkcqJMjlldkh5aU32EOsSpNDGR
         eknQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fsgP1WHm;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2faa6b53fbfsi14667173.1.2021.12.14.14.04.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:47 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id E5BC2CE1B07;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E2602C34618;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6AEA55C1506; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 09/29] kcsan: Document modeling of weak memory
Date: Tue, 14 Dec 2021 14:04:19 -0800
Message-Id: <20211214220439.2236564-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fsgP1WHm;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

Document how KCSAN models a subset of weak memory and the subset of
missing memory barriers it can detect as a result.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 Documentation/dev-tools/kcsan.rst | 76 +++++++++++++++++++++++++------
 1 file changed, 63 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 7db43c7c09b8c..3ae866dcc9240 100644
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
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-9-paulmck%40kernel.org.
