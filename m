Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNEC6XZAKGQEUHVKR2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F7481760F6
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 18:24:06 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id y81sf120046ywd.20
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 09:24:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583169845; cv=pass;
        d=google.com; s=arc-20160816;
        b=LOnC1JuunBYEt4bG3N82Xv6Ots40tNlE92Dn7GzGnBMgY4zlcekivF+wqoeTVYkxOc
         h4B22oE9uiXYb5zRHBdw1aUrlVfQKo4rac0gm4/rLHkZjM7YfBcAqTO9ZoZ/pGVNYyEm
         hCpVmx/CFTZrVXvX7vLkAwQZWhYpeAJGeAL12KxrwD/+/AyNKWpfhkHFkej+MnV5gfkI
         Ebe0NLjRfNE96udoNOW36LB266hjY1KdO9Lfa2T0WvPgQkh1Af5inoTyXa8Mz8ld2k0k
         9RPTAzjYVzu1pYOUKszFqROUnLLbn4tEZkPJYE4Ta0LoJ+SyzrlsKvLHiUNHZmo7VmKI
         GMgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=pVVLSsXFREyzHiQl8ZM7M1h51FS3oqkXfeT3QO6lU0o=;
        b=HU9aZipc1rI2L97DZdHtJ+r6Z2OdB0Dv6iQ/uhORWTu1+yrXbbZloc0bt44PFYuJfv
         Nng6DwbhhmzKEh8jP6j3qtH9DThsEUdkBrhZRqn79zynT/Pp+4QrJbpXbiqJz4F5orJO
         DfCYZeKlr1Ot+akYdzt44UlZrviYU80qN3yrKIear6AGTyCe155rwVoqoIeoDRsyUeed
         qCLaAJq8hWstpBkwNyLkZFob0uEm7VLdCu5iMCmAHvWJXYbMR/nMhLx857jLGhSY3ngD
         YZG3rlKyFKjOS5Rxc7I0Zt7cl9HiYOLtWX/aZuFTIzOiaNdTdUDVDpKEtfcZ56fnKVaV
         yhkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a8WVWpUZ;
       spf=pass (google.com: domain of 3m0fdxgukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3M0FdXgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=pVVLSsXFREyzHiQl8ZM7M1h51FS3oqkXfeT3QO6lU0o=;
        b=KF+YZeQsCakD8H4Hr7X3NX7P9xuygedTw4cc8Qtv0SktMPKLbvxWmXu3MEM9Ts1xoD
         +zx4MFU7R20Jwy9MP7Rex5aFR5GrQgzYqVz8BCnCA3yqsdDSh0TIhmiuZyv5xbNqoHEq
         e4KA6I7QacXao4zNXdMMRJ/SKLnAdwss8amz5A/eDLJjyuf0TEu690UhsThkMxi5JhCK
         +eJGZx3jCWbf13rlhmxHFHMveG8/OR9w1577uYhWJSahuEgAgP2pTRNeuDHka5yWMyKN
         hOVgB+OslAu8hbTNwERWyPzqzYrPLl1sTjO4bnr7j5n74121vHNG+8zQsHp4OEpzGccD
         asrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pVVLSsXFREyzHiQl8ZM7M1h51FS3oqkXfeT3QO6lU0o=;
        b=d96rl4GAnBpSbzmvx9BXbwqzabUY3otAbtehS4DtWORIt6cr1iGOdSfZe/RxoxCANv
         h0XI9In4wqfKfADiQWxJoWLprzb0NsYwGk957AQcR0RjMzHADr5uEotEzZ1SYzogEtnj
         XNHMjBO9TUjY4sl+0HqvMOFISyYzBCxU+IyP8iFZMUi3mqtsWTPc1XueYpzR9x+gObWI
         ATo9cC1bSkcW/crIB8zOHIys1XC+w1E81as1lnaGTuCzSbq4Nn/+FJqT8xBDw2tpTbtn
         wZGal/8be0djSn80qcD/UAsvV7LUo8g6VxS/Q27AHoRO2peeaw4xOxXOyS7Mk0JNz47H
         ihSQ==
X-Gm-Message-State: ANhLgQ35v1HLLi9lw4taXkdqDdKfW5ic83Gvq04UksIaVN9VwQjs0brj
	ppwUkKAQJcE8FxS1x1t0MeY=
X-Google-Smtp-Source: ADFU+vu8t5hsqA5pyc+X99NSzc2xFzwm/1Kcsz2yK9S79fqEMSobwKa8OseY6misPT6/qhajw+IRLg==
X-Received: by 2002:a81:5e41:: with SMTP id s62mr360252ywb.499.1583169844796;
        Mon, 02 Mar 2020 09:24:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d851:: with SMTP id p78ls97729ybg.3.gmail; Mon, 02 Mar
 2020 09:24:04 -0800 (PST)
X-Received: by 2002:a25:df09:: with SMTP id w9mr31089ybg.515.1583169844285;
        Mon, 02 Mar 2020 09:24:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583169844; cv=none;
        d=google.com; s=arc-20160816;
        b=0cwapnNSQXVpzVjlhjKK55BWyxdMJLCWU/8Szg5gKvAYitr8u1kPvK8byz+aUudr0S
         no+yhZqz3ran31uvyE2dTKIbhE5qi3BTepSY+lX/MLhzrGHlVLHmd6/zSrxSFcg2S5Pj
         3Ciyo8bcOXz0OONVtxe43zYA6vmef1/PvKI1eYipAJVK6X38hgKsfYpbcNfzjj0FkDU6
         oVwkRfUbwm2RGcNAGS92naoJ9YF8YM6LYRZNm6YUTD5Xza1gEng3ycZ70RojvvGO4YyJ
         U/9Lk3bBnFDX/Vij+bGRKDBlU72N9U/zHmByA1z8LeIBjaY+NPBXxbHqNVinRYI9nKOr
         Wt2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=PEbgu/4uO5bEzcphG1/CZ+Lp1xyyKDMrEeocqBAbQzY=;
        b=deU7k4tqXHf1nkOjJ0B/jCXX/2ru4A3/Y+P9pDOwRrhswdAv/5FIzteqs70QpSinJL
         eNWZxGbTQR8hUpTDA8tCVTYZS+qbFxaLqA5KkJ5/gd7hcoekfM14m0xZamvNR5gCwXsJ
         pJpVyvVaillVLPsZS1eOdf8h3BeC1wncnM9brAcc059JUPU/JR3J2ixusAhApztgQ2u7
         +hdsQEyXBz+MIpfvJbGfpDTs2o0kX66cULaPVTfVmZLa6Sl3D4Sgd0hzbcba13ouVK0k
         vLHXSwLGSUlQ2niRpOAAAhEDm8wUvT4YsQ5550vIGPUDF9KTSfRDF49c0vCq1KnlWZun
         tdkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a8WVWpUZ;
       spf=pass (google.com: domain of 3m0fdxgukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3M0FdXgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id u126si176744ywf.1.2020.03.02.09.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 09:24:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3m0fdxgukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id y3so301353qti.15
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 09:24:04 -0800 (PST)
X-Received: by 2002:a37:4fc3:: with SMTP id d186mr364070qkb.100.1583169843777;
 Mon, 02 Mar 2020 09:24:03 -0800 (PST)
Date: Mon,  2 Mar 2020 18:21:01 +0100
Message-Id: <20200302172101.157917-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v3] tools/memory-model/Documentation: Fix "conflict" definition
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	stern@rowland.harvard.edu, parri.andrea@gmail.com, will@kernel.org, 
	peterz@infradead.org, boqun.feng@gmail.com, npiggin@gmail.com, 
	dhowells@redhat.com, j.alglave@ucl.ac.uk, luc.maranget@inria.fr, 
	paulmck@kernel.org, akiyks@gmail.com, dlustig@nvidia.com, 
	joel@joelfernandes.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a8WVWpUZ;       spf=pass
 (google.com: domain of 3m0fdxgukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3M0FdXgUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

The definition of "conflict" should not include the type of access nor
whether the accesses are concurrent or not, which this patch addresses.
The definition of "data race" remains unchanged.

The definition of "conflict" as we know it and is cited by various
papers on memory consistency models appeared in [1]: "Two accesses to
the same variable conflict if at least one is a write; two operations
conflict if they execute conflicting accesses."

The LKMM as well as the C11 memory model are adaptations of
data-race-free, which are based on the work in [2]. Necessarily, we need
both conflicting data operations (plain) and synchronization operations
(marked). For example, C11's definition is based on [3], which defines a
"data race" as: "Two memory operations conflict if they access the same
memory location, and at least one of them is a store, atomic store, or
atomic read-modify-write operation. In a sequentially consistent
execution, two memory operations from different threads form a type 1
data race if they conflict, at least one of them is a data operation,
and they are adjacent in <T (i.e., they may be executed concurrently)."

[1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
    Programs that Share Memory", 1988.
	URL: http://snir.cs.illinois.edu/listed/J21.pdf

[2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
    Multiprocessors", 1993.
	URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf

[3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
    Model", 2008.
	URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf

Signed-off-by: Marco Elver <elver@google.com>
Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
Signed-off-by: Alan Stern <stern@rowland.harvard.edu>
---
v3:
* Apply Alan's suggestion.
* s/two race candidates/race candidates/

v2: http://lkml.kernel.org/r/20200302141819.40270-1-elver@google.com
* Apply Alan's suggested version.
  - Move "from different CPUs (or threads)" from "conflict" to "data
    race" definition. Update "race candidate" accordingly.
* Add citations to commit message.

v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
---
 .../Documentation/explanation.txt             | 83 ++++++++++---------
 1 file changed, 45 insertions(+), 38 deletions(-)

diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
index e91a2eb19592a..993f800659c6a 100644
--- a/tools/memory-model/Documentation/explanation.txt
+++ b/tools/memory-model/Documentation/explanation.txt
@@ -1987,28 +1987,36 @@ outcome undefined.
 
 In technical terms, the compiler is allowed to assume that when the
 program executes, there will not be any data races.  A "data race"
-occurs when two conflicting memory accesses execute concurrently;
-two memory accesses "conflict" if:
+occurs when there are two memory accesses such that:
 
-	they access the same location,
+1.	they access the same location,
 
-	they occur on different CPUs (or in different threads on the
-	same CPU),
+2.	at least one of them is a store,
 
-	at least one of them is a plain access,
+3.	at least one of them is plain,
 
-	and at least one of them is a store.
+4.	they occur on different CPUs (or in different threads on the
+	same CPU), and
 
-The LKMM tries to determine whether a program contains two conflicting
-accesses which may execute concurrently; if it does then the LKMM says
-there is a potential data race and makes no predictions about the
-program's outcome.
+5.	they execute concurrently.
 
-Determining whether two accesses conflict is easy; you can see that
-all the concepts involved in the definition above are already part of
-the memory model.  The hard part is telling whether they may execute
-concurrently.  The LKMM takes a conservative attitude, assuming that
-accesses may be concurrent unless it can prove they cannot.
+In the literature, two accesses are said to "conflict" if they satisfy
+1 and 2 above.  We'll go a little farther and say that two accesses
+are "race candidates" if they satisfy 1 - 4.  Thus, whether or not two
+race candidates actually do race in a given execution depends on
+whether they are concurrent.
+
+The LKMM tries to determine whether a program contains race candidates
+which may execute concurrently; if it does then the LKMM says there is
+a potential data race and makes no predictions about the program's
+outcome.
+
+Determining whether two accesses are race candidates is easy; you can
+see that all the concepts involved in the definition above are already
+part of the memory model.  The hard part is telling whether they may
+execute concurrently.  The LKMM takes a conservative attitude,
+assuming that accesses may be concurrent unless it can prove they
+are not.
 
 If two memory accesses aren't concurrent then one must execute before
 the other.  Therefore the LKMM decides two accesses aren't concurrent
@@ -2171,8 +2179,8 @@ again, now using plain accesses for buf:
 	}
 
 This program does not contain a data race.  Although the U and V
-accesses conflict, the LKMM can prove they are not concurrent as
-follows:
+accesses are race candidates, the LKMM can prove they are not
+concurrent as follows:
 
 	The smp_wmb() fence in P0 is both a compiler barrier and a
 	cumul-fence.  It guarantees that no matter what hash of
@@ -2326,12 +2334,11 @@ could now perform the load of x before the load of ptr (there might be
 a control dependency but no address dependency at the machine level).
 
 Finally, it turns out there is a situation in which a plain write does
-not need to be w-post-bounded: when it is separated from the
-conflicting access by a fence.  At first glance this may seem
-impossible.  After all, to be conflicting the second access has to be
-on a different CPU from the first, and fences don't link events on
-different CPUs.  Well, normal fences don't -- but rcu-fence can!
-Here's an example:
+not need to be w-post-bounded: when it is separated from the other
+race-candidate access by a fence.  At first glance this may seem
+impossible.  After all, to be race candidates the two accesses must
+be on different CPUs, and fences don't link events on different CPUs.
+Well, normal fences don't -- but rcu-fence can!  Here's an example:
 
 	int x, y;
 
@@ -2367,7 +2374,7 @@ concurrent and there is no race, even though P1's plain store to y
 isn't w-post-bounded by any marked accesses.
 
 Putting all this material together yields the following picture.  For
-two conflicting stores W and W', where W ->co W', the LKMM says the
+race-candidate stores W and W', where W ->co W', the LKMM says the
 stores don't race if W can be linked to W' by a
 
 	w-post-bounded ; vis ; w-pre-bounded
@@ -2380,8 +2387,8 @@ sequence, and if W' is plain then they also have to be linked by a
 
 	w-post-bounded ; vis ; r-pre-bounded
 
-sequence.  For a conflicting load R and store W, the LKMM says the two
-accesses don't race if R can be linked to W by an
+sequence.  For race-candidate load R and store W, the LKMM says the
+two accesses don't race if R can be linked to W by an
 
 	r-post-bounded ; xb* ; w-pre-bounded
 
@@ -2413,20 +2420,20 @@ is, the rules governing the memory subsystem's choice of a store to
 satisfy a load request and its determination of where a store will
 fall in the coherence order):
 
-	If R and W conflict and it is possible to link R to W by one
-	of the xb* sequences listed above, then W ->rfe R is not
-	allowed (i.e., a load cannot read from a store that it
+	If R and W are race candidates and it is possible to link R to
+	W by one of the xb* sequences listed above, then W ->rfe R is
+	not allowed (i.e., a load cannot read from a store that it
 	executes before, even if one or both is plain).
 
-	If W and R conflict and it is possible to link W to R by one
-	of the vis sequences listed above, then R ->fre W is not
-	allowed (i.e., if a store is visible to a load then the load
-	must read from that store or one coherence-after it).
+	If W and R are race candidates and it is possible to link W to
+	R by one of the vis sequences listed above, then R ->fre W is
+	not allowed (i.e., if a store is visible to a load then the
+	load must read from that store or one coherence-after it).
 
-	If W and W' conflict and it is possible to link W to W' by one
-	of the vis sequences listed above, then W' ->co W is not
-	allowed (i.e., if one store is visible to a second then the
-	second must come after the first in the coherence order).
+	If W and W' are race candidates and it is possible to link W
+	to W' by one of the vis sequences listed above, then W' ->co W
+	is not allowed (i.e., if one store is visible to a second then
+	the second must come after the first in the coherence order).
 
 This is the extent to which the LKMM deals with plain accesses.
 Perhaps it could say more (for example, plain accesses might
-- 
2.25.0.265.gbab2e86ba0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302172101.157917-1-elver%40google.com.
