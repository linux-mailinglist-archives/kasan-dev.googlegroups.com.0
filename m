Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPFL6TZAKGQEPRMDZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id ABB2B175CC8
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 15:18:36 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id x13sf1192180eds.19
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 06:18:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583158716; cv=pass;
        d=google.com; s=arc-20160816;
        b=TTh8iGW1DjDbcoAC7DblBiwt6StwTjYzZs0qL7UIbmRAhpgBMKXPLHS0ubpupLo6mZ
         SHgdXUpY1IZ5UEgvH2lpPF+W1VWRYPCJojFZP4ZJSQrBFtTvZxsQ1Gu+j25k2UbayH7D
         ar9melt3QHJcxJlDQr+dazuNIrgOYOqsmr/w3WQGgI1qRW+c85zMAV1uOEaSucqtl/UX
         mhayun3Un/UrmTrz2/e8RkU/+M5NBPmiDtJuaF1QRTgjTtK/JcBkWDIsv38vdmMgBDok
         p5UUohQgbDvDl9Qpxcwg6eopkzuIjBD9yJqrBmTiDlv/py8O5spKTTb9CwQ5/3km9ji7
         0YWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=2TxjekO4oXSrIJnf9/jCmWPRbYDz8d69fLAwue3013g=;
        b=LhArWwPf6jHF87AnVIs2HssHAUbqDu0esCYXwNtmZz0H60LN0/IEynUm1/kIhk1B6H
         OrqIIIemTMztIXszCNbQ+DEhKgNk4CnR0qsi61iaUqbWu+GH8N/TY2lw0LeKtMfaAgdr
         MYaQZCBvpqWEv9xS2imWY7I9VndBqDRGIb7E4SuPz0A7XtzZLpOAIe+nvPt0HHgioUT5
         4OxY31WgptohnAN6pLA/VNH3RK6hxbC09uly40FCdImMYVqoU2COJLWnAKsuVlnsfsCN
         3nSD4HFU3WbEkRgFkKf5M8zHyQUXa3My5BueSErj8F5D72sk3OSb2NljJoRwriuAHnlE
         /Lqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WvHVySHd;
       spf=pass (google.com: domain of 3uxvdxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uxVdXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2TxjekO4oXSrIJnf9/jCmWPRbYDz8d69fLAwue3013g=;
        b=KTVxPZy0jnhZcJ288ZBb2ZgYZRlaCxz+OJbx3vCBOeH9K/dj1li5bzwtWAMha3Zgc3
         CC7o0SDnGmh+54Q5qieWOxMrL5DGyyQbHD8sTlL7izLwvO8iuQRTpJF718EeDDjhqkMg
         gDGnupJGPP+KHMdO6FGAmgVuf10UgQ+G1BbM2SRYHeVROS617Wtc+Z9PcHv5d8BTac6M
         FhhD8+Di+sdGpHO+O307KtxzP93cD6RpoqKS9XoFigxQCEW0WWECxA3FET7c/uGXGtFR
         dBgBZ8e5nVCtdkRBObOPZyjD4KKAmZviXOkGNGq29zhbMXe28DAMuktRVDShFUiShXcA
         rpbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2TxjekO4oXSrIJnf9/jCmWPRbYDz8d69fLAwue3013g=;
        b=tmjOGuzboAQsvpd6aG3DNLgbGuNZ1GHw/WBROWR30hPWZpCqCmYs+8yS1VzrVacA9B
         GxqrBAxQH/3xL6Z9Hn6tLPKylbcmzrrSE/YyYT/SI4WTge1+B+vlmYyoGJhLedu1g0C4
         klHxQXyWbbFBPEJ73rJI5XmAGMygCBDae1o7YEor29aFGMjBnMkA1gZSyZQIRtuJzQ78
         TBvhO/8irgbAlMDi1Ob53Q2dGmu+7uP0E68ywZGWcntolHQj7qYcKcw35ZcVQODpV0NS
         rQLvjnLzPxFFt+8xJBRxzNu3S0JvrCY+GPdLPG7JC3M5ACfYObXNj7JYFDKC47CeZw60
         YT2g==
X-Gm-Message-State: APjAAAVIxEidkS3UETGtPyWL48Y/CiGcLM8tdRjFay/1D8bVW2cp2rk3
	gBZuUzX28lNCakM/QgYCM2g=
X-Google-Smtp-Source: APXvYqx9GUyh3uyd+DOceRjOnx9KzIarEK6tPUIKDukFZcNAQRFS2ELKkWukKGlwza+Le1+un2FYcw==
X-Received: by 2002:a50:f10a:: with SMTP id w10mr13340075edl.326.1583158716360;
        Mon, 02 Mar 2020 06:18:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:4d91:: with SMTP id s17ls2823022eju.7.gmail; Mon, 02
 Mar 2020 06:18:35 -0800 (PST)
X-Received: by 2002:a17:906:4e18:: with SMTP id z24mr15447687eju.214.1583158715690;
        Mon, 02 Mar 2020 06:18:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583158715; cv=none;
        d=google.com; s=arc-20160816;
        b=JiGnr17Qw8KCkIuNeU7j6VIG+ER3abIoMk2KNWFnDw6hdwYop4ZibDonZB1rF0bHAV
         pVqVZtwyJyYJVrJZmHeCRRRMU4vaNeBeF5pA49O2iDeyhwg9avPkV2uzMxnUmOuxJVzR
         0NrZJPc4+SgJNo+qr2sb7zk8xHstu7WkZ2KjjD5VdOwvTt5QYulsTvUhDuNfMDmuV5Us
         opzTc8sjJrQ8wh6POnl02tx5bXFfUgkFfAI/DJrB52hejsn7725S+2EJGQeVrdzs/FoC
         GhgzfAheF704LCMQQHRGH41GyS2YVl5w0uvBXSvJ/B0LKfpn61UUcfNSoC8WIzW1Phw4
         pqlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=fOeP7AroqcsyRTw6L8AA/q48quQG5ja31dye1VtPbXg=;
        b=tpgyOmJ8QZLLIDJ8VO58iv3SqI5Cx1mjqwCq2FzwuTb0IAcPkYCoXCkVZaEudiS+vI
         doAysEZr3aIYVkVpTrcXq92LUxasard7S4GZcnNf1l1ZnJEyV3rCxgncy0/5J1Hd6h8Y
         2jkNueYv9LugH2sArIM5YhvnwH4g2ZvkLEdpsJomB4mfjqOvIdFm+ycr6qV4jzSdjdTF
         m+mYx7/nouf0s19sZoNyeY4nCAbdQnDHzguiysy1r3/vxFy/kQMwButX/xXdgJv1v3v7
         lcVMp/lQCeSwUlyO7Fwxs8Z8QaXVVIDptpj8oJAdRb1qgqJ+ZF0BAfGBXoS+yH2M2RWb
         vr0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WvHVySHd;
       spf=pass (google.com: domain of 3uxvdxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uxVdXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id n1si910840edw.4.2020.03.02.06.18.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Mar 2020 06:18:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uxvdxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s13so5828154wru.7
        for <kasan-dev@googlegroups.com>; Mon, 02 Mar 2020 06:18:35 -0800 (PST)
X-Received: by 2002:adf:f70f:: with SMTP id r15mr22945837wrp.269.1583158715118;
 Mon, 02 Mar 2020 06:18:35 -0800 (PST)
Date: Mon,  2 Mar 2020 15:18:19 +0100
Message-Id: <20200302141819.40270-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.265.gbab2e86ba0-goog
Subject: [PATCH v2] tools/memory-model/Documentation: Fix "conflict" definition
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
 header.i=@google.com header.s=20161025 header.b=WvHVySHd;       spf=pass
 (google.com: domain of 3uxvdxgukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3uxVdXgUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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
---
v2:
* Apply Alan's suggested version.
  - Move "from different CPUs (or threads)" from "conflict" to "data
    race" definition. Update "race candidate" accordingly.
* Add citations to commit message.

v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
---
 .../Documentation/explanation.txt             | 77 +++++++++----------
 1 file changed, 38 insertions(+), 39 deletions(-)

diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
index e91a2eb19592a..7a59cadc2f4ca 100644
--- a/tools/memory-model/Documentation/explanation.txt
+++ b/tools/memory-model/Documentation/explanation.txt
@@ -1987,28 +1987,28 @@ outcome undefined.
 
 In technical terms, the compiler is allowed to assume that when the
 program executes, there will not be any data races.  A "data race"
-occurs when two conflicting memory accesses execute concurrently;
-two memory accesses "conflict" if:
+occurs when two conflicting memory accesses from different CPUs (or
+different threads on the same CPU) execute concurrently, and at least
+one of them is plain.  Two memory accesses "conflict" if:
 
 	they access the same location,
 
-	they occur on different CPUs (or in different threads on the
-	same CPU),
-
-	at least one of them is a plain access,
-
 	and at least one of them is a store.
 
-The LKMM tries to determine whether a program contains two conflicting
-accesses which may execute concurrently; if it does then the LKMM says
-there is a potential data race and makes no predictions about the
-program's outcome.
-
-Determining whether two accesses conflict is easy; you can see that
-all the concepts involved in the definition above are already part of
-the memory model.  The hard part is telling whether they may execute
-concurrently.  The LKMM takes a conservative attitude, assuming that
-accesses may be concurrent unless it can prove they cannot.
+We'll say that two accesses from different threads are "race
+candidates" if they conflict and at least one of them is plain.
+Whether or not two candidates actually do race in a given execution
+then depends on whether they are concurrent.  The LKMM tries to
+determine whether a program contains race candidates which may execute
+concurrently; if it does then the LKMM says there is a potential data
+race and makes no predictions about the program's outcome.
+
+Determining whether two accesses are race candidates is easy; you can
+see that all the concepts involved in the definition above are already
+part of the memory model.  The hard part is telling whether they may
+execute concurrently.  The LKMM takes a conservative attitude,
+assuming that accesses may be concurrent unless it can prove they
+are not.
 
 If two memory accesses aren't concurrent then one must execute before
 the other.  Therefore the LKMM decides two accesses aren't concurrent
@@ -2171,8 +2171,8 @@ again, now using plain accesses for buf:
 	}
 
 This program does not contain a data race.  Although the U and V
-accesses conflict, the LKMM can prove they are not concurrent as
-follows:
+accesses are race candidates, the LKMM can prove they are not
+concurrent as follows:
 
 	The smp_wmb() fence in P0 is both a compiler barrier and a
 	cumul-fence.  It guarantees that no matter what hash of
@@ -2326,12 +2326,11 @@ could now perform the load of x before the load of ptr (there might be
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
 
@@ -2367,7 +2366,7 @@ concurrent and there is no race, even though P1's plain store to y
 isn't w-post-bounded by any marked accesses.
 
 Putting all this material together yields the following picture.  For
-two conflicting stores W and W', where W ->co W', the LKMM says the
+race-candidate stores W and W', where W ->co W', the LKMM says the
 stores don't race if W can be linked to W' by a
 
 	w-post-bounded ; vis ; w-pre-bounded
@@ -2380,8 +2379,8 @@ sequence, and if W' is plain then they also have to be linked by a
 
 	w-post-bounded ; vis ; r-pre-bounded
 
-sequence.  For a conflicting load R and store W, the LKMM says the two
-accesses don't race if R can be linked to W by an
+sequence.  For race-candidate load R and store W, the LKMM says the
+two accesses don't race if R can be linked to W by an
 
 	r-post-bounded ; xb* ; w-pre-bounded
 
@@ -2413,20 +2412,20 @@ is, the rules governing the memory subsystem's choice of a store to
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200302141819.40270-1-elver%40google.com.
