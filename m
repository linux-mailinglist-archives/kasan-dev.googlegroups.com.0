Return-Path: <kasan-dev+bncBD6LRVPZ6YGRB6PL4XZAKGQEDWIVEVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D0E41740D4
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 21:20:11 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id r75sf6633525ywg.19
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 12:20:11 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9M3Ih+C7Lbuxhy5iZSjcbUNu3uOGk6ai95/Cl6qK82c=;
        b=KS1DMSKulSrqlTsmtIpYPs4wuyTUxqpe/Ikc0e58GfemxB1HZswZIwV9KlraehQD3U
         n6Z0HbvhOR/wOY2SIVl09d+9D62b0eHbuo/5ITc6vkISCSJqCCHDZ0lcHn3vAlAIg1cN
         kJk7g3eMjEPZankfL/baNOcTYsyhhdXS422gcHLicObwOY3/lhhedUn9MHp8q4IXqgO/
         xTV/uJZ2DsCH/F2Lm/WjMyLwhfeqr0aE8oPT5ncU+Y/kjm6DALb71Xr3f7axKDm/cYL5
         qZP6kCekPI96SIYsJ8ZMfWPgs8Gbiz7Uwi3OV3IX6PvmFYHc+Y8ZGTo6dD/S4B3dBcMn
         z1/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9M3Ih+C7Lbuxhy5iZSjcbUNu3uOGk6ai95/Cl6qK82c=;
        b=dgUKeZ3FSidtr5/cIMX+6OLYmXcTqa1hCmokddKAiYpjMj/usH9pP3JKdNs1zhp4ht
         ax9lFUekyskfbqtZOkFHO+LfhUEBW3UasQ3wTDOp0+aylEqwsDjgEvTeg8+ZgGmZeFIg
         RiV+sYSTEtJnNgO5cC945WsWLnF8c5BLEocqJJ9ixV13oVzOAnN0z4+IRU9qYXqR3LAC
         D0yUnszLPzYrAMMUGlQTWYVv6r/BU7lPEg6MJIr7wUXRoyiyC8Vk1fsZBN+WPt5HZMK3
         rt5EZZ+Cc4OngUIqkAHNEf3wzKqRsR+InqSzV0vtHP5pxeKPhlpFR7ZOI6QM6+kkYXAu
         rC1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWbhwOy95SdRUHeJfiigg/5KZZdiy9j22okMpTOXPZXQ0tTyaIx
	pdqS099a0eBm21JA3XCgz3g=
X-Google-Smtp-Source: APXvYqyB6LhbWMbbUUaJVykTu5RId+Bz0WrjF6XjumUoT3Tx88nDzRxcu/oZDmK7Wjm1YCPkcPnk0w==
X-Received: by 2002:a81:494c:: with SMTP id w73mr6206907ywa.93.1582921209868;
        Fri, 28 Feb 2020 12:20:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ab94:: with SMTP id v20ls318950ybi.0.gmail; Fri, 28 Feb
 2020 12:20:09 -0800 (PST)
X-Received: by 2002:a25:4656:: with SMTP id t83mr5190467yba.184.1582921209470;
        Fri, 28 Feb 2020 12:20:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582921209; cv=none;
        d=google.com; s=arc-20160816;
        b=agtCV5iFKUYowVibMuli3R03ZgUcb1N1XBippA7eX01XDfAieXMDcx7jpkD20iE0Es
         u6t8hovsoHh/9NVcN/B4QZbu50lfmk9XXoBdZgYYoEBYTRYqs2A7QUTeHnmbE8T/WaLo
         yvWdul+T44nCXJOFxEZO8WMhN3/o+VUMiT84DfZ5EuBT57fV9pTKr+ttzFPVRaQQGqtH
         lOwapQf6DQehOJdrzLEy0SD4txWdUcDYZ/QBrf6ijqwiRPbhkgzO6e2XqtrmSALqGpeG
         CXtklm275HKXpwF/cfXLOmLHmyjogj+qSnvsaQcY5Zkv7ZDfsiOcecUVpg76NvrP4jdw
         EVsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:in-reply-to:subject:cc:to:from:date;
        bh=9M3Ih+C7Lbuxhy5iZSjcbUNu3uOGk6ai95/Cl6qK82c=;
        b=b02zhZLZIjWdHHYCmeBsEjynT+pNixJ75qnDdNvw6AJlUtwzHMOJ/8G9tdxJYIjb8V
         7ocZ3rpPsFj0AjBUElvT9FhFafZZpIY1AkV1uGkcSkQR4iFfctgE4qRnf/+WEZngZUGY
         8QIfQndllmtCAe5UsbML66ZRUYzN3ChT9qO6bITx7dY9+yAybwHQW65HJ7pukUiKBppa
         69vPN7Cl9dE2UAozpkEo9krjGVW9Harsh8d3500LwPyUJvOqFDkwt7Y10X7SkLNXqEkT
         oOd4MhKNr44qquMs5zlxU8/TI2+0Lzqspiurs6LH4FziLgLTFkRDf/3wwoiDpYN/5fIY
         40qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
Received: from iolanthe.rowland.org (iolanthe.rowland.org. [192.131.102.54])
        by gmr-mx.google.com with SMTP id u7si415050ywg.5.2020.02.28.12.20.08
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Feb 2020 12:20:08 -0800 (PST)
Received-SPF: pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) client-ip=192.131.102.54;
Received: (qmail 5707 invoked by uid 2102); 28 Feb 2020 15:20:07 -0500
Received: from localhost (sendmail-bs@127.0.0.1)
  by localhost with SMTP; 28 Feb 2020 15:20:07 -0500
Date: Fri, 28 Feb 2020 15:20:07 -0500 (EST)
From: Alan Stern <stern@rowland.harvard.edu>
X-X-Sender: stern@iolanthe.rowland.org
To: Marco Elver <elver@google.com>
cc: "Paul E. McKenney" <paulmck@kernel.org>, 
    Andrey Konovalov <andreyknvl@google.com>, 
    Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
    LKML <linux-kernel@vger.kernel.org>, Andrea Parri <parri.andrea@gmail.com>, 
    Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
    Boqun Feng <boqun.feng@gmail.com>, Nicholas Piggin <npiggin@gmail.com>, 
    David Howells <dhowells@redhat.com>, Jade Alglave <j.alglave@ucl.ac.uk>, 
    Luc Maranget <luc.maranget@inria.fr>, 
    LKMM Maintainers -- Akira Yokosawa <akiyks@gmail.com>, 
    Daniel Lustig <dlustig@nvidia.com>, 
    Joel Fernandes <joel@joelfernandes.org>, 
    linux-arch <linux-arch@vger.kernel.org>
Subject: Re: [PATCH] tools/memory-model/Documentation: Fix "conflict" definition
In-Reply-To: <CANpmjNMOmirPRKbjX9=V+eZD-YsEvfhUU8r6EDefkOJTBLDYNQ@mail.gmail.com>
Message-ID: <Pine.LNX.4.44L0.2002281424410.1599-100000@iolanthe.rowland.org>
MIME-Version: 1.0
Content-Type: TEXT/PLAIN; charset=US-ASCII
X-Original-Sender: stern@rowland.harvard.edu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates
 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
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

On Fri, 28 Feb 2020, Marco Elver wrote:

> On Fri, 28 Feb 2020 at 19:54, Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 28 Feb 2020 at 18:24, Alan Stern <stern@rowland.harvard.edu> wrote:
> > >
> > > On Fri, 28 Feb 2020, Marco Elver wrote:
> > >
> > > > For language-level memory consistency models that are adaptations of
> > > > data-race-free, the definition of "data race" can be summarized as
> > > > "concurrent conflicting accesses, where at least one is non-sync/plain".
> > > >
> > > > The definition of "conflict" should not include the type of access nor
> > > > whether the accesses are concurrent or not, which this patch addresses
> > > > for explanation.txt.
> > >
> > > Why shouldn't it?  Can you provide any references to justify this
> > > assertion?
> >
> > The definition of "conflict" as we know it and is cited by various
> > papers on memory consistency models appeared in [1]: "Two accesses to
> > the same variable conflict if at least one is a write; two operations
> > conflict if they execute conflicting accesses."
> >
> > The LKMM as well as C11 are adaptations of data-race-free, which are
> > based on the work in [2]. Necessarily, we need both conflicting data
> > operations (plain) and synchronization operations (marked). C11's
> > definition is based on [3], which defines a "data race" as:  "Two
> > memory operations conflict if they access the same memory location,
> > and at least one of them is a store, atomic store, or atomic
> > read-modify-write operation. In a sequentially consistent execution,
> > two memory operations from different threads form a type 1 data race
> > if they conflict, at least one of them is a data operation, and they
> > are adjacent in <T (i.e., they may be executed concurrently)."
> >
> > [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
> > Programs that Share Memory", 1988.
> >       URL: http://snir.cs.illinois.edu/listed/J21.pdf
> >
> > [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
> > Multiprocessors", 1993.
> >       URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> >
> > [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
> > Model", 2008.
> >      URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf

Okay, very good.  Please include at least one of these citations in the 
description of the next version of your patch.

> > > Also, note two things: (1) The existing text does not include
> > > concurrency in the definition of "conflict".  (2) Your new text does
> > > include the type of access in the definition (you say that at least one
> > > of the accesses must be a write).
> >
> > Yes, "conflict" is defined in terms of "access to the same memory
> > location and at least one performs a write" (can be any operation that
> > performs a write, including RMWs etc.). It should not include
> > concurrency. We can have conflicting operations that are not
> > concurrent, but these will never be data races.
> >
> > > > The definition of "data race" remains unchanged, but the informal
> > > > definition for "conflict" is restored to what can be found in the
> > > > literature.
> > >
> > > It does not remain unchanged.  You removed the portion that talks about
> > > accesses executing on different CPUs or threads.  Without that
> > > restriction, you raise the nonsensical possibility that a single thread
> > > may by definition have a data race with itself (since modern CPUs use
> > > multiple-instruction dispatch, in which several instructions can
> > > execute at the same time).
> >
> > Andrea raised the point that "occur on different CPUs (or in different
> > threads on the same CPU)" can be interpreted as "in different threads
> > [even if they are serialized via some other synchronization]".
> >
> > Arguably, no sane memory model or abstract machine model permits
> > observable intra-thread concurrency of instructions in the same
> > thread. At the abstract machine level, whether or not there is true
> > parallelism shouldn't be something that the model concerns itself
> > with. Simply talking about "concurrency" is unambiguous, unless the
> > model says intra-thread concurrency is a thing.
> >
> > I can add it back if it helps make this clearer, but we need to mention both.

Then by all means, let's mention both.

> > > > Signed-by: Marco Elver <elver@google.com>
> > > > ---
> > > >  tools/memory-model/Documentation/explanation.txt | 15 ++++++---------
> > > >  1 file changed, 6 insertions(+), 9 deletions(-)
> > > >
> > > > diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> > > > index e91a2eb19592a..11cf89b5b85d9 100644
> > > > --- a/tools/memory-model/Documentation/explanation.txt
> > > > +++ b/tools/memory-model/Documentation/explanation.txt
> > > > @@ -1986,18 +1986,15 @@ violates the compiler's assumptions, which would render the ultimate
> > > >  outcome undefined.
> > > >
> > > >  In technical terms, the compiler is allowed to assume that when the
> > > > -program executes, there will not be any data races.  A "data race"
> > > > -occurs when two conflicting memory accesses execute concurrently;
> > > > -two memory accesses "conflict" if:
> > > > +program executes, there will not be any data races. A "data race"
> > >
> > > Unnecessary (and inconsistent with the rest of the document) whitespace
> > > change.
> >
> > Reverted.
> >
> > > > +occurs if:
> > > >
> > > > -     they access the same location,
> > > > +     two concurrent memory accesses "conflict";
> > > >
> > > > -     they occur on different CPUs (or in different threads on the
> > > > -     same CPU),
> > > > +     and at least one of the accesses is a plain access;
> > > >
> > > > -     at least one of them is a plain access,
> > > > -
> > > > -     and at least one of them is a store.
> > > > +     where two memory accesses "conflict" if they access the same
> > > > +     memory location, and at least one performs a write;
> > > >
> > > >  The LKMM tries to determine whether a program contains two conflicting
> > > >  accesses which may execute concurrently; if it does then the LKMM says
> > >
> > > To tell the truth, the only major change I can see here (apart from the
> > > "differenct CPUs" restriction) is that you want to remove the "at least
> > > one is plain" part from the definition of "conflict" and instead make
> > > it a separate requirement for a data race.  That's fine with me in
> > > principle, but there ought to be an easier way of doing it.
> >
> > Yes pretty much. The model needs to be able to talk about "conflicting
> > synchronization accesses" where all accesses are marked. Right now the
> > definition of conflict doesn't permit that.
> >
> > > Furthermore, this section of explanation.txt goes on to use the words
> > > "conflict" and "conflicting" in a way that your patch doesn't address.
> > > For example, shortly after this spot it says "Determining whether two
> > > accesses conflict is easy"; you should change it to say "Determining
> > > whether two accesses conflict and at least one of them is plain is
> > > easy" -- but this looks pretty ungainly.  A better approach might be to
> > > introduce a new term, define it to mean "conflicting accesses at least
> > > one of which is plain", and then use it instead throughout.
> >
> > The definition of "conflict" as used in the later text is synonymous
> > with "data race".
> 
> Correction: it's "data race" minus "concurrent" which makes things
> more difficult. In which case, fixing this becomes more difficult.
> 
> > > Alternatively, you could simply leave the text as it stands and just
> > > add a parenthetical disclaimer pointing out that in the CS literature,
> > > the term "conflict" is used even when both accesses are marked, so the
> > > usage here is somewhat non-standard.
> >
> > The definition of what a "conflict" is, is decades old [1, 2]. I
> > merely thought we should avoid changing fundamental definitions that
> > have not changed in decades, to avoid confusing people. The literature
> > on memory models is confusing enough, so fundamental definitions that
> > are "common ground" shouldn't be changed if it can be avoided. I think
> > here it is pretty trivial to avoid.

All right.  Here is my suggestion for a patch that does more or less
what you want.  Fiddle around with it until you like the end result and
let's see what you get.

Alan


Index: usb-devel/tools/memory-model/Documentation/explanation.txt
===================================================================
--- usb-devel.orig/tools/memory-model/Documentation/explanation.txt
+++ usb-devel/tools/memory-model/Documentation/explanation.txt
@@ -1987,28 +1987,30 @@ outcome undefined.
 
 In technical terms, the compiler is allowed to assume that when the
 program executes, there will not be any data races.  A "data race"
-occurs when two conflicting memory accesses execute concurrently;
-two memory accesses "conflict" if:
+occurs when two conflicting memory accesses execute concurrently and
+at least one of them is plain.  Two memory accesses "conflict" if:
 
 	they access the same location,
 
 	they occur on different CPUs (or in different threads on the
 	same CPU),
 
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
+We'll say that two accesses are "race candidates" if they conflict and
+at least one of them is plain.  Whether or not two candidates actually
+do race in a given execution then depends on whether they are
+concurrent.  The LKMM tries to determine whether a program contains
+two race candidates which may execute concurrently; if it does then
+the LKMM says there is a potential data race and makes no predictions
+about the program's outcome.
+
+Determining whether two accesses are race candidates is easy; you can
+see that all the concepts involved in the definition above are already
+part of the memory model.  The hard part is telling whether they may
+execute concurrently.  The LKMM takes a conservative attitude,
+assuming that accesses may be concurrent unless it can prove they
+are not.
 
 If two memory accesses aren't concurrent then one must execute before
 the other.  Therefore the LKMM decides two accesses aren't concurrent
@@ -2171,8 +2173,8 @@ again, now using plain accesses for buf:
 	}
 
 This program does not contain a data race.  Although the U and V
-accesses conflict, the LKMM can prove they are not concurrent as
-follows:
+accesses are race candidates, the LKMM can prove they are not
+concurrent as follows:
 
 	The smp_wmb() fence in P0 is both a compiler barrier and a
 	cumul-fence.  It guarantees that no matter what hash of
@@ -2326,12 +2328,11 @@ could now perform the load of x before t
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
 
@@ -2367,7 +2368,7 @@ concurrent and there is no race, even th
 isn't w-post-bounded by any marked accesses.
 
 Putting all this material together yields the following picture.  For
-two conflicting stores W and W', where W ->co W', the LKMM says the
+race-candidate stores W and W', where W ->co W', the LKMM says the
 stores don't race if W can be linked to W' by a
 
 	w-post-bounded ; vis ; w-pre-bounded
@@ -2380,8 +2381,8 @@ sequence, and if W' is plain then they a
 
 	w-post-bounded ; vis ; r-pre-bounded
 
-sequence.  For a conflicting load R and store W, the LKMM says the two
-accesses don't race if R can be linked to W by an
+sequence.  For race-candidate load R and store W, the LKMM says the
+two accesses don't race if R can be linked to W by an
 
 	r-post-bounded ; xb* ; w-pre-bounded
 
@@ -2413,20 +2414,20 @@ is, the rules governing the memory subsy
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
-
-	If W and W' conflict and it is possible to link W to W' by one
-	of the vis sequences listed above, then W' ->co W is not
-	allowed (i.e., if one store is visible to a second then the
-	second must come after the first in the coherence order).
+	If W and R are race candidates and it is possible to link W to
+	R by one of the vis sequences listed above, then R ->fre W is
+	not allowed (i.e., if a store is visible to a load then the
+	load must read from that store or one coherence-after it).
+
+	If W and W' are race candidates and it is possible to link W
+	to W' by one of the vis sequences listed above, then W' ->co W
+	is not allowed (i.e., if one store is visible to a second then
+	the second must come after the first in the coherence order).
 
 This is the extent to which the LKMM deals with plain accesses.
 Perhaps it could say more (for example, plain accesses might

