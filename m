Return-Path: <kasan-dev+bncBD6LRVPZ6YGRBGXR6TZAKGQEQPL467A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id DECC6176044
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 17:47:24 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id h12sf47228pfr.2
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 08:47:24 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTsgMaty/rFwxXS7jj8TT9GHh+FM8EiqE48enbpVM94=;
        b=s6KwIa6Q3UOOW6RiUY6DfJw77dSR5L14+d1ILs/Zxx1b24boDoMuv5mZAIaU7+PNz/
         Pv7wOZYZQUfiaxFTu2/UepqO/zZPumlRQvX2KJn1ms2SNv2pKMjdAQbk1wK0aLCxkRbv
         aH2ujeSFoCxiIldkoPtAMsusBJNVvFEZBjlZE9VvuopRDSv1QeO5MNoM4cDa/GQwsTaA
         y9KhG9Ikp0bBUWMZgBeUreSOHfH+GG5r6SYxx7giMYAsSyp5DMMUZCSrM4M39wEPmHP7
         nILuwK8bGTUQ1jSddiKqAt4z02uOX5WG5gthuU94XP6Z/rsfipzM4BunXoMB/atuMFO5
         r5qQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTsgMaty/rFwxXS7jj8TT9GHh+FM8EiqE48enbpVM94=;
        b=Ra57T9Nwm37WJzFUlF+psif7uctF5l+tprAaGN8jAWazZoGpWCVgYwoecIktQ9z4HL
         rHmQWU3BDNwJsj0QNGfb6MSoYhzpguVZeEdfkZjJr7wKCEMg50q9d1XG7GHsQ3/Xggy7
         OUTbA/oTc0nQGWcUYThXuMwZeXVe8qHP8q2WNNvgKsqR7Sc+RKixlU9hcsGPXdwG6Jcn
         Aku4/XayWKomtnlf3AMwZR8BqofJh/YnA1xzadBwPKAWpzzWOUN2RB+R4Orbg+NV96Uj
         ZyU5PH67/vBdbRS34yG9notCTjQ8alqKzXs1IK3o4CMm8vu20lvzihdtTol+dOhmK7Ir
         MPGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0K61zY96qR1wvpioly9z/TcnyOztV2gSGtI31oP1YonAOx/w8V
	V6FKLJTPYelbkQJC4RhI5cw=
X-Google-Smtp-Source: ADFU+vurGJcZgmkh/57CpCDh5rKilkHwQ3QwD+vnal/VdmPwUyb9ZXQVSmp2twDCBdOeaSqDUSvlUA==
X-Received: by 2002:a17:90a:cf11:: with SMTP id h17mr493693pju.103.1583167642987;
        Mon, 02 Mar 2020 08:47:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7744:: with SMTP id s65ls46765pgc.3.gmail; Mon, 02 Mar
 2020 08:47:22 -0800 (PST)
X-Received: by 2002:a65:5c46:: with SMTP id v6mr21340495pgr.333.1583167642151;
        Mon, 02 Mar 2020 08:47:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583167642; cv=none;
        d=google.com; s=arc-20160816;
        b=ooM+1eBJyF7A9Gkg0HihMyCVm5xXMl35vmedX1CoI1sVvX4pe6f2Ok7xqXCGcN0HvM
         8/b8JooI5glrzXlqiqM+JXDJfCpp4iPB+Tc8K6N55Shbqu3zs8whtiQcBbWW5Ft78T9P
         olg45+I8545oZC9RyxSJLUQMsGb6sU9lVt58tU99x7M2BsdWmgKsKSakxfznlLFPVPJM
         qrbYRxcTTDZy01IO0AJdUP9Ifkf/iQzXkLDqHxYjCiKHg8JN5LTjKaXpGT/M6UAhw/TW
         glxTvE9wgX0fdBS9HQD3rMTLBTr1E9qJXsEuHfspKgYtrP5xrgS6wi6VAj5bxqy04ozF
         zGeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:in-reply-to:subject:cc:to:from:date;
        bh=XTsgMaty/rFwxXS7jj8TT9GHh+FM8EiqE48enbpVM94=;
        b=TMBiUK6z7baEm/qkgAKsDCE/cOAyWdT91pZRYnCMgrJ4taQosdf5aegm+0aUajgMsV
         9kLBpcSmm+2k3QYyeN4eA2Koxdbn+e8ZKCOEXNUo7UDyYHnU5udBaXgM9Q0JHDYWIUhK
         lTqtwn9VjQMhlHgtHw5Qz2Uq57VEdK+YK4Rreb6sHXoY9QpT0ZaBkbxahepwxuntJFWX
         kZSkKlAJiz4/Lnp24TK6sKIaEUpPdLBNX7sAz7iFyq9BTCMHoOBF4D3Lpu00Q6qmzIKK
         ZgKS0ee5QjaCZJVeGir5dFxll8KVRFDG36WQt5r8BkrSAr7o8E2SbpJq0sp19K5It4ga
         G7Dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
Received: from iolanthe.rowland.org (iolanthe.rowland.org. [192.131.102.54])
        by gmr-mx.google.com with SMTP id i4si301029pgg.1.2020.03.02.08.47.21
        for <kasan-dev@googlegroups.com>;
        Mon, 02 Mar 2020 08:47:21 -0800 (PST)
Received-SPF: pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) client-ip=192.131.102.54;
Received: (qmail 3316 invoked by uid 2102); 2 Mar 2020 11:47:20 -0500
Received: from localhost (sendmail-bs@127.0.0.1)
  by localhost with SMTP; 2 Mar 2020 11:47:20 -0500
Date: Mon, 2 Mar 2020 11:47:20 -0500 (EST)
From: Alan Stern <stern@rowland.harvard.edu>
X-X-Sender: stern@iolanthe.rowland.org
To: Marco Elver <elver@google.com>
cc: linux-kernel@vger.kernel.org,  <kasan-dev@googlegroups.com>, 
     <parri.andrea@gmail.com>,  <will@kernel.org>,  <peterz@infradead.org>, 
     <boqun.feng@gmail.com>,  <npiggin@gmail.com>,  <dhowells@redhat.com>, 
     <j.alglave@ucl.ac.uk>,  <luc.maranget@inria.fr>,  <paulmck@kernel.org>, 
     <akiyks@gmail.com>,  <dlustig@nvidia.com>,  <joel@joelfernandes.org>, 
     <linux-arch@vger.kernel.org>
Subject: Re: [PATCH v2] tools/memory-model/Documentation: Fix "conflict"
 definition
In-Reply-To: <20200302141819.40270-1-elver@google.com>
Message-ID: <Pine.LNX.4.44L0.2003021134360.1555-100000@iolanthe.rowland.org>
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

On Mon, 2 Mar 2020, Marco Elver wrote:

> Alan: I think this needs your Signed-off-by, since I added you as
> Co-developed-by.

Here you go:

Signed-off-by: Alan Stern <stern@rowland.harvard.edu>

> Let me know if this works for you.

See below.

> The definition of "conflict" should not include the type of access nor
> whether the accesses are concurrent or not, which this patch addresses.
> The definition of "data race" remains unchanged.
> 
> The definition of "conflict" as we know it and is cited by various
> papers on memory consistency models appeared in [1]: "Two accesses to
> the same variable conflict if at least one is a write; two operations
> conflict if they execute conflicting accesses."
> 
> The LKMM as well as the C11 memory model are adaptations of
> data-race-free, which are based on the work in [2]. Necessarily, we need
> both conflicting data operations (plain) and synchronization operations
> (marked). For example, C11's definition is based on [3], which defines a
> "data race" as: "Two memory operations conflict if they access the same
> memory location, and at least one of them is a store, atomic store, or
> atomic read-modify-write operation. In a sequentially consistent
> execution, two memory operations from different threads form a type 1
> data race if they conflict, at least one of them is a data operation,
> and they are adjacent in <T (i.e., they may be executed concurrently)."
> 
> [1] D. Shasha, M. Snir, "Efficient and Correct Execution of Parallel
>     Programs that Share Memory", 1988.
> 	URL: http://snir.cs.illinois.edu/listed/J21.pdf
> 
> [2] S. Adve, "Designing Memory Consistency Models for Shared-Memory
>     Multiprocessors", 1993.
> 	URL: http://sadve.cs.illinois.edu/Publications/thesis.pdf
> 
> [3] H.-J. Boehm, S. Adve, "Foundations of the C++ Concurrency Memory
>     Model", 2008.
> 	URL: https://www.hpl.hp.com/techreports/2008/HPL-2008-56.pdf
> 
> Signed-off-by: Marco Elver <elver@google.com>
> Co-developed-by: Alan Stern <stern@rowland.harvard.edu>
> ---
> v2:
> * Apply Alan's suggested version.
>   - Move "from different CPUs (or threads)" from "conflict" to "data
>     race" definition. Update "race candidate" accordingly.
> * Add citations to commit message.
> 
> v1: http://lkml.kernel.org/r/20200228164621.87523-1-elver@google.com
> ---
>  .../Documentation/explanation.txt             | 77 +++++++++----------
>  1 file changed, 38 insertions(+), 39 deletions(-)
> 
> diff --git a/tools/memory-model/Documentation/explanation.txt b/tools/memory-model/Documentation/explanation.txt
> index e91a2eb19592a..7a59cadc2f4ca 100644
> --- a/tools/memory-model/Documentation/explanation.txt
> +++ b/tools/memory-model/Documentation/explanation.txt
> @@ -1987,28 +1987,28 @@ outcome undefined.
>  
>  In technical terms, the compiler is allowed to assume that when the
>  program executes, there will not be any data races.  A "data race"
> -occurs when two conflicting memory accesses execute concurrently;
> -two memory accesses "conflict" if:
> +occurs when two conflicting memory accesses from different CPUs (or
> +different threads on the same CPU) execute concurrently, and at least
> +one of them is plain.  Two memory accesses "conflict" if:
>  
>  	they access the same location,
>  
> -	they occur on different CPUs (or in different threads on the
> -	same CPU),
> -
> -	at least one of them is a plain access,
> -
>  	and at least one of them is a store.
>  
> -The LKMM tries to determine whether a program contains two conflicting
> -accesses which may execute concurrently; if it does then the LKMM says
> -there is a potential data race and makes no predictions about the
> -program's outcome.
> -
> -Determining whether two accesses conflict is easy; you can see that
> -all the concepts involved in the definition above are already part of
> -the memory model.  The hard part is telling whether they may execute
> -concurrently.  The LKMM takes a conservative attitude, assuming that
> -accesses may be concurrent unless it can prove they cannot.
> +We'll say that two accesses from different threads are "race
> +candidates" if they conflict and at least one of them is plain.
> +Whether or not two candidates actually do race in a given execution
> +then depends on whether they are concurrent.  The LKMM tries to
> +determine whether a program contains race candidates which may execute
> +concurrently; if it does then the LKMM says there is a potential data
> +race and makes no predictions about the program's outcome.

Hmmm.  Although the content is okay, I don't like the organization very
much.  What do you think of this for the above portion of the patch)?

Alan Stern



Index: usb-devel/tools/memory-model/Documentation/explanation.txt
===================================================================
--- usb-devel.orig/tools/memory-model/Documentation/explanation.txt
+++ usb-devel/tools/memory-model/Documentation/explanation.txt
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
+
+3.	at least one of them is plain,
 
-	at least one of them is a plain access,
+4.	they occur on different CPUs (or in different threads on the
+	same CPU), and
 
-	and at least one of them is a store.
+5.	they execute concurrently.
 
-The LKMM tries to determine whether a program contains two conflicting
-accesses which may execute concurrently; if it does then the LKMM says
-there is a potential data race and makes no predictions about the
+In the literature, two accesses are said to "conflict" if they satisfy
+1 and 2 above.  We'll go a little farther and say that two accesses
+are "race candidates" if they satisfy 1 - 4.  Thus, whether or not two
+race candidates actually do race in a given execution depends on
+whether they are concurrent.
+
+The LKMM tries to determine whether a program contains two race
+candidates which may execute concurrently; if it does then the LKMM
+says there is a potential data race and makes no predictions about the
 program's outcome.
 
-Determining whether two accesses conflict is easy; you can see that
-all the concepts involved in the definition above are already part of
-the memory model.  The hard part is telling whether they may execute
-concurrently.  The LKMM takes a conservative attitude, assuming that
-accesses may be concurrent unless it can prove they cannot.
+Determining whether two accesses are race candidates is easy; you can
+see that all the concepts involved in the definition above are already
+part of the memory model.  The hard part is telling whether they may
+execute concurrently.  The LKMM takes a conservative attitude,
+assuming that accesses may be concurrent unless it can prove they
+are not.
 
 If two memory accesses aren't concurrent then one must execute before
 the other.  Therefore the LKMM decides two accesses aren't concurrent


