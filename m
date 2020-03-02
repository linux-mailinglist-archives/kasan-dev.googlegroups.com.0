Return-Path: <kasan-dev+bncBD6LRVPZ6YGRB3UR6XZAKGQETYVPEOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EC001761AB
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Mar 2020 18:57:03 +0100 (CET)
Received: by mail-oi1-x238.google.com with SMTP id c66sf350728oif.3
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2020 09:57:03 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wyweNGuiEMz8LTFgBlSEjBCnY1v7Se/a96UGSXx/Fk4=;
        b=FeRSrIUFsZEV7h0QgJWiG5EqRO1vJoInrPAqN+4ifLHpCQ5C3jD5089TC0JBXk/Lcr
         2gPPQbEp6YI4RoaVx4I1a+EJUUymRRqA/MgEhGJvStOiX+qeVlY+xEkAc+Wh71dClhIy
         +tcO9uE3XIhlHJ8NNoY0gDmzEqleDDZKys5Ai+A9ftwLUPceYQwADzG+8f4R6dpMTE0A
         YmL7BJDLDlw9jw6lusxCgrnNCkiPpDFE7+bLfzMI8zWE1Mv1ZDZaQb2JgS2Lnrs6ThQT
         qBvEWK33beREHnGepmCuk2JGtuOs2K7DAi5Dywo1B3cMP7PoLrfl143QtXC8A+A3PbPg
         94zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wyweNGuiEMz8LTFgBlSEjBCnY1v7Se/a96UGSXx/Fk4=;
        b=BpJKxADG2JHCXuCOmSUBmwOa2ry90+hY727SxB8O26wgkVLpWQFI/3LYmXgbptrX6w
         oMcGbefq6rsj16m0sApDeKcoani62Kao99/CZgfRftQujOtEZ4RscuI/Zw93DulkWreR
         h28p2PQvhGb6bxKcsNP5M7HG5R7eiDKBNv2YzMxejVgc5PPrgYNQercOrW0cBonYUGCb
         6uz36TDA8N2Wa01XNSBTcsFfII7QT6i0AtwuqyW17jkKr7wqQuMyGhyj2IpaVBKHtB03
         3ujUYz5ccGdcLcpGloO0nqfiWUDyGaZ9X2xilEgIEKRWz7zbcaTGq02xy3EHQW4hso/o
         +isA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1B9cC73StQY14Q9zGCnaHTiUEOIkzUh+RNNXe20TPFJHAU7Vdg
	RBK11LQ+MiNQOIgVKHKSEpA=
X-Google-Smtp-Source: ADFU+vsFWNrYC9SjGf26lEFTcMjjQY/YS8V1p3Y5H7611etpQrmy/udtquxGmvaDC8+0DLWpVW2gIQ==
X-Received: by 2002:a9d:c69:: with SMTP id 96mr287901otr.129.1583171822249;
        Mon, 02 Mar 2020 09:57:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c694:: with SMTP id w142ls221661oif.6.gmail; Mon, 02 Mar
 2020 09:57:00 -0800 (PST)
X-Received: by 2002:aca:b483:: with SMTP id d125mr187836oif.167.1583171820468;
        Mon, 02 Mar 2020 09:57:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583171820; cv=none;
        d=google.com; s=arc-20160816;
        b=vokR6jih92pmZsQZJ5bEW4uSAf3F9xXY7R2K/UV42zBNguoXz5La0Zjr1xbEcMDpSF
         SKhLfF3F+HDGXxWlNepgj5GDLeR2FSAY3IE7I8nIQt4EE69aNorM4QL5CcPEpXCMil1I
         HZNHnqR9gTWe46xgD/73lBSAoLt6Lsjy70DT4nViLvOxCGaJXVCyJb8xCOrZwpMaMEeF
         9CZtQtcsZVEeG8xfcFdeFr9+6NAHnglsdRJrnz7fPW6mEfYy1QtPv9VJEy/oJnJYF//m
         bvAAGldVfUUuy4t1l0tj4q+9YeQctT3FcogE5VVTBUsi57+4m7QpJCpvqmFdrsoqNo5X
         URqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:in-reply-to:subject:cc:to:from:date;
        bh=wyweNGuiEMz8LTFgBlSEjBCnY1v7Se/a96UGSXx/Fk4=;
        b=RJzFY4SkGvaCrJ/kVyDRFgZvB+PAwmR0oCDDdFRziTIq22C7avnT6Efel/oJ4ZJVAi
         cHIr3WvDvQeWnWMh0rM/rmBbgdFUT/O8EH4zKOKxjLfhlu9iB7jP863UWLmrOECsLA/s
         IdoCld++S9mS9ErZHnjEnkRVeVPPqoBtMbQladf7rFNa3RF4ia8HERc1S3hav96afWTw
         i88svS61BIVSFSjWPir7Gc3mC+mhynikqGbPYXaJhLaWGatkbVy6XCatW8lMv95FCHxw
         XHVeFNVBhGaArwMXAIK46bfIrsvZ+d4yWn0a29CpplzEDehHR6Ln3lOBJ9bv3PUN12ua
         knew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) smtp.mailfrom=stern+5e5a5726@rowland.harvard.edu
Received: from iolanthe.rowland.org (iolanthe.rowland.org. [192.131.102.54])
        by gmr-mx.google.com with SMTP id h199si515763oib.2.2020.03.02.09.57.00
        for <kasan-dev@googlegroups.com>;
        Mon, 02 Mar 2020 09:57:00 -0800 (PST)
Received-SPF: pass (google.com: domain of stern+5e5a5726@rowland.harvard.edu designates 192.131.102.54 as permitted sender) client-ip=192.131.102.54;
Received: (qmail 4289 invoked by uid 2102); 2 Mar 2020 12:56:59 -0500
Received: from localhost (sendmail-bs@127.0.0.1)
  by localhost with SMTP; 2 Mar 2020 12:56:59 -0500
Date: Mon, 2 Mar 2020 12:56:59 -0500 (EST)
From: Alan Stern <stern@rowland.harvard.edu>
X-X-Sender: stern@iolanthe.rowland.org
To: Marco Elver <elver@google.com>
cc: linux-kernel@vger.kernel.org,  <kasan-dev@googlegroups.com>, 
     <parri.andrea@gmail.com>,  <will@kernel.org>,  <peterz@infradead.org>, 
     <boqun.feng@gmail.com>,  <npiggin@gmail.com>,  <dhowells@redhat.com>, 
     <j.alglave@ucl.ac.uk>,  <luc.maranget@inria.fr>,  <paulmck@kernel.org>, 
     <akiyks@gmail.com>,  <dlustig@nvidia.com>,  <joel@joelfernandes.org>, 
     <linux-arch@vger.kernel.org>
Subject: Re: [PATCH v3] tools/memory-model/Documentation: Fix "conflict"
 definition
In-Reply-To: <20200302172101.157917-1-elver@google.com>
Message-ID: <Pine.LNX.4.44L0.2003021256130.1555-100000@iolanthe.rowland.org>
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
> Signed-off-by: Alan Stern <stern@rowland.harvard.edu>
> ---
> v3:
> * Apply Alan's suggestion.
> * s/two race candidates/race candidates/

Looks good!

Alan

