Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZML366QMGQEFOPKWIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 818D5A3E91A
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 01:16:39 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e5dd69746f5sf2215465276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 16:16:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740096998; cv=pass;
        d=google.com; s=arc-20240605;
        b=eLw8m+XGXfc83kkoNAdLHYpoLPgSgx72w7MHMDw7DlYlywAio1ox8daNgD5oytoaTL
         xdCCO0vmLc1gOgXiT562uVfTpcccH3P0FZEhnjSQT5A6eyeGbTJXaS0IGZVhQ1w9M/Xo
         bKx1SbC86eLkmU/n+5jX8bV0ft88JdgbzHIPliWBo5ojKiUDdB11qKLpA+/ISDPMQYDd
         PMOjGBvteWiBv0wCKJlsMtGfXJ3ZNMZkQUVhuMVC5mOfrqlIouHg62E4oYnE8TjZR6nX
         VdgZc0T8lAlOP1RjG6kvdeTgoqJ93C38NZDguyGUwv97KzCxV6aAt3lD+An+kTzXZura
         p0Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DyxgoBu32SYtvglGXAa0GvLlvIzwP5ge2GhSbW+KKDc=;
        fh=RhA9xcnACwshotnJRq5xuHqPbqo+WtLTefJatkMB2eo=;
        b=dcz6J+1dN9div8+Bd+FVhaoRGoyXzk4G6w0415/BG8gazoBOB0FpSkXpMzmgNDs0S9
         uDLNNwbWbfYmFSFlbUzaa36wgg2JKiAtGBk4HxVZW5dM+mzMXsvz8vrtT35fNx9Bhz1G
         DFHvNc6OGAVLdOeOcKrjFqIvUR/Z2HFwPO7Gb99RDdYfxxUdCAnnsvCYNlSV4se4Fa7l
         GpYgyMRLEvrJg/NCB84h463vq30Si//PehoLvTubz3qa5R++zZtu83AoMWCBdG7r72yO
         U5859t06wT0bB/7E6TjJxr7nPA7Ow0ktaWz6HRmfK5eIZ1iKpMChhfb9dxNQF6/1sPVT
         ogUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NO5Ajqlk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740096998; x=1740701798; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DyxgoBu32SYtvglGXAa0GvLlvIzwP5ge2GhSbW+KKDc=;
        b=v77rN73dqhu0krOe//6NKNgMKVDw4gToqUP3TDFStmUDYs7tuegUpfXsIXEIoK+/ki
         fBR2E2CwGZGKhzIAtasI/yyYl7/c2Mc3BIWPN4DX1aGyHjX/U3fT6vnU0YifmS36ksdZ
         ZgDdi/zLF5qAGS0lf3lBnUoc/CejSP0TYx864HF0yTGLeL9WJHLZGb2nX26FqW3wa3wX
         dblmAqmTy8PAXgIl+sUM5vYGtPnOObu+mcPWviKTrZBziZ9N3xAblTh1OyZYZmCpCOLn
         5ZIz9FJD7wvU2QxTtMeAOprjwvT4bgY/KTnfF0ZmTi1ZEv6n2grbXrUFDyUOScWw6c2D
         lVbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740096998; x=1740701798;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DyxgoBu32SYtvglGXAa0GvLlvIzwP5ge2GhSbW+KKDc=;
        b=wX0ZTzuF/eP0EzAf25e5Rz3CGUrHproIhUWCPCBxNr3oQeBju5wkv2/g9wInwOkC74
         W3WcqcKj4VUaQTWfO3qMPSsGJtQe5EsuxPdwVt2IqeKuLMI4q8vCspCvUJwC8xo1ivKP
         aI/oQe1keJiGaYPH2u0RaBGHqfKpwjIvYkpRrRxwzmayOF7dGU8lomZBHxWpqrFw0qY/
         HGhPGOl8YuUBbLVED32xZcQsmQ9i8TuSLXdMl0yD70HdeHDqsl5ebl+rwqL7ET5ydhng
         1NwtL+pKzpVDsiqcNfRLnk5zNNWcwViwuEdS0fcPj4BApp5gSWFnywDBKkbLxtMwgZVm
         dxUA==
X-Forwarded-Encrypted: i=2; AJvYcCUF1Y5Uy8rjdeg4K0NwXOcKjYfvzTlcBlTl7Klc5lbk1elxRcCN4J81SIBaS7Ftlr/FdKUX5w==@lfdr.de
X-Gm-Message-State: AOJu0Yw9nOkCOGz8WRdXveyavu6SrBBXwvD5chNx9sSjzB9OedPOZ6YG
	b6o9IWFibimgh5rAyM1sXWi95GAHOQxKTzAf6po/GiDIrgVBMpql
X-Google-Smtp-Source: AGHT+IENEn2hYCrtG2/8+AxlZXO8rKl3mfFTA/4v6MkQsew3C7SSvKzszaF3HIvJg489NrD2JiEqGg==
X-Received: by 2002:a05:6902:2382:b0:e5b:3af0:d49f with SMTP id 3f1490d57ef6-e5e245af542mr1077523276.8.1740096998093;
        Thu, 20 Feb 2025 16:16:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFxLs16ddCC72n6kyAIFByr2DWB9jSz5Nq8jJAMvuQXSg==
Received: by 2002:a25:b20f:0:b0:e5b:3ee5:4212 with SMTP id 3f1490d57ef6-e5e1b0a728fls1232305276.0.-pod-prod-01-us;
 Thu, 20 Feb 2025 16:16:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQPcih2xTHF1oHXHs9CdfkFYeEdBEzukvBXmKgzy7bEoMu/ntRsjaEuxtaRKwMXqXgE6hNLmk76XY=@googlegroups.com
X-Received: by 2002:a05:6902:3389:b0:e5d:c7ab:5e0e with SMTP id 3f1490d57ef6-e5e245ad82bmr1229764276.3.1740096997168;
        Thu, 20 Feb 2025 16:16:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740096997; cv=none;
        d=google.com; s=arc-20240605;
        b=czkq3UueWZNkNjeSp5P7l9TA/nml/v+N4Uzv5mmJ8lu26f5xqewGHwLiMlOCvFRMLB
         TxaXywmU1S3MZ4jM5FgtXPkrwMlhrvlwCk8fB3nS/96xte4H3vSqGZKG0KzAB/LOR7XZ
         wxw8PnPCHojVXnnCN6v8MsMUZaC/acXv7LRWj9PBef417rrOQ3h2dtCfDMzq5tsiq/OU
         RP9rW3N7YKUpZn+7Ky8dat5ziEmg7JAsKnCGZ3sKePFG+/TfNQ+JZ//opboZOJP+o5RR
         Z653BkeaUgbcRaQLCbqm+GuH9Q+jUbQ3C3cSI5hrgd6j7ikNyNr7bDLCL2psYtnQ2ysb
         kxqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gOXx46W220E6FZEq/MsCwDe+Yct3ZgJbNWYU+dT6cGI=;
        fh=hd4SzWpEZvlPCLhE/G0teiIl0H2vaTqNR/pqiJW+Luk=;
        b=JfBsqDMaT+41MvnWDLqRhn87MJlWnLslWX0avENrAexVSBnyF+HAcrJ1Z6Ed6ZWAha
         Lj7+bQmAy7rt9ZIGqH0K/ILRa/u5IhjNE3rYMUstZgwhr/1otkswqYKjSiVB8ThylH7R
         VPCzBkLcLHHTaTA2wY6eLSMOC/elqPquDRyTF5+IJOxTkpaolmsdiFU/mKCb7FPW+aad
         1REK2zsN31Gx+VKYSXv4BCWJJVuGHb6owvqnSAABBHvUoU6DRPB2m1tqHlpPi9AQGwQc
         UBxiebpUhF5oTsRMaMaeeVhuvhzV7ESa/BiT5vKiYZKKoEbU8qM6BRuXeGygyiojhil9
         S2ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NO5Ajqlk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e5db9c278d6si1263265276.0.2025.02.20.16.16.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Feb 2025 16:16:37 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id 98e67ed59e1d1-2fc1843495eso2367586a91.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Feb 2025 16:16:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU40UdoMDUDbun/9CSrKZsnWva0uWKZaGeAGKncLkGFy84awuAYW5TBibvaO1yHcAo7Ki7H16o6eas=@googlegroups.com
X-Gm-Gg: ASbGnct82sNJWe9WFOXWaQl7SIJT2dOwpsnkPVO8STAe290Ld6MVXExfaH8G604lrtu
	RehAyPnCO1d1YX1UA8ffcZBedWpNIQhAKH6KNV7SknxOOMyrWedxSS/GpR/0LpWPkNC1OH7p/Ir
	Xw330xZ/f1FPy2MGhJmFRl668rG31g
X-Received: by 2002:a17:90b:1d83:b0:2fc:3264:3666 with SMTP id
 98e67ed59e1d1-2fce7b221c3mr1828235a91.30.1740096996554; Thu, 20 Feb 2025
 16:16:36 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop> <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
In-Reply-To: <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Feb 2025 01:16:00 +0100
X-Gm-Features: AWEUYZmivm5bHZ6EpPSxW_3r18VidjaU61lIM_KUqGThNf6OIvndggmyl3l59og
Message-ID: <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
To: paulmck@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Bart Van Assche <bvanassche@acm.org>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NO5Ajqlk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::102f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, 20 Feb 2025 at 23:36, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> Suppose that one function walks an RCU-protected list, calling some
> function from some other subsystem on each element.  Suppose that each
> element has another RCU protected list.
>
> It would be good if the two subsystems could just choose their desired
> flavor of RCU reader, without having to know about each other.

That's what I figured might be the case - thanks for clarifying.

> > Another problem was that if we want to indicate that "RCU" read lock
> > is held, then we should just be able to write
> > "__must_hold_shared(RCU)", and it shouldn't matter if rcu_read_lock()
> > or rcu_read_lock_bh() was used. Previously each of them acquired their
> > own capability "RCU" and "RCU_BH" respectively. But rather, we're
> > dealing with one acquiring a superset of the other, and expressing
> > that is also what I attempted to solve.
> > Let me rethink this...
>
> Would it work to have just one sort of RCU reader, relying on a separate
> BH-disable capability for the additional semantics of rcu_read_lock_bh()?

That's what I've tried with this patch (rcu_read_lock_bh() also
acquires "RCU", on top of "RCU_BH"). I need to add a re-entrancy test,
and make sure it doesn't complain about that. At a later stage we
might also want to add more general "BH" and "IRQ" capabilities to
denote they're disabled when held, but that'd overcomplicate the first
version of this series.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNHTg%2BuLOe-LaT-5OFP%2BbHaNxnKUskXqVricTbAppm-Dw%40mail.gmail.com.
