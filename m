Return-Path: <kasan-dev+bncBCJZRXGY5YJBB54L72FAMGQEWPOWH4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B320E4260A6
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Oct 2021 01:42:49 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id ot13-20020a17090b3b4d00b001a04f094a68sf1352911pjb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 16:42:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633650168; cv=pass;
        d=google.com; s=arc-20160816;
        b=JN8yiEJyY1SOqPYKcOQ3hfkC2WSK0s7//uUz5A6uec9ofY5H6w+ZYYic95XjLV1YvQ
         C+N67RsdC/MHxOC1Jtzcpwd3M9YRgjmF/3q498pc7TRfN3F8W/jzn6IcgMsAVsLf53XZ
         Is2Cf3vql3GFEHxxIF434mYrMI84XcEeRnMx85dCjOz0Lvctj33E0WczzwQFTlFg/4ik
         ViZrXxH96YLs/K5ECHAF7rxEH6CRUO7U6MU1a8Fodd7xEJzw1Hs/kpqHK+Bv6uJCa2Ih
         DjyB+nbq9T75RZZovOL6pu8BGb6WAXBfdA1tdpa7WmoBkDtI+2/yUIAUsPr8r3OLEl/4
         /8Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=YBNJ5Su9nNmrqscT9yYTiDPJ+u/9WX9sJZrgHbYE3Ts=;
        b=bsy94PJ5+6q1/xUgeac3HkwF7S9dLmJeosv6Hs5tcozKupc9PVS8YEDwrz6HPMUeT7
         Es4JcNzXRO4sFNf9pxoan2eFv/O1SR7PRtcCY3cDHrFvC0hWzSZ6UfWSVKSyrhxXcOIh
         ZvfjP2zbRI/qkBTKUpNggU0YNo4ZXbbKesonUGmlMZhN6N9MUvOs8ntXLx7uHG4FyV0U
         fZEnQco2vPxO3CcwI7Cm2oQFmS9qTTQHRYevGVIdiThzIcL3BwXVOGDrIvwAiXw2j9lO
         iCI0mAQxpvfU27AiBAtT2n6WJSudBGFwvmLbi8tPT3iag2c3Zl2LkF1p2PbD8tHRKJt8
         EeEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MGYwZGwW;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YBNJ5Su9nNmrqscT9yYTiDPJ+u/9WX9sJZrgHbYE3Ts=;
        b=YKj8q+qA9PGk+CMhGtiDu1tJbGMCYrpY2h7nasvWmgxI/tp40OTNcvfnEadfC2sGPU
         1QrnJbaZuyVYXZ7LxFfXxJpSyMbDrvcEFhcyAXCTVOeCgrtQREKbhwsUB1aJ/RhqQgvm
         vT7BXIBPppb6b2/rpBim2KIuYfdpbulkqX/cgqt1GnoOT6dAtJfpVqn9xE/WC6oad57A
         GkoTEnsdKW9zH2VfVrZwkLvm+nW550fbUL4tC/h6Jsvha6nGzo6+7n1kjT0hDXgTySmJ
         goLJX6EPfwqHnrfJQkDMpnKkbu0YHuvqJ1WPoknpDb/tMd/GvwuizBCKrpwFuu8mjTTO
         Rr3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YBNJ5Su9nNmrqscT9yYTiDPJ+u/9WX9sJZrgHbYE3Ts=;
        b=O+8EooYpKdI1cmS3Go05qxp5LpmRPRcjKz4COqK9alLBG+vAChtQnlF7yHqaGIR2f4
         gOU99uzE+OImHz5fYA82TooZ+3QUsOCtYaAMGKFHmIgGefAmmJ8Zi03fLGU9nnpBgtDd
         YDcgkuvvTGUzarYpI4BBdWR/mXI4NUWSY9wotBg+fPrK8tKGMIwdPdGHCQDNg3dbPiv6
         9EX4uoXboMM/zHJOQb5oGcFNsduk8F4bKfl15WoJzN8rO8EyNZD+hdNtm1T3WZ/EJk6k
         KqxnFyKOsKxZiCQyOIr5HFNPS2DJBc9pE9vc6lsZrJ1fSkkDhQX9ZFYiLvUlf6keIOBz
         TX7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530KXq6c+mqmDlh1JIvkh5wtLaEt9fiBAHN3iwXbCm9DjwFsnXNE
	k/vXe6t8s2zZILIJ0jB8UmM=
X-Google-Smtp-Source: ABdhPJz20s63CRAD0P/3SWyljsly6A4nzFi8Uv6aMfFrc94KjsmGP25ludeJ2o07UoWkJzvD4ylgjQ==
X-Received: by 2002:a17:90a:8b8d:: with SMTP id z13mr8777415pjn.214.1633650168065;
        Thu, 07 Oct 2021 16:42:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1392:: with SMTP id t18ls498399pfg.11.gmail; Thu,
 07 Oct 2021 16:42:47 -0700 (PDT)
X-Received: by 2002:a63:ec06:: with SMTP id j6mr1992945pgh.259.1633650167542;
        Thu, 07 Oct 2021 16:42:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633650167; cv=none;
        d=google.com; s=arc-20160816;
        b=O8rcWlhPDgkfg6+e4Q1UMoyzaEqsQ4i9XHnHeiS+94KxHpAT6GAGvmhv4DwJ5qi4+d
         KRyMdKLnIDsk6rhYnpqqx4OsTYiNbZX+7jYyMCU5siHqhuyHNcPuXAG6NPt8fKzyAiM7
         rFlORCJ67qBF7V4xwudWsKzjjmHcdackEYITXUj7IQ1sbvWh3zvZBVW0qRh4kxa1oPEa
         0g/lMEL5pFPogs/USF4kJruwBOJIGJ8phLeKSwiJPEYRM0Gflg2BpOkEDQSqOzYcjm/V
         y9jYBD6EG85cQS1ss7j/ZshHUNmZkxvyH7+vA1a+OJqxpX2IZlcM0ph/YFWvTVrke4X8
         zG3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=mYTwTQVs0NL7654nsAFjwtWptWQf4ScZhgZgtcuw++4=;
        b=xbaYLZWZNjbsy3lYpeA9twxzyqRre2yUpijGZlMjSQOmOzyIFAQ9KBO/yWvY/NpPlc
         JcT8DY8kD8VsTNt1CFnjrYJTTkN+XoPoS5Y5NGhuilKVfUUCk0WAvDbRxkqSZQXbalHL
         lAuWrZ2XKmXAjFFMOzljkE0sw3zcAd3SEyeLWNF99ssqklcWtjC+wz4sD4faHyGTmKto
         tH+c7ESEG+TK2MEkIU47Jx92rfyWT732nSQLNsZ8zeGVPfHrC/FYQhsWHf455yH03CZw
         JF+fbGmn3cekKkpDdUWmDsIbsWzHAKYUUE8UKl8bfka8vb8vAUc61KlxrfCCWtnSZ4sU
         DrKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MGYwZGwW;
       spf=pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c5si33449pjd.2.2021.10.07.16.42.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Oct 2021 16:42:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 43F906128C;
	Thu,  7 Oct 2021 23:42:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 12EEC5C0870; Thu,  7 Oct 2021 16:42:47 -0700 (PDT)
Date: Thu, 7 Oct 2021 16:42:47 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Gary Guo <gary@garyguo.net>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Marco Elver <elver@google.com>, Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux>
 <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211008000601.00000ba1@garyguo.net>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MGYwZGwW;       spf=pass
 (google.com: domain of srs0=t4ee=o3=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=t4EE=O3=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Oct 08, 2021 at 12:06:01AM +0100, Gary Guo wrote:
> On Thu, 7 Oct 2021 15:30:10 -0700
> "Paul E. McKenney" <paulmck@kernel.org> wrote:
> 
> > For C/C++, I would have written "translation unit".  But my guess is
> > that "Rust module" would work better.
> > 
> > Thoughts?
> 
> Module is not a translation unit in Rust, it is more like C++
> namespaces. The translation unit equivalent in Rust is crate.
> 
> > And the definition of a module is constrained to be contained within a
> > given translation unit, correct?
> 
> Correct.

OK, I now have this:

	Both the unsafe Rust code and the C code can interfere with Rust
	non-unsafe code, and furthermore safe code can violate unsafe
	code's assumptions as long as it is in the same module. However,
	please note that a Rust module is a syntactic construct vaguely
	resembling a C++ namespace, and has nothing to do with a kernel
	module or a translation unit.

Is that better?

> > But what prevents unsafe Rust code in one translation unit from
> > violating the assumptions of safe Rust code in another translation
> > unit, Rust modules notwithstanding?  Especially if that unsafe code
> > contains a bug?
> 
> Unsafe code obviously can do all sorts of crazy things and hence
> they're unsafe :)
> 
> However your article is talking about "safe code can violate unsafe
> code's assumptions" and this would only apply if they are in the same
> Rust module.

Understood.  I was instead double-checking the first clause of that
first sentence quoted above.

> When one writes a safe abstraction using unsafe code they need to prove
> that the usage is correct. Most properties used to construct such a
> proof would be a local type invariant (like `ptr` being a valid,
> non-null pointer in `File` example).
> 
> Sometimes the code may rely on invariants of a foreign type that it
> depends on (e.g. If I have a `ptr: NonNull<bindings::file>` then I
> would expect `ptr.as_ptr()` to be non-null, and `as_ptr` is indeed
> implemented in Rust's libcore as safe code. But safe code of a
> *downstream* crate cannot violate upstream unsafe code's assumption.

OK, thank you.

> > Finally, are you arguing that LTO cannot under any circumstances
> > inflict a bug in Rust unsafe code on Rust safe code in some other
> > translation unit? Or just that if there are no bugs in Rust code
> > (either safe or unsafe), that LTO cannot possibly introduce any?
> 
> I don't see why LTO is significant in the argument. Doing LTO or not
> wouldn't change the number of bugs. It could make a bug more or less
> visible, but buggy code remains buggy and bug-free code remains
> bug-free.
> 
> If I have expose a safe `invoke_ub` function in a translation unit that
> internally causes UB using unsafe code, and have another
> all-safe-code crate calling it, then the whole program has UB
> regardless LTO is enabled or not.

Here is the problem we face.  The least buggy project I know of was a
single-threaded safety-critical project that was subjected to stringent
code-style constraints and heavy-duty formal verification.  There was
also a testing phase at the end of the validation process, but any failure
detected by the test was considered to be a critical bug not only against
the software under test, but also against the formal verification phase.

The results were impressive, coming in at about 0.04 bugs per thousand
lines of code (KLoC), that is, about one bug per 25,000 lines of code.

But that is still way more than zero bugs.  And I seriously doubt that
Rust will be anywhere near this level.

A more typical bug rate is about 1-3 bugs per KLoC.

Suppose Rust geometrically splits the difference between the better
end of typical experience (1 bug per KLoC) and that safety-critical
project (again, 0.04 bugs per KLoC), that is to say 0.2 bugs per KLoC.
(The arithmetic mean would give 0.52 bugs per KLoC, so I am being
Rust-optimistic here.)

In a project the size of the Linux kernel, that still works out to some
thousands of bugs.

So in the context of the Linux kernel, the propagation of bugs will still
be important, even if the entire kernel were to be converted to Rust.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007234247.GO880162%40paulmck-ThinkPad-P17-Gen-1.
