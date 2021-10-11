Return-Path: <kasan-dev+bncBDRZHGH43YJRBYEYR2FQMGQEVZTKP7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 4CC8B42846B
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 02:59:13 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id k17-20020ab04d51000000b002c056f4f643sf7321216uag.21
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 17:59:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633913952; cv=pass;
        d=google.com; s=arc-20160816;
        b=hy4I3D7UobCd/310UAXxBJVTp/gj+yVgge14cQs5DfsVUA2l83/s0imOOq+5n1HMsW
         4WRgsJmHXtFiCAZKf+9+CW829vgMFjFEZIgV7V14QVryUX6sIyXkOWRI07W+AbmdddvX
         XVFGzR3gvLdUsoFLr3pzvpNpmQYQApcFnRvU6kqnOwgCV2AbpuI8m8h2DvehiPXLNLrH
         005+u4Y6z6YGzmrbN9ERdtjsAall3j1+hYYysVre1MGrZmLqTRWIXLSZyQz988KQ8yEI
         HMwQ4XunaSG1ywz90e5qke83FJHGtyTYdKwC7xpm4IUcivFv6KsY8UydjgmUiI1zIP18
         mInA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=X4PbCpp2xPf7l6I9Jmyl9+Sg9m+v3J2ZW78eHldVPQc=;
        b=gmhIHohMMB26bZ0ZBwH/qHr7X86wZkEXZSGkOIFQbHUZBBYGoOdLoc5RX/rDWCsILz
         n84JB6XRkwZC9MWLukfKZtzToC8LHnnjdE0FPQflGySDXZRswgJUXwW3IaNbJP9k7bRX
         Lu7xQh5Gydj1KXnAi0cU1M7dttZ+5JrHB68NmBHoQw9zYER3XlkJTpSRGlErvGTAFVgb
         TDA4RU5O1HDm/X21ZVT6J5C3hIGprMRu0b7oDkiSx/JlkT/5rngNN5NaZkJD3HrYQFEm
         TJNFqo+x9O/3Z9Gm0t2KXk4dJrQI4GTIaUH2j81ykVWX4yXBjRPAZSlXob1zty/71UE7
         TN/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WER49xjJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X4PbCpp2xPf7l6I9Jmyl9+Sg9m+v3J2ZW78eHldVPQc=;
        b=rI4i+zPl5ZgnTX0LUpgV9uT6KlxnBm0CxtAFC3erR5JmK3e9R3hOBFBx9e+W08afGt
         znvcICbcNMKp6kFJPR/cnErEEm83VlKcngyw0fFqUnwTGYQRh5P0AJZGEfiMzO5/8GZl
         97wQrd7ZCcJknuFz2F/FStD6ihbxQDi3PJiu6nyCgosY/KWrINPBQunLXuzrTtiaUJ3m
         NgMNM6hXTHxspGso/F7nZ8MK8iDqXiROBct1q1lhbvjQNoi+IpX3qQfbJm8b8T2wCFw7
         FUMV+zF/fwSZTPK2SvDygTlQIcMFLTxNaKA5NUmIHFTcFlKb1gxujFlejOEHIvLse8d7
         H+5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X4PbCpp2xPf7l6I9Jmyl9+Sg9m+v3J2ZW78eHldVPQc=;
        b=BWswG+9fLJWzri+xZU0OAy9fDjkNNKd6Vvjg3JllYdtBsu6NAieOWtQGY+1zQP/cPN
         IdHyua9p55aMQHlJYUqgcvgPr4pMdWBmHFJofbkin7L2kFHbZq9EduQLkXw0zYCoYHir
         J7vY5FPf5qz/HToU8TRsOqvtglVrhtVXXChKWd/aGSJ1Vd0nQoeto4IurOlAyy43yY94
         rou01fTx3GLfMARxODFUQijQkOQRsXoieounN1mJYu+stt/godx2dQDwNuniyOdE1iJb
         czjlPdD0GDikQpCX3jnYsR+HEYkYsvyZOszONsS+VGFN9/x0ZRs/tULBf3MPD0pzvRE2
         Z6+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X4PbCpp2xPf7l6I9Jmyl9+Sg9m+v3J2ZW78eHldVPQc=;
        b=dwSXGZj0Lh1iwzPFZBmyUbDOzC0xXzYePSRKZQsUsK7zhTeXsFATCOrQWgco9LE7uf
         1OmV89QX1uXFTdlikeeT0fFEhui6h5wIBTyTEO7GIY5hWNh4oXk1ubWbltcBmXHKe6si
         XKRb3J2Hblja221ELPtkfM3C8xFCJ1Knag4scIsHLvKl9z0WnGmejlA2O7iA98ali1wJ
         EAz7G6HRlQlyeKrMexcCh1FgwYMj5WK0czn3agCmImke/8NIDXsnoPNP9Dfm/n5EdRFq
         Mi3OqEfOC2xJ0QhWp11R7MykM0bFpQSEksrBedb1m2zBsO8SB1oOWPiqJOSIzKgE9aBf
         S5yw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530evwLO+wZOKb59aYJYS01xDGh6/HyBinB1wsfGOPf52THgKWP2
	jfNh+ghofOOzlgh5NTvC8Oo=
X-Google-Smtp-Source: ABdhPJyZLf3kB8VnuDQssPkqpUPeHNBNOYR5XZfyRS3irfxNB9995Zs3Y7/c4kc8BbsG+NjsQOBlXA==
X-Received: by 2002:a1f:e946:: with SMTP id g67mr17997107vkh.10.1633913952136;
        Sun, 10 Oct 2021 17:59:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ae4a:: with SMTP id u10ls2109471vsh.4.gmail; Sun, 10 Oct
 2021 17:59:11 -0700 (PDT)
X-Received: by 2002:a67:d79c:: with SMTP id q28mr20615283vsj.29.1633913951571;
        Sun, 10 Oct 2021 17:59:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633913951; cv=none;
        d=google.com; s=arc-20160816;
        b=ZoiJRkJt98fDodmZB2UsQ3Szxnex3QXuxCbwNl2E5dCPdI+zygg+6RTDgXwGBglao4
         O3D/eefxodJ7g0P3Ig4APohmrSbVtuuf8sta8+a0BM4rLyEPrNahnCVIopEbRYUl6ly/
         e2aGUXZhKMrVTLX8CypUJppm8N8B8gGL1RQNGfumvoUwObRbwG3CMshd4GyQLveRlpzB
         11pSDo7DBgVChB/SvVk4EeBISF3gaOC0XWgnbDcCp3NtlrQykun9rqAM8ol+S/9bbF+I
         kY1wcvws5MvZ0/wML8Vz1fdvDLAv1ZAOF7JPbpoPqM79iGk/QGkZqso1w6+B9ae6a30R
         cDGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kg1lM2jGKX12em01lUkwgIGQjeOxXQjzNmMLAv0o5ho=;
        b=k27Xup7QpH0meVPjKklrtjHwRAJzIgOUgf1BTc4RgG0ZVf2XFVjkhLFHse4/pGMzYz
         4oPTZQDd1WM0FWPrCKwr9/gsTn72Az7/YvgPSCcYRiP+qzeOKTXBTBTivXbXOfwiexdg
         +lgUDa+ncWuzftJi8QqBns/Ju+8H72LnDgzW6db6htK99I1Y93heJS2ZFeWfzYzDwYuM
         x7k2Gsjbb57oVE8Vp8wntxtadc8j5cClZyP6rTvkcyB5Lpj7bYCE1NYUTiBaV9fOn6mX
         qVuz4ssTnGoEtO2jhJdVMHAVJH84TDFrExwv11LSKhwO1BKEV8cQlwjS1Whyj4tUdf1b
         q8hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=WER49xjJ;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id u23si532268vsn.2.2021.10.10.17.59.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Oct 2021 17:59:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id r134so6625414iod.11
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 17:59:11 -0700 (PDT)
X-Received: by 2002:a05:6638:14d0:: with SMTP id l16mr16766540jak.142.1633913951248;
 Sun, 10 Oct 2021 17:59:11 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1> <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1> <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
 <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Mon, 11 Oct 2021 02:59:00 +0200
Message-ID: <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=WER49xjJ;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Sun, Oct 10, 2021 at 1:48 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> As long as a significant number of compiler writers evaluate themselves by
> improved optimization, they will be working hard to create additional UB
> opportunities.  From what you say above, their doing so has the potential

Compiler writers definitely try to take advantage of as much UB as
possible to improve optimization, but I would not call that creating
additional UB opportunities. The opportunities are already there,
created by the standards/committees in the case of C and the
RFCs/teams in the case of unsafe Rust.

Of course, compiler writers may be stretching too much the intention
and/or ambiguities, and there is the whole discussion about whether UB
was/is supposed to allow unbounded consequences which WG14 is
discussing in the recently created UBSG.

But I touch on this to emphasize that, even in unsafe Rust, compiler
writers are not completely free to do whatever they want (even if they
completely disregarded their users and existing code bases) and that
C/unsafe Rust also share part of the responsibility (as languages) to
define clearly what is allowed and what is not. So unsafe Rust is in a
similar position to C here (though not equal).

> to generate bugs in the Rust compiler.  Suppose this happens ten years

I am not sure what you mean by bugs in the Rust compiler. If the
compiler is following what unsafe Rust designers asked for, then it
wouldn't be a bug. Whether those semantics are what we want as users,
of course, is a different matter, but we should talk in that case with
the language people (see the previous point).

> from now.  Do you propose to force rework not just the compiler, but
> large quantities of Rust code that might have been written by that time?

No, but I am not sure where you are coming from.

If your concern is that the unsafe Rust code we write today in the
kernel may be broken in 10 years because the language changed the
semantics, then this is a real concern if we are writing unsafe code
that relies on yet-to-be-defined semantics. Of course, we should avoid
doing that just yet. This is why I hope to see more work on the Rust
reference etc. -- an independent implementation like the upcoming GCC
Rust may prove very useful for this.

Now, even if we do use subtle semantics that may not be clear yet,
upstream Rust should not be happy to break the kernel (just like ISO C
and GCC/Clang should not be). At least, they seem quite careful about
this. For instance, when they consider it a need, upstream Rust
compiles and/or runs the tests of huge amounts of open source
libraries out there [1] e.g. [2]. It would be ideal to have the kernel
integrated into those "crater runs" even if we are not a normal crate.

[1] https://rustc-dev-guide.rust-lang.org/tests/intro.html#crater
[2] https://crater-reports.s3.amazonaws.com/beta-1.56-1/index.html

> The thing is that you have still not convinced me that UB is all that
> separate of a category from logic bugs, especially given that either
> can generate the other.

Logic bugs in safe Rust cannot trigger UB as long as those conditions
we discussed apply. Thus, in that sense, they are separate in Rust.

But even in C, we can see it from the angle that triggering UB means
the compiler output cannot be "trusted" anymore (assuming we use the
definition of UB that compiler writers like to use but that not
everybody in the committee agrees with). While with logic bugs, even
with optimizations applied, the output still has to be consistent with
the input (in terms of observable behavior). For instance, the
compiler returning -38 here (https://godbolt.org/z/Pa8TWjY9a):

    int f(void) {
        const unsigned char s = 42;
        _Bool d;
        memcpy(&d, &s, 1);
        return d ? 3 : 4;
    }

The distinction is also useful in order to discuss vulnerabilities:
about ~70% of them come from UB-related issues [1][2][3][4].

[1] https://msrc-blog.microsoft.com/2019/07/18/we-need-a-safer-systems-programming-language/
[2] https://langui.sh/2019/07/23/apple-memory-safety/
[3] https://www.chromium.org/Home/chromium-security/memory-safety
[4] https://security.googleblog.com/2019/05/queue-hardening-enhancements.html

> Hence the Rust-unsafe wrappering for C code, presumably.

Yes, the wrapping uses unsafe code to call the C bindings, but the
wrapper may expose a safe interface to the users.

That wrapping is what we call "abstractions". In our approach, drivers
should only ever call the abstractions, never interacting with the C
bindings directly.

Wrapping things also allows us to leverage Rust features to provide
better APIs compared to using C APIs. For instance, using `Result`
everywhere to represent success/failure.

> This focus on UB surprises me.  Unless the goal is mainly comfort for
> compiler writers looking for more UB to "optimize".  ;-)

I could have been clearer: what I meant is that "safety" in Rust (as a
concept) is related to UB. So safety in Rust "focuses" on UB.

But Rust also focuses on "safety" in a more general sense about
preventing all kinds of bugs, and is a significant improvement over C
in this regard, removing some classes of errors.

For instance, in the previous point, I mention `Result` -- using it
statically avoids forgetting to handle errors, as well as mistakes due
to confusion over error encoding.

> It will be interesting to see how the experiment plays out.  And to
> be sure, part of my skepticism is the fact that UB is rarely (if ever)
> the cause of my Linux-kernel RCU bugs.  But the other option that the

Safe/UB-related Rust guarantees may not useful everywhere, but Rust
also helps lowering the chances of logic bugs in general (see the
previous point).

> kernel uses is gcc and clang/LLVM flags to cause the compiler to define
> standard-C UB, one example being signed integer overflow.

Definitely, compilers could offer to define many UBs in C. The
standard could also decide to remove them, too.

However, there are still cases that C cannot really prevent unless
major changes take place, such as dereferencing pointers or preventing
data races.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72%3DuPFMbp%2B270O5zTS7vb8xJLNYvYXdyx2Xsz5%2B3-JATLw%40mail.gmail.com.
