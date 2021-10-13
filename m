Return-Path: <kasan-dev+bncBDRZHGH43YJRBY4OTOFQMGQETVNLY5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 3327842BF2C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 13:47:50 +0200 (CEST)
Received: by mail-ua1-x939.google.com with SMTP id q2-20020a9f3842000000b002c9f4b7ede2sf1165628uad.10
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 04:47:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634125669; cv=pass;
        d=google.com; s=arc-20160816;
        b=BJzKTQLKIwvklVj0idmjqt4N2v/NVDSdIVgItiT/L4LWnXG8+aTXOTfzy5JSOVUj+5
         VqPsVQOmd4/OJH4W3BT8Uy1dZeCKL0n0mYwAYubS76KHpIJViSOFdhLB8DgEGOpWumb0
         QOH0UI9j3NiHd981kKDegUBxK7zsq/4MUvNPLw7BC109GPrOEZHTxgvHVRE/YOulSc2G
         kRNQVcNRC3iLdSAr2AwWikIY/Szd1qhTM2e4795N44HRBYkEPNLpPBxLCF7yENTMw6QI
         4PrPaqgc/kGsqYNeWm8cWETp62L2ixgmKeXAqvpTQ6Yyf0UEWxLFpgF39ZmE5y7Hgqb4
         t4Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rjLFbLzRX4VM63m/n21She+ia0ayzWl2VDpvQf2/86s=;
        b=Soj1UX78TKkJ7d4qx2UXwXyRFTJGvx27mBhCs+soxi/KjJIRBDW6YYRmEj1/4HjZLK
         eB1+uc4dBfM94fpKypauvhW2d6wDtKTKIUZTfsHhpwdcysAXnd9OOgct35pa+35cOhlo
         psBEIc8doHcXvjWjS8qijXjZV47Xvmp0H8FgGrrnBflVHkWw6sVAF3l4ZfpyVUrRmbxX
         rqc4EJrvPPeFrwQ1aZFO9v2DlZoE1ZRt3R5cFtYMz1l1B8ko8cq4un61ZSJOx9fahrog
         Z63DLShdvgHYDgfW3MGOoQW1UVXvzuC4Dkd3Nu8q13qy/ahzIEZ8mFdwPBe6v1LPl67B
         v5Dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UyxQKE97;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rjLFbLzRX4VM63m/n21She+ia0ayzWl2VDpvQf2/86s=;
        b=ElzuV5A/vYvRW9MeVekqxtJmbJHST4hIM7XRQRdto1J7/UqmTgP+eKTWdJvTBBtYN/
         QLffJXyIADI2AqkEYNlDdLgcm9+5MkzFlSu9ykoF6W+H+DgSSNeHV3vDJIaU4Oc8PS1w
         sHfWvmPZawIKUFDUsYYp6O9shaJnd01kLBm2lnqIBFMzUS/Ca7q/kPfppLfa75aDLyWW
         rPuQUMkdgMMJMYpCm9riSJUv2ucFvtJLIaVdA04vkbZITmJNGSPRqJ6gsyzmulPoC5Sk
         gpAjvf4S0QNMf3vtT82XHutx73rCZqvuNeyrmgZROf5u6gPMbQRKterz/FCYxAe/l6Js
         nO3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rjLFbLzRX4VM63m/n21She+ia0ayzWl2VDpvQf2/86s=;
        b=b/nITk3/+WeTkvRUWXfbRsnVz626WyDtwN/K1mG+FGIicRJj0gFDP3aSvetu/gWbPs
         WmC7rNhqc43nTJ7Funiu0NrfcX5TaVN5ExIaPCcwrDerkCiEsUPy6xzTuwTVuuQ90ycI
         WpRf8Yk6uObA+ytbLx9P8pHJV/Yl5nUCM8VLipKZG/fRik9nGsM1zdZ9JIHpx+CfeLzg
         5iEmX8p6/vWDrB//Omw67vFsSj/wG6EfVa+B34+BrDdpWIA++7apASrISEJVBB983xBn
         yXyOz7DJCyME4/vyBIBdvzpcfYatuoorPfGE3/TacLskr5+ExrLYNGS4/yJ5XA4Y0OOQ
         gPGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rjLFbLzRX4VM63m/n21She+ia0ayzWl2VDpvQf2/86s=;
        b=oTnYfXXhKC4VJOdpNfc3S997lOpoNBdWD22MjhOsMUD7txXPJ3ut42YFxJVStKIsyC
         cQzOEz2jnopKjdGeW2tR/kYe7MGqUhGt8ZDQfXiA+78yYOZfCv5n3RLeOON9PTsQhaTE
         aeZR3ctQsJm5hiAJk4IbkYOPW4g497Hh1YKyqTBS/SiduhHxNEHb38MBu6/NuM5B/KeK
         fGNg89w1Sk+JLMeAYeWZWuvl8fGjxWLt9xQtpWUULivRR7xTP5BXIKKQbdXMUzLfQ4xB
         Qc2aiu2D8zD+rqLcYl4dSvVZMLwLMMz96qK6fcWJwf305zdRZHUIcoRchCR4rOQmITNB
         4dxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QWC6pvSszBQVfKcF8lnXEoIDwH9mpwKol/rcveUtHxytNUyog
	492Skg51n6zOt/VPAAxrpKc=
X-Google-Smtp-Source: ABdhPJy1UmlpIPGd1js671iA0cM+TGlwNt7u3jSxNOPzXo8Ed7Q8RqjuRndFSEOE+YFW8PpPt0jURw==
X-Received: by 2002:a67:2285:: with SMTP id i127mr37651143vsi.57.1634125667449;
        Wed, 13 Oct 2021 04:47:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2405:: with SMTP id k5ls227292vkk.1.gmail; Wed, 13 Oct
 2021 04:47:46 -0700 (PDT)
X-Received: by 2002:a1f:3448:: with SMTP id b69mr22695042vka.10.1634125666636;
        Wed, 13 Oct 2021 04:47:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634125666; cv=none;
        d=google.com; s=arc-20160816;
        b=0CLUXYEqAxVi0vzKlPdHnWrYkKQk4pW53kZ9s2bboVilfuJXiXUNTI+Wo/bjVhItDP
         e0MoP4bD0mVB1g0y+SKugjauBg1IJ5h633kyu18gjMPtpLJ2z3uOlDifRq3/bk14gUoP
         y0Y7ScgHt6s/vMpZ9e0A7kPMUVKm+m8jLGdMmQwHiCCjqddpLnMO7BKRbrzO0XaySBXK
         tg+Wqm/I5L2cw8bBqw4ZkK58RA60Ef11Zo3MVwb/QIrWJksc5a31fk7RPahkHQvufh7L
         Bju5941CJG3u5L/r1lVhrx3XJgGOMvtO+kKl/rlbNBhY7tc7n6+63cVbOj9SjFfevtAn
         CbVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WNpZ64Dfc3sW2fQ35x9beQ3WXpgO0Vr7YbM8MXV6/e0=;
        b=JAXu7rW/VtrhNaELNYp8cD+SrtgCwmFaBdSXJGhfFAMeTEVQyX6stGqsvjxxkY4gEx
         QgnnFSB9y9N/BG1yZ9xa3wOnkhPb7ApCYWHcUO7H6Vfx3okGbNF9eHJiPTvxfjTLd+aZ
         9KdUo8vyWoWhoicXTfya3TPEp7ZlMO+GAj4jRaXDfZrVyDuKZy9kQnpfs76s7b3efP3R
         bY8jlPOqw1XEQ3M1lkD0vMibqspnHlnO3cXH9I7w5Isd4nryuxSttdyzGRUOzT7OvBJK
         JYPuY8MdiXnbJf0YGeuVdn0uTfAT9Xj9RLh0TOIPU3dMuzUPk/OWd2paswK4d1dG89hH
         uLoA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UyxQKE97;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id c19si575856uad.1.2021.10.13.04.47.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Oct 2021 04:47:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id k3so2387582ilu.2
        for <kasan-dev@googlegroups.com>; Wed, 13 Oct 2021 04:47:46 -0700 (PDT)
X-Received: by 2002:a05:6e02:1543:: with SMTP id j3mr10881842ilu.151.1634125666291;
 Wed, 13 Oct 2021 04:47:46 -0700 (PDT)
MIME-Version: 1.0
References: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net> <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net> <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
 <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
 <20211011185234.GH880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211011185234.GH880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Wed, 13 Oct 2021 13:47:34 +0200
Message-ID: <CANiq72k+wa8bkxzcaRUSAee2btOy04uqLLnwY_AsBfd2RBhOxw@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UyxQKE97;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Mon, Oct 11, 2021 at 8:52 PM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> I am sorry, but I have personally witnessed way way too many compiler
> writers gleefully talk about breaking user programs.

Sure, and I just said that even if compiler writers disregarded their
users, they are not completely free to do whatever they want.

> And yes, I am working to try to provide the standards with safe ways to
> implement any number of long-standing concurrent algorithms.  And more
> than a few sequential algorithms.  It is slow going.  Compiler writers are
> quite protective of not just current UB, but any prospects for future UB.

I am aware of that -- I am in WG14 and the UBSG, and some folks there
want to change the definition of UB altogether to prevent exactly the
sort of issues you worry about.

But, again, this is a different matter, and it does not impact Rust.

> Adducing new classes of UB from the standard means that there will be
> classes of UB that the Rust compiler doesn't handle.  Optimizations in
> the common compiler backends could then break existing Rust programs.

No, that is conflating different layers. The Rust compiler does not
"handle classes of UB" from the C or C++ standards. LLVM, the main
backend in rustc, defines some semantics and optimizes according to
those. Rust lowers to LLVM, not to C.

Now, sure, somebody may break LLVM with any given change, including
changes that are intended to be used by a particular language. But
that is arguing about accidents and it can happen in every direction,
not just C to Rust (e.g. Rust made LLVM fix bugs in `noalias` -- those
changes could have broken the C and C++ compilers). If you follow that
logic, then compilers should never use a common backend. Including
between C and C++.

Furthermore, the Rust compiler does not randomly pick a LLVM version
found in your system. Each release internally uses a given LLVM
instance. So you can see the Rust compiler as monolithic, not
"sharing" the backend. Therefore, even if LLVM has a particular bug
somewhere, the Rust frontend can either fix that in their copy (they
patch LLVM at times) or avoid generating the input that breaks LLVM
(they did it for `noalias`).

But, again, this applies to any change to LLVM, UB-related or not. I
don't see how or why this is related to Rust in particular.

> Or you rely on semantics that appear to be clear to you right now, but
> that someone comes up with another interpretation for later.  And that
> other interpretation opens the door for unanticipated-by-Rust classes
> of UB.

When I say "subtle semantics that may not be clear yet", I mean that
they are not explicitly delimited by the language; not as in
"understood in a personal capacity".

If we really want to use `unsafe` code with unclear semantics, we have
several options:

  - Ask upstream Rust about it, so that it can be clearly encoded /
clarified in the reference etc.

  - Do it, but ensure we create an issue in upstream Rust + ideally we
have a test for it in the kernel, so that a crater run would alert
upstream Rust if they ever attempt to change it in the future
(assuming we manage to get the kernel in the crater runs).

  - Call into C for the time being.

> All fair points, but either way the program doesn't do what its users
> want it to do.

Sure, but even if you don't agree with the categorization, safe Rust
helps to avoid several classes of errors, and users do see the results
of that.

> OK, I will more strongly emphasize wrappering in my next pass through
> this series.  And there does seem to have been at least a few cases
> of confusion where "implementing" was interpreted by me as a proposed
> rewrite of some Linux-kernel subsystem, but where others instead meant
> "provide Rust wrappers for".

Yeah, we are not suggesting to rewrite anything. There are, in fact,
several fine approaches, and which to take depends on the code we are
talking about:

  - A given kernel maintainer can provide safe abstractions over the C
APIs, thus avoiding the risk of rewrites, and then start accepting new
"client" modules in mostly safe Rust.

  - Another may do the same, but may only accept new "client" modules
in Rust and not C.

  - Another may do the same, but start rewriting the existing "client"
modules too, perhaps with aims to gradually move to Rust.

  - Another may decide to rewrite the entire subsystem in Rust,
possibly keeping the C version alive for some releases or forever.

  - Another may do the same, but provide the existing C API as
exported Rust functions.

In any case, rewrites from scratch should be a conscious decision --
perhaps a major refactor was due anyway, perhaps the subsystem has had
a history of memory-safety issues, perhaps they want to take advantage
of Rust generics, macros or enums...

> I get that the Rust community makes this distinction.  I am a loss as
> to why they do so.

If you mean the distinction between different types of bugs, then the
distinction does not come from the Rust community.

For instance, in the links I gave you, you can see major C/C++
projects like Chromium and major companies like Microsoft talking
about memory-safety issues.

> OK.  I am definitely not putting forward Linux-kernel RCU as a candidate
> for conversion.  But it might well be that there is code in the Linux
> kernel that would benefit from application of Rust, and answering this
> question is in fact the point of this experiment.

Converting (rather than wrapping) core kernel APIs requires keeping
two separate implementations, because Rust is not mandatory for the
moment.

So I would only do that if there is a good reason, or if somebody is
implementing something new, rather than rewriting it.

> The former seems easier and faster than the latter, sad to say!  ;-)

Well, since you maintain that compiler writers will never drop UB from
their hands, I would expect you see the latter as the easier one. ;)

And, in fact, it would be the best way to do it -- fix the language,
not each individual tool.

> Plus there are long-standing algorithms that dereference pointers to
> objects that have been freed, but only if a type-compatible still-live
> object was subsequently allocated and initialized at that same address.
> And "long standing" as in known and used when I first wrote code, which
> was quite some time ago.

Yes, C and/or Rust may not be suitable for writing certain algorithms
without invoking UB, but that just means we need to write them in
another language, or in assembly, or we ask the compiler to do what we
need. It does not mean we need to drop C or Rust for the vast majority
of the code.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72k%2Bwa8bkxzcaRUSAee2btOy04uqLLnwY_AsBfd2RBhOxw%40mail.gmail.com.
