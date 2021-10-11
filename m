Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5EPSKFQMGQEHICCIII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9FA429726
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 20:52:37 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id t2-20020a05620a450200b0045e34e4f9c7sf14665755qkp.18
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 11:52:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633978356; cv=pass;
        d=google.com; s=arc-20160816;
        b=wOx8Pr43OWxPW0ELojnw5w2nBAGSuDOMuXu9jCic5OK1yTI3y0ut3t/F/t+OiGTnAk
         7jjJU8jZmnEcl+bZHz8ZGLLCg+Z7TSigJ7mUkDffsXkaqVk04MjL316lNB0NSGX7+6OG
         t7i+v1f/zmqTOfBoNdXqI+uMsBvUnGjtMOQGcbcu6V0vCgnbgbP7AVdRuUgVyD3S+4pU
         qz4YnuiitW/FnqgFBSQDynSUz8GX7xVPV7hKaTyeoR7OXGQuMw+6/kka/go2rGIMXKkh
         zgw045h08LvitnSCPCCybt4Lu72LmxC2aHATFpG3qcjW9sMJPe2EYJsj8H0RdfoAeBA6
         UKMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=cDwt4aavDpVSZymTQTJl0huuM/GbUztovam/9RNN16w=;
        b=A1aisrTh+BefBtosxtbEKEKLtXGxGMGiu2uhM9YOd+Xn5d8zvvluQOYUm9VLfWbwoL
         PjaDQ4VAjIr950KcwiXRSzpdvdRINqne5ww7x0frYNxhiDiA3+4EU1wqvuApOPlOYR9w
         4mDVyvwcZeJmgsbAkk8dM8gtJtxYQGc92SB3iNGkAW237RHOJA3MU2JrefSj9yT8lpek
         lnFSQT4WSArl8b5VIxVhDbrU50iJx8XeOlK5NziAHv9q/tzNz00cpHnQnC9S4K5FvnRc
         +Xx5hbOgRc7h2ZTPwEj2fEpsY8S0aubhVRSWZ3LJdFjHLPbseUgcjafbSA0lMSbHw1a5
         IEjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fUN0V38b;
       spf=pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cDwt4aavDpVSZymTQTJl0huuM/GbUztovam/9RNN16w=;
        b=K4kYtandoOnXrc1o4+byJyQMe2zihqYqqOry8k/0J1fGeGbBkh/+7l/Wf/+7fr24pa
         /T59aouT2BiGqtR1UC3ZwzXiH6kfDCy/sbuEof0MPWyIlfXD6JOqh23XCUUkedI8jU79
         3uC6fKtiKWQ9C5c8nk+Ti8EKK9tE2EDPcegUnw8OZcX0cAnUiheOENJIhtkAKx/5TbEY
         yd/DFhE/0xSUibTQWOV05Q/R2C3Kio6pYQGGA/7+OQraJmvxl3hXGYSzEQ67Jtz+pKE0
         TdefXLZRi5RlxaLyUi8+YE5qxT/YXz7SXOEDYm8yQ4CSAulFOPLg8uhRV/yUblKoiaMv
         DKpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=cDwt4aavDpVSZymTQTJl0huuM/GbUztovam/9RNN16w=;
        b=wbHf2nNgNxXaueAuaQVnKEidFUsasmWvGOtOmbVaWV7vpwtlpptYLZA0mheSEZNRTN
         TFqhs6skRN5eZEqmC6uWsshdLoQJ22A2ZKCwguO0PHBDyE34Nux6SaOLCv/nK8k//6VE
         ZcI7dmjvUdTrLsBwhBE9MQvBGxiOQol9ECogzAe5Fa8I93K/4rRIAXOJk+WjDc47GWdF
         tmi4kg/2VOG2dAtc5TxgopqmAC0dGb6KiqD66DoMpSh5kPyYarQqQbI82qapqrCZtVG6
         AiHFTn7rz9j0rRqJouQz9K9yO+aPSX7SCIC6kQ1qWM1C2gyb20DW4UXiaIt9q6G7bDpg
         gbEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y17xwuLH8oLEkX++yCXj8h1FUr/4WZZz7YyOtSPnHNqX25Upj
	lVgvybtrGHDWSusynDZZ2N8=
X-Google-Smtp-Source: ABdhPJw5kmfMeVFqVGf1AOABE46uoD/FoznVNPZs1/qGpKss3vS7Z+PBrQIy2uTdb8kWkryoEa1c1Q==
X-Received: by 2002:ac8:610f:: with SMTP id a15mr16787661qtm.387.1633978356096;
        Mon, 11 Oct 2021 11:52:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:24b:: with SMTP id o11ls6241366qtg.0.gmail; Mon, 11 Oct
 2021 11:52:35 -0700 (PDT)
X-Received: by 2002:a05:622a:1652:: with SMTP id y18mr16951163qtj.226.1633978355629;
        Mon, 11 Oct 2021 11:52:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633978355; cv=none;
        d=google.com; s=arc-20160816;
        b=e04FJHGscSg4rs1fdI23N+SNxpGKEx4x+pNLafryYR7KBkazz/OYEVEf1XFLsgKlBE
         S21XZe75zX5pY9t5F+fcZfwqa1sWkGoZV8PS36/LzhZlk13jyClyRJQB4nLuCjjpgSyY
         LEeXFnfWvGyn9W/U4Y15vQ8YKjsZCXCL7nouUespzj8MWaTaksUHPZl2QSoRRDbcQihL
         zSbbxaWaxwnS9/6tjm5V7OcVi2oEwDBUpeDoB82yaRgw3Of8rsv/dpZtk9wpsrKomqiZ
         tYfmOPT6vQKRtILu6vtoYo7p2U+jia6WlozqivGg0EFD/p2knmQ8xcsEjB4hZT/N5/DC
         VaOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wNSUasnYbiScQfryvjk2HATgZpn9Av3d4EJksbCMDbM=;
        b=BgtwPOSy02L/1mpxLfajlwLQ/twwH9kUUX2py6u0JZAhJ/z5LIXI76pUV02ndIrk4l
         c3DAPISyprjhRDBm3pjWQZeNYXZYsL/rHLXgbj29AmOpQzHykdXaHgfTWL/bOeKrXoaF
         FIUg0UIt+vZLMFSXiNXZqenDKsPI8Bv7KD/T5VrvAc50UA7itQfovp/8mHLNAwf4CQ3F
         GtQwG31aX/FMbbGYcPBe8snKF6CCSrvNkCabrE0MniWphd2qBtxSraBYYbJm660HcXse
         YgYXpeQEWH5qQRjg+XkTCEp09zjdYVlGe/INz2TlXViqfZjhI5gcF5p2zzaNfFiN4XZI
         p98A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fUN0V38b;
       spf=pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b8si989065qtg.5.2021.10.11.11.52.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Oct 2021 11:52:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8AD0760F23;
	Mon, 11 Oct 2021 18:52:34 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 498AD5C0687; Mon, 11 Oct 2021 11:52:34 -0700 (PDT)
Date: Mon, 11 Oct 2021 11:52:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <20211011185234.GH880162@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1>
 <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
 <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fUN0V38b;       spf=pass
 (google.com: domain of srs0=rhci=o7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=rHcI=O7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Oct 11, 2021 at 02:59:00AM +0200, Miguel Ojeda wrote:
> On Sun, Oct 10, 2021 at 1:48 AM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > As long as a significant number of compiler writers evaluate themselves by
> > improved optimization, they will be working hard to create additional UB
> > opportunities.  From what you say above, their doing so has the potential
> 
> Compiler writers definitely try to take advantage of as much UB as
> possible to improve optimization, but I would not call that creating
> additional UB opportunities. The opportunities are already there,
> created by the standards/committees in the case of C and the
> RFCs/teams in the case of unsafe Rust.
> 
> Of course, compiler writers may be stretching too much the intention
> and/or ambiguities, and there is the whole discussion about whether UB
> was/is supposed to allow unbounded consequences which WG14 is
> discussing in the recently created UBSG.
> 
> But I touch on this to emphasize that, even in unsafe Rust, compiler
> writers are not completely free to do whatever they want (even if they
> completely disregarded their users and existing code bases) and that
> C/unsafe Rust also share part of the responsibility (as languages) to
> define clearly what is allowed and what is not. So unsafe Rust is in a
> similar position to C here (though not equal).

I am sorry, but I have personally witnessed way way too many compiler
writers gleefully talk about breaking user programs.

And yes, I am working to try to provide the standards with safe ways to
implement any number of long-standing concurrent algorithms.  And more
than a few sequential algorithms.  It is slow going.  Compiler writers are
quite protective of not just current UB, but any prospects for future UB.

> > to generate bugs in the Rust compiler.  Suppose this happens ten years
> 
> I am not sure what you mean by bugs in the Rust compiler. If the
> compiler is following what unsafe Rust designers asked for, then it
> wouldn't be a bug. Whether those semantics are what we want as users,
> of course, is a different matter, but we should talk in that case with
> the language people (see the previous point).

Adducing new classes of UB from the standard means that there will be
classes of UB that the Rust compiler doesn't handle.  Optimizations in
the common compiler backends could then break existing Rust programs.

> > from now.  Do you propose to force rework not just the compiler, but
> > large quantities of Rust code that might have been written by that time?
> 
> No, but I am not sure where you are coming from.
> 
> If your concern is that the unsafe Rust code we write today in the
> kernel may be broken in 10 years because the language changed the
> semantics, then this is a real concern if we are writing unsafe code
> that relies on yet-to-be-defined semantics. Of course, we should avoid
> doing that just yet. This is why I hope to see more work on the Rust
> reference etc. -- an independent implementation like the upcoming GCC
> Rust may prove very useful for this.
> 
> Now, even if we do use subtle semantics that may not be clear yet,
> upstream Rust should not be happy to break the kernel (just like ISO C
> and GCC/Clang should not be). At least, they seem quite careful about
> this. For instance, when they consider it a need, upstream Rust
> compiles and/or runs the tests of huge amounts of open source
> libraries out there [1] e.g. [2]. It would be ideal to have the kernel
> integrated into those "crater runs" even if we are not a normal crate.
> 
> [1] https://rustc-dev-guide.rust-lang.org/tests/intro.html#crater
> [2] https://crater-reports.s3.amazonaws.com/beta-1.56-1/index.html

Or you rely on semantics that appear to be clear to you right now, but
that someone comes up with another interpretation for later.  And that
other interpretation opens the door for unanticipated-by-Rust classes
of UB.

> > The thing is that you have still not convinced me that UB is all that
> > separate of a category from logic bugs, especially given that either
> > can generate the other.
> 
> Logic bugs in safe Rust cannot trigger UB as long as those conditions
> we discussed apply. Thus, in that sense, they are separate in Rust.
> 
> But even in C, we can see it from the angle that triggering UB means
> the compiler output cannot be "trusted" anymore (assuming we use the
> definition of UB that compiler writers like to use but that not
> everybody in the committee agrees with). While with logic bugs, even
> with optimizations applied, the output still has to be consistent with
> the input (in terms of observable behavior). For instance, the
> compiler returning -38 here (https://godbolt.org/z/Pa8TWjY9a):
> 
>     int f(void) {
>         const unsigned char s = 42;
>         _Bool d;
>         memcpy(&d, &s, 1);
>         return d ? 3 : 4;
>     }
> 
> The distinction is also useful in order to discuss vulnerabilities:
> about ~70% of them come from UB-related issues [1][2][3][4].
> 
> [1] https://msrc-blog.microsoft.com/2019/07/18/we-need-a-safer-systems-programming-language/
> [2] https://langui.sh/2019/07/23/apple-memory-safety/
> [3] https://www.chromium.org/Home/chromium-security/memory-safety
> [4] https://security.googleblog.com/2019/05/queue-hardening-enhancements.html

All fair points, but either way the program doesn't do what its users
want it to do.

> > Hence the Rust-unsafe wrappering for C code, presumably.
> 
> Yes, the wrapping uses unsafe code to call the C bindings, but the
> wrapper may expose a safe interface to the users.
> 
> That wrapping is what we call "abstractions". In our approach, drivers
> should only ever call the abstractions, never interacting with the C
> bindings directly.
> 
> Wrapping things also allows us to leverage Rust features to provide
> better APIs compared to using C APIs. For instance, using `Result`
> everywhere to represent success/failure.

OK, I will more strongly emphasize wrappering in my next pass through
this series.  And there does seem to have been at least a few cases
of confusion where "implementing" was interpreted by me as a proposed
rewrite of some Linux-kernel subsystem, but where others instead meant
"provide Rust wrappers for".

> > This focus on UB surprises me.  Unless the goal is mainly comfort for
> > compiler writers looking for more UB to "optimize".  ;-)
> 
> I could have been clearer: what I meant is that "safety" in Rust (as a
> concept) is related to UB. So safety in Rust "focuses" on UB.
> 
> But Rust also focuses on "safety" in a more general sense about
> preventing all kinds of bugs, and is a significant improvement over C
> in this regard, removing some classes of errors.
> 
> For instance, in the previous point, I mention `Result` -- using it
> statically avoids forgetting to handle errors, as well as mistakes due
> to confusion over error encoding.

I get that the Rust community makes this distinction.  I am a loss as
to why they do so.

> > It will be interesting to see how the experiment plays out.  And to
> > be sure, part of my skepticism is the fact that UB is rarely (if ever)
> > the cause of my Linux-kernel RCU bugs.  But the other option that the
> 
> Safe/UB-related Rust guarantees may not useful everywhere, but Rust
> also helps lowering the chances of logic bugs in general (see the
> previous point).

OK.  I am definitely not putting forward Linux-kernel RCU as a candidate
for conversion.  But it might well be that there is code in the Linux
kernel that would benefit from application of Rust, and answering this
question is in fact the point of this experiment.

> > kernel uses is gcc and clang/LLVM flags to cause the compiler to define
> > standard-C UB, one example being signed integer overflow.
> 
> Definitely, compilers could offer to define many UBs in C. The
> standard could also decide to remove them, too.

The former seems easier and faster than the latter, sad to say!  ;-)

> However, there are still cases that C cannot really prevent unless
> major changes take place, such as dereferencing pointers or preventing
> data races.

Plus there are long-standing algorithms that dereference pointers to
objects that have been freed, but only if a type-compatible still-live
object was subsequently allocated and initialized at that same address.
And "long standing" as in known and used when I first wrote code, which
was quite some time ago.

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211011185234.GH880162%40paulmck-ThinkPad-P17-Gen-1.
