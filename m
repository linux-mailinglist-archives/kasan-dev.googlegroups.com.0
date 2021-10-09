Return-Path: <kasan-dev+bncBDRZHGH43YJRBHUHQ6FQMGQE6Q3JF5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A64E427C03
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Oct 2021 18:30:24 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id g10-20020a17090a578a00b0019f1277a815sf9457594pji.1
        for <lists+kasan-dev@lfdr.de>; Sat, 09 Oct 2021 09:30:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633797022; cv=pass;
        d=google.com; s=arc-20160816;
        b=AJqaVteiyc4miyavg4n+5DZ5PzEd1JzHY1/VD72LR/3p3x1RJEH+UHbSSonuBGCz/0
         oo2l2PRfCyjj4oYj2iw9dhCDfpTcdly2GhSqogcVeVTQLAIofSba4PEEnnL60cZhxTKz
         eabvCJggK/SD5jKoTWlEioSd49RI8eufvPq5eqBkypOJUVAecxSlYAWsn8DbBIv91tYt
         k5RHVLP0cqSazoHuNffTFlSs4Sk1qYh3VJqgALDjVf7JR1pS54wu0pc7VIJvily3VbZ5
         bLVxcLcj+iJ76qtgCYenKRnEmYACMgRh71ELSN4O12I4DDdA5GT98vhIOpl9nYO2UsCi
         MUoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=dsFi7NsZS7wvRwkLhAR4FeKl1FoMjfWHndi8dRsUUDA=;
        b=O8EExdG7cQ4Dp/4L5sCOJRRuXgDacszesF7d3ZI/N/7xOgH/5Wh36/Vrrndgjl5ESH
         ULjB4hjxzBxHbxCE88XgoJYdoVIVctgZA2YwYA269g6Uv76e6dTO5DQSNRPWff8Zs2Hw
         z/yauUNj6AcTU66uL6qU96eqq3zmHvyMYQIGpScC0O1hMI++owfsA0pCXSx5yvPCWgd7
         w2LQJk4CJNakBvcy7uG8to4NthQedkJN4TEAnEWU8f48mgGOcI6fCFCT1HGObY6tyRI5
         WGGwjzGuXlfSqtq75FvoDMhC/lW8n1VbizU8TE2Gb24y/s0FtLULvZ38yuuLuqWtcJqc
         MHqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l5OSqSET;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsFi7NsZS7wvRwkLhAR4FeKl1FoMjfWHndi8dRsUUDA=;
        b=inkK7u2Um14+TLIWmmN4BSSzfMItUtBoseyPlooiuOFh7BYa3ondAMXro5K0X2I2W0
         TjAMaFQwXvOEW0h6SqD/FR+/UAr5JXyIMrMoPQnDT3ezQiEFVxHy3Ft/luHvj6FqJFyQ
         klyoRbya7QbbXVw5mnM+Jh8tM/70RJbWmHggwk3s4v6C9sEntSTCGFtQzBSRc4+Zw81N
         7uG15JNvMvxU/Jr5hzYLmfod0cJuvERAcJNcsBllm1cMM4mvovtqBldavijcpd0tNn5Y
         2nymxIfdpOWwogVY/1jFEQC4QrunystNTqZJZKOJMktR2MbIE4KL6iU+gl3qvXIcXp1K
         LUMQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsFi7NsZS7wvRwkLhAR4FeKl1FoMjfWHndi8dRsUUDA=;
        b=XgQXi1kQISc0lFE47PCaZgcBSF4E2K951a5qidiHL3a8ERp5pTmGXIwrkcGuKrKkII
         9yo5d7D74SWz7hoqfXgaRgRK2ZqqPZpsFh4kbCYA35F04H45LeGbfXl1RnP0V6UhRda5
         tKxVr5wWOi/XPtgf2UQOLWpjSfTYfVaTM92325/PfeQ3vF2+VwfNZREyEol37QeviD0k
         uOfAlGNTYCUyh0kFi1ehKazLXXYckchb1sOQ8OXysmJfnfcUoNPpumhTSQQWeVnysDlC
         QNTp1CPeuVF7o+TT0poaGg/kwuS80qxbmHyFxg+eXdCjVOu7Y+3sec3mzNmZ98Sbo72L
         hYbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dsFi7NsZS7wvRwkLhAR4FeKl1FoMjfWHndi8dRsUUDA=;
        b=ZpjONPkLLgBiNeT6wr7PGIwmURu95FYNmTCO1e6QJdtWioUehGd4+CRMyVQz9MWWvN
         HTAMGdreKecj+xuAtt0fRWgDIo7HSzwhuBGXYS1OZa/KgoKcyN5aDrmldcbQwpVmp6bt
         SxChbevwKxs/Gg81ZMZbEsRNP19FVg1ysLfpbc7+XNIg/t7r3LoRj/xUezKygZMtl0QT
         04N5zLDYN4SH5Lv+zG5HZBFT/NznCfBmzvqMsW87pq9Nxgbuv2QEnpr8EOSKdI0KIuyr
         uaocNrzZsPP8NcSijOgXMG3PZvevv8aliKeIiaBunmK/lAbK5/ER2UM5Z6pxaOLns+/T
         9n5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532OAztIn59iaz0A7XB7narqIAQg1f15K76KadXQvkwK6PX4OlR/
	TQ1InkE3UF+wP9F2Y65JzhM=
X-Google-Smtp-Source: ABdhPJwIbGzqOzkND61e4wbIEngutGQ3jvlgZVKrFh1KZL2ogIacj6bzjXmicSlpILMRNdlOeUNYSw==
X-Received: by 2002:a17:902:a381:b0:13d:f97d:74d0 with SMTP id x1-20020a170902a38100b0013df97d74d0mr15480435pla.61.1633797022658;
        Sat, 09 Oct 2021 09:30:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5016:: with SMTP id e22ls2301719pgb.6.gmail; Sat, 09 Oct
 2021 09:30:22 -0700 (PDT)
X-Received: by 2002:a63:ef57:: with SMTP id c23mr10297399pgk.60.1633797022028;
        Sat, 09 Oct 2021 09:30:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633797022; cv=none;
        d=google.com; s=arc-20160816;
        b=Tx+6pDk9ZXdLBBbFvWTYWLI/ap1jzjD4NW4Dypt5INDvvouubtaqduGvL5tS2mM46D
         NNj/+DbGlPb/Cf1Y/M5vMrx8cXN0kaCVYJve6GtIYuX5Ac/p6/rBbzX34C4ARAmJpOOn
         HG4rXL9gKk+Jr2qzDCvEtyk27/2+o5H2DT9HAv2OPddcHFuNNZqFZX22HvTwR/2hY8Zl
         +yulYF5kGEJmdKxzcyKTQbdPopg6rUAb2ZLyr0X+oxRvr5rayddw1of4DsLwtE/5+n37
         yI1yF6WBwoR7A9ulrHjBelCKxhW5bFAwU5BklLcRPIaagFu47+LZEP3Jrgx8VNyyyrNk
         QiTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y6JYx687k6xboEf2wHzwYIK5mYxKxPQWwDp9SWS5NZ8=;
        b=AWnJLi66GqyBUu876qSl2egHCvNk9RoKIJ844VeuJNfKunlImG9BidPCy1bQ1zhLEp
         D977+38uy9IiRgbq+rgySs4TfByCs8Wfad2tVIoINvsrd6oexNfDldRFDkjrkDpETOOr
         5v9dNKwZk+DxS29z7C//TdvRbQBBrK7Y9xOyK+rdCqAeV59oPhvBPddQ5nSK4qYo03Lo
         iODa1meoXdrWWQTc9fQ2p6k/XIc47mcDAmQgrieD3IoccLXJWazR83HoCtH7gOfiauU4
         CtiyX4tskEwi8EsWQ4EAG3Qj8DzRABSxU0jPul4zO7BJVDVI7Dw74ahefQTpaXgDXesx
         J2vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=l5OSqSET;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id w16si203021pll.0.2021.10.09.09.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 09 Oct 2021 09:30:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id e144so14449184iof.3
        for <kasan-dev@googlegroups.com>; Sat, 09 Oct 2021 09:30:21 -0700 (PDT)
X-Received: by 2002:a05:6638:2ac:: with SMTP id d12mr12504807jaq.133.1633797021729;
 Sat, 09 Oct 2021 09:30:21 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
 <YV8A5iQczHApZlD6@boqun-archlinux> <CANpmjNOA3NfGDLK2dribst+0899GrwWsinMp7YKYiGvAjnT-qA@mail.gmail.com>
 <CANiq72k2TwCY1Os2siGB=hBNRtrhzJtgRS5FQ3JDDYM-TXyq2Q@mail.gmail.com>
 <20211007185029.GK880162@paulmck-ThinkPad-P17-Gen-1> <20211007224247.000073c5@garyguo.net>
 <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1> <20211008000601.00000ba1@garyguo.net>
 <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Sat, 9 Oct 2021 18:30:10 +0200
Message-ID: <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=l5OSqSET;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Sat, Oct 9, 2021 at 1:57 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> But some other library could have a wild-pointer bug in unsafe Rust code
> or in C code, correct?  And such a bug could subvert a rather wide range

Indeed, but that would require a bug somewhere in unsafe Rust code --
safe Rust code cannot do so on its own. That is why I mentioned
"outside safe code".

> of code, including that of correct libraries, right?  If I am wrong,
> please tell me what Rust is doing to provide the additional protection.

Of course, an unsafe code bug, or C code going wild, or a compiler
bug, or a hardware bug, or a single-event upset etc. can subvert
everything (see the other reply).

This is why I emphasize that the guarantees Rust aims to provide are
conditional to all that. After all, it is just a language -- there is
no way it could make a system (including hardware) immune to that.

> I would like to believe that, but I have seen too many cases where
> UB propagates far and wide.  :-(

To be clear, the "effectively contain UB" above did not imply that
Rust somehow prevents UB from breaking everything if it actually
happens (this relates to the previous point). It means that, as a
tool, it seems to be an effective way to write less UB-related bugs
compared to using languages like C.

In other words, UB-related bugs can definitely still happen, but the
idea is to reduce the amount of issues involving UB as much as
possible via reducing the amount of code that we need to write that
requires potentially-UB operations. So it is a matter of reducing the
probabilities you mentioned -- but Rust alone will not make them zero
nor guarantee no UB in an absolute manner.

> Except that all too many compiler writers are actively looking for more
> UB to exploit.  So this would be a difficult moving target.

If you mean it in the sense of C and C++ (i.e. where it is easy to
trigger UB without realizing it because the optimizer may not take
advantage of that today, but may actually take advantage of it
tomorrow); then in safe Rust that would be a bug.

That is, such a bug may be in the compiler frontend, it may be a bug
in LLVM, or in the language spec, or in the stdlib, or in our own
unsafe code in the kernel, etc. But ultimately, it would be considered
a bug.

The idea is that the safe subset of Rust does not allow you to write
UB at all, whatever you write. So, for instance, no optimizer (whether
today's version or tomorrow's version) will be able to break your code
(again, assuming no bugs in the optimizer etc.).

This is in contrast with C (or unsafe Rust!), where not only we have
the risk of compiler bugs like in safe Rust, but also all the UB
landmines in the language itself that correct optimizers can exploit
(assuming we agreed what is "legal" by the standard, which is a whole
another discussion).

> Let me see if I can summarize with a bit of interpretation...
>
> 1.      Rust modules are a pointless distraction here.  Unless you object,
>         I will remove all mention of them from this blog series.

I agree it is best to omit them. However, it is not that Rust modules
are irrelevant/unrelated to the safety story in Rust, but for
newcomers to Rust, I think it is a detail that can easily mislead
them.

> 2.      Safe Rust code might have bugs, as might any other code.
>
>         For example, even if Linux-kernel RCU were to somehow be rewritten
>         into Rust with no unsafe code whatsoever, there is not a verifier
>         alive today that is going to realize that changing the value of
>         RCU_JIFFIES_FQS_DIV from 256 to (say) 16 is a really bad idea.

Definitely: logic bugs are not prevented by safe Rust.

It may reduce the chances of logic bugs compared to C though (e.g.
through its stricter type system etc.), but this is another topic,
mostly unrelated to the safety/UB discussion.

> 3.      Correctly written unsafe Rust code defends itself (and the safe
>         code invoking it) from misuse.  And presumably the same applies
>         for wrappers written for C code, given that there is probably
>         an "unsafe" lurking somewhere in such wrappers.

Yes. And definitely, calling C code is unsafe, since C code does not
have a way to promise in its signature that it is safe.

> 4.      Rust's safety properties are focused more on UB in particular
>         than on bugs in general.

Yes, safety in Rust is all about UB, not logic bugs.

This does not mean that Rust was not designed to try to minimize logic
bugs too, of course, but that is another discussion.

> And one final thing to keep in mind...  If I turn this blog series into
> a rosy hymn to Rust, nobody is going to believe it.  ;-)

I understand :)

As a personal note: I am trying my best to give a fair assessment of
Rust for the kernel, and trying hard to describe what Rust actually
aims to guarantee and what not. I do not enjoy when Rust is portrayed
as the solution to every single problem -- it does not solve all
issues, at all. But I think it is a big enough improvement to be
seriously considered for kernel development.

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72m76-nRDNAceEqUmC_k75FZj%2BOZr1_HSFUdksysWgCsCA%40mail.gmail.com.
