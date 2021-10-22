Return-Path: <kasan-dev+bncBDRZHGH43YJRBWU4ZSFQMGQEQJKZIPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19E74437E77
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 21:17:48 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id c17-20020a92c791000000b0025929f440f0sf3101631ilk.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Oct 2021 12:17:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634930266; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojqLzU3LUCbHhgsKS9SfoLYKRhx25/3+MKptITyDwZ9/M6iHATjbWSwV0UxBU0+G5C
         9jxG/EmJIaeG1eQQTcJUz3+1up5xt5zM7h6NUalPaxGcbNANcy1GFRsW/AMjUBVE/xC+
         lEwOGFY6NiwkODta4tju4GZKOAqH0XYgvPtSHlx+aDgKy2G6yHcv6DVjQA3T4a8UIKd6
         2JZ7Tqhkl36DSVPi2542a1n7faV44TlLdq58bXFG516B+BlSt61Ogn4hjpC446jCVkag
         57JnrBh8nwBMnA2lffoAxQ4fQvCamrv9BMei1QuOTB64XJYLh2WZyOl4FoqiJMdG+e45
         1+5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=nGqJDWQzVsFgmBdAWpcynAKy8SKBrheek4RMEYPIrpw=;
        b=w5H1jfZCCANDqV8IubDkJ9OL7jLhkKNSYKLqvcs33a3t9MbBPOcyMDucSF7tZ6vX3Z
         9xZG9hIIqjxJFw5RGlJiN7hjaPm3SGyCVRGqG5anL5J3pJcB28VI9T8wmitTfwXSCa7c
         yhxv7mNQNUXDwx7wdpj3JtBDBciqn0zbHWfdeGuN6DvKQfgH66CLpuf7HZ69hTfvNQ37
         gl/ttDJAkq2byL7ih3rAvzpWgV9zd2wZSf9ByVgR4t8V9Dh8jY2sRl05eUvqEjWL4Vqw
         53DAl6A8itJqNCJDoqVy0uCTmjSGqISvLxWb/AXMNSxtwWLanC1JqeLVvikC+sZZe4p1
         LAvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KTSH8Ohq;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGqJDWQzVsFgmBdAWpcynAKy8SKBrheek4RMEYPIrpw=;
        b=Gc/xwE5ft+XnV62qAlYre75Fn7ZiXanch9JwnQuD3WfCXI4D+PSbgzfnI+Kw1zqwdN
         kKGWPiUTuDtj9azq9/zzJuwxd5Mu08lzN/IG2uOo+iGPDlur4NkFq5nVm5aAe/sIzmDh
         bRs7Ef8q0SsE1mQyYi75q0g+q2M9nZ9CWbWc2B13ItuU9RNbVslHanHKThs4mlioR9Cu
         k26wwevnyLIypt9pcZO1gGnIuQwX0wA4xYXCBbCsWweMUURKT4OG8Uh8v3uL3oNhQ+Fw
         q460CdY0qxPPJ0X7R+DLYr/3T3pCI094UlZZXADDjxScmc9kvOR04dYdg9ncUp1+pks+
         RZPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGqJDWQzVsFgmBdAWpcynAKy8SKBrheek4RMEYPIrpw=;
        b=EeTholKl0qD27yzgRBurEw0ccZaaiyEU2mIX6o0Db/FCQVTjxLo/vPuMcklh+ySzb0
         CYyhBru9Oq2C28wN8RmBIH5oYhlkZaDsB7KF84v7fYsgF+h+lolj6fUISpzc+dkQxwHe
         nK/+uSI11fRSAYfZsuIlV0i4QQPQGn7k9ukwk+/+89HEcMeuXUy9u2mvL+QA/St8ftwU
         9d5PbeAiGHtqUI9naB85Y++vEIQSaA+kTAmM1XOsvcpDtnWObtb7ynNgIWqsjT/u96WZ
         DW34hM45O+GrsC8a/exF9Tu0yRYHDFXfCVN8kkinzXiAmh+A5x/jUOztkTzB1s3BMG5t
         c+og==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nGqJDWQzVsFgmBdAWpcynAKy8SKBrheek4RMEYPIrpw=;
        b=J2EKdVpfAo5iH5RARNKMJt5qfwrQMFh3RJn0VN4vIAoPjSH6ldsAYLfKY9Dv5PLWvK
         8SbOG2fb7Slnai6wpt5Btk0zw4jmySbX+qz0GcY3gPH7Yf4IlQ6bgREezUtYSZsI/FPB
         DsGeRfhJ1IaR5PMJti/81j5sTrSqxsLS8IsuFi6zAAbn5g3S4WW/hou8VaH8ZX7U17Y+
         Du7ZDc0nYZ19LjKiMhJgLqRvazHOng7Sgj+01MoXtdX3dnBfm7BiRClJG1zHkaYmbN82
         X82swdliTqVEbilc6/Rq6pgkU7NYbzookGpfYgZol1bXnGrc8KQdIAgjVZ+bcZk0Obc1
         j00g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ti9tbtA1L1qoQ7bX6KM4sP/E3vDufS1cG2jnSuyK9mkeL8v24
	pLYKXJ37wY6+3lgJ7ZikZhY=
X-Google-Smtp-Source: ABdhPJw+q0Y/aIQbYwP2Hrm65uevw/2Bg/t7uuw6zfD8rjiGvBe3E6PWjghxV2d0F15GLj/u/4Oqzg==
X-Received: by 2002:a92:7f0e:: with SMTP id a14mr1081236ild.215.1634930266710;
        Fri, 22 Oct 2021 12:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f906:: with SMTP id j6ls1863297iog.9.gmail; Fri, 22 Oct
 2021 12:17:46 -0700 (PDT)
X-Received: by 2002:a6b:dc05:: with SMTP id s5mr987882ioc.131.1634930266387;
        Fri, 22 Oct 2021 12:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634930266; cv=none;
        d=google.com; s=arc-20160816;
        b=YM0OdDKpqwBaUf62twPWG2/UYsLHayelB7zuUn7l9FV2y1UgWpst0uZoAvvwIIWB+z
         vpHLV25n5tssRA4Zp7zuLohuX9KHf+34piCzYTcrIaGGikGwydJVU5yHtZ2u8A0gDNjw
         LvyTVW33qZ/3vAc+9SF+l1XJ0unfLbSMDPrgXDzflQO7+jdXWpYjIdxOOfh+0aHrRXEU
         xbokwwBN2zyfeUZ/qIs4bqcRWglcn8PzIO3gurSZlAJ1jWeQRJhSfnLJmZFvEUasucvb
         thUl2xJ7QySV77NNPIAqF+QxIocJiw8MBpiKNlqdCPKR4AeNffdK9mrZ2auJMuD+lyF/
         pafg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2ulfGQ2/OGrqGipqel6m6LOJoxfozQy2WBLXzVVjKVk=;
        b=hNryL1XPDebKhOa0Gap2MutwM+qg1vDh6kPMNkQHA7kS03KqfkV/DsGVVpFiQ3ATXZ
         fK1A4HHOHRmeAwb2DKyzpcc2B1x0YpGNj8wclEG98TyEk1Uc3gl+FDXDVlnTtNuQCbyn
         0ZGKjGMFKnP74c797iNHUjEQaBX3UbnmX2KuYGbhZEKtnZkNX0+tcOavkTKWS521QVCo
         er5FvqYEQJsry9YVR5Bhqs6ltezRRHoSTCBCa7Lu96V1+qoeu7O+60o/Roiu9XjnGj9y
         CwOtGAGJPIDQs9WHZMnXMJ+ScOaSg3N6HeX2dN7W6roHEbMwKN45UNQgr3T8QkIkisAF
         BtDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KTSH8Ohq;
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x134.google.com (mail-il1-x134.google.com. [2607:f8b0:4864:20::134])
        by gmr-mx.google.com with ESMTPS id n3si579528ioc.4.2021.10.22.12.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Oct 2021 12:17:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::134 as permitted sender) client-ip=2607:f8b0:4864:20::134;
Received: by mail-il1-x134.google.com with SMTP id j10so2053354ilu.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Oct 2021 12:17:46 -0700 (PDT)
X-Received: by 2002:a05:6e02:1543:: with SMTP id j3mr1127059ilu.151.1634930266149;
 Fri, 22 Oct 2021 12:17:46 -0700 (PDT)
MIME-Version: 1.0
References: <20211007223010.GN880162@paulmck-ThinkPad-P17-Gen-1>
 <20211008000601.00000ba1@garyguo.net> <20211007234247.GO880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nLXmN0SJOQ-aGD4P2dUTs_vXBXMDnr2eWP-+R7H2ecEw@mail.gmail.com>
 <20211008235744.GU880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72m76-nRDNAceEqUmC_k75FZj+OZr1_HSFUdksysWgCsCA@mail.gmail.com>
 <20211009234834.GX880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72=uPFMbp+270O5zTS7vb8xJLNYvYXdyx2Xsz5+3-JATLw@mail.gmail.com>
 <20211011185234.GH880162@paulmck-ThinkPad-P17-Gen-1> <CANiq72k+wa8bkxzcaRUSAee2btOy04uqLLnwY_AsBfd2RBhOxw@mail.gmail.com>
 <20211013232939.GW880162@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211013232939.GW880162@paulmck-ThinkPad-P17-Gen-1>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 22 Oct 2021 21:17:34 +0200
Message-ID: <CANiq72m=MV2rF=SHKfrAi+E0vwEpKemeO_48h10=tvejJ_mAPw@mail.gmail.com>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>, 
	Boqun Feng <boqun.feng@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	rust-for-linux <rust-for-linux@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=KTSH8Ohq;       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::134 as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
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

On Thu, Oct 14, 2021 at 1:29 AM Paul E. McKenney <paulmck@kernel.org> wrote:
>
> So Rust could support zombie pointers without changes to LLVM?

I don't know what you mean "without changes". LLVM is not fixed, it
changes every version, and Rust sometimes has to patch it on top. If
Rust decides to support (or not) zombie pointers, then they will have
to look for a way to lower code in the given version/instance of LLVM
they are using in a way that does not break the zap-susceptible
algorithms. That may require new features for the IR, or disabling
certain optimizations, or fixing bugs, etc.

> The standard is for the most part not a mathematical document.  So many
> parts of it can only be "understood in a personal capacity".

Sure, but there is a middle-ground between a formal model and
completely unstated semantics where nobody can even guess the
intention. My point was that we should not rely on semantics that are
not precise yet -- if possible. And if the same problem happens in C,
but we have a workaround for it, we should not be rewriting those
algorithms in Rust.

> To be proven in the context of the Linux kernel.  And I am happy to
> provide at least a little help with the experiment.

I was talking about classes of errors that are avoided "just" by using
the language. For instance, using `Result` instead of hoping users to
get the error encoding right even across maintenance rounds.

> Working on it in the case of C/C++, though quite a bit more slowly
> than I would like.

In my case I am trying to see if WG14 would be interested in adding
Rust-like features to C, but even if everyone agreed, it would take a
very long time, indeed.

> However...
>
> Just to get you an idea of the timeframe, the C++ committee requested
> an RCU proposal from me in 2014.  It took about four years to exchange
> sufficient C++ and RCU knowledge to come to agreement on what a C++
> RCU API would even look like.  The subsequent three years of delay were
> due to bottlenecks in the standardization process.  Only this year were
> hazard pointers and RCU voted into a Technical Specification, which has
> since been drafted by Michael Wong, Maged Michael (who of course did the
> hazard pointers section), and myself.  The earliest possible International
> Standard release date is 2026, with 2029 perhaps being more likely.
>
> Let's be optimistic and assume 2026.  That would be 12 years elapsed time.
>
> Now, the USA Social Security actuarial tables [1] give me about a 77%
> chance of living another 12 years, never mind the small matter of
> remaining vigorous enough to participate in the standards process.
> Therefore, there is only so much more that I will doing in this space.
>
> Apologies for bringing up what might seem to be a rather morbid point,
> but there really are sharp limits here.  ;-)

I feel you, I have also experienced it (to a much lesser degree, though).

I could even see similar work for Rust going in faster than in C++
even if you started today ;-)

Cheers,
Miguel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANiq72m%3DMV2rF%3DSHKfrAi%2BE0vwEpKemeO_48h10%3DtvejJ_mAPw%40mail.gmail.com.
