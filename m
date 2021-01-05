Return-Path: <kasan-dev+bncBCMIZB7QWENRBYWE2H7QKGQEZ33XDDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 227702EAB4C
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 13:58:12 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id f19sf30573472ilk.8
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 04:58:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609851491; cv=pass;
        d=google.com; s=arc-20160816;
        b=L0VODEDUtaCAed7LA+rELqSwqIbO6NjcOYpHbeQk6/SVOKpi1mF8dBTQK6Rc+KxAcT
         ldp8L55hkvu4kHgA46j5vf+fwYQQe97FD9H41lh1dhwz2VxI3yOEI78xr+C9JHwhaO9F
         opP871mh4zx00vTv8u43VspYgHtSc5I5OiD6KKkkMKoJ/GTeIzlBamiVVxFFYpyArBzy
         P8yTMSrcEfjy/3HDi5u3nGCf84b5r2wA+kBNGwl3eVMM6z+YJqhWCv/759tGYE+Yyw/G
         /uk4wrQIR7ThC+JE9HYswGdfu/LqTLjvDT/3fIxV3dqgrrUp3pKvDMbaJSD6sggYm0QF
         dQCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aqNXnQ44b+oODLYtSWmESANBDt7rax4SPVKmsYQVnbc=;
        b=N01Nh/JRA4rUks4ssqluqbbV7f+8HoZqhDnw5+DJyZjA6DgNmjcOaXY8Y/m4y2/SAn
         NVvfPsvgxchrHqYeKTShvhhBUXKqdo1g0bojEXYa5dFe5E6LT3e59COgLMKDytS5ATQJ
         pyN3ERvDrUD6xeJUClVRqSlhwKSp8Bn/zGflCPc1ggInwZOMdzIKuR8ob95IryDK50YF
         ZKRfqLN6tJjed6PqLczFVtoY6an/LFr3uNkbV1z5UcfBcIoCIvSGfEt/qQFa5im16Rsm
         T4/ERAdWH30bC0XImjH+FujsH61W5hPChCgXKdYT8EgvF1VMRLHQ4dIVObQoZ06Wk+ua
         F0ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fHCbcpUg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aqNXnQ44b+oODLYtSWmESANBDt7rax4SPVKmsYQVnbc=;
        b=AbytXO8x8JyaB3lGrMDeoq+SbyLYCuX1BEP/TVles+GQcltaWcG+bLdD3J4BuAoxOD
         +p5MW+kc6iuSKDQ+gqAmJ6Ly858cCO0NqOqIqrGho+DfbrPmnauGrXvePHMQiL+0L7Ul
         bdfYlUo42D7ChiJmcjtJMlHCzcuLqM1hwDlL//BqFC/soRO1O441YfR+RVwO+7XwLTtP
         icLZ83hCtS9N0Boo8rvPZt0xbgpQbQvESaCRDHj0Z68iT4lj1oOmJW110qz5gbvxydxA
         69zgrYLFVbNpkoQ6DlxG1xg5Y95qIPmt9C3IxjT7hVBo3yrnlE0f/U/bcO/q6PIStZde
         lxIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aqNXnQ44b+oODLYtSWmESANBDt7rax4SPVKmsYQVnbc=;
        b=uB9jlDq8uVT7qK8M02xGrUd/6Qk8W4+j9tt59+Zx4jVX/thCp+0UosNMPyhuhd9I+X
         GI4r1qEVCam2YJx8kXJrZ3X5KkqUbiCo3Nt4nBRCuS4uw1ALkjaq+sWxwrw5aKdA20xF
         NTY+iyKVGKgSvMV5c3qwb9sHZRRW72qWVHZdCrslHYMSr/xmgiLDw88DIusoyjcYV4R9
         80kdWfYfSE6YEmVozk88UFfuzvF63Bxl/Eqxr/zNiKMt/SZahwBem2BOCu4F+9dMI9tm
         Q7KXVgHxCkaJ8+gP0wjjjrZB6EfUPQLnMf2U0FUQM3yTMh9ha3O/eyDPZ7JTUYCq/YUF
         IujQ==
X-Gm-Message-State: AOAM53049+3YiaRKgv7Nk1/xMlCKTjPNRqd1o2cVTggaM3gdkWBL/zKu
	RR5NMfI4pn6Jaho6PGx5z3c=
X-Google-Smtp-Source: ABdhPJxX+IP7vSmX8AyMUccRa7EYqo3a5aT7+jklh8Z9DNWlU21YJYLRwjiSE5KG3pxtpnyjcOpOFg==
X-Received: by 2002:a5d:9c91:: with SMTP id p17mr62481973iop.36.1609851491020;
        Tue, 05 Jan 2021 04:58:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:dcb:: with SMTP id m11ls9091079jaj.6.gmail; Tue, 05
 Jan 2021 04:58:10 -0800 (PST)
X-Received: by 2002:a05:6638:50c:: with SMTP id i12mr67561594jar.74.1609851490657;
        Tue, 05 Jan 2021 04:58:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609851490; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5HpeW1IBFeQgrZCfIkVv2Bcn9X8LQ2l/3Yuxww09gEr8ZhuvgfRwo6/epuEl35e79
         2qMb2vF7NtwaDLBU/SQKasO/7exzm1BcD3iqGDHSctQxHdp0uov/QNjF1y0eHW17jOYg
         NjR/EhB9GJgr645pXptkd5rvk43JC9xhr75gafBBPku0rVI79fts/lwWtLpTj0UX8s8e
         xzAvBmfMOO4MwZDA7sRd/x/qoRgxDtYW3lEsNqLKlRWJ/MEbQe6OTMkGfIDc2fIfUvoM
         Fv8aWsYSjsq/pKY5kClXxU8hhTJ3WtLrpy54//G13RH5DqcE2AH4TDtIqpOiG4nz6or4
         af0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NzbAt5rP1DZwHWQHYeFDkLYI3uGKyehX3WPDTmSzmy4=;
        b=J7Rw5zNiQvzEeYgG3dVgNz4uRqObzQal7UuuYPnoGVboC81OHH/tX+WZv6bQU0wrC+
         LnFjotaXVze7wzNDHIEfNzJdpGkYbs34fvWQPZTLwwx8XFonEu7CdTNGjWv7xoimjKCQ
         B/F/LSWE23N+6cTA9VlsjOqdKeelKDzObwlsTP5HqMV7gWgSU+QzuZCDuJroVPK3Y2hP
         m69wV9rIK2UvTSqE3INubZbjsBWISs4iW3HNYcmN3PCuwJ74XkjyH7c0UjMn/ASrvW4Z
         1lvvmbJvld7XTsodw87s+gKpQjYq7pIPGfLM2rtEVu5atY7KXIZt8i3evRL9puDgLAK5
         EoMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fHCbcpUg;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id k131si3986595iof.1.2021.01.05.04.58.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 04:58:10 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id d11so14563078qvo.11
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 04:58:10 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr47481040qva.18.1609851489935;
 Tue, 05 Jan 2021 04:58:09 -0800 (PST)
MIME-Version: 1.0
References: <20201014145149.GH3567119@cork> <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
 <20201206164145.GH1228220@cork> <CANpmjNNZDuRo+1UZam=pZFij=QHR9sSa-BaNGrgVse-PjQF5zw@mail.gmail.com>
 <20201206201045.GI1228220@cork> <X83nnTV62M/ZXFDR@elver.google.com>
 <20201209201038.GC2526461@cork> <CANpmjNNTuP7w7qbwp7S2KU23W0pvNrOk8rZnxzRYsxAcOXMO8Q@mail.gmail.com>
 <20201209204233.GD2526461@cork> <CANpmjNMXOYkG25Gt6n54Ov+pxVjGMXRUWAMkDD4JWtLCNq4jPA@mail.gmail.com>
 <20201229174720.GB3961007@cork>
In-Reply-To: <20201229174720.GB3961007@cork>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 5 Jan 2021 13:57:58 +0100
Message-ID: <CACT4Y+aAuJexS9o0Vct--v5WX-a123OfcuKmYKgAEUWxSbzd5w@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fHCbcpUg;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Dec 29, 2020 at 6:47 PM J=C3=B6rn Engel <joern@purestorage.com> wro=
te:
>
> On Wed, Dec 09, 2020 at 10:44:53PM +0100, Marco Elver wrote:
> >
> > I was curious, here's what I get -- sysbench I/O 60sec, 5 samples
> > each, reboots between runs, VM with 8 vCPUs, but using 500ms sample
> > interval which is closer to what we want to actually use.
> >
> > Static branch samples: [7272.36, 7634.77, 7380.72, 7743.89, 7480.7] #
> > Requests/sec
> > Mean: 7502
> > Std. dev%: 2.26%
> >
> > Dynamic branch samples: [7354.06, 7225.33, 7154.76, 7535.82, 7275.94]
> > # Requests/sec
> > Mean: 7309
> > Std. dev%: 1.78%
>
> Finally ran our benchmarks as well.  You'd expect a lower result because
> most of our work is done in userspace.  Then again, I've tested a config
> with kfence allocations every 100=C2=B5s.
>
> So far I cannot see a signal.  In one case kfence causes a 6% speedup.
> In one case there may be a 10% regression.  Most load points are either
> perfectly flat or have the usual random noise.
>
> If I assume that the 10% regression in a not-very-interesting load point
> is real, I can go from 100=C2=B5s to 1ms and happily live with a 1%
> regression in some dark corner somewhere.  More likely, the 10%
> regression is a fluke, just like the 6% speedup.
>
> Congratulations!
>
> Performance is too good for us to worry much and we have caught two bugs
> with kfence so far, with fairly limited deployment.

Hi J=C3=B6rn,

This is awesome!
Are these bugs public? Or do you mind sharing at least some details on
these bugs? E.g. type of bug, affects production, would be easy/hard
to find/debug otherwise.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaAuJexS9o0Vct--v5WX-a123OfcuKmYKgAEUWxSbzd5w%40mail.gmai=
l.com.
