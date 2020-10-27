Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5HR4H6AKGQESWPPPCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C37C29C930
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 20:45:57 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id v6sf1524715plo.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 12:45:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603827956; cv=pass;
        d=google.com; s=arc-20160816;
        b=bm1iM0I0yJC8qDHuwz4NYwuS11NYiYXVTgiqz0H9UxM/1SaPGuGuMMzgAfyys+SzLF
         3y/KUFjl1OEHCG4ySoE4qItFV8YCaKyUzVgFImbJ6JndrTMsVem18bxI4wDMLM7hdiXS
         BQsrbHt9jT27PWczDA8ISBpVYhQtBfHrkc0B/KFjOHFYdVdQ/x88LPVx83ZKOFx2ownP
         r8ArbBCkhgRvogR64ESZZUcSyUEFNKTW1wVwaTZ/dVf1QCKoDML7SaWzn9XheujI6tNZ
         10VADlpm/bx3MXO9sm1aJpgi16yzR8dye/fZaY0HOEtUm2llHXruD9XsEcuRvAYfJ2wK
         GVdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zcgaJSwGyuCFuFYwamt8HXm71J2RbY4lqjOcFndAkrw=;
        b=ckSfiJpCguQPhLBf6p7AWtLb7SlwcIRRi5h4luf4ezPgfg5cmACP4CBCTD5/MMjwtL
         6POIJg6teN0iP6l3dFqRwj0Op7JjFSk9kpd1HR+XHpHHEYKsZmzsdk+/rdilPXWctrMI
         PUH290xhsJDECL7vVhd5uLFmNVz23UyKdw6+a4N3GWPlSIX/Skgs+CuJZ3YxDYZ34h/Y
         sa4fev7TlOGXFBxk6eLYd0ONvi0OMLxFWhOb2u5FLoESuccOzs5AnuD3lqgEo86BlJvN
         UZsEeer+7D2dhEKeAdeUhZO6d5lK5RsT7UAV6FUymHck+vFX8bMH8TEeHBfPaIQrN+7m
         9g3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKOI+Eti;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zcgaJSwGyuCFuFYwamt8HXm71J2RbY4lqjOcFndAkrw=;
        b=NmGQKs3LftR5o1BigbSINlDaSdmOASH4U0kMzdsBcnzwt9xiVe9Xy0pOwU0Smjo/o7
         EjOln/DJkM7B/X7C82ln8Gio/eSQWpj+hSp0aDBkHnr492zC76KPRAQbYZbYecBQPHIx
         ii9WOh+9b/MptqzXDEyiO20M4p9QPiVWUsHTuyTcN67TXwidvDRkU4mmCYw5KoRM2UWN
         Y8OoWFA+Wd7jNfuPdpntHLv4RcIsE6F/3VD55ajKZ88hTqyaCYh+mXA/iATCQ697QUdJ
         WfOmrENe28D1Bk/xdy+T7S6iX1jVtZtM8qoM4qw//MVZI9ljf134YS7B0YpWsvfU0O42
         AROA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zcgaJSwGyuCFuFYwamt8HXm71J2RbY4lqjOcFndAkrw=;
        b=P/puseRR2UKBqhpksBfM9u+fSaCHVMHx3z6OVzj8D0YUpxjkblxU0/NTZKs3EW1t3y
         Sc5/oONGVlNyh1ZXB8WxlNRQx3AwkDgdbsrJGDktj8vku3EVh1GKZAUpP6H9VMsm9N1j
         Aj0ftp11xcxxSlbMn89qM/w0kdZOd8rpVPrEEd0Yx9b2VAfJ8gzHZfDC98BX/qmVKheG
         zuoxv0GN5lGpMYJmGTjedCJet9Tor/6dX7FhCi51JY9PW4S+FLgc5pIuPtPlhZxKBOY9
         Eb1nH5yWY8lg9eBu6ggUkfaxljwuOQAY4bRYTDqvIHDNdkkrcbO/JFyPzUvqln56zF0X
         HuVA==
X-Gm-Message-State: AOAM533walQGQxRurA5pWk4mID9Now9yCgGY1fJCM2wUNuduPBIvVv8W
	j1l3X6mFcBeN8lcf4OCuuVQ=
X-Google-Smtp-Source: ABdhPJwbxOlyxCmlxvdeoa1ONFR59EylNi/navYlyzMJdjq4FNenrtauzx1pXFhsId1rA7HPqlPp1Q==
X-Received: by 2002:a63:3543:: with SMTP id c64mr3277206pga.380.1603827956305;
        Tue, 27 Oct 2020 12:45:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd95:: with SMTP id q21ls743116pls.5.gmail; Tue, 27
 Oct 2020 12:45:55 -0700 (PDT)
X-Received: by 2002:a17:902:d904:b029:d3:d2dd:2b36 with SMTP id c4-20020a170902d904b02900d3d2dd2b36mr3988558plz.32.1603827955643;
        Tue, 27 Oct 2020 12:45:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603827955; cv=none;
        d=google.com; s=arc-20160816;
        b=R4McdRHPrXRYs4EhYdKTHyPY5CUxAHmCX/hBc6dSdlKORab8hlf0NrqLFRw0XEntfR
         kHEGF6D+0StQqFpNDVy1L0z9dFXjpbyuQHQy1HidxsK5n5ExeO7qi2/LQFySRTE/43sp
         uPq1nv8iTz+FqggMymDvUXarSM7sODueWlleJEf4F51gP4vffj4HqYd6QHWzNUAi/pOY
         oXfTWbU48iZP5bLQznwnDX/7mu0JRTqTribaWFxzzdJQVbosho1YSFHoE3EPHyPNIdq8
         5sBC+wObbkog3IKOpThAUQp5ckmcdpyv0pPxXGFpK6xvmsNNo/h0K+sfcZNQPkQOliu4
         3f1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2UuAnI3fpLSkqqbqcby7qgRRi+KejDcUiQcp3yUYFvk=;
        b=B+2Gn/nCIdcMRbH/XUeWmkn+rNOWP++gEOZYr0t26Ti57p3x43xf+bg2JRCbCN7Vjz
         lhdxZvEbUpwccQWRrRpvFfYIuP6XbWbnDkywPiZLi2jkFRtMQ4LLQQZxkVeIHX55nG3d
         OkpOVntiSCCWNd9pnUCaTv9/oTW30e1UnOumZEHGRnGbJVFcBkeH/Zl4pmQ/0xPOPcwR
         Ujoq0IoLx10pbxtpgxj6LKSLfiGYKAE6cka9kBgvrYlPT9a7dcNV0zuK9POkzmPSl/Xt
         vaxDZe5nP1R1/nNuGdJ/2MAgzL8vsYP5wdQfVJa/yq//6BTjDomdNZi/9m+sZiKPLUEZ
         MPrg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jKOI+Eti;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id 191si202374pfu.3.2020.10.27.12.45.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 12:45:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id k3so2232874otp.1
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 12:45:55 -0700 (PDT)
X-Received: by 2002:a9d:34d:: with SMTP id 71mr2456972otv.251.1603827955087;
 Tue, 27 Oct 2020 12:45:55 -0700 (PDT)
MIME-Version: 1.0
References: <20201027175810.GA26121@paulmck-ThinkPad-P72> <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
In-Reply-To: <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Oct 2020 20:45:43 +0100
Message-ID: <CANpmjNNxAvembOetv15FfZ=04mpj0Qwx+1tnn22tABaHHRRv=Q@mail.gmail.com>
Subject: Re: Recording allocation location for blocks of memory?
To: Dmitry Vyukov <dvyukov@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, Andrii Nakryiko <andriin@fb.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jKOI+Eti;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

Hi Paul,

Let me add another option below, as an alternative to KASAN that
Dmitry mentioned.

On Tue, 27 Oct 2020 at 19:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> On Tue, Oct 27, 2020 at 6:58 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello!
> >
> > I have vague memories of some facility some time some where that recorded
> > who allocated a given block of memory, but am not seeing anything that
> > does this at present.  The problem is rare enough and the situation
> > sufficiently performance-sensitive that things like ftrace need not apply,
> > and the BPF guys suggest that BPF might not be the best tool for this job.

Since you mention "performance-sensitive" and you say that "ftrace
need not apply", I have a suspicion that KASAN also need not apply.
KASAN itself uses lib/stackdepot.c to store stacktraces, which
deduplicates stack traces by hashing them; but over time its usage
grows significantly and may also not be suitable for production even
if you manage to use it without KASAN somehow.

If you want something for production that more or less works
out-of-the-box, KFENCE might work. :-)
v5 here: https://lkml.kernel.org/r/20201027141606.426816-1-elver@google.com

You can just get KFENCE to print the allocation stack (and free stack
if the object has been freed) by calling
kfence_handle_page_fault(obj_addr), which should generate a
use-after-free report if the object was allocated via KFENCE. You
could check if the object was allocated with KFENCE with
is_kfence_address(), but kfence_handle_page_fault() will just return
if the object wasn't allocated via KFENCE.

If you do have the benefit of whatever you're hunting being deployed
across lots of machines in production, it might work.

If it's not deployed across lots of machines, you might get lucky if
you set kfence.sample_interval=1 and CONFIG_KFENCE_NUM_OBJECTS=4095
(will use 32 MiB for the KFENCE pool; but you can make it larger to be
sure it won't be exhausted too soon).

> > The problem I am trying to solve is that a generic function that detects
> > reference count underflow that was passed to call_rcu(), and there are
> > a lot of places where the underlying problem might lie, and pretty much
> > no information.  One thing that could help is something that identifies
> > which use case the underflow corresponds to.
> >
> > So, is there something out there (including old patches) that, given a
> > pointer to allocated memory, gives some information about who allocated
> > it?  Or should I risk further inflaming the MM guys by creating one?  ;-)
>
> Hi Paul,
>
> KASAN can do this. However (1) it has non-trivial overhead on its own
> (but why would you want to debug something without KASAN anyway :))
> (2) there is no support for doing just stack collection without the
> rest of KASAN (they are integrated at the moment) (3) there is no
> public interface function that does what you want, though, it should
> be easy to add it. The code is around here:
> https://github.com/torvalds/linux/blob/master/mm/kasan/report.c#L111-L128
>
> Since KASAN already bears all overheads of stack collection/storing I
> was thinking that lots of other debugging tools could indeed piggy
> back on that and print much more informative errors message when
> enabled with KASAN.
>
> Since recently KASAN also memorizes up to 2 "other" stacks per
> objects. This is currently used to memorize call_rcu stacks, since
> they are frequently more useful than actual free stacks for
> rcu-managed objects.
> That mechanism could also memorize last refcount stacks, however I
> afraid that they will evict everything else, since we have only 2
> slots, and frequently there are lots of refcount operations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNxAvembOetv15FfZ%3D04mpj0Qwx%2B1tnn22tABaHHRRv%3DQ%40mail.gmail.com.
