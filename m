Return-Path: <kasan-dev+bncBAABBFPY4H6AKGQEZ65ZCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 436C129C94F
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 20:59:19 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id w3sf1429664pjt.6
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 12:59:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603828758; cv=pass;
        d=google.com; s=arc-20160816;
        b=G0KNghD3tA+vHbP+dzgXNqv5XYi1S5Jczlv27l6QaDj0AiOckfPjbOJ2bfJzkX+0Li
         aJKnotaTWlRdFHcJOmXz1OsEn1vvmGPJsqXrm1HIy+d8BbyR2fIaUmh3zXDQPyDbXxE+
         HLHZ/7liCtImhimm/tkxN3WrP2/95sTW2GqbGpGRaEMlMP4GvQjF2DDlIjYUkjFGaVzI
         hC3tNjYm+L8ZJFFqmHcXvvTOMpDmZB8KAFbVcUlz9wjuVpCBkN/bPZtvMGD7DJXQfgBG
         KSObTlZCLB8aLjrAN9szoXw/kzmfoQll9dQvfumupLYF4ISg4/PumvLM66veJxg14B+r
         KZ9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=gygiBi858+OMNq2QZ01iGVgTSQaMr/LYCUbz/sHwnYE=;
        b=XCuUR+efGzFaiC0Wi5F6Ihkx2gr7Odg+KTdGFsyBo71nJ7hmLGHRwu5X6swlo6uXTp
         enWh7awhSxC/fAVypb6kZywQBerc1gyLHHV3FuQm+h+8G9k8VGqR8ShSezBiU74koDmd
         CSabTAzxhDJpoWGxQKiqWUoayWS/LzUjAcrmp3OOCUz4hK3oi31QQ5JX8fmBQDXldTkS
         BpSqy4hEmQu2pxOW2O5YATxLAy3L2mPKkuh5RFAVzvfS7XrTqGU/aYmqsjUvNbWG0Ckm
         qECI11f+6j0oF562d8MNOmghwIeM/4jEGhM2oyIkaJx8CR+UKoYOt5vmb8DFAM4uuRWS
         z9dA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2ZNBcb61;
       spf=pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gygiBi858+OMNq2QZ01iGVgTSQaMr/LYCUbz/sHwnYE=;
        b=XFBYYMesJepp0QTP+6pXESqyfgzQi68nKFllyxIQeEWD7qiyvjc5pbrAVHjXqd8qPM
         wntA3hoG/YSEW45t89vtD2kzXGJFgVk86vkLY+rvApExMG2Ac1uEHdnUckbXAQfjYbId
         Ff0BBKhUmFRTXJoU3UBHSCwFV2pmPGOQMMBCGnqtc0xBoH3RcxSYqnM+IukHTmF5BshW
         8+0zDXEkFQAwxkkEhZ9kpCdqK96S+6F3MPcdN7lhOWYWeccNcfn0nA1SVAZ9oG1l6Cnb
         svZgdcv4VnAqd1p/s1yse3V6gP1RVC49W7iz9SnNcffrOL3/aco0+545idhNap0Ci/Pi
         JsXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gygiBi858+OMNq2QZ01iGVgTSQaMr/LYCUbz/sHwnYE=;
        b=tUQoLZhGoZRNyPfbkrReVCGTMWeZmCCSANWKQIP5U/WPzo0nqoUGeS4nWhrYbvq43X
         N3Mu/cAg/sFc7jQvokXf5xS4nhcTRNqmFpblVOCX7uawb1/hluUvnWoUQWWSWXHEBmi5
         MPNQzeeFifOf+1BfzvmGjdnQacdwXVeskYTzLwggq6oOJ5ZQ0fyJi90uVLTBg6NqYaNs
         WWWFKNO5cJRohzP9SMFg3q+5FshQcjsRTFgQQHd1M0pp2HYiZGCKe1BTzdb7BFrh7HOk
         LwbNmZH5DEZiBCBjVnvYFOKRlzfd9gn0Blz7LqtCayvd44xhTKaDV1rwsrphQKTKUUUI
         siBA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531D3kJ3LBmpSDtp6Gd+ViG5HiYt8PDIlHfDVia+ocx90+lphC1f
	o5Gimkfnh3OLwSvJGgBkfe8=
X-Google-Smtp-Source: ABdhPJwqjevXl47Cvhcf80BucK2Fi2XX52nMj7mlo8mu5Jd4Z4DHjtt8S267+1TlpHD4Mplho4DLbA==
X-Received: by 2002:a62:1bd2:0:b029:160:816:6e9c with SMTP id b201-20020a621bd20000b029016008166e9cmr3939277pfb.77.1603828757973;
        Tue, 27 Oct 2020 12:59:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:cf0c:: with SMTP id h12ls613065pju.1.gmail; Tue, 27
 Oct 2020 12:59:17 -0700 (PDT)
X-Received: by 2002:a17:90b:14e:: with SMTP id em14mr3558118pjb.186.1603828757460;
        Tue, 27 Oct 2020 12:59:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603828757; cv=none;
        d=google.com; s=arc-20160816;
        b=Nkk3dEUb8Z5wDcSU1hrfUjDdQhQZfyC9IBvuG965K3c7J5SFTGluSBxeMFQPBbhjU+
         iVsNuJhiU3mCba2gk0R2O6mjtDxkW2kRSjVOmEhtMMv2THylc96YWttpE3YeD8pxWJv4
         6LTeahu3uqELg6e9aJatZ4W6dHYK5Nfz6Sy3K9OtbEweuGvroqMizi0cAarMFJoVIkxU
         oC842X5AJpt8KtXLVDpewQapDXwQZC3yIJcXK9+5DKonfAGHErI+f0qAHlyZ8ezWOlw7
         CCpRki0mL8sG+YMzKoXaENBb+ya4owu8bGzpyS5RLg2o9rX533GmasXJ1DzwCZ6xZfvx
         MgOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=Gl6Az4RLQishE1k470zLyKpdZmbcruEDDoINRHvdi7A=;
        b=Y9Mx6CKJs2u9IBlPIuaugNRJB14+Y5eZRyI9mX/ftU7Sx3zRtk2leoAmjSriKhsujS
         4yCRus/ULTSj8a6Wgz/ROo9OflJeqcsz4t4nbvxUAKsOi6ku3k7Aoo8Zijnp3M/Uv5xz
         wqYhUFw9k7kTF2uHkG+0WXQ8nDhslkpi+95WYaXn4Z02SwOm9OL7Wl26eGiH/8LeW9kH
         VBO/kDfRas0dvr/aOiECIFsRJBzyHSxC71mDXMBUhZn/auj7m9MXDs1ZeIPtXZf/UDKN
         697xQyTTqSbo+gxoDBxUe67LILS59l7g9jES1o752Kt/l4HJfup26K8VmUfouLs1Jw4S
         6VKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=2ZNBcb61;
       spf=pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j63si173025pfd.1.2020.10.27.12.59.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Oct 2020 12:59:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id DAD262076B;
	Tue, 27 Oct 2020 19:59:16 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 7D313352285C; Tue, 27 Oct 2020 12:59:16 -0700 (PDT)
Date: Tue, 27 Oct 2020 12:59:16 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>,
	Andrii Nakryiko <andriin@fb.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: Recording allocation location for blocks of memory?
Message-ID: <20201027195916.GA3249@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20201027175810.GA26121@paulmck-ThinkPad-P72>
 <CACT4Y+bB4sZjLx6tL6F5XzxGk5iG7j=SPbDkX_bwRXmXB=JxXA@mail.gmail.com>
 <CANpmjNNxAvembOetv15FfZ=04mpj0Qwx+1tnn22tABaHHRRv=Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNxAvembOetv15FfZ=04mpj0Qwx+1tnn22tABaHHRRv=Q@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=2ZNBcb61;       spf=pass
 (google.com: domain of srs0=extf=ec=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=EXtf=EC=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Tue, Oct 27, 2020 at 08:45:43PM +0100, Marco Elver wrote:
> Hi Paul,
> 
> Let me add another option below, as an alternative to KASAN that
> Dmitry mentioned.
> 
> On Tue, 27 Oct 2020 at 19:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Tue, Oct 27, 2020 at 6:58 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > Hello!
> > >
> > > I have vague memories of some facility some time some where that recorded
> > > who allocated a given block of memory, but am not seeing anything that
> > > does this at present.  The problem is rare enough and the situation
> > > sufficiently performance-sensitive that things like ftrace need not apply,
> > > and the BPF guys suggest that BPF might not be the best tool for this job.
> 
> Since you mention "performance-sensitive" and you say that "ftrace
> need not apply", I have a suspicion that KASAN also need not apply.
> KASAN itself uses lib/stackdepot.c to store stacktraces, which
> deduplicates stack traces by hashing them; but over time its usage
> grows significantly and may also not be suitable for production even
> if you manage to use it without KASAN somehow.
> 
> If you want something for production that more or less works
> out-of-the-box, KFENCE might work. :-)
> v5 here: https://lkml.kernel.org/r/20201027141606.426816-1-elver@google.com
> 
> You can just get KFENCE to print the allocation stack (and free stack
> if the object has been freed) by calling
> kfence_handle_page_fault(obj_addr), which should generate a
> use-after-free report if the object was allocated via KFENCE. You
> could check if the object was allocated with KFENCE with
> is_kfence_address(), but kfence_handle_page_fault() will just return
> if the object wasn't allocated via KFENCE.
> 
> If you do have the benefit of whatever you're hunting being deployed
> across lots of machines in production, it might work.
> 
> If it's not deployed across lots of machines, you might get lucky if
> you set kfence.sample_interval=1 and CONFIG_KFENCE_NUM_OBJECTS=4095
> (will use 32 MiB for the KFENCE pool; but you can make it larger to be
> sure it won't be exhausted too soon).

Thank you!  I will look into this as well!

							Thanx, Paul

> > > The problem I am trying to solve is that a generic function that detects
> > > reference count underflow that was passed to call_rcu(), and there are
> > > a lot of places where the underlying problem might lie, and pretty much
> > > no information.  One thing that could help is something that identifies
> > > which use case the underflow corresponds to.
> > >
> > > So, is there something out there (including old patches) that, given a
> > > pointer to allocated memory, gives some information about who allocated
> > > it?  Or should I risk further inflaming the MM guys by creating one?  ;-)
> >
> > Hi Paul,
> >
> > KASAN can do this. However (1) it has non-trivial overhead on its own
> > (but why would you want to debug something without KASAN anyway :))
> > (2) there is no support for doing just stack collection without the
> > rest of KASAN (they are integrated at the moment) (3) there is no
> > public interface function that does what you want, though, it should
> > be easy to add it. The code is around here:
> > https://github.com/torvalds/linux/blob/master/mm/kasan/report.c#L111-L128
> >
> > Since KASAN already bears all overheads of stack collection/storing I
> > was thinking that lots of other debugging tools could indeed piggy
> > back on that and print much more informative errors message when
> > enabled with KASAN.
> >
> > Since recently KASAN also memorizes up to 2 "other" stacks per
> > objects. This is currently used to memorize call_rcu stacks, since
> > they are frequently more useful than actual free stacks for
> > rcu-managed objects.
> > That mechanism could also memorize last refcount stacks, however I
> > afraid that they will evict everything else, since we have only 2
> > slots, and frequently there are lots of refcount operations.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027195916.GA3249%40paulmck-ThinkPad-P72.
