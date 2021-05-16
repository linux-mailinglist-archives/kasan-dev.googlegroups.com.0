Return-Path: <kasan-dev+bncBCJZRXGY5YJBBVP7QSCQMGQEE7GANMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id A2302381F8C
	for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 17:52:55 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id m7-20020a6545c70000b029020f6af21c77sf2933906pgr.6
        for <lists+kasan-dev@lfdr.de>; Sun, 16 May 2021 08:52:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621180373; cv=pass;
        d=google.com; s=arc-20160816;
        b=GzdKISI8vj9CR43kYqp1BEFeAC2QSc7UIapo5jZ9HuspwkVZ+/t1umzxG1SaLUNJRH
         0JFEBmajdZ2iOgiMvRws7a0Q8TuXEvizwKouMNESiHzN6cx0mXxYuO/L8mmYcWdETmea
         +yXPDuH1JCa2n1c+fgU8v1DNlOWZ0R4I48x5NWh13hC+k3zQa8AovHmyRGO9KTS9RVj0
         7PszZi36hn7gHOlhIH1cn+xAvFWa5UhcgXnpt8yB3h/EDTmyeLUA6SMBOfwvcsK09F+1
         r7J3ojacQxd+OrVhyLiUdU8yOtcBjApzcfS17VLnQgFXmYMc0FxQYpjxwBBU/55X0P/q
         rGtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-disposition:mime-version:reply-to:message-id:subject:to
         :from:date:sender:dkim-signature;
        bh=32JNAKznsMDMKGeVrwGfvWwkaDqvQCgLHeIcetbqv4M=;
        b=XGAKaQJiHTUZOwfXA6gq1zbSiAghrbLRxrXDswrpo37YArRhe31+IHUoVgwIWMTeIR
         VTI3HCp9g6mi05mahTubg4+BuSeC2RyG9vCDxFT3iZG5cUF2RmX40JXxxsDHz9zRPOI4
         dpfyteywPlBs9CBUwFdyrbn3ONa3xiYRPphfe9H95czKINrZ7kgJT6qK6eq3hxHjni4d
         tOEvxOwuIuaWxo67mND29wR1kaoqUxWihyCUKtkDTYOzJrUOD2NYon6fcSlSpnC5bB7T
         s7z59PAfKrpV4yEE8AgCUmQIK2htYjeX4AJ3OGl0nmRTcFSFg4uOkMCg4v1OiA6R7M6B
         MZFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BlQGMP9M;
       spf=pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:message-id:reply-to:mime-version
         :content-disposition:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=32JNAKznsMDMKGeVrwGfvWwkaDqvQCgLHeIcetbqv4M=;
        b=TmVEOVxkYE6fwsdX88jUxywykbX4XsvPI53BbebjTQ3GAZn4piN4HzlnbBM7A09cA/
         J6KEWI/+btKA5v16CAG0FLW7fftc4c+4cyEXZCdmng6I8YLIDVkhO76JXQyNaUGm9jup
         q2tmywkEDH9eEGloT9S49T+bYmCjL7yFNxn1Ku9mZmsIiKcrZYqbtMWGtd48ApUm3Rz3
         ByJMH+45MvpD+7NL8zHZNNjQi51SzPy3eg0LDCzXNWaDTOF8dMgs0au1IvFvKGVuk8LP
         8cWlkR0fLyruusWT12dxin1gHBdZcc5RC24wm/9kzTor/bu48WWCAfSgedpV+tsqu+OD
         /pDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:message-id:reply-to
         :mime-version:content-disposition:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=32JNAKznsMDMKGeVrwGfvWwkaDqvQCgLHeIcetbqv4M=;
        b=AbHDOKeGGODfJOjC5bgTY6NVYYRiIQa5fr1nBCT/Q1ab9zrHz7ArNyfNsofjDeKWS9
         iQhyvbRNSAIypAqF81KC5zQwEwb6PkRjrEbiDl92P6rxkO5LycKLmtpYw6QILYrZka6M
         2mqqdG92mgfPtcSrj9XmFxWjvawi4uDnIlIK1n6iIVrSbBLtbpKVUXKz5M5zQhY9x5R0
         8nUsWhQTJNYlnykorYCWsYGbz0VtEqMw6oWDJcABr5Xh+u+2QK34p50Kdmdgu/KYJAdq
         QMcOv5leOFNqyt+UCAxnF/5eKsgTF7ZFJqOFrEpReZ3EtWutNDX5a5G5ulsr+SBEPxPt
         wxIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532r4XUePe3IVtl8fz7vWzceNkilat8gAEaF9wMU4nw+uaegUcXe
	GzpsmiXsmhG4aTWH/vSh0WE=
X-Google-Smtp-Source: ABdhPJwN+pdFCThJFd+JiFUmWImfwtb5y3gJfWwpUFBRE3bV0brfw27Pr2P/zEizRWd0U70dRImRag==
X-Received: by 2002:a17:90b:4b90:: with SMTP id lr16mr21585507pjb.203.1621180373112;
        Sun, 16 May 2021 08:52:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8e19:: with SMTP id c25ls5795589pfr.6.gmail; Sun, 16 May
 2021 08:52:52 -0700 (PDT)
X-Received: by 2002:a63:bf4e:: with SMTP id i14mr57081197pgo.277.1621180372597;
        Sun, 16 May 2021 08:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621180372; cv=none;
        d=google.com; s=arc-20160816;
        b=iWQgq5pOjxDyRwWUGGtTut09/ScCO2xIKMCDkd5mPajSpDnykrBSrfn9ywja/e1yCt
         wOiisyfHCcdYl3cL5Qdtm4qL1Uz0/gRt+ORnajcPdW96ZLKHpIqhBQzSOW2vrkcKxAy1
         1+k+zQj5insXsbpksx4Rdc/HdOhXOv27Cyn9V8vZ7WHOUiLUT2juFkOfIB2y/1NEMNAL
         lHBIPOj4UdehVakJgP39SmErYdyYxLBKRpDFTto38Th6j3UtK4j0DJww/O9yf+NE7D41
         y9EXG7sppmxBBUThJNiBzcYajMWcrUOHvWRVlTJZv8NeGh7q3DIP7coxrKNzlMY5GejM
         TgZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-disposition:mime-version:reply-to
         :message-id:subject:to:from:date:dkim-signature;
        bh=it2lQkmFqmR8Ponm+4rFKdPWgwUU0nRQDmyNA7dfTm0=;
        b=oi3DLtXJkHeqE9buTdoSMC0OEwpHRm2KiKjJiZyKJOj3kfNpIYO67But0GiWYiigEy
         ukAWYj01uZRVvHDFY6O7N/APODHPOJsYaK4h7WZhzwKQPbIvHc9D4Bm8sxx7IARGwI+R
         AC5PkiSJ0r2LLbUhKIKWQFqyq4Jea3xFprpjSwgK/vztJe3xLCHRWzV5fbHl5XXywrOd
         3VlonOkJPb7GCDWUJ0ym1Mm+VQMwCIWVi4X9azLT2mx5iflpc9JWE7dPenHOmbyh4Xs/
         Am6PM3TmEhHuoCEkGTgIsIXuzudHR6xjGa8y4cNN7yXxpqcwTv+UiO9GsMRNQJPVMEUv
         PLyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BlQGMP9M;
       spf=pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f1si880039plt.3.2021.05.16.08.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 16 May 2021 08:52:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 47F3961075;
	Sun, 16 May 2021 15:52:52 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A06175C03A8; Sun, 16 May 2021 08:52:51 -0700 (PDT)
Date: Sun, 16 May 2021 08:52:51 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Fw: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210516155251.GA3952724@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BlQGMP9M;       spf=pass
 (google.com: domain of srs0=xrg5=kl=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=XRG5=KL=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

[ Restricting to KCSAN people for this question. ]

> On Fri, May 14, 2021 at 07:41:02AM +0200, Manfred Spraul wrote:
> > On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> > > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:

[ . . . ]

> > > Actually, you just demonstrated that this example is quite misleading=
.
> > > That data_race() works only because the read is for diagnostic
> > > purposes.  I am queuing a commit with your Reported-by that makes
> > > read_foo_diagnostic() just do a pr_info(), like this:
> > >=20
> > > 	void read_foo_diagnostic(void)
> > > 	{
> > > 		pr_info("Current value of foo: %d\n", data_race(foo));
> > > 	}
> > >=20
> > > So thank you for that!
> >=20
> > I would not like this change at all.
> > Assume you chase a rare bug, and notice an odd pr_info() output.
> > It will take you really long until you figure out that a data_race() mi=
slead
> > you.
> > Thus for a pr_info(), I would consider READ_ONCE() as the correct thing=
.
>=20
> It depends, but I agree with a general preference for READ_ONCE() over
> data_race().
>=20
> However, for some types of concurrency designs, using a READ_ONCE()
> can make it more difficult to enlist KCSAN's help.  For example, if this
> variable is read or written only while holding a particular lock, so that
> read_foo_diagnostic() is the only lockless read, then using READ_ONCE()
> adds a concurrent read.  In RCU, the updates would now need WRITE_ONCE(),
> which would cause KCSAN to fail to detect a buggy lockless WRITE_ONCE().
> If data_race() is used, then adding a buggy lockless WRITE_ONCE() will
> cause KCSAN to complain.
>=20
> Of course, you would be quite correct to say that this must be balanced
> against the possibility of a messed-up pr_info() due to compiler mischief=
.
> Tradeoffs, tradeoffs!  ;-)

On the other hand, a few quick experiements with data_race(READ_ONCE(foo))
lead me to believe that this would do what Manfred wants.  If so, I should
add this possibility to the documentation:  Prevent destructive compiler
optimizations while at the same time causing KCSAN to ignore the access.

Or did I just get lucky?

							Thanx, Paul

> I should document this tradeoff, shouldn't I?
>=20
> > What about something like the attached change?
> >=20
> > --
> >=20
> > =C2=A0=C2=A0=C2=A0 Manfred
> >=20
> >=20
>=20
> > diff --git a/tools/memory-model/Documentation/access-marking.txt b/tool=
s/memory-model/Documentation/access-marking.txt
> > index 1ab189f51f55..588326b60834 100644
> > --- a/tools/memory-model/Documentation/access-marking.txt
> > +++ b/tools/memory-model/Documentation/access-marking.txt
> > @@ -68,6 +68,11 @@ READ_ONCE() and WRITE_ONCE():
> > =20
> >  4.	Writes setting values that feed into error-tolerant heuristics.
> > =20
> > +In theory, plain C-language loads can also be used for these use cases=
.
> > +However, in practice this will have the disadvantage of causing KCSAN
> > +to generate false positives because KCSAN will have no way of knowing
> > +that the resulting data race was intentional.
> > +
> > =20
> >  Data-Racy Reads for Approximate Diagnostics
> > =20
> > @@ -86,11 +91,6 @@ that fail to exclude the updates.  In this case, it =
is important to use
> >  data_race() for the diagnostic reads because otherwise KCSAN would giv=
e
> >  false-positive warnings about these diagnostic reads.
> > =20
> > -In theory, plain C-language loads can also be used for this use case.
> > -However, in practice this will have the disadvantage of causing KCSAN
> > -to generate false positives because KCSAN will have no way of knowing
> > -that the resulting data race was intentional.
> > -
> > =20
> >  Data-Racy Reads That Are Checked Against Marked Reload
> > =20
> > @@ -110,11 +110,6 @@ that provides the compiler much less scope for mis=
chievous optimizations.
> >  Capturing the return value from cmpxchg() also saves a memory referenc=
e
> >  in many cases.
> > =20
> > -In theory, plain C-language loads can also be used for this use case.
> > -However, in practice this will have the disadvantage of causing KCSAN
> > -to generate false positives because KCSAN will have no way of knowing
> > -that the resulting data race was intentional.
>=20
> Normally, I would be completely in favor of your suggestion to give
> this advice only once.  But in this case, there are likely to be people
> reading just the part of the document that they think applies to their
> situation.  So it is necessary to replicate the reminder into all the
> sections.
>=20
> That said, I do applaud your approach of reading the whole thing.  That
> of course gets you a much more complete understanding of the situation,
> and gets me more feedback.  ;-)
>=20
> >  Reads Feeding Into Error-Tolerant Heuristics
> > =20
> > @@ -125,11 +120,9 @@ that data_race() loads are subject to load fusing,=
 which can result in
> >  consistent errors, which in turn are quite capable of breaking heurist=
ics.
> >  Therefore use of data_race() should be limited to cases where some oth=
er
> >  code (such as a barrier() call) will force the occasional reload.
> > -
> > -In theory, plain C-language loads can also be used for this use case.
> > -However, in practice this will have the disadvantage of causing KCSAN
> > -to generate false positives because KCSAN will have no way of knowing
> > -that the resulting data race was intentional.
> > +The heuristics must be able to handle any error. If the heuristics are
> > +only able to handle old and new values, then WRITE_ONCE()/READ_ONCE()
> > +must be used.
>=20
> Excellent addition!  I have applied the commit shown below with your
> Signed-off-by.  Please let me know if you would like me to take some othe=
r
> course of action.  And also please let me know if I messed something up.
>=20
> >  Writes Setting Values Feeding Into Error-Tolerant Heuristics
> > @@ -142,11 +135,8 @@ due to compiler-mangled reads, it can also tolerat=
e the occasional
> >  compiler-mangled write, at least assuming that the proper value is in
> >  place once the write completes.
> > =20
> > -Plain C-language stores can also be used for this use case.  However,
> > -in kernels built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn, thi=
s
> > -will have the disadvantage of causing KCSAN to generate false positive=
s
> > -because KCSAN will have no way of knowing that the resulting data race
> > -was intentional.
> > +Note that KCSAN will only detect mangled writes in kernels built with
> > +CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn.
>=20
> And the same point on needing to say this more than once.
>=20
> 							Thanx, Paul
>=20
> ------------------------------------------------------------------------
>=20
> commit 48db6caa1d32c39e7405df3940f9f7ba07ed0527
> Author: Manfred Spraul <manfred@colorfullife.com>
> Date:   Fri May 14 11:40:06 2021 -0700
>=20
>     tools/memory-model: Heuristics using data_race() must handle all valu=
es
>    =20
>     Data loaded for use by some sorts of heuristics can tolerate the
>     occasional erroneous value.  In this case the loads may use data_race=
()
>     to give the compiler full freedom to optimize while also informing KC=
SAN
>     of the intent.  However, for this to work, the heuristic needs to be
>     able to tolerate any erroneous value that could possibly arise.  This
>     commit therefore adds a paragraph spelling this out.
>    =20
>     Signed-off-by: Manfred Spraul <manfred@colorfullife.com>
>     Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
>=20
> diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/=
memory-model/Documentation/access-marking.txt
> index e4a20ebf565d..22ecadec4894 100644
> --- a/tools/memory-model/Documentation/access-marking.txt
> +++ b/tools/memory-model/Documentation/access-marking.txt
> @@ -126,6 +126,11 @@ consistent errors, which in turn are quite capable o=
f breaking heuristics.
>  Therefore use of data_race() should be limited to cases where some other
>  code (such as a barrier() call) will force the occasional reload.
> =20
> +Note that this use case requires that the heuristic be able to handle
> +any possible error.  In contrast, if the heuristics might be fatally
> +confused by one or more of the possible erroneous values, use READ_ONCE(=
)
> +instead of data_race().
> +
>  In theory, plain C-language loads can also be used for this use case.
>  However, in practice this will have the disadvantage of causing KCSAN
>  to generate false positives because KCSAN will have no way of knowing
>=20
> ----- End forwarded message -----

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210516155251.GA3952724%40paulmck-ThinkPad-P17-Gen-1.
