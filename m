Return-Path: <kasan-dev+bncBCJZRXGY5YJBBKEK7OCAMGQET5UMR3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BCD6380FF9
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 20:44:57 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id b3-20020a4ab4830000b029020d5d68e38dsf150859ooo.21
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 11:44:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621017896; cv=pass;
        d=google.com; s=arc-20160816;
        b=SUzjbD2KmNT+1fb5smraVestbqynt5kYG26xRgsQskic3I3Hkpa3BMLTg33naunrey
         O+XaR/H4iGq987Es/TPFQ8lCCMOaWWKEwTFSfgp3dnzuRVLF/72T/a9HxetLH8PvLngj
         OVBT9HKonz2OnFcGL5F8RicdMYut19RZfNvXT8hq7RpXpygwm8QStDjDy92W27/EMCdQ
         0JyxI/gfEzjMtLTZmmEXpr2ZF4XYI/H68daGEr7W+C+HyS7vQxh+A7aH03KVUZ5Kkzmo
         OTm0XVUE++ILeX4fZaNVl7kYVotyVdfqfSCqwgfhNh1OPZ773MqAkQVzvuZSc+WLHfeX
         l1xQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Ex8y252ZQq8mHMR5H1GHxOzf5ptFgaQIm/7fzz7BALM=;
        b=kGwencXeegTrU68lPrxZgsPwxXrLSWfGxqGiwR9GhZq9JQc13UtV4ZRgDaj4wsLweX
         C8mfW8sJwYZUxJPPuH46VSoYJ+Mk77ztl7YDvaZ4pl7QqOgAqtTtpguLxcjJqjntUqnN
         w0nxLzmtUfYrAVPd4hKP1Wi+bAZy2BOmLNFZVKrJmEMqy2piXopH/VtqWdvR0p6Zh9QH
         auXs3l1NDN4md0JWYeDBLqWq0eIqdX4PnodmI7x27bvtA4P8kNzSblirZ68sN8egSThz
         Jgm9xCLlVOsf0Wdb3VGlnI77csHk0pGBbC7grqHpn2V4iZ3u92XrepAod2uEUo2k9iqM
         K2BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=L9B0QIsH;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ex8y252ZQq8mHMR5H1GHxOzf5ptFgaQIm/7fzz7BALM=;
        b=d+GmXX2a43HU2IHGxu2vcVD6I8gNU5VHsryAV39Y5r699HfbswyhsVsk3JIa0ERhFO
         +e4x9GocloUFVVpIb+YaHy0DNt7X+AXNULxTBwE29Ua3xS8CkokCXgodcgpMIk/FsfSd
         2LXSMR0SqPB/XibjQW+twTTByKOgCkPb9Czib4j4qm4vRzPqx3kPnEcLnB2syZt28EWr
         z5ghRiu2IVLfRw8ojlulkwXx7r+bZXNX7ZStkY6NB+woZAV6l9DDBgCFXsVihReBJ5wF
         BE323iEGreCLQcmKVGncX4pXaDfyYt9eRrae9NYZgRRsxlc8XfsZ9xARytH56X4qrQmQ
         wVvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ex8y252ZQq8mHMR5H1GHxOzf5ptFgaQIm/7fzz7BALM=;
        b=otCv4im3Sha325LLukkF5akD0OGnC8bkycM420w/yCe09lV5pUDeq7pmvtrD8hSw6x
         bIJvlN1SevrLI2IFi8gULH6sobxYwKcrUaLJMtlQaJqA4gySMcgKXC5d5gLbWHDFGcbm
         lIl7CPgLqOZQqFIdHq5VMmimChlvCFfSIUIm1r+oMjnr8OzRfrfzpangeI6Wm9xYv4NG
         Y8DLj+cIAiyO2f2i93XggRmew/PzZxnyp9M0gYqFCvkKOLaGStPThqxGODGa0tGwBtv1
         bpigEi3c7KGxeGnFW3Q/FG0F2lTXWO4alpohhdse9w8MFcMLKaEqmSLwiKWRg4BvG3AJ
         ZWUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ejov7UWgzXxsDEBlT8leKJ6kAkcESXb9GKbn5VBf6v2hkEvvy
	+zhca/lok09rBRgHk43czDg=
X-Google-Smtp-Source: ABdhPJzo8gOX5Br2EuOmyZruZ02LKgdDkA8HtpTFlZwj+GUoyfa+Gyjmd/BV999C/+X+vMzHdYKr6Q==
X-Received: by 2002:a4a:8706:: with SMTP id z6mr19923071ooh.41.1621017896381;
        Fri, 14 May 2021 11:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:a6f:: with SMTP id 102ls2818125otg.8.gmail; Fri, 14 May
 2021 11:44:56 -0700 (PDT)
X-Received: by 2002:a9d:2271:: with SMTP id o104mr40510569ota.201.1621017895983;
        Fri, 14 May 2021 11:44:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621017895; cv=none;
        d=google.com; s=arc-20160816;
        b=Jaity89J7R9aVcr91CQIL486Cqa+UcZVZRp8s90TKyfKpIaPgfG+4HYjs9LgIZkWX7
         SXrqD5nqLvxzRD1EDLGPy9KUNk0rhexJfFPlK1BThM3MKnQxchfZRT/5gItGhqU9TVVI
         hAHBUFneQ0vDFCTX0XFG7kjJvwRe8nYfEn7MWjDyNZldg3O+FyuNhyxCFsn4Irvys/+L
         oJ3HZCPr2cFQ8tAfDp+AACxhJjmbKEQxkCvlOZanjD3X0NVz4cxKovwXHmdx3UMA6tGr
         mE7PcNjPwGcJdkbmLL7G52wVZo2feuuo4Xq/Y8tdmMNpwmWRP6RTfLyEnEs+b1/VMEnC
         tHXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=G9/YH7HyrOnJuePuWbrF8iSWbzURph3OkKshKeXvwvg=;
        b=iiLpc0pUoGx82r3rVCU5UmKgExrGXAA1StjxM47b2PIEwBkNr7sDVyGoPFGuh/wf/D
         cLVWSXFTUoRMNe+J24+lKo+jFF0kziQlRcBFRSg/DcODNeb/QFVJoQukjY/WADSyfI/Q
         BBssN/BuKstBxtSue74naGbZdjsELAF+NEwOCLNkWipMy15qB/aF29+UHytyWD95kHud
         0j5WrjK5x3af18H/4MsRUmfkJznCcQbEw1ZS6RhdfZ5XqejEcKbHNNJfw4Gn4Ob6g7UC
         UFoA8YlgBn9rmGRW8ucN0ZU5bCRZZisZxN/1tBcIaRozgXlPCbuLMqoPxuvQUxNabRPV
         8aPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=L9B0QIsH;
       spf=pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x16si682636otr.5.2021.05.14.11.44.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 11:44:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3EEFF61177;
	Fri, 14 May 2021 18:44:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 0DB735C02A5; Fri, 14 May 2021 11:44:55 -0700 (PDT)
Date: Fri, 14 May 2021 11:44:55 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Manfred Spraul <manfred@colorfullife.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
Message-ID: <20210514184455.GJ975577@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
 <9c9739ec-1273-5137-7b6d-00a27a22ffca@colorfullife.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <9c9739ec-1273-5137-7b6d-00a27a22ffca@colorfullife.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=L9B0QIsH;       spf=pass
 (google.com: domain of srs0=/njc=kj=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=/nJc=KJ=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Fri, May 14, 2021 at 07:41:02AM +0200, Manfred Spraul wrote:
> On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> > On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
> > > Hi Paul,
> > >=20
> > > On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> > > [...]
> > > > 	int foo;
> > > > 	DEFINE_RWLOCK(foo_rwlock);
> > > >=20
> > > > 	void update_foo(int newval)
> > > > 	{
> > > > 		write_lock(&foo_rwlock);
> > > > 		foo =3D newval;
> > > > 		do_something(newval);
> > > > 		write_unlock(&foo_rwlock);
> > > > 	}
> > > >=20
> > > > 	int read_foo(void)
> > > > 	{
> > > > 		int ret;
> > > >=20
> > > > 		read_lock(&foo_rwlock);
> > > > 		do_something_else();
> > > > 		ret =3D foo;
> > > > 		read_unlock(&foo_rwlock);
> > > > 		return ret;
> > > > 	}
> > > >=20
> > > > 	int read_foo_diagnostic(void)
> > > > 	{
> > > > 		return data_race(foo);
> > > > 	}
> > > The text didn't help, the example has helped:
> > >=20
> > > It was not clear to me if I have to use data_race() both on the read =
and the
> > > write side, or only on one side.
> > >=20
> > > Based on this example: plain C may be paired with data_race(), there =
is no
> > > need to mark both sides.
> > Actually, you just demonstrated that this example is quite misleading.
> > That data_race() works only because the read is for diagnostic
> > purposes.  I am queuing a commit with your Reported-by that makes
> > read_foo_diagnostic() just do a pr_info(), like this:
> >=20
> > 	void read_foo_diagnostic(void)
> > 	{
> > 		pr_info("Current value of foo: %d\n", data_race(foo));
> > 	}
> >=20
> > So thank you for that!
>=20
> I would not like this change at all.
> Assume you chase a rare bug, and notice an odd pr_info() output.
> It will take you really long until you figure out that a data_race() misl=
ead
> you.
> Thus for a pr_info(), I would consider READ_ONCE() as the correct thing.

It depends, but I agree with a general preference for READ_ONCE() over
data_race().

However, for some types of concurrency designs, using a READ_ONCE()
can make it more difficult to enlist KCSAN's help.  For example, if this
variable is read or written only while holding a particular lock, so that
read_foo_diagnostic() is the only lockless read, then using READ_ONCE()
adds a concurrent read.  In RCU, the updates would now need WRITE_ONCE(),
which would cause KCSAN to fail to detect a buggy lockless WRITE_ONCE().
If data_race() is used, then adding a buggy lockless WRITE_ONCE() will
cause KCSAN to complain.

Of course, you would be quite correct to say that this must be balanced
against the possibility of a messed-up pr_info() due to compiler mischief.
Tradeoffs, tradeoffs!  ;-)

I should document this tradeoff, shouldn't I?

> What about something like the attached change?
>=20
> --
>=20
> =C2=A0=C2=A0=C2=A0 Manfred
>=20
>=20

> diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/=
memory-model/Documentation/access-marking.txt
> index 1ab189f51f55..588326b60834 100644
> --- a/tools/memory-model/Documentation/access-marking.txt
> +++ b/tools/memory-model/Documentation/access-marking.txt
> @@ -68,6 +68,11 @@ READ_ONCE() and WRITE_ONCE():
> =20
>  4.	Writes setting values that feed into error-tolerant heuristics.
> =20
> +In theory, plain C-language loads can also be used for these use cases.
> +However, in practice this will have the disadvantage of causing KCSAN
> +to generate false positives because KCSAN will have no way of knowing
> +that the resulting data race was intentional.
> +
> =20
>  Data-Racy Reads for Approximate Diagnostics
> =20
> @@ -86,11 +91,6 @@ that fail to exclude the updates.  In this case, it is=
 important to use
>  data_race() for the diagnostic reads because otherwise KCSAN would give
>  false-positive warnings about these diagnostic reads.
> =20
> -In theory, plain C-language loads can also be used for this use case.
> -However, in practice this will have the disadvantage of causing KCSAN
> -to generate false positives because KCSAN will have no way of knowing
> -that the resulting data race was intentional.
> -
> =20
>  Data-Racy Reads That Are Checked Against Marked Reload
> =20
> @@ -110,11 +110,6 @@ that provides the compiler much less scope for misch=
ievous optimizations.
>  Capturing the return value from cmpxchg() also saves a memory reference
>  in many cases.
> =20
> -In theory, plain C-language loads can also be used for this use case.
> -However, in practice this will have the disadvantage of causing KCSAN
> -to generate false positives because KCSAN will have no way of knowing
> -that the resulting data race was intentional.

Normally, I would be completely in favor of your suggestion to give
this advice only once.  But in this case, there are likely to be people
reading just the part of the document that they think applies to their
situation.  So it is necessary to replicate the reminder into all the
sections.

That said, I do applaud your approach of reading the whole thing.  That
of course gets you a much more complete understanding of the situation,
and gets me more feedback.  ;-)

>  Reads Feeding Into Error-Tolerant Heuristics
> =20
> @@ -125,11 +120,9 @@ that data_race() loads are subject to load fusing, w=
hich can result in
>  consistent errors, which in turn are quite capable of breaking heuristic=
s.
>  Therefore use of data_race() should be limited to cases where some other
>  code (such as a barrier() call) will force the occasional reload.
> -
> -In theory, plain C-language loads can also be used for this use case.
> -However, in practice this will have the disadvantage of causing KCSAN
> -to generate false positives because KCSAN will have no way of knowing
> -that the resulting data race was intentional.
> +The heuristics must be able to handle any error. If the heuristics are
> +only able to handle old and new values, then WRITE_ONCE()/READ_ONCE()
> +must be used.

Excellent addition!  I have applied the commit shown below with your
Signed-off-by.  Please let me know if you would like me to take some other
course of action.  And also please let me know if I messed something up.

>  Writes Setting Values Feeding Into Error-Tolerant Heuristics
> @@ -142,11 +135,8 @@ due to compiler-mangled reads, it can also tolerate =
the occasional
>  compiler-mangled write, at least assuming that the proper value is in
>  place once the write completes.
> =20
> -Plain C-language stores can also be used for this use case.  However,
> -in kernels built with CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn, this
> -will have the disadvantage of causing KCSAN to generate false positives
> -because KCSAN will have no way of knowing that the resulting data race
> -was intentional.
> +Note that KCSAN will only detect mangled writes in kernels built with
> +CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn.

And the same point on needing to say this more than once.

							Thanx, Paul

------------------------------------------------------------------------

commit 48db6caa1d32c39e7405df3940f9f7ba07ed0527
Author: Manfred Spraul <manfred@colorfullife.com>
Date:   Fri May 14 11:40:06 2021 -0700

    tools/memory-model: Heuristics using data_race() must handle all values
   =20
    Data loaded for use by some sorts of heuristics can tolerate the
    occasional erroneous value.  In this case the loads may use data_race()
    to give the compiler full freedom to optimize while also informing KCSA=
N
    of the intent.  However, for this to work, the heuristic needs to be
    able to tolerate any erroneous value that could possibly arise.  This
    commit therefore adds a paragraph spelling this out.
   =20
    Signed-off-by: Manfred Spraul <manfred@colorfullife.com>
    Signed-off-by: Paul E. McKenney <paulmck@kernel.org>

diff --git a/tools/memory-model/Documentation/access-marking.txt b/tools/me=
mory-model/Documentation/access-marking.txt
index e4a20ebf565d..22ecadec4894 100644
--- a/tools/memory-model/Documentation/access-marking.txt
+++ b/tools/memory-model/Documentation/access-marking.txt
@@ -126,6 +126,11 @@ consistent errors, which in turn are quite capable of =
breaking heuristics.
 Therefore use of data_race() should be limited to cases where some other
 code (such as a barrier() call) will force the occasional reload.
=20
+Note that this use case requires that the heuristic be able to handle
+any possible error.  In contrast, if the heuristics might be fatally
+confused by one or more of the possible erroneous values, use READ_ONCE()
+instead of data_race().
+
 In theory, plain C-language loads can also be used for this use case.
 However, in practice this will have the disadvantage of causing KCSAN
 to generate false positives because KCSAN will have no way of knowing

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210514184455.GJ975577%40paulmck-ThinkPad-P17-Gen-1.
