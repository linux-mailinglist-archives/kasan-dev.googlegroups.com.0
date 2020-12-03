Return-Path: <kasan-dev+bncBCH2XPOBSAERBBUHUH7AKGQEVFFVW2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D5122CCBCB
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 02:46:47 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id f7sf233123oti.1
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Dec 2020 17:46:47 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=drosMIcexCTRcnx/fytPZWwjKqeSH5tITihr8X10Lhg=;
        b=lmjoznS867S+6HIgo1NFPSReOpXWKtTNPAX1iBYpP67M89SlwN8shj2LKAkRw/2Ru0
         VWMMuNLuNWk7qVod4SQcwfNziNWPdIqhS1DGxKhxYVCEWJyLuzNlIPd8/FPbX0c/hfzC
         jVfduX7lBAU6bfk0P5WZmdpnDvEvNHdL36fNh0HB9Gy0lKnItKaLUerU2/vyEtSKCp4y
         LIfeBZf8i8jzk6+nUPdi56DV0edMDG8ggaFFQ7vaLF480uzKhpL+5BOCGW4Vc5oTG67C
         E//LSo7GV7QLaO2g71NGpfsBjTw1SVqn/N81NHk1a8QSTwKU6sn9nHw577o5zhcjl8/k
         V+3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=drosMIcexCTRcnx/fytPZWwjKqeSH5tITihr8X10Lhg=;
        b=EjoA9rQsUj0JuAceBvu5JBclwFBSHslrzfxo1L19NxcmfEttWFDh1H/XWMtQwYHphJ
         /NWAU96e0Ga7DwvOTccvnlZlauA5shitZvKP48GKEJmD1YM7pn9gBgH4aYeupfmsBKYD
         eYauOT0urkM5DjvBUi3dJJjycUGO7ci6Q7WABaAh9waJEBes/OqgpZAtX5c578yW6yYk
         pTaCNtntOsCwgOkQON8Tpn1MUV5tjKLllTkQSz1FVafi9p6GPBFPSHfUTlv1nf2dDHfV
         9zutSRPLqJbxP5hLpxw0VvxgO1ygWw7xSuXA5tVMHuLoFLu00RrzxDE3fHYjY0yIUx5Q
         bLFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=drosMIcexCTRcnx/fytPZWwjKqeSH5tITihr8X10Lhg=;
        b=dzWB6FzqkUYVZqmqtbpxCDWDxIUk0ub3rKrHptXTp3iEEztEZ4k/+zYUvwBNLDSUaV
         44sG3VbTp6e3wJtPTdthcyuKxQLoO9H1cfR8xx4442gukD83WuEqJYuulvqXyg2itH6m
         k0iTO4cK7S51ddAGzszHB3T8PsMf2ABD3zU2FpY6xHyvoqiNiawX5MmIA48c7na8eCWD
         3HL3CUloO6qJOS3B97EEupNk1/7+ARISXIYoo6/WPYJQDUVFJKQYc+wKU0yTbgDDRt8a
         K9p17OOLLndN6o28mbwgYsbp/AqLVzGgYABZhh/eLPJ8TMDxGNAeKUGT4NKKNxSXVABk
         3aOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NNYVKUfTRcmx6/x5hFPrIoHZ9RwkoMWYiPcYO/kBSXH0X7lBL
	22FGThlDy99DlNXHRxM8YYY=
X-Google-Smtp-Source: ABdhPJx9MjoICnW0e25RXpOfAtdB3EaJrI+cYE3uAO82+/tvfHvDAvDW7N9oHsmtXm/pV9jPOMxJ/w==
X-Received: by 2002:aca:ebc2:: with SMTP id j185mr484012oih.158.1606960006199;
        Wed, 02 Dec 2020 17:46:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7ac3:: with SMTP id m3ls980575otn.2.gmail; Wed, 02 Dec
 2020 17:46:45 -0800 (PST)
X-Received: by 2002:a9d:6312:: with SMTP id q18mr305672otk.264.1606960005655;
        Wed, 02 Dec 2020 17:46:45 -0800 (PST)
Date: Wed, 2 Dec 2020 17:46:44 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <db967ee9-01c7-4baf-a53f-dedbdf170cc7n@googlegroups.com>
In-Reply-To: <20201202124600.GA4037382@elver.google.com>
References: <CAD-N9QXFwPPZC0t1662foXgHh6_KEFpGGB01hWWryBL=ZsBs0A@mail.gmail.com>
 <20201202124600.GA4037382@elver.google.com>
Subject: Re: Any cases to prove KCSAN can catch underlying data races that
 lead to kernel crashes?
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_11716_443435787.1606960004982"
X-Original-Sender: mudongliangabcd@gmail.com
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

------=_Part_11716_443435787.1606960004982
Content-Type: multipart/alternative; 
	boundary="----=_Part_11717_1813621634.1606960004982"

------=_Part_11717_1813621634.1606960004982
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable



On Wednesday, December 2, 2020 at 8:46:08 PM UTC+8 el...@google.com wrote:

> Hi Dongliang,=20
>
> Thank you for your question, which is something we're currently=20
> exploring ourselves. We're aware that there are currently numerous data=
=20
> races on syzbot's dashboard, and it will take time to sift through them.=
=20
>
> On Wed, Dec 02, 2020 at 08:05PM +0800, =E6=85=95=E5=86=AC=E4=BA=AE wrote:=
=20
>
> > I am writing to kindly ask if you know of any cases or kernel bugs that=
=20
> > prove KCSAN is able to catch underlying data races that lead to kernel=
=20
> > crashes.=20
>
> Have a look at the last slide in:=20
>
> https://github.com/google/ktsan/raw/kcsan/LPC2020-KCSAN.pdf=20
>
> > Before asking you this question, I searched data race bugs from=20
> > Syzkaller dashboard for my experiment. On one hand, I tried KCSAN crash=
=20
> > reports, but it is hard to locate a PoC for reproduction. On the other=
=20
> > hand, I found some race bugs that trigger KASAN reports or WARNING. The=
n=20
> I=20
> > disable KASAN and enable KCSAN, however, In two cases(65550098 rxrpc:=
=20
> Fix=20
> > race between recvmsg and sendmsg on immediate call failure=20
> > <
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?id=3D65550098c1c4db528400c73acf3e46bfa78d9264>=20
>
> > and d9fb8c50 mptcp: fix infinite loop on recvmsg()/worker() race.=20
> > <
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit=
/?id=3Dd9fb8c507d42256034b457ec59347855bec9e569>),=20
>
> > KCSAN did not report any problem during PoC running. Finally, I failed=
=20
> to=20
> > find any cases to prove that point. Therefore, if you know of some case=
s=20
> in=20
> > which KCSAN can catch underlying data races that lead to kernel crashes=
,=20
> > please let me know.=20
>
> In the following I'm outlining some background, and my current approach=
=20
> to reproduce some suspected race-condition bugs.=20
>
> Just to make sure we're talking about the same thing, first of all, I=20
> want to highlight the difference between data race and race-condition=20
> bugs: https://lwn.net/Articles/816850/#qq2answer ("What's the difference=
=20
> between "data races" and "race conditions"?)=20
>
> Clearly, data races are defined at the programming-language level and do=
=20
> not necessarily imply kernel crashes. Firstly, let's define the=20
> following 3 concurrency bug classes:=20
>
> A. Data race, where failure due to current compilers is unlikely=20
> (supposedly "benign"); merely marking the accesses=20
> appropriately is sufficient. Finding a crash for these will=20
> require a miscompilation, but otherwise look "benign" at the=20
> C-language level.=20
>
> B. Race-condition bugs where the bug manifests as a data race,=20
> too -- simply marking things doesn't fix the problem. These=20
> are the types of bugs where a data race would point out a=20
> more severe issue.=20
>
> C. Race-condition bugs where the bug never manifests as a data=20
> race. An example of these might be 2 threads that acquire the=20
> necessary locks, yet some interleaving of them still results=20
> in a bug (e.g. because the logic inside the critical sections=20
> is buggy). These are harder to detect with KCSAN as-is, and=20
> require using ASSERT_EXCLUSIVE_ACCESS() or=20
> ASSERT_EXCLUSIVE_WRITER() in the right place. See=20
> https://lwn.net/Articles/816854/.=20
>
> One problem currently is that the kernel has quite a lot type-(A)=20
> reports if we run KCSAN, which makes it harder to identify bugs of type=
=20
> (B) and (C). My wish for the future is that we can get to a place, where=
=20
> the kernel has almost no unintentional (A) issues, so that we primarily=
=20
> find (B) and (C) bugs.=20
>
>
Quick question here. I found that there is still a sanitizer for=20
concurrency bug called Kernel Thread Sanitizer. For the above types, what's=
=20
its detection capability compared with KCSAN?
=20

> It appears you were trying to use KCSAN to reproduce bugs of type (B).=20
> What we need to understand, however, is if the bugs you have been trying=
=20
> to reproduce with KCSAN are in fact of type (B) and not type (C).=20
>
> That's the high-level problem out of the way. The lower level problems=20
> pertain to how the current default KCSAN filters numerous data races.=20
> So, when debugging, my default recommendation is always going to be to=20
> change the config as follows:=20
>
> CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=3Dy=20
> CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn=20
> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn=20
> CONFIG_KCSAN_INTERRUPT_WATCHER=3Dy # add this after trying above=20
>
> Then, as you run your test-case, gradually decrease this value at=20
> runtime:=20
>
> echo $SOMETHING_SMALLER > /sys/module/kcsan/parameters/skip_watch=20
>
> Alternatively, or in addition, try to increase=20
> /sys/module/kcsan/parameters/udelay_task.=20
>
> For debugging purposes, it may even be fair to insert=20
> ASSERT_EXCLUSIVE_ACCESS() regardless if the bug should manifest as a=20
> data race or not, as it can help highlight what you're looking for as=20
> the reports start with a different title "KCSAN: assert: race in ...".=20
>
> Thank you for your interest in this, and hopefully you'll be able to=20
> proceed further using the above -- please ask if you have more=20
> questions. We'd appreciate if you share any results, as it will help us=
=20
> understand how we can optimize KCSAN to detect more races of types (B)=20
> and (C).=20
>
> Thanks,=20
> -- Marco=20
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/db967ee9-01c7-4baf-a53f-dedbdf170cc7n%40googlegroups.com.

------=_Part_11717_1813621634.1606960004982
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<br><br><div class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">O=
n Wednesday, December 2, 2020 at 8:46:08 PM UTC+8 el...@google.com wrote:<b=
r></div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; bor=
der-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">Hi Dongliang,
<br>
<br>Thank you for your question, which is something we're currently
<br>exploring ourselves. We're aware that there are currently numerous data
<br>races on syzbot's dashboard, and it will take time to sift through them=
.
<br>
<br>On Wed, Dec 02, 2020 at 08:05PM +0800, =E6=85=95=E5=86=AC=E4=BA=AE wrot=
e:
<br>
<br>&gt; I am writing to kindly ask if you know of any cases or kernel bugs=
 that
<br>&gt; prove KCSAN is able to catch underlying data races that lead to ke=
rnel
<br>&gt; crashes.
<br>
<br>Have a look at the last slide in:
<br>
<br>	<a href=3D"https://github.com/google/ktsan/raw/kcsan/LPC2020-KCSAN.pdf=
" target=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.go=
ogle.com/url?hl=3Den&amp;q=3Dhttps://github.com/google/ktsan/raw/kcsan/LPC2=
020-KCSAN.pdf&amp;source=3Dgmail&amp;ust=3D1607046147650000&amp;usg=3DAFQjC=
NHu2ptGDazgt7Sol0J6a3KSw-ZazQ">https://github.com/google/ktsan/raw/kcsan/LP=
C2020-KCSAN.pdf</a>
<br>
<br>&gt; Before asking you this question, I searched data race bugs from
<br>&gt; Syzkaller dashboard for my experiment. On one hand, I tried KCSAN =
crash
<br>&gt; reports, but it is hard to locate a PoC for reproduction. On the o=
ther
<br>&gt; hand, I found some race bugs that trigger KASAN reports or WARNING=
. Then I
<br>&gt; disable KASAN and enable KCSAN, however, In two cases(65550098 rxr=
pc: Fix
<br>&gt; race between recvmsg and sendmsg on immediate call failure
<br>&gt; &lt;<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/tor=
valds/linux.git/commit/?id=3D65550098c1c4db528400c73acf3e46bfa78d9264" targ=
et=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.c=
om/url?hl=3Den&amp;q=3Dhttps://git.kernel.org/pub/scm/linux/kernel/git/torv=
alds/linux.git/commit/?id%3D65550098c1c4db528400c73acf3e46bfa78d9264&amp;so=
urce=3Dgmail&amp;ust=3D1607046147650000&amp;usg=3DAFQjCNGffWlKcR8aEfCxr1FTv=
R6WBvE7bQ">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.g=
it/commit/?id=3D65550098c1c4db528400c73acf3e46bfa78d9264</a>&gt;
<br>&gt;  and d9fb8c50 mptcp: fix infinite loop on recvmsg()/worker() race.
<br>&gt; &lt;<a href=3D"https://git.kernel.org/pub/scm/linux/kernel/git/tor=
valds/linux.git/commit/?id=3Dd9fb8c507d42256034b457ec59347855bec9e569" targ=
et=3D"_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.c=
om/url?hl=3Den&amp;q=3Dhttps://git.kernel.org/pub/scm/linux/kernel/git/torv=
alds/linux.git/commit/?id%3Dd9fb8c507d42256034b457ec59347855bec9e569&amp;so=
urce=3Dgmail&amp;ust=3D1607046147650000&amp;usg=3DAFQjCNGvUFL4-l34_ItHvdjfz=
dTmzeczOQ">https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.g=
it/commit/?id=3Dd9fb8c507d42256034b457ec59347855bec9e569</a>&gt;),
<br>&gt; KCSAN did not report any problem during PoC running. Finally, I fa=
iled to
<br>&gt; find any cases to prove that point. Therefore, if you know of some=
 cases in
<br>&gt; which KCSAN can catch underlying data races that lead to kernel cr=
ashes,
<br>&gt; please let me know.
<br>
<br>In the following I'm outlining some background, and my current approach
<br>to reproduce some suspected race-condition bugs.
<br>
<br>Just to make sure we're talking about the same thing, first of all, I
<br>want to highlight the difference between data race and race-condition
<br>bugs: <a href=3D"https://lwn.net/Articles/816850/#qq2answer" target=3D"=
_blank" rel=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url=
?hl=3Den&amp;q=3Dhttps://lwn.net/Articles/816850/%23qq2answer&amp;source=3D=
gmail&amp;ust=3D1607046147650000&amp;usg=3DAFQjCNGzk7-TMey28Q9rPstvNpHriRBr=
yQ">https://lwn.net/Articles/816850/#qq2answer</a> ("What's the difference
<br>between "data races" and "race conditions"?)
<br>
<br>Clearly, data races are defined at the programming-language level and d=
o
<br>not necessarily imply kernel crashes. Firstly, let's define the
<br>following 3 concurrency bug classes:
<br>
<br>	A. Data race, where failure due to current compilers is unlikely
<br>	   (supposedly "benign"); merely marking the accesses
<br>	   appropriately is sufficient. Finding a crash for these will
<br>	   require a miscompilation, but otherwise look "benign" at the
<br>	   C-language level.
<br>
<br>	B. Race-condition bugs where the bug manifests as a data race,
<br>	   too -- simply marking things doesn't fix the problem. These
<br>	   are the types of bugs where a data race would point out a
<br>	   more severe issue.
<br>
<br>	C. Race-condition bugs where the bug never manifests as a data
<br>	   race. An example of these might be 2 threads that acquire the
<br>	   necessary locks, yet some interleaving of them still results
<br>	   in a bug (e.g. because the logic inside the critical sections
<br>	   is buggy). These are harder to detect with KCSAN as-is, and
<br>	   require using ASSERT_EXCLUSIVE_ACCESS() or
<br>	   ASSERT_EXCLUSIVE_WRITER() in the right place. See
<br>	   <a href=3D"https://lwn.net/Articles/816854/" target=3D"_blank" rel=
=3D"nofollow" data-saferedirecturl=3D"https://www.google.com/url?hl=3Den&am=
p;q=3Dhttps://lwn.net/Articles/816854/&amp;source=3Dgmail&amp;ust=3D1607046=
147650000&amp;usg=3DAFQjCNFucqNjRLHYjrqgccyi6sy4A1rO7w">https://lwn.net/Art=
icles/816854/</a>.
<br>
<br>One problem currently is that the kernel has quite a lot type-(A)
<br>reports if we run KCSAN, which makes it harder to identify bugs of type
<br>(B) and (C). My wish for the future is that we can get to a place, wher=
e
<br>the kernel has almost no unintentional (A) issues, so that we primarily
<br>find (B) and (C) bugs.
<br>
<br></blockquote><div><br></div><div>Quick question here. I found that ther=
e is still a sanitizer for concurrency bug called Kernel Thread Sanitizer. =
For the above types, what's its detection capability compared with KCSAN?</=
div><div>&nbsp;</div><blockquote class=3D"gmail_quote" style=3D"margin: 0 0=
 0 0.8ex; border-left: 1px solid rgb(204, 204, 204); padding-left: 1ex;">It=
 appears you were trying to use KCSAN to reproduce bugs of type (B).
<br>What we need to understand, however, is if the bugs you have been tryin=
g
<br>to reproduce with KCSAN are in fact of type (B) and not type (C).
<br>
<br>That's the high-level problem out of the way. The lower level problems
<br>pertain to how the current default KCSAN filters numerous data races.
<br>So, when debugging, my default recommendation is always going to be to
<br>change the config as follows:
<br>
<br>	CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=3Dy
<br>	CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY=3Dn
<br>	CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=3Dn
<br>	CONFIG_KCSAN_INTERRUPT_WATCHER=3Dy  # add this after trying above
<br>
<br>Then, as you run your test-case, gradually decrease this value at
<br>runtime:
<br>
<br>	echo $SOMETHING_SMALLER &gt; /sys/module/kcsan/parameters/skip_watch
<br>
<br>Alternatively, or in addition, try to increase
<br>/sys/module/kcsan/parameters/udelay_task.
<br>
<br>For debugging purposes, it may even be fair to insert
<br>ASSERT_EXCLUSIVE_ACCESS() regardless if the bug should manifest as a
<br>data race or not, as it can help highlight what you're looking for as
<br>the reports start with a different title "KCSAN: assert: race in ...".
<br>
<br>Thank you for your interest in this, and hopefully you'll be able to
<br>proceed further using the above -- please ask if you have more
<br>questions. We'd appreciate if you share any results, as it will help us
<br>understand how we can optimize KCSAN to detect more races of types (B)
<br>and (C).
<br>
<br>Thanks,
<br>-- Marco
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/db967ee9-01c7-4baf-a53f-dedbdf170cc7n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/db967ee9-01c7-4baf-a53f-dedbdf170cc7n%40googlegroups.com</a>.<b=
r />

------=_Part_11717_1813621634.1606960004982--

------=_Part_11716_443435787.1606960004982--
