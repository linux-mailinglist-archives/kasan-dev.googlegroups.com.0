Return-Path: <kasan-dev+bncBCMIZB7QWENRBTOZXDXQKGQEPTJIIRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 33E16116C1A
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 12:15:26 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id u10sf11405690ybm.4
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 03:15:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575890125; cv=pass;
        d=google.com; s=arc-20160816;
        b=fyWnbaLU0eLv9Bw72x8HGz21gDSvuHqsv8YNc4k9LW5R3gjea3pFwIGLvIMz/MkIMk
         39KPPT/HD44bwbxIexe3B+E67WrPxUfGx/SevwB+JlgMh4s+ynr9/I/keO8gm9MqIniN
         HpMiESYzGCaED8mQbIJOjbafEZ9ESAFJVwlaGtCSW73NJ5F+9W90KVL485WJa2ae85xm
         Nkf3SMdUr8BRwY42teFQ6eQi3PVa1o/7/hjCmM1PC7CcuhXpiKWXkJdFc9m74iu7M7lc
         RoAb9IU3bFIs0XkCmGJ3+RcZOEGBqAyIAsaiPL2bVjpbsCPWcXej1YeT6zAF7OmnFZ9U
         4+Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aEs8aQfHuOBUzYfaEwVpLXSrz0hOB4xPgf+QfDVIwsQ=;
        b=N980mgtNkcEM5Je8pJ9HVvGOlxGE/aSic4566aUiIzrHIgiBeeytpNaSTaDEPikJKp
         ff8d4ahaqsKmIDg0pXz9R/BRYWALh5U9mNE6KC+DmOQZXHZTcReZ1AIkjduBQHiCOSAi
         PzcYiFtYFtq7UoE9ed/BOaTzRLnY74d1Prh8BZZt7cLqrpQUKq4GtfIOeCWjqsBsSU8U
         hZILuiRgMWmG3Ck9NIwYy5mgzem2y/1IMUlDy2TVAsctUp6YnxWrqiwhwq8YvG2jinTA
         BiO1cQDFVPnh2HOvVY1FUt0XaLkjcRgcQhMvnyFNKK7bHtPetXqkFiW/otEIg7cca1W/
         leBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tCDZx6bq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aEs8aQfHuOBUzYfaEwVpLXSrz0hOB4xPgf+QfDVIwsQ=;
        b=ZZYLuIsMGLg5+g+iCwYuE3k1/LGKV5EIv7XsLOeuBySOS4GChS3jJho74Fmoog5MOZ
         +hAulUpbR5DRLVfmO8XPC9ItLVSwudnexSiedEfGHifuj4ISWqAv4J6jpnkdHZDkcobE
         iu/u+Qb5oA1PW/dVqAhxvWC9zfi7CzlImf9s0ymtz/j0H3ZE322vSVrfWNzqJEXtHLns
         LBKymim4O3/0o3U97eqkpFJps5fQ9NCg4vz2V4nwU2JUK8ywI2zLkY7hIw4I0YZNq8Mv
         mF3FogrXO9pB6P1s2t2cAiMTBEIVuQ0BhpbPW6Kf6iLiJXJCPgy1fq6GWVNneaYriqdF
         3aCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aEs8aQfHuOBUzYfaEwVpLXSrz0hOB4xPgf+QfDVIwsQ=;
        b=pLRS/fJSqBXNtUdVjta8JlFBRshhV7cBKiwePo9OsKBJ4cc7QwCZsz1VBgRczE1BM0
         03QBoAq45f3pWNO3emqx7kLNK+M86fDCclrn4mqiL1N6LGGySSHmT0yAPKhcHavGjh6m
         sXbTcymEw4gdPXadC5AfkamxminOiPrFfFMbUwGVz7rzmQ+33SGxTR5qdRiN165kalF+
         JkCGypIoeZuGaJByqjmtbBMUI9EtXijF6NDf6TxsrGWdhb7UhIJ8Nr8aT+ixena0r/+J
         JCQWpPiMObY9HziNjjdyGSkP5dj5eI7wGDc7aPEdMLi6zi56/LMsewZUGYa07kL86vG6
         0M5Q==
X-Gm-Message-State: APjAAAWIF7iy1Pu4BSnaMgk7HoIOJrFtngznWRU0rvFi9vLc3kQvjG2h
	YcM348Fj3ZxP7ODUpkOyiVg=
X-Google-Smtp-Source: APXvYqzyvbN8/U6edIMxHWb+V3QLVofVuIJrgWMLqZcAfB2TTsZZbtkE99Yo0ufnlmefeHLZU36fHA==
X-Received: by 2002:a25:af44:: with SMTP id c4mr10568697ybj.12.1575890125089;
        Mon, 09 Dec 2019 03:15:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:c842:: with SMTP id k2ls1919112ywl.7.gmail; Mon, 09 Dec
 2019 03:15:24 -0800 (PST)
X-Received: by 2002:a0d:cc88:: with SMTP id o130mr20710378ywd.498.1575890124601;
        Mon, 09 Dec 2019 03:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575890124; cv=none;
        d=google.com; s=arc-20160816;
        b=fUL8r+u50m2dGz1j73+YLhdaa59D/w7XtmrFP+Ei/3U54nI2Pa/6iEYMxxZNrVV6ZR
         qdqSqacVgFFn78n+SVI4aXn060qaP7fhbD0w4FLo3zRLa0puXiGwKi4zFmVUP1y6B5N6
         4Iq+0BsQw1Sd/Au3iOloShgr5a7NGtx3LRQcVcPHVo8aoJXkEbwjtXbpNnEBGZi8x1c3
         sCmBa1d2trQfnT/CIBWhdPja2Sy37cCyr5VeeKnfaPTSydJl+C6iRlcl/0T74AhKREEs
         mvwL1Aa6lqe23VfkB/RJmg0Wo8VNEawy32rKctH/PdEjOOf814wNEAmvk8wnMo7SZeIP
         8sgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rpBNaTkpq+V5TSZ9PoY3jk4X1c9CjlhVIl5/hzykGmI=;
        b=IxvimOAZhiWKly9SrD2m5bERL1s3ficxvkU1lcUDBOG2UZ2y5Jv001UPC2PxQrNpgy
         BBHn9kDNrNCLneyFicst4PPPiyNdtCagAnrVWjAtkHfo6Gu0XtmoOsNLH3yicGcKreUt
         2Dkx8lmrA7C9uHOKE4PfFujsNY8W3DFyoVxxNXux/BjMjDdzHv7slEPGo3MkZVKiUfBO
         D4AXvxeJXyJXABxF8DkwHya8m9PN4exoKlounTIy2qctXg2utRYis4L3HNmIvNkNDNSd
         i85vtX9Jn3km6ikl1kMrPBokQAtgBTqTMxFEuwou+kPrEentQ7iFChlw4u0OUTkaiwa7
         AimQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tCDZx6bq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id v64si982364ywa.4.2019.12.09.03.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 03:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 5so15212338qtz.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 03:15:24 -0800 (PST)
X-Received: by 2002:ac8:2489:: with SMTP id s9mr24481305qts.257.1575890123780;
 Mon, 09 Dec 2019 03:15:23 -0800 (PST)
MIME-Version: 1.0
References: <f691fe31-aeba-b702-88f2-54c920e81250@gmail.com>
In-Reply-To: <f691fe31-aeba-b702-88f2-54c920e81250@gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Dec 2019 12:15:12 +0100
Message-ID: <CACT4Y+bytWRwvJ+bGhf025cRvhCMFz7CovkaexJ1Ry1EA8Jq4A@mail.gmail.com>
Subject: Re: KASAN for x86-32 and more
To: Adam Romanek <romanek.adam@gmail.com>
Cc: "dvyukov@gmail.com" <dvyukov@gmail.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tCDZx6bq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Mon, Dec 9, 2019 at 12:00 PM Adam Romanek <romanek.adam@gmail.com> wrote=
:
>
> Hi Dmitry,
>
> My name is Adam Romanek. I'm a software engineer, currently working for L=
iberty Global. I'm putting Andrey Ryabinin on CC, as I was in contact with =
him last year regarding this topic.
>
> More than a year ago I did a port of the initial version of KASAN based o=
n Linux 4.0 and the initial work by Andrey on Linux 3.x, from x86-64 to Lin=
ux 3.12.X and x86-32. I was always seeking to port the x86-32 code to the m=
ost recent Linux version and eventually make it public but didn't have the =
time.
>
> Quite recently I did the job - I have the code ported and running on Linu=
x next from December, some KASAN tests pass but some don't. I still didn't =
have the chance to analyze it, I simply ported what I had done a year ago f=
or our project - we had basic KASAN with stack and globals covered. Also I =
had to cut some corners in the code to make it work, so it needs some furth=
er polishing for sure. I saw some recent changes by Daniel Axtens [1] which=
 potentially can make my code easier to fix (on x86-32 modules and vmalloc =
occupy the same virtual address space, so I had to deal with it somehow, bu=
t it's not something which can be upstreamed).
>
> Just a few days ago I noticed in kernel.org Bugzilla that you're maintain=
ing the "sanitize" component in "memory management" product. Just as you di=
d, I also noticed it's hard to evaluate whether KASAN tests pass or fail (a=
nd how many of them do pass/fail).
>
> Now to the point. I'm a software engineer with 10+ years of experience, a=
lthough I have minimal coding experience in the Linux kernel, not to mentio=
n upstreaming. This port of KASAN to x86-32 and an older Linux was practica=
lly my initial attempt to make changes in the Linux kernel :) I have rather=
 little spare time but I think I could contribute some improvements around =
KASAN. I could start with this tests related task [2], then maybe I could d=
ig into some more advanced stuff. Of course I would need to familiarize mys=
elf with the upstreaming process too.
>
> In the meantime I was hoping to share and potentially polish my x86-32 co=
de for KASAN. Do you think there would be interest from the community in it=
? I mean the x86-32 arch is rather not that important anymore, so I want to=
 avoid putting more effort in something which would eventually get rejected=
.
>
> Please share your thoughts.
>
> [1] https://lore.kernel.org/linux-mm/20191031093909.9228-2-dja@axtens.net=
/#r
> [2] https://bugzilla.kernel.org/show_bug.cgi?id=3D198441
>
> Best regards,
> Adam Romanek

Hi Adam,

Yes, there are no automated tests for KASAN at the moment. You may
load the kasan test module and manually check if it reports bugs in
positive tests and not reports bugs in negative tests.
Running some kernel test suite may be useful too, though that may be
non-trivial. The last time I run kselftests with produced some true
KASAN reports, which is good for KASAN testing.

Re x86-32 interest, to be fair I am not interested personally. None of
the contexts that I am interested in use x86_32. But it does not mean
nobody out there is interested. I personally would not object for
x86_32 support upstream in itself (even if to provide better testing
and infrastructure for, say, 32-bit ARM). But I don't know what are
general upstream views on x86_32 support. Andrey should be more
knowledgeable.

Btw, have you seen the 32-bit ARM KASAN patches. They are not upstream
yet (?) but floating somewhere around for some time. If you can't find
them, I may try to find them. I would assume there should be some
similarity in 32-bit ports, so perhaps you will be able to reuse some
code/approaches.

Thanks

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbytWRwvJ%2BbGhf025cRvhCMFz7CovkaexJ1Ry1EA8Jq4A%40mail.gm=
ail.com.
