Return-Path: <kasan-dev+bncBCO4HLFLUAOBBKPIYH3QKGQECKIU3JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id AAB912032CA
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 11:04:41 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id t145sf9084419wmt.2
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 02:04:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592816681; cv=pass;
        d=google.com; s=arc-20160816;
        b=j+cXUZqA8pDhm+gUZsGA6J2hCMjYnpQJ2aShi18JP8Ro4Fd/8KVB0Vf+rFGyS5BjVx
         XCKs6BjC13IghCKqOsyjze62/EGoNs7I9tKrvNHv0T2RMZ1LW9R++nu4iWYyybgYP7AE
         vj20Y7y/G2xfCegl/L2+tmlpcOhPje31H+QHjIxq1wIvSsAYFehaRuwOSaAP9mXejON3
         agVGgNVDUnUocR03n5am+sGhxQ8ELvppTv3jTmXW7X93gfJpQYC2Uzfe262Urc2dFs/i
         g1XrjTnIDcavCdJjx7CzBoPNuxUMbkiqXgpHTjSd3uZZOl0/jLKnoUqFZxjXdoZ01DhV
         IZCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=9j0WA3p7Pal3D1bxevqGNtISQT3ZEmc3bLqvguBfkzY=;
        b=omxgdYI85Uh8opyxsmhqvmjZkufPawG3fIbMgLOmBj1FPes2umBx5Qb7f0rXzjPet/
         G3byicPqnnewWirc31myNNwTdS80U92Q3X9OhdK6e3lte8rSLwwdE7h93kGGcs9adMlK
         V3TF3iU9a0HPpEF0S+XXnv2jx03NRdqeaQ8ln5JvV3oRwquIPrLVg9eAsAL3F/K42sR8
         daMcQKEb966Srvzp4Rn86pvY0jIUKCwftuEDfp9OeVhvEggQiHrukHEfnpRD1Wpgmgon
         uSqf9r/1bqG7vB8wf9xDhbadLCU2oGn3VCp+69mxvwAN0ffY4IoazWW/ZC/tduQ6YIsC
         ze1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9j0WA3p7Pal3D1bxevqGNtISQT3ZEmc3bLqvguBfkzY=;
        b=KfaZAROd9CnEbsumD/5fy/ynxCKKL9xU4/fta51MnckCi4JVgIugjw8Fh15bQyAVym
         7J0VUPQec5XYVlSjzbcYqjzJrRNAzTzsGJZ0jdfdtJ6l5PeTg1r2Bl1Gpwb0/fxlGuUq
         yha09x8DUuVTqsFtVpHGG4JHEww16tp17ppRt3YdV7ypgllEhKKgDWUzhQfTZCIyZaRy
         xhDhjJEFNLWjy5Wm9dgXxLe87S2AqhXXzYBaolYHsw1gRf0IBXwPk3t4xwVEI7u4EHJl
         t2NH2aQUGxrt2uaidrSCeTY5rTUMtTMrM3GnUWMI57TTEX3e31i9nX22WfGC7kbkHqst
         U7kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9j0WA3p7Pal3D1bxevqGNtISQT3ZEmc3bLqvguBfkzY=;
        b=PkK+d2TKtp2KTbr3Om2hylxfxDS4pgefkOmx4NJhjplj5Jy6x8ZXVeUYqfLbSVL7Bo
         WXG8uSMewqDBkF0npJXIevzQ0aG/2k8KTaeldvoAwiPDhnQE5h3JJGs8DjHoZn7qaxCJ
         aXoAqCWrMX9bUTwPoeQp53a/agl9H8CD8rgw4a/TzwacvShoA91xaI7lqamQe5I27Gpv
         Aed7pOSYCr95wF6y/pY8+wTTWKw3Y68peQ1uUsYY9S+Pxq5ssemEz6eFBjB3UxCROuR8
         hbKkLmroklYK8ISyKoLNHTxa6nlbsqfCr9+iIHVwihcPM1MTQwEbqXl1W1QGQXcw37vV
         m4mQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530FHOr3yV+d7rVIQIFP+4fBcJHN7j265u1VgqkDgluDsuZZ8r+U
	rqRGHPqor8llIReJ0/LsHjU=
X-Google-Smtp-Source: ABdhPJygVm9o8CmBJCD1rBzY7YuOvRkMn+6CaI5CezTSrdmlJuW6Qvtj1X1HO8Cs1omHqJdhdawfnA==
X-Received: by 2002:a05:600c:2144:: with SMTP id v4mr6139270wml.128.1592816681351;
        Mon, 22 Jun 2020 02:04:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:2301:: with SMTP id 1ls2417090wmo.0.gmail; Mon, 22
 Jun 2020 02:04:40 -0700 (PDT)
X-Received: by 2002:a1c:8049:: with SMTP id b70mr17967892wmd.145.1592816680816;
        Mon, 22 Jun 2020 02:04:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592816680; cv=none;
        d=google.com; s=arc-20160816;
        b=ktPdNm0ZutU1TPU9H7dEJ8heJ+a8BpLR+6lrRXsf/YsItK2moNzDcLiX7im/rK+iiT
         GLskjTKfOgRjMlQlXgMOVhsKhZBPgz4k4LIyxcfZwslSMMPIjGb5k4FAxYK84BY5vKC9
         B7j5KE3nX6ZsvFvXJGHhMsNkfmSdiqlNxBKiEiDzvSZECOHbSZ+thmGdEIKsyAYDDJnP
         0GDuXFugIIeDhPxpbcjDZ0M2z2LLs2CcR0UumluEmnuwGPVdQtpvaV1Ihvu9WTnrhj/y
         Hk2w9jMlvW9za2oj900U/4pIBRKysmx8lsr/9hYTybqeKYCr3dqipC21Ztpb+b9hdPAu
         L5IQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=CfS12Xt3oQY4oSnb2jQniPUdS8fvrZ8eF1jqLdm7tho=;
        b=LOSrPa/YqWCeoZUFD9hco8EHrHzRMbuGdWrJMYyhaS5KcO7A3ggKFPPufQVFNnNTO+
         7T9NAoK7kcYqKXc21tpQQG1aFshGue5CmfOLWkYCMHDIbqs/+kSrUs0kJL65YRkKJaWs
         +w6VQQKCyFK8Y51TrIG0PU6BIY4neV1B5cDaKm1jp3J0uf10AtJ2CcPNhp+0XZpMwOl7
         Yib0LLCBDnzOyIInUS+HXvwqGojgsrepCj4Oa0ZofZsXlQ5qIASz6wHdC9QMUFeoXquu
         QCd36tmWEIKBMGHrmo3gyFaWvE1XJ/ywu3Qfg2Qv1Fx/6+O4pQZ0WvjhvF7vJIwtxecG
         9RLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
Received: from youngberry.canonical.com (youngberry.canonical.com. [91.189.89.112])
        by gmr-mx.google.com with ESMTPS id h21si343455wmb.0.2020.06.22.02.04.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 02:04:40 -0700 (PDT)
Received-SPF: neutral (google.com: 91.189.89.112 is neither permitted nor denied by best guess record for domain of christian.brauner@ubuntu.com) client-ip=91.189.89.112;
Received: from ip5f5af08c.dynamic.kabel-deutschland.de ([95.90.240.140] helo=wittgenstein)
	by youngberry.canonical.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.86_2)
	(envelope-from <christian.brauner@ubuntu.com>)
	id 1jnINK-0007G9-AL; Mon, 22 Jun 2020 09:04:22 +0000
Date: Mon, 22 Jun 2020 11:04:21 +0200
From: Christian Brauner <christian.brauner@ubuntu.com>
To: Marco Elver <elver@google.com>
Cc: Weilong Chen <chenweilong@huawei.com>, akpm@linux-foundation.org,
	mm-commits@vger.kernel.org, tglx@linutronix.de, paulmck@kernel.org,
	oleg@redhat.com, lizefan@huawei.com, cai@lca.pw, will@kernel.org,
	dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: + kernel-forkc-annotate-data-races-for-copy_process.patch added
 to -mm tree
Message-ID: <20200622090421.cw5r2ta3juizvkmq@wittgenstein>
References: <20200618011657.hCkkO%akpm@linux-foundation.org>
 <20200618081736.4uvvc3lrvaoigt3w@wittgenstein>
 <20200618082632.c2diaradzdo2val2@wittgenstein>
 <263d23f1-fe38-8cb4-71ee-62a6a189b095@huawei.com>
 <9BFEC318-05AE-40E1-8A1F-215A9F78EDC2@ubuntu.com>
 <20200618121545.GA61498@elver.google.com>
 <20200618165035.wpu7n7bud7rwczyt@wittgenstein>
 <20200619112006.GB222848@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200619112006.GB222848@elver.google.com>
X-Original-Sender: christian.brauner@ubuntu.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 91.189.89.112 is neither permitted nor denied by best guess
 record for domain of christian.brauner@ubuntu.com) smtp.mailfrom=christian.brauner@ubuntu.com
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

On Fri, Jun 19, 2020 at 01:20:06PM +0200, Marco Elver wrote:
> On Thu, Jun 18, 2020 at 06:50PM +0200, Christian Brauner wrote:
> > On Thu, Jun 18, 2020 at 02:15:45PM +0200, Marco Elver wrote:
> > > On Thu, Jun 18, 2020 at 01:38PM +0200, Christian Brauner wrote:
> [...]
> > > >=20
> > > > Both mails seem to have been caught by spam at least I don't see th=
em anywhere in my mails.
> > > > I'd also need to check what protects nr_threads and I'm confused wh=
y that data race would exist if it's protected by the lock pointed at in th=
e second response but I'm not near a computer until late tonight.
> > > >=20
> > > > That commit log still isn't anywhere near clear enough for this to =
be included.
> > > >=20
> > > > The report also isn't coming from kcsan upstream and apparently bas=
ed on a local test.
> > > > What does that test look like and how can it be reproduced?
> > > > Unless we see a proper report from syzbot/kcsan upstream about this=
 I think we can simply ignore this.
> > >=20
> > > We have this report, back from January:
> > > =C2=A0
> > > 	https://syzkaller.appspot.com/bug?extid=3D52fced2d288f8ecd2b20
> > > 	https://groups.google.com/forum/#!msg/syzkaller-upstream-moderation/=
thvp7AHs5Ew/aPdYLXfYBQAJ
> > >=20
> > > So if this patch is amended, it'd be useful to also add for syzbot's
> > > benefit:
> > >=20
> > > 	Reported-by: syzbot+52fced2d288f8ecd2b20@syzkaller.appspotmail.com
> > >=20
> > > The line numbers of that report match what's shown in the patch (they
> > > seem to be from 5.7-rc1), but definitely don't match mainline anymore=
!
> > >=20
> > > We're in the process of switching the syzbot KCSAN instance to use
> > > mainline, because all the reports right now are out-of-date (either t=
hey
> > > moved or some were fixed, etc.). Once that's done, more reports shoul=
d
> > > be sent to LKML directly again.
> >=20
> > Hey Marco,
> >=20
> > Ok, good. What's the overall strategy here? This seems to be a generic
> > problem with sysctls and a quite few global variables too. Is the
> > strategy to amend these all with data_race() most of the time where we
> > don't care? Has there been some discussion around this already and
> > should there be some before we start doing this?
>=20
> For the change here, I would almost say 'data_race(nr_threads)' is
> adequate, because it seems to be a best-effort check as suggested by the
> comment above it. All other accesses are under the lock, and if they

If we take this patch it needs to:
- have a link to the upstream KCSAN bug report (see below why I think
  that's important)
- explain in clear terms why marking this as data_race() makes sense
  (Doesn't need to be perfect, I'm happy to end up editing commit
  messages when necessary.)

> weren't KCSAN would tell you.
>=20
> But, for most of the apparently "benign" races like here, it's back to
> the question about assumptions we make about the architecture and
> compiler.  Although it's nearly impossible to prove that on all
> architectures with all compilers, a data race won't break intended
> behaviour, a simple question I would ask is:
>=20
> 	If 'data_race(nr_threads)' was replaced with
> 	'random_if_concurrent_writers(nr_threads)', what will break?
>=20
> Even if the data race is meant to stay today, IMHO simply marking it
> 'data_race()' is better than leaving it alone, because at least then we
> have a list of accesses we should be suspicious of in case things break
> around there.
>=20
> In an ideal world we end up eliminating all unintentional data races by
> marking (whether it be *ONCE, data_race, atomic, etc.) because it makes
> the code more readable and the tools then know what the intent is.

Right, the problem is that in quite a few places this also means a lot
of additional information needs to be processed when reading kernel
code. So there needs to be some balance.

>=20
> Some of what I said above is probably better discussed in
> https://lwn.net/Articles/816854/ in the section "Developer/Maintainer
> data-race strategies".
>=20
> Thoughts?
>=20
> Another thing that would be good to figure out is, if we send individual
> reports one-by-one to LKML, or some alternative. One alternative would

I'm not sure I can answer this. It seems like something that could be a
great kernel summit discussion.

> be to go check the syzbot dashboard and have a look through reports in
> code that is of interest before they're sent to LKML. Although a lot of
> the data races are still hidden in some moderation queue, would it be
> useful to somehow make this visible?

Yes, I think it would help to have them visible or at least let people
request access?

The problem that I have right now is when I receive a data-race patch
like this I'm not inclined to ack and take it unless I see this is a bug
report from an agreed upon upstream tool like syzbot or kcsan. Not just
can I then link to a standard bug report that everyone recognizes, I can
also be sure that this is based on a consensus that these types of bugs
are worth fixing. The latter part is quite important, I think. Most of
these (benign) races have existed for such a long time that sending
patches for them better be thoroughly justified.

Christian

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200622090421.cw5r2ta3juizvkmq%40wittgenstein.
