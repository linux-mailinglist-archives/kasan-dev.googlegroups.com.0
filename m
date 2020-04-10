Return-Path: <kasan-dev+bncBCMIZB7QWENRBRMEYH2AKGQELU4GG4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5509E1A44C2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 11:54:14 +0200 (CEST)
Received: by mail-io1-xd3d.google.com with SMTP id k5sf1517158ioa.22
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Apr 2020 02:54:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586512453; cv=pass;
        d=google.com; s=arc-20160816;
        b=hboHvq3PCJh20Ti3bH248fPKHbXF2uDnRAH/Ht8m86xm07J3isQMQ/Jri77OHNKHdv
         EyyWYg3Org1n8n2qR7eIqc1yXKR5pIvLt7I5Bu3GltT2Ar4JFGj29kAyDz8/fFsJlAP1
         irqPpcrR9nsyBcef32YUjUmHeAh5aZWtZMEk31ntLT7c0ZdIw3MieUKHtHcroM3ykvEv
         QCxCf+fKYVa3SyD5a/E4skAPbGV2Q3LsBO403+Kh220MCxGB5TaN1ES0MKMKdQ5MV2r9
         HEZR9vTjuc4o37jpVI/IgemFVoXNbX9iBv5YaOeiHb4T8jAfsoMcHeEx/OPTmJqjkNjC
         VEhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2yEQgQcMI26edkYuiuWkPtR+VhAtG8mrxmi/p3mIyqM=;
        b=OSCYR72J+jwUtAfQeipCZceQvEytmkN0GSo/rrLRkDKhY6IY99+LKMme9QpFluy2Ty
         HXNILHwvQEnxR+Q4Gb+nRG1uOkJ7J7Gpro8IdTrd5clQ6+Cm9GauEkb5n8wf8Y3ATONX
         4ccpy9IpskytFpvPZ4wChUQemR6X2Wq/WgfbVYya+pC8zFmWaFKZjQ4BHNMnjoVUt32j
         Gf6NNdr+EfSVV59qOwE9Ewza12MDNhrvQt5dV7BDjJ4CRA2Ia8wkjrdaT891YDdI5wCc
         LxGoh5h/cT5sMtCQRSmXDDPyIE91jrKFjXFp42K5CRt3MbyhGJPx358xVKX3U5+VKRH2
         ttow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aoIAW1PY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2yEQgQcMI26edkYuiuWkPtR+VhAtG8mrxmi/p3mIyqM=;
        b=ozV7F1EV5WHYJ/M5AZbRlzQj+REUpiHJi9gvFgtjlZUwjmCLXNy3J07JsS1f5SshHl
         E26rpsKJbtdFjwuSp3tCD7kqVxAqeq7GqM74Ai1QQRVXzp1wtLufyXNwyRZbeU1Z6wOM
         +BirrO7DnC7cdRehgMFQvc/W1xGfIOUGxHbPR/jyfGco8e7rb1r/os1WHOL3JNRIz9Vi
         /msa5REE1rbEWoZYsRW7bkS8Ym1oDPO8YsesDvbIV0KyL3xDxNeMSdEq/HETMxCCv3nC
         vzPAW84H6iJNeF4YWzqKVLJWq4a6i79auaEaDNyxsN69GY+gPbtiHT1UtrlT97S0W/XN
         qKLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2yEQgQcMI26edkYuiuWkPtR+VhAtG8mrxmi/p3mIyqM=;
        b=Aljr1vy3Zq5nFVW6J53xS5ELKUX8RZuWUCSBf6cUuy7k5rgSvQm/2k/FVxSiVEgsRN
         aRDMzBso2qLSenvHdh1il2jJ0letcj4wxVshpOTg05UWrqll1UZQJIavrHn8VA/v3JE8
         E1BeYQyCzjHWdkoHWXyy49GQbmDhajI4jFtVf3iK9PVxFgqdx46F4DGV5aIh6n3sJs7F
         9yvw0//fu9vOJjPOKYTSbz3XFvHG4DUPp+ZKo/2Km21hToDUd0V8l70DC3wpgLNT1yCx
         cN8FDFH54bRVJUlcStIn+Cl1g7SvuVP/ZcyBrwQRwN1cRDGUPeca+O4+m0CaPv03KRad
         YLuA==
X-Gm-Message-State: AGi0PuZkOCzdwFIOhMHQ9iWsS2JvLHaMoV4DjAFaUwe2GY/o+tUqPhk0
	pO3NR6PQWG2aPg0pfjcvtr4=
X-Google-Smtp-Source: APiQypK+gb0x26G7+ExVah6yqQNcjeum77BX3LJBh7pPlALcN19BhhrG9nNOd6xeF2lix6I2FvYyqA==
X-Received: by 2002:a05:6602:15c2:: with SMTP id f2mr3651884iow.179.1586512453112;
        Fri, 10 Apr 2020 02:54:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:3e83:: with SMTP id l125ls3466950ioa.9.gmail; Fri, 10
 Apr 2020 02:54:12 -0700 (PDT)
X-Received: by 2002:a05:6602:1214:: with SMTP id y20mr3605844iot.106.1586512452695;
        Fri, 10 Apr 2020 02:54:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586512452; cv=none;
        d=google.com; s=arc-20160816;
        b=Zq8UN7O/msHxKIfauQioLR4ufa5ciz66A+AVKHrU5a9Kpy3j+/JVs3Q/gHlsMvBkAF
         PqanCA4wb+ZRwRSqLTE3U7JbeYE2X19/iRs2P0kyKYP9Z9G/UEl67enMRZhHfAWNDmO0
         nZ7SBFSTufOpQsN978wLxEsc0X1ZnN3TfRaekiLjSaSg+IsnLqX4hkWLL+V5INQJxRKf
         ZeSXpLPw5l8Es3exOpThnhTZaGSgly6y1O9ME2Wlyl7c8JtRstMN2PGPIT2eXUtNYQ1L
         3veWBmovJoaiDrnQ9IPQ/9poA0703TE1KNd5bCJ7lP9JuuGSA4HZZxP2039J9pXwcJ3c
         SMCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UyZSDyekmUU3E4VwIqN3vNWyQNp9yBnt+O0Ta5QaXzQ=;
        b=xflcDlqpyi9nZNngAO1OQFx6sdoKjs9dClRLI1abR1YVNx4RwgYJHmZg2dk8Jm1FAE
         ed/UARhOYcnrnYtcdvqGmjeaHLCrLuBE1aGIV9mK65QOZ2cvKCutIrBLiGUSpa1d9OIv
         WjcNLuoXxyCa56G1JM8ST+xRT2fKvBekE24W4N2mfXS5vPYYd51j7YtMu5RhW+N8ZSlt
         1pxfSpK76TtCzDzLWG/I/dEBHNJy38/xB5/kIsvnUMSBCYUxJIL2aumtZYybFYHnhpOi
         rRVAqI2lyHJqpblQGkcuVqco3ipURs8Q5fPkEGtlVQWiQn9ZO0zqMgfA2s3sYugdTK4W
         nV3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aoIAW1PY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id o12si182700iov.3.2020.04.10.02.54.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Apr 2020 02:54:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id i186so1635059qke.1
        for <kasan-dev@googlegroups.com>; Fri, 10 Apr 2020 02:54:12 -0700 (PDT)
X-Received: by 2002:a37:8d86:: with SMTP id p128mr3316924qkd.250.1586512451763;
 Fri, 10 Apr 2020 02:54:11 -0700 (PDT)
MIME-Version: 1.0
References: <CAGm4vTP=4mVDXn4jAy1HrOFkq63nHK+w+mcZsPQXetyLTSmd6Q@mail.gmail.com>
In-Reply-To: <CAGm4vTP=4mVDXn4jAy1HrOFkq63nHK+w+mcZsPQXetyLTSmd6Q@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 10 Apr 2020 11:54:00 +0200
Message-ID: <CACT4Y+Ybc0wiFXStND7R-CtkLM8SS2=4rE6NbFNj5Te1yq9UbA@mail.gmail.com>
Subject: Re: LKFT design review of KASAN/K*
To: Dan Rue <dan.rue@linaro.org>
Cc: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Anders Roxell <anders.roxell@linaro.org>, Anmar Oueja <anmar.oueja@linaro.org>, 
	Ryan Arnold <ryan.arnold@linaro.org>, Todd Kjos <tkjos@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aoIAW1PY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Apr 9, 2020 at 7:19 PM Dan Rue <dan.rue@linaro.org> wrote:
>
> Hi Dmitry -
>
> I wanted to reach out and let you know how we have integrated KASAN into =
LKFT, and get your feedback on what we have done, and what we should do nex=
t.
>
> Until recently, we have been retooling LKFT out of a very legacy architec=
ture to be able to test more arbitrary combinations of tests and kernel con=
figs. We're now using tuxbuild (which we previously discussed), gitlab-ci, =
and other composable tools.
>
> Now that we have the ability to plan for a much wider variety of kernel b=
uilds and tests, I'd like to let you know what we've done so far, and then =
we'd love to hear your suggestions for our roadmap/next steps.
>
> As a first step, what we have done is created a new kernel build for arm6=
4 and for x86_64 which contains the regular LKFT config fragments, plus "CO=
NFIG_KASAN=3Dy". Then we run our full regular test set on these kernels, on=
 hardware.
>
> In addition to looking for novel test failures under KASAN, we parse the =
logs looking for strings that would indicate an error condition (such as ke=
rnel panics and warnings). I'm not confident that our parsing is correct re=
garding errors that KASAN might emit. Perhaps there is a more determinative=
 way to detect errors under KASAN.
>
> We know that this is only a very small first step. Please keep in mind th=
at we're primarily looking for regressions, rather than novel bugs as proje=
cts like syzkaller find.
>
> Now that we have some confidence and experience in this, we're looking at=
 the other K* options, and looking for guidance in terms of which should be=
 enabled, on which branches (we test all stable branches). Also, in terms o=
f testing, if there is anything else that you would recommend us running.
>
> Thanks in advance for your feedback,
> Dan
>
> https://lkft.linaro.org/


+kasan-dev, syzkaller for persistence, visibility and future references

Hi Dan,

This is great to hear!

Even if we aim for new bugs on syzbot, we don't do hardware at the moment.

Re crash parsing, checking for "BUG:" should be enough to catch all
KASAN reports and more. Do you have any specific concerns here?
There is no other, better way for KASAN reports. KASAN should taint
kernel (?), but I would not recommend switching to taint checking.
Taint is too coarse grained, some bugs don't taint, some bugs that
taint you may want to blacklist and ignore later (not possible with
taints, possible with output parsing), some bugs render kernel dead so
you won't be able to read taints, also extracting the crash message on
console is very useful for reporting anyway.

You may try our test suite of kernel crashes against your parsing logic:
https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/r=
eport

Or peek on our parsing logic:
https://github.com/google/syzkaller/blob/master/pkg/report/linux.go#L886-L1=
655

Re other debug configs, here is our set:
https://github.com/google/syzkaller/blob/master/dashboard/config/bits-syzbo=
t.config
https://github.com/google/syzkaller/blob/master/dashboard/config/bits-syzbo=
t-aux-debug.config
The first file contains some non-debug bits as well, but hopefully
it's easy to filter them out.
The good news is that all of them are combinable with KASAN, so that
may be your "the debug config".

It may be useful to enable KUBSAN as well, at least some subset of checks.

The FAULT_INJECTION configs won't be useful on itself. There are 2
options: (1) easier: use the old fault injection with failing some
percent of sites; (2) harder but more efficient: systematically fail
all sites one-by-one (see 3.1 here
https://www.sqlite.org/testing.html); this can be done with the new
fault injection: https://lore.kernel.org/patchwork/patch/774420. The
second option will also require some special ptrace-based driver or
something because tests don't know about fault injection.

Then there is also KMEMLEAK. We use it separately from KASAN on syzbot
for performance reasons. But the situation may be different during
unit-testing.

KMSAN/KCSAN are not upstream yet. KCSAN should be soon, but it's
probably not too useful for unit testing at this stage. KMSAN will be
useful, but it won't be upstream this release.

And here is a very good recent example of where KASAN-enabled unit
testing would be very useful:
https://lore.kernel.org/lkml/CAHk-=3DwgjGgfUfVm_DpTay5TS03pLCgUWqRpQS++90fS=
E2V-e=3Dg@mail.gmail.com/
linux-next is boot broken with months+ with 3+ different crashes which
pile one onto another. And syzbot is not really meant to be a unit
testing system, so it does not cope with this well. If LKFT could
catch, pinpoint and resolve such breakages earlier, it would be very
useful.
Note: this is not even tests or something, it's just booting. It's
just that nobody tests linux-next with a reasonable set of debug
configs and/or actually notice when bugs happen, as far as I
understand currently most "testing" systems happily ignore
use-after-free's, WARNINGs and deadlocks that happen during that
"testing" :)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYbc0wiFXStND7R-CtkLM8SS2%3D4rE6NbFNj5Te1yq9UbA%40mail.gm=
ail.com.
