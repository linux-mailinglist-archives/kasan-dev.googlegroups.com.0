Return-Path: <kasan-dev+bncBCMIZB7QWENRB6MS7XZAKGQE4TTCRIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C6E3178A8B
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Mar 2020 07:23:54 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d2sf795456qtr.9
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2020 22:23:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583303033; cv=pass;
        d=google.com; s=arc-20160816;
        b=IpLmT233ZscHTzXp/4WfY4fFsKSzlPzgvyELQHbxaAGCNuSGjEttHh+O59TPBjXQPf
         aNSLA4d9taJOfVrZhvyrIc+MU3cNEBuiZjYNE6NHq753f9hOdSyS+4VadXLsOQpmUK6F
         R2dfS3VT/fZz1IfA5KxKUcRCABSJkByyGHU+sWmLE3w6fkroU36iTZKQdOVpd6eUMmjt
         0KYGzIBK9VTQhezYuHPB237Id+ix6z2t3uZR152RGOOuWDjxGGvNfxVC+XRr9liSac5r
         IGDxNCrR+FneO15sjRCn7EZ79OHisAsJO6hPj7OKo4vJA32Mf1xzPRJYaPsgcceYGPlV
         RkTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g+G2aPNs+SOIlk+C204kqTR1iQu4mXGzl+IfJD9Yz/8=;
        b=m3xWB12OyMwdpKmL7T+E0DUVVLHKPTIHDDm/VQzxIiUBsdvZmwq+dAAh0NPiesqxyb
         eYWYUpNHs11j5MdwU4qr5JLahVrFs25887X2MNLKER6ZNXYTH8l6Si3OOayjmav/i8PP
         a1BADgcQZ0S2yQmh9hDuy4dMz3k13v3dclu4VMMUenjRTVgl9PIsRHvqkLJAZH614nch
         ZJb2QjXfLpLAq68B5xzDUdwT3E2fRifQW04IWgzkVpQjFcxCzteoQOCB48jBne1iQym/
         zLIqVCdosGsD/XXGqUl0dH4lZIQ9L1Jaix59yjDKaV6SrmtVcHBz7dTFAeVtINzYwAK+
         bdng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HBrmEvdV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g+G2aPNs+SOIlk+C204kqTR1iQu4mXGzl+IfJD9Yz/8=;
        b=mGvy9LSh0rGJ2z4zd/y5Hno8/cyQvHglVJNL3tsfUc1MNHJ4LvWlPhtv5PugHfgBaJ
         kg6IyO5sBNND81HtVXQEkdPPQHxsqJDqiDnsyeWrsxUEXnLTVeDG+uUWCyVrxAjl8CKp
         7UkCqDGGFHnrvTy868zRIpxxTSEHLS6jnBKLaea0GdHT8lyYEoBM1KdbCNcjhvq0Ha8p
         JViRGMQUb43tYFFKGKnxc6Wi5M5RyG/HDEdGAbyQAAU2XBDCnwGvgECI/OWa1xzw7TqE
         3z0kROXlDq7mTL9sRIRqqF4fhOGIdtDzXTeU3iLsHodzwDGduFW1Uqwy0NI1dWvwCQaH
         N1iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g+G2aPNs+SOIlk+C204kqTR1iQu4mXGzl+IfJD9Yz/8=;
        b=B7wZZd08q7tob5mzJR3OCD+fO/H/2+1gfGzMlVQjelUwc+KuwUGcoksmuWL8kO2/cR
         aaQkMc1Jys9F+O0f9WD5Gbzh+wwq0t7tqijaZYls711yoWQXs0Tm2Jy7oWlWoZBNBvSo
         klgTeBTPYUXib04AUgbNBYCjTyeOrzqEBAydjHCqnYGYNdhVz3m1dVtnU46ES7OMNs24
         f8bf/ZPTAdWu6KlMDvSuyLS37oy6/rB8B0hfVOIO+h8lVwVGXZHBF8kpYAfSGYdyhUAh
         K2TF+KuWY3P5L9ojEWpJPxABz/1XvYzk4nASBolLIwVc0YyUESykRJmgxsGcmB2OOTQj
         5qWQ==
X-Gm-Message-State: ANhLgQ2VraQOfS+Bo139XiPo7BSxaftcqHGMT0OOQufw1nvGhN4JOJiG
	UO3W165/Isw0Ach48S1qCHY=
X-Google-Smtp-Source: ADFU+vtKkQVc2xSX9O2Q4mAxdIgT8pPW59+DT71d/TOu3Modz8ncT0YKijxN1GOaEUmsFPmKnSRpvA==
X-Received: by 2002:ac8:6ec3:: with SMTP id f3mr1086363qtv.328.1583303033286;
        Tue, 03 Mar 2020 22:23:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:196f:: with SMTP id g44ls367512qtk.0.gmail; Tue, 03 Mar
 2020 22:23:53 -0800 (PST)
X-Received: by 2002:ac8:4e46:: with SMTP id e6mr1118641qtw.9.1583303032979;
        Tue, 03 Mar 2020 22:23:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583303032; cv=none;
        d=google.com; s=arc-20160816;
        b=UhrSIrCX98fsF0JC8DME8Oh2Ll1PXY45EoHvdDwOoVdxwclkJtfa68nbGA69e2yhFY
         V5CQpasiVjB83hNs3tuBE4OrtH4RFSGh3oRrOEg95/FUK+q27339oGuGTY2yVVmzskIN
         WFYYYzBw9/blJ1kwMOx+Gn/kpd1RszW7HQ6shMTyOv7t37wqtJCJJomy7PayouDYJurU
         9uXE6r56EjYTUjvjQKuec5UCo6emvCaLVDB109KY1JnU0RuQAjoVFx12GcIB4z8S8q9q
         fg94JytSGzEtSF4mLxe0zBJx7FFbJGJLWf7CtVwU/XbuAQ87LM3OSXkgrvS2jF1JO3hS
         aueA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9rIcuItk/t0HMMdxbMcrzdoYnAXfgWsnodSuFT2EgNI=;
        b=x3jl0T1DpOAvhw0BxPykFhq6H7EhXuOlGF+Z/nLVTWWs2Z5DeGHVxv8wsIGrSIGJUK
         rZz3+1LX9SzR99KTOrdtv5H6bDT6iOXWFXQZgvU23gjhttOCQq9aADvTXsG6L6sVQ+C/
         MN6pFQNWHAC228D8VrRaW7OFGsgiEGENynz519O0q6S02XfGT7fO7d6IoyniXCApOMzD
         b+yy+iIncA9M3oNj+FPB/mHHXagLtnqNhDK0WQRbO1pcbxUCA/5JsHztleVyvo2qskv7
         +Fyy6Ioe2FhuctunjR3nAmo049qA38ou/poSujdXRii5zAWTbLMQXdfC9tYUxtfoCntk
         woRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HBrmEvdV;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id c6si59957qko.3.2020.03.03.22.23.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2020 22:23:52 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id e7so306969qvy.9
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2020 22:23:52 -0800 (PST)
X-Received: by 2002:a0c:f892:: with SMTP id u18mr906230qvn.159.1583303032372;
 Tue, 03 Mar 2020 22:23:52 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
 <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
 <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com> <CAKFsvU+ruKWt-BdVz+OX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ@mail.gmail.com>
In-Reply-To: <CAKFsvU+ruKWt-BdVz+OX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 07:23:41 +0100
Message-ID: <CACT4Y+b5WaH8OkAJCDeAJcYQ1cbnbqgiF=tTb7CCmtY4UXHc0A@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HBrmEvdV;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Wed, Mar 4, 2020 at 2:26 AM Patricia Alfonso <trishalfonso@google.com> wrote:
>
> On Sat, Feb 29, 2020 at 10:29 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Sat, Feb 29, 2020 at 2:23 AM Patricia Alfonso
> > <trishalfonso@google.com> wrote:
> > > >
> > > > On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> > > > <kasan-dev@googlegroups.com> wrote:
> > > > >
> > > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > > >                 return True
> > > > >
> > > > >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > > -               args.extend(['mem=256M'])
> > > > > +               args.extend(['mem=256M', 'kasan_multi_shot'])
> > > >
> > > > This is better done somewhere else (different default value if
> > > > KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> > > > Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> > > > to be a mandatory part now. This means people will always hit this, be
> > > > confused, figure out they need to flip the value, and only then be
> > > > able to run kunit+kasan.
> > > >
> > > I agree. Is the best way to do this with "bool multishot =
> > > kasan_save_enable_multi_shot();"  and
> > > "kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
> > > was done in the tests before?
> >
> > This will fix KASAN tests, but not non-KASAN tests running under KUNIT
> > and triggering KASAN reports.
> > You set kasan_multi_shot for all KUNIT tests. I am reading this as
> > that we don't want to abort on the first test that triggered a KASAN
> > report. Or not?
>
> I don't think I understand the question, but let me try to explain my
> thinking and see if that resonates with you. We know that the KASAN
> tests will require more than one report, and we want that. For most
> users, since a KASAN error can cause unexpected kernel behavior for
> anything after a KASAN error, it is best for just one unexpected KASAN
> error to be the only error printed to the user, unless they specify
> kasan-multi-shot. The way I understand it, the way to implement this
> is to use  "bool multishot = kasan_save_enable_multi_shot();"  and
> "kasan_restore_multi_shot(multishot);" around the KASAN tests so that
> kasan-multi-shot is temporarily enabled for the tests we expect
> multiple reports. I assume "kasan_restore_multi_shot(multishot);"
> restores the value to what the user input was so after the KASAN tests
> are finished, if the user did not specify kasan-multi-shot and an
> unexpected kasan error is reported, it will print the full report and
> only that first one. Is this understanding correct? If you have a
> better way of implementing this or a better expected behavior, I
> appreciate your thoughts.

Everything you say is correct.
What I tried to point at is that this new behavior is different from
the original behavior of your change. Initially you added
kasan_multi_shot to command line for _all_ kunit tests (not just
KASAN). The question is: do we want kasan_multi_shot for non-KASAN
tests or not?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb5WaH8OkAJCDeAJcYQ1cbnbqgiF%3DtTb7CCmtY4UXHc0A%40mail.gmail.com.
