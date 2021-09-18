Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOHKS2FAMGQEFNOQBDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id EFFD341059A
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 11:45:29 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id u13-20020a17090a4bcd00b00198e965f8f4sf12006918pjl.8
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Sep 2021 02:45:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631958328; cv=pass;
        d=google.com; s=arc-20160816;
        b=FZqdJ2gL1AzKcKSYEudqAu2EF+4ntvyZ4tDQ9DICH8wu3ifq9IalDMuYs0UD7eYU8n
         +TPJmhnEWA+Dns61jjKP0PLWzhbcjsJew7PQtl+SOinOSH46aJRrztQFTVfiSF0cI+6S
         4+vWjI5xeOcAjiOIrrNdMBWwI8NyT6rMzexhYc3Z8rq6QgTTVQo+V2P6BLgI1mHlwHF1
         N3jiWyjattOIwoX2YCAsYzB6P5ticdTYRBtu+ix9Qq889mWg8Be/ZOQ6jI/pqSDLLPTM
         Y8Rq/CAZb5vj6ptc6K7Uc0+7YPXw/1YawtoFh1wW5cUIJv75C/ZRssdsjxE+cg2KJBmC
         LE7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IwVerrArGXtjdT80ghp7R4pOb0Y6JIVtZb4LD9uBoLg=;
        b=WkCuWKS+vJZn65VmYB+m3sKV1pAqArqjF9OMmYGe3dCMENOzuSOFL5iEfRfgXiksxr
         y+AnIUV45y/r6NDIVgHvp3ahw7Mf0vBYpY/3BOYg3h2S5MqUx792v1pf+85BjQr4rMtP
         y8CFooix8Kjg7knpmPgkQwXrM3gtszgrmAOd73rBx5PkL4l6ZsyLIub8+8L+M5N+AL5C
         YAVBUAY3Ye921am+5X7lCn+6/0t1yJ6iFzAEa8Wp2SZhE7K/ktVyLr76aU9fs0lAPUX7
         FQJ3XUxV0hz7dtQH55y69vvKUcLzkr5omkQ0cb/j5dtVNua76vBxR+5VDnkTdXXpmwyF
         HaFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R0gWqYQH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwVerrArGXtjdT80ghp7R4pOb0Y6JIVtZb4LD9uBoLg=;
        b=YpxqvRxCDH/mhTbBtpXAOZNAp2dKxL5BMRVHd5yvqcs6sy2VyeuT3qmAy7r3VWhG9Y
         dJw/01svQ+CW7Vpfy5sH5d4gIp3isocqEZeDprAzeIudd1CRvrQECmTj8GS1jTqe5aTp
         RETlpZCNFzGwAo6kiAmIlv+Y1pneETC8+4MrMp1vsWZGamMDbX9Wc+3I9Re5RfLz8GML
         ByzA5v7DDIHQGGraOZB25Vz2YoI3pJrjXDho5dvmSSTsooifY3hU+bdqIcShYklQKcQw
         oY7eeC874AffDv7SPFapyR2G4i8g0BaDL6BUE1Ewyma8LmM3bT79LpYJwp6DnTopKYB7
         Od1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IwVerrArGXtjdT80ghp7R4pOb0Y6JIVtZb4LD9uBoLg=;
        b=d1CulJYzkjUT4m+dAHgUkCxECMeC9hV51keAULzP8v4Qc1Ta2rthj8kJeYv2mp6ng0
         bcNlIkEhGMNM/EmIdW8Dl+WY7IuwJBgGzmQClDOPLHfJD9yt6EZ8MnCZWX0ODXU7v0nC
         dloJJvip6HOqnFrN7dm08a/tWEz1TtZHr7xgvrd+dEREQqlQfJyW+E6FcX4iI2L6lzb0
         y6X6TYd9rcs6aaC3faDoPeqPBRB9StCxjAEVWJkp4cMc+EnYrN+ic5n1eCMAV+K1/FWD
         YIEqms8fQv0etin4KIoVEV0GhqN9BwKNyBlzcq6zC6XyGSZGSEIwOY34u2GOKNOMs6uT
         wn/g==
X-Gm-Message-State: AOAM533+NY7/GzHujO69PLJLkPkf0CTxv7L8OKpjPDoLI91Jo9v7Y0OL
	mhlxsdXJVRExGNsfEGP7CSU=
X-Google-Smtp-Source: ABdhPJziQlSxFxTf1GnfAIh1gwp59jvsg31rHjZhc8vu6B+isv05xGtYJyOcUSIZf8shywFHinp62Q==
X-Received: by 2002:a62:7985:0:b0:437:36f1:d0df with SMTP id u127-20020a627985000000b0043736f1d0dfmr15138160pfc.52.1631958328380;
        Sat, 18 Sep 2021 02:45:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:41c5:: with SMTP id b5ls3987298pgq.11.gmail; Sat, 18 Sep
 2021 02:45:27 -0700 (PDT)
X-Received: by 2002:a65:5cc3:: with SMTP id b3mr13926517pgt.97.1631958327764;
        Sat, 18 Sep 2021 02:45:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631958327; cv=none;
        d=google.com; s=arc-20160816;
        b=isW/OGLa3VgOEbYj47pThnU/geBAECfUxf0yjNo2XiG2sszSyA6OtPMZ/xwIPi5DGW
         oJPbJkzBHzs/blYEIt+P1ygSUGcIkniKmFD/VdzwUz9isNSumekC2Wowk6g8ckhVZVQS
         TK8vEDN8nO5hYLWDWRuy8Cfv2GAcCX3dXaqD0cxz/oy5cnUfTNyH1FyrPGdmCOdco72Y
         LAY6RyEUu4f261xXmDYOzOZBjUvO0Pwt2HlvqOoAbSePAfM9pyYEQ6jqPOeD2kjmH3jQ
         4PnIkREA3ST9fBvVltxMFaqVxvXcheNT7TOLukoYhM47PtRYebhrBl9SFtYAC60jievQ
         SJTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vjDTvBteAJt6rqaanENmzaxCVEDC1Q1i6Nv/9nSbEWE=;
        b=GxijN9g9D4AAdy/ifWb0Q8x0viohx1eyRRw+AJPIRddY77kZdKXk/jo+0aaoy119I+
         gV9PEiiqv/iA7wfr+NciOE7IDGHdLfo69hgTdwBKXobnZWFro5mvhhDvsIosw9mydJDI
         BE1MkbaVdFSO4pIhvsRNAw22KDDmrwTI/3JbSAoi8eFO2WJ632Zke0jWQOW2sI/KDaAr
         Uaq+jGKwBeV5/6Y5yrDjJQaNsExulXJchIBrJrn+QKeqmZZzPXLFSn23UZuaWAT6EXAz
         wK958BAHHXZqYkxaj7HJn7dV9umH2bHXsv2+1Z6HtelIhHef0EjRkSsOdMqBwPvQMt3y
         Cx4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=R0gWqYQH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32c.google.com (mail-ot1-x32c.google.com. [2607:f8b0:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id m1si1129735pjv.1.2021.09.18.02.45.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Sep 2021 02:45:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as permitted sender) client-ip=2607:f8b0:4864:20::32c;
Received: by mail-ot1-x32c.google.com with SMTP id 67-20020a9d0449000000b00546e5a8062aso4244489otc.9
        for <kasan-dev@googlegroups.com>; Sat, 18 Sep 2021 02:45:27 -0700 (PDT)
X-Received: by 2002:a9d:71db:: with SMTP id z27mr13094532otj.292.1631958326940;
 Sat, 18 Sep 2021 02:45:26 -0700 (PDT)
MIME-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com> <20210421105132.3965998-3-elver@google.com>
 <6c0d5f40-5067-3a59-65fa-6977b6f70219@huawei.com> <abd74d5a-1236-4f0e-c123-a41e56e22391@huawei.com>
 <CANpmjNNXiuQbjMBP=5+uZRNAiduV7v067pPmAgsYzSPpR8Y2yg@mail.gmail.com>
 <da6629d3-2530-46b0-651b-904159a7a189@huawei.com> <CANpmjNPj5aMPu_7D=cwrDyAwz9i-rVcXYgGapYdB+vdHcR3RZg@mail.gmail.com>
In-Reply-To: <CANpmjNPj5aMPu_7D=cwrDyAwz9i-rVcXYgGapYdB+vdHcR3RZg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 18 Sep 2021 11:45:15 +0200
Message-ID: <CANpmjNOUt5is7iHCAz9aOdD2nBb_7tqAKXmuWtitY_VNOkmv5w@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
To: Liu Shixin <liushixin2@huawei.com>
Cc: Kefeng Wang <wangkefeng.wang@huawei.com>, akpm@linux-foundation.org, 
	glider@google.com, dvyukov@google.com, jannh@google.com, mark.rutland@arm.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=R0gWqYQH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32c as
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

On Sat, 18 Sept 2021 at 11:37, Marco Elver <elver@google.com> wrote:
>
> On Sat, 18 Sept 2021 at 10:07, Liu Shixin <liushixin2@huawei.com> wrote:
> >
> > On 2021/9/16 16:49, Marco Elver wrote:
> > > On Thu, 16 Sept 2021 at 03:20, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> > >> Hi Marco,
> > >>
> > >> We found kfence_test will fails  on ARM64 with this patch with/without
> > >> CONFIG_DETECT_HUNG_TASK,
> > >>
> > >> Any thought ?
> > > Please share log and instructions to reproduce if possible. Also, if
> > > possible, please share bisection log that led you to this patch.
> > >
> > > I currently do not see how this patch would cause that, it only
> > > increases the timeout duration.
> > >
> > > I know that under QEMU TCG mode, there are occasionally timeouts in
> > > the test simply due to QEMU being extremely slow or other weirdness.
> > >
> > >
> > Hi Marco,
> >
> > There are some of the results of the current test:
> > 1. Using qemu-kvm on arm64 machine, all testcase can pass.
> > 2. Using qemu-system-aarch64 on x86_64 machine, randomly some testcases fail.
> > 3. Using qemu-system-aarch64 on x86_64, but removing the judgment of kfence_allocation_key in kfence_alloc(), all testcase can pass.
> >
> > I add some printing to the kernel and get very strange results.
> > I add a new variable kfence_allocation_key_gate to track the
> > state of kfence_allocation_key. As shown in the following code, theoretically,
> > if kfence_allocation_key_gate is zero, then kfence_allocation_key must be
> > enabled, so the value of variable error in kfence_alloc() should always be
> > zero. In fact, all the passed testcases fit this point. But as shown in the
> > following failed log, although kfence_allocation_key has been enabled, it's
> > still check failed here.
> >
> > So I think static_key might be problematic in my qemu environment.
> > The change of timeout is not a problem but caused us to observe this problem.
> > I tried changing the wait_event to a loop. I set timeout to HZ and re-enable/disabled
> > in each loop, then the failed testcase disappears.
>
> Nice analysis, thanks! What I gather is that static_keys/jump_labels
> are somehow broken in QEMU.
>
> This does remind me that I found a bug in QEMU that might be relevant:
> https://bugs.launchpad.net/qemu/+bug/1920934
> Looks like it was never fixed. :-/
>
> The failures I encountered caused the kernel to crash, but never saw
> the kfence test to fail due to that (never managed to get that far).
> Though the bug I saw was on x86 TCG mode, and I never tried arm64. If

[ ... that is, I didn't try running QEMU-ASan in arm64 TCG mode ... of
course I use QEMU arm64 to test. ;-) ]

> you can, try to build a QEMU with ASan and see if you also get the
> same use-after-free bug.
>
> Unless we observe the problem on a real machine, I think for now we
> can conclude with fairly high confidence that QEMU TCG still has
> issues and cannot be fully trusted here (see bug above).
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOUt5is7iHCAz9aOdD2nBb_7tqAKXmuWtitY_VNOkmv5w%40mail.gmail.com.
