Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO6O2SIAMGQEH7O6PII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 828DE4C0100
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 19:11:08 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id 24-20020a5d9c18000000b0064075f4edbdsf9172064ioe.19
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Feb 2022 10:11:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645553467; cv=pass;
        d=google.com; s=arc-20160816;
        b=tNBgscWS30XEmEjnTISsqx9V/mbU0GovZmF6mhYtFR5+IyWmgPW/pa4PldMcbYTYMk
         b5oZAF08FP33kInxZazWSuMI0WiaLdPSw9qhV2+uNOoJ+iD0New0P7FosUb0w4NeSu4U
         QJ0ll8DLS9smlPLMh1zOGct9lbcKo0mmHRMCedHU9wtpthf89twxuF9MJ/DsafcBEvoT
         B6MU4gFS+v1in1PNuUXx0JEWFRVjl2Qwuu5EXiDpJ5ZdN0NpxUQOGZtgOyevQqPjqJV8
         /ll6Oy3AvB5n6N+dKknReD8GSlCAn4/Fb4/W5YaWpfVJnyWBD3MKhgl2ss/h0hbqDeaK
         B7Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eSITk3W3H7t37NkwXC5Z1mRQWYJTtyjzxLUcKoHsAv4=;
        b=w3YTi+JFgh5y3stDXLNBQUA+m8/ffiVF8Tc5KKjAFA/ZPM9zjDjC9u9N0pVtXCW57h
         ITY6dkurqDRVs9nIDIVsxfKF288G4Tc+J9BPx5010SlSfBJHiSRYA2X6BE5vHYXxJxtq
         I0qiRluX/exBa7wOAAv8+vbDyl7tGnpKmkXEqQ2PQ2+AQO/Ver5aSk/B7eCXuxYZQieE
         /opaZIy4/sqhKpg1y+6tCsT+xIFtFdj+yhq6tM8wX74piEgmjEt/LggMIsAIqDh3UF2X
         QMmolAHBLIhKsl25bJcLFHlDdNvG6XjIP7nSkQZvCUtCSmCOI/qn+voGaDu7LFCe7dVF
         l1+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ntHc747k;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eSITk3W3H7t37NkwXC5Z1mRQWYJTtyjzxLUcKoHsAv4=;
        b=FoTHK1ZDQAw6VymHDjhc50VgDJP1QF/KeE8de1VvXMTsWbYp/Me8YwyjLuqk/xZogu
         rs9L0O5bX5Pvbd8bdaKTYlVcHJHnag/p0PE3n+MpN/6DsIiCVqZYLkkTlQlkrz51VQ8i
         nVa0NIbvo/UmNRJssUiskzs3WHbERgYKcUj53Z2dF/Jt0wPxp5lcyk0KYTzUd3h+Ec6N
         qvOHbCtGd3VhQvS78P6ih1+xLS87xm6bfTQ9RWXnO7nMipQw4UlTsCuAyfsEf1D40q5v
         46Dd9BLprXygxwT4gnKZClVS/QsNBi5Wq0+9OZigXyVirYY0GFBArNineYk+Bflef6Rc
         BxgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eSITk3W3H7t37NkwXC5Z1mRQWYJTtyjzxLUcKoHsAv4=;
        b=0ENIHldsa0qiBpgCSf1ziaYqTBWohAOCmzjucF2L3Zg7zUIIz1oadIP1WhD4BzTvCi
         cpEujR8AMDFHeOQS/4gtfpUFawgtLil5usxnnaNrpgN0IRAb+6oweOS/rvgrRjmGEzKj
         vKLu59TOkFi7C+stGb+4sFWBdqPJmqn/4M4Iaz2VPJZCfhpWjsQMk20nRpiZIRbYMqPU
         7RWNQClGbNjVkbUy/hCoCMvbmIzPrOg+zM8+ynj1objdrQT/WVFp+dBdZ/S/lBWa0qyn
         0Vxn+Fh+5f6vB79mNjsnSA1fzZQnlEmAuHIaFl4jHnBeczFP2rzfXVVe3VaP7MsFQiFr
         312g==
X-Gm-Message-State: AOAM530NfYy2He609GHdn1Fgy5DBbMnre1mowzpmT6rr0YAxS/T1iv1m
	bowbI05TAletrZVqvqHoo9Q=
X-Google-Smtp-Source: ABdhPJyjiJsnWvTVjYV+vRQWOhYlEMzmwIRvAENijw56OMhzZhCAMZezapOOORy/3PX/md/t69OGig==
X-Received: by 2002:a92:8e4a:0:b0:2bc:1a0d:ed41 with SMTP id k10-20020a928e4a000000b002bc1a0ded41mr21963696ilh.96.1645553467539;
        Tue, 22 Feb 2022 10:11:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9298:0:b0:641:2914:5353 with SMTP id s24-20020a5d9298000000b0064129145353ls779149iom.8.gmail;
 Tue, 22 Feb 2022 10:11:07 -0800 (PST)
X-Received: by 2002:a05:6602:1656:b0:641:958b:d90f with SMTP id y22-20020a056602165600b00641958bd90fmr943165iow.51.1645553467143;
        Tue, 22 Feb 2022 10:11:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645553467; cv=none;
        d=google.com; s=arc-20160816;
        b=Ly4yNxpTlg7j8XJefozrVTPtTNUydteTvc7au6TqDxzrx3fHIKD45bwaLWLtv4dm8f
         3+UgSho8PAgjHpARupRVRzsme5JsV4nHMV7bjyG6QXPT74nV+BXwjxC1TVKSDQkK0EIM
         e/0dgDEuo6EG2Tcee3r/olZbb3MwP5h6MSeREnUOtzctMrl0V0fONXF5nGvAgnJOCOQN
         UQuAEPXslRIbCkdZp+wiTERGYv06iP6D3yUe6dIHbzbyDfgCize5eiSu6vVnZl+bUWNb
         337zcnFP8cdJuwXX4VDcio8aVaAFUfCYiKJvRXhJk2AvR2NZPXcBZoASb9l8OUZeElic
         fCNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vv7itYaWRJkHxlIs8WR7327QmS0peJ/llMiCwV0cNp4=;
        b=AeTkMLjG1DH24MWHa+pBO1soJgGxdJctfbWtTyvmPtWtAEGxX50khQFrQBbQ9aRLyI
         b0jJvOIaewJFeeUMy1l4zFb3uRN1g/kICGw3rd/3dakurYSQHqI1Dz7t4fz2j8uGbYO8
         VdTY8I11QoV1aMJCqvsdzHnWW6M4op3+dng4cdFd2MJ6QX7px8zHAI1kO80Y5wogII0n
         opctbeEtkjPFFE96itHqmgO1cMQ7Ic8AYLJ1L6H83SShQs+9bZLnj6V2Bmrlr4U5F+Yf
         fAa+DKUMjBc7qxtZKvXC9SNR3rrOO4qUnv6pyMmecDX+FN8ztGFdvH5A+jwDkTJpheju
         QnaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=ntHc747k;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id z9si2011365ilu.5.2022.02.22.10.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 22 Feb 2022 10:11:07 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id p19so42929106ybc.6
        for <kasan-dev@googlegroups.com>; Tue, 22 Feb 2022 10:11:07 -0800 (PST)
X-Received: by 2002:a25:e057:0:b0:624:2ade:2a8f with SMTP id
 x84-20020a25e057000000b006242ade2a8fmr23575031ybg.87.1645553466469; Tue, 22
 Feb 2022 10:11:06 -0800 (PST)
MIME-Version: 1.0
References: <2d44632c4067be35491b58b147a4d1329fdfcf16.1645549750.git.andreyknvl@google.com>
 <CANpmjNOnr=B_o83BJ6b1S6FKWe+p2vR58H8CHtGPNPnu6-cQZg@mail.gmail.com> <CA+fCnZf2jE1N8j9iQRtOnQsTP=2CQOGYqREbzypPQa-=UXjhDA@mail.gmail.com>
In-Reply-To: <CA+fCnZf2jE1N8j9iQRtOnQsTP=2CQOGYqREbzypPQa-=UXjhDA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Feb 2022 19:10:55 +0100
Message-ID: <CANpmjNN3-qX_brk9PTW0MkF0H=-DeM+n_ccge_QQ07oKBPx74w@mail.gmail.com>
Subject: Re: [PATCH mm] another fix for "kasan: improve vmalloc tests"
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=ntHc747k;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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

On Tue, 22 Feb 2022 at 19:08, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Feb 22, 2022 at 6:50 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, 22 Feb 2022 at 18:10, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > set_memory_rw/ro() are not exported to be used in modules and thus
> > > cannot be used in KUnit-compatible KASAN tests.
> > >
> > > Drop the checks that rely on these functions.
> > >
> > > Reported-by: kernel test robot <lkp@intel.com>
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > ---
> > >  lib/test_kasan.c | 6 ------
> > >  1 file changed, 6 deletions(-)
> > >
> > > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > > index ef99d81fe8b3..448194bbc41d 100644
> > > --- a/lib/test_kasan.c
> > > +++ b/lib/test_kasan.c
> > > @@ -1083,12 +1083,6 @@ static void vmalloc_helpers_tags(struct kunit *test)
> > >         KUNIT_ASSERT_TRUE(test, is_vmalloc_addr(ptr));
> > >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, vmalloc_to_page(ptr));
> > >
> > > -       /* Make sure vmalloc'ed memory permissions can be changed. */
> > > -       rv = set_memory_ro((unsigned long)ptr, 1);
> > > -       KUNIT_ASSERT_GE(test, rv, 0);
> > > -       rv = set_memory_rw((unsigned long)ptr, 1);
> > > -       KUNIT_ASSERT_GE(test, rv, 0);
> >
> > You can still test it by checking 'ifdef MODULE'. You could add a
> > separate test which is skipped if MODULE is defined. Does that work?
>
> Yes, putting it under ifdef will work. I thought that having a
> discrepancy between built-in and module tests is weird, but I see the
> kprobes tests doing this, so maybe it's not such a bad idea. Will do
> in v2.

Additionally you could have the test skip with kunit_skip(), so it's
at least visible. The code itself has to be #ifdef'd I guess because
set_memory_*() aren't even declared ifdef MODULE (I think?).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN3-qX_brk9PTW0MkF0H%3D-DeM%2Bn_ccge_QQ07oKBPx74w%40mail.gmail.com.
