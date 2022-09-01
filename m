Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHEPYKMAMGQEQXFW56I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 61B175A9432
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 12:21:19 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id bh11-20020a056602370b00b00688c8a2b56csf10399838iob.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 03:21:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662027676; cv=pass;
        d=google.com; s=arc-20160816;
        b=QY3CgrRRuk0xUS2d5QHeJFzRBUDRHGTRSlElghQaInzX0NR2vP1cCPTTvlF5na6ION
         Kn3wk4/C6N8yJ40EPuv1Ir1xBEpibPLoe2SpdoHapWM8iazIPeE08GeXq5TQ3SBbjXb2
         LOPcN3HbaSMLTKGIdElcIYNtUzuZzem50rKeSAHKh6Dcb4yWfvQnHokFiQobYiom9GeC
         0hfJSEFTxP2VzzQ6LQqLefN7QXF0KPu5BGACPNOIpZD5F1vayu1bbIfs8JuvP3iD8ZxT
         maizdCEcXApqi3TALcZ1n3a0yJJQ1aSLQeD8VgmbVTUPgOeSMTHMp47xVfs752IzvTi/
         u3lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HveOoG0C6gNZPcypJUUHI34rIIm4RaP0GC2x4DzOTSM=;
        b=Xe5VO1YjetwoxsR3rJWJUOMt52W62xsXoqc5ho5SmTNxjhItoTtYm+Ueaa+ST9hMEQ
         3u5cIggHIDmeq78o1WZ6kcMnPnK2tojo3bQX3l8T9Xsb3nErsXl6m0e48E49BkisE54T
         cMIMa+RL8bNW/J0jWZEZug+O1ZBch/HRMbcOdNeJeMAfAmcN8T06hbfp5k9/owdecNsy
         A339cqPr5sKp8j1twCsdwf+IJyGLU/ka8s6ae84HMbSJSbm5TRbaGlwxOptS/r0A0CTN
         31DHCNsi7M1mX1i0tjftfpAMirZY/FsqRCB1hwxcG5l6BDjyExr4OozcW1pthfh/ihBJ
         /rRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aimEc3ft;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=HveOoG0C6gNZPcypJUUHI34rIIm4RaP0GC2x4DzOTSM=;
        b=fbKIPQb7cqdbh6yRxuQkMIUJqGPyiNnewM7lr8HoBZZuECnHvoRgiJV/VUdf7+Sm/p
         fsqZ1LaUJX1e/QPaoggIRxKgs+ywsQVCNpEFCN24CkKmTYpF8E2J/RkVfR4bhQwRnxYz
         LsbQqMYF0ffISnXkTjQeOGE6qdS0HL/UoHtlZwZs2tpERTfIvmxV/8kHOvM8gDX2ag1N
         OqwlzuEh1+ypAOu6rJrc9X18i5GJIZlEM51D5n/TOeqXn4ceKdbT6CHGy4EOIA9lVihU
         iYkvBoDykoaPzwGEJ9AggKYhXW5OndMQoLrfrRyvjrVqOVv1QqK3oDMRdc2ajXdeCbIW
         A5dQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=HveOoG0C6gNZPcypJUUHI34rIIm4RaP0GC2x4DzOTSM=;
        b=E4u2zODuROVoF0CCGYuziimIvyx0lbPPBfnRglGujiuNodb83DT7cIfeImlWNasnT3
         C/dBHUhyglrX2q8cxa/S4MYUcyqxG88pjNtFVbYl0NrWSTT09G5/fqDBj8+I4mBxwBMT
         5mViwMx6XanqFZjw9C7Qd5pl9wURn2F6b6DD47Igyr1P5/9yss5GWcYdC28A0ON7UP4c
         yvbt5Vq5vjxrdGC6FilQeFqxrKaTZFkwHCQ/s34DhEWlKcENsege9BLF6mfaDsRhKrsv
         qv5DnVrmrhZfv0LC9/ztOuZec6KewlUbEHb8PDRe7cbKT98syymlP7bCWgQxhgsoVdb1
         2aiA==
X-Gm-Message-State: ACgBeo10i3HJ27ye55etMbSPMXtHq4OF2YNWgnRu7Yxt+SP4r3Rnuazd
	X3pC1hwQw03ahIJjQGbTuzM=
X-Google-Smtp-Source: AA6agR5wWta0cCAjj1Rc2sJSZDboXYJ8vk5ra2yVVn2VFsPWRkdlcqF++C0mIfwTPEJZ9B4PemEFrg==
X-Received: by 2002:a05:6638:1412:b0:343:c14b:839d with SMTP id k18-20020a056638141200b00343c14b839dmr16856359jad.119.1662027676165;
        Thu, 01 Sep 2022 03:21:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:a183:0:b0:349:e63e:93 with SMTP id n3-20020a02a183000000b00349e63e0093ls365407jah.9.-pod-prod-gmail;
 Thu, 01 Sep 2022 03:21:15 -0700 (PDT)
X-Received: by 2002:a05:6638:2411:b0:346:86a0:d325 with SMTP id z17-20020a056638241100b0034686a0d325mr17412224jat.28.1662027675659;
        Thu, 01 Sep 2022 03:21:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662027675; cv=none;
        d=google.com; s=arc-20160816;
        b=gn99VgFaPMOv1ws4U2YLyZG+fuSztn9FDy+8DwDrZLMOsa30Ai+XIikfUxncw2iejQ
         VBjB1Ob/RXz5U5oArQ7fIhYVeeIUQrM3+MM6P6aY+Lip432KJJwdrUzQPLAc3NkVqcfm
         Oe2GIjelq7aTsl7U2E+mHheBgnNyPB50kP60puv0WtcxZaCYlqpMkZuQFJPutIUa09QB
         aPS2THAlNN3QoElZe7QSuIKjuZqX7S2SSQ/sW1J5TiwFGyB6KxX8ClxbZBYmHCLAQKV7
         LpewQGbNG8+fJPrBu7dE43/6FbbAMmaDbilYDTQccGWLtLKEvVLfyPTBoPWlJzvaFybN
         +sxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dq57C6wCfbAHbefKG8GYTmvvjyg3019DyyLHKt8zuMQ=;
        b=cJ7UKQ/l+sFrMfG5m7UFogkrdeyOfX1Haz3arvISopGht5hSQ1ZfVws1Jhe+h4WdYD
         MHQhvjFnXxzOMEMj2D/+jDaPVrEK/KEBZ5U5apm8SccveFTXdXjJraF/f3UCB6cOwRDZ
         /zAD4qbxQms5qqoaJzzLM1CQfuTMByht4+GSFiPor/KLtZDZzjRTb/9M8MjD+nFlRWSc
         sLPrUmZfELNLaP5kDrc3vTs3998Wf62Ob5NuGyZiBW0aV7SqownMaDvA5I4CAyzUdODj
         /ajOjNUn/3m7fGM5I//LMFozdX/93gBw8lfefTGGdF8+IqVQHbiDMvaAouR68fr9W04D
         1MxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aimEc3ft;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id s21-20020a056602011500b00684e0ad0804si970538iot.4.2022.09.01.03.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 03:21:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-324ec5a9e97so331818847b3.7
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 03:21:15 -0700 (PDT)
X-Received: by 2002:a81:bb41:0:b0:328:fd1b:5713 with SMTP id
 a1-20020a81bb41000000b00328fd1b5713mr22919241ywl.238.1662027675106; Thu, 01
 Sep 2022 03:21:15 -0700 (PDT)
MIME-Version: 1.0
References: <20220901044249.4624-1-osalvador@suse.de> <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com> <YxBvcDFSsLqn3i87@dhcp22.suse.cz>
 <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com> <YxCC7zoc3wX3ieMR@dhcp22.suse.cz>
In-Reply-To: <YxCC7zoc3wX3ieMR@dhcp22.suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 12:20:38 +0200
Message-ID: <CANpmjNO0wzGBOcj1NH+O7AG2c31Q=-ZDwYZENmYmzUQcPZhQEw@mail.gmail.com>
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
To: Michal Hocko <mhocko@suse.com>
Cc: Oscar Salvador <osalvador@suse.de>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Vlastimil Babka <vbabka@suse.cz>, Eric Dumazet <edumazet@google.com>, Waiman Long <longman@redhat.com>, 
	Suren Baghdasaryan <surenb@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aimEc3ft;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112c as
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

On Thu, 1 Sept 2022 at 12:01, Michal Hocko <mhocko@suse.com> wrote:
>
> On Thu 01-09-22 11:18:19, Marco Elver wrote:
> > On Thu, 1 Sept 2022 at 10:38, Michal Hocko <mhocko@suse.com> wrote:
> > >
> > > On Thu 01-09-22 10:24:58, Marco Elver wrote:
> > > > On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> > > [...]
> > > > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > > > index 5ca0d086ef4a..aeb59d3557e2 100644
> > > > > --- a/lib/stackdepot.c
> > > > > +++ b/lib/stackdepot.c
> > > > > @@ -63,6 +63,7 @@ struct stack_record {
> > > > >     u32 hash;                       /* Hash in the hastable */
> > > > >     u32 size;                       /* Number of frames in the stack */
> > > > >     union handle_parts handle;
> > > > > +   refcount_t count;               /* Number of the same repeated stacks */
> > > >
> > > > This will increase stack_record size for every user, even if they don't
> > > > care about the count.
> > >
> > > Couldn't this be used for garbage collection?
> >
> > Only if we can precisely figure out at which point a stack is no
> > longer going to be needed.
> >
> > But more realistically, stack depot was designed to be simple. Right
> > now it can allocate new stacks (from an internal pool), but giving the
> > memory back to that pool isn't supported. Doing garbage collection
> > would effectively be a redesign of stack depot.
>
> Fair argument.
>
> > And for the purpose
> > for which stack depot was designed (debugging tools), memory has never
> > been an issue (note that stack depot also has a fixed upper bound on
> > memory usage).
>
> Is the increased size really a blocker then? I see how it sucks to
> maintain a counter when it is not used by anything but page_owner but
> storing that counte externally would just add more complexity AFAICS
> (more allocations, more tracking etc.).

Right, I think keeping it simple is better.

> Maybe the counter can be conditional on the page_owner which would add
> some complexity as well (variable size structure) but at least the
> external allocation stuff could be avoided.

Not sure it's needed - I just checked the size of stack_record on a
x86-64 build, and it's 24 bytes. Because 'handle_parts' is 4 bytes,
and refcount_t is 4 bytes, and the alignment of 'entries' being 8
bytes, even with the refcount_t, stack_record is still 24 bytes. :-)

And for me that's good enough. Maybe mentioning this in the commit
message is worthwhile. Of course 32-bit builds still suffer a little,
but I think we can live with that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0wzGBOcj1NH%2BO7AG2c31Q%3D-ZDwYZENmYmzUQcPZhQEw%40mail.gmail.com.
