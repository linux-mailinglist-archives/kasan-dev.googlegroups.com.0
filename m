Return-Path: <kasan-dev+bncBC7OD3FKWUERBNH4XWMAMGQE2QEQJLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id C2DF45A8138
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 17:28:53 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id v13-20020a05620a0f0d00b006b5f0ec742esf11905672qkl.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 08:28:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661959732; cv=pass;
        d=google.com; s=arc-20160816;
        b=asZJQ46s7ZKYoKHowY5Eaq+7Ol5XDTfNClVY4rjTo6vWBKcTwTwC8Qvu+6oS1hKgmo
         FB9+gBu13XHcQ44CUI+rFuHNEni4CfPFEAUVXwUOZKRtoCXpjkcdVubKNVyyB3YNYE7W
         yh5zz0JAhz6bowcgH6OYcSqyOSFyJPCUo9VGnYqb49ec5iIIXuyRDjEna6zfoCjMeVxl
         uv832GHwGlPFeqq7WIeWkcrIFQKyUAVx1NrfAD30GuhV21hboksD6O+48WACVo1uXocW
         Z4TsUgYTxZYLo7aPkTjsPvOWw3CX+cBANeXV452iYc3JW5UJFyW53qdHpvoGJYPhMwMJ
         SZOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZEpJLPfZniqolEAc/cKBVNG2JEsepmLfkCuURBuHzkE=;
        b=wcroiN616PUb3HH8C9QtKiqUqrPky9R6lAVqT1epeprCjJdwjsDh9JdL7G3NFa0mjC
         aQMzbyluxNHDWoFxZJUlJCElMDWEgWrx+fMwxtNQ6iXEp1lQAUQu5TkqJGfDrPQdeI/C
         E6G5gfsJAFyrVGLa4saotpqVSSpKZVfVLegeRNLRGuWZZzJ/xOMum+AcEf7Aic3orcre
         9dpPX8mjpNOHt7VG9sn5COr8cpjBRSLVsoWRKjnzK7s5jZXAw7GbsORU/DeL6H+yopWW
         whkbEE1+jSskrzA79fy+B89G7TMrNRyhWaDZ+qd8qUJCgHMyMKET0k1QRMzVH6fM6wAa
         VEvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K4mZtzeF;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=ZEpJLPfZniqolEAc/cKBVNG2JEsepmLfkCuURBuHzkE=;
        b=ZTFpFk37TjsMQh7oDOtKlkptaUecAVyhYERLjFLDfcVJBVJ4ro7UJbBbt6BXPpDqTK
         xx8Gw9hxUPZvXEA0vIxj7WenPSyUO2RKxWRmkDf8FPaZFn7RgcVhKwMgEX0f5jwRvyCL
         TX/ShJHqacNuhcuR2sf/2sJl+RpBCqwvW1p60rEANvKSoCcCUQfOFB4UTyBc8s+pqfBm
         ZRgtdQmDbnWEWvPEUZQ6uSeZRu6I458/YTnss8AYmCY0vIMLpdQ22aMnQZIZx4ldtmv9
         gwoTULzt77+9FVsSkK0R+Ve7OVjdD4syAbJTlbXqWvWxnvV+N2pE+j+ITGvVnII+YHH8
         sBkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=ZEpJLPfZniqolEAc/cKBVNG2JEsepmLfkCuURBuHzkE=;
        b=0EJz+ExXHE/rNY0can7PrRhnJbCzr9+MShmckUk0n1jluYMAtnwr6DGKy93DNSlHAm
         l78vp7ZLGaEmg+bSPQsUFdDLOrbmgB2dj0Oz/CMidLTrO6z8DMy5hRdP286KfiiMXpk6
         abq32CUr7mw6DnFLzf+gxBAlLQWJSjuAihK3K89C0OAw4+Vux/wyRBDzj5nHAHGzQ35R
         G0Hgw39NCrtSHQgeeL6uML0IlVyfqt4iaWHdN+MdkBF4VRqO8TCpmUUi1vweI3SskHOH
         uSLfOLTWKu9ECOAA70rhi1qJZCmDhUFcFKV6WJDEMCSsM/dSXbO29/Xvyjs8FbqcB0JA
         MLbA==
X-Gm-Message-State: ACgBeo0Z+zCFTtXupX+y2wnONA6+mmorCj3H8whLNjU019iOnbeueiJ/
	UPXJyfp634+G1NeLrCaH1N4=
X-Google-Smtp-Source: AA6agR6q4shxGzZ6sGpjm+d6altEyV19jRmyBaenM86Zm1jlF8WaJoQgUhwba6TJUb5LqIJFYhTM4g==
X-Received: by 2002:ac8:5b03:0:b0:343:679b:64f2 with SMTP id m3-20020ac85b03000000b00343679b64f2mr19849778qtw.260.1661959732702;
        Wed, 31 Aug 2022 08:28:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:b251:0:b0:499:9be:29cf with SMTP id k17-20020a0cb251000000b0049909be29cfls3826624qve.3.-pod-prod-gmail;
 Wed, 31 Aug 2022 08:28:52 -0700 (PDT)
X-Received: by 2002:ad4:5bc3:0:b0:495:d465:1aeb with SMTP id t3-20020ad45bc3000000b00495d4651aebmr19863533qvt.127.1661959732257;
        Wed, 31 Aug 2022 08:28:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661959732; cv=none;
        d=google.com; s=arc-20160816;
        b=FzB3qwXhOlWoROisYWFHmCguqKBPXpsTXSHuj/NqzeKYiRkRagJrXmW2d2tmLDzAUn
         8q+Ecw51Oiv1rZEGwBEKCKaxCxJGNbDR0EgwCOgDrDUl+6N8Lp1/zVI/keByoRVwucNl
         hq8ImMBCrjMLb3pHqktr5c8PyWq9Kv8t7AS1njOEmEmdFpOGM8FqTlAr82p4KP2+NSvt
         NvO6p3g6MU78O5p5BZies6uXGXmPHbM/Sn/JexQzzXPrhcgYDOU1lj/3PuRuijV4vnts
         /XIFWI6OrMtKpXx0DkL8HNW9S9sU9GPwO5eWhLnWgCBBvfqGZC5Nk7vvd1Y7M4/6WX9v
         MKfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WG3L5AqBV6fri0E+FNG2tsbDp/uFyzzRTMikwR7NSY8=;
        b=GTA+cIiqa0FtNzy2EQmKr1J38apDOkaajUY69Egii/9B4M9/8d+qgl5RmH70fzY4XE
         X/GOBhnDlmvIlB18Ju+ts93E39Vxln4FvnUYztmFeBo7sWzuk3q7rFaNcfQSdIu3y848
         ye5ntFWIJoRLs1zZ8f0QX4jJ/b5Ffnv/gvcPby/hmRMk2zo+1zjTpnFxtFPUYlg1fAW0
         Sm03KU8ULamIecRSt6ZyG8UupJq/r6esv4B33pho7nzc7MlrD2sWjX344vgU3HnbjSG3
         CHSDc1mujOQpYzqjdYbpuSpA47S/6b7UpfXmDt8fvR2hSRbBBZAV+w2i5N/7ihNuP2oI
         ZwzQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=K4mZtzeF;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id d2-20020a05620a158200b006be73a94ad8si447753qkk.4.2022.08.31.08.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 08:28:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-324ec5a9e97so310404437b3.7
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 08:28:52 -0700 (PDT)
X-Received: by 2002:a0d:d850:0:b0:340:d2c0:b022 with SMTP id
 a77-20020a0dd850000000b00340d2c0b022mr16165795ywe.469.1661959731749; Wed, 31
 Aug 2022 08:28:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
In-Reply-To: <Yw88RFuBgc7yFYxA@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 08:28:40 -0700
Message-ID: <CAJuCfpGZ==v0HGWBzZzHTgbo4B_ZBe6V6U4T_788LVWj8HhCRQ@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Michal Hocko <mhocko@suse.com>
Cc: Mel Gorman <mgorman@suse.de>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Vlastimil Babka <vbabka@suse.cz>, Johannes Weiner <hannes@cmpxchg.org>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Davidlohr Bueso <dave@stgolabs.net>, 
	Matthew Wilcox <willy@infradead.org>, "Liam R. Howlett" <liam.howlett@oracle.com>, 
	David Vernet <void@manifault.com>, Juri Lelli <juri.lelli@redhat.com>, 
	Laurent Dufour <ldufour@linux.ibm.com>, Peter Xu <peterx@redhat.com>, 
	David Hildenbrand <david@redhat.com>, Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com, 
	ytcoode@gmail.com, Vincent Guittot <vincent.guittot@linaro.org>, 
	Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Benjamin Segall <bsegall@google.com>, Daniel Bristot de Oliveira <bristot@redhat.com>, 
	Valentin Schneider <vschneid@redhat.com>, Christopher Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, 42.hyeyoo@gmail.com, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, dvyukov@google.com, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, arnd@arndb.de, 
	jbaron@akamai.com, David Rientjes <rientjes@google.com>, Minchan Kim <minchan@google.com>, 
	Kalesh Singh <kaleshsingh@google.com>, kernel-team <kernel-team@android.com>, 
	linux-mm <linux-mm@kvack.org>, iommu@lists.linux.dev, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org, 
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org, 
	linux-modules@vger.kernel.org, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=K4mZtzeF;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, Aug 31, 2022 at 3:47 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
> > > On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> > > > On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > > > > ===========================
> > > > > Code tagging framework
> > > > > ===========================
> > > > > Code tag is a structure identifying a specific location in the source code
> > > > > which is generated at compile time and can be embedded in an application-
> > > > > specific structure. Several applications of code tagging are included in
> > > > > this RFC, such as memory allocation tracking, dynamic fault injection,
> > > > > latency tracking and improved error code reporting.
> > > > > Basically, it takes the old trick of "define a special elf section for
> > > > > objects of a given type so that we can iterate over them at runtime" and
> > > > > creates a proper library for it.
> > > >
> > > > I might be super dense this morning, but what!? I've skimmed through the
> > > > set and I don't think I get it.
> > > >
> > > > What does this provide that ftrace/kprobes don't already allow?
> > >
> > > You're kidding, right?
> >
> > It's a valid question. From the description, it main addition that would
> > be hard to do with ftrace or probes is catching where an error code is
> > returned. A secondary addition would be catching all historical state and
> > not just state since the tracing started.
> >
> > It's also unclear *who* would enable this. It looks like it would mostly
> > have value during the development stage of an embedded platform to track
> > kernel memory usage on a per-application basis in an environment where it
> > may be difficult to setup tracing and tracking. Would it ever be enabled
> > in production? Would a distribution ever enable this? If it's enabled, any
> > overhead cannot be disabled/enabled at run or boot time so anyone enabling
> > this would carry the cost without never necessarily consuming the data.

Thank you for the question.
For memory tracking my intent is to have a mechanism that can be enabled in
the field testing (pre-production testing on a large population of
internal users).
The issue that we are often facing is when some memory leaks are happening
in the field but very hard to reproduce locally. We get a bugreport
from the user
which indicates it but often has not enough information to track it. Note that
quite often these leaks/issues happen in the drivers, so even simply finding out
where they came from is a big help.
The way I envision this mechanism to be used is to enable the basic memory
tracking in the field tests and have a user space process collecting
the allocation
statistics periodically (say once an hour). Once it detects some counter growing
infinitely or atypically (the definition of this is left to the user
space) it can enable
context capturing only for that specific location, still keeping the
overhead to the
minimum but getting more information about potential issues. Collected stats and
contexts are then attached to the bugreport and we get more visibility
into the issue
when we receive it.
The goal is to provide a mechanism with low enough overhead that it
can be enabled
all the time during these field tests without affecting the device's
performance profiles.
Tracing is very cheap when it's disabled but having it enabled all the
time would
introduce higher overhead than the counter manipulations.
My apologies, I should have clarified all this in this cover letter
from the beginning.

As for other applications, maybe I'm not such an advanced user of
tracing but I think only
the latency tracking application might be done with tracing, assuming
we have all the
right tracepoints but I don't see how we would use tracing for fault
injections and
descriptive error codes. Again, I might be mistaken.

Thanks,
Suren.

> >
> > It might be an ease-of-use thing. Gathering the information from traces
> > is tricky and would need combining multiple different elements and that
> > is development effort but not impossible.
> >
> > Whatever asking for an explanation as to why equivalent functionality
> > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
>
> Fully agreed and this is especially true for a change this size
> 77 files changed, 3406 insertions(+), 703 deletions(-)
>
> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGZ%3D%3Dv0HGWBzZzHTgbo4B_ZBe6V6U4T_788LVWj8HhCRQ%40mail.gmail.com.
