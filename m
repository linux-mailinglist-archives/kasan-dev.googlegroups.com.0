Return-Path: <kasan-dev+bncBC7OD3FKWUERBS5BYOMAMGQEHEF5VGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F7AD5A9BC2
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 17:33:33 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id h13-20020a0ceecd000000b00498f5b113e6sf9659645qvs.21
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 08:33:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662046412; cv=pass;
        d=google.com; s=arc-20160816;
        b=FGOhPAnBE2MDcjqV0d3fPjA2rbXFk/GzTsnJeL3FlYwl9DWJln1tmZilwLAz9hb3ga
         9IfRUout9/q58/PGS0byXwTC0SPWxjzo/6jO5H5+Sh/JAz9LAZDh2qjSMyTIHgYutGgF
         8967kZVjXPGvi0xyy1WMYBeCrdOgpP1KqM18RQHIMd+Ce3+ONav+UBfvg0L1pqYoP81O
         Q9SMlvXYNwC7Bu77tuGuwCl3MgVsLUKDTgk1oJSn5ALuRd/7VMDX3IJBF3KsIsXj6uHY
         1bLUmpkCu/aJnZhH6IDOFt7QItKZd9yjvinwJdipnUe8Hq8HtZJl0Echp00cmKV+fcGp
         Gz7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=QItM+cjxIgioHEe3aHJcNr4DUkTsUjjtr8pfnxS+AkE=;
        b=L0JD0YlgyQvzt9ikAGVXlMyi1bf+GsCeuGUmKUsI+mlG48tF9npJaldfviYMhY0+yi
         VwHbYbFY1utIlYNmllut6Nipw4xSyj+ZWwK7ik/wmv9nik9krJXDiwF1RIc3/DDMVWMd
         iGfc9kCDLPOuvzAH8GQXC3U/cCgabXBppLhccWh5EETTVppP8x1Vq0I051P/2cpO2dEk
         QQgGm9OrP8uJOTb1MKA2itC8b142xohqbhMJyLC4ozeSX0GqraQlzSF7+Ar5LylBQO07
         7pIUlp2ZoPOzGqnxd+QsHnRUdD7AuNlWqFIhcFnC4zGuV8Tj2DVctYWjVFMcBJf9+RaS
         bqYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nPy2aaUn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=QItM+cjxIgioHEe3aHJcNr4DUkTsUjjtr8pfnxS+AkE=;
        b=ehubULOFXfVpIR5DJ9CHNSXf3n399n+RfdGTKsw6Rvc7obgxR6sDajUhkvE0oiP6fc
         ineo28mo63y6iJXWK1M9gFsI35ebPPKKbwk6fM8l6re4o9MIeIwnJvEk7WiV7fa1qRud
         a4pC3vpewCEBkpI0ns274macKEv9m4TLvZ6l1Bnqpedb+VqSDQiv2zGB6EOUZBVPUc13
         UnaSvOeX0RTMdLtKrmrNdpBGybVyPVzDaIetsJ2kg6tC+Ea/QRAeowwNUzlTeH3140WO
         lj8C3HMazBqB6Xy3heVAF32Z1HN/uHtEzUDVu2jw1yKL1jU4oGlyb4TDirXodDItHkC/
         xwdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=QItM+cjxIgioHEe3aHJcNr4DUkTsUjjtr8pfnxS+AkE=;
        b=lThqkdCak84gJbyHqMgM4+K5aEmhshwFlAOLnPtJHqxqmtn8LdICk7W78Z5xQods/1
         lhsTNtT9casxMXrfmhd/OO0GnC1JBlesXiX6FKN+fDU8ryWClSOdoB53S7dddFWHBQi7
         JHfXmlWUOcgp7Fzxcid23mKzNDXXPmfp2EN+IUdBRWhj9VgdepxFAwg4JVl2D82gHIkM
         12M26t5HZKaJmj1uawNyxE6Qp3W1R5qu/3dJ3HURX9LXFEK1JcEbP4K0Knx1ngoh/yPW
         7o7aUV7z0S/8mY8/PsfoWO+WstWoOh73eDXSMNCOenySmH/VDxNEeG53RjJ4valxLwTH
         SZCw==
X-Gm-Message-State: ACgBeo1E3F1EeaTKCqLHYumSN9a7VvYEKP+b4/sQoxtEZt4gCEhdIG4k
	duFDh5EYEQf9muI4dIZkFCU=
X-Google-Smtp-Source: AA6agR4V/TQGssbgZNv3ybSvkUITxvBetmEiKwW6LefEefVEtJEc71rU6phu3C1doOgljZr99zs5hA==
X-Received: by 2002:ac8:7d44:0:b0:344:57c4:5f54 with SMTP id h4-20020ac87d44000000b0034457c45f54mr23502723qtb.446.1662046412009;
        Thu, 01 Sep 2022 08:33:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:dc07:0:b0:474:651c:ec46 with SMTP id s7-20020a0cdc07000000b00474651cec46ls1421920qvk.6.-pod-prod-gmail;
 Thu, 01 Sep 2022 08:33:31 -0700 (PDT)
X-Received: by 2002:a0c:e3c7:0:b0:473:7d9a:6237 with SMTP id e7-20020a0ce3c7000000b004737d9a6237mr24939657qvl.37.1662046411419;
        Thu, 01 Sep 2022 08:33:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662046411; cv=none;
        d=google.com; s=arc-20160816;
        b=N23hu4rBhd6brEprucuAL/rr8U3vcTyIZcoaFm03H96+ab8Ges4TmjXX8pWq0PSm3m
         65Rs6m0k5AQzI5sdRl2YQWXcqVL6jW7VWxzPGaBCFzlKJJ+rFmAGFYIEcIe3w+uTROE8
         gkjbF+R7XZNJcl14112nszWjcA7AV7oUmlWBd0vZAFrQIVgj0o05nLrs7uiAJ5B1t9Hn
         ZQ7elv4fz5Q7A3Ax2+2fc2LjvPAdA/9N7DTWjIUNr3DgdRvD6R4M+bLvYErE0Rly9ACg
         JwvcPSYtXWqfkLpytB7yjwkgm9CB9SuoEeKlLAyCFqIkhtoAdc1yLtcKBi08cnh0hoSt
         lXMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=cuZ+nGX7dbAKHVSMzM9WDnRxW6f4Hrbmbun1Vl7XZUY=;
        b=u0a0Ngs+gN63n2Uo2FiuOnFxOK3lBUGpdmDa+0xHkjDejD8+yjo5FJdC7UU4dC/Ljx
         L4HtU5f8DTkux6JnTMjc80oTBOxCDmogUQaEEKQCPQveLkkhZZD0//1FlT+Fyek2dbPk
         7MaelJBSkWwJUjLdH+urKG1u7ivOvC/tsV0s3uCvZA/jSQLnpqIPvNyZIfJTAty4FH6f
         xdpuX3yQRzBWozaUrPpChgV3E5XDUG6mLKsNkJXJmjPaKu85V0vMjBsshbNLPXEtnXE4
         kgZoHIotZ600mTQO6BaUM421YlW46jCgF4fprS2os2uCC+pEY+q6X8lr41mEP7iVpASo
         QKLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nPy2aaUn;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id 5-20020ac85945000000b003437deaebe4si516259qtz.2.2022.09.01.08.33.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Sep 2022 08:33:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 130so9122041ybw.8
        for <kasan-dev@googlegroups.com>; Thu, 01 Sep 2022 08:33:31 -0700 (PDT)
X-Received: by 2002:a05:6902:705:b0:695:b3b9:41bc with SMTP id
 k5-20020a056902070500b00695b3b941bcmr19699146ybt.426.1662046410779; Thu, 01
 Sep 2022 08:33:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <20220831190154.qdlsxfamans3ya5j@moria.home.lan>
 <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
In-Reply-To: <YxBc1xuGbB36f8zC@dhcp22.suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 1 Sep 2022 08:33:19 -0700
Message-ID: <CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg@mail.gmail.com>
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
To: Michal Hocko <mhocko@suse.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Mel Gorman <mgorman@suse.de>, 
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
 header.i=@google.com header.s=20210112 header.b=nPy2aaUn;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Sep 1, 2022 at 12:18 AM Michal Hocko <mhocko@suse.com> wrote:
>
> On Wed 31-08-22 15:01:54, Kent Overstreet wrote:
> > On Wed, Aug 31, 2022 at 12:47:32PM +0200, Michal Hocko wrote:
> > > On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > > > Whatever asking for an explanation as to why equivalent functionality
> > > > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> > >
> > > Fully agreed and this is especially true for a change this size
> > > 77 files changed, 3406 insertions(+), 703 deletions(-)
> >
> > In the case of memory allocation accounting, you flat cannot do this with ftrace
> > - you could maybe do a janky version that isn't fully accurate, much slower,
> > more complicated for the developer to understand and debug and more complicated
> > for the end user.
> >
> > But please, I invite anyone who's actually been doing this with ftrace to
> > demonstrate otherwise.
> >
> > Ftrace just isn't the right tool for the job here - we're talking about adding
> > per callsite accounting to some of the fastest fast paths in the kernel.
> >
> > And the size of the changes for memory allocation accounting are much more
> > reasonable:
> >  33 files changed, 623 insertions(+), 99 deletions(-)
> >
> > The code tagging library should exist anyways, it's been open coded half a dozen
> > times in the kernel already.
> >
> > And once we've got that, the time stats code is _also_ far simpler than doing it
> > with ftrace would be. If anyone here has successfully debugged latency issues
> > with ftrace, I'd really like to hear it. Again, for debugging latency issues you
> > want something that can always be on, and that's not cheap with ftrace - and
> > never mind the hassle of correlating start and end wait trace events, builting
> > up histograms, etc. - that's all handled here.
> >
> > Cheap, simple, easy to use. What more could you want?
>
> A big ad on a banner. But more seriously.
>
> This patchset is _huge_ and touching a lot of different areas. It will
> be not only hard to review but even harder to maintain longterm. So
> it is completely reasonable to ask for potential alternatives with a
> smaller code footprint. I am pretty sure you are aware of that workflow.

The patchset is huge because it introduces a reusable part (the first
6 patches introducing code tagging) and 6 different applications in
very different areas of the kernel. We wanted to present all of them
in the RFC to show the variety of cases this mechanism can be reused
for. If the code tagging is accepted, each application can be posted
separately to the appropriate group of people. Hopefully that makes it
easier to review. Those first 6 patches are not that big and are quite
isolated IMHO:

 include/linux/codetag.h             |  83 ++++++++++
 include/linux/lazy-percpu-counter.h |  67 ++++++++
 include/linux/module.h              |   1 +
 kernel/module/internal.h            |   1 -
 kernel/module/main.c                |   4 +
 lib/Kconfig                         |   3 +
 lib/Kconfig.debug                   |   4 +
 lib/Makefile                        |   3 +
 lib/codetag.c                       | 248 ++++++++++++++++++++++++++++
 lib/lazy-percpu-counter.c           | 141 ++++++++++++++++
 lib/string_helpers.c                |   3 +-
 scripts/kallsyms.c                  |  13 ++

>
> So I find Peter's question completely appropriate while your response to
> that not so much! Maybe ftrace is not the right tool for the intented
> job. Maybe there are other ways and it would be really great to show
> that those have been evaluated and they are not suitable for a), b) and
> c) reasons.

That's fair.
For memory tracking I looked into using kmemleak and page_owner which
can't match the required functionality at an overhead acceptable for
production and pre-production testing environments. traces + BPF I
haven't evaluated myself but heard from other members of my team who
tried using that in production environment with poor results. I'll try
to get more specific information on that.

>
> E.g. Oscar has been working on extending page_ext to track number of
> allocations for specific calltrace[1]. Is this 1:1 replacement? No! But
> it can help in environments where page_ext can be enabled and it is
> completely non-intrusive to the MM code.

Thanks for pointing out this work. I'll need to review and maybe
profile it before making any claims.

>
> If the page_ext overhead is not desirable/acceptable then I am sure
> there are other options. E.g. kprobes/LivePatching framework can hook
> into functions and alter their behavior. So why not use that for data
> collection? Has this been evaluated at all?

I'm not sure how I can hook into say alloc_pages() to find out where
it was called from without capturing the call stack (which would
introduce an overhead at every allocation). Would love to discuss this
or other alternatives if they can be done with low enough overhead.
Thanks,
Suren.

>
> And please note that I am not claiming the presented work is approaching
> the problem from a wrong direction. It might very well solve multiple
> problems in a single go _but_ the long term code maintenance burden
> really has to to be carefully evaluated and if we can achieve a
> reasonable subset of the functionality with an existing infrastructure
> then I would be inclined to sacrifice some portions with a considerably
> smaller code footprint.
>
> [1] http://lkml.kernel.org/r/20220901044249.4624-1-osalvador@suse.de
>
> --
> Michal Hocko
> SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpGhwPFYdkOLjwwD4ra9JxPqq1T5d1jd41Jy3LJnVnhNdg%40mail.gmail.com.
