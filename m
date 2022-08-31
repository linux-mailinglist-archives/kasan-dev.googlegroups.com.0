Return-Path: <kasan-dev+bncBC7OD3FKWUERBXNBX2MAMGQENB2VVNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 81BAE5A8375
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 18:48:31 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id l16-20020a170902f69000b00175138bcd25sf3751723plg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 09:48:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661964510; cv=pass;
        d=google.com; s=arc-20160816;
        b=dFp9Gi3s9pBZU3WF6/N+fsMRyqRBZd40/CGiWmwcaZi5WC/5CkBwo6gM4uiGoC3Kjq
         CIEuvuAqc70zd5PfixzXffi1EbfBWAmNkvHaAP3Pau2XF5G7XP1Z/PGvpQj8U9chABQR
         3zQbaxCMpEBz1hGk/sIu2wv58W+1+IMruIL2nSk5iaFVWe/Wz4Cii2EyxiJtjD4soiBi
         IyEkWevbDpwMcEe2yFLbey4kfaZEdvQbMi8dKs9RgS+Sm3lKYexVflnTXWde/AkKkFyJ
         thwPb8m7GdhiMBG8yJEJXaCowoGLEhyqK4TtvU28CKg/Pwzdn0S7g2U5gUTVA3fUY3CC
         lLbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WpTh8QKhUxxPdPN/Gx5GKqn0haBZl44EwfvGc3miU+0=;
        b=R/HNoLSWb5X/4BW7ar++djPW4QoHLBlXjgvFWNt2BSgEKKmdUYEO+a+X1QFWWs7Ns5
         y/AOPetxL/fQpCXsNb5nsFysSjbpM3tuDCXnHPNRWCTxve9HrYdYFHUld7g8LFHAUhm6
         7pfrrr8TWUzT9gwMz8xaAfsekH1l9S9Xa5fNUfOrQxxj4PrJhE5zmcvJHf3+z2zbaST/
         NBTzI3eEs1omKcL6jYtOMGr74EUxxOO51bulR5VPJ3KN3MBqpDtZt2+bicn9cOikOZ0Q
         osLmR9A4Rcd0A/hviPWFUTBqnzEABDJU8vbmh258416y2LUI5YbbCO9mjnpKEAjy9LsF
         g7lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VIdq+REr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=WpTh8QKhUxxPdPN/Gx5GKqn0haBZl44EwfvGc3miU+0=;
        b=cVCpGhIC1+unG9jeHhuhx914EbZuUvLcXfAtsqrOe3Y6mIBiKKwx/rhWkcGWqk4tZQ
         LztPlkCCAkdAoYY6pI4ZSw7tBKEcD7L/UopVMPrF13XskeFCeTNiwgK/kmbEFUQkSJOC
         EhA0EOPwZkm0TaTTO962++doBlteIgV8+umv+ppEOlEjD4LdMhb/Jvcbu7S9DP9BZgu8
         0MpUUR8TEkrR02TSDPDnqVvG634W+fZ8NlClkdLh/mEF5qIk2YjkFJt9FUC6WBqt3TqW
         3TyvN398JZFvmLyLOBa/Ta5ZCxySLwIEvRlrtfChGAR2XLvhFrbaFlDRhGWPn8/HzUJO
         wHTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=WpTh8QKhUxxPdPN/Gx5GKqn0haBZl44EwfvGc3miU+0=;
        b=W0vuUjLf3Hh4u8eU5tuavyem7TymEmGARpqSQfjgW4Uf/f2VFQkaHjuMDAsc07cP0i
         XwmJKBEv+M3h5deOCFXNyerSZ8fpTPpTy6i9jPJE3R5vyLIJWJ1rLGzpFOaO2UUu5F5s
         3MY/gWmpUdn914oUUqCkTXScLMfdhzbUS929Q+idpXqw/xUBUn3wKK7uOyhSe5XudPuQ
         C42sDJEmXpxgOVOvY35WbOOSWmunsz6DtYA3Os920oKTvUf0VYEbpsykOWjiyri5TjBc
         5fVI03rmjA2gFwn/Gqs80Yd0l9ni60uh+9zvoTcU6N6hVBGDb2dfHsd1JJw9KE0xuoa9
         pq8w==
X-Gm-Message-State: ACgBeo19HUzroHYVMaiHXtqBb9Dys8J4sWvMilOrgH5nb/C+92ksAkOT
	XA36FK6bnkLlIX2T6c/4qjk=
X-Google-Smtp-Source: AA6agR6LlBErY2HnuIk0TnMikyvkCGXk4PC6Atz3ZCZmjh83sxj3zMcbwImFUEH4D/RZu4ASnNf+1w==
X-Received: by 2002:a17:90b:3912:b0:1fe:34a0:e74c with SMTP id ob18-20020a17090b391200b001fe34a0e74cmr2824065pjb.233.1661964509940;
        Wed, 31 Aug 2022 09:48:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:418a:b0:52d:2986:99f4 with SMTP id
 ca10-20020a056a00418a00b0052d298699f4ls7200428pfb.8.-pod-prod-gmail; Wed, 31
 Aug 2022 09:48:29 -0700 (PDT)
X-Received: by 2002:a05:6a00:1515:b0:536:c6ea:115f with SMTP id q21-20020a056a00151500b00536c6ea115fmr26835593pfu.37.1661964509220;
        Wed, 31 Aug 2022 09:48:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661964509; cv=none;
        d=google.com; s=arc-20160816;
        b=MNmNqUPZrwipPHlH01N1MHtJtJJVB9eGYaggK9lOqMvw5a9gA+qJ4tWDl2zcoy5bAz
         zPADpUoiGaMoJFrj1xafUU2He9PNAK2mkK20dMMnzpe+PZ3VG0jRaMdJuujQoChm81No
         EWYxY1hUq/NtTeJRr/9ODyQ8mKQMQspJwZfHAWGXk1nkhfCLMvC2PfkX4KhcYJxO+tEh
         dSQ8+R3GOdoybKkQQD2/VIb6ZanfNii5cXp3yzpMtL3NRBqE/vNhSHNes3CR+yCKsV/d
         SdkF9H/U8C997CTKZC0lHUY1wenhcl5/4d/uMBmarby31QHA33N47iDcFqBMjqvZzQ06
         F01A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6n1zc63jDuzyjKJX97Ppd3P3cpaKkA3xHe9Swtr7rxY=;
        b=O5rd6rivUXOUOT7Fe+SIEjoYxL4ezTmkFFOvebPyqeGISQtHazaM5bbqoG0X/H7NRm
         K4Zu8lFZSm4CUFbegEXzrcnPWp0XeQJt0VYqCJaBhSZ10Zymv1bat3yXx4vlWbZ6Pvp6
         63aeh+enOTgjxK2bNEyIcgJ4ZygxjdW7o9xjoWhufCOs668q+lOSLwUSFdze7fuvLQD3
         +l9icRaT7t77waXLZnIJEq4gQSCNP+fb8bDYv+RXz7+oEPUgxVofW/nefoFlc0xIqGbe
         7LPCEHXBtRnk1LjOqoKTheMovjPzpLyYEPMnC8A6bjRh8wy9tZWVwICuWBi/zUOgzYl+
         D2jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=VIdq+REr;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id d14-20020a17090ad3ce00b001fb2bb70d4dsi174959pjw.3.2022.08.31.09.48.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Aug 2022 09:48:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 130so5000283ybw.8
        for <kasan-dev@googlegroups.com>; Wed, 31 Aug 2022 09:48:29 -0700 (PDT)
X-Received: by 2002:a05:6902:1366:b0:691:4335:455b with SMTP id
 bt6-20020a056902136600b006914335455bmr15675462ybb.282.1661964508623; Wed, 31
 Aug 2022 09:48:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com> <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan> <20220831101948.f3etturccmp5ovkl@suse.de>
 <Yw88RFuBgc7yFYxA@dhcp22.suse.cz> <CAJuCfpGZ==v0HGWBzZzHTgbo4B_ZBe6V6U4T_788LVWj8HhCRQ@mail.gmail.com>
In-Reply-To: <CAJuCfpGZ==v0HGWBzZzHTgbo4B_ZBe6V6U4T_788LVWj8HhCRQ@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Aug 2022 09:48:17 -0700
Message-ID: <CAJuCfpEuLjd+FJ7MQQ+y=ghVnYQP-WDcXxLCcy07JQ0VFweLEg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=VIdq+REr;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as
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

On Wed, Aug 31, 2022 at 8:28 AM Suren Baghdasaryan <surenb@google.com> wrote:
>
> On Wed, Aug 31, 2022 at 3:47 AM Michal Hocko <mhocko@suse.com> wrote:
> >
> > On Wed 31-08-22 11:19:48, Mel Gorman wrote:
> > > On Wed, Aug 31, 2022 at 04:42:30AM -0400, Kent Overstreet wrote:
> > > > On Wed, Aug 31, 2022 at 09:38:27AM +0200, Peter Zijlstra wrote:
> > > > > On Tue, Aug 30, 2022 at 02:48:49PM -0700, Suren Baghdasaryan wrote:
> > > > > > ===========================
> > > > > > Code tagging framework
> > > > > > ===========================
> > > > > > Code tag is a structure identifying a specific location in the source code
> > > > > > which is generated at compile time and can be embedded in an application-
> > > > > > specific structure. Several applications of code tagging are included in
> > > > > > this RFC, such as memory allocation tracking, dynamic fault injection,
> > > > > > latency tracking and improved error code reporting.
> > > > > > Basically, it takes the old trick of "define a special elf section for
> > > > > > objects of a given type so that we can iterate over them at runtime" and
> > > > > > creates a proper library for it.
> > > > >
> > > > > I might be super dense this morning, but what!? I've skimmed through the
> > > > > set and I don't think I get it.
> > > > >
> > > > > What does this provide that ftrace/kprobes don't already allow?
> > > >
> > > > You're kidding, right?
> > >
> > > It's a valid question. From the description, it main addition that would
> > > be hard to do with ftrace or probes is catching where an error code is
> > > returned. A secondary addition would be catching all historical state and
> > > not just state since the tracing started.
> > >
> > > It's also unclear *who* would enable this. It looks like it would mostly
> > > have value during the development stage of an embedded platform to track
> > > kernel memory usage on a per-application basis in an environment where it
> > > may be difficult to setup tracing and tracking. Would it ever be enabled
> > > in production? Would a distribution ever enable this? If it's enabled, any
> > > overhead cannot be disabled/enabled at run or boot time so anyone enabling
> > > this would carry the cost without never necessarily consuming the data.
>
> Thank you for the question.
> For memory tracking my intent is to have a mechanism that can be enabled in
> the field testing (pre-production testing on a large population of
> internal users).
> The issue that we are often facing is when some memory leaks are happening
> in the field but very hard to reproduce locally. We get a bugreport
> from the user
> which indicates it but often has not enough information to track it. Note that
> quite often these leaks/issues happen in the drivers, so even simply finding out
> where they came from is a big help.
> The way I envision this mechanism to be used is to enable the basic memory
> tracking in the field tests and have a user space process collecting
> the allocation
> statistics periodically (say once an hour). Once it detects some counter growing
> infinitely or atypically (the definition of this is left to the user
> space) it can enable
> context capturing only for that specific location, still keeping the
> overhead to the
> minimum but getting more information about potential issues. Collected stats and
> contexts are then attached to the bugreport and we get more visibility
> into the issue
> when we receive it.
> The goal is to provide a mechanism with low enough overhead that it
> can be enabled
> all the time during these field tests without affecting the device's
> performance profiles.
> Tracing is very cheap when it's disabled but having it enabled all the
> time would
> introduce higher overhead than the counter manipulations.
> My apologies, I should have clarified all this in this cover letter
> from the beginning.
>
> As for other applications, maybe I'm not such an advanced user of
> tracing but I think only
> the latency tracking application might be done with tracing, assuming
> we have all the
> right tracepoints but I don't see how we would use tracing for fault
> injections and
> descriptive error codes. Again, I might be mistaken.

Sorry about the formatting of my reply. Forgot to reconfigure the editor on
the new machine.

>
> Thanks,
> Suren.
>
> > >
> > > It might be an ease-of-use thing. Gathering the information from traces
> > > is tricky and would need combining multiple different elements and that
> > > is development effort but not impossible.
> > >
> > > Whatever asking for an explanation as to why equivalent functionality
> > > cannot not be created from ftrace/kprobe/eBPF/whatever is reasonable.
> >
> > Fully agreed and this is especially true for a change this size
> > 77 files changed, 3406 insertions(+), 703 deletions(-)
> >
> > --
> > Michal Hocko
> > SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJuCfpEuLjd%2BFJ7MQQ%2By%3DghVnYQP-WDcXxLCcy07JQ0VFweLEg%40mail.gmail.com.
