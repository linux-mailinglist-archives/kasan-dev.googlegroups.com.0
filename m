Return-Path: <kasan-dev+bncBAABBBF5YOMAMGQE3LFIQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id BDBC05A9D20
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 18:32:04 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id v1-20020a056402348100b00448acc79177sf6980038edc.23
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 09:32:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662049924; cv=pass;
        d=google.com; s=arc-20160816;
        b=A0vVkE9lgbEPlSD7iRgzDX532BdQ4XGX54oL2y5XRHGBDLQ90H5WNo4gOiPsSu8OeC
         xK0/BG14q3knEz4S0lo6EMjUtFxJCAQLlxpnR0+2YhnbwgV3aYXyTR4CkWFDx2XzwY5q
         AAlUYtK7/lNsIOdo8b1l5MytDfaJrT+bexa5ZGBI/rpVX74e+bVQJjAMtsqGL2Vc5hCq
         1AATBWS5h24ZzRQhXFWaPgShC0YgciWzt+GSyZQfvx8yhssfwhwY6Ee1FZwGFlV6fcPi
         hmMIQfDqPvHJ0uWMmFpm0XZILVx/e3MN3Ii19RvA7ZX1Qv7Fng1K56e5kH+abSXVB4CB
         t0yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ThaqCYgb9seP5RbDlOdIKiNtPYVtxL07NP439tM2j0M=;
        b=mH4VkLE4tNhgMoFsON6WcBENWes4HGhjKLiiDPIe1x5vgFdoG6u7LQmAlwUehxIi68
         oiRDUB0oLmhl3t83SDFF3n4WRl7XPNYq/Owq42SPzXNrPp5xvuoWTfFEtq/qT1kz15b/
         F2I8X8CIRWgYAxWyVoLcO1T44sS/oJ3F32LULg7PaXptsz6aLWa9Wf1GpGx8VdTg7k9h
         7F955L4s6Y2mAx/bmwwGTv9SdcaZ27lJJ3ApylXqLltA2+gpW7TQUcI5vKhIQvXaXFQD
         blbgalPdS4CV2WkOROPR/SmN52i9jekenL1o+rAPmUEsv8Q4Xg95lC6xT9RK5BSNwwwZ
         VJIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b+mGQz7e;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=ThaqCYgb9seP5RbDlOdIKiNtPYVtxL07NP439tM2j0M=;
        b=mz4/z6QaUqNwbyi8jSJfXJN2s6rVK8By6YpiAmCcMp3pw8uisM42IYtf0QBj1uvGGF
         IF7/zBH9Jb5s5+oOSgQ6UdHvS+PkvdBRbhurwjMsIG1nPFZLWQXgZyRIxGGeU69Q7NA7
         jdW1C00mVThvxcdTVfko63tblX0B2Bz4mKR7bAheOUf3cNB/CTtxkwAXbV30LmN6F4EH
         Bp5xxNpDcABCtdPEjiHLy447QBhv+CpfC7aSxCsZyAa20RmStiIgD1ORI1E46lY44BvE
         MU05rHArefMjxKgDorb4wdiQFQaJtCHckAHKTlxL4rbtVoAEUD3yfJgrM+3oAP8x3HeM
         +zMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=ThaqCYgb9seP5RbDlOdIKiNtPYVtxL07NP439tM2j0M=;
        b=7EbDjtj42Fsrm56Eew+80vCp9XP/xRyY+arWcQnwoK/w0llHSRW3PWO5lY+yvNw/v7
         E4ZC79uLqMpKP71/lSO2QOlN/KBoz4CO8G7z25lb3symgYUPrQqYmgwMt3H8CnJuqei8
         lV3E/iaw1n4K5oeKyhs2juERNMnhsgkXdMyWYXY1UE+eccNDTeiyhGzbcJi1TPtWJfea
         JZC3zhxzJVgdaX0w+IkiUt3vCAWJLexdfufiRBgX1QHriIMp3JYqz5KDeo3G0shG+/X6
         aPFcFqDnxK9es1tJ1e6btKuJMuEXY7TncLXh1v88Y429oRzK64B8gu1hfy1TdteAyWv7
         MNaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2vUygQxe+qAXiY00QeewVwgoup8dWE8Viy11HsRfCENVWJbonH
	Dnu+gOLD5c+0NEcI0NUzc04=
X-Google-Smtp-Source: AA6agR5AHdtShfbxN2R8fdqG+lJAXh7nMi/qCVbxhCogc5d6wjJuVWIIIKFX6hduh0VJaZcwTIRJ+g==
X-Received: by 2002:a17:906:959:b0:741:6f76:546f with SMTP id j25-20020a170906095900b007416f76546fmr16045679ejd.32.1662049924274;
        Thu, 01 Sep 2022 09:32:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:880f:b0:73d:afe3:ffd9 with SMTP id
 zh15-20020a170906880f00b0073dafe3ffd9ls1608845ejb.10.-pod-prod-gmail; Thu, 01
 Sep 2022 09:32:03 -0700 (PDT)
X-Received: by 2002:a17:907:1ca6:b0:741:9b0b:1988 with SMTP id nb38-20020a1709071ca600b007419b0b1988mr13412229ejc.195.1662049923473;
        Thu, 01 Sep 2022 09:32:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662049923; cv=none;
        d=google.com; s=arc-20160816;
        b=G3VcUvDYZkbbuJAKMhfxWDS/nwFAI+9U8O6VfrZhwiCGMdClwWnU6G0DAAKu2vLkJN
         vxfrKBhw4yU9y6hQWliGZGhlxs5ztagypqdwjDuhIzK0sNwZ9rxoBPDiAq87knKpKzMn
         NApF/uXPfknYvrIfwzi4XweDJJgYpzCCa2ivh7dYuOiYeiKsUBzocBE3dFIWf5xiTck7
         sK4F8/0mD2UvrULVfVfuOE04H3zCHt9sMVE3uIvRDYRo3RidiErj1jLrGCxtdAibpdUR
         UnAv694MyGGvQXjqFesZyv47mESBrjB/OA454zxwxu+ekI4zbtTKcXKhnXFP2Z/WKPiT
         kDzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=lF0nzK0I3dkKY+VmvooE06KpjT5GF7za7apoY2ziCzA=;
        b=ErsvBiGRGYrZ+2MuWOAhkS+LDi+D6kP2umLfi0F/BXSKdPwAhVzvTodciLuFZBwz6D
         D+/ggfc5BjPNO87TW+qdCS/eVeJ6Y7GESel0RMcIFnX0Tc430Bv3iqL+cOijBtnzb14Z
         GNrZErO2K4sf1tzQXa3JbyXhOoy4xp3wt53bU40wHoZegFdYIz1rv2+TKpVjwRkG/ura
         k3OIz/mRyeGNkgJnZVLRo8vTWwNTDF5t7ACw0a384iM/O17ITkICZK1cRjcCAiqdFLUY
         waAsFN+3iNfEPSr7u02EZ6DSBVopmcFrkREvJw5D9KEQCVoTUn6XwM4bbRGCV9tPMdvz
         e1wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=b+mGQz7e;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id g13-20020aa7c84d000000b0044609bb9ed0si134481edt.1.2022.09.01.09.32.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 09:32:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
Date: Thu, 1 Sep 2022 12:31:55 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Mel Gorman <mgorman@suse.de>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, changbin.du@intel.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-mm@kvack.org, iommu@lists.linux.dev,
	kasan-dev@googlegroups.com, io-uring@vger.kernel.org,
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org,
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <20220901163155.sz4dqtubicdvzmsw@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <20220831155941.q5umplytbx6offku@moria.home.lan>
 <20220901110501.o5rq5yzltomirxiw@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901110501.o5rq5yzltomirxiw@suse.de>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=b+mGQz7e;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Sep 01, 2022 at 12:05:01PM +0100, Mel Gorman wrote:
> As pointed out elsewhere, attaching to the tracepoint and recording relevant
> state is an option other than trying to parse a raw ftrace feed. For memory
> leaks, there are already tracepoints for page allocation and free that could
> be used to track allocations that are not freed at a given point in time.

Page allocation tracepoints are not sufficient for what we're trying to do here,
and a substantial amount of effort in this patchset has gone into just getting
the hooking locations right - our memory allocation interfaces are not trivial.

That's something people should keep in mind when commenting on the size of this
patchset, since that's effort that would have to be spent for /any/ complete
solution, be in tracepoint based or no.

Additionally, we need to be able to write assertions that verify that our hook
locations are correct, that allocations or frees aren't getting double counted
or missed - highly necessary given the maze of nested memory allocation
interfaces we have (i.e. slab.h), and it's something a tracepoint based
implementation would have to account for - otherwise, a tool isn't very useful
if you can't trust the numbers it's giving you.

And then you have to correlate the allocate and free events, so that you know
which allocate callsite to decrement the amount freed from.

How would you plan on doing that with tracepoints?

> There is also the kernel memory leak detector although I never had reason
> to use it (https://www.kernel.org/doc/html/v6.0-rc3/dev-tools/kmemleak.html)
> and it sounds like it would be expensive.

Kmemleak is indeed expensive, and in the past I've had issues with it not
catching everything (I've noticed the kmemleak annotations growing, so maybe
this is less of an issue than it was).

And this is a more complete solution (though not something that could strictly
replace kmemleak): strict memory leaks aren't the only issue, it's also drivers
unexpectedly consuming more memory than expected.

I'll bet you a beer that when people have had this awhile, we're going to have a
bunch of bugs discovered and fixed along the lines of "oh hey, this driver
wasn't supposed to be using this 1 MB of memory, I never noticed that before".

> > > It's also unclear *who* would enable this. It looks like it would mostly
> > > have value during the development stage of an embedded platform to track
> > > kernel memory usage on a per-application basis in an environment where it
> > > may be difficult to setup tracing and tracking. Would it ever be enabled
> > > in production? Would a distribution ever enable this? If it's enabled, any
> > > overhead cannot be disabled/enabled at run or boot time so anyone enabling
> > > this would carry the cost without never necessarily consuming the data.
> > 
> > The whole point of this is to be cheap enough to enable in production -
> > especially the latency tracing infrastructure. There's a lot of value to
> > always-on system visibility infrastructure, so that when a live machine starts
> > to do something wonky the data is already there.
> > 
> 
> Sure, there is value but nothing stops the tracepoints being attached as
> a boot-time service where interested. For latencies, there is already
> bpf examples for tracing individual function latency over time e.g.
> https://github.com/iovisor/bcc/blob/master/tools/funclatency.py although
> I haven't used it recently.

So this is cool, I'll check it out today.

Tracing of /function/ latency is definitely something you'd want tracing/kprobes
for - that's way more practical than any code tagging-based approach. And if the
output is reliable and useful I could definitely see myself using this, thank
you.

But for data collection where it makes sense to annotate in the source code
where the data collection points are, I see the code-tagging based approach as
simpler - it cuts out a whole bunch of indirection. The diffstat on the code
tagging time stats patch is

 8 files changed, 233 insertions(+), 6 deletions(-)

And that includes hooking wait.h - this is really simple, easy stuff.

The memory allocation tracking patches are more complicated because we've got a
ton of memory allocation interfaces and we're aiming for strict correctness
there - because that tool needs strict correctness in order to be useful.

> Live parsing of ftrace is possible, albeit expensive.
> https://github.com/gormanm/mmtests/blob/master/monitors/watch-highorder.pl
> tracks counts of high-order allocations and dumps a report on interrupt as
> an example of live parsing ftrace and only recording interesting state. It's
> not tracking state you are interested in but it demonstrates it is possible
> to rely on ftrace alone and monitor from userspace. It's bit-rotted but
> can be fixed with

Yeah, if this is as far as people have gotten with ftrace on memory allocations
than I don't think tracing is credible here, sorry.

> The ease of use is a criticism as there is effort required to develop
> the state tracking of in-kernel event be it from live parsing ftrace,
> attaching to tracepoints with systemtap/bpf/whatever and the like. The
> main disadvantage with an in-kernel implementation is three-fold. First,
> it doesn't work with older kernels without backports. Second, if something
> slightly different it needed then it's a kernel rebuild.  Third, if the
> option is not enabled in the deployed kernel config then you are relying
> on the end user being willing to deploy a custom kernel.  The initial
> investment in doing memory leak tracking or latency tracking by attaching
> to tracepoints is significant but it works with older kernels up to a point
> and is less sensitive to the kernel config options selected as features
> like ftrace are often selected.

The next version of this patch set is going to use the alternatives mechanism to
add a boot parameter.

I'm not interested in backporting to older kernels - eesh. People on old
enterprise kernels don't always get all the new shiny things :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901163155.sz4dqtubicdvzmsw%40moria.home.lan.
