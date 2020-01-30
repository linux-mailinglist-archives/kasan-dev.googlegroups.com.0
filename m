Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ5ZZPYQKGQE6W4UXPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6A7914DC1E
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 14:39:52 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id c130sf3335314ywb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 05:39:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580391591; cv=pass;
        d=google.com; s=arc-20160816;
        b=YphqqTUTXcVFLQb9SctW+iID8mDUOBA3VTRFrmdMeNXjAcNRUpCMBS6qW7nGoqKnB7
         gey2bAvLABXQ+E+3wk8LFxlUlqNPLuwgCLXx8qH+zk4Z8zeexODKzIHXP9LkBiQY9QSf
         0jclaPVayO+bMEEQJwhN2vEjlP8D8fWAHzt94QJnLz3/ccCdqh6LaZiFV7SaI2ctx06q
         v6VjGCfwyycvlH6hcXWvRdZxVeRjiJHs7ZUlZ1N4DhHveyMDmq3cl/kw0w2CkKvVk9P/
         9zIbFoC7baLxUDoEmugplgnNwqjxytlwrz+UXNBOArwlyh1B7edrO7lBGL5w8vSjhBMP
         GH1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4pfsUrB8bVIlGEzPDnoc0dppxPFBEQlvD2tshm/QPqc=;
        b=JmjB6rTgVl1rJK+Yit7lAnr/Tu0MZe3uzPVSdY0GpB9EhBzrvv3zN7lZFFyBPaHKMF
         CyS8J+/RJk40nj1oHKPelB87FOEPjJZnjrPAVzUZmvVBnB+9ks1UeSyHL5HgTyYtgbmN
         01FdA+P6hgU7R/1Cuc/4EF7hEFEiBptbRPHy1rRLWZitmYBlHdPp31GRtGs59UdI1YP/
         fYiIYgHNr39DbAtxQCgyfvH6oek7F1cYROwJG5mXBvoDEmKj64IiZGioIIHFTLY8BhWP
         BxejcVO2lgXkSG6w/eS9lKf/xyqvFcrlypVkJxkfLKuZ8OK08wQd6CztG+GJosJZN6cw
         44GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fpmvpHVJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pfsUrB8bVIlGEzPDnoc0dppxPFBEQlvD2tshm/QPqc=;
        b=H5YSKMDjzRRHbQzlQsaRQpQG33Y18dtmXbjalG6TTQBrccGiOFrcE54Qmv8/3SrqlU
         RkzqJ/FelGD5IAeCXZ92ylDUoXnwnUJSqxCwIt1mcKsk/4kB31D9BeGD7Jm/wYPdw+w8
         nFdbxt1F3hEeIHcDxnpoTIhVRaK6uKTK91GiXPzl8fozXUwrnIg2CHv+EIgYkWg4w3kl
         VAJqufZMmRg2zW3indXir+N2ymPSdbQixsZH/PYnDCoEBBV+pe22YrK5MHt4DeYqtzph
         bxg85gwMnl+Gn5Brm3idbKxtnIkVfBZqw86jzwPDL9NCcdYiKt/jZ8hoO+BxzTWYiOs6
         0qZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4pfsUrB8bVIlGEzPDnoc0dppxPFBEQlvD2tshm/QPqc=;
        b=jkxsO6oUBwXkSdRLLxBwPYKtvMh+mrrvo5x1SwOukX0+8VvIz3opba/bYGVAS6nTHD
         137D+pZwg/zzIXq+2sOm9f12uEW1DmaY5a+vJZMYr3z0WzygBVOUAhrz/m/8Qh7H75jK
         pinWvwqm8l8kdtikKVuzvyKZvMNEDQnxflV3REd956vgeIqCN69MXrz/cheMdE7hNZvM
         FpdbER6oDqtyv6bpuC7XmjaPNXdUV3DZp5iyXBcgrjSNw0zOkS4L+JThruIh/1PtZKdN
         1wN6ZBWTZf2bNB76qegTlsrxdw2Vdrf6nBmDw6gNvAH7b5EfgJKPgFVe1+MgXHvYfoJ7
         sW7A==
X-Gm-Message-State: APjAAAUKOeOtua86nA5CzOXzg6+WRRjLSuo14e2tBg79dProHtmfFU5c
	wb9J8mKZBoLjk6chd4JLS48=
X-Google-Smtp-Source: APXvYqzy+7nVHrrH7vT3mbwtWc31hEES2focqynoNLTnxpTCh+NqkEXW7E8V9Mf+TUyM+HCttNSxUA==
X-Received: by 2002:a25:8012:: with SMTP id m18mr4098351ybk.440.1580391591674;
        Thu, 30 Jan 2020 05:39:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2385:: with SMTP id j127ls669680ybj.7.gmail; Thu, 30 Jan
 2020 05:39:51 -0800 (PST)
X-Received: by 2002:a5b:c46:: with SMTP id d6mr4149905ybr.372.1580391591284;
        Thu, 30 Jan 2020 05:39:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580391591; cv=none;
        d=google.com; s=arc-20160816;
        b=ZmznMqyenv+k20h8985LGc5ZzxrST/poAJSDul2k/7qidvRhv41hWt26UvNWJT9dz2
         G76oGPdlCdPRPti2oTpeDq1GEeOXM667Q3hVUircfjfUnalPM8fZvOh76Qi7RujRsZ1D
         ZY9VhjX9cZqMmkWHiHHDJTgutQ0xeLVQeFotxhZXIoQBBVTB5DC6Tts9K0dHzjqAoIMN
         4Wtu9wHeqhkvS06js/uYlma5Ygux+NxrUOd3ySbysuotNf4VHfXZAbpBfpTEQTXxezmj
         v4DYc4jLNSvBrT4a+3wRVpzLXY5BVchLqFBd7/IIlQ0C6/cDdgm22gUYfL4G/Z8kMk4H
         PVDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P4H48YtpiLm+taBVkGC08gZKk3HEB7Nrcktl9EzCxbo=;
        b=em7jIyQK4D/409k/pA7J6Medn3JVYKsw2q90REZDLsxm59Aw9RqYrezabYogJfrt2M
         OiFT6O3SEAiV64PRRln4BihhbK60URoRg5bvYyTe7HaJx65wNLNAK9EWR9wpOU6P3JwO
         UeEs989eH8VyOWgmwe0Ss3z5R8lF25cQ9MP8fZxLYKekA3D42T4LvTP9XhDVaBUZWZ25
         FED+6vnrRxyZyE9066EGy8nxKEHg/tATxLFgsTWyJcXkdymHxB3pLnGyPleobc2gslq8
         8TR+Owiu2344MLS9tx1De2IgZtAtLhtQvqEJyMTxwyn2F26t3tvKydyaNdVQBcT2icCe
         MPyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fpmvpHVJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id g196si374903ybf.5.2020.01.30.05.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jan 2020 05:39:51 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id a15so3158424otf.1
        for <kasan-dev@googlegroups.com>; Thu, 30 Jan 2020 05:39:51 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr3755637otq.17.1580391590549;
 Thu, 30 Jan 2020 05:39:50 -0800 (PST)
MIME-Version: 1.0
References: <20200122165938.GA16974@willie-the-truck> <A5114711-B8DE-48DA-AFD0-62128AC08270@lca.pw>
 <20200122223851.GA45602@google.com> <A90E2B85-77CB-4743-AEC3-90D7836C4D47@lca.pw>
 <20200123093905.GU14914@hirez.programming.kicks-ass.net> <E722E6E0-26CB-440F-98D7-D182B57D1F43@lca.pw>
 <CANpmjNNo6yW-y-Af7JgvWi3t==+=02hE4-pFU4OiH8yvbT3Byg@mail.gmail.com>
 <20200128165655.GM14914@hirez.programming.kicks-ass.net> <20200129002253.GT2935@paulmck-ThinkPad-P72>
 <CANpmjNN8J1oWtLPHTgCwbbtTuU_Js-8HD=cozW5cYkm8h-GTBg@mail.gmail.com> <20200129184024.GT14879@hirez.programming.kicks-ass.net>
In-Reply-To: <20200129184024.GT14879@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 30 Jan 2020 14:39:38 +0100
Message-ID: <CANpmjNNZQsatHexXHm4dXvA0na6r9xMgVD5R+-8d7VXEBRi32w@mail.gmail.com>
Subject: Re: [PATCH] locking/osq_lock: fix a data race in osq_wait_next
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Qian Cai <cai@lca.pw>, Will Deacon <will@kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fpmvpHVJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::343 as
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

On Wed, 29 Jan 2020 at 19:40, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jan 29, 2020 at 04:29:43PM +0100, Marco Elver wrote:
>
> > On Tue, 28 Jan 2020 at 17:52, Peter Zijlstra <peterz@infradead.org> wrote:
> > > I'm claiming that in the first case, the only thing that's ever done
> > > with a racy load is comparing against 0, there is no possible bad
> > > outcome ever. While obviously if you let the load escape, or do anything
> > > other than compare against 0, there is.
> >
> > It might sound like a simple rule, but implementing this is anything
> > but simple: This would require changing the compiler,
>
> Right.
>
> > which we said we'd like to avoid as it introduces new problems.
>
> Ah, I missed that brief.
>
> > This particular rule relies on semantic analysis that is beyond what
> > the TSAN instrumentation currently supports. Right now we support GCC
> > and Clang; changing the compiler probably means we'd end up with only
> > one (probably Clang), and many more years before the change has
> > propagated to the majority of used compiler versions. It'd be good if
> > we can do this purely as a change in the kernel's codebase.
>
> *sigh*, I didn't know there was such a resistance to change the tooling.
> That seems very unfortunate :-/

Unfortunately. Just wanted to highlight what to expect if we go down
that path. We can put it on a nice-to-have list, but don't expect or
rely on it to happen soon, given the implications above.

> > Keeping the bigger picture in mind, how frequent is this case, and
> > what are we really trying to accomplish?
>
> It's trying to avoid the RmW pulling the line in exclusive/modified
> state in a loop. The basic C-CAS pattern if you will.
>
> > Is it only to avoid a READ_ONCE? Why is the READ_ONCE bad here? If
> > there is a racing access, why not be explicit about it?
>
> It's probably not terrible to put a READ_ONCE() there; we just need to
> make sure the compiler doesn't do something stupid (it is known to do
> stupid when 'volatile' is present).

Maybe we need to optimize READ_ONCE().

'if (data_race(..))' would also work here and has no cost.

> But the fact remains that it is entirely superfluous, there is no
> possible way the compiler can wreck this.

Agree. Still thinking if there is a way to do it without changing the
compiler, but I can't see it right now. :/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZQsatHexXHm4dXvA0na6r9xMgVD5R%2B-8d7VXEBRi32w%40mail.gmail.com.
