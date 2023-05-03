Return-Path: <kasan-dev+bncBDV6LP4FXIHRBYOFZKRAMGQEODF35KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A5F36F5D84
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:07:30 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-546daa02d08sf5070903eaf.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:07:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137249; cv=pass;
        d=google.com; s=arc-20160816;
        b=ksSalW0WGreR3VevHWfBewBOzZ29RQq3y/BDgnV/ViYbdXXWiKtwYfkLSvYpC3I1tH
         GEbH8nfCZ/yNqaTmO63024zNRdxghm5wyM7USbRr0C3pjsryq4fwqC99UCb18xfm9bA5
         +emSPB55oKCLrtzjRqOcl+K9Z/5ovHIFw3erR8HBCbbQKGCCnZZOqlKdbbCFPVrDS3j7
         Fz77Y0UdnKoVlO4l3hLyLDYH6Igb5+BYlF1OR0JDwu0rf3/CE1hoprFc+2VGhzzNiK4b
         vMD1IpDPIdP2jc1FSEHd41whB0PTVC+2f4PUz41M59UacPm/GbxN1+1IpeGdnhsJrSJ2
         mk2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lEYu8kWJHBiD32Gvw4j2rFWEvMWjmdtGMsdQS77iLAo=;
        b=u2wWO750j5N1L62xA3wFomPAjYBQgmW3QzZFra2JiCE+JFgUcY41ZMIUUzc/T1hal8
         a3zw/S1Lxp/6zpHmCRg90/lmi1I8+UOlnUEK/1kDRdD8h9FsM1tiOOhbyBTiHwiZyBqQ
         /sx+IzrMlDjKIZphVR4h8h3qMtJTXVR04Raz+0GimAWTvk2iovnOV2rICklCWc8cwzrG
         i0DjnFSJs6JL5/q4UmVfkkyRzJCWd399wx0bMmn0AQE4xB0FhQQIah6siEnpZCXkDFBG
         xxgwknKznsn4sKn8nuGwY1yGtAPzBZxXGhPkyGcQnHwDDY/e60q2pSAb6KcT6JXm7ZQk
         C8uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208 header.b=PO1zbleT;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683137249; x=1685729249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lEYu8kWJHBiD32Gvw4j2rFWEvMWjmdtGMsdQS77iLAo=;
        b=dwZewWGfDSYNM8QA4omRIoNq6L3Syi/nJKSxh+/ghBSpHOHFYN1kn4AIOaSpm4bmKk
         Emsh+dyM0d/OztS3a7Th53nQ81rEBZW3Pd051SDkTAnwqZ5By1mlL2VkJlQvR7slBeud
         a9T+pHDLFbGDtyT5eDUqAR7+JgSuyp4QsXYBZUuSxLHfdgeb5uhRrwz/PpOWPME8Uhku
         rbzj/IM/jadWdbQccMrTwt07SMkIdb2z4Jnsu6naQXiNMP/5cLlK4sJsWV0h89CjLz15
         J1JaOgOEBnkYXkPUtePwtxrKe1m3a/UEz3wO9jYg0fiKXdYKMQt6RnutOhJht0HWH+Ui
         7sbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137249; x=1685729249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lEYu8kWJHBiD32Gvw4j2rFWEvMWjmdtGMsdQS77iLAo=;
        b=FAq0brQBx8Af4PnLGKP3M7Y6+e/lkBVrbdsj6AQcnNURz3qUyDqsFiptBgOHY0Aj16
         LORhy/12Nog/hOHO2ZpapMOxo2v+hxisXrzTIaz38t8etQEuoT5TPgaS7r62n+eBm9tE
         o84nabHFglEHDhOdeaM1jo9rfUw+k5ZeSO96VCGPZYoP4w6BUIMHzczDJ3z/D/o022lY
         ce0EWVghvuJ4BBRUD0xSrFS9Zl+nHTLfX2+Ydj0+QWeDRSbUmCCGFb6KwGmMjPBzSWUV
         uCb6kHW93jeulfdcdYwQ66mJxbOwsk5D8GjxEZfkMNuhtr2GAjSnB3Q8jWBdQeH2twZP
         Qsbg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy9QomnAEhC/RwMUmBqRqNefkRlJ9eMZxGTJAPNoEhSKoo0MS8q
	0Ye42hfqT6xo2LdUiMYudMk=
X-Google-Smtp-Source: ACHHUZ7A/5afRE/16nF6NN/56o4lgUenrCMiJpZ0K7RyFjxAebCeJILxwkO5AH+r8WqGeEYy8paMvw==
X-Received: by 2002:a4a:6c4f:0:b0:546:f7dd:69c7 with SMTP id u15-20020a4a6c4f000000b00546f7dd69c7mr6336133oof.0.1683137249130;
        Wed, 03 May 2023 11:07:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:ece:b0:38e:dc69:4942 with SMTP id
 q14-20020a0568080ece00b0038edc694942ls4183457oiv.3.-pod-prod-gmail; Wed, 03
 May 2023 11:07:28 -0700 (PDT)
X-Received: by 2002:a05:6808:238b:b0:386:ca25:9cd with SMTP id bp11-20020a056808238b00b00386ca2509cdmr484290oib.30.1683137248581;
        Wed, 03 May 2023 11:07:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137248; cv=none;
        d=google.com; s=arc-20160816;
        b=dr2ziwGYcD7tS5vqrMqmRTUDyFLIYvM/0dD9mfCazwoV4OZyfFSQfysWvNjTVhbs70
         5ot6gsvOtjsGtVKJnDhRIhgJ+DRUZ9IW4PW2FLE2GMYHGxdKZYLGhCOrxHU0FT+uUveM
         vgM5LdJiC0oIZdNk/wycJ3st7bbRCTB3vp49KNzr+ge0RTfMVs5AGC9mq1PproQuh22Q
         O3YXKiK03XVwTIJI9rN4KXA9Sur4KkQrwpfmcksJU5UZjYFwwMMN/6bNezJWw4adp52b
         9Y5sacT8Fc6g+haHuKqEmh/XD/GFVjJ3peoZsCaBIhHnyCv8fKSsBI/TC3Zq0FR4Rq+b
         Qn/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=M2w9A9pnL0O0lFcU+PAMU7GlOP92xLISlqVzvjl6lgs=;
        b=K/gbdPIVTU9+h+a8uVIcyP9Bd6Map3Hz5c3G8bBD+LKcNv8mur9yF9lUxHS+Odyzdf
         9xsgnUFh9IE+oRvAZLZnHDJUzIOYwjdZwcdrJ6mFMh5udClBcdxzBGDKQdS4FwTF/wCd
         LKb9KxqFG+kbvZf59YCos+rfOCtN2VUz9w4gI0f0ocP8PY7oSiDhzbq/6BewOiADozcg
         JESbK1wi6szricNb68BlgAslfjphVGauEPLQuwfl86v5Uiw03IQ4bkO/2tMWvEnI6LnY
         fVLK29VWBCVTo/oSlRmY/TxJPvQwd4NQukL7Ay2hRZg9b4f/FEWgF6CmEE+72fgXsk4+
         gDjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208 header.b=PO1zbleT;
       spf=pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id e131-20020acab589000000b0038ee1b9ad6esi134792oif.0.2023.05.03.11.07.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:07:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of hannes@cmpxchg.org designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-61a80fcc4c9so19073756d6.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:07:28 -0700 (PDT)
X-Received: by 2002:a05:6214:20c1:b0:619:4232:aa87 with SMTP id 1-20020a05621420c100b006194232aa87mr11224719qve.24.1683137247516;
        Wed, 03 May 2023 11:07:27 -0700 (PDT)
Received: from localhost (2603-7000-0c01-2716-8f57-5681-ccd3-4a2e.res6.spectrum.com. [2603:7000:c01:2716:8f57:5681:ccd3:4a2e])
        by smtp.gmail.com with ESMTPSA id a9-20020a0cca89000000b0061b59bcc3edsm1473657qvk.44.2023.05.03.11.07.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 11:07:27 -0700 (PDT)
Date: Wed, 3 May 2023 14:07:26 -0400
From: Johannes Weiner <hannes@cmpxchg.org>
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Michal Hocko <mhocko@suse.com>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <20230503180726.GA196054@cmpxchg.org>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
X-Original-Sender: hannes@cmpxchg.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@cmpxchg-org.20221208.gappssmtp.com header.s=20221208
 header.b=PO1zbleT;       spf=pass (google.com: domain of hannes@cmpxchg.org
 designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=hannes@cmpxchg.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=cmpxchg.org
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

On Wed, May 03, 2023 at 06:35:49AM -1000, Tejun Heo wrote:
> Hello, Kent.
> 
> On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> > No, we're still waiting on the tracing people to _demonstrate_, not
> > claim, that this is at all possible in a comparable way with tracing. 
> 
> So, we (meta) happen to do stuff like this all the time in the fleet to hunt
> down tricky persistent problems like memory leaks, ref leaks, what-have-you.
> In recent kernels, with kprobe and BPF, our ability to debug these sorts of
> problems has improved a great deal. Below, I'm attaching a bcc script I used
> to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
> can follow the same pattern.
> 
> There are of course some pros and cons to this approach:
> 
> Pros:
> 
> * The framework doesn't really have any runtime overhead, so we can have it
>   deployed in the entire fleet and debug wherever problem is.
> 
> * It's fully flexible and programmable which enables non-trivial filtering
>   and summarizing to be done inside kernel w/ BPF as necessary, which is
>   pretty handy for tracking high frequency events.
> 
> * BPF is pretty performant. Dedicated built-in kernel code can do better of
>   course but BPF's jit compiled code & its data structures are fast enough.
>   I don't remember any time this was a problem.
> 
> Cons:
> 
> * BPF has some learning curve. Also the fact that what it provides is a wide
>   open field rather than something scoped out for a specific problem can
>   make it seem a bit daunting at the beginning.
> 
> * Because tracking starts when the script starts running, it doesn't know
>   anything which has happened upto that point, so you gotta pay attention to
>   handling e.g. handling frees which don't match allocs. It's kinda annoying
>   but not a huge problem usually. There are ways to build in BPF progs into
>   the kernel and load it early but I haven't experiemnted with it yet
>   personally.

Yeah, early loading is definitely important, especially before module
loading etc.

One common usecase is that we see a machine in the wild with a high
amount of kernel memory disappearing somewhere that isn't voluntarily
reported in vmstat/meminfo. Reproducing it isn't always
practical. Something that records early and always (with acceptable
runtime overhead) would be the holy grail.

Matching allocs to frees is doable using the pfn as the key for pages,
and virtual addresses for slab objects.

The biggest issue I had when I tried with bpf was losing updates to
the map. IIRC there is some trylocking going on to avoid deadlocks
from nested contexts (alloc interrupted, interrupt frees). It doesn't
sound like an unsolvable problem, though.

Another minor thing was the stack trace map exploding on a basically
infinite number of unique interrupt stacks. This could probably also
be solved by extending the trace extraction API to cut the frames off
at the context switch boundary.

Taking a step back though, given the multitude of allocation sites in
the kernel, it's a bit odd that the only accounting we do is the tiny
fraction of voluntary vmstat/meminfo reporting. We try to cover the
biggest consumers with this of course, but it's always going to be
incomplete and is maintenance overhead too. There are on average
several gigabytes in unknown memory (total - known vmstats) on our
machines. It's difficult to detect regressions easily. And it's per
definition the unexpected cornercases that are the trickiest to track
down. So it might be doable with BPF, but it does feel like the kernel
should do a better job of tracking out of the box and without
requiring too much plumbing and somewhat fragile kernel allocation API
tracking and probing from userspace.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230503180726.GA196054%40cmpxchg.org.
