Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2W3335AKGQES5ZRCTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DAEC26144F
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 18:14:36 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id d22sf2562016wmd.6
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 09:14:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599581676; cv=pass;
        d=google.com; s=arc-20160816;
        b=Cktq4fRVXMnTNqNqBBy1fCc8nBAp5iPcvhuIlxDBGNuQNZURo1ySK+XTjz8lYaIXKl
         OGsdEslOVg0l6Qu18hC+wTz2774Kr9iOTT+MVQBNHLyRhs9576y/ks5Lu0VTEBrMClOV
         V+wgMCLplrPdKzYnnyE9nh8m18hNY9mi5GZPLpUe8HF2WNBQHWic6HJ7KeNNu/r1O37G
         cfhEa6E9wt87vH8+EtndgeNYkx+w0viaF0EVroCRy+klcu849cDtor1VG8wgHgPFjlFO
         vAHqBqH+wdhogXPOHdzicv8q59/S5QHoHmKZonIlOgazwGzeM6Y6WCE+E/vx//O3QotR
         2UUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aljyfQim6P705YauUp7Hl+kF8YsG8QRP2SmJGLGt/5M=;
        b=jGXbY8Qjzu+VRtYOyWi0K3TwY48BfoVb/rG05WuoM/LBqheD4czVxq6gG/OMYseTEP
         Vr7tKQOpiKGckB7rHlxaY0LvOU5DcaTvcF+WNuvDcaB4bZUm4KPLiT3kCsoOZvjGcQm5
         gE78xhb8mwKDi7JZ+pjqUEN+3BFRky2H2lwkhGX8O8iC32f/T4iykQ8WcHm4vcJfMaHd
         PK8eaexTpjQI9KGBLfNxhPdn8VPiRv3kr6h9ihsaezoHpK4z27fGxd2vANYYTh4hWgSt
         o6llrDtKjoR4D6UQDGT/NsOYbCQPe7anA9J7F0OD5wnMe1d05lXhOvKrD4sp/1RlN92i
         zAGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QS9QO1x/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aljyfQim6P705YauUp7Hl+kF8YsG8QRP2SmJGLGt/5M=;
        b=CuAiTEgw2HgVEXdeoqHRza+JLx4XzDLeriO/eYYlQwy+A9Dlos8F7iyzUQsgkxv2FP
         Of+qcIB0vl9gk2A+SrvHoyEwFQuTSbPa7mI4D+s2hiMHq+nG3mvkwXzcVgMeAOQVcwE1
         Jr2xExHy/2FCwAyIZ9YpEaKn4frF+iH1CdvzF6rxn0V4WZ1ce6BRqq8cE53Su3XccP4E
         laN3gU2a80lgnzi/febs1/KYmorqcoJ3ria1IbTlF+fjPzPCCfbzK2eko/qcVFXLuV4I
         z1Eq96AweTIojDPANJ/V7wQkLgoNZTHCNvnM1g5CdeYOIxj5AXwWPxYlWUjGWkoj9vRj
         xfJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aljyfQim6P705YauUp7Hl+kF8YsG8QRP2SmJGLGt/5M=;
        b=laj6Q41c8eLb0eOp1I+D4MCRCdiV6YkDaawLbTE3TMZ+a5ELmi8skMnjDi1B7aqJYs
         7hGWyRVnR0gKN5M3akCX2LMoz2aImuiUga1niNuCGu2gzCHTXH0MnT8/cGbn3sWrAnta
         +mMBfeHGk5rC26BhAqPh1Yhnr1jVzoskGXckCNlSY5phFrWH2yQ32pqyGDl4kJhouCjj
         KBjPVURg5Mn15AB12EPCb1GJW01uGxbwHINEUqiFcWpEJ3syD1w4GelEtiGzyzqIKdv/
         5NjiYq+ftfrF0/9OLSy/aG5emzvKHyQrRXaP7vDIWxen0OjTOZtDZzsw5A3xs/BxaOYb
         wgJw==
X-Gm-Message-State: AOAM533EHt9mG11U0DgWmQllRnADB5a3Q1fS6REIypPvtm/T17XzssZO
	7tzjcCsHVKTTv5EiPChGfXQ=
X-Google-Smtp-Source: ABdhPJygBhJP2Dbb1ftD6Eb5NQo8tIXAe3yiepLeAMbVPf2ZzGz146R334vWf1J0aymjOA62jOoE6A==
X-Received: by 2002:a1c:f608:: with SMTP id w8mr255527wmc.161.1599581675132;
        Tue, 08 Sep 2020 09:14:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca44:: with SMTP id m4ls1675316wml.0.gmail; Tue, 08 Sep
 2020 09:14:33 -0700 (PDT)
X-Received: by 2002:a1c:a385:: with SMTP id m127mr253126wme.189.1599581673866;
        Tue, 08 Sep 2020 09:14:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599581673; cv=none;
        d=google.com; s=arc-20160816;
        b=p1TFAJG3B9lstv3NNtvMRsAGiHz6B8Ly3MTI7zOfDKwasfJ66wLMmZYsr/zubLVYIV
         6DYJWofsxQO/Cvg1GrpWmhlzkAUlSLQgbtj1Ewhle8f5nb7J+EQQrf6NI8AkCuSkXRCi
         r3gEczIeiP3jSsOQlsYNZB3uW2qnqTqJ9ye0kPvPsMOlFISKPPz/68c5LrJD4OGiRaF0
         z5ud2fi9dCai9RYSQNoyr7XBiSRyxo1/eAWlHGuSC+unyETx+JRb53wt+c2es1L5GwgA
         IzV9Qi/mMSTQ6exa10UdQNVW58HSueoJ3MxuXt7w5aB6cs+JjihTufE+ogE5L6CDD9kW
         kt5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=PYj2kwCEYY4tdbHxlRk9vou/mFIHHkfUJ8u/A93HB4M=;
        b=aia+/USGkYx5KLNr/ZAvIQktV8EzW6noQYrwj6nhzzaPAlC6n1c1fgYbi2qDuWdvpo
         ruSajMSDm3IYOF/vrtA99BlDmeidrl69tltQju/AUdkVsi0QKJ7uWorqXPSWiTjzffjH
         zgPDFnEESTuRhKeXT72LEciwaRo+nPlo4Khi6Y4LAQTxCU6nMCcW8Wj2b+7+3943jdpY
         qb4yJRNAeJYcrCBiM7ER/1WmtXw52Vp/ENZKdNe3c6avVZJXsVzqNP7+WQDaGBN6YJuY
         uAQ8p8gE5b1ziItH+h1mOZKUayyF9yM8oKkacnDtIZEaIsF8E+NVd9lUK49e4oY/Al4b
         AtYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="QS9QO1x/";
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id g5si1107309wmi.3.2020.09.08.09.14.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 09:14:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id z1so19795953wrt.3
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 09:14:33 -0700 (PDT)
X-Received: by 2002:adf:e481:: with SMTP id i1mr351083wrm.391.1599581673254;
        Tue, 08 Sep 2020 09:14:33 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id l19sm33290410wmi.8.2020.09.08.09.14.31
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 08 Sep 2020 09:14:32 -0700 (PDT)
Date: Tue, 8 Sep 2020 18:14:26 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dave Hansen <dave.hansen@intel.com>
Cc: glider@google.com, akpm@linux-foundation.org, catalin.marinas@arm.com,
	cl@linux.com, rientjes@google.com, iamjoonsoo.kim@lge.com,
	mark.rutland@arm.com, penberg@kernel.org, hpa@zytor.com,
	paulmck@kernel.org, andreyknvl@google.com, aryabinin@virtuozzo.com,
	luto@kernel.org, bp@alien8.de, dave.hansen@linux.intel.com,
	dvyukov@google.com, edumazet@google.com, gregkh@linuxfoundation.org,
	mingo@redhat.com, jannh@google.com, corbet@lwn.net,
	keescook@chromium.org, peterz@infradead.org, cai@lca.pw,
	tglx@linutronix.de, will@kernel.org, x86@kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
Message-ID: <20200908161426.GD61807@elver.google.com>
References: <20200907134055.2878499-1-elver@google.com>
 <20200907134055.2878499-10-elver@google.com>
 <3e87490e-3145-da2e-4190-176017d0e099@intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3e87490e-3145-da2e-4190-176017d0e099@intel.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="QS9QO1x/";       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
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

On Tue, Sep 08, 2020 at 08:54AM -0700, Dave Hansen wrote:
> On 9/7/20 6:40 AM, Marco Elver wrote:
> > +The most important parameter is KFENCE's sample interval, which can be set via
> > +the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
> > +sample interval determines the frequency with which heap allocations will be
> > +guarded by KFENCE. The default is configurable via the Kconfig option
> > +``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
> > +disables KFENCE.
> > +
> > +With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
> > +of available guarded objects can be controlled. Each object requires 2 pages,
> > +one for the object itself and the other one used as a guard page; object pages
> > +are interleaved with guard pages, and every object page is therefore surrounded
> > +by two guard pages.
> 
> Is it hard to make these both tunable at runtime?

The number of objects is quite hard, because it really complicates
bookkeeping and might also have an impact on performance, which is why
we prefer the statically allocated pool (like on x86, and we're trying
to get it for arm64 as well).

The sample interval is already tunable, just write to
/sys/module/kfence/parameters/sample_interval. Although we have this
(see core.c):

	module_param_named(sample_interval, kfence_sample_interval, ulong,
			   IS_ENABLED(CONFIG_DEBUG_KERNEL) ? 0600 : 0400);

I was wondering if it should also be tweakable on non-debug kernels, but
I fear it might be abused. Sure, you need to be root to change it, but
maybe I'm being overly conservative here? If you don't see huge problems
with it we could just make it 0600 for all builds.

> It would be nice if I hit a KFENCE error on a system to bump up the
> number of objects and turn up the frequency of guarded objects to try to
> hit it again.  That would be a really nice feature for development
> environments.

Indeed, which is why we also found it might be useful to tweak
sample_interval at runtime for debug-kernels. Although I don't know how
much luck you'll have hitting it again.

My strategy at that point would be to take the stack traces, try to
construct test-cases for those code paths, and run them through KASAN
(if it isn't immediately obvious what the problem is).

> It would also be nice to have a counter somewhere (/proc/vmstat?) to
> explicitly say how many pages are currently being used.

You can check /sys/kernel/debug/kfence/stats. On a system I just booted:

	[root@syzkaller][~]# cat /sys/kernel/debug/kfence/stats
	enabled: 1
	currently allocated: 18
	total allocations: 105
	total frees: 87
	total bugs: 0

The "currently allocated" count is the currently used KFENCE objects (of
255 for the default config).

> I didn't mention it elsewhere, but this work looks really nice.  It has
> very little impact on the core kernel and looks like a very nice tool to
> have in the toolbox.  I don't see any major reasons we wouldn't want to
> merge after our typical bikeshedding. :)

Thank you!

-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200908161426.GD61807%40elver.google.com.
