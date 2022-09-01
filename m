Return-Path: <kasan-dev+bncBAABBIVGYOMAMGQEXXIADPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id D73AA5A9BEE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 17:43:31 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf4476044lfa.10
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 08:43:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662047011; cv=pass;
        d=google.com; s=arc-20160816;
        b=JtR2+VdnCPx8/iKHb8czTvlh2F6s/GFK3VWl+x/cd65Ja4bmzHEi7wFyE7XxkCeK8L
         vIf9mMNoN4pE38HiEhA++oJZ1KHSI/AJh+TzWhPFrLzOs2a6J3mAkf+/mjn1bxZDiBy+
         u7L/OXQY2O3ru65EZ4vUhnjFNBdnFwVppIqL13a5ZT9DeuMqR/YqAg3i0Jli5CxDzGS+
         xujxUCDE6d3rA0CLO+XybvrG58IGJe/ChMuHB9Ut2ulbSyLCart6lSRDhzTarR1ihqvf
         13X5DoSYlC3IyEBB/VstoOIZ3rNRNbN/g3tuQxPA2d7OjP28MXr3ktVn4k20kTK5drWq
         eskA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sWGdO76XamaU//b7knnB/muEcvitu19bQsdJM3fl6ek=;
        b=djL+WYg1fD8tsKdnDCDmSetbBR1awPm7y12qe43udUZD9DnpBriNacb1rXtPYp+S3g
         rzreG8PDq/N81OXGJCMeUA3zVB7oTGYyoTciEZ7OtalXul+kYHScs66o6cOtb7jocFCw
         DipnuPrv7Vhbb7/oe4ZakVoxrrMXpBlXXdZuOcIxMbS4t23PTYvvOMN8raTDCNoFdGjR
         GiFfw3Xk/B2bDWOXq1ofjWtS86Wua0wFW3ueueu5lD95BHtHMGCeTaEbfFVV03HWWbCE
         M9wcM70qS1uT4HxNtFvSzjSKxE5+1Wz0/W+Dpi9zIQBjNZcJWN/5llrbomTecys+KTG/
         nHPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Zug2Ft4Q;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=sWGdO76XamaU//b7knnB/muEcvitu19bQsdJM3fl6ek=;
        b=r2wJ2e4L5UPbEystpfgt67xZigLiEBwm7BGTNw0xi4DRCHIlkYREPfKixlBXzsEEro
         5aIantMi7lNQGrnJvS20YUUW42afKs1Q3K+z1oMb9TqERCWxH7pA/wcqIfhDoS2bIR7m
         F+SqXLd1qHxQ4JARBK1ldpag3Et/BswH3XR3Z81cdL8mVvAHvEsoyLB+f9yoL9+B+cxh
         qroh6M3VI+xrHvis3OAz/HLr2EczGoN2cHUEdHoszk3DH2iExyasYgn3naEuSkTTTddb
         M7uz4AjR9OvW3Mp5PI+qTK/7zyU2OkBdM2WYyRn2BqLz3/RyJdKz12ZCgz9TZnZV9O1T
         nA5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sWGdO76XamaU//b7knnB/muEcvitu19bQsdJM3fl6ek=;
        b=IPeL1tLfIvnevXonXjn2dEnnXD9IOg2oC1C1qDak3JN8sRUjpJxm+M/juKRrGVo3sv
         gxrEglQr3suQjxv45koY91iaOUN6gqNDnO3TUHgn4P/yj5KGKaquQ7PHJcOib6Md0/MX
         mOHtdqX3qIsF1zC4O+knVtgSj2nnapLnDhoTHhncflmrvZ8lgL52xdz1dPFh/f2DRG3K
         deomCycxoCXdWhsqwPe2T6Y4kLSnMc0FjPRaRuJ73y09uICpOs9E9WXBvtft0pZBlLoN
         bBfvPRSWgbu9Lk7F+vAE6oMmTlvhW3xNWTVz6N2a4sPuekultEkagI/8XVgknn9XoAh5
         tePw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo27Tz/7vLjxm0dFHYBH1R9ha5gnLljPaaNxPXbGxT4yI+DpvOhC
	zDdyfbytQTPuKx4J0Eb95/w=
X-Google-Smtp-Source: AA6agR4ZNQesyjyxwa3oY0zoTKbxsMPcVzL4G0nr4aWZ5IwkmcgMuuGRf63c3DCCDozWEInVGQhYNA==
X-Received: by 2002:a05:6512:282b:b0:494:8721:2268 with SMTP id cf43-20020a056512282b00b0049487212268mr3050544lfb.323.1662047011134;
        Thu, 01 Sep 2022 08:43:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3582:b0:494:6c7d:cf65 with SMTP id
 m2-20020a056512358200b004946c7dcf65ls1765903lfr.2.-pod-prod-gmail; Thu, 01
 Sep 2022 08:43:30 -0700 (PDT)
X-Received: by 2002:a05:6512:39d1:b0:494:7698:8ae2 with SMTP id k17-20020a05651239d100b0049476988ae2mr4372571lfu.407.1662047010297;
        Thu, 01 Sep 2022 08:43:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662047010; cv=none;
        d=google.com; s=arc-20160816;
        b=CV+zTHNH8/DhvdrKvblkshymb1MJl5KbeLRXIBre3kL96SANPJ82ZWvd5/TLPp1+LZ
         WXkQ2ni4KHg2/SyBY88yk5FHV31iXzC+Nj8RZEvmufjOWBUi0STOBIDZDGZGOZhWqCzF
         ubV8wzkdduCveTsRKb4kqTH8bXFglnP0Aq0SrHoy/kwTdhzjLQhm/HHgP+z04tZfqvWO
         BDZX9apouj+CGAe9OpzXNGAXMt3xZ9uDufverphCWv9hBc/oQGtjbVxmb1xov/LGZblw
         nrtfmwwMqxDf6rjZuT8c6dkc+aVZbqbNqODDBfWhYAqP/pPKIMDCNcMXvCsH5syP7RGR
         7A6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=OCuFL4N5GVZjONQAdChOE7OJr7ThTUJDCIIbzLkwFEk=;
        b=ak3+rTT67PxxS99c/TDB0tUDZ5aVoZDCINFS3inp9HMwbhob557TjWBX1HsK0cNl+2
         QrL7TkWiM9p+qJ1PABGf64OgctPD4PoMuTBoHsxB507Mi+WJpNLpbG+OPSP6PTJ7/jdt
         hfg+6UWAQIZoP49LERSh0Ax+1OiAOe/GH/LO6yIvORDQ5G4uExFpAghfL3stlIdK18hl
         o6TEXkdVSX9n400dd1Yl/AojqUM7+4bLzifEcwMQRBh74wo4P7eH4doxbNm1PmEojVAF
         638AZss6ZUp2PRbsgpgqe9VMAW7rCgyu/hnnTv/WzvvzUTcN8XriWAFPt9gY3SSz4jZG
         tRyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Zug2Ft4Q;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id f28-20020a2eb5bc000000b00268b15f80absi112606ljn.5.2022.09.01.08.43.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 08:43:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
Date: Thu, 1 Sep 2022 11:43:21 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, bsegall@google.com, bristot@redhat.com,
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
Subject: Re: [RFC PATCH 03/30] Lazy percpu counters
Message-ID: <20220901154321.apyq7246srkjthfr@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-4-surenb@google.com>
 <YxBWczNCbZbj+reQ@hirez.programming.kicks-ass.net>
 <20220901143219.n7jg7cbp47agqnwn@moria.home.lan>
 <20220901104839.5691e1c9@gandalf.local.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220901104839.5691e1c9@gandalf.local.home>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Zug2Ft4Q;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Thu, Sep 01, 2022 at 10:48:39AM -0400, Steven Rostedt wrote:
> On Thu, 1 Sep 2022 10:32:19 -0400
> Kent Overstreet <kent.overstreet@linux.dev> wrote:
> 
> > On Thu, Sep 01, 2022 at 08:51:31AM +0200, Peter Zijlstra wrote:
> > > On Tue, Aug 30, 2022 at 02:48:52PM -0700, Suren Baghdasaryan wrote:  
> > > > +static void lazy_percpu_counter_switch_to_pcpu(struct raw_lazy_percpu_counter *c)
> > > > +{
> > > > +	u64 __percpu *pcpu_v = alloc_percpu_gfp(u64, GFP_ATOMIC|__GFP_NOWARN);  
> > > 
> > > Realize that this is incorrect when used under a raw_spinlock_t.  
> > 
> > Can you elaborate?
> 
> All allocations (including GFP_ATOMIC) grab normal spin_locks. When
> PREEMPT_RT is configured, normal spin_locks turn into a mutex, where as
> raw_spinlock's do not.
> 
> Thus, if this is done within a raw_spinlock with PREEMPT_RT configured, it
> can cause a schedule while holding a spinlock.

Thanks, I think we should be good here but I'll document it anyways.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220901154321.apyq7246srkjthfr%40moria.home.lan.
