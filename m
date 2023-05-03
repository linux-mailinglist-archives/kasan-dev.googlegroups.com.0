Return-Path: <kasan-dev+bncBCB5ZLWIQIBRB5PCZKRAMGQEZ4IE5HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C82836F5EE7
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 21:09:42 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-63b5cc55538sf3208015b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 12:09:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683140981; cv=pass;
        d=google.com; s=arc-20160816;
        b=D+C8jQfvITidw+gcfNhUbSrIssA0l1tYYTQOMr3X3pQExEP0yoq2DUs+I/LJSJmejC
         YP43rYPFs3eY7FioDyy47VItl29K3k2l60jDE2EAzWBiz2YZhXg5COm5aXbruP8mDptf
         gPFpuOxpPRtcsHHd8mpYygUdk9xcFk0YHlYl1z/ZjpHC+qRvG3T8u5nMWb7Dmn1ro5Jd
         ITFiVxdYv4JKwEO1CL4U/FqnaeiMtTvCV+d3nW3dtHLos7lpp4LUDeIENqQ4Uwl3gOWK
         BRp08p50Cj2g3CDTookH2wzO4OFB4eCp7YdTVas297mE1MNUHFb0LxDstUUeCy4wyyOT
         y/PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=jRKP4fQzCF2hSbvYbS2UpSGZykzOE85PmO38PYEr/io=;
        b=xgnvKKALv6fmZGeEGyzWYIOGot3shBnCTwO5WOA0iK47d5hXyvCuLetQa5qmbIJKv3
         lA7PSkqg0VdF353EH2n19Tn1Zsg6o2MhmiG+uTF3Fu1Z/REF8EyK+66ut1xjavsP8XFY
         sbWHljvJKUPvLhGQZImHWtxLndeeiMH9RAvussf2cwT8O7eeXqFleqPJHzn39myDPmYX
         IradOYKK++Bh65sDgFxpl6I1pb1Mjjm3lRdFNXZ+DyoeMQ2kFNnwVI6dRQiwWoNhpv4O
         4DrZYMK2vdgSMuJRhiEJYaik/1jbX6Q4XKVrCWq1BbfKQr3Lpe7yM5wvJZtpBFjHRZn6
         3zHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="DgGf/RDP";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683140981; x=1685732981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jRKP4fQzCF2hSbvYbS2UpSGZykzOE85PmO38PYEr/io=;
        b=lR1q8FH/vf440HPIARNuQxDNX8KxSkUsskzZpnu8CurE/O2rtz+yV1tqmRgj+oczZJ
         e2qX72bQXs1JnR8eBHDmIC6Ejz9FnGo0tlKnWLMI/ukSHeEqvimF6hE4eFhgFsK9Osyj
         d/1M2NrLDzzC0NHmt2o6lJotKBi51deJ3t/bBoB00wqH8CDLvKjVI21HQkYIpdXj28Zx
         0KkgA+R/4nHmcRadUlUn2UzA2Ujvx1hhRYRwBh9TRMWAlhor3cIv1os3rucbE0OqAe6V
         7xyies5Yxoczma691EyRrw9VXWpBEcBax3CGtcsRKreDJMFZbE7Xbuf6sOvtlMHW0ChR
         kKqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683140981; x=1685732981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jRKP4fQzCF2hSbvYbS2UpSGZykzOE85PmO38PYEr/io=;
        b=XLwN05HGtAph7Ztj2DGN8Rx3k3TH1tniFb3IQYQ6X18ZdyUrCyr3mWvGBlfEF0m2/q
         IBAk/Qz8uRtLiz8HyAO/rjLP3Mmz48plG3GlunAUoSp28u9NKD8ks4hsid9BXssPZ4a2
         mD5IdK8BYViHb8Km8go2ExdZRmSXKZAWCr92fUzrdFnCUc1u2+ee1q2RBStRgkKe/Ufx
         0ThoLSIGC8oBSeep+MOusTHBDsN+l8+hPpFLaQK+n7RLTe1DE1rWNgO6yzAx2nm3pmb8
         ZGRyg/ajBlWhRbdLrnm/rmE7MakGt6jyUBW2avTiAc/hoNeK3RkPjSRaE6DqRsUyCFcP
         ptZw==
X-Gm-Message-State: AC+VfDw3XFJCq8auZzGRi/Z7lK/9ZJfRljc16Czevw4VWDfHo8qy0/vK
	mVUMpEstcKMllTf66ABnQFw=
X-Google-Smtp-Source: ACHHUZ443WnkqqvIEDULVtTR5McuPtu34s23Z08p+m3RVeZ7xRq/iqRaFXlzQQOn3wLG/1auCqt/hw==
X-Received: by 2002:a05:6a00:320e:b0:643:4b03:4930 with SMTP id bm14-20020a056a00320e00b006434b034930mr566329pfb.0.1683140981370;
        Wed, 03 May 2023 12:09:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4b02:b0:24e:8dd:ef7e with SMTP id
 lx2-20020a17090b4b0200b0024e08ddef7els7005110pjb.0.-pod-canary-gmail; Wed, 03
 May 2023 12:09:40 -0700 (PDT)
X-Received: by 2002:a17:90b:17c4:b0:247:78eb:cb96 with SMTP id me4-20020a17090b17c400b0024778ebcb96mr20822519pjb.17.1683140980419;
        Wed, 03 May 2023 12:09:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683140980; cv=none;
        d=google.com; s=arc-20160816;
        b=I3N4bWdwASyWFI4JT1oHNnQ4AdsRAObsnN2O7YhbEE/OIqVKr2PUhXjL42hAdb2mn7
         oeuqqOUwiEMbIw67HHhsrLPevmSsaCuuv7fubFloRgCmkTtq+wdvNklvGR/fbUek1AUI
         duBe5O72kjYftDbIA2zBcm56qJvpuBcIamNzvvR6W7pOs0SoUYCOsaLRLqfOd3dlDmpu
         MhUNH4cKxUnB/YIpTo9Fmq7VXbiRgWC0d9zO68lEmQF4ZDX7X5LUs+ZX3NZtDhEDFdVJ
         BKUt2htIl9xA2ZxJ3WnjQDyfU4brSm7g0ZUiv5IWlx1NZBHDtgMqioxLLsnZStUmsQA5
         fnjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=m2prCTdjzaiRiaqQtudLpWKutHCUVL/OSWsxsk3W0H0=;
        b=lUtUvr4I9WiGFBi4V2FNts8l73VfhoBX9spP/DpzGlQb9lMp+E3zDwyA/Z6SseGB4J
         SUfL4eVIcjU2axUEKw2crVG1myRkrzDyd2NC1wf0a7peTZ2sn70VSkKNKG2Bab7NUMmo
         xT9FBW34oBO1YE/+XLAOysf3UjkSBUc7jAtMB91TuZkgQBTT1e+nMbBgBMsSK2pIFsRU
         umvgBVYSYAafEzDXVBxzfdHGjNlyn78Zkj8XsNC2yxvNb6gYezzgI8cIdvwF641vinOV
         4lZ/lQ1C1biqE17Zw021rSbIk0/P18ed9IKUMfV3bJq2UV0RozElvGT4ElpyvuSPFK2I
         Iggw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="DgGf/RDP";
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id l7-20020a170903120700b001aaf7c46645si270391plh.11.2023.05.03.12.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 12:09:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-1aaea3909d1so43585625ad.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 12:09:40 -0700 (PDT)
X-Received: by 2002:a17:902:8d8a:b0:1ab:5b0:6f16 with SMTP id v10-20020a1709028d8a00b001ab05b06f16mr1059467plo.43.1683140979705;
        Wed, 03 May 2023 12:09:39 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id 12-20020a170902c24c00b001a69d1bc32csm21999335plg.238.2023.05.03.12.09.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 12:09:39 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 09:09:37 -1000
From: Tejun Heo <tj@kernel.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@suse.com>,
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
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
References: <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKu6zWA00AzArMF@slm.duckdns.org>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="DgGf/RDP";       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 03, 2023 at 08:58:51AM -1000, Tejun Heo wrote:
> On Wed, May 03, 2023 at 02:56:44PM -0400, Kent Overstreet wrote:
> > On Wed, May 03, 2023 at 08:40:07AM -1000, Tejun Heo wrote:
> > > > Yeah, easy / default visibility argument does make sense to me.
> > > 
> > > So, a bit of addition here. If this is the thrust, the debugfs part seems
> > > rather redundant, right? That's trivially obtainable with tracing / bpf and
> > > in a more flexible and performant manner. Also, are we happy with recording
> > > just single depth for persistent tracking?
> > 
> > Not sure what you're envisioning?
> > 
> > I'd consider the debugfs interface pretty integral; it's much more
> > discoverable for users, and it's hardly any code out of the whole
> > patchset.
> 
> You can do the same thing with a bpftrace one liner tho. That's rather
> difficult to beat.

Ah, shit, I'm an idiot. Sorry. I thought allocations was under /proc and
allocations.ctx under debugfs. I meant allocations.ctx is redundant.

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKxcfqkUQ60zBB_%40slm.duckdns.org.
