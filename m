Return-Path: <kasan-dev+bncBCS2NBWRUIFBBIVKYCRAMGQENSVAJ6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 51B836F3835
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 21:38:11 +0200 (CEST)
Received: by mail-ej1-x63c.google.com with SMTP id a640c23a62f3a-95376348868sf343298466b.2
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 12:38:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682969891; cv=pass;
        d=google.com; s=arc-20160816;
        b=hV6m3P3JOzgzLMx/vSrp+mRwMDUOy99cXpayRzvZrlEZiXCXXArCMeAKp6gOC9g6sp
         xrF08+LHwFhOjY7/y08asqGbye+2IycqIOYfJ7xV2qWSuNkqaLomDq+uSwNeia22WYHd
         OXqR8G7Q5yVwiM6BVmSOTO7q9zOIkQDgGP6IsJJeNkUzhK6FIo8MrQmjNr/wNYFWRTJj
         xfD787kWAF1/A7Wssmr4YLyD7MktI+XGOvF04RN3cN6e78/4csnJRI5mHnZ47BDNJpNF
         ASfaFhBIwpxWqWkQwyeKWfj7A1CVDUAPYXt1RUYHfeKGig5INujtA81t2uMrgFVWGcv9
         JE6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1ckmMqz5tMbQoNG6CragYh/i+OQEOPb+0C+X6Kv4Th0=;
        b=oIAnl/6r7+BzUVwkj5+U5utgo/bNOkQKxWm5K6jteicfcZVtoH6berJx5uJHazFAO/
         kDRTL1YnEE/3WEMpnZx+/7rglFTZAOEQaiyJ9hIDc0Lctn5nuV4fGMc7THfZgSog+MSH
         i+btNEca/JXu/vL41iEPb4rRAENzja6wLkwUX/ZOy9Olffho8OmiaWccgwZ1ojnhRn2/
         HMyFO1QQ/RXZo4vWZPzqTapb2obDzYKkOtBRdQXGiUySobN3untyqo6dO4rwUJ1UegwW
         Mqj+ZX4oV4JSacCN5RYKgp3KlgrMMYF0M9HrJwwcgl9crsYq919LXb2LmQJ8Ts0pgtO4
         kRFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lnRRPNHD;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::35 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682969891; x=1685561891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1ckmMqz5tMbQoNG6CragYh/i+OQEOPb+0C+X6Kv4Th0=;
        b=UnjIuqjGaT3NVxX88bagPRSf6KM6/nsz+2z/DM4usiNRHvFQG4l7XHQbRcmgYcC0mP
         /s/P3iuKSk8c9YEP9sWS7rwaKvm8hD0U415Xxi2EwaUIAG2TMWlFAK7enV8RpsmBIqM6
         rXdCOMmMcR4EO0NO1HWp17FcwgW/NuBJ+4xOpS4GbFm3PSTCd+uJoP3L0OWOumgnGs4X
         VbqpjmaZgUJ1zW/P0xqFV+xQFpihkQoCieqfyaZNzJNE9c7s/9TZterQtzp3m1NGru5A
         +iNqWPtgmIZw1LBRTrlRUno6CmcK9sMxYoVCVcQ0Tlsl+qp7Rcor/+shHBzbEDJG8kkN
         jekw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682969891; x=1685561891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1ckmMqz5tMbQoNG6CragYh/i+OQEOPb+0C+X6Kv4Th0=;
        b=dHyNN3JynVPxXCpi+yvv2yNEWS0VXxMdjFDmNpJ1D/7PTgl/NM18lQVTDKqEJ91D9D
         PzoXSXa6p6ygDkmyTGRjC+/jtrupbOxR8JGxZ0Mn8KQVwHKJjKXkYjXCdZfwcFKBtuji
         H5PKYmciqKE5g7lup0FKTrkPqxMkeleECB09aze/R3+W7/srow3EsHgGdZOGhvQFscJp
         +PjFKXysrg4opND8YVCmQyl1r6zyIT1Y8GjC+V8uzj/jAepdzUK9LS0Yb6vGQi8zLnyG
         SVh+FyRWENnpNOqA5LtwXj1KahSaaXKhQEtRWd5y34R3LiknRDiCPGIQgd2VR50gzPfz
         TINA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzdGmkgwZRvbAY9uoR+5Wp7BQdHTQrovLndQhbUgXcsV1DW7Q/n
	HcKMbol7HIB1ipaCicEDDpU=
X-Google-Smtp-Source: ACHHUZ42VLLcMUXXoRHXOjnJf5iC3QCZIwZkeX5pCrTaQLJRnknrMeuYQbKJHnYYjaimufmWbWCfCQ==
X-Received: by 2002:a17:906:8a43:b0:94e:2d:e94f with SMTP id gx3-20020a1709068a4300b0094e002de94fmr5709379ejc.8.1682969890778;
        Mon, 01 May 2023 12:38:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:190e:b0:50b:cc92:508c with SMTP id
 e14-20020a056402190e00b0050bcc92508cls850849edz.3.-pod-prod-gmail; Mon, 01
 May 2023 12:38:09 -0700 (PDT)
X-Received: by 2002:aa7:cc85:0:b0:504:b6a6:cbe0 with SMTP id p5-20020aa7cc85000000b00504b6a6cbe0mr5619480edt.12.1682969889704;
        Mon, 01 May 2023 12:38:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682969889; cv=none;
        d=google.com; s=arc-20160816;
        b=n9FkSvVN40f3GZkMLVzIKcKeSOcgNma+wyA4qjr/BKWrYCYFtSRFap2DRX6G13sD4X
         890YZssg0qIFd3I1y5IEEwI4wwdVur0PhdvoYw+Enthy4TREHi2k0C+qFq70298Ag7Rr
         JRt1doaZS28GXzdzRe4or6E+VEDj0idYY1fc77M2ackFPxFqA2Etp0RXBMw7TBvvyJV9
         cTpiafvV69Pb/+VBiBA/juGWx+BAlcalw+UmDglQXkWTyRXDsIhVBoSFU3abkxxw6J+I
         7p2eM8gSSiSGLQTqh7pOV4nv05lw7+tMHDcmUpVeMy7d5dQsDUKcQhxFCOCmLZLkcjg7
         nxSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=541SBwyTjoC6k6Jt8ATpGdLRFrI++rPhwZtbphGiRj8=;
        b=AdUqEOhbYSxBBjLsa2CALpYEemyDqWjPgyPp2NzQsUNLW0mHtZ1tVlGI1FBDiRnDZ5
         dxAE2gBXy2XY7WpxP0/WcHGBUqLTnGJxYmFGlfjOtlBxw8J/6RQWbxvj9DZVVtYWZ5FL
         t5CcS19gkfUJXHkXS3EwiC/1/HY1gZQvtlwHZXnbyGgGCJFHr19o9cEwdrGIlBZwnyMN
         J2KzZ2uAJ8PpOj8mYRN6Z8oLmEcZ/34TMcDPNawtEKs6bK467Tf52QdXbEj8jOfCHKCh
         gNK7PGT5XLRjVx2J+RVMjyr++J1R3E9tAjnxO1YTYEyT3M39l2CsHjL4E257gTP0W7eG
         CWqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lnRRPNHD;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::35 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-53.mta1.migadu.com (out-53.mta1.migadu.com. [2001:41d0:203:375::35])
        by gmr-mx.google.com with ESMTPS id b13-20020a0564021f0d00b00506956b72a8si1748471edb.2.2023.05.01.12.38.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 12:38:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::35 as permitted sender) client-ip=2001:41d0:203:375::35;
Date: Mon, 1 May 2023 15:37:58 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Roman Gushchin <roman.gushchin@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFAVFlrRtpVgxJ0q@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZE/7FZbd31qIzrOc@P9FQF9L96D>
 <CAJuCfpHU3ZMsNuqi1gSxzAWKr2D3VkiaTY0BEUQgM-QHNxRtSg@mail.gmail.com>
 <ZFABlUB/RZM6lUyl@P9FQF9L96D>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFABlUB/RZM6lUyl@P9FQF9L96D>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lnRRPNHD;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::35 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Mon, May 01, 2023 at 11:14:45AM -0700, Roman Gushchin wrote:
> It's a good idea and I generally think that +25-35% for kmalloc/pgalloc
> should be ok for the production use, which is great!
> In the reality, most workloads are not that sensitive to the speed of
> memory allocation.

:)

My main takeaway has been "the slub fast path is _really_ fast". No
disabling of preemption, no atomic instructions, just a non locked
double word cmpxchg - it's a slick piece of work.

> > For kmalloc, the overhead is low because after we create the vector of
> > slab_ext objects (which is the same as what memcg_kmem does), memory
> > profiling just increments a lazy counter (which in many cases would be
> > a per-cpu counter).
> 
> So does kmem (this is why I'm somewhat surprised by the difference).
> 
> > memcg_kmem operates on cgroup hierarchy with
> > additional overhead associated with that. I'm guessing that's the
> > reason for the big difference between these mechanisms but, I didn't
> > look into the details to understand memcg_kmem performance.
> 
> I suspect recent rt-related changes and also the wide usage of
> rcu primitives in the kmem code. I'll try to look closer as well.

Happy to give you something to compare against :)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFAVFlrRtpVgxJ0q%40moria.home.lan.
