Return-Path: <kasan-dev+bncBCS2NBWRUIFBBE4IXKXAMGQEME6XNHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F78F856F65
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 22:37:25 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id 2adb3069b0e04-51151b8de86sf1251310e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 13:37:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708033044; cv=pass;
        d=google.com; s=arc-20160816;
        b=gxjwgRFfToWzMPS36HssvjCkCvCgGEQ4DuQQ1rCE9PcMpJYWupcg0+4huxiRldz422
         qz+s5wxQKPd+OA3X8V0AhUvwZNhbgHdvxe+IAvcxyWIfdI6+XemP5a07LXO0+HNbldCm
         8WoKwrs2nr+zZyP8t/4tvpKHebXnz94ZPtwoAlLgEyXIgFTKNe1SWLBN2vJsUlorzcdf
         /Ke0OxzaxpnUXiKhaxXD8gZSdGnYCR66+5PRur1ySx4RFJSGIYZTRJLx9hsX3ZayuZpb
         mPSpQncFgUxe+apojPihVFyWMR878wlZWzdAS5INbNmgh367QmQHuaMwpaDtkFXzBCIA
         Jx1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gPtSj+7DJ79M33havUu5VWDvJNRPL1XsqOIkGQir4fg=;
        fh=8IQ0XxAfuLQlnsd8c56M1AJYMWA3hTUl/P/P8PNYUhs=;
        b=ARgJsPNGDtM+PFwh9YkDSAAOwYmeffpMHr9dzOiGl1Rly/RfjnaEX7vY0knjNbw0us
         2ib1P5+oakoBogoAJpVHmTesXdkekkorMttLVFJ6uI4RrArkiFwuf2ROzZyU4d9ILjCQ
         OllSudaa1+BjW+a7IZYl2VNQqAMuKnCP7k8ndtMnMCQF17s99F96MzYLYDveIMT+L6Km
         3G6r8cQAn9tbovnfEOhhkyK/aiVX9Jf/yIIfb7vRFC3sXdl9xWIutIAwOYyKzUjm+HZ0
         H8o+REo2AY1ee+VJSFAz7At/asrDK8zmI44jl6E1ZRY05xrhxzKWbL2Chj56m3ogHvzq
         r6Tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Rnhwg+O/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708033044; x=1708637844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gPtSj+7DJ79M33havUu5VWDvJNRPL1XsqOIkGQir4fg=;
        b=goIlFp5khBO4/T2JrIAHcrkbfb3JNS9jl38b1snc26QnkKl4HRIP2dIpe2wWqLLqza
         6la2iu2ft3q49Lz7jszwCvrrrLUU6P3p4QuKTB6FD6nGRAc5wulYKKoKvULOlY/CzWDO
         6l2gR4T7XUU3vMxDX5I1t1RggXYImMQLXMeXGnbE1Rb9z/BGObmnHfZt1gFAzG6CPGLy
         198W5U7bcHqiRX9AKiPkgKDlsPtGuS8zYY9ppLUlrovIG8w2+N8nKRO2zHB+IVecqkj2
         bjrFiBKWjc7HAOe69TeCRVdQPTAgLL4ibDnydmcZlS6hQgVMtIzuvzs2RhAPONRHnEu0
         HKeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708033044; x=1708637844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gPtSj+7DJ79M33havUu5VWDvJNRPL1XsqOIkGQir4fg=;
        b=V9HYt3Sp+p0/RMT/10g632YpplP4eBLuU3wAWOhTr5R/9A8n2iSoE5AOrOrfYS2e66
         CLJIeV5my+sayX9prxbaDevYxtBEDr7hGhm4rG1JwXuk+tuooSUYOJjlm2APaKFPyAfD
         +C1r71migOxNCefgkj/kGRtvOT/5ZIgDoKLB1o4yCsL/uAXtwvEmes7W6OW5Oj7l2BMv
         KYEBV6zg7etipZhGBqzdojGyhXZrsRJdv6mKzRubFa5Fuvv5jFUjtOhNc7Au1ZfQnq23
         Yj/P4yjsMwt3Ez92fWlj3gSvz7C/Kg8yJbY173juP6BVafE8nuCwTQDENNvizGTQiMCc
         XhtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWy4OyhJyPMBIJBBmKkqKRAbAzGZ+V1aHWjMjGYclWo3Stv9d7x3G/8mLa6p7zrUpY0duUh109byRXrUnQXNqbBzZxMabRSlw==
X-Gm-Message-State: AOJu0YwzpZi/CnhWPRnEnmiDyVVD2fJ49HG+SBo7sazKdd739Sj5AlhO
	cMtnIk0u5YMkEotFzqb8d0qFOBsw+YTceKJxYKHdmpd1sKA9+CVA
X-Google-Smtp-Source: AGHT+IGbgnD8OO8f4DVtXnVIqU/sanAuRk60BCCC9YDlH4sCnGY3cltPSAsRbQdwzNpq6fNj2vf4Jw==
X-Received: by 2002:a05:6512:3494:b0:511:97e5:af0e with SMTP id v20-20020a056512349400b0051197e5af0emr2089219lfr.49.1708033043944;
        Thu, 15 Feb 2024 13:37:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3811:b0:563:94d1:8216 with SMTP id
 es17-20020a056402381100b0056394d18216ls80404edb.1.-pod-prod-07-eu; Thu, 15
 Feb 2024 13:37:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUUw+Vp+z0KtUs9eCBaQi6xuoOs4yrYmxu6S71NjgVfR1r1g0H/AL6OFJw2BXz0/4C5cOR0CD/NS8YnmDMTpGEaYoAIubcRbPmu+g==
X-Received: by 2002:a05:6402:3413:b0:55f:2f0a:d959 with SMTP id k19-20020a056402341300b0055f2f0ad959mr2193278edc.37.1708033041882;
        Thu, 15 Feb 2024 13:37:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708033041; cv=none;
        d=google.com; s=arc-20160816;
        b=zxqR+wzCXUtXIvdn6OqqIDVNzxvqB/Pyq4QV3vjYXpdbQfUAiI4E1Tej6gL9zVeNx8
         y4k1mwrIFq+n9Nh2cB9lONv/6oSCiNgHxrIw82+BLS5s/rN85wXQV3inYqDwXcel4Psz
         SlcuNYWDbco+NsTyILA0mdgK9oVouxJrFbAOFeznpGthgOI7H6Y8G/f2Uyf/LslAt1Jx
         y2gcl/X1bmqiIM0oaOp36L8ye3tQyKgcriTzvBXCYKY0nWKrGD5hE0xV0njyl4FW2Rzd
         uqpOTTcdefbe2pb6qFmWNpmgX9aDLLRVABzFd5TI6yyGAfS63ucBb4pGRo8KZIb+xQnP
         cMkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=39zmCdbpcZTkNZlIqIoMaXRRJS4y9GsAOFJTtoi5f0I=;
        fh=oLzH21GokMW2l86dFsMPozOxCJDwxgKqQI1fOLLTHJM=;
        b=DGM4Sooz42spUOnzGChCSQxnJA66/tx1s3mhcrtJTKGGlhu/V+sB606xfPDIi6Nmkw
         h+Z4Vl9QnGVclyMO0TBMUnvfFS010dC8udnls5JP3y6TDZuzq/cWioP6wfeIIDfQ6ED+
         1yCT5K7fcrD0nadBw89EstEi4Zci2fBXgrE5Wfmsh1oP26rEe17fVmtJan+KlVMkK6qD
         Wts0mFxQ2ghRvNPqdWZmaDIxa0p4c7SC2LM/j69jWhDUa9CIOPqYA+GI+3kC6GZQjXPf
         fLLYy09c3CCEJFoXhch8Vy/cUq0xjqTK4W0kTR8gEXzJkr7Loigc/2hbX7TIjyT6PBAn
         MSpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="Rnhwg+O/";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta1.migadu.com (out-187.mta1.migadu.com. [2001:41d0:203:375::bb])
        by gmr-mx.google.com with ESMTPS id m28-20020a50999c000000b005610f27d125si144639edb.0.2024.02.15.13.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Feb 2024 13:37:21 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bb as permitted sender) client-ip=2001:41d0:203:375::bb;
Date: Thu, 15 Feb 2024 16:37:09 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
Message-ID: <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-8-surenb@google.com>
 <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="Rnhwg+O/";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::bb as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Thu, Feb 15, 2024 at 10:31:06PM +0100, Vlastimil Babka wrote:
> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> > Slab extension objects can't be allocated before slab infrastructure is
> > initialized. Some caches, like kmem_cache and kmem_cache_node, are created
> > before slab infrastructure is initialized. Objects from these caches can't
> > have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark these
> > caches and avoid creating extensions for objects allocated from these
> > slabs.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/slab.h | 7 +++++++
> >  mm/slub.c            | 5 +++--
> >  2 files changed, 10 insertions(+), 2 deletions(-)
> > 
> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > index b5f5ee8308d0..3ac2fc830f0f 100644
> > --- a/include/linux/slab.h
> > +++ b/include/linux/slab.h
> > @@ -164,6 +164,13 @@
> >  #endif
> >  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */
> >  
> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > +/* Slab created using create_boot_cache */
> > +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)
> 
> There's
>    #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x20000000U)
> already, so need some other one?

What's up with the order of flags in that file? They don't seem to
follow any particular ordering.

Seems like some cleanup is in order, but any history/context we should
know first?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut%405dlfmdniaksr.
