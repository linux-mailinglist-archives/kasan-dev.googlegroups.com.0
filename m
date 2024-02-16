Return-Path: <kasan-dev+bncBCS2NBWRUIFBBME7X2XAMGQEQB52PFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B27618582BE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 17:39:13 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2d220086976sf2766321fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:39:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708101553; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZdRQCYVybeg4gNoTe+nEedayAxhA4cHiX14k2xG+xXaKpRwfEFn2mcJ9cc0oDv24Ga
         QSzyyz99IN4IH3ogZOuc+2+WpD7O4M5yQItCwThUgWkUfsRQjAaIaN8OcXIU8HO18Kqa
         fkSSzL0oXqml6c4kb9Xk1Vg7tPuiLKUvizeeOKysvMpaSl1kHoX2QXdLqrnSdXACUfWp
         H2jc4kyo//TwsSmwGTHj41Ls4BIUHJ0z9LJoRrJJ0/UxSiBOGcrnupu0XH5wJXvRopNI
         7Z509DCx8ycQPuKsvEHdBD0DYXAiTGceqg+WZX87dMmUXx8O30RXp6GOz/nGFP91uA3+
         sgiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Sv7ucvp5fKO9oTM2T6QMoUA7xHqWfXGu2AnDAW7Au80=;
        fh=ENsEDyk+il65LJsAEkU+EahdYohMTIffqquzbddKizY=;
        b=lLjVZxM+ppoePBGqH+rt4JKNKfxIj0vyugBu6HV95R6KKT3Ntf6M7w4pTaE8dNDxwU
         9/Zy4Riw4fi9BoZtyaQ/VspN50huZGVCx1BDk5U7rZxWsOmQPVL/4sle2K+6ycFyNCSg
         ve1dCWRgFRvssNEk2MBYRdj/kBe2HibxVqqLYNzhpyX+rXhcKC4n5lRfgxUIcSRjMj0X
         BFYC83Fr1OvdzlFu40yA4+rx/kQQ6Oo2Mria3nQXtSQ4ikylA4oCKMxfeFlHS+J9F21I
         GHvQlbVpu8PbA3gtIFPPI/hzCbjD5Y6GzXPcx/87+XwBUfe6kUeSYtv6M6kTRN6vbzOX
         zsCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="P/rHKmX3";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708101553; x=1708706353; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sv7ucvp5fKO9oTM2T6QMoUA7xHqWfXGu2AnDAW7Au80=;
        b=EfnIvdpLADTxwsRaqq3pZTtlPqlEZ9IgbytkC8PHo1fhmHgUEqMkomcpSM4N5IwSzv
         uu3B4fX05bw28zlCjJVBoYyULBMvKL+kUjxfBPH1wtlYhkj7ec0vxa/BtUtE+SR8YdCc
         21su7OsYYU/zI8k1lp0K6B8PK5rPFSyALXm7tHh/L2bUKUCS0oHjhSJiGLuLJxOJ9ZWz
         huiIcvJjkdke3wAChf8v7mwU2bDtkiYeZmDURx/Cd7x2PrAQ4kruin0RKjnf7h+iRDEe
         cX2kTrxPBqpVGBtqhbP+F340tSaCWPCJanCPUwKcTVTyZEVVgGojYS2ZuY/fU2LKvdZi
         ySFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708101553; x=1708706353;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sv7ucvp5fKO9oTM2T6QMoUA7xHqWfXGu2AnDAW7Au80=;
        b=ilHqNGkQNN1RK8qsacd788PmHUMACZStMGYQygFFIQvPEruZQxI049XSuxV7xdrT8P
         dKFcpD8IWTv9iveS2Sc7gJS927vXIY6YdwclRmLdgQfZlZkPQbOMNnQECP1ZEN07esht
         eYNFGuWcmYhATak8YyzEBmEfrOEjlTH5I8aiTPuP0gSXIdfhdEhdrRSEdnRE8y/d9D/q
         P+0copK33/Qcnv2nWOwBmXpOkPskwooj4Dr7k8X2kCYRzZWjGSBauz+xRDTS86ldXQVX
         P0t7o7o4kiY6RDVHqwBGrgkpzLj5STIcLqMY1Dzyd29Aq6Pf1RkS7qAPQCILb3kJZurv
         TbgA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+vxDXKr6VVbNM7aB9gjtwxtwcMmdT+LYSqe+/0AZTPc6Jr8NvLWj0RfP9N7uIH5l5r9KHYgoNv7h84/ItnZO8r6FEdPmRHA==
X-Gm-Message-State: AOJu0Ywbly5gTxsJTsJdKyjHzl+wkaGNb0r+t9N541ItxWUNgMEu1tS1
	QTN+RFsXmnUlNCKxYb9fV26BEG4amCneDRNLl8gfBDHGD3OoIFrJ
X-Google-Smtp-Source: AGHT+IFcoue75pPgbMxhxs0mvOs9Yi6ICzLsIhNWHR13yhtnGSXCs54xKE6aivTmfF4qNbpU14Pe5g==
X-Received: by 2002:a2e:9bc9:0:b0:2d2:1b51:76cc with SMTP id w9-20020a2e9bc9000000b002d21b5176ccmr1431604ljj.7.1708101552728;
        Fri, 16 Feb 2024 08:39:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a784:0:b0:2d2:1c51:61e5 with SMTP id c4-20020a2ea784000000b002d21c5161e5ls85659ljf.1.-pod-prod-02-eu;
 Fri, 16 Feb 2024 08:39:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/zY753YkSzFHhQGekkCipgRHUZOWcEHB9k33InhAlxKnK2SPqaiJVCeVayaOZuEx16Dfzv4+pr4rL7mXlbx/3lHqZuesY0Wnm0w==
X-Received: by 2002:a05:651c:2118:b0:2d0:a347:1cd3 with SMTP id a24-20020a05651c211800b002d0a3471cd3mr4450103ljq.28.1708101550620;
        Fri, 16 Feb 2024 08:39:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708101550; cv=none;
        d=google.com; s=arc-20160816;
        b=BHSmI0dNyulv8R9IVWapnNguOSS0H8xeZTIzEP7SGiLvQB7UrK3L/SCeIyR0vUF+6F
         ZmdK34DjVuxKa2lTY1I7Z4RSeSbI5YLHsS+oMYoFGVsOC5jVX47aJbi3Pl9ebhC8YfKp
         v8hTbJ+glUNKh2/Rg0EMdBQZguQJ62XJh7i8jDpMgl8XMl4p89UmXAZOSJIomAkfA4HB
         YkfyQ96zQbCAZFieKn3Atf2RMUo5iJJUhw7g9V1mrrJDugF5ojTEP1Uh9zq3m2556Y61
         /biemwstO/ccO3AK/tqdZDwm1sgkZpdHleQLnoXKRmwoQDNL00/h6J7gSSqbTsbHoGO+
         XZNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ykstDffvORkHR/QBul+dunCrpEbnMsgllsNmRKwgALQ=;
        fh=oLzH21GokMW2l86dFsMPozOxCJDwxgKqQI1fOLLTHJM=;
        b=LQVDDrPzqHWvKfYlGNVjT/OR5iQ7ZIp+ES8gjaxW+NE+9euXOzKIE1v2FTAKfXxm8a
         rT6oOUriA8WpWpXXd9h+zT0amZuDJdAh9h59Tzsd5gIIKFAKyS2QuY4+HD5MJy1dG7Pk
         eq8B5f53X212CvVk5iQNLGDgouHswDUKyFQNzUQjOxNcgjEMLGGbSeEr67DPExZrAfmM
         Bw9nGrijEDmMRtBtEhKwIv/MAsfE5D5IcAby9TFcPB7mvsnxWT+6MowMLRrfIYQMUSGK
         bL0MwCEgsVRF4vr0lHL5UizaZzotRbEa04Fy0U9OdWmR203DNgrwyWwhGx9Wwf5ffrgE
         L95w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="P/rHKmX3";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-179.mta0.migadu.com (out-179.mta0.migadu.com. [2001:41d0:1004:224b::b3])
        by gmr-mx.google.com with ESMTPS id fc13-20020a05600c524d00b0040ff8f0e6acsi89307wmb.0.2024.02.16.08.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 08:39:10 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::b3 as permitted sender) client-ip=2001:41d0:1004:224b::b3;
Date: Fri, 16 Feb 2024 11:38:59 -0500
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
Subject: Re: [PATCH v3 21/35] mm/slab: add allocation accounting into slab
 allocation and free paths
Message-ID: <vjtuo55tzxrezoxz54zav5oxp5djngtyftkgrj2mnimf4wqq6a@hedzv4xlrgv7>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-22-surenb@google.com>
 <ec0f9be2-d544-45a6-b6a9-178872b27bd4@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ec0f9be2-d544-45a6-b6a9-178872b27bd4@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="P/rHKmX3";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::b3 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Fri, Feb 16, 2024 at 05:31:11PM +0100, Vlastimil Babka wrote:
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > Account slab allocations using codetag reference embedded into slabobj_ext.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > ---
> >  mm/slab.h | 26 ++++++++++++++++++++++++++
> >  mm/slub.c |  5 +++++
> >  2 files changed, 31 insertions(+)
> > 
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 224a4b2305fb..c4bd0d5348cb 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -629,6 +629,32 @@ prepare_slab_obj_exts_hook(struct kmem_cache *s, gfp_t flags, void *p)
> >  
> >  #endif /* CONFIG_SLAB_OBJ_EXT */
> >  
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> > +					void **p, int objects)
> > +{
> > +	struct slabobj_ext *obj_exts;
> > +	int i;
> > +
> > +	obj_exts = slab_obj_exts(slab);
> > +	if (!obj_exts)
> > +		return;
> > +
> > +	for (i = 0; i < objects; i++) {
> > +		unsigned int off = obj_to_index(s, slab, p[i]);
> > +
> > +		alloc_tag_sub(&obj_exts[off].ref, s->size);
> > +	}
> > +}
> > +
> > +#else
> > +
> > +static inline void alloc_tagging_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> > +					void **p, int objects) {}
> > +
> > +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> 
> You don't actually use the alloc_tagging_slab_free_hook() anywhere? I see
> it's in the next patch, but logically should belong to this one.

I don't think it makes any sense to quibble about introducing something
in one patch that's not used until the next patch; often times, it's
just easier to review that way.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/vjtuo55tzxrezoxz54zav5oxp5djngtyftkgrj2mnimf4wqq6a%40hedzv4xlrgv7.
