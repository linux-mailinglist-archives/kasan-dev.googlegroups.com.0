Return-Path: <kasan-dev+bncBCS2NBWRUIFBBM5N3KXAMGQE3XENY2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id BFBB385EE0E
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:35:00 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-41256717763sf28008515e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:35:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708562100; cv=pass;
        d=google.com; s=arc-20160816;
        b=LhV3RftmEhm4pLw8x9WBzNH8BGBS6sUGfURH8Y8jwpuqEqDyO093j58J4EzYwnww2f
         BERktu3YVFoDsaMBJHf126L6xG9YnjwGnMK928LkkmrrF0SwbJPfVdOwQstwDkQBXLmj
         6b3rEOtxPi11Q/GOvL4ZDRSN5Rj3wJSeHTz2bMX/yJ8pc0lXjU/GxDhcgV4VWD+qHk9k
         qtjinKWZa5QuJZwffufMKBvhOTZyBv7AeRJaBkiyv6xRbIoi4aOspiRBXFdwDIHDZHRJ
         wOod4deLtRTv3tn5FKk175KfkQ5d7WfcrEvxjo5FE8lKy0GfYWGff5xrAUOA6aD8j/c5
         zizA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=FtG5s5VSFKOC+gDNR8NKA2KrOD8N0twS1xm/Q1ykct8=;
        fh=5Tlo1VCfMONmXcRuDbgaeV1ccEhHHw2DForNuY34ua8=;
        b=SxZh0JFMkEgW5iuYZACBnY0fNt+fLDjdQkdVWczh1vUyEJsyd3vmJ2myUKzb2Z5Ejx
         Ee6yJF+twDUJtnVdC56GHqC4n7CAtY2TwQozyLA2aqQuEXoHu6Y194ZqikIXi9u+gUpJ
         VE/4eSRqbgkm8oPFSoDQEPd7zFTrxZxQJcgTVSiYnSKNlNVlWw1jOorQyymPuaxcZ+9p
         HLGI3mOYlW2klJKeqmSsiTio+3QUj0gknfCiNjXaZ9HCsjv+E3r9mASyHhcQ0zGwBhAc
         PWoqsOnPWDZ5J4U3eKBcm9hAZH2Tb9Z85Rzs6FL+CvhzcKDLtxAJjcb9e/TUFk1TPhta
         blUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DNUFEkkq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708562100; x=1709166900; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FtG5s5VSFKOC+gDNR8NKA2KrOD8N0twS1xm/Q1ykct8=;
        b=U3M2Owk9j3h9Bcg8S5Che0bXwSAzONiPIt4MX9gfL1zcqVq7anOSBTsvV6qiFV7ybT
         vMXnZ5UuI6AhdHwluOJiQ2PKVIckUTkgg3gZodgz2PeDT6f0RbhNkLngvPPZ2YvLWrQs
         tTlcmeZB4FRIZnc+qGxdzmNc2gQVUq35yPzrWD27md6DmPM7JqFFK0y9a+VRu0trBVDy
         eOD4V6aStogTsLWOnkmLWsXv30VMV/dUvMplp4klQjcQtj0rXREjpyJJ09TSXBofkbbL
         6tsbfbqJ9yoE27DBmNsMp8uk3o3BXc1OGUjGGb1sCkfi5LyGnOEzUrxldcuQZvBiSznD
         D/IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708562100; x=1709166900;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=FtG5s5VSFKOC+gDNR8NKA2KrOD8N0twS1xm/Q1ykct8=;
        b=i7mZuxyZPzzTSZjGrDLVYn/P0WjskaBliO72YnZlLajpIjc/eu/ny9Aqi9BL6AH6HD
         BMD/aEPWQmqzRaHJVyZNKbbubjJ3ZCZwBm15EyD4w/ykC06guNHaP7sr95UuOSuXB1sh
         HfbjFFuLcTt1tukDEzJLp3iHQu3f8VQ9Otss/n8nbiKWOOICAlex7oh9kbATcbu1qloa
         Vg+mRup3Z8meNbweO37DZDwGAqyA4hBghQEJwBjG6gDQ+fn5SSLw4a0vJRDc04FqLGEM
         ZZuArLuQd7nvSLiNV0YIV7WGm0wjuRZMFl42A+gHBFEDJfaJZLZKsjmM5iV8gMu1pe5h
         Mi/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLVR6v5RwC6e6FoR4vwMlwbLieVyLHU54hEg3at96a/7HP29dqSHnrPtw7WB2iwDu7ArNv5jpvC7OorxbQyGtriUs+KPr8iQ==
X-Gm-Message-State: AOJu0YxRg7n4B89XQJsEcaCqAh7mnq16A5G8A0j/e2hgumWbNsGivPLV
	iAzDZDoan+1Pp9bOsNh/6vh/JELxCbdYxd/MUhvFnRUlgT7vaYtv
X-Google-Smtp-Source: AGHT+IF3wOedH05ObL+SAuuAmWFgoOUjHI3+5/sV6AUA59OAnrc/B6l2xQrIpeMU9VfxUbdxOFqzeQ==
X-Received: by 2002:a05:600c:18a3:b0:412:10a1:25ed with SMTP id x35-20020a05600c18a300b0041210a125edmr14614317wmp.33.1708562100013;
        Wed, 21 Feb 2024 16:35:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d90:b0:412:7920:38f with SMTP id
 p16-20020a05600c1d9000b004127920038fls398369wms.1.-pod-prod-08-eu; Wed, 21
 Feb 2024 16:34:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX8ldKesjMPrYysmmPhE9V+Ptj0CO+NcTSGkUkppR57wQ9OZIdse4f+CbbwDS5B3SxfM/hY0BdNTQPftDkz4p/eIPJpvBb4b9toFw==
X-Received: by 2002:a05:600c:3506:b0:412:283e:5797 with SMTP id h6-20020a05600c350600b00412283e5797mr13951083wmq.29.1708562098274;
        Wed, 21 Feb 2024 16:34:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708562098; cv=none;
        d=google.com; s=arc-20160816;
        b=gCPpcCL3BZ0d3LR+NGpvPt+17PCmY+eG29yyoEz65dvf+yWHTkr3N0pUEOJPPxRUPz
         Eop8Wax6PuOFJrPIohaoysadrNJan8a1JWq6ryHVh/6mQb/YV2MkX3vqEyRBwHBnrQR2
         WEC8pTvDNsflVcrFw8jtJBs4NbVh7yCEO0Ko9K8Z4dNBSGbcky5M6HPGYSxorpqdHJPc
         7AkdGMrRjeMBRfDYVeMMfeCFLjGOGbOjqLbiMFVuzmo69Xcxm73wV56IWPTsI9df3hf2
         XiC6xIedoVAAK/dpTGv5t3JdZHI0OSyqsGTy/MNPgwrXCbPR6OL2EW0LVA9l/8AynBP0
         zqpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=G88uSOyu1u80Eng+KqSI+b6wDgfOq5t2Nzkcxgmz8B8=;
        fh=F9GiZMx04XgnGjC+MLD3U0mn+SjPIBLXuOPXH0T8h4E=;
        b=KlFLmkqnzW2jyQCXzkjQ1J1NVu+1BKXJ95af1znQaWZC5g2VY3GLKeG24WbAcrXuEn
         It7USyv2KqOW4HAl9XWBtxD2Hf5xYevP17Ta0XWT+IWyxh1AUR96FHKXLrrS5eXsqB6s
         TuYwEP2sCAMETQGbJLFK0WUx0+OlLar1XslN920vVLUR/ukzc/qsNDx0bFVqRxI9k167
         Fvzmy/65DlUdrFoA4RNDZ7Q/RFli/9gjUjCRvcke63b7CIalyrw5UBlKZrojg1VKA699
         4NucEx0+qXQ/VaVMzdFl6+3uJpqXBcDJtbVJZs8lwxW2rBo3kkTFZO+UsLo0zn36Bc8b
         M8GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DNUFEkkq;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta1.migadu.com (out-175.mta1.migadu.com. [95.215.58.175])
        by gmr-mx.google.com with ESMTPS id n12-20020a05600c500c00b004126e2da65csi276083wmr.2.2024.02.21.16.34.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 16:34:58 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.175 as permitted sender) client-ip=95.215.58.175;
Date: Wed, 21 Feb 2024 19:34:44 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <vxx2o2wdcqjkxauglu7ul52mygu4tti2i3yc2dvmcbzydvgvu2@knujflwtakni>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
 <202402211449.401382D2AF@keescook>
 <4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk@b6ig5v2pxe5i>
 <202402211608.41AD94094@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202402211608.41AD94094@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DNUFEkkq;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 95.215.58.175 as
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

On Wed, Feb 21, 2024 at 04:25:02PM -0800, Kees Cook wrote:
> On Wed, Feb 21, 2024 at 06:29:17PM -0500, Kent Overstreet wrote:
> > On Wed, Feb 21, 2024 at 03:05:32PM -0800, Kees Cook wrote:
> > > On Wed, Feb 21, 2024 at 11:40:27AM -0800, Suren Baghdasaryan wrote:
> > > > [...]
> > > > +struct alloc_tag {
> > > > +	struct codetag			ct;
> > > > +	struct alloc_tag_counters __percpu	*counters;
> > > > +} __aligned(8);
> > > > [...]
> > > > +#define DEFINE_ALLOC_TAG(_alloc_tag)						\
> > > > +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> > > > +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> > > > +	__section("alloc_tags") = {						\
> > > > +		.ct = CODE_TAG_INIT,						\
> > > > +		.counters = &_alloc_tag_cntr };
> > > > [...]
> > > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> > > > +{
> > > > +	swap(current->alloc_tag, tag);
> > > > +	return tag;
> > > > +}
> > > 
> > > Future security hardening improvement idea based on this infrastructure:
> > > it should be possible to implement per-allocation-site kmem caches. For
> > > example, we could create:
> > > 
> > > struct alloc_details {
> > > 	u32 flags;
> > > 	union {
> > > 		u32 size; /* not valid after __init completes */
> > > 		struct kmem_cache *cache;
> > > 	};
> > > };
> > > 
> > > - add struct alloc_details to struct alloc_tag
> > > - move the tags section into .ro_after_init
> > > - extend alloc_hooks() to populate flags and size:
> > > 	.flags = __builtin_constant_p(size) ? KMALLOC_ALLOCATE_FIXED
> > > 					    : KMALLOC_ALLOCATE_BUCKETS;
> > > 	.size = __builtin_constant_p(size) ? size : SIZE_MAX;
> > > - during kernel start or module init, walk the alloc_tag list
> > >   and create either a fixed-size kmem_cache or to allocate a
> > >   full set of kmalloc-buckets, and update the "cache" member.
> > > - adjust kmalloc core routines to use current->alloc_tag->cache instead
> > >   of using the global buckets.
> > > 
> > > This would get us fully separated allocations, producing better than
> > > type-based levels of granularity, exceeding what we have currently with
> > > CONFIG_RANDOM_KMALLOC_CACHES.
> > > 
> > > Does this look possible, or am I misunderstanding something in the
> > > infrastructure being created here?
> > 
> > Definitely possible, but... would we want this?
> 
> Yes, very very much. One of the worst and mostly unaddressed weaknesses
> with the kernel right now is use-after-free based type confusion[0], which
> depends on merged caches (or cache reuse).
> 
> This doesn't solve cross-allocator (kmalloc/page_alloc) type confusion
> (as terrifyingly demonstrated[1] by Jann Horn), but it does help with
> what has been a very common case of "use msg_msg to impersonate your
> target object"[2] exploitation.

We have a ton of code that references PAGE_SIZE and uses the page
allocator completely unnecessarily - that's something worth harping
about at conferences; if we could motivate people to clean that stuff up
it'd have a lot of positive effects.

> > That would produce a _lot_ of kmem caches
> 
> Fewer than you'd expect, but yes, there is some overhead. However,
> out-of-tree forks of Linux have successfully experimented with this
> already and seen good results[3].

So in that case - I don't think there's any need for a separate
alloc_details; we'd just add a kmem_cache * to alloc_tag and then hook
into the codetag init/unload path to create and destroy the kmem caches.

No need to adjust the slab code either; alloc_hooks() itself could
dispatch to kmem_cache_alloc() instead of kmalloc() if this is in use.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/vxx2o2wdcqjkxauglu7ul52mygu4tti2i3yc2dvmcbzydvgvu2%40knujflwtakni.
