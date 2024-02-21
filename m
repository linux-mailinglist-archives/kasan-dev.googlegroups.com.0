Return-Path: <kasan-dev+bncBCS2NBWRUIFBBWUO3KXAMGQEASBPLEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 75DEF85ECE8
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 00:29:31 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5648a1a85aasf2174a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 15:29:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708558171; cv=pass;
        d=google.com; s=arc-20160816;
        b=d1mQUCPUFhKEbzuLviJ2h3mgq5V9kFm9FFZ47W4QH/bvpbkzk53lu5QfcHGuETfx0R
         OcBpRbj6DDCrbo7Bh4K4tT0kFH4WJNKrn1uqrnEaxt6/ua1g01vlOJNwdI9zyrWnHIwo
         fB1vIv/K/Y3FVp7o6QLD/td7p3hBToQE+E9OJwkLevK4ZiSfI0QrLsicsJX5A+rEEjDB
         elX9i36wYp8UXi4F+nBkiRE02Nt4mNT9xswqZRdAqhAW5SWKDawhfNUqwxXvcHN9r+PG
         G5NCdSovD0QNyIhyW532eCg+ngv4Itt4glHbgsWDX4JbaSfvinXaiSmjPzHX5BURU1/q
         73pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=5xwmApEHukQA4om6YsqsPRqsF24lCULilk4q9f6wCpE=;
        fh=4ORmXxAG47SJh137Ef5MwpUO/M8VUN6WnMshleqi8pA=;
        b=h7r68EsSamCXoaiGICtUS+kjaDIP5rbBkjEa2JrcTCYDYhYwXqc1ztIkL1eidHIE4g
         uzndeWbYWOI3l3lyzJss2sXYXmbC6V2k+/HBi9viEd44OlnVaqabkwNA22gngYYp7+Jl
         9Yocw5vfE8sa/Zahp/db1XuF4u/rf0lUbY4WYp4ef7HcF544BVGjlqPrPKu+DIr3Q5ck
         +p61wlX37qgVEg3lFeT7Pj8J450COr86ghKXCatCc7CwcsZ2+pg5owPjiBCZiZP62Lkd
         HBI+KV4n3gXuDmnUffYerS6tW74UsdzduNKvrbZxt720WIVWpXBBy8GBDTuIlr+zecAV
         mUiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lq+ly2y7;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708558171; x=1709162971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5xwmApEHukQA4om6YsqsPRqsF24lCULilk4q9f6wCpE=;
        b=tv5SQ3jr/gktZtSjkzxP7hARTtYlWCfhAmUA+zBBQ/A7acxXbSKwpL00cczK/nawN6
         YUSZDr7V1bb4fjVAyLPOLgamMpINeW+9Ewpwq0lPl9PDCYCyTqKI2isuxTKfVIcFprKq
         Lr3YjGkoDKAoTWS+Ezk7CQeKECoBfZtSDWWyofLqfImbKe8m/v6r3uIMmgpf4Q1mF0Et
         NiPEianLtztmp1CTTsQ+bXSpovewocLcVey8GQwdMKy5NL8YQnYsLkl2pZ+pkb5I9DQ+
         l62fMHgb5+ZHcyz4A7uFeC12g2ebWvoumQgPQ77/s35JvUNKnXSmPw2hdmk5voztATiB
         pDmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708558171; x=1709162971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5xwmApEHukQA4om6YsqsPRqsF24lCULilk4q9f6wCpE=;
        b=iFIVntpH0cbi4VIPyAqTnncaILtuXso97mVjjKf7BYVZfXih0UO3RMSYq/DMZdwPad
         QG2JJNX5oenpfRo+Tw5/1egli0EkmZyT/Ri2ZCm6N58iz6jZ7iCZLDcVFie3N4TBWPMs
         VSoXoghrxDJ/HvWe76meM0yZBXR1zeuc1J3W5+0t9cEQ1yz9DzVZIDkF7WYBFSi9vauy
         4jurRxxpNPdke6xERjnXHv0VmAjsMJCQOB5yfIv9rxuKKmW+BaidVdcW9SGzuaITRd+b
         jgX4t1OQ2JNi/5269zgUSa/JPMxfmPGQqvLDsBth+FjdD89j1ZqNHTTjohFbJ2Gnyhmo
         62lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfMTIPe+a5bSfym0gaitELwVLdyvXkDaZ93mT/Iu/o3eWkTZ2hq5KN/Z12y7PdxPKTCmOGB1EQbftLhv13XZM3zqU6mJXQzA==
X-Gm-Message-State: AOJu0YwHtZvgKSJJlQ65LXBn0bkKTCw5yeZzipB/ZX4BxdxeZEFI7XUv
	Kr9NBf7e5sbMRLZU4aGlxpvu7FzlDm7tqSC3LuzchirH/tuDk3Rg
X-Google-Smtp-Source: AGHT+IHLKmfVraC3HE/EEVRo56Lr8FS6Aj94RRrc4T0yQ76y63AL+6VU834bm6DnHYl/+UShyAwR8w==
X-Received: by 2002:a50:8706:0:b0:563:adf3:f5f4 with SMTP id i6-20020a508706000000b00563adf3f5f4mr276677edb.1.1708558170537;
        Wed, 21 Feb 2024 15:29:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:80ca:0:b0:2d2:2a90:7050 with SMTP id r10-20020a2e80ca000000b002d22a907050ls1159062ljg.2.-pod-prod-09-eu;
 Wed, 21 Feb 2024 15:29:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXyJUvCJOzqVWeV7twnRiT5YvdQS4tGScuchTlErQpidZ4ZXD5gbtaMaHtbZRgst2LRqnHpjZTpgOPa/2yNSdS4Ew2UcJjGXnlv7w==
X-Received: by 2002:a2e:8699:0:b0:2d2:20eb:dad8 with SMTP id l25-20020a2e8699000000b002d220ebdad8mr9662896lji.33.1708558168463;
        Wed, 21 Feb 2024 15:29:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708558168; cv=none;
        d=google.com; s=arc-20160816;
        b=deFB8hAy0NTtri9T+SBFZFDZX4ZrM+Fh7QUNDNoFeasmaj9cVI5atkFKDXtHYjEHaF
         aUxfQ/WqrMJeB4bFhDd6oa+gL3Dr5YraLaa++lN7KbiGJIf1OdbctgvRHQJO0tMj6JGb
         DEdoyyfMapH1BRg/ivnppi76rffvfNVB4fBI+MsLHhZjTYnvotcjlJcHweViHSsSVOex
         gFEAk95Bi/055aoCu8iHsSO3y+Gmly5S3C610O3jvJP7RQcvSiGosChmqK/iLG1/3nYS
         4DEIUclW4mbmetVCiuae/r7aenPPKAQXWgfDV51fJqrQSQtE50QIZRNZlo/eWYWAegKk
         h7LA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=6hjF2SQllee7ug3mHeFW3uN8wvM2xkpGrw/6L+GvqAI=;
        fh=F9GiZMx04XgnGjC+MLD3U0mn+SjPIBLXuOPXH0T8h4E=;
        b=ulm7okJaMXkMDVg8FDEub2i/12S45KFt18rnU7rrrJroNsRpqYkK/tYzq4ksTwXVeQ
         jfU0AeYfsYuvAdhQ1Vl/PVh9jNg1hQRGhCOolkIfCvviWA0XA10GlIihc/gBEU8l41w+
         IjEFtYGJw52PRum+iaJwWYeNWhgWWZeSnNR7iAhnH3lZWT3BkM7IgNO3hPH2Ny0fgsJv
         BZ8kz3HTQOfXKlwzp2qcUEWUG1YNDB2NSy5FVMEQYF/tnrsx/ILPR81KIaQ83vLsrmwG
         LqqEH2g2RTwYfbQUPZ4G6wd0lDlvUvOfKKhkzL7CjSluOnCgdAxYM1KyMRPX9GjWCjSx
         qlig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Lq+ly2y7;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-186.mta0.migadu.com (out-186.mta0.migadu.com. [2001:41d0:1004:224b::ba])
        by gmr-mx.google.com with ESMTPS id u22-20020a05651c141600b002d2085137d5si554807lje.8.2024.02.21.15.29.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 15:29:28 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::ba as permitted sender) client-ip=2001:41d0:1004:224b::ba;
Date: Wed, 21 Feb 2024 18:29:17 -0500
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
Message-ID: <4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk@b6ig5v2pxe5i>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
 <202402211449.401382D2AF@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202402211449.401382D2AF@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Lq+ly2y7;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::ba as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Feb 21, 2024 at 03:05:32PM -0800, Kees Cook wrote:
> On Wed, Feb 21, 2024 at 11:40:27AM -0800, Suren Baghdasaryan wrote:
> > [...]
> > +struct alloc_tag {
> > +	struct codetag			ct;
> > +	struct alloc_tag_counters __percpu	*counters;
> > +} __aligned(8);
> > [...]
> > +#define DEFINE_ALLOC_TAG(_alloc_tag)						\
> > +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> > +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> > +	__section("alloc_tags") = {						\
> > +		.ct = CODE_TAG_INIT,						\
> > +		.counters = &_alloc_tag_cntr };
> > [...]
> > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> > +{
> > +	swap(current->alloc_tag, tag);
> > +	return tag;
> > +}
> 
> Future security hardening improvement idea based on this infrastructure:
> it should be possible to implement per-allocation-site kmem caches. For
> example, we could create:
> 
> struct alloc_details {
> 	u32 flags;
> 	union {
> 		u32 size; /* not valid after __init completes */
> 		struct kmem_cache *cache;
> 	};
> };
> 
> - add struct alloc_details to struct alloc_tag
> - move the tags section into .ro_after_init
> - extend alloc_hooks() to populate flags and size:
> 	.flags = __builtin_constant_p(size) ? KMALLOC_ALLOCATE_FIXED
> 					    : KMALLOC_ALLOCATE_BUCKETS;
> 	.size = __builtin_constant_p(size) ? size : SIZE_MAX;
> - during kernel start or module init, walk the alloc_tag list
>   and create either a fixed-size kmem_cache or to allocate a
>   full set of kmalloc-buckets, and update the "cache" member.
> - adjust kmalloc core routines to use current->alloc_tag->cache instead
>   of using the global buckets.
> 
> This would get us fully separated allocations, producing better than
> type-based levels of granularity, exceeding what we have currently with
> CONFIG_RANDOM_KMALLOC_CACHES.
> 
> Does this look possible, or am I misunderstanding something in the
> infrastructure being created here?

Definitely possible, but... would we want this? That would produce a
_lot_ of kmem caches, and don't we already try to collapse those where
possible to reduce internal fragmentation?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk%40b6ig5v2pxe5i.
