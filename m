Return-Path: <kasan-dev+bncBCF5XGNWYQBRBP4D3KXAMGQEQXXMY4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F0E585EC78
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 00:05:37 +0100 (CET)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-7c49c867608sf618099039f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 15:05:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708556736; cv=pass;
        d=google.com; s=arc-20160816;
        b=cIqcN1wXZqxni5bmPgu/w/SNJXad1Tn/mF5KGbEjNdpbsmKCKu69iSLNwJ+37g0C+n
         pTTCr/OsUnHqii51hJQsgvK/twHbbcS3r/uI2Pbmsmv7ZrBzS254Arv0oqngf54M0WN9
         QiiFlBHGM8TccbBlzcNGwGe8dDCEBbupQK0jVm+UHEJtI+Blxo2IC2koTsM3ficza76n
         6FoR+09szaNeys8neyZb1yKYoT3hwAQGsACnDgt6Pgr/Bbv4FCXvlN66pegEaHto1GIf
         C0olNERZqlAfkjF/ogsK7TQpC7jj5t/cIsN6YWH9luRqmcNL8NW5fFjvtbtlKfhsQVhq
         ItLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0nNYFthhwLUpVdxB464aTZuyOAPRx6gSBzq472SDyyM=;
        fh=za9kSYk8gDJrtSSSRagj066r8blRsmEoj5rwH/XDQfE=;
        b=S9hyOyhyqqZQjwXEYyiCUgA7Pf13SQlpa7zCRZK4rtLaXy0y+gGZC8FLbh1fS0xexA
         FG+5rQ5k6sk0mQ1eEuHC0u92PT9mfSCXTENvGDTHrpU2RrqS5Ft6AMTNMz+/KSxhZfb2
         66mHMJs11aUzxrnlitPDzXASvPZJq58JTC/JtCDbPVO6Uver1l8O5vM8mQ7wJv1FEbVQ
         h3ikbluvh8WT9+QfB5KJqNqFlKbxoUhg2OXZ/rPjEsb50FAZkwt2vUB0QGz3YYWVlMAK
         HwT7pU+vTl7gLmwZ0SxStrvLoa+BKt1xKOeGdkhRGuGdg92udbbAB1ry9Sc8pN39Ji3F
         GlGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nDoBnjSy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708556736; x=1709161536; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0nNYFthhwLUpVdxB464aTZuyOAPRx6gSBzq472SDyyM=;
        b=eW+Lvi0aScPB1WnzrofFMWAVIyoyuE8dGWXt8U1DmwOguE5NZWltLxH2NSXq/iX7Hs
         znQEVvnncNNg7UYc482pYKNCclSAexYY6JLa2+SFBdVqWEZh+wCDkJwRXT2h9LHgeybL
         alJCIm8Ybpn0pAUk0m7vOZUs9L8iP5aXleVBBZwmZ/8N7XJw79/iSsgNh4gxMaWGD09f
         i66/nobsoX/zOxDocoohmSuOaHsNEyWo8N0LrFVGpdJZKTOLiZKT/9qIsYAAworInbSR
         k7Q4VNQn+1hXGJUUb3EF40cVI3KIu9nkhA5VRGLnntFCBMvXIENjrEbdE1kJAp7Ry4Gq
         6Yog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708556736; x=1709161536;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0nNYFthhwLUpVdxB464aTZuyOAPRx6gSBzq472SDyyM=;
        b=v30yKRb529f4IwfhjO3KdaLQwzQq/cxknyItQPPY77IlsAsNAYO1OcVtS5XSbqG6cF
         fI22cc9n2po3x2avBMxrtQPoW2kEc1jXg3WgSc5U0ZD/oTdsSObc3EJnwxo4CqcVm+/3
         aNJ5wjzO4Ja0ZWnLdUZq/Pfp59vx4fmK04MKa/cb/0e/dsCXjNi0caR1gxrAyaCn9yCG
         xCTaDfzJCiGrPWCsN4fgiMvhnNKJrgEE5wioVjxp3oTVRvu7K9grziCx95XNLiaRpO+E
         y5XHoqFWoY81rjGvHcfSfvrHT5z4DJx2U7WNDF3SEaEOrh5tF+774kdY7cxJ0fgWkc8/
         eqow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVekvFWU4RQlm6ez2Vc29c5h1ffwwCrdC9ZLvrT4J9ZSkS97wPXYYMiAxab9HDH9GIguchZmWJ+NUaP1yn+eTGGdH+748CA/g==
X-Gm-Message-State: AOJu0Yx+l5hsUl7I4GDA+xmYP5smSoNRxfn68cC14wfiFR4zKCk1SsX9
	nIKyABeykZeTLS5fcrI/ba/dZdXdPotp0KTsKEzbMbHXbXYkx6nE
X-Google-Smtp-Source: AGHT+IFYNqXw11/u4FJrCuRIlweVoFR+yRoIh9INxHmdsIH5663o3O4IJpXSuiLM5D25e2B4D9TeQw==
X-Received: by 2002:a05:6e02:c6f:b0:364:2406:992e with SMTP id f15-20020a056e020c6f00b003642406992emr20637669ilj.23.1708556736084;
        Wed, 21 Feb 2024 15:05:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1292:b0:364:f794:ec16 with SMTP id
 y18-20020a056e02129200b00364f794ec16ls3309043ilq.0.-pod-prod-04-us; Wed, 21
 Feb 2024 15:05:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWwhPMLNctWS4SAQ9ol0yBEE4+Qj52zR1IgmSE3iHCdU+BXBi/ogGMqJxd4blxZ5EJJR7BSI+e4uG9RG2YtTwKlCYoi4mQnkIZzbA==
X-Received: by 2002:a05:6e02:c6f:b0:364:2406:992e with SMTP id f15-20020a056e020c6f00b003642406992emr20637554ilj.23.1708556734339;
        Wed, 21 Feb 2024 15:05:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708556734; cv=none;
        d=google.com; s=arc-20160816;
        b=s+INcHw+iYaQypyMdk+Xd+3mSQHAwL74fkv5o+imaFjuRZAdRqOeN/NhkAz5qOmrcD
         cE8BQUKYsSJeqcPNuHWCkJQEy7Kx9jI1q+uyTc12lGEG931bvEQwz0JA1yHFNz7kPgS1
         rQPsnf1wBYRi31IrzDyicl2VeHjj1R8ULOtB4YOnOMCOxCsdZKvGg8Zgto+TetLHDpr9
         NjHwlRzhatc5K6svLiP5Dd+dwOCSEy5QCT+LVtl0st8OlyEF6tB5rspt8NR7Nhb4Tzqy
         9jIg9VwCgkcNEr7m74cx61s2x6vvIojApzfwIAB23N8MxEVhrXbCwndG0ZMXtNgBY9UU
         MXkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IaQv6IYiHqQsQRwxagN42nrCoy2L36X/io0NIlSKpEE=;
        fh=8jJtACGUoMorFxXQV5LprGtCH/mhC8vTZxYQN/iKles=;
        b=AGLLeNoabSf1Ow7vFX/+/mplvAyLVGDLUFjCNI9SIJtO+hUpxPVLD1/mv1SXq5HfSc
         8WR1eJuBKz4QmhyuTtv67KJ/EaAE3DowQhYkvXtbUvTvmXraqhIHA5FM6keotfGa8MWE
         kWc9NwNPrW8R2J3Of0PieF9sZgLA11ytSiE+LmG77GEtSF6JogbqRaz/XFQ33YjN5MnI
         K9R0E6J2llBXIDn6OXwO+pMUSMzIBNEgmy+22m4vptNVaII1wPF+x78f3e8YBEefG1ia
         vOD5Nfa+Et4GeaHJN+heIULXxC5LFsbGXPhmJu5fNh+5d2L0syND/CP8AbyS7iu4DeAa
         xSVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=nDoBnjSy;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id u3-20020a02c043000000b00474359ba1c8si313533jam.5.2024.02.21.15.05.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 15:05:34 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-6e47a104c2eso1692468b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 15:05:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVLiJBo7GpZ71VlWBad9Sv3LpQ9UWL8IXGbcC3eIaVrpkJYNTUQtoLD9/R8TGrfazdRQZXob/rI2fR5YC/+Xj9VUfVvF2dx0PlPoA==
X-Received: by 2002:a05:6a20:9586:b0:1a0:d25b:aaac with SMTP id iu6-20020a056a20958600b001a0d25baaacmr450464pzb.32.1708556733595;
        Wed, 21 Feb 2024 15:05:33 -0800 (PST)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id h15-20020a170902f7cf00b001db7ed47968sm8631428plw.30.2024.02.21.15.05.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 15:05:33 -0800 (PST)
Date: Wed, 21 Feb 2024 15:05:32 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, penguin-kernel@i-love.sakura.ne.jp,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com,
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
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
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <202402211449.401382D2AF@keescook>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240221194052.927623-15-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=nDoBnjSy;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Wed, Feb 21, 2024 at 11:40:27AM -0800, Suren Baghdasaryan wrote:
> [...]
> +struct alloc_tag {
> +	struct codetag			ct;
> +	struct alloc_tag_counters __percpu	*counters;
> +} __aligned(8);
> [...]
> +#define DEFINE_ALLOC_TAG(_alloc_tag)						\
> +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> +	__section("alloc_tags") = {						\
> +		.ct = CODE_TAG_INIT,						\
> +		.counters = &_alloc_tag_cntr };
> [...]
> +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> +{
> +	swap(current->alloc_tag, tag);
> +	return tag;
> +}

Future security hardening improvement idea based on this infrastructure:
it should be possible to implement per-allocation-site kmem caches. For
example, we could create:

struct alloc_details {
	u32 flags;
	union {
		u32 size; /* not valid after __init completes */
		struct kmem_cache *cache;
	};
};

- add struct alloc_details to struct alloc_tag
- move the tags section into .ro_after_init
- extend alloc_hooks() to populate flags and size:
	.flags = __builtin_constant_p(size) ? KMALLOC_ALLOCATE_FIXED
					    : KMALLOC_ALLOCATE_BUCKETS;
	.size = __builtin_constant_p(size) ? size : SIZE_MAX;
- during kernel start or module init, walk the alloc_tag list
  and create either a fixed-size kmem_cache or to allocate a
  full set of kmalloc-buckets, and update the "cache" member.
- adjust kmalloc core routines to use current->alloc_tag->cache instead
  of using the global buckets.

This would get us fully separated allocations, producing better than
type-based levels of granularity, exceeding what we have currently with
CONFIG_RANDOM_KMALLOC_CACHES.

Does this look possible, or am I misunderstanding something in the
infrastructure being created here?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402211449.401382D2AF%40keescook.
