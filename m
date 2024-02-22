Return-Path: <kasan-dev+bncBCF5XGNWYQBRBYFI3KXAMGQEMCRLC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id F1D3285EDEF
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:25:06 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-2995baae8b4sf4443883a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:25:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708561505; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4tqxj4F1ENBQipRWIQR31Zsp3ZMYPjmcVNMBrslQCzC8xJqEEo5aoCBjI81QWg82i
         e240vO+tx7T0iUv3RgH9DS0SC8RVyeTWfnqwvb6OB+0hcuboi6grdywEOZUvwQynZhsk
         vBJxGr5oToWFz3+s0dtKE/0cPiW24r6TdDgcmYTMkXzF8PiqPhgxlisbU+mBsoLKm36a
         QPnzxOj/LQ5T0siCeoJmCyomPpwggk/YTyBwQyC1LEdPgJpgV/te9EKooQqJkIxjjMO2
         FiY0hG8gfXXqCCbGbfff2IPfr83Qze1wqP3WPXkPmFxQixKWKskXokE8ZALNWDarjfW1
         m7Ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=J07zQaBJgRbx5Pdk26uZ52+oCqOfYkx5I8xxB35tcMk=;
        fh=Yb6YGxZl2UPF7WVSy+Ef3fQmv55Sa6F0ms2HeOD5X8o=;
        b=WkCC3g27vwwFJiIO43atnVovjweeUkcQwo5sXK95/tL5zT/dNMJeZXwX2umTJ4gBrH
         FlYx/p2+XBiZt7IUunCK3p76ZD2JwHX31fyqHHN4X2qYfX5XBZ2lmz5I399CTQy/+dPB
         TbOXWSkXsmMul7D8mqbECu4WgJiP7xymFCUPAbDeSYjmZR4p+5HV2ZSb1VMKRhHYiCoq
         H6G2eSPL5BsobiDv8SBGsGI4AKFoRZ78foQ/2Rc+hLvxAHup/TQxNhLLsNyhLu5P67wZ
         gyVXeILAKuSteCMzZZ7lhurAkh7taJ6wsNoDFfMiU3nVOyQj9y0UGArlJibuLQSia4l4
         6Zdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TMkb2jGH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708561505; x=1709166305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J07zQaBJgRbx5Pdk26uZ52+oCqOfYkx5I8xxB35tcMk=;
        b=S7/SCqXzBmup+vA8O4E1TsM5Z3i4509zJyipXfYsDXj+AFEbHvsxYPbUTvqMIf/+He
         OG6U2t4To0cF2W3S4br7BJvaZYZkOMyCTAvm3WbZc5qwIb8GEoj4lDS+3EOvJlOMI2Ev
         c+niFrHLDrtPqMFxhQ0ddEkzWbQV9Vrmh+f/OSbU8YWXyfkFAwCRB6pQimfMrlL8Fpsx
         2YVEGDDdDLKlgmcvruzTIpuzfl15H7Pvmth5IWgDH46P5yc8Pks/nhifWlmesa6fq3UI
         8YW9Ry/PfzdBtivvOay29fQLRq+S7zvczmuyFB9yWn4J7rDgiY38M8Qr56Mev3vHve21
         U/kQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708561505; x=1709166305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=J07zQaBJgRbx5Pdk26uZ52+oCqOfYkx5I8xxB35tcMk=;
        b=mY4sdgDM4GkCW+ShHZMTeFBOoyNZN8wpBkWsvCwxOVStzo8qeTTvs5f/nfvEjjulnD
         MUgcXa7cqiGgqGimAwyPn3c/XsVLqYsb573xu/0S5JElEi6MWajOpPLTzeWRDvnk/qro
         vAsli8WGnoVriTTKxel0JG2DchHXcUDeelJ8aSho2sM2I/0kildcQAP5DheALugTRTgp
         nAD/VOybPs/W4b2J+HD4Ft0ZZCQIQTXnEDUSsDnfp0A69q/xVIJL6JxEmV8qmgg6Z2v1
         VpyiLxf20pYW1Ot6+878V+k5U5wmDgasNa1ta+SabHL4Pwvj1GaSjhQ94UVaKonW3Xap
         DiSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXktyRE3zfdLyEaD/0OlJbcjYKoA6UgA35+CCThJI2UAvyGMHuc+14OGBIAQGwOyZ6do7dYvIla6DLUeZjwUifBJJ7JVA/HlQ==
X-Gm-Message-State: AOJu0YytcnY472kaXdWNjbXFc8hJRAucntriWZHvjgl4qMJ5BRuvggo3
	MXIUoWmeuCmMnBbLp9SUldA3l6m4NwscKNMAVd7R/9ySJ5CuvtLG
X-Google-Smtp-Source: AGHT+IG6FRFetCf8RSJ/ampP9jd0hEUCG+V6+Q2uIcgIvh6eAqQinBUEgzjqGf367f8CWRhJQTI4fA==
X-Received: by 2002:a17:90b:23c7:b0:29a:42a2:837e with SMTP id md7-20020a17090b23c700b0029a42a2837emr644415pjb.38.1708561505093;
        Wed, 21 Feb 2024 16:25:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ec8f:b0:297:252:b272 with SMTP id
 f15-20020a17090aec8f00b002970252b272ls4368000pjy.1.-pod-prod-08-us; Wed, 21
 Feb 2024 16:25:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWf55LYWaWVGqvW+m8IvcyJVtST9A0c2pLjQ8/TwCt/aZ/TdwRzNvDwJ92ghyu5nuUFyMeWuxMZxSDP4hR8hqa0p96o4p1gc/oVAA==
X-Received: by 2002:a17:90a:c706:b0:298:d377:153f with SMTP id o6-20020a17090ac70600b00298d377153fmr17019602pjt.15.1708561503600;
        Wed, 21 Feb 2024 16:25:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708561503; cv=none;
        d=google.com; s=arc-20160816;
        b=mQYP2WLKsaKjsUBomlGfWsutbNGtS6JGodCmEtHiBddie7L3ewy1OT6e1NgOd+JuHU
         hidG11aA8+2me4R4Xe8CPN+eoBYX/3trtpIgiMBhoe8YYuBx5VQ0mBQ843Wcpn61aU6D
         opskRweJX9WMVniQGrjnWA3Cn2WlD0Tqzwwu5tJqjsjTf23HlNVZo094Mc3UVWjX2FSg
         Hp5Pcr3TUYdM43iUYB1h+tHiHvbNKTi94LDlyKuk/7wiq9gdvqGAq32Jmy5FzlyZvxVO
         JRM/UBkGZ/iwKp6oejxnMSmP6h2eQ8MB+XydhGY5GJK1GDMdcD9ofLZBRrVqIHkSvJlT
         1hhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WrVxGxFZ9H3+hlcYIVohDlCBqheEbLY5A8SDm36k8gU=;
        fh=mzELSnqX3GxFqCxcEoHgC0CETbcU9M+FGoSgAhxG64k=;
        b=KDOPIZtpa+kF6HHAyutFyXiFmwkgDldCD8UMX/stuhaDiQh7jYEmBZiR0GqfRROuYd
         RCPuEB91r8BY76QvWWgz9hJXYyDCI8cJAetbpWRJLs5swFI1J3yA4+/4UjiisEDL49aZ
         Iiiat8VilkfzWoJaLLvfu6dCQt4r5wBnpUf53/vYYR1p4PQKkFp6p0novU/lUBQq7zik
         QOxaY63Ms6OzQaCFaDi6bkXRtKZxTdYrm+u8cMwaqb6x9GwOnFL3ujnUqL+oHTnv6+iq
         sOSR3kHVeDQzGiVBhPYm+gPcG0HaylMesmmLGkJVFFdhwTrBO0RGzHmMsjcGdSL0k6Gu
         Dvlw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=TMkb2jGH;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id e10-20020a17090a804a00b00299907bd50esi208526pjw.2.2024.02.21.16.25.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 16:25:03 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-1d73066880eso68935055ad.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 16:25:03 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU69Z39IEqSYX1ds9A2l0uHHOMaiInTFRIw9VcCDQtDO1Ru+grDA2DRTgKnptYRShQo+2ScgMa7CH9GRRV7Jfy+ty7XFcKsnxQj/A==
X-Received: by 2002:a17:902:e5c3:b0:1dc:87:855f with SMTP id u3-20020a170902e5c300b001dc0087855fmr11196593plf.28.1708561503247;
        Wed, 21 Feb 2024 16:25:03 -0800 (PST)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id li4-20020a170903294400b001db7e3411f7sm8727330plb.134.2024.02.21.16.25.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 16:25:02 -0800 (PST)
Date: Wed, 21 Feb 2024 16:25:02 -0800
From: Kees Cook <keescook@chromium.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	ndesaulniers@google.com, vvvvvv@google.com,
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
Subject: Re: [PATCH v4 14/36] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <202402211608.41AD94094@keescook>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
 <202402211449.401382D2AF@keescook>
 <4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk@b6ig5v2pxe5i>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk@b6ig5v2pxe5i>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=TMkb2jGH;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::633
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

On Wed, Feb 21, 2024 at 06:29:17PM -0500, Kent Overstreet wrote:
> On Wed, Feb 21, 2024 at 03:05:32PM -0800, Kees Cook wrote:
> > On Wed, Feb 21, 2024 at 11:40:27AM -0800, Suren Baghdasaryan wrote:
> > > [...]
> > > +struct alloc_tag {
> > > +	struct codetag			ct;
> > > +	struct alloc_tag_counters __percpu	*counters;
> > > +} __aligned(8);
> > > [...]
> > > +#define DEFINE_ALLOC_TAG(_alloc_tag)						\
> > > +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> > > +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> > > +	__section("alloc_tags") = {						\
> > > +		.ct = CODE_TAG_INIT,						\
> > > +		.counters = &_alloc_tag_cntr };
> > > [...]
> > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> > > +{
> > > +	swap(current->alloc_tag, tag);
> > > +	return tag;
> > > +}
> > 
> > Future security hardening improvement idea based on this infrastructure:
> > it should be possible to implement per-allocation-site kmem caches. For
> > example, we could create:
> > 
> > struct alloc_details {
> > 	u32 flags;
> > 	union {
> > 		u32 size; /* not valid after __init completes */
> > 		struct kmem_cache *cache;
> > 	};
> > };
> > 
> > - add struct alloc_details to struct alloc_tag
> > - move the tags section into .ro_after_init
> > - extend alloc_hooks() to populate flags and size:
> > 	.flags = __builtin_constant_p(size) ? KMALLOC_ALLOCATE_FIXED
> > 					    : KMALLOC_ALLOCATE_BUCKETS;
> > 	.size = __builtin_constant_p(size) ? size : SIZE_MAX;
> > - during kernel start or module init, walk the alloc_tag list
> >   and create either a fixed-size kmem_cache or to allocate a
> >   full set of kmalloc-buckets, and update the "cache" member.
> > - adjust kmalloc core routines to use current->alloc_tag->cache instead
> >   of using the global buckets.
> > 
> > This would get us fully separated allocations, producing better than
> > type-based levels of granularity, exceeding what we have currently with
> > CONFIG_RANDOM_KMALLOC_CACHES.
> > 
> > Does this look possible, or am I misunderstanding something in the
> > infrastructure being created here?
> 
> Definitely possible, but... would we want this?

Yes, very very much. One of the worst and mostly unaddressed weaknesses
with the kernel right now is use-after-free based type confusion[0], which
depends on merged caches (or cache reuse).

This doesn't solve cross-allocator (kmalloc/page_alloc) type confusion
(as terrifyingly demonstrated[1] by Jann Horn), but it does help with
what has been a very common case of "use msg_msg to impersonate your
target object"[2] exploitation.

> That would produce a _lot_ of kmem caches

Fewer than you'd expect, but yes, there is some overhead. However,
out-of-tree forks of Linux have successfully experimented with this
already and seen good results[3].

> and don't we already try to collapse those where possible to reduce
> internal fragmentation?

In the past, yes, but the desire for security has tended to have more
people building with SLAB_MERGE_DEFAULT=n and/or CONFIG_RANDOM_KMALLOC_CACHES=y
(or booting with "slab_nomerge").

Just doing the type safety isn't sufficient without the cross-allocator
safety, but we've also had solutions for that proposed[4].

-Kees

[0] https://github.com/KSPP/linux/issues/189
[1] https://googleprojectzero.blogspot.com/2021/10/how-simple-linux-kernel-memory.html
[2] https://www.willsroot.io/2021/08/corctf-2021-fire-of-salvation-writeup.html
    https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html#exploring-struct-msg_msg
[3] https://grsecurity.net/how_autoslab_changes_the_memory_unsafety_game
[4] https://lore.kernel.org/linux-hardening/20230915105933.495735-1-matteorizzo@google.com/

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402211608.41AD94094%40keescook.
