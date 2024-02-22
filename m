Return-Path: <kasan-dev+bncBCF5XGNWYQBRBGFY3KXAMGQEYOV5CRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C11E85EE5A
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Feb 2024 01:58:02 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-42e16ec3492sf42165581cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 16:58:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708563481; cv=pass;
        d=google.com; s=arc-20160816;
        b=cqdR/ji9GXOh3qCCYraJ9MUJ6BqN4M22C0VElAi0HXbcu98qMG9qelWxYKeeqybn/N
         GBVUL8QHnOUtlm3pVpmK9wJFclq4DpQ/CkuMSE2TpI+zwHhxMvexOGeshEQpmbU1q/cT
         lZpK4hFhxkuNOLK2mPizQSSsR0MToP8+XNtfx9nig/xMKbha6pMVAUVgD9ggC2BaOLhx
         V9P+e56GI5NF1DKSboXXbkyKGHzrvE6Dfa2cykPP1zpdepWkh3gEHsVrDUh/5kAnMlpt
         acj+AsAsP4t35zfT1swhlf3bTTSlyWb+akl8VqVJhcrrr5zOcR9T+RjUx4mhq2ho7bcX
         jlQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=75btHEYVgx2kjhY71dGo/3Vqb+lQg4K0MfZCq0BpjV8=;
        fh=fN1u73jv7h+kyc2NXVpc2Vg6R7VscxQXPukS2KZF3Tk=;
        b=MzohXPxFWTr1ui/lXmaOI1kABr6jdQgOvPHHeZ1eZUUahdlSnWCuT8m84Awhz6pHxM
         jh5lfczei9LaHQu195q8r2+YadaSc+OAE+k/7+b8sgiHMScK6jPV0IH3DI0k+aSZV7Sp
         MYbPsWT4twMbSu6wqi1pWaHtCIdz+nzj1RM764e31Wjfwgi/j7jewoqsJA6+LiNY7+yl
         u8wNAgmxEG5RMgIcRiB0qbnHaTBjb4l4zbA/yzfkdRrDYzPmyZO6L1U0bjd4wTjLHL8a
         9ifPXEmCBS8ETEZaUpl8n1ytwfchExQbBjghRZUbzwZO51p7VHtDoYnYgvrSSW6MeRW9
         4EMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="kMBuc//Q";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708563481; x=1709168281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=75btHEYVgx2kjhY71dGo/3Vqb+lQg4K0MfZCq0BpjV8=;
        b=MXXuPtG89QYkBw0ThhIoF+nwY0TY8OPhx31LAbjL1Yy1woGkGoOQ8VECCbVZtnw5ha
         JyffCeD+Idk/V0ESsdJ16MV7KrecSOvM5NhPCKn5C9o7bbc+MzRI/e2P4qo8++pzAttt
         4u6SmV8tc79av5Gjhnw1AFpRRYvN5SrcRVcAlKoIku2ckUB05O2MdWCFtFUO+cbT9jYu
         dIQyphZehrmKOslMSuuBvhMrT6hzRczCOHKzhNTLWJR3VYE1lfaVSo1Diik4aO28F0Hb
         7D46YK8+8WpAnkNQYUSOsk/8YI1G4Gsg82fnlm5crTmiICsGlIJ2OLUkPDsm1S1jJvYr
         7oaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708563481; x=1709168281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=75btHEYVgx2kjhY71dGo/3Vqb+lQg4K0MfZCq0BpjV8=;
        b=b5KH3NUlgc/QYu3+RTG/cqEIBU3VyZ+SBJ9OWMKWADOjM6nCBfhB8Eie6GXzv7HGCQ
         g6k1Ui3zPMf4JRRJv/HsefwTDQ+MJT1ZP+m12JGtqstG05vUM8NJnmVKWPfnLrFisYFj
         k993Nq8hECZrzfv/NFvm2QN6L+aljqWXHJNlj34EAx/Hb0FI/lMqMeuQDxjeddq19fI5
         qdPce1orTPskSjyo9DUoMCLuNpOTWCZzcQNBuY0iry9okjBCZz+KHmbeiEqyb7ljgTOJ
         2qaVF8khiGeu7MmTDD4hlQMKHn4TGMzymc1rmlEtizjVxzSqVrvoycVt0YyOr6hrusM7
         EsGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQ4N9Z4aFqQQW0lKSEia2OIRnItVwksqAr55VpmEC2YTZAqfa5chbqkjAy2TT9R2PqlqAEdGuqd2v1AaD8MdOhX9nAAQypew==
X-Gm-Message-State: AOJu0Yzjw0oZgcBhKjwIA8w+KzNecQkH/wrbcm+cnjPI0qyc3Y188cl9
	E+ldrYk+iJ6XeeFc8ZBFLRBaWveU8zWw/PV88kzjlKa3kpxoGise
X-Google-Smtp-Source: AGHT+IH+Ll+T3buya/vEIlxo/ta21TLR+EwhuOLuiR9j7WyTfUGv4tF5kpULZw2UENlaMMOYzKBeYw==
X-Received: by 2002:ac8:58d2:0:b0:42c:63ba:2685 with SMTP id u18-20020ac858d2000000b0042c63ba2685mr21563237qta.60.1708563480963;
        Wed, 21 Feb 2024 16:58:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5b81:0:b0:42e:490d:91e7 with SMTP id a1-20020ac85b81000000b0042e490d91e7ls338376qta.2.-pod-prod-07-us;
 Wed, 21 Feb 2024 16:58:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzn6pb6uK8e6bvD71FDkT30QC8tFHj5jYQwHt73/uJf13bKVvO1M62mtotkR78RxgLerwnZZPnye7Mq1qVLNCzMmIeVnSahR8VHQ==
X-Received: by 2002:ac8:7d13:0:b0:42e:4340:735a with SMTP id g19-20020ac87d13000000b0042e4340735amr1921427qtb.64.1708563480353;
        Wed, 21 Feb 2024 16:58:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708563480; cv=none;
        d=google.com; s=arc-20160816;
        b=oZEbYJVYE3jCgFGuLSUUrT3EEi4MVkaCyCV6K2lBEspv/fhu/b9s2GW0FU6I5HS707
         vyD0ok86TXmGforRiQ2EwsSNDlvhuCVtbDFYaN1Sxu4x6+GxL3XrIEt8/tWdZH8g2IRG
         V5+BArJNLRQWMf8HR4fnK7uq1cwYdum82XNlSUh8D893OiyP0PbtyR8ni72RbS2GqxJI
         nAzC3TCBU6M4lvdlvk4jxsZpoTtypuz6CuE455NBegUKGWG5yzBlyKLjIb7haKVfe/aH
         qUn7lsg/ZIVtyBgc0YRm9HxtJkFptBXg8gbnP1EXF1W+3WBFabiAE4Nl7ZXmwf9ZupEt
         9Lvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ulpOkHFvivSSE+e2M3yzbCAjenVPYV9xC3Luo/BV0yQ=;
        fh=PC+Wov7k+41vFTxvNbYjanv7DHjDernDFEgUMvg4wH4=;
        b=LWkG1z/3KHumGutAvUDxMyrbKzizbCbiGHFUzASVH1OWmaMH6zsuSc3mOnKNewH+yR
         jhKY/PbUBCy/VKHMVqGjUEkvMyNKBtd+0Mf/04C4Wyq8t+QSBCAL//EIMk5AxBmOf89Y
         M8xKzgiHj/+h+mCSoksSdgDisEzX+Z96BSJ8nFOA5ZI+xvPuKFE9pxbPAlMrW0g6RRIF
         vUbzMDJDO8cXKPZffWB3vEDA28m4qZndD740OTLDQ9GGWJZTgYFL4Qc40ICsQFIIKFnt
         GTjEkM5i0xASOjDs8ucEbjc8kaA2r/nr7kvyY41AGnIcp8SKi0eY9UpmR4UnyUYD8sjK
         WodQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="kMBuc//Q";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id r16-20020ac84250000000b0042db456496esi718755qtm.3.2024.02.21.16.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Feb 2024 16:58:00 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1dc0d11d1b7so28418955ad.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Feb 2024 16:58:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU2HxWsfUiJFhSm/Ht9lpCuXBEe4G2KgW6mSNIZYKHzKT2Bl0hW6XmXfwhYA5swuXFXDTXLDhz5msgP3HzyeoVWcZWTTW+FciPNSg==
X-Received: by 2002:a17:902:6504:b0:1dc:4aa1:df32 with SMTP id b4-20020a170902650400b001dc4aa1df32mr476220plk.14.1708563479629;
        Wed, 21 Feb 2024 16:57:59 -0800 (PST)
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id l9-20020a170902eb0900b001db63cfe07dsm8723498plb.283.2024.02.21.16.57.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 16:57:59 -0800 (PST)
Date: Wed, 21 Feb 2024 16:57:58 -0800
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
Message-ID: <202402211656.C3644FB@keescook>
References: <20240221194052.927623-1-surenb@google.com>
 <20240221194052.927623-15-surenb@google.com>
 <202402211449.401382D2AF@keescook>
 <4vwiwgsemga7vmahgwsikbsawjq5xfskdsssmjsfe5hn7k2alk@b6ig5v2pxe5i>
 <202402211608.41AD94094@keescook>
 <vxx2o2wdcqjkxauglu7ul52mygu4tti2i3yc2dvmcbzydvgvu2@knujflwtakni>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <vxx2o2wdcqjkxauglu7ul52mygu4tti2i3yc2dvmcbzydvgvu2@knujflwtakni>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="kMBuc//Q";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
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

On Wed, Feb 21, 2024 at 07:34:44PM -0500, Kent Overstreet wrote:
> On Wed, Feb 21, 2024 at 04:25:02PM -0800, Kees Cook wrote:
> > On Wed, Feb 21, 2024 at 06:29:17PM -0500, Kent Overstreet wrote:
> > > On Wed, Feb 21, 2024 at 03:05:32PM -0800, Kees Cook wrote:
> > > > On Wed, Feb 21, 2024 at 11:40:27AM -0800, Suren Baghdasaryan wrote:
> > > > > [...]
> > > > > +struct alloc_tag {
> > > > > +	struct codetag			ct;
> > > > > +	struct alloc_tag_counters __percpu	*counters;
> > > > > +} __aligned(8);
> > > > > [...]
> > > > > +#define DEFINE_ALLOC_TAG(_alloc_tag)						\
> > > > > +	static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr);	\
> > > > > +	static struct alloc_tag _alloc_tag __used __aligned(8)			\
> > > > > +	__section("alloc_tags") = {						\
> > > > > +		.ct = CODE_TAG_INIT,						\
> > > > > +		.counters = &_alloc_tag_cntr };
> > > > > [...]
> > > > > +static inline struct alloc_tag *alloc_tag_save(struct alloc_tag *tag)
> > > > > +{
> > > > > +	swap(current->alloc_tag, tag);
> > > > > +	return tag;
> > > > > +}
> > > > 
> > > > Future security hardening improvement idea based on this infrastructure:
> > > > it should be possible to implement per-allocation-site kmem caches. For
> > > > example, we could create:
> > > > 
> > > > struct alloc_details {
> > > > 	u32 flags;
> > > > 	union {
> > > > 		u32 size; /* not valid after __init completes */
> > > > 		struct kmem_cache *cache;
> > > > 	};
> > > > };
> > > > 
> > > > - add struct alloc_details to struct alloc_tag
> > > > - move the tags section into .ro_after_init
> > > > - extend alloc_hooks() to populate flags and size:
> > > > 	.flags = __builtin_constant_p(size) ? KMALLOC_ALLOCATE_FIXED
> > > > 					    : KMALLOC_ALLOCATE_BUCKETS;
> > > > 	.size = __builtin_constant_p(size) ? size : SIZE_MAX;
> > > > - during kernel start or module init, walk the alloc_tag list
> > > >   and create either a fixed-size kmem_cache or to allocate a
> > > >   full set of kmalloc-buckets, and update the "cache" member.
> > > > - adjust kmalloc core routines to use current->alloc_tag->cache instead
> > > >   of using the global buckets.
> > > > 
> > > > This would get us fully separated allocations, producing better than
> > > > type-based levels of granularity, exceeding what we have currently with
> > > > CONFIG_RANDOM_KMALLOC_CACHES.
> > > > 
> > > > Does this look possible, or am I misunderstanding something in the
> > > > infrastructure being created here?
> > > 
> > > Definitely possible, but... would we want this?
> > 
> > Yes, very very much. One of the worst and mostly unaddressed weaknesses
> > with the kernel right now is use-after-free based type confusion[0], which
> > depends on merged caches (or cache reuse).
> > 
> > This doesn't solve cross-allocator (kmalloc/page_alloc) type confusion
> > (as terrifyingly demonstrated[1] by Jann Horn), but it does help with
> > what has been a very common case of "use msg_msg to impersonate your
> > target object"[2] exploitation.
> 
> We have a ton of code that references PAGE_SIZE and uses the page
> allocator completely unnecessarily - that's something worth harping
> about at conferences; if we could motivate people to clean that stuff up
> it'd have a lot of positive effects.
> 
> > > That would produce a _lot_ of kmem caches
> > 
> > Fewer than you'd expect, but yes, there is some overhead. However,
> > out-of-tree forks of Linux have successfully experimented with this
> > already and seen good results[3].
> 
> So in that case - I don't think there's any need for a separate
> alloc_details; we'd just add a kmem_cache * to alloc_tag and then hook
> into the codetag init/unload path to create and destroy the kmem caches.

Okay, sounds good. There needs to be a place to track "is this a fixed
size or a run-time size" choice.

> No need to adjust the slab code either; alloc_hooks() itself could
> dispatch to kmem_cache_alloc() instead of kmalloc() if this is in use.

Right, it'd go to either kmem_cache_alloc() directly, or to a modified
kmalloc() that used the passed-in cache is the base for an array of sized
buckets, rather than the global (or 16-way global) buckets.

Yay for the future!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402211656.C3644FB%40keescook.
