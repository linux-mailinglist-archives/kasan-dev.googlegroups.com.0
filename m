Return-Path: <kasan-dev+bncBCF5XGNWYQBRBWGFVKXAMGQE223XKYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5FD508521D5
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 23:59:38 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-59a18ecf836sf4366147eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 14:59:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707778777; cv=pass;
        d=google.com; s=arc-20160816;
        b=tIAjvLRrh7Y6FWtHpvCpNfvXYWlZXsQvIyNOOkZc3UCK3PrK1kwS05tE93u+hqdv11
         P6C4T2MVPfCSwNGRUN0ZSate7D8+F4aBplDpsdr3g6AUhrD/LBhsFE1mfl3MZ1jE7m12
         fRi+8zXys7KUniyPu0zYAp257OWdu0S1Ymw571/gKhK3tkP/zBQ2w9WZNMxEM/zmpk/5
         dPZWUuONdg2MfSRhbJlesVmDCVBbzRi5JtADe9TKVMZO7tZmFedfMTjXJMpfCVTI4JKX
         L5L9Z+mfmp/ASxFZ2kPmTh3ALKXTkazlfqRlYOWDvNqntubGP9F+whBj27iJsW2xXGva
         X6qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=8Bf7M/SJeYSjn5UVL/X0n1sIWmXyT53im1I9WEdMtyM=;
        fh=fKy2yc5Df8sGkcp3BeXQu+aqyLaUw6sCT1IsxoN1384=;
        b=hdJDXMgYNkb7ewW8TH2CueH3uNRN7n7Rc2X6hGQjlSjhQ6Bmi8+pJN0cbwzDR39DUR
         4huDYtoykshqiC1zaCUYOEkl9mc036Li6Rfp2VXHKk2+i+t9E6slyBLHYC/1LsgEQxeJ
         QqBX4DSZDt2npWxDEkTH2D9Z957cVeO76IoMfST7vSVP8ofG1VMKMwARFKH2siudux4+
         3XVYbHnhB0AK9WJVougcenaiEuLNFuOt3Lw1EbPMp2V2e7Ll89f/9LBLVc/M+y8Ixt6t
         Ej5X4I6OIilKJOGkDBv2Dh9UVWaqQpORTgTcgFFs87JbcTnLqVkm3lgaNBWABxomNOnF
         6G1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QK4xkrDV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707778777; x=1708383577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Bf7M/SJeYSjn5UVL/X0n1sIWmXyT53im1I9WEdMtyM=;
        b=FlngLeTMBjd6T1jvnxZvOKFnU5ColOwVFQeeAkh3scjqghl3M04zDOOrWxIFsd9EWg
         IJnGjRdSlJJdsDEbmbBjUi9DnMKARrJ9anSWMRal0jVtPY7cbGRngGyIXDPVpUpjejVh
         Yo7x7/OQYMysVkBa/7V33pt1sy9eNQ/M0VTs/HluNVZ3Uwxoql2FVdgpRN04el0NBEm9
         5DVrMTJ/1iSqSVGrtLnTG7mknYNhRq3PpKdi02DmaXiJOJ9kgTdkw288NN3ejK7OMjMh
         hMFAwk/m5MKsK4zUl1ljYwJl6v/GjLF6MA6cd8dClg4EpvWanj82h3FMjAKBcDGazgco
         G3aA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707778777; x=1708383577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8Bf7M/SJeYSjn5UVL/X0n1sIWmXyT53im1I9WEdMtyM=;
        b=toWY6s0WUXAg/2zX7RJV13+5j5HfDoeaNbCtM/UQfJyG0Tuf81CHMPKoF5GB+Gvmjb
         p5HrzT5ZSmDdbzIBrtt1tKk0Lu8RGig4VRVRexdUKw57CmFbAYkgwKcj3Q2HeRsPSb5u
         cyInlEbmXGrt7+1ZxuN1fv258OcBtPItBHmk9hww15J3nQj7DWX6NDnXJsvJMnHZt4nX
         9ql9kIu9LxdDE1CKpH62jiqAAkw0Yw4YsbRFbXwa0gZJ4lazaGRd7/Y6dfLLautA4meI
         qo8wxqSxvqeMVOqEAup2AKpSKkjG1QFvDPDOHC9XklwiCzd6TZ7+2he4XMzVd0SxiZwc
         LSPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyKK93mDoRQjFeCJ7zJiGgAZy8jnnNaQxcOJzi42k/J1+uSNjuq
	9x4ES7NAONU1kqIgNSk4rKwGZXsH+5DZcolzej86+2T0LxsR1WCq
X-Google-Smtp-Source: AGHT+IE6q7cSz61o53OU8JAkIgg+jTUJJJqvX0cjQPNjgZCV23YHaBxmXcrVSNhXijhlFt2uu+6klA==
X-Received: by 2002:a4a:625b:0:b0:59d:57b8:8b7b with SMTP id y27-20020a4a625b000000b0059d57b88b7bmr3569673oog.3.1707778777094;
        Mon, 12 Feb 2024 14:59:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:af08:0:b0:598:dc0d:33b6 with SMTP id w8-20020a4aaf08000000b00598dc0d33b6ls3178060oon.2.-pod-prod-03-us;
 Mon, 12 Feb 2024 14:59:36 -0800 (PST)
X-Received: by 2002:a9d:6486:0:b0:6e2:d547:ccc with SMTP id g6-20020a9d6486000000b006e2d5470cccmr7878669otl.19.1707778776310;
        Mon, 12 Feb 2024 14:59:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707778776; cv=none;
        d=google.com; s=arc-20160816;
        b=qwpQP7povVO4qJxU7/JJ41eyJyWHrQstOijPvSMz6YNvIRBFnPp6jWlVDipxL4WhFK
         YRoIhZGucLRhaaALGTTGIcpPS5NTLti5S4YBPBcmWwtmfoVpDdq7/Nn1Fq1mshbIJHxq
         +/e1XXgwYP7WtxwqOS+Q8rxCnpKg7a90H1slg0CJJHh2iVogmdqVb3L3kf6Q3MS3u2/u
         WbNCYbE1f9ykcPGee4rAHnVGuD7hVyoYsO5MNws1QsQpERpdIHNSiVE9z2AB7uDC8NBE
         A6bd7Ay+Abafu4G6o7pgAzp0fWO24ML5DCAONNyOyED7stqsRFt6t17ghyY0eBXHXMg0
         8DfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=cK/4hrivw4h5tLS29gd+rDqZ0u3L8uHk5jM+4TIOhzA=;
        fh=fKy2yc5Df8sGkcp3BeXQu+aqyLaUw6sCT1IsxoN1384=;
        b=N/o1GU6OX/r0NXx4k6emvSXyM9yHONTUuago42p0oYn2LWRNAtghhxyY4bMhfRQKSG
         EFVUPeYHDYbvlmbR7J9PFesP0ShZn45HwlXUYGU/hETHTB/2f/ic/WZm1a/9MzC41NWl
         N0WB7etsxRFFfJ98oxP0alEeekDLT6QDQkaW8n4sRxKIdVKfBPSWvUOF4EF8QC8m4b5R
         3pmDbJ9KrxSH5GDsSnDoxafO+AIm+64A28h3s4T65Z3Ne0pQth1OMFIAPVpXTY+fOEyq
         9kgiSElbf/a4QiScqlG2/ZWoAquvTl9Unmzlc5Y3CLKYPygIzwKFjcM26iRI4LcGIzoa
         qfYg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=QK4xkrDV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
X-Forwarded-Encrypted: i=1; AJvYcCXXwq+ZsRLaz75WuLX2vyGZA1hhTMmVfbjor3u23UnScfzKITuOkukXKKvgec4TGh62DNWuSteUNtIOQ95Kv7XRHmsr+gvihkcCNg==
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id a26-20020a9d471a000000b006e2dc907d04si134006otf.2.2024.02.12.14.59.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 14:59:36 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-1d93edfa76dso30044245ad.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 14:59:36 -0800 (PST)
X-Received: by 2002:a17:902:d48b:b0:1d9:b5d8:854c with SMTP id c11-20020a170902d48b00b001d9b5d8854cmr9936488plg.58.1707778775229;
        Mon, 12 Feb 2024 14:59:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVNardpvwereV4FQHzQFLtod9BM5VLLL7JIz7/hRKNZr4lHFlyQGhbj3q2taJVUlTcqIhLMO51Y17U3ESBCcqzATSZCDUKdLoQi+hs5gETVV5Pn+oxF3w/Hbzj3/u7hfFS3vBjgI2qPeqXeHgWxK29hPaK3ThuzFKVCpIRQT595X5KGpXawf9I4NVpN4C5WS+w5NBhDap9iQ7FdTRV9PF/vqOmiG6sL36tmgefnEi/kPiAvW5G/Qmrc1v3dV5/yNqKNEBdZBK59KmVbp9NEuZgQiY7lScwfqL2/Y0TKftZLuHBhfyafg0tWs3rkKv8dwxEMSeqPkp47u1sBU9wCiiS47zQ2OBLNKAKD2NSZjI+973FCmVLHpu4BjZjcd6b/C24su/9hFjtPGFw1JEAe8z7ZzfFzR4YBxwSOS6EV7lBNYvOozWhHflOZpLfXEbRrWZCYmZ6z0v/chEldRv+E5YMws8xDbNHSbsRX8Fz/ah5VdlTh33fdYu7JbLucms8C4tNnu9Oxf4ihKgS5QAyE7MwYKqw0lRX9aSBFlhz6yLiGYvcuPyKrvpHnwzYYOBXB5QbvP7oXouqatYjPPLChqaGAmDNpKCqLOL1V31YJlIzKRMYkhXwza7NwShk4D4yscaN2bBePbXEHA7BCk402IkTD/IxoGqW67bDvkQGWUlyY7SAGpiMkn+JO8uR1R0GL5vm9h62i1iivjGgCdp1XGfVLj9yoLfIjZaFsXSVt7dp0fEVbDeGuOvuR9gJFGQWTFhjfqaQT64Tkfk0MbqSSp4GW59ybd1phXO6GDS1sm2QpfTahqAwl6R0m5hJ6rqwBBLvjSzrvqBxO21ifBRixzaH1Nq0JpE/a2QDtGsD7UfSvPFLpVLuOLMw5CfH7jbY/B4Npd98i30QtnJ5aW5K88FkGRGdV99tjBZj+9TNMX7jT6UBjMjztLu+CEoZ5JbxBOq0AwO
 Hl3+bOH5fyCsYeo/LwpnzKnnsxMtE7YTvDIaxyI6XcI+WWNDiBafaDCt9Rwe6o9eO6C3PoNwJ/80LG3ehYK0w4J5RWt4DKzG2k3d+eeNCa+uAK65RW45xchlKnX3wZ5ysmI1IwhyABK3QdUgmpCPzE/tXerFa7o0m9X9UgUIHw3Ep6vBn6FQ0eCh4FJNLOhAx3osq7dssrBIwIuyoYrEg4zDAZrInuyUwU6Mz8TR3nhUwutIF69wj4L01G4shK7RIrLiXljVk0Li7t2djdsku4Dmr1akyEOscaTLc1cURWcAvogn5sKxvcW6+ZcmaGm4r4C0GegsyF/1VnDACphX/zIYuYe3Gr6NHnNn/vbGeCrWgILxuI7ooxcgd8lVXR6Fo2VTnFhrylYNqcYnfrCBtLWcKGgQ3+eU7XmbH2zlgm01QRpvqkehDT2wGggKc=
Received: from www.outflux.net ([198.0.35.241])
        by smtp.gmail.com with ESMTPSA id u12-20020a170902b28c00b001d8f393f3cfsm820482plr.248.2024.02.12.14.59.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Feb 2024 14:59:35 -0800 (PST)
Date: Mon, 12 Feb 2024 14:59:33 -0800
From: Kees Cook <keescook@chromium.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com,
	peterz@infradead.org, juri.lelli@redhat.com,
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
Subject: Re: [PATCH v3 17/35] mm: enable page allocation tagging
Message-ID: <202402121458.A4A62E62B@keescook>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-18-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240212213922.783301-18-surenb@google.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=QK4xkrDV;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
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

On Mon, Feb 12, 2024 at 01:39:03PM -0800, Suren Baghdasaryan wrote:
> Redefine page allocators to record allocation tags upon their invocation.
> Instrument post_alloc_hook and free_pages_prepare to modify current
> allocation tag.
> 
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> ---
>  include/linux/alloc_tag.h |  10 +++
>  include/linux/gfp.h       | 126 ++++++++++++++++++++++++--------------
>  include/linux/pagemap.h   |   9 ++-
>  mm/compaction.c           |   7 ++-
>  mm/filemap.c              |   6 +-
>  mm/mempolicy.c            |  52 ++++++++--------
>  mm/page_alloc.c           |  60 +++++++++---------
>  7 files changed, 160 insertions(+), 110 deletions(-)
> 
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> index cf55a149fa84..6fa8a94d8bc1 100644
> --- a/include/linux/alloc_tag.h
> +++ b/include/linux/alloc_tag.h
> @@ -130,4 +130,14 @@ static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_tag *tag,
>  
>  #endif
>  
> +#define alloc_hooks(_do_alloc)						\
> +({									\
> +	typeof(_do_alloc) _res;						\
> +	DEFINE_ALLOC_TAG(_alloc_tag, _old);				\
> +									\
> +	_res = _do_alloc;						\
> +	alloc_tag_restore(&_alloc_tag, _old);				\
> +	_res;								\
> +})

I am delighted to see that __alloc_size survives this indirection.
AFAICT, all the fortify goo continues to work with this in use.

Reviewed-by: Kees Cook <keescook@chromium.org>

-Kees


> +
>  #endif /* _LINUX_ALLOC_TAG_H */
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index de292a007138..bc0fd5259b0b 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -6,6 +6,8 @@
>  
>  #include <linux/mmzone.h>
>  #include <linux/topology.h>
> +#include <linux/alloc_tag.h>
> +#include <linux/sched.h>
>  
>  struct vm_area_struct;
>  struct mempolicy;
> @@ -175,42 +177,46 @@ static inline void arch_free_page(struct page *page, int order) { }
>  static inline void arch_alloc_page(struct page *page, int order) { }
>  #endif
>  
> -struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
> +struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
>  		nodemask_t *nodemask);
> -struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
> +#define __alloc_pages(...)			alloc_hooks(__alloc_pages_noprof(__VA_ARGS__))
> +
> +struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
>  		nodemask_t *nodemask);
> +#define __folio_alloc(...)			alloc_hooks(__folio_alloc_noprof(__VA_ARGS__))
>  
> -unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
> +unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
>  				nodemask_t *nodemask, int nr_pages,
>  				struct list_head *page_list,
>  				struct page **page_array);
> +#define __alloc_pages_bulk(...)			alloc_hooks(alloc_pages_bulk_noprof(__VA_ARGS__))
>  
> -unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
> +unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
>  				unsigned long nr_pages,
>  				struct page **page_array);
> +#define  alloc_pages_bulk_array_mempolicy(...)				\
> +	alloc_hooks(alloc_pages_bulk_array_mempolicy_noprof(__VA_ARGS__))
>  
>  /* Bulk allocate order-0 pages */
> -static inline unsigned long
> -alloc_pages_bulk_list(gfp_t gfp, unsigned long nr_pages, struct list_head *list)
> -{
> -	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, list, NULL);
> -}
> +#define alloc_pages_bulk_list(_gfp, _nr_pages, _list)			\
> +	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, _list, NULL)
>  
> -static inline unsigned long
> -alloc_pages_bulk_array(gfp_t gfp, unsigned long nr_pages, struct page **page_array)
> -{
> -	return __alloc_pages_bulk(gfp, numa_mem_id(), NULL, nr_pages, NULL, page_array);
> -}
> +#define alloc_pages_bulk_array(_gfp, _nr_pages, _page_array)		\
> +	__alloc_pages_bulk(_gfp, numa_mem_id(), NULL, _nr_pages, NULL, _page_array)
>  
>  static inline unsigned long
> -alloc_pages_bulk_array_node(gfp_t gfp, int nid, unsigned long nr_pages, struct page **page_array)
> +alloc_pages_bulk_array_node_noprof(gfp_t gfp, int nid, unsigned long nr_pages,
> +				   struct page **page_array)
>  {
>  	if (nid == NUMA_NO_NODE)
>  		nid = numa_mem_id();
>  
> -	return __alloc_pages_bulk(gfp, nid, NULL, nr_pages, NULL, page_array);
> +	return alloc_pages_bulk_noprof(gfp, nid, NULL, nr_pages, NULL, page_array);
>  }
>  
> +#define alloc_pages_bulk_array_node(...)				\
> +	alloc_hooks(alloc_pages_bulk_array_node_noprof(__VA_ARGS__))
> +
>  static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
>  {
>  	gfp_t warn_gfp = gfp_mask & (__GFP_THISNODE|__GFP_NOWARN);
> @@ -230,82 +236,104 @@ static inline void warn_if_node_offline(int this_node, gfp_t gfp_mask)
>   * online. For more general interface, see alloc_pages_node().
>   */
>  static inline struct page *
> -__alloc_pages_node(int nid, gfp_t gfp_mask, unsigned int order)
> +__alloc_pages_node_noprof(int nid, gfp_t gfp_mask, unsigned int order)
>  {
>  	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
>  	warn_if_node_offline(nid, gfp_mask);
>  
> -	return __alloc_pages(gfp_mask, order, nid, NULL);
> +	return __alloc_pages_noprof(gfp_mask, order, nid, NULL);
>  }
>  
> +#define  __alloc_pages_node(...)		alloc_hooks(__alloc_pages_node_noprof(__VA_ARGS__))
> +
>  static inline
> -struct folio *__folio_alloc_node(gfp_t gfp, unsigned int order, int nid)
> +struct folio *__folio_alloc_node_noprof(gfp_t gfp, unsigned int order, int nid)
>  {
>  	VM_BUG_ON(nid < 0 || nid >= MAX_NUMNODES);
>  	warn_if_node_offline(nid, gfp);
>  
> -	return __folio_alloc(gfp, order, nid, NULL);
> +	return __folio_alloc_noprof(gfp, order, nid, NULL);
>  }
>  
> +#define  __folio_alloc_node(...)		alloc_hooks(__folio_alloc_node_noprof(__VA_ARGS__))
> +
>  /*
>   * Allocate pages, preferring the node given as nid. When nid == NUMA_NO_NODE,
>   * prefer the current CPU's closest node. Otherwise node must be valid and
>   * online.
>   */
> -static inline struct page *alloc_pages_node(int nid, gfp_t gfp_mask,
> -						unsigned int order)
> +static inline struct page *alloc_pages_node_noprof(int nid, gfp_t gfp_mask,
> +						   unsigned int order)
>  {
>  	if (nid == NUMA_NO_NODE)
>  		nid = numa_mem_id();
>  
> -	return __alloc_pages_node(nid, gfp_mask, order);
> +	return __alloc_pages_node_noprof(nid, gfp_mask, order);
>  }
>  
> +#define  alloc_pages_node(...)			alloc_hooks(alloc_pages_node_noprof(__VA_ARGS__))
> +
>  #ifdef CONFIG_NUMA
> -struct page *alloc_pages(gfp_t gfp, unsigned int order);
> -struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
> +struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order);
> +struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
>  		struct mempolicy *mpol, pgoff_t ilx, int nid);
> -struct folio *folio_alloc(gfp_t gfp, unsigned int order);
> -struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
> +struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order);
> +struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
>  		unsigned long addr, bool hugepage);
>  #else
> -static inline struct page *alloc_pages(gfp_t gfp_mask, unsigned int order)
> +static inline struct page *alloc_pages_noprof(gfp_t gfp_mask, unsigned int order)
>  {
> -	return alloc_pages_node(numa_node_id(), gfp_mask, order);
> +	return alloc_pages_node_noprof(numa_node_id(), gfp_mask, order);
>  }
> -static inline struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
> +static inline struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
>  		struct mempolicy *mpol, pgoff_t ilx, int nid)
>  {
> -	return alloc_pages(gfp, order);
> +	return alloc_pages_noprof(gfp, order);
>  }
> -static inline struct folio *folio_alloc(gfp_t gfp, unsigned int order)
> +static inline struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
>  {
>  	return __folio_alloc_node(gfp, order, numa_node_id());
>  }
> -#define vma_alloc_folio(gfp, order, vma, addr, hugepage)		\
> -	folio_alloc(gfp, order)
> +#define vma_alloc_folio_noprof(gfp, order, vma, addr, hugepage)		\
> +	folio_alloc_noprof(gfp, order)
>  #endif
> +
> +#define alloc_pages(...)			alloc_hooks(alloc_pages_noprof(__VA_ARGS__))
> +#define alloc_pages_mpol(...)			alloc_hooks(alloc_pages_mpol_noprof(__VA_ARGS__))
> +#define folio_alloc(...)			alloc_hooks(folio_alloc_noprof(__VA_ARGS__))
> +#define vma_alloc_folio(...)			alloc_hooks(vma_alloc_folio_noprof(__VA_ARGS__))
> +
>  #define alloc_page(gfp_mask) alloc_pages(gfp_mask, 0)
> -static inline struct page *alloc_page_vma(gfp_t gfp,
> +
> +static inline struct page *alloc_page_vma_noprof(gfp_t gfp,
>  		struct vm_area_struct *vma, unsigned long addr)
>  {
> -	struct folio *folio = vma_alloc_folio(gfp, 0, vma, addr, false);
> +	struct folio *folio = vma_alloc_folio_noprof(gfp, 0, vma, addr, false);
>  
>  	return &folio->page;
>  }
> +#define alloc_page_vma(...)			alloc_hooks(alloc_page_vma_noprof(__VA_ARGS__))
> +
> +extern unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order);
> +#define __get_free_pages(...)			alloc_hooks(get_free_pages_noprof(__VA_ARGS__))
>  
> -extern unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order);
> -extern unsigned long get_zeroed_page(gfp_t gfp_mask);
> +extern unsigned long get_zeroed_page_noprof(gfp_t gfp_mask);
> +#define get_zeroed_page(...)			alloc_hooks(get_zeroed_page_noprof(__VA_ARGS__))
> +
> +void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask) __alloc_size(1);
> +#define alloc_pages_exact(...)			alloc_hooks(alloc_pages_exact_noprof(__VA_ARGS__))
>  
> -void *alloc_pages_exact(size_t size, gfp_t gfp_mask) __alloc_size(1);
>  void free_pages_exact(void *virt, size_t size);
> -__meminit void *alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
>  
> -#define __get_free_page(gfp_mask) \
> -		__get_free_pages((gfp_mask), 0)
> +__meminit void *alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask) __alloc_size(2);
> +#define alloc_pages_exact_nid(...)					\
> +	alloc_hooks(alloc_pages_exact_nid_noprof(__VA_ARGS__))
> +
> +#define __get_free_page(gfp_mask)					\
> +	__get_free_pages((gfp_mask), 0)
>  
> -#define __get_dma_pages(gfp_mask, order) \
> -		__get_free_pages((gfp_mask) | GFP_DMA, (order))
> +#define __get_dma_pages(gfp_mask, order)				\
> +	__get_free_pages((gfp_mask) | GFP_DMA, (order))
>  
>  extern void __free_pages(struct page *page, unsigned int order);
>  extern void free_pages(unsigned long addr, unsigned int order);
> @@ -357,10 +385,14 @@ extern gfp_t vma_thp_gfp_mask(struct vm_area_struct *vma);
>  
>  #ifdef CONFIG_CONTIG_ALLOC
>  /* The below functions must be run on a range from a single zone. */
> -extern int alloc_contig_range(unsigned long start, unsigned long end,
> +extern int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>  			      unsigned migratetype, gfp_t gfp_mask);
> -extern struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
> -				       int nid, nodemask_t *nodemask);
> +#define alloc_contig_range(...)			alloc_hooks(alloc_contig_range_noprof(__VA_ARGS__))
> +
> +extern struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
> +					      int nid, nodemask_t *nodemask);
> +#define alloc_contig_pages(...)			alloc_hooks(alloc_contig_pages_noprof(__VA_ARGS__))
> +
>  #endif
>  void free_contig_range(unsigned long pfn, unsigned long nr_pages);
>  
> diff --git a/include/linux/pagemap.h b/include/linux/pagemap.h
> index 2df35e65557d..35636e67e2e1 100644
> --- a/include/linux/pagemap.h
> +++ b/include/linux/pagemap.h
> @@ -542,14 +542,17 @@ static inline void *detach_page_private(struct page *page)
>  #endif
>  
>  #ifdef CONFIG_NUMA
> -struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order);
> +struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order);
>  #else
> -static inline struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
> +static inline struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
>  {
> -	return folio_alloc(gfp, order);
> +	return folio_alloc_noprof(gfp, order);
>  }
>  #endif
>  
> +#define filemap_alloc_folio(...)				\
> +	alloc_hooks(filemap_alloc_folio_noprof(__VA_ARGS__))
> +
>  static inline struct page *__page_cache_alloc(gfp_t gfp)
>  {
>  	return &filemap_alloc_folio(gfp, 0)->page;
> diff --git a/mm/compaction.c b/mm/compaction.c
> index 4add68d40e8d..f4c0e682c979 100644
> --- a/mm/compaction.c
> +++ b/mm/compaction.c
> @@ -1781,7 +1781,7 @@ static void isolate_freepages(struct compact_control *cc)
>   * This is a migrate-callback that "allocates" freepages by taking pages
>   * from the isolated freelists in the block we are migrating to.
>   */
> -static struct folio *compaction_alloc(struct folio *src, unsigned long data)
> +static struct folio *compaction_alloc_noprof(struct folio *src, unsigned long data)
>  {
>  	struct compact_control *cc = (struct compact_control *)data;
>  	struct folio *dst;
> @@ -1800,6 +1800,11 @@ static struct folio *compaction_alloc(struct folio *src, unsigned long data)
>  	return dst;
>  }
>  
> +static struct folio *compaction_alloc(struct folio *src, unsigned long data)
> +{
> +	return alloc_hooks(compaction_alloc_noprof(src, data));
> +}
> +
>  /*
>   * This is a migrate-callback that "frees" freepages back to the isolated
>   * freelist.  All pages on the freelist are from the same zone, so there is no
> diff --git a/mm/filemap.c b/mm/filemap.c
> index 750e779c23db..e51e474545ad 100644
> --- a/mm/filemap.c
> +++ b/mm/filemap.c
> @@ -957,7 +957,7 @@ int filemap_add_folio(struct address_space *mapping, struct folio *folio,
>  EXPORT_SYMBOL_GPL(filemap_add_folio);
>  
>  #ifdef CONFIG_NUMA
> -struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
> +struct folio *filemap_alloc_folio_noprof(gfp_t gfp, unsigned int order)
>  {
>  	int n;
>  	struct folio *folio;
> @@ -972,9 +972,9 @@ struct folio *filemap_alloc_folio(gfp_t gfp, unsigned int order)
>  
>  		return folio;
>  	}
> -	return folio_alloc(gfp, order);
> +	return folio_alloc_noprof(gfp, order);
>  }
> -EXPORT_SYMBOL(filemap_alloc_folio);
> +EXPORT_SYMBOL(filemap_alloc_folio_noprof);
>  #endif
>  
>  /*
> diff --git a/mm/mempolicy.c b/mm/mempolicy.c
> index 10a590ee1c89..c329d00b975f 100644
> --- a/mm/mempolicy.c
> +++ b/mm/mempolicy.c
> @@ -2070,15 +2070,15 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
>  	 */
>  	preferred_gfp = gfp | __GFP_NOWARN;
>  	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
> -	page = __alloc_pages(preferred_gfp, order, nid, nodemask);
> +	page = __alloc_pages_noprof(preferred_gfp, order, nid, nodemask);
>  	if (!page)
> -		page = __alloc_pages(gfp, order, nid, NULL);
> +		page = __alloc_pages_noprof(gfp, order, nid, NULL);
>  
>  	return page;
>  }
>  
>  /**
> - * alloc_pages_mpol - Allocate pages according to NUMA mempolicy.
> + * alloc_pages_mpol_noprof - Allocate pages according to NUMA mempolicy.
>   * @gfp: GFP flags.
>   * @order: Order of the page allocation.
>   * @pol: Pointer to the NUMA mempolicy.
> @@ -2087,7 +2087,7 @@ static struct page *alloc_pages_preferred_many(gfp_t gfp, unsigned int order,
>   *
>   * Return: The page on success or NULL if allocation fails.
>   */
> -struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
> +struct page *alloc_pages_mpol_noprof(gfp_t gfp, unsigned int order,
>  		struct mempolicy *pol, pgoff_t ilx, int nid)
>  {
>  	nodemask_t *nodemask;
> @@ -2117,7 +2117,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
>  			 * First, try to allocate THP only on local node, but
>  			 * don't reclaim unnecessarily, just compact.
>  			 */
> -			page = __alloc_pages_node(nid,
> +			page = __alloc_pages_node_noprof(nid,
>  				gfp | __GFP_THISNODE | __GFP_NORETRY, order);
>  			if (page || !(gfp & __GFP_DIRECT_RECLAIM))
>  				return page;
> @@ -2130,7 +2130,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
>  		}
>  	}
>  
> -	page = __alloc_pages(gfp, order, nid, nodemask);
> +	page = __alloc_pages_noprof(gfp, order, nid, nodemask);
>  
>  	if (unlikely(pol->mode == MPOL_INTERLEAVE) && page) {
>  		/* skip NUMA_INTERLEAVE_HIT update if numa stats is disabled */
> @@ -2146,7 +2146,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
>  }
>  
>  /**
> - * vma_alloc_folio - Allocate a folio for a VMA.
> + * vma_alloc_folio_noprof - Allocate a folio for a VMA.
>   * @gfp: GFP flags.
>   * @order: Order of the folio.
>   * @vma: Pointer to VMA.
> @@ -2161,7 +2161,7 @@ struct page *alloc_pages_mpol(gfp_t gfp, unsigned int order,
>   *
>   * Return: The folio on success or NULL if allocation fails.
>   */
> -struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
> +struct folio *vma_alloc_folio_noprof(gfp_t gfp, int order, struct vm_area_struct *vma,
>  		unsigned long addr, bool hugepage)
>  {
>  	struct mempolicy *pol;
> @@ -2169,15 +2169,15 @@ struct folio *vma_alloc_folio(gfp_t gfp, int order, struct vm_area_struct *vma,
>  	struct page *page;
>  
>  	pol = get_vma_policy(vma, addr, order, &ilx);
> -	page = alloc_pages_mpol(gfp | __GFP_COMP, order,
> -				pol, ilx, numa_node_id());
> +	page = alloc_pages_mpol_noprof(gfp | __GFP_COMP, order,
> +				       pol, ilx, numa_node_id());
>  	mpol_cond_put(pol);
>  	return page_rmappable_folio(page);
>  }
> -EXPORT_SYMBOL(vma_alloc_folio);
> +EXPORT_SYMBOL(vma_alloc_folio_noprof);
>  
>  /**
> - * alloc_pages - Allocate pages.
> + * alloc_pages_noprof - Allocate pages.
>   * @gfp: GFP flags.
>   * @order: Power of two of number of pages to allocate.
>   *
> @@ -2190,7 +2190,7 @@ EXPORT_SYMBOL(vma_alloc_folio);
>   * flags are used.
>   * Return: The page on success or NULL if allocation fails.
>   */
> -struct page *alloc_pages(gfp_t gfp, unsigned int order)
> +struct page *alloc_pages_noprof(gfp_t gfp, unsigned int order)
>  {
>  	struct mempolicy *pol = &default_policy;
>  
> @@ -2201,16 +2201,16 @@ struct page *alloc_pages(gfp_t gfp, unsigned int order)
>  	if (!in_interrupt() && !(gfp & __GFP_THISNODE))
>  		pol = get_task_policy(current);
>  
> -	return alloc_pages_mpol(gfp, order,
> -				pol, NO_INTERLEAVE_INDEX, numa_node_id());
> +	return alloc_pages_mpol_noprof(gfp, order, pol, NO_INTERLEAVE_INDEX,
> +				       numa_node_id());
>  }
> -EXPORT_SYMBOL(alloc_pages);
> +EXPORT_SYMBOL(alloc_pages_noprof);
>  
> -struct folio *folio_alloc(gfp_t gfp, unsigned int order)
> +struct folio *folio_alloc_noprof(gfp_t gfp, unsigned int order)
>  {
> -	return page_rmappable_folio(alloc_pages(gfp | __GFP_COMP, order));
> +	return page_rmappable_folio(alloc_pages_noprof(gfp | __GFP_COMP, order));
>  }
> -EXPORT_SYMBOL(folio_alloc);
> +EXPORT_SYMBOL(folio_alloc_noprof);
>  
>  static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
>  		struct mempolicy *pol, unsigned long nr_pages,
> @@ -2229,13 +2229,13 @@ static unsigned long alloc_pages_bulk_array_interleave(gfp_t gfp,
>  
>  	for (i = 0; i < nodes; i++) {
>  		if (delta) {
> -			nr_allocated = __alloc_pages_bulk(gfp,
> +			nr_allocated = alloc_pages_bulk_noprof(gfp,
>  					interleave_nodes(pol), NULL,
>  					nr_pages_per_node + 1, NULL,
>  					page_array);
>  			delta--;
>  		} else {
> -			nr_allocated = __alloc_pages_bulk(gfp,
> +			nr_allocated = alloc_pages_bulk_noprof(gfp,
>  					interleave_nodes(pol), NULL,
>  					nr_pages_per_node, NULL, page_array);
>  		}
> @@ -2257,11 +2257,11 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
>  	preferred_gfp = gfp | __GFP_NOWARN;
>  	preferred_gfp &= ~(__GFP_DIRECT_RECLAIM | __GFP_NOFAIL);
>  
> -	nr_allocated  = __alloc_pages_bulk(preferred_gfp, nid, &pol->nodes,
> +	nr_allocated  = alloc_pages_bulk_noprof(preferred_gfp, nid, &pol->nodes,
>  					   nr_pages, NULL, page_array);
>  
>  	if (nr_allocated < nr_pages)
> -		nr_allocated += __alloc_pages_bulk(gfp, numa_node_id(), NULL,
> +		nr_allocated += alloc_pages_bulk_noprof(gfp, numa_node_id(), NULL,
>  				nr_pages - nr_allocated, NULL,
>  				page_array + nr_allocated);
>  	return nr_allocated;
> @@ -2273,7 +2273,7 @@ static unsigned long alloc_pages_bulk_array_preferred_many(gfp_t gfp, int nid,
>   * It can accelerate memory allocation especially interleaving
>   * allocate memory.
>   */
> -unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
> +unsigned long alloc_pages_bulk_array_mempolicy_noprof(gfp_t gfp,
>  		unsigned long nr_pages, struct page **page_array)
>  {
>  	struct mempolicy *pol = &default_policy;
> @@ -2293,8 +2293,8 @@ unsigned long alloc_pages_bulk_array_mempolicy(gfp_t gfp,
>  
>  	nid = numa_node_id();
>  	nodemask = policy_nodemask(gfp, pol, NO_INTERLEAVE_INDEX, &nid);
> -	return __alloc_pages_bulk(gfp, nid, nodemask,
> -				  nr_pages, NULL, page_array);
> +	return alloc_pages_bulk_noprof(gfp, nid, nodemask,
> +				       nr_pages, NULL, page_array);
>  }
>  
>  int vma_dup_policy(struct vm_area_struct *src, struct vm_area_struct *dst)
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index edb79a55a252..58c0e8b948a4 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -4380,7 +4380,7 @@ static inline bool prepare_alloc_pages(gfp_t gfp_mask, unsigned int order,
>   *
>   * Returns the number of pages on the list or array.
>   */
> -unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
> +unsigned long alloc_pages_bulk_noprof(gfp_t gfp, int preferred_nid,
>  			nodemask_t *nodemask, int nr_pages,
>  			struct list_head *page_list,
>  			struct page **page_array)
> @@ -4516,7 +4516,7 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
>  	pcp_trylock_finish(UP_flags);
>  
>  failed:
> -	page = __alloc_pages(gfp, 0, preferred_nid, nodemask);
> +	page = __alloc_pages_noprof(gfp, 0, preferred_nid, nodemask);
>  	if (page) {
>  		if (page_list)
>  			list_add(&page->lru, page_list);
> @@ -4527,13 +4527,13 @@ unsigned long __alloc_pages_bulk(gfp_t gfp, int preferred_nid,
>  
>  	goto out;
>  }
> -EXPORT_SYMBOL_GPL(__alloc_pages_bulk);
> +EXPORT_SYMBOL_GPL(alloc_pages_bulk_noprof);
>  
>  /*
>   * This is the 'heart' of the zoned buddy allocator.
>   */
> -struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
> -							nodemask_t *nodemask)
> +struct page *__alloc_pages_noprof(gfp_t gfp, unsigned int order,
> +				      int preferred_nid, nodemask_t *nodemask)
>  {
>  	struct page *page;
>  	unsigned int alloc_flags = ALLOC_WMARK_LOW;
> @@ -4595,38 +4595,38 @@ struct page *__alloc_pages(gfp_t gfp, unsigned int order, int preferred_nid,
>  
>  	return page;
>  }
> -EXPORT_SYMBOL(__alloc_pages);
> +EXPORT_SYMBOL(__alloc_pages_noprof);
>  
> -struct folio *__folio_alloc(gfp_t gfp, unsigned int order, int preferred_nid,
> +struct folio *__folio_alloc_noprof(gfp_t gfp, unsigned int order, int preferred_nid,
>  		nodemask_t *nodemask)
>  {
> -	struct page *page = __alloc_pages(gfp | __GFP_COMP, order,
> +	struct page *page = __alloc_pages_noprof(gfp | __GFP_COMP, order,
>  					preferred_nid, nodemask);
>  	return page_rmappable_folio(page);
>  }
> -EXPORT_SYMBOL(__folio_alloc);
> +EXPORT_SYMBOL(__folio_alloc_noprof);
>  
>  /*
>   * Common helper functions. Never use with __GFP_HIGHMEM because the returned
>   * address cannot represent highmem pages. Use alloc_pages and then kmap if
>   * you need to access high mem.
>   */
> -unsigned long __get_free_pages(gfp_t gfp_mask, unsigned int order)
> +unsigned long get_free_pages_noprof(gfp_t gfp_mask, unsigned int order)
>  {
>  	struct page *page;
>  
> -	page = alloc_pages(gfp_mask & ~__GFP_HIGHMEM, order);
> +	page = alloc_pages_noprof(gfp_mask & ~__GFP_HIGHMEM, order);
>  	if (!page)
>  		return 0;
>  	return (unsigned long) page_address(page);
>  }
> -EXPORT_SYMBOL(__get_free_pages);
> +EXPORT_SYMBOL(get_free_pages_noprof);
>  
> -unsigned long get_zeroed_page(gfp_t gfp_mask)
> +unsigned long get_zeroed_page_noprof(gfp_t gfp_mask)
>  {
> -	return __get_free_page(gfp_mask | __GFP_ZERO);
> +	return get_free_pages_noprof(gfp_mask | __GFP_ZERO, 0);
>  }
> -EXPORT_SYMBOL(get_zeroed_page);
> +EXPORT_SYMBOL(get_zeroed_page_noprof);
>  
>  /**
>   * __free_pages - Free pages allocated with alloc_pages().
> @@ -4818,7 +4818,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
>  }
>  
>  /**
> - * alloc_pages_exact - allocate an exact number physically-contiguous pages.
> + * alloc_pages_exact_noprof - allocate an exact number physically-contiguous pages.
>   * @size: the number of bytes to allocate
>   * @gfp_mask: GFP flags for the allocation, must not contain __GFP_COMP
>   *
> @@ -4832,7 +4832,7 @@ static void *make_alloc_exact(unsigned long addr, unsigned int order,
>   *
>   * Return: pointer to the allocated area or %NULL in case of error.
>   */
> -void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
> +void *alloc_pages_exact_noprof(size_t size, gfp_t gfp_mask)
>  {
>  	unsigned int order = get_order(size);
>  	unsigned long addr;
> @@ -4840,13 +4840,13 @@ void *alloc_pages_exact(size_t size, gfp_t gfp_mask)
>  	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
>  		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
>  
> -	addr = __get_free_pages(gfp_mask, order);
> +	addr = get_free_pages_noprof(gfp_mask, order);
>  	return make_alloc_exact(addr, order, size);
>  }
> -EXPORT_SYMBOL(alloc_pages_exact);
> +EXPORT_SYMBOL(alloc_pages_exact_noprof);
>  
>  /**
> - * alloc_pages_exact_nid - allocate an exact number of physically-contiguous
> + * alloc_pages_exact_nid_noprof - allocate an exact number of physically-contiguous
>   *			   pages on a node.
>   * @nid: the preferred node ID where memory should be allocated
>   * @size: the number of bytes to allocate
> @@ -4857,7 +4857,7 @@ EXPORT_SYMBOL(alloc_pages_exact);
>   *
>   * Return: pointer to the allocated area or %NULL in case of error.
>   */
> -void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
> +void * __meminit alloc_pages_exact_nid_noprof(int nid, size_t size, gfp_t gfp_mask)
>  {
>  	unsigned int order = get_order(size);
>  	struct page *p;
> @@ -4865,7 +4865,7 @@ void * __meminit alloc_pages_exact_nid(int nid, size_t size, gfp_t gfp_mask)
>  	if (WARN_ON_ONCE(gfp_mask & (__GFP_COMP | __GFP_HIGHMEM)))
>  		gfp_mask &= ~(__GFP_COMP | __GFP_HIGHMEM);
>  
> -	p = alloc_pages_node(nid, gfp_mask, order);
> +	p = alloc_pages_node_noprof(nid, gfp_mask, order);
>  	if (!p)
>  		return NULL;
>  	return make_alloc_exact((unsigned long)page_address(p), order, size);
> @@ -6283,7 +6283,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
>  }
>  
>  /**
> - * alloc_contig_range() -- tries to allocate given range of pages
> + * alloc_contig_range_noprof() -- tries to allocate given range of pages
>   * @start:	start PFN to allocate
>   * @end:	one-past-the-last PFN to allocate
>   * @migratetype:	migratetype of the underlying pageblocks (either
> @@ -6303,7 +6303,7 @@ int __alloc_contig_migrate_range(struct compact_control *cc,
>   * pages which PFN is in [start, end) are allocated for the caller and
>   * need to be freed with free_contig_range().
>   */
> -int alloc_contig_range(unsigned long start, unsigned long end,
> +int alloc_contig_range_noprof(unsigned long start, unsigned long end,
>  		       unsigned migratetype, gfp_t gfp_mask)
>  {
>  	unsigned long outer_start, outer_end;
> @@ -6427,15 +6427,15 @@ int alloc_contig_range(unsigned long start, unsigned long end,
>  	undo_isolate_page_range(start, end, migratetype);
>  	return ret;
>  }
> -EXPORT_SYMBOL(alloc_contig_range);
> +EXPORT_SYMBOL(alloc_contig_range_noprof);
>  
>  static int __alloc_contig_pages(unsigned long start_pfn,
>  				unsigned long nr_pages, gfp_t gfp_mask)
>  {
>  	unsigned long end_pfn = start_pfn + nr_pages;
>  
> -	return alloc_contig_range(start_pfn, end_pfn, MIGRATE_MOVABLE,
> -				  gfp_mask);
> +	return alloc_contig_range_noprof(start_pfn, end_pfn, MIGRATE_MOVABLE,
> +				   gfp_mask);
>  }
>  
>  static bool pfn_range_valid_contig(struct zone *z, unsigned long start_pfn,
> @@ -6470,7 +6470,7 @@ static bool zone_spans_last_pfn(const struct zone *zone,
>  }
>  
>  /**
> - * alloc_contig_pages() -- tries to find and allocate contiguous range of pages
> + * alloc_contig_pages_noprof() -- tries to find and allocate contiguous range of pages
>   * @nr_pages:	Number of contiguous pages to allocate
>   * @gfp_mask:	GFP mask to limit search and used during compaction
>   * @nid:	Target node
> @@ -6490,8 +6490,8 @@ static bool zone_spans_last_pfn(const struct zone *zone,
>   *
>   * Return: pointer to contiguous pages on success, or NULL if not successful.
>   */
> -struct page *alloc_contig_pages(unsigned long nr_pages, gfp_t gfp_mask,
> -				int nid, nodemask_t *nodemask)
> +struct page *alloc_contig_pages_noprof(unsigned long nr_pages, gfp_t gfp_mask,
> +				 int nid, nodemask_t *nodemask)
>  {
>  	unsigned long ret, pfn, flags;
>  	struct zonelist *zonelist;
> -- 
> 2.43.0.687.g38aa6559b0-goog
> 

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202402121458.A4A62E62B%40keescook.
