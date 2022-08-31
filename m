Return-Path: <kasan-dev+bncBAABB7N4X2MAMGQEFY5ULYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 225285A84A4
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 19:46:38 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id r19-20020adfa153000000b00226d74bc332sf2013017wrr.3
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Aug 2022 10:46:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661967997; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ux5z95jj+3W8jhneRHlyf3P65Nq4ozW7xpxZ3MuBuwucqWXTnL9LFlgGDDevffRWHy
         gEhShc3m3uBVmy8mQJfLIrjpm97wvxm27J4LBtvipkh0lhAM/qf/yeDT+9Co57DRLUJj
         uv+oXpd/4ktcKENQ6YtG2W1JcepcuklSsmfcvUNhtVttBqiwvJM41NhD6eG6Batbh5r+
         U2BVzPwB9M/7JVeWKukqdlecnptWQyJlVXL+h183JQQQxJoF+0RTJTL3qZdT2TfY0/G0
         ZB8PF9nJBMuSjzUSz/h3jR1nMJUSXBDpU7zbFJBMwUvadzAARUoYWL0WfjXrHW4FRLZv
         jxeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9p8J1X1Wr5CdjQ/zqKIIuBwUWph1AyMtiq3JrHXNHnk=;
        b=ib0ixv0ZBtxxbzhZnlWdkVfNswd5lqRq/1u7vf7F1f7TbNtmgVwTXxvAk5M/IkXT6I
         0J980nfCyun1j8ZAASUAYPIG/QEimCqw+aGL01UFq8dalrsFYA9A/Scl+9vdzk1yhYU8
         jkKBURPdjXu0zYM/59Ues75RfAWNjGiC3PFDCoojYKmVp/HlBdh3ok3hXNDbBR1K3liN
         j1U60/fY/9nwotSRVF5Gq8C6Y1oFSLeg8HybG8jM4wdBm9MmkA43avtLyk5qsI19jHmS
         dmNtRbvm9jvdxAkwW3LHjIdPQtqx9ghz3N459emvFCCSUV3P6LWC0o8SZUCSBFiLWcDU
         1K6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UvGgvRFF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=9p8J1X1Wr5CdjQ/zqKIIuBwUWph1AyMtiq3JrHXNHnk=;
        b=B5Hs9AjFh7t7P5ZoVC9/zlNr3uM8v8oOrk8lavsIQH9wQuy/7Yi8zFkx9uiajcXpBA
         uDMfYZvBWLcSz4KwkN+RXLBFF3v8YI/LFQqsCnsPPJwPb21Yvv4cOU/DYWuR0NXPC5Vq
         fM+gwAn653Zkn0St8cN2+QFdfUdTaSUhARPStjxjFqYMcGYiwZZW4s0h9LSXfKMh2YQF
         qCO06qDKB7RBEhJQLzVMRjg/nAUMXHih4PzOzCyj62IzhAwRJiXrtcxEYG1etmvPATxv
         vd/Jhsp42mUJk9aZM1IXGzUFuuriZOjeSC3/Q9J4KvuS3QzTRgW68GtX8JaJ0xAslNTr
         NLQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=9p8J1X1Wr5CdjQ/zqKIIuBwUWph1AyMtiq3JrHXNHnk=;
        b=8PqjatPWdsSChf9lPbGISoJjt4UB/b8T6kXmE+ioT79p/PrqGRN29YljF0oxvDvzrj
         J+UoiSQCUMCSVXnU7X4vnqWW8WwGwZQFenBpDjHsha9JghU/MlYY3AS6gDLfb1EBLT4e
         iqgm4Co7Cwj54NPjqNBuOVf8a8vcEiTVqdv0GKe4eMYltP92g3fHegNBMzOZxypqKScr
         VgXf7cw5rzfgHVyi19FXSgNKPYLPM/iiw0g6HCsf4LTPOJo2BOWxc6SmPWhO9KvUupWP
         U8sQcxC/3wKogncrLvxLX18g+1T6mLWx3DenkCkr9aVVUpeVm+HangZliUiuRoDL1Lv5
         ylag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo08E0/Kw4nwYQhh8UDrFVP0d3S/0mpmo/Ralp6PpJUCvNXOIQ1X
	2WrXov0V/2pjIYvKlMfZQlk=
X-Google-Smtp-Source: AA6agR6+7HfehsU83Mm7Qi24Mrcg2DcbDZENoiSrvG+Hg/4alM8MhS53XJP11WhZuPD2wPYyYEnQ7g==
X-Received: by 2002:a5d:4243:0:b0:226:d45a:3ca6 with SMTP id s3-20020a5d4243000000b00226d45a3ca6mr11129369wrr.588.1661967997739;
        Wed, 31 Aug 2022 10:46:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d234:0:b0:225:26dd:8b59 with SMTP id k20-20020adfd234000000b0022526dd8b59ls12180944wrh.3.-pod-prod-gmail;
 Wed, 31 Aug 2022 10:46:37 -0700 (PDT)
X-Received: by 2002:a5d:5984:0:b0:226:de85:30ab with SMTP id n4-20020a5d5984000000b00226de8530abmr7448932wri.232.1661967996980;
        Wed, 31 Aug 2022 10:46:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661967996; cv=none;
        d=google.com; s=arc-20160816;
        b=kLSs3TE5ebJpVilwCHIuH270fA9l+6xFhFFTj8ydYDfHkplTP5+iEYr/FXiatxAqYs
         0jA9zJS00TkOxnmAVYtskc42Tu+JtvcH8IaOj8XnS7R0a41yqUpSpn6jeTp9BA0r78sz
         aA/hzImS/XkBKMMXzGmIBgW8hXpSsj5Ib+AGDg0BoBYFN7NkK0Nr3NA08RwgMJNEEiTM
         GY6FCylcB3ol6dBdilB7KVQWopfV2sZcwFdaxgoocNv+MeYv73so8E4ZLwQ98g7LTgZz
         0c9D9C4gaRScM/AyijYbR9RNcgMndCTn5s10KY3s3zX0ZyF29DMmsA0BDTNutg9+2D2u
         txJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=cNGQu2INYppvwn/vrI+H9fLNjZAQ9LEc2ZMlyG9+b7I=;
        b=ItVVDXMbbi9h2qF/6+TAK8Aeoi6w0DAzcEhkMCVlGMjDn7qeTlKW53TnUVf53IhqKl
         BvVFXZfeEazTl0xQKt5qPtj6DcZElGSio0ld77HX5N1MJjFnK8BsPVr7MKJWP/fW1JNP
         nakE/Obbp6ykZcPgP+mediy8hFS+08uckuVqlI3GDVw3GlizpjD3k0kwvmx85T/Tl0QA
         tgtVOPQ8WawW9YX6oFp+mI4gOWCCzs8FW+XFojlyYWKGcoTLhgb9f11wBY6rj64yjo0p
         WWHdb3HM5Emxd2O7uPhJ4XM56WkfP78ZhG52igYZCRa62hZnJMkd4z2MONjzK3hJrB0A
         OYgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=UvGgvRFF;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id j28-20020adfd21c000000b002256e922345si613508wrh.0.2022.08.31.10.46.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 31 Aug 2022 10:46:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
Date: Wed, 31 Aug 2022 13:46:29 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Mel Gorman <mgorman@suse.de>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org,
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, dave@stgolabs.net, willy@infradead.org,
	liam.howlett@oracle.com, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 10/30] mm: enable page allocation tagging for
 __get_free_pages and alloc_pages
Message-ID: <20220831174629.zpa2pu6hpxmytqya@moria.home.lan>
References: <20220830214919.53220-1-surenb@google.com>
 <20220830214919.53220-11-surenb@google.com>
 <20220831101103.fj5hjgy3dbb44fit@suse.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220831101103.fj5hjgy3dbb44fit@suse.de>
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=UvGgvRFF;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Aug 31, 2022 at 11:11:03AM +0100, Mel Gorman wrote:
> On Tue, Aug 30, 2022 at 02:48:59PM -0700, Suren Baghdasaryan wrote:
> > Redefine alloc_pages, __get_free_pages to record allocations done by
> > these functions. Instrument deallocation hooks to record object freeing.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > +#ifdef CONFIG_PAGE_ALLOC_TAGGING
> > +
> >  #include <linux/alloc_tag.h>
> >  #include <linux/page_ext.h>
> >  
> > @@ -25,4 +27,37 @@ static inline void pgalloc_tag_dec(struct page *page, unsigned int order)
> >  		alloc_tag_sub(get_page_tag_ref(page), PAGE_SIZE << order);
> >  }
> >  
> > +/*
> > + * Redefinitions of the common page allocators/destructors
> > + */
> > +#define pgtag_alloc_pages(gfp, order)					\
> > +({									\
> > +	struct page *_page = _alloc_pages((gfp), (order));		\
> > +									\
> > +	if (_page)							\
> > +		alloc_tag_add(get_page_tag_ref(_page), PAGE_SIZE << (order));\
> > +	_page;								\
> > +})
> > +
> 
> Instead of renaming alloc_pages, why is the tagging not done in
> __alloc_pages()? At least __alloc_pages_bulk() is also missed. The branch
> can be guarded with IS_ENABLED.

It can't be in a function, it has to be in a wrapper macro.

alloc_tag_add() is a macro that defines a static struct in a special elf
section. That struct holds the allocation counters, and putting it in a special
elf section is how the code to list it in debugfs finds it.

Look at the dynamic debug code for prior precedence for this trick in the kernel
- that's how it makes pr_debug() calls dynamically controllable at runtime, from
debugfs. We're taking that method and turning it into a proper library.

Because all the counters are statically allocated, without even a pointer deref
to get to them in the allocation path (one pointer deref to get to them in the
deallocate path), that makes this _much, much_ cheaper than anything that could
be done with tracing - cheap enough that I expect many users will want to enable
it in production.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220831174629.zpa2pu6hpxmytqya%40moria.home.lan.
