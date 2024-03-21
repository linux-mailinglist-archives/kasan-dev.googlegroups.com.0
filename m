Return-Path: <kasan-dev+bncBCS5D2F7IUIKDUPRV4DBUBFI42MDM@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DD2C3885F09
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 18:04:34 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-40e4303faf0sf17615e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 10:04:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711040674; cv=pass;
        d=google.com; s=arc-20160816;
        b=cNnXtv2R3X3DSYhduELudR/3hIRzVmopJ39rTJ1LWEkrx2REyfApCRbQCJNYYeh5OR
         zt3JiDk4wcUMsRGEWYEHxX5ONWo8arEuLC9PoPqE5R4bW14BUIyHJV/8WGWWSbS9mS0t
         1qtCMvu9My5DlWKepK8KojWeSXKLVrDoSc2BUnsKiaRY28JZWTYoExC68W+fC5I03L/V
         q++75pQwaYKPU4UnnfYiaqiZZ9o7XIKocLoPiZDXUqlgHi6kzMSAO9sWLJVL+ZkSsXKk
         NvSUtVE96kQeNYgcuTQpCbeQWDpX5fbs3dhJfU9grBYizWVW/Nv3mN4DEFRq1ib1RZM7
         tqRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/SRZVdbXZPmTXE6UP7vL1QvcSIP9SKu7/8yPB5RkuZQ=;
        fh=v3yNDPnIqYpieh8uWwPHf4SV0Qj7jjxojbqom7Zp3Do=;
        b=Qvei+ld7LmqxzExdF5Ww4zlb8c/o4MJwSwduyJacQCljSgGl1Hoe/ZMDXCpwyEqUUR
         GWSBh7/iZHUiqyvZgr4/ZfmkHBdzGkgVTiCq8kxXPV99ZlvVI/7rfxdrhnceRazuCIIJ
         5ZiaMNhV2hgkHm7WmJhDr7N1UebijisAhJQCiFGzfqvGTA0sg7wRqEgD+SyzwuJW1yyl
         HRV/3aUkEVdpiXU3Wkxn0BXRibRU+hAJNNhv2tsVHthaCqr3bLyJG1jGNPY8pid1g+VJ
         npcP1RU1/KeizF4eRuMRRJwExIkCOcXXGoC3Q9cf8E2qXHlEkIb9/sEvkrT/gKRx6j76
         kSNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KvEPlgWf;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711040674; x=1711645474; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/SRZVdbXZPmTXE6UP7vL1QvcSIP9SKu7/8yPB5RkuZQ=;
        b=Hl8EUUp0KSdX+hUxDCqfi7NdgBxr+0TcrlRojSyP+NI0TQo8YiTGMpeAS57JlJfDEV
         CNQUuJPGreB64CxGWtUYgAFHEiQSBe4sgm+0XIpgq6lbfwjj/FIBbQCHDXe1K2WBz3wL
         t7Z7vKtU2OK6Q+RucsdDpPHeljTSwnTssWJ+MZX2EqFWaQmpdi75y6SLJnNSdpVsZsB3
         1ofkjGZo6ij+t4dDK6/WAwu0aP5EYY4CTD6tQ2SqcaCdkNuwliL36H4YvsLVZH66EyPz
         dpDCswQEl6zN0DqkFwnfuxfqvQwM6jpN+IVM+4QiagQtg9sGpJ0RpSEJFXHiSjmnY/y3
         9bDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711040674; x=1711645474;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/SRZVdbXZPmTXE6UP7vL1QvcSIP9SKu7/8yPB5RkuZQ=;
        b=Ojk75FrG0mNno40PA5NC2pSVDzUBe6W7LkHJzB19RvGoJYJMiQjM1iwsS3v5cBwrZa
         onB1SXxnEEZcUg6noGmTWKcFPCWhZuOhYUJps0mbSpaToZm4xI2F6CJRst+hkZL5WTpL
         EFgpkPgVxlQjkyJtxojzhQJfWG9+dW/4X/U4HlUtUxZ+lMk/k6H1eopk6WcJ+rMHLNKv
         jxbuLftCqUeInP7rHGrPH2P/2scZA3r0f+WfdgzqHey+BVgwPGYkMzw8/HPbqT8xl+el
         6r2uqQZU8auOecDGQo0IXi7wUwncpqFI49/5W0ighDcOO3iztKsQxKqRejkuq9Kt5MkF
         fhfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV10fzDxRS7kUTp/g23pgL1GtE2egcRfBXnVxyz08xdtOR8pvyW5Si62SdsCCzN4BSighu3vTkNCQ1+Re7TnCCo2BmrirWdRg==
X-Gm-Message-State: AOJu0YwuwXOSNK9Ail+M/PFWorUvd7J1BNKueO8bCNuBOpzzmESIhi7F
	r6YcU0MIv+lEl01GX4GHNv2tazLGWAvRP5Xsdv8wYU2j26KCfQAt
X-Google-Smtp-Source: AGHT+IEObmvkVZaSuppchzWAwrktO/l9kwm50gIkdOUTiJo/spSWkE2a2XxolDBP0at/5WWvHHDxyw==
X-Received: by 2002:a05:600c:3b94:b0:413:f266:c654 with SMTP id n20-20020a05600c3b9400b00413f266c654mr229220wms.1.1711040673878;
        Thu, 21 Mar 2024 10:04:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8d:b0:414:8fc:c9f1 with SMTP id
 bi13-20020a05600c3d8d00b0041408fcc9f1ls555805wmb.2.-pod-prod-09-eu; Thu, 21
 Mar 2024 10:04:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXACuGLtvmusQuo9KblIPaxn8tawEwnczXUsUKwDfNBX36gtfJIVGH6vuAQ1Em4fMJpY274bOTLAUL4JBQ7nV/4cllwa7DGws4yNA==
X-Received: by 2002:a05:600c:3504:b0:414:63e8:dfb7 with SMTP id h4-20020a05600c350400b0041463e8dfb7mr6326140wmq.4.1711040671934;
        Thu, 21 Mar 2024 10:04:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711040671; cv=none;
        d=google.com; s=arc-20160816;
        b=IIPTYCapKYwc2qSg+qOzj7aUiS+nUsUxi03JWrW0b+zGoUcLpGfpe+jIpqG19DbyCk
         WguQzgi2JT3dAmmxGbHajwm4V8jQGVEsHnMzfkWyknRbtWQc1zRd+cuikmmV5el/40Xt
         MdxogbyvEyDW86nrnvaN2tYvmm2ojCg2boN1Y41p9CgjQS1Sb22Zc5R27H8QEC2GzH64
         zW5kggUlwRmXftxT/kyfFA9zbZNv7h0qDpQWOwI+q9YNXS2jU9BrU7w4gSBsRbaArXUo
         YEE68xx/IHDguANAH7lMTqFgjTmJfqmbgh1m7uKMuQ9PM30u2bR5QNg21OORHFBTzGmg
         fUjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=grrtrTSALnjlmhusaSmHuxgXHvy0PaqBERbW2XOksq0=;
        fh=smj1+IZujXiiBWQPOPcy2FzTFvSfcA84M//ihXQ940Q=;
        b=nz2UyAjatzuweA7wO/xH472BRECoCiJKCZgapdsSiLZYwKCYX2uvAF9Lg65lkr+Q8W
         hAltmG1P+LGjHFOSxiMJBkHsK1bBbqzfzj3WuC/Eyj49YBQaCn9AcGXcPbGmDJuJZI4P
         HME4r6NxTSh+9jxuJZlS/vwOZzHT9KK1LpVbe7qZSoSi0alfkKXdmkJ3HGOWy/v0c6UL
         Ltemr+9vQXLFV+2h9HA5y3YEDqJCWd6TOVecXjzycXrcUECyAE4xsuldkMIptDirvpH+
         z5UsSXRPewAnnjHET/hNmOguSH1xW03bdwNvGoOaQEDm/jj41bNhuS9J9oW1cmkVCN8n
         nsqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=KvEPlgWf;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id n16-20020a05600c3b9000b004132f97fa43si214190wms.0.2024.03.21.10.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 10:04:31 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rnLpl-00000007AzI-40SJ;
	Thu, 21 Mar 2024 17:04:06 +0000
Date: Thu, 21 Mar 2024 17:04:05 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev,
	mgorman@suse.de, dave@stgolabs.net, liam.howlett@oracle.com,
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com,
	tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org,
	paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, vvvvvv@google.com,
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com,
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
	elver@google.com, dvyukov@google.com, songmuchun@bytedance.com,
	jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com,
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	iommu@lists.linux.dev, linux-arch@vger.kernel.org,
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org
Subject: Re: [PATCH v6 20/37] mm: fix non-compound multi-order memory
 accounting in __free_pages
Message-ID: <ZfxohXDDCx-_cJYa@casper.infradead.org>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-21-surenb@google.com>
 <Zfxk9aFhF7O_-T3c@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Zfxk9aFhF7O_-T3c@casper.infradead.org>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=KvEPlgWf;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=willy@infradead.org
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

On Thu, Mar 21, 2024 at 04:48:53PM +0000, Matthew Wilcox wrote:
> On Thu, Mar 21, 2024 at 09:36:42AM -0700, Suren Baghdasaryan wrote:
> > +++ b/mm/page_alloc.c
> > @@ -4700,12 +4700,15 @@ void __free_pages(struct page *page, unsigned int order)
> >  {
> >  	/* get PageHead before we drop reference */
> >  	int head = PageHead(page);
> > +	struct alloc_tag *tag = pgalloc_tag_get(page);
> >  
> >  	if (put_page_testzero(page))
> >  		free_the_page(page, order);
> > -	else if (!head)
> > +	else if (!head) {
> > +		pgalloc_tag_sub_pages(tag, (1 << order) - 1);
> >  		while (order-- > 0)
> >  			free_the_page(page + (1 << order), order);
> > +	}
> 
> Why do you need these new functions instead of just:
> 
> +	else if (!head) {
> +		pgalloc_tag_sub(page, (1 << order) - 1);
> 		while (order-- > 0)
> 			free_the_page(page + (1 << order), order);
> +	}

Actually, I'm not sure this is safe (I don't fully understand codetags,
so it may be safe).  What can happen is that the put_page() can come in
before the pgalloc_tag_sub(), and then that page can be allocated again.  
Will that cause confusion?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfxohXDDCx-_cJYa%40casper.infradead.org.
