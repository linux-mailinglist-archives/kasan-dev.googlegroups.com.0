Return-Path: <kasan-dev+bncBCS5D2F7IUIJRAOHV4DBUBFS3ODES@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 22EB887A9FC
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 16:04:59 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d33fa7f791sf11335101fa.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Mar 2024 08:04:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710342298; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJ7derfP25NeYxqfXh6ooLxMklnv9qT3ca7/A033qtAaBPkVPJ/ZSF05W3lbR8X36G
         kzBUkUZN9kfwpQWufWQtC2JACqQTcvpO4gZnv3D07M3i5H3oOVYwx05yrAM0IfHIl61V
         jbHiuAcwNgoCQPfffBtSyXyH7tLPUirbrFEhdDQHCq3TmNKf914+MFAFCYwksJ/Pqkzw
         VJrJLw0Kh1xnxRGJ3J1wHG17Z45xpsUPvGtQT7PcUsjoYOwPw4RdFu04tC1qIX7n88ZF
         8C+RJcdnrgBI7/Kho/o59DQboUGsCj6Vi+Cd3I+O1ZGO+fQVycu8ZS2lADG9AqGofVBy
         vh4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=p+JbDw2qXjt40EzOfzFe9M0TatU5YolLs7J2uCApsxs=;
        fh=4FMntpZzqdGcONqmpJLW27CWZyY6eXBhMaKYp+eLSHI=;
        b=E+a1jIYdx85RCVQSXtgIl2o7WSloorIFSs52mA9BEHk5KfXswKqCy4Sry9QJ8lTAGH
         42fuBcOZ05SS1ctktIRcnh2Vu9NsikJB+e5ygndESOOniLiNa/YKWRXhyguRPYfkRkFq
         qeZxOUMipWSCi3wv4ewkiYmOPWUo7/GkamL/ZVYFtjQ02rQdMbLgXJOqadcnL1g8aAI0
         OrNNLNYKeWd8Rf3t1cxKCBg0mT4MFbYVCvFxXzPUvwcXmJjXgtULEGXebSrN64lWAceI
         J27JMIHC46C60QC0eHosDMT+RLzodiaxB1If6MSwrc9JBgR6V7zWsqxb+SL9J+ZNI619
         +eCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=u4TINEae;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710342298; x=1710947098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p+JbDw2qXjt40EzOfzFe9M0TatU5YolLs7J2uCApsxs=;
        b=YiUnsBsQCirM3Gb3tmCiIFkgl83igBwk/8l4Uebpcm5iTTsyHhpuDKq8GerYUfwPcV
         YCTqjQfSs7tQKeF/zswQlLam0ctseaZVmAOPuU8Tra18+JgYLQwQBZkp95YeKBmQhszF
         q9zqI8fWrp5zg+6oCjIuFlXN6hfLBh/rl2Pgb6DqcpkCCR5cxyYDgiSOV4J65k9hTXc1
         RiMLGouUVQ/uGC+5vhYhaxCXVAPt4zGrRXL7vBztv99EY4uFhcEwVW+J31Fk4i9muOB8
         6zFrobyiQ9Qntt07DC4Oo68tQ86z5bWnsAJM3MjO3GPbD0afY2MHIrIV/swDAT2qhzwP
         uV1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710342298; x=1710947098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=p+JbDw2qXjt40EzOfzFe9M0TatU5YolLs7J2uCApsxs=;
        b=QF8Fh+Nen8RwgH4Z5rLiqX3W0nsS8RUApzPKyZXXmaPgB29eIi2lr7215d1KvZqbmG
         CILsNMwDiuEamSoS6c68U8GCozH1Tf6hiG8udx6dJyeJw8bN0MFei/txkxYkVPK2KbX1
         KwzElpaRG1Som3VYY+RkUc6X68+h5X3dffCbEOeFfWmEg6puiorfZ9VrdEIDbXzxiDvu
         wJiHUVezBZLZg+OyKmklkJdzlcpQZgwCBgESZk+Uoz576Y2RawqavuWs3B5a2B/kn815
         ugdqNFCGxYSOcwDolCYYMVej58yJ2xEwrFhTXvnHzdYvN7K48tjFZ5DbGUAzDx5EfEMh
         EIBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWLnpLnQ2gicpE/ret3CU0eys7W13Cw6ZzZkTTM+VCn+oKMH466dImg6sjptj3EWcf3xeh+O8vnMgcV0Im3YTXKG6MiqScO+Q==
X-Gm-Message-State: AOJu0Yz2mxxJlIPo40FRXxcXVtoQv3XbDm+Jh27avbwSDDTjmbo2nMRB
	y1hSnz5nRu4V9ZKUH7EYFvMhuERwDvsU0r1BOxxgWqMvJBCUu8NB
X-Google-Smtp-Source: AGHT+IFrqupj8Tigx+Rdr+UhVDPSrLIpJIS909tNXPPTVq6R8xKCpKZE4/QmqqLchhXzXeBVxgsY9g==
X-Received: by 2002:a05:651c:b93:b0:2d4:5b06:b9c7 with SMTP id bg19-20020a05651c0b9300b002d45b06b9c7mr3304936ljb.39.1710342296713;
        Wed, 13 Mar 2024 08:04:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9985:0:b0:2d4:122c:9578 with SMTP id w5-20020a2e9985000000b002d4122c9578ls958033lji.2.-pod-prod-01-eu;
 Wed, 13 Mar 2024 08:04:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKKBoANTSuetucALpmTj11ZvvhmgQ/LpwvI6nQjj89OMjzN01lvHv/kVoANgOOSTr7Hpw+e/YZu6DSWI0D0le2YHiEnaFDCVkZFw==
X-Received: by 2002:a05:6512:3b12:b0:513:2329:4308 with SMTP id f18-20020a0565123b1200b0051323294308mr6327178lfv.14.1710342294343;
        Wed, 13 Mar 2024 08:04:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710342294; cv=none;
        d=google.com; s=arc-20160816;
        b=oNtLV4geoo78BfpXtas709v7w9JxkgWtKoHDqX99FbTUH2mg+m464oxwz0cUHa6Qoy
         jg7DJcsLeWb0KPQBVfxt3/S7iA2hEcFWj0M+wRcjWZeCct1lKkHAnsLOUn5lH9L2/EL5
         uFouUGAcyfy40U4RjO+tqlwjHHPMUDEgHU+nJHAKL3mvF/L8QmnbGqsdtF+oYEw/l5dk
         mLs47CCTC5pms7ORNHI04W3HB6F44IPQGJ07Ih9LjnpDR8plgiVZSoMjZBlE5/JrrBtp
         5YWKje8TOfuXGmOwTBGu6swGQKqcKKLXvQKIn2/S2Ckug13C4oTddgcTibP/KXk+/wSD
         WjNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=BNxK5EuN2z1du2u9zHs8dUJAhvJjbhbwG8RbEiAeClc=;
        fh=+qdFpMEGzqHVyfOkCe9fTYp9J9ynW2SW/6j7r7ih/rg=;
        b=YNt1DDLy9IKObPJbLIZdXDIAoOj1osu19pQNxMh7JqDCMwk3nWB7teVXxvW7HUsqvJ
         dAxkeh5a8sQt9kaftc0RZ5w0Bgy3DO/mK3I91XAvelMgprOWHRB3TExYBNBfsNi8zOKL
         5t4lIpOQsgDCWfshqum7QjLMl9RM/L8qSBdBjj0wxEKRD1sNDjq4m2PWqD4/0ve/i3Td
         VfkUP0psftPLV9zQbGC9VvKGN2RFvYAgUa5AXAuvXSpaO2si4W/+4couUnU98jtUX+4m
         B4RZxmteQR0G7wK7l0aujUg/eaUaLuTMAYina3DP4YC+ZP3VmrptqClZXz3jml7uHz9n
         rpgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=u4TINEae;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id t13-20020a05600c198d00b00412c6c9f326si197571wmq.1.2024.03.13.08.04.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Mar 2024 08:04:54 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rkQ9R-00000005dNK-1tqa;
	Wed, 13 Mar 2024 15:04:17 +0000
Date: Wed, 13 Mar 2024 15:04:17 +0000
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
	elver@google.com, dvyukov@google.com, shakeelb@google.com,
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v5 20/37] mm: fix non-compound multi-order memory
 accounting in __free_pages
Message-ID: <ZfHAcVwJ6w9b1x0Z@casper.infradead.org>
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-21-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240306182440.2003814-21-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=u4TINEae;
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

On Wed, Mar 06, 2024 at 10:24:18AM -0800, Suren Baghdasaryan wrote:
> When a non-compound multi-order page is freed, it is possible that a
> speculative reference keeps the page pinned. In this case we free all
> pages except for the first page, which will be freed later by the last
> put_page(). However put_page() ignores the order of the page being freed,
> treating it as a 0-order page. This creates a memory accounting imbalance
> because the pages freed in __free_pages() do not have their own alloc_tag
> and their memory was accounted to the first page. To fix this the first
> page should adjust its allocation size counter when "tail" pages are freed.

It's not "ignored".  It's not available!

Better wording:

However the page passed to put_page() is indisinguishable from an
order-0 page, so it cannot do the accounting, just as it cannot free
the subsequent pages.  Do the accounting here, where we free the pages.

(I'm sure further improvements are possible)

> +static inline void pgalloc_tag_sub_bytes(struct alloc_tag *tag, unsigned int order)
> +{
> +	if (mem_alloc_profiling_enabled() && tag)
> +		this_cpu_sub(tag->counters->bytes, PAGE_SIZE << order);
> +}

This is a terribly named function.  And it's not even good for what we
want to use it for.

static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr)
{
	if (mem_alloc_profiling_enabled() && tag)
		this_cpu_sub(tag->counters->bytes, PAGE_SIZE * nr);
}

> +++ b/mm/page_alloc.c
> @@ -4697,12 +4697,21 @@ void __free_pages(struct page *page, unsigned int order)
>  {
>  	/* get PageHead before we drop reference */
>  	int head = PageHead(page);
> +	struct alloc_tag *tag = pgalloc_tag_get(page);
>  
>  	if (put_page_testzero(page))
>  		free_the_page(page, order);
>  	else if (!head)
> -		while (order-- > 0)
> +		while (order-- > 0) {
>  			free_the_page(page + (1 << order), order);
> +			/*
> +			 * non-compound multi-order page accounts all allocations
> +			 * to the first page (just like compound one), therefore
> +			 * we need to adjust the allocation size of the first
> +			 * page as its order is ignored when put_page() frees it.
> +			 */
> +			pgalloc_tag_sub_bytes(tag, order);

-	else if (!head
+	else if (!head) {
+		pgalloc_tag_sub_pages(1 << order - 1);
		while (order-- > 0)
			free_the_page(page + (1 << order), order);
+	}

It doesn't need a comment, it's obvious what you're doing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfHAcVwJ6w9b1x0Z%40casper.infradead.org.
