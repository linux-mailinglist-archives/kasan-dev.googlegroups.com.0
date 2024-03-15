Return-Path: <kasan-dev+bncBCS5D2F7IUIK3NGRV4DBUBE75KGEK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id B57E787CEB4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 15:24:46 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id ffacd0b85a97d-33ed71b926csf80237f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 07:24:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710512686; cv=pass;
        d=google.com; s=arc-20160816;
        b=jYSEAEwuJcFfsk3bQNbPwS0EBA85y4GaEuG9R/U9yFK+YwBVN7Ftz8cASk+m1XdJC/
         AINuYnsZ/v+DKuHccBB3oFT+sOQXJJiPqQ/4hUiy7+5tta7D7i6G3dXq2Edqa/BvR8EW
         wYSO6XXIT1Yg5ui/1qqVr+cFs14Bwkdw5W2+HxyCKuc+7ogXo1jxotRCCk8mnw/jLwZY
         Od5j5Nue9yyszIDHaXkjuBYUEBtzFdhBQ6HmvgtjwQt91mGpZ7obInQpvEaUcJTa4v3W
         3y/AJHy/odwOm9CgWj9byHYF+4TlOuSSv2Gr4lnblP/HgrfsUyeCRHBs6bogJkzpL78J
         pupQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QiITCkI274NwYbC4dlpeJYTDQkhHGnWFlahE7a/+akk=;
        fh=FD8FJmbdpGOrjPbmwDF7bjwMWxrLpWkfgUjB8WXxkIs=;
        b=g836AEtiIt/DHJpO4YIo/Gnb6Qifafa5UM6AbdbTGqW1+qwkTkamPdjxHgiVTSyADG
         IJVZjXWsO1DxxABECT6DnshSf/zZgDo75ltNf8CjLBRkBwtAuQPSO9I2zHMRMmoGfhyd
         XswxhjF0LBiDgKm5CwCPzrfJO8ZthEit3A5WP4PhbL0pva/eisGzxVAgbUJ1UJzquEZ2
         9XXcyP/Nt9km2HEd4yR+Sb1HHb+HN5luSxNQHoeRx69HqArpO4NrHDz3GKl2eNEU7b1q
         56Ub3J+rP4YWpL6i4gnfScMTCJceb3LSJcUvrj4Kw9zcINEpgP9bH1IDGU8IC1+XOGYc
         WAPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=g6icv7vD;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710512686; x=1711117486; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QiITCkI274NwYbC4dlpeJYTDQkhHGnWFlahE7a/+akk=;
        b=xuTkLZrPBo3vdP/tW2/Tl33u9fHSbzj68YotZ4oXp7w3eU79lW/RmivsWqR7b+CEu6
         qemQ6/aMEno6BjJfwxVGBFnLEahK+tlw+nh9WCBkQrHD8yM6gMKezLAhlg7hF9eKvAwl
         mS8RY7XQm5o/0GYxe/H0YnJ8y08IpucZVgJ83NpjC8qTi4+2hwrDi4+LJOTZboWEyVUL
         O/81VvfvXrAVldY1uEbdpFsbOUUIxhK3bEISP+G5iNregcAH5Q7ojP0P4CO6bBzZ64fn
         HrHjqcPDV5tR3qkC3UjQK9vuaTWrh15ok5I/hOuyJBzCzwloWPyLPJ1epxrqbbzDPDJU
         /7PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710512686; x=1711117486;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QiITCkI274NwYbC4dlpeJYTDQkhHGnWFlahE7a/+akk=;
        b=OWfzauE16iCeqLlS67KQGaVUY48AuoCNhg1H/f9jHc5B3Gm4toGltbKySPxRIhV28q
         d41xln59+JIpUKoND3VjZY16V7pxvd4gK8d+eYBzyMad1lgMVa3WukFvT39TzvQ120Tq
         V/WOK7WY5lTxypKvTa9gQB+nMIsCKePY4Nya2jYjcTmIQz0SugLraxBs8hvDAkrB3Y3r
         1w+zVvnj5juzsmSqf0ZphYC3n175cNOCMEy15ppuEw2UTxemYpdmb3fTItt1cbIYWPRa
         6kRR1HwYF4hbmYbmo6YereiZkJoaXiYewdAV/49Rc8J9dgxgRP3l75yq2VFxJttKxm9i
         ZEnw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWUlPlqOugLaF9WrlITZNyTIde8bYLjpqD6bjvXzDGndW/dF/mh/6Qf4qu35ddwPpsw/lljog+yhQl9afxNyc/qP4zo3HExiQ==
X-Gm-Message-State: AOJu0YxOpfa2j1eBzYjouVXP1YxxJHtWsk+XO1mT0AGWZXUm74nYfXfP
	6UrmxMrvIdoFzT9qvWbgd4lMsokXBoThf56OQihOR8A/FmhTldT+
X-Google-Smtp-Source: AGHT+IFUxR5SogXsqcBjVw26cBGUUJBy3xvE0HlnqhvFfonHdxpK+wZv/N4Mcb5JKs+PcoTonQi6vg==
X-Received: by 2002:a5d:67cf:0:b0:33d:2775:1e63 with SMTP id n15-20020a5d67cf000000b0033d27751e63mr3990948wrw.41.1710512685789;
        Fri, 15 Mar 2024 07:24:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4741:0:b0:33e:a1a7:6753 with SMTP id o1-20020a5d4741000000b0033ea1a76753ls575255wrs.0.-pod-prod-03-eu;
 Fri, 15 Mar 2024 07:24:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVT6UztPbRRZaBA1dnmw879D0HZ6JZw5FVBdVb2TAbhr+mIV73XHmY99jWRoWdi7oJDj1dK7g8PLjWciEFQIRPlAxIQcOjAuyAS0g==
X-Received: by 2002:adf:ce85:0:b0:33e:d470:da8f with SMTP id r5-20020adfce85000000b0033ed470da8fmr1206957wrn.17.1710512683620;
        Fri, 15 Mar 2024 07:24:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710512683; cv=none;
        d=google.com; s=arc-20160816;
        b=bKiBj4R/LJLNTydXOXXaid5VVsEymOldlFo4u8jjsE8sGH8FzUHV5z56gKRpLd0t0y
         tR747jDbhIizvszSi94wE+2k8Iqm04kMgRbnDdT1j2rnMDcdh1Nq9zdwB0OKGVs5dT6N
         iLR9V7yDEm+djHePT34VeQPn3L7MS5dDwhsOp8Mhc6PGU3kvslvkzyk+0th3Nyy9r/6r
         J02mLks2ViDndiBW0YsRacuZ2dt9ej+32SOoDDT9dYoI5r9shdEJ5g1OIMWdyjzdh/UL
         dxp+/isF9ZRWbjhs4qOI6ECr2E8xpDEHw0JJDBz/2xiAYZTThFR7AP9FaVyRQkS0rUC5
         TX9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=VRGW8z0NhLdznShUoOOXXxWys2yQ2J3P11bCMfJSNHA=;
        fh=+qdFpMEGzqHVyfOkCe9fTYp9J9ynW2SW/6j7r7ih/rg=;
        b=Dabf5nYy3Iw6CERrz+i3M9uDyxgCHd5pVN7ef9ubylRGoNIZW90VlDSVzV954BYY5E
         DtgavGHbhLQz6oR4JLE118kGqCzwvU8QXwj87+kU93EOqvb9MRxwo6RsY0toS09oXuWY
         6C0VcSh+RxF76ZHm3im7r7h1ucdoq3XCQQo1GLrsaXxslX2o62xLINdo/2d1JRpl16/t
         nSizcx+ykbvY6pGOlWzSUBkXMxYBH6NwWJRPIss0JMf/MGFEcWaiLsbMFYll0tcnt263
         Gys6T0wstTAyRZcfKH2snTQFgawVSF3N9BAz6HhAzqMpLDpD3sZZlbvKOTXzblSLqGcU
         YBhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=g6icv7vD;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id m3-20020adfe943000000b0033e082abbc4si199505wrn.1.2024.03.15.07.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Mar 2024 07:24:43 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rl8Tc-0000000AQWv-1Isj;
	Fri, 15 Mar 2024 14:24:04 +0000
Date: Fri, 15 Mar 2024 14:24:04 +0000
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
Subject: Re: [PATCH v5 14/37] lib: introduce support for page allocation
 tagging
Message-ID: <ZfRaBJ8nq57TAG6L@casper.infradead.org>
References: <20240306182440.2003814-1-surenb@google.com>
 <20240306182440.2003814-15-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240306182440.2003814-15-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=g6icv7vD;
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

On Wed, Mar 06, 2024 at 10:24:12AM -0800, Suren Baghdasaryan wrote:
> +static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
> +				   unsigned int order)

If you make this "unsigned int nr" instead of order, (a) it won't look
completely insane (what does adding an order even mean?) and (b) you
can reuse it from the __free_pages path.

> @@ -1101,6 +1102,7 @@ __always_inline bool free_pages_prepare(struct page *page,
>  		/* Do not let hwpoison pages hit pcplists/buddy */
>  		reset_page_owner(page, order);
>  		page_table_check_free(page, order);
> +		pgalloc_tag_sub(page, order);

Obviously you'll need to make sure all the callers now pass in 1 <<
order instead of just order.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZfRaBJ8nq57TAG6L%40casper.infradead.org.
