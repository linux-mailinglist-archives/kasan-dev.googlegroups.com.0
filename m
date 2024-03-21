Return-Path: <kasan-dev+bncBCS5D2F7IUIJVSXRV4DBUBHMRRRE2@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B60DB885E79
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:49:31 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2d599dba7fbsf11884561fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:49:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039771; cv=pass;
        d=google.com; s=arc-20160816;
        b=KKM0UqFBLoFVYYFKtqvw+BrwREYIrkTdap1Femf/e69VJvlioKnoy61Gr0Yxe6eMFL
         9wdEfUTZXQOXqDohcaSKMr/SRqetn7u/29gOuz9xZ7Fh7S+wj2Ux8B9Ov4bl3Qw5mc6c
         H8eT0jnd3tr2y/rZoNLUsFwvpMUVMY2XUAz0jIJHogDwHrFyWo5XsKEdm3wP8aPQSu/7
         C1Z7uavXXJ/A/t/svxtji8lKpHxYXV4UYr4hwx6ODEZscSz0AbPbxHRSgi+LWYfC8+rw
         T6oX+n+ThpVtMMj34SO7nfrzbCCSm+IiByceQjDXtaa4sx3d2DxMaNxQnnVZ75Nc8C6M
         uahw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=P71fj6s0pwr+cVPLJc3nlYH8yidHw3gSx2sYhcF4Yjc=;
        fh=4aRlJ/BVdeaXNkUGZVUXiA7sQlA5roV0Y0vYHwbS7ao=;
        b=a5R8/kedmNtpe0xq9x9+ChgbIBEAFPvO1SAt2KSpvQ4x9PPw+hp4maE3cHDaIvKbcW
         4Fi/yzXfjuhbJcg7BK/7kfxXqD/njYvy65nQCunae5LPWPsw3Kz3EyYaURRrD4+SDzKp
         heYSNnOaagr/n3GVujqaaep4SPxy/1CtqtKUz856zmlJkplI/VvMa7Uw2rGyrBT7M0pJ
         X0PJgWD8sAKxVmCtBdfRg5kMgT65epuDLYc39qIeNJ1X+Zduu9RvM7h/DRBGU3I2XmCD
         i7Olodlru+v+t2MxK0FA2uknFjZdYKqFNWcT1q3zhV9/okgOha6T3uBgBIyUP8YHgima
         olLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gGi8xJlV;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039771; x=1711644571; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P71fj6s0pwr+cVPLJc3nlYH8yidHw3gSx2sYhcF4Yjc=;
        b=xyrMXFLdH3XLfuqNJXwQDXX8wd2vPnUfP8G9ES2CBn7NApJbeho0GYBfEWz/xZuz9b
         5FLDyT3D/V5pohLuKy3r5hvYtRdh7/POuOn7AgGTfiaugBiLhdkcQ8V3Vf5L2MiOlmje
         lkxHmBBbFZYlxpOy0oDAD2J+BryawMOuYDdcXDtSDKo3CmGuGHw/FsXIKAeaBmHSaoQ4
         0vgauyIrYRZFhViuDhmlpz5rf6EdymPpBzuxn/P2R9eC8/3wZAwzjIn5YTmkqLAfMefZ
         FJQhcgmrxr2a3L2sFjc7BnVLjFWS1EfAtGT5dlDkQyZX2ZtJYsZOaWdsSqPsliEoYX7H
         FPvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039771; x=1711644571;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=P71fj6s0pwr+cVPLJc3nlYH8yidHw3gSx2sYhcF4Yjc=;
        b=M833YRaU3cZhMSzMaNSsytYAjveSi2FT21IWQCCtz+mfwu5nWN/5vGUV41p2M8CsB5
         IugnklwSH9h48kcTGByVL5kwKJJdKk8W8FVI1aRUSd9rchva0Lal8Bs6qjULAySaOKHd
         eZc9KM6+tXnhoNMQ0+ri5xfMQ8F+/Lf4i9cbB693A4yRdLk3XZAKaw4+tKKKH3qfQc1S
         uE6Iv5fGgcZHXAK9wDoy4uHa37SRGXK/u8wWDiRXIWnlvXfFzBSanU7bakxQdBZlB4l1
         F2ud4fw8lnUzvNUgiq2vWKIylUsRZz9k+QsDeptn0nFJM+eQ8guKexTFAPqW3cR+uvNv
         3hZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWK8LMSAMCLMbG68DDisTteVtM37qZL/KbdJgg3Aj4m9bQU+Ke4aQqmatxqPP0HOQh/b84C01saXck35+CJm4QD14+1DlazfQ==
X-Gm-Message-State: AOJu0Yxflbo0oRXWpkwz6Kf3+5Of3WZlONu6vByh0KZRLRJQBPaYsbPk
	c3aITIO5LiPv2PP/wtwMeNWYr7ENifo/bfYIIWLMeq4XhcnKsAVU
X-Google-Smtp-Source: AGHT+IGpiO5mIa+jPyaYAELaHXWhszV3l1VlLysFAv0HV+ii5RqzSKdV41nEPtAr/03T7W79vU2nYQ==
X-Received: by 2002:a05:651c:214:b0:2d4:4c4c:3c9a with SMTP id y20-20020a05651c021400b002d44c4c3c9amr59685ljn.5.1711039770492;
        Thu, 21 Mar 2024 09:49:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7019:0:b0:2d4:9683:bb0b with SMTP id l25-20020a2e7019000000b002d49683bb0bls222099ljc.0.-pod-prod-04-eu;
 Thu, 21 Mar 2024 09:49:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWqE5EBmbgXMhkixWCA8Bmyqrtbr4+Wk25U6hx3zEeIZTp+0O86zpn30ModKzIZcyQ1/4xp8cGmjTMNMBBUAddYjCOFYRFRFpf92g==
X-Received: by 2002:a05:6512:3705:b0:513:ce00:1a2 with SMTP id z5-20020a056512370500b00513ce0001a2mr1948302lfr.30.1711039767939;
        Thu, 21 Mar 2024 09:49:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039767; cv=none;
        d=google.com; s=arc-20160816;
        b=D8yHMM9JU17RgjvwUh9jaejv8X4blyxJ29yotkl4JytQkLA/61xbbtw8q2LpxX+BFP
         BRCO+yw4L9xiNDRBFXte/AVC21m10WqKeDDbXHCZ6xke0U++5frQ3Uip2n4fxyafRycH
         A6k3KG+Cw01xvipMU4dqdpdvRVHapLbclJvP6avZQQsVgt+o4Xh9R+jXG31/jghzf5/H
         Reka2t2NdIIsms8WqIc5tP0b9GfNk957Zg+l544sqdYi+3hfkRWiQTDNwIcheSDV82fu
         Glc7W7w8L95Q3niBnk9YJYJNdgtO7JqUMQkpNHkmX34scjlUAHacBxy2jftTZFIT9OQ5
         rY8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=V9mrRuAn6P0CI166dm0Zpc+lSpGuhBwRxOMqznP0Qc8=;
        fh=smj1+IZujXiiBWQPOPcy2FzTFvSfcA84M//ihXQ940Q=;
        b=0kq/tIeMW+CAIcs/X6sszLG8FS2ng8I982hN44y+p48zjYS6WykHy/3Zg82AM5yyQG
         ma0TIOcv+FL3woDO1gfhhY2gcvYXSk1eCTcTsejW4LorvIsBZlJuEh1mB67MhTlqgp4o
         SV2nOCT77dRpD7qerFiMztbK6crDQFtq02OM54uwFQx2PfFugaZ0JTKrVCq2nn9nU2d6
         YFRZbh9dYBBM7qLZ8dvHgR763kJZwgoz/iz2+JlaN/CGl8tUOe1d48Kh/gegYGEjDe4P
         OuXO7csBXCko1IaVg7/7wZm06vS5nUcceBksd5X3Ug3buii4Y+s/kMk2VjKhgQidAqjw
         yMRg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=gGi8xJlV;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id w10-20020a056512098a00b005132a886f68si1927lft.3.2024.03.21.09.49.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Mar 2024 09:49:27 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rnLb3-0000000793s-1qG7;
	Thu, 21 Mar 2024 16:48:53 +0000
Date: Thu, 21 Mar 2024 16:48:53 +0000
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
Message-ID: <Zfxk9aFhF7O_-T3c@casper.infradead.org>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-21-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321163705.3067592-21-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=gGi8xJlV;
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

On Thu, Mar 21, 2024 at 09:36:42AM -0700, Suren Baghdasaryan wrote:
>  static inline void pgalloc_tag_add(struct page *page, struct task_struct *task,
>  				   unsigned int nr) {}
>  static inline void pgalloc_tag_sub(struct page *page, unsigned int nr) {}
>  static inline void pgalloc_tag_split(struct page *page, unsigned int nr) {}
> +static inline struct alloc_tag *pgalloc_tag_get(struct page *page) { return NULL; }
> +static inline void pgalloc_tag_sub_pages(struct alloc_tag *tag, unsigned int nr) {}
>  
>  #endif /* CONFIG_MEM_ALLOC_PROFILING */
>  
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index fd1cc5b80a56..00e0ae4cbf2d 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -4700,12 +4700,15 @@ void __free_pages(struct page *page, unsigned int order)
>  {
>  	/* get PageHead before we drop reference */
>  	int head = PageHead(page);
> +	struct alloc_tag *tag = pgalloc_tag_get(page);
>  
>  	if (put_page_testzero(page))
>  		free_the_page(page, order);
> -	else if (!head)
> +	else if (!head) {
> +		pgalloc_tag_sub_pages(tag, (1 << order) - 1);
>  		while (order-- > 0)
>  			free_the_page(page + (1 << order), order);
> +	}

Why do you need these new functions instead of just:

+	else if (!head) {
+		pgalloc_tag_sub(page, (1 << order) - 1);
		while (order-- > 0)
			free_the_page(page + (1 << order), order);
+	}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zfxk9aFhF7O_-T3c%40casper.infradead.org.
