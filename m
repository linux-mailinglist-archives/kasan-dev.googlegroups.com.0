Return-Path: <kasan-dev+bncBCKMR55PYIGBBHE7ZCRAMGQEWUODWFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D0A986F51DC
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 09:39:09 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ac6acdeebasf3290811fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 00:39:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683099549; cv=pass;
        d=google.com; s=arc-20160816;
        b=HI7VWJRk7kreyT6pTRyHRz7KHj+6Tvm/Kh0v9F+N1yTkWNzEEC9DgL1X1ZD+9h8eou
         n62uzkcCQtTNewjAtZrvNBj/FdFLyWOfX7nt1IA5h4g7//Rdu8rocOOoUumsAoRODTQv
         udkwDUaFG65c0SVBMuboitML/Zw/WQrR6G+Af2yPe2CI8jbEuhSH+rGvCZTtWggkigI9
         eY1/tbqVXaV3z+xjVsCDv6uapUosP2xLroua9IOwLwWtKDxfxHHWQtZ+493yKkoHivwX
         a27oqqk+Xnt454AzngObar5HZ2XNAxZVatphI6AbH+rifsMX2cxIv7r4EF4tU1YzNtph
         MAFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=/H9rbi8MvsTyCGuVh5tHYVnu+Mz/2TwFHuprlpSLLqs=;
        b=zvBFS3VwJzzha1DoBo2kwhdePKj3uhUCC90ogLtbUicrzSLgYe4IOeW3jU3UmN8Qfs
         XpphIXyRN804RasKhoK0Fokh8M7IlC9rKWOx+AimmIFqvxb1sOy0reBrJPY8QtUnasT2
         OKFydUodHdQmC5QSgfRFCrpcatmnYNb2GU1bYj8cv4OQ2bndahph13mG7a7f4//k5pBB
         OmiDRRvGXkZtdwmZKRgTUGDtxK9R5gju93NUVAvgD4nNS4FWmWLXoTZJbS5Mw07adhVF
         yKAZQmTpadv6T3qrQS2NOZv9oVoClEmbqgY/7tCLOCm9Lcvshoy5uiwkPk64PVy/9VKc
         x51g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tncfUpOe;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683099549; x=1685691549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=/H9rbi8MvsTyCGuVh5tHYVnu+Mz/2TwFHuprlpSLLqs=;
        b=tjJZKzHK/ymfdslXqw4CjQdHeE1Fzk+nqc+JQO1wQu9AGL/pX6Pz5coqSo93k+OdlR
         RuxJDy7wzySK+qmvfJT3DSEYGrWBUziYFN1WWjIsd40hCSdZOCDL9D2Q3I6vYl2+Z6sW
         6bFC7DvZoJN01WPTSiYPXIs1PmkUQvpRTWZFE9rgYD9AyjALgbLVcWLnauNvzj7hJPlj
         7LA/pXPkFw+T6Lwhtx3FFOc2gk77LsL2JYxdvVMiYWlcdvfn1DqUEmXn1ILW1TiQySMb
         3/2tr0Jpxd5UMoAiI0Y+3NS2QW0qGxcWhgU0p3DZ7M8V4ZiQDDy8CvvH8dclp6ZUD6je
         UvNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683099549; x=1685691549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/H9rbi8MvsTyCGuVh5tHYVnu+Mz/2TwFHuprlpSLLqs=;
        b=IjEd57862s/Fn6zMuRMSzVct31eZD1oVOG1U5kHHdPj9AJsIlqXmTXGhjxBdMb5XV8
         9FuinqngCz1gsumzQfBIKCtroC7uHrD8UoctgMkPX+6CqsFvd/ezsqYH/k9PizPNPEyq
         rIx8AcjfZveuQsXspgfzh4DJr0PhK/lW2LgAlVJplrPE/O9tttExuI9i/lfhfwxcr/+z
         BrQnX6xN6brU8CY6Z/flhcov8Jronn+5U0NH0VyCFiY62utbBpGi3o5y4b5Cm4SZXymn
         e93kA5aGeZ8cjOY3/wO/YGwRr0ojg92ifta90AUS/V7GgOfNNCVB1+/zOf/smRCCe6mr
         qs2A==
X-Gm-Message-State: AC+VfDwzMcHLMVJI/wuNPH88hB1PcLQ+miB3hyWNByfqZL7AwQOxfvd6
	7bUZcqSiSvO/afSIe+05qUw=
X-Google-Smtp-Source: ACHHUZ5RUXHFpT7VllTAfevfCG/7Eqd4UKH1nFGUQD19VAZ+9zDnHy8lyS4kWpQ827iFMzpveVBkZQ==
X-Received: by 2002:a2e:3514:0:b0:295:a82e:ec06 with SMTP id z20-20020a2e3514000000b00295a82eec06mr4431782ljz.3.1683099549137;
        Wed, 03 May 2023 00:39:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:158d:b0:4ec:6fe6:9f26 with SMTP id
 bp13-20020a056512158d00b004ec6fe69f26ls29109lfb.0.-pod-prod-gmail; Wed, 03
 May 2023 00:39:07 -0700 (PDT)
X-Received: by 2002:a05:6512:11c1:b0:4dd:af29:92c1 with SMTP id h1-20020a05651211c100b004ddaf2992c1mr557756lfr.44.1683099547493;
        Wed, 03 May 2023 00:39:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683099547; cv=none;
        d=google.com; s=arc-20160816;
        b=swbsOa8Ge4jTGUL/xhgTZWqjRqyeWcuzv1SOfj1xQRg7VPoozknPYcgptGCs45a23Z
         m2fAJD7zVZKIceZ4o28kwmc1j6CG60hk9/PyT6ltVkvyUWj6mNn4YPHCA70KjovfbWsW
         zwnyQUFv94pqEwfizvOGE1Y436iByEPtuhzUB7/nXm6M0mWftfW7UL/tgA9jnzQ23XS/
         jzkLxQpBKz/Ol246RZCettZgPnDXV+7fXwjxopkj7qzTdMoyKqbN5D0nIMxG+LEVngMn
         zthQELmnLWfwzLW+EYVBAP4tW9MHSFK4NuDl8iiQCnt4vI50jLizf7fplR4X7ebVOlp0
         8XBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vE/ZqILzfvZWd4rot3GcUptJ3pMzFJC66caayH1dCe0=;
        b=sl50KGIMGQmDepjinlsVdV9kP5UFnrW5AUKIgPBjoQ3u3ZjkNBPXD0EjgbkQR+R0oV
         KonIVeEgT4HT3QNkJYxhsmkBFKQl8WGzn/Jwsv+fzi3TbZMgKVNKMTpmo3emZDimXx5c
         MuykA/vGXNVUjt902Lkmhd7claLpP8ysZkPDd4MIqL+W+7eol/EF1Ed/T/WXERQetfhc
         jkOa07xTlVahGZzYGkWMtkwNSLDHzVm16wL2jIt8SXs/WLvu8INQh0u+PskY7ultHLH1
         Wrr25GRO87LJ9vow2Ok7ZodHPK6HBApIWwX7/e6K8/F2CDJuFu4PMopALooZJwa65riv
         szSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=tncfUpOe;
       spf=pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=mhocko@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id p2-20020a056512234200b004dbafe55d43si2085113lfu.13.2023.05.03.00.39.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 00:39:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E5EAD223E7;
	Wed,  3 May 2023 07:39:06 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id BB17E1331F;
	Wed,  3 May 2023 07:39:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id v3OjLJoPUmQQVAAAMHmgww
	(envelope-from <mhocko@suse.com>); Wed, 03 May 2023 07:39:06 +0000
Date: Wed, 3 May 2023 09:39:06 +0200
From: "'Michal Hocko' via kasan-dev" <kasan-dev@googlegroups.com>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org,
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org,
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com,
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com,
	keescook@chromium.org, ndesaulniers@google.com,
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
Subject: Re: [PATCH 35/40] lib: implement context capture support for tagged
 allocations
Message-ID: <ZFIPmnrSIdJ5yusM@dhcp22.suse.cz>
References: <20230501165450.15352-1-surenb@google.com>
 <20230501165450.15352-36-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230501165450.15352-36-surenb@google.com>
X-Original-Sender: mhocko@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=tncfUpOe;       spf=pass
 (google.com: domain of mhocko@suse.com designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=mhocko@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Michal Hocko <mhocko@suse.com>
Reply-To: Michal Hocko <mhocko@suse.com>
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

On Mon 01-05-23 09:54:45, Suren Baghdasaryan wrote:
[...]
> +struct codetag_ctx *alloc_tag_create_ctx(struct alloc_tag *tag, size_t size)
> +{
> +	struct alloc_call_ctx *ac_ctx;
> +
> +	/* TODO: use a dedicated kmem_cache */
> +	ac_ctx = kmalloc(sizeof(struct alloc_call_ctx), GFP_KERNEL);

You cannot really use GFP_KERNEL here. This is post_alloc_hook path and
that has its own gfp context.
-- 
Michal Hocko
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFIPmnrSIdJ5yusM%40dhcp22.suse.cz.
