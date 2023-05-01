Return-Path: <kasan-dev+bncBCX55RF23MIRBJ7WX6RAMGQE3P5DO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C60F56F352C
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 19:47:20 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-3f173bd0fc9sf15366035e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 10:47:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682963240; cv=pass;
        d=google.com; s=arc-20160816;
        b=CQBU/y55jCZF6wgr8I41CsmzRw1NsrnAwqQx+S26xuBlByxSr+/vBCyx1HzXtpXb3d
         eYKSNhTTvgaBrLWPIGzOIKqoATfyQHM4AF925nC6n27ZrLj9QgO2p95tWxo/Cn0nJKO/
         tG03KOhcY8lDI2HO+BE10GsDJg/+te6ntyL5kVXzNBfRBRPSbhhPr8xmPatIH6hrcuwU
         8Q9y2+62japfqcFtp/P+0pzoHyyQYYfAaKCSj5Fv6yMf+N6l215iF0q4YbsAkEoet9en
         ugPGCz/M6KT3x7OFmfFJYH0Ka6le1+9WIz3EzGTF/LTyRSqo1vzGIPCHhUG8QjyRSGc8
         Ubag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3ut+bPnCHqPaOl3krz9DbyCj76E+9Yygt/JbcDFBums=;
        b=gvkOoErjK5fK4PGtJbFPiueHI0gHFWU1ytGtLxBNN1xRZZ/5JWFCaFRNbjMO561sOA
         /GSbS3WQ2XcDuglvQ6GqBoeHkJasTt6sgNjeaQ1xnUgWWxkx1FOGJl9fbHAxSQ0q0NfA
         PuG0Quvvztz9hWKS6+71NyuSwBaoejWuOvla46gHVb4xx7j6yEUyr2sS5RqwqucdLmc0
         D5vaz/9hmKH81vTJfqRKPTAye6GyVJwvMK+JeoCUIqcuu8LUIFdzlEGcQIjPmVpbtD2Y
         ofvWarAjaWy1+8PPmAf+05ULLzPRBzfbQdi1ylfBKS25PBA9sxhTrCWO5gqr382ib+TS
         5Ztw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DiqG+Df4;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.29 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682963240; x=1685555240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3ut+bPnCHqPaOl3krz9DbyCj76E+9Yygt/JbcDFBums=;
        b=XXcfkoKF4LnVrH8NRftKaGgpG7xSwOZzIGsEVxSK+ArrMqt/M4AdRUMLut1uqxlbsd
         0Q45ERYkpByKvgug/aoQTZ767OE4dBDvp7tiVZhtnWN/D/j+t5/0azGWfYmUBDhWLmvU
         T5DAYkTWoKbQy9vUixsrSfCX4RVrvXDI3Ru7z8RUu4MxA1Z/SG/+tQyjt060ITBaOt4b
         s6QXOnvUiyRjQBaTqrZo0Y1Ag2EWGxQHP8eAybk1knBVM/rzzHfGh5eXZxll67RL+N80
         nFBSdt+YvBlwRCmghJny6T2DyHV4pci8mXDIQB+lTxajAzZ1gzMwQ9xvPLbstDBOEKbA
         QBLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682963240; x=1685555240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3ut+bPnCHqPaOl3krz9DbyCj76E+9Yygt/JbcDFBums=;
        b=GH1a+C3PJZpy1zXScScyL31AKxWyrdAuop439DsLNHPwq2qLixSkOfgnDJ6CErzbV0
         9n5DVQ01ARaHcRythIfYCbBUXicR9llUE41yUbF6X88IrLNXgm9C4XhCvVwR3meNY3LO
         WnI6rvF6ReNN45HQ6g60taq7spf36LISS+hPc6l/bqlaNr+uZHz/bwhQwotl9jKD28XF
         5wfyFYkbLNuRUiNyydC1/K+rnrZShJ7jCHJZOkW1iUHlhbgytNcGH0Pqi8efiUAxwubm
         DupzxvHSOneRf6Hfm0Vf7Jg1++/SahB5y+Oatt1GXTzy+QAA3an3+jcU8zynIx3g9E4g
         5+iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy6DFmoudkWP+cJJVvVI0zZ60R6edWG9Mcf0zgPBYpwoQuOxeRZ
	i1yuWjsYwnd1h2AXKjm5eMw=
X-Google-Smtp-Source: ACHHUZ672eYChvWKdpT7zIyxAdcAEdwfAw3Rz5hoO4OIzFlVQivGRndG6g/VuUNriunWnInlDxug0w==
X-Received: by 2002:a1c:f019:0:b0:3f2:73a:f027 with SMTP id a25-20020a1cf019000000b003f2073af027mr2609534wmb.1.1682963240145;
        Mon, 01 May 2023 10:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d98:b0:3f1:76ba:6ea5 with SMTP id
 p24-20020a05600c1d9800b003f176ba6ea5ls7399007wms.0.-pod-canary-gmail; Mon, 01
 May 2023 10:47:19 -0700 (PDT)
X-Received: by 2002:a1c:7416:0:b0:3ed:6c71:9dc8 with SMTP id p22-20020a1c7416000000b003ed6c719dc8mr10564208wmc.22.1682963238911;
        Mon, 01 May 2023 10:47:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682963238; cv=none;
        d=google.com; s=arc-20160816;
        b=sPNainQskVVyPw9H310NNDioPMN76zE0xGHp4lkwiS+enyPYVkSJdPDqKCxB8jJKnJ
         sgam462xechFMYp4ChfS4H7qunR+aMzthb7uI9LMYo0UvngBtUtbtVe6HeblEZBpsSep
         JflaRKYrYprz0DNrxWWULMxvNec4TcWAFhhRIvah6JQE/kbtlehCxVTA81FSLYbrM54o
         2IA4KF8fBiHPLn7JtngdTnqYeLYdWCFTVUs6vlfZ5G65B8qVchvlCZ8/sM2F3tbWe1l/
         cXS+ifqszn6U1EbMNMrZBDohmTRH8KllGzWXplXHKT4jNZDgSyk05KPN4aOOZkZTaMrk
         fTtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=pCOJ4TIX11zw2jBaDOP97T7hx/pG0LP03OwHceiD+AE=;
        b=W6LX+oJa9Uzk+2dC4q5dU7jMUwj3kwVjyFGnn+F3tvkYehECoRy62ofBdAW3E5hyDE
         HR21CFAtEbgFMgDeX3fOxRLfsxcMyPcegj+tDCuKMN16CVvLFftw3vw9mzRhOQXsfKrv
         6B/BKNIZ8ZTQSOrhs3fwELb82diLrYBOQGGRecu2h+UI67V6PD93mg0bJ51G5GcQcXph
         Ur4bTiZM8pBuugpnkk0tgzwmCCcd/6+f8P2ropgPyGszCFDjoyw3WNqsO3j/3neXs5Nx
         TTiaANna7UbopJefT9l6eNdULQiQA2lvH4JFL1GBqFhQGre3Az4C9+RQ3lBU+fnkDoSw
         MhhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DiqG+Df4;
       spf=pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.29 as permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-29.mta1.migadu.com (out-29.mta1.migadu.com. [95.215.58.29])
        by gmr-mx.google.com with ESMTPS id v10-20020a05600c470a00b003f16ecd5e6esi1731309wmo.4.2023.05.01.10.47.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 May 2023 10:47:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.29 as permitted sender) client-ip=95.215.58.29;
Date: Mon, 1 May 2023 10:47:01 -0700
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Roman Gushchin <roman.gushchin@linux.dev>
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com,
	vbabka@suse.cz, hannes@cmpxchg.org, mgorman@suse.de,
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
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZE/7FZbd31qIzrOc@P9FQF9L96D>
References: <20230501165450.15352-1-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: roman.gushchin@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DiqG+Df4;       spf=pass
 (google.com: domain of roman.gushchin@linux.dev designates 95.215.58.29 as
 permitted sender) smtp.mailfrom=roman.gushchin@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Mon, May 01, 2023 at 09:54:10AM -0700, Suren Baghdasaryan wrote:
> Performance overhead:
> To evaluate performance we implemented an in-kernel test executing
> multiple get_free_page/free_page and kmalloc/kfree calls with allocation
> sizes growing from 8 to 240 bytes with CPU frequency set to max and CPU
> affinity set to a specific CPU to minimize the noise. Below is performance
> comparison between the baseline kernel, profiling when enabled, profiling
> when disabled (nomem_profiling=y) and (for comparison purposes) baseline
> with CONFIG_MEMCG_KMEM enabled and allocations using __GFP_ACCOUNT:
> 
> 			kmalloc			pgalloc
> Baseline (6.3-rc7)	9.200s			31.050s
> profiling disabled	9.800 (+6.52%)		32.600 (+4.99%)
> profiling enabled	12.500 (+35.87%)	39.010 (+25.60%)
> memcg_kmem enabled	41.400 (+350.00%)	70.600 (+127.38%)

Hm, this makes me think we have a regression with memcg_kmem in one of
the recent releases. When I measured it a couple of years ago, the overhead
was definitely within 100%.

Do you understand what makes the your profiling drastically faster than kmem?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZE/7FZbd31qIzrOc%40P9FQF9L96D.
