Return-Path: <kasan-dev+bncBAABB3PHXOXQMGQE4HFQNNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F408877F9A
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 13:07:11 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1d3d9d2d97bsf3186785ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Mar 2024 05:07:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710158830; cv=pass;
        d=google.com; s=arc-20160816;
        b=mST4WAGB1kNWwDeKmj2J3wJ799UCdZnpF+lwqmwiXletWTL9sWqLEPh507yW97+bIs
         7MXA4w3XixwMDioGlBeBSAHn0+W64egMdLcd1za0m1f7VOP/lVnS0QSHkcJyqXOYpqfV
         zbiUv21zcYw7ySSps5I35qaCr1IOczB4oaxU90OA+GhVnDiEWV2e8sMP1zC6qnkXCnse
         mleqiwK2NYqIaMtnmJFE88R0InGCgwubJOTOnKIDjzOwccBuV2UaPclO7klqmq7sZD+F
         fNx8eSSUr2VdH9pj/j+x5p0X+6vXvTDOmR4K3T2rVCMP6Xn1kCJOSnQymNEy6Ev5hkk8
         kdDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eRE5+0wpUukdDEFIV4a7Dvf5fGTTdgIhH08LdWvta/8=;
        fh=1ymaXIIS9NwkaytboUbU0PO8GLpr835v0yPaXNrUEz0=;
        b=YnZFEa0l+GFSpo/1FH1ysDWPAyJrCqWzs7RpCM6GASBBoDz1NeeLxTyl+4SVlsoaj0
         JoIxjwxhiFfPIQX1bT9QCS87g6Cyh5bvdAun6g0QbLo5mb9sNIlJJwzsHM9XKN5TOVrN
         Ou087srbZ/xRsxfpVg5AJXsHcShA0RDYhCwE+xczU1De+pQszm/AfsvfrzvBbIwv9z2a
         1EBGdZd+jVXyrJ+kULFgXpWe+aHJOi9Yux0Na5HYFsvbw7iG8a79sphM3izRBwdxUd5v
         yHgHysPT6RkZuhzRWKCpC2BGoAsKbCked7LeW+z0W7EXnXMH4qBI5AKftOUfPck8rfkP
         vlcw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710158830; x=1710763630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=eRE5+0wpUukdDEFIV4a7Dvf5fGTTdgIhH08LdWvta/8=;
        b=nQaRE8pL8xZBEWRQJc5uBLI28MDlEm8cNCt4lgn9W/TCfFX8evSBXeGqJBHQAg//UJ
         YeKtBjmREx1IJmIN5POhNx2WfEnSs1UQoFDphchZEgL7xnJejhsMQluuELvZNacquiqR
         gNlX8fgo7WYkRLXMlh2H2aq3VZMFNcJRZZ/ln/ftAtKrMQJxvCzQXmuhSQ7GIXtFzjYD
         JWlmSlLcya2KsR20N76CW4SKnOQaOvitENrJsaGDQR/nBnNqg+OmMWKEYumoCDOcL0Ax
         aKyn6vQNTSIF8ywNhDZiOQEyWquBlGDu3GVHgVcu8oMFkG/5HJJJslnnoVtSWdpsp7wC
         srJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710158830; x=1710763630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eRE5+0wpUukdDEFIV4a7Dvf5fGTTdgIhH08LdWvta/8=;
        b=KTvt5zYFhsquXJb0pM+zyHSMMXnplmCU37IDPAZ6Cpxzd58gImQtW+Tx23KanWdy2w
         TaFuMEWmq1gdftiDC3Pgn8kg7zwA1cN2w+Vfqs5TBIAykpMtVL3WdPRpOWhwenorLKgR
         0xlchYfWIw/iQjKg4IuhehSrm+3jrsBovECK+8q6MQf7SDJBaXdX1ou8HvuLO7Yv96it
         r3KZ09GnUWu8VOAQJUY/cEVXO0HzqK8uk8JhuDPFTRhEeldpiJ3r6aJfBxWyxfzX6B7c
         sUegDqM3pOLBDdwSwCjjmsZDvGbRLBqKpv8pgCJSjQFBXxQ0Yy1haJl7fWRF+ciJmB+8
         ZV+Q==
X-Forwarded-Encrypted: i=2; AJvYcCUo8jIhoWyhePBDNgX1f8J5w4pXXbbLDcPm8B3Zkqz2tjAwScLVl/V77GvZwllEoesy7nCjqaNn8njYW0J5wjFGUCNIDsXruw==
X-Gm-Message-State: AOJu0Yy1DxwKUQ4lZcyBZ6sX7v5eyRcM+Hfg7WdsGyM860Wg6kCwOfxq
	iP9rsIEAUZZcGkGb79G+t0kivdvMnabYDWd4B4q3GMqemhTk93ET
X-Google-Smtp-Source: AGHT+IF2C4tkFRw6i56NgYZ9mUiayFZQdRM752LxmrjVaw54Mqyb5e4Y0DghC7Do+No4jcBoVFlsig==
X-Received: by 2002:a17:902:dac5:b0:1dd:9cb3:8f83 with SMTP id q5-20020a170902dac500b001dd9cb38f83mr122431plx.13.1710158829827;
        Mon, 11 Mar 2024 05:07:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58d4:0:b0:5a1:2a2c:9ec with SMTP id f203-20020a4a58d4000000b005a12a2c09ecls4345097oob.1.-pod-prod-09-us;
 Mon, 11 Mar 2024 05:07:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXLuYg0MsZWe0BZi5a717k/jJHkyJdy2PhGI5d7z2hIlKHvj8cJeOkfLGBSO4TbmbGi42gbefdPrJyhvcLhDbNcv0DX98+f0s49Q==
X-Received: by 2002:a05:6808:200e:b0:3c2:50c3:df3a with SMTP id q14-20020a056808200e00b003c250c3df3amr1082148oiw.0.1710158828841;
        Mon, 11 Mar 2024 05:07:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710158828; cv=none;
        d=google.com; s=arc-20160816;
        b=eioi13NnidpfR3qTb+SnFYs2PMlT3Q0Abherp2a8YnuUu5clZLktOE1HNofuRGid+5
         wkDILfWZoGhL2BdFFZc5pbnmP6WoxIjTb3ocvHkDF/LWOpKGiGS/kyGOaTcCT5Kpc3Il
         cTFqDSEOgkJWVn7mu0Nde+zbD/MLh5QwpYL/91UJM6BbVurZ7koW6T4xNa/tRKuNKcYF
         jd2g0krikBCwUTQ3Oecazc4Bk5KXxckHRNIOccy5K4Dv8mBLh7VVItE0zNJUMv0PoR4B
         aGfqQmiwl2VcUE7rvbnMto8R5ybeiJsTPQxiUSDsE/WQYqPVHKK/+1jus178AmboD4JA
         T0jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=t+uehrKRpiH38VA174uD5qYjpsJHrPQAuUj7YG5ipCE=;
        fh=nyRikoTzNy8VPjvlG2UwB5Xu+O+PdwODPYw0IW1inkc=;
        b=IZVyppUW98eZwssJWEHkQ6WGYJhlUpW5cv4nq4zf9Yl9/JeamQ5pXEgn4KuoOcKNtg
         MzKrdO+BINf0u1xsaqnBerlZreJ/cvBDwlPTEbv8gUa4/x1y8NYw3Qn5oHiCrzgQLir+
         ycV5aVzUbfNR9zhNQIsVllAsnm2C5ieTorra7bGeAqWDRx9fvbjWu5RN8BqkYOJ1eSgv
         4UEH7d2n4/gVc0xJiXm3XCO8CE9dzUMFTGodMKh5/oOW/o3HPowVUgaR735LtuOEPG7X
         zuWDksJHgdZwPebiLkT04+qzQ+RyA58kzDnWwzGWBdly2Pv3IOxV7Md3cYZaNNSngxUJ
         cdkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=changbin.du@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id bd2-20020a056808220200b003c1ca7945f4si784630oib.4.2024.03.11.05.07.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 Mar 2024 05:07:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of changbin.du@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from mail.maildlp.com (unknown [172.19.88.105])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4Ttb7K0DgjzsXKF;
	Mon, 11 Mar 2024 20:05:01 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (unknown [7.221.188.204])
	by mail.maildlp.com (Postfix) with ESMTPS id 808DA1400F4;
	Mon, 11 Mar 2024 20:07:05 +0800 (CST)
Received: from M910t (10.110.54.157) by kwepemd100011.china.huawei.com
 (7.221.188.204) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.2.1258.28; Mon, 11 Mar
 2024 20:07:03 +0800
Date: Mon, 11 Mar 2024 20:06:59 +0800
From: "'Changbin Du' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>
CC: Changbin Du <changbin.du@huawei.com>, Ingo Molnar <mingo@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>, Peter Zijlstra
	<peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot
	<vincent.guittot@linaro.org>, Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>, Ben Segall <bsegall@google.com>, Mel
 Gorman <mgorman@suse.de>, Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, Alexander Potapenko <glider@google.com>,
	<linux-kernel@vger.kernel.org>, Marco Elver <elver@google.com>
Subject: Re: [PATCH] mm: kmsan: fix instrumentation recursion on preempt_count
Message-ID: <20240311120659.2la4s5vwms5jebut@M910t>
References: <20240311112330.372158-1-changbin.du@huawei.com>
 <Ze7uJUynNXDjLmmn@FVFF77S0Q05N>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ze7uJUynNXDjLmmn@FVFF77S0Q05N>
X-Originating-IP: [10.110.54.157]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 kwepemd100011.china.huawei.com (7.221.188.204)
X-Original-Sender: changbin.du@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of changbin.du@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=changbin.du@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Changbin Du <changbin.du@huawei.com>
Reply-To: Changbin Du <changbin.du@huawei.com>
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

On Mon, Mar 11, 2024 at 11:42:29AM +0000, Mark Rutland wrote:
> On Mon, Mar 11, 2024 at 07:23:30PM +0800, Changbin Du wrote:
> > This disables msan check for preempt_count_{add,sub} to fix a
> > instrumentation recursion issue on preempt_count:
> > 
> >   __msan_metadata_ptr_for_load_4() -> kmsan_virt_addr_valid() ->
> > 	preempt_disable() -> __msan_metadata_ptr_for_load_4()
> > 
> > With this fix, I was able to run kmsan kernel with:
> >   o CONFIG_DEBUG_KMEMLEAK=n
> >   o CONFIG_KFENCE=n
> >   o CONFIG_LOCKDEP=n
> > 
> > KMEMLEAK and KFENCE generate too many false positives in unwinding code.
> > LOCKDEP still introduces instrumenting recursions issue. But these are
> > other issues expected to be fixed.
> > 
> > Cc: Marco Elver <elver@google.com>
> > Signed-off-by: Changbin Du <changbin.du@huawei.com>
> > ---
> >  kernel/sched/core.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> > 
> > diff --git a/kernel/sched/core.c b/kernel/sched/core.c
> > index 9116bcc90346..5b63bb98e60a 100644
> > --- a/kernel/sched/core.c
> > +++ b/kernel/sched/core.c
> > @@ -5848,7 +5848,7 @@ static inline void preempt_latency_start(int val)
> >  	}
> >  }
> >  
> > -void preempt_count_add(int val)
> > +void __no_kmsan_checks preempt_count_add(int val)
> >  {
> >  #ifdef CONFIG_DEBUG_PREEMPT
> >  	/*
> > @@ -5880,7 +5880,7 @@ static inline void preempt_latency_stop(int val)
> >  		trace_preempt_on(CALLER_ADDR0, get_lock_parent_ip());
> >  }
> 
> What prevents a larger loop via one of the calles of preempt_count_{add,sub}()
> 
> For example, via preempt_latency_{start,stop}() ?
> 
> ... or via some *other* instrumentation that might be placed in those?
> 
> I suspect we should be using noinstr or __always_inline in a bunch of places to
> clean this up properly.
>
In my local build, these two are not that small for inlining. (I has preempt_off
tracer enabled).

$ readelf -s vmlinux | grep -sw -E 'preempt_count_add|preempt_count_sub'
157043: ffffffff81174de0   186 FUNC    GLOBAL DEFAULT    1 preempt_count_add
157045: ffffffff81174eb0   216 FUNC    GLOBAL DEFAULT    1 preempt_count_sub

The noinstr adds __no_sanitize_memory to the tagged functions so we might see
many false positives.

> Mark.

-- 
Cheers,
Changbin Du

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240311120659.2la4s5vwms5jebut%40M910t.
