Return-Path: <kasan-dev+bncBCS2NBWRUIFBBMU2W6YAMGQECUPIB4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 951BF897AEE
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Apr 2024 23:42:11 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-415591b1500sf1800555e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Apr 2024 14:42:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712180531; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrRWtSpcHD6Xvk0cnGHlme7H8Z2yfNpK2emlQy1TKFw+zlGESw/WRXgF2+rTDhHOCu
         /MEUKUvanv9EQzMkU1qMLAze2ccpgMobCClfJtaNOvOQfPki+w6UGiuskE4EdKV6IICB
         g3CR45FuurhpGaAZvqihGDoqAAB0HeVR1cfLWpZRvexd916IlpRBzrCptvZ8hl/8lzC8
         jkoPDw1Sja80sRTLvhqdUpy8xjyzNqP8pHTLd0qz3IUq1H+u9mH4gf9Ed0WxjDbQ9noT
         3d55j408XsYFYRwqCvno8NQjb/odBLnO25GvZwcgtl/ISDMbLEG/KRA0wYAvhrjXBZFc
         Ufmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=G6lBde0mM0vJ6i9MuFh/J3vAis5wYV8TLQQln9bQHb8=;
        fh=QZWoSl5FR/E1IZpdy9D/Dn3M9qi5UUye9/oobqWArv4=;
        b=gXVg5NNlM6dIfLFKSPVir39FQoZqmt/L4pg1vl/B8vuv7n0+ERtQvxGNXb6hBErvvj
         vq+r3oMg1aemoIXqFvK7aotnStd3VaY9gbf2hrq5gFzQDHv3bhtW1tcIAVKI8xiQQsuW
         6lS3xjHi0vLkDCdFlYdptDttdHIHEa7CwM5cZJVsl+D1Qm3ib3ZEoUD3jZq41aWsj/Bg
         +J2Bi9ci8dV4Z65g+jdN8KAAuzZukSuejxp6KNua2wIBMSs6Yp+vPNfZzyofpXePq3Tc
         Mnjs+bA8859ItJOTEFO2W8Wq9MV4zR29HfA1ucmPOMprM/ddvLbXJZ9DOkAGn2h7HNrG
         iBKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lGMlDuct;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712180531; x=1712785331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G6lBde0mM0vJ6i9MuFh/J3vAis5wYV8TLQQln9bQHb8=;
        b=g5C+iJVupJrnd0XNPno17zFZzcUXjTT8JwwMNmzMgkxKTawAvOTBS5MXIOcHWyLbfQ
         kDecsz7ImHIBofynchwwV5Is+9hudBzJNdKHA9a0+9yyiZZItGh6N6oNB42ApEtZjufb
         aZgTZtOxzbXyViHMUhCBLwxdCLxUmAtwnGTQRv2VTVQ7lQIcqLUiqBocRMswFT8e4UjX
         xK99WI6gpqOrW9gUMQFBP72sx28ykvWKrPf3f9PNOjLutfEi6hbopxQAH/G1RA5Fzca4
         ORvkhzXQNw1VMzn7JgN0cr5Xx9+8SSa/2RUevLfMJ105pK5wzHgt+/HOWm8IBnalA7eY
         LL0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712180531; x=1712785331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G6lBde0mM0vJ6i9MuFh/J3vAis5wYV8TLQQln9bQHb8=;
        b=bTtaun26TcTDHuijXxyQq8/ZJ6ivMhZRxMuLve8E4GnVku8owIDweybdtB1kr3ZZs5
         iK9xDJYPRI5zyWGGi618g0OF5/W9o6zKAQIl7muyRk6r3FkTdVyjlEXY7mhFHBKfV8vN
         RkNc1IHL+96pGUoapuexLovodk+qiIHMb50QZfsipRQx8nFZqiLKUWRHk7JsvAThbcJL
         oLtJds1R5aXXE+v0c4inqwKehS/bAbt1Bf32n046sNi1yIeTXVekpVpn1S7aCWUsOi+k
         4DkPZEF71zsiU10dSmfFSsjU5Pxkn++iNZOGHGJxURFBjDwWag38tZ9Rp/qjTcCPPQCq
         Gw6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU+rgsyumYqBM99dWSSFLNoEfoFwrAf8xOw1snO7cQ3CBAhrtjCEiTmeDJEQNGfvbX2M0Ux2dfNbITtetHM5ehoI5p7BERGFg==
X-Gm-Message-State: AOJu0YwK3gwQ6gSoKBZa40XYnDunIvW3kXDveDydTPO0ri+aImLyPHNh
	nQD3B2idmWNhfEzSq+aIDc6SDoK8rPt6KB84dlLBMPESIcMHq6I6UYs=
X-Google-Smtp-Source: AGHT+IHgcQAvUhZ3r5yjBFICR9YQ3HHXR8jGZ9zWS/E628oWVtzTIbB5eYH3fxcQk0U8GoyJQGBGiw==
X-Received: by 2002:a05:600c:2187:b0:415:4dc2:8fcd with SMTP id e7-20020a05600c218700b004154dc28fcdmr513867wme.11.1712180530802;
        Wed, 03 Apr 2024 14:42:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c2a:b0:415:509c:891 with SMTP id
 j42-20020a05600c1c2a00b00415509c0891ls265188wms.0.-pod-prod-06-eu; Wed, 03
 Apr 2024 14:42:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXieF3E5wX9LbQEewgh6cWhNNT3e/Nyd4OkpIfeQjjZYhEpp8ilKzNLylzHwSAkBEfRrNCSOmuXa+OSJkMEbvXRkkZNayGANOkh4Q==
X-Received: by 2002:a05:600c:55c5:b0:416:1c9f:3a3f with SMTP id jq5-20020a05600c55c500b004161c9f3a3fmr570836wmb.9.1712180528855;
        Wed, 03 Apr 2024 14:42:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712180528; cv=none;
        d=google.com; s=arc-20160816;
        b=KP6OeBJp5RvIIhJWJd7djzgWOoQ6fFiPzoH738oJKm2vznbnXAibJ65B38WNSCqd4L
         AT1wuty7VwEKvQKctAZpD56SV5tm8TghOAn94QVz4kHLOFVZqRP623Z5pXLV3ukFliKx
         3RpFkjcC6R8w36hI85TPGbkpqUBB3SBTw7WSc5AcHJneoNHFGjFQHRGqfaIJIPKgfj9O
         ubJiP5wBJ6U33GFzoXp+8ZeYhF/a4W48tAYZ69kvQPZSqvpEajM3IS9GOoImpgbzKZpF
         tnW6Sf+Q9CH9p43E3PJ8OtRLOB1v38lUXEgtdcuH9fodydzNx5xEaVb0Ve8RyqlisfE2
         LFvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=I8oAok5It38shVDkwL940Pa8qX3ifwx6XR6MQgkhnY4=;
        fh=aD1s6htktLVNlJaqCQ//t7I8aiAokVLePVrnW43wBvE=;
        b=VI34kycRdT+JE7hzD06t2juFmtuXA6GhVvrtKVfmikaTxzxwDcIy7480lJ7a92IA94
         kgwECGXeMEAbgVA9K6R2ZdP8xAFERtSU3t0bAnWmGkmUCKqcAOsbtC8jPHHakBkJDr2Y
         kufDhG8V/N694y2EQMGnOCUEvOZWAGeQM6bAMIA1+txT0dQA7BtPN8YoyLjTNrMcuxE0
         7J5WqVyCupFwegJbDF9sBw137SaRb+/PmhFxwFc9DhqMR5T1HzaU5nIQH07KhMy29vFK
         gFvOeyrbRu2fOi71Auleon6MhUsW+9zfTRsD/ulRcDEll1JdtUXXoHyNL+edB334wfWR
         RF7g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lGMlDuct;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-178.mta1.migadu.com (out-178.mta1.migadu.com. [2001:41d0:203:375::b2])
        by gmr-mx.google.com with ESMTPS id dx14-20020a05600c63ce00b004161ed6e07dsi271480wmb.1.2024.04.03.14.42.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Apr 2024 14:42:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::b2 as permitted sender) client-ip=2001:41d0:203:375::b2;
Date: Wed, 3 Apr 2024 17:41:57 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, 
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, songmuchun@bytedance.com, 
	jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 01/37] fix missing vmalloc.h includes
Message-ID: <4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4@vzdhpalbmob3>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-2-surenb@google.com>
 <20240403211240.GA307137@dev-arch.thelio-3990X>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240403211240.GA307137@dev-arch.thelio-3990X>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lGMlDuct;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::b2 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, Apr 03, 2024 at 02:12:40PM -0700, Nathan Chancellor wrote:
> On Thu, Mar 21, 2024 at 09:36:23AM -0700, Suren Baghdasaryan wrote:
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> > 
> > The next patch drops vmalloc.h from a system header in order to fix
> > a circular dependency; this adds it to all the files that were pulling
> > it in implicitly.
> > 
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
> 
> I bisected an error that I see when building ARCH=loongarch allmodconfig
> to commit 302519d9e80a ("asm-generic/io.h: kill vmalloc.h dependency")
> in -next, which tells me that this patch likely needs to contain
> something along the following lines, as LoongArch was getting
> include/linux/sizes.h transitively through the vmalloc.h include in
> include/asm-generic/io.h.

gcc doesn't appear to be packaged for loongarch for debian (most other
cross compilers are), so that's going to make it hard for me to test
anything...

> 
> Cheers,
> Nathan
> 
>   In file included from arch/loongarch/include/asm/io.h:11,
>                    from include/linux/io.h:13,
>                    from arch/loongarch/mm/mmap.c:6:
>   include/asm-generic/io.h: In function 'ioport_map':
>   arch/loongarch/include/asm/addrspace.h:124:25: error: 'SZ_32M' undeclared (first use in this function); did you mean 'PS_32M'?
>     124 | #define PCI_IOSIZE      SZ_32M
>         |                         ^~~~~~
>   arch/loongarch/include/asm/addrspace.h:126:26: note: in expansion of macro 'PCI_IOSIZE'
>     126 | #define IO_SPACE_LIMIT  (PCI_IOSIZE - 1)
>         |                          ^~~~~~~~~~
>   include/asm-generic/io.h:1113:17: note: in expansion of macro 'IO_SPACE_LIMIT'
>    1113 |         port &= IO_SPACE_LIMIT;
>         |                 ^~~~~~~~~~~~~~
>   arch/loongarch/include/asm/addrspace.h:124:25: note: each undeclared identifier is reported only once for each function it appears in
>     124 | #define PCI_IOSIZE      SZ_32M
>         |                         ^~~~~~
>   arch/loongarch/include/asm/addrspace.h:126:26: note: in expansion of macro 'PCI_IOSIZE'
>     126 | #define IO_SPACE_LIMIT  (PCI_IOSIZE - 1)
>         |                          ^~~~~~~~~~
>   include/asm-generic/io.h:1113:17: note: in expansion of macro 'IO_SPACE_LIMIT'
>    1113 |         port &= IO_SPACE_LIMIT;
>         |                 ^~~~~~~~~~~~~~
> 
> diff --git a/arch/loongarch/include/asm/addrspace.h b/arch/loongarch/include/asm/addrspace.h
> index b24437e28c6e..7bd47d65bf7a 100644
> --- a/arch/loongarch/include/asm/addrspace.h
> +++ b/arch/loongarch/include/asm/addrspace.h
> @@ -11,6 +11,7 @@
>  #define _ASM_ADDRSPACE_H
>  
>  #include <linux/const.h>
> +#include <linux/sizes.h>
>  
>  #include <asm/loongarch.h>
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4qk7f3ra5lrqhtvmipmacgzo5qwnugrfxn5dd3j4wubzwqvmv4%40vzdhpalbmob3.
