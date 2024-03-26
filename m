Return-Path: <kasan-dev+bncBCS5D2F7IUIMT6UIWADBUBFG5ZURE@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 8BA6188B821
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 04:13:14 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id 4fb4d7f45d1cf-5684bf1440dsf1551711a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Mar 2024 20:13:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711422794; cv=pass;
        d=google.com; s=arc-20160816;
        b=tW1VgmEyuAQcuq2+vMj22VKwo89zZyrcIKFZqXLhIcq+sbDKL8c0aLtfaHH1yOfNIc
         0BhKSaH1paTTspiVXx0eRq2j/Ci3b+sdH3WqH1bAnVmgfPSTqSF+x591rSMLAR0ZCCes
         urOV1zlWy0BsYEdDpmIU5b+dLbCGjH5oNcFfoTxJWgEm8wd7oZiR0MAR3ytYXr0esJ0L
         S6kPlSzZkCUzpagAu0mZ80WUcEOC3ASr8mBEeisWkKxctKu6glCIyJ+OnsdLjU3H7zdW
         R3rvsb8eGoSPlk4DonPUikKkrSFcZx8+QajhMK+vgPnFGyFUK6Aw0/u5NeHjdFj5HShx
         cSHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=4nZ258ZdarxG3isZGes0XPaNbyxfuDBj7moOXvN+1L0=;
        fh=6yP1M+08J1Vpos/xO0iM87aCnPEYoEhm/KKrsNao9hg=;
        b=F+4eoCg6dFHU0vTGJBjVrazSBMIK1IemkTcaEQ97OYaCiL2iq24LPAQoXl8N3xPwoH
         a48r7jXsGWSvmltWmgMWoLHb4AKH7kdqWgKXrmOg6kS59FSMiTxWjcdd8i31e42HZynN
         suC8rW6UFWOzDfyPwjjSaIasVqSYmM9FQjtdk8gZbJMZIirqkID4gyd1gewcsuayX/4I
         OHw471077mufVY5SWJ8yfd1UM0rOPs7RY03ibq4IHmS4+YQUFDFOk0g9yz2Zipr7nTzs
         rnGrd74wTN3k2wh+txUSjNHhaJo49Xkj19yWDnfUuZPO9ZYsEUEzXhRuyUwqbtKMwZhN
         003g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SCLuPgk5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711422794; x=1712027594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4nZ258ZdarxG3isZGes0XPaNbyxfuDBj7moOXvN+1L0=;
        b=YdlXqspWv44aeQ42wJZoJHmnj0fpyptgnTbT64TlsRZ/R0WFCg8fDxUJIxVJ7EXa+/
         2NV0GzrmaJb8DFjQkmM7bk+XCLQ1YWhEfNBLZH1RfBXWwAJcPLGYgtbBZEot056cPna6
         SD8VVUZzuGAfEAA9PioiBRTrT8SyYtskBUjGNX+oAak506fL/jZjLdUCwhoC14Q41g2E
         ntFe2M05lrZlyFj8rGtTfYq768ch60uR/ziZTwdmDh0K5GDam6ZSxpQ8yYSvz8lJ50Cj
         ewXMQ69KpOh9jhSxX/shHFKptjoCoJ5PsxLx6wVTExcWIpQ5+0R+oeVAb1UF+ZjBuXUq
         ew5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711422794; x=1712027594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4nZ258ZdarxG3isZGes0XPaNbyxfuDBj7moOXvN+1L0=;
        b=XN74b6WIk1k5elBOb3Rf5gOve3TP4qTE2ax+UggwaUV+xcrkxUMdLkY4/NdALQGWUb
         iR6jGe+mnmWZmMSSozXzIXbWNRVzlbdcyjaaW7EMNDyTKAUKLqJ2vpkcwpkjwMrmD3rs
         2WRmBIdsbbVEeF4d3h192Yi+3ANAasYqoxewC1L/Uu93+4pNQZwOVe7p28B05Bxg1LqX
         IAU3qm7kbNmXBmsehMfSoepIOxsvIxRh/7F7ISP41thYl04kT0jyAHMEDcuOlNRkmOOO
         bIYCMD0hcLs44anjhzuXYiRpofZEKHsXeBw5vFSI87PTodHw7Jz0Tg8JEUVpfGdWyUNL
         B1LA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVLuKoNar7nqx1MHbxinM4TFkOyWK9QHIQWWCYtGlH2c45yupAFX14xGnK1dHTJhip7jqTlPrSp93HRtgrSCILGs7MzioC00g==
X-Gm-Message-State: AOJu0Yx3qSdeRz+R+6FJNzuR0HZwfgqHsYVXZQcO+Fpe6qehab+yNr+8
	HvSyvQyB8IK6v1043adYtvlI6L178C/cV0R+vFa2Bp7lOc6AK5hL
X-Google-Smtp-Source: AGHT+IFJltDauxzqnLh3NeE09mdMkKtywxF3tbMFRLfAIsiRlbQCN6DLUOhkFtI5gur1oPXiQ4rVOA==
X-Received: by 2002:a50:d758:0:b0:56b:a969:e742 with SMTP id i24-20020a50d758000000b0056ba969e742mr5649994edj.4.1711422793381;
        Mon, 25 Mar 2024 20:13:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3896:b0:56b:ebf6:a8be with SMTP id
 fd22-20020a056402389600b0056bebf6a8bels495618edb.1.-pod-prod-06-eu; Mon, 25
 Mar 2024 20:13:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAKJy1wiUU506EGK76gEKV9gdvzj7SsqyLy50E8lVzRU7txDuDjgWKv+oEP3LIOsO/toM9HhD0e/0gev15qrAMQVDnZauTlyeP2Q==
X-Received: by 2002:a17:907:a0a:b0:a47:52e7:1068 with SMTP id bb10-20020a1709070a0a00b00a4752e71068mr4036489ejc.52.1711422791347;
        Mon, 25 Mar 2024 20:13:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711422791; cv=none;
        d=google.com; s=arc-20160816;
        b=VUfbPJvkKuK3vFtyxyD2aceRcacGvkUtkZR5RZ35ezl5ip8mSP8VeKa2SNmx/UOf+R
         SPODVZeqSbYIflejTIGs4dhRj5NN6r6LaVtD/VgfU/384XX20HgDaXupfghsVjr/ONzW
         gkCgxeAqtwvdM//ZerP0PdxtGErry0eyXTkuEU3CukkOJ6Wot/BAFJjV+S29CD0aPRf0
         81YwPDBQ/SMEIeoilmfyEasHkiZCqrSd9PJUfF7cc3pvO4go2TFc+TzqKtf7NaqTlebO
         oA7hHiGMSMmcY6xgcigIthuxEAmaFLV6+stpR5qPCP1MbX56xM1LncoQp/c1B9iSEIum
         Qj2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=oyTIYfAEgFR5EqikXW3EqaVFHy5A7Gf0H+FFygqy/tY=;
        fh=smj1+IZujXiiBWQPOPcy2FzTFvSfcA84M//ihXQ940Q=;
        b=fwjEMopslnylGH1yoBPiBgKSsjw7uTCQrtaFNJl6CLCQqejtXv3EWXH48EpEoGO0NK
         V9NZY4ws+ioEFAxTqaZZahSeeS2rCmKipkeVCbSCtSPtY9XQvsilCjTTvEe2G31E3amP
         7MCOIS1tsHt/sybGNTiCJ+nEt8zhPDZ3h7jWv2QiVOpdABAC56QsJ4c1T8KJJRh0WS2B
         GeA11HnjRHDzLdKoCZuDRp2GbmVy+R0GiGF3hfrlCa3uDPPmo8Xc2Jrd61cplQgLqxAD
         L+nmJsXDlqLbjQdpEVt949LFi2ZF0tZkHlisj5hrFsHql338+nfSh6XczSgEo4mGxIx4
         3qWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=SCLuPgk5;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id gt44-20020a1709072dac00b00a45a3691f9dsi235389ejc.1.2024.03.25.20.13.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 25 Mar 2024 20:13:11 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1roxEn-00000000Lm5-3f0u;
	Tue, 26 Mar 2024 03:12:34 +0000
Date: Tue, 26 Mar 2024 03:12:33 +0000
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
Subject: Re: [PATCH v6 14/37] lib: introduce support for page allocation
 tagging
Message-ID: <ZgI9Iejn6DanJZ-9@casper.infradead.org>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-15-surenb@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240321163705.3067592-15-surenb@google.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=SCLuPgk5;
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

On Thu, Mar 21, 2024 at 09:36:36AM -0700, Suren Baghdasaryan wrote:
> +++ b/include/linux/pgalloc_tag.h
> @@ -0,0 +1,78 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +/*
> + * page allocation tagging
> + */
> +#ifndef _LINUX_PGALLOC_TAG_H
> +#define _LINUX_PGALLOC_TAG_H
> +
> +#include <linux/alloc_tag.h>
> +
> +#ifdef CONFIG_MEM_ALLOC_PROFILING
> +
> +#include <linux/page_ext.h>
> +
> +extern struct page_ext_operations page_alloc_tagging_ops;
> +extern struct page_ext *page_ext_get(struct page *page);
> +extern void page_ext_put(struct page_ext *page_ext);

Why are you duplicating theses two declarations?

I just deleted them locally and don't see any build problems.  tested with
x86-64 defconfig (full build), allnoconfig full build and allmodconfig
mm/ and fs/ (nobody has time to build allmodconfig drivers/)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZgI9Iejn6DanJZ-9%40casper.infradead.org.
