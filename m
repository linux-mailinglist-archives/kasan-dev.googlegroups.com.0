Return-Path: <kasan-dev+bncBCS5D2F7IUIJLI4OWADBUBCANXBXC@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id C64B488D4FD
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 04:25:10 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4140d2917e6sf33176585e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Mar 2024 20:25:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711509910; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+Z6gTUoJR4fjQwmq/4Eui5sZcrNVxWoPgsR0MB1b0NIUDxF8YAvVEBF3Wiobk+j5d
         iL3oyLaWcnA2wdtfx+sNrLqvVOYCyc4xNU6ir7l4OVMOospLC/OyHl8Ajw4xuhPhkG+F
         t8o135zT1Ycu7Wqvzbggdj0vPoNh1R+NX2n4sNxDcfnWgnCuEDmN21VUTAqbCVRvZdWa
         eRy67q3pqVnXM79pcQa7CV9zhXXNzbRBgbT3+uDC4D2GWeT2uUEnMPV0F29o2NHksDWs
         p4tC+F0mUQNb8XuoYBSskL8ldJsQq+ZWSpb8ddHRYuIg1Q9xqIxQ6K6G3qcW+S5D+vk+
         tkDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=OYFyN1YCHLS1uol7SOcsEi1Ops/Pxcqiehq63khu4y0=;
        fh=2KbZ77ylrxiJBW5AALzxs63PTqswC2/GUtomgvVbQyU=;
        b=Nm+Ag2HwqISsRQVCbi12hWbgKa/BpKDAsILaVcNEJ4GXaIBh4EPZQNDnUOIBwinBjU
         Clb6fVj4NPLSL+kWxwZCIlGhGtX+gIV50NvoXVzwEg3Y1AKXkrfGb74PLYar2Bj17ueV
         cGVBxsga0lyK/nXeZrVBI0QNLVZx4GupTUSxZfagQ/y09rZ2Nc85VELEVv8uIox58yjj
         zj0jwQut6r1tk7XnqtkzfsA3Fa8Sxew82z0dLYgJFLQsGVoidXFw//r5WsA5Yn4LiYsE
         +DUJ6FNkGCBWwwmeZ/5QuWXYX5M0nnAoxkdfB2lOMxNwgmx+q7raPYV1EcYVFzP1yJZc
         l/bQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CvKbObme;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711509910; x=1712114710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OYFyN1YCHLS1uol7SOcsEi1Ops/Pxcqiehq63khu4y0=;
        b=bMsZt7HRD7IkXt13GpGFeyespMkd1EtvXqn6Zig7Y7VwlF7ksfKL7PifbC+sdeSUJX
         Kncm96S2DU5nUq+SYwGRAdsZQcIK5XE2/77sgJHQ9zwUpZBW5Hqnm06JCfC04Elmaf9s
         ZYD4XASnU9yvTaJr2e2f7vRb883NHJCQ8df5IePdZjWi/XVW3yqvlTDhBysfXyKU6KE9
         b1AihadGN9bEIKNsFVEICd8XmquJmbtPLy5WB5csT8UFZcdOqGwIZ3Hj11ELS/J9bFiq
         DCjXMrXC9fKX42use3I4q8+9mFVh9y8NRcdxmFRwH1c+1sMmCmBoQJ1tp8DEi4NNrFFV
         atGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711509910; x=1712114710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OYFyN1YCHLS1uol7SOcsEi1Ops/Pxcqiehq63khu4y0=;
        b=jjr1O31nlbAnY7n8gkSsJNvt8BpiPjfij3J26MJNyccVBDHoROLnpwDMYpy3kI9x8t
         iW7p0wHlmc8T5qhipPc2S3FgtzEbWNhf8W43fhSDRvFrsjqH8fTlt0A4IRM2mPIbbNNi
         jD9hal2q5dTLfyXkVuc4k6AZZWsS3gJHvbqHtoSyJLDZg1ymGRGTRI3DB2UNzxRbXBk5
         9Jr/g0xv260lvWftef4XOoWVsAB9y7RYhY80+VaNUs/4OwFQPkHWJrj9QVkk6JWEMuSb
         OyhdCnLhF8MwC1aovMhPes9E3t5V1duFHbeNbmC4M6jTdh4OOhcKraAAHJfD+7zOQu4g
         qeUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUZIw6TLZD2yVyqyS6BzRCuKRTqqYJYSvyvMqu7y+jQmHgkcmdF6cmIrSVULA9vyXrvKZ3JHA/ElBr+aoNRuvCtWWl2rp4ymg==
X-Gm-Message-State: AOJu0YxB3Xm9QHZUsup9PrCQwuXyfbnyUPJylU67NNU9CC42c4Ulg0FP
	nRHlfVgBFoLj/Al3FfCXJlZeZgMdp1R77okPr1YfcB3kYfeFmEFO
X-Google-Smtp-Source: AGHT+IEkDGVKCuHuUweRzCHNcIdx9KCsoa1SEeEA/ibJaFj4EFRvTikkc0nyjeml6rPRS2c5mb8zKQ==
X-Received: by 2002:a05:600c:ac1:b0:414:102f:488b with SMTP id c1-20020a05600c0ac100b00414102f488bmr2155011wmr.20.1711509909783;
        Tue, 26 Mar 2024 20:25:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:45d1:b0:414:89d5:9931 with SMTP id
 s17-20020a05600c45d100b0041489d59931ls1229880wmo.2.-pod-prod-02-eu; Tue, 26
 Mar 2024 20:25:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUnwPI3/PB1uppg7fwEXweOuo0aYacSABZgrIOxUs2pjpabX+ReovYYS9/gJ9el8AV/2W52xpCXVZwPUZImunRbE/AimtADckLEow==
X-Received: by 2002:a05:600c:4fd6:b0:414:82a8:24c with SMTP id o22-20020a05600c4fd600b0041482a8024cmr2175190wmq.29.1711509907789;
        Tue, 26 Mar 2024 20:25:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711509907; cv=none;
        d=google.com; s=arc-20160816;
        b=EJQHsVqhV3+b7mQmzlJ4xX3v4iihbh+HNrQnHEFGosAJDPrsQHW7aA6WGtSAJ1ScbH
         XIegO1/MoSwXBmr4+xiUOL/YM8ywLafnRXcGX2F37syC7zyNnTDFDFbnzSONg3WBOWKO
         P8M/Paq8ldlKNJV+8A0DK9fPnvbFCK5RTnAF5EJ+sF4myWVBPPV9aNzQWOUrgzoDQfx5
         zyBnCFTtTE3+EX1cOURl7mllDz+NKgM7cGZBZPMNPwUHMC6hf9xXXoiclIdFWgq5rs8H
         VxY15rx96vRMBHrvZrhxOYIjCca8k5wEe7XFLoKytC6qQLVRWOzm5uPCkjuPjG9kEk8I
         3K2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RlEUjYz6ln8uzzOTkIlgn9vdiC3nQ/IHmLuBP8wka2o=;
        fh=smj1+IZujXiiBWQPOPcy2FzTFvSfcA84M//ihXQ940Q=;
        b=eL1gD/R7FeDq9dopA56wqd40pAEGhnDDmuqc4UvP7KTJ2y1dCwJzNHdQmzOcapJdcC
         BWPVPUIJqhzjMEJuk9O4MoRXdjndd+6Vi3zsDFjT/F9zSk5OWs2/KetUGPU3i8jMifzA
         LPNxum2gPVYMM5vwWwPTOi9cczrRIuEuOBJ2qACtMfjl5RqpmJ0nXxUiFfBBCFT/5+qD
         uCtlGTkyddNkMaRkYWenyGWgV1t8kxBVtVqLkH/if5lf0NBZGuyOTEvu8/5NubITUz3F
         1xcqiO/wOzfXNHWbpKjZm7uB+mpcxtfm4BZJ4EaWeHit46+56dBnVxbutJy4SU5SOU/o
         06jA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=CvKbObme;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id e4-20020a05600c4e4400b004132f97fa43si228784wmq.0.2024.03.26.20.25.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 26 Mar 2024 20:25:07 -0700 (PDT)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rpJtt-00000002v5K-0VmM;
	Wed, 27 Mar 2024 03:24:29 +0000
Date: Wed, 27 Mar 2024 03:24:28 +0000
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
Message-ID: <ZgORbAY5F0MWgX5K@casper.infradead.org>
References: <20240321163705.3067592-1-surenb@google.com>
 <20240321163705.3067592-15-surenb@google.com>
 <ZgI9Iejn6DanJZ-9@casper.infradead.org>
 <CAJuCfpGvviA5H1Em=ymd8Yqz_UoBVGFOst_wbaA6AwGkvffPHg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJuCfpGvviA5H1Em=ymd8Yqz_UoBVGFOst_wbaA6AwGkvffPHg@mail.gmail.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=CvKbObme;
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

On Mon, Mar 25, 2024 at 11:23:25PM -0700, Suren Baghdasaryan wrote:
> Ah, good eye! We probably didn't include page_ext.h before and then
> when we did I missed removing these declarations. I'll post a fixup.
> Thanks!

Andrew's taken a patch from me to remove these two declarations as
part of marking them const.  No patch needed from you, just needed to
check there was no reason to have them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZgORbAY5F0MWgX5K%40casper.infradead.org.
