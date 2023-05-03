Return-Path: <kasan-dev+bncBCS2NBWRUIFBBJV3ZKRAMGQEIRUX3JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C5BD36F5D34
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 19:45:11 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-4eff7227f49sf3373611e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 10:45:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683135911; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkEG6EnXKA4oL/2i6Td5GZNEXYa8khKpg0tQKNOzx/ejuDfl/KQyD/lFqZV4aNwJlD
         aZazxCuKstqBJPZkySaMLgsuGVLV+pngTm6ChWK0MOUniylGvV5aS1x/cY/LOnS97aIh
         hyfwEOBF/Y9ThBKmTECvoKhfl67Vk22VVBESGQMVEkjaodScHPpZIu54zYHpWDgi/OBa
         uk6vCXXtMaiqcmgOKOIuWdPS5dSjCosH520UUrrUenp5B7YOHCv9dEGIjZuSYc54bou2
         rSTm53ND3ZeCyEB9Ba9+DRVaanE06BwPnl5pqYmps3BY2o1XTVhh5DRo5GfPXoGLReS/
         G0Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=skMgZrfVTBKa56h4lRwMvEjR81crZqAr4Lr6utdSmms=;
        b=dV3Ef4Rf/2o0DdPcjNr3b426OxYy3k9SLb0S9MxACJLbAOHjVSeNrce+3lphoWza2/
         vDCwZlDn9Btfl6rKZ9ea602V15vIt7LiSxdRhtfb7PHa7dQI8VJTctR+mHgpFbtvNotp
         wwaYkbBmES77eF0sYdrEr5Znjeriqr0/qTSbdImjCmYA1aQ1HA3RGB7ibSdJVasu2n7t
         FvUuIzEYe5aLNBK5TYkE9qTieyo2nJ6+rId/V9jrVP9rqP8vdz5qxNRk73XQsPMXiwA6
         k84R5tcmM1WxCnx8Hmm0g2bs3igz8N5I7SWp3FcJsfArPoRKguynbASNSioC8m07tSAN
         tJIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Bqk+D3wk;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::33 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683135911; x=1685727911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=skMgZrfVTBKa56h4lRwMvEjR81crZqAr4Lr6utdSmms=;
        b=IUf3LgDFP5x4Havy/8gEcjvuamkVmAw9S4ZSLt09aMwkfXSwSnJl2MJ0q8VjdI6JF5
         Hi12499FXI4zViNfInIgWOy7ObiNKmH5MdQWuiV190rP9XNJ/kb/9ZbWPWQMvgU+ZPRb
         eU3K1Q3tC7wrSPWgB4ua5GxzTuKO0KSoq3ht5CXMCMrCF/uEGoa54PAufnHNiXMbQcKP
         YhHYhfO2tpl5hP2yraifJHhEJhZsfYxca+8pYlVIFRZQP0xrOa4fsaRzc4I52upexUfN
         TMRNQUqoJt+hyEkJKagaeeyhiT+Z8ux+t0nZsojjgrdMReHbigP9D2baLWZ3up11KGpT
         uceQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683135911; x=1685727911;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=skMgZrfVTBKa56h4lRwMvEjR81crZqAr4Lr6utdSmms=;
        b=YsOE+kVUUxq1Ejh0ENJFVLLVUHb5caI/CGj5U02o8dq+cCXQSF8mVOvUbhQs/d+VjW
         AoXBXfoUFKsOzPgU59T27eq3S0onhXUCq5TewqCEdi6noahr20EjS0O33iWQMFNrcTL2
         LbKJVvMaE+ysij5Ec0bm0aXYPusGynfGYE84I09dszURisc39hfrJoa/ilaxDgDB6PUP
         0hgvV31QsY6fWk/QD+/6Sl6BDqTNawTpoZGeFfVE4QkMpSZSa0/XK6VYUgirB2eXY/D0
         Y2EeIJSOJ0a3XQVwcsn8ZB6BrVP5QZbY7Zex1m71a8mM6Xe5yFzvj3bNDQnoSjcUJJhS
         +t3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDxieLh/pn2zIq1eg0Xr+HpAJodILSJfLdH4np4mqo7trQVuum3K
	YlGDx6RUWB26UwTgRASIst4=
X-Google-Smtp-Source: ACHHUZ5RjmQOFlpMfdOiQsp2Mtt4oc4cJPoLt43aGVw8C8tmDBsM4O7Wa0rplYQ7apOi4fqb4SO4WQ==
X-Received: by 2002:ac2:5d47:0:b0:4eb:93a:41f0 with SMTP id w7-20020ac25d47000000b004eb093a41f0mr1026182lfd.4.1683135911029;
        Wed, 03 May 2023 10:45:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1617:b0:2a6:20dc:a0e8 with SMTP id
 f23-20020a05651c161700b002a620dca0e8ls3558445ljq.0.-pod-prod-gmail; Wed, 03
 May 2023 10:45:09 -0700 (PDT)
X-Received: by 2002:a2e:9bc6:0:b0:2a7:aeca:511f with SMTP id w6-20020a2e9bc6000000b002a7aeca511fmr259175ljj.43.1683135909599;
        Wed, 03 May 2023 10:45:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683135909; cv=none;
        d=google.com; s=arc-20160816;
        b=IdZQFWoqMG5W1CMLODgGlAFael6Qmzi07zlJAkWi7ry7xFLusDo+ACAUAbrOnqGNT3
         rQ1KaJFP4yNe5qLYHbXlRCKSpfrCDtFasmsSQ70WCiQ0RZ9MryyfIZcA36W7eZN5h9lO
         oyl+8E7JyxbRRjC1PVdMd6mG25oiAxkvh1Apr2X+xtxrF3WuogF/Ikg38RvCTshJ6jTn
         kPmoYckpeXMWwrwfKLuO1QKZjocvH/PW+QP4P99I98BAX9j0JGDepDNUCezHsYyy5V/M
         42b35uwKzZNsze8NFPOJlg91Sr29FHknxFhOTfJh0YEkMl09c54JfoJVQKNa2So6yc9D
         wC0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=VLjEZmUZdVYCB3vahsC4N4RlfMUKbdvDvHs1QSrBbkc=;
        b=TrYLFH+Laa7qJmH6Xc59UvOgO/ZOZ00OlrtQBZ1Hz5GuvDrwP/QRX4tnswGQALAasO
         1VOoFNB5yA/nTNIc39pnEPeKWsmpj5QsfoEG+jMCrNUmracqUrh5dYKdQC8as0uGcojZ
         qWhXijpnrBNXJBmNKwpw2f3MLuwptoPlixYaIO86BZ11G7F8LcAvsz8hqRCpxcW57DKX
         Rkb7K13M9TEP/hGcdSjy/G+VknFpLlVdmMo3FTAmw4gn43/D055PjKfoe10uhpGB+0CN
         6eqGCed9tf2IgU72BZQyy5T3gzVgs/vaAwMZ3HM3cX3bJufIJrv4JLPXT6gl91oQJUCQ
         bKvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Bqk+D3wk;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::33 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-51.mta0.migadu.com (out-51.mta0.migadu.com. [2001:41d0:1004:224b::33])
        by gmr-mx.google.com with ESMTPS id h14-20020a05651c158e00b002aa399f4d60si1720447ljq.6.2023.05.03.10.45.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 10:45:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:1004:224b::33 as permitted sender) client-ip=2001:41d0:1004:224b::33;
Date: Wed, 3 May 2023 13:44:56 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Tejun Heo <tj@kernel.org>
Cc: Michal Hocko <mhocko@suse.com>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org,
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net,
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com,
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org,
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org,
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
Message-ID: <ZFKdmMe21U3LqGGD@moria.home.lan>
References: <20230501165450.15352-1-surenb@google.com>
 <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan>
 <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Bqk+D3wk;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:1004:224b::33 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
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

On Wed, May 03, 2023 at 06:35:49AM -1000, Tejun Heo wrote:
> Hello, Kent.
> 
> On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> > No, we're still waiting on the tracing people to _demonstrate_, not
> > claim, that this is at all possible in a comparable way with tracing. 
> 
> So, we (meta) happen to do stuff like this all the time in the fleet to hunt
> down tricky persistent problems like memory leaks, ref leaks, what-have-you.
> In recent kernels, with kprobe and BPF, our ability to debug these sorts of
> problems has improved a great deal. Below, I'm attaching a bcc script I used
> to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
> can follow the same pattern.
> 
> There are of course some pros and cons to this approach:
> 
> Pros:
> 
> * The framework doesn't really have any runtime overhead, so we can have it
>   deployed in the entire fleet and debug wherever problem is.
> 
> * It's fully flexible and programmable which enables non-trivial filtering
>   and summarizing to be done inside kernel w/ BPF as necessary, which is
>   pretty handy for tracking high frequency events.
> 
> * BPF is pretty performant. Dedicated built-in kernel code can do better of
>   course but BPF's jit compiled code & its data structures are fast enough.
>   I don't remember any time this was a problem.

You're still going to have the inherent overhead a separate index of
outstanding memory allocations, so that frees can be decremented to the
correct callsite.

The BPF approach is going to be _way_ higher overhead if you try to use
it as a general profiler, like this is.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFKdmMe21U3LqGGD%40moria.home.lan.
