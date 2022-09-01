Return-Path: <kasan-dev+bncBDBK55H2UQKRB5WEYGMAMGQE3RPJKKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id C94335A90AE
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Sep 2022 09:42:47 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id o23-20020ac25e37000000b0049475eb7a25sf2246828lfg.20
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Sep 2022 00:42:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662018167; cv=pass;
        d=google.com; s=arc-20160816;
        b=UPD3rWZluf2JA7pg258bkcPk//yDO/RRfAvC1wKGWbGeJcDMbGRWnvYbpIsk397E5c
         JjkF9RlwNLFFYfrJarRANsU4CLsOXfd8mKxPg5JQ9u52/VhPWvl/rn0TgBfV/oLIlYr2
         zm+kqiHPdkSxKNjcfLrG2QD1C+Y4bawBQ8yIxMfzbeY1bVG+W3SFndS4lm2Pku+KTVc9
         YRqXpcTYAAAZygKlKmsya+3Z7lgY4cFmUQaVwA5VuoJ2TWUsX6/e3HzVH04pBASJLJri
         t5DaAwBvzJHWs3EZsfnHglC4hSIUw6pXrhjyWcPR9lBJRZ04392SyGXycPIRhuvPCutX
         C4tQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=72apmhBRFkgNOxnftNDdrEwL5oai8rzJb+dGNedfJlk=;
        b=TLjIuzIAhG1mj/WF/m58Tc565rVw1brHPko7/6d2i6oVAfB2k4QurRANwoEMz86r0Q
         Y0j2bBawVR1/gQbGvg7iU/sFuM4GyeujIXotVr/k6NPZqdIC6xuhXhp2LOEeVNCnhn8/
         Rj8b57DoB75DztT06tzq88ZpDn93I4Qrmlgwt37jOsWcJ0aXRunIwODIP+XlAnjHQ9gC
         FNed9Q9/cZFdg5CM9EeCCeGV7mhD3WsXCvBGk0Z5ENtwilRHiSMuUKCE+e3f3eG5wQPC
         eH5dplq/LdUUTxt3oSSHkmIMLl+JPtw92WvaWodeYTp1II814VSOS9Um+Fv4N1o7rhEk
         w/Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=cEnZuv0S;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=72apmhBRFkgNOxnftNDdrEwL5oai8rzJb+dGNedfJlk=;
        b=a6SJsXCNcoqEXEhbkQZyxx4l4qM2mtiuZboYgSS78mSoDWUfPFM3ECfbgkhb9EbWwH
         Wc5aiVFVje5/CRqEgQjFvuoCTt8JU5zDALhdAKwPiIGkeh/Rug3ZrWaGZ2xC38t8JnRr
         GA3XOInP3M7kGp84OKjw89CSWqYeuy8uwItphsFrIB3XrPJ7mRlMqEL/OVgJA7ZQ6DJk
         9QGEF0epWWVKil6Dt8FcfNmM8f0uiq3PauVxtXwU2EyV4wEReeVY64GwDf9yajMio1Wv
         vZ3NiJ6y1T7V+Drs5dU0dzWcMjtCbWOILeu1DHGzmblHAabDowTQw/qbBd9WxFt9W8oX
         wqdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=72apmhBRFkgNOxnftNDdrEwL5oai8rzJb+dGNedfJlk=;
        b=R0bbircISpDVhEVJT/DOHBFEflqXPx4msPcFXx2D4I059sxXcpTQ7m+PE6FHpKY+dL
         SgdUvv/c0eCtlLjpBUgfgQsqK1OWiJR5lCeDXdPRUhIsNizY32ULpnGBFhXvgdIllknF
         5rVDsAKvji1UQZWIZj7DrjXpqHpBU4xnizwcxhM10Lob2na1/bN1JYzxH2q0VI+kDzgp
         j9+R+zsjnjavk0VtvZIKvpqYCqfkhrARJb2BvKpzm/c0DHaiehaI/cC5u10NcoG4EhJC
         Sh5OQp6Yf+ISPyDKNbu3WbSvPz3MLudKENdqSWzQhkAF0fJZX+PFtBtdZP0sRK/+50EW
         kIcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3WtmUd73wkaU7iv3G7APIkZz6UJjnzluy+zIaXvzPK25I9OpwY
	aJD3rDgy49GcJGORBBSyiT0=
X-Google-Smtp-Source: AA6agR7PQbCCmlcyCnI1V6cI9IV+N1K+zJJx6wYoDJDGEhwNnlPpngRTSRNZO8Ut/k5vIhBi2G+JZw==
X-Received: by 2002:a19:5e02:0:b0:48b:1870:dc4 with SMTP id s2-20020a195e02000000b0048b18700dc4mr11055244lfb.4.1662018167044;
        Thu, 01 Sep 2022 00:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a912:0:b0:25d:4f02:5abf with SMTP id j18-20020a2ea912000000b0025d4f025abfls175028ljq.2.-pod-prod-gmail;
 Thu, 01 Sep 2022 00:42:45 -0700 (PDT)
X-Received: by 2002:a05:651c:516:b0:25f:f52b:3c86 with SMTP id o22-20020a05651c051600b0025ff52b3c86mr9318062ljp.523.1662018165583;
        Thu, 01 Sep 2022 00:42:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662018165; cv=none;
        d=google.com; s=arc-20160816;
        b=FV84YytBFy4RW666c4XxTFQg5pFuJTfozZa0u7X1b+ofme/tZMXcdzyeC21/t7bhgg
         +zdaUD48rPfu4Nmo7R5LfXUAd11MUmYT5i0j/xQNqzMBznW2E75oElC1fJCxjTHvYtOL
         JA08vJaaquUZeN3aZI4iJZAY5i9jv7wCuTeMkKwUhdwXImkFHSpiP9vzLvCBcI6heRmD
         eEXd/RfvqR+g/fN8ZufmCfE0RzFhbyud36b5EBLt3alPbHhuCY0s7h836pqCWjeFZJ1K
         dZCrQH0Y/OCeDY86BrSJuV2Ip9lj0s+/0Cbol/PfjwCUCQ45rSq7KhFsP0nayNB1ceg4
         rI5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3R95H7o4Ps0Xt8Fb2RGRK8ftexUpMSTfRccKzarlwv8=;
        b=BEZRyJvSOztN32eL+LIIwCfl3X8LAY1fcfNIAzeJkQUlbDAZaFwuGXNRvBZriLjDr2
         RwW8YSsqHySqS9G9q5NNFfDjfXZrfR6gzwT3WaJNNr2gpLGh5ry/EW4aHq2AzK+z+Z0w
         VItarMVguRGKnAFUPsPO74oF0+elThbMwSq95RgrRkbD1YMSR1PUHXPPoNF5Ho0vzhm6
         +/THt+wYCaiEw0xtDucaKk9I77mlpYc5dnL3Hx/Kh23DLL/I4gG+hwXAlVxOfHnCw+yX
         YHc8ElKZhSASJFTxwWHFegOn0DtzcYURihkkXv7LbTtCwome5lla6ionSwMAi47EILrD
         lz8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=cEnZuv0S;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id k22-20020a05651c10b600b0025e5351aa9bsi387049ljn.7.2022.09.01.00.42.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Sep 2022 00:42:45 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oTeqK-008Lun-Me; Thu, 01 Sep 2022 07:42:29 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 42B7B3004C3;
	Thu,  1 Sep 2022 09:42:27 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 344DD2B871FC3; Thu,  1 Sep 2022 09:42:27 +0200 (CEST)
Date: Thu, 1 Sep 2022 09:42:27 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Mel Gorman <mgorman@suse.de>, Suren Baghdasaryan <surenb@google.com>,
	akpm@linux-foundation.org, mhocko@suse.com, vbabka@suse.cz,
	hannes@cmpxchg.org, roman.gushchin@linux.dev, dave@stgolabs.net,
	willy@infradead.org, liam.howlett@oracle.com, void@manifault.com,
	juri.lelli@redhat.com, ldufour@linux.ibm.com, peterx@redhat.com,
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org,
	masahiroy@kernel.org, nathan@kernel.org, changbin.du@intel.com,
	ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, arnd@arndb.de,
	jbaron@akamai.com, rientjes@google.com, minchan@google.com,
	kaleshsingh@google.com, kernel-team@android.com, linux-mm@kvack.org,
	iommu@lists.linux.dev, kasan-dev@googlegroups.com,
	io-uring@vger.kernel.org, linux-arch@vger.kernel.org,
	xen-devel@lists.xenproject.org, linux-bcache@vger.kernel.org,
	linux-modules@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [RFC PATCH 00/30] Code tagging framework and applications
Message-ID: <YxBiY5hDUSE4ZqKM@hirez.programming.kicks-ass.net>
References: <20220830214919.53220-1-surenb@google.com>
 <Yw8P8xZ4zqu121xL@hirez.programming.kicks-ass.net>
 <20220831084230.3ti3vitrzhzsu3fs@moria.home.lan>
 <20220831101948.f3etturccmp5ovkl@suse.de>
 <20220831155941.q5umplytbx6offku@moria.home.lan>
 <YxBZv1pZ6N2vwcP3@hirez.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YxBZv1pZ6N2vwcP3@hirez.programming.kicks-ass.net>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=cEnZuv0S;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Thu, Sep 01, 2022 at 09:05:36AM +0200, Peter Zijlstra wrote:
> On Wed, Aug 31, 2022 at 11:59:41AM -0400, Kent Overstreet wrote:
> 
> > Also, ftrace can drop events. Not really ideal if under system load your memory
> > accounting numbers start to drift.
> 
> You could attach custom handlers to tracepoints. If you were to replace
> these unconditional code hooks of yours with tracepoints then you could
> conditionally (say at boot) register custom handlers that do the
> accounting you want.
> 
> Nobody is mandating you use the ftrace ringbuffer to consume tracepoints.
> Many people these days attach eBPF scripts to them and do whatever they
> want.

Look at kernel/trace/blktrace.c for a fine in-kernel !BFP example of this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YxBiY5hDUSE4ZqKM%40hirez.programming.kicks-ass.net.
