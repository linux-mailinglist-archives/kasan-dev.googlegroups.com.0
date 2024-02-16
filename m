Return-Path: <kasan-dev+bncBCS2NBWRUIFBBHG6X6XAMGQEOVQUNOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 099C1858A15
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Feb 2024 00:26:22 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-33cf6266c2esf1207646f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 15:26:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708125981; cv=pass;
        d=google.com; s=arc-20160816;
        b=wVkKORvj27BAJs5d5kGoXe1brPjEklyYq+0CLCJ5TTSYEWMRmNjrgGAZSoH45tbC2F
         XbjqHf85YTAgdmYILwr/6/y2kTEBKI2X62bCI2w1ObvuCk5u1XHVHpEegM8o2aH8OZHD
         I0Hz9mob28Kx4Qd3mXOFu4B0rg4Ws9dzJHZypK3QnewRMIflTxEZY3G1hJYl8YJda3up
         /AAtnQikTEatl8mR5RU1Z3iPGGRXYjkubMg7jmIDPxvbiYha+j/JpOCEYd+HzQ6ps9j0
         9YAgv8bEWf4AfNVWNzUHPMO7FA4FjCZ/8Wlx32fHV3MlGRT7BIRU4HFNb9Z2/cr78/hh
         EuHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wiUBvlqb6PcgCDeNn06yuNncYweB7hPmy4va+l7zmcw=;
        fh=DFHey2m0i5uSyd7l3WsUXhANPMjAfZ70CZFS+VRx5Es=;
        b=eFnKDmvsNqK6Ip5zvcUoS/S7ALPy1vw5ZEp2uA9jmo9xHdVHJXtJmo7vYGjdvlmGOz
         0jhWYKtb/GMGN/8A1wm/yvS7wajuszIQkaFD1CQT0Ms66yHhBpp0alxevQxSXKqMwP50
         uI4J2WyrpXdm3I46cf1TDqYi1L0Ctpi0+/hI+5whk3RQPJO10I/tG5+lX1/sFNBqz572
         FZOw8kmJzMfSrmKkesjjre1GKheHKhT6hPjSN0cZwQ5+t462d3soNe3JCzoctvcsXPjs
         OavoIxJunsE7ERVqXoACldhTm2l5o3+jd6xxELrnAcRXmsfchbOC1rCtOnwxt0JPbbuF
         UgDA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C1BPf5NM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708125981; x=1708730781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wiUBvlqb6PcgCDeNn06yuNncYweB7hPmy4va+l7zmcw=;
        b=gdD/KjfD01p26a+kHeozO/TnxVmckHXX0neqKXpSK/63Y49eFChGhlo0RB8MJOsO05
         vTgxZ8XgTQBlEvF0g+pj3cIeWUvEurUC4wUGyg6mTk4ijSR1Q/S8zQaPU5JmuwcqbE71
         XV4rmQsqjsawQMR1sYi/Oiy1lQZc5uJEGmqy0VOQ1JrINMUTf9/jv2plEgtARP9JT7dD
         ZsF+0nJtmOI+P90Q8MuFSBEymXzMVgznKhGQyiuypB0ItQbz+PegN41S4sLj4dqu5Fso
         UTZwJ4WGQr6xWm4L8EjqdNYYJoZyDvVWNDgtRD6G17uoQllYh4K0WjitfHl4WFnPBn+7
         nwkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708125981; x=1708730781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wiUBvlqb6PcgCDeNn06yuNncYweB7hPmy4va+l7zmcw=;
        b=Me22ovufbgFDzHNOTpF5+fOsW5mUwMKPShEYl7bNJLiDSODL/YxPzvGTcKYyTXTOno
         nRJ/tlHd2nqyYgeuj1wBWvcdnufcopL//G+n+Ma8KEk3BKqn1i1WWkOxOCUiO0zFoIYe
         0ECoEipsSUDgKBAy0cjYuRiw5/97bpEV5UYE+pxtlQrrUlaJUuc3+9xBfpeUmc95QFth
         NqyPd+CTDnSEKhiUOQweUuTYxpcB0IetA958XgERlSNItOK5/DL+bsqKeTQTFdNuT1W5
         5SLbsuTNdDSzsCbV4LnOFzSy6eaORqKmOhs9vBBANUoFmXe/FUNXCVs+rZg9YW4lpvP9
         01yQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoTs/hbvrJc8msYpfBIrwHRA7GrDpIblC3O12H0uCbeuYUt0XHDt0Eos9HvNCxmDhIXrwCajOTOjS44o1/wN7lMgrPrAIlRA==
X-Gm-Message-State: AOJu0YwDUztz3ZOh+s8yU/EytmGirpf35LPYXHMw0iGie0jdzj9kREkh
	S+vB/9VLXtsp7LZh3z0MZOKSEMh6PufmgT4tLqniL/zKC73di0zA
X-Google-Smtp-Source: AGHT+IETEaFIsNU6QZZ1dcFbCFkMCVOVIozhty/Sd5PljSscSeIBxaABpdPvaxxyqDmv2yqW8z7zXg==
X-Received: by 2002:adf:e504:0:b0:33c:f35c:a395 with SMTP id j4-20020adfe504000000b0033cf35ca395mr4203718wrm.52.1708125981081;
        Fri, 16 Feb 2024 15:26:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:10cf:b0:33d:1eea:9737 with SMTP id
 b15-20020a05600010cf00b0033d1eea9737ls283748wrx.0.-pod-prod-02-eu; Fri, 16
 Feb 2024 15:26:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzBoShVwPLPnHEEc/QdNli9P6uDZkJ3TMl3rduSONAD2Rw6zKjxZlGSBhVWQrxrjggUpRajv7SZWEgbddsd/Unih5CuNq+1OwnnQ==
X-Received: by 2002:a5d:4b4e:0:b0:33b:87c2:6700 with SMTP id w14-20020a5d4b4e000000b0033b87c26700mr3789197wrs.42.1708125979466;
        Fri, 16 Feb 2024 15:26:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708125979; cv=none;
        d=google.com; s=arc-20160816;
        b=NFNbBqew4yNPVsU4zQzknrNaVlVK2WH/NJjXb05/cjyBmI4EwRtwyfZrkZdzy8DTbO
         fRTFp93gYuZ1yogo0mYrPbkRRM0F86pQgUOQZOC3l7aQq7jclxLhYzHxMQvEsrKEVSVq
         nQVewVtWGa+YxXXkjiYEgxT/Js/Q1TO63ocZ6wkv66s5ITQc3EnxiRy5bc+ie98ps2XJ
         fqCKgBfp+FlhdMrsmResWE6xt7+xxMvxAygY8El0mz3BCedhl3JPYyJXkVomtCAq94ac
         Jdz5PGWMDJjeUaYb8Hxk4nPwqPN7C5eXBH1JWDiueLfmbJXilAmW1ErTpo1LLmlYafHX
         +r8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=i1dxXMhVUP1rgHFbx3bYUtrQ4Vj3OMrjAfFZh9B2nko=;
        fh=ZX1mQe9vQl9pPM1dVUQHi1h0y0vhcnnbIS+FULnWS30=;
        b=yeSbPLNKGhPfT5wmQaTUxQGQ7Ca7Pl74aEV57RiVo76hpWQEn32jBeW9CdRz9KAW4J
         czZKb3epMCho++dZs0FO6tv/hEAMgWyAnCNMhPjyyzrLlPO0hXUkY8fP8hGpCbyR40jb
         Yjr9ATfFHRnBzmAuhqAQKBVGnxocKhyEG+p5lkjLZmAWSIsmYG31qodS33kd1HgjXbAv
         HfFRrGJAusMZM0FEi5QiskOy+k0YHP8Tc42GJSGUNFzpXc01hv1aJmnaZBD6yJNjHBj9
         iZ7q5/FPiSxu3epCtBM0BZpllBmBNDRPwja/gLR0Df5zskwaDZpWDqMiISsHfjTNPcA6
         bZCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=C1BPf5NM;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta0.migadu.com (out-175.mta0.migadu.com. [91.218.175.175])
        by gmr-mx.google.com with ESMTPS id o19-20020a5d58d3000000b0033ce867f703si113361wrf.5.2024.02.16.15.26.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 15:26:19 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as permitted sender) client-ip=91.218.175.175;
Date: Fri, 16 Feb 2024 18:26:06 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Kees Cook <keescook@chromium.org>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 13/35] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <lvrwtp73y2upktswswekhhilrp2i742tmhcxi2c4gayyn24qd2@hdktbg3qutgb>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-14-surenb@google.com>
 <202402121433.5CC66F34B@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <202402121433.5CC66F34B@keescook>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=C1BPf5NM;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.175 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
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

On Mon, Feb 12, 2024 at 02:40:12PM -0800, Kees Cook wrote:
> On Mon, Feb 12, 2024 at 01:38:59PM -0800, Suren Baghdasaryan wrote:
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index ffe8f618ab86..da68a10517c8 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -770,6 +770,10 @@ struct task_struct {
> >  	unsigned int			flags;
> >  	unsigned int			ptrace;
> >  
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +	struct alloc_tag		*alloc_tag;
> > +#endif
> 
> Normally scheduling is very sensitive to having anything early in
> task_struct. I would suggest moving this the CONFIG_SCHED_CORE ifdef
> area.

This is even hotter than the scheduler members; we actually do want it
up front.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/lvrwtp73y2upktswswekhhilrp2i742tmhcxi2c4gayyn24qd2%40hdktbg3qutgb.
