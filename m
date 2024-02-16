Return-Path: <kasan-dev+bncBCS2NBWRUIFBBANLX2XAMGQEJ7GHS3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7139C85835A
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 18:04:02 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-40d62d3ae0csf12337315e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:04:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708103042; cv=pass;
        d=google.com; s=arc-20160816;
        b=yDwMlx88t8fVDQ1Awj5mZujnEwMpm7nlXWnIz3mxKHns1exq+pRO1kFdDcfkQZje94
         Jdq3atdCCrrvv2L2kItYmHIm15cZxGJ1NEHXTj7jDJ8FxeiskZETD7HXujkbqA2blOiA
         3bhO6w5CgQUt/QDJB0bdXH64W7Gw7kKPZgOmde2de6uzPNekPpkSgD7GFW9UTNGu15q0
         df7hcjtlQHN4HbuJoEQDnMeEjdtD+oDBi/2doJmqkmmxEvKmfxK2O7oMv0SyJH6US1A5
         /60j7cghY0noF0rxSlYSbsTZewSCLBJINto++VfwJ+WnMkCl7S5huiD3927NP2RIqFPM
         yHAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=d4KFXmQcwtEYA2ZnnQvsCMDjRyBOLhtHUK7ONO1IRTg=;
        fh=rK0MoF+XBfqc2jREfvGIYTS2aFyxOll0L0N0Gi7zlWo=;
        b=P5krU7VuyQ/3kwJScDn4GX+2RnofCdYX/Ixqhl7Zr6ZUSI/0VEsY8schZVcha2Rwvz
         MIL0eHQfr0R1fXbpqL8rkGZnn7Bh2VssOTgR57Z8YCIZLkgRW23DQVGttKVQxsJ0W0v3
         qUYDf7+i6y7JPZIY2AfdfycMGQ/RHdCwlNp6mII67HYqHR04IqXFbmaBNqFzLJIvJjsh
         Zvx8fr7t3ZwsDT0/R3k84xlz4VsxM+C3OytWVQpl/iwnqI4j/rTN84lmVCgwetMyT+gi
         X5IOB6BfI6/8sTHwefA2eqjXnzPYio4BDSnjjR7euSzDfd8N98iqI4YEcScoOtsLqFPC
         HXtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sfqp2+ZZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708103042; x=1708707842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d4KFXmQcwtEYA2ZnnQvsCMDjRyBOLhtHUK7ONO1IRTg=;
        b=NN0bUGtVeZ97rW78cZRjZMPJvi0BcDRoIeJklWnLn/jfo60BMRdbuPZyk1Eos51C8P
         T+N42haOUXN+PKijL5taIdvdp22d4zYeWokczgnf5M/b0xFVN6ePpcl1SPweFj9P9rLw
         MdjYISzksePFMLliX1kmOK4uJS+VsX41+5M2y7MlCnSbKRJgCzjD3eGaj3C859DULneE
         Tp4ZrtiEePxyhdWZd7M/ZTW+3IAIFvNN6FC8VIFREozIIn6is9yEZCLW2RTebdB0y+1A
         lwis2QYs5LCIChzTjUHEczITtj5OMp8y/IRzT/bG9uBN9mkSlAXbR1z0KtVjAZDbg9P/
         aPuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708103042; x=1708707842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=d4KFXmQcwtEYA2ZnnQvsCMDjRyBOLhtHUK7ONO1IRTg=;
        b=gVOJKqVNAxCvcrB4f0jF9nk0NIQVeL5M/2+scuhaKTAGE2a3bU3mR8R2qypza9J2ER
         x2wZ/ONc+k2uhLxLuTy/PiKEPAJTw/fzSTDwl9OjMMDRhTPo0T6O5Vuwmq//I4/hG+7+
         Ip7QGJAbSnQ1ywLyak9p9qEFPZ7MkzhqQnpiGdLsmWIH0d3PZTjEa+iU4JIAj+8MBwS8
         Xoj99h6MfI+vGHdALQUaOZ8SwHnIne6eKBz9YwevzieNPINSZvt5Kh52SyPR6/ROBM4Y
         feNJdjupKwdYXGDsXQZMgRKERHjMuhfEWOBVFnoZySWXva/MQ//b85+sslxxVExgiEcq
         sqjA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcm8a+xAOkwY7uf3lJfQStKdKjPPo6dsiAsM+oCeffmEn+Du+h+cRz0S30fgZV+Wo33aAPoTSts6yT9OR22t5AJnBkIJpKsw==
X-Gm-Message-State: AOJu0Yy+ZGU2YITF1d98zu92COwhTs2i872Hqpig1XN2fDJhi9TYYBOb
	LPlAGeXAZegWI5VuPPj4OEmNK1FHFk3m3vTtwRO2oRLkxOclixNR
X-Google-Smtp-Source: AGHT+IGaL3X5ltWjFPi7rvtlMKITRTfPZBzMFDqj52MlnhHbX/TPQZo/sIZyifp5DfMbaEuplHqPWQ==
X-Received: by 2002:a05:600c:358c:b0:40f:b691:d3c1 with SMTP id p12-20020a05600c358c00b0040fb691d3c1mr4079180wmq.30.1708103041620;
        Fri, 16 Feb 2024 09:04:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5011:b0:412:432e:43a with SMTP id
 n17-20020a05600c501100b00412432e043als392774wmr.0.-pod-prod-05-eu; Fri, 16
 Feb 2024 09:04:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW5RCtQEyNAxv5N4hWNH/22l2jL+uAbwTPt1CsVL0XRxqv/aGUwIKWYPNzEf0MYplxA5EOr6kSgYpydeeeqnjXqraUBelxHJqqQpQ==
X-Received: by 2002:a5d:6190:0:b0:33c:f968:e243 with SMTP id j16-20020a5d6190000000b0033cf968e243mr4229624wru.43.1708103039906;
        Fri, 16 Feb 2024 09:03:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708103039; cv=none;
        d=google.com; s=arc-20160816;
        b=CkE85KC0HK+cwGx/bGNBVKUGFDemfQILP/NDmU+LzNb0NsIQO6EOtx9QFurNhgRErK
         zMFbMz60ER/BO8BCrDFmQy8wd9qXHZZonH/WBwMEOLa27KWKm9Fgx9lUtUYnS2KYMWEg
         STu9xkTdqidmK07uV8khNvcoxxMKRwqTh4l4AT79o+5IjM2UZiNwujOlqEWqh9TQRBFT
         vMRFN+SmFjcnzUtn3J4pdCUALrea3JJOgN9QFmwqqk9X6n7L2hL8eaJENiR7oZyu0dxn
         bhdZTGE9jfshSTsSrhgsxoc5TPQ6FqWlyw3gDIqDo7/5WpALrHPsGUQIT8rMJieoEJlB
         2fLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=HmJQIqc4/OgO89xq5HkfBIYteF7nE9kIo+o5Vkmf1w0=;
        fh=oLzH21GokMW2l86dFsMPozOxCJDwxgKqQI1fOLLTHJM=;
        b=Np1RWgIv+M2MlVhk38CAC62mRlLpsj8x2JpBzYQmOSmM13an2xhDQSSBAqR3PZzQv8
         O+FQA2INMdCHSH2F2JClVqym5jyve5S/d+SfHpo0ao0ScBmdkK923tIZvQaE7KiG7LaJ
         YXqXg1hgm/JlfszY5T8TInD+KjxUK7mzj4vgjV/kfOqOOdZXQA6F0drmvJjWVKJGMInq
         88G/PaSc7pOeDPXvZFL/z7XH7FX3hTKv4PsD1Tk1g2sezLTpaAAuHDi4qPGzHLGzfiCs
         5LZhTJIl1fspRe3QwfZcYv2ZRqZ1zxwczJGe7qAPFmMWqGKiSyaKPhg8aXH7Oz3+FFNi
         6A7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Sfqp2+ZZ;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-187.mta0.migadu.com (out-187.mta0.migadu.com. [91.218.175.187])
        by gmr-mx.google.com with ESMTPS id n1-20020a5d51c1000000b0033cddf15870si79134wrv.6.2024.02.16.09.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Feb 2024 09:03:59 -0800 (PST)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as permitted sender) client-ip=91.218.175.187;
Date: Fri, 16 Feb 2024 12:03:49 -0500
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, 
	cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, minchan@google.com, 
	kaleshsingh@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v3 22/35] mm/slab: enable slab allocation tagging for
 kmalloc and friends
Message-ID: <axbekdy2s36zuvhacrikgp3yl2a2j3po5cw6zrgspem2cdabry@ypsxxzx3ve72>
References: <20240212213922.783301-1-surenb@google.com>
 <20240212213922.783301-23-surenb@google.com>
 <a27189a9-b0fc-4705-bdd5-3ee0a5c23dd5@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a27189a9-b0fc-4705-bdd5-3ee0a5c23dd5@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Sfqp2+ZZ;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.187 as
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

On Fri, Feb 16, 2024 at 05:52:34PM +0100, Vlastimil Babka wrote:
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > Redefine kmalloc, krealloc, kzalloc, kcalloc, etc. to record allocations
> > and deallocations done by these functions.
> > 
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> 
> 
> > -}
> > +#define kvmalloc(_size, _flags)			kvmalloc_node(_size, _flags, NUMA_NO_NODE)
> > +#define kvzalloc(_size, _flags)			kvmalloc(_size, _flags|__GFP_ZERO)
> >  
> > -static inline __alloc_size(1, 2) void *kvmalloc_array(size_t n, size_t size, gfp_t flags)
> 
> This has __alloc_size(1, 2)
> 
> > -{
> > -	size_t bytes;
> > -
> > -	if (unlikely(check_mul_overflow(n, size, &bytes)))
> > -		return NULL;
> > +#define kvzalloc_node(_size, _flags, _node)	kvmalloc_node(_size, _flags|__GFP_ZERO, _node)
> >  
> > -	return kvmalloc(bytes, flags);
> > -}
> > +#define kvmalloc_array(_n, _size, _flags)						\
> > +({											\
> > +	size_t _bytes;									\
> > +											\
> > +	!check_mul_overflow(_n, _size, &_bytes) ? kvmalloc(_bytes, _flags) : NULL;	\
> > +})
> 
> But with the calculation now done in a macro, that's gone?
> 
> > -static inline __alloc_size(1, 2) void *kvcalloc(size_t n, size_t size, gfp_t flags)
> 
> Same here...
> 
> > -{
> > -	return kvmalloc_array(n, size, flags | __GFP_ZERO);
> > -}
> > +#define kvcalloc(_n, _size, _flags)		kvmalloc_array(_n, _size, _flags|__GFP_ZERO)
> 
> ... transitively?
> 
> But that's for Kees to review, I'm just not sure if he missed it or it's fine.

I think this is something we want to keep - we'll fix it

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/axbekdy2s36zuvhacrikgp3yl2a2j3po5cw6zrgspem2cdabry%40ypsxxzx3ve72.
