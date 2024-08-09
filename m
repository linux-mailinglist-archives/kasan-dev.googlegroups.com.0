Return-Path: <kasan-dev+bncBDK7LR5URMGRBREG3G2QMGQEHWYPZBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DBF894D4A9
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Aug 2024 18:26:47 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-42816aacabcsf15782215e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Aug 2024 09:26:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723220805; cv=pass;
        d=google.com; s=arc-20160816;
        b=SSOgZQEn1xbjEFLUpGXt8q7t999sZqD4I/Ai9ukb1Jff40dR/Dufjv63bcC/8thJ+A
         BgIyA39yC8vKrOshlEre+F4+Q5PnEMImUnJ1Ov/heDcJuEqXoOTDMkJ26m5UCwnU7yQ8
         TSDl/wlFXmlYoH16NHCBNFiEBVy2MlNUWfM+gjDqMAPBRYoayle+7z5MVegcqfD5rL1H
         mB09KZJMw6f5J1+c9s2krV3PviAA6znEF4vUHc3ySCttA4hkLmAnMrzGpShKoYcrNXTD
         jDM91E3Zq35lJ1Ct7RRu5G9nk0EdMtuq0GQdndeYZCxE/3APSiefoXs0JHI6hyj4hIrj
         N/vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=3FWAzALm4pN5uItuH79IhDlaKsbH5DGSUvaEc955YTw=;
        fh=cLWwLcx1J1xiOWaJ4KuvNcHS5H/k0n5R3FQkl9bOy3o=;
        b=PQju9fyN74quiDvWkD4fYxoGY+nDZqdqGplHfpolij7+yzRrYEOxm1m47E8bUQpnjP
         y18p8nrBHIMNUcG671O/wn5JKfD76eKQZ/LEBFhvDoAO6EO/7QHnKw2k/syGSZVFTQCW
         RCDtUxYqblj2VEyS/WjLzFcvqJo1Z0fEJrtcRM424HaCanjbZcYClusz8R2fdx2AK1S1
         4GI+z4qQxRyZw6/Xr3E08EeOwoALWgRrsatGKnWz7fxyXKuAb3tsAcfgNibKMGyAneEG
         xSzVZazLcJY1h+St3j8DxUjuoV2ZUMJdHU9vDO6mZXDOxgpJ6D2qYDr+pOqbDUR1W02U
         SNmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RLdVA5x4;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723220805; x=1723825605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3FWAzALm4pN5uItuH79IhDlaKsbH5DGSUvaEc955YTw=;
        b=wRfbWZ2aaGBBTgkdhp4ijYF6Uftl8oJWnvFrhS7lTC4aZlSfFek/wvx4NwerHdn6Hq
         L5yEbLcxatUypCClVzVe4UpynqnBW0Su6eCEfZwVTMULznUDRxDSvuVob8pbP8896M31
         ZHsK/6GHapt1r+yJC3l2bKd/qVAa8hgFwgXH04lz0yHuLP8c/bL3sdkCfNF79zvyahbl
         m5AQs4cCuLrbyXW8bLNmnsV1mdeEMCGUbw5FgyijJJgrVR/K3kGl9DKXZ2crN6hzKK17
         IYrlFCUGfpjzbM9sky5O8UG4LY2DpN+sLCFJQkJ1mkH9TkIPjjIyeUeJQUBUyv2mnylc
         Z07A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723220805; x=1723825605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=3FWAzALm4pN5uItuH79IhDlaKsbH5DGSUvaEc955YTw=;
        b=MFPYKpjI6dISTmohF3MEhBC73faSjZuwLHiVuTfT8NTAT7w89zg5nPnBXcC3KfcbYh
         FoqbunPpLqMTDCJCdj4whY12RC/QJ81MNPsNsCK6LSjuw/i6t2Zqg0PUcu+13Wj+V9yN
         O3gxVnW6+aivA/N6mZBZS5q8XTB5qRtMmmxGR/WgQpHU3zgB8duAHMBDSRyEfWrqJtXZ
         pmol5FODdAFzSmLWbMSqCtPe5ZhsI5Q2oHwajwGbv5X6tF/0ZammVE/jofE0ShXvwJjJ
         Hpn/AlS3Fe8sXVBYJ2xQq7Nqf8IH1bb/i8/IeF8wUz6UMjf+6XHDpICaF0zG8+Of5NBf
         nBrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723220805; x=1723825605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3FWAzALm4pN5uItuH79IhDlaKsbH5DGSUvaEc955YTw=;
        b=PUnZYSsz7TakZCHNhwyP/ubGwiLLjA7d50UvbwmgB3TD2hxWXFihg19GYGoEt/Ix8s
         IJOcBmynEjbQn/8fD1nrgJ1/yumvBcvPWwFqtpwZ6ovE1fUWWYzlrCgf/+gixT/pjVZm
         h/jmXPaX3dvU43mqeU8rgpV1HGcpW4vBuUVkPPU4/WqMMSM6LvmY/i4NYTx+VzaC8Y6h
         Q2Dy8t3CYT3y7ompw+zbu+zm41L0QVWFMRSBRe/J5N9c9ZLoqdEZTX/FQgALExQCQ8JF
         ++RW78vnWUd9dmxc4K4/AHcw9MTZV78UVk3pWdw8U/JuVyHYfMeZC3neOeu8SFqpgzw0
         LlPw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXb3w2LpgjF0yi1tbatauYVNXsBDB8RH1qFH45KRSMfIx5uJ6FEeCk0G7e5aQZ+KxwdTV0w3EPNMRAFx0STjtu0HooxYFrLUQ==
X-Gm-Message-State: AOJu0YyilR2Hg33ElF3jbAQgo6ccp7KzwOzVz9zrQGLCrxwd3tEyZimx
	KNe1EHQtlQNcO53lziCRRiEPIjqlkChCxyArBBRhMbXkvyuTBcw0
X-Google-Smtp-Source: AGHT+IGhPaZHvk5esWTrydYdzMsNmSApJMV7G7bTZNpfcuUkPtdfb2W3GJacD9Y1FahQrCv3AuoUAw==
X-Received: by 2002:a05:600c:1c05:b0:428:14b6:ce32 with SMTP id 5b1f17b1804b1-429c3a22bd5mr16220715e9.9.1723220804667;
        Fri, 09 Aug 2024 09:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:510d:b0:426:6982:f5c6 with SMTP id
 5b1f17b1804b1-42909185297ls1694285e9.1.-pod-prod-02-eu; Fri, 09 Aug 2024
 09:26:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVirDdtthxSubn1+HaDTXQnAeO7BbnfytWWrSxK0PNmqKBPZnuVajezKbBHPjnElz2JzIygysqSV5VJCLUqMEUP6JXPNaS3AR3SnA==
X-Received: by 2002:a05:600c:1e1d:b0:428:151b:e8e with SMTP id 5b1f17b1804b1-429c3a22a90mr16452685e9.10.1723220802861;
        Fri, 09 Aug 2024 09:26:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723220802; cv=none;
        d=google.com; s=arc-20160816;
        b=VlzqV24uXO+WrDSoOd1aGcizcVV7olbTqclWNgzk1/pGGxr34Fl+f9q4a/AUQ9s/If
         Mb0igiH5KgoO4Tm0GdDuv8iegLZ9UI5lCrOmWzuGKPakEvX3LvYrtVRCKcjSzx733HkL
         149bBf8VPJbDIjqOUMST3RPOL6HZFu9dNEHPL61ycjbKaA7gdqUVEqPNu3Y0er49NFu1
         Xwik5QPaRRd2RE/3Y0hAYK3uEcgrz2zpn67+DjDmKrNviokpXzF50Qh8Uv0aLkEVf0lZ
         IHiOf2Vvc5vTjXLcfYA4v8fFN635i2PM5jk9CcH/G3exx3d/h2XYS7yp2BXGqPlFsfIS
         JmJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=8GhuZXBHrLQFERoBhWAzGEBHzpGEHA+J+lL0pNJNCos=;
        fh=SxlHiNvH1cgH9mHe+Igm6+u1Qz+Ts9napSmHMAhzcK4=;
        b=k/sZhRRYA54fdIUTjGIzi8vxPcqvbAtfXgXpgtrRtGOrMHe4fJCnl++LBGlMG2RrkV
         Grb468/s4XqhbAJpWKCFjrX7NPrvz1vpLcCTubUsAYiP3s9YTDNQAohg1EOnI7oTzSh3
         uRK1iH4sFwzp4fIKslpJQA1LK3ew1z4A1IbHFphZdyZBuJitW9ju0oM0x5Q5o/TXkt9J
         aJeNivDbTJJd+EicTXn84S0k/lECLOt05KBYOLy90bEGNpQhjhedsNg2hoFuw9xN6bYo
         PTScox/bFaGnrcBnwkpSdm7v2l3tb0xRTUEJfrYao+oj517bqE8k05CxMKe8wfYc98a5
         F3dQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RLdVA5x4;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::236 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x236.google.com (mail-lj1-x236.google.com. [2a00:1450:4864:20::236])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-429c2013df6si1135475e9.1.2024.08.09.09.26.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 09 Aug 2024 09:26:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::236 as permitted sender) client-ip=2a00:1450:4864:20::236;
Received: by mail-lj1-x236.google.com with SMTP id 38308e7fff4ca-2ef32fea28dso23857191fa.2
        for <kasan-dev@googlegroups.com>; Fri, 09 Aug 2024 09:26:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW0IwbPg4sY9JdQ1XzcAdK+leDPbMkYdQGWTDt8clRqphIzU3j+rReFbMI95fIOeMTUD5Jd5jKKNB6h1eXwrLKVyZRJIZOKK8lmpQ==
X-Received: by 2002:a2e:a581:0:b0:2ec:500c:b2e0 with SMTP id 38308e7fff4ca-2f1a6d1d1e9mr19917041fa.22.1723220801209;
        Fri, 09 Aug 2024 09:26:41 -0700 (PDT)
Received: from pc636 (host-90-233-216-8.mobileonline.telia.com. [90.233.216.8])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2f15e26038bsm25892501fa.117.2024.08.09.09.26.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 09 Aug 2024 09:26:40 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 9 Aug 2024 18:26:36 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>
Subject: Re: [PATCH v2 5/7] rcu/kvfree: Add kvfree_rcu_barrier() API
Message-ID: <ZrZDPLN9CRvRrbMy@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-5-ea79102f428c@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RLdVA5x4;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::236 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello, Vlastimil!

> From: "Uladzislau Rezki (Sony)" <urezki@gmail.com>
> 
> Add a kvfree_rcu_barrier() function. It waits until all
> in-flight pointers are freed over RCU machinery. It does
> not wait any GP completion and it is within its right to
> return immediately if there are no outstanding pointers.
> 
> This function is useful when there is a need to guarantee
> that a memory is fully freed before destroying memory caches.
> For example, during unloading a kernel module.
> 
> Signed-off-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  include/linux/rcutiny.h |   5 +++
>  include/linux/rcutree.h |   1 +
>  kernel/rcu/tree.c       | 103 ++++++++++++++++++++++++++++++++++++++++++++----
>  3 files changed, 101 insertions(+), 8 deletions(-)
> 
> diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
> index d9ac7b136aea..522123050ff8 100644
> --- a/include/linux/rcutiny.h
> +++ b/include/linux/rcutiny.h
> @@ -111,6 +111,11 @@ static inline void __kvfree_call_rcu(struct rcu_head *head, void *ptr)
>  	kvfree(ptr);
>  }
>  
> +static inline void kvfree_rcu_barrier(void)
> +{
> +	rcu_barrier();
> +}
> +
>  #ifdef CONFIG_KASAN_GENERIC
>  void kvfree_call_rcu(struct rcu_head *head, void *ptr);
>  #else
> diff --git a/include/linux/rcutree.h b/include/linux/rcutree.h
> index 254244202ea9..58e7db80f3a8 100644
> --- a/include/linux/rcutree.h
> +++ b/include/linux/rcutree.h
> @@ -35,6 +35,7 @@ static inline void rcu_virt_note_context_switch(void)
>  
>  void synchronize_rcu_expedited(void);
>  void kvfree_call_rcu(struct rcu_head *head, void *ptr);
> +void kvfree_rcu_barrier(void);
>  
>  void rcu_barrier(void);
>  void rcu_momentary_dyntick_idle(void);
> diff --git a/kernel/rcu/tree.c b/kernel/rcu/tree.c
> index e641cc681901..ebcfed9b570e 100644
> --- a/kernel/rcu/tree.c
> +++ b/kernel/rcu/tree.c
> @@ -3584,18 +3584,15 @@ kvfree_rcu_drain_ready(struct kfree_rcu_cpu *krcp)
>  }
>  
>  /*
> - * This function is invoked after the KFREE_DRAIN_JIFFIES timeout.
> + * Return: %true if a work is queued, %false otherwise.
>   */
> -static void kfree_rcu_monitor(struct work_struct *work)
> +static bool
> +kvfree_rcu_queue_batch(struct kfree_rcu_cpu *krcp)
>  {
> -	struct kfree_rcu_cpu *krcp = container_of(work,
> -		struct kfree_rcu_cpu, monitor_work.work);
>  	unsigned long flags;
> +	bool queued = false;
>  	int i, j;
>  
> -	// Drain ready for reclaim.
> -	kvfree_rcu_drain_ready(krcp);
> -
>  	raw_spin_lock_irqsave(&krcp->lock, flags);
>  
>  	// Attempt to start a new batch.
> @@ -3634,11 +3631,27 @@ static void kfree_rcu_monitor(struct work_struct *work)
>  			// be that the work is in the pending state when
>  			// channels have been detached following by each
>  			// other.
> -			queue_rcu_work(system_wq, &krwp->rcu_work);
> +			queued = queue_rcu_work(system_wq, &krwp->rcu_work);
>  		}
>  	}
>  
>  	raw_spin_unlock_irqrestore(&krcp->lock, flags);
> +	return queued;
> +}
> +
> +/*
> + * This function is invoked after the KFREE_DRAIN_JIFFIES timeout.
> + */
> +static void kfree_rcu_monitor(struct work_struct *work)
> +{
> +	struct kfree_rcu_cpu *krcp = container_of(work,
> +		struct kfree_rcu_cpu, monitor_work.work);
> +
> +	// Drain ready for reclaim.
> +	kvfree_rcu_drain_ready(krcp);
> +
> +	// Queue a batch for a rest.
> +	kvfree_rcu_queue_batch(krcp);
>  
>  	// If there is nothing to detach, it means that our job is
>  	// successfully done here. In case of having at least one
> @@ -3859,6 +3872,80 @@ void kvfree_call_rcu(struct rcu_head *head, void *ptr)
>  }
>  EXPORT_SYMBOL_GPL(kvfree_call_rcu);
>  
> +/**
> + * kvfree_rcu_barrier - Wait until all in-flight kvfree_rcu() complete.
> + *
> + * Note that a single argument of kvfree_rcu() call has a slow path that
> + * triggers synchronize_rcu() following by freeing a pointer. It is done
> + * before the return from the function. Therefore for any single-argument
> + * call that will result in a kfree() to a cache that is to be destroyed
> + * during module exit, it is developer's responsibility to ensure that all
> + * such calls have returned before the call to kmem_cache_destroy().
> + */
> +void kvfree_rcu_barrier(void)
> +{
> +	struct kfree_rcu_cpu_work *krwp;
> +	struct kfree_rcu_cpu *krcp;
> +	bool queued;
> +	int i, cpu;
> +
> +	/*
> +	 * Firstly we detach objects and queue them over an RCU-batch
> +	 * for all CPUs. Finally queued works are flushed for each CPU.
> +	 *
> +	 * Please note. If there are outstanding batches for a particular
> +	 * CPU, those have to be finished first following by queuing a new.
> +	 */
> +	for_each_possible_cpu(cpu) {
> +		krcp = per_cpu_ptr(&krc, cpu);
> +
> +		/*
> +		 * Check if this CPU has any objects which have been queued for a
> +		 * new GP completion. If not(means nothing to detach), we are done
> +		 * with it. If any batch is pending/running for this "krcp", below
> +		 * per-cpu flush_rcu_work() waits its completion(see last step).
> +		 */
> +		if (!need_offload_krc(krcp))
> +			continue;
> +
> +		while (1) {
> +			/*
> +			 * If we are not able to queue a new RCU work it means:
> +			 * - batches for this CPU are still in flight which should
> +			 *   be flushed first and then repeat;
> +			 * - no objects to detach, because of concurrency.
> +			 */
> +			queued = kvfree_rcu_queue_batch(krcp);
> +
> +			/*
> +			 * Bail out, if there is no need to offload this "krcp"
> +			 * anymore. As noted earlier it can run concurrently.
> +			 */
> +			if (queued || !need_offload_krc(krcp))
> +				break;
> +
> +			/* There are ongoing batches. */
> +			for (i = 0; i < KFREE_N_BATCHES; i++) {
> +				krwp = &(krcp->krw_arr[i]);
> +				flush_rcu_work(&krwp->rcu_work);
> +			}
> +		}
> +	}
> +
> +	/*
> +	 * Now we guarantee that all objects are flushed.
> +	 */
> +	for_each_possible_cpu(cpu) {
> +		krcp = per_cpu_ptr(&krc, cpu);
> +
> +		for (i = 0; i < KFREE_N_BATCHES; i++) {
> +			krwp = &(krcp->krw_arr[i]);
> +			flush_rcu_work(&krwp->rcu_work);
> +		}
> +	}
> +}
> +EXPORT_SYMBOL_GPL(kvfree_rcu_barrier);
> +
>  static unsigned long
>  kfree_rcu_shrink_count(struct shrinker *shrink, struct shrink_control *sc)
>  {
> 
> -- 
> 2.46.0
> 
I need to send out a v2. What is a best way? Please let me know. I have not
checked where this series already landed.

Thank you!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZrZDPLN9CRvRrbMy%40pc636.
