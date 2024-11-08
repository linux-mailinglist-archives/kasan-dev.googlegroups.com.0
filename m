Return-Path: <kasan-dev+bncBCKLNNXAXYFBBO5YXG4QMGQEF6HAYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B23D49C2501
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Nov 2024 19:45:18 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-539e13b8143sf3070570e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Nov 2024 10:45:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731091518; cv=pass;
        d=google.com; s=arc-20240605;
        b=j3ej353ZfYDMIaXY7o/TCGaKlHzgoQWBb0FP578+v8QoPk4uEHlU7iualZbFSOxvh4
         ZrXizbrIJTRJB+2l6587iiefnYdnPtx4innOr1C1yy8+Q0JOj0tX6Gd9wt9Dzkm0mWJj
         BwQIg7itTttsU1gswthd/MKEXXitGDeSi+qTBNzLvY1vJ5l74wXZa5OFyW/nP0zjWgo/
         YL9U9u8q8Mam2ri1FYvOsLHbJ3CtYxUp3FfoNnT2g68e/P8dip7D5Sv+hF/aorBVxu0S
         lQffTTz/D3XdO8yZVl+qqYR0eJv9+R0xGGxQk8h0vDs4wk8f5H19+0zB25lE5CqvNbvu
         1rcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1zrOUdyXy5TrepFFLBvMFYSd1KzP16xZMwfzSgqmyeA=;
        fh=qeco8+BuO5L4DUJxkiOkr2R1QJOphQJxX6DFwhYRsrw=;
        b=JHlXJh7G+GaYw2hqhp4fDzFErFsQeqvk1JUm27uWSy1UowwJYqFQXpgdrT/lzP8l2S
         bU3l4fJeOykQHMCcQIWh4hwn+3COTMqlyqxyXcBLUeVhY1LAo37Ffyqhz4ZD9bsmj2Kb
         z4k8QAigBmX+SzYmbibeSKqH/rjjoIIstBhGa4x0XRhkYvf134qtGRRhaCvzGaOhuQ76
         GtycoN5aMW5ZojvQ2OzSpTzeei24XjjwL3BopXNKgLgiiH8bZmKB/6enlO5aRxjHZtQp
         Jf4eZTw2WszzZDvlCugYR3Mxk/53vmXb8d3r9R+doQFTH6qXxP+3p/AZmn2igbkTe1+I
         in2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=zXftWIVt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=LeDBfPQI;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731091518; x=1731696318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1zrOUdyXy5TrepFFLBvMFYSd1KzP16xZMwfzSgqmyeA=;
        b=shXsGsZoBmHD7/ShzXddZWkdY5Ha37ciLBpU84cHuYRV9YhqxyWwJ9CyDk5oZEtN+k
         x1rSsqR3+INujDLpWc374p/QuhDepx/I25ZJOg1ANm1enzpy8vLZoAey79vR1yXyavkS
         Q/WzKm2JmzWRrfSIK4N0phAwonKUeLY7MPZ22/S1ikGLvy7zDqe/gp4a40F3J37Dplw/
         FLJdwpWKBaDM8lFO8CWXy7+7eJUlQwh8JwxVciKuzuoC/uv02iJtlbrepuoI2XVzeDTR
         kFJa3fsgqP7/GEtT1euQauxAwkj5W2surxC7KAzQNAb609FrES0u6TR2NSI/tWl7f/R2
         SoHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731091518; x=1731696318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1zrOUdyXy5TrepFFLBvMFYSd1KzP16xZMwfzSgqmyeA=;
        b=QzOgOJBBGTEC9BH7eTzqIGEFHNs1Rhz5NPN4Z8dAn9MPB3H2018U0MBFXRld1SAz5+
         lk17dt7lQVOD2D9/O1dJw7S+zJek3+Kk2lgoS3xqIUlcU+b4W/Wb6t2NFmiv58t2o17Q
         8hPgMTq6xhKMriFlCNtzAac8b4ITHxMlLdXYGwJ8kvraqxUYVCBJbNN3WP6sR59RUcCo
         hqrbDaBe+cHjkNphnLKh1Sgx5WLqOpc0zgiys3tM4E0CehyO8q7YPRMebhCp/zl2EEtg
         jUrQQ0VRPxr/5SswvyskoOL5kRgZzf0H+42LvhxDruAiAUoH1eB9uqx56LCZgCPOXFx2
         uAbQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcr3ZQBMmXFraj1vq06ITclzCzAAD01D97wo8zGt+8a+N9yXBiOQBxiJGGH7Vh2/LyLwniuQ==@lfdr.de
X-Gm-Message-State: AOJu0YzO++vH/KBEqJSj0xGsFTM0udZqJ4FglwlPkH2D/DjhVRwXOliO
	deXubMP2HgIMcI/1nyoSMsKrEDKSnmlKnkDViZXdRM3Mexi3RMha
X-Google-Smtp-Source: AGHT+IHQqZlQa+FxDi30/EPotGplF0qAaDmzoKYgtXefJrFRbawVxejZLWGIksgsneokIk0HIXCFhA==
X-Received: by 2002:a05:6512:398d:b0:539:ee04:2321 with SMTP id 2adb3069b0e04-53d86240040mr2069430e87.33.1731091516400;
        Fri, 08 Nov 2024 10:45:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1595:b0:539:fc31:fc7b with SMTP id
 2adb3069b0e04-53d816b6fb6ls397437e87.0.-pod-prod-02-eu; Fri, 08 Nov 2024
 10:45:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/cH5Oz3tZgitt09B1usdfiecbyhHbRsfObJ6kizCq0wYgZQVW23OKKqmGgmFUHEisX+gU+UvVxAc=@googlegroups.com
X-Received: by 2002:a05:6512:b9b:b0:539:f7de:df84 with SMTP id 2adb3069b0e04-53d86228b43mr2344411e87.10.1731091513649;
        Fri, 08 Nov 2024 10:45:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731091513; cv=none;
        d=google.com; s=arc-20240605;
        b=dFnku0UmW9yWIeZVPgmsxL1M3YnJ+E48NPhZJY3WOMYbsNsJDsXcj7edAdU2QmYiS/
         zFekkyfMam6FPkKbqCp/0+ZB+ZJVtVgplKLE55P1UPOeoDUsiMApGbZJz6OQWsWbbUpk
         3pQ/FMxAp/I1uqcHRBZVQs8eQdDFfNojGZsEURqmzaCn/UnLdE9Rij4ZneLMFivgskIk
         6AB/mTHcX2nfdOKm4IN8olUQ5qh7rZcIojeb1UL9mvkeB3pfgB+XR3OsdImcbMQ8KfXl
         Fxy7VWAL6OS15+G9eGWHXIZOp7zCUtZwxh31pFvzqf5Uvq0eE7yM6nmreqCjcsr6kHM2
         FK5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=smasxwc1HueSLuJ/s/xYGqRFsxf23PGmCoAvEW1t/yw=;
        fh=1gOGyjChgQoQSARoJcbwa9GHpTenRwN6fL2Fry+w5Vc=;
        b=bW44XPQjyB0sl1d2PXSyws47OmNFowyW1lc09NkVbQkdROmm8/Dnnktt/jcKWUCzyL
         yFfpCJWHSORVh5/Sn/SNaIy8GwjZOOMY3fGiWPXZS/x0cogtZa+Z2JQP5W3ezA7Zk/ll
         +h/vX9l5JduJM8qH3aeIu9n0mWg6/rCc/pPKY79UI8dMb4fwq9+4LKtrAY+akmX2yesf
         OQagnteiuN3eEu44L309jTXwThtCfHrmMyA50ZChVuKb4pqcExnKakRcevoL9C7Xi5g4
         HiRLXeI6j1L/qrz4jyonV7bpUwC3jnwafcaWuTzDsJQ6ABecPR/XLPl/eWlYjN9zka0F
         AxdQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=zXftWIVt;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=LeDBfPQI;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-53d8267d844si93240e87.3.2024.11.08.10.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Nov 2024 10:45:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
Date: Fri, 8 Nov 2024 19:45:10 +0100
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Tomas Gleixner <tglx@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, akpm@linux-foundation.org,
	cl@linux.com, iamjoonsoo.kim@lge.com, longman@redhat.com,
	penberg@kernel.org, rientjes@google.com, sfr@canb.auug.org.au
Subject: Re: [PATCH v3 0/4] scftorture: Avoid kfree from IRQ context.
Message-ID: <20241108184510.O8w42_-e@linutronix.de>
References: <20241108104217.3759904-1-bigeasy@linutronix.de>
 <Zy5OX5Wy0LsFPdjO@Boquns-Mac-mini.local>
 <18b237cf-d510-49bf-b21b-78f9cebd1e3d@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <18b237cf-d510-49bf-b21b-78f9cebd1e3d@paulmck-laptop>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=zXftWIVt;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=LeDBfPQI;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 193.142.43.55 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2024-11-08 10:33:29 [-0800], Paul E. McKenney wrote:
> Sebastian, I am guessing that the Kconfig change exposing the bugs fixed
> by your series is headed to mainline for the upcoming merge window?

Yes. It is in tip/locking/core.

> If so, I should of course push these in as well.

That would be nice ;)

> 							Thanx, Paul

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241108184510.O8w42_-e%40linutronix.de.
