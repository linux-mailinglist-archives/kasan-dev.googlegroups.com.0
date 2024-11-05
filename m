Return-Path: <kasan-dev+bncBC6LHPWNU4DBB6O4UW4QMGQEAPAD4DA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 269739BC241
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Nov 2024 02:01:47 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5eb65b1ae2asf3959885eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 17:01:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730768505; cv=pass;
        d=google.com; s=arc-20240605;
        b=U5cZfjuWTA0tOtX2k4eqXCkpGAATdkYYqrOzSKDJXbRlCR6wxVDq6Th4NQnVtJHKXi
         bpLYbuh4wKgUqOxuacy7aElcIksIHIo51zcHHJ7Jal+nSIcdIiXXenVKkAy9f4gUGK+n
         p604pXJa42qEuY9ICGN9BbRZJIIwLkGwG371cBjF62oBNYmFfgMMhULwf/mTrh+QtvYp
         EQ+N6IGNqXwSW4HqwaKM2l61XaxpU3zW46vdo6YTsFRdUnOrizaNrlF2hR6sSfpX4SZC
         98mzhL+SukPQ56uZx7b3u6iiLrxqWAHSh5JmL/fk6UVGmNFRPT2w0bQy2AeGDPzIMX6O
         qzig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=T/yfxuIf5qHlIRUsoeVsuTZrZMlJP4oet1hS70jNOdg=;
        fh=b0PItBeo5YmYRcK6QFNLdxtVOW61xa3MnMeZ+WI6wSg=;
        b=BzLhFAQXH//8nhpuJzYwo705cgCM8oPM71DP/3o3WHAob0Qyx7GLUdhjfjZkMDS/aQ
         4ACSTOJPhheAD8haMsofmnlGcWc468R6D/D7s0jgwz0IVAkA546GyW8UUG3/3I7fR0Cn
         Eehtla4Dl/Tgnew5VIWVNv97TM8fpzhJUMrLA3m+mKM/nUI74LuD+2yzU4s4aizWDOqI
         0qae6561Cps/5+D/RReeXAMpiO7SDkOhg8An4m+maFwlrS3E0F6nL1L8chd42w3dHK7U
         rzQny9YDS4+OZEkHjLnZsIDfKEcHr1553wmGHUeYH2nyYBkNQdGTJ/8gcltDLizvB7EL
         lXQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VC+x9wJS;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730768505; x=1731373305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T/yfxuIf5qHlIRUsoeVsuTZrZMlJP4oet1hS70jNOdg=;
        b=brPOL82iU1as/3mazp3UfczlIentnCxXaOrcndhTa+qxbn1yCVVcdlWrKxhUefy5gs
         RNwE94WuKFEyimriv1G77ZBCKB2yVhi4FX2pxMiRqgKylTqXV30/iNhs2N783LMQ39Sl
         4gY23l0sHcP+4GONFBQbGoy67Oh/S2mywGdOmHjTU9ztD5J92BM4G11c9DxQHIR+VNfq
         JCj20v0spddWcNmtCvYpZXmrYw3ynwKy2KjuPpfzEerIK0Hr69P9vCZkZM7twVUNqBh/
         Xgwx71uh9cTIq4sQqV75nQeiWsDbaanx+8CIKQyWpHR7F1MhJZeiQyj/2DMLGI6157TH
         Qptw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730768505; x=1731373305; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=T/yfxuIf5qHlIRUsoeVsuTZrZMlJP4oet1hS70jNOdg=;
        b=NETnzu2SEesS46GmLoDHRwGlQHm6cKlSdFIHcghsIlcqofLO0nTAaJDiZn2Dd9Z7Uf
         xmoZaLt2IENiBE0QAzh5FSjEcNzTF8h00eeftg3C1ic0rtntQixhrgkdYV0WQuBVkUOP
         kKlz853K6J6kZ4silgGvFXhiofKW5wjI8NPgv9Brp3ywLPOUDHZMg9SGzJLHo67UGks8
         det8PNfTdiPPtiN9UA1UO3MyJW51ibfF6zcTgZBJF+BatIA3VFuACI54ZlVKs+l/Ix07
         IsFr7WmcuL1MAi1v05dg5nFkD22RU8Wgnv0uIDi9z7zPUBlanSS9LSHk3nH83SGdi517
         lYsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730768505; x=1731373305;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=T/yfxuIf5qHlIRUsoeVsuTZrZMlJP4oet1hS70jNOdg=;
        b=MeSNGJQUJu8Cg22o/YEpNFiO0zLwfEedIC4IQQesMaIaGS3aT6LeVHvUpC21zkkZgJ
         X/4Xa8G5h8k5Cp/4iDrgLb1Yt9Ma/huB0QqbpLKGQoxXfUgXiJCapHoc6OgPXewqZolL
         I6SXsnf+yHEBOYPhMJwS1WsIDYD2K7cLu5oh2gFkzQGbitvKqrP5QrWg+qIjUebFun/c
         YYs22X3cYosBwtSCRxKJ9/k1MbHSQkW8jNC58zbZWXUn/K7JnIxa44Kb9oXK/ygodNPe
         JNBJ/Mrczx2sJ1Sj1nYZ6IEdaKdFRk5UPo0PT/jyoKWU1gD+Kd3JdTfckbuEDTIn1mDi
         A02w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRPWx16Z4u5kX1ZjQqYczFu9Y8+HWb8GchahSrfgAxuus2izRwtD4nKU8VcKB7jsxlii5Jig==@lfdr.de
X-Gm-Message-State: AOJu0YyIrU0wZp/REqx0pWPFzsfgEpCnq/vqrWLQeFweaptuqeKfRi6t
	gSdRkxZ2webJVEctnqXpW8Balx/amreg7PLTK9UGVFMJmHY/WY4O
X-Google-Smtp-Source: AGHT+IHcZolJCHx+BJIhNnK0NfVpbBMZTKwR//8s4USH9dpz+wASCLCdgNIyPHrbvjD76CUMtEvxKQ==
X-Received: by 2002:a05:6820:2295:b0:5e5:b652:9d14 with SMTP id 006d021491bc7-5ec6d942371mr11266185eaf.1.1730768505567;
        Mon, 04 Nov 2024 17:01:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e9bc:0:b0:5eb:be41:8427 with SMTP id 006d021491bc7-5ec6d2dc801ls2512402eaf.2.-pod-prod-03-us;
 Mon, 04 Nov 2024 17:01:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6jJ3L30kJFKeab2kPEg+ro2ZdPA3EWyEgtYz6V8QDruL269WW6HzEG4yapeINe/JpH1DSBxaaPLM=@googlegroups.com
X-Received: by 2002:a05:6830:4393:b0:718:157a:efad with SMTP id 46e09a7af769-7189b4dba89mr14709375a34.13.1730768504038;
        Mon, 04 Nov 2024 17:01:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730768504; cv=none;
        d=google.com; s=arc-20240605;
        b=BClN7uStuRiwv6yeVpptrYiEsZRjWKeWBUWw35B1s39jiKVbxa38sGO8kJBvKTuxsF
         S5rhC9kypv4RpNgMc5m4/Qihxv1wIdPvn3CaytObArHJkD8tVSHGqWAhmOABH8WLW2zn
         N8GfMPVuTXAlCLxaQ6erimv4NI9PBH+79yKv+H581KYE25NJTCwwPfqp00Jo3XZnR59P
         TeEeSWNAP2blFKdUWW2QeSQaxaIDW+Ahzo31Un0zip55bpApHEFtLPXPExMvxq9VR6fX
         v6WOd3FOAnN6RJ2QyRC0/rzAde4MaIBF9bAYjpHfjtScvodO7Wmh3Ox7JNwsAo9BOGw9
         DElg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=Or9PsYziaZUPWqGCBJkZi+Ijw9yEk7z687OLKIoWH48=;
        fh=TqJO0E7D8iwtwilAHDqQltveP4OWIZUdYusMRfJZ2jg=;
        b=KYg8OqfsbTKpeKKLIzgg6jwRCYD6HAUIVSS4qP4VILcXXLhuDmiCsNKCTKN6lD6wlT
         AnnQ61Zp8DC7yl4RVovlq6/SAGDe4E6ngANFLdF/BC9FpIGdTZ60iUDXbGdOD+gfyRuQ
         f4JzwfWbwYoDm6IMtViFKi4r6rN+EUbeeABJN0ENic/Pwm3gDhriieoepJjr9BQDxg1H
         2MZ2Sd8YCpYI0NN7yObLEsYR3TzFRwoGWUUGfX2JBpYNy5cECvIcZ1DCXnQKxxGGoMIR
         PLv4UBuNNOeLR6vSs5rJ59ZB8M4d53+mDeux+q3PCsb/K75pXiDvlCXMaGatmPilXzsS
         h54w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VC+x9wJS;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x735.google.com (mail-qk1-x735.google.com. [2607:f8b0:4864:20::735])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-462acf84abcsi5471641cf.0.2024.11.04.17.01.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 17:01:44 -0800 (PST)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::735 as permitted sender) client-ip=2607:f8b0:4864:20::735;
Received: by mail-qk1-x735.google.com with SMTP id af79cd13be357-7b1539faa0bso318136285a.1
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 17:01:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWNV2iuxhcGMce3iZ5eFmMZBONHWtfT/ptmDgG23xikjCGCghXHvsVnXadDdZY4n2+eCYDJaYNS96A=@googlegroups.com
X-Received: by 2002:a05:620a:28c4:b0:7b1:5346:e72d with SMTP id af79cd13be357-7b2f24dd7c6mr2557316485a.23.1730768503394;
        Mon, 04 Nov 2024 17:01:43 -0800 (PST)
Received: from fauth-a1-smtp.messagingengine.com (fauth-a1-smtp.messagingengine.com. [103.168.172.200])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7b2f3a868dasm472211985a.121.2024.11.04.17.01.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Nov 2024 17:01:42 -0800 (PST)
Received: from phl-compute-02.internal (phl-compute-02.phl.internal [10.202.2.42])
	by mailfauth.phl.internal (Postfix) with ESMTP id 2229B1200043;
	Mon,  4 Nov 2024 20:01:42 -0500 (EST)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-02.internal (MEProxy); Mon, 04 Nov 2024 20:01:42 -0500
X-ME-Sender: <xms:dm4pZ-XEOH2HKjiFpRQQLfcREpxc9fysqdObu-4bc7J7dcvWZWzNrA>
    <xme:dm4pZ6mvI7Pj8-wZMvczPvCl8PAGOoQ8RBpxQPnT8Um-UqBKOQRcHG4tCZye530-b
    4kNc90prQjKXhbSKg>
X-ME-Received: <xmr:dm4pZyb5L8srqyBwwIfvOxjI_JH2Z0OCZskiCKM_X-rqfL-JdA015t6CRlys_Q>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdeljedgfedtucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdggtfgfnhhsuhgsshgtrhhisggvpdfu
    rfetoffkrfgpnffqhgenuceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnh
    htshculddquddttddmnecujfgurhepfffhvfevuffkfhggtggujgesthdtredttddtvden
    ucfhrhhomhepuehoqhhunhcuhfgvnhhguceosghoqhhunhdrfhgvnhhgsehgmhgrihhlrd
    gtohhmqeenucggtffrrghtthgvrhhnpefhtedvgfdtueekvdekieetieetjeeihedvteeh
    uddujedvkedtkeefgedvvdehtdenucffohhmrghinhepkhgvrhhnvghlrdhorhhgnecuve
    hluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomhepsghoqhhunhdo
    mhgvshhmthhprghuthhhphgvrhhsohhnrghlihhthidqieelvdeghedtieegqddujeejke
    ehheehvddqsghoqhhunhdrfhgvnhhgpeepghhmrghilhdrtghomhesfhhigihmvgdrnhgr
    mhgvpdhnsggprhgtphhtthhopedujedpmhhouggvpehsmhhtphhouhhtpdhrtghpthhtoh
    epsghighgvrghshieslhhinhhuthhrohhnihigrdguvgdprhgtphhtthhopehprghulhhm
    tghksehkvghrnhgvlhdrohhrghdprhgtphhtthhopehvsggrsghkrgesshhushgvrdgtii
    dprhgtphhtthhopegvlhhvvghrsehgohhoghhlvgdrtghomhdprhgtphhtthhopehlihhn
    uhigqdhkvghrnhgvlhesvhhgvghrrdhkvghrnhgvlhdrohhrghdprhgtphhtthhopehkrg
    hsrghnqdguvghvsehgohhoghhlvghgrhhouhhpshdrtghomhdprhgtphhtthhopehlihhn
    uhigqdhmmheskhhvrggtkhdrohhrghdprhgtphhtthhopehsfhhrsegtrghnsgdrrghuuh
    hgrdhorhhgrdgruhdprhgtphhtthhopehlohhnghhmrghnsehrvgguhhgrthdrtghomh
X-ME-Proxy: <xmx:dm4pZ1WlMIWEVGiCuOYM-VF9oO2USd01U_CU4bS_U_nsi_ALnUfuhw>
    <xmx:dm4pZ4mH4MZS8TscmbX-MB4OJn-3Dv9z9iqVxwg69aWNskoeDvv56Q>
    <xmx:dm4pZ6dnkahyC-Ypo8e9-3Os6595Oij9nZJMoi8vVySIaJu6xMORUA>
    <xmx:dm4pZ6G9mjup8-HInUX6L3FVJeBoQUfVQtgBS_KlGYFh9Ci8yOSd3A>
    <xmx:dm4pZ2kwXt4AIdKLZretNzMT_-5Ry-GWhSp3eVK4c---SOLCIKrG5lH6>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Mon,
 4 Nov 2024 20:01:41 -0500 (EST)
Date: Mon, 4 Nov 2024 17:00:19 -0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, sfr@canb.auug.org.au, longman@redhat.com,
	cl@linux.com, penberg@kernel.org, rientjes@google.com,
	iamjoonsoo.kim@lge.com, akpm@linux-foundation.org,
	Tomas Gleixner <tglx@linutronix.de>,
	Peter Zijlstra <peterz@infradead.org>
Subject: Re: [PATCH 2/2] scftorture: Use a lock-less list to free memory.
Message-ID: <ZyluI0A-LSvvbBb9@boqun-archlinux>
References: <88694240-1eea-4f4c-bb7b-80de25f252e7@paulmck-laptop>
 <20241104105053.2182833-1-bigeasy@linutronix.de>
 <20241104105053.2182833-2-bigeasy@linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241104105053.2182833-2-bigeasy@linutronix.de>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VC+x9wJS;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::735
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hi Sebastian,

I love this approach, I think it's better than my workqueue work around,
a few comments below:

On Mon, Nov 04, 2024 at 11:50:53AM +0100, Sebastian Andrzej Siewior wrote:
> scf_handler() is used as a SMP function call. This function is always
> invoked in IRQ-context even with forced-threading enabled. This function
> frees memory which not allowed on PREEMPT_RT because the locking
> underneath is using sleeping locks.
> 
> Add a per-CPU scf_free_pool where each SMP functions adds its memory to
> be freed. This memory is then freed by scftorture_invoker() on each
> iteration. On the majority of invocations the number of items is less
> than five. If the thread sleeps/ gets delayed the number exceed 350 but
> did not reach 400 in testing. These were the spikes during testing.
> The bulk free of 64 pointers at once should improve the give-back if the
> list grows. The list size is ~1.3 items per invocations.
> 
> Having one global scf_free_pool with one cleaning thread let the list
> grow to over 10.000 items with 32 CPUs (again, spikes not the average)
> especially if the CPU went to sleep. The per-CPU part looks like a good
> compromise.
> 
> Reported-by: "Paul E. McKenney" <paulmck@kernel.org>
> Closes: https://lore.kernel.org/lkml/41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop/
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> ---
>  kernel/scftorture.c | 47 +++++++++++++++++++++++++++++++++++++++++----
>  1 file changed, 43 insertions(+), 4 deletions(-)
> 
> diff --git a/kernel/scftorture.c b/kernel/scftorture.c
> index e5546fe256329..ba9f1125821b8 100644
> --- a/kernel/scftorture.c
> +++ b/kernel/scftorture.c
> @@ -97,6 +97,7 @@ struct scf_statistics {
>  static struct scf_statistics *scf_stats_p;
>  static struct task_struct *scf_torture_stats_task;
>  static DEFINE_PER_CPU(long long, scf_invoked_count);
> +static DEFINE_PER_CPU(struct llist_head, scf_free_pool);
>  
>  // Data for random primitive selection
>  #define SCF_PRIM_RESCHED	0
> @@ -133,6 +134,7 @@ struct scf_check {
>  	bool scfc_wait;
>  	bool scfc_rpc;
>  	struct completion scfc_completion;
> +	struct llist_node scf_node;
>  };
>  
>  // Use to wait for all threads to start.
> @@ -148,6 +150,40 @@ static DEFINE_TORTURE_RANDOM_PERCPU(scf_torture_rand);
>  
>  extern void resched_cpu(int cpu); // An alternative IPI vector.
>  
> +static void scf_add_to_free_list(struct scf_check *scfcp)
> +{
> +	struct llist_head *pool;
> +	unsigned int cpu;
> +
> +	cpu = raw_smp_processor_id() % nthreads;
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	llist_add(&scfcp->scf_node, pool);
> +}
> +
> +static void scf_cleanup_free_list(unsigned int cpu)
> +{
> +	struct llist_head *pool;
> +	struct llist_node *node;
> +	struct scf_check *scfcp;
> +	unsigned int slot = 0;
> +	void *free_pool[64];
> +
> +	pool = &per_cpu(scf_free_pool, cpu);
> +	node = llist_del_all(pool);
> +	while (node) {
> +		scfcp = llist_entry(node, struct scf_check, scf_node);
> +		node = node->next;
> +		free_pool[slot] = scfcp;
> +		slot++;
> +		if (slot == ARRAY_SIZE(free_pool)) {
> +			kfree_bulk(slot, free_pool);
> +			slot = 0;
> +		}
> +	}
> +	if (slot)
> +		kfree_bulk(slot, free_pool);
> +}
> +
>  // Print torture statistics.  Caller must ensure serialization.
>  static void scf_torture_stats_print(void)
>  {
> @@ -296,7 +332,7 @@ static void scf_handler(void *scfc_in)
>  		if (scfcp->scfc_rpc)
>  			complete(&scfcp->scfc_completion);
>  	} else {
> -		kfree(scfcp);
> +		scf_add_to_free_list(scfcp);
>  	}
>  }
>  
> @@ -363,7 +399,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				scfp->n_single_wait_ofl++;
>  			else
>  				scfp->n_single_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -391,7 +427,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  				preempt_disable();
>  		} else {
>  			scfp->n_single_rpc_ofl++;
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  			scfcp = NULL;
>  		}
>  		break;
> @@ -428,7 +464,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  			pr_warn("%s: Memory-ordering failure, scfs_prim: %d.\n", __func__, scfsp->scfs_prim);
>  			atomic_inc(&n_mb_out_errs); // Leak rather than trash!
>  		} else {
> -			kfree(scfcp);
> +			scf_add_to_free_list(scfcp);
>  		}
>  		barrier(); // Prevent race-reduction compiler optimizations.
>  	}
> @@ -442,6 +478,7 @@ static void scftorture_invoke_one(struct scf_statistics *scfp, struct torture_ra
>  		schedule_timeout_uninterruptible(1);
>  }
>  
> +
>  // SCF test kthread.  Repeatedly does calls to members of the
>  // smp_call_function() family of functions.
>  static int scftorture_invoker(void *arg)
> @@ -479,6 +516,8 @@ static int scftorture_invoker(void *arg)
>  	VERBOSE_SCFTORTOUT("scftorture_invoker %d started", scfp->cpu);
>  
>  	do {
> +		scf_cleanup_free_list(scfp->cpu);
> +

I think this needs to be:

		scf_cleanup_free_list(cpu);

or

		scf_cleanup_free_list(curcpu);

because scfp->cpu is actually the thread number, and I got a NULL
dereference:

[   14.219225] BUG: unable to handle page fault for address: ffffffffb2ff7210

while running Paul's reproduce command:

tools/testing/selftests/rcutorture/bin/kvm.sh --torture scf --allcpus --duration 2 --configs PREEMPT --kconfig CONFIG_NR_CPUS=64 --memory 7G --trust-make --kasan --bootargs "scftorture.nthreads=64 torture.disable_onoff_at_boot csdlock_debug=1"

on my 48 cores VM (I think 48 core may be key to reproduce the NULL
dereference).


Another thing is, how do we guarantee that we don't exit the loop
eariler (i.e. while there are still callbacks on the list)? After the
following scftorture_invoke_one(), there could an IPI pending somewhere,
and we may exit this loop if torture_must_stop() is true. And that IPI
might add its scf_check to the list but no scf_cleanup_free_list() is
going to handle that, right?

Regards,
Boqun

>  		scftorture_invoke_one(scfp, &rand);
>  		while (cpu_is_offline(cpu) && !torture_must_stop()) {
>  			schedule_timeout_interruptible(HZ / 5);
> -- 
> 2.45.2
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZyluI0A-LSvvbBb9%40boqun-archlinux.
