Return-Path: <kasan-dev+bncBC6LHPWNU4DBBUXCSS4QMGQEN7BYK6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EC629B9900
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Nov 2024 20:51:47 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-5eb24a3a3d6sf1972387eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 12:51:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730490706; cv=pass;
        d=google.com; s=arc-20240605;
        b=hfp/bFeO40il6Fktd8PqDKlJkXbQxV+YX3F8p+spETBBILmN6kOzf+fwbt4exJKoPq
         Fzwnj77o5PV49C1hButECpUGxRpCnqF8Xpu28GV26rUDopZJ9PaG/+3SufA1LAtgpJjA
         xgL4wI8pAVI1UJY87Criu4v4adZNJFaYd5nJ9cji408ludXqG95aNWRel03TelMRW6lT
         SYRpV49SGGZBki2LK0KI4FaiOYvuiEx6Jqoa7jwFT7xaZB4pxNrACn0UT0+h0DdS9NT6
         1Ur/p97m8yhGUJ2s1WrhtQNe0hcYQTAzw49Bao3fxrIkO1bPfYIXsDOSpSCNhPoHkXmY
         zKog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :feedback-id:sender:dkim-signature:dkim-signature;
        bh=4vrYgDfOs4rMf0VUp/CdIYQcYgMLCrHVdVxKUNkeyhE=;
        fh=5vKaOHfh5VIkTqJ05T7axqQCtRwW1sOo98/eAdZIFss=;
        b=fN8ezYII4hoRM2gSjdQxDFBq95MgoivsgIbS/azJkMgTc4yjEcQSDL/DXeFZPHB3/r
         Mwp4ibOH3NqmCwcXcEaFB84G/j1HGpbHbyruLcGvseR3kREzfhIrr9u24j2pn5RakvkL
         x+siyxv3JArevhLKsXjBNOh++swdtX58zlDJvZvNdc3VtgNaEx8NyckPv4xtYJDpf76t
         K9rmsymZABtatRE8Ge91AzVrahaw3Yymqvf/vCgLtwYNef1ZCtC9+VfjNZJz/zL9Emah
         NwtHKGxSWP1zSaTssq4vl3v55vxju1lBSnHZu70fTWMEKdLQJSJZ/FyxDZ0zXX9nGXY0
         89uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZJ7WFjaS;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730490706; x=1731095506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4vrYgDfOs4rMf0VUp/CdIYQcYgMLCrHVdVxKUNkeyhE=;
        b=fUeXXXp1QDFtaFZmQApASbRyf1LJ+6j0z1fsJG/SDJ2qwaNAzyknS6GFnHER5EeFAC
         Y7Ab9ob55BxTjGJ77zKYQ/xd+b9OvBiixLj4/SQHJstRpxhlNeaF++niv3FGL/SOxJoQ
         ccBuzSzsdj5anhM2ervJ/XFA6q3TwaU3SiQJfpBlOriZTKSN4I2x2uwDX4UpEESXwY/f
         t7p+Vk+rTBUVsdIWiTXlBFj8dCz6WCKKRp1IqnxdK/LiIF8oT04+3dmx3aqrxikdfyPP
         /nrwn9Yr8+u+bzgdyyR/hRlPG5Bb8AoqVdLgFF7Ki8UDL4Xj1fBSiQv8sGum3ip08TlD
         xPrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730490706; x=1731095506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:feedback-id:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4vrYgDfOs4rMf0VUp/CdIYQcYgMLCrHVdVxKUNkeyhE=;
        b=U3cFElEzGU7g3nQ7bZzFV2Uwlc7SkJRutZ1WbfVC2g+o+aNxN0q5kDGlgLCHJq/Zf9
         pQRh3FIQDsnSojcOipKtc7/fKDY5LCekw8L2C1n2yiu2jNGciL6vePj799BSwYCzYCai
         lQEY1qV2U4JJfAii5oJMDcVcKHV0yJbO1xNfqNzqujB5zF4r4uNFQGpV5duSbY4iSz7S
         Z2k5oWxeLnN+25Y+ZNHJFIXGFmEDESxicFS7QYugvT3yNC3le4jN3DIsw1YkSTCxumHt
         fTUW3+UmdB8wsaAiHuJ9yYm3HvDmLeP+DE+q+XXNr3xrFLWGUc9BB2WmNvwb+igcU0cC
         VJEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730490706; x=1731095506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:feedback-id:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=4vrYgDfOs4rMf0VUp/CdIYQcYgMLCrHVdVxKUNkeyhE=;
        b=uI/EWtu/npwXY6A7DD1CC5eNosO48D5L9UMqfI6N5FD1tibAIU7KzOuQf5cJbl6Nh3
         pJNpq9X8Eqk6VAPbBlnWI6S+zmNEEj0M44U3XlH1+rfTig9UI+qERdHCm1s4wz3PWvfG
         uH5roNkw7Vl/BjogatMyXNQvcpKL9YVUT2G1Q446XprArCn3FVqjXyYKmOrCQwFZg7nf
         DE/vaq2sw3QnUD6nTXiDbOPYa+Qq/0MmuMuWLyKmMPuzjOZNgb8OdniZVrjUrjJzvoz3
         ql+pgRhE7GpCaswFt00bv5LXJx6n9Y0Sp72QmhCYssM/I++IcgphFeJOj6GD8oOAVnpH
         ZOXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURncganzzo4PYaxT/m+wGQT0Dx/vrI+5ZxjwOXHd2djivdBVRrPhA9FeP50vi422HEe0iSBA==@lfdr.de
X-Gm-Message-State: AOJu0Ywn3a/ZdDJBVSIH8WFN2UDpDZNAGsvSC7kUh5slr01mgIj6wSH2
	IYY0GQre7dasn4gxRIAB3NPz2Qr0WoM330Kn0Dz463aL1d6PWCjZ
X-Google-Smtp-Source: AGHT+IGuRFlxZtbuFTLLPIBk/W+2TCM82+gSMbPtYmpiW+XzbX9C5EzMhbNGYicaDVGDly/plfyFEg==
X-Received: by 2002:a05:6820:808:b0:5e1:ba38:86e7 with SMTP id 006d021491bc7-5ec23970a84mr16370740eaf.5.1730490706298;
        Fri, 01 Nov 2024 12:51:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:413:b0:5eb:ab34:cc2c with SMTP id
 006d021491bc7-5ec71612514ls1462128eaf.2.-pod-prod-07-us; Fri, 01 Nov 2024
 12:51:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXi9F5qlGZJeWdKlEF8GNx/JfJQ3VmW3jfRd/zg+G+Ax0JsxX4pxMoolspJVZdvTCMsBvLDb/70KN8=@googlegroups.com
X-Received: by 2002:a05:6808:384a:b0:3e0:374a:1a60 with SMTP id 5614622812f47-3e6384c4db2mr24569757b6e.30.1730490705625;
        Fri, 01 Nov 2024 12:51:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730490705; cv=none;
        d=google.com; s=arc-20240605;
        b=fbPnqJ3ug7Fe/QpTYgL9CeznqvCEjCD/LX+9OmbwHFTc+LWGNJfMY4l7taoDDww1tF
         hKqk+ouu7AG3+gU7UyhjgdwE+/RZf82B8DFBIJ2yLiXYxs1dREKqBrBEfs0S4BwFBD8I
         cOQ+fMxlv/EAECKWgdetxd7++0ts6ouUfH0Nv65bOprBvvGhDL9j1V5G6VO/JIvaEz22
         8aIuYf3yqmEYYmIEbxusnT24txgxHScwMr115ST/7lqSI3wKXwDBJ15MRLztQPbaStGq
         1bB5v8+ichXACZEo1L9kzknGIw+cKlYiaCUmJQpUJXuPwVS8140EA4v3Qi/l5C1uPHRb
         chGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:feedback-id:dkim-signature;
        bh=/Zt5Oyq2ZbDc+xfDrPzoymFKTcNzDTK9mifrrmXHggY=;
        fh=8mwkV8gpSNSXIYwb+KJanUKW/6T71hZ7hTmNPVfCejE=;
        b=iH4DsoSqrcomcSXhrHrM4YQemh1cNKi5SfBFgaLU0T6IgwQqCiq8MrGivvHE2TVqGL
         qTlgzCUoqMyW0uqs0NLXzqZ5/zYddKJkN5dsG4RwJJEIjmiGzA24aZI0x40ql3pUKuaj
         jVgLWKCIR1xfgTfPkpO3s92szMgqugfXuc1ckyXz5aXaD0zoztFBcckKA9G2oj1SN+rA
         Lxfv56fhcDajVENdD7q06Abx7T/578dfaqEkEltDgypkt79e4CgSWvXqdcyQ/BvpPU5t
         g4FpK0OVD50hxz61o90uxzLSuxdRGLwBdb1q3ELrC8TMEdlimGLxveOkSh1iqjYsXxo1
         iCtw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZJ7WFjaS;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7ee45297844si213499a12.1.2024.11.01.12.51.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 12:51:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id af79cd13be357-7b14554468fso157349785a.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 12:51:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLmWoeRveoBByf4zK4qW1q/xxIZLS+3AweylESsEbXm0xgMp3yNduiN+tEYf5jt/6WiZnDUdr3n98=@googlegroups.com
X-Received: by 2002:a05:620a:2410:b0:7ac:b220:309a with SMTP id af79cd13be357-7b193eea86cmr3366675785a.15.1730490704526;
        Fri, 01 Nov 2024 12:51:44 -0700 (PDT)
Received: from fauth-a2-smtp.messagingengine.com (fauth-a2-smtp.messagingengine.com. [103.168.172.201])
        by smtp.gmail.com with ESMTPSA id af79cd13be357-7b2f3a6fedcsm199163285a.78.2024.11.01.12.51.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Nov 2024 12:51:44 -0700 (PDT)
Received: from phl-compute-02.internal (phl-compute-02.phl.internal [10.202.2.42])
	by mailfauth.phl.internal (Postfix) with ESMTP id 981A91200043;
	Fri,  1 Nov 2024 15:51:43 -0400 (EDT)
Received: from phl-mailfrontend-01 ([10.202.2.162])
  by phl-compute-02.internal (MEProxy); Fri, 01 Nov 2024 15:51:43 -0400
X-ME-Sender: <xms:TzElZ10j-eXrd7GNpv30l4_b_AVMitAXoOkCDnFULD8gWgi_RIgsEw>
    <xme:TzElZ8G4i0hnOQjyccOf5Asbt-kOIQGYAHZJOnM2Orcm-1A_nAUbIFE12O4nUq4Uz
    FPmHkfdkBWQqTJlLA>
X-ME-Received: <xmr:TzElZ15oxxK0Zrjcg731hlviLBQa4qPFHPFtrGMBIOLtBsY33E4wagy65QmUXw>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgeeftddrvdekledguddvlecutefuodetggdotefrod
    ftvfcurfhrohhfihhlvgemucfhrghsthforghilhdpggftfghnshhusghstghrihgsvgdp
    uffrtefokffrpgfnqfghnecuuegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivg
    hnthhsucdlqddutddtmdenucfjughrpeffhffvvefukfhfgggtuggjsehttdertddttddv
    necuhfhrohhmpeeuohhquhhnucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilh
    drtghomheqnecuggftrfgrthhtvghrnhephedugfduffffteeutddvheeuveelvdfhleel
    ieevtdeguefhgeeuveeiudffiedvnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrg
    hmpehmrghilhhfrhhomhepsghoqhhunhdomhgvshhmthhprghuthhhphgvrhhsohhnrghl
    ihhthidqieelvdeghedtieegqddujeejkeehheehvddqsghoqhhunhdrfhgvnhhgpeepgh
    hmrghilhdrtghomhesfhhigihmvgdrnhgrmhgvpdhnsggprhgtphhtthhopeduiedpmhho
    uggvpehsmhhtphhouhhtpdhrtghpthhtohepphgruhhlmhgtkheskhgvrhhnvghlrdhorh
    hgpdhrtghpthhtohepsghighgvrghshieslhhinhhuthhrohhnihigrdguvgdprhgtphht
    thhopehvsggrsghkrgesshhushgvrdgtiidprhgtphhtthhopegvlhhvvghrsehgohhogh
    hlvgdrtghomhdprhgtphhtthhopehlihhnuhigqdhnvgigthesvhhgvghrrdhkvghrnhgv
    lhdrohhrghdprhgtphhtthhopehlihhnuhigqdhkvghrnhgvlhesvhhgvghrrdhkvghrnh
    gvlhdrohhrghdprhgtphhtthhopehkrghsrghnqdguvghvsehgohhoghhlvghgrhhouhhp
    shdrtghomhdprhgtphhtthhopehlihhnuhigqdhmmheskhhvrggtkhdrohhrghdprhgtph
    htthhopehsfhhrsegtrghnsgdrrghuuhhgrdhorhhgrdgruh
X-ME-Proxy: <xmx:TzElZy1QNyYU7a9rf9ekVospA4HpyM0JWbGzyFE7i6FPizV0ba1zeg>
    <xmx:TzElZ4FVVSPIiUo8miotxDfc1PRWwqUZfddrAhFzE7ra88UEcdhbzQ>
    <xmx:TzElZz_q-ed8t7TEugZbWFUoVIL_uLcRd3GI0Gxe6JlFo4tm5eVBaQ>
    <xmx:TzElZ1nojlQs2hENdw7GcQNjwE1Z4ZKj39ynW3uMy_8MwRGEgkOz5Q>
    <xmx:TzElZ8GwVc57024kIQWEePxJr6WDGBYrLUNkFqB8ed51-kRjzEFBBP57>
Feedback-ID: iad51458e:Fastmail
Received: by mail.messagingengine.com (Postfix) with ESMTPA; Fri,
 1 Nov 2024 15:51:43 -0400 (EDT)
Date: Fri, 1 Nov 2024 12:50:30 -0700
From: Boqun Feng <boqun.feng@gmail.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Vlastimil Babka <vbabka@suse.cz>, Marco Elver <elver@google.com>,
	linux-next@vger.kernel.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	sfr@canb.auug.org.au, longman@redhat.com, cl@linux.com,
	penberg@kernel.org, rientjes@google.com, iamjoonsoo.kim@lge.com,
	akpm@linux-foundation.org
Subject: Re: [BUG] -next lockdep invalid wait context
Message-ID: <ZyUxBr5Umbc9odcH@boqun-archlinux>
References: <41619255-cdc2-4573-a360-7794fc3614f7@paulmck-laptop>
 <e06d69c9-f067-45c6-b604-fd340c3bd612@suse.cz>
 <ZyK0YPgtWExT4deh@elver.google.com>
 <66a745bb-d381-471c-aeee-3800a504f87d@paulmck-laptop>
 <20241031072136.JxDEfP5V@linutronix.de>
 <cca52eaa-28c2-4ed5-9870-b2531ec8b2bc@suse.cz>
 <20241031075509.hCS9Amov@linutronix.de>
 <186804c5-0ebd-4d38-b9ad-bfb74e39b353@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <186804c5-0ebd-4d38-b9ad-bfb74e39b353@paulmck-laptop>
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZJ7WFjaS;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::736
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

On Thu, Oct 31, 2024 at 10:50:29AM -0700, Paul E. McKenney wrote:
> On Thu, Oct 31, 2024 at 08:55:09AM +0100, Sebastian Andrzej Siewior wrote:
> > On 2024-10-31 08:35:45 [+0100], Vlastimil Babka wrote:
> > > On 10/31/24 08:21, Sebastian Andrzej Siewior wrote:
> > > > On 2024-10-30 16:10:58 [-0700], Paul E. McKenney wrote:
> > > >> 
> > > >> So I need to avoid calling kfree() within an smp_call_function() handler?
> > > > 
> > > > Yes. No kmalloc()/ kfree() in IRQ context.
> > > 
> > > However, isn't this the case that the rule is actually about hardirq context
> > > on RT, and most of these operations that are in IRQ context on !RT become
> > > the threaded interrupt context on RT, so they are actually fine? Or is smp
> > > call callback a hardirq context on RT and thus it really can't do those
> > > operations?
> > 
> > interrupt handlers as of request_irq() are forced-threaded on RT so you
> > can do kmalloc()/ kfree() there. smp_call_function.*() on the other hand
> > are not threaded and invoked directly within the IRQ context.
> 
> OK, thank you all for the explanation!  I will fix using Boqun's
> suggestion of irq work, but avoiding the issue Boqun raises by invoking

I've tried fixing this with irq work, however, unlike normal
work_struct, irq_work will still touch the work item header after the
work function is executed (see irq_work_single()). So it needs more work
to build an "one-off free" functionality on it.

I think we can just use normal workqueue, because queue_work() uses
local_irq_save() + raw_spin_lock(), so it's irq-safe even for
non-threaded interrupts.

Sending a patch soon.

Regards,
Boqun

> the irq-work handler from the smp_call_function() handler.
> 
> It will be a few days before I get to this, so if there is a better way,
> please do not keep it a secret!
> 
> 							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZyUxBr5Umbc9odcH%40boqun-archlinux.
