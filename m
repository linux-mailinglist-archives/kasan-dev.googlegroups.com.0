Return-Path: <kasan-dev+bncBCS4VDMYRUNBB47UY2ZQMGQELUHXYQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C98F690D9CB
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 18:48:53 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-1f88cc86257sf23135ad.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 09:48:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718729332; cv=pass;
        d=google.com; s=arc-20160816;
        b=IsvxU/QOHsqatPDvGYSUkW2vjiz3mj0RPf6AYtCpUkGPLHe88yFNQUDrEfXCz8ii8o
         oemggdk1lmgHsR4cTiPkJg7FuK9rn7Kar3g/WARAyy7yKi5xWe10yuWl2aXQC+VWovSR
         uVbY7vXPQWzSBK05vOrOBqpnzxv4iJTRiCl8a3I0lZfNwWqSZBT4j++eAVrH8BU+30dj
         4rv+ze+/R3nuhAK4U0cl4NPXBg/N0oNPK7c3tjW2IIMRSMWI46rcN6/Vde/mBtVrzlyv
         f06Omi1LTXdF1C9ya1+VBKsw5qld5U4vk3t9TzS4lfX4VYNm9XXOOBYh3LBqst9smj6y
         FmLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=uD3ORDwrkSdRWTXe5tywEyEsEfEftzV0LpMxYkHoAH4=;
        fh=jEQJX5eZ7WrTISfxXXPHqG5WHJm5BUI5J6M1ffU95R0=;
        b=jaS5HiC2y2t1CQuKy32Ae9YfKfc35aNWxr/ZKLTzbmWuWKT2IcpK57BTUMwa83U7/w
         42rmxMbpogplwqFJhPzm8KTKA1/u/rERGQuwcM7A8CnclFvxTCvlDqd7Gzt8TVfxcocD
         +AsP8n/jiJuIeS1jajeXLPttuAEL8/s4b8Ma1+Eg8iTp1x3tbQfMMkXHJdZZZBZfQsNA
         p2Vn1MZQsHVtzA0DUQO8N4GgmUYBJXUes0/7BhYAN4teD2R7ZFvyotwWZPhWe2Ay5iDo
         xG0r6LRBZ5g25F5eB6HBZF4Ew9+7ewo+AfwcyA4rYaoAp9o39uY1AsqCCH7dGf/HFta0
         RdKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HrsVOBE2;
       spf=pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718729332; x=1719334132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=uD3ORDwrkSdRWTXe5tywEyEsEfEftzV0LpMxYkHoAH4=;
        b=cuDMiPEJkZO3Pf0cMiQUk76pqpc55EGsQebqvZrj8os5Pzjw43OoSwym7M1VVyIU3I
         bZe1wU3EaD8U0XjZmSEglnaHxgfDVzDdfJtEDm2L6Aw774Hk1R/GJRwhPOF3OB14Cmaq
         DumIP5p1zHN+RhZOCQ9Nzyxn+ysKd6m5FKD9W4uZuVMEd9Kl/OEeUk+9dGu3/1inJyy/
         C0YX9EtcekOvB8SJzg69y9POp4c6xPCO8jOBVRDUCr5ahnf3xNzO4sEbQ4Y7b03bxIvn
         UZ3fwI4m2QFO6x//c6B0dBy6V8vmlXZjzxBc71g/UpBhGeMPQGCcfHDlO0uhW/NvoZci
         VMZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718729332; x=1719334132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=uD3ORDwrkSdRWTXe5tywEyEsEfEftzV0LpMxYkHoAH4=;
        b=oB3iDFt1qiAjFTVWucANFed1oJrUhPo1pf5YqBxOGUOprw9+sMd91LfQjt/CmKTSdr
         TxcMLt9OpldwYhQzZR2YwMqitSK9vxfQ61UqRJKiYYk6gxh2HKmNpOdd2C+FLgY6uq2Z
         nGunpUoRMoZXh810NtNUB16Tk5X2Iios+MbPOgcx9fb0lok3Y+btBtIYiVmxGSlF7avd
         o4189ekgkeZZYng7F3q8A+IxEYEBbMeG6FKFrgJ49WKRtTAUXAGazCgbSI4uKWaPffw7
         DImhuVgVVUWZzyq1DVrcigBVyB3zkmtXPoslJteI7REqo6ppix0mE3+Rp64EFN8NIobZ
         RFMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3X4PyV/mIssGjK2Ai2bpJqEqiQ8rWJF1LhgZtftes6bZfC33YAjWz4fm4aQBCCmS16FciemMZHVBMesLmlZsGXiW2RZs1/w==
X-Gm-Message-State: AOJu0YwJvhAsFIeovx3SORu8zZWubZnDqTLKI6zAaCGuorBvEu8HkZAu
	QMQZKnEwCsnBM71n0wgM4QI+UDTZFFrkY1+vM9Abw1HcrSPZoKLN
X-Google-Smtp-Source: AGHT+IEd1VI/Blp3YQtOFrKbChDDclgFxQ+iMpd/x7Oy6k2oOmx0qQyix5itLc63LhP1uCJutrGRMA==
X-Received: by 2002:a17:902:b604:b0:1f7:2876:9947 with SMTP id d9443c01a7336-1f9927833f8mr3176285ad.27.1718729331881;
        Tue, 18 Jun 2024 09:48:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5812:0:b0:5ba:6b54:d29d with SMTP id 006d021491bc7-5bcc3e2a2c7ls1961317eaf.2.-pod-prod-00-us;
 Tue, 18 Jun 2024 09:48:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVSts3HNwNY35iXgRxVdZ2ElrmQCWhNUViDGm7hzaSkJrmFK4flnsTvSOWlmOGflLXA1uI1W1vhWzPfoGtm2f0FIDurlLzvEcDB9w==
X-Received: by 2002:a05:6808:1484:b0:3d2:2334:3fc5 with SMTP id 5614622812f47-3d51b677de0mr190384b6e.23.1718729330831;
        Tue, 18 Jun 2024 09:48:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718729330; cv=none;
        d=google.com; s=arc-20160816;
        b=a/heFzAHiNBLAFWdOku4V6ArRdg1vHRPRH1dQngivEnE/UWmr49QoPVZ4BlmErOcd5
         L6eVaZeEZw7F2Oj05zEqGgn5inonHM/K1mNd7EkK6loQxP3OuXVbbnNpH7kUXTcK/lMD
         mHO6m+t/yssPtGuSMSVihR5JxtbHUEY7FZL8+0WY411yD3EGrw7PznqRf5zKecrgxi4A
         vV8krouWO+8ew7RBSZH4VmzPXSDk1NM3KHEPHECoofL4WOSVOS2MfuT0u7EosZ0s3qYB
         4XtAoayF9h8MaoERplQpPVqatYUD17XBCiXuIzx3dHRQxO9JSJHCbcH5pNFA8PNeOE5j
         QMjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NTwWsIDsO8ilUN67seqctk+NSXumOtr5jDWkLesweYo=;
        fh=WOHLATDQ+alzitRV7ns5gUYiT9cUBXLZrQwbOeWsat4=;
        b=See1yB4kRfxFMD/dCBWcWlREdhKuhhpp1/mWdE0xRDNMI09a2SII23pM41zA9dijZE
         agvo3AVWi3NrBlHENm5mvUq/rVBF5l2BXf6Vpz8sdx7QYl+IEHJ9fIEigUdgDtJm4ZRd
         n0iTe+EqWoxVp6m0+DA4NStuTwYn0VDOs0TYBduIpu8lsGwz/nEJy4EMNVz4qDFGliuT
         UfsqZ198LPeea8JUnmdbMZCKc9hFMdbhYFkyC6IM/tjoQIsZIkSTHH2BCkDFEMpyFHqr
         7vVMnEiRbpjB5EpqHvIUl11Z0uNVZRmOjX7E4iWdl1qyTge4ydfc+grJfYuwdw+hV0tS
         2TuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HrsVOBE2;
       spf=pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2479698b2si503508b6e.1.2024.06.18.09.48.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Jun 2024 09:48:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 86154619D9;
	Tue, 18 Jun 2024 16:48:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2DFD3C3277B;
	Tue, 18 Jun 2024 16:48:50 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B9F83CE05B6; Tue, 18 Jun 2024 09:48:49 -0700 (PDT)
Date: Tue, 18 Jun 2024 09:48:49 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org,
	kernel-janitors@vger.kernel.org, bridge@lists.linux.dev,
	linux-trace-kernel@vger.kernel.org,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	kvm@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
	wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
	ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
	Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
	Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
	linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
	netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
Message-ID: <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <Zmov7ZaL-54T9GiM@zx2c4.com>
 <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZnFT1Czb8oRb0SE7@pc636>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HrsVOBE2;       spf=pass
 (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
> > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> > >> +
> > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> > >> +
> > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> > > wanted to avoid initially.
> > 
> > I wanted to avoid new API or flags for kfree_rcu() users and this would
> > be achieved. The barrier is used internally so I don't consider that an
> > API to avoid. How difficult is the implementation is another question,
> > depending on how the current batching works. Once (if) we have sheaves
> > proven to work and move kfree_rcu() fully into SLUB, the barrier might
> > also look different and hopefully easier. So maybe it's not worth to
> > invest too much into that barrier and just go for the potentially
> > longer, but easier to implement?
> > 
> Right. I agree here. If the cache is not empty, OK, we just defer the
> work, even we can use a big 21 seconds delay, after that we just "warn"
> if it is still not empty and leave it as it is, i.e. emit a warning and
> we are done.
> 
> Destroying the cache is not something that must happen right away. 

OK, I have to ask...

Suppose that the cache is created and destroyed by a module and
init/cleanup time, respectively.  Suppose that this module is rmmod'ed
then very quickly insmod'ed.

Do we need to fail the insmod if the kmem_cache has not yet been fully
cleaned up?  If not, do we have two versions of the same kmem_cache in
/proc during the overlap time?

							Thanx, Paul

> > > Since you do it asynchronous can we just repeat
> > > and wait until it a cache is furry freed?
> > 
> > The problem is we want to detect the cases when it's not fully freed
> > because there was an actual read. So at some point we'd need to stop the
> > repeats because we know there can no longer be any kfree_rcu()'s in
> > flight since the kmem_cache_destroy() was called.
> > 
> Agree. As noted above, we can go with 21 seconds(as an example) interval
> and just perform destroy(without repeating).
> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c8b2883-962f-431f-b2d3-3632755de3b0%40paulmck-laptop.
