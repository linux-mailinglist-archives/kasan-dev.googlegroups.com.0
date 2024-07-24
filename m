Return-Path: <kasan-dev+bncBCS4VDMYRUNBBYUOQS2QMGQEBW27K2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EE1393B200
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 15:53:40 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-70d34fa1726sf2647635b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 06:53:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721829218; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dcdp2+WfWmS8AGrzqe+x1yM3fqgQyAO73+54u0RkiHdi3N9929U4d5bL6SP9DzaE1H
         nsLql2GNncLCAaqQegRhfBATI2LaSpC/FJjMRKXuKfUVp6As8IC9Sj1u9Nsq9vr26Aa/
         lo+7/uH3TBZEYBhrB0I9TiDey6Hi3u3+yGMIjFitCbvFAZfq6ZSeAJJJ/gLvfcdpHrqT
         n5RXOuBUYsUFpZfSc5TOcXGES4rzHFx+UFn/39YtJY4sKiMi6BUDJOTVvMNgARrrHuu3
         s/UmugoKOiNm3pxkmQzLv1TuSYsS2f/xkRjdP3XMwDDE4AX939rXHU+i/a2/v2bLnXC9
         c5Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ZV0SNs63+jIUCpVRl561ci+9oVeTGNoZkGmldxNcOrc=;
        fh=uR9ljsVuUs/BViNbcyUIKfwM/pUHzFxHHcm31RO0u6k=;
        b=B04Poze/BZstFqEkl/xajQDxUUk7V4mV0hNpwA0/4feh2dog7JP+kDpI2KUJMPvJa3
         ci6MNNwkfjqoWUEwkogcSU33/r1J2usLyyg5u2128vKLs2dsL49cqhZqYnpaKgQn8MiF
         PKLfq/BwTemUoTuqhlE5xC89BQanTFasEKXGbDFtDrXMxB5G15M0pYyw+KCX2LL8RaKh
         i7inbvuOy+6HJwhV8kmWz5kGczhBB0Q7tPVCbJU2Og8eoYSU+MJG6+PcV/DLPj7loSvx
         BeOHFbqOd3lWggLVJyOg6p7dOOOfOGdFE3x7OOj2SQxtLPCLT42EKyjjEjQyyR19rYK8
         hKtQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WAP2//Vl";
       spf=pass (google.com: domain of srs0=mrac=oy=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Mrac=OY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721829218; x=1722434018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZV0SNs63+jIUCpVRl561ci+9oVeTGNoZkGmldxNcOrc=;
        b=HKCgmLHXEqQZwWa5bFFfUOgeMduSgPkaoWs1Q/NR4xfPBJewtvRmPWz08nzxibrpBq
         FaePeOaaSMtf+dIo9O4QXdAJX2nrd9EV+FhHE+yEPXjvLXe/1vT6GTHQpjNcHZhaGQ4o
         eLpe9FGjFRspPsnlFFgRcJ9LsPzfqtkXrMbssFU6BNIC3sBlAijBYsNpZL4GzOhbocoS
         hMwKrNIQ8tuhcHc5vPTtz0vzH1wuY+ab1zwSf9RYTYzsGEWNu9QuK2JW/0NjjsFDmDze
         d7p6gH3r3UC9egWWntf0i0Qt14W7CtEAtbuUTC4u/OlH5a6O5hxbx8Sydjxbpgsu4Wft
         hW5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721829218; x=1722434018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=ZV0SNs63+jIUCpVRl561ci+9oVeTGNoZkGmldxNcOrc=;
        b=Dg7YxDEtvSzaQYF/OiyQvgoJ3xSiaZ1kB7TxdBdmQfs8oH/eaZACdV7Eh0nzpCxG1D
         8DPTQ1wfCgunz2nKa+ThrsiHxx51sLOCs7NYjDBEwi1Im9zN7DIMenhuzJletIui3pa5
         EFobbLjBBzwYd/MdET9CyZVv0H2bkyWUolCQlZQZhO1q9DFGClgBfSsx9aK5PQkjBoVS
         xt/4X2vfZUlN0QQaXuzUrUu1Rc5vooS81M8jpyeLHekq9j5SSeQaliEjlW98ylCWP/0a
         pQW1QJJZmTOkszh7Vi6xpix6aRxIKW3ofLZunSMZb4FoUc97BjgvGf00PrSWiDflB0sq
         haZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsbD9YpyUQe3mG+h4rqM8GTlPpEp+5jREi3X2n5ulX00N2jrJ3fu1PsLAdn+48wwEdqcTvIJpHBR/5WnBfZmmirt+58gJhAA==
X-Gm-Message-State: AOJu0Ywr9s3g+v0LJbrZfXKHRTtm3pcqbYTDJrssAerWZAhJhcnmDu7N
	1oXcmCBYyu9ZzvZ4mMIc2HJPqXlB90QMu7a0w9U/zYOa05ZDydDH
X-Google-Smtp-Source: AGHT+IFiD7oL0+xcsfmaUtZaSVFIPBdmiWYqVXxq6aEZnw/PlPFKL2fQPC8+fhqpav9WsX60Mih3VA==
X-Received: by 2002:a05:6a20:cfa3:b0:1be:e6d8:756e with SMTP id adf61e73a8af0-1c4229a9b53mr18447726637.53.1721829218425;
        Wed, 24 Jul 2024 06:53:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f68f:b0:1f2:eff5:fd69 with SMTP id
 d9443c01a7336-1fc5aad32b5ls46389745ad.0.-pod-prod-08-us; Wed, 24 Jul 2024
 06:53:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWx1jwDb8B0Va0iiUrxWKgwRap5MIfMN3qLvOvniFyUheLlbY26Lxd9iR/LivdEMVnl5RbRwBWyGMZHB8Vi10j/u2kH1cnM2lge2w==
X-Received: by 2002:a17:903:22c4:b0:1fc:3daf:8a0f with SMTP id d9443c01a7336-1fd7451541dmr171681475ad.7.1721829216371;
        Wed, 24 Jul 2024 06:53:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721829216; cv=none;
        d=google.com; s=arc-20160816;
        b=0eAvGUAXR0hj1YbTKooQCT9xOgC/Zy4bbKoMYb5OwP1iaPtU1UBUVIFv2aSmpVtes0
         r9hhcYCpSUTrvIRdC1A8K8WHWhkXjCHmvacN6u96suwHDlzWiQoheYYRzvoU9TyA8ItK
         gqeIE2DhzxCMyYzQMJmdFDyNeF2qVHnKFEYYgnV+oxoS2D+Ca9Q6JlwmseFu9Fa8bBUP
         TW8hb7bifyy6B1qeShQLgr1w66WszK1ryYVi6bfrjVroMQWlhWgNPQ0EQFYTbPX+gmnS
         0cNZSMNbF99bjf7q1HF8ibmlFM25bwtsmK99i8CUQ06LZBJP7C8Cwt0DAxLndHggHq4d
         T1eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=utnv+WzGX4FSpAkpmgKR2kCr+/60C9Pnp/hEfW/beXI=;
        fh=b4rUQKQOOXPMgq1nkRYM+atCQEIVYCiymtW6U8DhPd0=;
        b=lLLvSPdvgqSzGAnRLopdCV5vVWA1h2eVLHYWw+mCJ6y9lY3T+N38c7wx0QkUZrqKdQ
         QUs2Q1G9yDW9h/59CO9GFXTg4a4IL00GtKmPzjm3BOHr8+qZ/J2SkS1jFqOS9UjBN/Ae
         /Vn3+wc+u/Ownz0fdLvYUTtGbyxupv+rfflLEhkv1gK2LpaQ4a09HZzqDBpWu47yH6PZ
         LAHVO7M8VFuH0uwRxsJ1SCgDlYGZE7Q9VdlfJlD3Cb9FuAaqZ3eslI0+1/1wBOGfPmPi
         uRCEEfN7Lp05/iVJE2WqUBBej3xjM7M0qgUvDxW/i2Xq9tQm8Rxtbeyr7SBCj61ho7Id
         vl5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="WAP2//Vl";
       spf=pass (google.com: domain of srs0=mrac=oy=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Mrac=OY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fd6f4252e5si3961425ad.12.2024.07.24.06.53.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Jul 2024 06:53:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=mrac=oy=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A68B060AC7;
	Wed, 24 Jul 2024 13:53:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4B0F7C32781;
	Wed, 24 Jul 2024 13:53:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A535FCE0A6E; Wed, 24 Jul 2024 06:53:34 -0700 (PDT)
Date: Wed, 24 Jul 2024 06:53:34 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
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
Message-ID: <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
 <ZnVInAV8BXhgAjP_@pc636>
 <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="WAP2//Vl";       spf=pass
 (google.com: domain of srs0=mrac=oy=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=Mrac=OY=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Mon, Jul 15, 2024 at 10:39:38PM +0200, Vlastimil Babka wrote:
> On 6/21/24 11:32 AM, Uladzislau Rezki wrote:
> > On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
> > One question. Maybe it is already late but it is better to ask rather than not.
> > 
> > What do you think if we have a small discussion about it on the LPC 2024 as a
> > topic? It might be it is already late or a schedule is set by now. Or we fix
> > it by a conference time.
> > 
> > Just a thought.
> 
> Sorry for the late reply. The MM MC turned out to be so packed I didn't even
> propose a slab topic. We could discuss in hallway track or a BOF, but
> hopefully if the current direction taken by my RFC brings no unexpected
> surprise, and the necessary RCU barrier side is also feasible, this will be
> settled by time of plumbers.

That would be even better!

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b3d9710a-805e-4e37-8295-b5ec1133d15c%40paulmck-laptop.
