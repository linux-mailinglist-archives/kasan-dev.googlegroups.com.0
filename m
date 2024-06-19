Return-Path: <kasan-dev+bncBDK7LR5URMGRBROUZKZQMGQEDUFYCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D7E0190E752
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 11:52:06 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-52c805e6f38sf4551079e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 02:52:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718790726; cv=pass;
        d=google.com; s=arc-20160816;
        b=uhAw1Cd+cn4k1P0i9eCPCosRPHRqPGOF1sDKxSJM73SjKQ0xjiQnBhErtnbX+gfcA2
         6RrF4fA8xBC25qHIC/JVwpRC2O5OQTyZf2yipp9TgG2TK3nGPuRlwKixme8knyWRJlJf
         zwyW0TTXTiLSY3L+YHxX9KV4GRm+PYMvyP1DgPQ9EZLv23x5fABmvafa0Udf/DIBk30S
         z4TZVi91V20ygLxn5E1mG7NPgtqs6WQKcdn8Ajb4JY2uUGy0c+luwOvDPhzyBq4huXBI
         Wo3TXLLSgP6Z8iSbofZ34onbEenvJQmYvfh76BU8M7gzLwR6WeQ5jvC7641kBqG9QviM
         lrjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=nO72syG9HBZNeF8pq7Vyh8KXXMeI9WAEk236EYI56vA=;
        fh=pN7efOKyq5XzgpOfjZ+QaMgALkTvvaH0LtPN5l/daPA=;
        b=KjRj9QSYkLJvup27XpD9GM0LwU3/ZDf1t3Fobu/vhmhes1nA63hq9Box81A3CJh5ul
         1JkFAy6tZPW6Ygp6zpSURwKVjVkC41RRxX9qmQI5xS1KVHQk/aeXBLtY+0qxzmu05E1g
         FHeFwbRFL21W/A39s7DdHAH+115pL8HjLqtJCpGy1BlCLdnLzhadnxy4EGecsaXSwMow
         eHOp/j1d8briFCD9W8qBpeBqSEukEDf1x2WmE0atmSC2s2buQ00TuOkJpeDp5riAQiKn
         PqWo16N5dwdYpBc/IxV4WST3JlrBvc4mxmOlmbF9t/rSpO/spkhUF4aJAr+9GWNQJpa8
         MIMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e1xd37J/";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718790726; x=1719395526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nO72syG9HBZNeF8pq7Vyh8KXXMeI9WAEk236EYI56vA=;
        b=Rbsa/1HgYXKPsuk+cYL1VM+fe6Pdysp/HXZNwRS4oyuYCJ3kG3ZetEatumRWAdQe7x
         0/E4RQ/NZsalnqLpTbU0z2UOyS/bKnqVwIgFZIsCuqHZSotvLjJLP7tfirt1MwKNBQE/
         bUd7znb5/ZJPqvB2xMX/qUbeopEj1Sb9cYkcGuz7yRP7gc8/JxuBOyZY9qoSRUhY83te
         7LT2SAVLOAnmS3zayi94M9S7FBKUzscCaS+BneuPAC6o8EGeESFznCh28fIbffG6nUiU
         XfdGsQv8b93nqLzkQjj/+39wLA/3q+MO5QS4ueUnn4kut3hbcPgeolOnOXweHnL4qFPB
         /4MQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718790726; x=1719395526; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=nO72syG9HBZNeF8pq7Vyh8KXXMeI9WAEk236EYI56vA=;
        b=b71Cy6GXMgBE9X0ykoxlqKiUdMCPtGARvgOXhM+qLUaVgXLM6Iq5Vxm3jwtxbBe69j
         ugFgbj5XajiU5qdfWJ/9qE769/qRjocly2dU/fa/wHHSQ5Hi0LDRqvmPT+frca/RFUL9
         1lKf7OrE7OK6MDH7E/VQHeIqrwx9TGa8Trod4CS5ai2kX9f5Ty0HVxj4mmLOPotDqScn
         l/4SV4wKReR0U+ELT0Nfj7gJ1BpS0HkOg7849dihGyzy1t6LEnUiZqLUTP4B500wlqR1
         4ds87lHUK+U3O+VLGm/4RafULcZWKL/qceVcccnAOXjulYYPwgO3m1YDx8Tk5IBZXT9N
         3xvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718790726; x=1719395526;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nO72syG9HBZNeF8pq7Vyh8KXXMeI9WAEk236EYI56vA=;
        b=RP+BQ+x06FoMprZhah3yXpc4j+3BVNFD4kWUUI/Q2O8E2wB+S/TaZhHfCBaMK9yFNs
         QkqaRm7/0TTlS7/TcByaY5/nTvmB3KBqcJ0y65XB1BPGPx21G3Nh1zkp3c+xLceQJAkB
         FzcOzP0KXUe7XdkPiuzFQxXwUxsyyhBxML+S7dlhR1B+eGlcMIuDOwTvkEHbxU9qvHFg
         CLrKA/DcXgwLTLLToYS0+qJ6gAAu0JvNH/ucXNVdKX8iAW3xT2dxQhNqnCgLEVHlHoXr
         C6shLCh3xpLhphi53W+Wp2aS50mXVhGjvegPX497Qm3MlKFNtJHT6Xpz+p7Kmcd2hENC
         Gaew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU4WUeszGnWDXNaZWVNT5P/+pQ+KAapm+E1/U+XqwIm9jVE2TkVGmU65WPQo1RccoH+y+8Hk+y39XviVQhuaK6SCSpjBeriBg==
X-Gm-Message-State: AOJu0YzcWZLBQNoJhxxeKjIVyKFSpCABuwVhRX0EDR/CIeVng+oXmo4d
	2Qn2xPki/ggldTiNpNwlKPFa2PiXlXMNJ9bquIxznwYgTJBondLk
X-Google-Smtp-Source: AGHT+IGSjZbnaoHBwDnDwq3nVGpfxQuBhrR2c1CWpJzo0VdAgA2l4Nqix9PzG6RT2A5BL8rn34MwLQ==
X-Received: by 2002:ac2:5191:0:b0:52c:9824:2780 with SMTP id 2adb3069b0e04-52ccaaa287emr1247734e87.64.1718790725570;
        Wed, 19 Jun 2024 02:52:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1383:b0:52c:2b7a:b993 with SMTP id
 2adb3069b0e04-52ca06ea136ls1690344e87.2.-pod-prod-01-eu; Wed, 19 Jun 2024
 02:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXNyBEqiWiJClH7VMH1UDRGf/Hb751Qyn9XiyCLiecUV1Vf7D7sjjp2rgHP7wVjs+cjXZNDNo1ZsiZd6doQGJeEa5Obr/g6aWuB+A==
X-Received: by 2002:ac2:4c2d:0:b0:52c:8a39:83d7 with SMTP id 2adb3069b0e04-52ccaa92803mr1218364e87.52.1718790723502;
        Wed, 19 Jun 2024 02:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718790723; cv=none;
        d=google.com; s=arc-20160816;
        b=MwkF3VH9IzK2aRzbQritLlqX7siOtRIK8RSeaJzGLg++hUVM6Fz4MCql307fMz5zyu
         a1hGZJNoSiaIiv9n59iJQJ1Gxt7X7Gtk1hA74ulL/YqBaO8wkwUCaFOE2h6iQZQUOFfP
         8hi9QUEvsSoyFwuSHaQbrzP7lHqSQiJ59SK451o2QNA3++ahE8K7OvTdAPSlakVbZ2U+
         ivXHHrpj7jOUyhFPeWUrptXpAzhhRLFCptg5vGXgoanCQADlCQdrXp5To1uNgAjR0Yxf
         vX69kVOubF3ZxBcwDle+4bjva8rPv5I+o1s84KQkmySIWOVXA92qNIdVeNR+FpwCjpXk
         RfMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=TY+TzI4NVOZe+bVmXFpZLf0ZfiG9DoMpTrEztVoxeCc=;
        fh=LOCdPIHsbWaUv63o2F35vt9GJ+zSRAhTesVHlLDn/As=;
        b=nNVEmUXoGbwveGpFaFAzNfu+ZnjKVWxqLX/CZgC70pGvamUq/1U60PaFiJol3wHqu1
         OGSWUD4N03ic4BFq1+hA0k0O+PFT0aIYJYdo/PLFtltWNwY7WdX29MfKu+mzKVBOQhQE
         23/6vIgYm5AFs3Cg2RIOhbZY+AhDIIwQJ8hK8uQoB0syOKZy4wfci1a2/lTzeQ9I7QBc
         iSVUvzVK6BtEi9cuMVGZJCWORdYpcWMLgQNT8ho9XKriXqE6GYx6jvUf3hraA2v47Nj/
         eYWpmAtfH3ESNF+oHcog0Z1q0P9xThv/Y0Pg48oYEbO4jqAkV6bKji1r6y3Z+k2K68G0
         Kq5Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="e1xd37J/";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x234.google.com (mail-lj1-x234.google.com. [2a00:1450:4864:20::234])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52cc6284718si77201e87.1.2024.06.19.02.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Jun 2024 02:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::234 as permitted sender) client-ip=2a00:1450:4864:20::234;
Received: by mail-lj1-x234.google.com with SMTP id 38308e7fff4ca-2eaa89464a3so72314781fa.3
        for <kasan-dev@googlegroups.com>; Wed, 19 Jun 2024 02:52:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWoCKK2gzC8OuA2DtHol2zqTDcqIdfazOuk04Hnna0Z3U45DewcRC4T85MysZI7G2GdHD+VhaCowuiqWJoWVMh2+jhdyweU/Pz3UA==
X-Received: by 2002:a2e:9cc6:0:b0:2eb:e365:f191 with SMTP id 38308e7fff4ca-2ec3ce93f99mr14054151fa.15.1718790722749;
        Wed, 19 Jun 2024 02:52:02 -0700 (PDT)
Received: from pc636 (host-90-233-216-238.mobileonline.telia.com. [90.233.216.238])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2ec05c06068sm19506721fa.35.2024.06.19.02.52.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 02:52:02 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 19 Jun 2024 11:51:58 +0200
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Uladzislau Rezki <urezki@gmail.com>, Vlastimil Babka <vbabka@suse.cz>,
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
Message-ID: <ZnKqPqlPD3Rl04DZ@pc636>
References: <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="e1xd37J/";       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::234 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 18, 2024 at 09:48:49AM -0700, Paul E. McKenney wrote:
> On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
> > > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> > > >> +
> > > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> > > >> +
> > > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> > > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> > > > wanted to avoid initially.
> > > 
> > > I wanted to avoid new API or flags for kfree_rcu() users and this would
> > > be achieved. The barrier is used internally so I don't consider that an
> > > API to avoid. How difficult is the implementation is another question,
> > > depending on how the current batching works. Once (if) we have sheaves
> > > proven to work and move kfree_rcu() fully into SLUB, the barrier might
> > > also look different and hopefully easier. So maybe it's not worth to
> > > invest too much into that barrier and just go for the potentially
> > > longer, but easier to implement?
> > > 
> > Right. I agree here. If the cache is not empty, OK, we just defer the
> > work, even we can use a big 21 seconds delay, after that we just "warn"
> > if it is still not empty and leave it as it is, i.e. emit a warning and
> > we are done.
> > 
> > Destroying the cache is not something that must happen right away. 
> 
> OK, I have to ask...
> 
> Suppose that the cache is created and destroyed by a module and
> init/cleanup time, respectively.  Suppose that this module is rmmod'ed
> then very quickly insmod'ed.
> 
> Do we need to fail the insmod if the kmem_cache has not yet been fully
> cleaned up?  If not, do we have two versions of the same kmem_cache in
> /proc during the overlap time?
> 
No fail :) If same cache is created several times, its s->refcount gets
increased, so, it does not create two entries in the "slabinfo". But i
agree that your point is good! We need to be carefully with removing and
simultaneous creating.

From the first glance, there is a refcounter and a global "slab_mutex"
which is used to protect a critical section. Destroying is almost fully
protected(as noted above, by a global mutex) with one exception, it is:

static void kmem_cache_release(struct kmem_cache *s)
{
	if (slab_state >= FULL) {
		sysfs_slab_unlink(s);
		sysfs_slab_release(s);
	} else {
		slab_kmem_cache_release(s);
	}
}

this one can race, IMO.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnKqPqlPD3Rl04DZ%40pc636.
