Return-Path: <kasan-dev+bncBCS4VDMYRUNBBVG6TO4AMGQERV3JMRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0715D997728
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 23:02:14 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbd3754f4fsf4172736d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 14:02:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728507733; cv=pass;
        d=google.com; s=arc-20240605;
        b=erl8Umkbgb62toHOpNzEbzEZxyiIiZxv3Scc0VCRHG10f6fN4bRFe8k+fD0dfThDwK
         Vd5A6qvoAOg3PnQ50V7vjk/9AJWIWTPiFaa7UIlxjoQ8IiI1wEijm++/awVxePUna3ba
         yab/OkATf/kl0sD5rIxuXxZNNjh0gL+qDRCN30LqQ6QQnQhc+Afujhqk2S8NkZ0w4m8B
         9HV7wU91anDXJKq15wgsDIcAXYNMYLMCY2AlfHKzxVR+R7mq792BtVgYYBmy81GcSY77
         PAtSFQgKoOxQirWVymd5wLVwuKzCNUr0qzUhED9XugQzwun9YBFLpr55iA1iIRd4fIU6
         oXRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Pvyt09E+yRXGlxfrkgddHouiKKldxm13hHmN8Cm8hRg=;
        fh=Z86xilYhfB7hNQ9Ns8P3apksDi20NVVJB37gKDnyNaM=;
        b=CMmsRP+Njrp+04nPar8wBPU2nPmMU4HYGt0VqDpQpY9rafJ/swZ0O6c389ex05TuyQ
         pVQxpOEoE1rZoT7LSnRiZsaWXT5zOaFY8UVdTDfIGGsJmxkWfP2SfHjbay1sHrGer8RJ
         ac8IIGYUTZr97JsLOg6IzKq/TTMJpR5jU059IdGbeO0i2Wr617YEJLJGpsYvepaRVqiF
         75AUQQxX3Cl2Z6lGtYqyqmrYprg4d/jXxnMdH0CulQkqSCr9xhUS/YGh2ig8hH9Vy5Bl
         M8DriumFnkSSWkcWLKCUDXL2iB+117TxhCPswhyWUedRDpmQJkN2Ri2J39zU2y1U7NPu
         cAeA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Isq85fPT;
       spf=pass (google.com: domain of srs0=gwj2=rf=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Gwj2=RF=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728507733; x=1729112533; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Pvyt09E+yRXGlxfrkgddHouiKKldxm13hHmN8Cm8hRg=;
        b=MOIlgUjSU2tJs24xSncUb6ezKQI233JlUiz9imNAQgaC38kfiBDUX/c3FSar/xnNjQ
         Pm9kBGe6N0Nc7+1N9oYWy5l/l9brDHqnKGc1zbl5Ys4+4+bSTNu5NK+kY3RuA02mZiOa
         B+UMXzYhYGxADIt9AjsgEFBBvIEwAQvea0EUZUjYGQiUC3vSRqNTK/+mbUOWGvZJnFW6
         TsYZth07VfqqFLMgMDSPA8oxlQ64IVCoMk8KljZcUOAmhEiCPJ9K5OmfpZHpmfYrdEbG
         9J4bCkF1Gggt2h+qW414BZGhrYoLCa1+GdmlKalGEO/vSwfd9RT9OfLKckUK1H+kTZ9A
         SvLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728507733; x=1729112533;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Pvyt09E+yRXGlxfrkgddHouiKKldxm13hHmN8Cm8hRg=;
        b=nyL09pruKPQwWXKJAG8gOjeMexCR7Mz0miWhOpLSVrOm/w+hjNTa+oW7EPs9YdXll2
         umv9pzICmvImD1STH+ibb8YvCCVBiYebxzSEZpv86dPRL5SrpNuHP/eSd9QIe0fDcJdF
         qXoGoI505jvdnHCiAI0kvyLDh9Zt45aTdePPCgH93GzhhF1J9B9p8mXObxTueu78oh/z
         Xtp/pZkxLy8xhA258MoSim+n0cshWYaymWfB5nonJEdC2Xd4UpZ5Ex4Bepbak0PQs2qI
         z/j3bEOplipLDkgfnIvWFJpoYDz3+TVVGDGH69wsVkmBDcDZ2D6TddOX3WgCXzliEcIE
         D/Qg==
X-Forwarded-Encrypted: i=2; AJvYcCV3xGOKawZZ8/gMJq2iurHt+Ki+y5WpGlnGni27bRQYoeYSMwMkhW5LzivdVj1TZT22yEFDVA==@lfdr.de
X-Gm-Message-State: AOJu0YwI88SfkosepvNlDrSceyKrOvJ2oV6Cszi7hlPi8F0U8R18PZmq
	ZtBSGx5S/ncHcc3bpdg/b6Pql58j5CAw1tPE0zuC0Qf+hkDEHArW
X-Google-Smtp-Source: AGHT+IFIusPdZusnXeiP0gCjMC4DqqC7vJECHvqXAvyJTd9FzQ5ndu8RcS/cQrAIwU8epAS/PJ2whw==
X-Received: by 2002:a0c:b691:0:b0:6cb:c98c:65b0 with SMTP id 6a1803df08f44-6cbc98c6674mr38672286d6.5.1728507732470;
        Wed, 09 Oct 2024 14:02:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c8d:b0:6bd:735f:a702 with SMTP id
 6a1803df08f44-6cbe5492556ls2996276d6.0.-pod-prod-03-us; Wed, 09 Oct 2024
 14:02:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmdEtlQFQp0krLoqxp1gw1QFO6T334nPmVIZmCkI4ZC5yH5IzEDfAqJygb61CbbfCHREbuQX7IpSk=@googlegroups.com
X-Received: by 2002:a05:6214:3f90:b0:6c5:c4eb:792 with SMTP id 6a1803df08f44-6cbc92d7d0dmr53998406d6.9.1728507731669;
        Wed, 09 Oct 2024 14:02:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728507731; cv=none;
        d=google.com; s=arc-20240605;
        b=QXFdumTYkxuWP2N62XctZRNzW7A9ij1+g2hsHYNyJg2IiaPwimiM5CLKSsVtSK3IXa
         83ZgiTlVMVjk5hOU8hbFHX0KYdwjYcoWTHSk/pxO3b9aNlm95A/G+ENRmcMe6u5KZDFz
         8MXx5PXJJS4YsnfNZL27Ff+QCnAw7kXPHHgIBz/ZaQjNztifBueoA0+dbKuO5sOcTSJf
         nimjaz/20YqpeO6pyzQlbwiPvkRRwOwsKDfRBD0r0p12Pol6qkEYSr1riE9f/FfZKMvO
         xsiN5B0ZHxha6CdfpoYED2kPM328+T8ijOAjgRo64s9nlUCubKL7o59ncwgc08TlE4nd
         SQEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NzCNyKDuveOyRr0rsy0vzm8/44DQhtEZ8WOLz0U7oEQ=;
        fh=gzOT4CgYwtEBZDEJ0gflB81C1mX64iray4RsQK1UJUQ=;
        b=b1oBDXKQ/a3vvb+JOIr2+pcklxh+YJKz4F5ycMbo2In5KRwAvDPiyBPpe0lELFuwUN
         v3AW9SJgTiuVHzvw1UFKmh2S+TmTX3q5zYWI7rRUk55izIorxzcJB4233Ks2Kntu3DYH
         3m0HztHk8b4eEY9jAiX3ckt1ZBConB959CYBe3Qe8dz3m4ovAeKswWLT3ejGeVBlDV63
         BpQLYMlICa4vC04JoHTJ8qMIBor0z1krOwq7fBxC205qWD22H/AtSiGSPeq2rY8I88j6
         UD8eZfG7iXbAATQJD3RYvwi489h0AMNg5DF+Cq5jWlAgKOeX2D5uUAyQuU752wvvBeIf
         BIdA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Isq85fPT;
       spf=pass (google.com: domain of srs0=gwj2=rf=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Gwj2=RF=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cbe5c84609si165236d6.5.2024.10.09.14.02.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Oct 2024 14:02:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=gwj2=rf=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B75645C5675;
	Wed,  9 Oct 2024 21:02:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A5680C4CEC3;
	Wed,  9 Oct 2024 21:02:10 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 4ABEDCE090D; Wed,  9 Oct 2024 14:02:10 -0700 (PDT)
Date: Wed, 9 Oct 2024 14:02:10 -0700
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Julia Lawall <julia.lawall@inria.fr>
Cc: Vlastimil Babka <vbabka@suse.cz>, Uladzislau Rezki <urezki@gmail.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Jakub Kicinski <kuba@kernel.org>, linux-block@vger.kernel.org,
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
Message-ID: <07880643-7181-44b8-8e19-e111cb44a081@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
 <ZnVInAV8BXhgAjP_@pc636>
 <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz>
 <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop>
 <37807ec7-d521-4f01-bcfc-a32650d5de25@suse.cz>
 <acf7a96b-facb-469b-8079-edbec7770780@paulmck-laptop>
 <2ae9cb0-b16e-58a-693b-7cd927657946@inria.fr>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2ae9cb0-b16e-58a-693b-7cd927657946@inria.fr>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Isq85fPT;       spf=pass
 (google.com: domain of srs0=gwj2=rf=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=Gwj2=RF=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Wed, Oct 09, 2024 at 07:08:58PM +0200, Julia Lawall wrote:
> Hello,
> 
> I have rerun the semantic patch that removes call_rcu calls in cases where
> the callback function just does some pointer arithmetic and calls
> kmem_cache_free.  Let me know if this looks ok, and if so, I can make a
> more formal patch submission.

They look good to me, thank you!

							Thanx, Paul

> This is against:
> 
> commit 75b607fab38d149f232f01eae5e6392b394dd659 (HEAD -> master, origin/master, origin/HEAD)
> Merge: 5b7c893ed5ed e0ed52154e86
> Author: Linus Torvalds <torvalds@linux-foundation.org>
> Date:   Tue Oct 8 12:54:04 2024 -0700
> 
>     Merge tag 'sched_ext-for-6.12-rc2-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext
> 
> 
> julia
> 
> diff -u -p a/arch/powerpc/kvm/book3s_mmu_hpte.c b/arch/powerpc/kvm/book3s_mmu_hpte.c
> --- a/arch/powerpc/kvm/book3s_mmu_hpte.c
> +++ b/arch/powerpc/kvm/book3s_mmu_hpte.c
> @@ -92,12 +92,6 @@ void kvmppc_mmu_hpte_cache_map(struct kv
>  	spin_unlock(&vcpu3s->mmu_lock);
>  }
> 
> -static void free_pte_rcu(struct rcu_head *head)
> -{
> -	struct hpte_cache *pte = container_of(head, struct hpte_cache, rcu_head);
> -	kmem_cache_free(hpte_cache, pte);
> -}
> -
>  static void invalidate_pte(struct kvm_vcpu *vcpu, struct hpte_cache *pte)
>  {
>  	struct kvmppc_vcpu_book3s *vcpu3s = to_book3s(vcpu);
> @@ -126,7 +120,7 @@ static void invalidate_pte(struct kvm_vc
> 
>  	spin_unlock(&vcpu3s->mmu_lock);
> 
> -	call_rcu(&pte->rcu_head, free_pte_rcu);
> +	kfree_rcu(pte, rcu_head);
>  }
> 
>  static void kvmppc_mmu_pte_flush_all(struct kvm_vcpu *vcpu)
> diff -u -p a/block/blk-ioc.c b/block/blk-ioc.c
> --- a/block/blk-ioc.c
> +++ b/block/blk-ioc.c
> @@ -32,13 +32,6 @@ static void get_io_context(struct io_con
>  	atomic_long_inc(&ioc->refcount);
>  }
> 
> -static void icq_free_icq_rcu(struct rcu_head *head)
> -{
> -	struct io_cq *icq = container_of(head, struct io_cq, __rcu_head);
> -
> -	kmem_cache_free(icq->__rcu_icq_cache, icq);
> -}
> -
>  /*
>   * Exit an icq. Called with ioc locked for blk-mq, and with both ioc
>   * and queue locked for legacy.
> @@ -102,7 +95,7 @@ static void ioc_destroy_icq(struct io_cq
>  	 */
>  	icq->__rcu_icq_cache = et->icq_cache;
>  	icq->flags |= ICQ_DESTROYED;
> -	call_rcu(&icq->__rcu_head, icq_free_icq_rcu);
> +	kfree_rcu(icq, __rcu_head);
>  }
> 
>  /*
> diff -u -p a/drivers/net/wireguard/allowedips.c b/drivers/net/wireguard/allowedips.c
> --- a/drivers/net/wireguard/allowedips.c
> +++ b/drivers/net/wireguard/allowedips.c
> @@ -48,11 +48,6 @@ static void push_rcu(struct allowedips_n
>  	}
>  }
> 
> -static void node_free_rcu(struct rcu_head *rcu)
> -{
> -	kmem_cache_free(node_cache, container_of(rcu, struct allowedips_node, rcu));
> -}
> -
>  static void root_free_rcu(struct rcu_head *rcu)
>  {
>  	struct allowedips_node *node, *stack[MAX_ALLOWEDIPS_DEPTH] = {
> @@ -330,13 +325,13 @@ void wg_allowedips_remove_by_peer(struct
>  			child = rcu_dereference_protected(
>  					parent->bit[!(node->parent_bit_packed & 1)],
>  					lockdep_is_held(lock));
> -		call_rcu(&node->rcu, node_free_rcu);
> +		kfree_rcu(node, rcu);
>  		if (!free_parent)
>  			continue;
>  		if (child)
>  			child->parent_bit_packed = parent->parent_bit_packed;
>  		*(struct allowedips_node **)(parent->parent_bit_packed & ~3UL) = child;
> -		call_rcu(&parent->rcu, node_free_rcu);
> +		kfree_rcu(parent, rcu);
>  	}
>  }
> 
> diff -u -p a/fs/ecryptfs/dentry.c b/fs/ecryptfs/dentry.c
> --- a/fs/ecryptfs/dentry.c
> +++ b/fs/ecryptfs/dentry.c
> @@ -51,12 +51,6 @@ static int ecryptfs_d_revalidate(struct
> 
>  struct kmem_cache *ecryptfs_dentry_info_cache;
> 
> -static void ecryptfs_dentry_free_rcu(struct rcu_head *head)
> -{
> -	kmem_cache_free(ecryptfs_dentry_info_cache,
> -		container_of(head, struct ecryptfs_dentry_info, rcu));
> -}
> -
>  /**
>   * ecryptfs_d_release
>   * @dentry: The ecryptfs dentry
> @@ -68,7 +62,7 @@ static void ecryptfs_d_release(struct de
>  	struct ecryptfs_dentry_info *p = dentry->d_fsdata;
>  	if (p) {
>  		path_put(&p->lower_path);
> -		call_rcu(&p->rcu, ecryptfs_dentry_free_rcu);
> +		kfree_rcu(p, rcu);
>  	}
>  }
> 
> diff -u -p a/fs/nfsd/nfs4state.c b/fs/nfsd/nfs4state.c
> --- a/fs/nfsd/nfs4state.c
> +++ b/fs/nfsd/nfs4state.c
> @@ -572,13 +572,6 @@ opaque_hashval(const void *ptr, int nbyt
>  	return x;
>  }
> 
> -static void nfsd4_free_file_rcu(struct rcu_head *rcu)
> -{
> -	struct nfs4_file *fp = container_of(rcu, struct nfs4_file, fi_rcu);
> -
> -	kmem_cache_free(file_slab, fp);
> -}
> -
>  void
>  put_nfs4_file(struct nfs4_file *fi)
>  {
> @@ -586,7 +579,7 @@ put_nfs4_file(struct nfs4_file *fi)
>  		nfsd4_file_hash_remove(fi);
>  		WARN_ON_ONCE(!list_empty(&fi->fi_clnt_odstate));
>  		WARN_ON_ONCE(!list_empty(&fi->fi_delegations));
> -		call_rcu(&fi->fi_rcu, nfsd4_free_file_rcu);
> +		kfree_rcu(fi, fi_rcu);
>  	}
>  }
> 
> diff -u -p a/kernel/time/posix-timers.c b/kernel/time/posix-timers.c
> --- a/kernel/time/posix-timers.c
> +++ b/kernel/time/posix-timers.c
> @@ -413,18 +413,11 @@ static struct k_itimer * alloc_posix_tim
>  	return tmr;
>  }
> 
> -static void k_itimer_rcu_free(struct rcu_head *head)
> -{
> -	struct k_itimer *tmr = container_of(head, struct k_itimer, rcu);
> -
> -	kmem_cache_free(posix_timers_cache, tmr);
> -}
> -
>  static void posix_timer_free(struct k_itimer *tmr)
>  {
>  	put_pid(tmr->it_pid);
>  	sigqueue_free(tmr->sigq);
> -	call_rcu(&tmr->rcu, k_itimer_rcu_free);
> +	kfree_rcu(tmr, rcu);
>  }
> 
>  static void posix_timer_unhash_and_free(struct k_itimer *tmr)
> diff -u -p a/net/batman-adv/translation-table.c b/net/batman-adv/translation-table.c
> --- a/net/batman-adv/translation-table.c
> +++ b/net/batman-adv/translation-table.c
> @@ -408,19 +408,6 @@ static void batadv_tt_global_size_dec(st
>  }
> 
>  /**
> - * batadv_tt_orig_list_entry_free_rcu() - free the orig_entry
> - * @rcu: rcu pointer of the orig_entry
> - */
> -static void batadv_tt_orig_list_entry_free_rcu(struct rcu_head *rcu)
> -{
> -	struct batadv_tt_orig_list_entry *orig_entry;
> -
> -	orig_entry = container_of(rcu, struct batadv_tt_orig_list_entry, rcu);
> -
> -	kmem_cache_free(batadv_tt_orig_cache, orig_entry);
> -}
> -
> -/**
>   * batadv_tt_orig_list_entry_release() - release tt orig entry from lists and
>   *  queue for free after rcu grace period
>   * @ref: kref pointer of the tt orig entry
> @@ -433,7 +420,7 @@ static void batadv_tt_orig_list_entry_re
>  				  refcount);
> 
>  	batadv_orig_node_put(orig_entry->orig_node);
> -	call_rcu(&orig_entry->rcu, batadv_tt_orig_list_entry_free_rcu);
> +	kfree_rcu(orig_entry, rcu);
>  }
> 
>  /**
> diff -u -p a/net/bridge/br_fdb.c b/net/bridge/br_fdb.c
> --- a/net/bridge/br_fdb.c
> +++ b/net/bridge/br_fdb.c
> @@ -73,13 +73,6 @@ static inline int has_expired(const stru
>  	       time_before_eq(fdb->updated + hold_time(br), jiffies);
>  }
> 
> -static void fdb_rcu_free(struct rcu_head *head)
> -{
> -	struct net_bridge_fdb_entry *ent
> -		= container_of(head, struct net_bridge_fdb_entry, rcu);
> -	kmem_cache_free(br_fdb_cache, ent);
> -}
> -
>  static int fdb_to_nud(const struct net_bridge *br,
>  		      const struct net_bridge_fdb_entry *fdb)
>  {
> @@ -329,7 +322,7 @@ static void fdb_delete(struct net_bridge
>  	if (test_and_clear_bit(BR_FDB_DYNAMIC_LEARNED, &f->flags))
>  		atomic_dec(&br->fdb_n_learned);
>  	fdb_notify(br, f, RTM_DELNEIGH, swdev_notify);
> -	call_rcu(&f->rcu, fdb_rcu_free);
> +	kfree_rcu(f, rcu);
>  }
> 
>  /* Delete a local entry if no other port had the same address.
> diff -u -p a/net/can/gw.c b/net/can/gw.c
> --- a/net/can/gw.c
> +++ b/net/can/gw.c
> @@ -577,13 +577,6 @@ static inline void cgw_unregister_filter
>  			  gwj->ccgw.filter.can_mask, can_can_gw_rcv, gwj);
>  }
> 
> -static void cgw_job_free_rcu(struct rcu_head *rcu_head)
> -{
> -	struct cgw_job *gwj = container_of(rcu_head, struct cgw_job, rcu);
> -
> -	kmem_cache_free(cgw_cache, gwj);
> -}
> -
>  static int cgw_notifier(struct notifier_block *nb,
>  			unsigned long msg, void *ptr)
>  {
> @@ -603,7 +596,7 @@ static int cgw_notifier(struct notifier_
>  			if (gwj->src.dev == dev || gwj->dst.dev == dev) {
>  				hlist_del(&gwj->list);
>  				cgw_unregister_filter(net, gwj);
> -				call_rcu(&gwj->rcu, cgw_job_free_rcu);
> +				kfree_rcu(gwj, rcu);
>  			}
>  		}
>  	}
> @@ -1168,7 +1161,7 @@ static void cgw_remove_all_jobs(struct n
>  	hlist_for_each_entry_safe(gwj, nx, &net->can.cgw_list, list) {
>  		hlist_del(&gwj->list);
>  		cgw_unregister_filter(net, gwj);
> -		call_rcu(&gwj->rcu, cgw_job_free_rcu);
> +		kfree_rcu(gwj, rcu);
>  	}
>  }
> 
> @@ -1236,7 +1229,7 @@ static int cgw_remove_job(struct sk_buff
> 
>  		hlist_del(&gwj->list);
>  		cgw_unregister_filter(net, gwj);
> -		call_rcu(&gwj->rcu, cgw_job_free_rcu);
> +		kfree_rcu(gwj, rcu);
>  		err = 0;
>  		break;
>  	}
> diff -u -p a/net/ipv4/fib_trie.c b/net/ipv4/fib_trie.c
> --- a/net/ipv4/fib_trie.c
> +++ b/net/ipv4/fib_trie.c
> @@ -292,15 +292,9 @@ static const int inflate_threshold = 50;
>  static const int halve_threshold_root = 15;
>  static const int inflate_threshold_root = 30;
> 
> -static void __alias_free_mem(struct rcu_head *head)
> -{
> -	struct fib_alias *fa = container_of(head, struct fib_alias, rcu);
> -	kmem_cache_free(fn_alias_kmem, fa);
> -}
> -
>  static inline void alias_free_mem_rcu(struct fib_alias *fa)
>  {
> -	call_rcu(&fa->rcu, __alias_free_mem);
> +	kfree_rcu(fa, rcu);
>  }
> 
>  #define TNODE_VMALLOC_MAX \
> diff -u -p a/net/ipv4/inetpeer.c b/net/ipv4/inetpeer.c
> --- a/net/ipv4/inetpeer.c
> +++ b/net/ipv4/inetpeer.c
> @@ -128,11 +128,6 @@ static struct inet_peer *lookup(const st
>  	return NULL;
>  }
> 
> -static void inetpeer_free_rcu(struct rcu_head *head)
> -{
> -	kmem_cache_free(peer_cachep, container_of(head, struct inet_peer, rcu));
> -}
> -
>  /* perform garbage collect on all items stacked during a lookup */
>  static void inet_peer_gc(struct inet_peer_base *base,
>  			 struct inet_peer *gc_stack[],
> @@ -168,7 +163,7 @@ static void inet_peer_gc(struct inet_pee
>  		if (p) {
>  			rb_erase(&p->rb_node, &base->rb_root);
>  			base->total--;
> -			call_rcu(&p->rcu, inetpeer_free_rcu);
> +			kfree_rcu(p, rcu);
>  		}
>  	}
>  }
> @@ -242,7 +237,7 @@ void inet_putpeer(struct inet_peer *p)
>  	WRITE_ONCE(p->dtime, (__u32)jiffies);
> 
>  	if (refcount_dec_and_test(&p->refcnt))
> -		call_rcu(&p->rcu, inetpeer_free_rcu);
> +		kfree_rcu(p, rcu);
>  }
>  EXPORT_SYMBOL_GPL(inet_putpeer);
> 
> diff -u -p a/net/ipv6/ip6_fib.c b/net/ipv6/ip6_fib.c
> --- a/net/ipv6/ip6_fib.c
> +++ b/net/ipv6/ip6_fib.c
> @@ -198,16 +198,9 @@ static void node_free_immediate(struct n
>  	net->ipv6.rt6_stats->fib_nodes--;
>  }
> 
> -static void node_free_rcu(struct rcu_head *head)
> -{
> -	struct fib6_node *fn = container_of(head, struct fib6_node, rcu);
> -
> -	kmem_cache_free(fib6_node_kmem, fn);
> -}
> -
>  static void node_free(struct net *net, struct fib6_node *fn)
>  {
> -	call_rcu(&fn->rcu, node_free_rcu);
> +	kfree_rcu(fn, rcu);
>  	net->ipv6.rt6_stats->fib_nodes--;
>  }
> 
> diff -u -p a/net/ipv6/xfrm6_tunnel.c b/net/ipv6/xfrm6_tunnel.c
> --- a/net/ipv6/xfrm6_tunnel.c
> +++ b/net/ipv6/xfrm6_tunnel.c
> @@ -178,12 +178,6 @@ __be32 xfrm6_tunnel_alloc_spi(struct net
>  }
>  EXPORT_SYMBOL(xfrm6_tunnel_alloc_spi);
> 
> -static void x6spi_destroy_rcu(struct rcu_head *head)
> -{
> -	kmem_cache_free(xfrm6_tunnel_spi_kmem,
> -			container_of(head, struct xfrm6_tunnel_spi, rcu_head));
> -}
> -
>  static void xfrm6_tunnel_free_spi(struct net *net, xfrm_address_t *saddr)
>  {
>  	struct xfrm6_tunnel_net *xfrm6_tn = xfrm6_tunnel_pernet(net);
> @@ -200,7 +194,7 @@ static void xfrm6_tunnel_free_spi(struct
>  			if (refcount_dec_and_test(&x6spi->refcnt)) {
>  				hlist_del_rcu(&x6spi->list_byaddr);
>  				hlist_del_rcu(&x6spi->list_byspi);
> -				call_rcu(&x6spi->rcu_head, x6spi_destroy_rcu);
> +				kfree_rcu(x6spi, rcu_head);
>  				break;
>  			}
>  		}
> diff -u -p a/net/kcm/kcmsock.c b/net/kcm/kcmsock.c
> --- a/net/kcm/kcmsock.c
> +++ b/net/kcm/kcmsock.c
> @@ -1584,14 +1584,6 @@ static int kcm_ioctl(struct socket *sock
>  	return err;
>  }
> 
> -static void free_mux(struct rcu_head *rcu)
> -{
> -	struct kcm_mux *mux = container_of(rcu,
> -	    struct kcm_mux, rcu);
> -
> -	kmem_cache_free(kcm_muxp, mux);
> -}
> -
>  static void release_mux(struct kcm_mux *mux)
>  {
>  	struct kcm_net *knet = mux->knet;
> @@ -1619,7 +1611,7 @@ static void release_mux(struct kcm_mux *
>  	knet->count--;
>  	mutex_unlock(&knet->mutex);
> 
> -	call_rcu(&mux->rcu, free_mux);
> +	kfree_rcu(mux, rcu);
>  }
> 
>  static void kcm_done(struct kcm_sock *kcm)
> diff -u -p a/net/netfilter/nf_conncount.c b/net/netfilter/nf_conncount.c
> --- a/net/netfilter/nf_conncount.c
> +++ b/net/netfilter/nf_conncount.c
> @@ -275,14 +275,6 @@ bool nf_conncount_gc_list(struct net *ne
>  }
>  EXPORT_SYMBOL_GPL(nf_conncount_gc_list);
> 
> -static void __tree_nodes_free(struct rcu_head *h)
> -{
> -	struct nf_conncount_rb *rbconn;
> -
> -	rbconn = container_of(h, struct nf_conncount_rb, rcu_head);
> -	kmem_cache_free(conncount_rb_cachep, rbconn);
> -}
> -
>  /* caller must hold tree nf_conncount_locks[] lock */
>  static void tree_nodes_free(struct rb_root *root,
>  			    struct nf_conncount_rb *gc_nodes[],
> @@ -295,7 +287,7 @@ static void tree_nodes_free(struct rb_ro
>  		spin_lock(&rbconn->list.list_lock);
>  		if (!rbconn->list.count) {
>  			rb_erase(&rbconn->node, root);
> -			call_rcu(&rbconn->rcu_head, __tree_nodes_free);
> +			kfree_rcu(rbconn, rcu_head);
>  		}
>  		spin_unlock(&rbconn->list.list_lock);
>  	}
> diff -u -p a/net/netfilter/nf_conntrack_expect.c b/net/netfilter/nf_conntrack_expect.c
> --- a/net/netfilter/nf_conntrack_expect.c
> +++ b/net/netfilter/nf_conntrack_expect.c
> @@ -367,18 +367,10 @@ void nf_ct_expect_init(struct nf_conntra
>  }
>  EXPORT_SYMBOL_GPL(nf_ct_expect_init);
> 
> -static void nf_ct_expect_free_rcu(struct rcu_head *head)
> -{
> -	struct nf_conntrack_expect *exp;
> -
> -	exp = container_of(head, struct nf_conntrack_expect, rcu);
> -	kmem_cache_free(nf_ct_expect_cachep, exp);
> -}
> -
>  void nf_ct_expect_put(struct nf_conntrack_expect *exp)
>  {
>  	if (refcount_dec_and_test(&exp->use))
> -		call_rcu(&exp->rcu, nf_ct_expect_free_rcu);
> +		kfree_rcu(exp, rcu);
>  }
>  EXPORT_SYMBOL_GPL(nf_ct_expect_put);
> 
> diff -u -p a/net/netfilter/xt_hashlimit.c b/net/netfilter/xt_hashlimit.c
> --- a/net/netfilter/xt_hashlimit.c
> +++ b/net/netfilter/xt_hashlimit.c
> @@ -256,18 +256,11 @@ dsthash_alloc_init(struct xt_hashlimit_h
>  	return ent;
>  }
> 
> -static void dsthash_free_rcu(struct rcu_head *head)
> -{
> -	struct dsthash_ent *ent = container_of(head, struct dsthash_ent, rcu);
> -
> -	kmem_cache_free(hashlimit_cachep, ent);
> -}
> -
>  static inline void
>  dsthash_free(struct xt_hashlimit_htable *ht, struct dsthash_ent *ent)
>  {
>  	hlist_del_rcu(&ent->node);
> -	call_rcu(&ent->rcu, dsthash_free_rcu);
> +	kfree_rcu(ent, rcu);
>  	ht->count--;
>  }
>  static void htable_gc(struct work_struct *work);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/07880643-7181-44b8-8e19-e111cb44a081%40paulmck-laptop.
