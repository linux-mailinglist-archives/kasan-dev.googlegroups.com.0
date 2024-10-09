Return-Path: <kasan-dev+bncBDZJXP7F6YLRBLXRTK4AMGQED3KY7BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C549972A5
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Oct 2024 19:09:05 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5c92ad674aesf289687a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Oct 2024 10:09:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728493744; cv=pass;
        d=google.com; s=arc-20240605;
        b=QYZr6nALggBIl2n1kVN8L18ZSdCQ9p8UY95tOqNmhY5CrD7JsGS/q3KYJTfy9pEgTH
         X5MCI6+GkTglMHRYfDGqtTZG3GGM71cHd+F/BidvDeOvbIhgTjpZgr+/Kb700hu34si/
         EHQGHWqVuirXn2nNee8cEsq+xL//EKZOBI6TeePPOUssaiIzfGJaoZLoa/nCELDN1oDV
         9id9CFRuiS4DixoXh0+0zw3l8xRWRn3wY4nUAUJg3fsiWFNxbd0EmQRPNkLVxew6rO+A
         gYVXQ8DH4B6t1SXhE/m8h/hRAgWM136TUbHE0udICUC1HA6p+/FqAq9R6w0Xw6iwCXX+
         T3aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:message-id
         :in-reply-to:subject:cc:to:from:date:sender:dkim-signature;
        bh=tkhFvsSzmF0DMJu9WVgxC0QuTthV0ik2J1EmYbSJrV4=;
        fh=5vARChcXBjsuKsLjsHy1x0dtJS9pxSgVti3yiTOiEZs=;
        b=XqYxLj59Qx+VBkzD9C+yTLoPaC9K+o/fpgd/C2nMtMJlKezWrEgsfr/zQ9zZ+tSbH6
         x3Urq90QzR5LwvjeBdl+UC6TKv4PnuF7wNJTSEbAMjeipkVxPk7hcmyFfyR13Qljlo35
         7F/DkrE11cunfebShNv6rmhM86QVQsPYzAD1pNhTIKulCa0dre5VOoWujKBNK4U+ftLv
         MTrsPQYAlayWt4964MDwuvduV8XGOGy9ykVCnxrPGgaj1JGnNyPxysn8N6/1HUYm6wog
         U2qA8Yjkay4wY7tinUrclddyZjxZfsaLwHVZTuhwxSgJQAJU6SaPKZPifQhklhtNH2Cx
         hV4g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=P2PqLt2R;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=julia.lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728493744; x=1729098544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:message-id:in-reply-to
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tkhFvsSzmF0DMJu9WVgxC0QuTthV0ik2J1EmYbSJrV4=;
        b=AX3T2Ynv0PhnmVlIO77dD9CO4c3a3uQlwha0DxjHj7t0LKERoA85xyI6SYscbX9+ux
         6lTIJHUhbPtn0OZk41ASUgLcBPyzO0rX9kmg7AODZSyAvZHkrVKGxV5gltvRq4saxUUw
         3iy4eaE5A/ibnCLVQCt8Nlf5qdfM6XmJHZGYp3h/+JtMpS6WuYStFz0Z6XTxwOxRzEoG
         AWHrWEPaZK4mbqUsn+Gtt2vAD1mTfS6DMzIA8qtvMU1nFKHGwLYCF//l3mETvWJ31nzJ
         rraqp/R6O2mJ8lcujdjWXD3ZzyV8WVyColpdJynLp31R6mmo6O7ZPcXQCDYHq1raWO8l
         kMUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728493744; x=1729098544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:message-id:in-reply-to:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tkhFvsSzmF0DMJu9WVgxC0QuTthV0ik2J1EmYbSJrV4=;
        b=e7TJp2l0gxHkhZZLX0R2GBl2EMV457mbzInkpJ5ZD2RCG1PzBSGkRWKjC/+eKs8LpW
         Xbs+eQ90uwzv+tdibZIPotqv5cfE0xdhBj6lUmiSGEQhQyFKP2Q+W9HrwvIujLtyUQEK
         v6FLN7qEKuSZkuZFh1MGli+ZLK1QHQAC3+kOijyaOFxqwGQ745Q3Qud83IbGxWgYfsZ+
         +Bi7I8ympEirOtTES9ZA20rEWxrwwh2cHkBe8qgNgRkTZqBfdRssfH6aXk3peH2G0Moe
         zw/RzNuq/8k1Lc+5/3BRLfzn+uT8QyV1kY5bNbdNzhOkFWbgaAJZfuHFRfZyrHIWzfmh
         Fhww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcCyFwvWvUCA1OcJgcaBuCcYwrCG3x2J9D9BfMXdYTLXx8ahvWeWnpuxfNbTmZSbzgWZMQfA==@lfdr.de
X-Gm-Message-State: AOJu0YyPN2+Ww48Oob5ksiKjHAeoBdd4VAgNZkCHOhf14pXhVB9FqClK
	dIjtOJ4Okb2ObZoAs1IJ5wEMcuCkKM+m3DOvbsqE10BWo00WrYzY
X-Google-Smtp-Source: AGHT+IE9VpPfDsIWo+oaZ+wHt5xYgNaWmYNPJ389F25lzrq/uAHWqmpG68J8laxlM1mNkNLrGomErA==
X-Received: by 2002:a05:6402:51ca:b0:5c8:9f3c:ea01 with SMTP id 4fb4d7f45d1cf-5c91d54d157mr2136904a12.2.1728493742905;
        Wed, 09 Oct 2024 10:09:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:518b:b0:5c8:acf3:1296 with SMTP id
 4fb4d7f45d1cf-5c933d3e2ddls26554a12.2.-pod-prod-03-eu; Wed, 09 Oct 2024
 10:09:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPPcJyEXahDU+QKFcbqzbV/E3nmfz+sBzwF7wYjXr90MIuGlln883i1ukgbLWJYbVKxZY03s8mwTI=@googlegroups.com
X-Received: by 2002:a05:6402:278b:b0:5c9:296f:8a95 with SMTP id 4fb4d7f45d1cf-5c9296f8e86mr1678938a12.14.1728493740360;
        Wed, 09 Oct 2024 10:09:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728493740; cv=none;
        d=google.com; s=arc-20240605;
        b=lLnM5VJsSeG6kxETODaGQV7De36s3E16Gg5nX69SRS7LBR8tqYgyL8hhkmUFMFliYB
         YJjfRBLa7jikhL0fymH2z0lNtwYTrdJ7kpqGwZbcxNo2cOBgGI925fcxvwzTxhWlPkP9
         ySElDUwCP2YEtHruSAVHqkel2miNdFzuDmcJbucZ995vu8StXSCXidKML1ps8S27djdD
         813HHpotmUNfdeYfxD4c+eQKxxbjWX+9RkpyhF14U77rILNadgskL6g9ohBGuI4e5gT6
         dxlewUrrswNOLfH6WNjYhCBa0l7kNELon81dqWeGAiVK1M8upvhn1oRqUN4udJgWyYAJ
         BRkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=Ei5tc3PfylWx64diDodItk/7guQ0rWtWfXKiWLfUtgQ=;
        fh=HXtrOteJFB6SnApnM5iSx4r3BCMQ8MTdEnE5dVnpHqg=;
        b=hNpku9WohBYd0eVvDW+YRJwVfdoZWMt3wm6zjXQvTCsKwEv0aQPHC7hPNooJEN+lFj
         CAmBcS3iPcXqEEaP8igBU9aVckvOV7inYo6SKpWg2R13OlI3ECvys71kUq67RG5bGr5b
         zVYfV03YWnrxvr7ODxLkHG8mo4PiekOGVstL/hZ8CAE3xSE4qCc28ayC5z+SD3goeiJM
         mmHoT9rKGf/S6126wOrw8rA+Fxz1GawmkkWMMMpkJXYBhbI7sg0PDc/OmAlHak/rPI0g
         W5Jd+yotmPL/I4e4uwW55/QYpUINRIeM6BbWkppodAvkyGRiuKBMCoFF3NHRiQ0Jr96/
         Qhjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@inria.fr header.s=dc header.b=P2PqLt2R;
       spf=pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) smtp.mailfrom=julia.lawall@inria.fr;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=inria.fr
Received: from mail3-relais-sop.national.inria.fr (mail3-relais-sop.national.inria.fr. [192.134.164.104])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c92a59ded7si17846a12.0.2024.10.09.10.09.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 09 Oct 2024 10:09:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted sender) client-ip=192.134.164.104;
X-IronPort-AV: E=Sophos;i="6.11,190,1725314400"; 
   d="scan'208";a="98667983"
Received: from dt-lawall.paris.inria.fr ([128.93.67.65])
  by mail3-relais-sop.national.inria.fr with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 09 Oct 2024 19:08:59 +0200
Date: Wed, 9 Oct 2024 19:08:58 +0200 (CEST)
From: Julia Lawall <julia.lawall@inria.fr>
To: "Paul E. McKenney" <paulmck@kernel.org>
cc: Vlastimil Babka <vbabka@suse.cz>, Uladzislau Rezki <urezki@gmail.com>, 
    "Jason A. Donenfeld" <Jason@zx2c4.com>, Jakub Kicinski <kuba@kernel.org>, 
    Julia Lawall <Julia.Lawall@inria.fr>, linux-block@vger.kernel.org, 
    kernel-janitors@vger.kernel.org, bridge@lists.linux.dev, 
    linux-trace-kernel@vger.kernel.org, 
    Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org, 
    linuxppc-dev@lists.ozlabs.org, 
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
In-Reply-To: <acf7a96b-facb-469b-8079-edbec7770780@paulmck-laptop>
Message-ID: <2ae9cb0-b16e-58a-693b-7cd927657946@inria.fr>
References: <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz> <ZnFT1Czb8oRb0SE7@pc636> <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop> <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz> <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz> <ZnVInAV8BXhgAjP_@pc636> <df0716ac-c995-498c-83ee-b8c25302f9ed@suse.cz> <b3d9710a-805e-4e37-8295-b5ec1133d15c@paulmck-laptop> <37807ec7-d521-4f01-bcfc-a32650d5de25@suse.cz>
 <acf7a96b-facb-469b-8079-edbec7770780@paulmck-laptop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Julia.Lawall@inria.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@inria.fr header.s=dc header.b=P2PqLt2R;       spf=pass (google.com:
 domain of julia.lawall@inria.fr designates 192.134.164.104 as permitted
 sender) smtp.mailfrom=julia.lawall@inria.fr;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=inria.fr
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

Hello,

I have rerun the semantic patch that removes call_rcu calls in cases where
the callback function just does some pointer arithmetic and calls
kmem_cache_free.  Let me know if this looks ok, and if so, I can make a
more formal patch submission.

This is against:

commit 75b607fab38d149f232f01eae5e6392b394dd659 (HEAD -> master, origin/master, origin/HEAD)
Merge: 5b7c893ed5ed e0ed52154e86
Author: Linus Torvalds <torvalds@linux-foundation.org>
Date:   Tue Oct 8 12:54:04 2024 -0700

    Merge tag 'sched_ext-for-6.12-rc2-fixes' of git://git.kernel.org/pub/scm/linux/kernel/git/tj/sched_ext


julia

diff -u -p a/arch/powerpc/kvm/book3s_mmu_hpte.c b/arch/powerpc/kvm/book3s_mmu_hpte.c
--- a/arch/powerpc/kvm/book3s_mmu_hpte.c
+++ b/arch/powerpc/kvm/book3s_mmu_hpte.c
@@ -92,12 +92,6 @@ void kvmppc_mmu_hpte_cache_map(struct kv
 	spin_unlock(&vcpu3s->mmu_lock);
 }

-static void free_pte_rcu(struct rcu_head *head)
-{
-	struct hpte_cache *pte = container_of(head, struct hpte_cache, rcu_head);
-	kmem_cache_free(hpte_cache, pte);
-}
-
 static void invalidate_pte(struct kvm_vcpu *vcpu, struct hpte_cache *pte)
 {
 	struct kvmppc_vcpu_book3s *vcpu3s = to_book3s(vcpu);
@@ -126,7 +120,7 @@ static void invalidate_pte(struct kvm_vc

 	spin_unlock(&vcpu3s->mmu_lock);

-	call_rcu(&pte->rcu_head, free_pte_rcu);
+	kfree_rcu(pte, rcu_head);
 }

 static void kvmppc_mmu_pte_flush_all(struct kvm_vcpu *vcpu)
diff -u -p a/block/blk-ioc.c b/block/blk-ioc.c
--- a/block/blk-ioc.c
+++ b/block/blk-ioc.c
@@ -32,13 +32,6 @@ static void get_io_context(struct io_con
 	atomic_long_inc(&ioc->refcount);
 }

-static void icq_free_icq_rcu(struct rcu_head *head)
-{
-	struct io_cq *icq = container_of(head, struct io_cq, __rcu_head);
-
-	kmem_cache_free(icq->__rcu_icq_cache, icq);
-}
-
 /*
  * Exit an icq. Called with ioc locked for blk-mq, and with both ioc
  * and queue locked for legacy.
@@ -102,7 +95,7 @@ static void ioc_destroy_icq(struct io_cq
 	 */
 	icq->__rcu_icq_cache = et->icq_cache;
 	icq->flags |= ICQ_DESTROYED;
-	call_rcu(&icq->__rcu_head, icq_free_icq_rcu);
+	kfree_rcu(icq, __rcu_head);
 }

 /*
diff -u -p a/drivers/net/wireguard/allowedips.c b/drivers/net/wireguard/allowedips.c
--- a/drivers/net/wireguard/allowedips.c
+++ b/drivers/net/wireguard/allowedips.c
@@ -48,11 +48,6 @@ static void push_rcu(struct allowedips_n
 	}
 }

-static void node_free_rcu(struct rcu_head *rcu)
-{
-	kmem_cache_free(node_cache, container_of(rcu, struct allowedips_node, rcu));
-}
-
 static void root_free_rcu(struct rcu_head *rcu)
 {
 	struct allowedips_node *node, *stack[MAX_ALLOWEDIPS_DEPTH] = {
@@ -330,13 +325,13 @@ void wg_allowedips_remove_by_peer(struct
 			child = rcu_dereference_protected(
 					parent->bit[!(node->parent_bit_packed & 1)],
 					lockdep_is_held(lock));
-		call_rcu(&node->rcu, node_free_rcu);
+		kfree_rcu(node, rcu);
 		if (!free_parent)
 			continue;
 		if (child)
 			child->parent_bit_packed = parent->parent_bit_packed;
 		*(struct allowedips_node **)(parent->parent_bit_packed & ~3UL) = child;
-		call_rcu(&parent->rcu, node_free_rcu);
+		kfree_rcu(parent, rcu);
 	}
 }

diff -u -p a/fs/ecryptfs/dentry.c b/fs/ecryptfs/dentry.c
--- a/fs/ecryptfs/dentry.c
+++ b/fs/ecryptfs/dentry.c
@@ -51,12 +51,6 @@ static int ecryptfs_d_revalidate(struct

 struct kmem_cache *ecryptfs_dentry_info_cache;

-static void ecryptfs_dentry_free_rcu(struct rcu_head *head)
-{
-	kmem_cache_free(ecryptfs_dentry_info_cache,
-		container_of(head, struct ecryptfs_dentry_info, rcu));
-}
-
 /**
  * ecryptfs_d_release
  * @dentry: The ecryptfs dentry
@@ -68,7 +62,7 @@ static void ecryptfs_d_release(struct de
 	struct ecryptfs_dentry_info *p = dentry->d_fsdata;
 	if (p) {
 		path_put(&p->lower_path);
-		call_rcu(&p->rcu, ecryptfs_dentry_free_rcu);
+		kfree_rcu(p, rcu);
 	}
 }

diff -u -p a/fs/nfsd/nfs4state.c b/fs/nfsd/nfs4state.c
--- a/fs/nfsd/nfs4state.c
+++ b/fs/nfsd/nfs4state.c
@@ -572,13 +572,6 @@ opaque_hashval(const void *ptr, int nbyt
 	return x;
 }

-static void nfsd4_free_file_rcu(struct rcu_head *rcu)
-{
-	struct nfs4_file *fp = container_of(rcu, struct nfs4_file, fi_rcu);
-
-	kmem_cache_free(file_slab, fp);
-}
-
 void
 put_nfs4_file(struct nfs4_file *fi)
 {
@@ -586,7 +579,7 @@ put_nfs4_file(struct nfs4_file *fi)
 		nfsd4_file_hash_remove(fi);
 		WARN_ON_ONCE(!list_empty(&fi->fi_clnt_odstate));
 		WARN_ON_ONCE(!list_empty(&fi->fi_delegations));
-		call_rcu(&fi->fi_rcu, nfsd4_free_file_rcu);
+		kfree_rcu(fi, fi_rcu);
 	}
 }

diff -u -p a/kernel/time/posix-timers.c b/kernel/time/posix-timers.c
--- a/kernel/time/posix-timers.c
+++ b/kernel/time/posix-timers.c
@@ -413,18 +413,11 @@ static struct k_itimer * alloc_posix_tim
 	return tmr;
 }

-static void k_itimer_rcu_free(struct rcu_head *head)
-{
-	struct k_itimer *tmr = container_of(head, struct k_itimer, rcu);
-
-	kmem_cache_free(posix_timers_cache, tmr);
-}
-
 static void posix_timer_free(struct k_itimer *tmr)
 {
 	put_pid(tmr->it_pid);
 	sigqueue_free(tmr->sigq);
-	call_rcu(&tmr->rcu, k_itimer_rcu_free);
+	kfree_rcu(tmr, rcu);
 }

 static void posix_timer_unhash_and_free(struct k_itimer *tmr)
diff -u -p a/net/batman-adv/translation-table.c b/net/batman-adv/translation-table.c
--- a/net/batman-adv/translation-table.c
+++ b/net/batman-adv/translation-table.c
@@ -408,19 +408,6 @@ static void batadv_tt_global_size_dec(st
 }

 /**
- * batadv_tt_orig_list_entry_free_rcu() - free the orig_entry
- * @rcu: rcu pointer of the orig_entry
- */
-static void batadv_tt_orig_list_entry_free_rcu(struct rcu_head *rcu)
-{
-	struct batadv_tt_orig_list_entry *orig_entry;
-
-	orig_entry = container_of(rcu, struct batadv_tt_orig_list_entry, rcu);
-
-	kmem_cache_free(batadv_tt_orig_cache, orig_entry);
-}
-
-/**
  * batadv_tt_orig_list_entry_release() - release tt orig entry from lists and
  *  queue for free after rcu grace period
  * @ref: kref pointer of the tt orig entry
@@ -433,7 +420,7 @@ static void batadv_tt_orig_list_entry_re
 				  refcount);

 	batadv_orig_node_put(orig_entry->orig_node);
-	call_rcu(&orig_entry->rcu, batadv_tt_orig_list_entry_free_rcu);
+	kfree_rcu(orig_entry, rcu);
 }

 /**
diff -u -p a/net/bridge/br_fdb.c b/net/bridge/br_fdb.c
--- a/net/bridge/br_fdb.c
+++ b/net/bridge/br_fdb.c
@@ -73,13 +73,6 @@ static inline int has_expired(const stru
 	       time_before_eq(fdb->updated + hold_time(br), jiffies);
 }

-static void fdb_rcu_free(struct rcu_head *head)
-{
-	struct net_bridge_fdb_entry *ent
-		= container_of(head, struct net_bridge_fdb_entry, rcu);
-	kmem_cache_free(br_fdb_cache, ent);
-}
-
 static int fdb_to_nud(const struct net_bridge *br,
 		      const struct net_bridge_fdb_entry *fdb)
 {
@@ -329,7 +322,7 @@ static void fdb_delete(struct net_bridge
 	if (test_and_clear_bit(BR_FDB_DYNAMIC_LEARNED, &f->flags))
 		atomic_dec(&br->fdb_n_learned);
 	fdb_notify(br, f, RTM_DELNEIGH, swdev_notify);
-	call_rcu(&f->rcu, fdb_rcu_free);
+	kfree_rcu(f, rcu);
 }

 /* Delete a local entry if no other port had the same address.
diff -u -p a/net/can/gw.c b/net/can/gw.c
--- a/net/can/gw.c
+++ b/net/can/gw.c
@@ -577,13 +577,6 @@ static inline void cgw_unregister_filter
 			  gwj->ccgw.filter.can_mask, can_can_gw_rcv, gwj);
 }

-static void cgw_job_free_rcu(struct rcu_head *rcu_head)
-{
-	struct cgw_job *gwj = container_of(rcu_head, struct cgw_job, rcu);
-
-	kmem_cache_free(cgw_cache, gwj);
-}
-
 static int cgw_notifier(struct notifier_block *nb,
 			unsigned long msg, void *ptr)
 {
@@ -603,7 +596,7 @@ static int cgw_notifier(struct notifier_
 			if (gwj->src.dev == dev || gwj->dst.dev == dev) {
 				hlist_del(&gwj->list);
 				cgw_unregister_filter(net, gwj);
-				call_rcu(&gwj->rcu, cgw_job_free_rcu);
+				kfree_rcu(gwj, rcu);
 			}
 		}
 	}
@@ -1168,7 +1161,7 @@ static void cgw_remove_all_jobs(struct n
 	hlist_for_each_entry_safe(gwj, nx, &net->can.cgw_list, list) {
 		hlist_del(&gwj->list);
 		cgw_unregister_filter(net, gwj);
-		call_rcu(&gwj->rcu, cgw_job_free_rcu);
+		kfree_rcu(gwj, rcu);
 	}
 }

@@ -1236,7 +1229,7 @@ static int cgw_remove_job(struct sk_buff

 		hlist_del(&gwj->list);
 		cgw_unregister_filter(net, gwj);
-		call_rcu(&gwj->rcu, cgw_job_free_rcu);
+		kfree_rcu(gwj, rcu);
 		err = 0;
 		break;
 	}
diff -u -p a/net/ipv4/fib_trie.c b/net/ipv4/fib_trie.c
--- a/net/ipv4/fib_trie.c
+++ b/net/ipv4/fib_trie.c
@@ -292,15 +292,9 @@ static const int inflate_threshold = 50;
 static const int halve_threshold_root = 15;
 static const int inflate_threshold_root = 30;

-static void __alias_free_mem(struct rcu_head *head)
-{
-	struct fib_alias *fa = container_of(head, struct fib_alias, rcu);
-	kmem_cache_free(fn_alias_kmem, fa);
-}
-
 static inline void alias_free_mem_rcu(struct fib_alias *fa)
 {
-	call_rcu(&fa->rcu, __alias_free_mem);
+	kfree_rcu(fa, rcu);
 }

 #define TNODE_VMALLOC_MAX \
diff -u -p a/net/ipv4/inetpeer.c b/net/ipv4/inetpeer.c
--- a/net/ipv4/inetpeer.c
+++ b/net/ipv4/inetpeer.c
@@ -128,11 +128,6 @@ static struct inet_peer *lookup(const st
 	return NULL;
 }

-static void inetpeer_free_rcu(struct rcu_head *head)
-{
-	kmem_cache_free(peer_cachep, container_of(head, struct inet_peer, rcu));
-}
-
 /* perform garbage collect on all items stacked during a lookup */
 static void inet_peer_gc(struct inet_peer_base *base,
 			 struct inet_peer *gc_stack[],
@@ -168,7 +163,7 @@ static void inet_peer_gc(struct inet_pee
 		if (p) {
 			rb_erase(&p->rb_node, &base->rb_root);
 			base->total--;
-			call_rcu(&p->rcu, inetpeer_free_rcu);
+			kfree_rcu(p, rcu);
 		}
 	}
 }
@@ -242,7 +237,7 @@ void inet_putpeer(struct inet_peer *p)
 	WRITE_ONCE(p->dtime, (__u32)jiffies);

 	if (refcount_dec_and_test(&p->refcnt))
-		call_rcu(&p->rcu, inetpeer_free_rcu);
+		kfree_rcu(p, rcu);
 }
 EXPORT_SYMBOL_GPL(inet_putpeer);

diff -u -p a/net/ipv6/ip6_fib.c b/net/ipv6/ip6_fib.c
--- a/net/ipv6/ip6_fib.c
+++ b/net/ipv6/ip6_fib.c
@@ -198,16 +198,9 @@ static void node_free_immediate(struct n
 	net->ipv6.rt6_stats->fib_nodes--;
 }

-static void node_free_rcu(struct rcu_head *head)
-{
-	struct fib6_node *fn = container_of(head, struct fib6_node, rcu);
-
-	kmem_cache_free(fib6_node_kmem, fn);
-}
-
 static void node_free(struct net *net, struct fib6_node *fn)
 {
-	call_rcu(&fn->rcu, node_free_rcu);
+	kfree_rcu(fn, rcu);
 	net->ipv6.rt6_stats->fib_nodes--;
 }

diff -u -p a/net/ipv6/xfrm6_tunnel.c b/net/ipv6/xfrm6_tunnel.c
--- a/net/ipv6/xfrm6_tunnel.c
+++ b/net/ipv6/xfrm6_tunnel.c
@@ -178,12 +178,6 @@ __be32 xfrm6_tunnel_alloc_spi(struct net
 }
 EXPORT_SYMBOL(xfrm6_tunnel_alloc_spi);

-static void x6spi_destroy_rcu(struct rcu_head *head)
-{
-	kmem_cache_free(xfrm6_tunnel_spi_kmem,
-			container_of(head, struct xfrm6_tunnel_spi, rcu_head));
-}
-
 static void xfrm6_tunnel_free_spi(struct net *net, xfrm_address_t *saddr)
 {
 	struct xfrm6_tunnel_net *xfrm6_tn = xfrm6_tunnel_pernet(net);
@@ -200,7 +194,7 @@ static void xfrm6_tunnel_free_spi(struct
 			if (refcount_dec_and_test(&x6spi->refcnt)) {
 				hlist_del_rcu(&x6spi->list_byaddr);
 				hlist_del_rcu(&x6spi->list_byspi);
-				call_rcu(&x6spi->rcu_head, x6spi_destroy_rcu);
+				kfree_rcu(x6spi, rcu_head);
 				break;
 			}
 		}
diff -u -p a/net/kcm/kcmsock.c b/net/kcm/kcmsock.c
--- a/net/kcm/kcmsock.c
+++ b/net/kcm/kcmsock.c
@@ -1584,14 +1584,6 @@ static int kcm_ioctl(struct socket *sock
 	return err;
 }

-static void free_mux(struct rcu_head *rcu)
-{
-	struct kcm_mux *mux = container_of(rcu,
-	    struct kcm_mux, rcu);
-
-	kmem_cache_free(kcm_muxp, mux);
-}
-
 static void release_mux(struct kcm_mux *mux)
 {
 	struct kcm_net *knet = mux->knet;
@@ -1619,7 +1611,7 @@ static void release_mux(struct kcm_mux *
 	knet->count--;
 	mutex_unlock(&knet->mutex);

-	call_rcu(&mux->rcu, free_mux);
+	kfree_rcu(mux, rcu);
 }

 static void kcm_done(struct kcm_sock *kcm)
diff -u -p a/net/netfilter/nf_conncount.c b/net/netfilter/nf_conncount.c
--- a/net/netfilter/nf_conncount.c
+++ b/net/netfilter/nf_conncount.c
@@ -275,14 +275,6 @@ bool nf_conncount_gc_list(struct net *ne
 }
 EXPORT_SYMBOL_GPL(nf_conncount_gc_list);

-static void __tree_nodes_free(struct rcu_head *h)
-{
-	struct nf_conncount_rb *rbconn;
-
-	rbconn = container_of(h, struct nf_conncount_rb, rcu_head);
-	kmem_cache_free(conncount_rb_cachep, rbconn);
-}
-
 /* caller must hold tree nf_conncount_locks[] lock */
 static void tree_nodes_free(struct rb_root *root,
 			    struct nf_conncount_rb *gc_nodes[],
@@ -295,7 +287,7 @@ static void tree_nodes_free(struct rb_ro
 		spin_lock(&rbconn->list.list_lock);
 		if (!rbconn->list.count) {
 			rb_erase(&rbconn->node, root);
-			call_rcu(&rbconn->rcu_head, __tree_nodes_free);
+			kfree_rcu(rbconn, rcu_head);
 		}
 		spin_unlock(&rbconn->list.list_lock);
 	}
diff -u -p a/net/netfilter/nf_conntrack_expect.c b/net/netfilter/nf_conntrack_expect.c
--- a/net/netfilter/nf_conntrack_expect.c
+++ b/net/netfilter/nf_conntrack_expect.c
@@ -367,18 +367,10 @@ void nf_ct_expect_init(struct nf_conntra
 }
 EXPORT_SYMBOL_GPL(nf_ct_expect_init);

-static void nf_ct_expect_free_rcu(struct rcu_head *head)
-{
-	struct nf_conntrack_expect *exp;
-
-	exp = container_of(head, struct nf_conntrack_expect, rcu);
-	kmem_cache_free(nf_ct_expect_cachep, exp);
-}
-
 void nf_ct_expect_put(struct nf_conntrack_expect *exp)
 {
 	if (refcount_dec_and_test(&exp->use))
-		call_rcu(&exp->rcu, nf_ct_expect_free_rcu);
+		kfree_rcu(exp, rcu);
 }
 EXPORT_SYMBOL_GPL(nf_ct_expect_put);

diff -u -p a/net/netfilter/xt_hashlimit.c b/net/netfilter/xt_hashlimit.c
--- a/net/netfilter/xt_hashlimit.c
+++ b/net/netfilter/xt_hashlimit.c
@@ -256,18 +256,11 @@ dsthash_alloc_init(struct xt_hashlimit_h
 	return ent;
 }

-static void dsthash_free_rcu(struct rcu_head *head)
-{
-	struct dsthash_ent *ent = container_of(head, struct dsthash_ent, rcu);
-
-	kmem_cache_free(hashlimit_cachep, ent);
-}
-
 static inline void
 dsthash_free(struct xt_hashlimit_htable *ht, struct dsthash_ent *ent)
 {
 	hlist_del_rcu(&ent->node);
-	call_rcu(&ent->rcu, dsthash_free_rcu);
+	kfree_rcu(ent, rcu);
 	ht->count--;
 }
 static void htable_gc(struct work_struct *work);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2ae9cb0-b16e-58a-693b-7cd927657946%40inria.fr.
