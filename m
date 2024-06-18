Return-Path: <kasan-dev+bncBDK7LR5URMGRBW5HYWZQMGQELLHSD7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B3B90C555
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:31:09 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2ebfe35b9fcsf38614531fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:31:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718703069; cv=pass;
        d=google.com; s=arc-20160816;
        b=RgYqf+vxnV2MzaTDE7kvZyM8DRRPJgVpWfN+CHBK5fQQ+785nOXcE6yvwJWYaUqVc4
         VhWQtUx/1yFCnPLbs7Gyv7pHUHWTl5HwupDvZ94jdFDvcBdw/5pIvEKyGLIKoTeN1sie
         Ussu5Yak+9CDEqUv5wKN4CMkQEuBoniqQ8GHGKq0Ljl4HMPTBFjtw2J33+/DzmhTEWwK
         nfFsPGb8KVsbDTI82ePSSQv0fX3ar8dIQqx1TGZkvY4YxcJDlFFzzpgCO8RNT9dIlUzk
         7c00SqYRiFFmiPfD/ph9CHzL9gLh2/wOozMlWdjq9PMGd3CXx85cPM2r6BYm/1fWJdQa
         oLGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=BsziDEMS7AC1IYN+OouPyiAD1jWI/pszyBmEA7KN1x0=;
        fh=q1OqnNz/iy6FgE9paHcG+bVoEuXjDUjqt3xpuwno0aI=;
        b=z/Ybo9JuHAaDeSlyEK0MfCQlaE/FZMk0Z4Er0o4WqVKl5303zdhO1IfFCrwHKr+Jgd
         AJSfmk0ikhKbJ5W/Wf/dencMu56gNMZPc/rMn37DJ+OW5K1Pwo+8hvpvN+DDckq3rf8p
         IvWtl8E41BvWNmpZ91NZE/gpHWQtRLLdPucF7NWz4LncRCBMm8r2wRN3PO4ogkkF6661
         pFa1BmMIKn8foYVUaSzo/sJe/Gm9Jt43AhOYbmc2Iu8vh/47MSRFpPsb45M2xwbE1EyE
         14pAY6EYLvY4vNrPN1Ht4ouRYZE00u7hryYR1+XsshgsO5W4WI4/DZdWZ1hhWLja86Gf
         oUYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IPukvzLO;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718703069; x=1719307869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BsziDEMS7AC1IYN+OouPyiAD1jWI/pszyBmEA7KN1x0=;
        b=uboMbwl+DNotrWI4QThcKrulYgGTD1wU0ToVC5jk8c+u01INiUC5l8IqNiO7QKqYh+
         D19enadNX6Ac/2fB5Cg/pugeEqXtiMZVhngNLEYw2YTQep/UEJ1Fz4qb1k39v2ogSD3i
         256rxVeMLcmbCiGRbDd6tAYXjFNwf5Ef1OhDQDoHERHTCCVWUCm+oMzMVQZtuepFvXwP
         B4lFKbnlFSIuD3bc3+FbN0+t6mkKnSewuT/x4A289afGjMpQM6j1yYbDHmIvAcPkZkGa
         D/eb4NYP+27X0FSLWVVyY8P+4kZTzUlj2kBgnqeoHd6Lrc/fTMXdb+knXKLfsN3TjKM5
         Cl5Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718703069; x=1719307869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=BsziDEMS7AC1IYN+OouPyiAD1jWI/pszyBmEA7KN1x0=;
        b=mzsBtDQtFo0M78CdeTOpHddMHyy+vsb9V2jgtZWbrxWrgI/0+ZVOIR4PTX4yNx8fru
         xuEPUscdgbh2QO5EhTJoCFJYKnqQr+OdaIBSh+l0jHoBLFvhOreoGlAxNqlZZPN3Wrxu
         zDcRq5oauiKXFsZEciIiUx7j8sXhoa2TXXQ2PVeCtEtZMTOMEe/0BZZHlvyedoyDP3Pw
         V8v5OtL7fRZhdwgdArNQ9MM3BC6AG8C/RnrF4LWeTOr6PYS4eUd28ENHNbAUgJY8po4J
         9fgRk/L2rzUDreRzoSoEI29/wQPdjeHzEo5jN4MmHpMlnBy1x/ZqG5OutIOQAuepLWMu
         7i2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718703069; x=1719307869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BsziDEMS7AC1IYN+OouPyiAD1jWI/pszyBmEA7KN1x0=;
        b=Hqckze38rBBMs8afRBPbXDF3c8QNAGCegpQ0/uee1vW8T8WCex2/I43q8g1M7idt8i
         l5fgf6Z/uSJ00eat08T4FFaj4F/ASdKFTYf/EGsjUAAVKB9xBOh/3toKY2ukMUzQJI5/
         aDVvUrmmmvZECZbsKtWwUl/LjDBJvVnZ7Xi4fU5it0Z71NDjfuDHJ793HTM8rNt8XZq5
         4Q9snMKB4OcMZFjLfQh9fZx4CaDZDKdRKP5xAviee424qEfQt7j55aFNWv3k9Ywhz4XX
         1mjA84Kbew+1siwdzTnBiGRj21daLZ8IvN/MeqtWAnYTVhcAx6AVZhp4NQ/FU2OKBWY0
         WPFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOZ9XpEVbtmZUKmUOFADrclgUPRhhSEPH/FEWmev55woBtf1zWA1jvRmTzH8JjNdkYdX0Fkv6Hqz2f0W3E2gjhUs9N2/gyxg==
X-Gm-Message-State: AOJu0YyqTB0c1phLIA19bfshP1E2ezEiVs+P/oOgnGs6+WUOZXLEAY5X
	/K9gkec0E+D3c8jvO7Vuy/o+ayEcVyzO1GfZnnyzEEA/1asRV25M
X-Google-Smtp-Source: AGHT+IGGSg3ghGhXufl6hsDvayC6tgDtRIeS9nNxhy6ScyVnBn68OUVb6ewm4O0QKn39nCnj9C+5qQ==
X-Received: by 2002:a2e:9d88:0:b0:2ec:2c82:2cb5 with SMTP id 38308e7fff4ca-2ec2c822d35mr32112471fa.23.1718703068125;
        Tue, 18 Jun 2024 02:31:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8846:0:b0:2eb:fe83:2b09 with SMTP id 38308e7fff4ca-2ec0294f438ls12783201fa.1.-pod-prod-04-eu;
 Tue, 18 Jun 2024 02:31:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWnDVc2wvM9hm5Mz9tUqALsT5um59J4+T9w1sqQVe+zFpN3+dvYfQFXG/b4hNymrl5TqAOvG+y5NswHd2v5+G1NHkN2zQUl88TwQ==
X-Received: by 2002:a2e:b545:0:b0:2ec:1708:4daf with SMTP id 38308e7fff4ca-2ec17084f80mr56004791fa.47.1718703065954;
        Tue, 18 Jun 2024 02:31:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718703065; cv=none;
        d=google.com; s=arc-20160816;
        b=BtWs36Gq1wlL9WbGpAe1Th6c4XcPmgmOZm5MuyKPJMHkhyozmQ5skswI0G1GHuKDuE
         OtEoAjygVOLICBBD3k2XQyxncpZOe6Xf8Qig7V5nqonxBbt37zTAcZALbYAih6zCTE/S
         i7YULisZt2zW+D9mWTQ8z9FmaC1iA9XdBq05x+rSc98m9O9i76DEGRnzg6QYJs+MI7ZK
         Mv/K/pHTS763G/rNo1HXBcgDrU1yTqmEmCT9MgItEco9XGthS1EPWZ9EWzwUhE0tRQmo
         t0rZQLF2/ALdqjSt+qkueR/c8hqi4DUH9S73PhkjFzflT6NJp+oLCP97zT21+nNkdOO5
         ZWzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=Gd0sb+wrja9GmMiLQT0DMWUWixEF5baH+EtRGLOjO0I=;
        fh=ITG6INhRTFp1DEU9Gv78Q2yTJbHsyNASS8eNKd2lJQk=;
        b=WNMknxieAwCCArMtQUIeZQeRo7J7w5XW1DPYXOOJkJkxtHDA90ZL2B8bFbj+7piSWM
         FPd03lDApqPNhDsKRaQ0mklSFS3T4d7osRR82bBuMmbSMh8ZWv1i3v+LHn46TtpUkrJ2
         rA9k2soCWBfH4ryQ/iZijDGnYoIy9G/dtZx9lEGQ8kz8sQi+9KXPb3yug2+7I46OB5RD
         Ufyg9pVu5gZysqvVl2sB69iXhGpjYSQIlmsQXeSZPFZvF96/eJTb04oXGYQ//GPOShAK
         4r/TXQsExriEbjrw6EiC5get+6dicshb34tAzT26fYgHoYldbU+pJkjV4hP7bni1VMnq
         Xjdw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=IPukvzLO;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x135.google.com (mail-lf1-x135.google.com. [2a00:1450:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42471e660dcsi414045e9.1.2024.06.18.02.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:31:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as permitted sender) client-ip=2a00:1450:4864:20::135;
Received: by mail-lf1-x135.google.com with SMTP id 2adb3069b0e04-52bc121fb1eso6131098e87.1
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 02:31:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUwHw617pY6m1spr8GjP7sFRFFWLxFdU84gZdr4LA+OTLEPPQVb4szfM56YhdEw5HoNF5fte+S8zrSkZzV9aqbGmYdcE7p8e1fkeg==
X-Received: by 2002:a19:9141:0:b0:52c:81d5:cf96 with SMTP id 2adb3069b0e04-52ca6e659demr6468892e87.28.1718703065080;
        Tue, 18 Jun 2024 02:31:05 -0700 (PDT)
Received: from pc636 (host-90-233-216-238.mobileonline.telia.com. [90.233.216.238])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-52ca2825b38sm1445362e87.24.2024.06.18.02.31.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Jun 2024 02:31:04 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 18 Jun 2024 11:31:00 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>, paulmck@kernel.org,
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
Message-ID: <ZnFT1Czb8oRb0SE7@pc636>
References: <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com>
 <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=IPukvzLO;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::135 as
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

> On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> >> +
> >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> >> +
> >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> > wanted to avoid initially.
> 
> I wanted to avoid new API or flags for kfree_rcu() users and this would
> be achieved. The barrier is used internally so I don't consider that an
> API to avoid. How difficult is the implementation is another question,
> depending on how the current batching works. Once (if) we have sheaves
> proven to work and move kfree_rcu() fully into SLUB, the barrier might
> also look different and hopefully easier. So maybe it's not worth to
> invest too much into that barrier and just go for the potentially
> longer, but easier to implement?
> 
Right. I agree here. If the cache is not empty, OK, we just defer the
work, even we can use a big 21 seconds delay, after that we just "warn"
if it is still not empty and leave it as it is, i.e. emit a warning and
we are done.

Destroying the cache is not something that must happen right away. 

> > Since you do it asynchronous can we just repeat
> > and wait until it a cache is furry freed?
> 
> The problem is we want to detect the cases when it's not fully freed
> because there was an actual read. So at some point we'd need to stop the
> repeats because we know there can no longer be any kfree_rcu()'s in
> flight since the kmem_cache_destroy() was called.
> 
Agree. As noted above, we can go with 21 seconds(as an example) interval
and just perform destroy(without repeating).

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnFT1Czb8oRb0SE7%40pc636.
