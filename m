Return-Path: <kasan-dev+bncBDK7LR5URMGRB2X6ZKZQMGQE75UUQDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id C710F90E933
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 13:22:19 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-42153125d3esf47181735e9.2
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 04:22:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718796139; cv=pass;
        d=google.com; s=arc-20160816;
        b=JRhrbI7YiRAbtF8g4o6PZKPQ/x+YPQtmpuwKvLBDPUcrbZGvKIDqbqw6m2uIAEALNV
         8M+yWnY59SoH9QEVo7ATUaeB/LxlWAT6CxspzpOkzK4poPEq5uiqiCFAg7y+8l4WAP1V
         Bvh78M/yMYbFz/H8+J9f35oRXQCFAawKzUfDX3CbnDfphb0c6v6a0vV5MHNucnhn+p3Q
         PzOqIee4shan4qrfwmu2p9qqIFKvwJ6z6JXjVW9cjcoG+X6mxQzOq31w29xrxpKfW6Bp
         4APzQRhYtdws/L/SP4FR7yPjm7iyHg6iin0LCAhxONlhEWAW8DSfsxrSFQnHoQpV2B2f
         6nCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=yGZxRLKLKCIrEEAyPy0o9sH1yH78pzcqDnrx+WxkGiM=;
        fh=4/P48zAQd87vYz0qvABUmX332zkchRKebkLAigoK4s8=;
        b=TinU0Azmy8RPTyP8aDPx5/UW0RuN03ZLCEFh63waojmDLDIRygg4dHgRxp8HUM6/ie
         mWWBT4deWQ14kruywBf06U0LU3E5Wm4UFJLSeYRwA2WLb9QOmfPWKQdakd50PP/oZ1cp
         G4haJHnNjO2aL+V6c/GLDwa6sobrXwh/MaHPFyIHsBOWNF5JnERZZBoG75SqVDoUd0AG
         PcQUzcnPBcN2v8Mnv1toOJVxWc7O5uodNv6dpqi8MOBctuQesvFDqt45twRsJeqf2U4N
         at29NwhFF+7lETqQkW4TLsNVe3+UrUkFWxLdDnBuql04cIvHYP5Ls+eOrGU1bxNB0Jhj
         MrsQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DU3UjtaT;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718796139; x=1719400939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yGZxRLKLKCIrEEAyPy0o9sH1yH78pzcqDnrx+WxkGiM=;
        b=UhD5dqnsVlLrEeuuHPL5EfqO7pQfh2aqc3GgIiMzPJQYYrZ3g6b7ZWaVjuzyIWbetV
         YAeuqiC9GRY+48GMYuc5PUE2FZ56wTnsEch8lKB4cUdSnXKlAYJBx2gRxxIIrl9U7g2K
         uOr4B+rkYuNRljkgPoMSqkOLMfWSUmkhd4oEgFN6KrweGSCoZBgv8iB5TQAl0yn0PBwf
         jniVmfVgLQMftrtJhtUfHX/2smrZSsgTXAevJGI4X4gAmdcdKHK3J8I/6X0Eu0tEN+Ec
         WpWA6gwpSd0DpZkQb9GOWJfFBggrJMGDK6gFHs5aOvbfzNtNzK1+I7AbPf6mD2FZtkAG
         kD/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718796139; x=1719400939; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yGZxRLKLKCIrEEAyPy0o9sH1yH78pzcqDnrx+WxkGiM=;
        b=OjeJVm/+fpdG0FxpHLJpH1y0rDp90xNVexIjlszVJSAfETCouKmAYbd4sTkWXsh+Sk
         zK8yIxoX6M6JUUXeWnzHI2PlR6iBfg+IRR2tsXkiG/HtxCTXzQrc2oe+5RTZrAHWK/pN
         TTtpI0LY8NtDbIO3bG5dqzE3jYJlBTDIvzt7bBqI3mr19PDayKqv55QHDrksA2xrcwMw
         /1Y15aqHSZARoBeHBSYqB5n7IjvK4Lq1RJYWTbdUj5RTcP8wGmulHztgNB+heoEyC/dE
         Udor4g+ZzB8FrE/8IYWLgdtVnNUCvjrwKs0hO4kbX+yUZJpaHxVKDKh62xMnbjnK5nJd
         lqMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718796139; x=1719400939;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=yGZxRLKLKCIrEEAyPy0o9sH1yH78pzcqDnrx+WxkGiM=;
        b=BeIjGK0r4qTE94z47ESY8Hld6VOrKqKHe7+BR9cjoO2Kddlw1gZ4vcKb9PL3NBVX+t
         tNPcQ8GEI9JYbbj6uBwvoBWVegclC5+f5M7oRO/UweyMkHrQ+F1vyXnvUhn++cpGS/T/
         q9iV/dHtTLvsmZCTxkkWfJDhPWEJYyHzu2RoCNoYF30tqsW0W8qFb1ZrXyr9lCMJM7TF
         Gdk7V3SSmtCvd9KPxKhJPmkK1gnFrnCImyjzNsC3lH0asOLvLhQGUoEQwfHrSoKbVH3n
         uDhFnqlk6fX3l1PyuUw6xv1ltViG6jyE5C/fgiZMqSkc3rXElOJkJ4/8cLCSMBoRDyne
         JAqQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjQur/zWfrAuibDjjnmsW94J9LG+KcUs9QCUCIqV56CwJYOsP8mEKiYHhrn0+ZlAAUPhKQBiZpNS8PDw4CI8hKMzO4pEDTKA==
X-Gm-Message-State: AOJu0YxNGdayYFayZEgMjCAMcrmUOiXxVu9nuWiroO79NLohYiUNcdja
	4gtBRRX5Jbog1Uy1ormn92maSus49NJnrAD55QLcEQ9vcykn7jay
X-Google-Smtp-Source: AGHT+IGElHV1br8+WB8byWbaTFDRWFkMsAsTw3W8zHrsoRzl8L4zSIY9dyi7vrziwVj9kMNugDBEAg==
X-Received: by 2002:a05:600c:33a9:b0:41b:fc3a:f1ef with SMTP id 5b1f17b1804b1-4247529df1fmr15743095e9.33.1718796138901;
        Wed, 19 Jun 2024 04:22:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7708:0:b0:423:7d5:b53e with SMTP id 5b1f17b1804b1-42307d5b970ls20123745e9.0.-pod-prod-02-eu;
 Wed, 19 Jun 2024 04:22:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQH8N3EheQbqJ0OrLZrCNQRcaaSEJznCYW8mTeJ9ekllG6rzboatUfOZ3CnKjUquVIcHsCbJLLlXnEYiZRXNfE2qXQIJpjLj36hg==
X-Received: by 2002:a05:600c:4f45:b0:424:777d:dcc with SMTP id 5b1f17b1804b1-424777d1648mr9327375e9.0.1718796137062;
        Wed, 19 Jun 2024 04:22:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718796137; cv=none;
        d=google.com; s=arc-20160816;
        b=SNfMH0gV0H36PEUvd9YkgRi7m8FVhFI28Td2C4qxq2dM9ZbgX8VT5OO8o4NouuggTw
         ni2DECbv2LrpEJ1FNg+lFE5bEgTP+QB+3OYzm16cNZ757uM+ejJlbwZx6qpJiBoG3jX8
         YO1pPvhtxgUzy2ed4ytCGr0ICwroTSQvck7mCqXZMB33bzwGI6YgYW6A5nqlbcBXBzet
         pugvozEfBKKrq+d8C6Ar1T952vxkMLiI3g9jzt+E1yH4X3ssL8I1937BdWKJl2ecwb/8
         nyXCuE6DSfQDZ1e2zvh7LBpQJ/vHJE6dzJTXughhnyHxXm6UKr7SCkPjMRLHGbCJICmW
         D2tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=1We8+J1M8/iGwbEuKq9QLdgleuBIYYNVC3Jie6+7WKQ=;
        fh=zYC/3ma0xyUO+RBnhUgvmPYsw1HmEOVKDAUxv8Gug24=;
        b=ulXFVwzdBuoX6juPKYiubNGurCLJT6tHaqRxCHgP1KS9VuhPQoICt17sQHdOynwdq8
         a1nVei3b6/q41RDGfgssSQ4BXm7vSh/xl2EyFXCbVepvAbIXmkBmUI1+SnKfjIzNMvnK
         65gYJ1cXIn3fAMww+vdh48kWYqOFK7EttyTu0PRefC0TPvK5htgU0iGXJhZnmIeS2WJw
         SJv0IdF2Gb9Lvuf6aL3NLmH3ykPwgssbJPK2M4I52qucjHPXstNUXqKZTq5dGQmpxG8G
         jOUIfph8yd43lULvoh/sa0TDAu0YOqhj5zjAwusB71bJoTHrhcDOdsqZxkeU5j+dOW6Y
         Vjrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DU3UjtaT;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22f.google.com (mail-lj1-x22f.google.com. [2a00:1450:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42471e66007si2374295e9.1.2024.06.19.04.22.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Jun 2024 04:22:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22f as permitted sender) client-ip=2a00:1450:4864:20::22f;
Received: by mail-lj1-x22f.google.com with SMTP id 38308e7fff4ca-2ebeefb9a6eso68488501fa.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Jun 2024 04:22:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV2R1R2F9gasY4bws5qssFSgxCaEitWIGhxnDvIYPFrChE2cB6Re9oeVl62q33AXiPJi6S+hz0TgVu4jyGEBaxBVqr4JYwQTed4ng==
X-Received: by 2002:a2e:7818:0:b0:2ec:3bc4:3e36 with SMTP id 38308e7fff4ca-2ec3ceb6a56mr15076241fa.14.1718796136224;
        Wed, 19 Jun 2024 04:22:16 -0700 (PDT)
Received: from pc636 (host-90-233-216-238.mobileonline.telia.com. [90.233.216.238])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-2ec05c78126sm19577951fa.81.2024.06.19.04.22.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 04:22:15 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 19 Jun 2024 13:22:12 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
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
Message-ID: <ZnK_ZLlFM6MrdEah@pc636>
References: <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <ZnKqPqlPD3Rl04DZ@pc636>
 <c208e95d-9aa9-476f-9dee-0242a2d6a24f@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c208e95d-9aa9-476f-9dee-0242a2d6a24f@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DU3UjtaT;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::22f as
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

On Wed, Jun 19, 2024 at 11:56:44AM +0200, Vlastimil Babka wrote:
> On 6/19/24 11:51 AM, Uladzislau Rezki wrote:
> > On Tue, Jun 18, 2024 at 09:48:49AM -0700, Paul E. McKenney wrote:
> >> On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
> >> > > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> >> > > >> +
> >> > > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> >> > > >> +
> >> > > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> >> > > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> >> > > > wanted to avoid initially.
> >> > > 
> >> > > I wanted to avoid new API or flags for kfree_rcu() users and this would
> >> > > be achieved. The barrier is used internally so I don't consider that an
> >> > > API to avoid. How difficult is the implementation is another question,
> >> > > depending on how the current batching works. Once (if) we have sheaves
> >> > > proven to work and move kfree_rcu() fully into SLUB, the barrier might
> >> > > also look different and hopefully easier. So maybe it's not worth to
> >> > > invest too much into that barrier and just go for the potentially
> >> > > longer, but easier to implement?
> >> > > 
> >> > Right. I agree here. If the cache is not empty, OK, we just defer the
> >> > work, even we can use a big 21 seconds delay, after that we just "warn"
> >> > if it is still not empty and leave it as it is, i.e. emit a warning and
> >> > we are done.
> >> > 
> >> > Destroying the cache is not something that must happen right away. 
> >> 
> >> OK, I have to ask...
> >> 
> >> Suppose that the cache is created and destroyed by a module and
> >> init/cleanup time, respectively.  Suppose that this module is rmmod'ed
> >> then very quickly insmod'ed.
> >> 
> >> Do we need to fail the insmod if the kmem_cache has not yet been fully
> >> cleaned up?  If not, do we have two versions of the same kmem_cache in
> >> /proc during the overlap time?
> >> 
> > No fail :) If same cache is created several times, its s->refcount gets
> > increased, so, it does not create two entries in the "slabinfo". But i
> > agree that your point is good! We need to be carefully with removing and
> > simultaneous creating.
> 
> Note that this merging may be disabled or not happen due to various flags on
> the cache being incompatible with it. And I want to actually make sure it
> never happens for caches being already destroyed as that would lead to
> use-after-free (the workfn doesn't recheck the refcount in case a merge
> would happen during the grace period)
> 
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -150,9 +150,10 @@ int slab_unmergeable(struct kmem_cache *s)
>  #endif
> 
>         /*
> -        * We may have set a slab to be unmergeable during bootstrap.
> +        * We may have set a cache to be unmergeable during bootstrap.
> +        * 0 is for cache being destroyed asynchronously
>          */
> -       if (s->refcount < 0)
> +       if (s->refcount <= 0)
>                 return 1;
> 
>         return 0;
> 
OK, i see such flags, SLAB_NO_MERGE. Then i was wrong, it can create two
different slabs.

Thanks!

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnK_ZLlFM6MrdEah%40pc636.
