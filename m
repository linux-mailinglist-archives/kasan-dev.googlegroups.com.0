Return-Path: <kasan-dev+bncBCS4VDMYRUNBBCMTY6ZQMGQEPO7IKMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A8B290DB18
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 19:53:15 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-44102aa2494sf56671701cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 10:53:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718733194; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjt5l3ydhj5GewyFg/ILCotCYWAyUP4ApTHNHCX5c9rYqglJ3OHIQ+1MruW3C+vKc6
         yMDPOZR/dpsKTLwQvPiBqIsmpblq23qHQZMMLHRNPJdvIBHC3xUgoRT0grhxCH3hGhEB
         CpH/T9Z6eJWYV85q7POQ3CUnuGmJQRqH0LZeQNHICp3jRCrmjmwJL/1JBQglWI8euNON
         eQROaKiIYJpBOf3wvRTMFCjTIgCkobprY7Zh+WTEk0uVRWKRG4ZZVuW90Q5BHvGmfBYc
         sWW16fTk180+cMBqidwZInfUzqHRNH6mgLhIZ0oVV34CK2JVmtUndcp22vZVvWSAfYCf
         FVuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=lqxFdYrmYgEkecPE/cxYqiKa+rNBgmtTGbVn1K32YnI=;
        fh=5uiGENZagjv6q8VudlIHsaXPMJuj5z+c05j8kWy1L2k=;
        b=xuNxuaHvcsznAYH8ag6RGQekGCr96mbSBo0OXFJAMmCjNuiie4nFKjYrxI5wZ6ADWE
         4hWv3YnUnxl4Eu+euo/+Y0LnD9hp1tVvVubJDux8fCAyFRfeZBUQVdH+toEMXWPjJ3jb
         L+/FP5a3J1Lgq0Mx9gPA9ta/wKf4kh6whHGhVqbpbMAtTFR2uvwEtivIuC9d/vDytwnc
         7zxoEf8TtMi/XNjuNjTLhhJNGSjAHugUL07LER3CiWRC3LwVx+PjXUHQQ3yk7DpYxcSg
         gQZvYtM0SmfLaik+iu1sTcDnrA99WvYQ1nEYeHV5p8XxaBsHdWUlAJigg+nwjASOV0F8
         DXcQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QkOp7f3+;
       spf=pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718733194; x=1719337994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=lqxFdYrmYgEkecPE/cxYqiKa+rNBgmtTGbVn1K32YnI=;
        b=nGlOccpRRM1l/Lo1/3kkU6POlR4LXaJ9WQIWzh1qTf9VK0Ba4HUxVw3t+Y2myiQRZF
         r/7ds6B3sWG+C8stdFU3ejAgLbSszevJKIyZbdB+ub+tjH3rRfnGQeIDloUlv/xCwXtG
         AYq/lGByKraF/1KVJmT/E50b6Kc4dIy20wGnKeEe7oOy6865d4Mfm4tVZiAu23zvMIXY
         KV6sqHLBZcighRoEKyMn+DzgfoUi/c3aOAnOzeMpp2vvrnv+PHRJLIYQA2WZ2+cqQuET
         7OOXbvUdYTk0Vua/yvbTalBDvCIm/v3grQ9Rh1/0/iapTws/FqwyM+SZPd06F8hBfsUI
         8q9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718733194; x=1719337994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=lqxFdYrmYgEkecPE/cxYqiKa+rNBgmtTGbVn1K32YnI=;
        b=Gxsq0BvHypYPV09ehqTErdo2uQm78GwZv4qBFt0FYwHYCHBgfznFi0jghHXOyQPS+C
         AvqE65HqoEaIeofhoUm2SewE20XwHLSacuYje+ppYrfTQgtGRTtR1Vcc4DKDqDhFvuZt
         Qa6Q3byhhGYnBIW8DPRfvlBb75XVKxGSxIYb2NpmM4xUYH2nqizpZD/qhoWZUzEYp1wP
         psvu/drtWpAf96SwsWcwrsOtqYF45b416Eg/xukHAF6K4WxhvDCSTfQYmZeFJ5JmwF2O
         B77psCAEOeKrI2/u9j7UhuO6TAPpW+6JhuQDDoEOpmDO2zzffvIiddfQpiSo+XTUhoCD
         LNSQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWewKKncNhcs5hCZAD7QRro0rkC9fYBNi1XI9j0jEDC/HeR34f8jhAAlN3hPa0FxX9EiMWkdgjNk1RSgxp4Xa5UG+vzPdW6ow==
X-Gm-Message-State: AOJu0YzuQJKcCg9EIvdPKC3b6ZOJPTW4bCBS3aNAWIp91VlEfZEHAD9r
	AnwXfYXOoHsM8rFVD+AYmHR//jvT+nTFHBBRLBfBrz2L8NVrQVFy
X-Google-Smtp-Source: AGHT+IHhAGD8mHsIVVpjNXrEu5KzA1x0256/ckdvjL2sxpTFr0faubLJSRo9BSRX/NpM5dDJlpkpbg==
X-Received: by 2002:a0c:f011:0:b0:6b0:754e:9869 with SMTP id 6a1803df08f44-6b501e10047mr4204416d6.15.1718733194056;
        Tue, 18 Jun 2024 10:53:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2b8d:b0:6b0:9433:af46 with SMTP id
 6a1803df08f44-6b2a337f06cls83780366d6.0.-pod-prod-03-us; Tue, 18 Jun 2024
 10:53:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBynny6OwF0tC8FKcYq0PVL9P521WWB3TtaCH85EWF6maAKVBf8RyRbfsiBS0dY1k9SW1Oha20lNO8aqn/c37YwfSgU/RUn2YInA==
X-Received: by 2002:a05:6102:acb:b0:48c:1157:2f58 with SMTP id ada2fe7eead31-48f1304ec09mr426561137.17.1718733192964;
        Tue, 18 Jun 2024 10:53:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718733192; cv=none;
        d=google.com; s=arc-20160816;
        b=amvUpzd64AXYWUoJvQbaG9tw00fQZnhdOhPH7iiePi1rs+vxGXKcfEvbbfK0f0Lrhn
         IUcdhZA/2Y05XjBRVuZeoPql+WTVMk9pHFAZ9en1CY8lCJh1ev0XQrKV8r5qh13SgSVD
         1ystdJSnMVJANOGj6RgcMR8HZn0SinzgUBO6ICsM9GzbamogBmmquy8V6Bl/khM5PKWS
         8WVpFNaT9b57Z0DzG9aNxwoz/7uIxFTHqg6B/aDL7SagBod+LdFwQEDVA631VV+g0ggh
         uJSR7dUHQYV1jiVs+loLUWXKozcboeG1L+VXE4no4Ayd18iakI2sd99CRxB5klu5aQ0h
         s1tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5b78H8bsaFwQq5iHUhmJjsrVINPcu3pONpX/sWV3+MY=;
        fh=b4rUQKQOOXPMgq1nkRYM+atCQEIVYCiymtW6U8DhPd0=;
        b=H8dtOFersshoS3MN5YXDOcIkPQzkc4/dVwsjFUbmAP3vKbmYS8L+ndM8AEsbVqkUQ8
         UO1ETI8VN31NHiSniA+r94dmZ9WwpGdyydOq4yxbCuo7eYRDW8NSBDwoJOPJ0Z22nIW2
         8eoRqg83JnqtjK4cu8DqhrR7dAmluyUcRu1h55Gy2+KuKP87CA1lEqQtC3ioMrbTEaLV
         sTklD0RWKaL60I2j5Z3+IHKYY8V5RexgbJnsHjiH8PYq2HOBapXSYnopbKx3Xj4LQjbr
         OZNYWjxI51JHa/JecJbX35HPZ6Diaegfp//xVy+89Rb9BJOj3EybUe1rLuFI1Lt29nhT
         ozaw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QkOp7f3+;
       spf=pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-48da449e8c2si553428137.1.2024.06.18.10.53.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Jun 2024 10:53:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 5FC9F61A24;
	Tue, 18 Jun 2024 17:53:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 078A0C3277B;
	Tue, 18 Jun 2024 17:53:12 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id A0B31CE05B6; Tue, 18 Jun 2024 10:53:11 -0700 (PDT)
Date: Tue, 18 Jun 2024 10:53:11 -0700
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
Message-ID: <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com>
 <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QkOp7f3+;       spf=pass
 (google.com: domain of srs0=2wyl=nu=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=2WYL=NU=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Tue, Jun 18, 2024 at 07:21:42PM +0200, Vlastimil Babka wrote:
> On 6/18/24 6:48 PM, Paul E. McKenney wrote:
> > On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
> >> > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> >> > >> +
> >> > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> >> > >> +
> >> > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> >> > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> >> > > wanted to avoid initially.
> >> > 
> >> > I wanted to avoid new API or flags for kfree_rcu() users and this would
> >> > be achieved. The barrier is used internally so I don't consider that an
> >> > API to avoid. How difficult is the implementation is another question,
> >> > depending on how the current batching works. Once (if) we have sheaves
> >> > proven to work and move kfree_rcu() fully into SLUB, the barrier might
> >> > also look different and hopefully easier. So maybe it's not worth to
> >> > invest too much into that barrier and just go for the potentially
> >> > longer, but easier to implement?
> >> > 
> >> Right. I agree here. If the cache is not empty, OK, we just defer the
> >> work, even we can use a big 21 seconds delay, after that we just "warn"
> >> if it is still not empty and leave it as it is, i.e. emit a warning and
> >> we are done.
> >> 
> >> Destroying the cache is not something that must happen right away. 
> > 
> > OK, I have to ask...
> > 
> > Suppose that the cache is created and destroyed by a module and
> > init/cleanup time, respectively.  Suppose that this module is rmmod'ed
> > then very quickly insmod'ed.
> > 
> > Do we need to fail the insmod if the kmem_cache has not yet been fully
> > cleaned up?
> 
> We don't have any such link between kmem_cache and module to detect that, so
> we would have to start tracking that. Probably not worth the trouble.

Fair enough!

> >  If not, do we have two versions of the same kmem_cache in
> > /proc during the overlap time?
> 
> Hm could happen in /proc/slabinfo but without being harmful other than
> perhaps confusing someone. We could filter out the caches being destroyed
> trivially.

Or mark them in /proc/slabinfo?  Yet another column, yay!!!  Or script
breakage from flagging the name somehow, for example, trailing "/"
character.

> Sysfs and debugfs might be more problematic as I suppose directory names
> would clash. I'll have to check... might be even happening now when we do
> detect leaked objects and just leave the cache around... thanks for the
> question.

"It is a service that I provide."  ;-)

But yes, we might be living with it already and there might already
be ways people deal with it.

							Thanx, Paul

> >> > > Since you do it asynchronous can we just repeat
> >> > > and wait until it a cache is furry freed?
> >> > 
> >> > The problem is we want to detect the cases when it's not fully freed
> >> > because there was an actual read. So at some point we'd need to stop the
> >> > repeats because we know there can no longer be any kfree_rcu()'s in
> >> > flight since the kmem_cache_destroy() was called.
> >> > 
> >> Agree. As noted above, we can go with 21 seconds(as an example) interval
> >> and just perform destroy(without repeating).
> >> 
> >> --
> >> Uladzislau Rezki
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6dad6e9f-e0ca-4446-be9c-1be25b2536dd%40paulmck-laptop.
