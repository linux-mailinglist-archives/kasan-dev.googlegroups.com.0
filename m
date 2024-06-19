Return-Path: <kasan-dev+bncBCS4VDMYRUNBB3MWZSZQMGQEUCUJJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5975790F469
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 18:46:39 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-37623ddfa1fsf99805ab.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Jun 2024 09:46:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718815598; cv=pass;
        d=google.com; s=arc-20160816;
        b=WJw4QIejvtNEcKSsmeKBUNTo71XOdzg4AS/JCkwPqamNpdXJ6HDZ+5Ke3zD9mvq6fU
         qY9Ng/mReG59jCYqY7Sz9xu9zD730S5Cc9DQgUY5jjtsGjYnD9Qe4062EYkSDjh6FLY2
         +ulbk29SxIGOsuzhMAo4rSeSShMnf+9+6aoLAB63ghFW+RjQf+EaNiZDZ23Po4Tffijb
         oacTGvTfdhc6odJ8frY837DZgEM3T/bkTMp2APf1Wl54hjrVGUDGs0snvCv/yIWEU5eh
         rwxdI2XvpJfybhgl+/ppiSh8z3NiW4mjqMfJJO56thXIiZNLTqtFyL3KDczY5vgd3tqn
         sgjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=IRc6v1rMziV3RauSIauEtewClGRjG5E1AuCIpce23k0=;
        fh=CjiZwqTjeoOnahLgzM0kbMOVUX273Nw3Y75rJK5cBqM=;
        b=0J/BmcDeZJqmWbvIuVX7er147uQPf5AqglyfAP/iPtvwocG77dUSEWEoIK0RNo2Klh
         nGiubnG7DV1I6k/fS2Yc/zg6O0eMqEhoniYGvQ2ncrKGRQb1R0ccHfcbO0KTjBSX4HZQ
         FqoFDnUD0yrv8RwX00GQRi1rcMCBZUzxrKDccBXy9u9aPRKFcXkmCRp/h6VFQHHuo2Ni
         OXf4c1eXQIJlth0hAR2QEuw902TFm0zMQhjK6w5h60ArVuJwQqeoTCDHcUfwSM4Gb+Dx
         9xrwnhTp68ozIh+nBtNKfK5I2li1Dq3ViyXolLmWuBbdtN8F3PJBimo7qwOWFaMHybYH
         noHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="U6v5z/sd";
       spf=pass (google.com: domain of srs0=wedf=nv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=wedF=NV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718815598; x=1719420398; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=IRc6v1rMziV3RauSIauEtewClGRjG5E1AuCIpce23k0=;
        b=SSP3USXhXypLKF/OI2AwkDYkJUTognzBunAAfHQ6KV2sENvGj39SrfHuKSMvhqeKyY
         uBAXav90yqqyOigihnOuT2PaNbMsYRO5oXx5rY5DTIewLVRvdRaDz552muhQGhAa0hG4
         4VYNOKvVwj6lrQdpwMj+Or5M2THe57s9CZv77WYCS/GiWVzANmhWxp16KMxSqLouAy88
         fcQPUbP+YUE6loq2UcJq/la0bslrZ7Em78p1FcMbGWrYldNmXZYz8Az+cRTHATKuolT/
         F8AZVkL26cWJ5MJxM7Torjdbty021T1BzLO+ElbAQ0S2tPAwbTvmmme5Zy3gwYdnWwPX
         tR9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718815598; x=1719420398;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=IRc6v1rMziV3RauSIauEtewClGRjG5E1AuCIpce23k0=;
        b=Hxp+dXPl/CXYUTN0Z11yoo7Q4XXk+ht28fIbco9Qxk9kjF+YqHzHtZMqgsAXMQCN93
         LGdTGSO/+zVYH16/4sAcuV4nwyg4axsyFTNRdPEUot7IDozhYXHfkTvmRZeYDCm/a4UI
         jmce02SlkR0CuZmCpvOsvCjjyaJaiIwP8I8sxfKVpKFMCuKMK26K/1OnK5XqFJ/oLAy4
         08C6BqM+yu8Yhyi9WKWZirBOwvqoumvd0cAnme+9fTHUovcNf1Uta3OE79YUruZdFxMs
         10zBifVpzlcJqvPsXDst9VwpCTf3bxXCc6PCv5HP4ovJ8G+tX91IdPIIBA2jvPqIzd05
         bTKw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWAi+Ji/0AGLwETZMa6sdGRpUSO4JQL3KN3Q/5z/SO4wNu55VgpybZcqOgFgyYrI8ctQXWKkOQhzAPgLy/ELH0OsvjB3X4GRA==
X-Gm-Message-State: AOJu0YzGNYP1V0YLAFenPkygxW1DGTeyNaXkAQnCGh17SCe1PUXjuY2L
	IpFhu7kgCMSnmF1eyflmImt5BlAczcYI7CSHh5+FFHQxG48PG5hC
X-Google-Smtp-Source: AGHT+IHrRZswN6pD9jlegvmRF96DzZRa0p3g6OV5mgCqyf7fbO1BwA2taY9fZhEVAu6bSWZaszOpJQ==
X-Received: by 2002:a05:6e02:12e6:b0:375:ee62:5917 with SMTP id e9e14a558f8ab-3761e7998dfmr4003515ab.6.1718815598092;
        Wed, 19 Jun 2024 09:46:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1feb:b0:375:af6a:e6ec with SMTP id
 e9e14a558f8ab-3762693b4f5ls508835ab.0.-pod-prod-05-us; Wed, 19 Jun 2024
 09:46:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWFAR4olZarWave6iS+St2umovlDjj4Q2p0cw6qgHMu3CNVk2iVWUzB3DWnikosxyNfPbb78wtvssCvpxYjRf1T0aXSgIUx5lXwAg==
X-Received: by 2002:a05:6602:3fc9:b0:7de:c720:ab1f with SMTP id ca18e2360f4ac-7f13ee82ac8mr367555839f.20.1718815597129;
        Wed, 19 Jun 2024 09:46:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718815597; cv=none;
        d=google.com; s=arc-20160816;
        b=KJEPUIKav28SBZG3TMSZeIRImxHLYYDkZtcPJZ6xmKC/mChKeZwcz/vU3kMcMbKX3J
         0+c8sqcEzvSdEkjE115DzARdypdTPOM7YhPWwQmRCWDvvEge6Lac7ByFhbJ7FEN/bdxM
         vhjQj7Xr9JW2Nf4AWI33l8c5Kv+pbA78NAU0u1wOmKEHR0OFimqaBIN2FCICXksQ5M76
         zpToS5L8DZ+seKB8bxDZ9tr4oyWRnBPnYfX3jR5+XJZMsPYBMmfEeAGhVQm3Rcbq1V+F
         3vCIIhKlECxM5LuVxzjbsMOKxxdSEQHygU95pPW9OvbuANK/lvyCX5FuAfcdJN6aFp96
         PFiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pw2BXTAQiJ3NTeflX4lSxzOg39efzfkAJJriAuCUE6w=;
        fh=b4rUQKQOOXPMgq1nkRYM+atCQEIVYCiymtW6U8DhPd0=;
        b=kA7ESkCvNr6LJG7COanTU9Hl4xJJTp5TyaYWydir8SamCx9+axGxJV6zzgdl5obIYU
         qN+JU53On4S48FPEq40iIvWcvgx3a9wymtk0QkI6DomhTOLEKBNcSXe2jTZ+QQq+Jw9B
         1ZLJke4qIZWz+fzmT/yjqT/BbDmardx/iU6qzzLPlUQlgeAS3mb5naYFzOajcha16VWK
         I8N+edB1wJNky9IqgQWOiTJhiwjw6OoDBel19qRWSG8EEBNgLd9zdNDpNwuL1Fbp4/3m
         m73O8DjwynT2Ap63Ta/hb6DfOQB9oKZnQtORkrZtqGgfPidEDkcasuJdxVPLYk0DY6l5
         xpKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="U6v5z/sd";
       spf=pass (google.com: domain of srs0=wedf=nv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=wedF=NV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4b9568bb7a7si632594173.2.2024.06.19.09.46.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 19 Jun 2024 09:46:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=wedf=nv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B54DE61E8E;
	Wed, 19 Jun 2024 16:46:36 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5E5A8C2BBFC;
	Wed, 19 Jun 2024 16:46:36 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id EC3CDCE09D8; Wed, 19 Jun 2024 09:46:35 -0700 (PDT)
Date: Wed, 19 Jun 2024 09:46:35 -0700
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
Message-ID: <04567347-c138-48fb-a5ab-44cc6a318549@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz>
 <ZnCDgdg1EH6V7w5d@pc636>
 <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
 <ZnFT1Czb8oRb0SE7@pc636>
 <5c8b2883-962f-431f-b2d3-3632755de3b0@paulmck-laptop>
 <9967fdfa-e649-456d-a0cb-b4c4bf7f9d68@suse.cz>
 <6dad6e9f-e0ca-4446-be9c-1be25b2536dd@paulmck-laptop>
 <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <4cba4a48-902b-4fb6-895c-c8e6b64e0d5f@suse.cz>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="U6v5z/sd";       spf=pass
 (google.com: domain of srs0=wedf=nv=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=wedF=NV=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

On Wed, Jun 19, 2024 at 11:28:13AM +0200, Vlastimil Babka wrote:
> On 6/18/24 7:53 PM, Paul E. McKenney wrote:
> > On Tue, Jun 18, 2024 at 07:21:42PM +0200, Vlastimil Babka wrote:
> >> On 6/18/24 6:48 PM, Paul E. McKenney wrote:
> >> > On Tue, Jun 18, 2024 at 11:31:00AM +0200, Uladzislau Rezki wrote:
> >> >> > On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
> >> >> > >> +
> >> >> > >> +	s = container_of(work, struct kmem_cache, async_destroy_work);
> >> >> > >> +
> >> >> > >> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> >> >> > > It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> >> >> > > wanted to avoid initially.
> >> >> > 
> >> >> > I wanted to avoid new API or flags for kfree_rcu() users and this would
> >> >> > be achieved. The barrier is used internally so I don't consider that an
> >> >> > API to avoid. How difficult is the implementation is another question,
> >> >> > depending on how the current batching works. Once (if) we have sheaves
> >> >> > proven to work and move kfree_rcu() fully into SLUB, the barrier might
> >> >> > also look different and hopefully easier. So maybe it's not worth to
> >> >> > invest too much into that barrier and just go for the potentially
> >> >> > longer, but easier to implement?
> >> >> > 
> >> >> Right. I agree here. If the cache is not empty, OK, we just defer the
> >> >> work, even we can use a big 21 seconds delay, after that we just "warn"
> >> >> if it is still not empty and leave it as it is, i.e. emit a warning and
> >> >> we are done.
> >> >> 
> >> >> Destroying the cache is not something that must happen right away. 
> >> > 
> >> > OK, I have to ask...
> >> > 
> >> > Suppose that the cache is created and destroyed by a module and
> >> > init/cleanup time, respectively.  Suppose that this module is rmmod'ed
> >> > then very quickly insmod'ed.
> >> > 
> >> > Do we need to fail the insmod if the kmem_cache has not yet been fully
> >> > cleaned up?
> >> 
> >> We don't have any such link between kmem_cache and module to detect that, so
> >> we would have to start tracking that. Probably not worth the trouble.
> > 
> > Fair enough!
> > 
> >> >  If not, do we have two versions of the same kmem_cache in
> >> > /proc during the overlap time?
> >> 
> >> Hm could happen in /proc/slabinfo but without being harmful other than
> >> perhaps confusing someone. We could filter out the caches being destroyed
> >> trivially.
> > 
> > Or mark them in /proc/slabinfo?  Yet another column, yay!!!  Or script
> > breakage from flagging the name somehow, for example, trailing "/"
> > character.
> 
> Yeah I've been resisting such changes to the layout and this wouldn't be
> worth it, apart from changing the name itself but not in a dangerous way
> like with "/" :)

;-) ;-) ;-)

> >> Sysfs and debugfs might be more problematic as I suppose directory names
> >> would clash. I'll have to check... might be even happening now when we do
> >> detect leaked objects and just leave the cache around... thanks for the
> >> question.
> > 
> > "It is a service that I provide."  ;-)
> > 
> > But yes, we might be living with it already and there might already
> > be ways people deal with it.
> 
> So it seems if the sysfs/debugfs directories already exist, they will
> silently not be created. Wonder if we have such cases today already because
> caches with same name exist. I think we do with the zsmalloc using 32 caches
> with same name that we discussed elsewhere just recently.
> 
> Also indeed if the cache has leaked objects and won't be thus destroyed,
> these directories indeed stay around, as well as the slabinfo entry, and can
> prevent new ones from being created (slabinfo lines with same name are not
> prevented).

New one on me!

> But it wouldn't be great to introduce this possibility to happen for the
> temporarily delayed removal due to kfree_rcu() and a module re-insert, since
> that's a legitimate case and not buggy state due to leaks.

Agreed.

> The debugfs directory we could remove immediately before handing over to the
> scheduled workfn, but if it turns out there was a leak and the workfn leaves
> the cache around, debugfs dir will be gone and we can't check the
> alloc_traces/free_traces files there (but we have the per-object info
> including the traces in the dmesg splat).
> 
> The sysfs directory is currently removed only with the whole cache being
> destryed due to sysfs/kobject lifetime model. I'd love to untangle it for
> other reasons too, but haven't investigated it yet. But again it might be
> useful for sysfs dir to stay around for inspection, as for the debugfs.
> 
> We could rename the sysfs/debugfs directories before queuing the work? Add
> some prefix like GOING_AWAY-$name. If leak is detected and cache stays
> forever, another rename to LEAKED-$name. (and same for the slabinfo). But
> multiple ones with same name might pile up, so try adding a counter then?
> Probably messy to implement, but perhaps the most robust in the end? The
> automatic counter could also solve the general case of people using same
> name for multiple caches.
> 
> Other ideas?

Move the going-away files/directories to some new directoriesy?  But you
would still need a counter or whatever.  I honestly cannot say what
would be best from the viewpoint of existing software scanning those
files and directories.

							Thanx, Paul

> Thanks,
> Vlastimil
> 
> > 
> > 							Thanx, Paul
> > 
> >> >> > > Since you do it asynchronous can we just repeat
> >> >> > > and wait until it a cache is furry freed?
> >> >> > 
> >> >> > The problem is we want to detect the cases when it's not fully freed
> >> >> > because there was an actual read. So at some point we'd need to stop the
> >> >> > repeats because we know there can no longer be any kfree_rcu()'s in
> >> >> > flight since the kmem_cache_destroy() was called.
> >> >> > 
> >> >> Agree. As noted above, we can go with 21 seconds(as an example) interval
> >> >> and just perform destroy(without repeating).
> >> >> 
> >> >> --
> >> >> Uladzislau Rezki
> >> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/04567347-c138-48fb-a5ab-44cc6a318549%40paulmck-laptop.
