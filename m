Return-Path: <kasan-dev+bncBDK7LR5URMGRBIMR2WZQMGQEBS7Y2YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 3940591209D
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 11:32:19 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-52cdb097139sf99080e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 02:32:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718962338; cv=pass;
        d=google.com; s=arc-20160816;
        b=iQEZCR6Op+j3jRjwIm4GRhlSlEwN7q9+h3onrKHkp0Wo/+SDBT6MPOJO06YDVGHhGr
         DMT6gUkCM81oyKkdW/hVE7ahiMDiZE/KKpRx+APbBN9fMwwvXRTcdeYdgqsz5QaKrws1
         MaSuwUVB0dmzErX1cbQWg2skadz1fjqWcUwTo0Mztnw4ivvBb9y/Z7lvlmnE8hClfn30
         0Q3M17lohtOYYONPKLpeTIvd2AzypGmhBiHVYbtETHOO+QbFVyEAyrcAlUxxYXsB6yuQ
         EaQz0jqy9XrmqnliPLvlXPokA4MwcPTdWrIC45/0JPNwxc000K/ryXoAjVPY0orTtpWq
         /uAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=zF1Vwx6e9vinElPni2oWMCdQK0stem9IUK/FgqWcJvw=;
        fh=mTWISll+iCHr00EEBt6G1hUrNEZS7W9K6w/vdNH5H68=;
        b=1BahyJF+Ii77FVMDHqfF4x34jXT5INf5aHmEvDPFTInlSONERU30b9p9pr4PPs8Cg1
         t7xDzirCw0JyUdzllP0LGJTGskYbiiBFunMwSOcQyR/fCRdlkUE4oH2rqZSHOAtylr4l
         qYcaNLWOvIWjRf9uPbZFpHcPbxMEA8vFtSIzAh7QmOLx0AaqyDMnA3cvBSaB8g/4GzOM
         P9CTUcG9Wq+15C45R0Ge9i5r71XNCLy8ciIB2O8m+e1QPiwBGKgif3/1Tsgzz76kbqU9
         fjSknH2hfZbcGDiMOrteuOnk5rpQ6ySMDg2XE/PaUy+/wDiogJY9LZM/AXBq/2SMQ/SI
         KLJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="m39/fAGT";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718962338; x=1719567138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zF1Vwx6e9vinElPni2oWMCdQK0stem9IUK/FgqWcJvw=;
        b=nF6GII7VlDlUxQHbaaHWZOeVcA87GEmxPy9T6xAt6pE2+aFggcPrXyj0ikF9uSuSKj
         mM7FVciz8erESuVaaMvFBBJgDSnvIE41gM3RvvFDiVToZ8VMvH/V0rL8LQBBlaS/5xwH
         0tMUw5MWWqmKPm+7y1reOVc9M0mwQ5BLT4pKOpJAdVgG090DYNxfLIymPHnkRPK/YDtr
         wnwXnBVRRe3jdlGTTPHemz5ScGM9qgUXLVvM7Uy4x5g1ZQFSGG+3fA0sc8pI6BPqzjXh
         r/hmHpAAmj8P9SMD4V409nd6PEJfW28zcz/swbdiant/7gUPq+PeVBZB6Qnvi6gnIU7i
         1zvQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1718962338; x=1719567138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=zF1Vwx6e9vinElPni2oWMCdQK0stem9IUK/FgqWcJvw=;
        b=BxzKowlkp9iMyDe/iJGIpVkiEYNrQsLrQ1LOk267216MDeFAcYJyTw+FxhMkRIEPAt
         886Z2cF21kVu506nhuvx7GIleONF5CIqvd2dmNyGr7o//gBKLLqypRfaRqqax1xivwkH
         ceTn45q7RBov06RbbsGpsWMca9GcDRC3cTmKZEa9Gr1/wwZR9nSqwzx5sj2mu36bp1HA
         bWIex7fYIzuya1BKbKXEpNLBiiGwLJA+25cKu+dL8xTnh9HmKe9Lyzfw2X5t3Z2pV4AB
         kkDxu9JTLryanaJ/my+q7oRy3Qh6g686O3NOhr8JruZdBz/lKFFFoqWLQ5ti0fuXcjE3
         jXhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718962338; x=1719567138;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zF1Vwx6e9vinElPni2oWMCdQK0stem9IUK/FgqWcJvw=;
        b=oxTeORlCdNr7uCqmNuz8RZjOrlUbZqjOxr3NGoMEzDK+r37kpuobi8YeG8KHnFszs+
         wnyy/PKOcaO34hsQJYM87CzLSyXCFf+0avZk1iLuI9VcP/pDitZoahKs2uNu+OoP/P0/
         SR5IBCD/3y9BVjRim404Rv0vMGX6Rroxdr/K9UPOhhA3hkbW5fweWtdU3umwbN89IUpV
         kwTJ9o1diQa+vZDNlXNM6eo2fACc4hR2xLVfNNAuR+tvT0AS7gyVT13SC7QuXy9u8qLq
         AlsRkHxMoryL+U3jjAc4h3BrthxchimfaNju0QcMI5CN0aRAH5qeSw3+G9+nqxLQRrCB
         W1Zg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXy/Cu6x+ov6XuOYvu7b5tIU0jkFhIK0zf1tMOpKVQLAwKN4Xnj746XwCM50isqScF6LUdw2eew8Cm/72HoGxtt4v/szUahBg==
X-Gm-Message-State: AOJu0YyTAnDT3FIhCX4mVYV5SthZsXjTHcDsNS/d17cCONrkUG2ak+li
	cDN/nWOmhsCEUQm6BHUsFBLbThE5OdNFYPXWNUxkxnT2GPcNdxK2
X-Google-Smtp-Source: AGHT+IHOfDuo72PyPZ1io/QL/xxaVAMTGYXioh786siCFeI6enZ3f++htYKJKQDSE0fZU79P12QrQw==
X-Received: by 2002:a05:6512:124a:b0:52c:ab21:7c05 with SMTP id 2adb3069b0e04-52ccaa599b7mr7332856e87.67.1718962337898;
        Fri, 21 Jun 2024 02:32:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:58e7:0:b0:52c:c928:37f1 with SMTP id 2adb3069b0e04-52ccf033376ls645432e87.0.-pod-prod-05-eu;
 Fri, 21 Jun 2024 02:32:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWZQmn2UWYOP4NLOtR/JQrXVMd/fQSSlv/JJ1mFGEkgpVlubPwrtMXP4ucAj3oFcTqiV/7rrxZmNhaRjHOErVRN0oZZ3yuvRoLvQ==
X-Received: by 2002:ac2:5466:0:b0:52c:8075:4f3 with SMTP id 2adb3069b0e04-52ccaa36996mr5583617e87.36.1718962335592;
        Fri, 21 Jun 2024 02:32:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718962335; cv=none;
        d=google.com; s=arc-20160816;
        b=wmxgZrOSKIrmRCNMP7EQJ0yhbrlKh4MFl/k5Qt6t3+fyQ+JjqLLAXYrr4ZWiVAObxI
         vnVvdzMoB9QM7wpMjpf8mnyfkrKzNBZbsiGMdJzZK5EQH6e57QHPvbfPY4NofThZUwGn
         /V79NpUtb36qIqzXbqT5I6eK1WmIzRoOzAwY91H2/oPzqlpCrYrZeGobgcffFQzfMh6c
         6wIVDwYbVyfs3IVbZqgq5VRfcLKLBUoNVWrD1d3SJithxUmayvUQMlJQdA3rzDrJYw1z
         WDqERTBbVZbHSOwjRXsROXQAOTZON2x2+if0ZbpsNXDAx/rzzlrBaEXXaQ+JihwWX7dO
         BGVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=LXjbiUeKX1jEQnL+FwWLcen6cX7ksdYWye9qn3fwv6g=;
        fh=QRzuBjsvgaO1XYQGtnbR6ht42432ZyQ/id9lgohK9Bg=;
        b=mH0qNlTebeSAVarDhZfmfEHzJTGoDSt1zF2JLh04oLst4A3bGBy4Oc0PgQpZHwnH3K
         qo4m9XlzabYqbtuML4rD0+Hx5a0ZZaygdi2mX+xHHCwJeNuI6Hf/88QgnU8tyK/n87fq
         DzH8TJiYc3iTRQP4rWiDR/dh8sNe5kmaeMIti9slL39mkMGTn9krPJNsr/xpLPVJascw
         NO3oMK6UIWYNHshP3pQYaVNTMTo2RM9HJjeDETaBEWXYaMejAW2fjSkmkonaaK6X/Gcc
         A5nL/cJrkLTJbpYA8didbIYAdLcI0TEh+0bSY7ModbqErLPct+DqZqO/UI+00HpW4elB
         Lpbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="m39/fAGT";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52cd642e432si18462e87.12.2024.06.21.02.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Jun 2024 02:32:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-57ccd1111b0so981479a12.3
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2024 02:32:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVXz5h2kFKUK0l5ZnM41V9QpmErGYZYINxKxzqv05FfVMYDs6nWaXgoPrNWpcRnWjvpf5sgY08/QGnwCDMbRbKIgM+tHBY+LK+LBQ==
X-Received: by 2002:a50:d60b:0:b0:57a:79c2:e9d6 with SMTP id 4fb4d7f45d1cf-57d07ea9ccbmr5867695a12.33.1718962334727;
        Fri, 21 Jun 2024 02:32:14 -0700 (PDT)
Received: from pc636 (176-227-201-31.ftth.glasoperator.nl. [31.201.227.176])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-a6fcf56e9f3sm62345066b.215.2024.06.21.02.32.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Jun 2024 02:32:14 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Fri, 21 Jun 2024 11:32:12 +0200
To: Vlastimil Babka <vbabka@suse.cz>
Cc: paulmck@kernel.org, Uladzislau Rezki <urezki@gmail.com>,
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
Message-ID: <ZnVInAV8BXhgAjP_@pc636>
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
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="m39/fAGT";       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::532 as
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
> 
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
> 
> But it wouldn't be great to introduce this possibility to happen for the
> temporarily delayed removal due to kfree_rcu() and a module re-insert, since
> that's a legitimate case and not buggy state due to leaks.
> 
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
> 
One question. Maybe it is already late but it is better to ask rather than not.

What do you think if we have a small discussion about it on the LPC 2024 as a
topic? It might be it is already late or a schedule is set by now. Or we fix
it by a conference time.

Just a thought.

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZnVInAV8BXhgAjP_%40pc636.
