Return-Path: <kasan-dev+bncBDK7LR5URMGRBNNX6G6QMGQEYK36UBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B36AA41D4E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 12:44:55 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4399c5baac3sf30483675e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 03:44:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740397495; cv=pass;
        d=google.com; s=arc-20240605;
        b=P1nR0JHt+UgADHVwqMpR/fxRYN5oU0sBRFp/0NBKdhGn6rOVwmvFr84SUYgqxhkvBe
         hmGT6UqXPzRhXhSVrzsnEtdq8FFoY7tPs5FgRz/8FaFSW1DFAZMi4/AmZdW/pfSoPXNA
         Hyy5PsqxobDBfiqYWsaKwkeQGoC0tE/tstazcBZX7ZoeUeKGjCkh3cEE1xTF4GD5CHEy
         vIRgQd8zMT9cXOwPiZGvLrP4Hy697xrvMI080+W0hKiiLuFPZJmyETbfQurXuVdy9Bc6
         ZkW05AaSWOxmQhRvt3So6DcziHIz+giP0AsRAMFJbsVHGKOVJj3X/1LuF+HyJXpSaRMK
         SJFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=pacNZ66BxKG6stEMiimbC2UQI6VE7LCmrs5fq7+s6DM=;
        fh=/CqveLY+W8JJW8d0vmnsVTx3fqJrWkFCRWUyEm72MiM=;
        b=bglGlWcp5qK9DgAAL460LH4YIxfycoLMLJwY+CDHPpmAQlG1Z3mKuwpekSOS3kzqAG
         WYzt46J4pJNhr2WRaboxES7LzRpjF+SixVNNEX8u5RXWG3LpRAKXJLelNANgmL/HYhnE
         t3kc/ZPHfgBDbOtXLPA0xkMJI1MmFFai30eB+q3oIXs8o0hwbDn45ivWIhLPhR5FOEsi
         XcthCKr6II7CtQpBcSQwHoJMvTjeyU/jIkTnyn8C2ZgSvcGrW7AOv3pucH+N6xxRDIEy
         EZTLGETeSXA3U8GFs//5vNDgM67E9TrB6MC9lMV+5dlDTQZBOXVgLBbtaUxcnt9GWCcv
         0wRA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a2kB41zI;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740397495; x=1741002295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pacNZ66BxKG6stEMiimbC2UQI6VE7LCmrs5fq7+s6DM=;
        b=S0lMbd2sUczLkVm7AAjxThE8dn+0SHrodP04ah6P2pVifAnF51X6H0voNGbt+RTuBp
         LkdVdDmvbVYVGDgPWSSQSF3MJ2MLgeiCFgiySbyiB4MKh6fqB+YMBjiX1T27EbaZbx3v
         6HXX+oBbIHV8A2whHdFLyJXvlQsuMS/2bcEOoV7BqiHUTpRx/Q78g2VCrFT7osxlUR/c
         XtpCSM/Mgpomm2IFCUIL0cC77m96mL4p94RQevaXUinCLW8xWtFhupdxKl2f9CiPP86K
         hIef2hOFhJzEaFSktAl0ndnED17Sgeg99ZgHqJW0rx382Vfw2Wia8ddDU8sanE2i7Hjj
         QLFw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740397495; x=1741002295; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=pacNZ66BxKG6stEMiimbC2UQI6VE7LCmrs5fq7+s6DM=;
        b=QWLAXynPaYHAhPLInJGcQHVuxwa/s2MXsIQJIB4FKeC1HmQYy7aWc+5amwt57+TSFw
         7+A1TFQbJa+AUhAahJW+uT9JGd68a8zKiEHXMg7+PEVBJD7K4PIK/LK/T/Autr3LSxXy
         frgewzf++MF9MLlXf+DkbunME76r4sufAw1KQYpnpHoaQSX0LJ9sfUUWEUABicfc5xWH
         JnwEoQ7kJhLuENAP8ENc53z5oO1aiMHG6i+3ANOPTNi7KAocJkCZZGeqP4sLGcMwv2uB
         QE7rrJwLYI1UwJBLDG/4hxKlI3s3jsPvWnoVyjf7FjgTAgeSND0orU3o2HFrG0C1nq2t
         3b9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740397495; x=1741002295;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pacNZ66BxKG6stEMiimbC2UQI6VE7LCmrs5fq7+s6DM=;
        b=jT8PhhCLKAuM+H7Ozaufl90IJvHxzIgBvGTtnWXnX2Eq1KCKfiyeOJ/U0wamLn5kg+
         HRKzsWaMVyF0pfHrfR3NHy/tKH5OQPBI1sOyDqcVh6U0zrcROb+E1R9jEYmWfdRTV5vW
         IirTjkqRTJy/6wXg9YZ364o1tdAP3xbauCD4IJsWyYRuwutsg7BrG7oRnQpq8zuVQf80
         Dh8QtUtDESH5SD1dhT2KONZWIWimxIltpa8gpZ+GBZTcrL/9fTuNF4ZgXUIgShI8T+gG
         inabgCk/yx0LYgcMD3n8iCm87P7TgOckLeW8nnASvzQnx+Vr/52RlPXPuK44O+9bHBP8
         yA/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWJRzubMnqrVNruEON9/Xy8PQqJBfyj50lY+wOg076BEotwW7/pS6xhwhjHMYsef1WSD5CQFA==@lfdr.de
X-Gm-Message-State: AOJu0YynJqDU2qzTKn+qVmPdApUQxGNfyoVVgjuB+iTWjAXbtfedghXm
	VejGUSkIOF4T+nRHX+8ty2rBUpDOzlkIZLDRsZz3Oe8Pt4L8eAFQ
X-Google-Smtp-Source: AGHT+IERlD8Bavz/F5KLvmnDxwh/ZKncmWcub9H5xGlK73X32l3U0KpWjCWw0NOTRzM8mUiVJ9KXQA==
X-Received: by 2002:a05:600c:1390:b0:439:9274:81dd with SMTP id 5b1f17b1804b1-439ae1d7b20mr86046325e9.1.1740397494134;
        Mon, 24 Feb 2025 03:44:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH7wdJ3gTXBBb49r6jpOMVVreHKLvn2ARcuTTjGaw/vcg==
Received: by 2002:a5d:5f88:0:b0:38f:2234:229b with SMTP id ffacd0b85a97d-38f61492ab6ls3168033f8f.2.-pod-prod-09-eu;
 Mon, 24 Feb 2025 03:44:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXHzZ7K14thpNU7AM/E0CO9wgZNNF/kbaTppZgVGLISGAvNyn1MMixHfeqFI/j1ZRC3IaAbX2UtvPQ=@googlegroups.com
X-Received: by 2002:a05:6000:1a8a:b0:38d:d5af:29af with SMTP id ffacd0b85a97d-38f6f0d1ddfmr8733936f8f.49.1740397491843;
        Mon, 24 Feb 2025 03:44:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740397491; cv=none;
        d=google.com; s=arc-20240605;
        b=VKR0eXEKNSTgQzF8wM1jMVEJTtuHKS4AIjWbrw+/VQotqTq6GIKoONaRJq+u32mObY
         t3Tup4SuJlFlT6NhUH8xmGBE4TmjXgq/BMpnOTj2g7PsW1y7vNXU9pUVDRrp/Ff8W+n7
         W9Znca2Y/X8sxi7v2H2yrLF2JJRTYSvTGlZIZ2+gpY3XQhFWAIRpIQlnFCM2YnnEHCd1
         wvgfv+5TI2+ukcHeDa5SD0qO8dXua9isvQlD+rHYY52vFUq5UrAqZx/uFFBLFYxa67gH
         G7xncDq1vextCyqXiCzcZRcx1vkMB0SpYakRirrUGWzOfHlmrvS99qBYKQ+C8Yc29dTe
         IDJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=GKmie4ql2EMQXkPV0dHeKHuPylk+abYCTsODvoG58iw=;
        fh=A8h5HIPU1DSb3axv6G2nPbCCQsOBm232PLU188DgumI=;
        b=bCpJFqoH49eM2cX5eXvQ1UuNdaesTLmbrx1LSUSuewG+s7TC5ZdsMgH/A5WjYF6QGz
         XIQh8euafkqAwFX5CvZPNDsSZEV0Mcwg0M3/+3N7pgnKVe8q/h6IVp96XnWtDIrONKX/
         PLT5ZQAkbpfOV5qjwufwtRuMR4XTgR9UiWvxwwna7acaJGO0An4gBBGlHFEiA2cMJ+OF
         kvx2Y+inanDng1lzsnHALwF3lQQJmKeBq/Kl10lbdjJu+oUkTn62yeE9VqO8/q8SIp7J
         lrjQSJgKTAKmlvRb0DBKpblgGoaMcU4KFqwiXUJvObdRw22aa/ku5KriUi/q5PyLyqPL
         QVww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a2kB41zI;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2590ea71si811724f8f.4.2025.02.24.03.44.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Feb 2025 03:44:51 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-545284eac3bso4262766e87.0
        for <kasan-dev@googlegroups.com>; Mon, 24 Feb 2025 03:44:51 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVWAsum7UtR5WkB7P+Pqtedu0yLzYoVkron+qMadlOP2VwcS3ZDmbCLJMHIRPRawobFlBsEHrtM6zU=@googlegroups.com
X-Gm-Gg: ASbGnctmbv0dHQOBHbO6753ByzThIi/dhigsFKZabaFaRpMygACu/0h4+670y/p0rlu
	UI0hCyp/lclsJpzM6UXIO/FryQgjm7xZwN2Z1iXsYfXtsJEKTIySmbzBVuilg+6N8mnbiZPG0pd
	cQqvk0G7u7mk+5w1bLFkN5sqG2k6THA4+kCZ7lmVv7L0oKdxlzvhRUDVUhXtY5wl3W8sMyqlLLS
	SWjU2lqUA9RLyiBN7+IkgvFHRy/219HM7Ts+p7zmh2fgnDkPvtm4mteNX6+u8/vA6YckzsAAZbf
	o21JSzUPXWtswL+LeZnwvjSRLR6L390jUEgfao1xVScWvz6A
X-Received: by 2002:a05:6512:1244:b0:545:1104:617d with SMTP id 2adb3069b0e04-54838eddea5mr5695115e87.11.1740397490753;
        Mon, 24 Feb 2025 03:44:50 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-5461f541653sm2376875e87.156.2025.02.24.03.44.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Feb 2025 03:44:50 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Mon, 24 Feb 2025 12:44:46 +0100
To: Vlastimil Babka <vbabka@suse.cz>, Keith Busch <kbusch@kernel.org>
Cc: Keith Busch <kbusch@kernel.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	"Uladzislau Rezki (Sony)" <urezki@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z7xbrnP8kTQKYO6T@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a2kB41zI;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::12e as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Feb 21, 2025 at 06:28:49PM +0100, Vlastimil Babka wrote:
> On 2/21/25 17:30, Keith Busch wrote:
> > On Wed, Aug 07, 2024 at 12:31:19PM +0200, Vlastimil Babka wrote:
> >> We would like to replace call_rcu() users with kfree_rcu() where the
> >> existing callback is just a kmem_cache_free(). However this causes
> >> issues when the cache can be destroyed (such as due to module unload).
> >> 
> >> Currently such modules should be issuing rcu_barrier() before
> >> kmem_cache_destroy() to have their call_rcu() callbacks processed first.
> >> This barrier is however not sufficient for kfree_rcu() in flight due
> >> to the batching introduced by a35d16905efc ("rcu: Add basic support for
> >> kfree_rcu() batching").
> >> 
> >> This is not a problem for kmalloc caches which are never destroyed, but
> >> since removing SLOB, kfree_rcu() is allowed also for any other cache,
> >> that might be destroyed.
> >> 
> >> In order not to complicate the API, put the responsibility for handling
> >> outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
> >> introduced kvfree_rcu_barrier() to wait before destroying the cache.
> >> This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
> >> caches, but has to be done earlier, as the latter only needs to wait for
> >> the empty slab pages to finish freeing, and not objects from the slab.
> >> 
> >> Users of call_rcu() with arbitrary callbacks should still issue
> >> rcu_barrier() before destroying the cache and unloading the module, as
> >> kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
> >> callbacks may be invoking module code or performing other actions that
> >> are necessary for a successful unload.
> >> 
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> ---
> >>  mm/slab_common.c | 3 +++
> >>  1 file changed, 3 insertions(+)
> >> 
> >> diff --git a/mm/slab_common.c b/mm/slab_common.c
> >> index c40227d5fa07..1a2873293f5d 100644
> >> --- a/mm/slab_common.c
> >> +++ b/mm/slab_common.c
> >> @@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >>  	if (unlikely(!s) || !kasan_check_byte(s))
> >>  		return;
> >>  
> >> +	/* in-flight kfree_rcu()'s may include objects from our cache */
> >> +	kvfree_rcu_barrier();
> >> +
> >>  	cpus_read_lock();
> >>  	mutex_lock(&slab_mutex);
> > 
> > This patch appears to be triggering a new warning in certain conditions
> > when tearing down an nvme namespace's block device. Stack trace is at
> > the end.
> > 
> > The warning indicates that this shouldn't be called from a
> > WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> > and tearing down block devices, so this is a memory reclaim use AIUI.
> > I'm a bit confused why we can't tear down a disk from within a memory
> > reclaim workqueue. Is the recommended solution to simply remove the WQ
> > flag when creating the workqueue?
> 
> I think it's reasonable to expect a memory reclaim related action would
> destroy a kmem cache. Mateusz's suggestion would work around the issue, but
> then we could get another surprising warning elsewhere. Also making the
> kmem_cache destroys async can be tricky when a recreation happens
> immediately under the same name (implications with sysfs/debugfs etc). We
> managed to make the destroying synchronous as part of this series and it
> would be great to keep it that way.
> 
> >   ------------[ cut here ]------------
> >   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
> 
> Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
> is after all freeing memory. Ulad, what do you think?
> 
We reclaim memory, therefore WQ_MEM_RECLAIM seems what we need.
AFAIR, there is an extra rescue worker, which can really help
under a low memory condition in a way that we do a progress.

Do we have a reproducer of mentioned splat?

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z7xbrnP8kTQKYO6T%40pc636.
