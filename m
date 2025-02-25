Return-Path: <kasan-dev+bncBDK7LR5URMGRBC4Q666QMGQEMV7VQNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 315C5A44106
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 14:39:27 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-3091f1bd54esf30633191fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 05:39:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740490765; cv=pass;
        d=google.com; s=arc-20240605;
        b=SLIBWYufvv1cvVz99yoo6z0xUQ+t/vq1GBPBlN/SlD15/p2mURqJ2EQ+zfTCh/TmuS
         l1YkUA8lyutCMdNv7b6IcjDfDx+sVi1s5Q/Yv9F6G2Aj8WiedP6lf/FyoHiegb4kgptT
         dDfSgKt0iFYkCf5y+xihvk0MOfawPJPfaDrkqUh8hvp/+ocWqUr9zdAPa+z0FCz8TJo3
         tRR5c5JFcXstL2ae/r+C1yxaoqbfexpFoluFTh+2IQDb2UWHqKY0uNAuxOSbxyfq8uxJ
         lwEJ1QqXcNIUSkmEE5WkXWUO6m3Kds4hlS8h8MOf+wdBDmMPV/eNxb4Zb+K5APfSh3UT
         7bDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=Ou1d9l9FFxUSqM5Hd2whHaO41Nj2MYSd9VhDnxbvw44=;
        fh=oe9vxrX1r3G38VfdLqUAHHuzs512gCE4ww+zUh/l/Hg=;
        b=Iyw7fPHhQziL3c8/asFU+N2x9OHwfvOBp4KdsgmSJDfuqD6VAWToK79ReLl2CSn/NP
         Stj4hmDG+fUcIhB/f+bPIcVtwusRkrTTmdSMgTuu3W1PwOGRSyUQhXDtCcYrFdmNkJAc
         ZaE7JQODSnM2M7gkVOIWapC/zibslqK3pb4+zYi4zGToe7jc1tXnChd9DhhahTbz2Qb7
         QZItFaPgFiXPSa+0kfRFXcMUJEb53mXVWJXcUJvFYHEVsVxQXcnEgXcZYnh+groWOffn
         TXO3pfd7QqJs/Ze3fT3r/ZH1vAe4h4J7DRPwIVxJYC06KYev05xtk1cHWWl6XrTKtS98
         NoEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FF7v2iqD;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740490765; x=1741095565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ou1d9l9FFxUSqM5Hd2whHaO41Nj2MYSd9VhDnxbvw44=;
        b=QUclp7hbNgutBY64TE6meCP6+zlnbZT8h40zCGOyMMw+xGSXES3Yl4hLcZPC5A6htr
         KVYWS8ORP/1jDtwJyGDwvWIUNyyAXppxI/J14xmCBsZLQdiUCTQj2VeXvrFMHO23Cbjm
         P8rlIxwSOkF+R2HJkMBnXzoyBwVZN98U4O7Z4JPqUpzV8oEvtubAo8Etp1dv/dP4gPys
         0+RyeVsMXYF6JNtLUvI57jdBG6w+CU4TaPeYIzcaj/cMulIpiERc40a7GZpo8wH6+JUx
         1WoyW0UNzi4pMJEVLne/ltokwC/Vn7L/f9rZUN97XQyiEKlSX0Dt201yGFVwQ/rhmn2H
         ZvLQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740490765; x=1741095565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Ou1d9l9FFxUSqM5Hd2whHaO41Nj2MYSd9VhDnxbvw44=;
        b=HwO8fbnibH2rZXUx6Gut3vGxQjRvB5xC80EGd9bFBzl7kgG139/4EKU2jmYBvZ1w6U
         VOGB/FL57h7qf12Ef5s4XkyZ8e7B4++d+7loJyKXxGzy8C/N84Xu1RT/aB1fCcwOyNbl
         abNeE607zqYBJUyVCkcjM259jO4Q2w2SD4GiH6z9+Dd6KQsKBxtMlDF26xaarRTeVBQQ
         DCMrSHTFKGFjIo+lOtBp/mwH+zifSu4NsvlK2FWVUtEaWy2pl/ZoWRhxYqLxYzFMurqa
         ePaI++FX48GmEp034k6gC0i3QT9Aloit/T1vBsUdly02L43FvBl+53F4O4XVE1zb8Nig
         bF1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740490765; x=1741095565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ou1d9l9FFxUSqM5Hd2whHaO41Nj2MYSd9VhDnxbvw44=;
        b=GClI18kQTvMNYvn7s8JFsjXREbqSvdZr44DwBrXBzo/Bz96KD+BdykF+POyFdTR7+Z
         VpzPFDfHBC1jSYd/gWJPjOnMvmmQespYMXq1M2xQXQekv/mMwMXordjur1GJnDZVrRcD
         tGPMJGDytDR+kjbJllnlblSoU8nHXye61F8VK9WS6zrJme3ZB1cwtLIqjFnr0PhJKR7V
         7jYA5cmYdpbNGeUBK+lY4GGLXzjcaV0087k6bELBzs1DUdDuIxGb+w74AuCIdfgb8i4a
         bMx0r7JvxsFEsVuIFkC//+IzxE0KPXnLm9in0bmvDDkhKHxgYX5pn6KKZcKzBp28efWO
         Kj0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5zB9hBCv5xahRF9n3oYg1XKRAvls7ux4TavVRBj1jiMGdJHZ2F3Onq1dqrsM63IdlHamifg==@lfdr.de
X-Gm-Message-State: AOJu0Yxwyty99XA/qE3x8EnrISmliuRCkZXECV8gZebp+4YtALk7YQZd
	bljZvIpSeRyzbdE0iLHgw2ykrEnr0bOiSa1j+fZIcuJf85Gdy7fl
X-Google-Smtp-Source: AGHT+IE/OxbfaUxtpk4gWYiT2e2nPzUU5L4LZQKlyU3zlzHtoEnkNkap6tK+mpItIqhHxRvLw6DCnQ==
X-Received: by 2002:a2e:95cb:0:b0:308:e5e8:9d4c with SMTP id 38308e7fff4ca-30a599605b8mr62082221fa.28.1740490764299;
        Tue, 25 Feb 2025 05:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFh3HILT8qaINd9cFlINd5gQhxxc2iN5NWy8X0XSRXh9Q==
Received: by 2002:a05:651c:b12:b0:309:1c03:d2d7 with SMTP id
 38308e7fff4ca-30a5001468fls4405151fa.2.-pod-prod-08-eu; Tue, 25 Feb 2025
 05:39:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVzArl2E5MUui61z5ore0llPEMO5Z4MDURwWvWdVEoN6tW2eVx5U+0iAblzm2vLwGcg+I1OlmO8H9Y=@googlegroups.com
X-Received: by 2002:a2e:80d3:0:b0:302:4a61:8b85 with SMTP id 38308e7fff4ca-30a599951ebmr57404961fa.37.1740490761636;
        Tue, 25 Feb 2025 05:39:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740490761; cv=none;
        d=google.com; s=arc-20240605;
        b=eBUnwSpQT5M4HMjU+ePlmjdFdK/mvYPR/sk3ZbtKEDTLtgx+MZhoEAwxyJr2TV0rAZ
         1mZ3k4W91bE8WV9FGN9IZKX4N9dujYFnfQ9QhYfZJSvQsif13+UAVbKvHNRAS0HYkFIC
         17TruG5n9W2dLtJTOlXcr1T3MGrNshgnq3W3YuRiO/LrQS/U4azPYyx4OGdXUkIm5b+u
         I107agz8vDEzT7O+yxYzgcXrTUrMS7STeTxURqlS/w29OSofXgnJEXwYD5K7abp0yrt+
         5RjON9+K+9EJh34vXwpE/PlKL5lTezU8dM48caDo1Ee184/WkAXfp0QP+hNFb/IMsUTO
         WhCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=uT3CYG520Dq/1dijGlLbTlImqbVeMFyUskqf9mGklcY=;
        fh=EFh4ReBvq1ghfhAo91opvkM8GtU6jS9EooPBBPbyD1A=;
        b=kn+lOgXQlGf9tM2rJRBAQ6HfxxNP2S7ludpYxaNdcCK5sXLblns9abYTXCWmK2IrFm
         NmkWmnKxK6Gfe0a4OhCVrxuoHbd6FzNq7yyIidCGxmito/xUhP5uPQOrANJ/HGUXwWvl
         xa5gGgTFrxE7xkTZ2E9OgzPcnQYuRVkAcIOoGe85k1Dd6yLV4GsIlzCzve3gjfrKG0+6
         QoKaOf7A1/p5K/SI0LTSNEs4fbwqDeho5OKP3txrTHmrNtEb8dFOzrgkRrCiDE1yuvwB
         nZztE78UMU+IU29KwMaUnE/jt0W6LLGpV8of3uC+f4GY7K36HcGR4u7gq+eC5Oi8jfXF
         ePvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FF7v2iqD;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x229.google.com (mail-lj1-x229.google.com. [2a00:1450:4864:20::229])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-30a81a2dd0asi1363741fa.3.2025.02.25.05.39.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 25 Feb 2025 05:39:21 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::229 as permitted sender) client-ip=2a00:1450:4864:20::229;
Received: by mail-lj1-x229.google.com with SMTP id 38308e7fff4ca-30613802a59so58072551fa.0
        for <kasan-dev@googlegroups.com>; Tue, 25 Feb 2025 05:39:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXI1nPVkSz0RLAHr4ulGHi0Q4ZbnrotKgjhfre10t33KiymwnhJiSZYy6ExgHY2DDmrTJFUx3l+TKw=@googlegroups.com
X-Gm-Gg: ASbGncvpB5rEmDvP7qCuZq99PRRP05lcOXny290RJRaOVrE9UI6QPKoi8b+qqIFhrNX
	5nOLOzxbwB444tyBXGKqYNCgDGSjTDP5A1ntqD1lfP66+rZQ6lqceCD1gQmUwjddDvCslS2Tr0f
	OdhB8N+2GIVKt3i4JY/NSfcvergaoWYxlC24pOJQHxlRAluVNYPiu6cLo5viESuAYEvx5BGYCQJ
	T4Zrvu00xcCEOmrPd+XfW4TyIyKDVz0admgNcJiAsrpgjSu2B+f7vChs8azvGqRSChg10eIXxlb
	aBw0Qmu/hva5lybnw4odqxhycNYEZNH78XE2otDeOJxLdRO5
X-Received: by 2002:a05:651c:2227:b0:300:3307:389d with SMTP id 38308e7fff4ca-30a598e5c7cmr69996921fa.19.1740490760754;
        Tue, 25 Feb 2025 05:39:20 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30a819f4a4bsm2372111fa.49.2025.02.25.05.39.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 05:39:19 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Tue, 25 Feb 2025 14:39:16 +0100
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>, Keith Busch <kbusch@kernel.org>,
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
Message-ID: <Z73IBMdk5fnmYnN1@pc636>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
 <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FF7v2iqD;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::229 as
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

On Tue, Feb 25, 2025 at 10:57:38AM +0100, Vlastimil Babka wrote:
> On 2/24/25 12:44, Uladzislau Rezki wrote:
> > On Fri, Feb 21, 2025 at 06:28:49PM +0100, Vlastimil Babka wrote:
> >> On 2/21/25 17:30, Keith Busch wrote:
> >> > On Wed, Aug 07, 2024 at 12:31:19PM +0200, Vlastimil Babka wrote:
> >> >> We would like to replace call_rcu() users with kfree_rcu() where the
> >> >> existing callback is just a kmem_cache_free(). However this causes
> >> >> issues when the cache can be destroyed (such as due to module unload).
> >> >> 
> >> >> Currently such modules should be issuing rcu_barrier() before
> >> >> kmem_cache_destroy() to have their call_rcu() callbacks processed first.
> >> >> This barrier is however not sufficient for kfree_rcu() in flight due
> >> >> to the batching introduced by a35d16905efc ("rcu: Add basic support for
> >> >> kfree_rcu() batching").
> >> >> 
> >> >> This is not a problem for kmalloc caches which are never destroyed, but
> >> >> since removing SLOB, kfree_rcu() is allowed also for any other cache,
> >> >> that might be destroyed.
> >> >> 
> >> >> In order not to complicate the API, put the responsibility for handling
> >> >> outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
> >> >> introduced kvfree_rcu_barrier() to wait before destroying the cache.
> >> >> This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
> >> >> caches, but has to be done earlier, as the latter only needs to wait for
> >> >> the empty slab pages to finish freeing, and not objects from the slab.
> >> >> 
> >> >> Users of call_rcu() with arbitrary callbacks should still issue
> >> >> rcu_barrier() before destroying the cache and unloading the module, as
> >> >> kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
> >> >> callbacks may be invoking module code or performing other actions that
> >> >> are necessary for a successful unload.
> >> >> 
> >> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >> >> ---
> >> >>  mm/slab_common.c | 3 +++
> >> >>  1 file changed, 3 insertions(+)
> >> >> 
> >> >> diff --git a/mm/slab_common.c b/mm/slab_common.c
> >> >> index c40227d5fa07..1a2873293f5d 100644
> >> >> --- a/mm/slab_common.c
> >> >> +++ b/mm/slab_common.c
> >> >> @@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
> >> >>  	if (unlikely(!s) || !kasan_check_byte(s))
> >> >>  		return;
> >> >>  
> >> >> +	/* in-flight kfree_rcu()'s may include objects from our cache */
> >> >> +	kvfree_rcu_barrier();
> >> >> +
> >> >>  	cpus_read_lock();
> >> >>  	mutex_lock(&slab_mutex);
> >> > 
> >> > This patch appears to be triggering a new warning in certain conditions
> >> > when tearing down an nvme namespace's block device. Stack trace is at
> >> > the end.
> >> > 
> >> > The warning indicates that this shouldn't be called from a
> >> > WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> >> > and tearing down block devices, so this is a memory reclaim use AIUI.
> >> > I'm a bit confused why we can't tear down a disk from within a memory
> >> > reclaim workqueue. Is the recommended solution to simply remove the WQ
> >> > flag when creating the workqueue?
> >> 
> >> I think it's reasonable to expect a memory reclaim related action would
> >> destroy a kmem cache. Mateusz's suggestion would work around the issue, but
> >> then we could get another surprising warning elsewhere. Also making the
> >> kmem_cache destroys async can be tricky when a recreation happens
> >> immediately under the same name (implications with sysfs/debugfs etc). We
> >> managed to make the destroying synchronous as part of this series and it
> >> would be great to keep it that way.
> >> 
> >> >   ------------[ cut here ]------------
> >> >   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
> >> 
> >> Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
> >> is after all freeing memory. Ulad, what do you think?
> >> 
> > We reclaim memory, therefore WQ_MEM_RECLAIM seems what we need.
> > AFAIR, there is an extra rescue worker, which can really help
> > under a low memory condition in a way that we do a progress.
> > 
> > Do we have a reproducer of mentioned splat?
> 
> I tried to create a kunit test for it, but it doesn't trigger anything. Maybe
> it's too simple, or racy, and thus we are not flushing any of the queues from
> kvfree_rcu_barrier()?
> 
See some comments below. I will try to reproduce it today. But from the
first glance it should trigger it.

> ----8<----
> From 1e19ea78e7fe254034970f75e3b7cb705be50163 Mon Sep 17 00:00:00 2001
> From: Vlastimil Babka <vbabka@suse.cz>
> Date: Tue, 25 Feb 2025 10:51:28 +0100
> Subject: [PATCH] add test for kmem_cache_destroy in a workqueue
> 
> ---
>  lib/slub_kunit.c | 48 ++++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 48 insertions(+)
> 
> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
> index f11691315c2f..5fe9775fba05 100644
> --- a/lib/slub_kunit.c
> +++ b/lib/slub_kunit.c
> @@ -6,6 +6,7 @@
>  #include <linux/module.h>
>  #include <linux/kernel.h>
>  #include <linux/rcupdate.h>
> +#include <linux/delay.h>
>  #include "../mm/slab.h"
>  
>  static struct kunit_resource resource;
> @@ -181,6 +182,52 @@ static void test_kfree_rcu(struct kunit *test)
>  	KUNIT_EXPECT_EQ(test, 0, slab_errors);
>  }
>  
> +struct cache_destroy_work {
> +        struct work_struct work;
> +        struct kmem_cache *s;
> +};
> +
> +static void cache_destroy_workfn(struct work_struct *w)
> +{
> +	struct cache_destroy_work *cdw;
> +
> +	cdw = container_of(w, struct cache_destroy_work, work);
> +
> +	kmem_cache_destroy(cdw->s);
> +}
> +
> +static void test_kfree_rcu_wq_destroy(struct kunit *test)
> +{
> +	struct test_kfree_rcu_struct *p;
> +	struct cache_destroy_work cdw;
> +	struct workqueue_struct *wq;
> +	struct kmem_cache *s;
> +
> +	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
> +		kunit_skip(test, "can't do kfree_rcu() when test is built-in");
> +
> +	INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
> +	wq = alloc_workqueue("test_kfree_rcu_destroy_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
>
Maybe it is worth to add WQ_HIGHPRI also to be ahead?

> +	if (!wq)
> +		kunit_skip(test, "failed to alloc wq");
> +
> +	s = test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy",
> +				   sizeof(struct test_kfree_rcu_struct),
> +				   SLAB_NO_MERGE);
> +	p = kmem_cache_alloc(s, GFP_KERNEL);
> +
> +	kfree_rcu(p, rcu);
> +
> +	cdw.s = s;
> +	queue_work(wq, &cdw.work);
> +	msleep(1000);
I am not sure it is needed. From the other hand it does nothing if
i do not miss anything.

> +	flush_work(&cdw.work);
> +
> +	destroy_workqueue(wq);
> +
> +	KUNIT_EXPECT_EQ(test, 0, slab_errors);
> +}
> +
>  static void test_leak_destroy(struct kunit *test)
>  {
>  	struct kmem_cache *s = test_kmem_cache_create("TestSlub_leak_destroy",
> @@ -254,6 +301,7 @@ static struct kunit_case test_cases[] = {
>  	KUNIT_CASE(test_clobber_redzone_free),
>  	KUNIT_CASE(test_kmalloc_redzone_access),
>  	KUNIT_CASE(test_kfree_rcu),
> +	KUNIT_CASE(test_kfree_rcu_wq_destroy),
>  	KUNIT_CASE(test_leak_destroy),
>  	KUNIT_CASE(test_krealloc_redzone_zeroing),
>  	{}
> -- 
> 2.48.1
> 
> 

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z73IBMdk5fnmYnN1%40pc636.
