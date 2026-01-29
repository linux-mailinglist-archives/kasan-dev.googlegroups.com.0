Return-Path: <kasan-dev+bncBAABBMUL53FQMGQELXZKEJY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qNbcIbqFe2mvFAIAu9opvQ
	(envelope-from <kasan-dev+bncBAABBMUL53FQMGQELXZKEJY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 17:07:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id D51CFB1D4A
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 17:07:15 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-658b6757eebsf1204255a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 08:07:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769702835; cv=pass;
        d=google.com; s=arc-20240605;
        b=XGlSxYoziEDJznz4dWc7I9UpPN+oqBMpSgaDCgCvsD31h2LGDYFTCgsjNhnq8JfjEy
         JNl7Cf997QoEgzDnHR/EgPOT/BMzPapLugE+oi51mjJVQElSuHgc7XGmKmFF6piFClZQ
         6CsNWy5fuCf/7Shw5Y9YGE9DFREI/8KCRA+UOf4aRs1WGmiMSllFP567Qf/4Z0hPNbdi
         M9Iju5bpY6R4Jch7AmTYw5K8vTHlLggdBNWvLib6YoTSScVeZ5o00kJayQ9Ph6SAUhHL
         CCyjEbDfIm3S1hFNio09TFVXGAEM/eHkpgsew0DjGPEaDvf/fbzzUcNrJjgV5YF08X7b
         iJsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=DSSgP97HsvH7MGxUGW84faBPrN3BGtpny7nfPjixg2I=;
        fh=Pf5bMh6/51+FGwItSjVzSMWLW5AWq+6PZn4UEmTlIPw=;
        b=OjtPpp9JnH+6ruxvQhE2AEm7A9TsqoTTdkVoWQMvvV9XqAZXrxbjhEb3Qy1+pJKIDY
         aBofTa70XsvHVK5KVaCBjGiBr0jFksjLBvXnhMKk7179cQIqW6WRlLDAqrLiCQ1LlTLG
         v33+NQM9Ticmnb78EkeGdvoFk4hHJxNeKwPBUkoEOGf7z57goEOyYLZKU0PU3lvZxhXa
         KgkDiIoxMYtE3B9T1Fd0WuxE5/2qycnKaWAeT9XaVNGGLv58yYurWlvd8yf02PTAzn0p
         A+y2RZvLMgx5EDIiMy/Pk2o8lU54bt0Ug/suQa+AJJ5TaTLJVw8YtoTy9XnwPMFkTpbd
         kgXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KQyhd+zH;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769702835; x=1770307635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DSSgP97HsvH7MGxUGW84faBPrN3BGtpny7nfPjixg2I=;
        b=fY2f+7y4otH3hp5g+rVrbsbNsLEcCBVuSkZWtXex83gMYSb1/muQ7Elh5DAFgc74UV
         GJEPIx9SpsNGIcK2UkR+kGAJGsS4LFx6yiOIuUmYhsGPMP6sfXsaqpQl5dB+jvAmOLA8
         QFOsmX38hVRoILThG8P4Nd8SI3Sy3tkqNrbc+dCbOgR7SgWLsV8qVMvXTt9Fwh9jepBB
         ZuxDU3GE1qC4jr2VvT9JGlPJ2bPPg0saAm51RA4Z+vPZ4jlz4YTeOqSDw84IvdqTqqi7
         S1nqb7cIg7o+kUKqf8m+K+9uOmSJymocqG7zU7oouq2nRgAlFEU4Jwt1KdZB6+0nq0i4
         ZPvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769702835; x=1770307635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DSSgP97HsvH7MGxUGW84faBPrN3BGtpny7nfPjixg2I=;
        b=JcZCmh49NR6KhKEBqNmilIvHz31BHbF2YjNZoVCyVe7jDWB/TXqRjjJ2Sn2lRGseC8
         2cT5YGi58BmlYUPnjGGIvi9ztQwBOsRMsjevbItKH9Vo9SeWDhGkRocaQOG4QBm4PPgU
         90ZltXzvL/Wo5r2cQ5Gwv1BluYtdBfhkjZeXpfQZ222uJxJcIYT0BPys56ktGU3/ZPzO
         mMcwqsqWtcKREnzsWzwB1lB8oEv9ljBNQK9AhY3X8REMMZQzM1IBqIHQWEoCpDrQVpVL
         q7rmzC7cV14Zd06ldHiEZMTOcVrTMOLdBu0nEItJL1oToLz7r4ijA7ndkm5mn8lxxO9o
         cwvw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVGpnfadNYuMGHRZ+8tZoEeK5LDva92UgAtwEAwZDIO2RcYZL868b3Uhh3WH9KZaqFzyhqd+Q==@lfdr.de
X-Gm-Message-State: AOJu0YzA6VG5iAmxvGPJJSC8up8trSr6mExIGGjSOjOF+l1I1pCGVjzu
	OkQlpX2anFH/vPWT2S9RFsvH7ctkDf1co8nyNk2vAzpjrpD2yqxgM9qy
X-Received: by 2002:a05:6402:26d4:b0:658:b838:1bab with SMTP id 4fb4d7f45d1cf-658b83849ebmr3531929a12.31.1769702835097;
        Thu, 29 Jan 2026 08:07:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ExBMTJ4l+huTQ+u5ndyRIeqRlxXUQ68lBMTvYwhP2ipQ=="
Received: by 2002:a05:6402:404b:10b0:658:1d2f:b8d6 with SMTP id
 4fb4d7f45d1cf-658ccfdf24als921538a12.2.-pod-prod-09-eu; Thu, 29 Jan 2026
 08:07:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUATCuF2CBSGFaRyQQ0JIuot5PDnilPK/JFNV5NwcPcyKEC95/f/eKweiAjPj+2ACFGgGQ7gr+c510=@googlegroups.com
X-Received: by 2002:a17:907:d0b:b0:b87:3cac:cd4b with SMTP id a640c23a62f3a-b8dab3059b0mr567421566b.15.1769702833431;
        Thu, 29 Jan 2026 08:07:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769702833; cv=none;
        d=google.com; s=arc-20240605;
        b=VoxYQuCP3FOE49T1i17FjDVKOUhKfWDT3JANNiPb/+8AF9SVbswGHhGViMTWNjBzmC
         f5T/qAGzVed7LGpx35vU/xR1T2N5o7VmTlMl/d4nondjTqoTWhfm2I0Ds6LLA9908RjT
         o7pSwPh9IYGoF8AcInVuEngz/4XHy1Y8yHP3VB6IePPlIEAfxEBAwHSiZipEndfIjLNh
         Br5mgKFdymimyF/GwOErmCztExiQpLecpg7+aJ1Ou44QGg1XiPtQUbzECGm9XDNOjJSV
         8Tapy4MKY5gTllcGot3KXgTPcpYUNZFk+8p2YKP6KCsaAPJqkOUMRQ6ROWkX4udsVJcE
         BzKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=W4DyRR+8pEpil2SIyjO3JCOq7XaAaTnp588uXM7WQog=;
        fh=IJc/xULCf01o48qWj7VfHKXKmbbWC8yCQEzHfREZ7bs=;
        b=EFCDkOfwW1I/OvYZkFNZi0p1MdHhgKW3NJ44gdtpVKNlbGK47bAlGKjcLgbHtpE73d
         Puy/MZpFwWJFEcw8rla4p6dzzIiIdAqrho9dCDtQ7KoA5jXAxnuBQvOfPcvzEzxVlv0v
         IwSmBKwhCP0hqqzmqUG3b7/zBqeA+mmXByqWEXU4dDw4Fw6cuX3M/ld3w4isW40Higof
         YZaBEeRoN5iU4qMvEg4HPJkppxKvzmdQjOhiPJIui3DP0RYkmYSthxjKPr8nPCpaL24q
         LzBIh5dBYHi5uoBrf9j2h9uzLIkVi4RJ3SucZjrB9/QaejZHrJ6RD+c7wDL0h2owE/gz
         vF8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KQyhd+zH;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-182.mta0.migadu.com (out-182.mta0.migadu.com. [2001:41d0:1004:224b::b6])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-658b47db996si125250a12.6.2026.01.29.08.07.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 08:07:13 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b6 as permitted sender) client-ip=2001:41d0:1004:224b::b6;
Date: Fri, 30 Jan 2026 00:06:54 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org, "Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Message-ID: <aozlag7qiwbdezzjgw3bq73ihnkeppmc5iy4hq7zosg3zyalih@ieo3a4qecfxg>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KQyhd+zH;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::b6 as
 permitted sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=linux.dev
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.11 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MID_RHS_NOT_FQDN(0.50)[];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FORGED_SENDER_MAILLIST(0.00)[];
	FROM_HAS_DN(0.00)[];
	ASN_FAIL(0.00)[0.4.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.4.6.8.4.0.5.4.1.0.0.a.2.asn6.rspamd.com:query timed out];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[20];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABBMUL53FQMGQELXZKEJY];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: D51CFB1D4A
X-Rspamd-Action: no action

On Thu, Jan 29, 2026 at 04:28:01PM +0100, Vlastimil Babka wrote:
> On 1/29/26 16:18, Hao Li wrote:
> > Hi Vlastimil,
> > 
> > I conducted a detailed performance evaluation of the each patch on my setup.
> 
> Thanks! What was the benchmark(s) used?

I'm currently using the mmap2 test case from will-it-scale. The machine is still
an AMD 2-socket system, with 2 nodes per socket, totaling 192 CPUs, with SMT
disabled. For each test run, I used 64, 128, and 192 processes respectively.

> Importantly, does it rely on vma/maple_node objects?

Yes, this test primarily puts a lot of pressure on maple_node.

> So previously those would become kind of double
> cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
> more than they should) since sheaves introduction in 6.18, and now they are
> not double cached anymore?

Exactly, since version 6.18, maple_node has indeed benefited from a dual-layer
cache.

I did wonder if this isn't a performance regression but rather the
performance returning to its baseline after removing one layer of caching.

However, verifying this idea would require completely disabling the sheaf
mechanism on version 6.19-rc5 while leaving the rest of the SLUB code untouched.
It would be great to hear any suggestions on how this might be approached.

> 
> > During my tests, I observed two points in the series where performance
> > regressions occurred:
> > 
> >     Patch 10: I noticed a ~16% regression in my environment. My hypothesis is
> >     that with this patch, the allocation fast path bypasses the percpu partial
> >     list, leading to increased contention on the node list.
> 
> That makes sense.
> 
> >     Patch 12: This patch seems to introduce an additional ~9.7% regression. I
> >     suspect this might be because the free path also loses buffering from the
> >     percpu partial list, further exacerbating node list contention.
> 
> Hmm yeah... we did put the previously full slabs there, avoiding the lock.
> 
> > These are the only two patches in the series where I observed noticeable
> > regressions. The rest of the patches did not show significant performance
> > changes in my tests.
> > 
> > I hope these test results are helpful.
> 
> They are, thanks. I'd however hope it's just some particular test that has
> these regressions,

Yes, I hope so too. And the mmap2 test case is indeed quite extreme.

> which can be explained by the loss of double caching.

If we could compare it with a version that only uses the
CPU partial list, the answer might become clearer.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aozlag7qiwbdezzjgw3bq73ihnkeppmc5iy4hq7zosg3zyalih%40ieo3a4qecfxg.
