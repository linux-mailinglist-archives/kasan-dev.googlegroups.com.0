Return-Path: <kasan-dev+bncBAABB2EW3TFQMGQEZ4BDKAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id bX/KNmkLd2n+bAEAu9opvQ
	(envelope-from <kasan-dev+bncBAABB2EW3TFQMGQEZ4BDKAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 07:36:25 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 7201884936
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 07:36:25 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-658150fd8f0sf3897119a12.3
        for <lists+kasan-dev@lfdr.de>; Sun, 25 Jan 2026 22:36:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769409385; cv=pass;
        d=google.com; s=arc-20240605;
        b=doiLzbZhlP59erIZg/UR8YPQ7T5kGv3T87myg0GuUWCsfAgPjSfproTPx0lpsbU4Pn
         8DZ4wIT/gj7JR2ztONwZTbDPOtC54J2CCEPdTsogC6Cwor6Twt0RTCp+3ygCCtGDRzp3
         PU1rzJvADDITmGsYi+9gj5bl3TgBYRCh2gT76XyVs6rt9d43f8WZMKA1jqTPm3/Pw/kv
         TTFCdb3jEbqPvfUXUhCa0d2HxP+eowxBpN62R23ztojLnvNb8QduqSOo00G4KiVkyfjZ
         K+rLOdupLimZKYXPYK3ffmF7rZ4e0MiMeM3JH5fFyrX0/4sIBN7QG+9+Xo3vM6rk2P+g
         tY3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=txf2TjOgnPoTDsB/pTq7ldAmIo5gs4qdlGFKVG7pvOw=;
        fh=xrY7Qb9tpFOclob414Y3JUH4JkVHr7akxnMLbJJ1BJA=;
        b=KFC69aVsqsYeL5JPohSF+kHn2i56SHUE/lqAILNDiuvgDwmVD156voGDHB8xPGZGRS
         juK0XtXDC0d0cS5SvJXmX87vSXLtqWCc7l4LqIDabVs/DA50r4mXK2EPb8WKvRNWjeDn
         l71jzMQBUcXS2WgYYRazYFuaXhqmlasMvHHtwRaH/pyFkzxd8QS1pvLzHW2ew0ApWRCQ
         IOqIL8Ftk6eZZb28Wx+W8iprgM97AWGyzt+fHZLySQ/L//hfmWd4SJtE4NCdPBySrl4s
         KsKUWlce+pCCvpcgwtQ8cqXrRyde5ZaQd08/7PNVrLuys1F9Vh8KrdbdiAjiVi5cUUF8
         /GWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B3DI4qlQ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769409385; x=1770014185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=txf2TjOgnPoTDsB/pTq7ldAmIo5gs4qdlGFKVG7pvOw=;
        b=AdluK0LhSreSrS4RtOR691h1MoSBLzra6Q4K8uYhxUToRfA75d/HpDHP8VpOoUYdzZ
         A5PXrbyERnikjbKkPqWy8WPvg3wCodZNJH63PpO7C0A77+////eIwFfo1aXDdDWs4GYB
         bZjqUe/YbSR3IPfQ4k8Y0kyAVwkyqREsHFEm5W2X0hE8YlYOwkNOvsunGTg44+PR35Cu
         FpcWZY5PQQUvUBhbPLKKrynQDGjaz/7PtBzO71vG2DwbgFlaHxofw35Ha/ajcSPzV0vV
         +gqaRbB9G1fIg5jxrt8F2BUDOS8OH1XFmopxsV+Z7oKoPwENjQlrP6vT3JaQ3OyMyT8l
         n4sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769409385; x=1770014185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=txf2TjOgnPoTDsB/pTq7ldAmIo5gs4qdlGFKVG7pvOw=;
        b=XQq2/vRVOeQ7OiL2Gad2uDeRYIGbkCZ3LfyYBbjOaoyzK84xE44itNwEbzmKFqpD63
         CYLeGcQaW/4zc7Qx45j7phaZSRC2NZST89S1SMeNZ+Noe3jjojByS9rsYBBxYw9gHKmA
         QtYvWyBLTd9CQ/I1x+91thJ6AJ3Ad5eu4RBUqqRL0nJIDNxcLL/EIxIcL98Rw3U4AziC
         WfDnEesXzKHqpLQaPUvsOwQZGgvESQgyfor4TfgBmr0+pBcLqimeegtdplLFapvfSUya
         z7GcEP5BNytYTS/vcBvZDRmHHdlWm/FJIXrN3nRzsYUHydK1226jEYZ6BMPBC6qH5k4j
         KjSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXYEaAxE5xxHmwftbIgEgjqykqJV4cSToFf7Uae2En55MHFh57nZVwScDhMoXWPslscsb4ZXA==@lfdr.de
X-Gm-Message-State: AOJu0YzTgoSweAfMEX2RTTgRC/RVum3Pz53PGXfHlCHxy++lkd0LjFYj
	xUisjS6RUJv186QtHTIf4j4Etl2LXRhjhnUpPXoMRnZfWpyzYft+zdxP
X-Received: by 2002:a05:6402:2714:b0:658:15c4:6790 with SMTP id 4fb4d7f45d1cf-658706d5e43mr1945349a12.17.1769409384622;
        Sun, 25 Jan 2026 22:36:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HipxZuCZteSFSKb2lNlD458blSal3VY8v32YxC4BLVUw=="
Received: by 2002:a05:6402:a25b:10b0:64b:597a:6c07 with SMTP id
 4fb4d7f45d1cf-658329f3392ls2882722a12.0.-pod-prod-09-eu; Sun, 25 Jan 2026
 22:36:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVGZFVJM/p5rLotMfSiShsvYvBE232VA3CQ6aItsYWQSpa5uo/iXttyVlSzXazvZyGQ1LLZmZDFCMU=@googlegroups.com
X-Received: by 2002:a05:6402:34cf:b0:64b:7eba:39ed with SMTP id 4fb4d7f45d1cf-658706b44ffmr2086607a12.13.1769409382799;
        Sun, 25 Jan 2026 22:36:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769409382; cv=none;
        d=google.com; s=arc-20240605;
        b=VymSpuJQKe+LURAg2t2gwVfOEZLdbBYti5Ir2DVSgJMIPmmpv5rTbzmj/EkjGECrHI
         BulTsTVb0z4KnFm69Jci+qS1A0onKobCgWq+Zr1EUkzMm10RA6xROKdpm/ucuPJmV3s9
         ZL2058PyP55BvINvhWD/1eiiSjn6liRLoTiVopnLErWY5m512XuLBLXiLWczQ5O8mlUk
         0y+s6m46cnyDqVYFqghUalC5xNVAnK+zFv4dNJT3/pyKev4qxfBkokomN7dLD9grZwHJ
         4vvHmdEkbc/ZP8ZXgCqtUynXP5kcdRLqY6i4CqySXF1IDBThtSkyHah0DQNiEeyYssvF
         kjsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=Pma8RaoRhbP3xu701FMXEsOkee35ycUd5xowwnvWuMw=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=hNUnbL7JnOOIlwTXF7polOgoYj1Bj9TKLos3eb+PVIWLb9rpsoP7J2v1MzgCUr/Q+t
         6e81fB0b8bti5a4WPuc0zU0GoaZY3uvwLV1cYqEoGjCWEgJXGa1Zk1ZSLvDpiLkEg6hO
         GyRqkl4eHjP2BZpbHaZEO4lwHeJ0hlY+yY+C+inR6MFZtiBXuDa64EY6vF8cZHcJYlZu
         h0Oqjk+V0cl166vswBCTXoC6ES0EVyphp1a5osxh3XnRchJbAlwLAsRycJ2KyxmmqjMf
         xfBNslK8t4G1khP6ULlbNaQ2SvrMySTFkuL7T4edeHsvWWRoKdbzxxn8TBdwwM85CmPB
         E+OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=B3DI4qlQ;
       spf=pass (google.com: domain of hao.li@linux.dev designates 95.215.58.170 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [95.215.58.170])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6584b929cbesi195041a12.8.2026.01.25.22.36.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 25 Jan 2026 22:36:22 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 95.215.58.170 as permitted sender) client-ip=95.215.58.170;
Date: Mon, 26 Jan 2026 14:36:02 +0800
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Hao Li <hao.li@linux.dev>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
	Uladzislau Rezki <urezki@gmail.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Message-ID: <7tds765fsicczreeqckiuwpny2tolotfrnbz6jhpjrch6x5pg3@5irfwnohvsli>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=B3DI4qlQ;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 95.215.58.170 as permitted
 sender) smtp.mailfrom=hao.li@linux.dev;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=linux.dev
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
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[linux.dev : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_COUNT_THREE(0.00)[3];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABB2EW3TFQMGQEZ4BDKAI];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,googlegroups.com:email,googlegroups.com:dkim,linux.dev:email]
X-Rspamd-Queue-Id: 7201884936
X-Rspamd-Action: no action

On Fri, Jan 23, 2026 at 07:52:44AM +0100, Vlastimil Babka wrote:
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
> 
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
> 
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
> 
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
> 
> Also do not enable sheaves for SLAB_NOLEAKTRACE caches to avoid
> recursion with kmemleak tracking (thanks to Breno Leitao).
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Also, looks good to me.

As a side node, while looking into the test results reported by Zhao Liu [1], I
ran a quick test of the current patchset with the will-it-scale mmap2 workload.
In my runs, tuning capacity up or down did indeed have a noticeable impact on
performance. Hopefully we can make this tuning even smarter in follow-up work.

[1] https://lore.kernel.org/linux-mm/aWi9nAbIkTfYFoMM@intel.com/

Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7tds765fsicczreeqckiuwpny2tolotfrnbz6jhpjrch6x5pg3%405irfwnohvsli.
