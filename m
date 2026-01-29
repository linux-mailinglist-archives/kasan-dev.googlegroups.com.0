Return-Path: <kasan-dev+bncBAABB67U5XFQMGQEZ6W5QGQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aByxKX16e2kQFAIAu9opvQ
	(envelope-from <kasan-dev+bncBAABB67U5XFQMGQEZ6W5QGQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 16:19:25 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C222B15F7
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 16:19:25 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4806a27aa31sf10651425e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 07:19:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769699964; cv=pass;
        d=google.com; s=arc-20240605;
        b=VWE6/hH4QEAKel9sKeuXsPMhJoWodk2kRjKpa0vsODfBvTHw4I1WhDq3BreOli3p3R
         FAKcnKW+GWMHjD5y4BFO9ozAZZ7tPM4ESJCNXN+t7TS+M1PngjZ0rqd9N9aTMaxuemhw
         xOm2QSLejxmUVFv00kUU8c5w8wHgnn0zGuaD6RtOvLw+cBOOoTo1vvRYmD/g7a0CNJ4n
         07wCD37QYbcZMOn+CN/Z4/8Y5f2vzus7Tesl3hDpYaobdswrj8oJXFU2f1T/x1OqMkqq
         chdrSw8LBna03RclU/VCRBmhW6UP5V0vnsS7sZ7GpXRHRjATq0afvIvmrk94tBbH8bfR
         G3XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=hrIRNDJzJe2c19d2cRf/rvdk/9wWwKCqgeeIKSLqfU0=;
        fh=H10KGdAWP7odI9H9wMoonRCiwh6xatKYTHNNGAJhGQw=;
        b=GegKMgE8OmDFUNCJOeSk4b4CR7Eg264qB5OZ/mLcF0/JlMoqk3T2MM7NahoCdDaSJq
         7fe952Oc7K/aR+c8mKXd9usv3mKlNYl5x3RK1NTc3AZwO22Irk6ReAiPSPp0ZYXSoBT+
         UY2UI3bHePqWEjJ9NmHUkn1HhHHbCNt4W6+rcAIrjM75gR4b1EBiUH+9s+no2nR9rjES
         mOomD9c0aJIEVrUQ5EAL44165HaljhvQSGq3xs4BaV1dT7PTP7Nn1HMT3oQcAgNMwMcj
         RnqzilXsODwwesJTNVJ/LNYuPoxjdqWPtgrB0xrirXk/B0sjDpHsCvoDXUpqneZtefPe
         dOiQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BR3wjJrj;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.189 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769699964; x=1770304764; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hrIRNDJzJe2c19d2cRf/rvdk/9wWwKCqgeeIKSLqfU0=;
        b=psZg73ZBjmYqSJyUX4mHT6hvANo2XiK3GirrU1/ssvM5PNO8vNTVN7tUA3st5W89/5
         bl8u0SOVApahc4+qwATUA7mPf1vCntCi+fOENUV3Q0Rlwvm3bAzPzaCk+pumqoANxFAp
         bMk5h2SeRySg0YCbzLZRwu7kdazv5bWG7BqsXvhLTIbns+ro2OkrQJPX6qq5VmRhLvI0
         Reu3rQEeQn/olBuPIvf2Il9n+iGdkDiELG49XfdkYlg/e1Gaw+BbdXtsS9KDP/soX7Fa
         Uc1Um5EplA1gSjy/p2MIJtIwoxtity6d7UoQYYPwJiK13QxvlRSIPs6QF+f8KoRjf3SI
         J7vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769699964; x=1770304764;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hrIRNDJzJe2c19d2cRf/rvdk/9wWwKCqgeeIKSLqfU0=;
        b=f8+viWgOBql7qm2ko/eFRXAeTrVQJFZ4A5NVaZykCs+iCWe0j/TfCbzPLZj1Oeqgdg
         8jnHYC/D8I/jTg4+ShCtOsIHpl0yxswhYybCxci+2/Ja7CW0yj5lsz3qIyu1oBTltjH9
         eIApVgI6MYYnl+fTsBx4oU2SK3Hpf1VMm9Ywj32k8TeApuVL9Id3lU7kOTJJbXTzPgfo
         8FcISnpGAemAnILapWUU22BQqIeT0/oxz1v5r9uKs8NglPrik58zJfm2s0U4qH4t5Nfb
         Jc7yWsX7rogsEERA+n+F0k1j8s2KMs3opMUNzTK7u+UK6iIoRZpRRviM+Xqdwq3IEgMW
         hP/g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXk3Cn896qZSlxPnxctG8sec+P4L/Ej3J3O6jHmTAzqAsEnHWBr2seJYWpVrgN6Qn3jhw+bOQ==@lfdr.de
X-Gm-Message-State: AOJu0YxgNKXuNNhIADP0lZHpLoZQIVEXKZSfeJEsXkk79Ek4x5f0Er3i
	o5oa9LNfVT9oWXlFDLp5JOpCFowMWuWuZe8Im+6VJtc8acqLgVV9Ls2v
X-Received: by 2002:a05:600c:474d:b0:475:dde5:d91b with SMTP id 5b1f17b1804b1-48069c54142mr124925025e9.17.1769699964190;
        Thu, 29 Jan 2026 07:19:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H1/sLd4Ofspix6QIVH3vQ8Il4nMHRaItVtw2keK1E8+g=="
Received: by 2002:a05:600c:1c24:b0:477:a252:a832 with SMTP id
 5b1f17b1804b1-4815dca1372ls7417465e9.1.-pod-prod-05-eu; Thu, 29 Jan 2026
 07:19:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW3TIn52rDCRNlzkzZ4DoxOYr+rpJGRK/o+FvzaFF2CuBSp+OXhNe0kEViyfcrtJ1C2Pd3/v/8ShbA=@googlegroups.com
X-Received: by 2002:a05:600c:3154:b0:477:5cc6:7e44 with SMTP id 5b1f17b1804b1-48069c1a7ebmr103261785e9.11.1769699962348;
        Thu, 29 Jan 2026 07:19:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769699962; cv=none;
        d=google.com; s=arc-20240605;
        b=WNRe8HWm6hQ5CjJcFpyV4m3tTdBZwfyvJhOlPGk/ndHFzGaimPek4idvWhfTNFqTS0
         5h43jPwF57xvDLxPB5DKemyETXkxSdcaXTlHHgxLeLrhEjC1gbGLhlzmajyrQEnD/K9k
         pOwf33Vx2SQ50E4HSaIUI6vM4QvNB4n9l7zYSFeGEiB3167i8Zrhrskhl3ACchr99XuO
         yLR0VMtr5SH8MsFkYZyH3S+EqbftWcg6y0dYJbRb5nPJK/xw6yK1xc7IigFMLtf+l8tn
         2AOV/gDBdRe8SFwYrKEPRlScRotOblVMhoLzHyNYXSBceBgqW+wvo8q9B5XwYnmYDdOn
         0jlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=lIp7jKuWgekJy97efthM5741IP+QBaVVTDcUYnJ8gmc=;
        fh=IJc/xULCf01o48qWj7VfHKXKmbbWC8yCQEzHfREZ7bs=;
        b=MOftHdlI7vflrb3wvH/ZBZR1EGsYPN36GzpxWwdc2EhSXEhSuaQtovl6YmfV/Rf01Z
         Gsz32QTQ0ZEpF7PcbSJKfD5NiAzJLJeROE4i22y/9WE/FjhclnVKOOmGvFCVJeSz6DHT
         LOtshwbgM66TbVpcAg4JNkOeIJNWKcXoYxOyIL67g84kbrvLsJLCsDpo/WZcjH172hk6
         e/y7M0A1EQbHSRp7iywl0VrUjcQ5WDhl7ZrhZeIzKDiEwXWmjuiWXGc+tntgfoCSrpuL
         DruXW6pRkbnVxueQZgDqtQVc9I/Z9418iyaJWPfi+Tg0jgxou4iBefFVTcdUhc06keGA
         Hm5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BR3wjJrj;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.189 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta0.migadu.com (out-189.mta0.migadu.com. [91.218.175.189])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-481a5d80f62si56175e9.3.2026.01.29.07.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 07:19:22 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.189 as permitted sender) client-ip=91.218.175.189;
Date: Thu, 29 Jan 2026 23:18:54 +0800
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
Message-ID: <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BR3wjJrj;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.189 as
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
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBAABB67U5XFQMGQEZ6W5QGQ];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-wm1-x33b.google.com:helo,mail-wm1-x33b.google.com:rdns]
X-Rspamd-Queue-Id: 4C222B15F7
X-Rspamd-Action: no action

Hi Vlastimil,

I conducted a detailed performance evaluation of the each patch on my setup.

During my tests, I observed two points in the series where performance
regressions occurred:

    Patch 10: I noticed a ~16% regression in my environment. My hypothesis is
    that with this patch, the allocation fast path bypasses the percpu partial
    list, leading to increased contention on the node list.

    Patch 12: This patch seems to introduce an additional ~9.7% regression. I
    suspect this might be because the free path also loses buffering from the
    percpu partial list, further exacerbating node list contention.

These are the only two patches in the series where I observed noticeable
regressions. The rest of the patches did not show significant performance
changes in my tests.

I hope these test results are helpful.

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q%40l2t4ye5quozb.
