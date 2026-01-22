Return-Path: <kasan-dev+bncBAABB3PFY3FQMGQENBR4DGA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aLh/Le6ycWkILgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB3PFY3FQMGQENBR4DGA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:17:34 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63f.google.com (mail-ej1-x63f.google.com [IPv6:2a00:1450:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 574B961F0F
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 06:17:34 +0100 (CET)
Received: by mail-ej1-x63f.google.com with SMTP id a640c23a62f3a-b870f354682sf37740366b.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 21:17:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769059054; cv=pass;
        d=google.com; s=arc-20240605;
        b=MOh3cFjOwG7aEIHEqnahdxE9DS4kDZC/l/yn0t03fn8nHQmhUPuYGTO9HKStxoV2GA
         jva8b/enUnc66kRpRU6AgC5qGlmwJyGzjq0lLmLu09mdiiYZFF9ouabBSJ9S/5frqvwX
         A2Jrwrgb0B5jqkkRaHqGCCDpxHzbh4VgHnT5f6PAYwUTJyCwYb+prvEy9Do14QvrhSOq
         xYiAtLD9tUBY0iz0nvIr/bdhDsq9dNcIlS572wqM0lUNji3uHxvKK3haH6LFemKxgQkm
         9Nyej6hRce+QV56fLqBDRwvBRpro/lVhwNYV45xa26L7gW7xklZk3FZwNtzy/uR1qwsH
         oppA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IxwoCi+tpEiNZ2oW8oKlM8MhJPYEzH3z2yC5rYOOzuY=;
        fh=qNthionJBYcNdciAQ4Wp+qpf+O5TufPJrtLYMivRn1c=;
        b=Wb0SJpAddzfUex8F6wCxX558r+v1p4hrMZVF28DjXeKtbmSxVRWUAinmSx1bnNv6XP
         tPLAfoMz57irk45n9lOBq/BiI8sqtqz9Kn7lKecjHhNRkcMPkiq+O6Tt96NS+hHx/MHq
         IEO/gcxghD/ZK52ZOsi8JOR4sd3Ro9ac4pykCz2LqUq0SWz2n8qAyUJuQAsLLMqZV6zZ
         I0gl/CdgLiBIxGazzXM2qs9KUOkiLIdb+Nu/bRBLXzr+4IguYWfnOUJMluePQQD2K66q
         qFfZSKb3QE15i4Lh/0m9FU1+je+tFRfydTjTt6poySRCIhxhjonRStN3S1iDtVfzMJJs
         ZJ0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uG2sPJdy;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769059054; x=1769663854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IxwoCi+tpEiNZ2oW8oKlM8MhJPYEzH3z2yC5rYOOzuY=;
        b=AwnF3dXpCa9omyOsqAO8c/LqBGxswHRmU0Fyh8fTGgzF2W4w8JqhkpTE+eSEzBYspe
         NAirn2JufoF2BAZlKiuOMFTL/ULpcfziqrrqqGaCQ25ATojcDOYvgWtCmfJoco9tv4g2
         J09UjuKfMa0+7p98uQMMNNjr8n/GlygTGSzbpwe5cPJ1MmMvcikX7J3pvDX9ydoN4IjU
         jJmxvgN7zLp54kgsj4MT5L3UeF8cLt5wV8enrHFJoAR6cVUIeF5Fc18QBMC3++J4T1jw
         neoCax1Xizu763rnaKZ9RrocyD+3YWBstKfqWbDVXTZOcne4vybQd/BmcDk4vkm8p/ip
         qdTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769059054; x=1769663854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IxwoCi+tpEiNZ2oW8oKlM8MhJPYEzH3z2yC5rYOOzuY=;
        b=kAkr/ZhlJ3xM7uQwRIf5C3bK/ILPACR5UrBYHhk/dM9gUHTipNendQ26xArT0aMGwn
         DPCfKMHvScyznCXMEe2RRJm0DymVb9DYFR5/Zza5GEkBe8w+h98nafAYHftFmbFwEZPY
         Hn782AfKABGfRUBWmyUePPPcAvS6dYxh4Xg1oYRaRkp5qOwbNP27xTObeyczPvtMAefd
         dUjj8N+V8npS/xWf9/gpL64qIH7DH29mL2vX/C4XooWUwSc0McLi6XpR4vVvO6B9oFOk
         E1drwIhYtvg3r/U92P65X9aPQo2jtIFhwKBLg1DEDGWwZADISSkaX3HlvyvXQbCpsdpb
         eA8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX5SYG4qxmlYxZkaXUwD1AiD2Yqhua7c1ibkNXaLpAiARXCQZlNSxoHXUPfxvHzBuSHlnLU2w==@lfdr.de
X-Gm-Message-State: AOJu0YwDQtJs7f1kQuzuf/hixhgvr9bH0moCDeV/CgPMO/vXYYlSGm0U
	UnQoEArlOZMerAkCMAwz7bV1h0F6nryI96MCSNHbizxRf7ICTAtoeQwv
X-Received: by 2002:a17:906:ef0a:b0:b87:39d:2bb4 with SMTP id a640c23a62f3a-b88003930damr604713466b.59.1769059053536;
        Wed, 21 Jan 2026 21:17:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H3t1ycjlTl4bZUytCz8R5YWtgd0geMr5IV9PCMNb/7oQ=="
Received: by 2002:a05:6402:a590:20b0:658:21a5:3edd with SMTP id
 4fb4d7f45d1cf-65832d4dd4els389884a12.1.-pod-prod-09-eu; Wed, 21 Jan 2026
 21:17:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqhbFLoy3mhbDRwRIfIH6d5ZG+yST1LnVpa1/ipBF3MemxzFD6SiemFC6vyjGWndI1H5Czn7CRdFM=@googlegroups.com
X-Received: by 2002:a50:c8cc:0:b0:658:da9:787d with SMTP id 4fb4d7f45d1cf-6580da97b37mr2757797a12.21.1769059051864;
        Wed, 21 Jan 2026 21:17:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769059051; cv=none;
        d=google.com; s=arc-20240605;
        b=HMhKuOPy59tX/FMEdJAXD196SI29yTFa/CViU5qka4gunRPn56mmng0droc3n6BAK0
         cuicMvmLbxr7dNz+WubmFarJPRxSr33vR3Oemq5mzI/bnLx0t8lyNDT5Q2wpUAfKsh7Y
         QW21SVVTZFV5/rBC9jmi5dQq9Xgj4GEBydLl3PivT/+VQkRp/oHYAux4j1rQThf6sqX2
         YfPudOVlA2A0IHziUTcvC0VX4BvKklRb/vMqUjF5FAwtKMrYuHaXcowXD81gNpkEe157
         Mk6h1VSLBqs6P40Dw9RUPMLg6eH53Q5MQWRdvcwLV6Y5Vigc3kQJp6cH2MhhVvu2sIlg
         0NZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=FvXyJ4IjTH3psLgpa4Edg9bKy8go2O2C/kV6B2QSdmE=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=DYpKR7WFw92jGBQXwrDR18+BFZRJAkjQfOHoy9Yuex5Gi3z7MrXykplGSh2XTGQl/J
         8xDQtkF6se0AnVm4WNpUM8idrH2XJN8/hZbpSj6EwPZmCML7p/Mt0bpSOCYh1ejWOvGK
         HoZJ8a+Mz65Pp97zRE5+ivfVTYlIx+ZGJLI5DaRIKhBpgq8gf+E88IxpdyzWc8WuiVEX
         GHR/yBTV/FWpFKGCKy6LyGjgv/LtW/NMmKKenKFoerWYKKafjQ/clVBgvDWhdwHPxy8d
         CnVX69nm9yqVcNAbpJHOxUhFXXGby84KRUSNQ2J4ZoX8NA5sw+CBXLfGvPHbXnatucfu
         fjeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=uG2sPJdy;
       spf=pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta0.migadu.com (out-171.mta0.migadu.com. [2001:41d0:1004:224b::ab])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532d768bsi396771a12.7.2026.01.21.21.17.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 21:17:31 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ab as permitted sender) client-ip=2001:41d0:1004:224b::ab;
Date: Thu, 22 Jan 2026 13:17:17 +0800
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
Subject: Re: [PATCH v3 20/21] mm/slub: remove DEACTIVATE_TO_* stat items
Message-ID: <onpv3vtvqrybt2ceuyyzv5dm7a3lt53vyr3cc5mlfirf2y3pti@vkpypvv62ijv>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-20-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-20-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=uG2sPJdy;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 2001:41d0:1004:224b::ab as
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
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	RCVD_TLS_LAST(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_NEQ_ENVFROM(0.00)[hao.li@linux.dev,kasan-dev@googlegroups.com];
	TAGGED_FROM(0.00)[bncBAABB3PFY3FQMGQENBR4DGA];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 574B961F0F
X-Rspamd-Action: no action

On Fri, Jan 16, 2026 at 03:40:40PM +0100, Vlastimil Babka wrote:
> The cpu slabs and their deactivations were removed, so remove the unused
> stat items. Weirdly enough the values were also used to control
> __add_partial() adding to head or tail of the list, so replace that with
> a new enum add_mode, which is cleaner.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 31 +++++++++++++++----------------
>  1 file changed, 15 insertions(+), 16 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/onpv3vtvqrybt2ceuyyzv5dm7a3lt53vyr3cc5mlfirf2y3pti%40vkpypvv62ijv.
