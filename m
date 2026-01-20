Return-Path: <kasan-dev+bncBAABB37BXXFQMGQEFY47OPY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id gKWpHEevb2lBGgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABB37BXXFQMGQEFY47OPY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:37:27 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1008947BA1
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:37:27 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-65811f8a102sf184737a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:37:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768927046; cv=pass;
        d=google.com; s=arc-20240605;
        b=UUF+YQIB79I2kLHWurQIeJPOYAUqH1T8dAi7/3572Zt6fKXt6PL+Au4cxuPwlsefbg
         UbNLDaIVOuOjuASNr/ebunGNnqPlw518PSqwA8y5iuVHi/mim1VsxsZRMcER+7QRISeU
         79Ekx9kuuBrHD78XqrA1ck84O6h0TUw4Wj+55hibrRNzjVjrORvf4vcmjaJtj9xoOOuX
         y2DnTM6gKpwz+wNIZQtmdylx/Ec8joL2RvylXfq1phgmyJ1Gv9TGqn9mFiD6b6ceLAbb
         9uDZIpeSky/l7wTnjDoEeLZmeGPzm7iA54rBARaxlYkpjn4iJMgqBqs+hZu/vixjNfQ8
         x7pA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Y12rnKeViTjVcZc4Vz7sO/X+nQrg3+OeuMpcKsdAhyQ=;
        fh=enAeonm/ULWt4EP3Og5eKjo92FjotaZGalIPVUVGbfg=;
        b=DBKvt8M3Cra/gBOza6x1Rok1AkOrwkzs4WREyAexLMtMP8cdgVAMmrUurz1y7v88Nu
         GKpAUambLcCMuRvUrAiUO1r6Wao0G5fCCAwkc9GR4ECBId8CojymMLlWa2Lg6XdNMESA
         jo8eHNJrp0Kg5W0EYM7UbYDuoVQoWX0gq96hCUhi7izXQKmN4U5ox6m66D5WgQ8MRXot
         xQ+StvEI1eKyithXLdtb2WVBNj0h6LrfJ1x8X9JAJA1SKcWTJMNlcI6+orYTaPKcfxtO
         cs+h7OftBSUNfpZESWd4dyCtgfw5+VG4oN4pzF5EErtojLJVs31PA+jMZZmI6QkKlVd3
         EeNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=q4pTiUAf;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768927046; x=1769531846; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y12rnKeViTjVcZc4Vz7sO/X+nQrg3+OeuMpcKsdAhyQ=;
        b=LK5Iy6Y0dXSDseiCCJj961g4t2W61g5WeHnehZ5zDGJJt7Z+tEtoHjOIxpBDhalbml
         4wCcQ84XzPlnzW8mdmyEEaAQ1njeKr+V662WLGiav7bnL54+uDLzdbpYHRIDQTXvBs4E
         eXyHQng2hROh2MMIMQXGHCAZ6geT+uQXM8BemI5qbR97Ry0NNgvD6W4zxRYdkVjMUSFu
         9/vWC5wyfPnp0UNnDAp1W9t+nvkEm3v/eTwnF0fTSYP8uxc81ysj4a2yt3e01F3EGbdZ
         1FVLhXKV8osIviOvfY3M8AJ87dD6ammZY+E/p0U6yUk+B13Y5YwMCqwSmEu4XCdRjnnf
         104g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768927046; x=1769531846;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y12rnKeViTjVcZc4Vz7sO/X+nQrg3+OeuMpcKsdAhyQ=;
        b=KWHDGQ6WMEtCrfCEb2/x6oRjfcbNEVWhNFox0o/6it84W0+ITfSw/frXAGG/rRM/w0
         QSpufUOgP1DEp5KOZVuGlS2TU5wRkjGrMsD4ZjKD3D1Vj4AtygVBA8uAycin87kXMMvL
         Bn7V3q0Gpvq9BkbReZdhFL4B5qurS0Phfp0jO76ITzohTv24VompMteyFwuAfgJrSd9B
         WqFDfHWHnz94AjGpQLNrJMZ4Sgx/e3pOlOFxQgYl0048L5f5s9X9ooYRMKtE1K6DWeJ0
         yQ+hyad7sBkAlMnAEbItRQmYkTvrRHFche8m94tkfRHtUNKcCoPZxZpN4bKyGU2Q2Cws
         Apdg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/5d16fOxKSZYVGmSSBQcK1xSWzc1KzBVLxW/iW9s1G2dH8tJPn9yk85RavCJ8oyj4awH14g==@lfdr.de
X-Gm-Message-State: AOJu0YwW/pHickiz64FB6VWVvPygdg4gNty+ATr1aZfsZKQa58zUQmuD
	xbVBI6MXlH0YrUyLfBdRx0+twU0nnAaHT2RzC5jHyKdcdR+4IW5PGd15
X-Received: by 2002:ac2:4f14:0:b0:59b:a040:2ed5 with SMTP id 2adb3069b0e04-59baeeba0f5mr4734022e87.15.1768911087833;
        Tue, 20 Jan 2026 04:11:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FxvYqV3DY1qdKZ8JehND98ofg+OvYYO1PDy4Lq0U9+lw=="
Received: by 2002:a05:6512:31d2:b0:59b:6d6e:9887 with SMTP id
 2adb3069b0e04-59ba6e4edcels1758756e87.0.-pod-prod-02-eu; Tue, 20 Jan 2026
 04:11:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWJeL+DY7BPw7qHcdUUONXCdu+hrJrYUORHutMjocfKrQM7Nayf2KnqpepG1ogkR4oohUsQwTYjj38=@googlegroups.com
X-Received: by 2002:a05:6512:3e18:b0:59c:a027:b168 with SMTP id 2adb3069b0e04-59ca027b457mr3407774e87.30.1768911085778;
        Tue, 20 Jan 2026 04:11:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768911085; cv=none;
        d=google.com; s=arc-20240605;
        b=P3dE3U86q+32FTNEQzG+0Oc61NKR5paDzovc9P50D6gRXA//GL0GJfdrKM5FkdJX9o
         RoemroWy55k6eJFLcBUgNGrHMmArVdq0lxYJ3FO8CGO+4u4JQHD3wSsw2twuxjPrMgWm
         /TbNN9fVcTLxvrQ2Vlwr61Ug5iFGC3P8KogVuCDwxjaE3+v0sNFe484KC8fkudY7jrki
         eOoZy9XRZI/bClZqSYOhCqCZ4/RZa6gspzgyJhY5OnkUS5dOpL9/VX6KYRDngFCpC/EL
         xTiBJ3wzhwOYJKHSHbs0CW1vhrulZei4l4BDTG4E4qZSVfix4rADUolj6NByl+F30/yA
         E4Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:date;
        bh=ft4cfnsazH2fqh82dag3UKKoVEEmk8hPCPptOiIZ6Ls=;
        fh=2eNRZ9ECquILDe9T7DsfDKzbtYQIgOYM00xcI0sJ8bg=;
        b=isT0ekQYFZ7kHHSaTP+w2g8O5dYbNfTea34Zt8rmjYZyWPKZ27oQZsXMtDsIc/hFvZ
         SWfkRHrEGzfn0wTF9gnZYq85TDlA+3Sm0F2SOwvNM1MC5gZ0+H4MelfzVLqDTOjlXX7u
         AfzsOzhuFbibiVOopbWuEq4rE4rU+PVxFFUameef4d3Xs0IxynLByUtWr8KIpGsCtw5m
         AFuXGxr9nGbve/e8oRqDPpaBh7Z5UedXBmO1ztDH1eosxdGHGYPFAZ3F27HN13A72A9S
         nlSXGCgMnaJ8EtpAQyS+dfG18v1fzeVnvvDLdeDYwBn5ucjUQF3VmSJ8bhupzdLrJb9Q
         StPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=q4pTiUAf;
       spf=pass (google.com: domain of hao.li@linux.dev designates 91.218.175.185 as permitted sender) smtp.mailfrom=hao.li@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-185.mta0.migadu.com (out-185.mta0.migadu.com. [91.218.175.185])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384e285a2si2885561fa.5.2026.01.20.04.11.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 04:11:25 -0800 (PST)
Received-SPF: pass (google.com: domain of hao.li@linux.dev designates 91.218.175.185 as permitted sender) client-ip=91.218.175.185;
Date: Tue, 20 Jan 2026 20:10:55 +0800
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
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
Message-ID: <3vjyq6wpkvaczzgl3r2qhwi7zdluh6zldejjxnki2hft7vxr52@g7gn4lqbdi3c>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: hao.li@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=q4pTiUAf;       spf=pass
 (google.com: domain of hao.li@linux.dev designates 91.218.175.185 as
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
	TAGGED_FROM(0.00)[bncBAABB37BXXFQMGQEFY47OPY];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[linux.dev:email,googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,mail-ed1-x53b.google.com:rdns,mail-ed1-x53b.google.com:helo]
X-Rspamd-Queue-Id: 1008947BA1
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On Fri, Jan 16, 2026 at 03:40:31PM +0100, Vlastimil Babka wrote:
> We have removed the partial slab usage from allocation paths. Now remove
> the whole config option and associated code.
> 
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/Kconfig |  11 ---
>  mm/slab.h  |  29 ------
>  mm/slub.c  | 321 ++++---------------------------------------------------------
>  3 files changed, 19 insertions(+), 342 deletions(-)
> 

Looks good to me.
Reviewed-by: Hao Li <hao.li@linux.dev>

-- 
Thanks,
Hao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3vjyq6wpkvaczzgl3r2qhwi7zdluh6zldejjxnki2hft7vxr52%40g7gn4lqbdi3c.
