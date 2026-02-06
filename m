Return-Path: <kasan-dev+bncBDXYDPH3S4OBBANVTDGAMGQE4LGDP2I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id kBOmM4IahmlNJwQAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBANVTDGAMGQE4LGDP2I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 17:44:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 761B31007C1
	for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 17:44:50 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4803b4e3b9esf7129905e9.3
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Feb 2026 08:44:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770396290; cv=pass;
        d=google.com; s=arc-20240605;
        b=KEBOIEWuCAvwb3NmGeGxeqEmufKFugicFahMLel9iYHUoGVk6wTERMttkNoowYlEKR
         j2/ncIsVytdlFVoUNdopVLInxmSupFbjjbNRrcrrjIAy3lzChEkQ1SqyHLru9XkX5UJm
         vOdEDeJqlQhaiQtna7wcbnse3DrIdHAVVSE2J4Yf/2HP0Hza/A0KvdKxJbsk+euV4BAF
         4HJkDZgvzsRUBoeoRviYV7d3VyOvoJ31i3jnbRWrwmB7fmtkZE7xNx4R9wVRjZyJclhT
         XU4QpzsXrF3I1Fq5bWY88iafLmqkZLRCahyRTiLKdE7XXEwEam2l9SVVRL15Ouc3oP+i
         MKGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=/uBbaJfh/DmW29a0b6sGl/Ogu5ChPlQzlM6vHu8mbyI=;
        fh=CSnLdatFULMyXiiH7jEoD4c79lU2bDa1ORA3wyObzlU=;
        b=VIaZ1pCbxT5qcgLdM6opi+v8HVmJU2F+3fLAc7WFUAcoKcLV0WCoeEpwjMX0RJ/zLx
         Y99wQqTphlztDcCapzoy+p6To0S6Tbd2wthuQHKeejl/5zJ0j7+fggQkjccCFMdEmWTz
         WRxcuMNe3DVFrifBvNzvD2REWA30+X/AgFZDKB6sauFEGeKC2V9wfiMj05DrFMgwJPnD
         9XRqg7aZ/dtXjTdekke6fInmVUFeDm+gEnkOj7HN7A5RYBEUZBtvQlqqJNffCUTVH9Nk
         PcCR26NGIIjlsUJaJVSqjkhab059iR5jJKAEhJnaFQ1cw+sqlAUvUD+x4xWjPMjlb9Wk
         a8jg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="JH/1Buh9";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oftyxcvz;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770396290; x=1771001090; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=/uBbaJfh/DmW29a0b6sGl/Ogu5ChPlQzlM6vHu8mbyI=;
        b=AuynaoJynWOwUs3+LZERM0JOsZPGz62TaBvraCvUuS9WV55unSX96jCTyp+fFawL+x
         HvzhIhhfKsiU5Kj1ZsrLB050abfFhbCCofLK86VNtQTch7SRJf8+ot3BtY4JuOcMWjmL
         7kzX5kHMrBjWZQbvYf843u4SsXphzr/t0dlbBudvF7veAlk2ZXOcAZaL9h30kc9/bejW
         bzdALqp7wPjf0Gg0ft9CU/36+wDpcWL5LSPV9R9PjgLSLuetFgxwcjw3fTVGEIEkGqc5
         yfDjQKMOLz9l6k54lV4f3yy0VNF71QHWmcih6G678Qe8Mi8oWXyEqYe3/Dis4S/rTQ8I
         Dr0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770396290; x=1771001090;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=/uBbaJfh/DmW29a0b6sGl/Ogu5ChPlQzlM6vHu8mbyI=;
        b=b7DXSLPmAHBOVCMc/ryOQCUu3W1PlR7aeGleFgY2PGPKyNbb1+4laA+Jubk5QQTk8V
         mxYdgS0GEsljYbpclohwK90eGDUFS7kFNSKrrbLpKbeO8OEqt0Q7w2QipVWPTNFN/olC
         EB8GTWDvm1KwOzlWSkcKovIYaenRmQmj3r71hmT/V9gRD9HGhbQEkEKmT8rkY3RgSHZy
         wc9D3j6O0kL1zpouGZJdxNpRpnzHxIwIBsuYED8N7cTVIJKOx9EUM+fEUFQPHp6HD8qw
         CbTTdaqOf/k0jX5DlGZlu7qc2qmx2qsD6cPHAQvsGp2SZO5tJNvlPoyqB//JgLGzNHC4
         5fww==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmsE/Gj9HACwmGmCPkedXWLaeqqA+x5Y/OrNGjaT+oiKyuFvZUR7x749QVX0e/xnnHVrEQ0g==@lfdr.de
X-Gm-Message-State: AOJu0YzJ+yyN9CPboQj4lbk1lFv7T7ZBYeS4FHZJMaqmAj72+6vDI1B/
	vnPv46LnWs/xqyp7+5LKGyg3qGDNZam0fZf6jM9f6rhyVQu/AjAuRCKT
X-Received: by 2002:a05:600c:8116:b0:475:dd9a:f791 with SMTP id 5b1f17b1804b1-4832021cb5emr45519065e9.28.1770396289533;
        Fri, 06 Feb 2026 08:44:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Fd5+cPs0Nti6OR6nM4B1znVkDqg/QHCP0cuxgl7Oq8YQ=="
Received: by 2002:a5d:5f89:0:b0:435:95d2:8af4 with SMTP id ffacd0b85a97d-436206ef03als1520952f8f.0.-pod-prod-04-eu;
 Fri, 06 Feb 2026 08:44:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWkCGNrH4iER1awAYbJNB/cGwwGqSnElsK5ta1HDsnDjyKBh5VKk0S2q/e9gImQOFsbZkvxpDuSF7k=@googlegroups.com
X-Received: by 2002:a5d:5f91:0:b0:435:9770:9ecb with SMTP id ffacd0b85a97d-4362938ef27mr5551607f8f.56.1770396287282;
        Fri, 06 Feb 2026 08:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770396287; cv=none;
        d=google.com; s=arc-20240605;
        b=VLtsgdiNhON8DuTdF6ROKRy/M5zLg8aphHs4BJj9z3ot4a9JsSXr1dlLYTf18Tv+tB
         8zrs0ooS6J6+HkNoOB4m3I5L9Xa20uSttpmklu9z4G8xvVf0Xv/BBRcedzYGck1LgEcX
         UPx1+2Kd0dNdZJ8e6nBp1PgMftTHCDBzZBps49Yqg+2sWeSorrW+LnRx8E2jGugO5BE8
         MPMs9Ag5e8waYL7IbQ+t3XidZwvbAO2mIwYwBOt6+Fbu/LiOtwfqlZG8Z+zR++mcBwU3
         Eyduj5ZtLxvz9lOidzHtkvasVQfFXdBcnd/7DcU4/h+u4U6NS5mgsB5XLuNN1SewAEYG
         /IjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Iae96BpziYNnFm2n487MAGMR4usXUTx6hjnk1gdR25Q=;
        fh=qH2A3DIjkzmOCbLUnIl8mudgxkrwNG+cmi9IjKInfHQ=;
        b=UxSRxaaqYzMuQWPArAqBPmCq5b0/XVWp3dRUYjsN9KR17Ok3Bss07FHNtl4QT/ZS55
         PTQvrAWh/SVZIVo95Z/Sg4LbUfIpz6aoH8poDt0kTwdNXktSm89lMRpRqCqH3kI/MVt9
         mQ5ACvYIYL+I1H/sMyNwK3rhPSRl2xZuB+oSNLLhzZ7LrYvMGPD2K7ADzlqCT5bqnjvl
         GNT453hi6YVdNwLnv0U9IWjBtHrsmw7MmCRhFqIrV6g89XrrMgV+p/2ywGGoYIuzt0Jq
         kXTtq1e3gpVIor+WR2++NAeLJtoiWYj0DC8D+UlsS9dbdJvuIZYSh6g+XOAV2aL8kkvI
         DQrQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="JH/1Buh9";
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oftyxcvz;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-43629a6a295si63502f8f.6.2026.02.06.08.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Feb 2026 08:44:47 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id A88F23E6D4;
	Fri,  6 Feb 2026 16:44:45 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 739CD3EA63;
	Fri,  6 Feb 2026 16:44:45 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Itz5Gn0ahmnxVgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 06 Feb 2026 16:44:45 +0000
Message-ID: <699982e5-6660-4e48-be57-3ee7326a20d5@suse.cz>
Date: Fri, 6 Feb 2026 17:44:45 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
Content-Language: en-US
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
Cc: Hao Li <hao.li@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Petr Tesarik <ptesarik@suse.com>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
 <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
 <665ff739-73d8-4996-95e0-f09c3e5b6552@suse.cz>
 <2abde505-1e35-8d74-2806-7a3cd430e306@gentwo.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <2abde505-1e35-8d74-2806-7a3cd430e306@gentwo.org>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="JH/1Buh9";
       dkim=neutral (no key) header.i=@suse.cz;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Oftyxcvz;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBANVTDGAMGQE4LGDP2I];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,oracle.com,suse.com,google.com,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,mail-wm1-x33e.google.com:helo,mail-wm1-x33e.google.com:rdns]
X-Rspamd-Queue-Id: 761B31007C1
X-Rspamd-Action: no action

On 2/4/26 19:24, Christoph Lameter (Ampere) wrote:
> On Wed, 4 Feb 2026, Vlastimil Babka wrote:
> 
>> > So I think the performance of the percpu partial list and the sheaves mechanism
>> > is roughly the same, which is consistent with our expectations.
>>
>> Thanks!
> 
> There are other considerations that usually do not show up well in
> benchmark tests.
> 
> The sheaves cannot do the spatial optimizations that cpu partial lists
> provide. Fragmentation in slab caches (and therefore the nubmer of
> partial slab pages) will increase since
> 
> 1. The objects are not immediately returned to their slab pages but end up
> in some queuing structure.
> 
> 2. Available objects from a single slab page are not allocated in sequence
> to empty partial pages and remove the page from the partial lists.
> 
> Objects are put into some queue on free and are processed on a FIFO basis.
> Objects allocated may come from lots of different slab pages potentially
> increasing TLB pressure.

IIUC this is what you said before [1] and the cover letter has a link and a
summary of it.

[1] https://lore.kernel.org/all/f7c33974-e520-387e-9e2f-1e523bfe1545@gentwo.org/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/699982e5-6660-4e48-be57-3ee7326a20d5%40suse.cz.
