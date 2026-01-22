Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLOBY7FQMGQEY2QLDYA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id wNmjEq/gcWk+MgAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBLOBY7FQMGQEY2QLDYA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:32:47 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id DF0C3631F7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:32:46 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-64d01707c32sf899784a12.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:32:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769070766; cv=pass;
        d=google.com; s=arc-20240605;
        b=BlOLcxGrPh6iqNPtC9ZgUCffZ6r+TgCksighJomR315mcM8k8Le73joMu4sVqylJyv
         pVIMwLXTWrMvbFw5yJkIV2jmlt6fQI1kza0YM/2w5RZc9Yl2JfcpuuTMe71I0kNhmfej
         aTxH0NoAVSSH0TvQDneEywg+mVmlZaIkuBVOm7t8tQ+CDfcqO55x6roQE7FTR02vDwVB
         OOjGYCaqbpnCCPSXxMX3KxwrVFCKAvZp6DYJUoVgqQi/lG2G6wHShtcIqV49hvmLMzSp
         bkqCL2Zk1Pv9RqJE0TLiq13dkAaTES2phjwNp5i45R8mOJy4mpZOFOQVhGeQvY65Z942
         rLhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=5djXXDhE9lGZ3bJABH9Yk9bN3O6/5SvYSC3byUfU0EQ=;
        fh=Cnqv2FCC3d647MY8I5MPW0jwqpmshRvVhe/G/UUepXk=;
        b=PkuTZ/DXIEiG2DSd9jENfB+ISIk0QdFRs9+eHLdCYHbeak4q9bFIHzBsa9+Ln3fZwU
         nW6YIqT3/YXE1UouLS/cduWZ2HMKjRcmko7gGdIR+cJkKDasDtkmrg+Z6h4AvbCfVF/s
         HjE9LCUdP9kLqG8QhVtXcHseKbjw7zlDv/skYx7la0pFwwxRPg65VsFo0dsbJkRvJiQo
         rSTyF4ql4YE1jXk9LT9wnhyPvUcNjjyKWMFIpOaAyTYzZ3+r8TI/9BLRRt1lJS24RfBT
         V0xbtrlR05CQ13z6l+sdjAd68hkFdGxkuKOAanVIInsMEKSWIX7hrADza7HmDMcFvBAe
         dJIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CyOHD67W;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vF8bn8e1;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jd36sMSt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769070766; x=1769675566; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5djXXDhE9lGZ3bJABH9Yk9bN3O6/5SvYSC3byUfU0EQ=;
        b=umtN4lIjYN2W0wx69wSqdFmG1dzDielZyzvA5Og98ST3HzEhxVk9Jjliob9J3fOIkV
         rFSnqawEIXfpwSRWFJDLXBg3S+iDEqxlQseap2nkRJGyfAWibdS6jCeeuqKaeCatJCjL
         y0ytVEBVYyoRissxddXxXySaU3pOOv01VlfhbJm7a3AbwH7PA+JLa7+VrBxWVkf4Zyoo
         oF04cDXSPJInnEbsUvfnOa7P+sttFG2VqlBg1wJNXx6Ji8FxdTDYHHkvJtHcauARTgFG
         y+3h3hoMMJT1XA/XuNJqOnbubU85W6G/s5YCYuhhD9jb/7zDn6JW3msXWKv2V5dNiQ+V
         vOfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769070766; x=1769675566;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=5djXXDhE9lGZ3bJABH9Yk9bN3O6/5SvYSC3byUfU0EQ=;
        b=bDC5iIveRbXBoO0+T+qaIpIzObZlwyt0yfZlYx2yuJz0IggXcIWJgk0hAtIAGhriU+
         3Lu3pIkmbOgRizC+kLG7n19t1/LY0PEB2yImF7sBuSJw4MyQHn8X+pCqIIfBCJqTdEKE
         pfGVTNRPvz1/FAgaJJLiB+85XJf0M2sSHViTtWj3urKqYvDJLax7T9g/spDfvg/Duydr
         Uti7HSeKccqOMvt1S2hD0SP6NnOWzjncjU9spOTTsL0b7TbLoqyIJ9qtAKdWrS8WubBX
         2UJJ55V7Logvu75ohzNeaYMJbH4HodSNjNbHtskdT61Cw5eIncOyy5HVgWgRlwhHeLth
         78iQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDVaGii6DqjGOffQKVTi2pd1Pyo5Jd2f31ef+c7XEvJ/EmMxUNemPvHCDY8KCJWzo6K/u8gw==@lfdr.de
X-Gm-Message-State: AOJu0Yyv6oFvVPZ4QGx0yWbo+cjO6H4N+mu/NL357q78+c4xgLHO2zo3
	Gxl83MRwmTkMJF2tX6vkZrYG/udlavUN1sZqKxIeuNBB4+qo9Q3C83GY
X-Received: by 2002:a05:6402:401b:b0:655:c395:457b with SMTP id 4fb4d7f45d1cf-655c395480cmr12281504a12.21.1769070765920;
        Thu, 22 Jan 2026 00:32:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ht1Sf0lFlSOdJiIpjZxJPbeXKMsCEHNeZb952RULQDhg=="
Received: by 2002:a05:6402:42c2:b0:658:1a1c:69d7 with SMTP id
 4fb4d7f45d1cf-658329fb6c4ls665381a12.0.-pod-prod-04-eu; Thu, 22 Jan 2026
 00:32:43 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU0uKwQmOelZh6pDsq+ihvDjveARnjtjcGpoidsX5DQp35L9ufPF7udTIklkb21qUnnpDUhjlvOjfU=@googlegroups.com
X-Received: by 2002:a17:907:c22:b0:b72:b289:6de3 with SMTP id a640c23a62f3a-b8796bc4f7emr1911669366b.58.1769070763741;
        Thu, 22 Jan 2026 00:32:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769070763; cv=none;
        d=google.com; s=arc-20240605;
        b=PKEtjPL8kKxLoBEBR6TDvuBnsOZWMtqpBKDVV3W+K9cPokO6U+k77WjTe8zIqPMhHf
         Ttr2GEpoPNHaiEvl/b3lF7pVBT3QGtvO5eW5ZS8/nLQcE4qzZ4FM86EmO3Vv80RrdOC8
         SXTBvDtUOKgT5z5t3AgDe0yx+PdaeSiF8f3JQnUaIsoe87Hn2AMAHUUeUb6q0Mw7NUJ7
         myxnISddM1YkLumoVt5GhVgcuJdu5+wNvguhToLT2CDjkKP8rydFtP7JsarNYTBg5+6K
         uaYfYrESHHfw+Y3/P87sWghQugUwingnuvFDu0QceEc5q7/BwHE+X0plzL4RylhpCCrT
         ebeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=0aOmUmdAgwAgA81uoRZYrgnrXyhYcc/zOlOcDMoVAz8=;
        fh=F0Ugs/KnYVMrxGPEYvOB808vqz5Ww/CfFkiIgtC+gfU=;
        b=eMdDgPxKGpOjgyAgAnYrKOMxb/DcW5B2wVxzrhq+FTYCu+Deecat8QQjuTY5QXbw9v
         ByRuFs7lCmpMyoJZ4AKMyT023GFyHRLRXlHRdLpISMzl9iBP+W+lj7VOgGHeQOEsnjoQ
         qyIDqnClRen11v4bm4NJvoSs1hiBDVY+dtwubV6pkWwfsTAVNTd20FQAWvM4lU7FSray
         3MFnw/r0EyCBNO/VbaSmLKs0e3Xlbs2Gx5bn/yEdgHZuB2u0MY7ETVPS7xwjsXQLR30L
         usbQgyZkoHMhQCRc93zqn4V+CerQP5XikSHt+CfJUtuou22BkTKOp1qTp5XU3qhFDd6L
         0gmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CyOHD67W;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vF8bn8e1;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jd36sMSt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959e0a04si27761166b.4.2026.01.22.00.32.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:32:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id E9126336AE;
	Thu, 22 Jan 2026 08:32:42 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BA1193EA63;
	Thu, 22 Jan 2026 08:32:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CcwWLargcWm/aQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 08:32:42 +0000
Message-ID: <317f1725-5fc8-41bf-95cd-4f85dd1eb137@suse.cz>
Date: Thu, 22 Jan 2026 09:32:42 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 17/21] slab: refill sheaves from all nodes
Content-Language: en-US
To: Hao Li <hao.li@linux.dev>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-17-5595cb000772@suse.cz>
 <gmpxnzifhxamwnngr6holbcfdd42fvuq2xtqrqvdz75zv6fb57@hxbmcgfxtuko>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <gmpxnzifhxamwnngr6holbcfdd42fvuq2xtqrqvdz75zv6fb57@hxbmcgfxtuko>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CyOHD67W;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=vF8bn8e1;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jd36sMSt;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBLOBY7FQMGQEY2QLDYA];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:mid,linux.dev:email,mail-ed1-x53f.google.com:helo,mail-ed1-x53f.google.com:rdns]
X-Rspamd-Queue-Id: DF0C3631F7
X-Rspamd-Action: no action

On 1/22/26 05:58, Hao Li wrote:
> Just a small note: I noticed that the local_node variable is unused. It seems
> the intention was to skip local_node in __refill_objects_any(), since it had
> already been attempted in __refill_objects_node().

Ah, I'll remove it. Such skip wouldn't likely do much.

> Everything else looks good.
> 
> Reviewed-by: Hao Li <hao.li@linux.dev>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/317f1725-5fc8-41bf-95cd-4f85dd1eb137%40suse.cz.
