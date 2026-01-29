Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBHZ5XFQMGQEO3ECTWQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mCjvLIZ8e2kQFAIAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBBHZ5XFQMGQEO3ECTWQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 16:28:06 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 53DD7B16F1
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 16:28:06 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-65811f8a102sf1148452a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Jan 2026 07:28:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769700486; cv=pass;
        d=google.com; s=arc-20240605;
        b=NkE0eQ4lMo8P46TLj+vsQOAaaFwhTMPfrtQzOyyJnJzwNE38KwP6faA2ggFQL3kCOo
         By95qC5gsDtAM3UkQEAVK3hWjPO93lWOE7BVMkDZBWShMl4B3i/FyJzSlwEgSYRCb8s6
         8x8v1zypMXNJEEepy2Jukoo3ccCiwGDGDzLt2cG9ceCLgIV9Pz4Oa5NqjPoklxut3Shy
         xWyQYVdmVxDg+EjA90PXbA9fNlNnObywQslWDnvVh6Rrebmv+ZYqnp8iS1TtvlEeEiQv
         GYMgahZ7Ql/pDtqTaRT2FQ4pbXGjEXEE4RrrAYzx7TpNJh8a2FzXDLtN/Uuk7EvC237O
         gsNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=h6H13rx0PI1yTMcHR/Ddh9vsLiwbqX1Qo09kmyaa1+4=;
        fh=FI9wdZWhr5GCJBunyfqFa3lhLLBZlFcT+Q9UQ9qoMwY=;
        b=RV52CmFUtfLk1vI25Mk9GOa/qUzN0LWFVw0gMfIR60oA4GK6z08TZgn8n/8K1EIgFQ
         soHTqbogL012e0i591ywYvdtWHbGMbmbtv3iNhbTsuDARlowp5bmHEWDghuwL9juBz8k
         tnm5Kjxp0TNR6IdYbRsWtZHbuFLqDREOru1qwh1Qh9zttPp/NpIfBof62lgeM7LMCWqM
         glM+v3LP5ZDQqI/InAg7LKixDSMdvh36fmhdyukdLDzQKjoM9An9rZvRQ62Bo3Mftdn4
         jjqs6zXjoQhRQ3FiKokuOqJZ28RGcqRMVWoi4HqNU+5St7KjKgiHWuyQy0CXiHMlOYgG
         KRHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SPvQ6zPt;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SPvQ6zPt;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769700486; x=1770305286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=h6H13rx0PI1yTMcHR/Ddh9vsLiwbqX1Qo09kmyaa1+4=;
        b=k3mC8NHbQMUELJnyEHvhhLcbUR2NRkvi0RMYt7L0ADf1GzAW61pzgef9fsaRc4/Q5O
         +JdQ+3zqYutwqaNrSudlCY78iyY3G55mGhTRNio1tGLq4peJ+vyljhf6j5IgyoJLcnuT
         JvDhRUVe2qujOoTqujBagsuz3chWhhLRP1jVV6HjMycpT3CSaGSTvMaCX+NkyzaXTzcB
         KR/lk6Tdqytelr/3DqaXLq4IzXYvO8x/1nN3h5Umm+ByMo3mZbO4hhg4e8UnnsZYGdUQ
         PgHkafRiyZ2/Kh419DKWH9zAnrc2gWTcPRC/gX0yRNw4uXIQrv4frzhPLiyYD/oSaBzT
         lb7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769700486; x=1770305286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=h6H13rx0PI1yTMcHR/Ddh9vsLiwbqX1Qo09kmyaa1+4=;
        b=l7yuoU4VtF1ChZCSu2kHm9G264JkZn7hsqs6dYEOYM/K34fAVggeANLFLA3afnHrOg
         IdlSVz5ksTqILcA55Z8QmbxdwrBBaqAmOjBOUz/aMwb2D2iJtB4whrZAAdtc7/+hkZCo
         BTh99iLJ0PEIkO6u8TeKvuqc8QDTeHtOyY4ko98AYnzLosi5GRvX/5l9GKaVnHAi222/
         t1q8dVudOBh6j0HoIbg7JCBNB2sby/3hN3zMB1HV9O5pG12z/PH6zMvlOXXazG6uEmPf
         1nWEUM4wainGtorXYPYdvAWimU+ryVhuVrwtoNNT5gxw17NF9oN3znCAZH8ifn59x2eg
         /FyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQK9vwTqKKKIbPQvlVxO4E9dBJZzaGSX9/Mv+D0+n+9HszPFuKZOL9bXnKJ9NmME6la6tWnA==@lfdr.de
X-Gm-Message-State: AOJu0Yx5ZgohhTJX7GBbpAQbd6IfJk9gg3aLv34YbE9wejXT/fcaH2MH
	eXE0CAOMHAiRro56QX/GkcaLCuVpLwI+zYzek0OE8NZuxJ8sNVKlVvO3
X-Received: by 2002:a05:6402:51cc:b0:64d:c54a:334e with SMTP id 4fb4d7f45d1cf-658a60b8d28mr4894898a12.29.1769700485464;
        Thu, 29 Jan 2026 07:28:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EnL+b7/7gD4ebzqM6dGjNCiswI1d+5yMtXmtaYymG2Nw=="
Received: by 2002:aa7:da06:0:b0:64b:7641:af54 with SMTP id 4fb4d7f45d1cf-658cd1d1dddls505269a12.2.-pod-prod-02-eu;
 Thu, 29 Jan 2026 07:28:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvUF0agihMcWNTndqPct9YgCoH6KAHsAncsGZGR4QuR/cskCQcz4hf9jUVA/cpYYO8fTaD11V26eU=@googlegroups.com
X-Received: by 2002:a05:6402:50cb:b0:64b:6e20:c92e with SMTP id 4fb4d7f45d1cf-658a602e49fmr5699368a12.10.1769700483149;
        Thu, 29 Jan 2026 07:28:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769700483; cv=none;
        d=google.com; s=arc-20240605;
        b=Bsf77oqsQhjgkbOndib82Z+uHRGnj1FME+FLPNxYy9SCP4bL3as6wqSmRjgZrs3XhK
         tyXtuOPXT2J9DoUzvMDQoRs504PDkO6goZvu0xashPOC1okEYhJJRh6x4hLgoc+jl9gG
         QonBgOiLWsorHD6or9rvm+Odj+T7/1hEmVCS41e9drFvpc6z6VHm2bYKcnFo9iMYtO2X
         t7UhrSy1kJS6g8z6oq3AqD1ubDNC0+qx+PJMr26L+n0ofDEYSJJTdZDw2ChDcCxh2dw8
         IzgFhUltMduI6Hvtb1nyTrqqa27WrEEBglXPW5I+rOOQO2EANGwpDJjcK/iUP6uWIO2l
         eyfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=EeqYiO1LEtxxtRWamYuqS6iEqkru6NTx0+Qpp776dGI=;
        fh=ngwNtXOvbBBHoNhygZAQlTzYqwUYZZqGROokf1fQAwU=;
        b=NkUpU8jCZLnRrL+HGIAF+FastJbrV3OBKI2af3oZLUaW9aZElVcdWYxl66Y6m6eEbQ
         z0VxzJpdQqScilscHbMnMdG8Qxnlyk6eGh56dksqWBfuzeh7J8D7pdC3zUT6vCOuRaV3
         PaOFzHFcvt37hmziEftkpKnm5USAci/fkYx8cSjCItxLBROUlnS+RTSfpoizWAFZEiW4
         w2C4A9rRxryTE1ClrPe2G5iqzdjTg/5Y2DzBIiiHSG1wvlzT0/lMjoGXnWxg6/z1aW/e
         AIoAusiIQwCW7zniuIFfTV+9IBWB/zmXPnNGFV3FephNaBdbWmzEcdFRUymBW1pybBsk
         AFWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SPvQ6zPt;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=SPvQ6zPt;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-658b4680823si122238a12.1.2026.01.29.07.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Jan 2026 07:28:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 678BD5BCE2;
	Thu, 29 Jan 2026 15:28:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 352C83EA61;
	Thu, 29 Jan 2026 15:28:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id K/UsDIJ8e2k7MQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 29 Jan 2026 15:28:02 +0000
Message-ID: <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
Date: Thu, 29 Jan 2026 16:28:01 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 00/22] slab: replace cpu (partial) slabs with sheaves
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
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <imzzlzuzjmlkhxc7hszxh5ba7jksvqcieg5rzyryijkkdhai5q@l2t4ye5quozb>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=SPvQ6zPt;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=SPvQ6zPt;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBBHZ5XFQMGQEO3ECTWQ];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCPT_COUNT_TWELVE(0.00)[20];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.998];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,mail-ed1-x53d.google.com:helo,mail-ed1-x53d.google.com:rdns]
X-Rspamd-Queue-Id: 53DD7B16F1
X-Rspamd-Action: no action

On 1/29/26 16:18, Hao Li wrote:
> Hi Vlastimil,
> 
> I conducted a detailed performance evaluation of the each patch on my setup.

Thanks! What was the benchmark(s) used? Importantly, does it rely on
vma/maple_node objects? So previously those would become kind of double
cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
more than they should) since sheaves introduction in 6.18, and now they are
not double cached anymore?

> During my tests, I observed two points in the series where performance
> regressions occurred:
> 
>     Patch 10: I noticed a ~16% regression in my environment. My hypothesis is
>     that with this patch, the allocation fast path bypasses the percpu partial
>     list, leading to increased contention on the node list.

That makes sense.

>     Patch 12: This patch seems to introduce an additional ~9.7% regression. I
>     suspect this might be because the free path also loses buffering from the
>     percpu partial list, further exacerbating node list contention.

Hmm yeah... we did put the previously full slabs there, avoiding the lock.

> These are the only two patches in the series where I observed noticeable
> regressions. The rest of the patches did not show significant performance
> changes in my tests.
> 
> I hope these test results are helpful.

They are, thanks. I'd however hope it's just some particular test that has
these regressions, which can be explained by the loss of double caching.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/390d6318-08f3-403b-bf96-4675a0d1fe98%40suse.cz.
