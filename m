Return-Path: <kasan-dev+bncBDXYDPH3S4OBBNUTR3GAMGQEHSRGHMY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uEunE7iJg2lDpAMAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBNUTR3GAMGQEHSRGHMY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:02:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB30EB51D
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:02:31 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-385b736d4f7sf470131fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 10:02:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770228151; cv=pass;
        d=google.com; s=arc-20240605;
        b=Tkr2GdUsZjj23EWBEogwYsmF/Mz9hdTxJF0vHkt4f/yB7ySTrN+qlfQAxkqdYTD7MI
         GnzQdHyGPK9S/fBsShtObamF6c6yxi7SDec3ewB9Y8mBIgRS099j6p5Hb+TOlbS2G16I
         JPb0N2i7W97YCaJ0CEt9dhj8XDmkpBczvzeHQHIxmeKqafwAX81xkvuc/qmRMhnKXV6P
         9w1tHFSCBgh7Y620xCkq3S1xYjKvPgYBNwk4PRqlyfA9TabJI3TgG1D8N+WpcmmoukNH
         K3rEef1dcv+WFtIWlsCmgWOGZY19Rxy6RqRO+tO/9V3NRwbSVHkd9TNtnD8DSEc/CTkk
         3ibg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=nZJZ+sj61dk/3sVJgmJn8FaC1ttyguaCTQ+//7AD0nI=;
        fh=S71eRH//tVTFaURyCPpKqm6A2ZTyswr4aj0A4i6D9+A=;
        b=EB1XZ8Su6oCDTOmhzVyZ9dJQNvKY4kgNBQUT/WqTB95hzQMYzk9kbHl31ZyMnT2iHU
         BFTpZpZZkv2ZClwiJ1t7nnrCFZWSLUS6NEYrMRheo0wwQkYaDKdVCK9QmYxrK848gCg0
         26od+D/egZgpOKZ4419Gbm+t+FALRMha+rUimZRIa6D2uDQ4TGg4B30bBnwdySDBLR0w
         PYEwhNeI4zPm6zvFHjpp5JE3m9GAcsGHfgJiZnmgY8T4uNDAxjqWTk69o83moZnovAER
         ePtLsjGDKRDwzbJ9qieUkwJ5hHFNNWRXiNcOQKyCvqgxvHFSSx6N5ORwGbge+o7AyecO
         ehBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1TOJkMnQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1TOJkMnQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770228151; x=1770832951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=nZJZ+sj61dk/3sVJgmJn8FaC1ttyguaCTQ+//7AD0nI=;
        b=N9MyItq5/B3riqC3LogB0tmhr3tdJU2pzBRBbDnbv+oa2WuP8UfY/t/UNr347IpR5G
         8s9yQxokwHlYBAAFP3cVguAGC6rIIha6NcIr76MF9cbBz7XCg0ZOqgQ5LWOv6DwLXpc9
         eH5ePbINrqh6hiiJc7mvCgg4frTKnKpvkzLMCgHgKo0HVYjJ/wgRuDvBQFKvDbvPq2QV
         XeqobOa2pagoug6Iw35Q7gd/CMNMmxtyPTPvrEcxb7eSNq8gCDfvWvx5NH98mYDzz2/w
         WMYTv/cfYRrKmXy/X9x+hGpiIXSvxHtAhB0cjN0nqQjhpO/snq7JC06GiPDvteeN1kij
         eYIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770228151; x=1770832951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nZJZ+sj61dk/3sVJgmJn8FaC1ttyguaCTQ+//7AD0nI=;
        b=ZRY5SCRaUt8w/jPsJ83fcAI6qFY1Pc8OHpA2SQG7GlxlgNqUNSPFdFnT3cy8TVrSCJ
         +JpZckfjpA28O58uxPS8QNxrxhvlu5hoyQk0wo/0Fo5wo+xsMMZZy0BLwIut0PVus1+T
         Ht0/PuiEDNB4QV1ASPWqnTyUjAUu1AvqZBVzJ6hPm0AsyC06RnJCydf7gF2vA8ZFo3X3
         rhYn723hhuJJtBzgXD41uY6ZSCqMhzJf87gtZ1/o/ktFyi/J0Imn6+9GqpsuWyA+slQ7
         MQTQRvFxwnZDqfr1JU1QrscP2j83OZiCMV4wXC08P5THJri+pFuOL2M2L01OM5e/lvhX
         OTNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW9bchhiXUMR5aUIdqG0xXSTv5UmV0KVkwSZRmL0wQBnplcZPYMjW8njFlOfWNWnwzi9decog==@lfdr.de
X-Gm-Message-State: AOJu0YwdNRt4BxomIzEF04EyCLRL5cAiJKayGHQHzDGE4v1RkI6rPK7c
	BIkx5m9myLJqc/rm78likHG5/ybyHsFB+U2nU9JfeKYTFLkhShp6B1XX
X-Received: by 2002:a05:651c:41d5:b0:385:d1a0:6be0 with SMTP id 38308e7fff4ca-38691ccf82emr13230991fa.19.1770228150973;
        Wed, 04 Feb 2026 10:02:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GND6+piAQudhIvGw6jXPR/pU2Q7aroRbmq/JrZiYTEFA=="
Received: by 2002:a05:651c:4413:10b0:377:735b:7cbf with SMTP id
 38308e7fff4ca-386a05efbeals108051fa.0.-pod-prod-08-eu; Wed, 04 Feb 2026
 10:02:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFLiElMJ+AQ7NbNa0RFS12Fr107lEpAuKnAesbJkMZSYJHI470KkxjHq49zHGw+EGEZbYI4Qlm/k0=@googlegroups.com
X-Received: by 2002:a05:651c:41d8:b0:383:2bca:a610 with SMTP id 38308e7fff4ca-38691de0db3mr16606171fa.41.1770228148272;
        Wed, 04 Feb 2026 10:02:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770228148; cv=none;
        d=google.com; s=arc-20240605;
        b=WCU8gRfv6rd7k80v45QhzPKAaWjokmXf4wrfrZUEWnUx8DnAZ3BRcsRejFO7wzCPZ5
         oYYgYXu1LfdPLdhYCU0bJQNKONX2ZINbBFZyRV9Ow9FIDHFfQsV7ceItkXYTpuLv+tqA
         fflYuE+SxPo/mKg3BG7nW3oJk7/cHc3vipIelPhxqXhCxf4qv0b9oQFFsd3AhgXTuCah
         JuhhEBwN/Ql6d2RJQvVAZ3uFUslJZB0jqXdZK6kOZZcGhRopcTONrsLqKBkaUfkpdZFe
         4NKzuuM7VVYObHRBpN8Bs49I1KzXe9YdL5I9l9Fe4s4aPZ+pKKDKI+/a0rq1dz5VluIQ
         oRqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ZZ3f5XE99Y5O1R9K1/1yZEnq3LWfNqveoQu7G+G/Vj4=;
        fh=ngwNtXOvbBBHoNhygZAQlTzYqwUYZZqGROokf1fQAwU=;
        b=RxhMXMuq+76aXQJHIUaYXPj0fkpyUmE+1pOXzuvIZ4TiAzUK5IuT/SdJ5mPZ8jJjLG
         +6Z/OILhac+aIl5mn5lNKS3b4LoC5LF2bikHZ7qFAU93hoHPoWD9qsoQiFDdToZLqOnb
         lLo0zFiUSh2aSvl0WnaD267IlSpqa+7oo8BdHi7giC8lRf9P3sdXZZhvd6SZTKBctYMI
         SgWgXJaqHNTH49WPvtqdl/8eOJP0SZv0lhwcgUBEUKjlCHa4r+eOxUSpCPue6AFoLBSX
         yhBn35Ki4fZ5fZ7TYeY6hxfof2k1djdGmPLsQQ06um/CD8N7Zn05dmXSmH/WNbJicnIg
         4imA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1TOJkMnQ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1TOJkMnQ;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3869202c262si738041fa.6.2026.02.04.10.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 10:02:28 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 5B8075BCED;
	Wed,  4 Feb 2026 18:02:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 29B803EA63;
	Wed,  4 Feb 2026 18:02:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RZfcCbOJg2nwKQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 04 Feb 2026 18:02:27 +0000
Message-ID: <665ff739-73d8-4996-95e0-f09c3e5b6552@suse.cz>
Date: Wed, 4 Feb 2026 19:02:26 +0100
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
 <390d6318-08f3-403b-bf96-4675a0d1fe98@suse.cz>
 <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 xsFNBFZdmxYBEADsw/SiUSjB0dM+vSh95UkgcHjzEVBlby/Fg+g42O7LAEkCYXi/vvq31JTB
 KxRWDHX0R2tgpFDXHnzZcQywawu8eSq0LxzxFNYMvtB7sV1pxYwej2qx9B75qW2plBs+7+YB
 87tMFA+u+L4Z5xAzIimfLD5EKC56kJ1CsXlM8S/LHcmdD9Ctkn3trYDNnat0eoAcfPIP2OZ+
 9oe9IF/R28zmh0ifLXyJQQz5ofdj4bPf8ecEW0rhcqHfTD8k4yK0xxt3xW+6Exqp9n9bydiy
 tcSAw/TahjW6yrA+6JhSBv1v2tIm+itQc073zjSX8OFL51qQVzRFr7H2UQG33lw2QrvHRXqD
 Ot7ViKam7v0Ho9wEWiQOOZlHItOOXFphWb2yq3nzrKe45oWoSgkxKb97MVsQ+q2SYjJRBBH4
 8qKhphADYxkIP6yut/eaj9ImvRUZZRi0DTc8xfnvHGTjKbJzC2xpFcY0DQbZzuwsIZ8OPJCc
 LM4S7mT25NE5kUTG/TKQCk922vRdGVMoLA7dIQrgXnRXtyT61sg8PG4wcfOnuWf8577aXP1x
 6mzw3/jh3F+oSBHb/GcLC7mvWreJifUL2gEdssGfXhGWBo6zLS3qhgtwjay0Jl+kza1lo+Cv
 BB2T79D4WGdDuVa4eOrQ02TxqGN7G0Biz5ZLRSFzQSQwLn8fbwARAQABzSBWbGFzdGltaWwg
 QmFia2EgPHZiYWJrYUBzdXNlLmN6PsLBlAQTAQoAPgIbAwULCQgHAwUVCgkICwUWAgMBAAIe
 AQIXgBYhBKlA1DSZLC6OmRA9UCJPp+fMgqZkBQJnyBr8BQka0IFQAAoJECJPp+fMgqZkqmMQ
 AIbGN95ptUMUvo6aAdhxaOCHXp1DfIBuIOK/zpx8ylY4pOwu3GRe4dQ8u4XS9gaZ96Gj4bC+
 jwWcSmn+TjtKW3rH1dRKopvC07tSJIGGVyw7ieV/5cbFffA8NL0ILowzVg8w1ipnz1VTkWDr
 2zcfslxJsJ6vhXw5/npcY0ldeC1E8f6UUoa4eyoskd70vO0wOAoGd02ZkJoox3F5ODM0kjHu
 Y97VLOa3GG66lh+ZEelVZEujHfKceCw9G3PMvEzyLFbXvSOigZQMdKzQ8D/OChwqig8wFBmV
 QCPS4yDdmZP3oeDHRjJ9jvMUKoYODiNKsl2F+xXwyRM2qoKRqFlhCn4usVd1+wmv9iLV8nPs
 2Db1ZIa49fJet3Sk3PN4bV1rAPuWvtbuTBN39Q/6MgkLTYHb84HyFKw14Rqe5YorrBLbF3rl
 M51Dpf6Egu1yTJDHCTEwePWug4XI11FT8lK0LNnHNpbhTCYRjX73iWOnFraJNcURld1jL1nV
 r/LRD+/e2gNtSTPK0Qkon6HcOBZnxRoqtazTU6YQRmGlT0v+rukj/cn5sToYibWLn+RoV1CE
 Qj6tApOiHBkpEsCzHGu+iDQ1WT0Idtdynst738f/uCeCMkdRu4WMZjteQaqvARFwCy3P/jpK
 uvzMtves5HvZw33ZwOtMCgbpce00DaET4y/UzsBNBFsZNTUBCACfQfpSsWJZyi+SHoRdVyX5
 J6rI7okc4+b571a7RXD5UhS9dlVRVVAtrU9ANSLqPTQKGVxHrqD39XSw8hxK61pw8p90pg4G
 /N3iuWEvyt+t0SxDDkClnGsDyRhlUyEWYFEoBrrCizbmahOUwqkJbNMfzj5Y7n7OIJOxNRkB
 IBOjPdF26dMP69BwePQao1M8Acrrex9sAHYjQGyVmReRjVEtv9iG4DoTsnIR3amKVk6si4Ea
 X/mrapJqSCcBUVYUFH8M7bsm4CSxier5ofy8jTEa/CfvkqpKThTMCQPNZKY7hke5qEq1CBk2
 wxhX48ZrJEFf1v3NuV3OimgsF2odzieNABEBAAHCwXwEGAEKACYCGwwWIQSpQNQ0mSwujpkQ
 PVAiT6fnzIKmZAUCZ8gcVAUJFhTonwAKCRAiT6fnzIKmZLY8D/9uo3Ut9yi2YCuASWxr7QQZ
 lJCViArjymbxYB5NdOeC50/0gnhK4pgdHlE2MdwF6o34x7TPFGpjNFvycZqccSQPJ/gibwNA
 zx3q9vJT4Vw+YbiyS53iSBLXMweeVV1Jd9IjAoL+EqB0cbxoFXvnjkvP1foiiF5r73jCd4PR
 rD+GoX5BZ7AZmFYmuJYBm28STM2NA6LhT0X+2su16f/HtummENKcMwom0hNu3MBNPUOrujtW
 khQrWcJNAAsy4yMoJ2Lw51T/5X5Hc7jQ9da9fyqu+phqlVtn70qpPvgWy4HRhr25fCAEXZDp
 xG4RNmTm+pqorHOqhBkI7wA7P/nyPo7ZEc3L+ZkQ37u0nlOyrjbNUniPGxPxv1imVq8IyycG
 AN5FaFxtiELK22gvudghLJaDiRBhn8/AhXc642/Z/yIpizE2xG4KU4AXzb6C+o7LX/WmmsWP
 Ly6jamSg6tvrdo4/e87lUedEqCtrp2o1xpn5zongf6cQkaLZKQcBQnPmgHO5OG8+50u88D9I
 rywqgzTUhHFKKF6/9L/lYtrNcHU8Z6Y4Ju/MLUiNYkmtrGIMnkjKCiRqlRrZE/v5YFHbayRD
 dJKXobXTtCBYpLJM4ZYRpGZXne/FAtWNe4KbNJJqxMvrTOrnIatPj8NhBVI0RSJRsbilh6TE
 m6M14QORSWTLRg==
In-Reply-To: <pdmjsvpkl5nsntiwfwguplajq27ak3xpboq3ab77zrbu763pq7@la3hyiqigpir>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1TOJkMnQ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=1TOJkMnQ;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBNUTR3GAMGQEHSRGHMY];
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
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lj1-x23c.google.com:helo,mail-lj1-x23c.google.com:rdns,suse.cz:mid]
X-Rspamd-Queue-Id: CFB30EB51D
X-Rspamd-Action: no action

On 1/30/26 05:50, Hao Li wrote:
> On Thu, Jan 29, 2026 at 04:28:01PM +0100, Vlastimil Babka wrote:
>> 
>> So previously those would become kind of double
>> cached by both sheaves and cpu (partial) slabs (and thus hopefully benefited
>> more than they should) since sheaves introduction in 6.18, and now they are
>> not double cached anymore?
>> 
> 
> I've conducted new tests, and here are the details of three scenarios:
> 
>   1. Checked out commit 9d4e6ab865c4, which represents the state before the
>      introduction of the sheaves mechanism.
>   2. Tested with 6.19-rc5, which includes sheaves but does not yet apply the
>      "sheaves for all" patchset.
>   3. Applied the "sheaves for all" patchset and also included the "avoid
>      list_lock contention" patch.
> 
> 
> Results:
> 
> For scenario 2 (with sheaves but without "sheaves for all"), there is a
> noticeable performance improvement compared to scenario 1:
> 
> will-it-scale.128.processes +34.3%
> will-it-scale.192.processes +35.4%
> will-it-scale.64.processes +31.5%
> will-it-scale.per_process_ops +33.7%
> 
> For scenario 3 (after applying "sheaves for all"), performance slightly
> regressed compared to scenario 1:
> 
> will-it-scale.128.processes -1.3%
> will-it-scale.192.processes -4.2%
> will-it-scale.64.processes -1.2%
> will-it-scale.per_process_ops -2.1%
> 
> Analysis:
> 
> So when the sheaf size for maple nodes is set to 32 by default, the performance
> of fully adopting the sheaves mechanism roughly matches the performance of the
> previous approach that relied solely on the percpu slab partial list.
> 
> The performance regression observed with the "sheaves for all" patchset can
> actually be explained as follows: moving from scenario 1 to scenario 2
> introduces an additional cache layer, which boosts performance temporarily.
> When moving from scenario 2 to scenario 3, this additional cache layer is
> removed, then performance reverted to its original level.
> 
> So I think the performance of the percpu partial list and the sheaves mechanism
> is roughly the same, which is consistent with our expectations.

Thanks!


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/665ff739-73d8-4996-95e0-f09c3e5b6552%40suse.cz.
