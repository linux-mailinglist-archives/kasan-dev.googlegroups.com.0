Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHFWYPFQMGQEH3DSJSA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YPQtFB7bcGnCaQAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBHFWYPFQMGQEH3DSJSA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:56:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id DFC2E58045
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:56:45 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-4779ecc3cc8sf48499215e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 05:56:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769003805; cv=pass;
        d=google.com; s=arc-20240605;
        b=SWl8ozGMM9Jq1BScvf7gT2UP2GQK5yFhkUNQwTjLH86puFCRCxPUCL0wNR0JvjFlrH
         mLDL8/Y4S2S8BOlSWNtS6z5kQgaKQMOaqgEe1erAugofTyevI2mkTxNQ5LRiDBlm3Krm
         Lonza9PgoIT4fMB0JnNOGVQG4aXuoU0cnj/2Js17qy+Gx2/eOf5mYz+iNg7I88ZWdwo4
         2Br+q25+QoQ28+wAWsasR0v1LmqamVlnjBEW6MbeuUzAyJEo6Yx9pQWZ4UU2cvmwKrsX
         N1B0wrLcsTDXtkTsi7/lXwJRFBk8aYec9W86X7aHLQ8Z7BXrtjYV0vBmIeF4jxgtJ5jb
         4OAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=l+HPGzwyGdEQEkBG8WVYLE9VI2DuXv0ri2Kj0mlLPHk=;
        fh=tFabQH2hYStzqwiArjr0GJiglO+FPiFm8SlqTvNE0qo=;
        b=dq4dQnZWC45jRdWbty3QpFzqXFqwkOkKq98XZeTEq7X/7/U45q3x5lRsSTmzM+/xCk
         cZPcG3NbV5ZxI+JXZzX5GNsW+W8i6ne/tD8fQJYswm1s9tUY0qqPPue+V3FzmjPIJlaO
         Rs0tAy2N/G2q0n8RoHSI96laAG0TQv3bfr+oTeQyQzFMqj3goXC6KLx5sZO3Jek1F+F3
         bzK04JJ0lg7drR99YIlMD0Q+W5+5Hj3t9aNTxd9HR1adtqar1JSjc0ih1JbqUu93He9k
         fXuAmZoNhlpE1OvE+LVEQMZbkzUVciiBpSXfQGFGELu92sy49BO/hOrzMLgb1Kf/6pRq
         vCwQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RLeqqG3F;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tFX5PEb0;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769003805; x=1769608605; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l+HPGzwyGdEQEkBG8WVYLE9VI2DuXv0ri2Kj0mlLPHk=;
        b=B08ZvhZmIdiMWgXXAYiwCupaw75mH4oYriTXYN/fusk6AV4M7YAuPwZVfFg0MWcJzZ
         FWdGpwVVjsataBbvQ+mxMBnk2r+RMza/niSnD8WxyKXUt0dzv0pFljzh0fjR7cIDSDlZ
         h4aY2w+zUaYoANMBN7hbCgEJxFpersZWtuTCbvCAEKn99Z67uPokejFGa/JJDx+ZlD9H
         hlXaOMlUKqHSVfJWmplWoqwMDRy3cU6hy7ZwlCmFjs1DKWPkG28i6rExSaOvtr6zmSf+
         gvVw4cFcSveFIUC2kCTlzntEPzzXLehp4ybceUbEUOK7wlMvOL8++elwOsuTYR2HKlat
         tOIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769003805; x=1769608605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l+HPGzwyGdEQEkBG8WVYLE9VI2DuXv0ri2Kj0mlLPHk=;
        b=p48K4dI+3wk4b4Q0sZatk/ZfUo6BJCeMIVyJxiQ9FvzCewYuD6clPNrGEWOXp8rDW2
         Ms5qwt+X5Yg/BrhGOSpBkUxupLiBh3VY25GcSQLCTKtePrHoK/d4HlxfvBJ0xXmNwOG6
         h0smXLK0+iyo/u8a0OdXU7UXoO58TYaWD+6hUUJp0qofNg2NQkAcL/8EMqFUUtqFER5M
         voUy+4bFM/YqHpkr53+yeO5yitlOL3qadHYSoCyWN5jF4wfj+AjTg0BTaVNUNsxG3PGX
         6aebMeMP1yTAiOgevbkMh6WZ/KDPQYiW8q5pSRYcSBYmf0J0qzN/+dhYQ/8U0JU3wsHd
         orfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXV4saABWGnGr0ERJ30MMd5ahlTpz3059crP/Ukw5bQcpnVQEq4DLn7LjYMfPpiprC/b0omzg==@lfdr.de
X-Gm-Message-State: AOJu0YzAN2wnyLPZ0lkPEYuQKVboKuSPeJrMuRVOTfn53tQPHOkQzbsZ
	KEh2/3pCgLE2rGzpVR3rqPMxauPxaF0B9WXlywXGtVVvLIk21xb59CJs
X-Received: by 2002:a05:600c:524e:b0:477:7c7d:d9b2 with SMTP id 5b1f17b1804b1-4803e7f1860mr81912405e9.32.1769003805035;
        Wed, 21 Jan 2026 05:56:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FkqiwU2Jn04FidDLEpV1K6bf6AGwK4UhGUIO+6Ofip+w=="
Received: by 2002:a05:600c:8b16:b0:477:a2eb:9a0a with SMTP id
 5b1f17b1804b1-47f3b7a692els39571195e9.1.-pod-prod-07-eu; Wed, 21 Jan 2026
 05:56:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW8ijTHAdp/ZrfQo7hYEpj5smFOjQM2sMNlgRFOMPLm9JAc2FR6+ByuxYjzBtaG0xRTXhRncoPH98w=@googlegroups.com
X-Received: by 2002:a05:600c:a09:b0:47e:e57d:404 with SMTP id 5b1f17b1804b1-48045f7c2f2mr13586975e9.16.1769003802533;
        Wed, 21 Jan 2026 05:56:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769003802; cv=none;
        d=google.com; s=arc-20240605;
        b=NXfPDQgAX+Vu2jXB7bQbnICp/bY0/1aAE1hd59QtLI36/Bxa87qJdWeM/NSI2Z2EeG
         HkbtoO0MLW+h0YcwWsleGxS8AWSyJ/P3KIzfS/np+bH36KcBsBCqcX3XFvWRFqXeahUP
         AVtwv+dwOUWcV7LHZoL8r6Dwo52Dc3G+QXropnhdRXTDotQytXDLRVDSoylMKEseaRqS
         mr7Uue2T4aCsYmnOyXx0Nj2NlYPE82KuSxgKDHZqoX8qmYY33PaXEmGYv6mqXyXR18J8
         4iXeAfM7L49PaqowrJa5fEFs/oqH9IxS+5ASpfDQc0rqdoUCeV7bZ1brxhGY89egaiFo
         w4jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=F9wHHlvguHOFteeiwaIUOv2HvVMORPBkdi/Fa31GaTI=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=ObnAAF8ZK+0/PeLZvyVMCQAP1GBTz40d14MvS3X9G1SHalP5mIqx+WT031yc9EtpOJ
         zyFTrl5AQmav52xkj6Zffd/bWk1rzeOvUfZp6YgNsIzzC4M8G4C69eYpchhBRmx4fE3q
         rf0kWH4YGkVfEKm52fliPHHBO1DA8cw5Y0Fen3S3c/eSDyJkRCZ8lNmBfvqLvH3CDvVY
         5nsW+nY03u1tv17H3RNhgXgrHqC/7FVfo8I/asOBTVDVZUUbBMtLSEGxP8qAvyTrO0M4
         4CSUNE0jyh2PZrJjYguCsU9p1tW6KRHXNh1m/YShewjySS8jOW6ej4T6O8x7YNz52zZX
         ZzJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RLeqqG3F;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tFX5PEb0;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-48042b80886si235645e9.2.2026.01.21.05.56.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 05:56:42 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id ED0035BD00;
	Wed, 21 Jan 2026 13:56:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BA82A3EA63;
	Wed, 21 Jan 2026 13:56:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id mixHLBnbcGkTSgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 13:56:41 +0000
Message-ID: <c6ba66a3-0346-40c3-a27e-5528f30fc782@suse.cz>
Date: Wed, 21 Jan 2026 14:56:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 10/21] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Suren Baghdasaryan <surenb@google.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-10-5595cb000772@suse.cz>
 <CAJuCfpEEUs98yCiNA=QOPY6Qk7=QhSBF+gqPn5a+B+bYbQwvsQ@mail.gmail.com>
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
In-Reply-To: <CAJuCfpEEUs98yCiNA=QOPY6Qk7=QhSBF+gqPn5a+B+bYbQwvsQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RLeqqG3F;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=tFX5PEb0;       dkim=neutral (no key)
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBHFWYPFQMGQEH3DSJSA];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid,mail-wm1-x338.google.com:rdns,mail-wm1-x338.google.com:helo,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: DFC2E58045
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/20/26 19:06, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> We now rely on sheaves as the percpu caching layer and can refill them
>> directly from partial or newly allocated slabs. Start removing the cpu
>> (partial) slabs code, first from allocation paths.
>>
>> This means that any allocation not satisfied from percpu sheaves will
>> end up in ___slab_alloc(), where we remove the usage of cpu (partial)
>> slabs, so it will only perform get_partial() or new_slab(). In the
>> latter case we reuse alloc_from_new_slab() (when we don't use
>> the debug/tiny alloc_single_from_new_slab() variant).
>>
>> In get_partial_node() we used to return a slab for freezing as the cpu
>> slab and to refill the partial slab. Now we only want to return a single
>> object and leave the slab on the list (unless it became full). We can't
>> simply reuse alloc_single_from_partial() as that assumes freeing uses
>> free_to_partial_list(). Instead we need to use __slab_update_freelist()
>> to work properly against a racing __slab_free().
>>
>> The rest of the changes is removing functions that no longer have any
>> callers.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>=20
> A couple of nits, but otherwise seems fine to me.
>=20
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>

Thanks!


 > -static struct slab *get_partial_node(struct kmem_cache *s,
>> -                                    struct kmem_cache_node *n,
>> -                                    struct partial_context *pc)
>> +static void *get_partial_node(struct kmem_cache *s,
>> +                             struct kmem_cache_node *n,
>> +                             struct partial_context *pc)
>=20
> Naming for get_partial()/get_partial_node()/get_any_partial() made
> sense when they returned a slab. Now that they return object(s) the
> naming is a bit confusing. I think renaming to
> get_from_partial()/get_from_partial_node()/get_from_any_partial()
> would be more appropriate.

OK, will do.

>> -       }
>> +       freelist =3D get_partial(s, node, &pc);
>=20
> I think all this cleanup results in this `freelist` variable being
> used to always store a single object. Maybe rename it into `object`?

Ack.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
6ba66a3-0346-40c3-a27e-5528f30fc782%40suse.cz.
