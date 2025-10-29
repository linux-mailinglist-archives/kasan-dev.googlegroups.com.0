Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHX3RHEAMGQEHMPRPNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 92A0EC1D480
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 21:48:31 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-63e0fe97842sf517350a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 13:48:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761770911; cv=pass;
        d=google.com; s=arc-20240605;
        b=jUGLjfJ+lIDcstdXdZFC4AiDvPr6xYTlXECI+kWh0jUf1VEdCntI5B7t1QZ1izOypy
         TDh99DFNwLGQk0iJ2G6QUrUO/UIoRu3iYzun18uLZorEnyX+otGrQRhRQ7JYB90D8i44
         pTCRZ+orPzhZOWfqQSzIU3laCpl0rGcyh13CbT/eQweaM0N/KKWfbUPMG9bMA+s0aZpS
         DGkyFHLvLCuu7Rj60Nx8noGRnXwYx6nXyBUzU3LC+eW/w/FUwkhfn6n5eSA8O2rgsbgV
         J9+M6BbIJDma2Aa47XOsEPWE7srSwFf6YeRWNiM3dxL5P1lmJxWcQxJYz+2XsZrWjAEm
         bU1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=sl3mEMsAIplMc8Z3W3RMUEmJrr8p45foMkCAXvNKr9w=;
        fh=YFdy3Ua035n2rmkpgTR+zJK7rmBhwmuH8MszBkaPjGk=;
        b=Ikoej7OrtWm/1v6x8Afz4BOhApQjLvkmjQixywVqUbMtq5N9wKTr9Q69Y9JxgDON7f
         LPVTmCWfCOoOU58bSct4LzGPjjpHc3HEHPfS+TKmsYvBApOkd4WDfA02pNJflrB6nVKO
         6mNEoI6dSchrg9ldyzdmv9gz+X5VHxEi3SKMLTNKEPOMgoM9c82XRen0RSYL6cqUKxmL
         hOQeCO3vGsZ+/xMDTcBtSRlALVK+7Ut2PlMvuO28CD6AlONN/12LjMYdCIXySF9IAtkG
         ccFG3RiYI8PogbXC+iorbEJ+BBrPDNyzsDAGsgUJov41cvHkJa3BSimkmkyC5bDttOht
         461g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761770911; x=1762375711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sl3mEMsAIplMc8Z3W3RMUEmJrr8p45foMkCAXvNKr9w=;
        b=Jplx1vidT49Z9rG97psl/noYo0MgwOuYxDqxychfUtZFX0cjVB4JLN1C6mKTz5Cx1U
         9hyezef8ny5f6M1iwULVRH/532lv+HIufSLJcwsS+IDTW73XLqx8/YF10sKQSvE5Wf5l
         4MJ0nFVT9USuAGT/AF0sBt+Cl8D3I2PHXJF4hdDDMyCUyIdtFJwH70D05lxe+2aFXNgJ
         d7dAxhtrJvlvNtQ+vhgDkyI8E9Zp33pqJ7wVXo7Wh2fJphmQy1kZ2aGCywo5fj/PG4UD
         NU6pwrqvp0IVQ9bWEkNl4UXRdJyTAMZdCs/MVCjpQuyCdLxiN8wNsbRlA2BI19L0TJF2
         r1Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761770911; x=1762375711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sl3mEMsAIplMc8Z3W3RMUEmJrr8p45foMkCAXvNKr9w=;
        b=Lwoh84AFZCVUrDqrHMF8l2ZWZ4ZTVqyEp8w5HIKIIRIWTr/shBtiF84Vj09ubhpDky
         rbMM/dIxiO3ycqAJ0ruZpKBl88WhcdqTNrSMUHfDLOPJ8x6nVazx6rMgj1gJalJUsiFc
         Rp00yDg4p5IbTIDB60oyyypZ2OeRLI3CITxKDC35r0vgrF9cB5kDDszz2MtpUGNQw31K
         qjZZvuW2S94rvEofURC2bR2C2K/VoCZO+QjH1lzx3LnN6UszMEYZcvdxzwhuAcK8QFuo
         3qzuHjTsS2bTi24Ujx+Ot04ZsLK7M2KdDAWdHLdrrK9gnj+1yxfdbZSOn/oUJhJbz47h
         hTog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUQocMu8zotqqGsmtT8VToWbYvwY399bOV8AqXQKmojNPhVVcZUSogEvltteLjXmKqcmQBJ1Q==@lfdr.de
X-Gm-Message-State: AOJu0YyQ3Y8NregwYFhv2wPHaFex+R+5BSJ/ORcaGQaimifIQj7q3ogZ
	Varq6C8YPqiZJkKii8Z2lptZb2KJmZAwML2wXDA7oxm+IT4CFWWiK/nk
X-Google-Smtp-Source: AGHT+IEt+oILTNR0R/qTdJ24zOHMgCSuUX4qLQ9UZRXwrLMzlPN2IJO1dpxXV+JPxaxjDnqkmw4gTA==
X-Received: by 2002:a05:6402:13d3:b0:63c:1a7b:b3bb with SMTP id 4fb4d7f45d1cf-64061a207f9mr555440a12.1.1761770910876;
        Wed, 29 Oct 2025 13:48:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bNqNQH3N4BA12CyBLAyrg7KwclcLoDEbkVt9DjTpTQSg=="
Received: by 2002:a05:6402:5354:10b0:63e:4530:fd8f with SMTP id
 4fb4d7f45d1cf-6405fa585bals431636a12.2.-pod-prod-09-eu; Wed, 29 Oct 2025
 13:48:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKez/3JIn9kQj9Y/xNef7QRoCyLKjrVv+Xz5GE2G81JOy68ud9ddhH4C4lomSS216IY9rtLwwxK28=@googlegroups.com
X-Received: by 2002:a05:6402:5193:b0:63e:85fc:4ebe with SMTP id 4fb4d7f45d1cf-64061a3419dmr443819a12.15.1761770907998;
        Wed, 29 Oct 2025 13:48:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761770907; cv=none;
        d=google.com; s=arc-20240605;
        b=PepngRkkz7jx0AEEJS7y8jLPRlWAPVPcakT2Yrzq8BpDkbtQMcGZdzq02eNn4ED7Lj
         S8bE+WQHcZy/922SYfmmIgUio7/dd/wFjmjEPtNcFG+m1tn/iTwd8I4DnP7DYFSO9vS4
         qig4M3uQzs933XQxblxzKQs60rwkK3TRkDWFhoKxFHFnaWZ9w9TEGjyQG1iPgdwkaKzy
         DEETuYaywIeX6VVNQ/Df6vwjbg+IeYTAS4lWTlIkxiytLzrixcRnLdDl518NxN4MbTUv
         M4OgMhRVOnY5Ck2lil8Vh04roJSj9ebfzw16nWdr6wXWIRd8KLE+1qv96mBGTPEv0bg1
         CvxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=xXMm+8rNL3B9SMoW6XqHW2hL2qMAKNxXr/FwREZjE5o=;
        fh=wT+3rUFrxSfWDlIbk/kN62IDJ/K1d10IIhdAHgvNHAE=;
        b=Q5I/z77S7y2bzjlvWdLmz7/hLTcWS1hfghW5BpvY5CbEMZIBpX1/um+f9u0EfLWOpJ
         b54Idf1NYDKzj1IwZaMZ4Kb+Mm0RKRcwQWjpNKQuFb60ohv5Qa5Q9NuU7NzzvE0DZidP
         xlvOJf+HSZLSgWGELO5C9Bgp+Z/WkmnCWgakNvJnMldgn4/rq+Qk/7ySJVXE9ws/TIgL
         fhvsS35EvWtWzYGgxZcVNWwclpiU5Arp+arBTFMU189mMCA96aodLJC4G2YVaDbSqGeP
         bEmS3ycX+PPay4KpvOUood60+4K5+321r0X9fWDaOCTawWEuVBDeEdD7bR3Ch+Nl9WtC
         JVQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e811672ddsi297174a12.2.2025.10.29.13.48.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 13:48:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6D1095C797;
	Wed, 29 Oct 2025 20:48:27 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5083E1396A;
	Wed, 29 Oct 2025 20:48:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id wxFIE5t9AmkgJgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 20:48:27 +0000
Message-ID: <113a75f7-6846-48e4-9709-880602d44229@suse.cz>
Date: Wed, 29 Oct 2025 21:48:27 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 09/19] slab: add optimized sheaf refill from partial
 list
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-9-6ffa2c9941c0@suse.cz>
 <aP8dWDNiHVpAe7ak@hyeyoo>
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
In-Reply-To: <aP8dWDNiHVpAe7ak@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.996];
	MIME_GOOD(-0.10)[text/plain];
	ARC_NA(0.00)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[15];
	RCVD_TLS_ALL(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="FX/p9nMP";
       dkim=neutral (no key) header.i=@suse.cz;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/27/25 08:20, Harry Yoo wrote:
> On Thu, Oct 23, 2025 at 03:52:31PM +0200, Vlastimil Babka wrote:
>> At this point we have sheaves enabled for all caches, but their refill
>> is done via __kmem_cache_alloc_bulk() which relies on cpu (partial)
>> slabs - now a redundant caching layer that we are about to remove.
>> 
>> The refill will thus be done from slabs on the node partial list.
>> Introduce new functions that can do that in an optimized way as it's
>> easier than modifying the __kmem_cache_alloc_bulk() call chain.
>> 
>> Extend struct partial_context so it can return a list of slabs from the
>> partial list with the sum of free objects in them within the requested
>> min and max.
>> 
>> Introduce get_partial_node_bulk() that removes the slabs from freelist
>> and returns them in the list.
>> 
>> Introduce get_freelist_nofreeze() which grabs the freelist without
>> freezing the slab.
>> 
>> Introduce __refill_objects() that uses the functions above to fill an
>> array of objects. It has to handle the possibility that the slabs will
>> contain more objects that were requested, due to concurrent freeing of
>> objects to those slabs. When no more slabs on partial lists are
>> available, it will allocate new slabs.
>> 
>> Finally, switch refill_sheaf() to use __refill_objects().
>> 
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 235 ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++--
>>  1 file changed, 230 insertions(+), 5 deletions(-)
>> 
>> diff --git a/mm/slub.c b/mm/slub.c
>> index a84027fbca78..e2b052657d11 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -3508,6 +3511,69 @@ static inline void put_cpu_partial(struct kmem_cache *s, struct slab *slab,
>>  #endif
>>  static inline bool pfmemalloc_match(struct slab *slab, gfp_t gfpflags);
>>  
>> +static bool get_partial_node_bulk(struct kmem_cache *s,
>> +				  struct kmem_cache_node *n,
>> +				  struct partial_context *pc)
>> +{
>> +	struct slab *slab, *slab2;
>> +	unsigned int total_free = 0;
>> +	unsigned long flags;
>> +
>> +	/*
>> +	 * Racy check. If we mistakenly see no partial slabs then we
>> +	 * just allocate an empty slab. If we mistakenly try to get a
>> +	 * partial slab and there is none available then get_partial()
>> +	 * will return NULL.
>> +	 */
>> +	if (!n || !n->nr_partial)
>> +		return false;
>> +
>> +	INIT_LIST_HEAD(&pc->slabs);
>> +
>> +	if (gfpflags_allow_spinning(pc->flags))
>> +		spin_lock_irqsave(&n->list_lock, flags);
>> +	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>> +		return false;
>> +
>> +	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>> +		struct slab slab_counters;
>> +		unsigned int slab_free;
>> +
>> +		if (!pfmemalloc_match(slab, pc->flags))
>> +			continue;
>> +
>> +		/*
>> +		 * due to atomic updates done by a racing free we should not
>> +		 * read garbage here, but do a sanity check anyway
>> +		 *
>> +		 * slab_free is a lower bound due to subsequent concurrent
>> +		 * freeing, the caller might get more objects than requested and
>> +		 * must deal with it
>> +		 */
>> +		slab_counters.counters = data_race(READ_ONCE(slab->counters));
>> +		slab_free = slab_counters.objects - slab_counters.inuse;
>> +
>> +		if (unlikely(slab_free > oo_objects(s->oo)))
>> +			continue;
>> +
>> +		/* we have already min and this would get us over the max */
>> +		if (total_free >= pc->min_objects
>> +		    && total_free + slab_free > pc->max_objects)
>> +			continue;

Hmm I think I meant to have break; here. Should deal with your concern below?

>> +		remove_partial(n, slab);
>> +
>> +		list_add(&slab->slab_list, &pc->slabs);
>> +
>> +		total_free += slab_free;
>> +		if (total_free >= pc->max_objects)
>> +			break;
> 
> It may end up iterating over all slabs in the n->partial list
> when the sum of free objects isn't exactly equal to pc->max_objects?

Good catch, thanks.

>> +	}
>> +
>> +	spin_unlock_irqrestore(&n->list_lock, flags);
>> +	return total_free > 0;
>> +}
>> +
>>  /*
>>   * Try to allocate a partial slab from a specific node.
>>   */
>> @@ -4436,6 +4502,38 @@ static inline void *get_freelist(struct kmem_cache *s, struct slab *slab)
>>  	return freelist;
>>  }
>>  
>>  /*
>>   * Freeze the partial slab and return the pointer to the freelist.
>>   */
>> @@ -5373,6 +5471,9 @@ static int __prefill_sheaf_pfmemalloc(struct kmem_cache *s,
>>  	return ret;
>>  }
>>  
>> +static int __kmem_cache_alloc_bulk(struct kmem_cache *s, gfp_t flags,
>> +				   size_t size, void **p);
>> +
>>  /*
>>   * returns a sheaf that has at least the requested size
>>   * when prefilling is needed, do so with given gfp flags
>> @@ -7409,6 +7510,130 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>>  }
>>  EXPORT_SYMBOL(kmem_cache_free_bulk);
>>  
>> +static unsigned int
>> +__refill_objects(struct kmem_cache *s, void **p, gfp_t gfp, unsigned int min,
>> +		 unsigned int max)
>> +{
>> +	struct slab *slab, *slab2;
>> +	struct partial_context pc;
>> +	unsigned int refilled = 0;
>> +	unsigned long flags;
>> +	void *object;
>> +	int node;
>> +
>> +	pc.flags = gfp;
>> +	pc.min_objects = min;
>> +	pc.max_objects = max;
>> +
>> +	node = numa_mem_id();
>> +
>> +	/* TODO: consider also other nodes? */
>> +	if (!get_partial_node_bulk(s, get_node(s, node), &pc))
>> +		goto new_slab;
>> +
>> +	list_for_each_entry_safe(slab, slab2, &pc.slabs, slab_list) {
>> +
>> +		list_del(&slab->slab_list);
>> +
>> +		object = get_freelist_nofreeze(s, slab);
>> +
>> +		while (object && refilled < max) {
>> +			p[refilled] = object;
>> +			object = get_freepointer(s, object);
>> +			maybe_wipe_obj_freeptr(s, p[refilled]);
>> +
>> +			refilled++;
>> +		}
>> +
>> +		/*
>> +		 * Freelist had more objects than we can accomodate, we need to
>> +		 * free them back. We can treat it like a detached freelist, just
>> +		 * need to find the tail object.
>> +		 */
>> +		if (unlikely(object)) {
>> +			void *head = object;
>> +			void *tail;
>> +			int cnt = 0;
>> +
>> +			do {
>> +				tail = object;
>> +				cnt++;
>> +				object = get_freepointer(s, object);
>> +			} while (object);
>> +			do_slab_free(s, slab, head, tail, cnt, _RET_IP_);
>> +		}
> 
> Maybe we don't have to do this if we put slabs into a singly linked list
> and use the other word to record the number of objects in the slab.

You mean we wouldn't have to do the counting? I think it wouldn't help as
the number could become stale after we record it, due to concurrent freeing.
Maybe get_freelist_nofreeze() could return it together with the freelist as
it can get both atomically.
However the main reason for the loop is is not to count, but to find the
tail pointer, and I don't see a way around it?

>> +
>> +		if (refilled >= max)
>> +			break;
>> +	}
>> +
>> +	if (unlikely(!list_empty(&pc.slabs))) {
>> +		struct kmem_cache_node *n = get_node(s, node);
>> +
>> +		spin_lock_irqsave(&n->list_lock, flags);
> 
> Do we surely know that trylock will succeed when
> we succeeded to acquire it in get_partial_node_bulk()?
> 
> I think the answer is yes, but just to double check :)

Yeah as you corrected, answer is no. However I missed that
__pcs_replace_empty_main() will only let us reach here with
gfpflags_allow_blocking() true in the first place. So I didn't have to even
deal with gfpflags_allow_spinning() in get_partial_node_bulk() then. I think
it's the simplest solution.

(side note: gfpflags_allow_blocking() might be too conservative now that
sheafs will be the only caching layer, that condition could be perhaps
changed to gfpflags_allow_spinning() to allow some cheap refill).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/113a75f7-6846-48e4-9709-880602d44229%40suse.cz.
