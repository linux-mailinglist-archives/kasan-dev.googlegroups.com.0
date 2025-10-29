Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOEPRLEAMGQEK4QW67Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D5C7DC1D72E
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 22:31:37 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-477113a50fcsf1904195e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 14:31:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761773497; cv=pass;
        d=google.com; s=arc-20240605;
        b=kYiofN5TNBv2q+Zy4leiSk71s0EeuBEGo0lIcFVjqkjzYWuFXg4AmXyAINKmslOTCB
         MH5P0aq8egWSQ0NoFX+dpXZJpDa54Z3bJyMu36So9jhxZSOX8+sJN8AKXgUQ//YWgCuv
         ZrB4hgGD+Bb1aGC+GLBb1pLDly94ZCDIWkk7kO5wsw1Pf8lycVHzbI6RJKsN0d/RxwWX
         Rh/Qrcnj5rI6bcd/iJ+VSrV/mSQIuzyORt/lZyYkzam5qH34K/sqWwsx6abUbOt02AbG
         r+7fGTkCed74+CbI6BKhBoHZX6eTIYxiMX893CCAigOWgP8DVWFMjKR7b4ral/0nWT4p
         5f/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=wrU8xqEGGyHUsszZBpemTcXMvyH8MJ7F3H36m3NZ09s=;
        fh=fY96byOLIQyqIHWqz0Rq6tGmQzDhmRNj9ZAGQvE4neg=;
        b=GHUdskx7aGKiKkgjIOS16ZjQYV6WP17oOLJbTx2VITYJSK5ZVkh2LKCQ85reZae10l
         aml9yv5qr1vMbohKNXwOdoguarZD0z7S/Dd4gajd0yGtsDLHmdrP7szUXGieoWqB4OKB
         VqvWNfSRE8zKuVecG+cbvQYyc6Qxbdttj3/D4HPItvSJ6mYOGHoxngo7NNQm3QIInQrz
         4+CbTblJvEvgWc55MlF8cFEv3smy7vV/1O6WVo/RHHmpFVVGlMKrib+RTFp/ARqEHaBO
         Ciw9Cnu/4CcrhcWXfp+erigDh9kwayb7K2TuuvFp4DxkZuKeZlT8dYrQb6bFeDKKBnqz
         1BIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tDtOAFjD;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tDtOAFjD;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761773497; x=1762378297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wrU8xqEGGyHUsszZBpemTcXMvyH8MJ7F3H36m3NZ09s=;
        b=mlT3WIq1oEhp9GFFsvMQwdow8+xEVwxrzi58ZuFttrUqdUZ/BQmi84h+S0rD7kOtPS
         igFKc4awITrX2VqKc5UGtLD2bogzhKqMM4m7QlginqtiG6CdXZHf5eIaWqjs5KCHFTBC
         nRV9YICNbm3F4Eax5qV5q2HayeM59naYLKgUvd+k7k8GcN1s4sHOpAQfuq5ob1Lq7vRT
         2Yqi6sxhmzM+gdsUdRp/P9m5SwAbpCGeukjbTCNU1CZi9eQZgSSLr2DztJxgFb5sqdDP
         61n+nmGlGQpWTs7zlB2QpH+hBTXhm3otDYQ10s5UgNv+6YIt74lLWC21ynG81VcRX/ry
         G88Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761773497; x=1762378297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wrU8xqEGGyHUsszZBpemTcXMvyH8MJ7F3H36m3NZ09s=;
        b=Era/Z3A/69ywtgszkHco+urE8a+VJImmh9wgzpwMd0ywnGjeWqklFilClblot0FFcT
         up+nc506NYxxQlvNHj1Biflj9pMGsq/cKu3aKTUvzd5bpwYBAjJcLthZDhSkfmUk03NX
         MggeU4zqzJPcK7O9f0u3srysmbRn+NGelwrO9i7Y3hJzWzGUWvhHMTaTCmhulxveFjWp
         k8/MY5K7hWxtrEPjTS5sqIatB+q0oUheOOdg6BLJiy4Rcu9nWe712eE1ewusNtHYNuTW
         MDxQOEVttgVvLhJezw1Vi155HtkcVhvaZWS5ZP3meoDcCss6JCLeN5bNp0B0VWFZuEHm
         nRzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUxYZ6Jpw9qpZv4OpPzZbIyz8cTtdY1R/gHpbLVREtNZ1BS3nzVi4j/ZRzdALZcf26hUNqLJw==@lfdr.de
X-Gm-Message-State: AOJu0Yzq7B6DX1I4ui00CJr6Ndct7hll0ZNUyc7G4OgraG1/9epA3sdg
	96jSvzFWs274Ird/YEParkdZZtX2033wI/c4MQ0aL8sS+RkUIA/c2ted
X-Google-Smtp-Source: AGHT+IERsZFxno2gP9+5+D8HFS5gC3bk/wiFzlO2Epb+LM71UKvBJRcoFkX3FlhFMy4GbrRxESm/mA==
X-Received: by 2002:a05:600c:4708:b0:475:d8c8:6894 with SMTP id 5b1f17b1804b1-4771e34a956mr39577975e9.9.1761773497233;
        Wed, 29 Oct 2025 14:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aeoronW8SfqYOnb7Vk/43Hg1XhfsgSsCsKNLF3+yFjdg=="
Received: by 2002:a05:600c:1c9e:b0:459:ddca:2012 with SMTP id
 5b1f17b1804b1-477279fa893ls1196815e9.2.-pod-prod-05-eu; Wed, 29 Oct 2025
 14:31:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnpBLfkL3jIX60rVTNOr5Oxu9uZVAjn3oDxHoCstMD1OiZUz7GrSbf1QgFFCJPbo9QmKl63ucg4Vo=@googlegroups.com
X-Received: by 2002:a05:600d:8307:b0:471:133c:4b9a with SMTP id 5b1f17b1804b1-47722c8d852mr19320985e9.6.1761773494331;
        Wed, 29 Oct 2025 14:31:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761773494; cv=none;
        d=google.com; s=arc-20240605;
        b=iqCY8k1JqApigxM4KipwGsS+tx9ZoQ6PE8u9x56waAcUeZ2x6n4tGsyLiOpQnhfW1o
         fxg1fcdXLMJ2zb1XhlPoDuykpxhwxefqLmJIgUGrcgVbNNhaHeG42T77TzE/llKiga7N
         92JOx5ilyuYSXIL73XIc/FqRllK/kdGUUIYpN0awZ08OLfzFF5dyREwUCLNN+27Hb5OD
         5b1/W2R75W3ixY3/Mn4UWLF6OewjiaF7qFw/ugLSj61aZtF1M/uYd8h7raLOu30oiHfM
         lCy2Dy8vKMuOBGX9VxVY8XM4pXZDQ+1zu7iMZF7PPsLjkXlxLRnKsvbWUIJgzdJr0FAd
         k+Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=teyx4ePeKu0+OEWBtNCRjoDpTuwA8U7pzqN5XpR9ge0=;
        fh=o5F+zdD+BrF1g389dqaHWhI8yyYLrSzZl2Fw5mCrJ38=;
        b=i6xzkuRe819DUukJUIW2LcSSwjsS0FgPIkLS36iZdVXIeQGslLMWSqrDgsKaQjS0HY
         Zl/qwKezHOl7pQZlXTXS5X5EYEBWqZDhd9FmE1E2Vo3tm4Cb5kEdNwuo7aYwFecxXXTh
         gDMB8A7N2TSEc+ej8aVuxTC0f0v5I9QXmTPpwejHgy3+L/KtDbAQ4POmswYEym7zw/+5
         KAm0kQmAoXsyJkjfR5PWmyL90HupqNZeT5GqEgcKMGd6suGf+KYsC38iWWZW9p0T0Jeo
         kyWXTTpvMz74FXc/Fg8Q1/0sajY/YhorILFrcVTgWwMsesAvF0XC/siD8UF4onXIL/HH
         mGZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tDtOAFjD;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=tDtOAFjD;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47727fc5eb9si30035e9.0.2025.10.29.14.31.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 14:31:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id A9F7220F8E;
	Wed, 29 Oct 2025 21:31:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 881DB1396A;
	Wed, 29 Oct 2025 21:31:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id bKLiILWHAmkGTwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 21:31:33 +0000
Message-ID: <937b6cb3-27d5-4416-8152-df12b45979be@suse.cz>
Date: Wed, 29 Oct 2025 22:31:33 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
Content-Language: en-US
To: Chris Mason <clm@meta.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20251024142927.780367-1-clm@meta.com>
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
In-Reply-To: <20251024142927.780367-1-clm@meta.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: A9F7220F8E
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=tDtOAFjD;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=tDtOAFjD;       dkim=neutral (no key)
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

On 10/24/25 16:29, Chris Mason wrote:
>>  	else if (!spin_trylock_irqsave(&n->list_lock, flags))
>>  		return NULL;
>>  	list_for_each_entry_safe(slab, slab2, &n->partial, slab_list) {
>> +
>> +		unsigned long counters;
>> +		struct slab new;
>> +
>>  		if (!pfmemalloc_match(slab, pc->flags))
>>  			continue;
> 
> Can get_partial_node() return an uninitialized pointer? The variable
> 'object' is declared but never initialized. If all slabs in the partial
> list fail the pfmemalloc_match() check, the loop completes without
> setting 'object', then returns it at the end of the function.
> 
> In the previous version, the equivalent 'partial' variable was explicitly
> initialized to NULL. When all slabs were skipped, NULL was returned.

Indeed, this can happen. Thanks!
>>
>>  		if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
>> -			void *object = alloc_single_from_partial(s, n, slab,
>> +			object = alloc_single_from_partial(s, n, slab,
>>  							pc->orig_size);
>> -			if (object) {
>> -				partial = slab;
>> -				pc->object = object;
>> +			if (object)
>>  				break;
>> -			}
>>  			continue;
>>  		}
>>
>> -		remove_partial(n, slab);
>> -
>> -		if (!partial) {
>> -			partial = slab;
>> -			stat(s, ALLOC_FROM_PARTIAL);
>> -
>> -			if ((slub_get_cpu_partial(s) == 0)) {
>> -				break;
>> -			}
>> -		} else {
>> -			put_cpu_partial(s, slab, 0);
>> -			stat(s, CPU_PARTIAL_NODE);
>> -
>> -			if (++partial_slabs > slub_get_cpu_partial(s) / 2) {
>> -				break;
>> -			}
>> -		}
>> +		/*
>> +		 * get a single object from the slab. This might race against
>> +		 * __slab_free(), which however has to take the list_lock if
>> +		 * it's about to make the slab fully free.
>> +		 */
>> +		do {
>> +			object = slab->freelist;
>> +			counters = slab->counters;
>> +			new.freelist = get_freepointer(s, object);
>> +			new.counters = counters;
>> +			new.inuse++;
>> +		} while (!__slab_update_freelist(s, slab,
>> +			object, counters,
>> +			new.freelist, new.counters,
>> +			"get_partial_node"));
>> +
>> +		if (!new.freelist)
>> +			remove_partial(n, slab);
>>  	}
>>  	spin_unlock_irqrestore(&n->list_lock, flags);
>> -	return partial;
>> +	return object;
>>  }
> 
> [ ... ]
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/937b6cb3-27d5-4416-8152-df12b45979be%40suse.cz.
