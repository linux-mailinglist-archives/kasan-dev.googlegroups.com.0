Return-Path: <kasan-dev+bncBDXYDPH3S4OBBE7VW7FQMGQEHB23KNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5306D3A323
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:34:13 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59b686eaeafsf3608237e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:34:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815253; cv=pass;
        d=google.com; s=arc-20240605;
        b=jrV5oHgU+djxfGAtT9P7J/cK1b2Y8pFBFkjFe792WzIFZqdGZNoi3iZMvRfx10Ghax
         Ki8IuG4kTseSyniDbxuZZgXXnIrclH5fE/xqx8hlXTKEHoeQQst4zEqOW5/zD8y4zPa4
         KoGF9IY67y4nakZIuNgucgNOUBfnelpUljNEhKkFp408S0jk+r043IIatuFPAg8HiBtg
         qhx3eMX+hHrqxXpy3H+0V1nXTKStxcbEm7ZFU28cF5Ks+RW9xDOqW+Hb1Y+qshdZ9aB+
         Oo9v3EHxJSTe7Opko4C/H4/IKqpInzKMy8BDn67dp/U6t4cDrpXdUgxL51rHraIGSEnV
         jz9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=E48zD7k8F6t98452xvfOrsd9VQRSLW4khwbMPsooxWo=;
        fh=l1HxLKLhbP57j48mVW0Vp5iKqfGHQS3A5YcTfL7+A+s=;
        b=X7j7CD8aAfc2njsagwtzgcCH4KtWxVx6EMRfpfV87XoC+vlgTQwtkWnS5skF1quMkm
         M252IhpnsZqvxHEmlP25CBZFsXb0Zpnypk8C0LsPrxsIm4EycOAqh8NOw2kURZWYfYNV
         bvU9uUHW+2JycGt964Z3u7q/PKLpWQ5ruBPG6GqhRscBlqoKhUmnV8wA6yNklS6zQxkT
         k2fNzXIiYpAjIGBZnDlxlB0hJ/oqcKsP9I+OKdw7nS5w0bXU5bStxn5ujgEgZUOcMjiD
         x0+/9d8bXsPY2516qE2RlPXHvT24fDxj/zNFbzPjaiqCoRbFEVynUnNAONWK4OMZougu
         l7Fg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YV3pO5JV;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YV3pO5JV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815253; x=1769420053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E48zD7k8F6t98452xvfOrsd9VQRSLW4khwbMPsooxWo=;
        b=WxiJlKmIGStTQP8gPQenjNsqZx7CTn6NL0aUS7zB4sQO44PtmBKFt75HAGR+z5lNPe
         kH+vAfcSapXlShGrQ+EeJ+5Upttjxex8x9mrUQCkSq+IiOvpk47R8JBFO/YNA4UxiHD3
         nbmYfX6dR5pJhF//dyYxCHX4mKcDqxiFHCT4spob5K/x0uEPHvJSLKOtSGW7OHRUcmxU
         vK4FwPBfObIj6Ptv1x/2hGvgzdiJtPvc64KA5mMEos+fNbnzQtaMngLSJ0tS5ZshDtA6
         i07OtrJV0t9GP9UkmUSBInBIA6OClYdLPmdL+6p/UpYHJGkHh77u+NsdA/ju/4zaQBvH
         2vQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815253; x=1769420053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E48zD7k8F6t98452xvfOrsd9VQRSLW4khwbMPsooxWo=;
        b=BYATsf7zkMMiLq8Wagvce5X9+FC/2hRPUZoygFiwZcfdSXS8KJM0m4wsHXijNJ9fS4
         Q6Wek8mJ0U6NWylcc1aEsMBvdpklAAPGe5+gbYpJs/THa64d4OthR1JjnJwLam2GcyC7
         2+HANksZCMvzGyg4aTBYh3BVznq/Vupva4FkUgyiHwyzFUHYNjMiv/PdavOpJx6buogv
         y9RQ5+jPQwbOzhA4eu5c0k0BasGaML7sBeM7Q0DF4nQBfPUdOWWCQlBOpAAG7tkjPpLE
         tUGIMvmoO2pJKeM63x6TVBVsi5p21YEw37jcyP9gNTE3p8lxgWjBg4tZT7c9abZzTc3k
         3dJw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqhPDB5uhk0vd5IdCcccARb0N4A37txdwbKB5giMUU/HqTg9Geyh5jN3FcvpvrAB6inXEXvg==@lfdr.de
X-Gm-Message-State: AOJu0YzMfy2Vvh2hU1+ErtbbXfsRWZzXUAOQ0HFF/u84rA6EaL4P80Ca
	v7KM+ZvHyEKPXPMhGUCFocYmQhxq83xMLCn0bgwPr7hv98GkcmJWM0bw
X-Received: by 2002:a05:6512:3b20:b0:59b:7b84:df69 with SMTP id 2adb3069b0e04-59bafdb2c8dmr3021827e87.6.1768815252388;
        Mon, 19 Jan 2026 01:34:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F6rHt8Fdm4FvqKOZX6v08XfMKjUBTIc4DZP5ABfXpEWA=="
Received: by 2002:a05:651c:c8:b0:37b:97ac:627b with SMTP id
 38308e7fff4ca-3836ee24901ls6245371fa.2.-pod-prod-06-eu; Mon, 19 Jan 2026
 01:34:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW+fclWn14kaAyNVUkhc4UdBwjAAWrptWJGRtSZgNMGZfLK54t5srkjnRMag9OWiMAbhFWn5H1dnOw=@googlegroups.com
X-Received: by 2002:a2e:bea2:0:b0:383:20cd:52fe with SMTP id 38308e7fff4ca-383866fd63cmr38808331fa.17.1768815249278;
        Mon, 19 Jan 2026 01:34:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815249; cv=none;
        d=google.com; s=arc-20240605;
        b=ELA9Dt9y/0+uxs0dWIC9PXwN5Sj2FHu1h1mWLYQyF3zh3eXdgBZt+iNnItP+TdgB45
         TfBGYlq9nYXraRI73E4Am9RQcrZotOa/ErM4L7KSSt1yKRK4OqbX+Imj1DUm5MC4H15y
         LvfxWdTCPMnU2i30eMI6yQIEJU/s/+8lVzqEuBp76whpE8tiLsfy1HvOtouJ2H1zZNmM
         3HynNtqNlLUdyverOjudf16eAUBr79iJWIeuZQb2YRSbzvvtAkktjMeAV2EiNBhtU0dA
         f15daAyXetcYdHMIVfOhYe0SaiSxMYXXMtOGJxtNSvDEEZAUdVhTIACBjvbZkn+l7qM0
         4h5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=ikLK1Mgji5k5g6jyOPReFRltrTEuDlSX80eK5Jr1uK4=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=KFgbR7CxblarIIBzvSbXVJDwPBpTVpjqCPUQPWi4gSyUPSuUgway/wNe+sD/7XEOKn
         mvPPHr2CReBg+ssV2T5lnetaj+IePZo0RFhI6Cxybea2waE0MABrYTfT2aVueXZ2rQZC
         kBR9ERRH5g4ogyjCjjTdbaCYS90cpM0vX6uFJ6VyK6fCJj0f9Zld1gzvzpEXXen2NnTx
         KkGAM5lxGTnizW6mWv2wvFppZh0FYwaTF4MOmUnuvEXDCZTkra9ablYcFgfkydNlPoVi
         QPOqqyoyxiseGlNknfw6Br0XEm05rj2stLLHeOq6LZ8ybEP6XlZV+gCIy71S4ji7XMmY
         w+VA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YV3pO5JV;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YV3pO5JV;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38384d0ff92si1918841fa.2.2026.01.19.01.34.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 01:34:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4CA145BD44;
	Mon, 19 Jan 2026 09:34:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1EFFC3EA63;
	Mon, 19 Jan 2026 09:34:08 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id QpVoBpD6bWn1WAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 19 Jan 2026 09:34:08 +0000
Message-ID: <4f60e230-c76e-4ab3-a0f0-7598dcb15d1a@suse.cz>
Date: Mon, 19 Jan 2026 10:34:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
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
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
 <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
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
In-Reply-To: <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.51
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Spam-Level: 
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 4CA145BD44
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YV3pO5JV;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=YV3pO5JV;       dkim=neutral (no key)
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

On 1/17/26 03:11, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>> Thus sharing the single bootstrap sheaf like this for multiple caches
>> and cpus is safe.
>>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++-------------=
-------
>>  1 file changed, 81 insertions(+), 38 deletions(-)
>>
>> diff --git a/mm/slub.c b/mm/slub.c
>> index edf341c87e20..706cb6398f05 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -501,6 +501,18 @@ struct kmem_cache_node {
>>         struct node_barn *barn;
>>  };
>>
>> +/*
>> + * Every cache has !NULL s->cpu_sheaves but they may point to the
>> + * bootstrap_sheaf temporarily during init, or permanently for the boot=
 caches
>> + * and caches with debugging enabled, or all caches with CONFIG_SLUB_TI=
NY. This
>> + * helper distinguishes whether cache has real non-bootstrap sheaves.
>> + */
>> +static inline bool cache_has_sheaves(struct kmem_cache *s)
>> +{
>> +       /* Test CONFIG_SLUB_TINY for code elimination purposes */
>> +       return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
>> +}
>> +
>>  static inline struct kmem_cache_node *get_node(struct kmem_cache *s, in=
t node)
>>  {
>>         return s->node[node];
>> @@ -2855,6 +2867,10 @@ static void pcs_destroy(struct kmem_cache *s)
>>                 if (!pcs->main)
>>                         continue;
>>
>> +               /* bootstrap or debug caches, it's the bootstrap_sheaf *=
/
>> +               if (!pcs->main->cache)
>> +                       continue;
>=20
> I wonder why we can't simply check cache_has_sheaves(s) at the
> beginning and skip the loop altogether.
> I realize that __kmem_cache_release()->pcs_destroy() is called in the
> failure path of do_kmem_cache_create() and s->cpu_sheaves might be
> partially initialized if alloc_empty_sheaf() fails somewhere in the
> middle of the loop inside init_percpu_sheaves(). But for that,
> s->sheaf_capacity should still be non-zero, so checking
> cache_has_sheaves() at the beginning of pcs_destroy() should still
> work, no?

I think it should, will do.

> BTW, I see one last check for s->cpu_sheaves that you didn't replace
> with cache_has_sheaves() inside __kmem_cache_release(). I think that's
> because it's also in the failure path of do_kmem_cache_create() and
> it's possible that s->sheaf_capacity > 0 while s->cpu_sheaves =3D=3D NULL
> (if alloc_percpu(struct slub_percpu_sheaves) fails). It might be
> helpful to add a comment inside __kmem_cache_release() to explain why
> cache_has_sheaves() can't be used there.

The reason is rather what Harry said. I'll move the check to pcs_destroy()
and add comment there.

diff --git a/mm/slub.c b/mm/slub.c
index 706cb6398f05..6b19aa518a1a 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2858,19 +2858,26 @@ static void pcs_destroy(struct kmem_cache *s)
 {
 	int cpu;
=20
+	/*
+	 * We may be unwinding cache creation that failed before or during the
+	 * allocation of this.
+	 */
+	if (!s->cpu_sheaves)
+		return;
+
+	/* pcs->main can only point to the bootstrap sheaf, nothing to free */
+	if (!cache_has_sheaves(s))
+		goto free_pcs;
+
 	for_each_possible_cpu(cpu) {
 		struct slub_percpu_sheaves *pcs;
=20
 		pcs =3D per_cpu_ptr(s->cpu_sheaves, cpu);
=20
-		/* can happen when unwinding failed create */
+		/* This can happen when unwinding failed cache creation. */
 		if (!pcs->main)
 			continue;
=20
-		/* bootstrap or debug caches, it's the bootstrap_sheaf */
-		if (!pcs->main->cache)
-			continue;
-
 		/*
 		 * We have already passed __kmem_cache_shutdown() so everything
 		 * was flushed and there should be no objects allocated from
@@ -2889,6 +2896,7 @@ static void pcs_destroy(struct kmem_cache *s)
 		}
 	}
=20
+free_pcs:
 	free_percpu(s->cpu_sheaves);
 	s->cpu_sheaves =3D NULL;
 }
@@ -5379,6 +5387,9 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp_t =
gfp, unsigned int size)
 	struct slab_sheaf *sheaf =3D NULL;
 	struct node_barn *barn;
=20
+	if (unlikely(!size))
+		return NULL;
+
 	if (unlikely(size > s->sheaf_capacity)) {
=20
 		sheaf =3D kzalloc(struct_size(sheaf, objects, size), gfp);
@@ -7833,8 +7844,7 @@ static void free_kmem_cache_nodes(struct kmem_cache *=
s)
 void __kmem_cache_release(struct kmem_cache *s)
 {
 	cache_random_seq_destroy(s);
-	if (s->cpu_sheaves)
-		pcs_destroy(s);
+	pcs_destroy(s);
 #ifdef CONFIG_PREEMPT_RT
 	if (s->cpu_slab)
 		lockdep_unregister_key(&s->lock_key);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4=
f60e230-c76e-4ab3-a0f0-7598dcb15d1a%40suse.cz.
