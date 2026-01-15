Return-Path: <kasan-dev+bncBDXYDPH3S4OBBS4HUTFQMGQEPZTCYEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D1C2D25323
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 16:12:13 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-59b796a0d0asf772459e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 07:12:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768489932; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qxsq3l970TWLLZeQNLL1jkherJlyUmjWHB7wFYfjOXrmiuM8Ja440QmoCaZVKOrp9S
         NyXiJjWkb8VJIJm0ITvDwW1Iq3adiz6Xe3A8oFZOPOpucuDdXsM7HTN4ByKlg1WqPhbp
         itEbeNxh2ADCy4OYi5SoC1wHI9Q6YoBO6BMLhB/SNDJCHEbGed/FSl4bcrjuA8izaZ7X
         yyGN4n7L6Q+GCIvI2ofneSFhTCsKSFP5nlELapDYv7bsM9ObFKffYAF4JIQTqvjMpXlm
         04n6JZZZeKmFW4snnoXO9HwuVunk9w7tqiKDfURNZ0nfS/Jv/UZLiKBpJwEfRXsqk8jn
         xoqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=xZt0kVDkN2F8Ep9AXddTpFbAQ/kMmlSVHjw2RvwuMGE=;
        fh=epr59Ap/EY2qGTiaoWlMiMBSlUz3csC7g+Zsyoo4jY8=;
        b=HsSGfNvwQaIWSI9qdmzSrXB/CpI2gRL8EPZU+o3pz+JO9rdTi1f4xQxFPags81cFyh
         ohn+B+6SmDg8A0WY4x+hqG9h0RH766UG3ts7lkhApIakhGDoM5b/zoCiJzj3FEE52CqD
         h7BBbWVFmQUK7l4YxzaDM2qCirJHdVvNBrHLu9daoHyJp+xp5Im7NbJwXFEgIDFd/WiO
         eo1CjzkGmpwUWeEjYqJpWz7D577ayTkQYWSfmNqllFuhFJuwb2bzzqda+2dGuvmEV9Ak
         Cayzg7kYaH5BeEZYxX31GLH1/2zfk1hH5RflQPSrxMa9MjEECQcty7A6cCuQOLWIHdQi
         7vMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oe+Td0k4;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oe+Td0k4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768489932; x=1769094732; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xZt0kVDkN2F8Ep9AXddTpFbAQ/kMmlSVHjw2RvwuMGE=;
        b=Ya3TclV2O79e5yb01BdLP316sGt5kNTI/PGz31ZYTtcXJ3tUmiYRn7dfII4a3UVSic
         ajbwBu+wBwxFWJumyjNYC5boigE62V/UrH6OC+JkWKLrzKVweMz1xcsB95c93wAzmWW7
         ZU65+rUQ8JlXovJCTT2RK3ubpCIjFUIrKll9inMS4FQ+UjjDctdWn80Z2dLr75AGcAey
         Hpie9ppVsTSMLV9T2dnt+dSZSa2XHRIp3lnshrnhDPCxz9aKzXSClhLxBeqC979FQYdw
         VwGEnmIsslJ6Pm/aQkVrHOcEHkmyWnSKgcmYxL3YYtwD+DqHp58I28/0mFBoOVJcmps4
         Ee8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768489932; x=1769094732;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xZt0kVDkN2F8Ep9AXddTpFbAQ/kMmlSVHjw2RvwuMGE=;
        b=rKKCgteP7yHEdzj9sxzHXQ6WKMMKA1LOlqrwU53ShTdV8hhdEwWWz8GUdTl/9BgMib
         bWp0W43jCNWBEHF/chlMATjcclbtXQCFYdcm+E1Hb8OpBf5Vm64Kc+WKu24pHxOPAPni
         VNvdawFkkAxXDoMPN6AXdktNaB2d2/hnV0n0MpYjzXJ/xhrnFXInFnVP8gt3zQqjICe2
         iYVnnPepgaXzsfFgDJAjSTnYUt8+ODihOBfh/4Pi2ld6uXQR2MsYa6+Rct+2GHKbofr0
         U34SbZ1ZmM5YVmgNciCUlFKPj6l69kyeu+h/mq4RBQMHAi1MwwCv/xEC2tfPplt3hkLD
         s+dA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWFfIrBREq0F5RIIwRN2u9Wxcz01dbYYVmZCppVaYHEqOG1/x6Q9RlVPyFyeJ5oBNddn5HzNQ==@lfdr.de
X-Gm-Message-State: AOJu0YwF9HXmD+OTc+UwU6RDtJkKzh4tz1hESzWlQCl6ofmq67uhA7E/
	mhn/SpHm0RAQGvk15Uaac9D2CX8lkeLkWHH41nUzTwCmy+z+8nyA2N4D
X-Received: by 2002:a05:6512:1325:b0:597:d6f0:8816 with SMTP id 2adb3069b0e04-59ba0f5e246mr2250513e87.7.1768489932092;
        Thu, 15 Jan 2026 07:12:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FrcyP7cPrF11lzYpi9oRmC8USOee1vpBhT8TJHHIDJ3A=="
Received: by 2002:a05:651c:4356:20b0:383:eee:5e20 with SMTP id
 38308e7fff4ca-3836efe9453ls666391fa.1.-pod-prod-09-eu; Thu, 15 Jan 2026
 07:12:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvwR+U1JhHPhTCLMAEg39tViTMfA2qRZ/4RMy8VDA72+uqdZ6ojRHgC7DnNXSVuyL8KBXOMcB8s/4=@googlegroups.com
X-Received: by 2002:a05:651c:508:b0:383:5482:b853 with SMTP id 38308e7fff4ca-383842bcaeemr92981fa.21.1768489928924;
        Thu, 15 Jan 2026 07:12:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768489928; cv=none;
        d=google.com; s=arc-20240605;
        b=d6MqFeOgiHu8YE+VuhQcrz0mPvsP9qU5fn+WwngcIuroNH9HKDNiXZkVhBDvGLDch2
         07MgBF/TSKAQbkXxVYokJx22O/NpJvMq18sIQzfPRmdLEvktb+n9i5JQoYE1DqolrhJS
         XGSwH281zpXgrVKVPqSjnGXwdAMMpdpsVwwa4Cwam7GNg06m0jg+WsbZX7XhxrjT4Xpo
         Cj5hhQe25+CezPpdmVjZrJAcF/iZT8o29WMxzITXy0/8YRbx1IQxVN1xMGKwYQQ9Q3FY
         cm3Bq4iHItN2d9zkzmnT8EkOQnUO2yU2FoBck48PSrOVuwG9ZZn6Cw4j0spHd5fp4PaA
         CAVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=elMJW99Aqg4ZRWyy1Tm+k4UtFI51uPd4F2wPebrnoJE=;
        fh=hsHBnuEFqOuHSK1NJ3mYJ9Sw4UDQd+nM7Ij3ICXe4YQ=;
        b=lfJ3WQp+htGGG4dCVaM8qHhblaMB90QUgfOKYH8OhVXzWIF8nw7nS18J5jznTpfuff
         CDtU+rPndNRyPhwUDA7DEii5ZXKsAvBKlgXF78PungGAw4Gy9xotryAPY9UTDgX/KOYI
         DeHuAVgq4cnYT5hj3BGrYV7wYXb68hn/TRURndnmaD9t/rClvsYBrGOAA3kngtoL61O5
         jmAr2IlWqxxx0y5/BAzjlNwIUdpfe3i07J7V7D3HDK++1TExH76P/W5Rst5sYTasN/16
         TTKApvpLkDYvJ2BaXs1Omw6FMLrCFV/XuA/oSY7TDzuxfKaFpvvc7f0ZeauZXKTu68aK
         WXqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oe+Td0k4;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Oe+Td0k4;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382ecb22dfbsi4425671fa.3.2026.01.15.07.12.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jan 2026 07:12:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 180513378D;
	Thu, 15 Jan 2026 15:12:08 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E790C3EA63;
	Thu, 15 Jan 2026 15:12:07 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id vcoBOMcDaWlcEgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 15 Jan 2026 15:12:07 +0000
Message-ID: <8c508b65-3b80-4b91-afa0-145b44686b6a@suse.cz>
Date: Thu, 15 Jan 2026 16:12:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v2 00/20] slab: replace cpu (partial) slabs with
 sheaves
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 kernel test robot <oliver.sang@intel.com>, stable@vger.kernel.org
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
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
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[19];
	MIME_TRACE(0.00)[0:+];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,intel.com];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 180513378D
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Oe+Td0k4;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Oe+Td0k4;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/12/26 16:16, Vlastimil Babka wrote:
> Percpu sheaves caching was introduced as opt-in but the goal was to
> eventually move all caches to them. This is the next step, enabling
> sheaves for all caches (except the two bootstrap ones) and then removing
> the per cpu (partial) slabs and lots of associated code.
> 
> Besides (hopefully) improved performance, this removes the rather
> complicated code related to the lockless fastpaths (using
> this_cpu_try_cmpxchg128/64) and its complications with PREEMPT_RT or
> kmalloc_nolock().
> 
> The lockless slab freelist+counters update operation using
> try_cmpxchg128/64 remains and is crucial for freeing remote NUMA objects
> without repeating the "alien" array flushing of SLUB, and to allow
> flushing objects from sheaves to slabs mostly without the node
> list_lock.
> 
> This v2 is the first non-RFC. I would consider exposing the series to
> linux-next at this point.
> 
> Git branch for the v2:
>   https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=sheaves-for-all-v2

The current state with collected fixes:

https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=b4/sheaves-for-all


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8c508b65-3b80-4b91-afa0-145b44686b6a%40suse.cz.
