Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCFGYPFQMGQE2NOC4CI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mNYVDQrTcGkOaAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBCFGYPFQMGQE2NOC4CI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:22:18 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FE215776B
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 14:22:17 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-59b7a803c5dsf588701e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 05:22:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769001737; cv=pass;
        d=google.com; s=arc-20240605;
        b=UWTbyAw4XkYgyI2dZpJJss+vtADePSIqv1Mz7U7pPuah54kMvkl1LPsVgNDIpJyNlf
         RH3x80kZVxKJgfgOqOZYde6XGpI6TUYZ2+f1/7q5JQYZ+CjJljZG9+O+3UvC2GCj2vZh
         MfurQ8xmU//GK/hVqz8UpStOwB8OO14jlM3m9HDKwtXSPV2yXaUsrK9LHi8mA7oZ4+m9
         mXKWYxxJfIqNZgRUiC1LbB+ZCL8cp7upWpaXUMiO4Qu0DnYE0951gCNbH3NhzHC1G6by
         TN/dNpdfx53yutixrVhWprRyh/CMkILncCMRLzBqRlGewa/brxa7YDfWcwteJ/bsnOml
         2byg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=B6y2uKt0EggAgJBesNStyPdPGyWn7AzbtwGAlqQO/Zc=;
        fh=Ht9tWqBRaBPwibG4FlKw5poHFZSih8jRTDSn3sFZUDw=;
        b=OkYP4Zj4uLk1bBYK2ZF76PmPK1FdVQIP7ZR2B9tEJFCW93t+i4ChB6lC4f5mUF4Qe2
         ApM0npO3Mwo/gxZOxOdfBW771CxJ9QcyyzaNHekGo4+d/1D/Ahzuv+0ReHbgJzN3QRts
         mzABxCWDuhd3A4sa8uXA052BKzZgxCuHkEUfZ2h6jO4p7Tahd+VxgmF+J81I0lJzfT/5
         pbahFduEMU5J5udlxOlY2gjv2Igu29E0YX9fYRCqrRtnN7W+KD0r7e1sBZvt5VZG0j+5
         /2qA9AlLcmy/cjbgwu3YL3uspha2sCwfVM9dc4RBKjsQ6lbYLrzIQjLexwFzbmdbmd/V
         vOuA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CKZTLDQ1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CKZTLDQ1;
       dkim=neutral (no key) header.i=@suse.cz header.b=Xv57NFaS;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769001737; x=1769606537; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B6y2uKt0EggAgJBesNStyPdPGyWn7AzbtwGAlqQO/Zc=;
        b=dCjZz+/gck6WeQGPhIRKBv8Ix9bWuy6Jbtd5lKTQ68VuIBHR8sAvbcAsQct+tAYCwt
         lLdXelp93ErYJaOvaMXOy2ZQCkAjRoCKHb8o4HFtLbcaF79I+Wi+W0S5KUfTXnaBJAk2
         z1bIftKXxxCTa4OGRzOFPdL4Pf+nPPjsJYokdC85Q9cX5Y1yirHpX9FvaB46huJhSelC
         ziNlcxU7PivE5pL2HUm5dQGK81GGjwa2EtSyVz8m+nF29KUtWKJPYMFDHof9LyubYhD8
         eS3fg+12lCL9e97c+0+VYL1MXtjK1Zyv2rhid1LKZ9TU+hWdsWP4jXsLkCkQbwKMyJpi
         f8uQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769001737; x=1769606537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=B6y2uKt0EggAgJBesNStyPdPGyWn7AzbtwGAlqQO/Zc=;
        b=uMEnYtbbbBmbaYt/tWHzu2DOfKv0H4kxsvNZTu3zqDAgqSLv7UdzI8zNaVOC6Ly2YV
         Z8mpsr4YicL3SYLHHJ1W1iasIKHgq2ZL3trIVd+stvnf0tJRXtlvtYt4aldatfy3sgDb
         ClqMYhlnEbXbqHrcn/cpVTygC4AS8BOsodWxEyP0nTKGuTDTbA44nrydIoaxfvltEOil
         xlIrVxq2e0CJld6tklxXAUXyqVbLqmPoOybZJXY50E3J4MrYZlvAttRluKMWQH6cPAMl
         rgpMnhgEn7U7EGaRad6A5q9y8eo0Tb/FU67wXEvPtpMl3i6/BcIHkzc3G/iuAwBlo1Qg
         tVKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUuyowIQGS8T7OfZxzcNjUazddAWvfNB7KfMxwSS80YE0uQ9ofl0Z5aGrw9aUNHsF0HCrEmVg==@lfdr.de
X-Gm-Message-State: AOJu0YyD5m0WUmC3YUqFOukBnRI8NZXW9w/9srbq6PxcJQR6poYtoUzX
	CSgbsBtUun1NJZUPmoC/8BY/ak2eswNQ3qyVTMA/0ImWqQB7UdpcjT6g
X-Received: by 2002:a05:6512:2394:b0:59d:cf16:a983 with SMTP id 2adb3069b0e04-59dcf16abbbmr1087108e87.16.1769001736736;
        Wed, 21 Jan 2026 05:22:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FXNlz/LOLAjZXpuookLPHg9OCyNCHz+RIjNcrDr+Trxw=="
Received: by 2002:a05:6512:2247:b0:59b:739a:3ae4 with SMTP id
 2adb3069b0e04-59dcf01a897ls310361e87.2.-pod-prod-00-eu; Wed, 21 Jan 2026
 05:22:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW9C8ycD/aCwbhgrbX7vzmu8e3icjCgnUeWwh+tRIg69mIVlj3FD5O9599m7JhXgRrDewwwQX+G9Hc=@googlegroups.com
X-Received: by 2002:a05:6512:2244:b0:59b:67cf:ac0c with SMTP id 2adb3069b0e04-59baf188751mr5690477e87.17.1769001734000;
        Wed, 21 Jan 2026 05:22:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769001733; cv=none;
        d=google.com; s=arc-20240605;
        b=MSvu77G22bgRXl2h5QD/LgQUku6bmhr0a4geRocxt4S6tTcF2C9YWGGd15f5vaEWmC
         7puBwozsnBx1JYaEkxG9anAfkeoG2Rn88uSjkJ8/YZosMJD6EEK9Ez0svXt4V0Sly4Qh
         MfQDtHlkchZN6ifU9glpp4hzgcTtZDvpfX7AXA5AKhkB9F05G3mMr8r1cCkDaDGq0MwE
         LJjoe6us+QI5Gbtz1VK52bIze8YRb+muYF8jgQMxnOvL0IdchO4jcHBAPBgc/oMZKH1C
         NoiWYtgcXoZwsYtRhlrtVw7no2siAMuFWO13oa1ZBLCCxsZsFOg0Xulja/ZjWI4YDRxY
         fsVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=shsGpPkdTpgh2O3TvGdc0KosuzZDmGShHqMUn9wd7Ck=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=iKu2YQjtFAReezV9OU5/05dArUHiu5HDR4Wh4zSIrn+RJpEKgHD0ln+CUeocmsqY16
         kvhkWdmSM6tp5gq3K/WHsbktX1Z+N3iy/QfEuso2d5mRpwNBc0MH4Trd4i6+4bjsf7RJ
         B+wQS5XWMYeNcjn6lSLSbmFbOQl0f0+JGJFw405vrif7yD5W9jXuW+SEwvUIxuNApAER
         offh2b8c9DlcOM/EPuDYl+D7j9JRVcE4Yw6VoyJRJCFyOMSsQ3A3iD+oTwowfPRPL45a
         yl71VU12KBk1Rg9ZZMt8jiYdE+apmoWvuw8NfURqbZIhRWcz+qIA5ZSm4nHzotY6w2EZ
         6CCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CKZTLDQ1;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=CKZTLDQ1;
       dkim=neutral (no key) header.i=@suse.cz header.b=Xv57NFaS;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf39cbbcsi381533e87.7.2026.01.21.05.22.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 05:22:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1A28D336A1;
	Wed, 21 Jan 2026 13:22:13 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6A6F83EA63;
	Wed, 21 Jan 2026 13:22:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OTCoGQTTcGlWKAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 13:22:12 +0000
Message-ID: <fec4ed92-32e1-4618-99d6-0eac77da1ff3@suse.cz>
Date: Wed, 21 Jan 2026 14:22:12 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 09/21] slab: add optimized sheaf refill from partial
 list
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
 <20260116-sheaves-for-all-v3-9-5595cb000772@suse.cz>
 <CAJuCfpErRjMi2aCCThHiS1F_LvaXjkVQvX9kJjqrpw8YnXoNBA@mail.gmail.com>
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
In-Reply-To: <CAJuCfpErRjMi2aCCThHiS1F_LvaXjkVQvX9kJjqrpw8YnXoNBA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=CKZTLDQ1;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=CKZTLDQ1;       dkim=neutral (no key)
 header.i=@suse.cz header.b=Xv57NFaS;       spf=pass (google.com: domain of
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBCFGYPFQMGQE2NOC4CI];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,suse.cz:mid,mail-lf1-x138.google.com:rdns,mail-lf1-x138.google.com:helo]
X-Rspamd-Queue-Id: 9FE215776B
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/20/26 18:19, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
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
>> Introduce alloc_from_new_slab() which can allocate multiple objects from
>> a newly allocated slab where we don't need to synchronize with freeing.
>> In some aspects it's similar to alloc_single_from_new_slab() but assumes
>> the cache is a non-debug one so it can avoid some actions.
>>
>> Introduce __refill_objects() that uses the functions above to fill an
>> array of objects. It has to handle the possibility that the slabs will
>> contain more objects that were requested, due to concurrent freeing of
>> objects to those slabs. When no more slabs on partial lists are
>> available, it will allocate new slabs. It is intended to be only used
>> in context where spinning is allowed, so add a WARN_ON_ONCE check there.
>>
>> Finally, switch refill_sheaf() to use __refill_objects(). Sheaves are
>> only refilled from contexts that allow spinning, or even blocking.
>>
>=20
> Some nits, but otherwise LGTM.
> Reviewed-by: Suren Baghdasaryan <surenb@google.com>

Thanks.

>=20
> From the above code it seems like you are trying to get at least
> pc->min_objects and as close as possible to the pc->max_objects
> without exceeding it (with a possibility that we will exceed both
> min_objects and max_objects in one step). Is that indeed the intent?
> Because otherwise could could simplify these conditions to stop once
> you crossed pc->min_objects.

Yeah see my reply to Harry, it's for future tuning.
=20
>> +       if (slab->freelist) {
>=20
> nit: It's a bit subtle that the checks for slab->freelist here and the
> earlier one for ((slab->objects - slab->inuse) > count) are
> effectively equivalent. That's because this is a new slab and objects
> can't be freed into it concurrently. I would feel better if both
> checks were explicitly the same, like having "bool extra_objs =3D
> (slab->objects - slab->inuse) > count;" and use it for both checks.
> But this is minor, so feel free to ignore.

OK, doing this for your and Hao Li's comment:

diff --git a/mm/slub.c b/mm/slub.c
index d6fde1d60ae9..015bdef11eb6 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4505,7 +4505,7 @@ static inline void *get_freelist(struct kmem_cache *s=
, struct slab *slab)
  * Assumes the slab is isolated from node partial list and not frozen.
  *
  * Assumes this is performed only for caches without debugging so we
- * don't need to worry about adding the slab to the full list
+ * don't need to worry about adding the slab to the full list.
  */
 static inline void *get_freelist_nofreeze(struct kmem_cache *s, struct sla=
b *slab)
 {
@@ -4569,10 +4569,17 @@ static unsigned int alloc_from_new_slab(struct kmem=
_cache *s, struct slab *slab,
 {
        unsigned int allocated =3D 0;
        struct kmem_cache_node *n;
+       bool needs_add_partial;
        unsigned long flags;
        void *object;
=20
-       if (!allow_spin && (slab->objects - slab->inuse) > count) {
+       /*
+        * Are we going to put the slab on the partial list?
+        * Note slab->inuse is 0 on a new slab.
+        */
+       needs_add_partial =3D (slab->objects > count);
+
+       if (!allow_spin && needs_add_partial) {
=20
                n =3D get_node(s, slab_nid(slab));
=20
@@ -4594,7 +4601,7 @@ static unsigned int alloc_from_new_slab(struct kmem_c=
ache *s, struct slab *slab,
        }
        slab->freelist =3D object;
=20
-       if (slab->freelist) {
+       if (needs_add_partial) {
=20
                if (allow_spin) {
                        n =3D get_node(s, slab_nid(slab));

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f=
ec4ed92-32e1-4618-99d6-0eac77da1ff3%40suse.cz.
