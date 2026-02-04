Return-Path: <kasan-dev+bncBDXYDPH3S4OBB6ESR3GAMGQEMLWRZDQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 4DZoJoCJg2lDpAMAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB6ESR3GAMGQEMLWRZDQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:01:36 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1571EEB4DF
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 19:01:29 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-59e35f8e679sf22122e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 10:01:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770228089; cv=pass;
        d=google.com; s=arc-20240605;
        b=JAFR9HY2KFnx0BtitxI8PtuTKNn8M+1F0yVcqCaJkWj+393+mRbZMaxG3bdRL5/npl
         5buIwE4Q1dz9fa6j5eobqgnsYsmFGR+yoCWXNVnvDm2uItdMVawfks8GYHMhilO5eHPR
         DyjUOKO2XdE6vJ6bUdpkGPlCgOtZExvLg16YMq3cOBwdBwQIKvRjQuqiKV54ORhzCnvW
         qSyYIAUQxTphmy/L/AhkYKIyGpF32/W56UkYMVGV+2JmXEDiF0JhRXAE4Dpj4J8aGWr2
         1AG81ZsIiDKpG8nmG0cBMRQSuUhqXjK70rwLx63NR0NL/pR3uQVcCTFuiXAR6tz0k89N
         ycaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=8X7pVIoIzhlY/Ivt6b6GovcEH+1geHcw5U6fH5bV9ls=;
        fh=Lq7X4xmrcHYYeuIygrCBimPI7vlprngsET7yHNpo//U=;
        b=kj/Z/ca5atVFr1IWKzSVmCqk5D5CqRDObKfBYy8ySnK3tQ5VLrPC51cWADpaiPsXYY
         MnvTSa2PK7T/dccHQGyCYJ+/mWUZAWdtHOb0VnwiNIlm94KSQ+a8iwG0gTXR58aP1gak
         DHf25ZcUuQ9hqusQVVidR0ulL99zMyR8gj5MNGR4CXoaSQppJmXQzHuFnvrv06H1kNFE
         6csv2HGI4jCWuNUyFOBVrwD68ez/xgNo/GXhX5d+HKGASiwI9SjjlUcXVBiPbEsAyRDn
         rPuRqhElA0y+Uq8E9B2rRbMKF/fzAH+eHBLiEyaarnpWyVO3zR0MWQ+q7XVE01ToBLZ5
         Sb8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1jsLW73E;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NbwMHFj0;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770228089; x=1770832889; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8X7pVIoIzhlY/Ivt6b6GovcEH+1geHcw5U6fH5bV9ls=;
        b=mUH/Guv/0e8kFtAPXFusNtiRZWO32b/hywx6fUcKYRVZW+HzcVXdRz699PyQAo8MME
         h0ockxSvBzWAsBlExp8KT3nEB/j6yrmlhRLtJs2sZyC1B0TjJrwMdrJNp8y8X7QDxSWh
         J9VbPgDlmP8mtD6PAVVUzrgU0NmQ/GlR9ymhpXmWINKgxQ+1DDIZbT+G8Z8BHboKx31W
         w1p/awDHdgB31cLP5kISy1CA0HCytGVdKXj8gNrS4SCVAvqLJW5GZHx/i1HETFaP83kx
         s0IidjakA71GSJNPRN7dVnOaKvgDYrQRRzZPHpVShypZ7AuWfLCgz8MN6I/vy9ZDTA7L
         inTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770228089; x=1770832889;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8X7pVIoIzhlY/Ivt6b6GovcEH+1geHcw5U6fH5bV9ls=;
        b=RDBGfVNOtS6vPsOFMQREujiU3H+EXqFKibqR4yRlZOZfLeT10ZHB0Ytt9TK49YHGGJ
         m7TtQskKci54Hdo3L7JnuFffMLp8EaWIUFplWPHRQEZ/x2le6ca1YPsTZDMNik8Ce8nk
         spQFv3PkIg1bE3YZsdT6Sv55MHaU+C8+Zm6WFe2b1/pkJ3tXrRg9aqidawx2vJ7DhtoC
         1IaBWFk7fBlut73J5dK8YIEzOchanU1wTNjopXzKl9RkGu/YliWAcjLGULz2WKztVZ62
         e8E5kVPR2AB403CFZ2iQAjUvqSyc5f0BRxyqT4QpYfqoMiJadd1ziYbbwIeW6CR4wOj+
         E6Bw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWt8ezxaItMrp7GXqSJyt/He4lzGsyxRKpIu4ws1fEXI0XUtWwKVOodeuG8q5bYRd5qw/mMrA==@lfdr.de
X-Gm-Message-State: AOJu0Yx0tg7ySadbCo8Ct3A0PVj0GMeupfdlHfSRZTFvbl+mym6kYw0J
	aCPNVUCVcbBs2P6fdfRNnYBC9Q2Z2S/rVEBvqSP/aux9QBTlJP3jv81e
X-Received: by 2002:a05:6512:2529:b0:59e:3b9c:76fd with SMTP id 2adb3069b0e04-59e3b9c77ddmr371930e87.1.1770228088654;
        Wed, 04 Feb 2026 10:01:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GINEq5FQCInIIeKBIRhXQa7M0f04DXKpwYznBPC3V17w=="
Received: by 2002:a05:6512:2215:b0:59b:6d6d:c with SMTP id 2adb3069b0e04-59e3c47e2fbls35017e87.2.-pod-prod-09-eu;
 Wed, 04 Feb 2026 10:01:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUl1aMPQ0+sU3hXJrjZ9Fz9R6QuoNuSHYLOHsADxAS+4jGjazGwoyQ6LwRAWm6v4+lrrMO2pXJiAFE=@googlegroups.com
X-Received: by 2002:a05:6512:1309:b0:59e:92e:7d0f with SMTP id 2adb3069b0e04-59e38c45f1amr1242824e87.45.1770228085919;
        Wed, 04 Feb 2026 10:01:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770228085; cv=none;
        d=google.com; s=arc-20240605;
        b=jdapTPbEgZuweHl1otC3MTw3KvDGKScxihq8KZsTTgJ2zCpLni/uOH7HQqeQtRu6WN
         NzKyeGeMkpMZPAciMRbtt0nOcAEzKdBfNbEgW+SRysl47D/uEzLKcStm/9BqKChfstIt
         9DhGg7j9bbjvcAhmSR89E7RbD9pIfUXxxYFh9wH3OMMtCaL0eLfc2JaFA6BZo4bNSCI/
         0qWM1mD2Sv1fjs4wT+iQQMYkgnZ7vfP8EVG7rmrXN2CTOtS12GM+zBEMB0GLAAVCaa+P
         upqIvFisg7S8n9UG4VvP9pUMLuY+H35UBC+apfh1DRROMHUWofCur0TdOf7pJ13Ck8Ss
         5p/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=D/h1H75MzwyM0dxtB6t3yKM2GtQfPuU1slinrxlGbIs=;
        fh=IGvdOSJj5z2z4QJUKn17Cn2jNjDMsMnR2CrE4yEzswQ=;
        b=kfO2KX2G1ZasDRnp49Sz0IMlnCd1pQGwHLYl/FFTI8q+ZsXILpV38VlqSPnh1dmbLl
         RxNLLe37i4mEoaAvJXqJF/+r/aMaZ/CuoPJwMxsrfTHtBZI+bBsEMXkUbKZuXL6ngg2U
         MZNf3u4Icn8LJD59UNg8PYUYAdzM6DfFhn4PljqJ3vTnCn3Kyvycq+TZk1EUfvcU8PYg
         zRHShfSQ171Pw5uKL7QoUGKfn/ChvuOfhJg8AcMeKsWliyW7wAYYXqykKxdFGM/qDM5J
         RPWCzDjTyUiUGIctMqsccovzQTqStNl/JlwFIU6VXHMojrL79QbuLsOSMkqtIsS74h6T
         Lxrw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=1jsLW73E;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NbwMHFj0;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59e3886baa7si65768e87.5.2026.02.04.10.01.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 10:01:25 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EED375BCED;
	Wed,  4 Feb 2026 18:01:23 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C1EA43EA63;
	Wed,  4 Feb 2026 18:01:23 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id XgjqLnOJg2kQGQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 04 Feb 2026 18:01:23 +0000
Message-ID: <23df6018-69c5-4c94-bbdc-05c03f837f2b@suse.cz>
Date: Wed, 4 Feb 2026 19:01:23 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 06/22] slab: add sheaves to most caches
Content-Language: en-US
To: Zhao Liu <zhao1.liu@intel.com>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
 <20260123-sheaves-for-all-v4-6-041323d506f7@suse.cz>
 <aXsLKxukv60p3QWF@intel.com> <2cd89ed5-0c8e-43f8-896d-1b7dee047fef@suse.cz>
 <aXxaryFUrIFo7/hL@intel.com>
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
In-Reply-To: <aXxaryFUrIFo7/hL@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=1jsLW73E;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=NbwMHFj0;       dkim=neutral (no key)
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB6ESR3GAMGQEMLWRZDQ];
	RCPT_COUNT_TWELVE(0.00)[18];
	ASN_FAIL(0.00)[9.3.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.4.6.8.4.0.5.4.1.0.0.a.2.asn6.rspamd.com:query timed out];
	FREEMAIL_CC(0.00)[oracle.com,suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x139.google.com:helo,mail-lf1-x139.google.com:rdns]
X-Rspamd-Queue-Id: 1571EEB4DF
X-Rspamd-Action: no action

On 1/30/26 08:15, Zhao Liu wrote:
> Hi Vlastimil,
>=20
>> > vm_area_cachep's capacity seems to be adjusted to 60 and
>> > maple_node_cache keeps 32 as the args setting.
>>=20
>> Good to know. It is a bit larger.
>> Hm I could have probably applied the args capacity before doing the roun=
dup
>> to make sheaf fill whole kmalloc size. Would add a few object for maple =
node
>> I guess.
>=20
> Re-considerring this formula:
>=20
> the nr_objects in set_cpu_partial() in fact represents the half-full
> case since it was used to calculate nr_slabs in slub_set_cpu_partial().
>=20
> Therefore, the maximum capacity of this partial approach should be
> nr_objects * 2 (and should actually be even larger, since it doesn't
> account for the object on CPU's freelist).
>=20
> But here, for sheaf, the implicit assumption is that it is completely
> full, so that for the maximum capacity of objects per CPU, the sheaf
> approach is "half" that of the partial approach.
>=20
> Is this expected? I'm considering whether we should remove the
> =E2=80=9Cdivide by two=E2=80=9D and instead calculate the sheaf capacity =
based on
> half-full assumption (e.h., full main & empty spare).

Yeah the non-doubling was intentional. Sheaves can be always fully filled u=
p
by freeing and fully emptied by allocating. Cpu partial slabs don't make
freeing as cheap (except never needing the list_lock perhaps) because it's
the locked double cmpxchg patch. For allocation, we might be obtaining them
from the partial list either on allocation where they might have any number
of free objects between 1 and slab size, or we put them to partial list on =
a
first free to a full slab - and then there will be just single free object,
but we hope there will be more frees before we turn that slab into cpu slab=
.

So the half-full case is an estimate that might be even actually less as th=
e
freeing side is biased to almost-full slabs.

With sheaves no such estimate is necessary. Not accounting for the cpu slab
size was maybe a mistake. In any case we can tune the sizes later, but this
should not be based on synthetic benchmark only.

Thanks,
Vlastimil

> Thanks,
> Zhao
>=20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
3df6018-69c5-4c94-bbdc-05c03f837f2b%40suse.cz.
