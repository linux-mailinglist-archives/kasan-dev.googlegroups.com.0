Return-Path: <kasan-dev+bncBDXYDPH3S4OBBIG4Y7FQMGQE3XOH7II@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id KIwCHCLucWlaZwAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBIG4Y7FQMGQE3XOH7II@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 10:30:10 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C7A8648E4
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 10:30:10 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-435924d554asf154393f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 01:30:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769074209; cv=pass;
        d=google.com; s=arc-20240605;
        b=GgZNJV+3Hb9qAsvDClQoCEWdIfuwjjd1xbx+EMhV4t01Vt7WXJQ/ghzG4CemUjOpWi
         4dgmVcfJlkQI04Yti8DslV4Ptp0jpNuv/PBKfdL0b5Bh9y2AVhRNPLFNio+H088xQenT
         8qX+0V5aqt0ziaruQTJMwiV6oZh/ZlTV648U/swTBmkoE8L/WVsCeqno42zwGP51XoK2
         usnQFCbm4Va80OkOpsFkRPTfisI0c8gM+n0hL26SrUt0pzmOnDh+imgKCTpWqHS7ajeU
         ZRTt4yncUTaKZfI/qNeMdOB3XJPKx/RKxmhTjO2fV2q2GVjRNIcFdJLIwxjEU90cSnQw
         68oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=KcRlNt+SYjts1Juon89AeqrNrHGGO8/b2gDbjnzDpzA=;
        fh=y6LcQjvfjXBlNBUdthDgctg1udNy2EeAgm9VotDkNT0=;
        b=WxbAPIrimbaWvd8UxtkV+9zRoURcQPHMp86iCKpByg2CgTvi1YNg3W2ZjmSBGbc0dZ
         GxFjbAth7LlL9A8rV+HSBaavmSrw+DhTqerQx72U9AgbTLdDkNNBm0kV/dSfNI1i+Ezq
         Nb+xZlthqe9ay2KtRjzSbbEBMbiI2YkQ0FvsP6fweRt03RfNe1FGo6VMHEmgzoz1VEiq
         w4R/nFELUnLUo0b0ua31gJEWUbM3iHR5heAQ1uAJuxvE0x4GsDVR5gNOxrh4CzsuLYSg
         KaIW/UFzUpJu2yxFPC7JKNh7UWP5AAZldpJHRqCSHGXTzHXJpK20fAAY8TjKhuQpFsTa
         lvWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jFiLAw3L;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jFiLAw3L;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769074209; x=1769679009; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KcRlNt+SYjts1Juon89AeqrNrHGGO8/b2gDbjnzDpzA=;
        b=IklZE2AckjyQm0br7fLyZYePmdMFwvyqVjAKjvCiW+zBd8si5MSLLV7zgUIo+sgE6y
         UewM8+cdWTN2JCUhKZpRmpwAbm0o8Vz3v2maWRIjCEfYgx7via5pHAs2q5sXWjPbS6Lg
         W/6qwRR+fvEXd1lSHS3Ybb2NATntcKWbgqVeQLvyU41df9Lv+vZUKlBCWbcGxq8ybOf5
         syYJZumnzbvPC/KIVurw6tnNXvpe0yDmrr1XhhSFxNL0Bhmo1Wsxn5pMlJONQyCkBXDH
         UyMHGJcQmQ41ztRK+mpFL3jiYLEg748DIE6CRiO0MJDKx6ZkBY/H53rGpXYk0VwM4R3Z
         yogw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769074209; x=1769679009;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KcRlNt+SYjts1Juon89AeqrNrHGGO8/b2gDbjnzDpzA=;
        b=UwasbcuDP1qtVjBEmetFoIvSKt0LP8OlpfJL8YapboUDfuC8rTTeH87oUsR3l+iifX
         wsQZVMq6Mm0Ys6k3/8NVjqVui8opmn7SKcQeeld5W6DxzBzH3HtdRgb+yq4b0Fpe0CO9
         wk/ZtjU1nW7FyYTPJ9COXS2cQ4aHXz9yUXRliOdU76KD5tfjIj35gjn9y5uMl7uqLg1G
         DEBs3aYMup6zKF7hmxl/DaCqwx972huGREew/H/GT1B5Ik7u65kvQXXSzH5agO+WAskW
         5uaxjNmRMB2h0TojUJ5/YIzmYjBdnTC0eKBAO/HPsj3xoGDxTtEHlvrJtBn1nCUhDbTs
         b9sg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPBZxUS4eucuGrTlcyM2zneGpW0XaIi0KYnblr8Wj6PlmFUVFEfwglfEZH3UlgGDHqz2mAWA==@lfdr.de
X-Gm-Message-State: AOJu0YxlCITACmUyirQim4UGtoujmvqsoxnEg0zNRYrQUybVqYmqwZ3V
	sM2LPuPoQ7/fERphDhrAUFcW477VoYrjLA47sbrqZ9/J2pJSBWfDKWx+
X-Received: by 2002:a05:600c:64cf:b0:477:a6f1:499d with SMTP id 5b1f17b1804b1-4801e33c5ecmr174169895e9.3.1769074209069;
        Thu, 22 Jan 2026 01:30:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EigSlye2VsRA3pTCpIEiHKhcjK/ZPdqSYOLa45fqz3kA=="
Received: by 2002:a05:600c:3b89:b0:47e:e8e5:f41f with SMTP id
 5b1f17b1804b1-48046fd6268ls4771745e9.2.-pod-prod-05-eu; Thu, 22 Jan 2026
 01:30:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXzOkKHzVeMct43h2wBJxF7pCERPUZInRA2r7nJp5vyq+nkRcTxEQNpo91/35M6fFCZCeV2RYUQRgc=@googlegroups.com
X-Received: by 2002:a05:600c:8685:b0:47a:975b:e3e6 with SMTP id 5b1f17b1804b1-4801eb035e1mr194611655e9.18.1769074206886;
        Thu, 22 Jan 2026 01:30:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769074206; cv=none;
        d=google.com; s=arc-20240605;
        b=dHsKW9Fm2Ms/0u1+t8XP7TGs4v4cVzc8FMXncxx8rLzYb9jRRXimvHvOTTQJXEdilV
         tEelVN3onYioWF3WYD7QOkcBPMbo2RpMD2G3uh2QPqcUFuiRpTVtQVKiNS1IxJfT6rN0
         jmv/ING48+sp4BXK27vslv6YJW70+HO76vP1APaMEFY9FmDeGlRbX3eGRVaMO7Sc+0Yf
         vG6tSern7b8C8w0ecYDq3lZCFvIYE2IRkjZVHhrGICiWnV1cI2axBhQaw9x6cBzaRnIO
         uzoRRCYz7lQRciFIMbvUcoY1BXsrPHuFlcfpTdGKL94iWnuXAg5Cqe6Hs92Ft6r9rvhi
         nKJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=JAT1+es+A4HBBS3yZMDrVW5I/Uvw14juxNaFJLZ0ZB4=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=HcgAdT44kL7iTdmw0DI8aH6pFHO/0s4X2l5HDNQ5AwHGTiicrLP9viUg+lEUEucvXl
         0SoW4H0YPDONgk9f0XkSnQytVyHUp6Z1z1gKkrBzRfDem5tzYEuLVyzMUm6WrktQVo5f
         SSMA624n+vUMoxVBEcLUeEGmjroxo/VFdVquGhXueHEsjK+293e3+WAE57smUPq7z37Z
         /A6dbBAWYklMhPXgNNtBmLXKwJO/C2FhOXhxsxLZUAu7LztbsUGCQCFwgc3IJ/aXef2q
         uT6Gbcxdi3NrWRZ6xhDpCj9eW9tnXDzHhsMZTGKhrUK4fUeoTMLmaE1xZ2VKN22ANLXr
         mhqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jFiLAw3L;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jFiLAw3L;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-48042b6e068si485175e9.1.2026.01.22.01.30.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 01:30:06 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6BACB5BD61;
	Thu, 22 Jan 2026 09:30:06 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 1EA5813955;
	Thu, 22 Jan 2026 09:30:06 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id rBoqBx7ucWmACgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 09:30:06 +0000
Message-ID: <5cf8b74e-5ba3-4788-ba1a-4cfe9ef366d3@suse.cz>
Date: Thu, 22 Jan 2026 10:30:05 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 21/21] mm/slub: cleanup and repurpose some stat items
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
 <20260116-sheaves-for-all-v3-21-5595cb000772@suse.cz>
 <CAJuCfpHg9YfkVwtfCUvLH_0HNWzUgx1ekQ-QMyYBW_Qeqt=WjA@mail.gmail.com>
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
In-Reply-To: <CAJuCfpHg9YfkVwtfCUvLH_0HNWzUgx1ekQ-QMyYBW_Qeqt=WjA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jFiLAw3L;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=jFiLAw3L;       dkim=neutral (no key)
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBIG4Y7FQMGQE3XOH7II];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,mail-wr1-x43c.google.com:helo,mail-wr1-x43c.google.com:rdns]
X-Rspamd-Queue-Id: 0C7A8648E4
X-Rspamd-Action: no action

On 1/22/26 03:35, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 6:41=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> A number of stat items related to cpu slabs became unused, remove them.
>>
>> Two of those were ALLOC_FASTPATH and FREE_FASTPATH. But instead of
>> removing those, use them instead of ALLOC_PCS and FREE_PCS, since
>> sheaves are the new (and only) fastpaths, Remove the recently added
>> _PCS variants instead.
>>
>> Change where FREE_SLOWPATH is counted so that it only counts freeing of
>> objects by slab users that (for whatever reason) do not go to a percpu
>> sheaf, and not all (including internal) callers of __slab_free(). Thus
>> flushing sheaves (counted by SHEAF_FLUSH) no longer also increments
>> FREE_SLOWPATH.
>=20
> nit: I think I understand what you mean but "no longer also
> increments" sounds wrong. Maybe repharase as "Thus sheaf flushing
> (already counted by SHEAF_FLUSH) does not affect FREE_SLOWPATH
> anymore."?

OK will do.

>> @@ -5111,8 +5100,6 @@ static void __slab_free(struct kmem_cache *s, stru=
ct slab *slab,
>>         unsigned long flags;
>>         bool on_node_partial;
>>
>> -       stat(s, FREE_SLOWPATH);
>=20
> After moving the above accounting to the callers I think there are
> several callers which won't account it anymore:
> - free_deferred_objects
> - memcg_alloc_abort_single
> - slab_free_after_rcu_debug
> - ___cache_free
>=20
> Am I missing something or is that intentional?

I'm adding them for completeness, but not to memcg_alloc_abort_single() as
that's not result of a user-initiated-free.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5=
cf8b74e-5ba3-4788-ba1a-4cfe9ef366d3%40suse.cz.
