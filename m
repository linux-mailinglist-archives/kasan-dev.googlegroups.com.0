Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWU7666QMGQEMKNEPGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AEF1A4420E
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 15:12:44 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-43947a0919asf53741705e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Feb 2025 06:12:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740492764; cv=pass;
        d=google.com; s=arc-20240605;
        b=b9Qh21ykOuT5ILOHtnydgoPNzgfzgNEmPojqDsnNy9rTX0E/5aFkgfiWYcrAHE6/j1
         NBpT3SVO9AKMPGU4k9SzQWfOpB7bV47joZk4B9OgzFYJ0lRGVpX/12obpX9SgsEzireS
         5RQhz7BsUKFIUmaAufC+dw9B9o0JsTjqFEXhKQfilBzbflw+drD0tp3F3fPKUh9Enbo7
         zE0qu3fSqKUeGQu8Hvk4ZNPITmcgbIZS7bJcHEWuC9GTfAdWUH6AOIhcfKKbDWWsCGW5
         X5fHO1M4ZMIHeJY/tQemg5mvTW8KuycFm9IGnPeYmlVI0jM+lX+4ct9eUJYM1LT1mz94
         atYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=EixWKP34N2jh/w72kgoCxl1BS6BpzYEFY7BPAk870ng=;
        fh=pBKBQq/F7JOTZtAeJt/vyybTDKKs+qK7zOfwBHHiuPY=;
        b=O9ZkjIsQN8uMQm1o1WJWSp4bXvOzURntZd2Xkaf44mB8FrXFNm0zHLsqZkgsVyKwbN
         1amHOhLeq0pRQkFWAE2lsSVtcamjzTas8hQ0EYhrZDztlDs97D7s5AUyEGgF6O5iB3+T
         PTNR/Z9KWlPcfabjSJ1w7AukO8jQVOYR5XDdCR8Nd3UZ737ddm8pSTQ/jGhNFRqGsxd6
         2ozTMB4pfbP5E60+5bTORhZHd8jQUVg4iM5ntkdwBl4k7IWxs+FDbwp9OD+ISUPBvqsi
         arfb8sXCu8tBRtOLe3V4wTyLYK3OkNpYQt0wt33ifHwcUx63hf1e2VFLpkc27WhyoBK5
         tWjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lD8cUpUq;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lD8cUpUq;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740492764; x=1741097564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EixWKP34N2jh/w72kgoCxl1BS6BpzYEFY7BPAk870ng=;
        b=wIA1JyV1VqQd5A/wjhXeCZfUEEbsggAAFrTbxkXh3OXCjAnoSjIjxLoFBe6/FmDJt1
         4+YkFeuypadvFqJDPyRAjzTa3SDRMjrvLoSzcbE9G7X6VkD92STP/UBjwmj5BBeON4yP
         Y0gejn+fYVr2YKsLXedPNI/TPJsaRLT7hyCbdZDDVeq0xymNlf0SE8BYdu8OViXsaw7W
         llVra5NI1zu38LtSUlM4kPcsBR1KoKMERYKeUljXnEKWfqGUzJr9w1t7sLZEU1YR/gpO
         D0Do+kVIbEBuc1B/g6nwM5pI8APPv4jGpbuwll55VZid1aAbjYHZc3iWRlPGgiXtHTWN
         PmhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740492764; x=1741097564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EixWKP34N2jh/w72kgoCxl1BS6BpzYEFY7BPAk870ng=;
        b=vCQ/PlPrbzKJOZ7ZvcURScR3zXbOOCUAxxlia1+jz7xcz5Cy7mSQhvOoLkqEpleWAv
         OmBFOOMux6AZofb0SLwyi3mnj/34ZIX+52u+Mr+CNCY3nvCx9qUHJpGoAHQPwuCD+1eF
         xyNZfKXvH68G1x6cqhPLrjj7s5IcWpyLjcoI+GdycQ7n02LOvFGZZz8UEQ3cfbm+s1ke
         bhDmkTzEEe00l7W/+o4BBeHg42OEO5aVB5MiVmnYFgAdM/my7riDXgRuEbpaZc6GTunK
         xkCKDtozr/xaaLNoJ+k2EnmKvt4/oca4bI+5RsOrqkt+UJiOZTM+jHPsBY+nuAb4Affz
         yNBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV/CHet1BaMcKeHRnh2GIMHr02ZEmhlbffxVHPKQf3oddFk+IIcMPhiuOjRu6rir5AeFL0HPg==@lfdr.de
X-Gm-Message-State: AOJu0YzLr6joXK7aEVqUd3A10ZJia+yiQAUCBdNxG5XifkyfzSIQptjr
	jYpthy/fHoj7UDwHI4ok7jlZqYxsBg4uTJvYqTH1XDy4o8fyC/o1
X-Google-Smtp-Source: AGHT+IEGuXVaIKUk9bA0Ahn2i6Q3TlotXpsDGclovopE5l8LFYMNgrjqGAjUXD8Bu6jKGgms38j0WQ==
X-Received: by 2002:a05:600c:3516:b0:439:88bb:d023 with SMTP id 5b1f17b1804b1-43ab0f2dd01mr41360545e9.11.1740492763001;
        Tue, 25 Feb 2025 06:12:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGL/aytOQgPnVdcWYGsTVz6JggrcBMb5BYFLQaaeQJJ2w==
Received: by 2002:a5d:6d01:0:b0:38f:22fc:ecb6 with SMTP id ffacd0b85a97d-390ccab5b44ls787265f8f.2.-pod-prod-05-eu;
 Tue, 25 Feb 2025 06:12:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWt7egEuDt3BQjoW2/pVYq0zyYeucYIGmb7eciPBMwyXRDqromb60tEA0jQvOgoRvWkAvZk5NckzuA=@googlegroups.com
X-Received: by 2002:a05:6000:2c1:b0:38f:2990:c091 with SMTP id ffacd0b85a97d-390cc5f5755mr3308886f8f.6.1740492760660;
        Tue, 25 Feb 2025 06:12:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740492760; cv=none;
        d=google.com; s=arc-20240605;
        b=j5FZWIu+2kY5i/gVEQeBVdUa9MMaO/om2nfakYhrKBsLb+pWVNVesbNDRX4DphzJdO
         bJWM6B8OQHA2ACTctX87zGpgEGiHk9DpWtElx/x3LyGKQ322jRmeW9t1eojpHpMWWmDo
         vWS1bWmLtv2Z/IHzCqD/Yvd2al3YT0gwlHMwA87kwyAjKC5jO4rNRFrjqMU06yjXwkTR
         Etfq+69J30+i75mtWGJwkHo8BdDUxCKy410ENV8NdMPG94o2kcgzPPS7f52CBu14vXaF
         L+j2NyrR/DnSXSpbXMzx7VYv+hALQ7xXXZE8QgXLfrl7wffaSxVpK+8iPqSL2fZQxmss
         Tz7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=hJT945ZAVtCY93qXD8XatLgSRkcHkm4XIW7jbJlYEAA=;
        fh=9UzpwRz6h8TaR+48UcBlkXraL1fDqdmtyS7gIHDt7W8=;
        b=UbpjDfLr+9IBOW4v26ijl9JCUaI4szkznd2ruJ1p5JBXMQmPn627En+8hO1uJmrqfI
         or44i6PYiKdVzR/ZYaTd8JNLTDMGDSOzkUVmHFtpm/dWRZghR5qzFLcxpwKrXopFXgH+
         SfnRXXngwYbzHwfcDEaZBQZobprLyWlSoTdvv3u6Z1dzePuvShP/+vaRDIP8DI5GNaVO
         O+gZ5nzkMOh6dJRgnt7lQtdTe8RfLNr/oLuQzNI9mKG+/OAy1/VoXVcjO2Gtoug6d79F
         evH+QI5U8KyxxZ1qUr0gPEApZRbCJ6Wv62uGef3OiPoJ9Oj6ZCMeOL/GGa0PnQPHpZ0E
         pxvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lD8cUpUq;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=lD8cUpUq;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390cd8fb00bsi88958f8f.8.2025.02.25.06.12.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 25 Feb 2025 06:12:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0CF861F45B;
	Tue, 25 Feb 2025 14:12:40 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C4F2B13888;
	Tue, 25 Feb 2025 14:12:39 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OhamL9fPvWc8BAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 25 Feb 2025 14:12:39 +0000
Message-ID: <32b9d3c0-e22a-4960-a5da-a3f21c990a3a@suse.cz>
Date: Tue, 25 Feb 2025 15:12:39 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Content-Language: en-US
To: Uladzislau Rezki <urezki@gmail.com>
Cc: Keith Busch <kbusch@kernel.org>, "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>,
 linux-nvme@lists.infradead.org, leitao@debian.org
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
 <20240807-b4-slab-kfree_rcu-destroy-v2-6-ea79102f428c@suse.cz>
 <Z7iqJtCjHKfo8Kho@kbusch-mbp> <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636> <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73IBMdk5fnmYnN1@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <Z73IBMdk5fnmYnN1@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: 0CF861F45B
X-Spam-Level: 
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FREEMAIL_TO(0.00)[gmail.com];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[29];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:dkim,suse.cz:mid]
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=lD8cUpUq;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=lD8cUpUq;       dkim=neutral (no key)
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

On 2/25/25 14:39, Uladzislau Rezki wrote:
> On Tue, Feb 25, 2025 at 10:57:38AM +0100, Vlastimil Babka wrote:
>> On 2/24/25 12:44, Uladzislau Rezki wrote:
>> > On Fri, Feb 21, 2025 at 06:28:49PM +0100, Vlastimil Babka wrote:
>> >> On 2/21/25 17:30, Keith Busch wrote:
>> >> >   ------------[ cut here ]------------
>> >> >   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RECLAIM events_unbound:kfree_rcu_work
>> >> 
>> >> Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
>> >> is after all freeing memory. Ulad, what do you think?
>> >> 
>> > We reclaim memory, therefore WQ_MEM_RECLAIM seems what we need.
>> > AFAIR, there is an extra rescue worker, which can really help
>> > under a low memory condition in a way that we do a progress.
>> > 
>> > Do we have a reproducer of mentioned splat?
>> 
>> I tried to create a kunit test for it, but it doesn't trigger anything. Maybe
>> it's too simple, or racy, and thus we are not flushing any of the queues from
>> kvfree_rcu_barrier()?
>> 
> See some comments below. I will try to reproduce it today. But from the
> first glance it should trigger it.
> 
>> ----8<----
>> From 1e19ea78e7fe254034970f75e3b7cb705be50163 Mon Sep 17 00:00:00 2001
>> From: Vlastimil Babka <vbabka@suse.cz>
>> Date: Tue, 25 Feb 2025 10:51:28 +0100
>> Subject: [PATCH] add test for kmem_cache_destroy in a workqueue
>> 
>> ---
>>  lib/slub_kunit.c | 48 ++++++++++++++++++++++++++++++++++++++++++++++++
>>  1 file changed, 48 insertions(+)
>> 
>> diff --git a/lib/slub_kunit.c b/lib/slub_kunit.c
>> index f11691315c2f..5fe9775fba05 100644
>> --- a/lib/slub_kunit.c
>> +++ b/lib/slub_kunit.c
>> @@ -6,6 +6,7 @@
>>  #include <linux/module.h>
>>  #include <linux/kernel.h>
>>  #include <linux/rcupdate.h>
>> +#include <linux/delay.h>
>>  #include "../mm/slab.h"
>>  
>>  static struct kunit_resource resource;
>> @@ -181,6 +182,52 @@ static void test_kfree_rcu(struct kunit *test)
>>  	KUNIT_EXPECT_EQ(test, 0, slab_errors);
>>  }
>>  
>> +struct cache_destroy_work {
>> +        struct work_struct work;
>> +        struct kmem_cache *s;
>> +};
>> +
>> +static void cache_destroy_workfn(struct work_struct *w)
>> +{
>> +	struct cache_destroy_work *cdw;
>> +
>> +	cdw = container_of(w, struct cache_destroy_work, work);
>> +
>> +	kmem_cache_destroy(cdw->s);
>> +}
>> +
>> +static void test_kfree_rcu_wq_destroy(struct kunit *test)
>> +{
>> +	struct test_kfree_rcu_struct *p;
>> +	struct cache_destroy_work cdw;
>> +	struct workqueue_struct *wq;
>> +	struct kmem_cache *s;
>> +
>> +	if (IS_BUILTIN(CONFIG_SLUB_KUNIT_TEST))
>> +		kunit_skip(test, "can't do kfree_rcu() when test is built-in");
>> +
>> +	INIT_WORK_ONSTACK(&cdw.work, cache_destroy_workfn);
>> +	wq = alloc_workqueue("test_kfree_rcu_destroy_wq", WQ_UNBOUND | WQ_MEM_RECLAIM, 0);
>>
> Maybe it is worth to add WQ_HIGHPRI also to be ahead?

I looked at what nvme_wq uses:

unsigned int wq_flags = WQ_UNBOUND | WQ_MEM_RECLAIM | WQ_SYSFS;

HIGHPRI wasn't there, and sysfs didn't seem important.


>> +	if (!wq)
>> +		kunit_skip(test, "failed to alloc wq");
>> +
>> +	s = test_kmem_cache_create("TestSlub_kfree_rcu_wq_destroy",
>> +				   sizeof(struct test_kfree_rcu_struct),
>> +				   SLAB_NO_MERGE);
>> +	p = kmem_cache_alloc(s, GFP_KERNEL);
>> +
>> +	kfree_rcu(p, rcu);
>> +
>> +	cdw.s = s;
>> +	queue_work(wq, &cdw.work);
>> +	msleep(1000);
> I am not sure it is needed. From the other hand it does nothing if
> i do not miss anything.

I've tried to add that in case it makes any difference (letting the
processing be done on its own instead of flushing immediately), but the
results was the same either way, no warning. AFAICS it also doesn't depend
on some debug CONFIG_ I could be missing, but maybe I'm wrong.

Hope you have more success :) Thanks.

>> +	flush_work(&cdw.work);
>> +
>> +	destroy_workqueue(wq);
>> +
>> +	KUNIT_EXPECT_EQ(test, 0, slab_errors);
>> +}
>> +
>>  static void test_leak_destroy(struct kunit *test)
>>  {
>>  	struct kmem_cache *s = test_kmem_cache_create("TestSlub_leak_destroy",
>> @@ -254,6 +301,7 @@ static struct kunit_case test_cases[] = {
>>  	KUNIT_CASE(test_clobber_redzone_free),
>>  	KUNIT_CASE(test_kmalloc_redzone_access),
>>  	KUNIT_CASE(test_kfree_rcu),
>> +	KUNIT_CASE(test_kfree_rcu_wq_destroy),
>>  	KUNIT_CASE(test_leak_destroy),
>>  	KUNIT_CASE(test_krealloc_redzone_zeroing),
>>  	{}
>> -- 
>> 2.48.1
>> 
>> 
> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/32b9d3c0-e22a-4960-a5da-a3f21c990a3a%40suse.cz.
