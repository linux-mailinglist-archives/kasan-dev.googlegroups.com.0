Return-Path: <kasan-dev+bncBDXYDPH3S4OBBVXP4K6QMGQEZFF6VVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EA373A3FD6F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 18:28:55 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-38f28a4647esf1166692f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 09:28:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740158935; cv=pass;
        d=google.com; s=arc-20240605;
        b=gmOVw0wmPK/CkYibWPVetnJ/ymj2v11MGw9Pfca70sB9QOOA4XmLFsGNy41+br/EUG
         4VRQhOJh+dtTlKT+RYAVV5OWee6hhIdjrV5wfGZPmwNMOZJ9b7sVvGPwhNt1SLbpAAww
         vvaPiUxsLrmrhsY0UUgNd4XCleWGLnnyPup6cI9eSjMf7gJpKCpdBOH1X0isvGILc2Z8
         5cmm+ikxM57bqaHbAZCx3gaY8wA0NA8CNg1qiAR9Z7janv7nt4Y5LkIwayddPqlHNZVV
         4DuRRst1vNSgTj05/KJoG/Zz2vK3scBSKMUddqEnmz78SRh5JTk+V1hRjCuYw4NAuTHS
         2Kfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Z9Jf+vRmRzlkFHv27Ya3QbIDfD47VTfILzljpss3hXQ=;
        fh=64/wnhoG6YLwklnJ2og/Gw6dFF0rXzzo4aCfrhUKmxU=;
        b=Y256AK3c77LaBZjtYlCT6/NiWNJJuyHItdqkNbFzSDRDQ2d8TUuX3vdFT7fItOcVIN
         dbdRdYxukBQf5QBO6jjfmpBFtJ/2c+o1GskFm6UGbTQwm6p9fbxw1X/hEDcnFa1Gsn4C
         FHhyHYjaMdA+HYsUWHt8H+iAnjS5+eJ2eyklknt2lOihP76JaMNB5o5vMZu8yJso2KGt
         9A2IoF9ej+yYh++FCGzojgUi3gEjJQoLH+Dn6/2yYvQrPRJ188U2LW3W//P0WfqTydG6
         J6xZ2AukWzR411N+5gnaduJ/AZjDF4OkVfLwHs7prtDGIs3NoOJCVZbEyNx0nq8vW3hy
         jLDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GNkqfTTI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AFnBheAX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740158935; x=1740763735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z9Jf+vRmRzlkFHv27Ya3QbIDfD47VTfILzljpss3hXQ=;
        b=HTs/6BfIiEB6U6y+3p8QkijwcFBil0j7IMqBi86D13NtpQsDRc2mqmwv3fNbjSzh9J
         Z+R1bs3qLb/K/7NpzOq3+O2NTlyCOp/oRDly11Cv647JTYZYsWXEgDi8kEeQXC0MAyx2
         7KtTiQKShJyPERBytbI/V58NeuEoR9cnPjKN/p7AiZ+uSDThlCg8jkFhpxU1fL4kp0G7
         tFfGbXI13oZ2YEFVO9L68Ai/TrcyEps3VwHgtKt1jEPznRcvoIXeVr2pKCnx0ilLlesd
         G4C2cuViqVRaSlOSqrar9PBsxnNlexB7mpW1vGQX9o8YANYr9yjF45hYmOlvuMDvHgqv
         RzOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740158935; x=1740763735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Z9Jf+vRmRzlkFHv27Ya3QbIDfD47VTfILzljpss3hXQ=;
        b=Q7YgJukTMPVbVzcjyP9qkCRVl2CRE1IOWjv+JIq/Atyatofa1/WF7ixbdKDRXF90oG
         lDrC0eLyoDXqLm0MgizjIyPulKiY79pd0O+/XwGySeIod1KjtR+kWPsfQOBqt7K+vC78
         vsfIIetmeGVXbEKBIGcWtKqscaOO+htxkJse41uGEHcE5qhrJgVwBZEcf3lOx/QzjikV
         bKom8oY3EHWqFMWVKTn8I0spPVQvcWFV5vHIhvUP0cUKVGcjDRgf0rc6DJVEkpZtb6+v
         U8r+LNdWF7ylrCjRV9adJ9JqlqSSkvQRnklk5Rzxtr1AQUYuV9yBhdn1hLXO/NKbVBjo
         fECw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU6iPRmA28KDphv6Fs4qi6pqzlUwSYk4XEqXeoaTzjS/P4zgQBwIfVDVysqyOTq16Qb6z+sww==@lfdr.de
X-Gm-Message-State: AOJu0Yx8wIwi3fTypHHTe1zIreBDH90fRzHWTXxDqQtP0mmlpiOry9eB
	GpS/6ArnJYakAI4LtkKeS58UC1+lKHHHyKZSpd7fN7Me+pvuF6/s
X-Google-Smtp-Source: AGHT+IEDEkpLsx9/ZWKyKqHeJrxRmvBeWavWb5ee3KM4IAJtt5iczGL7E8ZO3uwmsap4KGOukOG8vA==
X-Received: by 2002:a05:6000:400f:b0:38f:475d:1411 with SMTP id ffacd0b85a97d-38f6e95c042mr4277721f8f.18.1740158934598;
        Fri, 21 Feb 2025 09:28:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGdcnBN4mul8uPQ3UWeMqVDxTg4FHKrt4NwA1tLBOZXig==
Received: by 2002:a5d:6d8b:0:b0:38e:5a45:4a6e with SMTP id ffacd0b85a97d-38f611ccd02ls1181970f8f.0.-pod-prod-06-eu;
 Fri, 21 Feb 2025 09:28:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWtJVxnRwJBcSNXdt0dr2swt70jnxlhfCNMVcoQu4oIH58zxdrkNkkiRfKtHMDx3bJWd4B6UhZsGoE=@googlegroups.com
X-Received: by 2002:a05:6000:4024:b0:38f:4308:e552 with SMTP id ffacd0b85a97d-38f6e95b29fmr4527145f8f.14.1740158932249;
        Fri, 21 Feb 2025 09:28:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740158932; cv=none;
        d=google.com; s=arc-20240605;
        b=ApxtzLWTl82NdrLpVnhxnkwG+i8F+tLOR5eJmzMIc4MhkNWrG5U7V6VJPslENj/kaZ
         GLuPE7Hl9Bk2T4obm319KQGe5irJdszG3GTyOY91zZNUSaqjJfdlbTvHC30YR7qxaGPa
         skRQEMyUlS0nfTtllrQf4I0gkleKUEtvhDUuxuVi5zbruEBpI2pbmRzkYJcRrikAxSEl
         9TLuAKwBZzHvg1v6qlV7Fi3tDFLJjsVQgHSnSxLQvr/UR7sYQzcY7kqI1A1HX31FKmVz
         3F8ZJk8AHZpidqpSTzYayNSmC5IltPK4H9UXLbdbuiuvo7mlumGSClBEdD1JSSoglnBg
         HsDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=CsRD3Ev6tUSwaFtN40VJ1v7re9buaBfAHoPVv5PtZKo=;
        fh=4MBdtzerxO8+bU3LfA7k23x3Gt6h4U6D8AA/TccsGF4=;
        b=EtmE+A/n9QJJ4+xj+ltiawnO9eo1slp6g+5awoe2NVk0ehpMz/Nrqr7zkRyuhKECL2
         sHi7MIPSvtuLC9SNzz1pYxNWW68sooTnUeNG4RXzZjaY5JWJOQ4bc0zEahhBMP1gH1I2
         PDaad4+2aZO4sEhObJBpl4xx3p85Ni1XzTdlrAAku9e4Pwwa+NAWN6uWqFEYj/nMf31p
         hwK6Bo5T+eg89HVgJSVf79xWV8eAGhXSLtCX/ceezwAeFZgQ3Fnps/URvizfoBAopS+1
         yRwOa3hC3ouyXnUoQcf4u1TJ6HmDTfjUS/XVMs8s8EPReUdhHPBnv93fCIm3jnqDhh6E
         6tBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=GNkqfTTI;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=AFnBheAX;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38f2590ea71si640108f8f.4.2025.02.21.09.28.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 21 Feb 2025 09:28:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 91FCC21E2C;
	Fri, 21 Feb 2025 17:28:50 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5391E13806;
	Fri, 21 Feb 2025 17:28:50 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id RDZvE9K3uGekQgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 21 Feb 2025 17:28:50 +0000
Message-ID: <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
Date: Fri, 21 Feb 2025 18:28:49 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Content-Language: en-US
To: Keith Busch <kbusch@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Joel Fernandes <joel@joelfernandes.org>,
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Steven Rostedt <rostedt@goodmis.org>,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>,
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>,
 "Jason A. Donenfeld" <Jason@zx2c4.com>,
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>,
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
 <Z7iqJtCjHKfo8Kho@kbusch-mbp>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <Z7iqJtCjHKfo8Kho@kbusch-mbp>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Queue-Id: 91FCC21E2C
X-Spam-Score: -3.01
X-Rspamd-Action: no action
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	ARC_NA(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[29];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com,goodmis.org,efficios.com,inria.fr,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,googlegroups.com,lists.infradead.org,debian.org];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[];
	R_RATELIMIT(0.00)[to_ip_from(RLctujmen6hjyrx8fu4drawbuj)];
	ASN(0.00)[asn:25478, ipnet:::/0, country:RU];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:dkim,suse.cz:mid,suse.cz:email]
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=GNkqfTTI;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=AFnBheAX;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
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

On 2/21/25 17:30, Keith Busch wrote:
> On Wed, Aug 07, 2024 at 12:31:19PM +0200, Vlastimil Babka wrote:
>> We would like to replace call_rcu() users with kfree_rcu() where the
>> existing callback is just a kmem_cache_free(). However this causes
>> issues when the cache can be destroyed (such as due to module unload).
>>=20
>> Currently such modules should be issuing rcu_barrier() before
>> kmem_cache_destroy() to have their call_rcu() callbacks processed first.
>> This barrier is however not sufficient for kfree_rcu() in flight due
>> to the batching introduced by a35d16905efc ("rcu: Add basic support for
>> kfree_rcu() batching").
>>=20
>> This is not a problem for kmalloc caches which are never destroyed, but
>> since removing SLOB, kfree_rcu() is allowed also for any other cache,
>> that might be destroyed.
>>=20
>> In order not to complicate the API, put the responsibility for handling
>> outstanding kfree_rcu() in kmem_cache_destroy() itself. Use the newly
>> introduced kvfree_rcu_barrier() to wait before destroying the cache.
>> This is similar to how we issue rcu_barrier() for SLAB_TYPESAFE_BY_RCU
>> caches, but has to be done earlier, as the latter only needs to wait for
>> the empty slab pages to finish freeing, and not objects from the slab.
>>=20
>> Users of call_rcu() with arbitrary callbacks should still issue
>> rcu_barrier() before destroying the cache and unloading the module, as
>> kvfree_rcu_barrier() is not a superset of rcu_barrier() and the
>> callbacks may be invoking module code or performing other actions that
>> are necessary for a successful unload.
>>=20
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  mm/slab_common.c | 3 +++
>>  1 file changed, 3 insertions(+)
>>=20
>> diff --git a/mm/slab_common.c b/mm/slab_common.c
>> index c40227d5fa07..1a2873293f5d 100644
>> --- a/mm/slab_common.c
>> +++ b/mm/slab_common.c
>> @@ -508,6 +508,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>>  	if (unlikely(!s) || !kasan_check_byte(s))
>>  		return;
>> =20
>> +	/* in-flight kfree_rcu()'s may include objects from our cache */
>> +	kvfree_rcu_barrier();
>> +
>>  	cpus_read_lock();
>>  	mutex_lock(&slab_mutex);
>=20
> This patch appears to be triggering a new warning in certain conditions
> when tearing down an nvme namespace's block device. Stack trace is at
> the end.
>=20
> The warning indicates that this shouldn't be called from a
> WQ_MEM_RECLAIM workqueue. This workqueue is responsible for bringing up
> and tearing down block devices, so this is a memory reclaim use AIUI.
> I'm a bit confused why we can't tear down a disk from within a memory
> reclaim workqueue. Is the recommended solution to simply remove the WQ
> flag when creating the workqueue?

I think it's reasonable to expect a memory reclaim related action would
destroy a kmem cache. Mateusz's suggestion would work around the issue, but
then we could get another surprising warning elsewhere. Also making the
kmem_cache destroys async can be tricky when a recreation happens
immediately under the same name (implications with sysfs/debugfs etc). We
managed to make the destroying synchronous as part of this series and it
would be great to keep it that way.

>   ------------[ cut here ]------------
>   workqueue: WQ_MEM_RECLAIM nvme-wq:nvme_scan_work is flushing !WQ_MEM_RE=
CLAIM events_unbound:kfree_rcu_work

Maybe instead kfree_rcu_work should be using a WQ_MEM_RECLAIM workqueue? It
is after all freeing memory. Ulad, what do you think?

>   WARNING: CPU: 21 PID: 330 at kernel/workqueue.c:3719 check_flush_depend=
ency+0x112/0x120
>   Modules linked in: intel_uncore_frequency(E) intel_uncore_frequency_com=
mon(E) skx_edac(E) skx_edac_common(E) nfit(E) libnvdimm(E) x86_pkg_temp_the=
rmal(E) intel_powerclamp(E) coretemp(E) kvm_intel(E) iTCO_wdt(E) xhci_pci(E=
) mlx5_ib(E) ipmi_si(E) iTCO_vendor_support(E) i2c_i801(E) ipmi_devintf(E) =
evdev(E) kvm(E) xhci_hcd(E) ib_uverbs(E) acpi_cpufreq(E) wmi(E) i2c_smbus(E=
) ipmi_msghandler(E) button(E) efivarfs(E) autofs4(E)
>   CPU: 21 UID: 0 PID: 330 Comm: kworker/u144:6 Tainted: G            E   =
   6.13.2-0_g925d379822da #1
>   Hardware name: Wiwynn Twin Lakes MP/Twin Lakes Passive MP, BIOS YMM20 0=
2/01/2023
>   Workqueue: nvme-wq nvme_scan_work
>   RIP: 0010:check_flush_dependency+0x112/0x120
>   Code: 05 9a 40 14 02 01 48 81 c6 c0 00 00 00 48 8b 50 18 48 81 c7 c0 00=
 00 00 48 89 f9 48 c7 c7 90 64 5a 82 49 89 d8 e8 7e 4f 88 ff <0f> 0b eb 8c =
cc cc cc cc cc cc cc cc cc cc 0f 1f 44 00 00 41 57 41
>   RSP: 0018:ffffc90000df7bd8 EFLAGS: 00010082
>   RAX: 000000000000006a RBX: ffffffff81622390 RCX: 0000000000000027
>   RDX: 00000000fffeffff RSI: 000000000057ffa8 RDI: ffff88907f960c88
>   RBP: 0000000000000000 R08: ffffffff83068e50 R09: 000000000002fffd
>   R10: 0000000000000004 R11: 0000000000000000 R12: ffff8881001a4400
>   R13: 0000000000000000 R14: ffff88907f420fb8 R15: 0000000000000000
>   FS:  0000000000000000(0000) GS:ffff88907f940000(0000) knlGS:00000000000=
00000
>   CR2: 00007f60c3001000 CR3: 000000107d010005 CR4: 00000000007726f0
>   PKRU: 55555554
>   Call Trace:
>    <TASK>
>    ? __warn+0xa4/0x140
>    ? check_flush_dependency+0x112/0x120
>    ? report_bug+0xe1/0x140
>    ? check_flush_dependency+0x112/0x120
>    ? handle_bug+0x5e/0x90
>    ? exc_invalid_op+0x16/0x40
>    ? asm_exc_invalid_op+0x16/0x20
>    ? timer_recalc_next_expiry+0x190/0x190
>    ? check_flush_dependency+0x112/0x120
>    ? check_flush_dependency+0x112/0x120
>    __flush_work.llvm.1643880146586177030+0x174/0x2c0
>    flush_rcu_work+0x28/0x30
>    kvfree_rcu_barrier+0x12f/0x160
>    kmem_cache_destroy+0x18/0x120
>    bioset_exit+0x10c/0x150
>    disk_release.llvm.6740012984264378178+0x61/0xd0
>    device_release+0x4f/0x90
>    kobject_put+0x95/0x180
>    nvme_put_ns+0x23/0xc0
>    nvme_remove_invalid_namespaces+0xb3/0xd0
>    nvme_scan_work+0x342/0x490
>    process_scheduled_works+0x1a2/0x370
>    worker_thread+0x2ff/0x390
>    ? pwq_release_workfn+0x1e0/0x1e0
>    kthread+0xb1/0xe0
>    ? __kthread_parkme+0x70/0x70
>    ret_from_fork+0x30/0x40
>    ? __kthread_parkme+0x70/0x70
>    ret_from_fork_asm+0x11/0x20
>    </TASK>
>   ---[ end trace 0000000000000000 ]---

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
811463a-751f-4443-9125-02628dc315d9%40suse.cz.
