Return-Path: <kasan-dev+bncBDXYDPH3S4OBBL6LYKZQMGQE2I2YA5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7084C90BC95
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 23:08:01 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2ec1db2e843sf20106221fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Jun 2024 14:08:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718658480; cv=pass;
        d=google.com; s=arc-20160816;
        b=K5QwTj2OJTJscon9H2kALfBG7S5w4Ibi0lqrR6ZlHkd53P1ggkI4FlKPb8oTuh8mKD
         Fds4LDUWZnvFyurtOOWwp6XezYK7mqYU13+NUh0u9GNrP118lgAax7El6lZZe+Nz2Uwi
         hqoCg6ItcqK1kYkHeUS6OlWP8amAAjwHXOVzCa6VTRPDHXruimliPn3W/+0dwQMCgtS8
         MsUTUVUJy0YbrMbBNSAlSziNwpQtJZ83BzNu/2SHJ+szCXzoYLDCUKX/oDzRapIJUWuT
         fAepvf1EvWvYKoSiI9vvwqytEx1jKMfSQMvtlABaXLA/THq8+kr4y4LwrD3MaPb7whTm
         B00g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=3LZ7nmpIARXeFU7jBZZSQKEjMQ+n9vuWW8SYtldTO6k=;
        fh=5dvRRgJVMEelokdmQCrkPjxCXjmMGalDnQNP3AkBNu4=;
        b=X5ftVUpiFDY1uPVRLqy8GVLB2c8jVUWGFpx/ZjTpwUKgj8/59UTYeIUowYDOyv+F05
         uhUHDZvt8T+6xrewzRpnbfH4zzObTvKvmeAKuEcmFxWLee4wpn1CxcnrbtnUi9XiS6RF
         fUSpH8BsWoRB6Yie2qkroCE1ChgAkax09dOrDEd6q9aMrjkimHPrADrXkul49I27UslT
         ISMKgVUgfO2rVFHchlNdJmkOUpzg4zDSzJq9r0b4GdH61MPI7JbKMmJNOlaLVgMXDWMq
         uMEgkrDajXANLYl7q942fI35J5fSh3i/eJRocztrbIseZJrKR0C8roMvLMm9YKP/nWLE
         ihyQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=j8DR5IyT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=kBTrNAKz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ExLPViHA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718658480; x=1719263280; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=3LZ7nmpIARXeFU7jBZZSQKEjMQ+n9vuWW8SYtldTO6k=;
        b=TlHn+MOBqCkSEJ3Tots6EwYu3Zj0d/Ee7tAd/TxO7E5pqIWYDMMcd4ZawMXRZoAhLD
         +e68ZtuwnW4OAHC8LehG3GN9hVTc2dUOtpnjS1jZJxcwmqE00w6mL6pmbJcktwTSlZjD
         ktWLHtmCdKGmy7iz3Fzfu0UlIj439euApoEU3vTdSiN9OIADN/h6+mKyVvNDE+kePf4A
         4zQ9zxEa8+MTCahl3aG6xIM6yels5x1fK8JBjGckG5hTafr81VU0wLAKV5qpS5iR+aP5
         Kr9MjXqR/L7J8GVxXySh3GIiG7xDSw0+GfJawWzC0hNbBtE2w1h6+NkVNljKRJ7pAt1P
         Zk8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718658480; x=1719263280;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3LZ7nmpIARXeFU7jBZZSQKEjMQ+n9vuWW8SYtldTO6k=;
        b=CCGwJKNgUKLF7UZxsrFiHMtE+ALza61Azj0U12oXbz2cqjupxMb6iFWoEQ7RJWq5bw
         x+TRKUUDCGK/jgBrh7GXoQ4t1628NRr/Caf96hfnfXfGtyBCwpioyCwQ1Yf3xpYZqiBk
         RgRNkWGgZ/QyiaDQoNcH0YT553XW2MC1sEaQtQ8nnNggbJIc/AuGr1FcD+0Lc52rjd4K
         qweMUQg8glGKuu/0bOBr2oxtsSiW+jWOHvWho2VfC85X2Oz0B8mjILTgXwTTActr7kig
         4bHJpaiw7VnjXr2oRXBLV1sltYjqt/2iwDXm7Gu/26wFFsoLrFC+RjAr3js+fb1SnFB5
         6dxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURfAf5NT4CmG8wwzJ6S/PCrUJaCKyqnrXDWF3bSPyfjuc4inpJjG/XBCxd76JfBpk478+ra/Hmpkw6o+zrlokM7D3Gi8rELg==
X-Gm-Message-State: AOJu0Yx8/db+Ie7WHd482TP6T9EJ4xXRwlUBGUZCg2FYT6EyXZ6KKaID
	BffFTKMRQZ/IoQcy163nrNo8raUKawjFJEJVRBEWD8f8BBzp5w40
X-Google-Smtp-Source: AGHT+IE6dvqEWMxozCFnBt6m17/D2WeZ2AQpfJNnQzuO1I9zwL4fQ543rsMteWU/CFQJn6NWL+VCJw==
X-Received: by 2002:a2e:7018:0:b0:2ea:e56c:f898 with SMTP id 38308e7fff4ca-2ec0e600462mr73021241fa.33.1718658479749;
        Mon, 17 Jun 2024 14:07:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9d53:0:b0:2ec:454:2e9c with SMTP id 38308e7fff4ca-2ec04542fc2ls15382391fa.1.-pod-prod-01-eu;
 Mon, 17 Jun 2024 14:07:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVt3BryO74bW67xEwhSQtYfuR5jJpis3BNZQu35lG3pLR46tnseQnfp60aCSm0iEvQxEewqAPayjvGBtw0Szf4T6U67QTQQjNGpBg==
X-Received: by 2002:a2e:240d:0:b0:2eb:ef78:29c8 with SMTP id 38308e7fff4ca-2ec0e5c675cmr70870311fa.14.1718658477789;
        Mon, 17 Jun 2024 14:07:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718658477; cv=none;
        d=google.com; s=arc-20160816;
        b=gB0P/tbYWSHmw23EsNpz31ZXHRmiEUajdtvKNwCLluzr6anwjtnWQuyaCt5q1n3UY+
         2+9G0Nr2dAqUAuNsUs8FZSPLtRmpNCEYoyEK4ATsqiFLqKuapyxhwMgJBsuSWl7el3Mw
         9iwFTnncr+09KYRLE956lfPosxJ1hq+13k3zwKTzYgqyunS64nDVXhagVLSjxuIhVde/
         FMCgLPP+iOUriyjnBuEK/9POdh8nB7/7vM/ykomFGZpzKIjiOUYXs1wEwaX/KyiGp10a
         57ABLigc8gYodskhgVYlZfptrJ0bMnypADfHBfD6YeAHXcN00YjzYIeLApgOWiaeeNQI
         k4PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=GhqD1JZCa8h9LMBNO3ezSkJWmrAJo6LNKwZwWzpwW1M=;
        fh=kPgoZ/TakvrG477Osm2XIQkgvYddNMQ0TlS2daNPXRg=;
        b=kt/cJ4HqjWvwT0DojanxyJnX73Z1DleorzzCExNxKvBzftLjpJBx0YAoiLFlFxY2ek
         2Z4/f529/pvRDFdQzQYC2SPv4bYfxM0kh2CpkYwUQdKxaJHqy/GDS3VUw/erTy9VfI4B
         NHmJdDJejq7Pi7lHINyAJv21hLG6sYCBXtU7aMhr7qFmdgycu+iy33oaVGwC1Fv6tOsj
         MgBhv7Cmia8beOVK/cbo7Zaky794xNPjh7qAdHZC10Qm/YRUVxbTT6Ln1hxOkm7ovm/X
         vgY9TpboQSxhZC++i7rsuOt/7OaDBJCMWp1/kisorq9mjfBc20o1SO9L1J1r+qFCdNI7
         xjug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=j8DR5IyT;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=kBTrNAKz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ExLPViHA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2ec05ca6debsi2161871fa.4.2024.06.17.14.07.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Jun 2024 14:07:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E56CA1F395;
	Mon, 17 Jun 2024 21:07:56 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id D268B13AAA;
	Mon, 17 Jun 2024 21:07:55 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id MnYzMqulcGZ9SwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 17 Jun 2024 21:07:55 +0000
Message-ID: <36c60acd-543e-48c5-8bd2-6ed509972d28@suse.cz>
Date: Mon, 17 Jun 2024 23:08:58 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 00/14] replace call_rcu by kfree_rcu for simple
 kmem_cache_free callback
To: Uladzislau Rezki <urezki@gmail.com>
Cc: paulmck@kernel.org, "Jason A. Donenfeld" <Jason@zx2c4.com>,
 Jakub Kicinski <kuba@kernel.org>, Julia Lawall <Julia.Lawall@inria.fr>,
 linux-block@vger.kernel.org, kernel-janitors@vger.kernel.org,
 bridge@lists.linux.dev, linux-trace-kernel@vger.kernel.org,
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, kvm@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Nicholas Piggin <npiggin@gmail.com>, netdev@vger.kernel.org,
 wireguard@lists.zx2c4.com, linux-kernel@vger.kernel.org,
 ecryptfs@vger.kernel.org, Neil Brown <neilb@suse.de>,
 Olga Kornievskaia <kolga@netapp.com>, Dai Ngo <Dai.Ngo@oracle.com>,
 Tom Talpey <tom@talpey.com>, linux-nfs@vger.kernel.org,
 linux-can@vger.kernel.org, Lai Jiangshan <jiangshanlai@gmail.com>,
 netfilter-devel@vger.kernel.org, coreteam@netfilter.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240609082726.32742-1-Julia.Lawall@inria.fr>
 <20240612143305.451abf58@kernel.org>
 <baee4d58-17b4-4918-8e45-4d8068a23e8c@paulmck-laptop>
 <Zmov7ZaL-54T9GiM@zx2c4.com> <Zmo9-YGraiCj5-MI@zx2c4.com>
 <08ee7eb2-8d08-4f1f-9c46-495a544b8c0e@paulmck-laptop>
 <Zmrkkel0Fo4_g75a@zx2c4.com> <e926e3c6-05ce-4ba6-9e2e-e5f3b37bcc23@suse.cz>
 <3b6fe525-626c-41fb-8625-3925ca820d8e@paulmck-laptop>
 <6711935d-20b5-41c1-8864-db3fc7d7823d@suse.cz> <ZnCDgdg1EH6V7w5d@pc636>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <ZnCDgdg1EH6V7w5d@pc636>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Result: default: False [-8.29 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gmail.com];
	RCPT_COUNT_TWELVE(0.00)[29];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[kernel.org,zx2c4.com,inria.fr,vger.kernel.org,lists.linux.dev,efficios.com,lists.ozlabs.org,linux.ibm.com,csgroup.eu,gmail.com,lists.zx2c4.com,suse.de,netapp.com,oracle.com,talpey.com,netfilter.org,googlegroups.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	R_RATELIMIT(0.00)[to_ip_from(RLr583pch5u74edj9dsne3chzi)]
X-Spam-Flag: NO
X-Spam-Score: -8.29
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=j8DR5IyT;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=kBTrNAKz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ExLPViHA;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 6/17/24 8:42 PM, Uladzislau Rezki wrote:
>> +
>> +	s = container_of(work, struct kmem_cache, async_destroy_work);
>> +
>> +	// XXX use the real kmem_cache_free_barrier() or similar thing here
> It implies that we need to introduce kfree_rcu_barrier(), a new API, which i
> wanted to avoid initially.

I wanted to avoid new API or flags for kfree_rcu() users and this would
be achieved. The barrier is used internally so I don't consider that an
API to avoid. How difficult is the implementation is another question,
depending on how the current batching works. Once (if) we have sheaves
proven to work and move kfree_rcu() fully into SLUB, the barrier might
also look different and hopefully easier. So maybe it's not worth to
invest too much into that barrier and just go for the potentially
longer, but easier to implement?

> Since you do it asynchronous can we just repeat
> and wait until it a cache is furry freed?

The problem is we want to detect the cases when it's not fully freed
because there was an actual read. So at some point we'd need to stop the
repeats because we know there can no longer be any kfree_rcu()'s in
flight since the kmem_cache_destroy() was called.

> I am asking because inventing a new kfree_rcu_barrier() might not be so
> straight forward.

Agreed.

> 
> --
> Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36c60acd-543e-48c5-8bd2-6ed509972d28%40suse.cz.
