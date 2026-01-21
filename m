Return-Path: <kasan-dev+bncBDXYDPH3S4OBBE6CYPFQMGQEFZFSMPA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id QOs8GhXhcGnCaQAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBE6CYPFQMGQEFZFSMPA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:22:13 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 06D5D58561
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 15:22:13 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-6581abb27basf663437a12.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 06:22:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769005332; cv=pass;
        d=google.com; s=arc-20240605;
        b=a69y3pYbbsZyT+MWUiWZyr7cTIWVvyd4buITgytsHDLWH+xsHFXjLYzYoQRQZPX8e6
         Z+WDOqu1KEHuOyzEK/mB6P4Dt+f06a+QB5wwELnHCGIg2kQSjkGJjR+x9OrPIyoD5lqq
         Z2kKcHtDbbntfTdK2vu3CcZ+MCVpdcAOwCLW2sRPmOhh+nFfv09EbTKVA6PnB/a10PCH
         EJk7eOw6+4wdoAUc2bDH6Fe8wFunCLzurhaJFC27WbpuUKDubPZUrGibAsB0REmznc/b
         L/uaEzZtc1C5QxY0kKWQiK1jqIEw9OeRLBQ33x08u2HFrUjrVafJDDOMpcDLQzrGEpE/
         XY+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=rb19RXDZ2T7spOMMaZsaOxr1D/F1N1cVYmjzpwDRv+M=;
        fh=vJSOU5BQGbmQ8MQ2Q8bETFujJingJTLFnDKu0o8UPvI=;
        b=SjoRXO6eb0vTlpV9Amb2MDTcUxa8ogiRzCUkqPHOMc6oOXjtvpkqh5BxzaVwD7r6UY
         /kIiUr/kQ7wYmYDRCqsa+hkBq2uLlKe6VHT7EkE49kkMEMdxAII+izRSbbUXAfCzLK57
         nJWZqkolyESinDRRmEi87mcmfO4sXYQNTNuTgZdzjJ4kEp3cozImMyK+TkSyUGg7Gu1O
         g3VA51rUZUz4zorhL5ubJuwDLY90Jawkm9uKJ+KnQpf4FCHYoPzxEJImGECcRYyjlBMR
         HcuPWk2uirotlAdd7zj6ri4KsEsqi4MeOj6n/0fnknzSanOWO0EhFyOUh2+g9N/TVcGK
         D2Uw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769005332; x=1769610132; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rb19RXDZ2T7spOMMaZsaOxr1D/F1N1cVYmjzpwDRv+M=;
        b=AoSGkMXeF40Ejjon1iXXGBzkvwLA6FhlrsqT4Sb8YETU/x/TqRdgwo8AMDSmaslUQR
         t7+xCXNhkNiWeWbNgnAH1hral921ColsS9y2QFo3XQg6RVD1+7nlE2sOuaxvWgx1mlPT
         n2JrJEJfqTolXQK4s1+hEuvlZM3VEUpXSZu3kZstP3cXIkKohUj7X5W+QFbTBh4l3+S/
         ZmTdMYj5J7vlo+qFh2xmM3L9fBq5JdA7Ls0wYjNAahrxAi0LaF79/Jfil+tcO8Ilcl7j
         RPlUSus+CIUUf12ittff1FQzc5zqWO2T+eyEaZE9rwfrzuq5n6j/VsuGEE+4n38Ufeu7
         +Jng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769005332; x=1769610132;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rb19RXDZ2T7spOMMaZsaOxr1D/F1N1cVYmjzpwDRv+M=;
        b=ijIxi9XKi4bVycgmlzc6QoROPKGcUxMadDaInGD6eSKQjZOiN5IzK3spYOuyfZlkwo
         4TNgmH7DSxFmEdejnUAi3qiQJHsmZ+1uTdPxhHpgbzABSiYVpvQKIG9JlMK8Snx6Agl2
         gDUdnxC67c0Z6WDbUL+uW9Jchyd8289Vor9YwN7xlaxq8YYJwZ4xfIOR68WYlORq2TkP
         VsMdaSUX3z8dY5lnprMKOcCo29YNcVthzOkrtkq+69neJNm+rCwZS0mU3hmAkMGHvHpC
         L4AKqdQv5ICn0A2SLGm2QUBWuOyzbZW998WfheVfvu+B8SQ8rS9DIhKhPXz4MVaXMcvn
         w+UQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1p+VwF+uOkkO6sRBDKr/ua/LFzt1RC5gFG5BEZsPdB2AoayBaGl6FlxdUzANx98y7KwvmKw==@lfdr.de
X-Gm-Message-State: AOJu0YxSkolPNGzsGBAV9vDVrek18dxMz06cZSYrNJxG9HG6XXrPF99w
	mvWLjMZhb/BQPI0ZPDHzYFKVHwhOdS/FDvsM66aN5J3qcgQBYvYP3ivz
X-Received: by 2002:a17:907:5c9:b0:b87:20eb:a66d with SMTP id a640c23a62f3a-b87932eb188mr1449448466b.65.1769005332115;
        Wed, 21 Jan 2026 06:22:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GQwAfFg+ke/BtVXHYbohYOKUXodv1rv0ka61dyzrfeoA=="
Received: by 2002:aa7:df14:0:b0:658:2f63:8d83 with SMTP id 4fb4d7f45d1cf-6582f638e9dls120942a12.0.-pod-prod-01-eu;
 Wed, 21 Jan 2026 06:22:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZHltY3phLaPLm5a0hetjKl27E9GVTnL2FtCH5ywI4JQk0oiJsuPgmkynjVnLpDLUQybGlf/XD6Xs=@googlegroups.com
X-Received: by 2002:a17:906:209c:b0:b87:bb45:bd59 with SMTP id a640c23a62f3a-b87bb45c493mr831428766b.45.1769005329889;
        Wed, 21 Jan 2026 06:22:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769005329; cv=none;
        d=google.com; s=arc-20240605;
        b=DGCFYzP3wqcD/PCSKotKbCJbG1WgOvKk6HDTeJAaSnzL1EIGK1qWKav6I5StmYQZhU
         C+/QTxlDobMiitjNQAvgCMcodhjDYSeUesZ7pdtEMUSJ5cw9Z7x+BPHb2BxpGyPU186b
         ypVvm+r7QahQmUVz2bLTHg7mIZXwQHULcRT0LgKkJKRdA/ibpWI90d8Y7V1f3dXkSjjK
         0AxEtKLiXq7YgPh1W/T7ThAjPjEeZtcHlJwttDWExky+tGup9oL2DVZ0Tj2usTKhjIoc
         4sTlnyARBYn85RdYhdcMvWxOpiv9w1dbg6+tj38N1NIuMMnAcw78R9dOXHoFuBzhKp+u
         QROQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=Z+yin5yG1LXvKg7jj+26aW4ppEi8musD0t2dIbcTZus=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=CiZBaR2b6c99w4+uSCOsaDisGJDC6woQMxavRmGGR3HKUX7jwWiJYP8M9NvquQSe8V
         M6dcnZiFPxb02txNz/cPksbh+PdHR44vGwEEGKkJ2hA77bO49W+614sQYLmy1NUCbszI
         ZU9Y9JVpO42RjGRpc+EB40nHPbhUH5W4oim4XsNP9x3EgQsZ0YL3eYM9Mm13fQjsLfiN
         mrsGIOnCnP62ropO8yGu4nEokz4L3gleJuP6BmgTiZPp7AHPOYk7ejWCuO6+tHL9hObL
         ptmUMZVXPq/5nxHHgf1WrZTk5FQQl1tY+XyotcPQ1zh9TgGGz+EsgAsAI4FYnvpm51DD
         sHyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8794f89946si36929666b.0.2026.01.21.06.22.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 06:22:09 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 624093368F;
	Wed, 21 Jan 2026 14:22:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 34D053EA63;
	Wed, 21 Jan 2026 14:22:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 3Z4bCxHhcGmiZAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 14:22:09 +0000
Message-ID: <c17d4413-1ffa-4d3e-8d87-0e7c2b022c16@suse.cz>
Date: Wed, 21 Jan 2026 15:22:08 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 11/21] slab: remove SLUB_CPU_PARTIAL
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
 <20260116-sheaves-for-all-v3-11-5595cb000772@suse.cz>
 <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpHaSg2O0vZhfAD+61i7Vq=T3OeQ=NXirXMd-2GCKRAgjg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Spam-Flag: NO
X-Spam-Score: -4.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=ysbgqLyh;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBE6CYPFQMGQEFZFSMPA];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,suse.cz:email,suse.cz:mid,mail-ed1-x540.google.com:rdns,mail-ed1-x540.google.com:helo]
X-Rspamd-Queue-Id: 06D5D58561
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/20/26 23:25, Suren Baghdasaryan wrote:
> On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
>>
>> We have removed the partial slab usage from allocation paths. Now remove
>> the whole config option and associated code.
>>
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>=20
> I did?

Hmm looks like you didn't. Wonder if I screwed up, or b4 did. Sorry about t=
hat.

> Well, if so, I missed some remaining mentions about cpu partial caches:
> - slub.c has several hits on "cpu partial" in the comments.
> - there is one hit on "put_cpu_partial" in slub.c in the comments.

Should be addressed later by [PATCH v3 18/21] slab: update overview
comments. I'll grep the result if anything is missing.

> Should we also update Documentation/ABI/testing/sysfs-kernel-slab to
> say that from now on cpu_partial control always reads 0?

Uh those weird files. Does anyone care? I'd do that separately as well...

> Once addressed, please feel free to keep my Reviewed-by.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c=
17d4413-1ffa-4d3e-8d87-0e7c2b022c16%40suse.cz.
