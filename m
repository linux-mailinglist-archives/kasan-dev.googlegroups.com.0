Return-Path: <kasan-dev+bncBDXYDPH3S4OBBHGHZ62QMGQEV56VRUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4582294B1D2
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 23:14:06 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-36848f30d39sf118332f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 14:14:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723065246; cv=pass;
        d=google.com; s=arc-20160816;
        b=cPc+cFEiHPaBkZzE90az6nVfx5ysA0rpBIi0pn19LqHG3jPPCZESrwGcNy8raU56k8
         DUH4yc1T5pyNBxt4ODqJ6OrflnOIeQHWYgrhlZO4bN6P6adUba2dpdhKI/vvueqla1ET
         QzQzxYWZaz+pXvcGERnUQxOk31YgWqR/ZptmOf/UD6hCLziWa61/Xc1GLSlmxC3uNqO0
         b3GzfPqUcJz+pJB1ghN9eyZGxgz7agghiQe1CrSQlVDOigd0sd/a8CQwPIlWO0SASMQq
         CWbHegeoaPgPU0bjSS07hv+j3A7PJlQM0pMNJxgjiyxdZFXBNgqH4ZxLXH6+MzG82FKz
         P3fQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=23h+jqFzs7IgUHWGXzZRVO4T8Ij1gYOLKtZDqVBiQQ0=;
        fh=8LC7z4H6aRWsyE/b7s0HH9/UVaDX59FiA+gTtOKELIs=;
        b=kGgULaJr7kCFh7Ljq48K4kLfrLezT7FAxDGj1aqPKsHs8Lzy6hBFmC1XMBbTrFx7As
         60lso3aOQTI+ZikJ3v02p1cpCFlh1naE7O++0DT3RtW7xucxETG/q8EIySYVUYL8hxMT
         gHb6NLnXByRHYm9v1fynC7LCpnNmDaIGIeShdH8saFvFCmOzhUn2EiEQFsCOtvwLzeFk
         L+1A1ijeTKknROZ8/Rq+ogrJt2lmKS3UTQNI1Q5ZP/6dp3rFUuyGLZQqzUKJg0naaDAb
         Jt/RkaWJI67CYmHvov9cpy1Y95XCn8kgtvapoTEZF01EkdUEQ8QP+ggLwBsTJ6RQGW3c
         4y9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723065246; x=1723670046; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=23h+jqFzs7IgUHWGXzZRVO4T8Ij1gYOLKtZDqVBiQQ0=;
        b=JrdgSlgN477qqJ5j7+tvg0Uw5MD6bluO8ZJezBPtrhqxjKEG8v9PLiKOcWTid3tffg
         P3ILz2OYZ1Fgvmn1QHgY4UeOPiHDpg/PsoNjUhk4kZ2xnQFRVxKGNUseDAuRHbtO5FW/
         lHRynU5/Ljs+Z34dTfgSunkyiEI/RaLRzjkoj5qKiuAgnx8o0bW0FjrI3lwJYZBFu+PQ
         MhxBQPdhRKbkvGv1jfU30TWHH0rSSqDd6wAzENGsvjcvvtgFBmm0mYD2zWlhZX0h34c4
         YZ23GMP3pUNDVEPB/M/F9T/rCxKFQE5WeoCQjirq5zF4khby7xrUVKglgXn4PCj/aiWJ
         1SXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723065246; x=1723670046;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=23h+jqFzs7IgUHWGXzZRVO4T8Ij1gYOLKtZDqVBiQQ0=;
        b=bnwRrD74wlvBLCLWTwnRVJp6U12XzJw8uhCm1htZBHzuV1k5RKlDJIztiv6TxZDQpC
         NxIdgxPsyWhk3a6TBvmgufMa79Q52mRJ3bQGUdCXSwHvXelkP5qkDlc8IC4Pje/SJYNL
         8Ys0NMXNhFZC6SnT/FshTblBpX4xf8WBUyICxlBL+evsT6qQ8qhrp9SPyhcQg9Szk4ch
         VkQLvAboj5HOAvDrjjLE9xq/HXJI/YdfQVOuebMezEKcLSVBTayX/oagS57TfhDlL4pN
         pJz69pAmW9U2cIw0OQbKysOTcXs3Nisf0ZF4fFP9uHzy0wmhVAyskQ1lBQIuSe4o6epl
         CIlA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhMfaoZ6M6yRSAfXid49uTzKcrTKTesszw66M+lyNIx1eCCUDVgpUco2CjzhKPgmAl6k3u+uHW54OFmIylSMRWQwBV0MeSRw==
X-Gm-Message-State: AOJu0YxFeXgv0Pc4bNRikNrotj6WhmR1SjPk03I7pf0K4bK3P46TH2/B
	AagUrW6rbJ9FwJ7A/gLA0kASU79qtbeff8+3LGZ5Qsv3ya8fvZ2C
X-Google-Smtp-Source: AGHT+IFOGbPU2/8E6iL4tWHyu7GXf0Vq67giw/iDCgqvp8MemA0tXBHndbtXf1wV7WJF1VcdAh3J6g==
X-Received: by 2002:a5d:58ca:0:b0:368:7564:5a1d with SMTP id ffacd0b85a97d-36bbc10f5dcmr13592059f8f.35.1723065245097;
        Wed, 07 Aug 2024 14:14:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5345:0:b0:362:606d:1022 with SMTP id ffacd0b85a97d-36c8134c754ls70309f8f.1.-pod-prod-04-eu;
 Wed, 07 Aug 2024 14:14:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWI26fwdPL/P5x9diENdrNzKIOJfVCLJJfAACTpDMqOy2IgGiwsuY2Svf7obKkzql2UmGD6ZD0PXQUFNIUC9Apbqyh5vJ9s/Bvp/Q==
X-Received: by 2002:a05:600c:3552:b0:428:314:f08e with SMTP id 5b1f17b1804b1-4290aee0495mr149875e9.5.1723065243248;
        Wed, 07 Aug 2024 14:14:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723065243; cv=none;
        d=google.com; s=arc-20160816;
        b=KG+Ibu5BAfa9G/40yGLhuN/kfiazqqrx4a40NOciwuMFdREOtSvkII9X+IZ/0rF+mK
         K/ZKrzIICR2jkGAxkKLse8EKqXJbvnbX6lTds+2svD0uXjb392ieprraQXtEtBU3s/I8
         zxGb0bVtveLwADmsjtkgsv1FdlredeW5hdrVlSJlmYP+c1KTvC8rjl762C6H0xaZ4M7m
         8Uwh402hzydXO3b2uP9pyp+Px7lRNMlgayRnZ75G9kAxNnY0IXM0sH6Awa2yXm+xOQ7R
         vkghKZHJ5gFm0no2h99T+deqxl7vCXMbqZ5XoDBshTBOwhRnAEEWJkSwbmlsGFEz+ihd
         cfew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=eQD4Br/ZzkU5aWA9puuXt04qjFbGSUKuou34lXjuW3Q=;
        fh=GJQHVfLY7tV7xmEoTG7nVHA2Hyb6i4zglgDjbMqriLU=;
        b=dj+Yn1ERFO+i399ohNitefW9sRTCnhZ4c66kSBFFwVeOqdCHc1rQmUUUHh/bM4GWwz
         EUZ2ZMwppIzU07qgZgKagAVEfQSZDvVOeEuMGq9KzMief9BggW6sr5/IM8OIVFxfTdlX
         8sWcywkjZ91PSQYaNQbr41XFeoMFk7LLpKC3spIJFDeJTX2fV6pGKme2tekvYlJTjPnH
         urcuPRsS0L2ukEs9MjZJwMGRCl5GklS+aD8Yn06FtItVLYjw7AsyUZmRB+krCVLbHCmO
         3gSVqAGrZx+KzLxjmlADPwYmJATmMjaZB+47SZpMkBoYznPKWQVK/UuKatThgbyWb3UM
         T6ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42905698ebesi465395e9.0.2024.08.07.14.14.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 14:14:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 8563E21CFA;
	Wed,  7 Aug 2024 21:14:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5F75B13297;
	Wed,  7 Aug 2024 21:14:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jEDwFprjs2btYAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 21:14:02 +0000
Message-ID: <9d250713-d62d-459e-be3a-e6ad8da78d1a@suse.cz>
Date: Wed, 7 Aug 2024 23:14:02 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v6 2/2] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Content-Language: en-US
To: Jann Horn <jannh@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
References: <20240802-kasan-tsbrcu-v6-0-60d86ea78416@google.com>
 <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240802-kasan-tsbrcu-v6-2-60d86ea78416@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-3.00 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	XM_UA_NO_VERSION(0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[google.com,gmail.com,arm.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_TLS_ALL(0.00)[];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	MID_RHS_MATCH_FROM(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DWL_DNSWL_BLOCKED(0.00)[suse.cz:dkim];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[263726e59eab6b442723];
	TO_DN_SOME(0.00)[]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -3.00
X-Rspamd-Queue-Id: 8563E21CFA
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=P+umTWfE;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 8/2/24 22:31, Jann Horn wrote:
> Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
> slabs because use-after-free is allowed within the RCU grace period by
> design.
> 
> Add a SLUB debugging feature which RCU-delays every individual
> kmem_cache_free() before either actually freeing the object or handing it
> off to KASAN, and change KASAN to poison freed objects as normal when this
> option is enabled.
> 
> For now I've configured Kconfig.debug to default-enable this feature in the
> KASAN GENERIC and SW_TAGS modes; I'm not enabling it by default in HW_TAGS
> mode because I'm not sure if it might have unwanted performance degradation
> effects there.
> 
> Note that this is mostly useful with KASAN in the quarantine-based GENERIC
> mode; SLAB_TYPESAFE_BY_RCU slabs are basically always also slabs with a
> ->ctor, and KASAN's assign_tag() currently has to assign fixed tags for
> those, reducing the effectiveness of SW_TAGS/HW_TAGS mode.
> (A possible future extension of this work would be to also let SLUB call
> the ->ctor() on every allocation instead of only when the slab page is
> allocated; then tag-based modes would be able to assign new tags on every
> reallocation.)
> 
> Tested-by: syzbot+263726e59eab6b442723@syzkaller.appspotmail.com
> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>      [slab]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9d250713-d62d-459e-be3a-e6ad8da78d1a%40suse.cz.
