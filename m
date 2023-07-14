Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBT4BYSSQMGQENEPX3HA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6680C75347A
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 10:01:20 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-3fbb4401021sf182645e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Jul 2023 01:01:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1689321680; cv=pass;
        d=google.com; s=arc-20160816;
        b=KyXJYE+HbHrXZZQdydLu89AJKqdaCzGKiAbNtY/9UaC3dfmW6WNrHsekiEigVEldaf
         dWTB6EG/DUCAC2DwJCBcVdC4e+/ZS0RDmOgUjT6SvEI0QrEAuWD6p7l2t5x65Cn3H3FK
         chuFw+rfAFdtnsOCFMyPWv1h8EUpprCz2qiZbbAiuBSoEGfRgonD72b6jgFfQF5T/3mQ
         svkpSb5IY6cs/VNrYnxw62NzE0PhkMvIWeNj/r8EygZoi7DfHa3s0qwGOkNDUOdtSr1Q
         mPaVUBzY6t01uYK81YhDRXyMYKr34yntlavE6Ct8tVQCJvpXpYHd3KTUzpHm75weNhq0
         nOOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language
         :references:cc:to:from:subject:user-agent:mime-version:date
         :message-id:sender:dkim-signature;
        bh=0DjWY10/nsI3GKIXjxWXRvCfP1T2XRNV7gqreJxg/WA=;
        fh=m6I1Pql7K94sY7FiQBH0Wk1yFjG2FUZUwPXu2sjjSLg=;
        b=C9SzVVzf4Sm3U7yWU2UFUgqogc1oIXG0tUy5VUorc7+tbNhRZP8IbuJYTMIhL+IwA6
         qcx0Pi3LI46Xe09xz0WKPBJRAY5kr3r5JhQ7g8w7zvUtBc6FAIULcij/nyh3GnUt0Iie
         aHAwSR7Up3GExHRdIRhxl9Wal/87TJ8++sXxDWXW8YSAIZJ8QFtDN6m4P8FkqoRIM1t+
         d/HqYEUfQGYHT1p4B+N64tXKNamzJWMGVwGYG7DPgKSSGV/NKLKGs75bjAKQYSwdXPkI
         MLZlvmLX8nPuP1sH2VMN3Vk5tWjjrKwa4G0oHmMZCtptaY0jga9Kdqux1h4dYalrnAQV
         p3Fg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=odJB0X3q;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1689321680; x=1691913680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:references:cc:to
         :from:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0DjWY10/nsI3GKIXjxWXRvCfP1T2XRNV7gqreJxg/WA=;
        b=e4eTVbOn5MxcQccRMjyTJhf0AaPllpPxGXRAEcRJSy/xDSOu2lglTTjtI2EvgNbbSa
         dBQitzuRl5VTusETsCdcW9Naiq4K+gbWcpqgmPmRTXNSbBsaF/M3/uiX5VtVI5zFKmUF
         rFmuZDWSpYf5hxteE+2Y7FD77XIqsWngjVs81dkQMXdm99QieVeS13yBSDcPbYz7MAcB
         h994RmVWn1JAT3HrrwiEC96wfJW1qaR0wGh0zvyLSQyt1IEj8/C4YednLtJbC7CFGUK2
         EAtRJ41bLZpDvBIr9pC1kTwT2Ck76xhSTGwrsZjgQaamC+GoCiIV+9xhik7Pd23SGd1B
         hJ0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1689321680; x=1691913680;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0DjWY10/nsI3GKIXjxWXRvCfP1T2XRNV7gqreJxg/WA=;
        b=M932N1wKgclzfVQCwQgbDAeskqDRg6KlJtCbvCFzTQm5ClCRPnZjiLc3dVxisli6Vz
         7nJXZer97TYFvbzMfEfr2+LUeya+707dfAwPANMpR6rrL/fIUvfHMgThvCCtlWyeqtaE
         6asRAeEFt9Im8w08e6WrKl9RwIz91g+UU23A9aEHif3flI7BTE9bPo80MYACqU99G5NG
         N481EW6wsDxjucU5g9IlsCfUaDVqnQ5MKjKLDsAgUBF5aSOyW9hl5x6Wb0wYC2GU3lDN
         4houCd8+WS537UvUKcjL1A2kaxfVUEYiKPA2gvilTWfYdxWinLRPKpGisvYjVasZfiAN
         6k3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLZY00QpdQaNm5qAzh/FjJAayhHN440bXMqTcWCOPsOIU094ay5L
	PU16Vt5C3YLpZHjP9/Rm5Xk=
X-Google-Smtp-Source: APBJJlHeEQ9B2o9WSbcl4j76rvFZJ2dGPx/uBZ59KM4xAZK28aiFIbRn0AzSObRo7+qbTvlKRRIgZQ==
X-Received: by 2002:a05:600c:4e01:b0:3f1:6fe9:4a95 with SMTP id b1-20020a05600c4e0100b003f16fe94a95mr323042wmq.4.1689321679384;
        Fri, 14 Jul 2023 01:01:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc82:0:b0:2b0:2eee:3eb3 with SMTP id h2-20020a2ebc82000000b002b02eee3eb3ls113124ljf.1.-pod-prod-03-eu;
 Fri, 14 Jul 2023 01:01:17 -0700 (PDT)
X-Received: by 2002:a05:6512:3189:b0:4fb:9469:d65f with SMTP id i9-20020a056512318900b004fb9469d65fmr2978061lfe.37.1689321677263;
        Fri, 14 Jul 2023 01:01:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1689321677; cv=none;
        d=google.com; s=arc-20160816;
        b=NzaB3aC5Uoke13TCVvfrZH8zB9yhDhEhc9+lriJ295M8pLRNlp+wOo2/M1RJG0eCwa
         RizqJKQLgnh7UjIlMWh1G0kB8mzlmEBAc0UDfNJpNl9SiyvISOM8B3RBEqmBqta2p0k0
         VFaoy1Z0ASyF0PlJ7HMDjt4yE7kSquWvcMDOI5SHB+NmfS3yQxSagty/jwY8USNQrtxP
         D45l2tnXOlzC5kyWHt8ZvAFF80nMcE7RNUVquKejS/8WoEeklWTeOJteJAqz2ijYKLFy
         nhdo0uGQSewrlZTL9st/p5Fkzyhs4SzQyrpvoU39kARs6q87rqFyWHs8TIRY2e62g/Ai
         mVjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=Q8U17kbz9Qkptcs1GwSYT3csRlRYjC4fhM5H0d02U/E=;
        fh=m6I1Pql7K94sY7FiQBH0Wk1yFjG2FUZUwPXu2sjjSLg=;
        b=jMV/txmU4DVVN8FcU4p6P+MN5gakWXMjBnInT5eaOE2/L0ad3m5YP09i4K0EnHQzuX
         Qh3f9LzqZTs8LqhnMv1KDkAh04C58U2GDASH2UYpb016O6x9VmLyIfT4EtgdbqA+6zFg
         qgm4kj13picPbQ4UxQPAw9oby4X4St/i6fE9a+gIZEQa/8OBB4Sr5t6RvbA0U8aN0YtE
         NnBCdITbH4JpSNoNnVtHtfi4e2mBEDk/Ip6DK8PM2NghVexCIEOsYW93fHltkATGALrW
         V8+pl0ODumZxKzRC4JPVbcI+3sQeoZ5FPmg6MLSbrU143Ov9jYKq0auz3CTXs/o3RsSw
         dBtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=odJB0X3q;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id k41-20020a0565123da900b004fba307ab75si703686lfv.7.2023.07.14.01.01.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Jul 2023 01:01:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 843231FD8E;
	Fri, 14 Jul 2023 08:01:16 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 4513513A15;
	Fri, 14 Jul 2023 08:01:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id KeAdEMwAsWQDSAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Fri, 14 Jul 2023 08:01:16 +0000
Message-ID: <7c33a6c3-4ded-e0e4-820d-ffc337da9800@suse.cz>
Date: Fri, 14 Jul 2023 10:01:15 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.13.0
Subject: Re: [PATCH 2/2] mm/slub: remove freelist_dereference()
From: Vlastimil Babka <vbabka@suse.cz>
To: Kees Cook <keescook@chromium.org>
Cc: Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 patches@lists.linux.dev, linux-kernel@vger.kernel.org,
 Matteo Rizzo <matteorizzo@google.com>, Jann Horn <jannh@google.com>,
 Andrey Konovalov <andreyknvl@google.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org
References: <20230711134623.12695-3-vbabka@suse.cz>
 <20230711134623.12695-4-vbabka@suse.cz> <202307110917.DEED145F0@keescook>
 <b18ca2ce-5ebc-1a38-bb9d-a8bb9070cdb1@suse.cz>
Content-Language: en-US
In-Reply-To: <b18ca2ce-5ebc-1a38-bb9d-a8bb9070cdb1@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=odJB0X3q;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/13/23 09:44, Vlastimil Babka wrote:
> On 7/11/23 18:21, Kees Cook wrote:
>> On Tue, Jul 11, 2023 at 03:46:25PM +0200, Vlastimil Babka wrote:
>>>  
>>>  #ifndef CONFIG_SLUB_TINY
>>> -- 
>>> 2.41.0
>>> 
>> 
>> I like reducing the complexity here, but I find dropping the "object"
>> reassignment makes this a bit harder to read. What about:
> 
> Alright.
> 
>> 	object = kasan_reset_tag(object);
>> 	unsigned long ptr_addr = (unsigned long)object + s->offset;
>> 	freeptr_t p = *(freeptr_t *)(ptr_addr);
> 
> Are we really so benevolent with declaration-after-statement now? :)

I've left the declarations separate for now so it's similar to
get_freepointer_safe(). Pushed the result to slab/for-6.6/cleanup and
for-next. Thanks for the reviews!

>> 	return freelist_ptr_decode(s, p, ptr_addr);
>> 
>> ?
>> 
>> They're the same result, so either way:
>> 
>> Acked-by: Kees Cook <keescook@chromium.org>
>> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c33a6c3-4ded-e0e4-820d-ffc337da9800%40suse.cz.
