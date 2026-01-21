Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBXAYLFQMGQEXPBER7I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WD9AHgiwcGmKZAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBBXAYLFQMGQEXPBER7I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 11:52:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 15448558A6
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 11:52:56 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-b8715782415sf654875866b.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 02:52:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768992775; cv=pass;
        d=google.com; s=arc-20240605;
        b=XebZS6EQFifp9UMd7sx3AN2ckaZZTfyPsOvCtzPZxn1t+JY22y3/dxAFTMBs8pl+pD
         xR/SFU3635ZbjU1HHuWmAaGuqM3zMdcSXzgiHQRgWiNcOu7d7rUXzI9+3Rxxwt7FbV+/
         tDhu8nPoqHTqGW2aJNt37720o4ovTmCZbsJ0JlrQI6YLXY0bbzGg67ZTBHMy2Q441hCH
         5QLI9AJcfWXtGAZYG5r/mo3gfz5BqhkIEwiTnB4YRNbGgXWszLd+71E84tjesR060Arp
         5Nbq9WfDzmbnLF8QEJ7rtvDvqiU7Xst16SK8TZhilnfS5MmngCFHXICVtO6TgCFuMLhA
         6k2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=He5NiJFZ8MxfvIzI7XSYbt6KWef3d4zsUEI5UbK5TDA=;
        fh=kJ84BMz5fJteJ6t8imul0m2g523kxYhfSXbRlnBczR4=;
        b=EGHyNQGN55xTmFmj+gm+Zp/QoYAsPP7OZXd3WPnKeQ02TraFS5GfD3uBg3xtUrYm4P
         eANq6f2f+bbFMvZPDLYNg5ko7O/djVoPit40yFfsGwiMj4j6zK31jRYgNGckXDhNYDem
         2ycgNHwWjeuKLOiwM4zDpgHwRTfHLrEcfj1kdVfXo2OeytfibCU+gsz9j36SwiRHJ18N
         AhzD6FUgX+xUbxHxcuH+0H/dT4lVaqQEWY3r1mFw60eOFE33QS3MgbVkbU1xs9+EqNvk
         d9yiM8iqOQlUChh0nB3Lsedcn+iHtHap+fiw9jur1MSDR691vkieFBhUvbkYRM55amvC
         Isdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768992775; x=1769597575; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=He5NiJFZ8MxfvIzI7XSYbt6KWef3d4zsUEI5UbK5TDA=;
        b=HvlJMxKnvlAKiJ0tRzJvqp3584lVATsUWGIsmGxeB7j2qmbDomeGq0rmy80H83GBFG
         IgS9aJ6uZ/rWBxwc0o/xbl4NX0ANUoDGeDADjcOgP2BRtUacshhHpLIi1dRFRN5DKK2M
         y9HHQAs4wM/t5QWaot7/oJLKtiUgLckWHlU+J5Er5ypAFoWXGLfyE5piQJo5xL+2E8LP
         F3BAL1qwmUIXQVVQat8KJlZaw0vRu79sqquiMh0vIagmdseWTvBmBYJ607c+8DZ+n07w
         ZMbNGeGuXuKfba2LrOaF2AvbsotJuNXxjSxlL5EhM7pYGAyw4iB4iV++5eK5Gu6BXPzV
         za3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768992775; x=1769597575;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=He5NiJFZ8MxfvIzI7XSYbt6KWef3d4zsUEI5UbK5TDA=;
        b=UyqvRYFUe4mnRQSOeKCYixKjLI25EnNnCZleBR/JxA/wBGvniR8Iqzv4BEM13S7I7B
         9qPb2bJ4sXUPqNtcgplJMNH+3ZnyXCnOtldLm20UjFcWZRbkOETObH/GY5lOjJNEZpm9
         pVllizmWoUEFc3FpiVjB95lEc/mVVVnCDlAAERL9RSbHOfPtcF3rhTfzhGmyg4Li65Rd
         CDcVelVjOu352pqC/1xs5jayZwPqnx0d4Q1NATw3eJk9tnQ8mTTHTTwiEwIDw+1dfDXb
         1h1tI4YbSq5LlIha8S0QNnB4s0saeG64j5u2dD/fhu+CaEp0Sk3IWbd9ESwILbGhPten
         Eysg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULp6e9SKohBZWHRzKa0qxb+MMf/pfGA5P1qc228e/YTyA6aP8FZtVASlEXciH4r8fcUAAOsQ==@lfdr.de
X-Gm-Message-State: AOJu0YxO7+07UcoAL0OxgBnNE1pEwabdnLmbMDloCbSc0ZLwUM+eR9z/
	JuIpwlelkBQ8XE4iUA81FkXKCyOXljRT0U0iNowK22ZYrkZgrX80CT/E
X-Received: by 2002:a17:906:9f92:b0:b87:1c20:7c68 with SMTP id a640c23a62f3a-b87968e56e8mr1563752366b.16.1768992774985;
        Wed, 21 Jan 2026 02:52:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GamwkNC6Y/d6rC8YMQMvYt0kZamwC8wphI0ArdUeY67w=="
Received: by 2002:a05:6402:a254:20b0:641:5a07:215b with SMTP id
 4fb4d7f45d1cf-6541c6e6c63ls5213505a12.2.-pod-prod-06-eu; Wed, 21 Jan 2026
 02:52:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVNCaXWvgSqNTGXGRhv7toeEu/odhGfPmP8FKTJR7VGWmwHMWRISfamMA4UvqKeu1SRQOoKzIU6ryg=@googlegroups.com
X-Received: by 2002:a17:907:9496:b0:b87:17df:4d65 with SMTP id a640c23a62f3a-b8796b83e53mr1483091766b.51.1768992772666;
        Wed, 21 Jan 2026 02:52:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768992772; cv=none;
        d=google.com; s=arc-20240605;
        b=YoOZ/eHmMw+32u+7trZrlqA8Ogn/ibJ9UxStO99Tb3HWwJ2v+hCC967holBz6MECEe
         /oi3fRFhZgOHSBNTmuA+FMfC8SbYdHiBdiaXdwAyBg/zatsYIive3UcaZZRDig05tfiy
         1Qk4GeR/U8Dj2dAH+Dfj5X1jCAwb5UcDweg3oL1EkMJSzXvK0B/qXfbV3sEgxvf1wMHw
         aFZYnWRdlAByXrDapXo9yaUx7GUR9/SsIplt4qtbXlpB+kGFkg6crCYJMjdEMNtrNhuV
         tCECGuppXF80+JPIU/VyiOfQe03HNlikeQZKYL+uhf7fdxkls8iyZiA6opdAVybyXtRP
         eEfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=3yWKsT/r92oQGsuDyaTQKStsDqOsMPpZ822IiIl7384=;
        fh=cQEqfC/HNDeYlLQ+tf+O8CAK70FYEW4o+eW5yVM5K4o=;
        b=lra7mLs9K8RrVp5/puo1azlfbJAFDAjAaLH2hJ4PafF6c6XctJJz6TZUDyhTU3t6XI
         pTucLkhmEH2tFUkQh+5hX1BjDxjuPBqXn1m0m/xB8MxpZifvKXZ+iv8MmFniM/TU/jFM
         8hRJ37lgYpSq29o9rv0ehZPXhk57MYgBNqkDKyE5vlxFyRVbMGKPgvEgsOGdFWsDDdck
         xTWdMGCMJQlG7w8njTdNBdEHcmqTPcPh3FFTedSxCTf2CbTeFpvFhB2SvyDpU9bRPqYj
         va1YrzRDwYBCkyesusEFj8ye+EU+EwQiCwXMj+uMac1Cr+Um66L7gNjGSDP0VgTtGRpb
         sq+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959619dasi27974366b.2.2026.01.21.02.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Jan 2026 02:52:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id F128933689;
	Wed, 21 Jan 2026 10:52:51 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id C49DC3EA63;
	Wed, 21 Jan 2026 10:52:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id 9h+wLwOwcGkYEwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Jan 2026 10:52:51 +0000
Message-ID: <a3e1d8cc-f7f1-40bc-91e2-1ce5c5b53eaf@suse.cz>
Date: Wed, 21 Jan 2026 11:52:51 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
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
 <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
 <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wDtfqc1H;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBBXAYLFQMGQEXPBER7I];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,mail-ej1-x639.google.com:rdns,mail-ej1-x639.google.com:helo,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 15448558A6
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

On 1/17/26 03:11, Suren Baghdasaryan wrote:
>> @@ -7379,7 +7405,7 @@ void kmem_cache_free_bulk(struct kmem_cache *s, size_t size, void **p)
>>          * freeing to sheaves is so incompatible with the detached freelist so
>>          * once we go that way, we have to do everything differently
>>          */
>> -       if (s && s->cpu_sheaves) {
>> +       if (s && cache_has_sheaves(s)) {
>>                 free_to_pcs_bulk(s, size, p);
>>                 return;
>>         }
>> @@ -7490,8 +7516,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>                 size--;
>>         }
>>
>> -       if (s->cpu_sheaves)
>> -               i = alloc_from_pcs_bulk(s, size, p);
>> +       i = alloc_from_pcs_bulk(s, size, p);
> 
> Doesn't the above change make this fastpath a bit longer? IIUC,
> instead of bailing out right here we call alloc_from_pcs_bulk() and
> bail out from there because pcs->main->size is 0.

But only for caches with no sheaves, and that should be the exception. So
the fast path avoids checks. We're making the slowpath longer. The strategy
is the same with single-object alloc, and described in the changelog. Or
what am I missing?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a3e1d8cc-f7f1-40bc-91e2-1ce5c5b53eaf%40suse.cz.
