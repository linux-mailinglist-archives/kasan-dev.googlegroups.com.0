Return-Path: <kasan-dev+bncBDXYDPH3S4OBBJXTUK2QMGQE44LZUYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CEC6940E7C
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 12:00:08 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2ef2b0417cdsf42914821fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 03:00:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722333608; cv=pass;
        d=google.com; s=arc-20160816;
        b=TMcggDVluPDByl5skt5ezLLSesU+Jblgoksbo+M9xeI/vE2FGdWA6rKgXEqDjyqwg1
         DIfe/JCkL4ofHIG7IgVm5Fy5c249fMGr5j+Dbmx4M3g5mOTDjgJR3S1+EE78NolKOctK
         NCQ0i2eYnLPyioYeosh/XxdlztOeituzien4ml7v08hs1BJ4hz7Lrnmur3PhI6KL9Kqf
         mGuqhfvpdUcCkjvOKt2Pt9gG9SjhHCdmOD7hKPaFqEuOMkNh3hiXAsW/N4sgRqxPoeML
         LC8b/v/FzpJtVohlvNmhPnGR6oG55WTJ7qDXEK3PUjTv628kgxsFlJN5mvScVb2Y6maK
         z3Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Ws5uvbML/reG4gCwcGE2BEqEFMFt65xONwxy9b6EjHc=;
        fh=ulmL0RxubMjKDmwg9I16Dtoj3YpBiA2R/IPlh2h1NFk=;
        b=PGRwpICxe5ZcpqC/6SwUlA0O793SnQFJlbmR4+FBaPBqswNNk7QH2XNDUhSbF09pmW
         XnAKadBqQlxGEpYMVEnFXciXIjuApyHdi6cdIaWef3qb7Mvb9FbP4NWTY1uSiHWoC8sI
         U5P6/p+XzL41XGWY9K+bunTCEKivecFk9zNrWhCI1658HNxbeqxQ2diFC5f1320m9uup
         AJ2qs3uld8D8e3uttrxSVGPNl0zjiJVRB4VaEOek4jGL7zFUpuQ06G88mkTt1sAdBzLI
         ns3EpZMnr6/UPMZZGZw2+pCm+ohcRpI14+bv0D02vPnCNoN9L6MmgoMmIEFxm1uuQp/8
         MAgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MRjJlkb9;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DoVEuTLv;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722333608; x=1722938408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ws5uvbML/reG4gCwcGE2BEqEFMFt65xONwxy9b6EjHc=;
        b=jAELJaDKoZ71+vhkwppEY2gyP60oJMITy5bY9FkWbrj7ykZA81QKQEqD64eE8Cczi0
         n9DjTbHr/Utxca/XsnEi4FyRulEUODlys1vysq8rPbNyxFBl0Qf8IFGVUs7OjTFLRAe2
         4xk/M6gJva1bZ0M2h63qI63jVAoUKy55rt6ooeW9OGrfzYv2h4WqKh8v+oEUJt8Mb1Nt
         1+h/tz2XrwdFzO1KjES2NAFTugSOeECG8z1YK1Yz8unAr1+4w/LMgiZblER7axn/Ajkz
         QuKnEW9ExXzP0DaUC+EukOIwTopC6TK08VvxLtYaD1iFzEHGfCwQAxSrw0+w+M5kFHtL
         NSPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722333608; x=1722938408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Ws5uvbML/reG4gCwcGE2BEqEFMFt65xONwxy9b6EjHc=;
        b=naDj9KM22V1VYwjF2QfuVr47JOpPgQIEOUbHCpB2Hg3RNIgBbFjmoObKeBZxq+5Qs6
         sthSRuZF98sW/sEYzUKay0X4YT4tUchBkb5qXK9SoyYy+UXc3nsMhMzPFTrDbh+P8ATY
         CnoEbLSJ5g+wBOjUqgswyqV7Vf6pON2B2z0lTz552Sl7FFQxvwBlYc577Z+kuUtKbLij
         tXGA2GKgvxtuAU6CrB6hm6UyXc5BpxNuvMtwoaOc3rmT2YT/Hfouf2P5coquFwlbdhac
         ToO5SqAYKPCg4j/mwCAHaS7rRnFp90eYiqVDLs4XIg46SzWllS9vzpYcygvz6eB/iBef
         sBYw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAdLcbQVlezn+vTfe4POxjYLjx8Ezgha4fak7aBanEFce9GgFf1KGxPjSqmTZuTTUdQAs9RP2827cHssJpKZ0ypvQdL++mOw==
X-Gm-Message-State: AOJu0YzIenz90h3KU1F/iTIXlNovzwzR8CW6HWHBlB8lf55QDelizsEF
	aopCyzY/LNu3wNmoYM1D2vrOtdx7WZfc3XY93/So4Tj38sl3CP1S
X-Google-Smtp-Source: AGHT+IEkk6iYIQf8jORmeOemV9koY118O8DhQ+l3U6U7TUHJN5Ny7XuzEZWn3Bethal/TYX4980z3Q==
X-Received: by 2002:a05:651c:19a9:b0:2f0:1a95:7108 with SMTP id 38308e7fff4ca-2f12ee1bd3cmr72086981fa.32.1722333606728;
        Tue, 30 Jul 2024 03:00:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2110:b0:2ef:1eb3:473b with SMTP id
 38308e7fff4ca-2f03a2b4be5ls25373291fa.0.-pod-prod-02-eu; Tue, 30 Jul 2024
 03:00:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcUfR10L7xrMPSDkygNdJ7oQtVRFap2wTQXgpU2shv56M+tUVBCC6cAmG2CyajH83PSQNDXNnQACooNAFwzTURlTc1+oFxxk51Lg==
X-Received: by 2002:a2e:8296:0:b0:2ef:2c86:4d45 with SMTP id 38308e7fff4ca-2f12edd6978mr63768171fa.27.1722333604427;
        Tue, 30 Jul 2024 03:00:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722333604; cv=none;
        d=google.com; s=arc-20160816;
        b=mlTxBRKUWYMCKwSBml/ux+s6W/ipWiH/Bq4xZkMoOv2S7fwzh2NzhuLopzt3mmw1YK
         It+iwqzIZUqGT4O/YWKoGgVQUoicM0TRgp8kmMfAyzBH1w98euHC9MqweRSDhd2NLmWQ
         snzZHVjL393F1OpEWmfqwiJ/lDnFZM307QvORQL1VVZukqhSRCdVfSMPRlZrnQLuVWMY
         cRUi2kSxZuoubg6hWka0AWWXu1ZkTDKesRHZh7EDWx9S9PgWTRQcfLBHC3XLRva9qMpW
         +gUhOIDhp75S35vZYNdgZgjmBI/Ik7c2AKQoSXGcceoIepiock7A5hG3qosjdAjTVIrX
         GmpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=FYE/yrKasWTDsioKmGzRTK+De0ZmQxvlTJ0eyUHh8tU=;
        fh=WCnmA+7Qn8EW+EZSGtNKkAMtwXvPHoCda3ZDsHfCXog=;
        b=tP+N7Ir4m8aJzThjohUVTb2V/4Dflc8+BUoketG4oOZGGOmwALblxuGQ8VPhLLO6fG
         K4U2IwHp7DKaDsHP/mEjdT8ghh+aY7XvZf8VvwWckpcNHtnUsGgWa4Xyghxu95D7nUh/
         zO7p0nNMpzlDRUsvZpezR9nMD7KuPXI1xW8RJ1WiLqy7h+0rKcegvsNWPC29hXox2j/v
         rn8uI186a7MDGKq8FVasplkluMnOlxgDfqDCb4ERqnpFLGEeodVNolVZscuOdkDqvA+o
         pwYEx8USZFyA0sgRJlCnRNlCS95PMJMH7o5wMrs43vk/bSAr0Q98STo5Sr9hXG8BLBq+
         oIWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=MRjJlkb9;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=DoVEuTLv;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f03cfff36fsi2658641fa.3.2024.07.30.03.00.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 03:00:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 56DB321B13;
	Tue, 30 Jul 2024 10:00:02 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 44B8213297;
	Tue, 30 Jul 2024 10:00:02 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id xHmFEKK5qGYCHgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 30 Jul 2024 10:00:02 +0000
Message-ID: <0d6e8252-de39-4414-b4e7-b6c22a427b0d@suse.cz>
Date: Tue, 30 Jul 2024 12:01:44 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] mm,slub: do not call do_slab_free for kfence object
To: Chris Mason <clm@meta.com>, Rik van Riel <riel@surriel.com>
Cc: Pekka Enberg <penberg@kernel.org>, Christoph Lameter <cl@linux.com>,
 Andrew Morton <akpm@linux-foundation.org>, kernel-team@meta.com,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, David Rientjes <rientjes@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>, Jann Horn <jannh@google.com>
References: <20240729141928.4545a093@imladris.surriel.com>
 <044edc48-f597-46dd-8dc8-524697e50848@meta.com>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <044edc48-f597-46dd-8dc8-524697e50848@meta.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 56DB321B13
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[12];
	RCVD_TLS_ALL(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=MRjJlkb9;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=DoVEuTLv;       dkim=neutral
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

On 7/29/24 8:46 PM, Chris Mason wrote:
> 
> 
> On 7/29/24 2:19 PM, Rik van Riel wrote:
>> In 782f8906f805 the freeing of kfence objects was moved from deep
>> inside do_free_slab to the wrapper functions outside. This is a nice
>> change, but unfortunately it missed one spot in __kmem_cache_free_bulk.
>>
>> This results in a crash like this:
>>
>> BUG skbuff_head_cache (Tainted: G S  B       E     ): Padding overwritten. 0xffff88907fea0f00-0xffff88907fea0fff @offset=3840
>>
>> slab_err (mm/slub.c:1129)
>> free_to_partial_list (mm/slub.c:? mm/slub.c:4036)
>> slab_pad_check (mm/slub.c:864 mm/slub.c:1290)
>> check_slab (mm/slub.c:?)
>> free_to_partial_list (mm/slub.c:3171 mm/slub.c:4036)
>> kmem_cache_alloc_bulk (mm/slub.c:? mm/slub.c:4495 mm/slub.c:4586 mm/slub.c:4635)
>> napi_build_skb (net/core/skbuff.c:348 net/core/skbuff.c:527 net/core/skbuff.c:549)
>>
>> All the other callers to do_free_slab appear to be ok.

changed do_free_slab to do_slab_free in two places.

>>
>> Add a kfence_free check in __kmem_cache_free_bulk to avoid the crash.
>>
>> Reported-by: Chris Mason <clm@meta.com>
>> Fixes: 782f8906f805 ("mm/slub: free KFENCE objects in slab_free_hook()")
>> Cc: stable@kernel.org
>> Signed-off-by: Rik van Riel <riel@surriel.com>
> 
> We found this after bisecting a slab corruption down to the kfence
> patch, and with this patch applied we're no longer falling over.  So
> thanks Rik!

Indeed thanks and sorry for the trouble! Given that
__kmem_cache_free_bulk is currently only used to unwind a
kmem_cache_bulk_alloc() that runs out of memory in the middle of the
operation, I'm surprised you saw this happen reliably enough to bisect it.

Added to slab/for-6.11-rc1/fixes


> -chris

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0d6e8252-de39-4414-b4e7-b6c22a427b0d%40suse.cz.
