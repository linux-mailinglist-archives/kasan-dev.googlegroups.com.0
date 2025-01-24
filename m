Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYVEZW6AMGQEV23XUZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EF66A1B1D5
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 09:42:12 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5dbaaed8aeesf2147240a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 00:42:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737708131; cv=pass;
        d=google.com; s=arc-20240605;
        b=glUTqp/CmmCjzyNhIpvF9vKSJsndCslesJL2umlovuvNloiRr5CZI3VlJAA6v21vd6
         iEI3YB85Tav9tJ4qyPTMvabzFWCzr3Bn2F8X7fhuBohCbvdxS5IzFxyj6TqVqvEqVzu8
         QSSmH/De+GzBPrVyrAzLkKj6hyayCP2iZHKnzZaJ5Wkv7MsUGED8MxuUpQXp+VB2fXsv
         zYa9Iez7ASoloW8QLEKlECgBMXuvhuhwrthJnzf9at9LtSK+ohKpy3w7XwR0O4Vijjgf
         sMlmhsyKQZQD4tjpIuyglgylouHRapwID+7B01vj8QVpxAUGzu5Ed9jnMGgwo8zT8I8H
         E72A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=0TojSogP7Dr45nCFAzhN6PfF5kurfE3MprtdNN8dOs8=;
        fh=+jGTaz2lYl/uJGuzvrFH9CmWbkqB3KiTJJrWxON/0wU=;
        b=SgrZ0S3byTIF8hGJUE+K/KIF1Omd2/Yg5cSYZATTAycEalw53hUDYW68VCRXe8RmBe
         GtwrMEXJ9Hz+T/11RkTWrf5QEFm6DuRlqNDofBsUMHJB6yHmUToOWP3NIM7tPTR8eQfq
         Wm2dEms8hLNJPYuaH4I3xxg0RlmruaaeGWjGgbvRjAqA048vhIBE1W/nrNQQn91MZZed
         sZQ0TsTXqXkU2urpsQQpm7CQSG/ZxgauJotEv/hxJJrr711lRHGlKWwOPveFUC1vg+FU
         R8NlB4pFWzafyQBRPnxEAv96eDF0UWA81oPbycVkMeTikUeEOhlS3CofuUKZ8CoOwrRT
         Onww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xYwGOHZc;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xYwGOHZc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737708131; x=1738312931; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=0TojSogP7Dr45nCFAzhN6PfF5kurfE3MprtdNN8dOs8=;
        b=YG7DIFVX55n0F7+7mPWRjDSdVamNWsLH7HgBicM2GiUTEmoEPLIRKUShne78s0Jx89
         Hdq/v+C4Loti6Q7EVL41xEHvmrwaRQNQEZWItNyx3OL9QZU5WQXDRUQRulF62hnp691N
         PN34EsUKmFpePvSRofR0yH2pL0FDRzHNxkWg4xkZ26Fe5oY9Wv5nh1t3vJCLQB1OGZjb
         FLt2y2X4z4TNl1luoEEvxfCbRKp6SUN0yEa4LB6xTgWqGEaElmVueLLUa6M6Gv/bb/lG
         RVo4EVNiGRR9SbidmAceD7ctrK9FlGQIqkBHD+IlZgwonfwlxa6ZJAkQE4Y3wHPpZ7bF
         baEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737708131; x=1738312931;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=0TojSogP7Dr45nCFAzhN6PfF5kurfE3MprtdNN8dOs8=;
        b=B97o5M7byCaqTqLFazW0Oh1D7sXpacMiLeW3bxOhUQRMvwb0bjJ8+HiDq+24nhJX1a
         /vSLOsbALrb4MeCrXOauLCeBDSd99SkfMZnvHxOgISE48Svx2jrWvBiH/KTWo3oCWiN6
         3+WE4/Su+kJMUQR3JgRmKlEXjmd1SpSidZckKf2ELHZPQEvqkTd2fTx7ewBS/hLlU0h6
         zdO4Gr2ek3MMMi2CGJbekcva8al1BpadKokOTOuRbwHPRD1AtRhxV3bXK9LE3ms3C4w7
         a8s6HEjF/o9KqC8rYfaHtimUf3cmfQFvXyL7ko11/bWY02oTVxc8vnVxdYvS3e7xB+XS
         Ps+A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZNb+goN+j/tIv/RjHYlEEBhqGYl2Bui+PeaqZQLseBTU67mlWLGcy6/7pUnt8mbPdbYnAKw==@lfdr.de
X-Gm-Message-State: AOJu0YwHEZY4nKrPQ/VwbEZnX4dPOeC0ki9mtFaotl5psnmftC2fsFmr
	H/FHYYwwsAlS39HMKI0Zrx+wvTTd5ay4NNWVrofIcgiTzJuCQRMG
X-Google-Smtp-Source: AGHT+IHKWky9ikV3QSBrzwM/eYyRXZKv7/euriHaTR8YKTeQJfEpUL48deGFH02afO1mEMW3H4K9Iw==
X-Received: by 2002:a05:6402:520d:b0:5d3:cfd0:8d46 with SMTP id 4fb4d7f45d1cf-5db7db2bf02mr30356115a12.30.1737708131030;
        Fri, 24 Jan 2025 00:42:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:8d51:0:b0:5d3:eaf5:6da7 with SMTP id 4fb4d7f45d1cf-5dc07173b12ls3771a12.0.-pod-prod-03-eu;
 Fri, 24 Jan 2025 00:42:08 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW62c3W15CtUyw7uETBAcg2uj1WZkP6i4mc60PCG3o4uLnU/rpXOKHW5H6BZECGpayqe/IKLUQ093A=@googlegroups.com
X-Received: by 2002:a05:6402:2792:b0:5da:105b:86c2 with SMTP id 4fb4d7f45d1cf-5db7db078b7mr23013226a12.20.1737708128169;
        Fri, 24 Jan 2025 00:42:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737708128; cv=none;
        d=google.com; s=arc-20240605;
        b=ghsDtkBHhBEQBljq5l+B7lgHWZdBps77rZkNV1dgbnDEbhIFliZBunvS/qrrschMy2
         9ew4tGFVe5KCGXDPcqv0QXvDlQnLgaNB0s4GeVW9EXKzIiBQqbLv725GqTcRp/s7Pn1Z
         KeMjI0ykuQssToN75Lg4BrUb70T2zEMDAWQmWYBcdoY8d8JBfm4AJzrwcG0MpYbIKR3Z
         MKzUziSf8tkblNPhphO4VDwjPj+54ADKTyhLBsUXoVvXk+/m3DTTOxsJF+1QLjSZ4742
         3wMKXBHUPwuwcOGzKCVIWecRQKvtkmryYm5gDcL1rFL1NvI/AE2y7WRsIRhczzMs5ole
         WE4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=P5pcIisQBoc/vj62B6JCNR0VgIqEyMNIvQJZH0InrtM=;
        fh=190knQfbucenu4LSl10TP+SWFmHo17/qiaIUsXGKPd8=;
        b=Aw6Sj2R24w5dVZ9wKu59czb/weSQZAjcHN5B5SDoTERssMhCLIAsAqGdCLlEGLElWF
         0gMlBoiB+a6gb9lNDrKhKvGN4cOQOA8lIafjC/+t7ITMYWvqsc2ZVGRPG0uOzhrVSot8
         VaDhZ9Xlm3NxbaN2Ld4/0xflyB/IchRviKcZUUODfujjY7Lxo6F01s07WQSvfnrUdOCd
         wQcMYyEvwXtlzNmBf0WeDuYUuk/IXt/yAJoEGka5e5G7JNEWOhbizTEvDlZ2CPy/cVYj
         wj6V+TxI3mUftP4fA4uyewwPOEMaVchN7vnb31UJo7MYM4k6dxUFSpoOv64Jea0bgdFx
         W78g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xYwGOHZc;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=xYwGOHZc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dc1868b6ebsi20553a12.3.2025.01.24.00.42.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jan 2025 00:42:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 95ED92116D;
	Fri, 24 Jan 2025 08:42:07 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 69DA6139CB;
	Fri, 24 Jan 2025 08:42:07 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id seV4GV9Sk2c7XAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 24 Jan 2025 08:42:07 +0000
Message-ID: <c63dd8c4-a66a-4a97-ac94-70b3159ba3a8@suse.cz>
Date: Fri, 24 Jan 2025 09:42:07 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: cl@gentwo.org, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Jonathan Corbet <corbet@lwn.net>,
 Andrew Morton <akpm@linux-foundation.org>, Yang Shi <shy828301@gmail.com>,
 Huang Shijie <shijie@os.amperecomputing.com>, kasan-dev@googlegroups.com,
 workflows@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, Christoph Lameter <cl@linux.com>
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
 <b788d591-4c5f-4c1d-be07-651db699fb7a@suse.cz>
 <CANpmjNM_2EB-sTBjPDADNh_cAEJS8euY_71pw0WNu2h_eisAYA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CANpmjNM_2EB-sTBjPDADNh_cAEJS8euY_71pw0WNu2h_eisAYA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_ALL(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[gentwo.org,google.com,lwn.net,linux-foundation.org,gmail.com,os.amperecomputing.com,googlegroups.com,vger.kernel.org,linux.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=xYwGOHZc;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=xYwGOHZc;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 1/24/25 09:37, Marco Elver wrote:
> On Fri, 24 Jan 2025 at 09:13, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> On 1/23/25 23:44, Christoph Lameter via B4 Relay wrote:
>> > From: Christoph Lameter <cl@linux.com>
>> >
>> > KFENCE manages its own pools and redirects regular memory allocations
>> > to those pools in a sporadic way. The usual memory allocator features
>> > like NUMA, memory policies and pfmemalloc are not supported.
>>
>> Can it also violate __GFP_THISNODE constraint? That could be a problem, I
>> recall a problem in the past where it could have been not honoured by the
>> page allocator, leading to corruption of slab lists.
> 
> KFENCE does not sample page allocator allocations. Is kmalloc()
> allowed to take __GFP_THISNODE?

Yeah and SLUB is honouring it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c63dd8c4-a66a-4a97-ac94-70b3159ba3a8%40suse.cz.
