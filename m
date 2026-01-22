Return-Path: <kasan-dev+bncBDXYDPH3S4OBBDWJY7FQMGQEF6SPYWA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id IJjmJJDkcWk+MgAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBDWJY7FQMGQEF6SPYWA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:49:20 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 18E6363697
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 09:49:20 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6583901e817sf281452a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 00:49:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769071759; cv=pass;
        d=google.com; s=arc-20240605;
        b=IerpgRnbVwgmjktIeoMEuTAPvKHIXCYFA0vzQzi/Ubp7mUV4U/25cEFo9C1C+BevUq
         9PA0XT/nw/FVTdDU/iWL0kuVEVjjnMGtNx7D4XZuDgsFzwYhVz4urbCHpWLl8WtNRbAJ
         vL3P4m0zaFsERM8BQhA1xaHpOf2a8bxIMgNTl3c2Xh2Q2UWbh8RSlRJmerYxi9LeiPnA
         Ewc3d6D+i06tzHhNV9TnMQjNoWq6kfYOza9aCsKUJ8pNGMzvzSnnkMsZBoz6ffIIeUag
         c+OQw8qHZ3p5ZdpZdjopbPHBD5+kJyOd8NzD1iNGAzqEf0CsdTGUAvotueLv1VpfvF93
         GveQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=cOfPGQN5R0qyIg94dyvjPHGEMFryI7xYyEsPDDGLpEw=;
        fh=n+IKTPmyGeRzx7tp8ekWFm+wB75cYOkERHrIC0iUnhI=;
        b=laK4N8pHvY6XGWzhZ4piXNpXmxP2ZqZnvRa86Qy7JKRSOygD/Ld3v4DWbNvNdGH4wo
         rn21XcFbo5aMBh5dQBh8XgtMgi6BU2bOfJHa5WvJZDwNZeHMqxHHibNoLZuoUuMdt1rR
         Z3OOStUMHSHUAElh6UpTnx3tzyqcwU6s6JdZSzwlLf5x8Pe0NEsl63qrmHv8NMKq3iw3
         JtcQ4Q1vGfGR0fYg/kkyfbTcmcWs2/ZOH5Ne1YsqN9lBUtDWDvti/GUQy/J7o03LFS5c
         FLF/476NYZxYevxotyJTg6L8QH4+iatbT+doszgwmIAD/rBdH98IxGlW4dbWaOPiOfFY
         6FdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Yvk96SCx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Yvk96SCx;
       dkim=neutral (no key) header.i=@suse.cz header.b=wB4wkh1L;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769071759; x=1769676559; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cOfPGQN5R0qyIg94dyvjPHGEMFryI7xYyEsPDDGLpEw=;
        b=mjtEzetAmzniqoWD3ILe2CsTzFW/xbPBKBG/0pr5ci91Qo1hWZc0REAQERlnAKGHyv
         qRtARsfxLC+AXtiDDZrIfyGHmXc8Hcwt7SymRPmkdmmniYCHLjubBeOiUJ1PHNk8ku3m
         PahYMEq7a2GGny9zcP2NnG7vCh9HhV7/Ghi1fVlxXNSCF4fW8MzH0sbRcGa2EY5FtZ8R
         KhMvCn4KimOQsB1ZRaDIiDsE+LVFM9EHBjR4DpEESLVRNruwaDIzE8ky8QQv7MG+RbQL
         g0nyqX7QNoTXXOrQiybon/+5s0STDY6fJEES1ooIAoso4oHd4diqOPRNHruzzHgI84Gz
         bU8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769071759; x=1769676559;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cOfPGQN5R0qyIg94dyvjPHGEMFryI7xYyEsPDDGLpEw=;
        b=c3XKxNky12b5Q+uCFOs8agMknWYhxuB80jj4jzz04N8rntgFmuP/9NKhDBNqij8itg
         lWFMF4Dg45khzbxaYGhj9266PxvW6BAL0LiR22moineeBV3BMPRspIQu5BitKdTz3uca
         rzi1C5fFLsm0Ln1P+ZE7pPxYYa6nGGBPROxqCOZuOfLzP4678Q6r+wheDiVQCuUOVd6H
         EccB02Wj4CDMC1o6/YPvVfgOT1+E5+DMyCfyjjGRmLGg2ONvKxwTM3Ip68CLj19eJJo9
         Vr8hyulghZNXJjmbWRT5w4knh49j4HiTYUBV93uvo57kx8EemH9hresZ52V7a2k57ZVf
         E36Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjyrGQNTYFGcOai61qe57NmvIoVJcLwJ7cz5uPPQryD5hoJJd7zMunhD0hS8t/MuhxmMSyrg==@lfdr.de
X-Gm-Message-State: AOJu0YyM71m3fzygiirvK6VTS+eN2mJeSGlmvbpvG03H8o/hmTgzbwyX
	G53+kGFZi/+KzjqGHWYBkRNX3MoHavRGi2rPHDLCrOP8exDwTDO90nq8
X-Received: by 2002:a05:6402:210a:b0:658:3a5f:2b16 with SMTP id 4fb4d7f45d1cf-6583a5f2daamr536722a12.0.1769071759422;
        Thu, 22 Jan 2026 00:49:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+ForZNHZsXZC89Qf5RatfRU/vpUbACqR980TiVxP8iqRg=="
Received: by 2002:aa7:d0c7:0:b0:64b:a683:5c87 with SMTP id 4fb4d7f45d1cf-65832d7f281ls507558a12.1.-pod-prod-04-eu;
 Thu, 22 Jan 2026 00:49:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUM8MmeDr8Nh09jq81R63WNGB3qMjdpX7s9C0Qqx59XITX5t3jCoSaST1BQgDriyhhS1HS8A85nGp4=@googlegroups.com
X-Received: by 2002:a17:907:6e94:b0:b87:6f58:a847 with SMTP id a640c23a62f3a-b8796b7a3c2mr1594342766b.45.1769071755838;
        Thu, 22 Jan 2026 00:49:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769071755; cv=none;
        d=google.com; s=arc-20240605;
        b=kQIdzBasQ8ObRiovNrnWGG3axjmnEE81olHXmGg3IvoCLE6f1qa4kDACf8lqlB6hmv
         xdZUqKJUCNdMF3sA/DZ80Wkr3hv/qB96UNy3iZsQM7lwiaIPynpFqPC3U+YUAXS+SXer
         H76eiQuLhUt9jgxnkuOlT3qheUTkWpyJqeoj/oTGKhQCDzUKLZAKq2PKBau6UVozTYxT
         boYW1Curgd2gj/bu/QTNOK3thqeonVdnLs+ctEOTgXTfdMMj2poGjwm9sf44uumGLxCf
         HTUwdYl9fs+1ONAuBe302VvnVz/5M1Bbc0acxpYeWQZqsTED/pIHddGCWSXO+zq0tC0q
         h9zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=sK1ACyocc5KtplqXf/k5n7xl2hUWgnhGLVkAdPAkMIg=;
        fh=KDJM2J+CluSNuZFMRpSGdSzTe0G9RbhFzt5xcVD9hkE=;
        b=FU8rOOckOlW4QXQ86l1W4AuMVmnlk0T4ucOFLQHTXYLeqtCw73uqlDxIhSMtTyaIzl
         OD2NKi63gyIeZp/7vBuRRQjh2RYIBnQB7Gzv0UkatHwX9TCA46lscDdfkbWeQUgbNewj
         n/pBaGYQ9f4+l3jk4YZcDRR8UkM6tqqw2ZD2EgUwUrtuOIIzyeaGIfNrWCeQCae/HmHX
         /IN0o9eFjqBcWf6ssv9wxs4NmSEM0hccmWK1IYStBNimPnT0IcZUVnFcvpckoXzmeTAD
         FlIkMyhPsi/8FTAjuhiV8wUkckRyfRrsKXZdl084RdCsRsgUbviJKw2+QA1Jav6N7Ow2
         ebfQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Yvk96SCx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Yvk96SCx;
       dkim=neutral (no key) header.i=@suse.cz header.b=wB4wkh1L;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6581224b74dsi85738a12.0.2026.01.22.00.49.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 00:49:15 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 4E4EF33697;
	Thu, 22 Jan 2026 08:49:15 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 306693EA63;
	Thu, 22 Jan 2026 08:49:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +qgXCovkcWmFAwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 22 Jan 2026 08:49:15 +0000
Message-ID: <1e3092b1-23df-441d-8849-84aa0632ee88@suse.cz>
Date: Thu, 22 Jan 2026 09:49:14 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 18/21] slab: update overview comments
Content-Language: en-US
To: Harry Yoo <harry.yoo@oracle.com>
Cc: Petr Tesarik <ptesarik@suse.com>, Christoph Lameter <cl@gentwo.org>,
 David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>,
 Andrew Morton <akpm@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
 <20260116-sheaves-for-all-v3-18-5595cb000772@suse.cz>
 <aXHGfLV6FdlNPc14@hyeyoo>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <aXHGfLV6FdlNPc14@hyeyoo>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -4.30
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Yvk96SCx;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Yvk96SCx;       dkim=neutral (no key)
 header.i=@suse.cz header.b=wB4wkh1L;       spf=pass (google.com: domain of
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBDWJY7FQMGQEF6SPYWA];
	DMARC_NA(0.00)[suse.cz];
	RCPT_COUNT_TWELVE(0.00)[17];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[suse.com,gentwo.org,google.com,linux.dev,linux-foundation.org,gmail.com,oracle.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 18E6363697
X-Rspamd-Action: no action

On 1/22/26 07:41, Harry Yoo wrote:
> On Fri, Jan 16, 2026 at 03:40:38PM +0100, Vlastimil Babka wrote:
>> The changes related to sheaves made the description of locking and other
>> details outdated. Update it to reflect current state.
>> 
>> Also add a new copyright line due to major changes.
>> 
>> Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>> @@ -112,47 +123,46 @@
>> + *   node->barn->lock (spinlock)
>>   *
>> - *   lockless fastpaths
>> + *   Lockless freeing
>> + *
>> + *   Objects may have to be freed to their slabs when they are from a remote
>> + *   node (where we want to avoid filling local sheaves with remote objects)
>> + *   or when there are too many full sheaves. On architectures supporting
>> + *   cmpxchg_double this is done by a lockless update of slab's freelist and
>> + *   counters, otherwise slab_lock is taken. This only needs to take the
>> + *   list_lock if it's a first free to a full slab, or when there are too many
>> + *   fully free slabs and some need to be discarded.
> 
> nit: "or when a slab becomes empty after the free"?
> because we don't check nr_partial before acquiring list_lock.
> 
> With that addressed,
> Reviewed-by: Harry Yoo <harry.yoo@oracle.com>

Good point, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/1e3092b1-23df-441d-8849-84aa0632ee88%40suse.cz.
