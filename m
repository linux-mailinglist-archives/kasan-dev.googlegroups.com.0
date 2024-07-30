Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAVSUO2QMGQEFNBJQ4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7519994119F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 14:13:55 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-4280b119a74sf27342315e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 05:13:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722341635; cv=pass;
        d=google.com; s=arc-20160816;
        b=Za+sEabrUhS5k8vIgApX6kxbs1QfRp9lcavX4PjUSbstE6cYujC5/qPhfwXFlnY2O5
         4h9kfn8IiGuXHslKNaLzCOGPRFkKVAl5s/4gqh4TykP412FRQX1jxZiPxHu92f9WMFpT
         dkl4C1Kq19Xa6RyHEOIfwtPAtDm/oJYl3y30qSkOGtfapL8w5Awu97ZjmiWYiVYKBBLT
         MzyGrtxqbtJX3PL9o8/BeaPG9ZwNxswXfZFxHylJF6zkDOr4DfKbUw2cE8EE5hadEkEE
         F4eATy2lB3y9aPi0jlJ+BLImc/J5yI26mnDwB6yHT+Lc2EiDd9HydjVnYHVSznmgL1Qy
         VjWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=z1ZojUphmJlSftsJDRPAV+EWoEx9S1xnxoDF1xGcCdc=;
        fh=92pawvmtUrLDxMc8xwKh+IwPhbQ4WSvo9d9DtQi7Z/k=;
        b=ma5zIYwGUKS9n4ZEN8Q7NJdHGvv4pcwT9Ze2lf7kU3e2sef/NXO/vQl2+TUi1oq1za
         xuGPcH/XZIoSnP6S3zXrqa3jyE+0ovl0x0uoz36LYE1xT9wNA/kJ6mFmBkewiktj6W5R
         7xe36IjjJM08SWIKVDdJ/hG+XNnGKEx3uAXnakVsxIuaxxJEozc2cDiZ0CNNHSgItUBm
         JJV4IStewp5RhxdF8tsOQn5wz78hY+NdQQChOcVQRFc3mVmZGsw42m7QMT3XNdEkkZvQ
         5qXhnh2tJ+I8dZ67q8ik7kEpN90VuouoFl87W1BM0DbkZTTa8e2rcX0Yrdvpv9fUWydl
         1zXw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;
       dkim=neutral (no key) header.i=@suse.cz header.b=pAiSiIfD;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722341635; x=1722946435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-language:from:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=z1ZojUphmJlSftsJDRPAV+EWoEx9S1xnxoDF1xGcCdc=;
        b=bvxDH35jcAOF6LngHksOJXNsJKXlPsfgD2sWHVmrSePUd8nXtxGjRvffkcYfm5jwAN
         7TiRgCPngw++AmE24Q7QvMZsQ7iehpzeklX1H9bmf4D1VO5B9UTttjKQT2DTZBLLP0/w
         WQ9qhuTyjIvkiNld8oBSD+0Zo/9hTT/zGtzJ34FNAx1mNcJjtCTLbltNEVn20kyVZzbL
         9hr2iUyJgLg2OiyeHeNLMRs1rFfrgrcpQdgmrUAJc0i+CJXfnLtEQ0CcrKPWqzRzAvOx
         MeFuXzYOfDOR+HuA5kU3grOOsHHsIocuRzuwhZGFgNxMnOweGZvuViHPRupoI4IooJNT
         ChoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722341635; x=1722946435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z1ZojUphmJlSftsJDRPAV+EWoEx9S1xnxoDF1xGcCdc=;
        b=aUdRUQVZW1tQirZ5AySGvaLuXp46apFcDBBJ1bAYJFv5NwWIknAkwC3/SxZWt5Edjc
         c30/4Dzn7pqKi7VUREIO1QHZrTX9OaqRC7BD/+Nzff9vljgPnTLs5ZIwjEb491PjqVQY
         v4Ltoill5VkWrciou6MHzjQWooSyYPBX6Ew/CnwcYjuD9n8Pb+7E2DgbLOoA+CuAIV2r
         flopg8iYrwbvjZBZSDaLNdV93okGxFT6DySCMkvTwT2WBkQaGZ2b0cW5iOR1X2Q3ekfd
         Rq/jKnBKvdeZFW79vAHKEZf+J71rvPGdOac0vLn65Bpgn0+FV9DBBkL2vsVG9kzYk6Ad
         TA5Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXgS2XEJQ6RseqSpo9t8tSmua2YjXk96O1FzPpcacecx3WT5OAvsg2hHFjuEMdWAdUagKn04bONABnv4cvAhZ5jsFUOSpH5JQ==
X-Gm-Message-State: AOJu0YwLY/WwkG29NlI1l+cPI4GWTQDOilZBp3ohGkRgG8YPPoyZXcx2
	UchunxoviuILtnwoEw+nK+t/ZPFABjmxIBvJU7picx4FqYKPM064
X-Google-Smtp-Source: AGHT+IFe6e953HujSj8Yjt/lO8a6aNu+5foJ9Q1g+SiUtV3b9ENylohxg9UyjxZGTql/oOC15XcIkw==
X-Received: by 2002:a5d:6204:0:b0:367:99d8:70 with SMTP id ffacd0b85a97d-36b5d0b8371mr7072945f8f.61.1722341634860;
        Tue, 30 Jul 2024 05:13:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f108:0:b0:368:31b2:9ea2 with SMTP id ffacd0b85a97d-36b31ac76f5ls1843249f8f.1.-pod-prod-06-eu;
 Tue, 30 Jul 2024 05:13:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWpMMO8n2kaaC6v4VqT8+/G1GdeqD9LZQ/NHlKTpMdu1GHOs59C5vr9uRZ2R+sCuEmvPEoUUh8McRDwtCFFJYYd8TF0EI87+YzKRw==
X-Received: by 2002:a5d:6692:0:b0:367:8383:62e2 with SMTP id ffacd0b85a97d-36b5cefef5cmr6191141f8f.29.1722341632851;
        Tue, 30 Jul 2024 05:13:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722341632; cv=none;
        d=google.com; s=arc-20160816;
        b=PwSaA6QhTM4FpzAt/RCt1s8Ra3KR0e5oy4V3r17opDX5yONjSc+Zs9CKZWh+gnKkCy
         nAJvq+1378ubZmBWvV7up5LkF9vKyW3gnCvrKyr29/u142daAA+szixo993JESJgn4Y6
         lYNpotX49OvQqSnAdSeHP0+9R/sLaGEKY89e9zbS0osTqhpYtOpro/tZix2PQ91wb+9x
         96sapkLLBUUMlxUFEiMttt8H7CHuApdX5kWy2iezGAgunZ4ZqHQOx2kk62CSBIgZpF9a
         muyewgv75b5cn06yc97cJKRQVdXrQk2giW1gYgRet+P59MuH8323Xf0CXUXV/yobxEbC
         h3iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=gewwiAOFBIXgHIYvN7XPN/gKtcFdzSUlsLbeW58038k=;
        fh=rbcTT3JSVrPSc++gBSPkZj4/f4crDCAcafdoFrC4BI4=;
        b=l/cLOHJX80K8F9IwW1C06jXzlmK6UDq1pfGms6IblfYUhtvdXdP4wwCS+YcJnWdZX6
         goOzGtaiYtseByeqvLVlp8jTUanGv/eiY8gEZp3EOJiaYcaHiLYb08ne7ZO1kuTa8y28
         FGF6i+YIlq0oEe2QewDa56l3Tx3kbd2vdk/UpUihGfNiE3RAkdmBP+MhV+nAkVmlMjOM
         kRxxSmsD++AkEtYkRN0fSCJLqR3foFokY4Ah67uqLN0FiC+m35cH1b/U6l3MYNjaDTKC
         w/LDnd427pQbb1YzdyfcXfT9r+td9X/TRk3UKHMg6yd88yaHoLsOnbj2ItdRBbjmfIHw
         clkA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;
       dkim=neutral (no key) header.i=@suse.cz header.b=pAiSiIfD;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b36855dfdsi235832f8f.7.2024.07.30.05.13.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 05:13:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1AB1021B58;
	Tue, 30 Jul 2024 12:13:52 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E62A213297;
	Tue, 30 Jul 2024 12:13:51 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id dfH1N//YqGZMRAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 30 Jul 2024 12:13:51 +0000
Message-ID: <44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7@suse.cz>
Date: Tue, 30 Jul 2024 14:15:34 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 1/2] mm: vmalloc: implement vrealloc()
To: Danilo Krummrich <dakr@kernel.org>
Cc: cl@linux.com, penberg@kernel.org, rientjes@google.com,
 iamjoonsoo.kim@lge.com, akpm@linux-foundation.org, roman.gushchin@linux.dev,
 42.hyeyoo@gmail.com, urezki@gmail.com, hch@infradead.org, kees@kernel.org,
 ojeda@kernel.org, wedsonaf@gmail.com, mhocko@kernel.org, mpe@ellerman.id.au,
 chandan.babu@oracle.com, christian.koenig@amd.com, maz@kernel.org,
 oliver.upton@linux.dev, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 rust-for-linux@vger.kernel.org, Feng Tang <feng.tang@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240722163111.4766-1-dakr@kernel.org>
 <20240722163111.4766-2-dakr@kernel.org>
 <07491799-9753-4fc9-b642-6d7d7d9575aa@suse.cz> <ZqQBjjtPXeErPsva@cassiopeiae>
 <ZqfomPVr7PadY8Et@cassiopeiae> <ZqhDXkFNaN_Cx11e@cassiopeiae>
From: Vlastimil Babka <vbabka@suse.cz>
Content-Language: en-US
In-Reply-To: <ZqhDXkFNaN_Cx11e@cassiopeiae>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 1AB1021B58
X-Spam-Score: -2.80
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_TWELVE(0.00)[24];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,infradead.org,ellerman.id.au,oracle.com,amd.com,vger.kernel.org,kvack.org,intel.com,googlegroups.com];
	RCVD_TLS_ALL(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,suse.cz:dkim,imap1.dmz-prg2.suse.org:rdns,imap1.dmz-prg2.suse.org:helo]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;       dkim=neutral
 (no key) header.i=@suse.cz header.b=pAiSiIfD;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=nQELhS7V;       dkim=neutral
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

On 7/30/24 3:35 AM, Danilo Krummrich wrote:
> On Mon, Jul 29, 2024 at 09:08:16PM +0200, Danilo Krummrich wrote:
>> On Fri, Jul 26, 2024 at 10:05:47PM +0200, Danilo Krummrich wrote:
>>> On Fri, Jul 26, 2024 at 04:37:43PM +0200, Vlastimil Babka wrote:
>>>> On 7/22/24 6:29 PM, Danilo Krummrich wrote:
>>>>> Implement vrealloc() analogous to krealloc().
>>>>>
>>>>> Currently, krealloc() requires the caller to pass the size of the
>>>>> previous memory allocation, which, instead, should be self-contained.
>>>>>
>>>>> We attempt to fix this in a subsequent patch which, in order to do so,
>>>>> requires vrealloc().
>>>>>
>>>>> Besides that, we need realloc() functions for kernel allocators in Rust
>>>>> too. With `Vec` or `KVec` respectively, potentially growing (and
>>>>> shrinking) data structures are rather common.
>>>>>
>>>>> Signed-off-by: Danilo Krummrich <dakr@kernel.org>
>>>>
>>>> Acked-by: Vlastimil Babka <vbabka@suse.cz>
>>>>
>>>>> --- a/mm/vmalloc.c
>>>>> +++ b/mm/vmalloc.c
>>>>> @@ -4037,6 +4037,65 @@ void *vzalloc_node_noprof(unsigned long size, int node)
>>>>>  }
>>>>>  EXPORT_SYMBOL(vzalloc_node_noprof);
>>>>>  
>>>>> +/**
>>>>> + * vrealloc - reallocate virtually contiguous memory; contents remain unchanged
>>>>> + * @p: object to reallocate memory for
>>>>> + * @size: the size to reallocate
>>>>> + * @flags: the flags for the page level allocator
>>>>> + *
>>>>> + * The contents of the object pointed to are preserved up to the lesser of the
>>>>> + * new and old size (__GFP_ZERO flag is effectively ignored).
>>>>
>>>> Well, technically not correct as we don't shrink. Get 8 pages, kvrealloc to
>>>> 4 pages, kvrealloc back to 8 and the last 4 are not zeroed. But it's not
>>>> new, kvrealloc() did the same before patch 2/2.
>>>
>>> Taking it (too) literal, it's not wrong. The contents of the object pointed to
>>> are indeed preserved up to the lesser of the new and old size. It's just that
>>> the rest may be "preserved" as well.
>>>
>>> I work on implementing shrink and grow for vrealloc(). In the meantime I think
>>> we could probably just memset() spare memory to zero.
>>
>> Probably, this was a bad idea. Even with shrinking implemented we'd need to
>> memset() potential spare memory of the last page to zero, when new_size <
>> old_size.
>>
>> Analogously, the same would be true for krealloc() buckets. That's probably not
>> worth it.

I think it could remove unexpected bad surprises with the API so why not
do it.

>> I think we should indeed just document that __GFP_ZERO doesn't work for
>> re-allocating memory and start to warn about it. As already mentioned, I think
>> we should at least gurantee that *realloc(NULL, size, flags | __GFP_ZERO) is
>> valid, i.e. WARN_ON(p && flags & __GFP_ZERO).
> 
> Maybe I spoke a bit to soon with this last paragraph. I think continuously
> gowing something with __GFP_ZERO is a legitimate use case. I just did a quick
> grep for users of krealloc() with __GFP_ZERO and found 18 matches.
> 
> So, I think, at least for now, we should instead document that __GFP_ZERO is
> only fully honored when the buffer is grown continuously (without intermediate
> shrinking) and __GFP_ZERO is supplied in every iteration.
> 
> In case I miss something here, and not even this case is safe, it looks like
> we have 18 broken users of krealloc().

+CC Feng Tang

Let's say we kmalloc(56, __GFP_ZERO), we get an object from kmalloc-64
cache. Since commit 946fa0dbf2d89 ("mm/slub: extend redzone check to
extra allocated kmalloc space than requested") and preceding commits, if
slub_debug is enabled (red zoning or user tracking), only the 56 bytes
will be zeroed. The rest will be either unknown garbage, or redzone.

Then we might e.g. krealloc(120) and get a kmalloc-128 object and 64
bytes (result of ksize()) will be copied, including the garbage/redzone.
I think it's fixable because when we do this in slub_debug, we also
store the original size in the metadata, so we could read it back and
adjust how many bytes are copied.

Then we could guarantee that if __GFP_ZERO is used consistently on
initial kmalloc() and on krealloc() and the user doesn't corrupt the
extra space themselves (which is a bug anyway that the redzoning is
supposed to catch) all will be fine.

There might be also KASAN side to this, I see poison_kmalloc_redzone()
is also redzoning the area between requested size and cache's object_size?

>>
>>>
>>> nommu would still uses krealloc() though...
>>>
>>>>
>>>> But it's also fundamentally not true for krealloc(), or kvrealloc()
>>>> switching from a kmalloc to valloc. ksize() returns the size of the kmalloc
>>>> bucket, we don't know what was the exact prior allocation size.
>>>
>>> Probably a stupid question, but can't we just zero the full bucket initially and
>>> make sure to memset() spare memory in the bucket to zero when krealloc() is
>>> called with new_size < ksize()?
>>>
>>>> Worse, we
>>>> started poisoning the padding in debug configurations, so even a
>>>> kmalloc(__GFP_ZERO) followed by krealloc(__GFP_ZERO) can give you unexpected
>>>> poison now...
>>>
>>> As in writing magics directly to the spare memory in the bucket? Which would
>>> then also be copied over to a new buffer in __do_krealloc()?
>>>
>>>>
>>>> I guess we should just document __GFP_ZERO is not honored at all for
>>>> realloc, and maybe start even warning :/ Hopefully nobody relies on that.
>>>
>>> I think it'd be great to make __GFP_ZERO work in all cases. However, if that's
>>> really not possible, I'd prefer if we could at least gurantee that
>>> *realloc(NULL, size, flags | __GFP_ZERO) is a valid call, i.e.
>>> WARN_ON(p && flags & __GFP_ZERO).
>>>
>>>>
>>>>> + *
>>>>> + * If @p is %NULL, vrealloc() behaves exactly like vmalloc(). If @size is 0 and
>>>>> + * @p is not a %NULL pointer, the object pointed to is freed.
>>>>> + *
>>>>> + * Return: pointer to the allocated memory; %NULL if @size is zero or in case of
>>>>> + *         failure
>>>>> + */
>>>>> +void *vrealloc_noprof(const void *p, size_t size, gfp_t flags)
>>>>> +{
>>>>> +	size_t old_size = 0;
>>>>> +	void *n;
>>>>> +
>>>>> +	if (!size) {
>>>>> +		vfree(p);
>>>>> +		return NULL;
>>>>> +	}
>>>>> +
>>>>> +	if (p) {
>>>>> +		struct vm_struct *vm;
>>>>> +
>>>>> +		vm = find_vm_area(p);
>>>>> +		if (unlikely(!vm)) {
>>>>> +			WARN(1, "Trying to vrealloc() nonexistent vm area (%p)\n", p);
>>>>> +			return NULL;
>>>>> +		}
>>>>> +
>>>>> +		old_size = get_vm_area_size(vm);
>>>>> +	}
>>>>> +
>>>>> +	if (size <= old_size) {
>>>>> +		/*
>>>>> +		 * TODO: Shrink the vm_area, i.e. unmap and free unused pages.
>>>>> +		 * What would be a good heuristic for when to shrink the
>>>>> +		 * vm_area?
>>>>> +		 */
>>>>> +		return (void *)p;
>>>>> +	}
>>>>> +
>>>>> +	/* TODO: Grow the vm_area, i.e. allocate and map additional pages. */
>>>>> +	n = __vmalloc_noprof(size, flags);
>>>>> +	if (!n)
>>>>> +		return NULL;
>>>>> +
>>>>> +	if (p) {
>>>>> +		memcpy(n, p, old_size);
>>>>> +		vfree(p);
>>>>> +	}
>>>>> +
>>>>> +	return n;
>>>>> +}
>>>>> +
>>>>>  #if defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA32)
>>>>>  #define GFP_VMALLOC32 (GFP_DMA32 | GFP_KERNEL)
>>>>>  #elif defined(CONFIG_64BIT) && defined(CONFIG_ZONE_DMA)
>>>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44fa564b-9c8f-4ac2-bce3-f6d2c99b73b7%40suse.cz.
