Return-Path: <kasan-dev+bncBDXYDPH3S4OBBA6Z7S3AMGQEURLT7II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 1CBFD972018
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 19:12:37 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-42cb22d396csf15162325e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2024 10:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725901956; cv=pass;
        d=google.com; s=arc-20240605;
        b=dd/SQG0fYhoN/GzkhSygaNrU+n4UUBrm4Rc+MP/c/3rVVh4Z4K9BKpFvInEn16imI1
         MsT6TbKmJZ98sMsBI9uutxViWzXXByzfF1bPJbc7pd35M0kXFN7nDLCy1Q7Pj0v8m/Jz
         tTrBxEywU8Z2EFsBFB/yzsN/igS+weCSakP6TAH5pqQMS2GsmZ5d7Sgumc8d4RkIt0+r
         uzkeBj5lFYw2lJraeAFryqhtkVs7Q6Ywu6ZkibadLn7jOZxX7e4zxcHeaM4k2TAB9LCS
         +yUDkto5fkRRVBO6yuFMYvqOcPl58xhEpFfeshMetD4cWqIkO7Twzr6G/JIxff876/XA
         S++g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=Y3RDE/SJ8ab9wALaoWE6Z3CEeZzVt1v1Wji3OtZ4TBw=;
        fh=kiqMjJgZvbzWpBiuOEzZKnxM3fW2h90QuTN1awQnmk0=;
        b=SVpq85SxhjCi7HVSkU1+rYIUbujjvjFLcNdo/JSVZgKEWoMRTEPLFMBhgH7o7yVjEF
         1WO/C/Hjo/fBd8tXkb3SeSP4WmKQkGXt4ruWR2YkI1RNfDEzFC6kEZMqZAYSW/616APG
         xaPobhkWJwvlbeQGGbM6lgc9lru1bwU1UngsPFWK9dLljaaRfyc07Tf4gd9xKJ/02R8B
         eVEFWxcto5uz4MHD6w0CCnZtWygQgB08MdWVHkEi/EwfCSOfxM4kmRBun15YWxZwETgj
         J4YQlFHyry570p1cILLtyagx/LwSHKpTQziWEkZ5IcRdFuE6dRFdimoHdtMsRhm+lzC8
         WgLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Hs+SOynR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pS0riaUn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725901956; x=1726506756; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y3RDE/SJ8ab9wALaoWE6Z3CEeZzVt1v1Wji3OtZ4TBw=;
        b=nuPHTB3epxW9zx8ZCipiAXyTCKpESqB0Q0VeKu9fY5ZGmPx9qrjed+jjQOla2Ayzi9
         WOUyMzqMu838qINxlBRKdM/+Q5FgiQYz8EuyPFCrw50DsFfFwzPBFli5yDXTkkmUbmKM
         BtqwVMz9azT5LE8YZ+uYAY3RroirvO9dzzleqANNXm8yshCxX8bvBBeLSYL2a592CdY6
         8oS1+iQcqlrjgQIof0GbGTIPSdlxbEm69T7WVJ7Lh8lUTns4BJyJioLvz8KTvQUrieCo
         z9j1tiIWVtTrfWMy7VTEfao5UVNv9zMc7BUuau1jOe1YHYJqaFqPBLIOIaUFzcIbj4Gc
         zT7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725901956; x=1726506756;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y3RDE/SJ8ab9wALaoWE6Z3CEeZzVt1v1Wji3OtZ4TBw=;
        b=nCYpEqrioZP64MlUNrR3Tzkcn5tDAFsh0gnOzEHLV8Vg5qC9AlaOrB8r0+ZKzvpf9D
         wX8cB5QDLi//Y2dVED55X9T4IoklcBXs1vdsw/UkFDbygS8Oo4Ddpuf8KB/Tw3zv7Ymb
         gkaTBxVeS55YF+3dB66lDCPMkUqDup8vMYSZ8BzKNL12tqwkNeNHMwiYwefza/RCEYZX
         +Du4/d+U0yzUePII0cM0gyp1VlXH/BKF/Pey4V+h4VIYQQ77HKoWbNW9u8feXMVN/LM/
         1UfGgt66d6F5kZkxiPDxJIqJ62U3GMH7/lYZc9560leI7yNGboZLIcfGwJHt/gxcPWTj
         LIGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUS+/Q7AKD8a/YRhqn0RvI9rn2Sn6fgkQ7fDgASbm7Z/61Yw8fmhLr9mjYJNLWKk7JUQDUkDg==@lfdr.de
X-Gm-Message-State: AOJu0YzNh82ly2Na2TPq5TCI47NE3RcY1nVkf44aojn0lfEohIydvEFV
	+5ZcB1EzhPyKJ/Izb2mj3KoWRlk/ywl7QZf3SANfW+N+EHG641dN
X-Google-Smtp-Source: AGHT+IFG1D1NVReONU03xggvf05hv5Fwrs0B9nP2ZasjxgL2apguSoDHZJtTuR5gSr/fj4vFFraXqA==
X-Received: by 2002:a05:600c:5102:b0:42c:bbd5:af60 with SMTP id 5b1f17b1804b1-42cbbd5b298mr13684465e9.24.1725901955752;
        Mon, 09 Sep 2024 10:12:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:510a:b0:42c:af5b:fad1 with SMTP id
 5b1f17b1804b1-42caf5bfcd2ls7093795e9.1.-pod-prod-09-eu; Mon, 09 Sep 2024
 10:12:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyFws2ooXe9TfgYrkDACdQbOzQmn3Q7R1P2hMI02WEj9kmAGPt10sORHmaIAiWMUw/pBeP1q8adr4=@googlegroups.com
X-Received: by 2002:a05:600c:1d8a:b0:42c:b0f9:9b28 with SMTP id 5b1f17b1804b1-42cb0f99c0amr51277155e9.28.1725901953876;
        Mon, 09 Sep 2024 10:12:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725901953; cv=none;
        d=google.com; s=arc-20240605;
        b=SLxU1do9tcjEasM/bvyfSXtZz+4nC2zTPC3lpMhaTwj65D8L2Ax0oefdFn9BLqcpIF
         baGzOXoWyKyY85lUABuoWgLJZb3RKxJWDbXA6MSQjMeQEXjQAsIIgeNyxt298/kEycuG
         Qmxx3VgjhKWctPSTMr7+6WRPimsOG9foPHII7oqljU4f2MrgMeYyjTryyMhCfrIY07wu
         7iiP4nOmLdMNAFEiQN2Hf1PqSrdQrog0CtD/4S/yRZkQwSQsNSlZdrB6BA+NEAkgRkPp
         q8cjaHPDxpU9vfxqD6z8SgV1178Aeg7dvXAhBxJRqHoG8mpfI6ul4XabfFEKIdkPKSKC
         EMvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=GujdpzXwQLob4MAahamAEEmRJyiFm/Q7cuWc1AY/HRo=;
        fh=0xRBb/eFYt1OwNgyWpv0boRELUlsWEBHSNu42J9xXtM=;
        b=UekhPVYTwfjYRrtQRGNtvFsWpZHmFagxjqcDD6xj2y4uffc1OAVI4vcq3kciesF7xs
         LmJBMO1P6+ZRLJJZ2KDi+OOFqgqZk904ua3fDESKsX1TlGgPQTvac3mLs7VJ0vsAd95q
         Gp/5BUBv8lLbjmex645fhT/a9ldp+5AiVYcOhDHcm6yCm7NKY+jjVPsjcABSPzUffKOg
         m6JMewuNNYS/PJL5KZGLbGJHREP/dwWeGFT0C5tCUCA2DyQwZRUaAMM9NTLUpnL3PAnn
         Nt2bSRKGeyjcJUas83hGAvGd2gGvjaIh2vMmjlAyTbg0HUoshN+b8ptf0GBTAZqS8D/+
         ee4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Hs+SOynR;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pS0riaUn;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42ca583662asi5049555e9.0.2024.09.09.10.12.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Sep 2024 10:12:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 123E01F7CB;
	Mon,  9 Sep 2024 17:12:32 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E450013A3A;
	Mon,  9 Sep 2024 17:12:31 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id H8w2N38s32YfRAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 09 Sep 2024 17:12:31 +0000
Message-ID: <edd4e139-363b-4a8a-a4bb-b5625acac33f@suse.cz>
Date: Mon, 9 Sep 2024 19:12:31 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Shuah Khan <skhan@linuxfoundation.org>, David Gow <davidgow@google.com>,
 Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20240909012958.913438-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[99.99%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[16];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Hs+SOynR;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=pS0riaUn;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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

On 9/9/24 03:29, Feng Tang wrote:
> Danilo Krummrich's patch [1] raised one problem about krealloc() that
> its caller doesn't know what's the actual request size, say the object
> is 64 bytes kmalloc one, but the original caller may only requested 48
> bytes. And when krealloc() shrinks or grows in the same object, or
> allocate a new bigger object, it lacks this 'original size' information
> to do accurate data preserving or zeroing (when __GFP_ZERO is set).
> 
> And when some slub debug option is enabled, kmalloc caches do have this
> 'orig_size' feature. As suggested by Vlastimil, utilize it to do more
> accurate data handling, as well as enforce the kmalloc-redzone sanity check.
> 
> To make the 'orig_size' accurate, we adjust some kasan/slub meta data
> handling. Also add a slub kunit test case for krealloc().
> 
> This patchset has dependency over patches in both -mm tree and -slab
> trees, so it is written based on linux-next tree '20240905' version.

Thanks, given the timing with merge window opening soon, I would take this
into the slab tree after the merge window, when the current -next becomes
6.12-rc1.

> 
> [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
> 
> Thanks,
> Feng
> 
> Feng Tang (5):
>   mm/kasan: Don't store metadata inside kmalloc object when
>     slub_debug_orig_size is on
>   mm/slub: Consider kfence case for get_orig_size()
>   mm/slub: Improve redzone check and zeroing for krealloc()
>   kunit: kfence: Make KFENCE_TEST_REQUIRES macro available for all kunit
>     case
>   mm/slub, kunit: Add testcase for krealloc redzone and zeroing
> 
>  include/kunit/test.h    |   6 ++
>  lib/slub_kunit.c        |  46 +++++++++++++++
>  mm/kasan/generic.c      |   5 +-
>  mm/kfence/kfence_test.c |   9 +--
>  mm/slab.h               |   6 ++
>  mm/slab_common.c        |  84 ---------------------------
>  mm/slub.c               | 125 ++++++++++++++++++++++++++++++++++------
>  7 files changed, 171 insertions(+), 110 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/edd4e139-363b-4a8a-a4bb-b5625acac33f%40suse.cz.
