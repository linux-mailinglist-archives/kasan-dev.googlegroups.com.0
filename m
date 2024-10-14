Return-Path: <kasan-dev+bncBDXYDPH3S4OBBENYWO4AMGQEPVZALKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C56899C41D
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 10:53:39 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2fb4c35f728sf3224251fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 01:53:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728896018; cv=pass;
        d=google.com; s=arc-20240605;
        b=BNojndIQM39gXmIqm7E5V3sTrnyeyvEP1VnWh/qchsiDMaVwnBC4IHRV5EQqpz0O6a
         Jwejsxe0AKF1TWbq+TMzbB2vVDJYaVwvCN+aKxvPMl/xxq4VcUZL558xuijRSqhwJJwE
         6bEO4E0cZC0XPrpz9cfZRBmqtmWZyHsCJZ0crvMDruDwFtx83xKrCIyBQ/QjEYzmjrvV
         QCRDDrMFUbs0H3c+d9DsWm95WEmVkgtcbRNmBJEak4dpE43JJ7gCiT1BiRw3oPpSR0Rk
         Rw+rf5zceQH8P6x+xgyaPUvTgxk/pRvMfxRBD4CMaU47mIcSP1D3cjbsD2l1I0MtKOMk
         NMgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=dR0XxIM9KDiiJnmi5295dhhx8l9HM7hpzPpU3vMsEjg=;
        fh=f5EmeV9KnDnrIwvkFHE8T/XoV+UOh9krgj2x+YZwpXI=;
        b=VVikw0AhiQCLptPd6lMxqYy+DIY04syU4HCAWBj5oUoRxdYzh3sIDF4wQg7r/TevKz
         bwTa75kjvU0dNWJDvxElm2Yf0R73HYXgTis82wE45+ncP3jvdAIm2WMgFoZZ+Nq6+BMT
         PY2T+QmzIk+rhrHcLevJBmzDwDeHZoFJQSCalv+OFgBV4EcQ4+NyCShKRg2r4/x1DUFF
         Z7VZF3XZqQhpsZN2B/lutbNZlXEXrh9Ol062xhbQdtepHDe8fQyVsZQFIjHAAsFZ4MHr
         TcohMomtU8OmR80bsGg56wZRYhLC0T6WKGQe2dYbLyqmn3fGuSqPr7VL1YmU0rXG5LK+
         iKNg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=txCMgrn6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H+2eXESj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728896018; x=1729500818; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=dR0XxIM9KDiiJnmi5295dhhx8l9HM7hpzPpU3vMsEjg=;
        b=jUgGjdGrS/svByGJ0zV1Ideua4Zcy45Nzafe2e8jgb1BrJhIri7QtXlMxKWwZlwsQo
         5u8HivtwRBgIDcYoPQ9X5PqbUKXFFSGh87NZNOPuS+QubBsqk4xJ0P6tx9a83AOlu9Vt
         iwr8GRJWAXErCvboH9XCgWIZk22Do0cDT9BwYjVxqr+IwUD9FjHLq8Kws4x+vHGubeDd
         /9GwP15mi3VJbQ1lMY4J+bgOxCVdY9Q3SyjtNKaxCbvZ3C3kGvtqAFs5PAiWCYfPT29Z
         7grJNGtaLbXpUkutf8yNHFBup5i0/zi44i+R3b6t+i2QbdHxGZl5YCgyf8OT90/iRwuc
         y9Hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728896018; x=1729500818;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dR0XxIM9KDiiJnmi5295dhhx8l9HM7hpzPpU3vMsEjg=;
        b=m7iCxZ5dsn0fexu6+03JZzsSAGV3VSFs67WasV8rtfcy+n4bCT4cn7rQ2FDzz9Dc3+
         X0FY5GGCdFj/iHFnY/0e5zzhv+P5VkbNS2ftQg7SsLKfTcmeYAjLqPJx8sKGP/n5HRCD
         1F5YEcwu7U+ZYjErkS/CiPf8jR7G3Lpy00m5Uok28PXgLhXC0OdSH7EU1ifVpT8jbsjo
         gIfEo3e6+Ut9n6Ms97VMWIRlxw5oyFM2BMNZj7mCyiTc220ZDGUTmk9q+H7Zm0JRcX+w
         t70vH5TRkARNZBoyuceujyNJ6AUuUUOsG+rV53/yLARYmSzuLOTxM7yXWQMaOtgYdClR
         +AVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVB/4mqORzVOrB2t06EQCN+j0rbSIGyYrYK4hXmU237AhpNoidt49WRnK89AatEILm7colEEA==@lfdr.de
X-Gm-Message-State: AOJu0Yw0J1iZdusfBCn2m63qfO21YTCzz5UDpaljsZT9zKYz6eEAsn07
	w9aSemI7rxhnISuLv62EMQ4ZWmqw4tacO08uoHGOSQl1++ayP2wd
X-Google-Smtp-Source: AGHT+IGx1BK0Q6TXydfz7T8QMwDQv7T6RnZAf9zXTXIVEZpNw18eydDGnBsL5fSbSCeIs+NHF6HlMQ==
X-Received: by 2002:a2e:b890:0:b0:2fb:3960:9667 with SMTP id 38308e7fff4ca-2fb3f196642mr34634261fa.14.1728896017568;
        Mon, 14 Oct 2024 01:53:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:1f01:0:b0:2fa:1c89:d436 with SMTP id 38308e7fff4ca-2fb20f0b528ls4890951fa.0.-pod-prod-05-eu;
 Mon, 14 Oct 2024 01:53:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW4SO/ay4TaTD6GRmk924kWrfIhtTRgzALrWwuIi9q2WQV4b5zLrSEMqNbnkHBrLj372q0RHpGHWVw=@googlegroups.com
X-Received: by 2002:a2e:be8c:0:b0:2fa:d7ea:a219 with SMTP id 38308e7fff4ca-2fb3f2edd5amr30447111fa.37.1728896014884;
        Mon, 14 Oct 2024 01:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728896014; cv=none;
        d=google.com; s=arc-20240605;
        b=HmHn3Odh9KIVHW3+Et/JnQeQBzDcIoBAWh+bI3KUpZmzySpkzXtkGQKs+3n9Hgyedv
         snkD3BTIGlJfQV4ADxToxrLBCawIUYCGq1QFfSfXyaKRh4cjfpNpqIAk0l1L48TseV2G
         hcpRyqZHyecVHj/ChtKSXRmZkVC3GAxYKC5K8Zv2MQifSQdlongQyzaBa3dzt5AeJcel
         4MXjXZps5FoFV4GZFe/QAWWMe/5ESX/cGAYJF9G6P2koOGdx8MVPeCnVnpBZiSISjVZ8
         QgMOtNoeIjloIPdHJIN7oKdIowkEibzhEZXIuqymVP3nMLIPg1TZ0ZHKglk9BuO9F5pn
         Hrlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=VkZ73gkatyjPy2/ge37jSry6pjGozQUYmtnYd9iTMRI=;
        fh=TECl6LEnngzTK3i/Bv0LsAC+15/hICXe4AtrUivP0lE=;
        b=IUcZ/1mFvCrXCLourQmyoKSONcoF/tGLdoaBMcTi8vncC9TdzCal4xBrqhy+4H6hO5
         Dqxm/qk453C4ZYjWGtJjQVS7ljFQGnv+3p570JaPuV2M/CP+gZu2nklJk1sNV0e5ghhW
         F8XUMJj121xkOY8j9OrrwW/n6j8RsbyIR4j2mFpmQZHxF0+b7v6QYlhsEJveeTJrgFt4
         ypyr1e5XAX0TWc1qAZ1euFYfkj59yll2nIluL/+gkE9Mg3ntzjLaOhwVJcPDPotaLGrQ
         HOOSHhjCCdzMRoCfzQMqOUixyTZWAw0WVT00PGrQuBPOBHeMnuLDkHOU7YrR3QdjI6nl
         1xTw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=txCMgrn6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=H+2eXESj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb4d7ecd5dsi406101fa.2.2024.10.14.01.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 01:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 01B2021BD1;
	Mon, 14 Oct 2024 08:53:33 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CAAD113A42;
	Mon, 14 Oct 2024 08:53:32 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id Ju0iMQzcDGc4ewAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 14 Oct 2024 08:53:32 +0000
Message-ID: <a34e6796-e550-465c-92dc-ee659716b918@suse.cz>
Date: Mon, 14 Oct 2024 10:53:32 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
To: Feng Tang <feng.tang@intel.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Shuah Khan <skhan@linuxfoundation.org>,
 David Gow <davidgow@google.com>, Danilo Krummrich <dakr@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 Eric Dumazet <edumazet@google.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
 <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
 <CANpmjNM5XjwwSc8WrDE9=FGmSScftYrbsvC+db+82GaMPiQqvQ@mail.gmail.com>
 <49ef066d-d001-411e-8db7-f064bdc2104c@suse.cz>
 <2382d6e1-7719-4bf9-8a4a-1e2c32ee7c9f@suse.cz>
 <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <ZwzNtGALCG9jUNUD@feng-clx.sh.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	TO_DN_EQ_ADDR_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TAGGED_RCPT(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[21];
	RCVD_TLS_ALL(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[google.com,linux-foundation.org,linux.com,kernel.org,lge.com,linux.dev,gmail.com,linuxfoundation.org,arm.com,kvack.org,googlegroups.com,vger.kernel.org];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=txCMgrn6;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=H+2eXESj;       dkim=neutral
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

On 10/14/24 09:52, Feng Tang wrote:
> On Fri, Oct 04, 2024 at 05:52:10PM +0800, Vlastimil Babka wrote:
> Thanks for the suggestion!
> 
> As there were error report about the NULL slab for big kmalloc object, how
> about the following code for 
> 
> __do_krealloc(const void *p, size_t new_size, gfp_t flags)
> {
> 	void *ret;
> 	size_t ks = 0;
> 	int orig_size = 0;
> 	struct kmem_cache *s = NULL;
> 
> 	/* Check for double-free. */
> 	if (likely(!ZERO_OR_NULL_PTR(p))) {
> 		if (!kasan_check_byte(p))
> 			return NULL;
> 
> 		ks = ksize(p);

I think this will result in __ksize() doing
  skip_orig_size_check(folio_slab(folio)->slab_cache, object);
and we don't want that?

Also the checks below repeat some of the checks of ksize().

So I think in __do_krealloc() we should do things manually to determine ks
and not call ksize(). Just not break any of the cases ksize() handles
(kfence, large kmalloc).

> 
> 		/* Some objects have no orig_size, like big kmalloc case */
> 		if (is_kfence_address(p)) {
> 			orig_size = kfence_ksize(p);
> 		} else if (virt_to_slab(p)) {
> 			s = virt_to_cache(p);
> 			orig_size = get_orig_size(s, (void *)p);
> 		}
> 	} else {
> 		goto alloc_new;
> 	}
> 
> 	/* If the object doesn't fit, allocate a bigger one */
> 	if (new_size > ks)
> 		goto alloc_new;
> 
> 	/* Zero out spare memory. */
> 	if (want_init_on_alloc(flags)) {
> 		kasan_disable_current();
> 		if (orig_size && orig_size < new_size)
> 			memset((void *)p + orig_size, 0, new_size - orig_size);
> 		else
> 			memset((void *)p + new_size, 0, ks - new_size);
> 		kasan_enable_current();
> 	}
> 
> 	/* Setup kmalloc redzone when needed */
> 	if (s && slub_debug_orig_size(s) && !is_kfence_address(p)) {
> 		set_orig_size(s, (void *)p, new_size);
> 		if (s->flags & SLAB_RED_ZONE && new_size < ks)
> 			memset_no_sanitize_memory((void *)p + new_size,
> 						SLUB_RED_ACTIVE, ks - new_size);
> 	}
> 
> 	p = kasan_krealloc((void *)p, new_size, flags);
> 	return (void *)p;
> 
> alloc_new:
> 	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
> 	if (ret && p) {
> 		/* Disable KASAN checks as the object's redzone is accessed. */
> 		kasan_disable_current();
> 		memcpy(ret, kasan_reset_tag(p), orig_size ?: ks);
> 		kasan_enable_current();
> 	}
> 
> 	return ret;
> }
> 
> I've run it with the reproducer of syzbot, so far the issue hasn't been
> reproduced on my local machine.
> 
> Thanks,
> Feng
> 
>> 
>> But either way means rewriting 2 commits. I think it's indeed better to drop
>> the series now from -next and submit a v3.
>> 
>> Vlastimil
>> 
>> >> Thanks,
>> >> -- Marco
>> > 
>> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a34e6796-e550-465c-92dc-ee659716b918%40suse.cz.
