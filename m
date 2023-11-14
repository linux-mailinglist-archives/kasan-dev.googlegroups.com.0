Return-Path: <kasan-dev+bncBDXYDPH3S4OBBC5SZ6VAMGQEZWZ7HPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 644717EB7D1
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:31:09 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2c737d1ba09sf47666731fa.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:31:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699993869; cv=pass;
        d=google.com; s=arc-20160816;
        b=aqr1rVDiiQ2pnvoaoXUvp3GFoveexfpLeKjSe/ysW4r+Kro2bcmUjV+gXOA6pLdO1J
         04aVOEHtf3p4sn7jA85AYX9tecmchC/Rk8KEmnLZPLN97OD+2RvA6PQ9T6v/BuYehZGc
         IuiTuUWPskd1jte5pe7yDp0XM3S8sL46qjNgRbVa54/8HfzKGOk0+7Ne0fCkx9HBPW4S
         u4JjhzDnvkI1W7gPRRYSP0U4zur3WyvvW38kloaTPAbaNIQ5a9R4VRn4XHHYHooBMI0o
         wAP9+c+j3afr+P97ksZXnw9DW8KkvpEKeQgpAAbvk93Lw3mIGqBkfSO8B39D9dQGcnVh
         XIBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=HDb/4IdkjSywZBjmTXcWRXXOx3UscM8sqcQU4u0X1IM=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=HmjC1gnkhP4MTXraSbxDWDEl+sNXHx8aTEy45tn9wWDOZg74oHgnzHYqKJhV26X0/n
         ADf2O+mGdcJy8UZShV1F9HuTjCSLhSUTcOSj0wISMCydJLKD2N2M46BoB0aQU8Om7WQy
         rCwwYOhNgNUCdebq6TWhST0/cBBej94Ce9Fb+az/2l490QD+buPsFpum4cUAt8mEpu2T
         pT8zPf+reeIIQbPGPncbo+nO3wCVsyRXz2h0WRsyAMmMooKmhwL8OakWjizB1OM+eXth
         ZcnrBKI8L+CnlBzYqL4eXtmByVJzFbrhZyC96ZFfSrr5m7lPtYZ/WgmHHnCLcMcy38mg
         gThQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bz0Tanb9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699993869; x=1700598669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HDb/4IdkjSywZBjmTXcWRXXOx3UscM8sqcQU4u0X1IM=;
        b=NAtvcgBY5DoyLJ7WwVAeq1nXdviHlsUZVntYRjcNwKmCTdjMURT49o/m4vf/phOCME
         JqI5gh9tG4jOEAMm6b3UlS8aptHJfB1rsL2jbTketGxX+ul0llrk551DnlmbE8eWbaFV
         HATWzZtUsqb5W00u9V7TrHjJChoWMg1qZ3/lmK0fwEQjDm/tcYIXF284hQOFZhdDZU9b
         KaGHV+ulsI8S6dnfQfjkMnXDNkIkNqBpw9gSiZZYml6AXl1iBdygol/9an/9LrdzE18v
         4a2akdfKHTYr1JKe+0Z7nac+InFTVfTUgUa9hE0Qi5Rbb5F6PI+fTS3ZBsiIx87JDe9T
         avag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699993869; x=1700598669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HDb/4IdkjSywZBjmTXcWRXXOx3UscM8sqcQU4u0X1IM=;
        b=dA2H7eR8Ouu8GLQMYcaV07TAgWtdKOYtNM5XiJ3VHcOcPWgmGdZgmRC2yrGj9xraKP
         Y7rCd1D4Ki0bBMFrpsJWCe62j3hktFIoh+6vbLS2c1th1bB5WTNf02M3ouZ6jwvrCrB5
         ZbG1OLB1/bPis29uHFDL/bbC9Jw/FEuJBCq5t4kUTLruVIgfpzvbniscgb4iOe9hi0Z1
         PNHXQUzGNufHfR5I1DdTdGHr1QaAW4Gd4IwZcCZHnH/s+UbKgWgU6Oe3HjWagGav9dOV
         wtZoPnNV+FD45Pn8FHaFYWbpff/tSPYqAUzF+dQSCKHQQuuamT6szxyLvEc857EVIG2l
         ozZA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw9HwyGON6vRSZv39FW2T9FK5v/aU4og8X0c7y6E1VSjEFJI9kq
	Vzft1tk6OS8BKN1kV+jzNCE=
X-Google-Smtp-Source: AGHT+IFNNElqamHjTcpt11xu2f7RnLHrp3C3+N3H/CBfUGk5b9ZjCf184XGxA5hHjBpdS8egre/0cQ==
X-Received: by 2002:a2e:88cc:0:b0:2c5:2184:c53d with SMTP id a12-20020a2e88cc000000b002c52184c53dmr2591031ljk.25.1699993867592;
        Tue, 14 Nov 2023 12:31:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c91:b0:2c5:dcb:9764 with SMTP id
 bz17-20020a05651c0c9100b002c50dcb9764ls826709ljb.0.-pod-prod-02-eu; Tue, 14
 Nov 2023 12:31:05 -0800 (PST)
X-Received: by 2002:a05:651c:1a20:b0:2c5:3322:c2d6 with SMTP id by32-20020a05651c1a2000b002c53322c2d6mr2739002ljb.7.1699993865583;
        Tue, 14 Nov 2023 12:31:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699993865; cv=none;
        d=google.com; s=arc-20160816;
        b=X/AvX+4MiFamY7SGDe6C1VDKBHzOoZe2Soa4+vV3L3nc5T/bzHIo1W8xLZm9UgBVCr
         bFMUwqCg1O3Cp5uprmTLLPGTYyq6+EvHSs0vaQ8rpqmxZBZ8lhybwbvSzg/U7+Ru0KhH
         QcCI95wt9ApXoMi0qAKTiOJVg8u84JDdlxRTpqhw1xoOjIeZKFoUjvU+156ylyCL2eu6
         YSqB8Ah0UdvNuQ4UvTcym8BryZnGe8GzQFBhAG/qKchGwycH4Pci+uGYO/chpbTju1yQ
         /6M5jEHdNijHGEoH+1RkOgDNt32Jc3kJQCx0gxD4rwVH6LnNf7XYaQPMTY2IuGjYihce
         uE7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=K8/NrlXrx7sKxKw33qQLGmJG4ajpbjlsvtZQ38cozIM=;
        fh=ZYn9MgmVpwKFi+h1WPMvL6yHYpyqaynezClwMkX7/CM=;
        b=Xl8cSFEgLuBfcY/s9oSH9g9UI86TSAR/yK0PfsV6C1osn/PfYl+WoT8FFx8bHFZAw1
         oEiRKcMeORUGgJkmKlcJ3RaBKAYCk4j502Fx7qdSRMerCwQLfHcEof7JulMRuXS53PfS
         sRMm5PLTuhbN8bjRZhnugxsytWpQ1O9pSraQr8VGyUyvApamNfTQbVqYN+vEXa7GkY+R
         qSju9C0lZTEGyDQ1gs7nDfd5PoX49sMc+khAdlX4MqReeAiJccPM+jDO1gKy3wt/B9YW
         u5KCgCuX1ImpmF9Uif74XLcqwl4thyfo3mvEH+mD1QL1syI7tpxddr8bOEp5WEeFhTD0
         TnDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bz0Tanb9;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id z21-20020a2e8e95000000b002b9d5a29ef7si326500ljk.4.2023.11.14.12.31.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:31:05 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 4C50F20430;
	Tue, 14 Nov 2023 20:31:04 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0337013460;
	Tue, 14 Nov 2023 20:31:04 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id O8kbAAjZU2UpYQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:31:04 +0000
Message-ID: <b7fd34fa-5623-5f78-1d95-d01c986c2271@suse.cz>
Date: Tue, 14 Nov 2023 21:31:03 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 18/20] mm/slub: remove slab_alloc() and
 __kmem_cache_alloc_lru() wrappers
Content-Language: en-US
To: Kees Cook <keescook@chromium.org>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-40-vbabka@suse.cz> <202311132048.B3AADC400@keescook>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <202311132048.B3AADC400@keescook>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -2.60
X-Spamd-Result: default: False [-2.60 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 MID_RHS_MATCH_FROM(0.00)[];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.00)[41.96%];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,googlegroups.com];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=bz0Tanb9;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=softfail (google.com: domain of
 transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/14/23 05:50, Kees Cook wrote:
> On Mon, Nov 13, 2023 at 08:13:59PM +0100, Vlastimil Babka wrote:
>> slab_alloc() is a thin wrapper around slab_alloc_node() with only one
>> caller.  Replace with direct call of slab_alloc_node().
>> __kmem_cache_alloc_lru() itself is a thin wrapper with two callers,
>> so replace it with direct calls of slab_alloc_node() and
>> trace_kmem_cache_alloc().
> 
> I'd have a sense that with 2 callers a wrapper is still useful?

Well it bothered me how many layers everything went through, it makes it
harder to comprehend the code.

>> 
>> This also makes sure _RET_IP_ has always the expected value and not
>> depending on inlining decisions.

And there's also this argument. We should evaluate _RET_IP_ in
kmem_cache_alloc() and kmem_cache_alloc_lru().

>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> [...]
>>  void *kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags, int node)
>>  {
>> -	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_, s->object_size);
>> +	void *ret = slab_alloc_node(s, NULL, gfpflags, node, _RET_IP_,
>> +				    s->object_size);
>>  
> 
> Whitespace change here isn't mentioned in the commit log.

OK, will mention.

> Regardless:
> 
> Reviewed-by: Kees Cook <keescook@chromium.org>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b7fd34fa-5623-5f78-1d95-d01c986c2271%40suse.cz.
