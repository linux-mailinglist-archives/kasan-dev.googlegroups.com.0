Return-Path: <kasan-dev+bncBDXYDPH3S4OBB64MQG3QMGQE3MAXBEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id BF234973867
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 15:15:40 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5c24c92db25sf8870173a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 06:15:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725974140; cv=pass;
        d=google.com; s=arc-20240605;
        b=JM/NBOxegHnP7BEZMbLYwmAA9slhrslvXUWn8nX89dmqczvpeQaXt+NmRxNozpbi6O
         UO/iSZbGUXnfRzZyPq40x5xU/Mzx6iFy2xkihoD4nVFDRN7EQ3kw7PltVHNPo8vX02Lb
         /NXju7BpHlhvbzgJWQpS1zVU/EVRkiW5EkACdjGNz90fWUFpDa9wLB7CAC5x6byf5XVp
         GBdqkjD6naLFJEDcqACaacX6nOG63pdDzm9hrGaQe38u6JdxZTBKhjnS2pvK0fk65V8K
         9quebjb7Dzv0Wvgx00KlksV1P+bPACoUdC0TBctEIBRrXW0T/aHkomCbKm7IWugYPVfh
         Uy/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=2zslqXrWXCAXMwGlbRI/MeYDmY9foAqKo8IiV0kNDlM=;
        fh=FJPoOn6kHY6a1D6xyH8P5Y1x9G5BDcGwsOjbf+Z+O4U=;
        b=Gifx4UV41Pph7t03f7ieeK5zaD6XvQuyzKvYk6f5DblkYcjKcUI/0PbSZYKkghVALb
         2CNRC+OMjMswDj1uYzZeTGj7cKjRdY8vyYNYRsbww1jLrO7XP9N6PLMECGHqlZV27FDX
         CpQ+pObij01IqW7YU157MIzXI8Z9AF+ezXa8lRWEM4EMpZj62ObRj8LzWlvt85hYo+PS
         3w3or+/mcZ1DX8wq0D8t9uncfisqxw0raFi1lfHtNgAIKh1YYTNwj6XtktXX4dc8kpYp
         yk2B3ERjnRtGnBHLN2jNa74A26asKD0pmmS1MrYUHPXrwXgCueql8X++999dPs+H8+1U
         wd5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725974140; x=1726578940; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2zslqXrWXCAXMwGlbRI/MeYDmY9foAqKo8IiV0kNDlM=;
        b=e4nZoBKOH9NorlrMmNq1Vm4QcP8LMvxS104piLtdMps94V54XL0lVzZ9S5CdzeSLvS
         h+wASsku7wcROmoOSUpk4tr8CY6JDcu3oH+wKqAHhIQv8XUY49daT7At46LcKR8qNPuI
         o4o4nLuXm5LfFYodQwpQFofkoZ1KVVFgCIR2Go5jbcpzR9KNoM6z7DECd6NQDFkC8hua
         MveoSNNI8pDYPploX0Jx/Be6pP5eesQsT8yA55/vVV2hnC/DGd0apggrvZJsI1Z/baWr
         GyLmdIDioWoMJY870e6C7gT/HqfNvy7oDXkVAMG8Zi3hlflajFS9+XB32giXKr9IvLKv
         qkaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725974140; x=1726578940;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2zslqXrWXCAXMwGlbRI/MeYDmY9foAqKo8IiV0kNDlM=;
        b=ly4J4ivQFIVr/6p2xubocfVGZ+QtyzYdZFHsbetQIFyKIt1OrteGz/WOAmAYcrNlVP
         0CSlqMjlWmAdisB+3yn1vIWb4/amVYDzw5+EYrgBAP4AZlYikTiJaCS7DJRTkYDXM7xY
         4r5vZo/nmYOV+Rav4ey8zvrIFnsRQb5VnTYM8fbico4Jgi20vD0BR0KtrqCMfZHEUlWp
         MoLelQCD/IwoBsDz5c2V4Bb0dhgDpLYc91n6d/w2o/2Ft5rTsTQ/f1L2GzRBfX+kk/Ch
         54qOVKpNrwn2mdDEeSt0PRJqBG1pm8nyXjhqY48zqvkli0THbHOxywkY3NoDtpstuc2M
         aRUQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUHHKJqDqzDybTsnKKCznU3LribuTe8ViAD30rjNj8dnLODVciAHscpz95dnhcAgrxHezKOdg==@lfdr.de
X-Gm-Message-State: AOJu0Ywdo+Vxl73jBBjkpuD38OTStBQ1KQG8ApCKJxGf7CXjepdoqm/1
	mGnY+/ys4evD0oSXtx0yc1/5Zsxy1lFjeqWZUZGekqfVXbzm6hqn
X-Google-Smtp-Source: AGHT+IEHaukbobtzqgTdABYfKXFs4hq98XtZLEE98qk9or5PgbYKrMkeIZwYX+eLB3mo2BCN4tIccg==
X-Received: by 2002:a05:6402:5106:b0:5c2:6c75:4359 with SMTP id 4fb4d7f45d1cf-5c4015e70b2mr3570043a12.9.1725974139303;
        Tue, 10 Sep 2024 06:15:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:13cc:b0:5c2:1813:8ca8 with SMTP id
 4fb4d7f45d1cf-5c3db5eab80ls202325a12.2.-pod-prod-00-eu; Tue, 10 Sep 2024
 06:15:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUOUDyTu9/mIs+EM5kZlb2Y3SjYxY44uZzjFkCjgYCYkdlxoPiNM9GQomIk32fbELPvbDCFAS92EAo=@googlegroups.com
X-Received: by 2002:a05:6402:26c7:b0:5c2:6a52:ccc8 with SMTP id 4fb4d7f45d1cf-5c4015ded0dmr3561567a12.5.1725974137434;
        Tue, 10 Sep 2024 06:15:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725974137; cv=none;
        d=google.com; s=arc-20240605;
        b=YxkvIFmHxUYvcrQpRDfhWqGBy55qLPi7FjexYOjbH1IF7PB5AuVq3wr7j0A3CwaMj+
         HZZawhrh1jhpOr+crTtrcLqjFlcrdBGi8JnGdr59qS5HTZ6mTDtvN9Q+Qxlymr454yRs
         /iBbMuKJl2J2dEznGw9JWLfiC0x4CDtJMjbG+fegDvB3OKUdE2qq1hR0unBzAtKqz4q9
         4zFhawNZk9f4ZhC/kvTtb6g89dXKqWoSIDZnPEOFlIYE0WUlP+cLrNAfDZXi3j+Z2wOZ
         FVDkj+a4P4Wj8GTdEaG4Bx1cWyjxv4kraZ3LAUGgglPSbG6qzaeFvkkHGoT4+PQvnhI6
         2jkg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=eYxgScMlrAywO8ISaAn/OQYFEqBmsn/J5LCyirmrP8I=;
        fh=0xRBb/eFYt1OwNgyWpv0boRELUlsWEBHSNu42J9xXtM=;
        b=JoDdGtqNu+8yO+zl7iqD5Yewk3bvGsIlKiCNI8gGeit8jH6XQQVfJIczIx5gx3GSky
         lI5t/T0sTm2G6ENmsw6Pd/L7q7OsYai5+z6XhlWSDhYhz9JYm+2eKPET3iOjbxl8M4er
         gECw13caKo7ytB+N/BnOr11TNeADr905SFsIEUUKF2yGsH/aU24KABGzRWTLVdTDH1pu
         fx9f0XjW0BWCtTNDBVG044u14j4mgvAspH4TGZ0BOmbraDINdQNAs1m2dg/4+rkLgi0l
         STEEXU8WZMHhVow3uNeGAtRH+5ty6i/ZUltlQbowGZXpjTn81WmIar6xyEhzkqDC8X+j
         2wMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5c3ebd46f5esi72576a12.2.2024.09.10.06.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 Sep 2024 06:15:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0D3EE21291;
	Tue, 10 Sep 2024 13:15:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id DE22013A3A;
	Tue, 10 Sep 2024 13:15:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id hlbcNXhG4GasGQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 10 Sep 2024 13:15:36 +0000
Message-ID: <dee10b40-0cf5-4560-b4e7-6b682de3f415@suse.cz>
Date: Tue, 10 Sep 2024 15:15:36 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 3/5] mm/slub: Improve redzone check and zeroing for
 krealloc()
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
 <20240909012958.913438-4-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240909012958.913438-4-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org];
	TAGGED_RCPT(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[16];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	TO_DN_SOME(0.00)[]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=NZa4wUWq;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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
> For current krealloc(), one problem is its caller doesn't know what's
> the actual request size, say the object is 64 bytes kmalloc one, but

It's more accurate to say the caller doesn't pass the old size (it might
actually know it).

> the original caller may only requested 48 bytes. And when krealloc()
> shrinks or grows in the same object, or allocate a new bigger object,
> it lacks this 'original size' information to do accurate data preserving
> or zeroing (when __GFP_ZERO is set).

Let's describe the problem specifically by adding:

Thus with slub debug redzone and object tracking enabled, parts of the
object after krealloc() might contain redzone data instead of zeroes, which
is violating the __GFP_ZERO guarantees.

> And when some slub debug option is enabled, kmalloc caches do have this
> 'orig_size' feature. So utilize it to do more accurate data handling,
> as well as enforce the kmalloc-redzone sanity check.
> 
> The krealloc() related code is moved from slab_common.c to slub.c for
> more efficient function calling.

Agreed with Danilo that having the move as separate preparatory patch would
make review easier.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dee10b40-0cf5-4560-b4e7-6b682de3f415%40suse.cz.
