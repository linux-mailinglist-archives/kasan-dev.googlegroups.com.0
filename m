Return-Path: <kasan-dev+bncBDXYDPH3S4OBBRMBYGVQMGQEPP5F34Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45695806AD0
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 10:37:11 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7b39e0d8185sf681443039f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 01:37:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701855429; cv=pass;
        d=google.com; s=arc-20160816;
        b=fZ6L6wyag7tCeowj75qX8o8I1V7FODaOXNSWe5ufL/2gy99gijsk9W6dIP+KY4SCAJ
         3yfqDKLgAa2uvGfxz2OY9xFapZXorQt/s5saLDEPs7iWCmwA9cQJueJmy2pO0sViwjU3
         zp3pf/+BKE8lQbXYVx1yoa1itrHNLNL7JQhEoTKgkELbBEHtU/X6qBhOOgYGl7gJquQI
         n2OuicGO5ISuWE0DgId0KS0kJuF5HIREhaywv/dUsJbcKhta1pYy3/ANo0VhUlK8ZCVN
         rsKV4W786c3nyA9vyvzZlH/9bbWwsshA/D7xsPm/j4TU7uf3jEPqYjtaP+P42BfOPA4b
         1I6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=sAienBsfVVPco4cTvCgUQUO5pkaHlzKLu2HSk5TtD5k=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=1FZhYyg26Yk6O4NTD7GsebvcFujI2lisu5S2VRlkpufmOQKbBceGuJMANOd/duBPhN
         2+5FxJZUpVB3eDIS0uBKx5sZ7fV7S32TziWD2rhhqdfEvYdDq6uxFthvdUT1EV/rqMSc
         +9TccgqCFr99w2EyYWe/bj4Qo6rqJGzRn0ZhXWTLCxFi+Z35MnuCeC0x3Q1ObnsgFY+L
         OdKdjJC58PgB38codl/cgIuv+fllIp802K2ordeY7Ml4RJlliqDdxtLVn8dvU7HCopKF
         iJc2xAkht5RPE3lz6L3tfTqiV5h64C3VkEW0JafObkdDhzNgoXW8w+K6cJJwspk/3zmo
         6Vkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YMsDkGCg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701855429; x=1702460229; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=sAienBsfVVPco4cTvCgUQUO5pkaHlzKLu2HSk5TtD5k=;
        b=it6scVq/2az3navrDZCg+I7WYx/KR8mAL9i3NxRfSwnL7brjwm7G9kaTe/B5MUqyjR
         VXi/FJYYNVyGbgdmJm3ej2p69CRtoAZIOeqUjqsDY8FvdwBHgmJFZKuZzRt+hjydPa7r
         n+l1kfQcNfX2kPOSbZ3hIkd4pXs3Z0zp7QOCFMb1OqNyrrZjVnMvaNXe4MAh/pRUo3NV
         5L3GuOzAU49r14RAvB6Q4xEvf0NP1+Tj3XB++SQIEJ2cs/iX10aGbSt+IijXqIs6U9gV
         AEFlNirP445gT1rOju28Dh+FpWnRnoL7s14CoR9nhVkSLHPy2bnMrDCDsGIteXtiHQm1
         cUKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701855429; x=1702460229;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sAienBsfVVPco4cTvCgUQUO5pkaHlzKLu2HSk5TtD5k=;
        b=L0vScOyKwxweIgZlj4n3vb4r4UfSBTHT13KO/IR+doQF3LeFUAEq6Nt0dDM49a3PwH
         IwwdK+qaTOSr56IRsJMDlyRbLiRdOWm4GaDY+FFRPl7CGj3+zMxQ0zgmLbaGR4JOGBNh
         Z8vRxNsArin91Jq4uqQmcnwOnVH9WWvDMptcW7zb1wylf4iMRMITvJlCnXyjWt0jSZj6
         exxzWWkx5ai0b26Gsl/F12zO0BcH6jN3fu4yJ3zdh1i/9Gag/64hG8ZtoQ6B4T8ZW+do
         TZnuzGPb49TaGSARoi0DaPdCf7p3Iu0QBTWEafmSQwx7/GrxUCTzE6A91C2YxksDg3oy
         cSaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx3QXKc/GBHqOm293b4OHZM7eat+dtwDfGA1uN/J9xVLMLDTK3D
	2DnXGegoCEAe3Vlv5yLVkZY=
X-Google-Smtp-Source: AGHT+IELWhdY+xlGbcygCHfMtAmvFYKMUVBXuFHTLdw2y3Khw2UsmjjToq3dz+nmpgZeihDohr2bPw==
X-Received: by 2002:a92:760d:0:b0:35d:59a2:bec with SMTP id r13-20020a92760d000000b0035d59a20becmr743764ilc.130.1701855429589;
        Wed, 06 Dec 2023 01:37:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c081:0:b0:35d:6f98:f426 with SMTP id h1-20020a92c081000000b0035d6f98f426ls2164193ile.1.-pod-prod-03-us;
 Wed, 06 Dec 2023 01:37:08 -0800 (PST)
X-Received: by 2002:a92:d591:0:b0:35d:6648:ae51 with SMTP id a17-20020a92d591000000b0035d6648ae51mr630167iln.5.1701855428458;
        Wed, 06 Dec 2023 01:37:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701855428; cv=none;
        d=google.com; s=arc-20160816;
        b=B+c505+QDgcpBsybSmmd/+yF43ZEoITpsdZ+sjpt2mCmcKMyZ7ilqbJfVR/2juAU1j
         F+k+8HAJ0ayWmxEh5R+aHVug8m6b5USZXpu2+tHtFBOJhQXbc0W1epDHkVlpcx0rjyBj
         ww4KTegNabi1GFLz9fONjzgQWX0ZwxWwSl6Ff6ZSHlivzatpf0+gyJ1ZnzIlpwpg3txT
         Fl6MSHlxLYEe5AB9SLoHoEo4aF6tCQ2RCrhTjaxroaUCZ7Gg1HZ+SHMiXbRk7O1vOmdu
         Yg82YHSsQWjKMAvg/jff9LEwZSY9ktj5AjdKy/7kP+/Lc+kqiLHjigOw1ZgZ8C2OWbOf
         IV8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=0RhjCKHQblZR+lvAtLCjbDfVvYyouCwUYRk6G4t7QCw=;
        fh=06sOGDy6+X3nN0awOxb/HH+z4VuvuKLqmFUbQx9UqP4=;
        b=NfLTP+oUhHM1p/oX7JMZgMCR/HEzpct0rmcxiMDrCAnACSd4dJFAb+vYIC+Ef9x0js
         P2DEjVMKfds2WixmZDAKlZMlXcMIY5kZ8wvrxRUCoYHuqpYsAMM1aCjq7skoPntw9yow
         42DNvNb7zVqWydtca8XgBcbfyXZwGoUIsVs4jaygbuy1fjLH4zEqEWdnAl7vTbnngdrF
         QtE4pRyCyFnFZEvJduK5FxuWARTPyarGzUJkLSq3P+8w1fHDukmndGZUZiJKpvgrH08s
         ZGW3oJhiIOE9OKpLvNRvbqN1rZukEdaqrXBYLKY57YAubhB5zfvzyp50d8pqGcX5Uvw8
         SP0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YMsDkGCg;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id t10-20020a92c0ca000000b0035c8d7c3820si265379ilf.2.2023.12.06.01.37.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 01:37:08 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0548921A3B;
	Wed,  6 Dec 2023 09:37:06 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CA3E313408;
	Wed,  6 Dec 2023 09:37:05 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OgMBMcFAcGXVRgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 06 Dec 2023 09:37:05 +0000
Message-ID: <15e22e38-6eee-3a55-df27-51b7bc0c5976@suse.cz>
Date: Wed, 6 Dec 2023 10:37:05 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH v2 09/21] mm/slab: remove mm/slab.c and slab_def.h
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver
 <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>,
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
 linux-hardening@vger.kernel.org
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-9-9c9c70177183@suse.cz>
 <ZXA+Ur55OR1EU/5L@localhost.localdomain>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <ZXA+Ur55OR1EU/5L@localhost.localdomain>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Flag: NO
X-Spamd-Result: default: False [0.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[23];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[chromium.org:email,suse.cz:email,selenic.com:email];
	 FREEMAIL_TO(0.00)[gmail.com];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com,cmpxchg.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.20
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YMsDkGCg;       dkim=neutral
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

On 12/6/23 10:31, Hyeonggon Yoo wrote:
> On Mon, Nov 20, 2023 at 07:34:20PM +0100, Vlastimil Babka wrote:
>> Remove the SLAB implementation. Update CREDITS.
>> Also update and properly sort the SLOB entry there.
>> 
>> RIP SLAB allocator (1996 - 2024)
>> 
>> Reviewed-by: Kees Cook <keescook@chromium.org>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  CREDITS                  |   12 +-
>>  include/linux/slab_def.h |  124 --
>>  mm/slab.c                | 4005 ----------------------------------------------
>>  3 files changed, 8 insertions(+), 4133 deletions(-)
> 
> Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
>> diff --git a/CREDITS b/CREDITS
>> index f33a33fd2371..943a73e96149 100644
>> --- a/CREDITS
>> +++ b/CREDITS
>> @@ -9,10 +9,6 @@
>>  			Linus
>>  ----------
>>  
>> -N: Matt Mackal
>> -E: mpm@selenic.com
>> -D: SLOB slab allocator
> 
> by the way I just realized that commit 16e943bf8db
> ("MAINTAINERS: SLAB maintainer update") incorrectly put her lastname
> (Mackall is correct), maybe update that too?

Right, thanks a lot for noticing, will fix.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/15e22e38-6eee-3a55-df27-51b7bc0c5976%40suse.cz.
