Return-Path: <kasan-dev+bncBDXYDPH3S4OBBH6H6S3QMGQESA3BERY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id D606698D17E
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2024 12:42:41 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2fad27f65bfsf23985621fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2024 03:42:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727865761; cv=pass;
        d=google.com; s=arc-20240605;
        b=GJhwKhyzh6pkUWxCFYVr/iAF/PUq5hLDvSY6bioVcuX/UHsg3+w4etB6tvaaxSYJue
         CDlgGx2IhLPNVB7UBHce2Lm27W6UV3AzjcbtKV5x7Vfl7UcGLKPCzZ23YZMjttY/npZm
         a1GsH/GspH3P+Mib2BnX7VtJaW9RE3FYrsEkMX3Rwfbdq99ZrjkITcog47E24kovWazR
         82b/750xcDbIiNQN/W5+XvaHDr+gHg92jSwvVp7tCqENE3vzoSOxXigNZgSkchjSmKBY
         yhOOJ6arVOivXxXHZsiTdgVzLDTn6XAQxejopIv18eb6s5KB4wuXr5lhYKioibm4q+FY
         eXqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=7cMxUWmbSGyL2YYAx29yWgBnbz6SUTKF37JqIXssGNE=;
        fh=GEKKT52/66DNiD4Xr7INEGJhWAmEWoNr7deP334lk88=;
        b=ThbuksIoHrIaZiSW7Hmv+vuYoiXj11GJvPbYbp+w0pDd2+GErqqbx/cX/5lumJXzER
         qi1x/YnwtF3b7lt7somV+ft7wLDw3bBYBRdk68QjmPOupXgR/i2mA0Y2jPs46+759D1R
         ULRKHb6pb+nvIcd/He6ot1cV54WjH0wemnKLY4lvtvxO2i8J0EJGT1JupbauamrLAdXY
         jaVFhffqZGY/4Cnt+uvl5TAX8PTruC7hmzow9qfZKsH+8IfjoOekBO74prKuyv4UuK23
         HidmuZYhv8TMi3W4hLvU33z6zTFLm4V8a7rFcsV5XOWFdiSf5ys8Sak6zJNEhYlrSsDx
         RDaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=D3HHB9Aj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=n+nX3td7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727865761; x=1728470561; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7cMxUWmbSGyL2YYAx29yWgBnbz6SUTKF37JqIXssGNE=;
        b=NI3taFoCKTfrAkGM3ZFEuoPFxR4G9EwkhzUIM0BlZgPtyGImKAPPqF7ADCHE+P2lzE
         IiYnyzYEpYpSZJqvPFKPTCj+yUZ/Ixqnh6maASI6CQ1EmhgqPN7CowuX5RHdja4i0FkD
         bMYUwUYLScNAgb5YQRmM8YNptiDE7uEkZ/HrCZX23qz4vCRkvsnftkuBM6J3075pDioV
         VVNKCreMItdz0JMus+FgKtvf0XG+wXCJvo9es6lgeFt7Y4l8pjTsat8jrAQICX/5HiwA
         IxprbjPb/W8E7qpCGMzDt5XNJN/+9fvayF7hR1rhPD1LGLmpgDq4VetzqLAVNN7te9MX
         4yoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727865761; x=1728470561;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7cMxUWmbSGyL2YYAx29yWgBnbz6SUTKF37JqIXssGNE=;
        b=fmvkIklESMniwU5bsYeX6BS+KLx1zPhImtFp4lOGcbMKCD+/W/U+M/8dEIlmsIOO8J
         3VqgvPKcQpk3q5/YYO0kt+9/N+MVv+1E7xYpzNmmu8KXlIRoxU1ooatOaOSXsZTExfl4
         cxuyHTF3ggkyGJF5t8qchbCq3fWv86meVGDNB77HneDb0355InQiw/c7ENyyesv509rs
         qGSvs3s3zK4cnEVBQr0kRGwNCM4Uy4OemYrs60JzdGUaNGoPC1J9OtloJtWjvjARtwK0
         b6WYvG2i7BeG0IqV5n0a0Cmc0KNaCh6IMUv2f+9AeTs+h3RGo5KGcQLYZm31Gp2+89Kq
         lRXg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRzdNsBPyb8zy1CkJlw7YsakBsS46rURf95vOaBU3B/x5hKLdOMwwn8vioorXq9kPO9qUxcA==@lfdr.de
X-Gm-Message-State: AOJu0YyDU8F/hsRodc49ATE9RJfrll4wRilKyM/stOsFYJ0xkoejr3oE
	HjWd6zZRxcSN5yjlHB+Px1p0PLY2dmEOaiPhOGzHjiw6BjeOe0bs
X-Google-Smtp-Source: AGHT+IFr3JQQ84+oOQ3rqSnnXwe9dnJ2nTzyqYxD7mr0wxIEcB4S9ywVvihsnj7SVebLEYHq1ScCPQ==
X-Received: by 2002:a05:651c:1a0a:b0:2fa:cdac:8723 with SMTP id 38308e7fff4ca-2fae10c53b8mr13551101fa.29.1727865760181;
        Wed, 02 Oct 2024 03:42:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2ac2:0:b0:2fa:c49f:f113 with SMTP id 38308e7fff4ca-2fac49ff2b4ls3645311fa.0.-pod-prod-01-eu;
 Wed, 02 Oct 2024 03:42:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlXuAJX9eWRLA2gYeykW+IHigE+C7M28CxjWZ7EhcCdiSgbjFGTFZVeCKlTMuvWIoXVPnfSvWDWIU=@googlegroups.com
X-Received: by 2002:a2e:515a:0:b0:2f9:d359:50e2 with SMTP id 38308e7fff4ca-2fae10e7eeamr12387281fa.39.1727865758078;
        Wed, 02 Oct 2024 03:42:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727865758; cv=none;
        d=google.com; s=arc-20240605;
        b=TfCgd+3TGBMXXrxF4wSwuEEr9WEe5Vsqoyt3BmJm0tSsImYtuOkhgzntlInJeOJUKY
         A7C2+PaD/yf0Jk7YbTtXRf0oWFxq06+CacXM0piaoWcdhX7njoLpB5yu8V+WUPKDChqy
         RwzGE37h8Ab9RIooFeEKh75OZXC37+K2mTIoBoNzCYp13Jts5I9za8c+SvalhtDcd8cw
         3rvSQs6pHzPScPdx0EWECjT4TtIEtwYheFa7MRsUNeD1WKxjTBAaKGnlIsgZ69h4aQBA
         B2rItYxvA1ZwzB/outJ74E9dRnSdVOzo7n5N9cv/EzUcr/LHuxyUPzRTeHT81D+huctE
         QDqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=i8E6YBx9IYbiLWKiah4rdepV2BvjUAiHQI2nwFPWPZ0=;
        fh=yvFl2UN4jWODLbYNxw9ZslROYrrCQfWo3FIzeqYdZd4=;
        b=U9U8aTfivwcoFJiU9xhG673kmnp9JiKGF4W/00ipLdgkBz5GPuFBYHtH3OqK+ib4bd
         KG+1UzihGXxUQSPToAh2BrJFFBxOWpJHZqWybciyPbawG9I1jNzYUjTD8mr9qmbK/4Pl
         oEBnGG+3zsZ1iP0HWDfECvMe57CTgRTam3qwHgTqUlXjVRCrSgVV50Kml0bvpqOdKV0B
         s0hpErEFco46MS1ohMTbDJhQ++wb6e9BIZAl90D1LdDc+5VIAEk9i4NSTfW+sh7rZio5
         K4/TwiYR+K12Hf+x8MrMI+O7dAR7JzhhixLQR6dCrDpVM512y5rbE6fL/UAPVpGgIMo5
         h/ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=D3HHB9Aj;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=n+nX3td7;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2facfa8d54csi1333551fa.1.2024.10.02.03.42.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Oct 2024 03:42:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 01C1E21B6B;
	Wed,  2 Oct 2024 10:42:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id CD31713A6E;
	Wed,  2 Oct 2024 10:42:35 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id lrrFMZsj/WbFZgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 02 Oct 2024 10:42:35 +0000
Message-ID: <d3dd32ba-2866-40ce-ad2b-a147dcd2bf86@suse.cz>
Date: Wed, 2 Oct 2024 12:42:35 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 0/5] mm/slub: Improve data handling of krealloc() when
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
 Danilo Krummrich <dakr@kernel.org>, Alexander Potapenko <glider@google.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20240911064535.557650-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,linuxfoundation.org,arm.com];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[20];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -2.80
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=D3HHB9Aj;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=n+nX3td7;       dkim=neutral
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

On 9/11/24 08:45, Feng Tang wrote:
> Danilo Krummrich's patch [1] raised one problem about krealloc() that
> its caller doesn't pass the old request size, say the object is 64
> bytes kmalloc one, but caller originally only requested 48 bytes. Then
> when krealloc() shrinks or grows in the same object, or allocate a new
> bigger object, it lacks this 'original size' information to do accurate
> data preserving or zeroing (when __GFP_ZERO is set).
> 
> Thus with slub debug redzone and object tracking enabled, parts of the
> object after krealloc() might contain redzone data instead of zeroes,
> which is violating the __GFP_ZERO guarantees. Good thing is in this
> case, kmalloc caches do have this 'orig_size' feature, which could be
> used to improve the situation here.
> 
> To make the 'orig_size' accurate, we adjust some kasan/slub meta data
> handling. Also add a slub kunit test case for krealloc().
> 
> This patchset has dependency over patches in both -mm tree and -slab
> trees, so it is written based on linux-next tree '20240910' version.
> 
> [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/

Thanks, added to slab/for-next

> 
> Thanks,
> Feng
> 
> Changelog:
> 
>   Since v1:
>   * Drop the patch changing generic kunit code from this patchset,
>     and will send it separately.
>   * Separate the krealloc moving form slab_common.c to slub.c to a 
>     new patch for better review (Danilo/Vlastimil)
>   * Improve commit log and comments (Vlastimil/Danilo) 
>   * Rework the kunit test case to remove its dependency over
>     slub_debug (which is incomplete in v1) (Vlastimil)
>   * Add ack and review tag from developers.
> 
> Feng Tang (5):
>   mm/kasan: Don't store metadata inside kmalloc object when
>     slub_debug_orig_size is on
>   mm/slub: Consider kfence case for get_orig_size()
>   mm/slub: Move krealloc() and related code to slub.c
>   mm/slub: Improve redzone check and zeroing for krealloc()
>   mm/slub, kunit: Add testcase for krealloc redzone and zeroing
> 
>  lib/slub_kunit.c   |  42 +++++++++++++++
>  mm/kasan/generic.c |   7 ++-
>  mm/slab.h          |   6 +++
>  mm/slab_common.c   |  84 ------------------------------
>  mm/slub.c          | 125 ++++++++++++++++++++++++++++++++++++++-------
>  5 files changed, 160 insertions(+), 104 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d3dd32ba-2866-40ce-ad2b-a147dcd2bf86%40suse.cz.
