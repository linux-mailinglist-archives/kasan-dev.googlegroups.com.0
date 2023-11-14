Return-Path: <kasan-dev+bncBDXYDPH3S4OBB7VMZ6VAMGQEERCEHII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D4647EB7AB
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 21:20:16 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-40901b5acb6sf109105e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Nov 2023 12:20:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699993215; cv=pass;
        d=google.com; s=arc-20160816;
        b=QA2UUkYEyONgif4J/PfUhrP3DuNBHDupV0+fRZtfOZOfBne7Vm2O/wj4X0kVybSSYv
         nvyJTL5f0vLtDEWTHFqRUL6W2VxhQvo3Fx5AsCbs3uxhKU+oAiDS5lRa6n2kZiyaqv3R
         Zpp8GS+z4mqsqACibK+Hpy7HSCwES+/gNLMyzayEi89pV4uhEBt7GfLNyVOKGkSWht+s
         /LrQEPGqU8qL5t+wIGBVO5ReBbsPUNfVMohiLru1RdPER8+R8FvFqXF3O1LdvS7rDATG
         01t9IfhmpTCm3J84N+bNwlAaXg9J9VmVbbUaS9dFRb9Y7eqtSu+Dcw8U8OWklqgkxnkR
         W+CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=iXPkrU2d40pVYVYxtp3NvlcZX6cFhPq5vhKZqrq8rZM=;
        fh=p9mTBDQRqraFr7jHrB4gF2PB19S3iP4FAxq4ld8XWBU=;
        b=dQ97XQr4UytOe4MQwZzEj4fcsndRrrN9Safbn1s50z2mF2Y9Im5+DS+JUAfwgQyNHS
         SlhUPe60KByG2vp3d1kO6rRzcyXDV71pqYPbi8bhXNNClhVTia65JLiw8PneDOYh0/X5
         KM5XeeHQyqR1Pfa9eDtXFqviZI+TuTD626U8/tsLZ+0LpM4WO2OhY+o18x8j3/GiAUW7
         CaCH+AeLSRBO92cKzHBFUs49QK16yoSMFYQnebpOz2vFXtmgiHWkP9wtarLHw20LBgIM
         ovzlL6tQ7/9KfFvj3oamzWCCK/ErTKPRXzccku3WztNso2d9AJ3jFhMBuBxbRMVJXi34
         b3rQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oehcGKUo;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699993215; x=1700598015; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iXPkrU2d40pVYVYxtp3NvlcZX6cFhPq5vhKZqrq8rZM=;
        b=VpBbjBceH9S28SfNYLswCY1g5rC+IuNYWg+KlVm3FWJYdMZgqdhVPvCakw0I4pv8ec
         /xHP3olRmIupYo1+tyzpGbNV11hRT3ofqcP4KyoD4pE5KVR4tjjhbRKqjbdvs/rGYpoY
         wb80YqgNEILvML7z+pK2JsC2HrjHSYnRQ35de2FQSuzl8gYN952hgHzdKNMUb2Kb3C3D
         edPkF/d2/nHeJ4jkjDFm3v+dMWZ2vjm3fMosEkpFfVLDHyY2+6ITc2xy9QCT6dHnStzN
         vEsCgOAF0wRrZV5uMG7WGmtZ/b5KRftgAU6GGHzvnoF66UwYRbG9fPRsQY3QC1le5OfY
         PR7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699993215; x=1700598015;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iXPkrU2d40pVYVYxtp3NvlcZX6cFhPq5vhKZqrq8rZM=;
        b=AvyXgx5RBZSo/gPMwoYOlByca5Yvo0aS91hp/+iKtwspiS1DpstG3jOuvPUCEy06jc
         R1yhuZmR+JbiGyF0hsqO0hhFEIlYkG53oQ3z0pYxN9R0/KgcqPGkfAL0kfETBOVjpkXy
         2OeAe781slUFb0HkFY+NE0XpUo3fcYhBnK49QamNNR+aPFrueMbQJRfhkR9ohg8g3uwA
         XAxXUI+xIW13uh37v3kj3T5uLWOLXKf87SxkRA9qxDfn/74Vua+UCZrWtjZONsKDgxsK
         hLvlfIFgLYC1aJToCCnZiqbl7knRLMNFiRcMlSQZ9dJ4sFQ5R53OqZF/Zsr5NY86Dzub
         pb/w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw615x25Nr9L2eBuME9gsYUYDQdNbEYLWshBH716laiI5DkOXGq
	RnUdcuZaWffMkXS9dmwIeqU=
X-Google-Smtp-Source: AGHT+IHX1teGEcZNgoJgtsLH9LDD3CgvIQnF6LuUZbEOtAQsx19CAKECh4VTrd/W0/JBP6NXEKP1dA==
X-Received: by 2002:a05:600c:1c25:b0:408:3e63:f457 with SMTP id j37-20020a05600c1c2500b004083e63f457mr30991wms.2.1699993214940;
        Tue, 14 Nov 2023 12:20:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e27:b0:409:15fd:800b with SMTP id
 ay39-20020a05600c1e2700b0040915fd800bls1503022wmb.0.-pod-prod-06-eu; Tue, 14
 Nov 2023 12:20:13 -0800 (PST)
X-Received: by 2002:a5d:4743:0:b0:32f:932b:e02f with SMTP id o3-20020a5d4743000000b0032f932be02fmr7660255wrs.55.1699993213048;
        Tue, 14 Nov 2023 12:20:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699993213; cv=none;
        d=google.com; s=arc-20160816;
        b=cZMftZ96yLj+Jr2NJPkzul8hPSiEqO7hTAIUP3BnWqYei1XdYhqKuvgsA61q1QH40v
         onvFZfHljQPd9aVeVcdUr8WCgyxyFTcrMyQUNSS0UZOeBxn1YaItlRVtMJAYEgYNHk+F
         HdMcEFwgJSNxpGfubtPI08m47MwOWdBZgkauqbxVSHMnePIPlUejJIBu+uAKWB568tUP
         rg4b+kTmqlALq8ZQDUR1/GWqKliScjl3KRh17foO+wRoPLzV1gOvvghPovwf1als+PuN
         xsXgtdcPOPGSxfCfnTBtYqhrSdTm+dgB7IpJbadm+HFKqS3Vl0c4H6hMu7jMf2rUjWAB
         ui2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=yRZqg1eyXGXcPqi9GpGEFNWWf1q5PJQkVGVoL8YbRuE=;
        fh=p9mTBDQRqraFr7jHrB4gF2PB19S3iP4FAxq4ld8XWBU=;
        b=zhsEyWr/27tMxzU1zliIkQvLSytznr6U//SgFGAGkjANq/CU71RWNzRWGaFAdxF2LV
         y5E94qiRM6aQXSmmau0umrIflLm3qTFYv0fHRq5VeCZVvbDIQOmBw/NMq/l4oSS3Pk++
         wBu8yJiVF8repQrMaOeJIw5Ro+eBZiJ/tQ1bbpxGRFC2rIetY0JZM3u7JiqL94peeFy2
         nEqd1bDMIfvg/usTG0n8Dgf8wrP1p643BVXPfnx4mex0fad3PzqvokQSkk9zKasuZfA4
         22oE+gMKljqlq/Ir0fb4GT76GJU9ZHqfMeek6+FbSdbn2yMIBo6T0WzcBEK6Dbovywme
         EOYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=oehcGKUo;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id az13-20020adfe18d000000b003233224954esi359144wrb.6.2023.11.14.12.20.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 14 Nov 2023 12:20:13 -0800 (PST)
Received-SPF: softfail (google.com: domain of transitioning vbabka@suse.cz does not designate 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 6D871204CF;
	Tue, 14 Nov 2023 20:20:12 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 32DBA13460;
	Tue, 14 Nov 2023 20:20:12 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id j8/QC3zWU2WFXAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 14 Nov 2023 20:20:12 +0000
Message-ID: <6d8b51c5-4610-66b0-d4a0-e1032597bcb6@suse.cz>
Date: Tue, 14 Nov 2023 21:20:11 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH 08/20] mm/slab: remove mm/slab.c and slab_def.h
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, patches@lists.linux.dev,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>,
 Shakeel Butt <shakeelb@google.com>, Muchun Song <muchun.song@linux.dev>,
 Kees Cook <keescook@chromium.org>, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org, Mark Hemment <markhe@nextd.demon.co.uk>
References: <20231113191340.17482-22-vbabka@suse.cz>
 <20231113191340.17482-30-vbabka@suse.cz>
 <CANpmjNNkojcku+2-Lh=LX=_TXq3+x0M0twYQG2dBWA0Aeqr=Xw@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CANpmjNNkojcku+2-Lh=LX=_TXq3+x0M0twYQG2dBWA0Aeqr=Xw@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spam-Score: -6.63
X-Spamd-Result: default: False [-6.63 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-3.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-1.00)[-1.000];
	 BAYES_HAM(-0.03)[57.16%];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[google.com,linux.com,kernel.org,lge.com,linux-foundation.org,gmail.com,linux.dev,kvack.org,vger.kernel.org,lists.linux.dev,arm.com,cmpxchg.org,chromium.org,googlegroups.com,nextd.demon.co.uk];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=oehcGKUo;       dkim=neutral
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

On 11/14/23 09:06, Marco Elver wrote:
> On Mon, 13 Nov 2023 at 20:14, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> Remove the SLAB implementation. Update CREDITS (also sort the SLOB entry
>> properly).
>>
>> RIP SLAB allocator (1996 - 2024)
>>
>> Cc: Mark Hemment <markhe@nextd.demon.co.uk>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>>  CREDITS                  |   12 +-
>>  include/linux/slab_def.h |  124 --
>>  mm/slab.c                | 4026 --------------------------------------
> 
> There are still some references to it left (git grep mm/slab.c). It
> breaks documentation in Documentation/core-api/mm-api.rst

Thanks, will check.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6d8b51c5-4610-66b0-d4a0-e1032597bcb6%40suse.cz.
