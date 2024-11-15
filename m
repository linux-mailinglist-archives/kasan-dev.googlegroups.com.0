Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSMZ3W4QMGQEQMWEYUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3600C9CDFF0
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 14:29:52 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4315c1b5befsf12809485e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2024 05:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731677387; cv=pass;
        d=google.com; s=arc-20240605;
        b=WmLz/taLF2MDpbVhVkfMHmDhjRyeO9/ixHbdhEaCJVCa2so0LB760UWMXdX1U3Q2Iv
         uhYHXoDadNsqeOE3pZm9Hdyh2kJbjjs+8h8sDZ+ZMv72OZMFbOF9PjpRnOftVNw6iE8k
         etz6+B6XlWVsiNPxS44qkrBcrbq8eL09JtSCqoUm90jeFTdfOh5PyFCalCCeqZ9Pe3sr
         7umYQ3E3RxHXgkLbl7Igc/NqrIBLmg9C5Z4dEkXajizphR9GO0U+HgHMv/r3s6Ic96KV
         nAqOAqsFokG30Nkc5ytxAqcHZxoMoPM7lv/mCfxaHsHu/epS2rPOPgXHcO1VJdEw7Ez3
         CQcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:sender
         :dkim-signature;
        bh=Tp9MFHTXhDwOd+5KwQAfWsIIajiKXRDIpUSg65o2+KM=;
        fh=/0QXfKaBz3YmwAr4zjiKvKELJpXayNZ2h0TJ2/Ugek0=;
        b=NkRfC6LB1mbGJjqhylIdWuE7pIadYoCBjnmHHaL9Q8VpRgYoUYW9WAlZzEBgGm7jro
         S4dZKKa4BjHQfZRmyPViHxa2WwoFUvi2IjOkRNOrQ08UBzVUK17Ll6awcoAJWEClP3al
         RZJ2b4FpN9SP6ZCxeqwT/22FiPXtdiFQSyTjhtyVOJ67R12zvlqYyvbP1BpSwSrIBBn8
         PLr/8i1OCyVWPIu+HmoDAXT78gakVPB8blNlVjeq18OOY41QK1zn0w4SJ9OZQpvx5HgX
         XpnoYArzx1WpgzV0mfJIg/Qgsn40AY2bs4mGiqghQhL1QEmsrfqMT/9zwptPBcIJuTYg
         JydA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eA8Yrwbx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Bfopt31V;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731677387; x=1732282187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tp9MFHTXhDwOd+5KwQAfWsIIajiKXRDIpUSg65o2+KM=;
        b=pp66Asp1xa1wbxHfINGmAGN8TH2vc4Q2xwWk5GVZPSqZfI5GtnkFPbkiooWyjNCoa0
         2l2NZM5SOhwuBuatHzQGzXkjr5ckTmF6wR/FOxX3UnGBMzco1p6Np2HNux6XFg/n42CL
         bI1kxgBdQ3E8DsR9s8c00sL6Nlt/7m+nLu5DQr/HbFsyZMRc7KRDyHA2x68KYr/Wm8s0
         6khIeUobXHzPB3Yh1/7UCVNcJcx6qyg/tBuXAMBUQEYcKqijdsxXG8I22EUNW88v8N9Z
         kosh7PgzdKoTjvO7CyvNfJPjbflnJqYUSR9gIue8RgBFGjMtzpuOyzMpYGPbfgcqlZ74
         sHrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731677387; x=1732282187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tp9MFHTXhDwOd+5KwQAfWsIIajiKXRDIpUSg65o2+KM=;
        b=RmR27JD3zC8P8zc2CqEPqzhvk7wEU49osc0zmJRPX3vyteonALhWWfv465SeSSrg43
         dXDu041GBskcxfAsW6ZbBWFgTEw6nHJkL6zrMvfjBdztueNgwp9kerH5Adv6KHeg2KwM
         bYFdrxdkuBLTFL1OdJnhRMUwZTFDHoD+xAqlpkeXsNMCYWR32aHdfZri15za94Kvy/q2
         EbfT6mt2IB+KYZIFBVWyoYvPonXZirlPxeSBWmC/fnK9JK0buBeeHhybhIjr18RWKYri
         bRwFkmk79VRntWmisLmU/m/tQXNSvuRkJtWJT50W0S0TI09FOzxkyPTqLpYusXCFwH0q
         Ed7g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkSlK+bZ0+U5aOAsNQXIB5sRTelb5bbuiAMhbEdUZ1EjJzHFtUy9GT3kd/XsJgOWUm0xK+pw==@lfdr.de
X-Gm-Message-State: AOJu0YwQiYF7JVCEVExl/RSZrd6xVxl2J5mzuj3nwcq/XwNNXXkYxMTg
	A/RnxWBb0U7wwH4menFoBql7F6vRYWbccY8TlYGjiN4RPyVxR/oY
X-Google-Smtp-Source: AGHT+IG8dwLMWWiPUJ3cOsQJ0jViXG2rY+Yjy7JbC9qTSvtXIjr65e52BqUJTzx/ou4kTTcSSwTfig==
X-Received: by 2002:a05:600c:4712:b0:430:54a4:5b03 with SMTP id 5b1f17b1804b1-432df71bd0emr21203815e9.6.1731677386133;
        Fri, 15 Nov 2024 05:29:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4798:b0:430:5356:acb2 with SMTP id
 5b1f17b1804b1-432d9f01c98ls6979865e9.0.-pod-prod-08-eu; Fri, 15 Nov 2024
 05:29:44 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV0uNtkZmGyzORtVm1ulktMPYHKhjPa/XsS239W6qRI3QalRcmxeXBXmlISKn3ExkAWqi2CZLhGYuk=@googlegroups.com
X-Received: by 2002:a05:600c:4f10:b0:431:5c1c:71b6 with SMTP id 5b1f17b1804b1-432df74c8f1mr24896635e9.17.1731677384081;
        Fri, 15 Nov 2024 05:29:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731677384; cv=none;
        d=google.com; s=arc-20240605;
        b=DeuGbKhS9iisTHVsftSAJgyet56exlcjtJ8FErOsgSfcIT7Bcxp3B9F/HMR0X8f478
         88rwH/rIcsMJ9QoEzXkKVhLG5Wd0Svf3F0iVlHPRPTZa3wnvpUDe70WvMtAnykfdFDzN
         liVcJLskq/n2uT4eFVPh/YGH/xjcnqI0oyyizWhdNqsd6Wvr56BgBcEPSvIwzLcehpxL
         lIliZG/hFV08UqwCzovVlyB8fEG0Tw552i5tRmySHH0Lhbw9SYbrVJu0PY1gwrgoSurI
         Bv4z3RKOefPhiCPJfeyb2ScUudeMFVMAbBh23taKNnTrjviX0z3LehvMO5fzAuadI/yk
         CZVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=klW9mk1OBna+iR5vt4sj+lP9w1g7OCAAjSCAHllQfnw=;
        fh=dEvZUQRPbYkgbFISNGI9lCoJmcW8ztIBAW2MEf9y4i8=;
        b=Mz//7HNjAUouObzFieKpX6vzJtV5tzKWCN/pGM7dNU6BkJqIxRQpiC+mhEJ+cvEMXQ
         cVgzCHHfkR6uOAuOJsvbAwFB20p/yTlIr/meqz2DwEfwdJSunazEf8kNn0+piSqXzZJD
         AxKl/Y/aZY3TkMlCzFoP7a7fHFAdXy+pVqGJTPoz5JKvm4BBgXwXV2+s7EMwL5IbWGdv
         EblnYk0tVZ2gErlyUk5/tyAGvAbaaXG37I3zVEjD8GqfHKCnZRjOjDJCOgaT6sP7s1pn
         dRzUOk+KiOTtCSb4O8bRDCHWyVhzGujonR0Zp6QdJEHalfbaFWzjJRHqqYFW3KoGW9zE
         Rjjg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=eA8Yrwbx;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Bfopt31V;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432d4788319si3508605e9.0.2024.11.15.05.29.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 15 Nov 2024 05:29:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 583FE211D4;
	Fri, 15 Nov 2024 13:29:42 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 23B22134B8;
	Fri, 15 Nov 2024 13:29:42 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id tfBECMZMN2fQFAAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 15 Nov 2024 13:29:42 +0000
Message-ID: <95c1aedc-1bb3-480f-9c82-efc22d2beaf8@suse.cz>
Date: Fri, 15 Nov 2024 14:29:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 2/3] mm/slub: Improve redzone check and zeroing for
 krealloc()
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Danilo Krummrich <dakr@kernel.org>, Narasimhan.V@amd.com,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
References: <20241016154152.1376492-1-feng.tang@intel.com>
 <20241016154152.1376492-3-feng.tang@intel.com>
 <CAB=+i9QUC+zscxC6AuK9qUaD-Y9VmAv2-Ovqt8JRJJARWxZ-EQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <CAB=+i9QUC+zscxC6AuK9qUaD-Y9VmAv2-Ovqt8JRJJARWxZ-EQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Rspamd-Queue-Id: 583FE211D4
X-Spam-Level: 
X-Spamd-Result: default: False [-3.01 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_TO(0.00)[gmail.com,intel.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	RCPT_COUNT_TWELVE(0.00)[17];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FREEMAIL_CC(0.00)[linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,amd.com,kvack.org,googlegroups.com,vger.kernel.org];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,imap1.dmz-prg2.suse.org:helo,imap1.dmz-prg2.suse.org:rdns,suse.cz:email,suse.cz:dkim,suse.cz:mid];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from]
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Spam-Score: -3.01
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=eA8Yrwbx;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Bfopt31V;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/14/24 14:34, Hyeonggon Yoo wrote:
> On Thu, Oct 17, 2024 at 12:42=E2=80=AFAM Feng Tang <feng.tang@intel.com> =
wrote:
>>
>> For current krealloc(), one problem is its caller doesn't pass the old
>> request size, say the object is 64 bytes kmalloc one, but caller may
>> only requested 48 bytes. Then when krealloc() shrinks or grows in the
>> same object, or allocate a new bigger object, it lacks this 'original
>> size' information to do accurate data preserving or zeroing (when
>> __GFP_ZERO is set).
>>
>> Thus with slub debug redzone and object tracking enabled, parts of the
>> object after krealloc() might contain redzone data instead of zeroes,
>> which is violating the __GFP_ZERO guarantees. Good thing is in this
>> case, kmalloc caches do have this 'orig_size' feature. So solve the
>> problem by utilize 'org_size' to do accurate data zeroing and preserving=
.
>>
>> [Thanks to syzbot and V, Narasimhan for discovering kfence and big
>>  kmalloc related issues in early patch version]
>>
>> Suggested-by: Vlastimil Babka <vbabka@suse.cz>
>> Signed-off-by: Feng Tang <feng.tang@intel.com>
>> ---
>>  mm/slub.c | 84 +++++++++++++++++++++++++++++++++++++++----------------
>>  1 file changed, 60 insertions(+), 24 deletions(-)
>>
>> diff --git a/mm/slub.c b/mm/slub.c
>> index 1d348899f7a3..958f7af79fad 100644
>> --- a/mm/slub.c
>> +++ b/mm/slub.c
>> @@ -4718,34 +4718,66 @@ static __always_inline __realloc_size(2) void *
>>  __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>>  {
>>         void *ret;
>> -       size_t ks;
>> -
>> -       /* Check for double-free before calling ksize. */
>> -       if (likely(!ZERO_OR_NULL_PTR(p))) {
>> -               if (!kasan_check_byte(p))
>> -                       return NULL;
>> -               ks =3D ksize(p);
>> -       } else
>> -               ks =3D 0;
>> -
>> -       /* If the object still fits, repoison it precisely. */
>> -       if (ks >=3D new_size) {
>> -               /* Zero out spare memory. */
>> -               if (want_init_on_alloc(flags)) {
>> -                       kasan_disable_current();
>> +       size_t ks =3D 0;
>> +       int orig_size =3D 0;
>> +       struct kmem_cache *s =3D NULL;
>> +
>> +       /* Check for double-free. */
>> +       if (unlikely(ZERO_OR_NULL_PTR(p)))
>> +               goto alloc_new;
>=20
> nit: I think kasan_check_bytes() is the function that checks for double-f=
ree?

Hm yeah, moved the comment.

> Otherwise looks good to me,
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9=
5c1aedc-1bb3-480f-9c82-efc22d2beaf8%40suse.cz.
