Return-Path: <kasan-dev+bncBDXYDPH3S4OBBXONRDEAMGQEAVLZS2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 575A3C1B479
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 15:38:23 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-639494bed86sf9319560a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 07:38:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761748702; cv=pass;
        d=google.com; s=arc-20240605;
        b=QUu2t6j4X6WL1tqXdiqrrEIBf2lZbqubS9MekqT1Sdf0L0hZwoADVWodDeAaTFlASA
         VORsQc0NvuG9goN4rbSMgGlJ5YPl7SQpcddINY+PHlxuuM0liQ/Ym21EF1k8+NT4uDti
         IkNG98T39DSzuwtWCsfQsaZFkuL3TxgMBMKWB9qbpFzIChmSUsUE3CA9Sd+GHEgS8SDv
         W2fHjbDLTPsKzt2k2ZpWL9JlH9zUXg1pOEFEU4jXPLnciYp0aTvyjpr5GQ/KQ4SOWj2/
         9izlF4lQ+r2wfRLk5hVyBJZPhsBQnpxmMjgTC43IU29oBFDXViEalJeHjjlZDIVNOjFh
         N0rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=BCZ3BfQjZFFSGQ7Xzw6X4qNKswOoDXbe+RwnCsme7aA=;
        fh=xgcmjb2RCqVCIC2iv/j+OTjiALktkvSjkv77xps5Ugw=;
        b=WuX8IlmhORXGOlu7GTrsm407QydZAuddu6uw9vBdIqmbabs9as/KBhfVUS2qGQoEOp
         Lx++dOBPbJ6KoRXlLOcCKIdwCMsAJpe8N9KewjZLhIbVWKgg7ry2p1wuQotUnmoWwSj9
         gnnKFT4NDEZslch6BdNKllzjwg8OnSBDhorH2Z5bh1Fy+Ku439g01PJob7g33lRmlLtw
         FDnYfe7hlPfOjWTkVWveRxIAJRhKXasSTfjehz9OI2ZMHHVIudlYRIPJjyPtsTXFsFrD
         ctDc4QRjT6WO6X1SUB2cikkirgirGmVyJeQI4Sgj8YXuc0dmxPwUBxMO+SHEIM4prEkU
         TcHw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dy2ejHyb;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dy2ejHyb;
       dkim=neutral (no key) header.i=@suse.cz header.b=YXvv7lfk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761748702; x=1762353502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BCZ3BfQjZFFSGQ7Xzw6X4qNKswOoDXbe+RwnCsme7aA=;
        b=e04UVKmxiUU7RCCzX1ChGR+osdPFBU6ghOaKNy5+OnVJVIq6jJ6stIAgVhfuW1MS3I
         q9OIShX039zncN3eLvGNd+kH3YtZu3LXDW9vdixr4sshmGynjXWTT0xsD4bJvVY3FUoz
         /0NPMh9NIVV4NgWKezw/9aPUcy4Pm5cal5QwCLMwE4Z7s5FUlU1QY9hpnRMtG18YtihG
         uYvNVdFq2bNTgCKB1lkuXYmHjSKJobDuf5nSUMpxHWBUhMFZt8B5lmx02W6VAISD1NPm
         dDPmCQZaOat2bFlvY7g+0LdUTsXwRQNbkWBqNBm+JL1zxGG8Rzd0p1Hc0taZgs0ZvqLR
         vxAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761748702; x=1762353502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BCZ3BfQjZFFSGQ7Xzw6X4qNKswOoDXbe+RwnCsme7aA=;
        b=B8BLm3GI8Ml6yZ+nrNlz3KYr36gAG0Yfa9ipFkEm/sGGEPBVzUbsUdbDsJFktP82UF
         WBnOOyF3I2jkm1NxHo5OPWT4yviDzDzkQ0AF4KnTYN4nX4zku8VMyW6QET457hwMJsht
         b0U2k/JjI6UpUwxEs8ABfCDbVr/xpEMYOCizoSNMiEtuE6Lh6Y64OyZP7nIhOo4dvDXe
         DIeFjys/c40bH79j3z6HCkIBPu02W9tcZ/qRWPInT9b3npt6sB6twXwEtlLU4zHSuB7k
         sdgB94SnKJ64rYPHV9zL+jfabzBa8zb/nzjGZ2WAsScjulcey3T6655JtZzO7L96tiAV
         WqLw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXGfqIwxmo+IRvqVhEmHLfL3A3HLL0A5yDjTP4uk7hqrrIS4eIlcj/L/imjGz0e9yEmatIQpg==@lfdr.de
X-Gm-Message-State: AOJu0YxlLn2fI894z3/2ot7BgNGfCH1rM7rH5JoPuZsGRzGdIawq2O0i
	JIWF97idprW/Ns4WaThmV8/Jhp5ZGRksYC43/B4pCfRY91rIc69XF7PT
X-Google-Smtp-Source: AGHT+IHgaHXyUyNj6WLwGd19q0reSyAOkA5FUkLIKNf8dSHKUevVTNVXbS+yGjmfBjHhtJVHcHdEPQ==
X-Received: by 2002:a05:6402:51cc:b0:63a:5d3:6a1e with SMTP id 4fb4d7f45d1cf-6404439820fmr2623331a12.33.1761748702476;
        Wed, 29 Oct 2025 07:38:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+av+yZ+a4K4qB9dLuRUMFCer8ZgJuP04k1Hy9PbCG/iig=="
Received: by 2002:a05:6402:5343:10b0:63f:b547:f3b7 with SMTP id
 4fb4d7f45d1cf-63fb547f45els1988570a12.2.-pod-prod-03-eu; Wed, 29 Oct 2025
 07:38:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX56Q1rO5EAnWx87oKrBJ/5M0PlT/wb3iQ7DEpAoxwIn0/9AOyxh4o8hUY+WOu3Zg47g8P5nEag0xI=@googlegroups.com
X-Received: by 2002:a05:6402:4311:b0:63c:1362:47fb with SMTP id 4fb4d7f45d1cf-640441af13fmr2555255a12.2.1761748699393;
        Wed, 29 Oct 2025 07:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761748699; cv=none;
        d=google.com; s=arc-20240605;
        b=Z0FvJ6+4JLfnLl0SmFz8rQo0dKPnErG7NdjO93UOtsMS/4MDHtPmxXTADSw1r7iCg+
         Q9Qo04sGpQ1fqBWFzotPqxbVMB+kRfIiwK/bEngHR+OkouT1KKHSw8+wkkUPGieYNW6c
         fEZiWI2+8VZGOWMrpUss+nrSYOcNcFpRA453tYuU6EOQGIMHSEsyiD5wbBatiQ29/JVk
         oBVBY0+bQZOklLFoI+XZieKzgpZjaajydemKlnpeGg2JZp9YGXVBdFEi0ryEiDctT/RA
         ITvBxhzQlllJXvMBz5gu0xE5B7LtP7XrCXSEwPhEa4y1jsVHnrsDWZdUhmIzV3fIdm8e
         7ykQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=/w3MRB+TOS2yBG8/nTaTk+4AfwEGJiuVEcv9DVs4O0w=;
        fh=l6wz2fEWB5WfXPoiFWXPOzZGMlLpyfp6bj3soYdhj10=;
        b=jQMtTV0M5jzjjRnTTxa2FYgIPawG+w4WBUAn/Fqh/LoqmDDuQW0PWNadahG/MKONxt
         Ptr1jNKmuISNB2APfg2KOIQWdYI9+0HrEY67N6uzL2CcSVp9CgVkitKo/Hvj4PUM+H3P
         og/Nok+vSDmSJGKi7P9oSzWwZn1WQ/XGk6sUygJzRuBAHKbKITd4fIz8Tw1M7Vgn/g6l
         saXxAhUuG9tzAsprPHPVNUoJRyRXFohLBAod0dHEnsUjw6gF7hy527UT8ieXXRCg4JRV
         MiQOI04leSIGYIBAJPIbBA85w19ztU8uKc4M5GWxu0kBDrAsNaB591FbeBDO1ITHD1Qs
         BVtg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dy2ejHyb;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Dy2ejHyb;
       dkim=neutral (no key) header.i=@suse.cz header.b=YXvv7lfk;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-63e8147e937si411566a12.3.2025.10.29.07.38.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 07:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id B80E020E00;
	Wed, 29 Oct 2025 14:38:18 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 9980F1349D;
	Wed, 29 Oct 2025 14:38:18 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id TG6wJNomAmldPgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Oct 2025 14:38:18 +0000
Message-ID: <0f630d2a-3057-49f7-a505-f16866e1ed08@suse.cz>
Date: Wed, 29 Oct 2025 15:38:18 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC 01/19] slab: move kfence_alloc() out of internal bulk
 alloc
Content-Language: en-US
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>,
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>,
 Uladzislau Rezki <urezki@gmail.com>,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Suren Baghdasaryan <surenb@google.com>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 bpf@vger.kernel.org, kasan-dev@googlegroups.com,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-1-6ffa2c9941c0@suse.cz>
 <CANpmjNM06dVYKrraAb-XfF02u8+Jnh-rA5rhCEws4XLqVxdfWg@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 m6M14QORSWTLRg==
In-Reply-To: <CANpmjNM06dVYKrraAb-XfF02u8+Jnh-rA5rhCEws4XLqVxdfWg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Queue-Id: B80E020E00
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,gentwo.org,google.com,linux.dev,oracle.com,gmail.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Dy2ejHyb;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=Dy2ejHyb;       dkim=neutral (no key)
 header.i=@suse.cz header.b=YXvv7lfk;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 10/23/25 17:20, Marco Elver wrote:
> On Thu, 23 Oct 2025 at 15:53, Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
>> allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
>> but it's conceptually the wrong layer, as KFENCE allocations should only
>> happen when objects are actually handed out from slab to its users.
>>
>> Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
>> object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
>> was refilled with KFENCE objects. Continuing like this would also
>> complicate the upcoming sheaf refill changes.
>>
>> Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
>> to the places that return slab objects to users. slab_alloc_node() is
>> already covered (see above). Add kfence_alloc() to
>> kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
>> prefilled sheafs, with a comment that the caller should not expect the
>> sheaf size to decrease after every allocation because of this
>> possibility.
>>
>> For kmem_cache_alloc_bulk() implement a different strategy to handle
>> KFENCE upfront and rely on internal batched operations afterwards.
>> Assume there will be at most once KFENCE allocation per bulk allocation
>> and then assign its index in the array of objects randomly.
>>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Marco Elver <elver@google.com>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
>> ---
>> @@ -7457,6 +7458,20 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>         if (unlikely(!s))
>>                 return 0;
>>
>> +       /*
>> +        * to make things simpler, only assume at most once kfence allocated
>> +        * object per bulk allocation and choose its index randomly
>> +        */

Here's a comment...

>> +       kfence_obj = kfence_alloc(s, s->object_size, flags);
>> +
>> +       if (unlikely(kfence_obj)) {
>> +               if (unlikely(size == 1)) {
>> +                       p[0] = kfence_obj;
>> +                       goto out;
>> +               }
>> +               size--;
>> +       }
>> +
>>         if (s->cpu_sheaves)
>>                 i = alloc_from_pcs_bulk(s, size, p);
>>
>> @@ -7468,10 +7483,23 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache *s, gfp_t flags, size_t size,
>>                 if (unlikely(__kmem_cache_alloc_bulk(s, flags, size - i, p + i) == 0)) {
>>                         if (i > 0)
>>                                 __kmem_cache_free_bulk(s, i, p);
>> +                       if (kfence_obj)
>> +                               __kfence_free(kfence_obj);
>>                         return 0;
>>                 }
>>         }
>>
>> +       if (unlikely(kfence_obj)) {
> 
> Might be nice to briefly write a comment here in code as well instead
> of having to dig through the commit logs.

... is the one above enough? The commit log doesn't have much more on this
aspect. Or what would you add?

> The tests still pass? (CONFIG_KFENCE_KUNIT_TEST=y)

They do.

Thanks,
Vlastimil

>> +               int idx = get_random_u32_below(size + 1);
>> +
>> +               if (idx != size)
>> +                       p[size] = p[idx];
>> +               p[idx] = kfence_obj;
>> +
>> +               size++;
>> +       }
>> +
>> +out:
>>         /*
>>          * memcg and kmem_cache debug support and memory initialization.
>>          * Done outside of the IRQ disabled fastpath loop.
>>
>> --
>> 2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0f630d2a-3057-49f7-a505-f16866e1ed08%40suse.cz.
