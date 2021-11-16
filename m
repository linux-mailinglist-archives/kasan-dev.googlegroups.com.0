Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBWMB2GGAMGQEKW4JJJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F32F453CBC
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 00:38:01 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id r129-20020a1c4487000000b00333629ed22dsf1913230wma.6
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:38:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637105881; cv=pass;
        d=google.com; s=arc-20160816;
        b=eQWzPJU90234prxDQktFfKdgYzOI3BAGQVCCBG38EQXHqfh3j8788noFzliddA8A/k
         AZT1tjNNTQqAlGABKWGrfyk8wAn4hS0D0PUcATwyD+oawQD73CPcPIJnzkOc47jZq8QX
         xEPr/PDRo/cAdCUmWBM011SHteosAHZgKaGLzzau/3MGDVfV00IsJPiNqkbvj+Fq444b
         o7UnOxcx/t2r3ywdJdS5SKRaJ5dfevRT3UoblVNOXKAU4awEhPug6AZzZSfxSVMxFZC/
         nS8n6B/wBMwrEszyU+DgTz5aihqqMWSvrqitjvHyL4aRsSKq2G+j7FY72S3rPGHLInVA
         PF7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=EoUR9GfE2v38EfMGUq80lzVFbU734LKaNZXSO+zKo2w=;
        b=bdmx95RcK7M94w21K+q8RTNTrTip6Thn6wVdB6UxavY+bq5hA7MolhHYEhUnCIxGVL
         ahZHWnOhcLlaxRVZsUcVYG6CdKMtsw84tjcS9vpAk/c12SUfsDmdbAlNIkIuxCF8ma1y
         4XFGszzvdqCIZtq/Vi3PFNBqcvZSqMDw9KYss9fpf5qVjCXaGOey2NOCuYAEKgkxIR53
         jQ8za+iwvP2JPvKYVwDmm8RMEdvBlGDgg+a6/E2ep90hVYonfbm4upcfY3z/pcGG68wj
         L30L6l0y/yUB5rHsRBhPZRNA6WlUQOH2aOv/lzXlUzeYKXngC9cP6D0OmET8mHRkI1Pa
         M3Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o+YYhc6I;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EoUR9GfE2v38EfMGUq80lzVFbU734LKaNZXSO+zKo2w=;
        b=YQ18+3OoB0rk7PGHUDjCOpHxdxsHwddz9yh1bEWsrjWmBefGHa/ZxSrUWLZucs98OE
         N/nf/YA2yDJUCf4YZos0nb2LBfbxAcSBvLy5F2moENKp49ixS4eMit5NhzP24Z7+gQK4
         2HnD8kL9wCdskowwHhLk0h7lA1iYsw4ORFHtHNg+Vt1kfVhfwWGd6mM8huHpN+kWHBK/
         qI6zuXgWT0Uq/6LE1pjeaCX+1dvLlnQCeE8zUaMQLPVs/mDrq4oIR01kiNoNeaeywcwt
         slNNhJDS2lTn831wAggDLG472n9bReTOS4DRmKQn6465yIOKX4cTSGoUR4PJuA+NdZEg
         dOeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EoUR9GfE2v38EfMGUq80lzVFbU734LKaNZXSO+zKo2w=;
        b=x5exGWsWf7S18CKVbVFtdIj3VZrQfeIPHC0GSF2Tpp+L3x2zkyLX03La/O8MTrCOyk
         lXM+16ovAzK+UxiIRiN7VxjczmCzZaRgA5ONhgZcCf3VJOgO3m/5kBNIp/3qiLxwO70o
         rGdXDQNODVKhA3EK2ZelygK3HIlkalYeWZonY02n9kQZIsi+/tW5RswwVOVu8YAblU6X
         vh/qDMZOIZ4gTgjtNTUZpxUcJ2L20476zhTArovQiIlG8RgLStkUwtHDQtlqcJzaqBG6
         /MfPU5UtGdyA2VpyfMAAwHPU6dgjLTePlrTagLHBDFAIyGh/s6lQqHufHLTWZ7VvGNQT
         NJkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532svfgInSCd4M5kzcQHWrpZWUWWJ4qmYDt+bpswGyaDnfv7KEyy
	J8RbKcgpZa+VtFb8+qnelgA=
X-Google-Smtp-Source: ABdhPJzE54UItVwRnENu65v42ztIGPK/5k/QLlod8fzdTfM/sHSU9Vbd9aL0nNoNBz/w4yaAvqwGUA==
X-Received: by 2002:adf:f20f:: with SMTP id p15mr14122521wro.187.1637105881375;
        Tue, 16 Nov 2021 15:38:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1943:: with SMTP id 64ls1899393wmz.0.gmail; Tue, 16 Nov
 2021 15:38:00 -0800 (PST)
X-Received: by 2002:a7b:c8d5:: with SMTP id f21mr75296388wml.146.1637105880469;
        Tue, 16 Nov 2021 15:38:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637105880; cv=none;
        d=google.com; s=arc-20160816;
        b=lJkW4npVbVD2s9gNOjWigl19vQ2PCn06aQLe9OEzNsYYy3qwLwJZaccL0/ZRSwzOuT
         JMflAtVlHAiNpQ+PP98tvIDv9GVMkQqV5aLy8cZ5FweY7GV9Mz1svcYGzGYhnoZ1tMom
         jCEupmv3Fvm9S639zd4/Nd8Nfc6gph6+F7QDUOgROxBE/iRXSi5O5pB8GxBEO/p3sqDg
         MD/Hrbsr5Gvr5kVtxXMeQ2T0J36tXytZP2Jlqbesi2bwDYWmhPWcnYHQRc6HfopjbLs7
         ePQW0cWLY+IwWlcFwl0vd/DetfKWEx4Z7kA0hmRCULQfPi+7vyVWrfwlmZ4ASyp1TRuw
         1otQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=B5bLQ6GbPOxbu8UfgtnzISb6N4GArkk8FZZtgzRR1Pw=;
        b=SlI4ePhsTfTgrdQCBn1dc1JcuatDEA8XhjGN8edw2NMtPZ3CHUvCq9KtptpaRdzySk
         OmqZPJi+/mNMG0NsXB0tUBXlwYug8+QMTNlOTs0d1bJLJWR2ZMniXWqo86NhiuasZjJg
         aIcCJPL0PR4FiXVrPuZYK1rouFH4dlCLZnVOC7pkJPbDezNvqUe+Lpt6zTogKUwlPhYY
         8r1M3fO1H+SOCn84GA4arYLsUD0HgTcspJ8/jSsqkqMe+PVJPvBh/HtDWYJ8pnd46MSB
         2ro90nxHrsJ28ga6RjQ9v7BW1fjX7BeJnLbzKjYSqqobbrLTOVWMNcTmUQcgbjzA1WG4
         mgvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=o+YYhc6I;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id c2si432040wmq.2.2021.11.16.15.38.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Nov 2021 15:38:00 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 0B00A212C4;
	Tue, 16 Nov 2021 23:38:00 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 0A7D413C6A;
	Tue, 16 Nov 2021 23:37:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id U6uhFNZAlGFURQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Tue, 16 Nov 2021 23:37:58 +0000
Message-ID: <52923dbf-82f7-8e0d-dc82-cbead3a526d7@suse.cz>
Date: Wed, 17 Nov 2021 00:37:57 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.3.0
Subject: Re: [RFC PATCH 21/32] mm: Convert struct page to struct slab in
 functions used by other subsystems
Content-Language: en-US
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Matthew Wilcox <willy@infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Pekka Enberg <penberg@kernel.org>,
 Julia Lawall <julia.lawall@inria.fr>, Luis Chamberlain <mcgrof@kernel.org>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Michal Hocko <mhocko@kernel.org>, Vladimir Davydov <vdavydov.dev@gmail.com>,
 kasan-dev <kasan-dev@googlegroups.com>, cgroups@vger.kernel.org
References: <20211116001628.24216-1-vbabka@suse.cz>
 <20211116001628.24216-22-vbabka@suse.cz>
 <CA+fCnZd_39cEvP+ktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ@mail.gmail.com>
 <6866ad09-f765-0e8b-4821-8dbdc6d0f24e@suse.cz>
 <CA+fCnZcwti=hiPznPoMNWR-hvEOQbQRjEcDgnGbX+cb=kFa6sA@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <CA+fCnZcwti=hiPznPoMNWR-hvEOQbQRjEcDgnGbX+cb=kFa6sA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=o+YYhc6I;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/17/2021 12:04 AM, Andrey Konovalov wrote:
> On Tue, Nov 16, 2021 at 5:33 PM Vlastimil Babka <vbabka@suse.cz> wrote:
>>
>> On 11/16/21 15:02, Andrey Konovalov wrote:
>>>> --- a/mm/kasan/report.c
>>>> +++ b/mm/kasan/report.c
>>>> @@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
>>>>
>>>>         if (page && PageSlab(page)) {
>>>>                 struct kmem_cache *cache = page->slab_cache;
>>>> -               void *object = nearest_obj(cache, page, addr);
>>>> +               void *object = nearest_obj(cache, page_slab(page),      addr);
>>>
>>> The tab before addr should be a space. checkpatch should probably report this.
>>
>> Good catch, thanks. Note the tab is there already before this patch, it just
>> happened to appear identical to a single space before.
> 
> Ah, indeed. Free free to keep this as is to not pollute the patch. Thanks!

I will fix it up in patch 24/32 so that this one can stay purely autogenerated
and there's no extra pre-patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52923dbf-82f7-8e0d-dc82-cbead3a526d7%40suse.cz.
