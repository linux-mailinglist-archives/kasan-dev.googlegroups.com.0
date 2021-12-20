Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBPFF76GQMGQE57THNRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id BC0B647A31C
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 01:47:56 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id f13-20020adfe90d000000b001a15c110077sf3042584wrm.8
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Dec 2021 16:47:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639961276; cv=pass;
        d=google.com; s=arc-20160816;
        b=UMJjWxhkNDFLhe+S3HVp+MfKkeqiqNV17xxsc1uyOECpgv+REW4haMXZyPm5c5hWch
         NLl3BRbYFAulKqIdlf1tMNVfM2uG+sl9vWJ4AgGixxPS7YkuRgOgWHgjZasMyE9x/3cY
         QiXrGT27KAIt7dGDfbq8omCdjRfSezFoltWk0228i/psloMZPr72oYyFa+wE5hOcdag1
         0hvbNvL8d9vVUv9ATwbDvAT38jcigR6MVSVpRxDRsW28/wGo3RNn3ZW/N0KEMEAsGBkZ
         Wo8PNqwHmkWOG1IydaIM7zRxCj0FS/HsX1KEKWr7DwmEussizpwYNfrfemlWsxdhIUfJ
         dk/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=zAWBlfuEPZFO5F///lxRO2N1+uL2/6QwhW4ePTyEGGM=;
        b=qT+163/WaRk/azsIxmmbjrMCFvWs7B/nrqZ4LkuwSbNlVNrUZD9+S3ZQi8pd9cz7Ct
         7L9QRTSky4Ul7CJIbk31wFRQvOfb223Ib/nZZn3mtiLmf9xQHiXaWH5c662LB4oy1+n2
         XDiXtEXac+iS1eQv17/pNZ5JEdSyipEcEvjOXudE93SbfMFNxNtQhOcv5+y1CAjTuZbQ
         0JlbjyyKWMDXR+7LqJS3OHmLVywsd/A8FoofjysxIRdjJpW3EDi0o/GFxNTtd+R2ULpi
         scjkiUyMYON01QNNbZwA+n4mKGnAEaRjHZ/DlvuuM1Zsuz2/ZtAhCvEQw2L8WWoXExa1
         6n3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bXsxoOzc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=d+lrN53w;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zAWBlfuEPZFO5F///lxRO2N1+uL2/6QwhW4ePTyEGGM=;
        b=YjAgBYl0xiaVNWwZD0m3wnc4r/9qYyWNNkhk7nf7h7b8Ikh2j9sV+V5wjVC5/ezo1K
         cmTJvYyW1iKa3GFINjxMD2aa7k8/RCW2VLaRnZzfgdf+BHrixUrBksvRrkh7cguoBmoe
         e1XnMKo4688LWj/sks2OC1WPdkzgwBcdpAFZdFfLHiX17uWXb17SnLcyXoOGxFpbga/2
         uIg60WFrgiqGbBVjU5shgW45MywiHOn+IMqHbLKi2SfpKO+IAVB4AGCCKjxZJRAt5q/D
         o8MgIupis9pFZGji2KMLV6XJxEg9P3/qaBmUF0roJzAHkNOf6sAFgAtt0pKOyntYcxMC
         80pg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zAWBlfuEPZFO5F///lxRO2N1+uL2/6QwhW4ePTyEGGM=;
        b=AqVmx5z73/aaEWEsy9IspqjFsfSirboq3CTH2f3NYSbu60tbD2e7WC/ns1pJwweU4U
         3eIEG/Bb2HOuOI0rsxjRmUcazL8IpfN5u3LgCT2lM/e+KYP/cDw8+OcMkjbOD/HOG4fS
         DoxLXi+rNd6NjA/HzrMs/hdJvFufu1NUTp2x5RYHbuK3VX71AD7A2EtUUrb8bv2y9FB+
         jIEOZs3RObH5Omu+KlsTxrQvm14Canal2U1lqe/9745kyLsTwy6ztMfRbQ6eJMgep7AI
         kUtqiWTOyf/ZKbYXB9oxY81vnIS26+91tkHv6jt2wFKP3XRxNvvJr4WE2WVe68hKvJjf
         iSgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531K00F3ohuoWY157unnCQh4zykyQ1PoCN6XraiaY6mWTWzf7WaF
	Tsjd4OpTyNfmPaeXy+V0pcY=
X-Google-Smtp-Source: ABdhPJz3vMB9cGWQMtG3PFf2pfYdoGDPP/JDUrfDZhslgZeWAhl1QhXo6R5eldmxKqX9aoe/SGV3kg==
X-Received: by 2002:a05:600c:3583:: with SMTP id p3mr12019030wmq.180.1639961276395;
        Sun, 19 Dec 2021 16:47:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca47:: with SMTP id m7ls2424586wml.3.gmail; Sun, 19 Dec
 2021 16:47:55 -0800 (PST)
X-Received: by 2002:a7b:c40e:: with SMTP id k14mr11350782wmi.128.1639961275510;
        Sun, 19 Dec 2021 16:47:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639961275; cv=none;
        d=google.com; s=arc-20160816;
        b=hHeh+dXljHXpGqHwcJVQZQSF78vLuvd1vJTO7fJcMulOdUItsA/iKpMFZFyO7H3pcJ
         SDZAh5L1gLf6ENWJCkUR+jlDWnDSUCoHNiuyL2AAkRfyNnT4xjEDmiTMsYYHGyjsMhX7
         a4sL9oAAiMC3NOad0yUGQ/DWwv6hhReft7X+kuFBVb+BA9FQJNBigAjxkbJAxmdbkz85
         qwiptpOEgGPPyntbMrsXPHaKZfb/d/SG3zoc8bB7pbDNHmYYAtE1v/UyfB7ZwpB3qfjK
         kNPB2ZBP02SvviauiDTRignxKQyPGGLCa5M+yX17Xfic1jGBTXnlbHKFAwE7HrtxwYrA
         FCtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=GljbjGESLyxg+ngLc7mhGY1oQBxex2sK+C5XSkEFVyI=;
        b=PiDsIODy381jfJtA9iOVJRypsj0rA8ERYMwYYwJqiBE5oD0Xg35wdKvy7iePKnEQoS
         JSKH7aEqwOruVLgwyST8Pi8ep8EAVt78rN9618xuv9WjL9Xl3HWZHvFRPedYlwA7kRv9
         KQIDOBbwNHeN4Zlh6fjPijAF+v64NB+ZRuFgm3V1LFyg8TprRd63OzZFvOpQGLJHdWxm
         DduoZgxHp1Z+nUKx0uugTyP4DLhNUEd1XEmK8tpSHpISSiPHR99y/cswvQMag9hGLmUp
         /BoaZ00PpvUyvRkuAPcuud5uTMqqG7wI4EkqJDZldbBLy4gpIpXaq90HKTuB0R+8w7Di
         Agsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=bXsxoOzc;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=d+lrN53w;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id c13si42279wri.7.2021.12.19.16.47.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 19 Dec 2021 16:47:55 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0BED61F395;
	Mon, 20 Dec 2021 00:47:55 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 66B78133A7;
	Mon, 20 Dec 2021 00:47:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id yFyaF7rSv2HcbQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Dec 2021 00:47:54 +0000
Message-ID: <86617be0-8aa8-67d2-08bd-1e06c3d12785@suse.cz>
Date: Mon, 20 Dec 2021 01:47:54 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Content-Language: en-US
To: Roman Gushchin <guro@fb.com>
Cc: Matthew Wilcox <willy@infradead.org>, Christoph Lameter <cl@linux.com>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
 Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andy Lutomirski <luto@kernel.org>,
 Borislav Petkov <bp@alien8.de>, cgroups@vger.kernel.org,
 Dave Hansen <dave.hansen@linux.intel.com>,
 David Woodhouse <dwmw2@infradead.org>, Dmitry Vyukov <dvyukov@google.com>,
 "H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
 iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
 Johannes Weiner <hannes@cmpxchg.org>, Julia Lawall <julia.lawall@inria.fr>,
 kasan-dev@googlegroups.com, Lu Baolu <baolu.lu@linux.intel.com>,
 Luis Chamberlain <mcgrof@kernel.org>, Marco Elver <elver@google.com>,
 Michal Hocko <mhocko@kernel.org>, Minchan Kim <minchan@kernel.org>,
 Nitin Gupta <ngupta@vflare.org>, Peter Zijlstra <peterz@infradead.org>,
 Sergey Senozhatsky <senozhatsky@chromium.org>,
 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
 Thomas Gleixner <tglx@linutronix.de>,
 Vladimir Davydov <vdavydov.dev@gmail.com>, Will Deacon <will@kernel.org>,
 x86@kernel.org, Hyeonggon Yoo <42.hyeyoo@gmail.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <Ybk+0LKrsAJatILE@carbon.dhcp.thefacebook.com>
 <Ybp8a5JNndgCLy2w@carbon.dhcp.thefacebook.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <Ybp8a5JNndgCLy2w@carbon.dhcp.thefacebook.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=bXsxoOzc;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=d+lrN53w;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/16/21 00:38, Roman Gushchin wrote:
> Part 2:
> 
> * mm: Convert check_heap_object() to use struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert detached_freelist to use a struct slab
> How about to convert free_nonslab_page() to free_nonslab_folio()?
> And maybe rename it to something like free_large_kmalloc()?
> If I'm not missing something, large kmallocs is the only way how we can end up
> there with a !slab folio/page.

Good point, thanks! But did at as part of the following patch, where it fits
logically better.

> * mm/slub: Convert kfree() to use a struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>

Didn't add your tag because of the addition of free_large_kmalloc() change.

> * mm/slub: Convert __slab_lock() and __slab_unlock() to struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert print_page_info() to print_slab_info()
> Do we really need to explicitly convert slab_folio()'s result to (struct folio *)?

Unfortunately yes, as long as folio_flags() don't take const struct folio *,
which will need some yak shaving.

> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert alloc_slab_page() to return a struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert __free_slab() to use struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert pfmemalloc_match() to take a struct slab
> Cool! Removing pfmemalloc_unsafe() is really nice.
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Convert most struct page to struct slab by spatch
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Finish struct page to struct slab conversion
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>

Thanks again!

> * mm/slab: Convert most struct page to struct slab by spatch
> 
> Another patch with the same title? Rebase error?
> 
> * mm/slab: Finish struct page to struct slab conversion
> 
> And this one too?
> 
> 
> Thanks!
> 
> Roman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/86617be0-8aa8-67d2-08bd-1e06c3d12785%40suse.cz.
