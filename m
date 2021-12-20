Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBVU276GQMGQEAQWQMQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF7EC47A316
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 01:24:55 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id j9-20020a05651231c900b004037efe9fddsf3686269lfe.18
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Dec 2021 16:24:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639959895; cv=pass;
        d=google.com; s=arc-20160816;
        b=PU17OzVe/U25t3HuuCdEUT/zig+Bf6dG7zI67loFWXHt14Mtu0iquPVbN7xlBj96tB
         PcAKAqK0TWInu7+T7NkFbOPoqr6fNDm8GkJQM0lN7BIMyX+2SZgn5Oq3B3NhL6/9QbxT
         1esrsX1hGRJWLAHJQtnbrkCEjD33HaJHDMkIrNUMFSMBqw9qwTqG1Ts6bP0sjuBZNFAi
         XgGsa3wMjNwEvaj+0miGOOmRfEzWOJwaz7q4161lLXQLbHyl2CtZYl0x/U6+M7TNdOco
         O6G056MUDX9sCjHrPzvdgKNGhVf+i+7F8KkpfKrF1MEByeQNWEd8kKflGk/f1WG3yVVN
         kfqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=f9GNv6eUgcpVdxGqAnTYubk9WBwbZsHpGQjVXyLKmok=;
        b=Y/B7mAGSuyb3IUcmQX2AwWtu5aydpcsWlWbcafbbw7b0zmVK4FqoAxKdMru1XBXEXU
         kLsnR5yFimJSfyWMF3sOeuWl+QONVzNi9FbOJdYCejAehruEWFtxk86hoVDMLq21c7FD
         bccrWPkU75+0kZop9h1nZrhAAhKBmVIpkG2QxWUMeoZbLY+aq+ArnZ8FsT30OOm7ucGA
         1RbKfLuP1Zj5l66kJlw26/6mZmZGhHuRl3Ka1ReseCJBs0CihB8R4T4we8by7KpKbH3u
         9U+DGO63qE8tDuFe1KvDZW1df+bbGLKLPbA/bPELCZ7M9Pplp/Hex4dOelU8Y0p0Mbu3
         ns3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EFlINYyd;
       dkim=neutral (no key) header.i=@suse.cz header.b=en4PMr7J;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=f9GNv6eUgcpVdxGqAnTYubk9WBwbZsHpGQjVXyLKmok=;
        b=pkvTP5pMDro0NxbQ4PUp+4ArDKXQO56FjtRbtn32FALgZacY+lq9N0Bp/WaengBXn7
         GvqPjwOE2gKWeU1VpFyjtDMjgY7QRM1veND61nw2rnVLQjw2p5BA9f5kWgAxKDLFBse2
         ZKGwl3Zz/VFWyMwCgtVDNzDPFg0FFPKUgTq05WcN09W2FzYZ5qpIvBkR72fFooPOc2ud
         uSH5q15Bx6PCq3eeqj35FhZsZ7gJmO0cLTylGvCPT0mlw5esSRhQqUa2G58D9CdiECRh
         RBVkhfkZqVpANs+KOgkoXWIjPL/o6YKretCiXni1P7RzXVQ4rmg+HF+JfNspdv0e2dyN
         TC9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=f9GNv6eUgcpVdxGqAnTYubk9WBwbZsHpGQjVXyLKmok=;
        b=j1Nmj8f+4XpUNFQC1+45WlMdYAiNncmHqiykeQBph2yKu79FPyfgPr29VNfyW/J5Zd
         IcYPyvwcZLYmhxQP/2IrppCb0EcyXH4gWneV6r12FlI1m4GlTgd2vpFi021dx5/E0t+i
         gxnMpIwbbkOSaDGVMyTFIjX+c/3ELNVL0PCEJCbpIAhZuyfNj8GtuQhHJwQxzM9tTXGC
         Y+HA8H5eUu6uLG1FncRjG1SgTpN3vfDHG/H0lzzGfqkgIfYOstSnPQ4Vz/ZjaKNYhFEu
         RaYTdeHxo7c3nEnsETtrpuhTGm2BnlLZcgHIiTjT9+xkOwT9SJoLxzsf4UQdGFQIS2Z8
         rzPQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530dJTPbgEnCpM5B7WaCtz0vdmh1iPg0/GsFcUa+3SmfCQXyX3R8
	PSOPbYObbzIkaYYfuHAx62k=
X-Google-Smtp-Source: ABdhPJz/ZATSZ6cfvHauZmnGMZr+7Qs7kQs4FL/3XXRPzNNLWCl9V6aiwlrSE1CtOJM/ewr2S8Ttlw==
X-Received: by 2002:a2e:920a:: with SMTP id k10mr12411705ljg.234.1639959895059;
        Sun, 19 Dec 2021 16:24:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1258289lfu.0.gmail; Sun,
 19 Dec 2021 16:24:54 -0800 (PST)
X-Received: by 2002:ac2:5319:: with SMTP id c25mr13987439lfh.153.1639959893887;
        Sun, 19 Dec 2021 16:24:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639959893; cv=none;
        d=google.com; s=arc-20160816;
        b=wMmLDap8+5CyvgbRKZgRPp22xXUxloYviz1D5y/cgB/RKFMNZjdJmnb3yhF9wT2DoB
         QS/oxm3HIZBKffJB/CU8MFOEQp3ERMYs16AhmoBs13b0JEG6l6owgaGBNbXmWQLZoihK
         +HE3y8aS46QqthiIA2GjQJ7qzNTGzODOAR+EQ4wq4WsLSZ1iV2iBh7fZqm5UfkQ27mQh
         //YIIvPSWjsgao6/MIG+khVUOTWlaLMFilM8cPCeFQPdtOEAGPb1udbXfZbDz20l68eE
         NYkMTlxq8j7ePljdm5+ij20d4jzlGcSjCNXBYrcVULoGf7VLqMJrnj8kt5WSaCQK9Krt
         V1fA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=QS/OCdCcmeiC9lIu10Q6seQIOyuScTvbNIZyhMByFhM=;
        b=wRtXhQ0RZxGDFdjAMUhDqmVvBcItTb426VDjD80y1CCyV3QoHCk3/H3S3lVkTEbyay
         ufJatqPdkvr2vB5ZwNuKJ9Od1/8ZpfI3W/ccnct10G6Gm8E1u73UGEkjujJit8sH7Mp/
         iEoUBnkvoHoX8rS78YoegWPXq05Q++LzfOwgvcCfraclOxtPktaReXazixAKouaNIC9C
         NrTqkmp3ZcJ5/lhRlhTp5Vu+3wqt8/o0FHTpHpL/tUI1vfczczRg54BMmsXA8it0rsE/
         7OFQlr3dB/f3jYx2pl97hSv69HbBHO9nf9KvJq2a4m/U5kyF2PAkllqjZOqPhcJC6x6F
         GCww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=EFlINYyd;
       dkim=neutral (no key) header.i=@suse.cz header.b=en4PMr7J;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id v8si761056ljh.8.2021.12.19.16.24.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 19 Dec 2021 16:24:53 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id ED29B2113A;
	Mon, 20 Dec 2021 00:24:52 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6E3BB133A7;
	Mon, 20 Dec 2021 00:24:52 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id lRYvGlTNv2HrZwAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Dec 2021 00:24:52 +0000
Message-ID: <b94c2530-0f17-11c4-e3ef-effc6b7f0d33@suse.cz>
Date: Mon, 20 Dec 2021 01:24:52 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
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
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
In-Reply-To: <Ybk+0LKrsAJatILE@carbon.dhcp.thefacebook.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=EFlINYyd;       dkim=neutral
 (no key) header.i=@suse.cz header.b=en4PMr7J;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/15/21 02:03, Roman Gushchin wrote:
> On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
>> On 12/1/21 19:14, Vlastimil Babka wrote:
>> > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>> > this cover letter.
>> > 
>> > Series also available in git, based on 5.16-rc3:
>> > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
>> 
>> Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
>> and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
> 
> Hi Vlastimil!
> 
> I've started to review this patchset (btw, a really nice work, I like
> the resulting code way more). Because I'm looking at v3 and I don't have
> the whole v2 in my mailbox, here is what I've now:

Thanks a lot, Roman!

> * mm: add virt_to_folio() and folio_address()
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slab: Dissolve slab_map_pages() in its caller
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm/slub: Make object_err() static
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Split slab into its own type
> 1) Shouldn't SLAB_MATCH() macro use struct folio instead of struct page for the
> comparison?

Folio doesn't have define most of the fields, and matching some to page and
others to folio seems like unnecessary complication. Maybe as part of the
final struct page cleanup when the slab fields are gone from struct page,
the rest could all be in folio - I'll check once we get there.

> 2) page_slab() is used only in kasan and only in one place, so maybe it's better
> to not introduce it as a generic helper?

Yeah that's the case after the series, but as part of the incremental steps,
page_slab() gets used in many places. I'll consider removing it on top though.

> Other than that
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Add account_slab() and unaccount_slab()
> 1) maybe change the title to convert/replace instead of add?

Done.

> 2) maybe move later changes to memcg_alloc_page_obj_cgroups() to this patch?

Maybe possible, but that would distort the series more than I'd like to at
this rc6 time.

> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Convert virt_to_cache() to use struct slab
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Convert __ksize() to struct slab
> It looks like certain parts of __ksize() can be merged between slab, slub and slob?
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> * mm: Use struct slab in kmem_obj_info()
> Reviewed-by: Roman Gushchin <guro@fb.com>
> 
> 
> I'll try to finish reviewing the patchset until the  end of the week.
> 
> Thanks!
> 
> Roman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b94c2530-0f17-11c4-e3ef-effc6b7f0d33%40suse.cz.
