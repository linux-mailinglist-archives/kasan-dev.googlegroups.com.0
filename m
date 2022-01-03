Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBSHRZSHAMGQECIU65ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D0E7483671
	for <lists+kasan-dev@lfdr.de>; Mon,  3 Jan 2022 18:56:25 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id r20-20020a2eb894000000b0021a4e932846sf11486484ljp.6
        for <lists+kasan-dev@lfdr.de>; Mon, 03 Jan 2022 09:56:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1641232585; cv=pass;
        d=google.com; s=arc-20160816;
        b=YfQ4KEDxviZ5Aypm7mWqDML75Pnt5OpfCGGwGvbG17YAlkM0MMo5tfR1eCMvwJgSsf
         EuB+7O9nLyuZkUdSmzxWcDwkzd0U6MqhCELcIK/rH8c47brdJTeLicdaoDE83amXrf5+
         L5U+QwP2c3DEQVDR9gdEb7B2KFA1QGQXrf4NLH2isz+f3LAEwewgR3oM3bpSSer3BR7q
         XOICNrvehRsig/4GM/GRli9SISDIlHR9w4RON5Kf6fJrwSD520IYr1WUQtV3HgEeb1jX
         YHcARmxLObb1Kw60rQ3rY+HbyaM74ipAh8g+4vq75dmqh/R4I7KqJgYCBQDpixQtqSil
         VPlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=k9YpkSgdLvBitrjw/9JfY8/ME+37yQiHsYoREJ/quWQ=;
        b=rng/12rnJIomgi8jU81YSo7BAK1iA68PvhC2NYu02hPoVyk+7/BoZV8bCRNep6X0XY
         bKwT/eDCAVyksRbxOpbKxjDaBgoB+xiXNUN2HYMwVbAhAyyed4JTdPfZaSTSscbzhQRI
         lNmLTRUQK/zBAYUI6ccw7qJBJ84sC1ttxS90T1PvHHhbchWLDIYEawT16T2REF+R5eWi
         ZTjl7vaSiqDA5Ep3UvI8QJ9v7S6nhGBzdsux6U8LSasOa3y80VQIllvdoEDQuxsPwGnX
         j21cpzTg4t+Cv8tLq5kOXAr7/1glk889u5YbR/C6iSQ/0Qa9bdV8twoCDkXBR0Hjiv+y
         1q4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RhtzrMx8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=t8qwh7PK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k9YpkSgdLvBitrjw/9JfY8/ME+37yQiHsYoREJ/quWQ=;
        b=lldNgfRNKrpietBJfMs6boISX4BeCzAhX/s7cITCyjrqqW/1PFepzOENNZ4ortN+UK
         vpkf9JDzCuX82E+FDWIGqLxaBoygfoWI0VJIoRttI6a5E9Y9r5NmRbcdJWPPYQ8FOI9I
         +mkYrD0rkOL8nT5XbF86hPMjJ4Iuw1lSZuLvDSHZv6GAOU9ueQhTU6KuvirbbNhq+pL6
         2t4TsYOX9D2K14nCgnG0a+MEaH/YywsPHIWGdRf6TKS+bo67qNo2qibQP09wpg6+0Mbl
         ab2nKSc9s5qXBaYjSYfkw5rKu1ueCvqRJ7tpB/JnQJo5tkqlO4MD3tTdwV/aTwnii7En
         Evbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=k9YpkSgdLvBitrjw/9JfY8/ME+37yQiHsYoREJ/quWQ=;
        b=iGtAqhHm2Y2q2Erl1uUttDikOZphKBvVKlEehx+E24oxVv4VgGe3Z+pG6dYA0bPibK
         LmO3MiZlJLedEDJWwV9PvctwODeXqwpKXOpG0HKUYMLXsKOYRCYzHp+wTLnnJ1l9GSs6
         z4f2Agx3n6+YLl6Ow9nnYMG/R6eSpUwI67k41CM9X6Z4ktJDXDz16zHfA9vmufygl7g6
         Ky6WrvCiMuBeMFdq42iKY2beI1Okml8AvzIQUf8Lk6CkghX1UZFro4kTtbEPy6xiuDun
         O0zdFD1zm20PQOj6zERUFbeg4VgndnaQSTd1yVYcfPqFJsK0viAAMYAE29ETewDHhyuV
         +NPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ltfMpMUE9X66lD37Fk42f/lWvhLDVekKUZ4wZ0iHS/EwJcFOv
	x4ba2ocBwhABeodXxqMBsto=
X-Google-Smtp-Source: ABdhPJwRiKCkaLDIAgAXVoTGKsd0nPSs8Q+IldFlJFnNiboXkRZhWShVwUxSdbd2gIzu/ocgfdaHYA==
X-Received: by 2002:a2e:b043:: with SMTP id d3mr33855182ljl.415.1641232584930;
        Mon, 03 Jan 2022 09:56:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1112:: with SMTP id l18ls3345295lfg.1.gmail; Mon,
 03 Jan 2022 09:56:23 -0800 (PST)
X-Received: by 2002:a19:5019:: with SMTP id e25mr42224218lfb.254.1641232583810;
        Mon, 03 Jan 2022 09:56:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1641232583; cv=none;
        d=google.com; s=arc-20160816;
        b=E2Yth3vD/x+CD0oYr1xNqNAIHO6NM+lCG7gENXfAWjexKK2FAMK5mov40b44NrBFLi
         1/3hG6xEBCq4Cpo8xYcSpg3A/G53lixKccIL7nZTJPs66pkoSPjZr3dEDSiqSFZYpV7T
         ljj2ujBoo3kVBAVdHHaYxm7GeEeru4oH5+fqRUhRNb7m3QTYlfjfq9cWD3UJ4w3Okbmc
         EhAOPtbcq+NNcxxxDus4Srh2U8mGS5tKCZE/hDebNE5PzzOt9+w7+drKI22w0ESsqAhd
         3LlCrlemL9U14Jz1qdYHQ9ZyF+cAFSPvtXWWvKMxwl2z2w3KezmbekKqEbjXvFixZOKd
         u96w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=CWXmfQBKbsotJ+DKTiOu/dBjpnMA9AO60pYklnpK268=;
        b=DmqtUn0FhCVU+cqJzJi7S6CXFGMj7Kx45UMxs8nN3N926o9kP3YjEn9LyYZC9Y6NIY
         khRHd93wOEJLL6z4huyYVVC5LNUtrsm0uDknM6BlMSDZ2Xs1V0S9I/JTyuWzMZS37CXK
         V8fqm3SbVAjvR7qIrzZen0MLXhYNKRUSQLu558gLKCuvmFrN1ItmnDnWbi1OT3M8jf0V
         PMm8Y4CCM/HO+uKOdLOGrQlXzAoBx4HZsyZWSRLeYL75wYTzZUg3/mxnEZrT/Ls8as0Q
         N+2ONv1vxl8ZDZSK4nfdJI/RPvODvpz1f8aGgx5ZkPJZfGLYxrfQsM7MxFuXb0/9KAt/
         yGKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=RhtzrMx8;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=t8qwh7PK;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id x32si1818714lfu.8.2022.01.03.09.56.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 03 Jan 2022 09:56:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CFB7D21108;
	Mon,  3 Jan 2022 17:56:22 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 40BC413B0C;
	Mon,  3 Jan 2022 17:56:22 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id Wx1+DsY402GiJQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 03 Jan 2022 17:56:22 +0000
Message-ID: <d3f0e9ef-7d21-8de6-5b15-116f39c2aca3@suse.cz>
Date: Mon, 3 Jan 2022 18:56:21 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.4.0
Content-Language: en-US
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
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
 x86@kernel.org, Roman Gushchin <guro@fb.com>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
 <YcxFDuPXlTwrPSPk@ip-172-31-30-232.ap-northeast-1.compute.internal>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
In-Reply-To: <YcxFDuPXlTwrPSPk@ip-172-31-30-232.ap-northeast-1.compute.internal>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=RhtzrMx8;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=t8qwh7PK;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/29/21 12:22, Hyeonggon Yoo wrote:
> On Wed, Dec 22, 2021 at 05:56:50PM +0100, Vlastimil Babka wrote:
>> On 12/14/21 13:57, Vlastimil Babka wrote:
>> > On 12/1/21 19:14, Vlastimil Babka wrote:
>> >> Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>> >> this cover letter.
>> >>
>> >> Series also available in git, based on 5.16-rc3:
>> >> https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
>> > 
>> > Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
>> > and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
>> 
>> Hi, I've pushed another update branch slab-struct_slab-v4r1, and also to
>> -next. I've shortened git commit log lines to make checkpatch happier,
>> so no range-diff as it would be too long. I believe it would be useless
>> spam to post the whole series now, shortly before xmas, so I will do it
>> at rc8 time, to hopefully collect remaining reviews. But if anyone wants
>> a mailed version, I can do that.
>>
> 
> Hello Matthew and Vlastimil.
> it's part 3 of review.
> 
> # mm: Convert struct page to struct slab in functions used by other subsystems
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> 
> # mm/slub: Convert most struct page to struct slab by spatch
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> with a question below.
> 
> -static int check_slab(struct kmem_cache *s, struct page *page)
> +static int check_slab(struct kmem_cache *s, struct slab *slab)
>  {
>         int maxobj;
>  
> -       if (!PageSlab(page)) {
> -               slab_err(s, page, "Not a valid slab page");
> +       if (!folio_test_slab(slab_folio(slab))) {
> +               slab_err(s, slab, "Not a valid slab page");
>                 return 0;
>         }
> 
> Can't we guarantee that struct slab * always points to a slab?

Normally, yes.

> for struct page * it can be !PageSlab(page) because struct page *
> can be other than slab. but struct slab * can only be slab
> unlike struct page. code will be simpler if we guarantee that
> struct slab * always points to a slab (or NULL).

That's what the code does indeed. But check_slab() is called as part of
various consistency checks, so there we on purpose question all assumptions
in order to find a bug (e.g. memory corruption) - such as a page that's
still on the list of slabs while it was already freed and reused and thus
e.g. lacks the slab page flag.

But it's nice how using struct slab makes such a check immediately stand out
as suspicious, right?

> # mm/slub: Convert pfmemalloc_match() to take a struct slab
> It's confusing to me because the original pfmemalloc_match() is removed
> and pfmemalloc_match_unsafe() was renamed to pfmemalloc_match() and
> converted to use slab_test_pfmemalloc() helper.
> 
> But I agree with the resulting code. so:
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> 
> # mm/slub: Convert alloc_slab_page() to return a struct slab
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> 
> # mm/slub: Convert print_page_info() to print_slab_info()
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> I hope to review rest of patches in a week.

Thanks for your reviews/tests!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d3f0e9ef-7d21-8de6-5b15-116f39c2aca3%40suse.cz.
