Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBB4J5SGQMGQE2PCXJSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8454C476D3D
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 10:19:04 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id r10-20020a1c440a000000b003456b2594e0sf1437401wma.8
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 01:19:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639646344; cv=pass;
        d=google.com; s=arc-20160816;
        b=zLqv5NNUkc238RwHCgpaVsY09sLZ/nt+LynaeuHYriwytgarONP/BCx37o637MS3S3
         KFAf0yQp1d2cWWVT7v2a1EN06spmlCetJWng5MM3NIc6sUlUihPJKm2sr903Ldw+oO9/
         vEcZ+XXXg841IbRa+yDqsFutKMMjza12yr3zQWjvS56WIzCAOM1AuQHJJVj8D3m+Nhhq
         286rN4sGVX815QcS45noB33XSjK8stkVzQteUApijEn2sVC6WcY2H+dCOKUeFM3xEIjE
         D/rzfmnB8ZQyr3GZPuL9X+jA5WIRHtFO9FHZl7tGvpxUWf7lXN6rUz0H35/dsE9gGSvv
         0IPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=sxjYQHasa06X+1/pJTOQh6cLJKMJLAV1QwuOIOkfefs=;
        b=wLgpo+Nsv94A2rCji+XJdLJH8cz4BxxZjfUZcHvjDLc2e5y1NYEWAS0gmTxqbKuEPD
         0dzSyAkn8tbrI4iZnq/u6yHR1AVCMUKjg4etDpxfjGC1DlUHxwamEQcRO5Nh5cq9OBpt
         /6tYAoosI7FyQq7qR9By/a7zU5ZKPK0B9gV9EscShsw8v8naTc7dydkfNJKxltt8hICh
         UaoNA0Ggk/0h8IO4hD/4AoovnyNSYG3+mU8hPcdqad95GYpX739eWR5f9P4HCl8LzoEt
         Cuk2bZnWHaokFW7FZO77kVXaSZ2srbjDwclUbnRz9X91d58ky97q3Y0LceH1lv0WtfL6
         kPtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZYRquT7w;
       dkim=neutral (no key) header.i=@suse.cz header.b=9KCZzAFw;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sxjYQHasa06X+1/pJTOQh6cLJKMJLAV1QwuOIOkfefs=;
        b=jI7LrR1Yb2S0qYxFotZICCuAdWIyPGrnlR4tM5Qu12uIWBzz9+q7zuLEs38xpk1ojA
         sZbN7fkjVN7W180ZOTPl25ExzLDu7NAKCGrsx6xg/sp68qTnW0AZs8z9Mh6bXxeRpAvV
         86cXyupblQTQDtPsxAj69V13CXES5FVaqNlL0CpJdEStQSkH22chAw/2vLjdOu3Ir4y9
         hJyGqoFf8IDOcAshR0Ik33+6PVzNL5Ghf6z2qxSGhfShaGzomfxmOIxOv4Mji3HR6el5
         eKh/w/fAuEMJEYf0q24PTdFM5HhmuUWNYuhhO/kiXsejHTVGdumloX54KPNmB9xEfGpZ
         Ze/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sxjYQHasa06X+1/pJTOQh6cLJKMJLAV1QwuOIOkfefs=;
        b=2rE5seczDDAmNdZ53pexEMKLtprBtgltjzQPzKVYDuQ8OubLx2F7PCTPvT71wDL6Wb
         WX28y9HzifGlijwJilJmhlSXLvCNDn6TyJMjsmoxOs+7f2Zs9uXKY+Jl/f41SuV6dKGD
         YO3oF3X/+tJeHbv7ym9E5usZAjOUMopZ6/4induEXSArgJiGr9viU2knF053CNdKmWAK
         4QuTEGA3mkTwXOKs4VKRP2x0HGCw2L6KPF4e/DL40c475wWzyuKjMZpQVpad0CbShBW+
         72EdNQpsPE5n0f/4KMrGRW8Qx9T1U/TCwcZgEAhXva87spAXmzHZGawiSwV6OXbCp9yd
         /cVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532pAQgXLyaLNrWUBdc+4AyLiNfIWoEnWKXWFVRZKo+kZd6pJkov
	M0xm3xadCTkh2mU+YbEQ7tc=
X-Google-Smtp-Source: ABdhPJwF27wVanVaXfjwmwSGP30IJfxjreqqq3guDMRjSIYe2YMqPgPYnzsn5aiwDzzcKk33MHhpHg==
X-Received: by 2002:a5d:4c87:: with SMTP id z7mr8298855wrs.108.1639646344111;
        Thu, 16 Dec 2021 01:19:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls4754941wrb.2.gmail; Thu, 16 Dec
 2021 01:19:03 -0800 (PST)
X-Received: by 2002:a05:6000:1885:: with SMTP id a5mr8135550wri.258.1639646343078;
        Thu, 16 Dec 2021 01:19:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639646343; cv=none;
        d=google.com; s=arc-20160816;
        b=uArFylvI048WO302aXNRpDgWtkPoVtvRwI8jwUXDgmRVQAFIMOae5sMScswFQ0Zp49
         4XKoaNGJLTd82ar27StuM+fByLuywzUilhTPIdD5u/DD/XCQuaVqWTX+mMyv1UuMkdCF
         9L6f22QNaUBKVUbBx1LX78EMRKYkNy9c2mEEW9cScKMlC5ImXeUSBDZIpBkELEhyltth
         Nbpdvgs6rBuNU6A0p+HPX1O1YlwmTGHPUAs+DH73ejS6R9qIfBUm3dol1Kep+blH5W9M
         CdVLCjYUOtjrzYYB8UpQy4TQBKiAkuX8v567TzFmWfB4+uRYYNIkU0ihLgRIxdnlwtGq
         i0+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=rSmtMs4D/JMgdDSMfUX2HHXghuzhz3dXnYIHGOrCvIE=;
        b=ERGrqTVZG3CYGkwuBYueYUZdF4hMvtI9JPo1MnuwiVTcDYgYcbJ6JLMcOR1FlWXuBf
         gdZQuG2NE7Jc3ow4lKh0yo8HBJ3XJUq+1tlbPiPTbM+RoToZSC47AaCWEHiDEXwuJkCd
         XNXz/uNgFN3kO0+SukcZVxHb2b/E2gZDP+5fit+KAatiDvPZVy0bnyRk9ojDWhDpH96z
         HnZbFMMjCoJFzzOv4R1rQPwgz6Cl1RXdIAYcGHwLTADxkcKIP2CZ9m8qD915zjx1IS6a
         Fikf8p/6qxEsQDIzESRrBbeIpbxx4wOkt1AnLYKR1PKCl9WWQXV7TDvqF6SvOklUjUZy
         k6XQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=ZYRquT7w;
       dkim=neutral (no key) header.i=@suse.cz header.b=9KCZzAFw;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id a1si190776wrv.4.2021.12.16.01.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 16 Dec 2021 01:19:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 817CB1F45E;
	Thu, 16 Dec 2021 09:19:02 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 01F1E13C1F;
	Thu, 16 Dec 2021 09:19:01 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id taJdO4UEu2FwXQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Thu, 16 Dec 2021 09:19:01 +0000
Message-ID: <956d76e5-a319-7e3d-14b9-af5106b5333f@suse.cz>
Date: Thu, 16 Dec 2021 10:19:01 +0100
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
 header.i=@suse.cz header.s=susede2_rsa header.b=ZYRquT7w;       dkim=neutral
 (no key) header.i=@suse.cz header.b=9KCZzAFw;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
> On Tue, Dec 14, 2021 at 05:03:12PM -0800, Roman Gushchin wrote:
>> On Tue, Dec 14, 2021 at 01:57:22PM +0100, Vlastimil Babka wrote:
>> > On 12/1/21 19:14, Vlastimil Babka wrote:
>> > > Folks from non-slab subsystems are Cc'd only to patches affecting them, and
>> > > this cover letter.
>> > > 
>> > > Series also available in git, based on 5.16-rc3:
>> > > https://git.kernel.org/pub/scm/linux/kernel/git/vbabka/linux.git/log/?h=slab-struct_slab-v2r2
>> > 
>> > Pushed a new branch slab-struct-slab-v3r3 with accumulated fixes and small tweaks
>> > and a new patch from Hyeonggon Yoo on top. To avoid too much spam, here's a range diff:
>> 
>> Hi Vlastimil!
>> 
>> I've started to review this patchset (btw, a really nice work, I like
>> the resulting code way more). Because I'm looking at v3 and I don't have

Thanks a lot, Roman!

...

> 
> * mm/slab: Convert most struct page to struct slab by spatch
> 
> Another patch with the same title? Rebase error?
> 
> * mm/slab: Finish struct page to struct slab conversion
> 
> And this one too?

No, these are for mm/slab.c, the previous were for mm/slub.c :)

> 
> Thanks!
> 
> Roman

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/956d76e5-a319-7e3d-14b9-af5106b5333f%40suse.cz.
