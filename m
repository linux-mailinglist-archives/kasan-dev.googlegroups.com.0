Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBGNRQSHAMGQE66NRZAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 590ED47B656
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 00:58:18 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id p19-20020a19f113000000b00425930cf042sf3596295lfh.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 15:58:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640044698; cv=pass;
        d=google.com; s=arc-20160816;
        b=AaSG00qbKcbLXZTgLStKQh/aMvkPNWOKy5dBsJ8ky2xWRDH0W0aix8b+zLf4fHghb7
         75HzgiUo2+QQmiopszYXT9E8WxFDQH17flKwQy1JsM09nHjptTaZvyzCCCV0pUSs0wyo
         PrBN3pSoGA5I0hdjeaeJFfILOFKmUdimB7U4JlcmnxUWmKIMOoUjrfEcBWjhm66hrItx
         Uz/NKb+EJupX/FnDsO2RoMvHabj9DCx1p/zLoEFH+1pWNDzOwnbQ+Y7NgVtXY3fyfziy
         xjuu5+Pz0yK42vOyzmALGqa6n+bTFu2q++kVZXldQJJdmkVWs7AO9EYsCUWcKpUZd1EL
         W+pw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:subject:from:references
         :cc:to:content-language:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6Nylh6FZw5uDCpFRdoo6ftsdnZxfj7r3Zi11l1s66Rc=;
        b=u79J8cUb0J8ug7AT16UvT3FkImyxqCqkNPK/a390gGA2+fwH3CO/rlbBU/34epigal
         VYp0gJK7hdHPZJKwW2cjIzVsMKnYs8oUbz4w5nt0UZIRZ50krb7sgQ2HGz4k4tUj008D
         mRrvk+WMuJMiVjuw9EhB3a/vy21j78N/4Yw5RzcWkPsGxubyVKhx9OxwNLyqKpL8GEkX
         KxXyGm7x/UC9s9VuQ2WBKHZMs2wJfCcHIptAQ3V3l0RpypOIKShBwxm3UrXBnWQnFcKA
         hd2n8Ptie3glntH4tpFQsOZTUWzc9LKZGUKlGcLhWHCrxPvQyxt6WWOCusVG2oCmL2RP
         iq8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wJXxRniA;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:content-language:to
         :cc:references:from:subject:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6Nylh6FZw5uDCpFRdoo6ftsdnZxfj7r3Zi11l1s66Rc=;
        b=c7UBgcmqt5WOeDAqjWxjLp+JH0N4Ecj0opEyrXylZbBei+jeks08gGCGpREVLXYguf
         1fhKPmTftAuqVhMzNQVs3kA3uYiej41+YnrMLbruw5V5MnOxuJnykw5nrsnAh23/Imtl
         1y3x5kpVYzA6R1a/D7gAshUOz7DHSX1utCRoC1kMJgSr1m1vqV5m2rW/tGz7okg1Jhcj
         qwXytjuhSPTncji7MaolBNGawSFHQnyzMGXxlFp8SUPRkSEhmGV6JvPL5Uco6h4NfBZq
         TBxD7uIWqyOii+kJ7FOu5LNCCy1EfeO6zq1hjoapfBuMiRSZg8mhfh21dCPj+/qmdh4s
         VIXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :content-language:to:cc:references:from:subject:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6Nylh6FZw5uDCpFRdoo6ftsdnZxfj7r3Zi11l1s66Rc=;
        b=L9CXMB90rCBPmvaTCR+cXC0f1NFijQKbhaCD9IJbAX/z99WqUfNevd+Fjvblfa/17N
         FzCk7Ve/YZ93Ra4vYJQfFb2xqgDiNjQb4ewBzZ415WXTG9IVMHcWqeLPrynlJ2mKz6hP
         nprAJX1Oi5Txmj8lWAdB3sT5tY9RxOCCYYjT1K1f0rzscG4tf5yRXEje07AOpTWJcOkh
         7p7LP3enZ5vSLWa9r1hu58XtoB62KWxvWNeXFH8llSNLSeK8wes+4krRAsqsWO+QaXM/
         Otd11LzKV24sWUHmOPIPqAwXrUedrI12zFnwQRpvoKBF0wYDrOxNfgNUhQJIe4EIKofQ
         bRcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530bn2YK449IeAdxX+rYN3nkSVMhsyiStP+7gPqVNqhTW15DlJ6a
	n3N1EjZ6GbyDub4+vgEsi4Y=
X-Google-Smtp-Source: ABdhPJw17mfuSFuGvnM/IL1LxJ83uTenIPNCoxq2GGA5avCT/xG9EiepJpBq9KYoFi2VZxhGZgxo4A==
X-Received: by 2002:a05:651c:612:: with SMTP id k18mr417513lje.260.1640044697787;
        Mon, 20 Dec 2021 15:58:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3389:: with SMTP id h9ls926278lfg.2.gmail; Mon, 20
 Dec 2021 15:58:16 -0800 (PST)
X-Received: by 2002:a05:6512:2204:: with SMTP id h4mr531756lfu.315.1640044696687;
        Mon, 20 Dec 2021 15:58:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640044696; cv=none;
        d=google.com; s=arc-20160816;
        b=B2rthhEg9FNePl0wtK0XAo70mvyri3WjNsy6kWR9ZoKSETgdKLJvLGbsxUvFBFvPbt
         oOnZaoHYcUbFm6i8qPNqhg312BnPVFQzpO7oWAJ1t29zXj+GWZTZlRPTsiA1H8cWrVoF
         Szgl/melQ7VVUI1CEVDNBARXyuw8KUJGzSFfkkmBg8MqgWKplUw3dOrTRdotB9QLgKvo
         X1i4+lnyz69eM9kEWgYYlt1Bbxq0/pBAf960qgtlunOa1EeunDVbUvNHVWAiS37XYS/n
         tMvu0mAAqvvpyghA/zNrRa3G7YcHzUnFu+VLruVepP7V/QBmmk8YEumhexzljhsWMdU1
         Fc2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:subject:from:references:cc:to
         :content-language:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=NJEE0BI+qmu1Y2XQPzW4LyX87NylVjyFwU3a62yJMoM=;
        b=ztTZyXP4H/SxIkPqyteXtOh8adlTFekRL6Y1N/wef4vTMo8htB0lOQJy+fRJ0Eht9Q
         3pISIw2NgnEc2U2IIzCfRDo08eSu5BYQ1GYcViKINTQgtyMa0KyVVsg95k8t0fqljTTJ
         4eSzw+X5rfNmoJOmoy402h8NDoO9BXc7Y85NnLtMg5Qr5Zj8MF/OPlvBk7zhkyBGsmL0
         8M6exBJ3yuNL0nDD33CnOv/cbCjWTF0XI2SxtqQbaWVGmkGBm/nRAPhsxhUTRpLMFINo
         ebg/DiT9TAATmHUAovrbdQ/55mfmI18P9SwZW+5oWeBlVKwfA8aO2unwaf3Bidnb3wOw
         sXXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=wJXxRniA;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id d18si895163lfg.3.2021.12.20.15.58.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Dec 2021 15:58:16 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id D9C5D1F3B4;
	Mon, 20 Dec 2021 23:58:15 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 469C213BCC;
	Mon, 20 Dec 2021 23:58:15 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id C/mKEJcYwWFkfAAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Dec 2021 23:58:15 +0000
Message-ID: <38976607-b9f9-1bce-9db9-60c23da65d2e@suse.cz>
Date: Tue, 21 Dec 2021 00:58:14 +0100
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
 x86@kernel.org
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <YbtUmi5kkhmlXEB1@ip-172-31-30-232.ap-northeast-1.compute.internal>
From: Vlastimil Babka <vbabka@suse.cz>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
In-Reply-To: <YbtUmi5kkhmlXEB1@ip-172-31-30-232.ap-northeast-1.compute.internal>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=wJXxRniA;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.220.29 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 12/16/21 16:00, Hyeonggon Yoo wrote:
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
> Reviewing the whole patch series takes longer than I thought.
> I'll try to review and test rest of patches when I have time.
> 
> I added Tested-by if kernel builds okay and kselftests
> does not break the kernel on my machine.
> (with CONFIG_SLAB/SLUB/SLOB depending on the patch),

Thanks!

> Let me know me if you know better way to test a patch.

Testing on your machine is just fine.

> # mm/slub: Define struct slab fields for CONFIG_SLUB_CPU_PARTIAL only when enabled
> 
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> Comment:
> Works on both SLUB_CPU_PARTIAL and !SLUB_CPU_PARTIAL.
> btw, do we need slabs_cpu_partial attribute when we don't use
> cpu partials? (!SLUB_CPU_PARTIAL)

The sysfs attribute? Yeah we should be consistent to userspace expecting to
read it (even with zeroes), regardless of config.

> # mm/slub: Simplify struct slab slabs field definition
> Comment:
> 
> This is how struct page looks on the top of v3r3 branch:
> struct page {
> [...]
>                 struct {        /* slab, slob and slub */
>                         union {
>                                 struct list_head slab_list;
>                                 struct {        /* Partial pages */
>                                         struct page *next;
> #ifdef CONFIG_64BIT
>                                         int pages;      /* Nr of pages left */
> #else
>                                         short int pages;
> #endif
>                                 };
>                         };
> [...]
> 
> It's not consistent with struct slab.

Hm right. But as we don't actually use the struct page version anymore, and
it's not one of the fields checked by SLAB_MATCH(), we can ignore this.

> I think this is because "mm: Remove slab from struct page" was dropped.

That was just postponed until iommu changes are in. Matthew mentioned those
might be merged too, so that final cleanup will happen too and take care of
the discrepancy above, so no need for extra churn to address it speficially.

> Would you update some of patches?
> 
> # mm/sl*b: Differentiate struct slab fields by sl*b implementations
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Works SL[AUO]B on my machine and makes code much better.
> 
> # mm/slob: Convert SLOB to use struct slab and struct folio
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> It still works fine on SLOB.
> 
> # mm/slab: Convert kmem_getpages() and kmem_freepages() to struct slab
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> # mm/slub: Convert __free_slab() to use struct slab
> Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
> 
> Thanks,
> Hyeonggon.

Thanks again,
Vlastimil

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/38976607-b9f9-1bce-9db9-60c23da65d2e%40suse.cz.
