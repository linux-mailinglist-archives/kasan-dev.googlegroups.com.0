Return-Path: <kasan-dev+bncBCM2HQW3QYHRBQFVTWHAMGQEROWDDRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id E1DA247F42F
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Dec 2021 18:54:08 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id k11-20020a05651c0a0b00b0022dc4d55f14sf165724ljq.22
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Dec 2021 09:54:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640454848; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3ALiaQi2JHvuxF4+4Xb/EgVJfG9yRgJEQwEe63PJ7i7TBMqXWSM2Oi/YbpJax2fig
         i+y4QMPkT3pqpb8X/pvY3uuu8KI0ftrZSyThLV1oKpJN4cXsoSEYLgmFVHlTwHr6z/wp
         udWwSu3A4sS6IrfysYjPaXS7qYpYEo+hiwY8EV/FHMcHu0tgcm00EWPEdGTSeVAPS8oM
         3r7qrFlElkPZQmwjJoOxUI0vbDQrR53yFCSMzelPQDAzmwpGqx0CHshwt+xNbSgTUUad
         hzoE4MtWPqXBlqNEuWpBx4C7VK6DeOZcH6a9NcVnmWYQarVLVIIZrWZgnM/6a8kukCJL
         mOFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZDGwnoDDlzVPUg5Wcp/RLynHGK59OniYkOb4uH21GS8=;
        b=m1Ubmpl0fw8zS4cYcBqg7fI37mcSmsUtpk0h9wLjh0nXEGwgBCuPkVHE9QBnBHkHWd
         PRav8FIzuq4SCdUY5FJ73UNovLZSG+Ip6lIiWLgf8U4gvZaPkg7XwkC/091Vrf0GgtLX
         tUQzy1TS7jdsA3Y9SbmYH4rqvIZeocH6WsYuP9ITitVIeO1HLmQ1rHkzvo5S0qzfKirM
         PVK0tZN+rujMEJwBEDVqcMU8Pyisk4ZvNhdxMym7SECnLyGEHPlQWAO7CnkUgANYTzjd
         gYB5Jmxp+ISNBTQfXgAvOyJ1TlfslbBAV5r1oxLveaE6Xld3Xv75LZCaXFURIIkNWoUP
         XVvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=P8eHkVOb;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZDGwnoDDlzVPUg5Wcp/RLynHGK59OniYkOb4uH21GS8=;
        b=DfNZmRzSIg/FJFYo+HE6tvqvM5g+Dzn3wCWCa1Eoe3Pgqwju9u/ImnRa/aCWuOm+q3
         iaR0cxHCTASm55y33qag/rwfSOIDue22FxPXgnItSf6nRSA3BjdVfzIjpKzEU92etWCB
         9nTZL77CScw7ck+iQwX6GckSMkWTCCpS0RzlWLsTfskUx3YWZPBNQL6hNieZflD1hMqN
         VVRF/YwhQk8PNuAUYdPujJYFJIbiL+Rrv0oQLWDbxknhCv9Rw5Hz7LBapZSY2j2aHXR6
         9WT8oG7meDQPzl0yxZylLuipnyR4asTn9shVuWG9A4GR8gK/AblFMB55wx7mcKsnWHdt
         aFSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZDGwnoDDlzVPUg5Wcp/RLynHGK59OniYkOb4uH21GS8=;
        b=2raw+vYbDkyFfbt62M8aYcO8q2Kptx647ffqKMFJ9cL0Et72LSi06E9H+aKGCCTNgm
         p2wfxJtFX5hbDF/S82FfkUX5E73PhAWFWeorAtSXC9q1H4GqVEqVfYYV9JMQzxJtAOmF
         qC5oltbU9z48lM0s/CJ9tZqePv+otgnyCd+fQ4nSguzTNHcI2vEfVSN/MuE/VTdv/678
         nTkiJBDdk+rTh+bMamkRUCv6bzwBgCWxrWuN/kKCfHhmUF/HJa3O8gP18buPP9LLa4qG
         IEmyaVE/J+UEAfQ/E3HyRnLrv556KOZhZYu3WhhuWy/YHFProXol4EHqPlYI6wOvsNhK
         LaWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zHvT52/S0m6GdZVnndPA/X7Mb1s/4GJxYIgtl2MZucJIIgX9Z
	wyeGxYT9eCi9ojpiZMJCMjE=
X-Google-Smtp-Source: ABdhPJyzcz2dMkiaeJhrbXKiiXAbLBZLeKxrPQHEDPDIGPpaI69rxq1jZQ6isbGHjdWtLEY/xnmHiw==
X-Received: by 2002:a05:651c:24b:: with SMTP id x11mr7375777ljn.422.1640454848229;
        Sat, 25 Dec 2021 09:54:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf18:: with SMTP id c24ls1457842ljr.10.gmail; Sat, 25
 Dec 2021 09:54:07 -0800 (PST)
X-Received: by 2002:a2e:a7d6:: with SMTP id x22mr1273073ljp.76.1640454847264;
        Sat, 25 Dec 2021 09:54:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640454847; cv=none;
        d=google.com; s=arc-20160816;
        b=rXgzDowr1d0VWGX87baIs1Z9syyz3mnYEmxNhcAYyzcp5LYFglrWL2yTSJxlEjnxQu
         ItePs4lf25navm6bQjscOno65PjczpanAd68Qm/ruVHlZR5iCl1TmbJHI4UlgBAGyBGr
         PNdV+GKdMz2SqfUc4gTOfAlXFWTUi7MC2kJgzaUM2xC9XDbFX54fwgyUThVplETt4hx4
         bJsjUJOL5bBlIqk3YKqwFEMsD/FsdM11tWbetOSBYtkvoKhzRrJnJnPPv2OTVq9tnTI2
         QXVSXcPmCKqy+OcRpQrlG6dFmsNslpJlS6wzTUmEO3K3Glp8veQzy41/hcNnPFwBNuqd
         y0Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DsB14TIFCiBAdP7rD7EHBmZ2vEchTQE1iQvq9NRvB9w=;
        b=U/9JrdoVRIWf3mforxI8X5Dk4kVAdMlH0NKmUjsu8nEbjZQyACAILrXq4d4pxdkCSo
         XU0yz5zTGbAYhcVajd7d/FfNV3xPp4HllfUwcLgtPleKHkXwZO8ua9/jgWB5VVakytpd
         0RmeW3nlY/COo7JDaCGe43AX6RWL8GHdJk6RM2boL4msXFeFYxa5bai9PnxfDpmTVMm2
         vnZMsz1dOP+4fnbVzcsM5ZpkV6QQFEgYG8FqUi4pry2nfRaA/dTJ37ZSG1jTEbjHdz6p
         C2WC+9CNey354Ubj2JyXuZfuyySzRAjBdJnVDXnCwsTnfHKF9+NoqKe1dPwkjyrtFGar
         tbaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=P8eHkVOb;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id w24si242733ljh.6.2021.12.25.09.54.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 25 Dec 2021 09:54:06 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1n1BER-005yjd-Ai; Sat, 25 Dec 2021 17:53:23 +0000
Date: Sat, 25 Dec 2021 17:53:23 +0000
From: Matthew Wilcox <willy@infradead.org>
To: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Pekka Enberg <penberg@kernel.org>, linux-mm@kvack.org,
	Andrew Morton <akpm@linux-foundation.org>, patches@lists.linux.dev,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
	cgroups@vger.kernel.org, Dave Hansen <dave.hansen@linux.intel.com>,
	David Woodhouse <dwmw2@infradead.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>, Ingo Molnar <mingo@redhat.com>,
	iommu@lists.linux-foundation.org, Joerg Roedel <joro@8bytes.org>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Julia Lawall <julia.lawall@inria.fr>, kasan-dev@googlegroups.com,
	Lu Baolu <baolu.lu@linux.intel.com>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@kernel.org>,
	Minchan Kim <minchan@kernel.org>, Nitin Gupta <ngupta@vflare.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vladimir Davydov <vdavydov.dev@gmail.com>,
	Will Deacon <will@kernel.org>, x86@kernel.org,
	Roman Gushchin <guro@fb.com>
Subject: Re: [PATCH v2 00/33] Separate struct slab from struct page
Message-ID: <Ycdak5J48i7CGkHU@casper.infradead.org>
References: <20211201181510.18784-1-vbabka@suse.cz>
 <4c3dfdfa-2e19-a9a7-7945-3d75bc87ca05@suse.cz>
 <f3a83708-3f3c-a634-7bee-dcfcaaa7f36e@suse.cz>
 <Ycbhh5n8TBODWHR+@ip-172-31-30-232.ap-northeast-1.compute.internal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <Ycbhh5n8TBODWHR+@ip-172-31-30-232.ap-northeast-1.compute.internal>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=P8eHkVOb;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Sat, Dec 25, 2021 at 09:16:55AM +0000, Hyeonggon Yoo wrote:
> # mm: Convert struct page to struct slab in functions used by other subsystems
> I'm not familiar with kasan, but to ask:
> Does ____kasan_slab_free detect invalid free if someone frees
> an object that is not allocated from slab?
> 
> @@ -341,7 +341,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
> -       if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
> +       if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
>             object)) {
>                 kasan_report_invalid_free(tagged_object, ip);
>                 return true;
> 
> I'm asking this because virt_to_slab() will return NULL if folio_test_slab()
> returns false. That will cause NULL pointer dereference in nearest_obj.
> I don't think this change is intended.

You need to track down how this could happen.  As far as I can tell,
it's always called when we know the object is part of a slab.  That's
where the cachep pointer is deduced from.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Ycdak5J48i7CGkHU%40casper.infradead.org.
