Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBYPDYSVQMGQE4VGR2BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D1E9807EEB
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Dec 2023 03:45:55 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-58db4b9a52esf287382eaf.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 18:45:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701917154; cv=pass;
        d=google.com; s=arc-20160816;
        b=VUwpx5YxKf1XBU9MHajxANXLBfEU75JVEHLQy3r1q1aV1KgyK/O9jI0rXgyt2RvAzF
         6pwHoiSUFc3UR58xmGr5jwS5tGAs/HwYH0QD12AW7sf1fsDsUWNMtQiqoQvYrGfBDZIi
         7heHY52G7ZTAIFznfi54m2xDX5FB/QsyxA8OOMNcbxTVB64LxIX9HjVDN5DjW8dMnwcV
         /cx09fBeBBcj84vvZm51i9fYYNI39keyvkmUCqPQa462wrIiSvNCsg5SxjrPPtoYLFc9
         lz0F2MhSfnqs3DjkMNT9HrEiJsmmfcqLoKttI03somBE7jZXQvfcybOGkXoB4KhRqvGQ
         ZbXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=UTTAFw6BHIw2MeR0uPKY23Dc5cqu7z9EPuD4FWbtTCc=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=u4IuuiuC3Ay3a3ew4fUt0BweD8v46zK9iByTCms2o8MA/Odd20nPFf9+5vkXkTonIx
         c+hMTAZGduyGTgnX2imGCKnBZV/2kvYEB3c5/sJU/6Q00n8tA/9lcJirkwEkgH8bwhqT
         9HPA60rp13LTN/QbhFHWIRu75Ye3Cau11NX1Vrr5Wn1COBkHTmOH1s+Jg+YlYU8orHS4
         pGAzOeSO/od+VuASqFMWjJBrfAjdJrcUV1sm5zRv549Dwofq/koypc1+Pocgkb2vGd5z
         WJTIq2BmtuQSdT8xmh//9etz8so0QZDb2os3MbFT1hKmnpihFUcaaIOqdfNdRmBRRgyz
         qlog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FiFbDQm1;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701917154; x=1702521954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UTTAFw6BHIw2MeR0uPKY23Dc5cqu7z9EPuD4FWbtTCc=;
        b=msn2bOhdHmvFgJ/V50ztxVOOA1BvXe0wphtTHfrYbbCM9r8YhG0/c35GXeBxTue7P6
         420kwVlsOdsAgBMohneLy/63GVyLVAEl0h7N+t8458lUWxDSRM1YoeQmqa26dO8oxxKT
         H2YqaehufJRJGTUeehsJ1k+xGEoQQ5MHAIfI/ME5f+65Ky6kxSRuBOaEYl0ClwqY0WEq
         0q3uFP6mF8lPqIGdYa0PtVPGIz8vzO+kMxFuRJnx5svxWg+tXxue+eQgp+x/FihCiMs6
         XTeH6vnaKmnvT+9XaNTx4gv2KNfE+7S8Lo9yc3oMscoJoulANYiJ2XSt6Cmyv8oN2ROM
         ndiQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701917154; x=1702521954; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=UTTAFw6BHIw2MeR0uPKY23Dc5cqu7z9EPuD4FWbtTCc=;
        b=Y6WMK4UoIRKMjkmA82W39U6OolfuLovusoWn0hKenALZEnp0HNTdapUhyXH0JY1GKA
         lY9MmDNrr9LS8rShjgFSakTS36s+BsqwqduCZdBrIH03cyqKPTi9aGHJYEH21Y4HGX4b
         AvL4YbrnA4N63ocIDDlNM1XTFcspArTgcUzkL60WO7RA39EFQLoLz2v32+E3DrG9WWlg
         IaMHWR/3YbjQITY+d37ICRaQBWKRR4+Ao04a4j7dJLzet02ZAVJZpbuMSZUlU9xcie0j
         q7C+oS5pW4w3wj/9VQh1kWIrJaxWAxRUuD91Anwl5VHuynNwrGZVUkpUIx8cksXYFFlR
         gxxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701917154; x=1702521954;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UTTAFw6BHIw2MeR0uPKY23Dc5cqu7z9EPuD4FWbtTCc=;
        b=B5UQX6ZYUww9OBpm63EH6CWWv8izmJWFuPPxk9sQ4fr0N+Im8V/V6f4APGnNONQR/f
         DW+773UwItMEjHnbk6ADP6fg6LI8Tl9hvKhDXoQpIr1OJOo8APXqEwNJ+Hv6nTNq22SR
         UwFRpO+hO8R1AkY8voQ4iQ1Ml3LbTDEttYFMsfXazVTvfZ1jyIym1sNTIHwtxky88xja
         4jQ+VXGnqn6SFZiIWp1kjw8Eru834M6S6nLjDWSN2KK+Cx4SkSYNGAz2knMwlCP4X+Ds
         68ffHZnpHfm/O1iSQ+XPbOEcK1MScw40tvMAmTpyiSHkT7aoiMHf0oyC+oRqAJtEzCUX
         R7gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw65E0KoAmmREoXh6RW3B4OJmY3L955/9Gb+Msfdfn5BLUhtgRK
	+aAqSVNqorAQGEC6XgSY81g=
X-Google-Smtp-Source: AGHT+IHdJVhbFvPaK6Li+TwawQ7d4qbYRlct6tAmnnNSzWUPUXgCw1te/kxYV2i3cXDosdRBjZ7Fpw==
X-Received: by 2002:a4a:e4d4:0:b0:58e:1ac9:79c8 with SMTP id w20-20020a4ae4d4000000b0058e1ac979c8mr2114724oov.0.1701917153971;
        Wed, 06 Dec 2023 18:45:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1ac8:b0:58d:be41:d25a with SMTP id
 bu8-20020a0568201ac800b0058dbe41d25als378536oob.2.-pod-prod-00-us; Wed, 06
 Dec 2023 18:45:53 -0800 (PST)
X-Received: by 2002:a4a:d0b2:0:b0:590:6d8f:fcee with SMTP id t18-20020a4ad0b2000000b005906d8ffceemr245955oor.8.1701917153208;
        Wed, 06 Dec 2023 18:45:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701917153; cv=none;
        d=google.com; s=arc-20160816;
        b=pVDsAHb7Mdy5i9PWguOSV1lvj0r3W4DkUbV97FtefTNd49ZKCcDC3dxv8PJjeFFh1W
         q2ucVzxxcdqjRdOrmK+2V4XYM6qU0g1cwUi40eIvE7pwsaXTU5Zm5lVTe/ha0r+FURSC
         Bhwuxji+GNAWJrNHrM8DgQs2OmakdVddBcLutltezAIDLJsCO4jlEGbC91p6F7wroI/F
         Gb4Y3H2sAeWcPxSAYauqB7Qm+J3SOsRBRUQqtU7nzmHBU5fZO1gZFdjIqtR9ZLClt4GL
         3v8lkUlg2xt4nJWV2SKoBAB4cFxYaXfaSfuTqEIaPnaU3wGs4zy08/EehIwwPAitms0b
         HNcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8eVcl2KDPJ4smMer/60vC6K9DZX/lHwn01b8AXePVZA=;
        fh=2r5aaXXmN8Cw+jz/mFF4Be4bCeBgMfrMSyfH8yhLbGA=;
        b=MwgNzuGa7RLVvAfmRa38BA77p/TIQJEgkvweS8+2iCxi2jgxiOxYxvpm6aTXrN1VZ4
         wSVvzApzhLjRjekzAvzWUGaG8tL6qItd1LWGXHWm6B0Nti9Kv/JsLoXZZv1pRBkasa7P
         /h3bDi/cfwy/9DbjF2zpxoQLVvjfixF+6FdhA6xHLTidETRa1kffQasDEzHWcE8CdgSQ
         diUZTksr25FvBXh+G7nb95bQrR+ciZyA3GJcbpYmHfxN2wwo2kb2sDNNYu3iCyp1Y7+k
         ws42uGxQ+sW93U34MXI2aYwjNAfEmsjn38AnhXuNV92XpbRWvA3dnNPL4JvkG7ztBf+a
         ikbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FiFbDQm1;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id y4-20020a4acb84000000b0058ddf7336a4si46971ooq.2.2023.12.06.18.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 18:45:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d2e1a72fcca58-6ce6d926f76so133862b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 18:45:53 -0800 (PST)
X-Received: by 2002:a05:6a21:170f:b0:18f:9c4:d33c with SMTP id nv15-20020a056a21170f00b0018f09c4d33cmr4986434pzb.44.1701917152256;
        Wed, 06 Dec 2023 18:45:52 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id p24-20020a639518000000b005c676beba08sm177028pgd.65.2023.12.06.18.45.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Dec 2023 18:45:51 -0800 (PST)
Date: Thu, 7 Dec 2023 11:45:43 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org,
	Michal Hocko <mhocko@suse.com>
Subject: Re: [PATCH v2 00/21] remove the SLAB allocator
Message-ID: <ZXEx1/p9ejRmkVTS@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FiFbDQm1;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::42c
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Nov 20, 2023 at 07:34:11PM +0100, Vlastimil Babka wrote:
> Changes from v1:
> - Added new Patch 01 to fix up kernel docs build (thanks Marco Elver)
> - Additional changes to Kconfig user visible texts in Patch 02 (thanks Kees
>   Cook)
> - Whitespace fixes and other fixups (thanks Kees)
> 
> The SLAB allocator has been deprecated since 6.5 and nobody has objected
> so far. As we agreed at LSF/MM, we should wait with the removal until
> the next LTS kernel is released. This is now determined to be 6.6, and
> we just missed 6.7, so now we can aim for 6.8 and start exposing the
> removal to linux-next during the 6.7 cycle. If nothing substantial pops
> up, will start including this in slab-next later this week.

I've been testing this for a few weeks on my testing system,
It passed a set of mm and slab tests on various SLUB configurations.

For the series, feel free to add:
Tested-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Thanks!

> To keep the series reasonably sized and not pull in people from other
> subsystems than mm and closely related ones, I didn't attempt to remove
> every trace of unnecessary reference to dead config options in external
> areas, nor in the defconfigs. Such cleanups can be sent to and handled
> by respective maintainers after this is merged.
> 
> Instead I have added some patches aimed to reap some immediate benefits
> of the removal, mainly by not having to split some fastpath code between
> slab_common.c and slub.c anymore. But that is also not an exhaustive
> effort and I expect more cleanups and optimizations will follow later.
> 
> Patch 09 updates CREDITS for the removed mm/slab.c. Please point out if
> I missed someone not yet credited.
> 
> Git version: https://git.kernel.org/vbabka/l/slab-remove-slab-v2r1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZXEx1/p9ejRmkVTS%40localhost.localdomain.
