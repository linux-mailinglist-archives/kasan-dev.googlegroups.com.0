Return-Path: <kasan-dev+bncBDX4HWEMTEBRBHUPTWAAMGQEA5ZISBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ED6E2FC1A9
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 21:57:03 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id k187sf11357416vka.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 12:57:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611089822; cv=pass;
        d=google.com; s=arc-20160816;
        b=cov7i7rRqjq9Y6XueZyIfTzYzUD0r2X3WqhPZdNM6+/FaZt/GQnfv0N+YsW1eykewo
         Gjcpz6jx7p/0yPCFhW97zhRi/KsYCNDLycCD7GG4xdHq2maxyX4AELqeB/krnyR/t/wG
         P+w2oWmUFVWPRJQ6NTSHaghI/aYMPY7qy4CWTF7TZhyMDbrnV2E/6ONmoafhwhtSTdx3
         yUoSKMgZtFNTDiBI8iYmzl9waI6D18V2HV6ohSuewM31NjKYIlGPdWGW0qMs8v2KZ3WS
         enjb8GVU7SSTWwqDNzM9SF8KpWFjUPQWDlWJe5oFsosnqZBCOZZrcrNo4X6NAjH5b2eb
         /Dvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=jIxnJSj/l7auhJy5k9CIHTKGPpP/ure6v3k3c8/kwho=;
        b=fDuFivDQV0iTyFg7cAhInipnynlzWMTUCSM+H5vHS0C4wLDfUVoX/YSm1tVdBIHpG8
         zQwyLo/kwkpNs8JYpuudObJU2MSMKSHvVtvn4EiTBDAc7idzuwkHKM6ekFEMm6pXHW3o
         wRNAC79Onl3ZCjS+fXQmNgJOukz0RHQdLlCorP0URdJdInlOILbeIqBvlDr1nIucsbju
         JqG4hAL8tITBpJj2gVtKnQPIwkDSzRBJuGr8xcAlG9LUF+O1nSde3aTKlaqf3584opY0
         kV6ZdJyJhE0PIJT/0xv9A4pO99v59nXzPq2Ya2V6LS1feyUKRbqsMdROY+BL3LT45yco
         eweQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CqXMEVK5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIxnJSj/l7auhJy5k9CIHTKGPpP/ure6v3k3c8/kwho=;
        b=iLbDqws7hVi2EpujY2HTnuBwHR9xucHctyxZnsotSfiQRmbZbjBT40NlsxD+ug/BYC
         NeGOLKdUPuqQQYta6MqhJgEb5+lk/d5C/G+4v3bKBUfEeperjt+56zgbxLyg+QQ5hMIy
         Mgaxqd7oqx1k1QTkGgTAwmPJQlcQOEwOg59jiICrbiPy2mdHCxn/x2Csx90x2AbwAGWh
         WGfGykVmnke2wrE66ID9z6tHEP8n/Cm5TsDhFc5xmcaS236zt3F9C4KLDHsbWjiFmu24
         cR0IyWZvH5OtTkhNz7JWOeRnRAUa2YVyPUlD6huJzrb9LoWlVoERDU0u0nivfMwhHaQG
         gsMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIxnJSj/l7auhJy5k9CIHTKGPpP/ure6v3k3c8/kwho=;
        b=ZBRUd9T2iyGeD4yUvDYxLlPoCWvmf55qWOUt0MmbDQMwV3HshRHy1uAK/cMCYZXjKp
         VMobeIe/ffiJVreRkxPsmECPPn34xo/N9b1xE+77PwcV8Ymd/qzoLq+NPc+gY+woNVkN
         TxaI4PzAmMpz0PW6qJREcgM8P9fuSIxAovunkUhcuITpsxyFCVX6edAdde3YsrcotckD
         ui3r1fVf2LLVVkkNTaye0pIxIQt+Q5uuTMJrXJdLHt2UbeN/em849HOz6FNaU2vUXV2q
         EWwTFUNbmCynpNLHKhGPbvF7TGzDIneTNI3yK71DvSJJwXj2vGWyYnNrZRHn1MyqfGwA
         UKqA==
X-Gm-Message-State: AOAM530pW9ah2ZmTmwyl1QoQPhAc7l+tGwTHMf/fIRin1SlEiby7K9yt
	3+0yi4VkCKXNjSQ9PXomwuQ=
X-Google-Smtp-Source: ABdhPJxpiVYxwpfFe3B2MBk2Ht+HZp+gFdfJDvPpYo+VzIbtw/ImV1eNz0yrQiIqrzEW5cTDLFzbVg==
X-Received: by 2002:a67:facb:: with SMTP id g11mr4437829vsq.19.1611089822368;
        Tue, 19 Jan 2021 12:57:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e287:: with SMTP id g7ls3113678vsf.5.gmail; Tue, 19 Jan
 2021 12:57:01 -0800 (PST)
X-Received: by 2002:a67:401:: with SMTP id 1mr4564929vse.51.1611089821909;
        Tue, 19 Jan 2021 12:57:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611089821; cv=none;
        d=google.com; s=arc-20160816;
        b=dLhrGdYNG0Cd0nwOYAe5Z1ikQaCvj/++vr/2n0SSwstwNCA8iO1hx3qsJjI21Bg5Jn
         P4wyJK7OAMxfGyqOVjZ5RqSjR8GBaZOz9CT2AgS+xX+lhz2RN+nLok+sX5p807+2N8Yv
         QYlsCw3r5t4waHsX0TGfIIzCoM05Ex3zEU9LzngTnb3Lc4XQmMRProHmDCo8n7KxUWx5
         6a/pd7XAoN0ZtkCYtQemvK1z9IoVM7yJ0C2qU7ePU9rL2k1h3Iq5HsResbNdlljCxNgG
         pyBYBGunEIo2epos2Xehc88b84rgsSZFOSITUA5Pv/Mq6pD6aO2RjRV5Af8LBhqJE9UT
         +CZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=m3o3M1xuSeBDnr/2NRBnrOChpur5nQMVpX1X5cQHNno=;
        b=kYtfW9RH5f7gi9Kk2PoHPoBzCoVjsQciMpkRwaw5MfGzQ/4k5+dPXtcB5oxdh6JERx
         gHoKKwkuhuUmBJkwOVdtrcWHJT5GuehUIKhu9fhxb9eCWh8DppdrjkxJ3DhITH4pK8U3
         Sr7lRITK++86TxpqmRhLUgXBrCph+BdfE19GdCJ99gemlwAQ28nWRifiojr3lo1v9abw
         PXXx3Q3Pi1M8NXIZgCEZQktKL/4ZJrMeGWcPGM260eswaZY5Ht64jreJiGEIqE6s341D
         Ged2VMA4pQzfRFsCHzj1HtpjwVc2zfohNmnPjpMlu80fH3w5Vm1P0wk6073K9Cyvgfk+
         r1pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CqXMEVK5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id y127si1502293vsc.0.2021.01.19.12.57.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Jan 2021 12:57:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id x20so705201pjh.3
        for <kasan-dev@googlegroups.com>; Tue, 19 Jan 2021 12:57:01 -0800 (PST)
X-Received: by 2002:a17:903:31d1:b029:de:8361:739b with SMTP id
 v17-20020a17090331d1b02900de8361739bmr6643756ple.85.1611089820931; Tue, 19
 Jan 2021 12:57:00 -0800 (PST)
MIME-Version: 1.0
References: <20210119172607.18400-1-vincenzo.frascino@arm.com>
 <CAAeHK+zpB6GZcAbWnmvKu5mk_HuNEaXV2OwRuSNnVjddjBqZMQ@mail.gmail.com>
 <20210119185206.GA26948@gaia> <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
In-Reply-To: <418db49b-1412-85ca-909e-9cdcd9fdb089@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Jan 2021 21:56:49 +0100
Message-ID: <CAAeHK+yrPEaHe=ifhhP2BYPCCo1zuqsH-in4qTfMqNYCh-yxWw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Alexander Potapenko <glider@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CqXMEVK5;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102c
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 19, 2021 at 9:32 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> This seems not working on arm64 because according to virt_addr_valid 0 is a
> valid virtual address, in fact:
>
> __is_lm_address(0) == true && pfn_valid(virt_to_pfn(0)) == true.
>
> An option could be to make an exception for virtual address 0 in
> addr_has_metadata() something like:
>
> static inline bool addr_has_metadata(const void *addr)
> {
>         if ((u64)addr == 0)
>                 return false;

This sounds good to me, but we need to check for < PAGE_SIZE or
something like that, right? There's some limit below which accesses
are considered null-ptr-derefs.

>         return (is_vmalloc_addr(addr) || virt_addr_valid(addr));

Do we need is_vmalloc_addr()? As we don't yet have vmalloc support for HW_TAGS.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByrPEaHe%3DifhhP2BYPCCo1zuqsH-in4qTfMqNYCh-yxWw%40mail.gmail.com.
