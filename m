Return-Path: <kasan-dev+bncBDW2JDUY5AORBRE23SFAMGQEC6RML3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C6C5D41EE97
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Oct 2021 15:29:41 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id o62-20020acaf041000000b00276562d5a75sf6369342oih.13
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Oct 2021 06:29:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633094980; cv=pass;
        d=google.com; s=arc-20160816;
        b=u2vWayvWctxOXRF+ZnKvsOUi0cFSuOgqL5/GPTPz/uLcsnUNQLmgGjhSCrotn15oOz
         0TGn86YwpzPcchabZiUja0nuNB7APtPwBKe75ZWkfekGseI8fy3Za7BN+Ci+0FjuN8M3
         UqRaAy1Hb6WiMCVKbx+SlXhq9CfNzdJAAfmJXb1WXYVjb8270tQJsm20VCHXdjelgfoG
         1Y159DCozwi+Zp7YMbGBsq1E5I8HNKL0Wk0u1IXt9reucOzdwLGkrkmk9t5ltfecXmQS
         TXXoH9xu7yvMckG3gTEhn6VC6agld1ETC1W1RvJr7wotri5W69glDoTttokYDQD0dLP/
         XPqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=xI18PxywITa3plB7qHCE04lnaQSsi24/6TNUdYV7GhA=;
        b=va8VF6G1EjMBPXdkdhHnPOrep2urzPwdpkP8bHquTInRfFA2LRmgXNdfg+JMub9xKs
         fj71rCcILWTaCuV9r9eoTHes4ec9rWa0t6N9V2PfUmEmWHrDAyZiMhu4LDFEAjsEsIjN
         hBvAvHCIUEMAmeWdeyWljoTd1VtLGlzcwQoyZjJucyDut0tn1XVPdHdQ9Mb8bUNP9N8B
         +TgSLdIev7eOs6WbcawQ7ysYAazlGQADZXFxISi+Wu8l8nZ0xyDMGnIksByY3W46mnz+
         Xv2svfS6rWkTJAdpkVxCV0ahBYIzssISifWpzawHaExNMjfXYgQfz0tRf8CxFhiimY8R
         kxlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pEDuSEGR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xI18PxywITa3plB7qHCE04lnaQSsi24/6TNUdYV7GhA=;
        b=Tcsz6q2rOulXKKqzJum2kaKoHGiD/nlXeMDniP0qBDbCPnM98wxRHcEhDGt69DMKQj
         87UwludpqNqr4GTeKrqQn064AFcBC7WibK2IPh3b1U24OF2Pyi5UOoI6raG9SSv+gplF
         m2tBn+VGW5r9L4eW4Zc9GVf9feVNygPeq4VwNsNXGX+c64e7Tbgi0LstpNWpbzgx4InL
         HyUpHUv2kIyyb86c7K7OkDGhseSmOGd7f1paADCBlRPAtpyRV0X4nOIUCsSc5bBkSdAT
         Ux8sgJ2gm/M7ZOSQqw2/alsJjhh+nYDM7eXpcaUGGh/4OzoVfj9fpyxCevq9G1oyXoQp
         XZDA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xI18PxywITa3plB7qHCE04lnaQSsi24/6TNUdYV7GhA=;
        b=NklKo0kXC891n8tFanNt7S1g3rzldPXtKPw4yV0aaTl93yO7cmAnXVfckqVJTcspX5
         z3sGUQ89OvhCCgtKUn6LmmVyyCRqdaIzuBeFUzXaA0i+Bvrl4IumGLlRf1MqnNiHjJrX
         65mk9Cn2AaaUh0Yl15Qp0eT4dtG6K7581DQykVg9BrfjX+f0/v+EovY9gO/GoWwbwt2T
         0gMRBsFG9H4luCPMpMZD1AdiAPgceOdZrz4tv7ZoD+EWFbxhB8ZQ15KqwjukedZ0536x
         sMRKD6RPkUTT9op8RPWm79zFQNG6Ri+sglt9PhaRroqlD9yiCWLwJmjDO5FOtNbEO3R5
         80Tg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xI18PxywITa3plB7qHCE04lnaQSsi24/6TNUdYV7GhA=;
        b=00iwLxgRycfe+Y/7h7aIGvU9YkXmfb7emZqUOrQnpX58gVxBHnHvR4bPMWfqcQ0T03
         BiMgq6jftQOifo8vqPRdOmxXtfYf/Z/SDa11nV/Fq2zVT9oj/IwwsZ4ZwEBNRn+nfSBZ
         Cz5XmudeBr1AYx5gn7ThqqXWA0HRsQ0qJlzmn+T+TniKkEHWaX9O5GMAmNADnquVZ/gl
         oqHC4pR8CZVSxiyMpfYP1Rh318SvjIlV0mO1SOWzcuDh0eQDqvtyvPr0gDDjs7FboFF0
         DDyxrU0B69lUx0hAAcwxEjOUgtjOunfdbQo8AOgq472wQQP4VSnoOE7USyV/J/uVniic
         QYVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/ZsQZBau3rI7yjr9f+4yn2Tc9KfbpBRHyxmzuBzlAWfx1QPhv
	c5aY5bpyCLtAPlv/dQrnHGw=
X-Google-Smtp-Source: ABdhPJzc09GEvO9qQvErsnzHj7piQKfjlFIE2WwG+Im+6wF4LZqpyQdiCvtCOe7KRZLhjqcVHeZgIw==
X-Received: by 2002:a05:6830:9c9:: with SMTP id y9mr10337829ott.6.1633094980654;
        Fri, 01 Oct 2021 06:29:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4bd8:: with SMTP id y207ls3042150oia.1.gmail; Fri, 01
 Oct 2021 06:29:40 -0700 (PDT)
X-Received: by 2002:a05:6808:256:: with SMTP id m22mr3811503oie.150.1633094980325;
        Fri, 01 Oct 2021 06:29:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633094980; cv=none;
        d=google.com; s=arc-20160816;
        b=y/SRtO8zYUwV13ez0BRAAv60uIuXXfgf0MWYkA8wjNmSOrq7sSyF9p7JLBwwuWJRjF
         78Lr5qhwXt9GCAje8s8awGNgum/Oz38YnyAeZNVpgr/iserHwgq8gCs531yNoe53oS6v
         a18BBygbQ6/sJuyzXuj6TWG1vCfZ0ORmyrU0wna334tDB6sDf97kTWE6itg+eKWe5SLC
         Lz+4GVBPnKSC0BtCpeWsQp/JXeMoDZTyRSGHYg6wetmOPtqEB9JwUq2cHQwC1ToufORj
         Llr03tZ3/KDC1++d++TemBqHQ9qWKi4GTjXLeOJVQbCTNczNjORyYsF5HeWUXWBPZmMW
         3KpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xMs0fSTF4k4sXUPE70Z2JKEpyq5JyqRAgQ76CwZyzaE=;
        b=qLMzgb86d3HXJVHe1aBFjutg3EcUVLE4ay5cgL3nFRIFHZ3tZE1KD9/k2E2EpTkLse
         vScFa+9kX8K8QimJh7GATnNbgMvnqJYMuUIj+YH0/RIt/xT7jhgAvCmkSkMt/N39MXhn
         5mk9+vR9xVEkYOouLD0dvOusCDnMqIQ6BtGS11F8WaSPE8Tyt3aKJjguUlsqWo0I4fcJ
         hlPUC6lgsV82/5h0eGUYIYnadE+YLhlLnyHHiz9HJ8khdgGM3pNKxA0XuXktVjMJ+k74
         xt0xtp6yAhw26/D7pZQPwS15IbW9sCG+dMpb7FykfGm5YbmAeOjz/v8KwpHag7KJjGlS
         kCRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=pEDuSEGR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id u18si487793oiw.3.2021.10.01.06.29.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Oct 2021 06:29:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id y17so2248346ilb.9
        for <kasan-dev@googlegroups.com>; Fri, 01 Oct 2021 06:29:40 -0700 (PDT)
X-Received: by 2002:a05:6e02:1a63:: with SMTP id w3mr9162209ilv.235.1633094979971;
 Fri, 01 Oct 2021 06:29:39 -0700 (PDT)
MIME-Version: 1.0
References: <20211001024105.3217339-1-willy@infradead.org>
In-Reply-To: <20211001024105.3217339-1-willy@infradead.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 1 Oct 2021 15:29:29 +0200
Message-ID: <CA+fCnZfSUxToYKUfHwQT0r3bC9NYZNc2iC3PXv+GciuW0Fm79A@mail.gmail.com>
Subject: Re: [PATCH] kasan: Fix tag for large allocations when using CONFIG_SLAB
To: "Matthew Wilcox (Oracle)" <willy@infradead.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=pEDuSEGR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Oct 1, 2021 at 4:42 AM Matthew Wilcox (Oracle)
<willy@infradead.org> wrote:
>
> If an object is allocated on a tail page of a multi-page slab, kasan
> will get the wrong tagbecause page->s_mem is NULL for tail pages.

Interesting. Is this a known property of tail pages? Why does this
happen? I failed to find this exception in the code.

The tag value won't really be "wrong", just unexpected. But if s_mem
is indeed NULL for tail pages, your fix makes sense.

> I'm not quite sure what the user-visible effect of this might be.

Everything should work, as long as tag values are assigned
consistently based on the object address.

>
> Fixes: 7f94ffbc4c6a ("kasan: add hooks implementation for tag-based mode")
> Signed-off-by: Matthew Wilcox (Oracle) <willy@infradead.org>
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2baf121fb8c5..41779ad109cd 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -298,7 +298,7 @@ static inline u8 assign_tag(struct kmem_cache *cache,
>         /* For caches that either have a constructor or SLAB_TYPESAFE_BY_RCU: */
>  #ifdef CONFIG_SLAB
>         /* For SLAB assign tags based on the object index in the freelist. */
> -       return (u8)obj_to_index(cache, virt_to_page(object), (void *)object);
> +       return (u8)obj_to_index(cache, virt_to_head_page(object), (void *)object);
>  #else
>         /*
>          * For SLUB assign a random tag during slab creation, otherwise reuse
> --
> 2.32.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfSUxToYKUfHwQT0r3bC9NYZNc2iC3PXv%2BGciuW0Fm79A%40mail.gmail.com.
