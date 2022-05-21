Return-Path: <kasan-dev+bncBDW2JDUY5AORBPGIUWKAMGQE2WWVXNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D1A2752FFBB
	for <lists+kasan-dev@lfdr.de>; Sun, 22 May 2022 00:14:21 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id o4-20020a0566022e0400b0065ab2047d69sf6251724iow.7
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 15:14:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653171260; cv=pass;
        d=google.com; s=arc-20160816;
        b=FHKssyNhXjTw7tDSf85m4duHxgG24Oh3/qah6rAqR3NmbohsEaedCR1tyGw6dfDfaU
         1bd4/yUD00hBuiPsdM35G5bGhFeKTmSq19YaMTmHVh5s9KpF+eYFT+kCyfZrnDJpggv0
         2c9mxHQJsraZb5DHICEtxU1qgezsfz7ZDoJMBq8GKTP4EZsQNU9/7il2/EflDjXn34VW
         ss7Pi8zi0rhcG52CiwQqspsTWHgCO96Vt/Y5kUlmiyjv+e0fujtveZHDOVf51NFKPifY
         7sHYcOzjZoDFajq3ogfggJ0etKLiyVqD9ZTVdPgFXDw8xRfNSq+SxX6z4aXG5JFXTGSL
         jSTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=AB4mlhp7Z/JuGNRx7/aVHMv8mOR5kXh7RarXyYauN+w=;
        b=GaKVzuaQfyiH/WYX66SGHG4fQKN/uLJvVsHFHMgC+6T0aw0/4KYa7Xrg9vz54CXsDm
         hHlP2HhvnrztwxGQbSHocXxDz1/6ysX8+tkbWAEBXlLHIgyzDJcrzOve8evNf9uEZjBO
         6JZbJVSSGMAx/hbV/4zvm6ojjJm3q+yd7ozJXE7s9YAJbxy11vqaJGhKHsuAoEpylL5C
         WI5mZDrZ8DgH3uZeLW/V3oqvwgtlCgljude4dfxUP7TaM6Wf9f1QV8V/FimpAVUdzb+4
         Iw7yEtxYgJeFhQ+zxknMgNs6QtRTWCOASgZaThCA0aJv1KCUZbIyD5kSDPCIEBSPLNKK
         b/Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bkuDGxZq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AB4mlhp7Z/JuGNRx7/aVHMv8mOR5kXh7RarXyYauN+w=;
        b=A30l/8hbSkPKtAGgfqMbY92IoljxjlPKpzdGs54sB5b+/U9mY15MXG9I73SVNfSM/p
         WHK2asPLC6tByjZlSiUAAO5oa4B98iFp/r1nE4r8wRlf1REOzHXUZ1zVyMWOYRPo2Hcv
         mSr7ZbAh9LR/gNhV8KSMeLCQrHone91UIJEX7CEhgN99ThWmSdmGPefKNpxME4r3sLsk
         lTl3ZlWuFgcpbeMvAJOrEACyu5j2B22rqRok4+dwYTnUP3ktcMfUg1XeZ+qgY+lBtToI
         6YaDiId70e/L7BYpSJedCt/OqTmaiBzIHBmerH3Sim2QNWpDqkuNxwXsNTpEAwgnMXar
         duGw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AB4mlhp7Z/JuGNRx7/aVHMv8mOR5kXh7RarXyYauN+w=;
        b=Nd2Av/nBfmhs3G4bk/aKkE5mpeGP8PBfDMJb6Q2c0uEMWcvej9BO0F3C64WKzTZ4vW
         XjZVUHIfw7BXzffg2KodHeF/L/3wfu8PNhKl3Yoz42w0bEsOijleJc2fzxJ466dpZ0S2
         BOwWxabcUCF1QczZQQoG1ocDLJq9+N001+yseCXk8fzgBsJN/KeOvq7egn394QF9g2ew
         02nFPYRHk6u3BI/rmy9+Ih506FyRGxXymSvxs3fisE06Np9z83QwdcJdJQEbg1I33Kbg
         /bIo9RywmVgJSDOE9lJBqgTa251GIIXqXNEnQIYZY3CITBjh+DAKrSWnoQ5elybaPEEL
         ofQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AB4mlhp7Z/JuGNRx7/aVHMv8mOR5kXh7RarXyYauN+w=;
        b=Hiru9PZ6plgYFaP8MAh81bEzeao7BgqOguLmWH7yPx2/22j/KMkcHn3BlpJr741DXy
         eobFeTtJOQl+fOrGpyavRjKFo8ztMfcLReBcFTvxU47SqLeV6TyYEyP7Zf7zB5L3fQyX
         kZiu+CGO249mZ8pcMZ03Dltb1aOvTc5y+c1Hrncz6RoNSWYfhR5/iJfLCctH8T/CU8cL
         oTNtKf2a8s7P/oqN5cl4VrN4FgB5CmmQjgpmACEBJarsI4ZDlifHAJkc4LPa4Q1DEwxa
         /0eW3b0fSB5LKKhnovkCRAIfquzjxixs5N4Q9HNzj2kT/rTmE7fhNCVM6DjbMdtqmnPG
         FoKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531mQiWPBWIkZ+9+I+RE2YXDWsEXKhj56Ojksn3lWieyLBNFbTfh
	eg4+QagWJelvovClIyY208w=
X-Google-Smtp-Source: ABdhPJylV+KAtvelN5dGNrWCXBEnyh/b+R7AgiDNu0pMNFJMYjr7WXdCn/pEcsy1YJd4WuEglh10/w==
X-Received: by 2002:a05:6638:4913:b0:32e:8081:f39c with SMTP id cx19-20020a056638491300b0032e8081f39cmr8401560jab.1.1653171260512;
        Sat, 21 May 2022 15:14:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca06:0:b0:2d1:68e9:e90d with SMTP id j6-20020a92ca06000000b002d168e9e90dls1157060ils.0.gmail;
 Sat, 21 May 2022 15:14:20 -0700 (PDT)
X-Received: by 2002:a05:6e02:b23:b0:2d1:59c8:a4c1 with SMTP id e3-20020a056e020b2300b002d159c8a4c1mr8534704ilu.296.1653171260039;
        Sat, 21 May 2022 15:14:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653171260; cv=none;
        d=google.com; s=arc-20160816;
        b=0b/L1ScP7XXyaDI+ZbAV/0FMRUo+R9xX91qfYp+OtvY/88jdGPYQaoSWzy6/o3tvnL
         Aekow04V4AzNMs04jFxqjKXD/o951NZQp5EueePjJYrDBinXslErGkuflr6gN23KA+D0
         pkmvYBCNFOUdYZpxZvFFBcSFLA9WIWZftdcgNM47FY1+ynrQCPfU5BhClyAXfTpMa3f9
         qnbN/ACvIoFrAJFoSZXd5Sgw2poU6Er4+hcjVrrrEIJkhY2CaaQ0T4oHqxTxW/klG4sq
         5mbfWTfvGVGN2TlJlExfz4k3D3v55yOevwXzVEShpjnLaiazuauOyLIeF6xGvS/uk+5X
         JieQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J9gd0qUzz4d3HMlWIGrSPIDm63/hMmsz4M05qPRAs9o=;
        b=cVj89yW9FXXbCv9kfj172JebIL2qopNz8fr4yFhe1bkJbqmlk1Cy38/lTD0H/4fGLy
         1ohpYhDgJma7kxf6GxfGn8ipNPQPeBdRJBnFABIA5HLNuFNGJno/tkJjUVxef91t77Zj
         UCZgd3f9PplIbQV44ef0C9h9SHPUeLvaKp+LE2LGMBE44nzkd+1bY+N3nEEeplgkZj5i
         S6Wb/03IACu5iHBVhw/BBhHXctsM2GnFjczgwfQEM6i1T3k3Ou4+gxEM5fGVUWJEqqAC
         vzpHPird9itlnbg9iOh9MtaiuTS8ChgffgjCqt1EC4MG+RmSkKJVvrT+Jkxp78ohwN+Z
         GLww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bkuDGxZq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id y21-20020a02c015000000b0032b603bf16esi450499jai.2.2022.05.21.15.14.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 21 May 2022 15:14:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id i74so5285265ioa.4
        for <kasan-dev@googlegroups.com>; Sat, 21 May 2022 15:14:20 -0700 (PDT)
X-Received: by 2002:a05:6638:381c:b0:32e:49f9:5b6e with SMTP id
 i28-20020a056638381c00b0032e49f95b6emr8924144jav.71.1653171259846; Sat, 21
 May 2022 15:14:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220517180945.756303-1-catalin.marinas@arm.com> <20220517180945.756303-2-catalin.marinas@arm.com>
In-Reply-To: <20220517180945.756303-2-catalin.marinas@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 22 May 2022 00:14:08 +0200
Message-ID: <CA+fCnZe6QNgmpOYxT7QVMY4FdPrcmpe7uW8-Z4TO_kWC06PeLQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] mm: kasan: Ensure the tags are visible before the tag
 in page->flags
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Will Deacon <will@kernel.org>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Peter Collingbourne <pcc@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bkuDGxZq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
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

On Tue, May 17, 2022 at 8:09 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> __kasan_unpoison_pages() colours the memory with a random tag and stores
> it in page->flags in order to re-create the tagged pointer via
> page_to_virt() later. When the tag from the page->flags is read, ensure
> that the in-memory tags are already visible by re-ordering the
> page_kasan_tag_set() after kasan_unpoison(). The former already has
> barriers in place through try_cmpxchg(). On the reader side, the order
> is ensured by the address dependency between page->flags and the memory
> access.
>
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/common.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d9079ec11f31..f6b8dc4f354b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -108,9 +108,10 @@ void __kasan_unpoison_pages(struct page *page, unsigned int order, bool init)
>                 return;
>
>         tag = kasan_random_tag();
> +       kasan_unpoison(set_tag(page_address(page), tag),
> +                      PAGE_SIZE << order, init);
>         for (i = 0; i < (1 << order); i++)
>                 page_kasan_tag_set(page + i, tag);
> -       kasan_unpoison(page_address(page), PAGE_SIZE << order, init);
>  }
>
>  void __kasan_poison_pages(struct page *page, unsigned int order, bool init)

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZe6QNgmpOYxT7QVMY4FdPrcmpe7uW8-Z4TO_kWC06PeLQ%40mail.gmail.com.
