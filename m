Return-Path: <kasan-dev+bncBD63HSEZTUIBB5FQUX4QKGQE3T3AAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ED2A23BAA1
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Aug 2020 14:45:41 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id 189sf4847249iov.16
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 05:45:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596545140; cv=pass;
        d=google.com; s=arc-20160816;
        b=bjKm0X97AJ+cC170qWqaXOVOUYS/Hop2WbKQ9tAF+dp1pPxz9uo1TV28niMezHpsJ/
         N1Hp+DhQ/8UIbOqamLhKzAqEfjoQdYStHiDN5FUKF3n8oSTPpFrYGOCthfjsxF0ux1To
         7L4efL31qwvXel9XLo5C4YJ4WIgojG+Irpoa5RkSLa1/Nm9/zzpEMf0ZPRx3RkWAwLdp
         Hz2/bxu+5kQDu9iSohOVJk5XaX0rsLaom9T5UwqAbaaRBpFr/yq9gekCuzFmIN+4+BLM
         k9VnlF6OAK46cIr1SDG0U8U0x6KkTo5K2NSdL1Lv7lf3NUERUk1d60DO9j6SHV3xcqsl
         C9wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=hQx0//EeBpdgcAqfd+EM/DcF2hFMV6O3P9TfIdcvuL0=;
        b=BD1v2dBPSpwsWNCkFGz6M7w7SqSCU/G+hK5wGKWIqZJ/qAGsbfjq2tmM7BNOF90ukh
         Tqe9gz2amrTFsNc+YRVkkItOva7MoaJVcUaCRHAJM5OV1hWSYq297YYHY1ASgVA2VucN
         LcQBJUVKayBx8J7j9m/kxgh3B7JiRnZH+84fSn71H2Zf1aZY36R94PPSlI0jgo4PAXy4
         P2sE8ic1ROxBGXKAW1rtNfc3jhgvoMEl+tTUgmzGvVIt6kSvxtRcfh+SXwfB6mpP1kQJ
         XMD85hp/mLAYOAHc86pxt1m1ELnLcBN1tpKuijj2e0Rvl5To24PbUDtMr5yJUNRLE8PT
         L2rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kyt2DYaB;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hQx0//EeBpdgcAqfd+EM/DcF2hFMV6O3P9TfIdcvuL0=;
        b=i7N9NSu6Xf1DmLbQ6vT/XQ8vsTK/BI+x8QTZb6fNks5xeiEL7M61JEaf6bEdmVzBfd
         nhIOUMiNDITko9AfvtneU5GiJ9jS5H3pqfJHJRTw8z3Z96sVoyoIUlO/d/w45v5hPSVD
         Xxpf3pZ/nF4XNzvjV3jjfZTJXkAZc2HZjKeA0aQs9L0+8aS5qsG5egSFaK+rw0Rf7u9e
         bcYO9sjDKFgsu0RGQmlkOFSSwQQp/p7n/XbElvhE2g484gs9Pb2PqfrGfvflh/qX/yRC
         zFC4I52WK7pxnuVraQFhO5JhmTsRJd5DwkkmhC/fSizIrLtKo0q2C9SZgCBznsG/dxMg
         Fqqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hQx0//EeBpdgcAqfd+EM/DcF2hFMV6O3P9TfIdcvuL0=;
        b=qJG6+LdadAmFnZChpsLVUzjcDVq80kPRoZSIPisVql5Cnsb3bXP4ey2pSKhDzcZJLD
         jbkAj4iP3jVaXrQGtt1Z4/eYl2jjGXbS0T6/P2rRwBL/rBfnM8SUKYTEgpjjxmxxyhSv
         1P8x2cXDb0IsHCTWjiYuVdjhsisLz4TCknZ7a6PgYP4FM4MtINztfpA1y7KdNFYEjNgM
         vvcSUTfhozjr5w02gxlIaKiTsTqcM1rqkScyyfiofNTs4bZUQFT/cZU4skxuw4fynb+s
         LwftLp8dwGNZ5iTNjTPVR0HHNPcUejtsPAXk6QFQeqHwSHHwLQLpbHGsv5HIji+70ibV
         ZIag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530oR8YH6KJZaFP60U9z7xFjd9QmSAXrSd6JT9stN0Ufvh32BHve
	LATMZSye0OgLld9y8ty0Gnk=
X-Google-Smtp-Source: ABdhPJzscyjH21V/EFIybtlBbSHK0IPMhunkS/F6KG6SnidEthyUmrGe73hRnSnj41pdDM2Rc+OjlQ==
X-Received: by 2002:a92:6a07:: with SMTP id f7mr4676616ilc.271.1596545140082;
        Tue, 04 Aug 2020 05:45:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:f702:: with SMTP id k2ls3610111iog.0.gmail; Tue, 04 Aug
 2020 05:45:39 -0700 (PDT)
X-Received: by 2002:a6b:fb01:: with SMTP id h1mr5018110iog.18.1596545139710;
        Tue, 04 Aug 2020 05:45:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596545139; cv=none;
        d=google.com; s=arc-20160816;
        b=q7JdsX5kvWEa+zXa6VkvptoPETeJ5+UIzNeeMwxnL9v5D2OFDlRbCjUxRCsXq84Yj/
         HZlGBGYLS80ZCLYAkdmtvany5UyU1dAtc805q94N3McqCob/CO0941+LL01cGfxrlirF
         VxJvoxevpUy7CfkJPG780HRY4ol4K3bWDzwrug7IPgtWjJQ2zzmAgz0s1IDTx0yxSM/X
         ub8/MEUzYCxV+Q5XCbhZsaHR7NpsnK9Rg2SDuH6kNUqXhkCfwIoEahCmREpwsWBFM4Si
         7H9K+TBJmOj45M1CT8jsNartuIERC0f9Fi5P7uptcxb3GqDVr8OERZLPyfjaPTquovUn
         y/8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GC5SArjhiW32XfF1PIyKrnnN/IVYATNx52nPhegFJzY=;
        b=vHZ9FLBI8/Hek4fec7O6PTe5bFB2+QC0AgVXDZQDPIBegS9y4hvGRDNVD947xDipMB
         qp8X/cpJO7jFUU9gFXCTfqUeRwgi0JNJg3T0LFXQWOeFzv6nKuNRRe/HJdk5CJWLwsVA
         D3pQnb1mqy7nc9oTrc4milvSr9SM2GjLs2fu77wZVz5bpb5CPxv3TT2V+Lw3fAnW+/JQ
         nG8KV1slxvIfT0U9MdmQik3BolANpr+f82Lh0MQquFfP3eT3+MqGNGjo+r5ZdhxGtpVs
         Iw0oR17zmbeuNUAR57ylYc9Ers010UX4E+xJOuLjBtS+weIhqo3CsP55EvRnL9keAz+/
         kQNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=kyt2DYaB;
       spf=pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=ardb@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p1si1142388ioh.3.2020.08.04.05.45.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Aug 2020 05:45:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail-oi1-f177.google.com (mail-oi1-f177.google.com [209.85.167.177])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 06FD022B42
	for <kasan-dev@googlegroups.com>; Tue,  4 Aug 2020 12:45:39 +0000 (UTC)
Received: by mail-oi1-f177.google.com with SMTP id l84so23638840oig.10
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 05:45:38 -0700 (PDT)
X-Received: by 2002:a05:6808:b37:: with SMTP id t23mr3331033oij.174.1596545138345;
 Tue, 04 Aug 2020 05:45:38 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1596544734.git.andreyknvl@google.com> <6514652d3a32d3ed33d6eb5c91d0af63bf0d1a0c.1596544734.git.andreyknvl@google.com>
In-Reply-To: <6514652d3a32d3ed33d6eb5c91d0af63bf0d1a0c.1596544734.git.andreyknvl@google.com>
From: Ard Biesheuvel <ardb@kernel.org>
Date: Tue, 4 Aug 2020 14:45:25 +0200
X-Gmail-Original-Message-ID: <CAMj1kXFua3LuoD=-7rkS1UuBXXCppsc32tZryyu2GoS4mpwzVQ@mail.gmail.com>
Message-ID: <CAMj1kXFua3LuoD=-7rkS1UuBXXCppsc32tZryyu2GoS4mpwzVQ@mail.gmail.com>
Subject: Re: [PATCH v2 2/5] efi: provide empty efi_enter_virtual_mode implementation
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Arvind Sankar <nivedita@alum.mit.edu>, kasan-dev <kasan-dev@googlegroups.com>, linux-mm@kvack.org, 
	linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Walter Wu <walter-zh.wu@mediatek.com>, 
	Elena Petrova <lenaptr@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ardb@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=kyt2DYaB;       spf=pass
 (google.com: domain of ardb@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=ardb@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, 4 Aug 2020 at 14:41, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> When CONFIG_EFI is not enabled, we might get an undefined reference
> to efi_enter_virtual_mode() error, if this efi_enabled() call isn't
> inlined into start_kernel(). This happens in particular, if start_kernel()
> is annodated with __no_sanitize_address.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Ard Biesheuvel <ardb@kernel.org>

> ---
>  include/linux/efi.h | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/include/linux/efi.h b/include/linux/efi.h
> index 05c47f857383..73db1ae04cef 100644
> --- a/include/linux/efi.h
> +++ b/include/linux/efi.h
> @@ -606,7 +606,11 @@ extern void *efi_get_pal_addr (void);
>  extern void efi_map_pal_code (void);
>  extern void efi_memmap_walk (efi_freemem_callback_t callback, void *arg);
>  extern void efi_gettimeofday (struct timespec64 *ts);
> +#ifdef CONFIG_EFI
>  extern void efi_enter_virtual_mode (void);     /* switch EFI to virtual mode, if possible */
> +#else
> +static inline void efi_enter_virtual_mode (void) {}
> +#endif
>  #ifdef CONFIG_X86
>  extern efi_status_t efi_query_variable_store(u32 attributes,
>                                              unsigned long size,
> --
> 2.28.0.163.g6104cc2f0b6-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMj1kXFua3LuoD%3D-7rkS1UuBXXCppsc32tZryyu2GoS4mpwzVQ%40mail.gmail.com.
