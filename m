Return-Path: <kasan-dev+bncBDX4HWEMTEBRBL42UHVAKGQEOTHLK4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E68182065
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2019 17:37:20 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id w5sf52944360pgs.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Aug 2019 08:37:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565019439; cv=pass;
        d=google.com; s=arc-20160816;
        b=wCWRoctCXhYN6Psnl91rHWeFLajseUf7v1Ddt1CdUGN9DjBY6NCrNe2zO/4QAHAxHW
         juxZv+KJ/MlOea1LNImPcs5X/68+pUZjmLgTVQHZndhx9z6b0oYA+DqOfmWj3UgRoxGY
         36Xfr220PkmasKP2tybHOsJxidTFCThprJmGIx0Fg5RbCsa+uIukeD879lBWVV/8dVfT
         3+Zl6cfVqkzR02NMueMmX2FbI6D9Ndta17O5u6jybxLyyWB8JVDDLE2ePQh7g0uduYep
         LEARg02Ah63ew61iWwtzJLwfycRcr1M2Py0V4wwfIS7IIXUC3119YQvlkL/d8CMV8J7v
         b3Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=k3GzryoHbgbfC1GszkqfpxgEsplkhZXvKRjyDdSjPLg=;
        b=FJ5A4hd+EK1P6whnJn8qCKGIhB1lGzacEbu97sFsU3AU5HLkSTXQwD7XUKOgKIr/s+
         kQ0h2iKna56AvvVu/WXU2nTEJCyuTmwbY9KSYb/0a/xOiP26HU9GBWJ8teuqwyPqktlB
         4GcWTDw901lkJh9ybIc//sELdMoGOE/7YYWZRAePU+QJOnwNeBBtTOGuevXaG+EC7NDi
         lCr5bTMbQF5a0qmkTa/ocGcuB6Jcw5/J/2RVgzecSxAUUk+CpcIWkAs1caq7Bg3b3mu0
         G8fNN1INetjvrlNdqveIIUKHc9IFId+E42LOSUvNWEbL0rxUQDBcwkxo0GZq+RKg/trn
         aSCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aZHdw82y;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k3GzryoHbgbfC1GszkqfpxgEsplkhZXvKRjyDdSjPLg=;
        b=YydyR28VcPJX9Nbeq2Ond0dzEm3zaVYv2aPwUz4/pkn5togxx4eFmgUUu5+24+YmDJ
         9QBUHS4GSizDyFbWPSFoxUgYllbz2jzfnhYW6wTH6N1vyCfHu+/iOFy/PHrMEdXkIlDJ
         7c2fON4Fcvyf4AqaTdSZHq4NsWyql3y597wfpEFAKSQdJnX+cDQFi8y1mzdvMR/xxF3Y
         ewU/uTmNlGACiuKVmLNz4NH17tK/hAWa8eAys+A3cDlr1jcVVR/wQZCT0iAoeLLwbxFx
         S5msfhMb0Pr3Juaxu4NP6rHPuK6KLRt+B1eApz5V7vJYBfhbCPe06RZMDw8WopCE3H6v
         UAUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k3GzryoHbgbfC1GszkqfpxgEsplkhZXvKRjyDdSjPLg=;
        b=URnnUSq/Ro19blyYysQVKuUp8N6eC7EDUuYEobEjWzHkNvT87X2B9L89+irSbMmqZL
         oor02WL3C/bZhoON2jr0UK18r/mSYgj4dauFfqP3/HYhBpBp1ovlhzIsk4PQbr1Kp+Ta
         bKHJJnwUdwLuvyCf20HLzJp0h0QWo1hVQ3F4bqPSLsDVobLzjFeJUW7k5ELwNCx57PxF
         KHxp+pYJpdErK2N2/3QZpkn81/uhRB/OkAROx7naOIMpYgowjRSByzKiidaGBPvXBEFq
         L3VUkL1LMryM2iPukR3RqawGpYhnPSKv12sF8f8wOyz4+4/CmK3xIcZiMM0BsTwYX8aL
         dXgg==
X-Gm-Message-State: APjAAAUbZ33O/lQf878KL0Bin/rpfKCGdn1YWA5rihX8bxa7GBKYlOXg
	wyPvKd33DkxRHzCb/eobop8=
X-Google-Smtp-Source: APXvYqxwlFRbtjaI8P+6Rnq2h6uwjiJ77B+HTwdKQimFMj09auFtI6hrpYOvzkeK1PFdY4Zl4QFL9w==
X-Received: by 2002:a62:5252:: with SMTP id g79mr72405863pfb.18.1565019439043;
        Mon, 05 Aug 2019 08:37:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:1021:: with SMTP id b30ls23660549pla.1.gmail; Mon,
 05 Aug 2019 08:37:18 -0700 (PDT)
X-Received: by 2002:a17:902:a413:: with SMTP id p19mr146041819plq.134.1565019438769;
        Mon, 05 Aug 2019 08:37:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565019438; cv=none;
        d=google.com; s=arc-20160816;
        b=ocJSYwfuXyQYOEtvx/Say48Q633xlk94m9mInjAc/VkJUCpF/Bfb5kEbpbH5TI2Dz0
         WHTUg96QqO/0PSPNyrlN/Ec6mGlbVt5XzroQD9WI/HZQiWK/NTxXS+kCK/SXmsQS+RbV
         vbXoOisHVzaNfkXOhtXAtb7bEQ39OdG6yevbSmeHk3CRkOQcpX9s1rOuPTo1SeEJDa3N
         DuxqzKzh5ByfONkPoQX0uFjBhztq8USZ8vzQCeW7VMvi8RHHiiP5D7zA/RNHq3yvsF7O
         9xTsyRhaLZzW+Fc80RcDl8RTiUBQ9uxfNt0iZPkw7xPx4e3AbqdeCXuWzk4x6g8U8PqZ
         2QHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BRP6laDcYsaagqowX6PM5vV1ql9YojC3f98ieQbfibw=;
        b=bTDeiXNpUAp63GJditQ9gm+mBIcIU1Xad6IqYFzPQUransldqQG16UvFbH2E1LaC0V
         1f43qGSVfHfayCsIJvCkXiiALpd/r+jddz1cH1+OTB0qzClhrkWUxPEU+oGopB/7EJWl
         5gkwshsobe7SZS8kcW4BtXI8aDqs8CCrJEUAs7veeYB3V5RLTL9iIvzebE3tslbwGNTZ
         lVH0kgByzsn2PK+hxgbxoSRGj2/iYa6/3QXzvv8ekIiF0sCVQ6trquiIU6gSS+9wrK3P
         UGXVINbJEUw46t5IlhTjxAYVMXOp3/C5jI1DCEoXQ33f763Op3n8UlxvaOo5IyZ6o9hP
         42Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=aZHdw82y;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id m23si3059231pls.5.2019.08.05.08.37.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 05 Aug 2019 08:37:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id c3so16704343pfa.13
        for <kasan-dev@googlegroups.com>; Mon, 05 Aug 2019 08:37:18 -0700 (PDT)
X-Received: by 2002:aa7:97bb:: with SMTP id d27mr73075178pfq.93.1565019438226;
 Mon, 05 Aug 2019 08:37:18 -0700 (PDT)
MIME-Version: 1.0
References: <1564670825-4050-1-git-send-email-cai@lca.pw>
In-Reply-To: <1564670825-4050-1-git-send-email-cai@lca.pw>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2019 17:37:06 +0200
Message-ID: <CAAeHK+xMQ5m-_eeQUPM2DoN=6OV-1uC6NX3dVnSKcmEqwSM5ZA@mail.gmail.com>
Subject: Re: [PATCH v2] arm64/mm: fix variable 'tag' set but not used
To: Qian Cai <cai@lca.pw>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=aZHdw82y;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::441
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

On Thu, Aug 1, 2019 at 4:47 PM Qian Cai <cai@lca.pw> wrote:
>
> When CONFIG_KASAN_SW_TAGS=n, set_tag() is compiled away. GCC throws a
> warning,
>
> mm/kasan/common.c: In function '__kasan_kmalloc':
> mm/kasan/common.c:464:5: warning: variable 'tag' set but not used
> [-Wunused-but-set-variable]
>   u8 tag = 0xff;
>      ^~~
>
> Fix it by making __tag_set() a static inline function the same as
> arch_kasan_set_tag() in mm/kasan/kasan.h for consistency because there
> is a macro in arch/arm64/include/asm/kasan.h,
>
>  #define arch_kasan_set_tag(addr, tag) __tag_set(addr, tag)
>
> However, when CONFIG_DEBUG_VIRTUAL=n and CONFIG_SPARSEMEM_VMEMMAP=y,
> page_to_virt() will call __tag_set() with incorrect type of a
> parameter, so fix that as well. Also, still let page_to_virt() return
> "void *" instead of "const void *", so will not need to add a similar
> cast in lowmem_page_address().
>
> Signed-off-by: Qian Cai <cai@lca.pw>
> ---
>
> v2: Fix compilation warnings of CONFIG_DEBUG_VIRTUAL=n spotted by Will.
>
>  arch/arm64/include/asm/memory.h | 10 +++++++---
>  1 file changed, 7 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
> index b7ba75809751..fb04f10a78ab 100644
> --- a/arch/arm64/include/asm/memory.h
> +++ b/arch/arm64/include/asm/memory.h
> @@ -210,7 +210,11 @@ static inline unsigned long kaslr_offset(void)
>  #define __tag_reset(addr)      untagged_addr(addr)
>  #define __tag_get(addr)                (__u8)((u64)(addr) >> 56)
>  #else
> -#define __tag_set(addr, tag)   (addr)
> +static inline const void *__tag_set(const void *addr, u8 tag)
> +{
> +       return addr;
> +}
> +
>  #define __tag_reset(addr)      (addr)
>  #define __tag_get(addr)                0
>  #endif
> @@ -301,8 +305,8 @@ static inline void *phys_to_virt(phys_addr_t x)
>  #define page_to_virt(page)     ({                                      \
>         unsigned long __addr =                                          \
>                 ((__page_to_voff(page)) | PAGE_OFFSET);                 \
> -       unsigned long __addr_tag =                                      \
> -                __tag_set(__addr, page_kasan_tag(page));               \
> +       const void *__addr_tag =                                        \
> +               __tag_set((void *)__addr, page_kasan_tag(page));        \
>         ((void *)__addr_tag);                                           \
>  })
>
> --
> 1.8.3.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxMQ5m-_eeQUPM2DoN%3D6OV-1uC6NX3dVnSKcmEqwSM5ZA%40mail.gmail.com.
