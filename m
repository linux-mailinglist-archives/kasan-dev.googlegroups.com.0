Return-Path: <kasan-dev+bncBCT4XGV33UIBBSW5XOYAMGQESKM2GSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF876898DD4
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Apr 2024 20:17:47 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-3c4e9231a20sf1328810b6e.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Apr 2024 11:17:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712254666; cv=pass;
        d=google.com; s=arc-20160816;
        b=PDAJNbWQxNZUKAIh6yhEycIsYzds5sx+5N9IXVlz3Wp06RH6XvR63E+D+cwgBGZDrm
         4yzi4rv6WK7yCAsgHpHgfuOp+uPy5visVQpMg/+K+g9bGBBgYeDNQOMGgXLISibNh9aK
         rAYSEmuFoEGYAxn2+KXQNZzzKwlj1QLdynr6RYZdJgFggUcg49K/sGUn2HRo3pr8Me+H
         JwQUNz/rIhxkJmZmtCrIIfYG6mbLD6dhpP65AUtHx+npirFc+1d+buAqAJagX0Xg/VmN
         fIYtxolyWb38lvdOc/Y6+gCtlY1RKbr9Zh7Sm/zNUpUbjUaIOaI953nlk3/wBNVNhNy1
         wLPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=xnebtnMa4NF2/oq9zR+xwzW8sXJLG8qGF524RPU14PY=;
        fh=TSv3//KVDo5y+L1ZEXo6mb+FMc7W9/y07IF7kvpbciE=;
        b=NcuUiD5wx+RUxQi1ZGQVwSKeNsoochCE6uSPdIHO/onLJgEf0Paqd/rfkLNv8fUM2z
         849RO2GOe+hwirxzK85CuFipH26jrFWD9hgNVDjtcEDaScLLGLkN3PhzcLJ2f2unYsb5
         qpO4I6/xFdCGby1gDteukjyboxD8PafFqUtFPtKVcxsNuQJoa/RnSq2L8quxLeJJ/SKi
         YyIJDwGYts1s8unzI+HW7k88HI4G/+6byFU8VIjgA8tT4/NKEDsX/XKwY4igt3IXdtQU
         PEXVNZhmvx69TDWQ5q90KOU00AYslPtthxqKZZ494HWrHtLM4my6oeVx+jIiTZrNOtdb
         Rn+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VKWxIBSO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712254666; x=1712859466; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xnebtnMa4NF2/oq9zR+xwzW8sXJLG8qGF524RPU14PY=;
        b=lW8LNfCzBVIuNCDdTjSjnVC4yjNPRIOqCRqNVK02MNOE31KZsBPiqSHW+b1x4eReax
         89TrmKbf1BuXTlm4cOHKK7TeDig4M7sGnEul+0jFUNoqrcS/jomWBG/qNWkaR+5OyfVW
         dR3ZZCOEGJX3Dj/7CsTGZ6ALZZzVoNSAW82bsjRVSZUYhBCVIehX+ao2ZcIcJOX49c84
         +GXnB/mBfdRW9uMB+NGTNBNqj2GNQsweFiIFDZtPIl7rWpVrFyXbFd1JEc1QOTSDHgJX
         zSl/UyZ2mQ24Hr4NMFu0W43Rmne5AM05yNtdu7Gbe17AOV/DDtgnH8LKTK1Fxb63gMkx
         IqxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712254666; x=1712859466;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xnebtnMa4NF2/oq9zR+xwzW8sXJLG8qGF524RPU14PY=;
        b=Pz08Cz2E3JOerP+ucigINucAvW+je9fjkdpPplFOtVJFHH44ixDj90rbENMSI+CyQn
         iw8HQELazD0dAM/EbHA+7Er2MsPtC/y6hIVS2MibkvlHculkq0qxn93EOXUJKXL2mbSF
         cZiETPequHvvj6UWp/koHVr/pCH4XwZmdUv2Vb+osk0nLOsOtzBIud40ioO3ussL00xz
         Qxdhsbs681picRukx4KqtDCPIg/xpAAiEH6nRxEdIc1LkSxTnZm1XSfN7hlDSkfEWWPL
         lLkWlzd80Zgr6K0eCaee5wX//2mFoagl//JRprcpmNghRuFCTXvCuI0LthPny7G7FQnn
         2TLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnQ404xrY+3qci7LA+XpojY9TztNoY/6fqypr7FQCc/i1GWY72Us6Sbu3pmo02OyweV4xOODjhBosgT2EvSOyKnbgJUwu73Q==
X-Gm-Message-State: AOJu0Yx3UURPug04HRugxyBUGNcYN3vTseqD8wD+2bvIJtTnB+BzrQ1l
	6tA3Ka9G9RchUdj4hekjRW0WPiGESPGgZQMuh/YxbYOvMcej9Ps3
X-Google-Smtp-Source: AGHT+IGvMxEdGxd1ls1SnhE9awRFI9bFyjFjQpE3PedkdXUHFPEw9QWvfx7flC6umajQQigqc01wEw==
X-Received: by 2002:a05:6808:207:b0:3c5:56d8:bc4b with SMTP id l7-20020a056808020700b003c556d8bc4bmr135660oie.24.1712254666522;
        Thu, 04 Apr 2024 11:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:c908:b0:22a:b101:1bfd with SMTP id
 hj8-20020a056870c90800b0022ab1011bfdls478584oab.1.-pod-prod-00-us; Thu, 04
 Apr 2024 11:17:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkh5nUcFJIcbPB8u9tNP7Un5wL96Et9hIFAPKXwCUqIfgcm9kfb/9SS4+u8tShOil0sb5eTxwG6RpvYfqvSsiHhHKIwE0x/g/OlA==
X-Received: by 2002:a05:6808:4349:b0:3c4:f529:c4a7 with SMTP id dx9-20020a056808434900b003c4f529c4a7mr119950oib.2.1712254665603;
        Thu, 04 Apr 2024 11:17:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712254665; cv=none;
        d=google.com; s=arc-20160816;
        b=bCiReJzz9JFpya1mps5wSsEQCbN2KJxOuEYmrRdDqONCBOpehKoJw7i4ks/e3jhVUn
         pzCrT75OfuPyc4Pldn/1v81b9QSzJPa9xX1y4Big8qwMmIzaGDGIoTiISSezVt3ytn+Q
         F+nt7eB7qTXSMmtARTe6HaKP7wRk3vjnH+mRzuDWUaLyoV9I94vwkJdzpUReY4oXo5lF
         dkmwY7BZ/lCLOHcbVztaznyzfqf38KM77JPUhemjGf4MCZ8go9SzaFVJeAQn8NHesje4
         O7QD405+VTvxwTvfZF6CMs3EoBtOZL2vx9I9BYUD2qEbivbxW0FXxZ6rDALjIfuBpPM5
         tP0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=83I9k9ZrdsX2r7O7H5Gkj8PYJzbyq6W1ygBD5t31yoI=;
        fh=m+YWFlRqUXjqLUk5yRy3vB91R35Y4Nvz9bDMUD2sCdY=;
        b=DF49f7XYdhqZODfhYIImzyBklmLgbhgr0jDCk+u9oeLPaAzZn1Vj6oRmTfgCo2U5Yi
         TGAR/CcYSk6Jwb40BaHHc4m2IaFmLBWAWyljjvHt0GPUpj/RiS5kN1Nzro41zMf8vIRL
         p/WOrNiH+Qnlhn/EP2lVlYPRNvmeelZOBxF1tYvwFEv0qZ0NfntC4A0EXwn/OeNCqu5z
         YzQZJbJOh94j/dk1mfj/uiY5xhJ+8DokxiJ/2OTJ9kEwuWIJeCPfb+QNYhk77rllCiPF
         xIPgdUWz5PZlXoC6c/xJd/nfGS6CqvFg8rrvc6zN7pE3ia/GjCBT4Z9b12q9wFp/lXun
         ka+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VKWxIBSO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id eo7-20020a056808440700b003c3c59ac917si1019847oib.5.2024.04.04.11.17.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Apr 2024 11:17:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 4D53F616D9;
	Thu,  4 Apr 2024 18:17:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A4C39C433F1;
	Thu,  4 Apr 2024 18:17:44 +0000 (UTC)
Date: Thu, 4 Apr 2024 11:17:44 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Arnd Bergmann <arnd@arndb.de>,
 Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: hw_tags: include linux/vmalloc.h
Message-Id: <20240404111744.40135657cd9de474b43d36c7@linux-foundation.org>
In-Reply-To: <20240404124435.3121534-1-arnd@kernel.org>
References: <20240404124435.3121534-1-arnd@kernel.org>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=VKWxIBSO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu,  4 Apr 2024 14:44:30 +0200 Arnd Bergmann <arnd@kernel.org> wrote:

> From: Arnd Bergmann <arnd@arndb.de>
> 
> This header is no longer included implicitly and instead needs to be
> pulled in directly:
> 
> mm/kasan/hw_tags.c: In function 'unpoison_vmalloc_pages':
> mm/kasan/hw_tags.c:280:16: error: implicit declaration of function 'find_vm_area'; did you mean 'find_vma_prev'? [-Werror=implicit-function-declaration]
>   280 |         area = find_vm_area((void *)addr);
>       |                ^~~~~~~~~~~~
>       |                find_vma_prev
> mm/kasan/hw_tags.c:280:14: error: assignment to 'struct vm_struct *' from 'int' makes pointer from integer without a cast [-Werror=int-conversion]
>   280 |         area = find_vm_area((void *)addr);
>       |              ^
> mm/kasan/hw_tags.c:284:29: error: invalid use of undefined type 'struct vm_struct'
>   284 |         for (i = 0; i < area->nr_pages; i++) {
>       |                             ^~
> mm/kasan/hw_tags.c:285:41: error: invalid use of undefined type 'struct vm_struct'
>   285 |                 struct page *page = area->pages[i];
>       |                                         ^~

Thanks, but I'd like to know which patch this patch is fixing, please. 
Is it mainline or linux-next?  I'm suspecting it might be a fix for
fix-missing-vmalloch-includes.patch but without knowing how to
reproduce this I can't determine anything.

> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -16,6 +16,7 @@
>  #include <linux/static_key.h>
>  #include <linux/string.h>
>  #include <linux/types.h>
> +#include <linux/vmalloc.h>
>  
>  #include "kasan.h"

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240404111744.40135657cd9de474b43d36c7%40linux-foundation.org.
