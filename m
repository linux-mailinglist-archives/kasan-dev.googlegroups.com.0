Return-Path: <kasan-dev+bncBCMIZB7QWENRBX5Y4XUQKGQEQY34TPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3d.google.com (mail-vk1-xa3d.google.com [IPv6:2607:f8b0:4864:20::a3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DBB0574848
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 09:38:08 +0200 (CEST)
Received: by mail-vk1-xa3d.google.com with SMTP id o202sf21291662vko.16
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 00:38:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564040288; cv=pass;
        d=google.com; s=arc-20160816;
        b=MwZ1QKTSoJJinmwc7Gm3W4hhNxFl0wofIen6Uce9akZL8a9RZ2GdQG11v+2QhkuhFs
         vCC/03MR4JgSPcwsiaNbSdLWpS9duRYyBqmNYOJ3iMdKsXbzWdG3M/oDLUXBwi4Wjdco
         f1lIUzMQmNN+9S44EmtQhXnOoE/nuv8Ju0noLKyfbi8DNhk1e64Oej0weBhBmAFKsFIN
         bWpuTslA3SstVHW2wyvpHP3ryXkDiE+D/0GcZdbUE5trYfjdG3dCJLbbMA50NCL7lIYW
         87rHgEsu2PMp8EYBtcJz9vBmSEdeKG6m3AnIui1wEj7oBlNrb3Ea9B1O25qSUcLYU7jO
         iXRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VhT5Nb0eNo+xrHW+RxLPCGPzqI4URZzYpvZw0OczWHY=;
        b=XCJCvY3ENrYykCeLfGsdyk07FBI8URcs6469D1YKVkccGG4CP2PCZXsNcPnNQIujrB
         23S0QCPuYe6Or8lgUl9Z/L7p9VgV095A8gS6xV7PzTRgQUY5zWvh8jBrdGbKSaJhxSuW
         54U9m7wt3IemZ+BtPVnmGQ2Ml1axLvitcmEA1tTs9WPlezIMzGmXpdRqD666DHMDaD4R
         Faau+LVTNxWMusi2//x6jy6LT9iMG3mGdECDgJthZSJqTG0O8MgqnS4V29ePq2j3xS7X
         chW47BjicQUe6iq6+j6tlLZ15diPf74U18buFhJKw/3/2RRjFhQyF7rFlnABhfuWvHCu
         CpGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fr9l8juY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VhT5Nb0eNo+xrHW+RxLPCGPzqI4URZzYpvZw0OczWHY=;
        b=OcolA1KvxN2LSwjmAcwJ3qZ7CwfIr7upUqS6W6OlE5vlRF5qUdsuQ36L2xY2G8q3Eh
         0TMapA2eEljED1nTYnEt0DqAEwDighUOy8vycn8yWe8tMB0xJf5IQdhxxOjAqPlatTw3
         +g3rYg/+XXNC6qIOI08J6/ESjKpikuPsUblx3QUmKt7O31ZljfU9JAB0IklpGCeiHb5x
         h5WaAejOKx8KgDIBEm/z96FOxgZtWAH7aGWTYucjQ6Knpn1yf54RPGd5tcXCb0fNPVNn
         RFNSdml3DFDcxu4YlfR7RCxLLsQ84q/XCoagR3m+u6Jh2qNUMYb43U31lkmnvZUAQODU
         Wwjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VhT5Nb0eNo+xrHW+RxLPCGPzqI4URZzYpvZw0OczWHY=;
        b=c3VtL4dNAiKFpwHoyIrfAiSts0560xaHkhAMKEJoqhIsXq9W0vqKq08rskZ4Tu0OnN
         LB3CDW29eXUMVEVW4nskJ3Lyx5iCh6e23X0we76hDcVk9zmfUZ9J9trvbtEt4hmRUmiA
         75yed5ZTmoPK4lEUKZLhnFV/dXnOneNuODCjXAVKbYayR8BDkM3w05pH5Sl2zsF5nuKV
         NuesU6KUg2IObz8BPwTihnl2lgyi+ahJHToZDUt+v8fPtns6HSF+ivLAsnKQ+GCK5XuU
         28aGkoUPTZw7WIbn82RgZR22vMZ3htWlHAkmZyQ5pKAmPR5RQKHayq4RoU8amb2QhYDH
         0zrA==
X-Gm-Message-State: APjAAAWUxuQs/tyOdkCZtLcqgNbkNl88OY5Z4NSWGtNYm0/Nbzg413CR
	LOJRaqzUYcmNkPQGXgqcxjw=
X-Google-Smtp-Source: APXvYqyHlD3I17gmOS8zGUn3wiLxaP0s9U+56b+U431EW8KynspKWSdaQz6DVtE/cnoxmDn3gxcRoQ==
X-Received: by 2002:a9f:2027:: with SMTP id 36mr5887054uam.52.1564040287985;
        Thu, 25 Jul 2019 00:38:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:61c6:: with SMTP id v189ls952468vkb.10.gmail; Thu, 25
 Jul 2019 00:38:07 -0700 (PDT)
X-Received: by 2002:a1f:e002:: with SMTP id x2mr23136864vkg.1.1564040287705;
        Thu, 25 Jul 2019 00:38:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564040287; cv=none;
        d=google.com; s=arc-20160816;
        b=Jbu6MrV6GgZqjMghLReKe1lohqqG5R+SuxLfiSO6UFn0OseKNIRed9CZ7+pLsSq3bT
         VI70/mpf/zuIF2ackzjcgcgLcO1o8SCtrSxzkxz5ThLDr//SO4VYZ0NaqAhz8fcubmaY
         Eap+QW5reDFfOFfP/mT3CzwmQkyX9DsHTO9aWAjfVOQQcf/9c+GZdLAdRgJiOqlq/Bxa
         1yveYQqIeXWU1sojn1OroZE/fMDXUwo15fV7ca/sc8efm5YMTSEL8JzX26TtWzeGb/Ju
         VguOEytLoFhSloRBmX3YnL2PunUGgxdWwfN+FENFU+SphkoBuONENPEtShv3E/FxfxJu
         G1Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xNvB2ONftmaWiXRhMLu1nth3BAaraeOQSf/+WChcARs=;
        b=OLduJSH1+2VHjhwj8sDZvzGlwJMCz8Uu3IKll5GbCi6w19B8SIsSP/is0B3SOiCGTx
         v8QfqoqZgkAFu0fvGgHSX4nqdQinTYm7cxH5jqmM1J0/YXbeAguL8ikCQK7fePQlZpo/
         kufSRquK074wR07FtXApsr7dIgihULLVJNQ6o7bPTu4ZRQclhLW0aWqqZ2asLduIyaCZ
         D2MFXGtkh5rDa3wXJsdtlh5BBNq0X5agozCvDoF+fztrPAuZCMSgBGhuS5YYvQDPhq/E
         h1jhbDI4pPkTfCEuOVwq8PpPBgaQ49JW+vKUnzJJJR60b7qN3zlyVVMFUEh7n2Hp+rgu
         HDMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fr9l8juY;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd43.google.com (mail-io1-xd43.google.com. [2607:f8b0:4864:20::d43])
        by gmr-mx.google.com with ESMTPS id k125si2636511vkh.4.2019.07.25.00.38.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Jul 2019 00:38:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43 as permitted sender) client-ip=2607:f8b0:4864:20::d43;
Received: by mail-io1-xd43.google.com with SMTP id e20so64829882iob.9
        for <kasan-dev@googlegroups.com>; Thu, 25 Jul 2019 00:38:07 -0700 (PDT)
X-Received: by 2002:a6b:b556:: with SMTP id e83mr78484315iof.94.1564040286860;
 Thu, 25 Jul 2019 00:38:06 -0700 (PDT)
MIME-Version: 1.0
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-3-dja@axtens.net>
In-Reply-To: <20190725055503.19507-3-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 25 Jul 2019 09:37:55 +0200
Message-ID: <CACT4Y+YDjnv_GhGkN7MfjTD-KmA8W6uDkwn0isxRoANTVFD8ew@mail.gmail.com>
Subject: Re: [PATCH 2/3] fork: support VMAP_STACK with KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=fr9l8juY;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d43
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Jul 25, 2019 at 7:55 AM Daniel Axtens <dja@axtens.net> wrote:
>
> Supporting VMAP_STACK with KASAN_VMALLOC is straightforward:
>
>  - clear the shadow region of vmapped stacks when swapping them in
>  - tweak Kconfig to allow VMAP_STACK to be turned on with KASAN
>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  arch/Kconfig  | 9 +++++----
>  kernel/fork.c | 4 ++++
>  2 files changed, 9 insertions(+), 4 deletions(-)
>
> diff --git a/arch/Kconfig b/arch/Kconfig
> index a7b57dd42c26..e791196005e1 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -825,16 +825,17 @@ config HAVE_ARCH_VMAP_STACK
>  config VMAP_STACK
>         default y
>         bool "Use a virtually-mapped stack"
> -       depends on HAVE_ARCH_VMAP_STACK && !KASAN
> +       depends on HAVE_ARCH_VMAP_STACK
> +       depends on !KASAN || KASAN_VMALLOC
>         ---help---
>           Enable this if you want the use virtually-mapped kernel stacks
>           with guard pages.  This causes kernel stack overflows to be
>           caught immediately rather than causing difficult-to-diagnose
>           corruption.
>
> -         This is presently incompatible with KASAN because KASAN expects
> -         the stack to map directly to the KASAN shadow map using a formula
> -         that is incorrect if the stack is in vmalloc space.
> +         To use this with KASAN, the architecture must support backing
> +         virtual mappings with real shadow memory, and KASAN_VMALLOC must
> +         be enabled.
>
>  config ARCH_OPTIONAL_KERNEL_RWX
>         def_bool n
> diff --git a/kernel/fork.c b/kernel/fork.c
> index d8ae0f1b4148..ce3150fe8ff2 100644
> --- a/kernel/fork.c
> +++ b/kernel/fork.c
> @@ -94,6 +94,7 @@
>  #include <linux/livepatch.h>
>  #include <linux/thread_info.h>
>  #include <linux/stackleak.h>
> +#include <linux/kasan.h>
>
>  #include <asm/pgtable.h>
>  #include <asm/pgalloc.h>
> @@ -215,6 +216,9 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
>                 if (!s)
>                         continue;
>
> +               /* Clear the KASAN shadow of the stack. */
> +               kasan_unpoison_shadow(s->addr, THREAD_SIZE);
> +
>                 /* Clear stale pointers from reused stack. */
>                 memset(s->addr, 0, THREAD_SIZE);
>
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-3-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYDjnv_GhGkN7MfjTD-KmA8W6uDkwn0isxRoANTVFD8ew%40mail.gmail.com.
