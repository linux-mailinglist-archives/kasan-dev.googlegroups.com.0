Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUMWVSDAMGQEBVW44QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 985423AAF02
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:44:02 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id j10-20020a2e800a0000b029015f88d3e725sf2419047ljg.6
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 01:44:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623919442; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZvGjpqeVb94Zm0jgH4WAjxPm5evHWrUwncEJTeq/+5B0Lb455HjOiOYnEGCixS/6dh
         ZWIu9Ksavg7mdSmB0NqZMnpx5s5gm0AKqltzDYd0o/wsu+D5+LKK8eYX4GkWTKvhdlPH
         rhYUe5zmhM6WnYxTzobEErFTjDW6tbKVZjKRRm5BhOHI3mSaRFKUJsA5QE7yl1HNcGpA
         rJZhzoQnATDPokl2yjnbZiSU/Q407vHNsz/P069bc00yTmCsx3nu5iEeLlk/8wRfy4Sr
         jMgpZCVVRHHl4vpgHoRQwtjOZEVq+KheeILknSVJuwZu39RHtuSOk5FYMp5MDaEUrvur
         qDvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=04WucXMO4R9gEnwkNKybRDtTUe9jSvkDTsor/NEt2Kg=;
        b=JBj4Ap0m5yf+XAiaoj3RbHEIAMlJATCIcxcngq3GVEuMriW8wmXSz7LAZ/WMfHF2m2
         3QaFEhNSCV14u05/1uquc5PGzZ5B+nRVJpuVyXM0bNyuy6FOktt+0g6AJJRU2HPzgYlS
         VSBLvHTr59oBrTQRfzQBy4OFEKgANmLpBN8gOHjOhgmUNO1zDbi0Il9VqzXI/dUU5QXd
         JBIdV0S2GoJfKLaltVh5OLLKF4b3k8aRlz5+qMjlzpvMDQHr2SLS1GA9H5WpOH82ooi8
         /vUexTfDyTpImF6nUO8Vk+usnV8Y5XlxhwzE0gunZZCZORu4GYkVRzd3FEziZAOxt7QR
         /Svg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RKz7GWfE;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=04WucXMO4R9gEnwkNKybRDtTUe9jSvkDTsor/NEt2Kg=;
        b=kRfJrEbFxWJpZxjteRwO3kN2TMoF6p6TVWIQdOvRlm0lP3ZXJMzZ8v8j1K6/ff1KA2
         gv4QObYDpkgdI15fl23sn0sIRZ9TwpiJLOBO7WtVDud5z04g9RTdxIuwlkc7vx9nQj1V
         WVo8/WINuulmLULrxPpulj+kUGG7VLMpgb5RCXOzH3/ny/BlQbw2jvUhDM5MKlZYwVAf
         EcTi+FvMtgMhcnUDXIHKn1WA/xC7//rR2uW69cFEBu0rsX1kuX2D5bYFpRwjMhDP6lvV
         0cLyZf2p+c+qorOMsKI5Y1SxEYqw63I4QqI2g36wYd8ZggRWixtvcSdeEg81tcNdcyY1
         zuww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=04WucXMO4R9gEnwkNKybRDtTUe9jSvkDTsor/NEt2Kg=;
        b=TPc/1J/rvQJ9S8SWM9H3wOwpB1yIX8RxUUFVL1qPBGlpEM1ZdqOib90L4FhaKg2b/Y
         WftrpvTu+UPM7a7WUososflEFbHMvhBf6bC7qrNFj0EnEwuCjYn6jY0xvffaUcwU1E5j
         xOUXWjXE2nekiweKwDcsY2GFHzSNgkGy2yeAUpvqlCoRDL+puP3TdPib+tX1jNUaJ3hB
         mE5qqKwcYNiByayqWJx0iqH948WYvV20O+E43NzngZNtgmrJclxn4icxWgke1Jw2WQsz
         u4eexiCg2PXoEMZIMt5rRUgOo5CZj+p2GDqXhnd4YMSMp0uBbph7jkHmt+dP7bO5btZf
         A+4Q==
X-Gm-Message-State: AOAM530fII7R/zA6GXamzg6fq/oMAr0+g4IHfjxIiAjiK7mSJLt6M7q5
	cdnqUj9gkq7MV3lNv7e4Wdg=
X-Google-Smtp-Source: ABdhPJx8SRMQrMzxzY+dL34Td8mJJUz1FKu9ZepcShQGJDjqD2VgzLpFg0Syge98NRc/wX0G8DbZnQ==
X-Received: by 2002:ac2:549c:: with SMTP id t28mr3059011lfk.205.1623919442186;
        Thu, 17 Jun 2021 01:44:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:f515:: with SMTP id j21ls799372lfb.1.gmail; Thu, 17 Jun
 2021 01:44:01 -0700 (PDT)
X-Received: by 2002:a19:f809:: with SMTP id a9mr3327291lff.342.1623919441062;
        Thu, 17 Jun 2021 01:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623919441; cv=none;
        d=google.com; s=arc-20160816;
        b=aYKliGzoODWZfsyXMmpZlB7vgYjvpB05PMmlJtdGA73ELb2M2wbSWRB4IBfsrBQt0i
         FVlAQe2bDHxYz4evoziHdy9PUUciueBzQO3VZViEUsBspJbqZS2CAhbWOz7tbOAmLnnO
         +IFIaAO0+oFi30IDzllurHOWfro5/8dAeHoPUsYx0+8K5bmW/BATtRErsfJuER4Xkj5U
         ygU0HUAiUMZak1M3rWuDBcAN2Do76hPXB7GEu+MGoeNBco1jDqagesxF9VnJjtNVl8p5
         NTHYb3MrifQWrg6VHXDjVGQAaFHkfSHLqcjNfdaux1nvKzL8ihOBbe4dVKVsxmtXEi6a
         TfLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qse5cGxpg1Wx1K/bFNdJr9abCnEgN9q8mxTJmYsQZpY=;
        b=ZQesKsgGsMMHvDlvOGWxJDM0DbPWr0U/yc2+Y/TZUiREV4f8of8dtONgntq1ivgeKT
         QUwNAQKU31EmvGMhDTdgka5p7eDqKNExQ6L06xJcYEzpNIWzUJpNn4Ecz6hptZ7/r5MF
         mUjbVFhTYa6Lw29x/j3nCNxv25+vP2gBxWSFmaRe2ZuyCK4RRSZvRaz1wAHSZ4XLBmU4
         e5MASLIqPIyq5vh7D8QXeHE2/qOB55tTeBZ0HbjXvdRYdbXhKelssHVsfmXhhiBl44hN
         nvD3nYVI2AHLRL1+74pyYEng6ZtRO/cJjl1K5augiqAMybL+R3Dtv0U1bYUgCUF1fBXJ
         4aGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RKz7GWfE;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id j7si30514ljc.1.2021.06.17.01.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 01:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id r9so5765537wrz.10
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 01:44:01 -0700 (PDT)
X-Received: by 2002:a5d:5151:: with SMTP id u17mr4339152wrt.302.1623919440466;
 Thu, 17 Jun 2021 01:44:00 -0700 (PDT)
MIME-Version: 1.0
References: <20210617081330.98629-1-dja@axtens.net>
In-Reply-To: <20210617081330.98629-1-dja@axtens.net>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Jun 2021 16:43:49 +0800
Message-ID: <CABVgOSmYiVA008enEkGy4XTooVQ7DftXvWySFLL16bZETocpqg@mail.gmail.com>
Subject: Re: [PATCH] mm/vmalloc: unbreak kasan vmalloc support
To: Daniel Axtens <dja@axtens.net>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Nicholas Piggin <npiggin@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Uladzislau Rezki <urezki@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RKz7GWfE;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Jun 17, 2021 at 4:13 PM Daniel Axtens <dja@axtens.net> wrote:
>
> In commit 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings"),
> __vmalloc_node_range was changed such that __get_vm_area_node was no
> longer called with the requested/real size of the vmalloc allocation, but
> rather with a rounded-up size.
>
> This means that __get_vm_area_node called kasan_unpoision_vmalloc() with
> a rounded up size rather than the real size. This led to it allowing
> access to too much memory and so missing vmalloc OOBs and failing the
> kasan kunit tests.
>
> Pass the real size and the desired shift into __get_vm_area_node. This
> allows it to round up the size for the underlying allocators while
> still unpoisioning the correct quantity of shadow memory.
>
> Adjust the other call-sites to pass in PAGE_SHIFT for the shift value.
>
> Cc: Nicholas Piggin <npiggin@gmail.com>
> Cc: David Gow <davidgow@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=213335
> Fixes: 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings")
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---

This fixes the KUnit test failure I was seeing on x86_64, thanks!

Tested-by: David Gow <davidgow@google.com>

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmYiVA008enEkGy4XTooVQ7DftXvWySFLL16bZETocpqg%40mail.gmail.com.
