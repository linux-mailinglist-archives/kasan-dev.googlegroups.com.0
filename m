Return-Path: <kasan-dev+bncBCMIZB7QWENRBEGAZWAQMGQEFH5Z5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 64707321179
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 08:41:05 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id x4sf15697110ybj.22
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 23:41:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613979664; cv=pass;
        d=google.com; s=arc-20160816;
        b=0AaMjsb0CzAdcqz59ldeO30N0291iIR75gXQd/vjB51hA8/vwki5j0/9MBG/dWQpAT
         S3bzq+HHMOGPBRDkptVBz8T3DIpOr9XoTWld8VonoTE8gRxnvjR5AWJ6VN+oRMsGg+gC
         TrDMSzfiUGA7wUMlfUgAc6UAgKJPfmBIt3cbfVMUzYq1MZpxJYVUzyJklAvSc783NNrR
         Z0AHED+A6SOxnaQubfZNIJl4etoIqZmnB4DtKN+oFswAe7FQu0Ua2MGOZ3n49H9hbweQ
         YmvtcdhRAIsbFVDnx5LBNHezCKuxGg3lHCf2+UdrqWGG+mx3QSf5K5qxE5ne7izw5Vjk
         E3ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9f51x7NQyJLkwRk3sLoRiYfUkeytz4TUXhMFP1P69oI=;
        b=fP/Cl73nkkCsigqxnxX27y6y/97UtzU8TdLhsjNfEXpZjyfVENk5OYXfm4/7O+vsOR
         H82N+H7gRhjAwvrKWotgTaOcbMRsq5em17N+zaTZYy63s3heCrQJYrBBtKJyIbRo5c/5
         TEDv6vZokD5aAramH8ti517wEUKVqpqSOZtLJEmrdKtTIbJEqP6IDcFm1RhEkXXkgcIs
         rlu+7KCxR2FDOx1z1QINlniI4kX312ZFAS15ds+Eoa0C81fSkAv/faMjTKC4ZrhE0hVM
         bkCnFp6uEnUaT/zyWfEo6PyTY9VNlx/d9nqPSp4Z24FgFEfmaAP7sG090cMlVOvdprS2
         j9bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nGMJCi59;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9f51x7NQyJLkwRk3sLoRiYfUkeytz4TUXhMFP1P69oI=;
        b=iInDYFNy8BdUZHrlnZKBGGK5fFOdaHsgPIrLFogmFLmuQAxnNEY7iosm+9TpRWOBRn
         Wxpl25vUxDGIMKQUmF7z92ZNewpt9wHdu8tQ4YPfwRHkP+hl/mE8iVZveDUOD4e5z9ri
         p37ZbrB7cfYeZRSqhs79cNzQtFZ24scoC/AyeeACZ76+ouir0aAHq4R/TA99NSQp6Ju4
         Vwjj+gULjMwf5hc9oGO0jXCEmGnW24JH91Xw46IFLHGV/GYBTyqOuHkS9eaFfaejX1G+
         hDGRuZ9hrjl/xcyhgeVm/azUSSJzV4UsnqlQ+6o5vn+eF7SyipSjg9esQXb/IVx/Ohgm
         B5sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9f51x7NQyJLkwRk3sLoRiYfUkeytz4TUXhMFP1P69oI=;
        b=IdwfMg4aXrzXf0+2hx+i0G7oo/PIbJYrRRgMVFmM7+8xfsY+MQkG40sDbDDRZEnZYh
         6HDyiF3miBVKr2/W7LDGWl8110At0BHS4iPeAIAbQ+7HZKsPR4dYsu7/M7e4CrJXHxFz
         fJbrKAEIMccjvkWaNrWfPVmUC8ZjFW75uoC8SSl61Evpg6oZVaJaXdcLsKoZ8E0Yzqoo
         ozjYkU3QJeqF73zPE49TAd+b3Lq9UGeKN2+ecRjvDGq/c3+a2tgKKBsFJbVgXHYGWuhq
         8cCyKi1S0EJN9gvPyhuobMcGYl8uvqpxks600sP9Q/InTnargQ6kb6toS7uvv2WIoKeP
         p9lg==
X-Gm-Message-State: AOAM533qc3naQgFBQavnzYHRthzFt0YN2o3cSdJ1L6CMvK3uW0ORR2MD
	jZma610Y4lMMiAuZuRTslkQ=
X-Google-Smtp-Source: ABdhPJyNj+3JsFc1XSBB2h3YcqBvkgkgclIm4GZPd6fuhvs5jL1RC11LA9OKHOLJj2BNOsvg1WjRnA==
X-Received: by 2002:a05:6902:68d:: with SMTP id i13mr12283390ybt.334.1613979664208;
        Sun, 21 Feb 2021 23:41:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3006:: with SMTP id w6ls7848647ybw.4.gmail; Sun, 21 Feb
 2021 23:41:03 -0800 (PST)
X-Received: by 2002:a25:5289:: with SMTP id g131mr6325546ybb.178.1613979663772;
        Sun, 21 Feb 2021 23:41:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613979663; cv=none;
        d=google.com; s=arc-20160816;
        b=gTSWcHs4uzKtoTJihI8AtBBWYye36fdO7w3MzSSz3g9/GjzePncBgc/50+NMM19K+y
         C/hjjiWysk2hIajhl3Lm6hNMyWRgRO5zskKFRoSmQDKg+QBpOBuZSXaBMWWydzbfIu4b
         V3KzTKKt0hF+5+OSiCDmk7UvLVTLqVLbIXGcHDEn2qgczB71IIJ1uPzJwzkd0GLQaRai
         a50jSXAah/PcZmBmRMyYBSBXAj4am3LwtGKoNcuvnhCpdU8E+l2lOCbQ3zZ3nTuDXtZn
         kW8doxpxVBXla4boFKfpgsdaNPqd+cBq+6vKO4/n1QYf0uE06HJtQPtrRD1lLZ6U4RO5
         antA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DA1rxnC139fkp05L9pB0MTnjTfTAu6RLwtL0vBni21U=;
        b=BB0RMvDgaR4n6m7hWELrzrE6849/Jq4yhIvXCE+0+fuo80+D9Ks1EtyQY8FDMM3QMb
         xnzPoagLtbtsm0oq0PXjUxGq2vsNudcX+ewVElBtLfcFCN8VgPQ4mGIwJmql79RZ0vjO
         Knh74mJpaBYmS372WeMrLr/JwjwNIsiu3l8oycNoWhVeyorvgqI+IYkh2J4/ilMeMFlv
         eY+8gzgD5aNVsNENvYzcCH16zRmdBaU6OWQZxg0+HDeiWPuVeQ5RJud7dU6QkCpiwMir
         PkhvcDreluAqCY0b2Af4uU2YYp4YOslBl/VkDeWKd/Hf39pyUDGrhCYgng4N/zdMF84v
         2A0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nGMJCi59;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82b.google.com (mail-qt1-x82b.google.com. [2607:f8b0:4864:20::82b])
        by gmr-mx.google.com with ESMTPS id c10si1165909ybf.1.2021.02.21.23.41.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Feb 2021 23:41:03 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82b as permitted sender) client-ip=2607:f8b0:4864:20::82b;
Received: by mail-qt1-x82b.google.com with SMTP id d8so4531860qtn.8
        for <kasan-dev@googlegroups.com>; Sun, 21 Feb 2021 23:41:03 -0800 (PST)
X-Received: by 2002:ac8:7514:: with SMTP id u20mr19064148qtq.66.1613979663168;
 Sun, 21 Feb 2021 23:41:03 -0800 (PST)
MIME-Version: 1.0
References: <1613971347-24213-1-git-send-email-daizhiyuan@phytium.com.cn>
In-Reply-To: <1613971347-24213-1-git-send-email-daizhiyuan@phytium.com.cn>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 Feb 2021 08:40:51 +0100
Message-ID: <CACT4Y+b3-EN7FbCGCi7L_OdW-LM0Orgzzm70v3QPjUe14xn2Rg@mail.gmail.com>
Subject: Re: [PATCH] mm/kasan: remove volatile keyword
To: Zhiyuan Dai <daizhiyuan@phytium.com.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nGMJCi59;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82b
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

On Mon, Feb 22, 2021 at 6:22 AM Zhiyuan Dai <daizhiyuan@phytium.com.cn> wrote:
>
> Like volatile, the kernel primitives which make concurrent
> access to data safe (spinlocks, mutexes, memory barriers,
> etc.) are designed to prevent unwanted optimization.
>
> If they are being used properly, there will be no need to
> use volatile as well.  If volatile is still necessary,
> there is almost certainly a bug in the code somewhere.
> In properly-written kernel code, volatile can only serve
> to slow things down.
>
> see: Documentation/process/volatile-considered-harmful.rst

Nack.

This function does not require volatile variables. It uses volatile in
the same way as C/C++ atomic functions -- it only supports operating
on volatile variables. The same meaning as for const here. Such
functions need to use all possible type modifiers to support all
possible uses.

Anyway, the function is declared in kasan.h. So you would need to
change the signate there in the first place. But the kernel will
either not compile, or it won't compile in future when somebody adds
__kasan_check_read/write for a volatile variable. Such a change first
requires removing all volatile uses from the entire kernel and banning
volatile.


> Signed-off-by: Zhiyuan Dai <daizhiyuan@phytium.com.cn>
> ---
>  mm/kasan/shadow.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 7c2c08c..d5ff9ca 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -25,13 +25,13 @@
>
>  #include "kasan.h"
>
> -bool __kasan_check_read(const volatile void *p, unsigned int size)
> +bool __kasan_check_read(const void *p, unsigned int size)
>  {
>         return check_memory_region((unsigned long)p, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__kasan_check_read);
>
> -bool __kasan_check_write(const volatile void *p, unsigned int size)
> +bool __kasan_check_write(const void *p, unsigned int size)
>  {
>         return check_memory_region((unsigned long)p, size, true, _RET_IP_);
>  }
> --
> 1.8.3.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb3-EN7FbCGCi7L_OdW-LM0Orgzzm70v3QPjUe14xn2Rg%40mail.gmail.com.
