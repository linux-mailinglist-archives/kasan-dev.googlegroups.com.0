Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQM36SEAMGQEQGES7HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C41EA3F04FF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 15:40:18 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id q15-20020a056a0002af00b003e2840527cesf1302123pfs.11
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Aug 2021 06:40:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629294017; cv=pass;
        d=google.com; s=arc-20160816;
        b=xwIint9yDMEmkhRXurwUXQqrmX3Td9fdC3YAy0VMAcTPDyoqnj0qQMlgozV7ouZcFa
         nlC45FYh4yuA91+ZBLPALC5U/bhQfrORYWzvAaDqcz1mpVxYDQBPf+rd7dyaMg1trpr2
         kYQQu+Fjdc7lhZsz5K04s/DHp/8eEFy5QBjmr39vUE7ZJFa99zebNVb46Ko5spl+5XcG
         2xZQgIR/jN0R84XdRQEW6yHZkpH3GQ/H6bapH1mFgQs3e9ZYPnNId9yb7FH8whbwjuL4
         qj9+4Zkxp1H8U5+d8LPImVrKKyl/7evVDkJcXhZ1nxE6/u6Lp/A4rt1CBM/FLmceLvB2
         /klg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Pq/pSEWO9t+ccN2L/t94xlt9IqoQ/iuJoM0/Oy52AxY=;
        b=RHPh9CuGJxuN60EVAgaOUKJETB2DJ8ict2xwLnOqA3p9hwrqhl0L+E5vB3WMZfTMjB
         R/urAfyDyXNqHtHAfrWVX96jusOAp6Box4AuCd5qlOtEmmeDRAg4szmjM55WGDYxVOgQ
         H/fHhbjju2Hv1EywIAMGapKnYnybqPco2LA5ewntJXjnxGoulwaa4hzQ600yj2WJgd0j
         pI8ApmNhC2ho+y82ZWtXxuWQ7H1x8b2PbLF0zeY2QPbkzECtGwAXUoZZ8re1PNNyAEHV
         KFM20fFQ0VImKd6l8vMMdwM47WH9uRcd2J+pv71Rghuz9dTYTihy+lUc4s6hEFJonoCT
         91Kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqlv99p3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pq/pSEWO9t+ccN2L/t94xlt9IqoQ/iuJoM0/Oy52AxY=;
        b=FVI/UuQrNBl6FJQvEGMC6dUO16V57IXIMqDd+JmCSHkBu+jpmIfEwBlZ50YDMYQZFT
         F2OLtm23THXCLpxKOfNFycEVrj9Zbl3qQi4el0TZUcrBt74eWWtwE2SBArxH6k9cJl1P
         8WJ6muTbAYBGpeIhULt5wFGonSJexaxqtCIA72Y35ZhyQTZHXQ8jGAhWmsdgscV1i9/k
         q4fLMlQK8zuzsWffyqyHbV6s5Ymwuw67qvklmotE0WaRN1grex28iI67ZHe3u/xvyBQC
         3BLaaY11RGtHmZfu6rUeacg6n6BNJMctOkN/QFHw8GraCAiOtOuIYsNFI2IHhSp+2td0
         M0nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Pq/pSEWO9t+ccN2L/t94xlt9IqoQ/iuJoM0/Oy52AxY=;
        b=h86CGQ8KXUVS6BLFooeg44tymQ35xVvvoDhFW4uY9nMCvKSrdNA15Paa/MrSpWQuJv
         xksLDNKvi4VmG6/lZlTjxJcDS+/SYRnH2J/kdD/D+SF4GnxQgRQIHJmb1M8i2rlGxq4G
         jqOl4vt1kDG8NbUUwJbFxy5pcKXxhmVzTA9jgiDW6+6b39pgpLJXoSMUWmSgkzr/+pyO
         3LDHdJMbpHyTcH1xJVQCTSkVBgmPeescZ/6/Q4vyzI7RnQi2cKEuHTySGIMHf6UAK3dJ
         4oHvkqu7CKmcrOwyje1mG+xe3fc19P4Qm9CZhsNNiIXSyyUjUnkV9aMEOY+ZTK37QBHW
         UJ2A==
X-Gm-Message-State: AOAM531N9LUH+nsk6pfhKxzirzGNphvQDZvchYVigIwJvW4kY1x16TT8
	qRGlwwlZQKIx9sxgUXvhOt0=
X-Google-Smtp-Source: ABdhPJypeXWWiZPaK0LHPXhGYOF0ErLes9AF1/pXEIZjKS0L4m4pIpa3ktKCqyW/OqvAnPo55sFUug==
X-Received: by 2002:a63:590e:: with SMTP id n14mr9033287pgb.434.1629294017438;
        Wed, 18 Aug 2021 06:40:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ff04:: with SMTP id k4ls1145964pgi.11.gmail; Wed, 18 Aug
 2021 06:40:16 -0700 (PDT)
X-Received: by 2002:a62:bd09:0:b0:3e2:99c1:9b4f with SMTP id a9-20020a62bd09000000b003e299c19b4fmr7651495pff.54.1629294016803;
        Wed, 18 Aug 2021 06:40:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629294016; cv=none;
        d=google.com; s=arc-20160816;
        b=weBZJoveRqtopcTjfoH9sFD0+nP+r3VzWtNIWFXpSIHOuX1lyiIBVQFEEM5sXfM6t1
         ASubX3A1buki7PIHPCDxNA4pnVDei/XP+u51pat1l/snUD91vWx1QVxA+h0q1i2paK1+
         W12d7xiCP3wguc5aRc9HlcszXmiNYLPb/y+Vloy7S0cOEYSQ/5IwQpJAGtZySnsvg8pL
         4x6WuEU+rGkuxgEH4BqxNdxuxXg+HBPRhPDs0JQDS5ULKVoF+X6mBpOHvFyOrvU+pcdr
         Q8mnBPUxcmAIikP+etzM3FZdxcyjwS7pOMd1v814qP/EmsFFa+kI7ev8nC42lA+izf1x
         8qGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=92kjzJHPbu8CdHkXkohUqea/s0XZxMJWcWOY/L8K0Q0=;
        b=RtmaVMZzmzm8oJhDX8dkHnmZVkgFHaE/SbKXm8dH9pTyG9prYhI5qWG1XIb2qlvRUp
         bF7Je7iGV0n7bzFojI80H/lYdRFQL4UE/OXLCPYUvbRPBob7dP33DKhfHsHei15+StUF
         HM/mGv3mC2Xa6/nBMSfN2P+3NdXs3yAsAxcZDnmeSBr1kieNuws3wnTdsiPUXbuqOO3S
         4d3JxL7nUv09n4Ff9qgTkBnGCpSewknxUpXrZndB4nIMO6rSukJS8AfUODmv38ILIXy/
         1uAti3eW/QSkeBwyOtHv4ywCn1bSNDWoo9xNA9N1cbCNUEIYqLmmheaszYOznVbb/H/2
         SdVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eqlv99p3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id r9si267172plo.0.2021.08.18.06.40.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Aug 2021 06:40:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id 61-20020a9d0d430000b02903eabfc221a9so3598847oti.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Aug 2021 06:40:16 -0700 (PDT)
X-Received: by 2002:a05:6830:3114:: with SMTP id b20mr3849263ots.17.1629294016304;
 Wed, 18 Aug 2021 06:40:16 -0700 (PDT)
MIME-Version: 1.0
References: <20210818130300.2482437-1-elver@google.com>
In-Reply-To: <20210818130300.2482437-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Aug 2021 15:40:04 +0200
Message-ID: <CANpmjNPX0SANJ6oDoxDecMfvbZXFhk4qCuaYPyWT1M8FNpy_vw@mail.gmail.com>
Subject: Re: [PATCH] kfence: fix is_kfence_address() for addresses below KFENCE_POOL_SIZE
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, stable@vger.kernel.org, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eqlv99p3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

+Cc Jann

On Wed, 18 Aug 2021 at 15:03, Marco Elver <elver@google.com> wrote:
>
> Originally the addr != NULL check was meant to take care of the case
> where __kfence_pool == NULL (KFENCE is disabled). However, this does not
> work for addresses where addr > 0 && addr < KFENCE_POOL_SIZE.
>
> This can be the case on NULL-deref where addr > 0 && addr < PAGE_SIZE or
> any other faulting access with addr < KFENCE_POOL_SIZE. While the kernel
> would likely crash, the stack traces and report might be confusing due
> to double faults upon KFENCE's attempt to unprotect such an address.
>
> Fix it by just checking that __kfence_pool != NULL instead.
>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Reported-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: <stable@vger.kernel.org>    [5.12+]
> ---
>  include/linux/kfence.h | 7 ++++---
>  1 file changed, 4 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> index a70d1ea03532..3fe6dd8a18c1 100644
> --- a/include/linux/kfence.h
> +++ b/include/linux/kfence.h
> @@ -51,10 +51,11 @@ extern atomic_t kfence_allocation_gate;
>  static __always_inline bool is_kfence_address(const void *addr)
>  {
>         /*
> -        * The non-NULL check is required in case the __kfence_pool pointer was
> -        * never initialized; keep it in the slow-path after the range-check.
> +        * The __kfence_pool != NULL check is required to deal with the case
> +        * where __kfence_pool == NULL && addr < KFENCE_POOL_SIZE. Keep it in
> +        * the slow-path after the range-check!
>          */
> -       return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && addr);
> +       return unlikely((unsigned long)((char *)addr - __kfence_pool) < KFENCE_POOL_SIZE && __kfence_pool);
>  }

Jann, I recall discussing this check somewhere around:
https://lore.kernel.org/linux-doc/CAG48ez0D1+hStZaDOigwbqNqFHJAJtXK+8Nadeuiu1Byv+xp5A@mail.gmail.com/

I think you pointed out initially that we need another check, but
somehow that turned into '&& addr' -- I think that's what we ended up
with because of worry about another memory load, which is clearly
wrong as that only works if addr==NULL. Simply checking
__kfence_pool!=NULL is enough. I also checked codegen, and the
compiler is smart enough to not reload the global __kfence_pool.

Wanted to call it out, just in case you see something even more
efficient (probably the only way to do better is to get rid of the 2nd
branch, which I don't think is possible). :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPX0SANJ6oDoxDecMfvbZXFhk4qCuaYPyWT1M8FNpy_vw%40mail.gmail.com.
