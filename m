Return-Path: <kasan-dev+bncBC7OBJGL2MHBB47EYWDQMGQEMCSTAYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 34DF73CB6FC
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 13:50:12 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id n5-20020a05600c3b85b02902152e9caa1dsf2292263wms.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jul 2021 04:50:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626436212; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWjynWumsZ6LkBs2QYpDnn6YOGmHJ/D5Nm0L+ffcHg4rNkCQv7bs4oKLYnJeuyTM+t
         BpikwTEFbKSFHLJa9QeVCXGDt1/gJepn/HrM9ybh+y6MD/O55tq7loLCIr5uKJVIo9yK
         6TFscwBlR3C7+8XIE5jBMkNBbC4PPq3ApJZHJg0sxE1lmVvoMMNhFuwY/TGe14vJabQP
         YKqJaCNM5M3HTSUw85v0EIcVbRkKjTFfo28CGcp3WOCUvzqi5VZPB8rDiy/fcb2wXn/W
         bEkRPe8KwO+rhIXSSbyTUoop4uibkzSJJm3qVRCd4SYx4cy2CPBoXWCmdKFf7m5FAuqU
         vD9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=eNNYzXj1FVGelAQ/OZ66cEPnzumI8fYq6oTSU10GKlA=;
        b=vyWjsixmpTukKHUI3k1Sq/7yok6yYqXkMQpNEZNNwuQGRN/DmFaYwj6yZez58Zuw9y
         WusbVYZ74JueNHvQRppwzwBmOxchEWoq6Uobzi5wZ3xfYFYSDP3b9FviOdR0TfWGrnW6
         1XGieqkXyOYN03RxA9pZHo/vIKqctDf/KrvMmRo4aqYAEFmI21qHrLIu2gtHw3Msow+7
         exv1Ooy3ZHJCXWsgotKD3CMK0cZOy/7Pu0WyUcPoIPqriBu5zNpgOegDctyyVh5lGotl
         utFtTP6q/Xv5r6YKTtqP13rP/pdYT0kQixDBSzrgtK+BjiHcch9r2IOrzAqAEczQGX8P
         1O9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vZIQ2SoX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=eNNYzXj1FVGelAQ/OZ66cEPnzumI8fYq6oTSU10GKlA=;
        b=f8o/7hBO1zrY0AEdWkHQBVqGzuU15HumDNFkku1mH58+YB1tY9VnRabx2zjYdW4at4
         Z/GmRYen1wPQmb56IVGqZQkJ3CH4PdiKcn27wDLYIP+q4B7QnZL54O5KJ+HyumgV5WkY
         LU5RChQU18/0K7lNUr2WxbYTABj2MXB8YqrzUQ93ZgXU7XUy7qE9TB0/yTQmDJy8hMhV
         EAd75vwD26eYC1N8x4au7fMh89meUtcxUeBfH0E3wOBOC0ki3OFKVvjQ272H0995tkk7
         ovMAX3CPw0IO6cg0DC79T/pT/soNk8tXLoQV9oubjIBJ5L811hpMuZom2k+x4a+jj4Oi
         p5Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eNNYzXj1FVGelAQ/OZ66cEPnzumI8fYq6oTSU10GKlA=;
        b=A3dnGfWdn6flBh8bl9ZLOa3vCQgtgjJyL7iaXZIXQEHT9i2C2V4SW88G9glYNi19JI
         3xw6fATBDT/WWsL+5zf5V1MZeWSVTlGylB3cGa8bC6MrkLFd0SU8Rt+b1t1YocXuRZZl
         Mror1qEHmcPfco0KRLHA9x/h7nkLWlI1GNrhv6Jm/UG3Nf+k6x2GA4rFKQyRJN4GFPij
         +NOsNN/ZCnwYtgzAbo8w9meoUfczqlgF3c6JiIz527Ha1ehwkLPuCJocJbbvGiWOlziE
         QtmEVGPqJCq4pDA3lkndlyPZ+ZQ5hlws5YG4YK+x/oGqBfhdkLiBv/4dhO2U2yptxsZr
         7tIQ==
X-Gm-Message-State: AOAM5333TDgf860SIA3RHljstUn7YHbP16SaHPaY9Wvid3nR42GfrCop
	LkqCQgDKkDOjLhh/2xoothI=
X-Google-Smtp-Source: ABdhPJxuUbx1e99TmsvLRupYPMTfJjyJX3o9eGdsZA2mBMZG2lAaLLkzXBgxYw7eOdr5tO4M8DNfRQ==
X-Received: by 2002:a5d:62c1:: with SMTP id o1mr11934104wrv.125.1626436211918;
        Fri, 16 Jul 2021 04:50:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d07:: with SMTP id l7ls7135074wms.3.canary-gmail;
 Fri, 16 Jul 2021 04:50:10 -0700 (PDT)
X-Received: by 2002:a1c:790a:: with SMTP id l10mr10202051wme.8.1626436210901;
        Fri, 16 Jul 2021 04:50:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626436210; cv=none;
        d=google.com; s=arc-20160816;
        b=BfYLR5jucugu8YhCKJZvLn5idNNm2AHKyRHHXt6khtHGSIC/EdTtQuh/Zg8Noa3KZg
         rlcQ8hejuGlU42m7NlE9AZPhMecMY/WMWMMllcGhshws3K40CiHlUTSFWPeIpinO9LJo
         WNm6VSPwdC9mZ+05t3FKMNSquvXHOmG3KoqXDbkI2GAxwNYwsLDH3313CCEB8ZyiZizl
         2K3jqGCaY3W1xmfuDpF2HX0aN2uDtYN1B0k+1Bt3IR8earkMVA+PK91r3blTUYuqovUl
         dB9Ne3AVo82BChHMWNpJ3CLvam9oNQgHaccoEG2kdImJe4LnR+yjXP81TNmleqrvzklp
         if0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=nzabWvrTaM3dlhAMkGE1TPAE+zrQX3XHiWsmylmIlBU=;
        b=BokhVLPxFqnjo2dDoYxUEjCb9tDQVl4T2T/nYdHxkJvgeB2RFlnmt1pR6DdOBM2xLb
         jBey7UqK/YZ+Khdz3vgsAa09n50hs8rLoVoBQ8HIMe0DpSThBRnH5cURVdjSPQGnLybM
         +a0CYvdnbSC8edrkD7+TETE9PjuJQCrqM50ekXmMLT6SZnxV7mXy1k87+DOGt34ww6TD
         ZP5iL+tVaTmMYr6tsKQqqfIuUKScl+PiO2uuZ4VAUTq2bJHtk2dUjQOyXCBUA2lh4z9K
         8xfht/QkjLLARfj5nRz+pw8gK+cRS3CL8iQf1Xu8FdCLypKI4N1a8zv1WIMPC7gOVhw5
         NYVA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vZIQ2SoX;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id u16si375553wrg.5.2021.07.16.04.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jul 2021 04:50:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id u8-20020a7bcb080000b02901e44e9caa2aso5656506wmj.4
        for <kasan-dev@googlegroups.com>; Fri, 16 Jul 2021 04:50:10 -0700 (PDT)
X-Received: by 2002:a1c:39d5:: with SMTP id g204mr16168668wma.66.1626436210180;
        Fri, 16 Jul 2021 04:50:10 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:fb3b:45b4:a42a:5668])
        by smtp.gmail.com with ESMTPSA id k24sm10147181wrh.30.2021.07.16.04.50.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jul 2021 04:50:09 -0700 (PDT)
Date: Fri, 16 Jul 2021 13:50:04 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Arnd Bergmann <arnd@arndb.de>, Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 0/6] Final si_trapno bits
Message-ID: <YPFybJQ7eviet341@elver.google.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
 <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
 <m15z031z0a.fsf@fess.ebiederm.org>
 <YIxVWkT03TqcJLY3@elver.google.com>
 <m1zgxfs7zq.fsf_-_@fess.ebiederm.org>
 <87a6mnzbx2.fsf_-_@disp2133>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vZIQ2SoX;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::334 as
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

On Thu, Jul 15, 2021 at 01:09PM -0500, Eric W. Biederman wrote:
> As a part of a fix for the ABI of the newly added SIGTRAP TRAP_PERF a
> si_trapno was reduced to an ordinary extention of the _sigfault case
> of struct siginfo.
> 
> When Linus saw the complete set of changes come in as a fix he requested
> that the set of changes be trimmed down to just what was necessary to
> fix the SIGTRAP TRAP_PERF ABI.
> 
> I had intended to get the rest of the changes into the merge window for
> v5.14 but I dropped the ball.
> 
> I have made the changes to stop using __ARCH_SI_TRAPNO be per
> architecture so they are easier to review.  In doing so I found one
> place on alpha where I used send_sig_fault instead of
> send_sig_fault_trapno(... si_trapno = 0).  That would not have changed
> the userspace behavior but it did make the kernel code less clear.
> 
> My rule in these patches is everywhere that siginfo layout calls
> for SIL_FAULT_TRAPNO the code uses either force_sig_fault_trapno
> or send_sig_fault_trapno.
> 
> And of course I have rebased and compile tested Marco's compile time
> assert patches.
> 
> Eric
> 
> 
> Eric W. Biederman (3):
>       signal/sparc: si_trapno is only used with SIGILL ILL_ILLTRP
>       signal/alpha: si_trapno is only used with SIGFPE and SIGTRAP TRAP_UNK
>       signal: Remove the generic __ARCH_SI_TRAPNO support
> 
> Marco Elver (3):
>       sparc64: Add compile-time asserts for siginfo_t offsets
>       arm: Add compile-time asserts for siginfo_t offsets
>       arm64: Add compile-time asserts for siginfo_t offsets

Nice, thanks for the respin. If I diffed it right, I see this is almost
(modulo what you mentioned above) equivalent to:
  https://lore.kernel.org/linux-api/m1tuni8ano.fsf_-_@fess.ebiederm.org/
+ what's already in mainline. It's only missing:

	signal: Verify the alignment and size of siginfo_t
	signal: Rename SIL_PERF_EVENT SIL_FAULT_PERF_EVENT for consistency

Would this be appropriate for this series, or rather separately, or
dropped completely?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YPFybJQ7eviet341%40elver.google.com.
