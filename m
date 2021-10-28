Return-Path: <kasan-dev+bncBCT4XGV33UIBBY4J5SFQMGQESYW27XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id C93AB43E968
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 22:15:32 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id bm9-20020a05620a198900b004629c6f44c4sf4652184qkb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 13:15:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635452131; cv=pass;
        d=google.com; s=arc-20160816;
        b=arXJTo9FWGTzcOoHeI32eVkxPJs2k9NXetZfjXjUrCJg4MejBTqg4b/USXZecfY1Bw
         +5AcN/ii17KwtxvftRmj/HTcqyxky1OpLuK1Dz5SjoJK00OcBMuwNlF6fUwKwvJEE5Hd
         n5aTcEqM4XVapEnKSdRSlm8P+RUGJQlaYRMTSJn/nUziW47qIySaWv1hLXzdNkP60xNu
         oES1+bRa+k8aWG2ixAYWPC7asKHtgUqbYEPjzk+PEPDdByq+CapItcmtTuh08zZYSL5v
         j2wFADJVlBn8B/ZE/kkXhRrYf27WrKeiFBt3ZlAGs5A+vHCm/1Vn5xgk/xzkR6dRZOdX
         in/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=tqJoIufBL3iVpQwjrsHj/01xqxcL3yZ+uJp4kH/feFs=;
        b=ybtJMXGzFIq1WOhPoy6VmcA6V34363GMzVxI7XYRD7GtPQFrCNyh0p2Zo/Zm9eJjdV
         7ZTIuRuu0nKWM9b60hVjoL5NsyD/Aux6xOnlWtDcIBoqNUpABo6ELLPfmZ9vJ8RZTbYV
         x66fgoqQR52SgS4T4LFqeMIbPaFEBuuSKILDRWnrtWbfKJ0qZoQPo2heH4Hf6RcHM3ev
         nHoZ8WTXDAuGF7bJlpqTozibiPet6C/Ck3s34hVwOHsxd/C5+soa/7jEdt3p59o5w1tL
         j8yWKKxbPkbdkI45JV9Za4OjxXHOnAMMQ/ixPDrddYSTfAFchIN/XFLLVW2sI8am9jHd
         zSFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=gdwBhM8a;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tqJoIufBL3iVpQwjrsHj/01xqxcL3yZ+uJp4kH/feFs=;
        b=sbrLEJtgWQjrrWKYQcvgxH0qS8WqKZ/0FxAy7GXtHtGM5AG4wfD1u5H/7BMbSNPcAH
         Tpo+534a679LBOyiVL69yXSoEKG3dFrctQh4g8Fx42uFm5y/9m6lY0W+eeVXRrr3npa5
         j/MmLDBo3ffg28pxKCIqvzgmjoNk6as33LQ00uMWlx8klqgup1xniL7l0d6Iu+ACwW7G
         /rHDJSPYzsz66nLeO6dSTcnOrpWDxHafV4UnfRzlff7aqsAG39UtrQT6yEUEd5XP5ybU
         BfvLUVO3YU8NtlXBKb1OBrTCalX521Jodu1LUx1yIODS90ltDyWbzLLmtUJhSsrGHJeS
         ROVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tqJoIufBL3iVpQwjrsHj/01xqxcL3yZ+uJp4kH/feFs=;
        b=zbqncrjfFNFdEeNj95Z7jHmu0H7sa7sGyjlvu5LTDnMaEKsqdtvddnbwlFfVq/0qce
         fGrpkuQe/wp4cFQGMnsec/pf3VVA9pYSrpgkySgQ0+xBe1x6RAlELCZD0tJpEdac9osB
         xOTZKOZAANAx4qfvcftUXk+HHsEc0nPM+7Bhic+w4t5gow0eNttacJ19ojlWeC1zf2fD
         qbkEChSN01j0mBtUChDgEN78woGhRJdFjLZcJQvrp6R9nF1Mlyli34m3s3jAQdYdSeZY
         5tEOBA/8hwEDcYAXWHjRfZnQW76K4OhpTj4OVq13bSJS3i22nlLT3GPIiFvwTaz7LKeq
         zwxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Aukhwm48bv1/cffCuZbOn8Xnh2TEWdZUS0q+LROLy+03ojpUd
	fTDFauv5dTHjU0geu7IEiGQ=
X-Google-Smtp-Source: ABdhPJxNfB2nIyAkdsjYQyKlal3jPl3Zhl92FhEn0Xm07v8o/63+Z04bNJLyqqPYmOjO4nrt3vN6Tw==
X-Received: by 2002:a05:622a:1486:: with SMTP id t6mr7274028qtx.319.1635452131476;
        Thu, 28 Oct 2021 13:15:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:240e:: with SMTP id d14ls2458110qkn.6.gmail; Thu,
 28 Oct 2021 13:15:31 -0700 (PDT)
X-Received: by 2002:a37:e40e:: with SMTP id y14mr5427288qkf.456.1635452130965;
        Thu, 28 Oct 2021 13:15:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635452130; cv=none;
        d=google.com; s=arc-20160816;
        b=uugXDFPkQ3GBtJYbP0FGTEoZQqE8L6tQUmFIXwkiSebwcV7xvklqj6WaBnImeazM4N
         t+ERZTGPa7vbgCmovzoKNbCipEZ8G3DQv0LpPGyU5V59wn1O/9cignVQ/Kgp746bFPRA
         gRZ76+/ee5mtrVjEla3X8cIQI8l8tofIsvgMosThOEpcUD9iQO0hyjfXeD2L4CL7a+7X
         dtUIW7DYrqgqfCvlSNS07kn+oMPRozj/+pV0NnjYVW/reU5SHGrOowUA2Uh1H6LqPNb0
         hAUj9dw8fRyAf3VbQ1mpqkWuYBjf/fRPqPM3dwfdt1i2GUIce/4mQIt3tPnxMe55aomG
         qJYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=GiTi7nDoySXy4f2PLFxAq0NLcyBFUDniERnyM8cVKPs=;
        b=Cm1mpCZUKDGalmBKwdQEoQaqxzRxqU534Fk9akAdl5sM/1DLpuLPqZA6qYnzCYdsOH
         YPbcJQhHGTjckZ+TdXgf3QVDMvnNtTUCX9fQE3hYAfR1RCLUEpFCF+hBRoQQflgjsCBU
         pu3bHcGqcFNh8zt7TWa5iR7jbj8sOPyxoXuwZBoFBAI/I0Zjsng0W5VmvkInirwZAhN0
         5DBLMkR9WeXtvIuRcTsE6vxK9G9ry3uGTgI5zlexfsDyKuPfWf9Tej3IYXS92tra01xQ
         awAf+SOEfCH+f/Ps1DsrHN/c0jFWZZ2J9QeNoe2AP4AK3NQV5NcKAdIo97ZDeKo8Pc1O
         /e6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=gdwBhM8a;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ay44si522087qkb.1.2021.10.28.13.15.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Oct 2021 13:15:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3A5F660C4A;
	Thu, 28 Oct 2021 20:15:29 +0000 (UTC)
Date: Thu, 28 Oct 2021 13:15:26 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kees Cook <keescook@chromium.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Arnd Bergmann
 <arnd@kernel.org>, linux-hardening@vger.kernel.org, Kees Cook
 <keescook@chomium.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, Arnd
 Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Peter Collingbourne <pcc@google.com>, Patricia
 Alfonso <trishalfonso@google.com>, linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/2] kasan: test: use underlying string helpers
Message-Id: <20211028131526.d63d1074a8faa20e1de5e209@linux-foundation.org>
In-Reply-To: <721BDA47-9998-4F0B-80B4-F4E4765E4885@chromium.org>
References: <20211013150025.2875883-1-arnd@kernel.org>
	<b35768f5-8e06-ebe6-1cdd-65f7fe67ff7a@arm.com>
	<721BDA47-9998-4F0B-80B4-F4E4765E4885@chromium.org>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=gdwBhM8a;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 14 Oct 2021 19:40:45 -0700 Kees Cook <keescook@chromium.org> wrote:

> 
> 
> On October 14, 2021 1:12:54 AM PDT, Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:
> >
> >
> >On 10/13/21 5:00 PM, Arnd Bergmann wrote:
> >> From: Arnd Bergmann <arnd@arndb.de>
> >> 
> >> Calling memcmp() and memchr() with an intentional buffer overflow
> >> is now caught at compile time:
> >> 
> >> In function 'memcmp',
> >>     inlined from 'kasan_memcmp' at lib/test_kasan.c:897:2:
> >> include/linux/fortify-string.h:263:25: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> >>   263 |                         __read_overflow();
> >>       |                         ^~~~~~~~~~~~~~~~~
> >> In function 'memchr',
> >>     inlined from 'kasan_memchr' at lib/test_kasan.c:872:2:
> >> include/linux/fortify-string.h:277:17: error: call to '__read_overflow' declared with attribute error: detected read beyond size of object (1st parameter)
> >>   277 |                 __read_overflow();
> >>       |                 ^~~~~~~~~~~~~~~~~
> >> 
> >> Change the kasan tests to wrap those inside of a noinline function
> >> to prevent the compiler from noticing the bug and let kasan find
> >> it at runtime.
> >> 
> >> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> >
> >Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> How about just explicitly making the size invisible to the compiler?
> 
> I did this for similar issues in the same source:
> 
> https://lore.kernel.org/linux-hardening/20211006181544.1670992-1-keescook@chromium.org/T/#u
> 

Arnd?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211028131526.d63d1074a8faa20e1de5e209%40linux-foundation.org.
