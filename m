Return-Path: <kasan-dev+bncBCMIZB7QWENRBLU7Q72QKGQEAT2TTOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 09BB11B61E6
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 19:26:08 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id z13sf2033151iog.16
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 10:26:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587662767; cv=pass;
        d=google.com; s=arc-20160816;
        b=mFqI5RcawinncSPb7QOMs1Y5Y2a7QXA+Kax/welf9zsFv8X3tr+VX1qYRWdpRJLWIE
         Ay72k39JSBdJy+coHdCpLi2+GhBltnl6EJpobbCtWppfOoOQhuwja2q7S48ur5jtFQyo
         5xUHAtlPa1CP4qsOicO5m4ILuJsFJtpcUIofU7YwO8HlUW2vCnDevdaPeXeFKZndlKHu
         pshIuI8C5q2dZZMOFsJMZM4lZZYX3hCQ6UVPzB01HTHwnUwF8PADoMW6qCXxMI54dOEs
         0s5roq9vUzhuTazVFpN1Osmmv59lLD2qbSnu+suQpVGMT1fidMe7+b0MKd+OwlVmQulO
         Ot9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=40kcDs2LqY4fVNzWXWlK6TrE76XDtmAZcw0zfNKUu88=;
        b=lt4OIPQGqgE3qOZKgdpTpG3hn3aXRxWnKNFiIx/wyOAluSqgXTk46nhTBnt0W55gHR
         dXdR9AdMm1WoEHse9mYzGWYGzYW9Rwjj2meuTFZQNZFVLfJkn4RExchgX4skx7DR/uZW
         gzFHlU+uxXsIebNwR1SCoM4OryXSSa46R+IahxeTNvs2wZ/xXXEFT1G/IkrAGMkopE37
         AjMonZSwPeYzWzFGySXlu9XtK4S6NvU5JI3V+32R5+NHU8DoR0bz7ITT9gZxqhhaiB6i
         fxmOdfskzp/VsTrRre+kf7a0+IxrqweggMMXnPXLH4uwZpe21gXOLBdPYFF3SjjqVALe
         Y0HQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AjNZAuK8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=40kcDs2LqY4fVNzWXWlK6TrE76XDtmAZcw0zfNKUu88=;
        b=CYDkwRkaIPPcN1xi6Hc4IXhB3thGLSgskMFtgPHmMXeze/I71ucP4Ww84CHKQ0AEbL
         8IrtPsglag39HKtGWwL3U5lhzSMK5vBBa+YRHGl6WhgHB/kFlcEMi/CB5fv+dVzPDLLF
         IyUJLfCZbrI80TijdXG/FaJ1qUiOttf86DtcDjfj3SoyK4gZyBRfIoZnOF5bvuji3FNY
         RIzVCbfBF6Ul8BT0M4wzpqUR7db7RR673223TAGrlAhIRnp2EhDoSD54pp3q1MTW6S/B
         YQ41QviP8tXJRIaZGIBGSCowVJdW1jfX0guGOLKhFbOSMhS8nGDubDjx0mQL4gq4TCmP
         Ojbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=40kcDs2LqY4fVNzWXWlK6TrE76XDtmAZcw0zfNKUu88=;
        b=DDwoB0EO16B2EyeZc2uFKatTu4e1MUcT9cWB9UeiBjITK2odFc0Utpa3sgJNF1NJlO
         Z0y5J3UCIPjX1rWl30Bn9MfwoBCyBm3lnGGcT/YnOZKRbiLFNfw/zZs2sV8Sx8Ved/wo
         pU9LU5dz9saETReQimcCfwWEqALY2kCgossiIRjSbOtFOB84irwWIiVIitbJTMZ0flJC
         J8c4UJBUv6zjYRoihKVkhU//wescHWnB7IuRd9z6gQ5IUM4kM4rJ4GweXnnTyTwzoW1I
         az/5ru01Zvo371kn5AxT2p2whzXZFDnlN2orzjhXWmwkO9xr24I0jGdHGvz43i+rxkkr
         YHag==
X-Gm-Message-State: AGi0PuYKMK3gjBjxuIzkAwTlYQJl9Xfq/9f4wWS2Rr2ww6UYkHiKfu3t
	X+Ug2deov2LV8d/uLjDUkE0=
X-Google-Smtp-Source: APiQypLtki5kZdkqaS1pNMl0wFIRraCdcVrL5XCxz2+BUZ4tL5XIqQbpGlx+vMfKE0t+RydS4W2twg==
X-Received: by 2002:a5d:960f:: with SMTP id w15mr4854505iol.34.1587662766921;
        Thu, 23 Apr 2020 10:26:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:5244:: with SMTP id d65ls1478748jab.3.gmail; Thu, 23 Apr
 2020 10:26:06 -0700 (PDT)
X-Received: by 2002:a05:6638:44f:: with SMTP id r15mr4405006jap.84.1587662766544;
        Thu, 23 Apr 2020 10:26:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587662766; cv=none;
        d=google.com; s=arc-20160816;
        b=DUfs46YuI1a3I37jI5Q7YVBBqEiWZuDbECtObcVDa09F4f6fIH5LDw6zTzDVL5QxiO
         nvg1AchT+FvYEEnehBIYlwSSF0RjdI9YMU4UHUaY4/F07RA/63wxB8Yoo3oWT/gz8cfr
         Vrubvj8f2BU9j5YhtGR5H5fBH3/IWwSi0x1S4QMOViRDKYxWbn1SQ7/S72q9ki1AAG4A
         TGNBqS1419CjKhnr5FrVKObpJ6j97zzZahQhiyy4h8C9rRTPs+b0IlL+PwD+TkaqFrnp
         vIF2Yoh9ezvNYmkymKPSB7Gj+kg5ZIyL/wiDQMMAclP8mIuVbEE8mDgtfbDqApti8AF6
         fA6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=i0wqst2mhEuWLnZwDqC3VBRcH3//gDPmWLfGb4vS/m0=;
        b=huavtykLXxuMTvCpTipSCBnc0EWB1nHUpltlHgke5YOomzieRyTXE49+iWF5gykQVW
         clT+ET+xQosCOjMjL/Oe3dMtaxDCl0QEo30gmt5PaQ4TkeqNJxSmP1s1wcVvI310PP+h
         cwJTKdJYiYvGEh9ApxTbao0WT7bsYsIkcVFU+X/GCDgrTaz+eJssaQ7i+XV96RKyEDJE
         40tJSpZsp4pZ3sWJ4HC9bSPIDxVqAQj9zGjSDNb1MuVkwJRf7ZauuQowCe/BEmS5duw0
         7WlI9J+j88lnamZuT4jkYSr1MF36deN7JkVf31IHyIocbd3MlQopuLUkrydgdtlQj44+
         xqKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=AjNZAuK8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id p5si125154ilm.1.2020.04.23.10.26.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 10:26:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id 23so2378065qkf.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 10:26:06 -0700 (PDT)
X-Received: by 2002:a05:620a:1362:: with SMTP id d2mr4610858qkl.256.1587662765591;
 Thu, 23 Apr 2020 10:26:05 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154503.5103-1-dja@axtens.net> <20200423154503.5103-4-dja@axtens.net>
In-Reply-To: <20200423154503.5103-4-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 23 Apr 2020 19:25:53 +0200
Message-ID: <CACT4Y+b7omyQ0bBBApOs5O_m0MDZWjoBi3QV6MxG4h_14gUa2g@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] kasan: initialise array in kasan_memcmp test
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=AjNZAuK8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Apr 23, 2020 at 5:45 PM Daniel Axtens <dja@axtens.net> wrote:
>
> memcmp may bail out before accessing all the memory if the buffers
> contain differing bytes. kasan_memcmp calls memcmp with a stack array.
> Stack variables are not necessarily initialised (in the absence of a
> compiler plugin, at least). Sometimes this causes the memcpy to bail
> early thus fail to trigger kasan.
>
> Make sure the array initialised to zero in the code.
>
> No other test is dependent on the contents of an array on the stack.
>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> ---
>  lib/test_kasan.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index 939f395a5392..7700097842c8 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -638,7 +638,7 @@ static noinline void __init kasan_memcmp(void)
>  {
>         char *ptr;
>         size_t size = 24;
> -       int arr[9];
> +       int arr[9] = {};
>
>         pr_info("out-of-bounds in memcmp\n");
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);

My version of this function contains the following below:

memset(arr, 0, sizeof(arr));

What am I missing?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb7omyQ0bBBApOs5O_m0MDZWjoBi3QV6MxG4h_14gUa2g%40mail.gmail.com.
