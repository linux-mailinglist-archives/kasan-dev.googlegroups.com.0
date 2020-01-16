Return-Path: <kasan-dev+bncBCMIZB7QWENRBUFTQDYQKGQEJUJHAEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CC4A113D5AC
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 09:07:45 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id i19sf1916690vsq.16
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 00:07:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579162064; cv=pass;
        d=google.com; s=arc-20160816;
        b=AsZuzC+Hgr7VoCnhG3GFo2AvnIqkj4mcmio7HF6DbzACGbYDYoHltcJD0FwIBsAcyn
         VUMEwKvPgH2X7Ywuqec1TdjZXm3MRy3b8pnUkgd0I5q7rarkYAiB+oq+JofDzThi6XPj
         q3ICyRdvY5IEypzcngNovZmLFUq7J4gjC+fLgpZBZMxHNWShYB4cuKb9ueB+D8vepLVf
         pPTqMXCPcGD2pE+HgxtUgZuuCMt4r0Uw8sZ9rfTcShypK0UeK6FFZbfh3Tk1c8i9EXmA
         sIjVUmcNVn1y8MPzKTpihFyjmlNSKApWULO0kQ6fT3zO215SUFmW06GF+qqS8YwvJ+S1
         gSnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FIwWvueSdnRkgFkiiaLajnytV2k4WlZi+w03nl+qL/4=;
        b=dJdE53LF2Rspxt2O4o23etK1/p2wEMgoi7xUX/2okeQQoayL36HgLi1roBrW4HdluW
         qd6LSNFcFhyKYbuNfe64ZwQCFOq41ZOOcsZ9MKI8xdUCajs7xJcUO6c39vNhUtDL7WNn
         CT1y4dhrrI4x7Zeq4d9QtbJzKQHnt21xG+39bPZ4y6/MzOPwxGIdVeu6L5Y3SsZxar9a
         zhtzwVTvX7eUCMPDG8HUOgFBWw8RmvteSjQf80ywKPNL9ZwfhXA7LjnFUbIYkdcaNZ2A
         JTVz5meESDv9/qV1akm0YXOIbyrxKEGxY4zyZfuWrfffHs8CAEkjZP8ogrpMOVx9GcwL
         Yemg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qfoDxmeh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FIwWvueSdnRkgFkiiaLajnytV2k4WlZi+w03nl+qL/4=;
        b=l894OASCWwbdkkRJZgCxb40t5atL1rusX1E38e/zc+EBFBk/V59IJsHvOeODbJRLEx
         pAdzNYgcwogvyMOxfwlDT9MXBQpFc4jKLy8h25t5heihtOfSh180uvEjGkNevqr+xaxY
         42nATU8VqUYuATT52ZWj/goZ0bBz9nvzwQH4DZ5Ti6JKH2+myKAty8fXzZgLu/FpIiGd
         S4Q7zRsNzE5JAbm6ceLCaDfNJJGmjsCwJqkRVHgqyweIRhl2WizoAjjxNTVsT49xV0Kp
         W2eL4YhoiDznZOTgxVe5l+Hvh6xTK6ihLE/TDftjZrLwD/jtuyzxs0zrMXZS5zzvivTw
         tL3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FIwWvueSdnRkgFkiiaLajnytV2k4WlZi+w03nl+qL/4=;
        b=dUFEBXauioBQ21HENObUbuZwNrwi7MUYuNaMZ/nzFjL+/bpNkoTceSSGuLl6ndx/r4
         y/RN5hYiazs1DDDwZQVglH/uR1FLXi+9P7eq39w8rOgVSYI9eEzuR52X85Vy7B0Guywx
         G+saBxrC3P0VxI6yv9RAd/4FlyB/GIb4UYBqns88IcrFt1fXPwj8q/G/8gsSokIgY4H2
         QfK8npvj3NA3l2hClQjleOLsl91Yz681WiijwqWXoH+y5H99YeqiuFdenHQNUeWIjbZ5
         D5jqqlwjmswcxVEMhaB8r3AwYumsFvipIuc5lRwp0Aic2a6C9ZGadAM4rPkt/pMyZ63D
         jCbA==
X-Gm-Message-State: APjAAAWbEhWxlPBXmaO9qyeQhXEQrjzs3A+UXID+vC2PqHKblmFM5qCV
	VTRW5kA+bRZgmE7XHNyB0rM=
X-Google-Smtp-Source: APXvYqyr+oS0phqGcj2C7/q6+HanKL56Tv3XVPwH0rJrGqLjMXm56h8uA4+mBqdLtCChjFNtTxxA7Q==
X-Received: by 2002:ab0:1051:: with SMTP id g17mr18781184uab.52.1579162064729;
        Thu, 16 Jan 2020 00:07:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:201d:: with SMTP id p29ls795567vsr.5.gmail; Thu, 16
 Jan 2020 00:07:44 -0800 (PST)
X-Received: by 2002:a67:fc1a:: with SMTP id o26mr724774vsq.229.1579162064418;
        Thu, 16 Jan 2020 00:07:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579162064; cv=none;
        d=google.com; s=arc-20160816;
        b=Hdd/dJtXU9ZarQvyqHkZ8v6C+riii+MzonK8AFw2I/tYt2GtXvrWG44Gyn0q348Ncn
         L5/fEo7gLo90AhbX8WZykxw2hZqobImg6BjzdfZuHanGWjxjQ5fcJM/daRYbQ2B4CDD9
         zqFER+xNywFgPAluiR0q8qxsVy1VJRjFTU+1g8e1i8ny3WASkeVCuQRRjgrW9oUfO+ou
         trQI2AmC39hs9+7Vnsjijvf8CAobjIO2X9dzIBgXwIdo60BD+iPQFT9xhHBNBNiJ16UE
         A3Jb9bDKoa2pdd8nLm8D3O25fXJE9YSeZR2Q0vWWO00IdruO7N7hswASNGc0sGxGOhgk
         cv9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7IBdjvFRag9yZE/BKc5brHAQDARDtIXaGhkF8uJXRlQ=;
        b=Z8WOdFnIKdah8F1XmbTfDXhqBA+XWBG0c7MWx6zrs7p9h7J98sbn8gM8P/m88GHtZp
         d3C6csO3bJzGg0B9CATdyuJU4aJGYCCXY89JYSwXZghRRYoKQ5tfpAsE+yPwfaUv4yxg
         xYTCNwC7XHxKd8CgA1FFNn7W+4aXaAqqwHs8TB8a6wHWCgRZpG3Sk8MxtmHX0QDfpQ9T
         E9+ZXjl04IGQWsbcShu21sJ1okosPjyi6P2zVLKrO0JGKs7rdyXF39ECfBOX/7VBXvq8
         zVwUlBlK4m1bX6r1pBTHXxiTccT11VPDh6TFQMZ4P7El2XDo/1R8/+bHDWv8wrcevNGS
         Oe5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qfoDxmeh;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id t16si293068vsn.0.2020.01.16.00.07.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 00:07:44 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id w30so18143855qtd.12
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 00:07:44 -0800 (PST)
X-Received: by 2002:ac8:30f7:: with SMTP id w52mr1194993qta.380.1579162063680;
 Thu, 16 Jan 2020 00:07:43 -0800 (PST)
MIME-Version: 1.0
References: <20200116062625.32692-1-dja@axtens.net> <20200116062625.32692-4-dja@axtens.net>
In-Reply-To: <20200116062625.32692-4-dja@axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 09:07:32 +0100
Message-ID: <CACT4Y+YpOm9cDk5Hi62iAwMFgiotzWjfiK4i9-9jkha_ZNwuvw@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] kasan: initialise array in kasan_memcmp test
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-s390 <linux-s390@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	"the arch/x86 maintainers" <x86@kernel.org>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=qfoDxmeh;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Thu, Jan 16, 2020 at 7:26 AM Daniel Axtens <dja@axtens.net> wrote:
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

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  lib/test_kasan.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index a130d75b9385..519b0f259e97 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -619,7 +619,7 @@ static noinline void __init kasan_memcmp(void)
>  {
>         char *ptr;
>         size_t size = 24;
> -       int arr[9];
> +       int arr[9] = {};
>
>         pr_info("out-of-bounds in memcmp\n");
>         ptr = kmalloc(size, GFP_KERNEL | __GFP_ZERO);
> --
> 2.20.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200116062625.32692-4-dja%40axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYpOm9cDk5Hi62iAwMFgiotzWjfiK4i9-9jkha_ZNwuvw%40mail.gmail.com.
