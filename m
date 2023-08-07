Return-Path: <kasan-dev+bncBDZKHAFW3AGBBO4PYSTAMGQEGXB6VRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 73E9C772883
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:03:25 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-56cff6fe7edsf7293720eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:03:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691420604; cv=pass;
        d=google.com; s=arc-20160816;
        b=NC81YTTlmO2X0hpYnqnIbdAYthhz0L03SfMK2ZJq3NBvQtJ64QkiHYv43S/do/qifZ
         +Jfz+NpB+riBnmoUJ2Y9f3GpflLLFyv9yOd0bco2fa6UF1ij5eoQ0BwuD3hp4q3znfU/
         0ET7oBYEfewjLUDAGLrofzNPdGK+UVjPwB1Qxx/te5imcvhusRVjgMm91vsK7TEsvv4k
         sHzJ+OZyxW4GpGcuO8ce6I90nZMyZmCvwZ2MiH3n9ghuCRI2Lo8ApFUra20svEsSy7mG
         B7P0pGyOtrAT1nLpbwSc9//shIERT1egL54drhQTjkQbdfnLqMe0PEVYhKAZuYIks/m/
         lYXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=szrM5+ls4g6FPnPCsftBEild96lNOFizxFJ4fmV7tOI=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=mHOIXJ3eF4uvzVD/5n7jHBickY93pdohv/VzLjm+8aNXybDkvE6qTNmk59BwfBcMn/
         foR303fRQqIQXXweIFSPtwUeGy7jO51+BTmYUkR7se/R+et7rQ7U4j6YnaUO6jZsK0Jq
         ODTNCetdpQyJlgYhObqHfwx90KgL6ZcGu35y182dX1osDqU12FlZ/WChTI4tv0bIiTEb
         Wv4hjviQJtha7W9agYspI7ae8ADIMEFvH/o7o9mePJ07fGgnyPYp16BkLc+qq5N5x59o
         f3zVohHHCwIT78m5Vz0gjkvtQZ/NFy1y+ejiSycy3IAey/13mW7f1HSPn586Maa+nW7x
         t4Rw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=e6SNj8R7;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691420604; x=1692025404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=szrM5+ls4g6FPnPCsftBEild96lNOFizxFJ4fmV7tOI=;
        b=GBxwdFVdipk+oYPM0qdjziWo88WZq3nXGSz5olWlKGljwnnFTgYECbXRASKKaKAQSO
         ZVjKs9vqMseBE7IOt/ebtIj+7J0OmntfpZhYQM4WtIvECmDc79Ie39eSOi+hiQW2ilx4
         R9SPNxFjBkOmKnPfl09RXit9IC8x3/4QWzBxWi8eD0tHcZd6NizjOXWrtfdTidCTKUIE
         L8PZM4CVXRHvlIeTTa8xKHtpAlrSslFkCdlmYN38MR8KWKVRBFCwCK5dLopHE4oS4Xbt
         4clQsak6TqgLYvdocnDGQN4lm5DGqquZB6uZiNgDDkbi11DLZLZDsa0XzqpO6VgR8JIF
         FR8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691420604; x=1692025404;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=szrM5+ls4g6FPnPCsftBEild96lNOFizxFJ4fmV7tOI=;
        b=gO6Xr95bVgb6i182YaL6bUtuzAOUD9upqUU8jqinNYdydbD2M3oCus8G0BCqAwaonW
         WGInPDhmloIW1b9qn8sJOFhmuf9E4FB7KO/aBcKn2sD8W3rBOJOVMGqo3dDb3ASpHiCe
         FL+NEoJiAUJkWsdMNTK5GvfVMJkxeCWpHc5pWf0bKYguGaE9RP3E3tB5AVbhaDJ45u/C
         wl5c44T6lbnMrO87Me92okCYcP2aGxsoaCuDAwweGDUfQDtBJolVUigNUbLT6N8dQZTo
         H3KY2Ys+O85zo9KTWEoJoBTBGRVD3GWlArDni+42d7pWtNJTeUfVvkE3yFfmz7Aq+kj6
         GQyQ==
X-Gm-Message-State: AOJu0YyKPIzAqoXOq27HHs3NqyS2HnnnESZapqNDY1j4aRvq0/bX0+2p
	+N6WTxgQYP/iUUHk41IceaE=
X-Google-Smtp-Source: AGHT+IG5JYTD7w1gVx0FN+fC7AnlphWQTYSF/mH+bL/drnhCux8+iHzb806LeTJQ4ukvYAipaZ7MUw==
X-Received: by 2002:a4a:9243:0:b0:56c:e17e:72ab with SMTP id g3-20020a4a9243000000b0056ce17e72abmr8892498ooh.2.1691420603583;
        Mon, 07 Aug 2023 08:03:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:41d5:0:b0:56c:94b1:684d with SMTP id x204-20020a4a41d5000000b0056c94b1684dls3189881ooa.1.-pod-prod-08-us;
 Mon, 07 Aug 2023 08:03:23 -0700 (PDT)
X-Received: by 2002:a05:6808:128c:b0:3a4:644:b482 with SMTP id a12-20020a056808128c00b003a40644b482mr14520758oiw.52.1691420602944;
        Mon, 07 Aug 2023 08:03:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691420602; cv=none;
        d=google.com; s=arc-20160816;
        b=JAs3/YTyfcRVVtj+gF1fButpXbZYwrHPlsM3C+7icXzjp0GZKiradeVSArgVRpbmMz
         YF6kQSxKuYjkmITJTLTPpNSXJKMBvksUILf0J2YikCJ62sftlPucSfJXeJz2I24fJcG6
         O0dvYC7LpQj4TFayJcmLe8f2to9Lx3UKWy/W8FlGiXscWXxKOM6CAnHlVecUVamrYXVY
         vps6Mr2RspqRgFA9D8gpCmMMIcdvQb6cEY4ZTFGgzqm8ifTeLTTrtIdV7FeNal1SkZaI
         8gtE1SixcLmMg49c3d/iHSSj81+o4AXbKOpbblONluPC4P2o/+KoZi8+11DV6sZYb/7Q
         eIXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=X3A2NsvXpmNRnd8PNau9KuaPdja1LGVqq+oucwV7B34=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=LMiynBMVljddSzpEyJHUaLv4NVQXI9M45x0U4YiT+ukmEM+tor4GNZpnOvw+c3XmAb
         EvW1wILoMLi/Tn8nXcOqTq73y7h1x5rA1pZuFqw7VrvyuaB99utQGF+6qGjPi41vaURK
         aeF011hwbU7E9AkZZmk3iBNeaGDw0iJhg0T0pRiGcNwKxwLxPIIya2Yl/8HzwniiFRIF
         cIJVSEgBMLHzz57mNp5smALTCfQfDQWiWd9RwQ7HQ2IuQZwWvDfFCC5xX16Em0+bJXX8
         i2wfS7y7Eiihl00DVGLVWyHltrVTzsFu54FCEHP6g5n4Q35q6Nq4k1ee+Q0a2iWYo0sF
         uPpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=e6SNj8R7;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id bl10-20020a056808308a00b003a747d9498esi618582oib.4.2023.08.07.08.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 08:03:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id DE1E91FE49;
	Mon,  7 Aug 2023 15:03:20 +0000 (UTC)
Received: from suse.cz (unknown [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 5ADD22C142;
	Mon,  7 Aug 2023 15:03:20 +0000 (UTC)
Date: Mon, 7 Aug 2023 17:03:19 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNEHt564a8RCLWon@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=e6SNj8R7;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:
> kernel.h is being used as a dump for all kinds of stuff for a long time.
> sprintf() and friends are used in many drivers without need of the full
> kernel.h dependency train with it.
> 
> Here is the attempt on cleaning it up by splitting out sprintf() and
> friends.
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  include/linux/kernel.h  | 30 +-----------------------------
>  include/linux/sprintf.h | 25 +++++++++++++++++++++++++
>  lib/test_printf.c       |  1 +
>  lib/vsprintf.c          |  1 +
>  4 files changed, 28 insertions(+), 29 deletions(-)
>  create mode 100644 include/linux/sprintf.h

I agree that kernel.h is not the right place. But are there any
numbers how much separate sprintf.h might safe?

Maybe, we should not reinvent the wheel and get inspired by
userspace.

sprintf() and friends are basic functions which most people know
from userspace. And it is pretty handy that the kernel variants
are are mostly compatible as well.

IMHO, it might be handful when they are also included similar way
as in userspace. From my POV printk.h is like stdio.h. And we already
have include/linux/stdarg.h where the v*print*() function might
fit nicely.

How does this sound, please?

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEHt564a8RCLWon%40alley.
