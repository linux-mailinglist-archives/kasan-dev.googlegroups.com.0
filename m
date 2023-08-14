Return-Path: <kasan-dev+bncBDZKHAFW3AGBBP4K5GTAMGQEOUQ3Y5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC50D77BCC9
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 17:16:16 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-4fe2631f5a6sf4185849e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Aug 2023 08:16:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692026176; cv=pass;
        d=google.com; s=arc-20160816;
        b=GAqatwwl0zB748rYrkFbiE3flCnaWcTcygBd17iTfI5mC74FHzwhzGYQRdOxhEKjjn
         YUpXJqOAbahMrqs9hLb+fEuHC1u+rMm+CXvEO83RH977soWZME2QCuoq/wmXyGOnFjVi
         P0dvneZr0XcJVVKAPQDQbgiO9Yz1jcbUGhD9ApTQkOQyFj3WroHApBH8aMCfrdi+KOx0
         nseXQOk1iirgosBz5U+OOxhGBSkDD6yLqB0+NmB4es7jgzwM0l/Nzbm0DPHuelXKDYMe
         5H10sW3oOAPYb/hbpKxowOJ46ROamURbqjmt+emWaPOuk/J7tSDnCJDg7TrVD29touoK
         +hRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TDq+aIvBkGY4xx9fZvl8Sd00FTeo8h2mJ2bQOYaRNpY=;
        fh=u/gF7ZyBGMmmo/UTc8bA1WEwOtMaWAUQBwUz8Vu+LGM=;
        b=WdIT3CT8IjlxG47LmQ+QdKIhLmqu81ETfblC9nbuSwGUv/9LjBgxhjITYEVQ/6h5Od
         cjTqab5AcuegfANFaN4HCqpSe+rJDfCQWDlXWlOz1CjWYn51wARdK9R/3emC/WOi8nQQ
         vg5f5BMbdeJPAgq7bsnzavzVC3h4SDQXjjXpMrYtb35oUk8d46sXGii3hR2ADw2R6SDG
         deoj0aK5xMHVS0afARGMRgKrQP1Mc0pmnYhtR23FkXhf33HNOT4ooXrssRNfM744w7mm
         0YerRD1NVRHTplZD9iVP3Yuq/Ny2bfe9Oj2tauseWqj9rj+PKCpi7BVOBJLHrVmQq4HE
         0ceA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ezgzhu83;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692026176; x=1692630976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=TDq+aIvBkGY4xx9fZvl8Sd00FTeo8h2mJ2bQOYaRNpY=;
        b=Sqk+a8MsETac88IQRsYPPikzQeo3JVyEFYOl/Q98HUbEiVTKXNhWzMqH8PALiVSYbP
         x+HT1LMy0n7oBIMD9yzvBZONgy6gBJJdiqS9jcz8PTAP+SOPzc6SwQgM7HGAfsr5wEj9
         JgR7vRcgH98dFzZPiN41luPfMC7BGrPq817BLilKNasqoS0lxXNV/x44FGuNdH6OIOBN
         /WF4CfIh4JjY8+s0RuP1Y6VsMyRdwB7XdKTFroPMnJspWdij1yP7xmbgRdMF2OA7TNti
         +sGqkPxDKLGaNIbeYGvn79hXHUUE0rJnwodC7jPTDu8wFyf0J4ICVh5F5LcB/Sjhe8wL
         q6+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692026176; x=1692630976;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TDq+aIvBkGY4xx9fZvl8Sd00FTeo8h2mJ2bQOYaRNpY=;
        b=Ps2W69pyVpUhgmWbBakh7+sHAj/Mf18wgMqHDCwEj5WZaUh0F3NaeF0K/773Dlc+Sx
         rBgFmEpmmgv5soRXtc45/iPwLt/M5Qaj9RQipW/q3GgHth4gmwyVsAsCmmHkjWD1G9rm
         b2yjTcNIy7imB+zga5FwGGUQp/FTA0madpMJSU2yI0i7nC9/U8IhHQj0QpkNj5TI9uL/
         I4/Xt+XOx6O31ZOXnaV8jBV1bO2LFUZ92bKm6ir/MjhGoWUHwcuu9cmhyu3PN6ednTd2
         4VLNdyQPwRRKO7qrw3omgVbmJCWJabBWykQfasBSBkanGH6QhH11nxzRauuMV2EhpDWQ
         W6JQ==
X-Gm-Message-State: AOJu0YzKCQLQFjDcTAY/+KiMkl/gmozvRMeE4AYQlRk7uZzNqPDhSL4H
	Qk9B6BWVN85DX5Lm/wYn5/0=
X-Google-Smtp-Source: AGHT+IG83Qr7aeKuuvPNx+wKkYcRYUSJWsxxyavGDahMjsT1ksrvWQcsU0FHUL4PnF31kYBwrlE4ww==
X-Received: by 2002:a19:6547:0:b0:4f8:6abe:5249 with SMTP id c7-20020a196547000000b004f86abe5249mr6225413lfj.3.1692026175736;
        Mon, 14 Aug 2023 08:16:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4db1:0:b0:4fe:678:6a1f with SMTP id h17-20020ac24db1000000b004fe06786a1fls97166lfe.1.-pod-prod-06-eu;
 Mon, 14 Aug 2023 08:16:14 -0700 (PDT)
X-Received: by 2002:a05:6512:3d0b:b0:4fd:faa5:64ed with SMTP id d11-20020a0565123d0b00b004fdfaa564edmr8589441lfv.11.1692026173941;
        Mon, 14 Aug 2023 08:16:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692026173; cv=none;
        d=google.com; s=arc-20160816;
        b=HHiSOZbW9bg+8RPOXpH9XuC6FuWH2ooSDXwOifR/oUHLd9fWGHnOrrpbCK/qYPDRWR
         mawot1OG4g/g89OnmVK8fvjFalME7j/kO8i6iC7Ny+S2wZwvrMb2IB/DAiQODHZtpSYk
         Cn2vcMRZ3tgLzeDsKjU0RDLPjMSP5s39Gn4wpZNcpZlKX4zPyXxjHjxL8ldLzQBqOc3S
         SaL9Sj/AKxXXtEcx393qW2VatKGNDN2nwukqBPsc9ATw06hL7JRyCY9yyMugsOiOWFzn
         k0zowS/WVCJAGXQH523984wiO/sp22VYth5PnkyDGU3KvfJ6Bfz/Vguf14K0pkRmSejl
         v6MQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=EW4Ch8A2iSc+Cjz4p0CqaXWCxLaA43Mv5OGHJCgj2xA=;
        fh=am7PL/OkltPhRBlSqiRNdvZyQXhf053wUWF7t3kZnH8=;
        b=02KBwT8LxgJJBo9d5MgV79Ppti7EASkRhvre1mrPKuW/L97oHfrB4h0bzP1aq02IpX
         e2dBJAHks7jt99KN3b157vzHSQrhAdfZkGGda2euBmAY95SQd+Key1nzCM6vPHWITLZ0
         yDeD22JUU6vCAQfzQdbYiP3ZMK4OecOj+qGSQql2T/+uJ34jdQoLMsn/0DMgM+NSbBxH
         /WpL2gYZzvKQ3uSYgWB47TzdMFWOHujVOqUMHc5W9oUfQPZqHJM1mNhXHH8XZTn8LwlL
         Db0Jv8oMBQDVa3G1x06Hp39QwEhvsP4NDEpvCUHR0LDxg7VtgpzmNNNXd/HHQD7XNlzF
         sKPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=ezgzhu83;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id fk15-20020a05600c0ccf00b003fe0df12dfcsi962992wmb.2.2023.08.14.08.16.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Aug 2023 08:16:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 81B9321905;
	Mon, 14 Aug 2023 15:16:13 +0000 (UTC)
Received: from suse.cz (pmladek.udp.ovpn2.prg.suse.de [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id D31712C143;
	Mon, 14 Aug 2023 15:16:12 +0000 (UTC)
Date: Mon, 14 Aug 2023 17:16:11 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 2/3] lib/vsprintf: Split out sprintf() and friends
Message-ID: <ZNpFO38u9zfPRHvf@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
 <ZNHjrW8y_FXfA7N_@alley>
 <ZNI5f+5Akd0nwssv@smile.fi.intel.com>
 <ZNScla_5FXc28k32@alley>
 <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <67ddbcec-b96f-582c-a38c-259234c3f301@rasmusvillemoes.dk>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=ezgzhu83;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.28 as
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

On Thu 2023-08-10 11:09:20, Rasmus Villemoes wrote:
> On 10/08/2023 10.15, Petr Mladek wrote:
> 
> > Everyone agrees that kernel.h should be removed. But there are always
> > more possibilities where to move the definitions. For this, the use
> > in C files must be considered. Otherwise, it is just a try&hope approach.
> > 
> >> Also, please, go through all of them and tell, how many of them are using
> >> stuff from kernel.h besides sprintf.h and ARRAY_SIZE() (which I plan
> >> for a long time to split from kernel.h)?
> > 
> > I am all for removing vsprintf declarations from linux.h.
> > 
> > I provided the above numbers to support the idea of moving them
> > into printk.h.
> > 
> > The numbers show that the vsprintf function famility is used
> > quite frequently. IMHO, creating an extra tiny include file
> > will create more harm then good. By the harm I mean:
> > 
> >     + churn when updating 1/6 of source files
> 
> Well, we probably shouldn't do 5000 single-line patches to add that
> sprintf.h include, and another 10000 to add an array-macros.h include
> (just as an example). Some tooling and reasonable batching would
> probably be required. Churn it will be, but how many thousands of
> patches were done to make i2c drivers' probe methods lose a parameter
> (first converting them all to .probe_new, then another round to again
> assign to .probe when that prototype was changed). That's just the cost
> of any tree-wide change in a tree our size.

OK.

> >     + prolonging the list of #include lines in .c file. It will
> >       not help with maintainability which was one of the motivation
> >       in this patchset.
> 
> We really have to stop pretending it's ok to rely on header a.h
> automatically pulling in b.h, if a .c file actually uses something
> declared in b.h.

Yes, we need to find some ballance.

> >     + an extra work for people using vsprintf function family in
> >       new .c files. People are used to get them for free,
> >       together with printk().
> 
> This is flawed. Not every C source file does a printk, or uses anything
> else from printk.h. E.g. a lot of drivers only do the dev_err() family,
> some subsystems have their own wrappers, etc. So by moving the
> declarations to printk.h you just replace the kernel.h with something
> equally bad (essentially all existing headers are bad because they all
> include each other recursively). Also, by not moving the declarations to
> a separate header, you're ignoring the fact that your own numbers show
> that 5/6 of the kernel's TUs would become _smaller_ by not having to
> parse those declarations. And the 1/6 that do use sprintf() may become
> smaller by thousands of lines once they can avoid kernel.h and all that
> that includes recursively.

OK, I did some grepping:

## total number of .c files
pmladek@alley:/prace/kernel/linux> find . -name *.c | wc -l
32319

# printk() usage:

## .c files with printk() calls:
$> git grep  "printk(\|pr_\(emerg\|alert\|crit\|err\|warn\|notice\|info\|cont\|debug\)(" | cut -d ":" -f 1 | uniq | grep "\.c$" | wc -l
8966

    => 28% .c files use printk() directly

## .h files with printk() calls:
$> git grep  "printk(\|pr_\(emerg\|alert\|crit\|err\|warn\|notice\|info\|cont\|debug\)(" | cut -d ":" -f 1 | uniq | grep "\.h$" | wc -l
1006

   => the number is probably much higher because it is also used
      in 1000+ header files.


# vprintf() usage:

## .c files where printk() functions are use without vprintf() functions
$> grep -f printf.list -v  printk.list | wc -l
6725

  => 21% .c files use vprintf() functions directly


# unique usage:

## .c files where vprintf() family functions are used directly
$> git grep sc*n*printf | cut -d : -f1 | uniq | grep "\.c$" | wc -l
5254

  => 75% .c of files using printk() are not using vprintf()

## .c files where vprintf() functions are use without printk() functions
$> grep -f printk.list -v  printf.list | wc -l
3045

  => 45% .c of files using vprintf() are not using printk()


My view:

The overlap will likely be bigger because vprintk() family is often
used directly in .c files but printk() is quite frequently used
indirectly via .h files.

But still, there seems to be non-trivial number of .c files which use
vprintf() and not printk().

=> The split might help after all.

In each case, I do not want to discuss this to the death. And will
not block this patch.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNpFO38u9zfPRHvf%40alley.
