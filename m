Return-Path: <kasan-dev+bncBDZKHAFW3AGBBMWHY6TAMGQEV63PJ5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C39A773847
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Aug 2023 08:41:56 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-40fe2ac4356sf621541cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 23:41:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691476915; cv=pass;
        d=google.com; s=arc-20160816;
        b=GGnzNLkV8VkEeCgisIauzLerR2u7xHhkBNHD3Gz69hRoGR325/ALXQ0b79bwMCHRK3
         pAEH1IhMDPJRfD/6QDGI1wX6PaH3Zepn+twTQ7KP8ZJnlu137WTMdnPIA95+BkF8ACYL
         xER+5YvSYYB74xX/wrsAZc7jc2xYHBa0pksa8RVzGjfMSyfzToOWnUaJhbNfgcaJVdy6
         AIBN6Ypc3CYppqspvTPF/qCGokl3jTDMWl8bP4v0IM7uvZuM6EY8rzNxA837SWkxRp8x
         TGzT9w4j02KuQf1fgeVa25H062nQu9dOgcLUZ4CrQyTiuyjVfBPN//ZXOyYGRHvuE5XN
         4/lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=l732cEeDHScM+leu7JneyDJFksCgFmY66u17YG1lKMo=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=zT+WejIf38Xn9X4TOrnAn0x3AB6k3T4ae2LFesJaaXEIjwKHFM3lhAQ8Utua6R65CM
         TBnslAbcf56+oJIu7ZTp+NUnas2mDrQR4MzoDBxCV0zEfaFAVh2/ABTiG3vL9x9F9KMY
         DKUNT8Cy4CAngPYCxNmQTpqqbQzunkAz/qS3Oq06VuB9ga0m0z0LGuN2bULdwMC4A1x4
         MrpvYL6iyPq0rVjSjR0BZQSk4sXPSYNqreYc1sc5jUdn1uiKTxM4rHqaxfwNT8FYPy3W
         L48wMRnnJRTUWa3NJM0JVsMHSHwFbnvt4TMELJBJARofRCvO3N8W+ovSwYub0ihRswAo
         3bYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=jOO7Z6NL;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691476915; x=1692081715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=l732cEeDHScM+leu7JneyDJFksCgFmY66u17YG1lKMo=;
        b=QGw4HiMrZ+Jd+gggiJhFS3K1/K6vTsU3rx+7oDOydaIESQ1KZYYXQN5bwLYCJFjSvb
         /Ty1oHLRQvNmhQka0I1WGkohr79g3j6Ymyff4tYsatpM25XHxQ8AI9Hb+wRcKOYW4KXN
         wjT2TJqyEkNjJHuZnPfSRJPscPF56D80wS7n1tGhkGlxkE4q9FYioD1K9zxLvmXg3e2d
         9uiXJ1NkXbIsqFVZ8lzh1c4nO/P4eRrc2GTeyRLA3q7dGWTbgt2bRvz1Pszu7Mq1pznl
         B1NGzFwaKXh1m9/YTkFBUKKaNerqbN0QCQ9sY+go5/Amx2Ea0YRJfEyxcbTVJaT0YxoT
         qqMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691476915; x=1692081715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=l732cEeDHScM+leu7JneyDJFksCgFmY66u17YG1lKMo=;
        b=MOx+Mrbva5zAfiuK9lJ/2sGQP023aMrhjsrjl92d1g9oHRjHCIhMJ/CAz+2kX+ulUn
         IhzmZiH051GCOtN2jJppG0QFM0cDpWTdSmZSPK5WR3QZ4kf3VvW+iZYnUJpJrtPptHrX
         tVdKtqDIXbtNmA4IRT+I+Egqe/t61Azl2UVTjRZORDUuZtO16leKOeDmz0oIfSMbkNBB
         MtqNBbLVBt1982E4kQJAlh3IO9EjQ75ea+o0T14pv/Z70k6r8ZsytYYwa8A9pO3J/4w7
         3KZvwi+e/13GKzTPfkqjTRcfmo7qxqrIT9FEvJ4YG5/us9YCgBuHDyiFQBgWnoh9gmUB
         +bFA==
X-Gm-Message-State: AOJu0Yzocfd08D75gwH7T1XNSo4Lu5/8tJsdw3OCRLEOuMnjUFAEXtcT
	onkQOyvNv5e3OZvJUgxh4yg=
X-Google-Smtp-Source: AGHT+IElpGxRpSnXhJhOVAkWieDHRcZAOc7wS9ZoQgKr8Kz6O/87XOyV5qUidn6ux2zIvsEhTrBLRA==
X-Received: by 2002:a05:622a:d0:b0:40f:d387:65d0 with SMTP id p16-20020a05622a00d000b0040fd38765d0mr757625qtw.16.1691476914937;
        Mon, 07 Aug 2023 23:41:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f3c5:0:b0:635:e8a7:8831 with SMTP id f5-20020a0cf3c5000000b00635e8a78831ls3774198qvm.2.-pod-prod-05-us;
 Mon, 07 Aug 2023 23:41:54 -0700 (PDT)
X-Received: by 2002:a1f:e247:0:b0:486:484d:3058 with SMTP id z68-20020a1fe247000000b00486484d3058mr6026650vkg.14.1691476914128;
        Mon, 07 Aug 2023 23:41:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691476914; cv=none;
        d=google.com; s=arc-20160816;
        b=NlcoXw6uKq1631sbeBh0kz8zY+3D/w7rmD1dHo0cteHvkZLebtpfgv/j2A6OM8wwYe
         g4bFBiToyG2azmSXCXVvhbEN7nF2wEGyAomzsf5OjaxV8rVRQKZDsVMNehh71u5smcrS
         uyM0PTr4gww8Q4zFVAsa5sfk010HTTKU1uSHiRoH+OrY7j/OpHcVYOroO9/LgwcJEcdY
         lXuzuoN0iOxbX/aUH/5oevfI0h2ur1wxOmxGlJXbeRT4+T/92uvzg06dQGwP6t5QvuVn
         4fr0IbUM9gE4DT6KkMUkmHrLIh5nD5STnXIf11re7hm+NRG9M+AiT4IPgKQ6jfCpkFjL
         1EZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=fn8p9+Au+wVsN8+8boY+m/Rgvhm2LtPNdNtgtmsLtSc=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=B1WUf4g5EVQ662FgWMRZtZRusSrO8yEcJsWWNv2kq3v6F7VXIypICibhrDSTCRtPWM
         R40jd6J7BFXiV+isF1B0qfPapFtEx9wOZ1+9o1EZfaG0uCSbTm9J/QQtRp72Oy0tS/dL
         gRjtNIpmhL1lJM99DLgF/lY8EMwXKZEU/6JnFxKNHl8EMxvCoSJN2GnQlndH35Qs2Q6t
         511Psl8irWd3HRS8PctEsMVoDewJ1OQnTyhPk2cM53eM8AaAic8KIW2zou96mr8P+85W
         WvyTou2z6BNlunD/hF/TiuwH6vybAlau3n1197YUc2onIKejjWvDIN2qwWFGGLinJqMw
         MAIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=jOO7Z6NL;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id bb40-20020a056122222800b00486ab151600si636087vkb.3.2023.08.07.23.41.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 23:41:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id ECAA622471;
	Tue,  8 Aug 2023 06:41:51 +0000 (UTC)
Received: from suse.cz (pmladek.tcp.ovpn2.prg.suse.de [10.100.208.146])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 5CECE2C142;
	Tue,  8 Aug 2023 06:41:51 +0000 (UTC)
Date: Tue, 8 Aug 2023 08:41:49 +0200
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
Message-ID: <ZNHjrW8y_FXfA7N_@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-3-andriy.shevchenko@linux.intel.com>
 <ZNEHt564a8RCLWon@alley>
 <ZNEJQkDV81KHsJq/@smile.fi.intel.com>
 <ZNEJm3Mv0QqIv43y@smile.fi.intel.com>
 <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZNEKNWJGnksCNJnZ@smile.fi.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=jOO7Z6NL;       spf=pass
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

On Mon 2023-08-07 18:13:57, Andy Shevchenko wrote:
> On Mon, Aug 07, 2023 at 06:11:24PM +0300, Andy Shevchenko wrote:
> > On Mon, Aug 07, 2023 at 06:09:54PM +0300, Andy Shevchenko wrote:
> > > On Mon, Aug 07, 2023 at 05:03:19PM +0200, Petr Mladek wrote:
> > > > On Sat 2023-08-05 20:50:26, Andy Shevchenko wrote:
> 
> ...
> 
> > > > How does this sound, please?
> > > 
> > > Not every user (especially _header_) wants to have printk.h included just for
> > > sprintf.h that may have nothing to do with real output. So, same reasoning
> > > from me as keeping that in kernel.h, i.e. printk.h no better.
> > 
> > (haven't check these, just to show how many _headers_ uses sprintf() call)
> > 
> > $ git grep -lw s.*printf -- include/linux/
> > include/linux/acpi.h
> > include/linux/audit.h
> > include/linux/btf.h
> > include/linux/dev_printk.h
> > include/linux/device-mapper.h
> > include/linux/efi.h
> > include/linux/fortify-string.h
> > include/linux/fs.h
> > include/linux/gameport.h
> > include/linux/kdb.h
> > include/linux/kdev_t.h
> > include/linux/kernel.h
> > include/linux/mmiotrace.h
> > include/linux/netlink.h
> > include/linux/pci-p2pdma.h
> > include/linux/perf_event.h
> > include/linux/printk.h
> > include/linux/seq_buf.h
> > include/linux/seq_file.h
> > include/linux/shrinker.h
> > include/linux/string.h
> > include/linux/sunrpc/svc_xprt.h
> > include/linux/tnum.h
> > include/linux/trace_seq.h
> > include/linux/usb.h
> > include/linux/usb/gadget_configfs.h
> 
> Okay, revised as my regexp was too lazy
> 
> $ git grep -lw s[^[:space:]_]*printf -- include/linux/
> include/linux/btf.h
> include/linux/device-mapper.h
> include/linux/efi.h
> include/linux/fortify-string.h
> include/linux/kdev_t.h
> include/linux/kernel.h
> include/linux/netlink.h
> include/linux/pci-p2pdma.h
> include/linux/perf_event.h
> include/linux/sunrpc/svc_xprt.h
> include/linux/tnum.h
> include/linux/usb.h
> include/linux/usb/gadget_configfs.h

This is only a tiny part of the picture.

$> git grep sc*n*printf | cut -d : -f1 | uniq | grep "\.c$" | wc -l
5254
$> find . -name  "*.c" | wc -l
32319

It means that the vsprintf() family is used in 1/6 of all kernel
source files. They would need to include one extra header.

If you split headers into so many small pieces then all
source files will start with 3 screens of includes. I do not see
how this helps with maintainability.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNHjrW8y_FXfA7N_%40alley.
