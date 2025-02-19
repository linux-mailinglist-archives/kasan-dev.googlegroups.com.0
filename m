Return-Path: <kasan-dev+bncBCT4XGV33UIBB4OD2S6QMGQEXFWSTXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 16F98A3ACFA
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 01:12:35 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5f32b797245sf7216980eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 16:12:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739923953; cv=pass;
        d=google.com; s=arc-20240605;
        b=NmQX880Sgdp38F29tE+dMucFy/c/B9H8lUBhPTSyL6nUZ/kYuUOzZDN6LNTxe71nEM
         kKX5hkOW/62m+3Cg2S/pSSsKwZUgeXOzABi+wbHTZOb71t8OxEuy5+DqAUwd2PuY2G+z
         5BTTjJOZZ00wyysxgonXGbjD6Q5G7eQfl411zIIM77+IGOVwzVIxlO0gygSR6Sf+x2UZ
         gLDF8C+qBZZLNT0BPZxYbLZ+rlNgJQ7gSRUxyZ5Hx0qauq12Ka0OOQ7zPLk1DLGvoySZ
         tX6KVsf14mHyHfMa7+lguqmoKs4yIbkQSv7AKJzE/G4saXn6a6f4bWp7jMwHb+elkwpq
         508A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LSHRb5IpwxqDluWin2/xRdt5muzSr1GLGgxdAS43HoM=;
        fh=GpXQBYxc7cOLqZOwl7BvDmIu/8vg3FTnDu096D0W2LQ=;
        b=NH274gn/5DGplnTmXvHqovtjyAbbR0q1VqYBSiB/oxjiqnO02Q6OmreZgv6FM9wTa9
         R5m/78OOyGkscoIr6iqaYFXQk6geJ9zGHLLIyUwFxZUq9mEZ1Tf6VrfmiWa6FFMkC2vX
         ycrIG/IuutPqDY/FvTMGvTzCaCIJf6B4ejsLoJKg+pmPVWdWr3CvYnsvwPJr5wE+fRpp
         YgjdS00mVRNla8VevYu0TlaFkQ0RtiOrkuMvCqqU13Qa8cWSfu4klGCghrAhQsgcTLf4
         5TdI16RQtvXxDq9UpuCnCR+vDg1NRuMVNDNqdZl8mLMhLc+v7ZI5ugm568NIUPa/46wV
         pd3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FTphuxgJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739923953; x=1740528753; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LSHRb5IpwxqDluWin2/xRdt5muzSr1GLGgxdAS43HoM=;
        b=xz4MPeE/5RIf+hRynDHZbm9zEbxG5KRq0EQwBN57nNU2a7TF61xzzT3VuEvRHDS666
         bfBoFbGdK/F7+F4WPSl5yWc5rlCCKN2PuTCQzwAiTLuQhOrFLqp9kIX0J4tgISdOrNt3
         Ye/49huo8THJ6ahBH+GufCBf5IFtjU0ylrKzVAYf0Ng9h/JnfYRtzrcTrohXJtVGiA+D
         cbsdtLmFQCdUU5a3OaOGUBNT3brHLjOJ82grMWXtdQH8hNVudcPLsgS5uJQ+CJx2Gb2r
         Ysd+xutQ3Jmqzwgrh+rgGGRad9GeXQjqsKRi/5JYijfwPTrBCwbSWM41krS8WJ9FxP1V
         qk/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739923953; x=1740528753;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LSHRb5IpwxqDluWin2/xRdt5muzSr1GLGgxdAS43HoM=;
        b=FPCuANL7pt4XflUQpwTATGtNLo/JcrumEC+58SIdUuz2dLsXNo6UvaP9kVUHWSlgxf
         ZYWmtBocSqutac7pPbdbPfq4BeTibJ9cB9nwLXlZCSRwfj8JB6Nwbi7rhzoAx9Y3RORz
         m9g3Hp0Fmr8WXTTIaJ/WuuCGIc3rKuHbJkqmSjT0iYlMiXY705EE9Qy/T5TZq1R5n9jF
         i72hrjaJJgiJfqDLP2Mrjir7Gatmox4t54LcNp/l+OBTdZuznpN9JxYiKm94vPi1sitW
         LNtDKr4lGiP2nQ+3E5C+9xpxNdPjSCOlUVCdTGTNdcwMc2PXkE1LtsdDkr2v8bI70MQt
         YAhQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVf22yhYha53qrET4gn3CJ1usTNOeOZILfxnLNDguxVTMSzKnAXJS8BLPWcAzF8r3pPpGLNMA==@lfdr.de
X-Gm-Message-State: AOJu0YwEV2Gt2WCTbDGtEXyVbQ3JQ4RAuiMpvl21F1ZhewKWoaL1Ei2o
	t1MfIAVF1B4WOtDH/d6+lS5G/gwumAdlc3sb0fpNeGC0PTE99UJQ
X-Google-Smtp-Source: AGHT+IG0b+VEUQZKufNp69Z9hIyHV2ywjV/aBdvo6oiTdGBXpPEa4p9ZUZiMMMY777N+QuIedQY3kw==
X-Received: by 2002:a05:6808:bc3:b0:3f3:c9fe:7f9d with SMTP id 5614622812f47-3f40f1e5740mr1091913b6e.14.1739923953668;
        Tue, 18 Feb 2025 16:12:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGVWYb6D9vQczUvrk73a6IJH6u7V8r57oS00veIYY/ZCA==
Received: by 2002:a4a:d0ba:0:b0:5fc:ed3a:db37 with SMTP id 006d021491bc7-5fced3adbb3ls857151eaf.2.-pod-prod-09-us;
 Tue, 18 Feb 2025 16:12:32 -0800 (PST)
X-Received: by 2002:a05:6830:44a5:b0:727:28a:1ca5 with SMTP id 46e09a7af769-7273777aa54mr1224129a34.16.1739923952330;
        Tue, 18 Feb 2025 16:12:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739923952; cv=none;
        d=google.com; s=arc-20240605;
        b=gO3SCmITLmXjS0ljO1Kag3nOuhQKd9O3WHt1w8XyjbJXeuUQ/DshBhn7mW3lyfv+K1
         QLMHnc8GInwo8kgh130GAxAU75ecPTeou0IdEathuyt8Pt3Oyq8u58UoHtZou6cOaAHv
         YHfQsuevUtlAh95ko7OnhV7sI/T9rcTjsTTbk/lqXfrdJGFaI6tK5jDOGc4+EeyZ3PbO
         Mg0AO/AJQjBanNToSzacLNffcCsrwTmSAjDMzQOpsyc+1jA79YOozpagXQkUXHd6hoGN
         Qzd3fgVxhcdrPfh9mMpiLltsgDZlq4roH/JnK+7CbfL38r8tdPgUKr2X1zrxKztrjhmM
         VA7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=dgmt0cbpsff48sLIal6btf7zwzG/jjV7AyjUiUggS7k=;
        fh=sgpNh+JL8T6yA/giX5MLBfEGEge12ex5c5OTupBj7Z8=;
        b=Qhu0uchbL6LU8c93WcvOMJXVIW8UkNQ4GE1hXxQ/kqyLK1R+p35VMyge9gTVpSequr
         qyrPmBXnHFgGX+Yh41iPHKR8z2IBNWc3SlLa6cCC8L+4utdmgxKQ+93UpLwiM8qugm0a
         hfc3fQfcY3G171b+rZO0bs80WZlnXAaM44BP6mIRAyZe0twMAMhSQ0rQzCdf1dEsCvWi
         0S2ORvLd32cLLaQ9xxeTb4X/XOjTeJoOHKaNoQC8f21YpeedcjGRP607ib4sP2fXZ6dX
         CI2Bka2F9RiL+s4NE58zqcYTTKOBQ+ATZRVAPGWiMWNb2ljfHpBV5jbdjJFTM7AaLSOW
         qPsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=FTphuxgJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-72722fd8a0bsi200538a34.3.2025.02.18.16.12.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Feb 2025 16:12:32 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id C90A5A409A4;
	Wed, 19 Feb 2025 00:10:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EE70EC4CEE2;
	Wed, 19 Feb 2025 00:12:30 +0000 (UTC)
Date: Tue, 18 Feb 2025 16:12:30 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, Alexander Potapenko
 <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, kernel test robot <lkp@intel.com>, Peter Zijlstra
 <peterz@infradead.org>, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, linux-kernel@vger.kernel.org, Thomas
 Gleixner <tglx@linutronix.de>
Subject: Re: [PATCH] dma: kmsan: Export kmsan_handle_dma() for modules.
Message-Id: <20250218161230.0d06d45190b1ecdbf9e97564@linux-foundation.org>
In-Reply-To: <20250218091411.MMS3wBN9@linutronix.de>
References: <202502150634.qjxwSeJR-lkp@intel.com>
	<20250218091411.MMS3wBN9@linutronix.de>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=FTphuxgJ;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 147.75.193.91 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 18 Feb 2025 10:14:11 +0100 Sebastian Andrzej Siewior <bigeasy@linutronix.de> wrote:

> kmsan_handle_dma() is used by virtio_ring() which can be built as a
> module. kmsan_handle_dma() needs to be exported otherwise building the
> virtio_ring fails.
> 
> Export kmsan_handle_dma for modules.
> 
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202502150634.qjxwSeJR-lkp@intel.com/
> Fixes: 7ade4f10779cb ("dma: kmsan: unpoison DMA mappings")

It's strange that this took a few years to be noticed.

Thanks, I added cc:stable to this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250218161230.0d06d45190b1ecdbf9e97564%40linux-foundation.org.
