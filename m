Return-Path: <kasan-dev+bncBCT4XGV33UIBB2V7WTCAMGQERJIMKVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id D9414B187FD
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 22:13:31 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id d75a77b69052e-4ab7fb9c2d3sf14855461cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 13:13:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754079210; cv=pass;
        d=google.com; s=arc-20240605;
        b=Amli0RTP54B/l1HDxAy5TZzH/xeQZlAqVO+g/dmoShs6eLPj7KLAAeEoYOTQbBhOhV
         VhF6VErLBonFdnFAzgkCo6iup6awnxjEE2SaQ53q+3d4uBKHhbhU0iYCaSoKmBKbtUps
         TNk9t/CcSFfTvYpKwpgnhzFyCvYFBCsKgNK9LlpUTAihiFtuA/RiB0k1n8m+wxuK0wju
         vrsaDAmsYzSoqz+4QzvDrKrPcrhUP/7o7JFCcn/n4UBj+5TEI5YDLbaSXliuVCTIMxgM
         7S/n/5sOdG9YgSAJJLv7qKju9pFQlnaZ2L9BafVCPQbwmkWMNrpjqwTGndK7A8NsXovO
         SlQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=H7K8C5atG0vTh6mnA+mtV5I87E1yHmnMzGQLMwYYBsg=;
        fh=ckiiQQrQttXTZDrkiVFgGdATQbvoZYq0ns+gdwnBfKk=;
        b=dVsJtORmWfPpeARWEWeqOXx/K59IHJYe/0N47Q1dBLm0PabuyZDZW+GCKlmZDajBdl
         nELTpZn8cd+CTI+IHTDFu9gcci3Ed28L0pIS5KYkPVgIi58oHUBs8YBIGIiOXJZU1yic
         jX5GHg9uiMyoUnSfqwTIi645+qwK08AQ8POFpfDm2B706nmnXm/YwkrCoV/l0e6minqs
         xkGTphWdXFz77Xp0U8KriHiTPNcGfsejRoGHccnF6R52+s6TqWUT6BOJl8P780Hax0J6
         jp64QY11+61EqStO1USgkbqIrZHVmdJ9FB32wHYI7rEoEpRmn00Q1inzZHUazot74pVR
         EBEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=W4canb2S;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754079210; x=1754684010; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H7K8C5atG0vTh6mnA+mtV5I87E1yHmnMzGQLMwYYBsg=;
        b=weW+zmvaXf2Cc0uiGvlK/02i+2MG73+h5kmBSmUxwHqMcCuYZwNZQOPc1iw1v6Dch3
         TFtUjjyQ0nkqWTr5ZvBxrwU2KeGcDsyqSrjTBR7Rhx7KfEDFdKGnvZclOd/3n3Xum5H6
         qj2RJGzDMG9dQ3HHvkt2LyGj8D0jCT0rvmnMq0c2+Cl9KtF8KSKKno6AWuwP8iOPn/by
         9mZNUlztXRxUKyW+5xmKWKZA3QY6S9abcLHvPuca+LnOdH+9a/DQZZzRmUaATdcl5i+t
         e3aakVtpJz/XmwJyHU4pcrcFc0mFPkes9cEDsKi+X3xX4tgO495jghGUIRP9mbHyItjr
         txtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754079210; x=1754684010;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H7K8C5atG0vTh6mnA+mtV5I87E1yHmnMzGQLMwYYBsg=;
        b=IJ8+uRvjvTbd0zl5jzDwm88V6HrzFjlT/XrfDCtUi7hRSj02QehGVypLMslqPI2zDB
         +0KymowKO9RuOPcHLWJFlPnZkr/JORjSTroFELf0wX2kAGgYDtBtjENVMBrZQRXaA5jN
         29TP1VYMvJKRti2wxDJ5cUyLxCR93VhRnvcLvea4tX8l/JLLIWqEBW4m8D21Lb9B2Jig
         ASLeAeqMIflL+x8MxMh08vkyY7hw51lMgbVo6w8bTizTKtva17Je+bIekV0ZdPiC04S7
         F2Cdr9iBmrXorNI8S37CDWEZ1g87b/zrm5fy637+Bnu3gS0+mCXwwGdE/qF+qVkSgv67
         u5OA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV44M/wR1P5hbj9qAbdtsTn6AVQg6wgnndcMQdWb6kZAA2TsfcmaZaFUi/GUO5eSizVIwWtMA==@lfdr.de
X-Gm-Message-State: AOJu0YxTTge95UQX/6s7XNlLfY61PhdUOYI1JUc7xfrkkUPdkUt/mk3g
	FjQB7VyfbX97XtUBe94ASxz6vg9yXQwzJPpzAG8q1Iy5G2U4YwRxxewA
X-Google-Smtp-Source: AGHT+IHBb0zoiNa+Yyyhs+ke6bkc2wYz65701opoYxOQfVp9EQ94ilRdTzEzHnSVpVNYHPvqS6NRgQ==
X-Received: by 2002:a05:622a:e:b0:4af:f69:b30d with SMTP id d75a77b69052e-4af10d1acd8mr23868141cf.28.1754079210315;
        Fri, 01 Aug 2025 13:13:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf+AuTbi+HrH2jrVasq5EGXRd9PGMyZq8DDtgtrdr7+Ww==
Received: by 2002:ac8:5a0a:0:b0:4ab:8d30:5860 with SMTP id d75a77b69052e-4aeef24d30bls38503651cf.1.-pod-prod-08-us;
 Fri, 01 Aug 2025 13:13:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURZ5eOyBE0a3Tvy87XTPL3XGn0vue4fBaOnr2cMrji1zSd49C1oRQ6vulNoYOXblge+2mCPOkgDDI=@googlegroups.com
X-Received: by 2002:a05:622a:411b:b0:4ae:f830:c0fd with SMTP id d75a77b69052e-4af1077c816mr22956181cf.0.1754079209271;
        Fri, 01 Aug 2025 13:13:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754079209; cv=none;
        d=google.com; s=arc-20240605;
        b=YMSe/fTC2bjs9X91wXy06xY/p/y6OZ/+oUA1XrWlfl3+Ixb30y5Yf4iVv/CTYF/JRV
         KMuT8lc7l0GDLx/8FLFz/GYaPeLcL1JHnaLVrirMukViVrotT+jfKz3CmKuXe3U99243
         kPu7u824f56h7vULCTKnGIis1haHRrYshkX9nqxFlIY0Hpk3Kne47VlQofH4e63N3DUe
         R/FW57tIEKW8jsBrNfsD+rfTUERZEZvUUFEhvQzFc4ZxCHFDXbpajbHgN6HrC1HO/ZEU
         6YyyU8Yn+X8glqw9dkGDK4ccDgUF7Z9TWBHRgO3phHk3iI4YmbPk8ztDCBo3nwBv6xQI
         vu5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=tRxRA81UCOepWIEaQkaCu6xBDyfNQBkbQLYOh2c2n7k=;
        fh=722MfNXOXcHEbI4JAs5mFiHZw/tD613SMkITiaPv430=;
        b=Z3yhCyx+MkKk/DBws44J+h0w6njGuB/Dw3I6kYKBdLmpUP+p+SxIVIhfU7MQZEXfNQ
         O96i4c8YwQ7yDY2GWvnMaGQn7J/dOrv3XzVy1ZY4iS3shid52r/pKMYeC1IE3qb5as9P
         rW4PfrpJm+592/sa8Nwwm9nEKrTshoifNEDtoU9zNzpfVNKannwAtTYMjMbbbh66XRoC
         /IpyKdL3BqM8+cGWR5Q4SeBMmOs2nf70m8k4PYlMEG3aKE+Gd8tYtJYZ9XPgpHV5WqjI
         drJyx8QEnaAlbha/IWbdjKxzbvgDVO4dCsFUIiE7KXhUpoeaDFVtkUsO8GHXK/bCjfe+
         hGNA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=W4canb2S;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e67f4c0beesi15340285a.4.2025.08.01.13.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 01 Aug 2025 13:13:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id D057EA5596F;
	Fri,  1 Aug 2025 20:13:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 348F2C4CEE7;
	Fri,  1 Aug 2025 20:13:28 +0000 (UTC)
Date: Fri, 1 Aug 2025 13:13:27 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: thomas.weissschuh@linutronix.de, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3] kunit: kasan_test: disable fortify string checker on
 kasan_strings() test
Message-Id: <20250801131327.8627459bf3d94895d42b95b2@linux-foundation.org>
In-Reply-To: <20250801120236.2962642-1-yeoreum.yun@arm.com>
References: <20250801120236.2962642-1-yeoreum.yun@arm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=W4canb2S;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri,  1 Aug 2025 13:02:36 +0100 Yeoreum Yun <yeoreum.yun@arm.com> wrote:

> Similar to commit 09c6304e38e4 ("kasan: test: fix compatibility with
> FORTIFY_SOURCE") the kernel is panicing in kasan_string().
> 
> This is due to the `src` and `ptr` not being hidden from the optimizer
> which would disable the runtime fortify string checker.
> 
> Call trace:
>   __fortify_panic+0x10/0x20 (P)
>   kasan_strings+0x980/0x9b0
>   kunit_try_run_case+0x68/0x190
>   kunit_generic_run_threadfn_adapter+0x34/0x68
>   kthread+0x1c4/0x228
>   ret_from_fork+0x10/0x20
>  Code: d503233f a9bf7bfd 910003fd 9424b243 (d4210000)
>  ---[ end trace 0000000000000000 ]---
>  note: kunit_try_catch[128] exited with irqs disabled
>  note: kunit_try_catch[128] exited with preempt_count 1
>      # kasan_strings: try faulted: last
> ** replaying previous printk message **
>      # kasan_strings: try faulted: last line seen mm/kasan/kasan_test_c.c:1600
>      # kasan_strings: internal error occurred preventing test case from running: -4
> 

We don't want -stable kernels to panic either.  I'm thinking

Fixes: 73228c7ecc5e ("KASAN: port KASAN Tests to KUnit")
Cc: <stable@vger.kernel.org>

What do you think?

We could perhaps go back earlier in time, but 73228c7ecc5e is 5 years
old.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250801131327.8627459bf3d94895d42b95b2%40linux-foundation.org.
