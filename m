Return-Path: <kasan-dev+bncBCT4XGV33UIBB46EZCQAMGQE6AWIBMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D9386BBDA9
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 20:54:29 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id bp16-20020a056808239000b00384dfa31ab8sf8877824oib.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 12:54:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678910068; cv=pass;
        d=google.com; s=arc-20160816;
        b=t3tVXoJxIjUAHkVC5rXC69lidIENuVf78yx2ld6VF1WpK+ntFCBYBh6h3lZNN5iEW9
         IlUOVvNBUdwSganEuSIFdxcDJUAnWnDaPLPiIGwlpVhTavddyxQJKzZmpvsJ8OrzYGge
         VtAOsB5p+Eig+VWdBl7VJ9xJ3ZtkUcVHmueHD0vH70EJkVB+HoVHKSkNe7vLtapMuhPN
         QTX3neG+MBKvP/SVwyyB/CYJQ9rTInE7xPaW4i1HlApZ0VdKj98e9QGJGfyFuY8FtBUS
         JoPsS/QJExJ9+G6z9sJS9DiexgRUBYuRAVFAcXynGOZPFfhMrUHSaaAsQRabQY414qb/
         lC/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=eKw3kwclOquuQXSFV/ycae/ISHgNftc37bl3XMNrGeg=;
        b=WexALWKxu5o/5XFfM3AKKDvxWtmYpWAx+AqvtBt43QNan72j4VnU2htW2ba6W2T2Ee
         uQ55onmnbZFG8aSYMxGwFJAgzaXAyyA9d1ST7hKoNMa4y8MuPnhMqmfrKn1Sjjm7pCwE
         SfYuz6tgjJUnxDEUOXNxgZofbU6J5/lzB2rAl2U6QeeYRzCRiKrLpW1ySTQB+BYcExuN
         Mzt1TjILywqLUwKGPP2Y8UvpnD2I52nXC5t8LFDpFCMx3QwxoJ7OLHWbgTOYrF3uRM4y
         FswE5wrgEPXl1FJ3FQebvOk4hXjZiedxR3/Xn54IdH7Hz8Y1nSG+XurGkLAaMUoPXMjY
         xkIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=luFvZF6t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678910068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eKw3kwclOquuQXSFV/ycae/ISHgNftc37bl3XMNrGeg=;
        b=o3fpfohBy7vXkuGAMuwmyC3F/FJhiL2x4O9KLWbMsqd7M1Z6NqmmHe0EYv1U9jqxRu
         VqBoWcEcwGlRhU7v7rY89S6tR8lEo4aAvnl8lbzXSKO49VEhS65d0QkiLjyfKc3Q1I47
         1lzW6YPkHqtX03kFZIvFec46EIYu6/hYQ0hfAXk9cwZ6pYbbRb6ucQHDPZztW16Ocv/4
         2t3QbwvVAlHR4BitqmLHsJPUSxzFQ8EzkN730XHz2cm1fnL6n7k4E3F6+FMKMk7Bk25A
         Z3zvYysT0kfECONObd1+/a6naEokTg/qGjIKKieLyhcM66p3jBoT8kdSUIeVK+uQywzr
         isAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678910068;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eKw3kwclOquuQXSFV/ycae/ISHgNftc37bl3XMNrGeg=;
        b=1OWT8mfTlLehndIQOZHJPAxtE89Jy7kBMHir+1At6dLWSWgV9e+hxN77xOmEEx576y
         v+piWBdx0rqn1a7Y5aEYFeHYYwz95w1l/Zb8bFzVSFTMvmSNJo8AaE61NfCorXVeM7Zo
         rrVfb3UpSAd9bjQW9O2cxEhCp+8+baU7qlEigGkDVVxPvbZeZSlpm6mG2tzHblMcvGMX
         G4O/Nk75tR4iHJfO7mI9BOMus3HdnGeLZkLpEs2PO/4a7x+zZ7KFU4jGRvd5pJyM2vVH
         IPEcjCn1bjpNswdvW1Yb2uPIOQThuY1wxKBX1ezta84tWE0s8YwsrT69p5Sf/7R4ngqR
         e43g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW+klyi/javUPejCR+nQqP9wj8SKYmkBgMfzpY2n2EnwrVEmWaC
	xyD5biWlIdW7YtO/vwdRiGk=
X-Google-Smtp-Source: AK7set9S1Q3lhXrIiOC5Q6sGVaRiph6dVZHwVdHsV5zC9f8BsgADkGTSOPKF6kLFROicJLrJawOW3g==
X-Received: by 2002:a05:6808:57:b0:384:2b09:45f7 with SMTP id v23-20020a056808005700b003842b0945f7mr1238694oic.4.1678910068089;
        Wed, 15 Mar 2023 12:54:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:524b:b0:177:90a9:cbc3 with SMTP id
 o11-20020a056870524b00b0017790a9cbc3ls6398539oai.2.-pod-prod-gmail; Wed, 15
 Mar 2023 12:54:27 -0700 (PDT)
X-Received: by 2002:a05:6870:b694:b0:177:b985:a37f with SMTP id cy20-20020a056870b69400b00177b985a37fmr7764102oab.16.1678910067565;
        Wed, 15 Mar 2023 12:54:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678910067; cv=none;
        d=google.com; s=arc-20160816;
        b=PCNVUN+l9HWcJgXP56a+0LJJ4u31Hu9mjUwE73TampxLzVGuv4736vQMmYbnuqL9RM
         hwvuPyPyaJKfE89gRtcA+1CBFH+PYZxIS4XitgqdYKhX3K+r2EK8QOj+MC7fzskNoubB
         RZfIclZehMUYHiV3gzycTUTsNGTuWfKhAuK1MSxMihCLlV1EBYdT9FD/6IDpiPjbEyxn
         jM2hHvirNzHBS3XVEWgOWrK++vXS9sHAoWCdX41hIfuqyCX20eV0NegkwUzYoEMMK8nC
         WWvwa25Rvf/D5dePzGbqZgGbmzUNlL5lPL/WCufFnuZTgwmjhrEF6la7/4pP2fONprH8
         xlsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9AAou3U/n5lP2mER/7d+hOVC3C65p98RSFqEEa/lZg0=;
        b=NEELWZhAKKUusGWFNNsfMKkOVza8Z2psrl2OXZ8N2fXqpYQA36CZVG6ezP2xbxIuTY
         CqCTRc273xPyXX2xiyFf6sN/rUBrhTsD68NGSHF6ELNUzJdprc3YRipt/TXBDvvOi5xE
         ais01jpTaNVpeweO6Eu3mzeLdwI1JBXGUZG2Z+l0ZgltLyi4JYLAZwGRqwOA32BsBxRI
         0ywL8yBx01zrN5nQS83vQrpgCsHdUFEcClDhDVpiALH37kh/+0OsM4VuhEUxHlt8Y3w6
         O5F/mLrEp5/KyYsUaatSvFVRCsSVFZeXgOEatob8RHIaiGGbsCGBIoGZqAaEN7Pg3K+M
         E6uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=luFvZF6t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id pn12-20020a0568704d0c00b001723959e146si1074831oab.4.2023.03.15.12.54.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Mar 2023 12:54:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 46DC761E74;
	Wed, 15 Mar 2023 19:54:26 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C6856C433EF;
	Wed, 15 Mar 2023 19:54:25 +0000 (UTC)
Date: Wed, 15 Mar 2023 12:54:25 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Muchun Song <songmuchun@bytedance.com>, glider@google.com,
 dvyukov@google.com, jannh@google.com, sjpark@amazon.de,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, muchun.song@linux.dev
Subject: Re: [PATCH] mm: kfence: fix using kfence_metadata without
 initialization in show_object()
Message-Id: <20230315125425.70a22d32cf46b23d249775ec@linux-foundation.org>
In-Reply-To: <CANpmjNMxDT+AHBZra9ryhm6aw+WqBsdJ_SKdcdZr6CBsh97LyQ@mail.gmail.com>
References: <20230315034441.44321-1-songmuchun@bytedance.com>
	<CANpmjNMxDT+AHBZra9ryhm6aw+WqBsdJ_SKdcdZr6CBsh97LyQ@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=luFvZF6t;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 15 Mar 2023 09:07:40 +0100 Marco Elver <elver@google.com> wrote:

> On Wed, 15 Mar 2023 at 04:45, Muchun Song <songmuchun@bytedance.com> wrote:
> >
> > The variable kfence_metadata is initialized in kfence_init_pool(), then, it is
> > not initialized if kfence is disabled after booting. In this case, kfence_metadata
> > will be used (e.g. ->lock and ->state fields) without initialization when reading
> > /sys/kernel/debug/kfence/objects. There will be a warning if you enable
> > CONFIG_DEBUG_SPINLOCK. Fix it by creating debugfs files when necessary.
> >
> > Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> > Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> 
> Tested-by: Marco Elver <elver@google.com>
> Reviewed-by: Marco Elver <elver@google.com>

Thanks, I'll add cc:stable to this.

I assume the warning is the only known adverse effect of this bug?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230315125425.70a22d32cf46b23d249775ec%40linux-foundation.org.
