Return-Path: <kasan-dev+bncBCT4XGV33UIBBEW5U2BAMGQECWBY3PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E63A336BBC
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 06:45:56 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id b9sf1916883plh.9
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 21:45:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615441555; cv=pass;
        d=google.com; s=arc-20160816;
        b=yda8s0m4OfBuYbFIRbOv3iMChYDCvh5V7bj1fWreTS6vQMXbxdlBkE6gn6n0um46RF
         xytdkcb7xwTjJE7OUaaEFRzK8TewUR8mjbfFnfA7t3g+Gi9jQdOdwVlwWTrCGX4gPE0k
         1cI6ZLcPInF6loknuUI5f86hIeb3Vjvw0+YvREaUC2wqdqEnS/BWxKVjLskj9qYOHFjq
         1xdmiPLSUxo18Ostm/MaJZXAl4mD7phctiaUNFcMJesU8vmEwaybVL2+2m/TKNZB7S4P
         nSV9vI3XhF1clW8aKTe9i7FuwKAx77L3+1MeJVLabiNC+XQR/dxU61UKz+a08FuPBwHs
         A7Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0nqOd1s+PTKqC8//bPAghc8PCn6Ldbg7MmRq4a+6nn8=;
        b=DhIL9Smg+jZ6jMu/kT0MauqpaUuaflSrOHNamHcm+S0qC/s9p8VVBu3YH6YE4juoWe
         2uRAYoZHGBgw+5GYjJHtmfjCTE5ApnIn9EqxO6c2ToulMkvxR46/JuOYm6/AoCsEWdbH
         crgmBgctA04xO0lOdUe6enjFq7gftiU41r56i8Jvatt4eGnBNS7kJzQcF/wlbOUd0tFf
         KlWF+hvpOGvlsmB30Np5JgjZCseoCdzUl6NgHivusp+arXlV4YN48Btxk7gGD6xd3whl
         Z6StyzoErjtqHoWvxE1Iq+v69dzYa6Vf0x0py0hoEW4ueV5plEhuLjxxYqQFFnoMWwrs
         f6/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OHIU/hI3";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nqOd1s+PTKqC8//bPAghc8PCn6Ldbg7MmRq4a+6nn8=;
        b=kM64+Sj0vJPBsg/I7wbdgbDYxKFNmeXrPC/O750y7+yrETAKe37fAo6p8HQKiZsInb
         C3gFO5dEPxZisVvT2MN2XKgxrVN2wyFEwry8EJU3lVPRLd3ItjXcCubYFOxl+w2vpyYe
         GZRxCbPEX/uiKZYJYxixRfnGWXdRW0pZaYUzDk1MoZrTXRu/aXSHHTyoXPaCIfRjyC/b
         BpMw/buRXw2OVv5Zu38jAPbSEoOumqtYBj7JJsl5IUY2r0U6HMBT5Gu0IIvTA3J+0AHA
         ioEgJGRZoy4LOFFYmolvxHloOeGq6c/EjHKPjGB4xCRRJ0cLpKoO7V+pg3jdGch08Ltk
         1Rsg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0nqOd1s+PTKqC8//bPAghc8PCn6Ldbg7MmRq4a+6nn8=;
        b=CBETEbWqc7fCKnmb/3OocUwRQ6V/oA+Ksy0XYtnZJifkC1JhqN47gnjjEE6FMV8PJ2
         bWKuK/fpEmEDgU3kdfNjDa/0TgnkgJApen0OrrCa9ScRxHlfEIRPhuoLN7CEXv/i5O4S
         cmAzkc3Lo9h8V12F5XARE0hbo7wGf25BJAAC8hKa3ZvYzcu6U4Ap5Wl4bA0oE3s3qJAV
         UhHtaMQIXeQANIlaVEJL0h5RmQc2STkJXqrUJPBnC6bm0CH70AykHX7GjcLTkI8HVUkL
         ifodF0s+Ahnix156dvbJ14UPNxR9dLIC6LMB4crCh1QDAxBagHLXlsgszMxSuKxo02Vq
         5c7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530E0VOu7NUjPaTAPUrBW9L4UP4Pyjt13egBb69a6dB5oUYOptoQ
	u//Ew8brWm/ikp8daYTuNh0=
X-Google-Smtp-Source: ABdhPJwYL6xee/nDqFzCEporsSbdaqsl7/4YdgYqCgNDoW0eHUoNcwllHn/xYu2eebZ+EePj5Lm8cg==
X-Received: by 2002:a17:90a:bb81:: with SMTP id v1mr7516839pjr.123.1615441554895;
        Wed, 10 Mar 2021 21:45:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6902:: with SMTP id j2ls2510347plk.10.gmail; Wed, 10
 Mar 2021 21:45:54 -0800 (PST)
X-Received: by 2002:a17:902:a707:b029:e6:52fd:a14d with SMTP id w7-20020a170902a707b02900e652fda14dmr6693052plq.34.1615441554284;
        Wed, 10 Mar 2021 21:45:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615441554; cv=none;
        d=google.com; s=arc-20160816;
        b=Dz3pe2cLSqSMwev3bQU14YUv3rZUtzHciUFtma+oIMFs630xWimMQbgJGhYaNEYvcc
         IkrI1O2/f4F/XleFrcK2BKKFMPX0EkYUcYga6Mm9Mdxyl8d65nIrlZIB7TJOAJmElG+1
         OmGutFL0kVcjvnuNoLkZDpFWnnpdnfWJz1Jg3OPboxZJ2YtJ/2t2HCycta7hTKQiQIna
         IMaotOMc/2w6lOsgfQ1+w/NjStF2kaPfEvwlALUb7s1FgaD2wMf9qo9YFYP321y1mFob
         7OuzdFYSzkwywjnKC1QiAOIjblRgYsa55K6FDwZUATE3eamnsN+B2NiT2kq3vOKOiuss
         WRGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FRPO5EJGMzlTjItyn9i19FJGjAWl0q1gPtsc+t04CIg=;
        b=ei/vNGY0Md0rmQBWbnufH7cUQdD+3BNTRbHu8zdcmX0hcIran7wGA9K6Z243Rt34q1
         pE1/Yr9CkjOKFmfOjfNMtlZ1qsTUq5PNJ9rTDj2g04YiZmYleyT4pB1eS07AuLYXiVTH
         7lPMaUtvTQhUcQvJNGakV4MDOjvZA9MIPFurmITWhv9jipQumSNIkDEMKJka2Udit+XE
         sD6t0rhQhwFDpEfBPzfUFgzTrMdTZEAqJSN29FEM7pSzmd/z+5OFiVhQ+TCij2FHlxWu
         0g+/eL54aJ20IkSxklZosavSUj3VVgK/QnAVGyapiRCEpUPqonxhrL1aasRslwKXTucw
         jIaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OHIU/hI3";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r2si1406pjd.1.2021.03.10.21.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Mar 2021 21:45:54 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 36DB164E46;
	Thu, 11 Mar 2021 05:45:53 +0000 (UTC)
Date: Wed, 10 Mar 2021 21:45:52 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>,
 "Arnd Bergmann" <arnd@arndb.de>, Andrey Konovalov <andreyknvl@google.com>,
 <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
 <linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
 wsd_upstream <wsd_upstream@mediatek.com>,
 <linux-mediatek@lists.infradead.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
Message-Id: <20210310214552.6dcbcb224c0ba34f8e0a0a54@linux-foundation.org>
In-Reply-To: <1615426365.20483.4.camel@mtksdccf07>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
	<1614772099.26785.3.camel@mtksdccf07>
	<1615426365.20483.4.camel@mtksdccf07>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="OHIU/hI3";
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

On Thu, 11 Mar 2021 09:32:45 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:

> 
> Hi Andrew,
> 
> I see my v4 patch is different in the next tree now. please see below
> information.
> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c
> The different is in lib/Kconfig.kasan.
> https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/diff/lib/Kconfig.kasan?id=ebced5fb0ef969620ecdc4011f600f9e7c229a3c
> 

They look the same to me.  I did have `int' for KASAN_STACK due to a
merging mess, but I changed that to bool quite quickly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210310214552.6dcbcb224c0ba34f8e0a0a54%40linux-foundation.org.
