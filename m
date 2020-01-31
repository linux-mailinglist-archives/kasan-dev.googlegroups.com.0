Return-Path: <kasan-dev+bncBCT4XGV33UIBB343Z3YQKGQEBBW7IYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 4791914E6FB
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jan 2020 03:16:16 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id d22sf4261261ild.3
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jan 2020 18:16:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580436975; cv=pass;
        d=google.com; s=arc-20160816;
        b=kv5B9nwX4fXb2zzXDj7uddlj5XZ6LnzWEDoxAlUinTkEh7oKgX6/QFxEtSg04cIXXF
         hfBMbakh4WYM9ndomIoSFLCjjE6eAipZ8rqGBCQFrwGiImc4fSQSQjOcPvrB7PCaUAMz
         2wEOEXLF8ggdTs+hRW3CgBtFqozejoyoEllhoZ35Psb6mahpoFRP0RCsKDA6DscNXazA
         bhAr1oOKCU0ElEsPwqruaLcDyTMTriNA1jtmnBXLRbKf2+nzrjh/uquWUbQKiLVDu9zr
         7hypn4O3q/V8Zjcvhvgrzg+5O95MFTOMfLfcgrDdSm1hq7kHc4l77ZSANdqf9fg2ymvH
         2KHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=O93XXQF7eSFRmWkMqZxZUU5ZGxEM31N2i9miqGU5PpM=;
        b=n1XEqYLaqLbIgRCWjRpX5AzNY++XjRCxlnSL7l7XYDYoCGOHOcUZY2NOe9jjoSiBIL
         g8kB9m+ReInpl5MNRasZl5ZS1qfL5V6a/6erRz60hYQQ1rfr8z8cdmUcZYKTcuKJN+Zo
         fnskgeckhMlpVe9VAUOjkPv20Al1LfM5F/k7aKBEAyYcp6/oBOJhkdzubmCsnoGnWlJT
         +gQzXZvCgSI/NFjLoR+RAK0DsvbaeZnVcsJe8W1rDxK2+yFFxzz832T5JRF1qKZ1a/Om
         R4+UlX8Cnha1CndNWSZJWBD2hz4VRf0zvpv1AZt1UY1D0O37Uo4Rkg+v7S2j15+BTAZT
         hZzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=naQx0E8T;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O93XXQF7eSFRmWkMqZxZUU5ZGxEM31N2i9miqGU5PpM=;
        b=FtXaTbzCnasBQ+OKcDbsoquIUjNJ6FxuGWRCPewVmLRhkqy5JoaM7AqjKW4QAIrHcO
         f6WBlOx1dozgS+WHvvYY4jqb77kXkHwJt/1LkwmxSCe+G5omhy1W2+vC9O9m37JZmu4e
         oju8ZDWcNfpBwYYElcHkLbH1HTpebrPR57ke80qGVjFug4HL35uPDTdXb2cgJFVZbVwv
         4RpiPBESCqbFKapyzoTAyImdhB6D85mtpix0O5BkL0FzIMZNkFEY42VLxoNZXtB9OtFP
         fSA8uPLCaOI5i71sTQhNVEJVWhthHOUJqnGxmk66MNsmC5qfyJ4hUKqCFNfNbQNgktzk
         20dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=O93XXQF7eSFRmWkMqZxZUU5ZGxEM31N2i9miqGU5PpM=;
        b=t0/xYS3Ln3eOVpZqzYRiaMLFuU7FUUibvUS4ru/nmh18mWRDORy+qvVwaApKeUjB4i
         Ti8MGFtbUeaCmbs5COpxJOWz4qeHK/cDdU7wtfzpiVvic9XolMEDXcird87jL0zADVXY
         H3uuq3VqeDq9t0/7qycWwUF2dMO7re2pnK3xk8L3fNRR/r/tUNZ33gdkdca+ybQADzh1
         /+QftzpOXJeJPNwP6Icw+I0TK6GVtWJUZrDaMDb8NQhfnfIV2c5f1cOh0l3i8WYTa52r
         jCfVxyXhX07drgkd8LYgvgT3HhxISrS7kaJXSoZqzhbQceOtRL3cBpfwkuH2WIoXIBQy
         fYhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVVt6Lxf3cB0Ok9VejAtezPIKvP5UnJQu+JK9oKLuO7kpCZ6BZw
	fXm1mCgmY7e/omri+9VK1sI=
X-Google-Smtp-Source: APXvYqwpSiKSjMFmN1bDlk7pzm0bW6ekkA0unGv+6CC29gJAfMJvtP59rFvIlVRF4zGPJxc3vBcL2A==
X-Received: by 2002:a92:d98e:: with SMTP id r14mr6783244iln.15.1580436975181;
        Thu, 30 Jan 2020 18:16:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:8c10:: with SMTP id o16ls1083566ild.6.gmail; Thu, 30 Jan
 2020 18:16:14 -0800 (PST)
X-Received: by 2002:a92:aa4c:: with SMTP id j73mr7040245ili.305.1580436974816;
        Thu, 30 Jan 2020 18:16:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580436974; cv=none;
        d=google.com; s=arc-20160816;
        b=rI8i0z6+UIahEC1c3yzyFsD49dxBH6qFd8Y6NnMcqUDHWlCt2GmnQpgUsZwvDNvEAW
         fcOrwEHP1tRV3mH7AZTemqCY75FaWPmzdTaIOdfD+cMUEPAERHA5IE+P1bPma4OrN/uM
         hy5mNhqkn+7lfixPbTmoBCCCTvMBTvNIK04W+QSjDm5AyfrhmoHsRfssRlLR/Pk2nI2C
         3YWrb1IAfjknTFldw86tRZXYuEH2/WX/A5+AEJsXdg1SS2E3dAh/3dTxiLBrhW13mVP2
         UzN4bszTQFH2sqvbZf89zworFv0CThdGb19jlEu4yjUFLmAUK4fRfSsKALWlFau8+mVt
         ylGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=9wRTR9/NFSAJy1EBQO2ut4uhCb3EUB09ghHk4yTUVNY=;
        b=d0Ccw3nD03PvMPcUyiYCP+tvAI6g5pcUDFWDGky0auEP3DWVeBARH7nvAyqmeg0yEF
         /lTByEil+CzlDjiRC/YYcjAZOnhDFgnUkCyo4TclWv1mMwsQTyApOnl28SkOyIBpE8wz
         Bb0HjAmwf7+S46t8exLsMAaGAMHB2uO4sS1Ibf7GwPKMNV2Z1FU8hR8RNEDpTKYwuqml
         XsI/TSD6dojEDLV8wSmwRdoZVhz9igjWgvtXRtvhVLpj5+7qhKc/IWTGg8PDHEZHEZ/4
         cjmp7PIWmkr0IOT94cCtfXz4/iBbtNBzydKAOomCuct2Xuyx9w4XtG7N0O3uef0CoXiv
         CmUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=naQx0E8T;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si339826ioi.1.2020.01.30.18.16.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Jan 2020 18:16:14 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost.localdomain (c-73-231-172-41.hsd1.ca.comcast.net [73.231.172.41])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A3E66206F0;
	Fri, 31 Jan 2020 02:16:13 +0000 (UTC)
Date: Thu, 30 Jan 2020 18:16:13 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Matthias
 Brugger <matthias.bgg@gmail.com>, "kasan-dev@googlegroups.com"
 <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>, wsd_upstream
 <wsd_upstream@mediatek.com>, "linux-mediatek@lists.infradead.org"
 <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH v4 2/2] kasan: add test for invalid size in memmove
Message-Id: <20200130181613.1bfb8df8e73a280512cab8ef@linux-foundation.org>
In-Reply-To: <1580355838.11126.5.camel@mtksdccf07>
References: <20191112065313.7060-1-walter-zh.wu@mediatek.com>
	<619b898f-f9c2-1185-5ea7-b9bf21924942@virtuozzo.com>
	<1580355838.11126.5.camel@mtksdccf07>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=naQx0E8T;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 30 Jan 2020 11:43:58 +0800 Walter Wu <walter-zh.wu@mediatek.com> wrote:

> On Fri, 2019-11-22 at 06:21 +0800, Andrey Ryabinin wrote:
> > 
> > On 11/12/19 9:53 AM, Walter Wu wrote:
> > > Test negative size in memmove in order to verify whether it correctly
> > > get KASAN report.
> > > 
> > > Casting negative numbers to size_t would indeed turn up as a large
> > > size_t, so it will have out-of-bounds bug and be detected by KASAN.
> > > 
> > > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > 
> > Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
> 
> Hi Andrey, Dmitry, Andrew,
> 
> Would you tell me why this patch-sets don't merge into linux-next tree?
> We lost something?
> 

In response to [1/2] Andrey said "So let's keep this code as this" and
you said "I will send a new v5 patch tomorrow".  So we're awaiting a v5
patchset?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200130181613.1bfb8df8e73a280512cab8ef%40linux-foundation.org.
