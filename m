Return-Path: <kasan-dev+bncBCT4XGV33UIBBKHEZWBQMGQEDIPTYCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4686B35B71A
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Apr 2021 00:03:22 +0200 (CEST)
Received: by mail-oi1-x23b.google.com with SMTP id l197-20020acad4ce0000b02901593d7ecdd7sf2096272oig.19
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Apr 2021 15:03:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618178601; cv=pass;
        d=google.com; s=arc-20160816;
        b=SOddDU0XV00zN+P5b0Tgsbvxh3p6s+HFN6n2J/7GYxErs4h8t3W3vFDrXssX+FT4Uj
         g5k+ZyXxm/dtoPrieWus34Q5jurUcsrTmqOYAi0/UU95ncMQ2mDRwJd2usS+VX6Bqq/S
         LjEOX9rfczJq93NTDOD3Ig7FXMEpnIQVVy23n57DaMCpC1njxYxtdfGBp0379/95kPQ9
         YADlbxenGZPM1UOBKipnApK4oOV2aZVYRE2/vIW13N0BCxBqRrzaa47KOSMR4bHinH1z
         eafd+2XXes6qU0TVLk60rpLNkzMnktcdtTLsOSAgSvJT2Jwct2MeTJo/Q9/+z8yPjsVY
         wXKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=GSOI36x0l9nPNlWeLozpJzOOWubiWBOB9MwElh4bUro=;
        b=nKd6OkvF/5AWX1/KC4yWpvtwNVytQKKbeGXB+mg2bv1ok2OZkfdj6WjuFfR3DDm8gB
         XDhCqfTeCGKd7mxVO4g8Lse2esxn76RJNgNeYapziJCSXbfQ3ECXLm0QC6sBt06PzhZx
         PKPcJNztB13HkPjsN4QW70VVARch3tAvbxbLAZwQlayX9dvVkjMMknToRLpKaQiEQkKy
         OtCYI0EXiIE/XJ5ecdsUXtGUnlILet/CKPuiKA5dsS1vRYIGIGTmJmKEDzpdCOSIvV4q
         BXLVhpngsl4Kqo6fdPuD0K8LdLlBOtreD8E4Vkk+MNcsQMA+T2COss5eSha0SITg/5H9
         cNbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ASNK5lYW;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GSOI36x0l9nPNlWeLozpJzOOWubiWBOB9MwElh4bUro=;
        b=WASkbMPPoixYaUb21bpR88IPDRvhDmvJBmJ8+m8DclsZZew1hKKitKOJilV303r4QB
         IIjDJQ5F6Jav2/6/GYOp9hNn/QEotjG8RpNGomCxgf8JTvlrKl6e1t7TgqrXyPuaiDJE
         R140CVKd4KkJjmXTIoTS6l3hSoonkEpEmu0Smmd5leqmkSRxbVG26QqpM/e55JuWIapw
         8suFD0P7ZYv2w3FXZ97D8+67boYNVJVXcD9eD1OhS71Sux3j/cORXOLm6sEVNcASaBr6
         rNisTUTa5H1oEyIMjKz7zIjFypQVlC8R3cf6K8F6iaXYbJijRSsQRARWjEksCECgbkhQ
         bZGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GSOI36x0l9nPNlWeLozpJzOOWubiWBOB9MwElh4bUro=;
        b=AXFto2ldZi5iGGu/T59g+CmfhfLoHcjI/rEkZYlEXQaHzy7tg4xDxG6d5LuKXymf7x
         Vi1J+NuSdMAMJ/UpEJsDsJNtoYmqcS3NC7UObPun+7PkippWgCVjCqptYYqiPdMOfSqI
         eTgyqEcB1QRXvwu/CxrrecZG54nYhGgiiRxPONlUYsO+3PNc5w/pYqISHhzGrvM+lj32
         iwHZ81mx0GC5LSDj0ZICCILlfr5ZqJIJK7K2TXPNfIpWBYK0IXRICCKaX3zRZMCZQuI/
         v8zdR2OvYgwhQLr0QvynM9j+YtFbnP8x/bNKundMWOoav2MYvfJDWKizXsLwxY3uVhAx
         WsVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335trs1hpAC6jeYGuCGbv2TiL9WdX1sSjVPHfuyeMaDmwwzGymp
	aiP9vvR7OCE0j0Zz1qxiNaM=
X-Google-Smtp-Source: ABdhPJxwjHcbetpBhgSgp3uJhUay8KVq0wbeAsntR2t3C586SJDSLSxqfycquvjJR2dTedl2Z/TBow==
X-Received: by 2002:aca:f18:: with SMTP id 24mr952043oip.76.1618178600969;
        Sun, 11 Apr 2021 15:03:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:480d:: with SMTP id v13ls1389849oia.5.gmail; Sun, 11 Apr
 2021 15:03:20 -0700 (PDT)
X-Received: by 2002:aca:d941:: with SMTP id q62mr17468675oig.119.1618178600460;
        Sun, 11 Apr 2021 15:03:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618178600; cv=none;
        d=google.com; s=arc-20160816;
        b=qV+/1GPf4D0RyoB8l8mKTgyOOUZkTy8fiS2npMIsZN7V/ILwlCZhm29eEpREI1biJr
         cgOibqtob6eafoF4XN5x361AMlcY+j8rioHkv+8RZlqLImtkrapsgKGB4A/7qbXXa3HG
         I88k+zGw83ibYUylErEfcYolvG++v6l30e16gKap7Npn5c/ynq/DkSDLs2DqVoEC9U+b
         LmwBbAtBVVGJmX5dEvM1SoUZS5LNna3sAokiJsEgEzZVm+IwfnfgmRUXpnmYv4MZSzIO
         odWvVo+xSyo6Twyzo76ERLJ92Uz7DQ570MAE41OirNqEiqD/+oVYzaGsODWqmcj1tPTC
         dXZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=pKgbfkgJ+Io7T9BvlIxsRcKSeSgsnh/PrgYOrtYRPyE=;
        b=x6JOqxwFgvui6RT1WofCq+6lF3vRjrNgmMjx4PKN55x40UzihiuxZfbewDSAYlzxfX
         JhRwL8nXFPhqb2Hx9nmwKsIUaffnEW2b0GoUgJVwkMFS+RtwlLpFfuyWrNsLCS3wYLyI
         Prj+t6YTibr0A59dJRbOKBZj1EnA58Uh5bwmbk+B/ukY1r7Jlvc6AFnxOmIOpqD3qfLN
         YCERZR6HSkxUQAhKuXc+2dNj4bSwb1m8z7dxNiqXUIUGycimbJpdrL2rKjJl6T/VmAi3
         UqC9zq3ASiWYxRDvq+SoGH3cplhLcdZVpNIln/Ie5HCUd7sbLbo2ch6KlUvuR89ELsZU
         2WkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ASNK5lYW;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 6si477335ooy.1.2021.04.11.15.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Apr 2021 15:03:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id CE6AD610CB;
	Sun, 11 Apr 2021 22:03:18 +0000 (UTC)
Date: Sun, 11 Apr 2021 15:03:16 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Nathan Chancellor <natechancellor@gmail.com>,
 Arnd Bergmann <arnd@arndb.de>, kasan-dev <kasan-dev@googlegroups.com>,
 Linux Memory Management List <linux-mm@kvack.org>, LKML
 <linux-kernel@vger.kernel.org>, Linux ARM
 <linux-arm-kernel@lists.infradead.org>, wsd_upstream
 <wsd_upstream@mediatek.com>, "moderated list:ARM/Mediatek SoC..."
 <linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH v4] kasan: remove redundant config option
Message-Id: <20210411150316.d60aa0b5174adf2370538809@linux-foundation.org>
In-Reply-To: <20210411105332.GA23778@arm.com>
References: <20210226012531.29231-1-walter-zh.wu@mediatek.com>
	<CAAeHK+zyv1=kXtKAynnJN-77dwmPG4TXpJOLv_3W0nxXe5NjXA@mail.gmail.com>
	<20210330223637.f3c73a78c64587e615d26766@linux-foundation.org>
	<20210411105332.GA23778@arm.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.32; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ASNK5lYW;
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

On Sun, 11 Apr 2021 11:53:33 +0100 Catalin Marinas <catalin.marinas@arm.com> wrote:

> Hi Andrew,
> 
> On Tue, Mar 30, 2021 at 10:36:37PM -0700, Andrew Morton wrote:
> > On Mon, 29 Mar 2021 16:54:26 +0200 Andrey Konovalov <andreyknvl@google.com> wrote:
> > > Looks like my patch "kasan: fix KASAN_STACK dependency for HW_TAGS"
> > > that was merged into 5.12-rc causes a build time warning:
> > > 
> > > include/linux/kasan.h:333:30: warning: 'CONFIG_KASAN_STACK' is not
> > > defined, evaluates to 0 [-Wundef]
> > > #if defined(CONFIG_KASAN) && CONFIG_KASAN_STACK
> > > 
> > > The fix for it would either be reverting the patch (which would leave
> > > the initial issue unfixed) or applying this "kasan: remove redundant
> > > config option" patch.
> > > 
> > > Would it be possible to send this patch (with the fix-up you have in
> > > mm) for the next 5.12-rc?
> > > 
> > > Here are the required tags:
> > > 
> > > Fixes: d9b571c885a8 ("kasan: fix KASAN_STACK dependency for HW_TAGS")
> > > Cc: stable@vger.kernel.org
> > 
> > Got it, thanks.  I updated the changelog to mention the warning fix and
> > moved these ahead for a -rc merge.
> 
> Is there a chance this patch makes it into 5.12? I still get the warning
> with the latest Linus' tree (v5.12-rc6-408-g52e44129fba5) when enabling
> KASAN_HW_TAGS.

Trying.   We're still awaiting a tested fix for
https://lkml.kernel.org/r/CA+fCnZf1ABrQg0dsxtoZa9zM1BSbLYq_Xbu+xi9cv8WAZxdC2g@mail.gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210411150316.d60aa0b5174adf2370538809%40linux-foundation.org.
