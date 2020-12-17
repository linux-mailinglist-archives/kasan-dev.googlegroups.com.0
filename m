Return-Path: <kasan-dev+bncBAABBZ7F5T7AKGQEIGFHGEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B8C892DCF78
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:28:57 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id 68sf4116609pfx.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:28:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608200936; cv=pass;
        d=google.com; s=arc-20160816;
        b=bGq3j92/I0oyNMfmYgD7/Ea3TDRoF7fqrdF0O4lEovXHqwOCDH0xXHqkPRnQuc+qyw
         VbJoZUzRdXpFCVlptMXN5IcQmvCnjA/JIZsR8K9q+V85nkPm3IR74ze5qMzoNgx87ixx
         yUbMDOungB+CG7cki6qv7mt87yjvy+zTAXqzQRu9Ekv4xK2zfBveO5KlDFlkyf22QEET
         3X4a2LIQ6TBYqLwi5FVlHm9543flFoaEv9OtmnAAxYcAZpY99q3FlGeAsM/Z1fXBeHCC
         hOoOAEXpOt7kE70BgmM91kXylYhebN5MtY4fOL/Bif52S5NZCM4xGBqJIolDn9BTsV2B
         3T3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=LBcV5SjII9RvaJcHW3ZeHIrrPwnvycp/DGY4Ne82tNQ=;
        b=yzk5g4dzGAhxLLIepBUPyuub+XDugXe2galA9PlJKLaiZFmzY2YhQMEu9pAPu4slsp
         FOLQz26fLib5/96EAI4G8gT3aLnLSD4x7fQnTmlZFS900XPNb+7L4HtBY6ExXMjr5Uc5
         /72diR1BNIJEOpY4nbaWUkgx6ipfPTIjmG+O7lF1RIVedIh2Q2BNkoebTFHZmYJmvz3v
         VwSZktGZRTyp6YNzWokCWoI0N5bn7ZSyxU83zOkZ1X5/944KNCr9sJO5NeVhJbYs/Orx
         J5QR45rr+afqUuuH5uPq0yCQmDlsvfos7NWHW5EZXC06OS2Y+WOjjuzrCJ6sIf21kPlK
         EKSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Ppqa+J3v;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LBcV5SjII9RvaJcHW3ZeHIrrPwnvycp/DGY4Ne82tNQ=;
        b=c/CGTrOlWhezQR/GcCc17IZ9WBY7prY83ldD0TkN6KcQfjk+4cjcI0JdtSh8DQqgrQ
         Hoyzcp0NHzAOaj59qNOuM1XqFIk5g/cSya6dz98SOp+YqgZDgqzoMuzFX1TGcZTa4duJ
         bLygY/CDzhuC13ExwzAcP/DaTtITj0nqHvpeoV98TlkW9IYDNtIM+Si2OUvoJqlGwIr+
         9e0V2eQKFYhgaCjuaZCMlma6dZJkx84toZUSxtgIMMaLJrjijigN+HgjThOri3UxGJPe
         f2hvcimV7fJnj/XXtW/Ni3n9lhC3OTFvjAoeqf94eJLhIlL7iGpsV4pE29DQgAb8CTK8
         4mtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LBcV5SjII9RvaJcHW3ZeHIrrPwnvycp/DGY4Ne82tNQ=;
        b=anrEU7gh4gkHUCyv1eQQMs2gOq7plTPtHLW88wW0jcR4WbJz610Egd4DeT8fiBAoP5
         HNO2eQnlkz9Kj2xIQxfjdWzU7PRvQdcyYmSOJgUnjLSmM0/Y+Q9hBMMtTFegq6Jniyqc
         RbrO8ZxqUXs+NNi/tNgsRxCXBS79BFNbivK+j6jIUwSc+uYZFXZYkcJRBQWaY5Jb955d
         cjK6ycTSxCdR9sdKHvdQRdkUxUc6NiXRweXgLu+phxLLgNgRt0gPeY/I7J7pTJpiz09L
         EdmxPhSDLRz5vjDuo/4b2LDOwsyG1O+v8K6pS8Dv+krXT/EPFuJXwKVNjFkL+L68M11W
         2zHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336bfHweju6Q08kUH3r8yg9EROdCY1cIgCDGl1MtF+QdspcK3iq
	JaerZh/sJ4uCnXBqT/ooZQ8=
X-Google-Smtp-Source: ABdhPJyjIIsFzuPRHZ+ThSUMZnZG6Dy+edPOx/L3gwd1RUPSpHw2WaU/3j4CJFXqxQVKtAvxV13JzQ==
X-Received: by 2002:a17:90a:4892:: with SMTP id b18mr7318915pjh.64.1608200936086;
        Thu, 17 Dec 2020 02:28:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:52d1:: with SMTP id g200ls10467239pfb.8.gmail; Thu, 17
 Dec 2020 02:28:55 -0800 (PST)
X-Received: by 2002:a63:1959:: with SMTP id 25mr37437578pgz.201.1608200935622;
        Thu, 17 Dec 2020 02:28:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608200935; cv=none;
        d=google.com; s=arc-20160816;
        b=T6ENR8chtV9RxMaRic2T7j9LpyK9EVkTBEc/GJj3/U5TZ8gf+FiUYhr7UOdThYdTeC
         qvp22ILKGh+ksgdMO2sTvSQHaV4aO7knhJpIXlTsOakdC33pRToSAxccXQm3n3BKJ5Hy
         EpRv66MPKfh5nKy0bv387WMJVm7U9AXU2pbgAdQtJFexAD4LBbC+owUIgMTSBls5MvNS
         J61QtG2h872mRTqFH33mc2xggrSa8PftRGadIyADCWYoCBvadRmhhh7UVWVXhbjOoesc
         bGqMlBYHexv1VJEEeAP6gHIYjFWT9dkPwJ0t1HN96qTiDNsmgqN4I98gTAd4NVMe9zoN
         1UOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=NJ+Woh3w6z3vlb9GDrGYWFJxOWvffKrwn6YuBZHwOtc=;
        b=fwazr6KYCOQNJKSguFp67BJp6TISHozlfG7Ms4xrM9K7DIrbYTvPGSsl5ndt+hhZkK
         PYI7KiL8XjnkoGCc+BuXqnGOxGOwvZ4jnBGQM2xYQjiIL4qfjOpyGDCWQOIH801+5jzk
         +BDDV+ruCN66wcU7c8ruf0wAXOAbFGZRgdMQprOTyC+BtN1Iazve6XVSrkGapQUo1B16
         dpg/cBXrr5UrS306dIywAq7/VfzHS7Tfgr1yM+E5K/W+14OG33cvQaR+kwTc/EhGv0WG
         tj+aRrkF57ke31uVMs9rFNty4MqPHvD4EkeoLOZkZtQe/NKj2nGEJCLlP6EmzmIcv3nG
         NhUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=Ppqa+J3v;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id q15si372891pfs.1.2020.12.17.02.28.55
        for <kasan-dev@googlegroups.com>;
        Thu, 17 Dec 2020 02:28:55 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 93d1136e26624109865faab7044a0562-20201217
X-UUID: 93d1136e26624109865faab7044a0562-20201217
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1630589223; Thu, 17 Dec 2020 18:28:51 +0800
Received: from mtkcas10.mediatek.inc (172.21.101.39) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Thu, 17 Dec 2020 18:28:47 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas10.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Thu, 17 Dec 2020 18:28:47 +0800
Message-ID: <1608200928.31376.37.camel@mtksdccf07>
Subject: Re: [PATCH 1/1] kasan: fix memory leak of kasan quarantine
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	<wsd_upstream@mediatek.com>, <stable@vger.kernel.org>
Date: Thu, 17 Dec 2020 18:28:48 +0800
In-Reply-To: <1608031683-24967-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
References: <1608031683-24967-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
	 <1608031683-24967-2-git-send-email-Kuan-Ying.Lee@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 2752E72A10EB865FFDCC2B6C40094E72E1BF4CF53284D1973037E26C5DE696AE2000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=Ppqa+J3v;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Tue, 2020-12-15 at 19:28 +0800, Kuan-Ying Lee wrote:
> When cpu is going offline, set q->offline as true
> and interrupt happened. The interrupt may call the
> quarantine_put. But quarantine_put do not free the
> the object. The object will cause memory leak.
> 
> Add qlink_free() to free the object.
> 
> Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Matthias Brugger <matthias.bgg@gmail.com>
> Cc: <stable@vger.kernel.org>    [5.10-]
> ---
>  mm/kasan/quarantine.c | 1 +
>  1 file changed, 1 insertion(+)
> 
> diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
> index 0e3f8494628f..cac7c617df72 100644
> --- a/mm/kasan/quarantine.c
> +++ b/mm/kasan/quarantine.c
> @@ -191,6 +191,7 @@ void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache)
>  
>  	q = this_cpu_ptr(&cpu_quarantine);
>  	if (q->offline) {
> +		qlink_free(&info->quarantine_link, cache);
>  		local_irq_restore(flags);
>  		return;
>  	}

Sorry.

Please ignore this patch.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1608200928.31376.37.camel%40mtksdccf07.
