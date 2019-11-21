Return-Path: <kasan-dev+bncBAABBAMZ3LXAKGQEGV2LVTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc39.google.com (mail-yw1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id A9B951052B4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:09:22 +0100 (CET)
Received: by mail-yw1-xc39.google.com with SMTP id b184sf2031335ywc.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 05:09:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574341761; cv=pass;
        d=google.com; s=arc-20160816;
        b=IfsAuISCFGEYer3XJbWSCWAYbrx0Jz0UJ6dhlUfI+JjwNxoPIipFAc0kCijSCqVgCi
         ZeFEWH8FWsJPta/f29LU4jdfHBSwNpYOUG3WuUHhtfDe1eW2GkjDNWOVw9XuI8snIvPH
         5C25X0wNjeODkT/riI4KFjCRy3D5Ftok0Q+/GTKF2k/WJDX/F1ahocBCDngIEt5JZiQ2
         jY0X62vEdTSXPPb38BkcHn4vPXJD2jygnRFEl76MZScR8Ibx60KiCUY7nRSOUr94DMEB
         8rOcB4wqmqG88EOaLRyKepEXzMxjsW1ZQP8s5KReJeP9rL8u/fiU0AovXhbpzUMl+qbB
         EZvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=XNvsXgP/HFvKurIr+d6LLRwILKvtIAPrxH8yv52wEFw=;
        b=Xgy4kCn1IYmLK6z3LmWkeiExKLMYsFESaR6rIbbVK3N0jqCgMhihhGUQ91fJGvfF7r
         ciZsulNWDIgVZweRwUe/Q4o77R8KmZeC8tfKL+HJhLG6KAxEBmax5nsnut1g+pHsf5hX
         +wMQ//hvKmu9swa0qRWg4nbXb/3zn06eu+mpHQKNqgeXzJad+qGegcGCaqeX0ZFV3ggC
         4az31b5Au9LJ7zYMrswnukKhBhi7Nd24GetZS8ojK2H/F+R7J70jnyhFA1IRb8zqdlXa
         GDqy803Lbso5iwaxqmN+nzMXVSImclyfq5sa1b+L+y6Agi89MrpvPIldt8CEp49ecMHl
         qfCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=K8JOzSEH;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XNvsXgP/HFvKurIr+d6LLRwILKvtIAPrxH8yv52wEFw=;
        b=pyCGdgCCXdsEjCCrr8X1GOGwggYy1epH5Fg8jTLvb1iN9BB7l1DgXePHX/XVoKm0vd
         5Tk+xA0mQnJ/DEBMlXvc+2WWm7k1ZUCHqV7whlYEuYgH6T1SbdQ0vKrTsFNFTJ826cEu
         PbToiXDU1ot7p8PR6K5TeysWttIe0nXT0pWcirOMSZRAAu10YTVgm2w3O24bU6hM9cvn
         IUZ5KP7YfLKEEuIH6JF6yG9rhXPUni7hUqgSFNucDVICVx/ZXaLOA61AKjNJPG/s6zdA
         HnJrRRFhTQqWposdLw9o/il8zX8hzq5raGkQx1pUWYsa9a1dxqVGkAildtNVk6nlmuCG
         rgDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XNvsXgP/HFvKurIr+d6LLRwILKvtIAPrxH8yv52wEFw=;
        b=U/pb54c3jVSjNHHosOELYBEw29/gJm4+ddXl7vgcaXppQW2JUVlaMpImkXiBOjd+5F
         tq0wXFPXSviwCmEOPNpTRx/2Xs5sDvzqULJRQQULUrYJrS9yt1LUHIhIHiIqAFQS2aWv
         3ag3rpTbj/FXE6Pm8jm9VZoW5RecS1klkdHRaKwHlP7BZvsZfTsk5sMNl0nOfhxzUkuR
         8nRTohR73ZROswaS4lG4nvc33ZLDksMNVJmloFPXXNB+o/ADq9OZ6wXhGil6xkf+cPOD
         a8rhwrNUOuK8Ekm4cJ7v5lwZucr7cuBonAFnIxXhM9/dVueCGbiLp1gsZ6l1RLV2UoU8
         +Xcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVOwXAKQl3xm3FuXwXU6m7PgkFTvuYG2ySGR0xRr0VtQ6ULs61A
	dmRdVx2MwLIGjgSFoMiQnbw=
X-Google-Smtp-Source: APXvYqzL9S2yhyvi0n747aRPTMdzQ1Hn5TsoaaQUg2tiLGzaN6+HRPLot3HF18GLndncs6KOP6pduQ==
X-Received: by 2002:a81:b617:: with SMTP id u23mr5190633ywh.295.1574341761511;
        Thu, 21 Nov 2019 05:09:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6c89:: with SMTP id h131ls997959ybc.16.gmail; Thu, 21
 Nov 2019 05:09:21 -0800 (PST)
X-Received: by 2002:a25:258a:: with SMTP id l132mr6146197ybl.227.1574341761062;
        Thu, 21 Nov 2019 05:09:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574341761; cv=none;
        d=google.com; s=arc-20160816;
        b=AtwGkUF5/sLqsOswbPjJSYjzjEVyt7HKxEldUdPYwupvlTHn4pTPazhsH/1Dt7XKut
         CqI6nDTfACLehliZbpESxD0qpcLY26kUOnFBvnXBgzBZY1eEG8G1uG3bwB6B5LsoGjSS
         vfHuoNofFPfg+/xkLFDJ4YynkIjQHado5y2x9fdfpsEXae+IVlcfSxiejF9goZXgpalN
         JoPxrQTcNkHfa5enzlHEZx8WS5X/DYK88U2ZdXfwT2UM295eIC65pxWq1BMBZlzlSHpc
         B0H3yablvi91XyHfNk0X5YZUC4bf7Xl8Ay/svysNNEmjJYe+oEKtOhgLC3r666NwasKr
         0Bhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=GKRpbk2ZaobBcrGmB5jVBprxNIO5Hbu7SfyTwGSrIKk=;
        b=B9HGBP8J/KxeEYqNTqRjVqjxN9i+33qysiKwS09zl7G8WL9taY4heCWKWEz3gPBBoV
         oVKhFRTv8o61vDGujd2Mx3BrPrxwmn4Kr/1msnixLGpdkjt5knOrMOdElrEVNZWX4/wZ
         nU05xjPYa0b3QzI0I4PY/UAde3YTzpXr3BuBkoPh/bMIf5KiTproKQ8lqDR8w+awLZDo
         nfMFuJg1r9HiBtXzq06+xBheArbKhxuKibrK4YOz2weTTsx4BWW/vkgaTJXJUkADl//z
         tsp2iORgVhrtuRnyttUywO65dO7Zd7v8LICNaYCdYeQQZCwCDG0LcN2062pPZUQ5DvY5
         kF2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=K8JOzSEH;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id p187si79897ywe.1.2019.11.21.05.09.19
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Nov 2019 05:09:20 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 68b52b8743034574967e8b319804cedc-20191121
X-UUID: 68b52b8743034574967e8b319804cedc-20191121
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1392207874; Thu, 21 Nov 2019 21:09:14 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 21 Nov 2019 21:09:07 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 21 Nov 2019 21:09:08 +0800
Message-ID: <1574341753.8338.7.camel@mtksdccf07>
Subject: Re: [PATCH v4 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>
Date: Thu, 21 Nov 2019 21:09:13 +0800
In-Reply-To: <217bd537-e6b7-3acc-b6bb-ac9c5d94da89@virtuozzo.com>
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
	 <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
	 <1574341376.8338.4.camel@mtksdccf07>
	 <217bd537-e6b7-3acc-b6bb-ac9c5d94da89@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=K8JOzSEH;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
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

On Thu, 2019-11-21 at 16:03 +0300, Andrey Ryabinin wrote:
> 
> On 11/21/19 4:02 PM, Walter Wu wrote:
> > On Thu, 2019-11-21 at 15:26 +0300, Andrey Ryabinin wrote:
> >>
> >> On 11/12/19 9:53 AM, Walter Wu wrote:
> >>
> >>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >>> index 6814d6d6a023..4bfce0af881f 100644
> >>> --- a/mm/kasan/common.c
> >>> +++ b/mm/kasan/common.c
> >>> @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> >>>  #undef memset
> >>>  void *memset(void *addr, int c, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> >>> +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> >>> +		return NULL;
> >>>  
> >>>  	return __memset(addr, c, len);
> >>>  }
> >>> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> >>>  #undef memmove
> >>>  void *memmove(void *dest, const void *src, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >>> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> >>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> >>> +		return NULL;
> >>>  
> >>>  	return __memmove(dest, src, len);
> >>>  }
> >>> @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
> >>>  #undef memcpy
> >>>  void *memcpy(void *dest, const void *src, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >>> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> >>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> >>> +		return NULL;
> >>>  
> >>
> >> I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
> >> poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
> >> but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.
> >>
> >> So let's keep this code as this, no need to check the result of check_memory_region().
> >>
> >>
> > Ok, we just need to determine whether size is negative number. If yes
> > then KASAN produce report and continue to execute mem*(). right?
> > 
> 
> Yes.

Thanks for your suggestion.
I will send a new v5 patch tomorrow.

Walter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574341753.8338.7.camel%40mtksdccf07.
