Return-Path: <kasan-dev+bncBAABBFHIUTXAKGQEFHTT6QQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id DFEE9F719E
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 11:12:37 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id v130sf11131522oib.5
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Nov 2019 02:12:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573467156; cv=pass;
        d=google.com; s=arc-20160816;
        b=E2b2LkbRH5e/8J4XNwiFxJfREhYmaYGeCitmLOgSWwIQnNNRK+5Go7SS63AlXA9n4g
         +7wyXOKJ5DGKyi4VaKxTuBkcMzuwWoHQx/+OiDROJv91ssX6WsO6bCR1XXTcxSuatugP
         5LAiRFLDdyS5OzkmNUEYW+rb2xYDRsQ1Iv43INPj1+FVk1pdJYC1uMmkgKNy9/iPbdIF
         Prd87OuE9lsRbWuK2KWVgJWD11+kHcefohqTGnYEYFrnwOiCMEaSKBk5gXvYB4Jvku6A
         R64PvxVqb/vPOdDxF+BvwaislTl+OpStxrfg18u7bZ9K1B2RLLLtnoKGZ/rAGmlN4VGU
         Bq+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=hVRMTmIEwoteRbNlpi7nbtvpydMqrQHXedJ1AXNyUHs=;
        b=xsRDYBCOmoBvFHPS3hCO6I6aAFSTK4Xol59sWZq0Ro8rdhQbR7qqXbyEsvDbHV3O4T
         owEloC+Xmt4xiE81uWf8hZ/6sWNcTtbFNmc+KNUyNXUAYOU+pfEYsjm9Mk/WzZaIvvW3
         xX9vArVk86sXcUM/ioXMLSnAI8ULAW9HxYatOzvanl6QDHJC0rsArjiit8cko26gXxe0
         PThNS+Qozg/abJrEjEhPIPA3bu0RfQeX8R/CKJ+P0Vl0o/1uU7j2umgIluX8C4SPK4RS
         R2whiSuFGn4po0Rv4RinQn8bGQv1ROFjhh0U7JgimmaTaQ6EvY3sE0KAKebUDtCPevZ6
         xvWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=pTHWaONq;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hVRMTmIEwoteRbNlpi7nbtvpydMqrQHXedJ1AXNyUHs=;
        b=lg6H8nmNBOb+TeoseIX49IGiT7l7Pv+tcB2OxocBP2XRoBSOXTkeswnkQUbaPe967w
         pW25URgABSV5nUWXaWpoKWGZs8q7JdKI6ErZP7rgnSnnDRwH9OdrTGKYjPMQG5+zu21h
         qKRYMU3vKL1wGSPjuIPWxOlLfCnAQiZCqlQEKtdbQ7s3cv+7OaIiHrYvptODrwRG8Ve7
         Jm8kKM4sr90R02NqxVwv+iiTZsfsgyZvLmyGXVkXOJY4bxcLwP8/l+h6tOqIxkSWDkzB
         YcUfDaSKVx2oAzPyjNFr9ywhuThwxL3WWs1Zv3hXtZtXLmCFek/L/7uAU07LOLpfxm//
         E71g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hVRMTmIEwoteRbNlpi7nbtvpydMqrQHXedJ1AXNyUHs=;
        b=lXi3B0szzqoAQyrEGyTXQCufju/0hRD72VI7Xb7WL53n6QbBa+TTH8W5zAzxV35ICo
         FhS4/S45fut/eLwulaWdwwSHqN8yecAe78mOiJzqWLbzY6odEZRT2/asqWk2GgbOCOcr
         MAArPhofGkwtfUxLENfKBQYM62Vr8zd0oFGsYNSOckv+XGcKBahmi3FkuWVjDFaRgfPk
         +vTEaonjqLmXLaty/t3qGH0r43GwNhG/7zSO+M2FAQB25CGru7vQ5fHhpPOYOznn3Bx1
         EwPiRwVdQcN4wIEn5qGQFLldFcTEh3QKjYYmtQLPR1zC3R2FPuMw0glGSc+/NLMbI598
         Npfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVr2BCJd+QDfKXU1Kn8i0H5e9IbyDHxuGJYzmU6cew1CwZjSTd
	SzTBf1VQmT+nWo7EMnw6aQc=
X-Google-Smtp-Source: APXvYqxzkb/xtJMkCblyoLqEh2DdIb4+xbDQrKW8TkQcfTmsoRmhItFqgNahOYTZOOMKTeUTlBRuzA==
X-Received: by 2002:aca:ded4:: with SMTP id v203mr9390226oig.96.1573467156768;
        Mon, 11 Nov 2019 02:12:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:5da:: with SMTP id d26ls2016845oij.4.gmail; Mon, 11
 Nov 2019 02:12:36 -0800 (PST)
X-Received: by 2002:aca:110f:: with SMTP id 15mr20123138oir.47.1573467156494;
        Mon, 11 Nov 2019 02:12:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573467156; cv=none;
        d=google.com; s=arc-20160816;
        b=azQWpwhPDiJXrIppez/KNakT7JV+qQjoHHCnMfIvwGMJeqfJpwNt1Vg+1Od1RdcEWs
         hEWSzaqZC8ga/nvYIm3SfZG4jFptYxg9L9hUnhCskrGO9zPlEarKbs8kRCipTqN6Clk3
         Uuvu5lgL5SO/KZ6AgW97KnNS98eHyE8WPAkGNBxB4xhV89DiHnytnIYcTxR+dWv4ef74
         ++1J+LYMXaGkSRUEVpucVLB0Heh6OVJP6+98zQgOFAngvDUx0Ql0WwJLbgxETDDVmmrn
         /hbNvwsnExATvfZ8PwKLRs6dr/8d7ZEzzJ008XrnmkGXOmjIukTUwjxjBTn/EjdcpMij
         E+hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=toF+FrGCVhoFJVjUfttIEjB8V6geaXrgJXG1BEMe0Ac=;
        b=vb88uB8zbGFbmiUmRhCAqFH4Ua2trKfH9Y8m9nPfM4HRHQ26qlPOlwpC+ry4wR7bZZ
         lFtHitIP5P+b8KOAzKGPa+FIoG6kNBDWBHQWUtk6wDosBkcb/nD5i3pgyUcM/Qej9Doc
         VScODxFkrX2vOFb+JdWn6ANa1bygVAcP3420frjDp/N2AkZ0D+LjASpO6Gp3uomRP8iL
         cah09BW2vkrLuSyVYimwPxxNONgCHHG+d+5XZiwKqvISAi2s6jG4ksrMb39zoB9u6xXV
         P7Yy7RZlljgXJGtIY/ZIHgIXaQnXEWFo/rmZ76Cc6oCYwSkC1C6eOnsEPIphb6SGNzMD
         LBxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=pTHWaONq;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id l5si845133otb.1.2019.11.11.02.12.35
        for <kasan-dev@googlegroups.com>;
        Mon, 11 Nov 2019 02:12:36 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 70df4b08df754a48a14c29be91d7b985-20191111
X-UUID: 70df4b08df754a48a14c29be91d7b985-20191111
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 346899562; Mon, 11 Nov 2019 18:12:31 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 11 Nov 2019 18:12:28 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 11 Nov 2019 18:12:27 +0800
Message-ID: <1573467150.20611.57.camel@mtksdccf07>
Subject: Re: [PATCH v3 1/2] kasan: detect negative size in memory operation
 function
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alexander Potapenko <glider@google.com>, Dmitry Vyukov
	<dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Mon, 11 Nov 2019 18:12:30 +0800
In-Reply-To: <757f0296-7fa0-0e5e-8490-3eca52da41ad@virtuozzo.com>
References: <20191104020519.27988-1-walter-zh.wu@mediatek.com>
	 <34bf9c08-d2f2-a6c6-1dbe-29b1456d8284@virtuozzo.com>
	 <1573456464.20611.45.camel@mtksdccf07>
	 <757f0296-7fa0-0e5e-8490-3eca52da41ad@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=pTHWaONq;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

On Mon, 2019-11-11 at 12:29 +0300, Andrey Ryabinin wrote:
> 
> On 11/11/19 10:14 AM, Walter Wu wrote:
> > On Sat, 2019-11-09 at 01:31 +0300, Andrey Ryabinin wrote:
> >>
> >> On 11/4/19 5:05 AM, Walter Wu wrote:
> >>
> >>>
> >>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >>> index 6814d6d6a023..4ff67e2fd2db 100644
> >>> --- a/mm/kasan/common.c
> >>> +++ b/mm/kasan/common.c
> >>> @@ -99,10 +99,14 @@ bool __kasan_check_write(const volatile void *p, unsigned int size)
> >>>  }
> >>>  EXPORT_SYMBOL(__kasan_check_write);
> >>>  
> >>> +extern bool report_enabled(void);
> >>> +
> >>>  #undef memset
> >>>  void *memset(void *addr, int c, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> >>> +	if (report_enabled() &&
> >>> +	    !check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> >>> +		return NULL;
> >>>  
> >>>  	return __memset(addr, c, len);
> >>>  }
> >>> @@ -110,8 +114,10 @@ void *memset(void *addr, int c, size_t len)
> >>>  #undef memmove
> >>>  void *memmove(void *dest, const void *src, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >>> +	if (report_enabled() &&
> >>> +	   (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> >>> +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_)))
> >>> +		return NULL;
> >>>  
> >>>  	return __memmove(dest, src, len);
> >>>  }
> >>> @@ -119,8 +125,10 @@ void *memmove(void *dest, const void *src, size_t len)
> >>>  #undef memcpy
> >>>  void *memcpy(void *dest, const void *src, size_t len)
> >>>  {
> >>> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> >>> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> >>> +	if (report_enabled() &&
> >>
> >>             report_enabled() checks seems to be useless.
> >>
> > 
> > Hi Andrey,
> > 
> > If it doesn't have report_enable(), then it will have below the error.
> > We think it should be x86 shadow memory is invalid value before KASAN
> > initialized, it will have some misjudgments to do directly return when
> > it detects invalid shadow value in memset()/memcpy()/memmove(). So we
> > add report_enable() to avoid this happening. but we should only use the
> > condition "current->kasan_depth == 0" to determine if KASAN is
> > initialized. And we try it is pass at x86.
> > 
> 
> Ok, I see. It just means that check_memory_region() return incorrect result in early stages of boot.
> So, the right way to deal with this would be making kasan_report() to return bool ("false" if no report and "true" if reported)
> and propagate this return value up to check_memory_region().
> 
This changes in v4.

> 
> >>> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> >>> index 36c645939bc9..52a92c7db697 100644
> >>> --- a/mm/kasan/generic_report.c
> >>> +++ b/mm/kasan/generic_report.c
> >>> @@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
> >>>  
> >>>  const char *get_bug_type(struct kasan_access_info *info)
> >>>  {
> >>> +	/*
> >>> +	 * If access_size is negative numbers, then it has three reasons
> >>> +	 * to be defined as heap-out-of-bounds bug type.
> >>> +	 * 1) Casting negative numbers to size_t would indeed turn up as
> >>> +	 *    a large size_t and its value will be larger than ULONG_MAX/2,
> >>> +	 *    so that this can qualify as out-of-bounds.
> >>> +	 * 2) If KASAN has new bug type and user-space passes negative size,
> >>> +	 *    then there are duplicate reports. So don't produce new bug type
> >>> +	 *    in order to prevent duplicate reports by some systems
> >>> +	 *    (e.g. syzbot) to report the same bug twice.
> >>> +	 * 3) When size is negative numbers, it may be passed from user-space.
> >>> +	 *    So we always print heap-out-of-bounds in order to prevent that
> >>> +	 *    kernel-space and user-space have the same bug but have duplicate
> >>> +	 *    reports.
> >>> +	 */
> >>  
> >> Completely fail to understand 2) and 3). 2) talks something about *NOT* producing new bug
> >> type, but at the same time you code actually does that.
> >> 3) says something about user-space which have nothing to do with kasan.
> >>
> > about 2)
> > We originally think the heap-out-of-bounds is similar to
> > heap-buffer-overflow, maybe we should change the bug type to
> > heap-buffer-overflow.
> 
> There is no "heap-buffer-overflow".
> 
If I remember correctly, "heap-buffer-overflow" is one of existing bug
type in user-space? Or you want to expect to see an existing bug type in
kernel space?

> > 
> > about 3)
> > Our idea is just to always print "heap-out-of-bounds" and don't
> > differentiate if the size come from user-space or not.
> 
> Still doesn't make sence to me. KASAN doesn't differentiate if the size coming from user-space
> or not. It simply doesn't have any way of knowing from where is the size coming from.

Yes, it don't know where is coming from. so we originally always print
the existing bug type to indicate negative size, or we can remove 3)?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1573467150.20611.57.camel%40mtksdccf07.
