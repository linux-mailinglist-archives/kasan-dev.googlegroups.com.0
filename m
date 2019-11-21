Return-Path: <kasan-dev+bncBAABBCEW3LXAKGQE6SVZRMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 90DFE105290
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 14:03:05 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id x187sf1681627oia.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Nov 2019 05:03:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574341384; cv=pass;
        d=google.com; s=arc-20160816;
        b=q4mQ+IWZbk8xD2Foe0qqC1y4JONN9S5hef22lhsR0QhK7WJMskpZ/0cypYAp1MURnD
         uCbdkkViCdBjFlcD/iCpky31is6tnWDuLI6f3CfFHDJ39H8CWuNx7sRhGw7PU6iTQh33
         iCkWJEwDMCB5BLvZmMxy2ruZpAZF1NAA1sXqzTrtgh55DYROWjldht/xFlBaGqvj7+TY
         pZfM/p5dyrye25t9cdI4LTp8mpOuhz76tFYbmEiNVNEHhp0fJdZT2dNegOVCWqK85a48
         ipNhJ22iPoLfYs2nZ2SuFBn3do3H4Z0b0cMrfdWCAly1f2/7nSlB4p8yemRTGHiqleLR
         3yAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Jc30lDv7FjWuuwlCZVNEwL67omuMVFoteAf7wZYFFRk=;
        b=gHYlMb+0OS4szIDQN9QJB6OFDrVHbCj6ddIi+V4NPv4z54L450+ltdxHosf8/zZD7j
         oSLy8NvPFMr7Z4mXeyq7gau0EzVhlL02ND+faAHtdk7x+kCjYfOYCSCqm2rXIyzZMrDA
         brhXYTFc280NsT36b45NtanocV9RBQat4iJsw1LkozyDQxKNRPKTaTl1QnfMa6eQMaA3
         lI1+Nq5tDPCEPuWwJ8rWRHx7E3w7dt3y22SKOtPbknvxpNKKO1zsqcfC+FhsR4CLz2RR
         B9Zvl65an74d9ZDZNmeFpUhmkeXkw5srXmv4IMjz475Dy7bI7HuBGp8vdDn8KXV9/jrT
         XaeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FssLwQtJ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jc30lDv7FjWuuwlCZVNEwL67omuMVFoteAf7wZYFFRk=;
        b=pXfEczkzYdHa92Mo+mcOgH6jLHO7Tvqy9ZnFQpy6NkKVkkeWOpxfhozna0t3qoN19f
         weefRne0fpVTmUWQwx8BfiG7/RNF4k7mOsgyMXTsI3dfrvAScNS/p8tHbQCXrmf32fNR
         jepXIx5+Qr9g3CP/2PtEdfyisLpgb0kXh+mNsrDUUdQN4bozl4FCkyOZObpjGzTHPML7
         kWnEGFSWpgwAeuGCOrytSNyqchwrfN0UHlo98mC7zhi/unIsfU5em5JncbmaNTIIr9QY
         4qU1/q1iufrVOFg5ZpaSPCYlvVh1k0N81VGuFhQMVGbDX67mAiVnn5otmW5+zAyrC9OU
         WSTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jc30lDv7FjWuuwlCZVNEwL67omuMVFoteAf7wZYFFRk=;
        b=AXCmFYr9o1EkbFPA2FFKht9+wtXQYOV4Bgmsh7J/GxQkzEboPx93Iok3QYBJns5KKR
         FALERwGtgVH5iEE0Fa0Mi67XlacHWXnT4BHZ+TfezzWaCVmHjQ8ioZtM5b2GQhkM/W1Y
         NVDloud9EwztC03dUaRCPPpMMsken7g94RYfUi1rmAaLMO7ctXxkxxogOxhigAx+6nMw
         EZ8M0rrtVC3WTTP+TKo8dNAbxueYPsiNZPVneQ1AANeK/mFocbu2fnWlG+AsuHO9/X8S
         dNlrlFWAJgdxIa9z5Zg+EFOC/TldS/uDFqG7XEVMzUnhKFxMe3ehiYhSbGpWhpervIB7
         azDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVq+yc6nbKhzCCgYsZHszf2kAWOjMR49n7PzDvS/KQXs4jaOjOB
	aNA+i8buR3+714y1SMRn5CA=
X-Google-Smtp-Source: APXvYqwJtmvweJRAnMxaXt0NQssrGFU5BzqWnk1dxIi1VPg7PeqZ2ABfyPOO+eJh5Uy88xmsZwrIdQ==
X-Received: by 2002:aca:5f84:: with SMTP id t126mr7747695oib.8.1574341384119;
        Thu, 21 Nov 2019 05:03:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:49a:: with SMTP id z26ls923510oid.1.gmail; Thu, 21
 Nov 2019 05:03:03 -0800 (PST)
X-Received: by 2002:aca:1e02:: with SMTP id m2mr7604913oic.81.1574341383817;
        Thu, 21 Nov 2019 05:03:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574341383; cv=none;
        d=google.com; s=arc-20160816;
        b=TRAaV59Ijk9/jkVLTS7hWu51Yg9RgoBqQnE0t3EqdWUE25soP+xhk4wYfC9f2pi5uF
         asewFtW+lLFy1NsbLODfZx5dfoQcceeLdqi0t50dBjQg/z7Ps6OTQVe7vB3mtzZ4dSaG
         L8j8JhPONIY9PHzk6o7aQcepF3sNagu25qFhfzm5jYPELBPJKI5XM8COFKEof8HpWqU5
         uwmt+nmw9iMBJOtjA7jogjCG84D/aZtWjnQOaU2dmX5WxMsusXNYwE8jnHlnGF9Jhe/Q
         9yCtlMaToL+DRCoHD3MX05gA0Myxanh66tSf9hCGBB8K9aTaDMQuExirl+0cNLNCzw4g
         1/Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=NsE4689yAaWq1T5b/skLebYVU2kKGZUndAF8Pm3G/5k=;
        b=EIrd09Q/zHhskk9HsyC61LZXwZobhEaOgc90dYsUXrBRL8vR4MsNFHDCl+tr7CBxPe
         bXxC6U22N6qP5HcBuAWui9cDlBeLZlaMJwpI89l5CotVj6YFTTgg1mdy78VJ6d4fPXeY
         29DGpI1pJL3LCw1TNLWZYFJTWgomC9FcX09Ya85P94WwYuv4n+YU2cKzpLFXkJKOFcjT
         Yoyk/C9WITdT+/ctxGFdrlXowZHxcMpD+9hdQt7ZcZz15IPOsNpNQJTzHEvnXo+XSA5X
         d0KaTSLFFBT4Bhs0HvQ+GpQB821KSQbs4vKk/maJu0WGDhUbuVWSEUHJ/xOci+wSYoZd
         U7PA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=FssLwQtJ;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id 5si110905otu.2.2019.11.21.05.03.03
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Nov 2019 05:03:03 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 1b33c3166c46481bb7e9762f99332aec-20191121
X-UUID: 1b33c3166c46481bb7e9762f99332aec-20191121
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 302700734; Thu, 21 Nov 2019 21:02:58 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Thu, 21 Nov 2019 21:02:54 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Thu, 21 Nov 2019 21:02:51 +0800
Message-ID: <1574341376.8338.4.camel@mtksdccf07>
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
Date: Thu, 21 Nov 2019 21:02:56 +0800
In-Reply-To: <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
References: <20191112065302.7015-1-walter-zh.wu@mediatek.com>
	 <040479c3-6f96-91c6-1b1a-9f3e947dac06@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=FssLwQtJ;       spf=pass
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

On Thu, 2019-11-21 at 15:26 +0300, Andrey Ryabinin wrote:
> 
> On 11/12/19 9:53 AM, Walter Wu wrote:
> 
> > diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> > index 6814d6d6a023..4bfce0af881f 100644
> > --- a/mm/kasan/common.c
> > +++ b/mm/kasan/common.c
> > @@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
> >  #undef memset
> >  void *memset(void *addr, int c, size_t len)
> >  {
> > -	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
> > +	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
> > +		return NULL;
> >  
> >  	return __memset(addr, c, len);
> >  }
> > @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
> >  #undef memmove
> >  void *memmove(void *dest, const void *src, size_t len)
> >  {
> > -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +		return NULL;
> >  
> >  	return __memmove(dest, src, len);
> >  }
> > @@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
> >  #undef memcpy
> >  void *memcpy(void *dest, const void *src, size_t len)
> >  {
> > -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> > -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> > +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> > +	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
> > +		return NULL;
> >  
> 
> I realized that we are going a wrong direction here. Entirely skipping mem*() operation on any
> poisoned shadow value might only make things worse. Some bugs just don't have any serious consequences,
> but skipping the mem*() ops entirely might introduce such consequences, which wouldn't happen otherwise.
> 
> So let's keep this code as this, no need to check the result of check_memory_region().
> 
> 
Ok, we just need to determine whether size is negative number. If yes
then KASAN produce report and continue to execute mem*(). right?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1574341376.8338.4.camel%40mtksdccf07.
