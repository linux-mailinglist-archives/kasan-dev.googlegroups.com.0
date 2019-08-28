Return-Path: <kasan-dev+bncBAABBWO7S7VQKGQE4LTM6VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id DC6679F896
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Aug 2019 05:07:07 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id g76sf570346otg.14
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2019 20:07:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566961626; cv=pass;
        d=google.com; s=arc-20160816;
        b=cpVVNWePjTvSSct/HWg6eugJUFh3DlWluHk7haq0iJWpyofAMA/gF7jcX2RBvGypqc
         6KrFrPC0KYmqHdLMcR0Qf8LWmtw/TYexoI0/95OTBMBThdqW7dOqKHQ9g0ApUEkZMd3D
         nizC+PGEQPpBZWfIU+ciwehtEJDPDHsLcyRek8PJe7KQCUqb0WNNdOuU00yjfLv6o8JI
         gU+klgOXryyQBt0dNiBtXQI5IxDhkfETzr9YQ4lnDcwMny5OrcZbjAuAekLWY/atSkQc
         WXW1mLuESKmcLZcc1ABk+zRJNCueZq8+VhXfaWy0pQbs1mg9LPVfEAdH82R9jNep0Hjy
         IrCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=1Em1TrYsaCLPUaQn0O7x4VTAAbyx6y9AYmqexqCXIWU=;
        b=SvkbZ3OPbDZL9s6c9YC6pNEEdqoHA6/yPVae5d21H3ySKjUseCyA6im3WHKI2FZTNG
         scHfRcurr5FpHhcC5m+kSZ4035amQivheMhJn10+fcKhybckQphMRBfkRoFq+sCv2m4z
         2kfojvKOjN7wszPGkTsFpfx1Cgqa13xvALvs5ktAUn6ttrCjQcz3nNK9anlPB+fA2VNl
         Gs57Qw4fOAw9k47XnFTt39KUpto+DvD7RWij7QOr/Azd6x0UxX+sJY19ElIMeXoA8I+H
         eGAPo9Fae89wiP/AVkEQawuHSaeUiRO5qzyaXzAu0gZX7in7k3qZ4ueQSZ44K/fj40oT
         Bn6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Em1TrYsaCLPUaQn0O7x4VTAAbyx6y9AYmqexqCXIWU=;
        b=XLIh8CAXinP7snEuBLs38IGf76mXAXjzIeyYvBX8/VUtRPeg2M9xNFuspKuUVm0HHu
         P5ScLyJP59VN0KkGtICkI61DOJpBYiv69xa2oniZ70/Iv7cEEhnBlqLNIbkPUWzKNjkJ
         FRkYddnrkbfunN/9iuuWuNiKDUcxhH31ERL6Rey3Xwg5jtHl1CQEo/hhulauh9JhazWx
         EYMOHDMNuA/iwcqgzlguXgFQ995PUwVh6o/oL5v5RZrbPq8OlbVTaTD6ceEET4iF3ORN
         8Eia/LoUPK9NDOdKd51ZmW9Bscy3Y/XR1zBpsBdUszbH1AzmuUkkR4fzrzf0RoKwCzGq
         hG4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1Em1TrYsaCLPUaQn0O7x4VTAAbyx6y9AYmqexqCXIWU=;
        b=Vu7HwYFHBlJ+EH6zupmxFcHrVXp5eJZ94bhFbN2MsYLUSbQH5/BjsN5PrrEvLVSiV5
         FkBcpYPSlzMBUwDQhcY3ho0SF++ygbLC/JIeDzQO8Z7d5Xsg0Lt3E8Y6cKtzYvTr9bHq
         WRt5oYz6CbpqdAB36MA6C8cQhMHyz6MPWib8bYoz4M+yD5cyK832Ob3f2RZ3gd9pvgTH
         zwZFk9WNGr1Uaz5HUQz4RZIDeq2XilbbNxKUsqfW7ZUVMinXR7eFLP7t+5c42/oaGTsN
         mHurJ3m4KOMrgUWmByVDXvyCdSwlg05kHpyk2lf6nqfbpnnMkQOMoOOMLrfgnvqnwa5y
         019Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWvRDxI9thsY44qPz80sWoLjtyAZnvk7GINKBqHHk/28s41znCP
	0t7APzbTXF0CdciU1rjZCcA=
X-Google-Smtp-Source: APXvYqxaZpEtB9EpWGC2KVjjUo660UubduuPXnkXUQoVqTKfujjwX+bmfWm4Qvxp9338lmLuHjfDGQ==
X-Received: by 2002:a05:6808:b3a:: with SMTP id t26mr1296863oij.67.1566961626215;
        Tue, 27 Aug 2019 20:07:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:482:: with SMTP id 2ls133867otm.14.gmail; Tue, 27 Aug
 2019 20:07:05 -0700 (PDT)
X-Received: by 2002:a9d:6854:: with SMTP id c20mr1580649oto.120.1566961625852;
        Tue, 27 Aug 2019 20:07:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566961625; cv=none;
        d=google.com; s=arc-20160816;
        b=KfDlSykCgSmbEvig3coWfRH+GmJt7WbYaAWFviGu46gaaasKJmiqci263ISh+O4Aqw
         X/Q5kNA06yPSg1UglfOPyN0iI0My6A+EeKHBNJu5vAYkzjfTad12YPlX/0XaGFV1XXs+
         0l52j7G5YbDx/FFlDMqNKWIJvhVb4huo+hlyuBWuHls5OwAh9+oaXhnj4V5AmTVilb//
         kj1SBVHv/yfyDytrJOyA4OmFibrqlnkfq/iX83vnm+vkiOxsFu5OQJwEuKNy3Z1Nrzff
         NM4vnFopsxgAvIrXXsBmrBYUvisYUNy3XW6SS1vbOmefrECSAZLwApiUX3BjmbHsypl0
         9x9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=rbXEvQKBEbgGZP+zn9/tCTouaWYBRGkJ1hxAOLdl26c=;
        b=fiyuoedXx1t9wiiuHkb07JU95PBPyijwQ85UK/AYD+Gc3u1ADym0nsX+1Tnxgu4/w1
         VuBpXFNsjosWA8XD+/kgcEnraaEq/0mDHoWpPSLPy6L7acjI5QtzeOjmkabccrOIwZEx
         NwOa1me5sl6rmD7AqpWVWCXbxEBh0uIvjw6ZOw1/Ds0H7JC0g5jzrG6hJ6RKoUOFglcg
         V2JHPoLWxPtKL36yEdLNcft+5bBBcf1IUgKVzmymooKSp7HFljCq3ew/sW9e3BmqUsSV
         VH2HbaoNALGZMxljkfU0lt9a1EkDWVfuVcuLZ9A2fWjP3f6EthhyjXTvYA25LLqDNvaC
         37jw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id f16si83284oib.0.2019.08.27.20.07.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Aug 2019 20:07:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7S2s7NW017694;
	Wed, 28 Aug 2019 10:54:07 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 28 Aug 2019
 11:06:44 +0800
Date: Wed, 28 Aug 2019 11:06:44 +0800
From: Nick Hu <nickhu@andestech.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Paul Walmsley
	<paul.walmsley@sifive.com>
CC: Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "paul.walmsley@sifive.com" <paul.walmsley@sifive.com>,
        "palmer@sifive.com"
	<palmer@sifive.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com" <green.hu@gmail.com>,
        "deanbo422@gmail.com"
	<deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com"
	<dvyukov@google.com>,
        "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
        "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com" <alexios.zavras@intel.com>,
        "atish.patra@wdc.com"
	<atish.patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190828030644.GA20064@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
 <09d5108e-f0ba-13d3-be9e-119f49f6bd85@virtuozzo.com>
 <20190827090738.GA22972@andestech.com>
 <92dd5f5f-c8a2-53c3-4d61-44acc4366844@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <92dd5f5f-c8a2-53c3-4d61-44acc4366844@virtuozzo.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7S2s7NW017694
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Hi Paul,

On Tue, Aug 27, 2019 at 05:33:11PM +0800, Andrey Ryabinin wrote:
> 
> 
> On 8/27/19 12:07 PM, Nick Hu wrote:
> > Hi Andrey
> > 
> > On Thu, Aug 22, 2019 at 11:59:02PM +0800, Andrey Ryabinin wrote:
> >> On 8/7/19 10:19 AM, Nick Hu wrote:
> >>> There are some features which need this string operation for compilation,
> >>> like KASAN. So the purpose of this porting is for the features like KASAN
> >>> which cannot be compiled without it.
> >>>
> >>
> >> Compilation error can be fixed by diff bellow (I didn't test it).
> >> If you don't need memmove very early (before kasan_early_init()) than arch-specific not-instrumented memmove()
> >> isn't necessary to have.
> >>
> >> ---
> >>  mm/kasan/common.c | 2 ++
> >>  1 file changed, 2 insertions(+)
> >>
> >> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> >> index 6814d6d6a023..897f9520bab3 100644
> >> --- a/mm/kasan/common.c
> >> +++ b/mm/kasan/common.c
> >> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
> >>  	return __memset(addr, c, len);
> >>  }
> >>  
> >> +#ifdef __HAVE_ARCH_MEMMOVE
> >>  #undef memmove
> >>  void *memmove(void *dest, const void *src, size_t len)
> >>  {
> >> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
> >>  
> >>  	return __memmove(dest, src, len);
> >>  }
> >> +#endif
> >>  
> >>  #undef memcpy
> >>  void *memcpy(void *dest, const void *src, size_t len)
> >> -- 
> >> 2.21.0
> >>
> >>
> >>
> > I have confirmed that the string operations are not used before kasan_early_init().
> > But I can't make sure whether other ARCHs would need it before kasan_early_init().
> > Do you have any idea to check that? Should I cc all other ARCH maintainers?
>  
> 
> This doesn't affect other ARCHes in any way. If other arches have their own not-instrumented
> memmove implementation (and they do), they will continue to be able to use it early.

I prefer Andrey's method since porting the generic string operations with newlib ones should
be a separated patch from KASAN.

Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190828030644.GA20064%40andestech.com.
