Return-Path: <kasan-dev+bncBAABBP77ZXVAKGQEXQ36QEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 308428C9E0
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 05:28:01 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id t14sf2501884pfq.15
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 20:28:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565753280; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q8jEQNPI+BRKLJMg1tmXvPOa1hKRAAzNIYgEfCUl29K3ibGxk/pykm6oEFlBggJ26l
         FEY3TokGjqnSMnylelvAtjF4lQM+V7oBbcYNIHNRLNRl4TakTQ/jHxmfp7DV1EARD+GU
         Ood4RGgOZMAS6R0lENlIKnFziQKO28GmFZjcWYRaX8tZ+TXf+EqsC5uKD28bUXCUTjwy
         Z74BtQu2K0tYbkOePrBHDugb5303Jd0t9fEHupGui/Mjyd/VnqqK5E+v0FgLlEjVCJPL
         zH/9TQ/UNvyfp/sDxO/t+0c5YBvZTYawGwQxghc4u9Dh6Xqh09fVteDAXCOz5RWJ5B0Y
         nY6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=5NhGoxGvIEhmuJebQzeFZoUtTFJ/IpQafuHWBX4l8Es=;
        b=eSH27BNJEa3oIA/B3OwfQU6gSQTxv/z1PUrmRTohGmgw+ACruNEQsasr7p6yncmmw8
         1F/NwOG5NdBBiO+MSHUFEWzmQF5+6YXRaUrEfa4k7U8/0hHZxlL1Ojw8E48wGxM3YMWw
         mrPmbMFJpQY7PNCzW5gYxKYuUHmLuueB0c1lCZ+lJHns4CE/W7bq+KBt9OO3PUBRzN3R
         aUD2Gm2Te5z1zgFFQZlFCNCIkDkjcY4y9mb+x3jWZKmgqBp5DAuW1mOxYv3m9bvRLj2H
         UpIrCjd0GB1RGo2P1qwE2sTTyiBvKNDh4zi1Nv9W6I7dELiCoUSbrHnIQl9oSxgbybz5
         FycQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5NhGoxGvIEhmuJebQzeFZoUtTFJ/IpQafuHWBX4l8Es=;
        b=YhYKI3uuz/W908LTwzQNFjfVDNXaEHyYU6KYQQGUDyj/G9tR6IuuDM5P8PUsrmmazq
         1T4EWt8BAXHArzRo+svNgjaMpLClQSG7nzu3zSFNpWwAfY/SnCKMaivitxYfM+/I8iMi
         JBzHXIr0MY+ZSKkJFOSEAiKJ5+M2BjeNtkxHd3Nso4DBsq4evayXfIabP+RlX73BLuaA
         oHfC51IwdfmpE/o20w9gYud685n07PK2TMJD/vPGz6t6bJcV7JINMXtVPOACvlK8vlel
         FQEHnyPX6F3V2t8MMghu99ct5dsxE6fgm7HCd8FspU+DfGl7qwA1LPrMRSc62hufW0G9
         CJ5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5NhGoxGvIEhmuJebQzeFZoUtTFJ/IpQafuHWBX4l8Es=;
        b=KfLaHMiXvw4nueEkklnLFjKruxE9SRYyuqPQtkkK+A+JU2cKLmDIytegCjUYA+2C1N
         aSzP029rmC0VHvF7NguKaw7ebYYudC8J+Pc/Sivxrtagjmt3yHrA5eo8iszsxaoVlYAv
         x/u7WZUlcyRwpyGJZzHtuX6uXaZBH/Zjp8aqfesgJ6mu2Donc+SYDEjAwj1BMuVPsosN
         669YRUbK/x1ieq81oRwmt0SfnIB/8TWlP1Nf3mNHPmslTAmhDVXCEk4BOjyAbG5qDwAm
         UCoVs0Y33yK+eypAhUrvLCwOBqitHjI3yrrMW4DfCYKHSr/M4z0vLFt2afcVxttcCMDI
         PBBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXojXGrcJaPNU/sYzUOz5JR+vepzXp0fx3cK0AHFZh7Sv9J81f3
	YScrOao9bZqTZMEFmp7lrvo=
X-Google-Smtp-Source: APXvYqyAJozCz1QV4GKVXe4FiEAY9M6fpaWfqlDn0qqxoVKNlVdM5OXsqUf7/nncibjBmn+yEXMXzw==
X-Received: by 2002:a63:121b:: with SMTP id h27mr37275212pgl.335.1565753279507;
        Tue, 13 Aug 2019 20:27:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:568d:: with SMTP id v13ls169273pgs.4.gmail; Tue, 13 Aug
 2019 20:27:59 -0700 (PDT)
X-Received: by 2002:a63:381d:: with SMTP id f29mr38130233pga.101.1565753279200;
        Tue, 13 Aug 2019 20:27:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565753279; cv=none;
        d=google.com; s=arc-20160816;
        b=IE5ouT3XIfdKYRmsJsKHcZ2CMovhxZVw81eClVEh+vtragG98sINfX5h9l+iqxNEvk
         TeaUqupBFOv0nXnAI5pJFTYuZcxdg2uYhHTCz60uOxSxstdP9ifsWx0sueZ1OAvYB4/n
         A7fRCJKr2JoRJoGaHtBiluIRTPHyfIi6suZBYcabU106I5WinGiRdN4eZ8SvsXT1hjDo
         10PxCVFWjVZHnD2bbID1pmOW/GvCczG/Hq5qnFsBtSvP5ahpsbjcVxgMTd0gDj6Wq7TO
         b4WJ63VpId/nIyuod0S+uo2PpCajgiC2hDS2WzGCJHHLoALE8593vJcRuAISIoV50cSc
         e8uQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XrgLkjrPICHwgApgT3/klkUJR7obvhDhJsCZqlvVLQI=;
        b=dgimT4QuMd8AdNS5LorQFgrC1l0PUtk8vO3woqLjNd20DZNUIfnVIMOaJR/M0dm7E/
         9UPo2IQPh1sJ19cM9oQs3jhjGKWc518SmNYVK2qR1LiCjQpHKjO5KlYOCFWnzpJ+EMbR
         O0QKj4Gu9hgPBnooMV90OcvVKzuVMmiCbnemZHQ5hsxX+jc9Ls6U694aH7V4jiFMlDE2
         zXQX3uIkYR54gcoYq/JB6B8qKUx8kaRTDBHFwUrEyHwKsq4A0BKN0CNZOQLHj7v6myW2
         PQ2FeHN8JakMYjw0/8fvdihj1Tz+mIz4/d51slx3kqcFcJpcOQuHTq6iTVIUaiaQVLvL
         l09g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id f125si5565129pgc.4.2019.08.13.20.27.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 20:27:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7E3G38F041472;
	Wed, 14 Aug 2019 11:16:03 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 14 Aug 2019
 11:27:32 +0800
Date: Wed, 14 Aug 2019 11:27:33 +0800
From: Nick Hu <nickhu@andestech.com>
To: Paul Walmsley <paul.walmsley@sifive.com>
CC: Palmer Dabbelt <palmer@sifive.com>, Christoph Hellwig <hch@infradead.org>,
        Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com"
	<green.hu@gmail.com>,
        "deanbo422@gmail.com" <deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org"
	<linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org"
	<linux-kernel@vger.kernel.org>,
        "aryabinin@virtuozzo.com"
	<aryabinin@virtuozzo.com>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com" <dvyukov@google.com>,
        Anup Patel <Anup.Patel@wdc.com>, Greg KH <gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com"
	<alexios.zavras@intel.com>,
        Atish Patra <Atish.Patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190814032732.GA8989@andestech.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e>
 <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7E3G38F041472
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

On Wed, Aug 14, 2019 at 10:22:15AM +0800, Paul Walmsley wrote:
> On Tue, 13 Aug 2019, Palmer Dabbelt wrote:
> 
> > On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
> > > On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
> > > > There are some features which need this string operation for compilation,
> > > > like KASAN. So the purpose of this porting is for the features like KASAN
> > > > which cannot be compiled without it.
> > > > 
> > > > KASAN's string operations would replace the original string operations and
> > > > call for the architecture defined string operations. Since we don't have
> > > > this in current kernel, this patch provides the implementation.
> > > > 
> > > > This porting refers to the 'arch/nds32/lib/memmove.S'.
> > > 
> > > This looks sensible to me, although my stringop asm is rather rusty,
> > > so just an ack and not a real review-by:
> > > 
> > > Acked-by: Christoph Hellwig <hch@lst.de>
> > 
> > FWIW, we just write this in C everywhere else and rely on the compiler to
> > unroll the loops.  I always prefer C to assembly when possible, so I'd prefer
> > if we just adopt the string code from newlib.  We have a RISC-V-specific
> > memcpy in there, but just use the generic memmove.
> > 
> > Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic
> > Linux functions?  They're both in C so they should be fine, and they both look
> > faster than what's in lib/string.c.  Then everyone would benefit and we don't
> > need this tricky RISC-V assembly.  Also, from the look of it the newlib code
> > is faster because the inner loop is unrolled.
> 
> There's a generic memmove implementation in the kernel already:
> 
> https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/string.h#n362
> 
> Nick, could you tell us more about why the generic memmove() isn't 
> suitable?
> 
> 
> - Paul

Hi Paul,

KASAN has its own string operations(memcpy/memmove/memset) because it needs to
hook some code to check memory region. It would undefined the original string
operations and called the string operations with the prefix '__'. But the
generic string operations didn't declare with the prefix. Other archs with
KASAN support like arm64 and xtensa all have their own string operations and
defined with the prefix.

Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190814032732.GA8989%40andestech.com.
