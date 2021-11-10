Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBWUGV2GAMGQEAZNNANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FB5644BCE7
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 09:31:24 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id b1-20020a05660214c100b005e241049240sf1322079iow.18
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 00:31:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636533083; cv=pass;
        d=google.com; s=arc-20160816;
        b=bkzv+qlU+s6cTmF733EklqsThKcPP4UN1pGOg8bpuoxthnE6YvgSc/US7Uphg/uYuP
         64QIWUNhGGXjA0G1/ympi6+Gi4TU7UO9vWroUW0pr9oEz7Aq2i4drVk3ExadtOTSKh97
         eTmuVmSFsobCJA9r92dTZQp0/CdBG1IvU6hbuC+EX1Ph3ol/Ln+HZn3nlENdq6/R9NPS
         mwIms1voRK/zWnQFJUylOCFVbDhHtg35f6Z49gDqIO22CkzTkS2Zwy90VGxj9eQRajZp
         iUf06FWEvsoRLrqkhSV/eZvERpEoszORExlMvu4DjZ7XSqfnrEES7MdXnOcvvRlDqXv2
         +AOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=2vValwwWHT7CR7bgrhgV1Rj3XvCq+X+bhUILwKgb+pM=;
        b=FIQMyTmdAEt8t659P/emGrpGwdJXznH6D36xmsX7xJJ45xpXPtrfRvaq93V2GXTQ2x
         Po+rVcrz5Zd7ljVE0Ufg3LzfPObvFBvHg87LPl7/9xB53abVEHbxUgg+6Ol7dzGp8X/t
         B+sV+jDeFnOWls5EY1mqRTnIN4v+16+G7Pfz2Gh13P8Zp1Ygpuyv4KecjE3qJTuL1879
         KRbw7rkIBjrHBwRC3/l9eXp+k4jTQwOlUGlFVLwA5/nrJzcP6yBss9S7j1dQtq6OKtRu
         7CWR4Zt7dlDaOHM6kLqm7vCFeDCy24U88GQWqff+vKa5JQLzQhtOrkLxU40V/cDtVdOR
         Ww8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=0lO+EfYu;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2vValwwWHT7CR7bgrhgV1Rj3XvCq+X+bhUILwKgb+pM=;
        b=diKTQsURrooMwLNpSZE6EWY8gESPR7/f6cKBtOlhzvX1HNsP0G5U8bpBJSedI/qOxo
         sgwus5wlH0FyESYd4gW7kj9W9dUz2WlDWGajmtMsa7CuIo1i7aEst0YNJ9JVvrl4L/zp
         mxx7FEeMtT1v5kUd43sgodh0rFjWUGLcMnyk7bMmqW5MIl0lMnOuzHi/l9k4Swh0OuHu
         1ldv5QskRp92fA5UcP7ie8E/X2a+iSNvdCndVlTiLvzZ+mkl2CVM7eSV43tBBIVO85nz
         96499oPptrsmj/4B9Wr6UEt+OuZ3UEWUqt+yII47XiHLMJbvyZnq52WadnYsUHarCVq7
         MmuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2vValwwWHT7CR7bgrhgV1Rj3XvCq+X+bhUILwKgb+pM=;
        b=Rk0j/xter0Paq/MkLrGwxJ/dGd1uttR1PMbsSlfiIQ15F0D4dOYmeGIEMQ2HDkUa6S
         wRQpdcImFZOz5P//baOejfkWDAr/BlwdGjlmDYlEpTl6ya3ktkiYg/ZsYw1DhWrbWPXP
         nx0HvjQV6ExRuJd/m/PRUmeq4gFwnRbMPG7UBI0D5TgNbpFcoaYp8pFdBsoRWy66t3x7
         7f6+vVP2093zPmwLDiTrAWmg+5gssfCQzLYTEPLu/VmKvXejnzJ2bf7iCNhfo4izyrkz
         HD4zOl8/T+Wp9JYqmxChIQckXS5duJusYcnWYqg6H+xHacD9VW/tec9ObOLliA8D23Ce
         r2gg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532RB8Pmk53DR3M/gO0KaIPhUwMvoTbnsdbd63Wo5Y+e9BWdYhrH
	1H//xJIrhZpqs74ERXMho7E=
X-Google-Smtp-Source: ABdhPJyTJ9PwJeauSylReoTnBDo//xOH1HNTrrPp+aIzXwPus20ve/iiYe0gld0NRRlpGCvqbcaUtQ==
X-Received: by 2002:a05:6638:4113:: with SMTP id ay19mr6665039jab.149.1636533082933;
        Wed, 10 Nov 2021 00:31:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:408b:: with SMTP id m11ls2582810jam.11.gmail; Wed,
 10 Nov 2021 00:31:22 -0800 (PST)
X-Received: by 2002:a05:6638:349e:: with SMTP id t30mr10855755jal.49.1636533082644;
        Wed, 10 Nov 2021 00:31:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636533082; cv=none;
        d=google.com; s=arc-20160816;
        b=ykOU1ZUFKkChn+YBR74r9mwSV8AikoFiIQZ7tMml/Ssem6PBSRp9hIhttsUJsQGmnL
         x/bv7Rz+fPmAkj+GizvuYMpHuyh/yUUMbl25tl6mowamAw+MicNHqZKxDGCJgh6V9Iq5
         nDvYFhW078wVbJZqhEmG5k9bZn9ArrL2TNCugblpfFPHukHGvUeHMO1/4MySy7kFazyC
         j4fT7kg6rHpOeIVUfQEsAGQXNidw/snRhuMHeZQJ7mOSSKraVXQ7XyOi5WnHiY0qg0I+
         AHQuoEp+iyhc1PEx6VLzEmrQJHe/RMq3e485ba1sru+hf5LxMkzzaYQwNN1McXEs2ZZ8
         KcZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kQsmDC+IONh7AXjXC5nWhoeyHbGMkgD0N2E820Jvt0g=;
        b=tfEHIvVtSFUI4gs5N0HjIILyxfACZsS9U6o5Ks+aT7tRpMK5gp/me7tulbMWvJmetn
         9493n2I66SWzehqAHJFIyQd/agDpU3LV0S0A+DEvG2wOWG/pxVK8p3ekC/7uMhr1Dd6i
         wfYXxm4cK1VHVd3kDu8mqgNxjiFElTpsoWkxOJKPZt/OggRr1GOJAyKhRr7TnCQB7ypz
         gDMkjTiEkloAHk4vphXJOcAGdjrbfYuTEfI9B6ViXfl6tPUEKWs/v7nKa52Rnu3Ak5Ga
         +BUwQtScpy2ynh4BPwdE42lIqTJ2i1COrf4GHeo9bZLiMSUPrUUMg7Qqv8OBHH7UeEmr
         BFPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=0lO+EfYu;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f19si530395iox.3.2021.11.10.00.31.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 10 Nov 2021 00:31:22 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6851561076;
	Wed, 10 Nov 2021 08:31:21 +0000 (UTC)
Date: Wed, 10 Nov 2021 09:31:19 +0100
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: stable <stable@vger.kernel.org>, Sasha Levin <sashal@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [5.15.y] kfence: default to dynamic branch instead of static
 keys mode
Message-ID: <YYuDVxniscyNtBua@kroah.com>
References: <YYqtuk4r2F9Pal+4@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YYqtuk4r2F9Pal+4@elver.google.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=0lO+EfYu;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Nov 09, 2021 at 06:19:54PM +0100, Marco Elver wrote:
> Dear stable maintainers,
> 
> We propose picking the following 2 patches to 5.15.y:
> 
> 	07e8481d3c38 kfence: always use static branches to guard kfence_alloc()
> 	4f612ed3f748 kfence: default to dynamic branch instead of static keys mode
> 
> , which had not been marked for stable initially, but upon re-evaluation
> conclude that it will also avoid various unexpected behaviours [1], [2]
> as the use of frequently-switched static keys (at least on x86) is more
> trouble than it's worth.
> 
> [1] https://lkml.kernel.org/r/CANpmjNOw--ZNyhmn-GjuqU+aH5T98HMmBoCM4z=JFvajC913Qg@mail.gmail.com
> [2] https://patchwork.kernel.org/project/linux-acpi/patch/2618833.mvXUDI8C0e@kreacher/
> 
> While optional, we recommend 07e8481d3c38 as well, as it avoids the
> dynamic branch, now the default, if kfence is disabled at boot.
> 
> The main thing is to make the default less troublesome and be more
> conservative. Those choosing to enable CONFIG_KFENCE_STATIC_KEYS can
> still do so, but requires a deliberate opt-in via a config change.

Both now queued up, thanks.

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YYuDVxniscyNtBua%40kroah.com.
