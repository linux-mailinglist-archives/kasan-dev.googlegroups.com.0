Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTP4VKAAMGQEENPEJVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2245030023D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 13:00:15 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id y20sf8242749ioy.18
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 04:00:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611316814; cv=pass;
        d=google.com; s=arc-20160816;
        b=VN+AJOABsm6XYjnBYF9Qm61D03TzCAtun1yl2D9P63ClUkB/MHxnTdqueaRI133Kim
         xYc+jqHUwfpJOwzayt258AK8S+lC/xrk9L/2Tq4ipMvW20B+XlIY0c9QjVK8bkex6c5x
         yS3Od90sHLWbJFpCcqPFxaTf4aM49yP4lbihd9K6SlwA4kQmYxajQtO+ClEV+uQ/6iVZ
         fa+7rA2GURCofBN94eGhC1xRYqOZF+TPMrTa+QD0uCNzNIQePv9LRX5in36KDxCtL97t
         gNvrGnwi4Nq1WV0Lah1DVNLM5u8HO4FJhCOFMLu1FzYOfQFEpxrGJAWbF1R8+kKoOLpW
         jwyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=r4oYF5+YI6Wij2lifWR3jlGkMDLnaCbEnKBxqnSOzdk=;
        b=VFJ+ecNZt0ngyn6BS8IwLMY+4/dGtP/QC81C7an0mAPFtDxXTwJo4qmaqXppd+Sa5l
         yuISlZ1iy2dvTQUAPniqv5HB3jXBZ/mnBa+Kur77h3ZYI+naxu/8741RUlFiaeMT7w5M
         NtUG094exztrk+CkqvtVlyA6Hq1PXAL9PxQx5i/SqDVkwMsKy5jhdVjr5YiLJOPWu9oA
         nVkLDn+nqr0XoORcFIn7vrO0Z0xg1L5EdDVUk7gijfyvlZAaBVIzwulOt8bxOAPjhrmy
         Cc9zhzHdf5jDI2zYnuW7MmHCOTPiZej4Q39/D5M+Aa1NH3bZR3KiDJXirAUJDuwfzqAP
         uCHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r4oYF5+YI6Wij2lifWR3jlGkMDLnaCbEnKBxqnSOzdk=;
        b=KH4v9GDCQcLJBtiDLA8q7PNa7q1uCRZc66oE5srCvdFW2OmjIaNLu7XL/gw7ZDBv3z
         L8exs9y4HFDoeH/l437CpYz+g2uPhdowJv5vvsKfwQC7Wq9cpEb/OSbJxCuE+JlG0LhL
         ssF3igZvdx+qznT7uDqC+49vp2q0VqRMZxfKX9d4sx8fymjL+EiyP92D0VdDpkes406a
         NmPu9szWPBpN0eEizAn0AXRWX5Bepx+9I1YWl2mqmO52uWIw03MvyhFCCixeHO5yRYnU
         ii+rWPq/abkMhe6WZ/cA1/MA4uNTeZZPNUGCmSRkACCAjiG0XmibNnE+iVlgXHdtcFwr
         g1aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r4oYF5+YI6Wij2lifWR3jlGkMDLnaCbEnKBxqnSOzdk=;
        b=WCsqaAifSnCfhC8yjFOlvRfwQlifBxtWQArFxP9ralsCc03IEt13Yi0WN3456MT344
         mvI0MLuaOJjBpczzIFnxKzacVpuFc7dLlKtDe3uzW3fwKQTNtNgtCF1jl/LKrUK/kCy8
         YrwXrR0oIHjVMNVcSRxM9zmHz/JSBxdN1DWxZJrnOEXd0vD/1NmgNLrahWBFUA6UyGoK
         kwrGsF4DWy90ZRb4XP4YATk7C+w7Vga225CkF//+X63T8WdasNAcM3MGKnTqml1LgIDm
         kjxS8RCBlZfCYJrdKQyckZzhOwhbmeBg9vfMm0OMQvLy9/jsmS/FQ59CnmEI/Bn5F8Xb
         8FIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531S7E4dOxQawm+kSvAXjCqtXCw1lw7gjUKPaipcJoNHfjmee10V
	xkjx3DAO8+4iL/xOI3sZ9sg=
X-Google-Smtp-Source: ABdhPJz03HhZfDWiETnOJVWn5NRKFLOXKlfke/G7A3g0r6oG2uXSluyop9e1qHHU6g0JIhSSryibwg==
X-Received: by 2002:a02:6064:: with SMTP id d36mr232778jaf.104.1611316813764;
        Fri, 22 Jan 2021 04:00:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:fb06:: with SMTP id h6ls773556iog.9.gmail; Fri, 22 Jan
 2021 04:00:13 -0800 (PST)
X-Received: by 2002:a5d:9a8e:: with SMTP id c14mr1622231iom.178.1611316813376;
        Fri, 22 Jan 2021 04:00:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611316813; cv=none;
        d=google.com; s=arc-20160816;
        b=I2+sm6PdCd8DbyCvAD8ISrUGtfzCVUM+3njw1bLDkfhpX3P5kpMumakyDhbn5a9qus
         sD1MZhmNyHYT+4Nq+k24iaM9C851U2MYILoD18l3MuXTMdzzOWLvSPj7hRHIxeYG7X9C
         N8kOlYlwtCuWI1QHZl2P5nDdgexBU2iDrHgDFsuC1lGCvq/KvY44Ee5Q6nHAVE2oTvE3
         WpTrBf35vP2nGH72z4LtQ00ne0698S+ClYXKiMi1zJHAZyKCzDJ8yWy1mmoWJPjv7Y/Y
         4jNzQss3QnYNenKb/r4H2nb5tGmNey7s+9ryPnZ7fg5HHm12PI/Su+kEwCbhiQCE6/Y0
         1brg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=5whX1Ac5j1DcAXuya+l55ncchTV9zKzDwEfY795Blgw=;
        b=kMkbt9qfMrMrVdX9oAxPxzeRcuXFWKRfeabEaaFtDwYs440EiX3a8057vHABO+HxBQ
         1ibIbIvEsr8S2yAPQv5t77SYPkIA8/AB9QWAZzl/VUyBh/eietKeqmj7SCYMY9k8KWI8
         nQUYpip4vzGsnwgPKeZG+sTVgT9csxujqeD3KphSqq3FBnJhMQnCrZheEhGP1VQ//fr8
         R1p+sWSTGgnAiwHVpQ3pLFrOUFyTXHBG3YpMzTIjuy0JtvylvBd9aMotVOJPY0Nwo8HM
         bpc1m5TNEFvgo8pIoDYuCRLO2KG49ps+AuE/EG/d8VAUHdT9vaSOAY1Le/yBE4+2mjeQ
         gX7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d13si344072iow.0.2021.01.22.04.00.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Jan 2021 04:00:13 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7EC0422C9F;
	Fri, 22 Jan 2021 12:00:10 +0000 (UTC)
Date: Fri, 22 Jan 2021 12:00:08 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>
Subject: Re: [PATCH v5 6/6] kasan: Forbid kunit tests when async mode is
 enabled
Message-ID: <20210122120007.GB8567@gaia>
References: <20210121163943.9889-1-vincenzo.frascino@arm.com>
 <20210121163943.9889-7-vincenzo.frascino@arm.com>
 <CAAeHK+yaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+yaFtXUDVExoyqkYysOPdxLVhfY53nb-msFYEJLZx6k8Q@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Jan 21, 2021 at 06:40:35PM +0100, Andrey Konovalov wrote:
> On Thu, Jan 21, 2021 at 5:40 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
> >
> > Architectures supported by KASAN_HW_TAGS can provide a sync or async
> > mode of execution. KASAN KUNIT tests can be executed only when sync
> > mode is enabled.
> >
> > Forbid the execution of the KASAN KUNIT tests when async mode is
> > enabled.
> >
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> > ---
> >  lib/test_kasan.c | 5 +++++
> >  mm/kasan/kasan.h | 2 ++
> >  2 files changed, 7 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 7285dcf9fcc1..1306f707b4fe 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -52,6 +52,11 @@ static int kasan_test_init(struct kunit *test)
> >                 return -1;
> >         }
> >
> > +       if (!hw_is_mode_sync()) {
> > +               kunit_err(test, "can't run KASAN tests in async mode");
> > +               return -1;
> > +       }
> 
> I'd rather implement this check at the KASAN level, than in arm64
> code. Just the way kasan_stack_collection_enabled() is implemented.
> 
> Feel free to drop this change and the previous patch, I'll implement
> this myself later.

I agree, it makes sense.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122120007.GB8567%40gaia.
