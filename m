Return-Path: <kasan-dev+bncBAABBA5Y2HXAKGQEKK3AM7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A555102E21
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 22:17:57 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id s204sf11370220oib.7
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 13:17:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574198276; cv=pass;
        d=google.com; s=arc-20160816;
        b=WoADTHbHRjpTxXMfGiKek4PPUgiIpGxpppfT7gZHbQk4eiO2EzmA/egK3VVWnHgiS9
         Gu8Ftu21g36sep/mb9gvbjIoMkKVLcBRzIP4fpFUrbYSNakp5eezcglIkzUCp18jUCdk
         v00bvN+Q4aTm7NOkQdlbTRsxohefkXZh0Pq2ZOTUZV7yH8OT4pxP3RWOe9UtIaLA6O/V
         9sBe/egFAmoCtq8QRgswQt9NGiyfTeBerpE4Rk9OUDJPvG0laPHxdTt3GqLIw8iQ8qj/
         pEW8yOAHoP38azOHhjnYDJGpfdPEN4g6WqAvMIiKGtLRJ2MWga0L1W3zhyytrRBdNr7P
         j0Eg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=FCXusi+v7RRdQCOVAKngXkcTs2ELoQxLrmq7+G+wekw=;
        b=WNiE4p6SS1Y3Q74lK6du01QpyCysxBgHVNGe7sVy32gsHIEYqYDzsVWriYVUxeYe5S
         1XvDD9mHI/aiqlcDHX9OKZ70TwXQwU0pVbGLT8jdpqGT466XVq8vnVEF2tEAseSGrTP/
         +rRx0Zpw+ZBTnBZgcXKqDIFA9t6mWhnOgFilXs88+fbFUAQRzoqzDrCZhrBwIy1jHij9
         Q3Spqx0L8I4ZB2r0137KAbChPS44m8i1Arwx1VDBa1Duu8EVfG4mzKdQPyf3dCB4kzeB
         G0dj+fT/vAIOPoHX8xECC7AVhCuT43iT+W30HeiNRYGPDzIQaGM1cylWhz3OgD8BGUY/
         kwXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HCoLX8+8;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FCXusi+v7RRdQCOVAKngXkcTs2ELoQxLrmq7+G+wekw=;
        b=qLWftQV5biXDiO85cqRNvXaG5n+uS+PfIws0MdYNuP+TywVIvOf+jRU2EksUieWwjx
         meCE17npiID7wvpeC5+eZ5bWnAy6asq8cLwWpVntuiuHcOceByfCs6+iIv5CtBliOAJu
         aLQmlCY1KU/M/b7RhWZMnFeLa4xKmAj+tZK/1123GNYE3egnU1TCbpxSIuPpKdW9QAaN
         FNKJbAyLDE5U4I9FEu+LJMNvQDOejfyL0P7/zXjteC3E6++WOEJDZSxp8Pmwx9RO24Kt
         gpoT8i1HNydYCzDss4H7ApiwAJ1As54XlpNoCTzV3u0VQJxZ5SCHC5zoU7rkAqi9ysyQ
         z/CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FCXusi+v7RRdQCOVAKngXkcTs2ELoQxLrmq7+G+wekw=;
        b=itXpPFmC4jEEzFQtSlPcU4XpppcmN5u8/XqN3SNJ6TmIrnq5S1ZmYSm1r+0sb2Un8R
         rS49YXpc7fGS3vOKRB0SuTVpfgPvU5LrOHqYwEHEQ77iCSukDXu5dQdZzYgJ/bdxTLuc
         Ij9z8nstZTsUPT5jTqUQlykQ9Usgh3RsCLwshaUHZAq5pXr4o20fk0TFT9qX/k5jLI4P
         snqcRI5zWOm6+6xlf2rL6orceKWT0pHPXdZTx7U93jnnoYKasiZGTMoPQsVzYJLG+TXU
         cL/AlyRnjHGEdMriXY3OwqD5YnPsotunJJzMl4nRJZGl02/cV4JFvf/4j0G8v2FT8ovb
         SuHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWJpyPoYFTMlz4spBiaqkenqYe+I06Tnrovq61oB87x7jud1lKv
	HbFpQonJ5NBwC8wknThNf4k=
X-Google-Smtp-Source: APXvYqwYmR8KwdOLFTyfaTwhKERJBqp5wMUadAB2kg25Rfkaojiv4S4tep752CQfcdYGxtKaoKMANA==
X-Received: by 2002:aca:3889:: with SMTP id f131mr6066083oia.14.1574198276036;
        Tue, 19 Nov 2019 13:17:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:72cd:: with SMTP id d13ls4795950otk.6.gmail; Tue, 19 Nov
 2019 13:17:55 -0800 (PST)
X-Received: by 2002:a9d:6f15:: with SMTP id n21mr5569689otq.231.1574198275765;
        Tue, 19 Nov 2019 13:17:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574198275; cv=none;
        d=google.com; s=arc-20160816;
        b=i6HvGqDVTfUhsm64yQYWxLj0VwbkS3wN2z0pDL39LV0Gi4Yn8/l43JEkfMhCXNNVBy
         TelbxJ3WJ4c7GaLLad1dFrovKAiTRbfMK8AuE+0n1xrnDxb8zrFFQZLyDUOWe/w1bhnI
         AzrgJ/At7tm6EK6fofmQRPv7e+cX5xVZG6E5MwZt1dt3Gz1guXWsGKalhuWLZx/C3iJY
         RSTEr900PtJ6g/pQqb+6nDageqCCswX22BM99nuTfrPfWxXaFNGPePjpEAcQ2F5f5Nmt
         ToOvHQKLTKnII+Dc1YP/8xQjeaSmdepwzFSi2uAo4viC+qgfFYrMBdZjENMuM9JZTxrs
         3FTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=4WEOVJjIVmi0eL/klbwkKhs1uAMNDYXyeN9UrlURFUE=;
        b=Dw1OiDzXvapXeoQ9jQxC1a6S7FQ8UOoPKUCTeIdWvz1NgIdYv5Cb6I9yHD0OEMiFUB
         xgq/CyseOxOvzdL5ysnwM+L7AsDMVS2ezjn78+Zudm379KXOptPSMkXLIT0szywcZnwd
         wn6I5m8YftIeQhseyOeRTSXDw/TSg31nY0py3Twdtjpq87v2Iviss6kw1xbexH1RemMG
         q2X89lOnfT2P/uCoQ+L03wQYXT37HAfbCKR3nE8hbX66S0G+7VZxJ6nFAMkwp6/hJOqn
         0LUVotLKTJLZ6X2AseRxGsNEqMR/GAwJz4s2NYLVhNWoCCz1r3y3CqJd2htbytRNwqiT
         PysQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=HCoLX8+8;
       spf=pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i23si1258329oie.1.2019.11.19.13.17.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Nov 2019 13:17:55 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [199.201.64.135])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 02BCE2245F;
	Tue, 19 Nov 2019 21:17:55 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 90BA83520FA7; Tue, 19 Nov 2019 13:17:54 -0800 (PST)
Date: Tue, 19 Nov 2019 13:17:54 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Randy Dunlap <rdunlap@infradead.org>
Cc: Marco Elver <elver@google.com>, Stephen Rothwell <sfr@canb.auug.org.au>,
	Linux Next Mailing List <linux-next@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH -next] kcsan, ubsan: Make KCSAN+UBSAN work together
Message-ID: <20191119211754.GI2889@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <20191119194658.39af50d0@canb.auug.org.au>
 <e75be639-110a-c615-3ec7-a107318b7746@infradead.org>
 <CANpmjNMpnY54kDdGwOPOD84UDf=Fzqtu62ifTds2vZn4t4YigQ@mail.gmail.com>
 <fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org>
 <20191119183407.GA68739@google.com>
 <20191119185742.GB68739@google.com>
 <3b8e1707-4e46-560d-a1ea-22e336655ba6@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3b8e1707-4e46-560d-a1ea-22e336655ba6@infradead.org>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=HCoLX8+8;       spf=pass
 (google.com: domain of srs0=yygb=zl=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YYgb=ZL=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Nov 19, 2019 at 01:07:43PM -0800, Randy Dunlap wrote:
> On 11/19/19 10:57 AM, Marco Elver wrote:
> > Context:
> > http://lkml.kernel.org/r/fb7e25d8-aba4-3dcf-7761-cb7ecb3ebb71@infradead.org
> > 
> > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> Acked-by: Randy Dunlap <rdunlap@infradead.org> # build-tested

Applied, thank you both!

							Thanx, Paul

> Thanks.
> 
> > ---
> >  kernel/kcsan/Makefile | 1 +
> >  lib/Makefile          | 1 +
> >  2 files changed, 2 insertions(+)
> > 
> > diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
> > index dd15b62ec0b5..df6b7799e492 100644
> > --- a/kernel/kcsan/Makefile
> > +++ b/kernel/kcsan/Makefile
> > @@ -1,6 +1,7 @@
> >  # SPDX-License-Identifier: GPL-2.0
> >  KCSAN_SANITIZE := n
> >  KCOV_INSTRUMENT := n
> > +UBSAN_SANITIZE := n
> >  
> >  CFLAGS_REMOVE_core.o = $(CC_FLAGS_FTRACE)
> >  
> > diff --git a/lib/Makefile b/lib/Makefile
> > index 778ab704e3ad..9d5bda950f5f 100644
> > --- a/lib/Makefile
> > +++ b/lib/Makefile
> > @@ -279,6 +279,7 @@ obj-$(CONFIG_UBSAN) += ubsan.o
> >  
> >  UBSAN_SANITIZE_ubsan.o := n
> >  KASAN_SANITIZE_ubsan.o := n
> > +KCSAN_SANITIZE_ubsan.o := n
> >  CFLAGS_ubsan.o := $(call cc-option, -fno-stack-protector) $(DISABLE_STACKLEAK_PLUGIN)
> >  
> >  obj-$(CONFIG_SBITMAP) += sbitmap.o
> > 
> 
> 
> -- 
> ~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191119211754.GI2889%40paulmck-ThinkPad-P72.
