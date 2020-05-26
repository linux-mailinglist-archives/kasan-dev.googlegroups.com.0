Return-Path: <kasan-dev+bncBDAZZCVNSYPBB3EKWT3AKGQEFA55VFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 667FB1E2189
	for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 14:02:54 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id o192sf16599796pfg.19
        for <lists+kasan-dev@lfdr.de>; Tue, 26 May 2020 05:02:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590494573; cv=pass;
        d=google.com; s=arc-20160816;
        b=C5CLP0Ctwibx+zR0yYNkaxNMdODSKh6j3WsVwYDHZR+rlXASODf7PVG1W0eyawlN+a
         R1ietE3FbXLLT4jz3GXpbKSc9vhgIbJjMQNsPcvS0MJ3AVvS4vHmKCLcG0L5tih3900B
         it4LFZc2PIzqe36G47UaDjmDHyuAAWTXYzDCQelsJuGVv4RxtC+1e5kSvbnyFO8J1wmH
         LJLdrF28rSZzbJioft4sZnDKwUrc5XPdohrKZ3jm50onkYgRDCWuYsg/PU7nyGOiFNIO
         NXaXxbCKohVV/U5OTqtEinY5jePkY3U2LHFcQS4XuAZ/zZFZzZceu7DCTo63CKAjheo+
         bBAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=pmraSzf7REPWIYy5iF0zUeyXF1YwEURbQn//cjHHxgs=;
        b=xAsOtxF8RC3GHqWezip65sbOr5cXwdkSBGH5D3SY8CC8kH2dbMfbs4u6Yh/hzzP4xQ
         AXvkNbP5RuxEDTyYzm4XQUwHAshALepCJmZeyv83duonA+4IuNyPhNDXqe07BUDLPS07
         K8bMLD2Xi2uKb4KxSCAyV9FAitgsF7wxApT7fGj9D7Hn8e1R23mKE7hv/x66dLqjK7GO
         n52TxxKFYhsO2+le8Jfwj2GGw9p34t9b1S9EQp38IfqPL/MaUWSIvi343E2X5yihGy7+
         ey+Dm3fx7o2/3CBYthbkul1PoTT4x8pgnwSmsNAkFbNs6yunBdK1RFG8uJWqPrzxrWSC
         lXCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BwvigOde;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pmraSzf7REPWIYy5iF0zUeyXF1YwEURbQn//cjHHxgs=;
        b=dyBPurqgk7DDAiKQW4MSFwJa6x4V4daTddoKBBzTp/G0zjH9dF99iCZ281AI/xdjzG
         HcvQMk1mxptKRoMyZ4fUSbLdJCQU8UmwHeY42BgD9tKhYs5EAPwKSVrZIy3m84yn1Kfq
         sDaN3B0OVQiurpXqq15CL5JnDKdI4dzDvgAeZPO/syFWwthlUJfafYCx1dKTCBJnoWqT
         DNYX343rkeLjfi4RhNrj6I1PQK5UYpUeAcCXfsV10cCT4Z7hrpoVBS+QiFHCw0dH3jBl
         iNtM5NOF1t8fvhixxBPt5zLFWiIIqiovQ11uqc1aBpgykdsSSzmB5NmSxLVRnIRsmNoO
         YKlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pmraSzf7REPWIYy5iF0zUeyXF1YwEURbQn//cjHHxgs=;
        b=VsYCi4IT435KZ4Ms442t6qf5beZJZoSh4imfPisylOA0aV+SJ4QYFfwqwMYBbJcXR1
         v/4DTo6wByLqYoamjTAqzhsWg44xO/4RJNcrn6cZoji8BU9URhQm+41Ew5Elg5qAeXV/
         2Be7xuxCpLxyN+yAqyFEg/EJNVhfR6OTa1ePQEgToZerdjHjaH5uiLxnERzhXjNtJCiA
         cvuXq/GdXg/FHN5zOwzCKwVYGY70edzT8IO6/+4rueXGyOjvKcUapmSTDsbr7lbA9y+j
         7QPgOqGgcDyhctlNe+FwKELKZA+8w+OPfzZUA5p0TTvqKDFET4oJX9+xZ/imYBrF7NAl
         hBWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533BfbHUPFKmuRcdX2347pZ+wZWkMmckQ2+iYs5s5EfyXEhNAULf
	EKMBAfUMByuBt02r7Vv9pEA=
X-Google-Smtp-Source: ABdhPJx+uJ3In/bMM2W9suO2pXQ3O2/YnWn7tvbxMkmiv4qvo4b8eJkVhW44miv/AOQOaHdEzhbARA==
X-Received: by 2002:a17:902:9007:: with SMTP id a7mr817287plp.194.1590494572798;
        Tue, 26 May 2020 05:02:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d90e:: with SMTP id c14ls4904467plz.0.gmail; Tue, 26
 May 2020 05:02:52 -0700 (PDT)
X-Received: by 2002:a17:90a:aa8f:: with SMTP id l15mr21475378pjq.156.1590494572392;
        Tue, 26 May 2020 05:02:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590494572; cv=none;
        d=google.com; s=arc-20160816;
        b=F7FNS7qaNcFmg0Wr6fcYNCAAOXjzuuVHBSHzDx0Gh+FdubQiNjZ8z31aLSs4gAq1CN
         cjvPoOGI6KR7VKlVUS3XfVaw1JV/ZaWGNy3C1gssA/eJQ2Jqjn+uGDRmkebq297gOeRR
         C7nswKiOi5r+Jir+sA7/yvOnOt2Yft8OQ4NxLEq06oVfzHEvPcvth8usX+6yB0TQ7X+d
         1y2ym3BG127GNCgB+GVrFa+xpn/32sCDCD5M/MX4IUvjfY62zErP6qNOrSeoRYDktVIl
         EaLTWWZ4gH33iTQ9JlS1Ba0pendmjJ+8RE2zM+N/ZFDHll8F21Q4cINedpiCfxyt2f0P
         3q4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xqZ8tDZyMGACQr8QYdf8t+Y80QZ12zIALE7NrLi5yfI=;
        b=DplvD4pDJ8zyYPAmGAI9YpnJZuojTJZhOLwwh7zkUTbR5CiedPrPEeGn/qH+gJUJVf
         78Y61WGYiQlhhIcP+gn+LAU03oqa9w1PFRUwj/sHXN2V1IIEpRZs05Ov9YjWI2kWwbIo
         xqPdUk7HTNxCMksWF+BtvcncRjnvjk6gfdmOWAbuSMnxDZWy9OVpR6HyUCcm5KX5ISaV
         INPeJky4ZehW/bmdGKiOCTa20T1fa467i7ZLSJSn41dr2qNkdRJPcYWYtt0qrh/8FppK
         VDg4jbuln/cacobyDEx05CxgBYppsP+4DVSYGXW6OUuuwpOdwWDg1eH1QflUzR0f0jtZ
         QSbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=BwvigOde;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z145si1311158pfc.0.2020.05.26.05.02.52
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 May 2020 05:02:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id D5AD62073B;
	Tue, 26 May 2020 12:02:49 +0000 (UTC)
Date: Tue, 26 May 2020 13:02:46 +0100
From: Will Deacon <will@kernel.org>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Nick Desaulniers <ndesaulniers@google.com>,
	Marco Elver <elver@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Borislav Petkov <bp@alien8.de>
Subject: Re: [PATCH -tip v3 09/11] data_race: Avoid nested statement
 expression
Message-ID: <20200526120245.GB27166@willie-the-truck>
References: <20200521142047.169334-1-elver@google.com>
 <20200521142047.169334-10-elver@google.com>
 <CAKwvOdnR7BXw_jYS5PFTuUamcwprEnZ358qhOxSu6wSSSJhxOA@mail.gmail.com>
 <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAK8P3a0RJtbVi1JMsfik=jkHCNFv+DJn_FeDg-YLW+ueQW3tNg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=BwvigOde;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Tue, May 26, 2020 at 12:42:16PM +0200, Arnd Bergmann wrote:
> On Thu, May 21, 2020 at 10:21 PM 'Nick Desaulniers' via Clang Built
> Linux <clang-built-linux@googlegroups.com> wrote:
> >
> > On Thu, May 21, 2020 at 7:22 AM 'Marco Elver' via Clang Built Linux
> > <clang-built-linux@googlegroups.com> wrote:
> > >
> > > It appears that compilers have trouble with nested statement
> > > expressions. Therefore remove one level of statement expression nesting
> > > from the data_race() macro. This will help us avoid potential problems
> > > in future as its usage increases.
> > >
> > > Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
> > > Acked-by: Will Deacon <will@kernel.org>
> > > Signed-off-by: Marco Elver <elver@google.com>
> >
> > Thanks Marco, I can confirm this series fixes the significant build
> > time regressions.
> >
> > Tested-by: Nick Desaulniers <ndesaulniers@google.com>
> >
> > More measurements in: https://github.com/ClangBuiltLinux/linux/issues/1032
> >
> > Might want:
> > Reported-by: Borislav Petkov <bp@suse.de>
> > Reported-by: Nathan Chancellor <natechancellor@gmail.com>
> > too.
> 
> I find this patch only solves half the problem: it's much faster than
> without the
> patch, but still much slower than the current mainline version. As far as I'm
> concerned, I think the build speed regression compared to mainline is not yet
> acceptable, and we should try harder.
> 
> I have not looked too deeply at it yet, but this is what I found from looking
> at a file in a randconfig build:
> 
> Configuration: see https://pastebin.com/raw/R9erCwNj

So this .config actually has KCSAN enabled. Do you still see the slowdown
with that disabled? Although not ideal, having a longer compiler time when
the compiler is being asked to perform instrumentation doesn't seem like a
show-stopper to me.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200526120245.GB27166%40willie-the-truck.
