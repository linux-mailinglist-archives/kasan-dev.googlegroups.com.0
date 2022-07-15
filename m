Return-Path: <kasan-dev+bncBCT4XGV33UIBBNPSY6LAMGQEZBBWMNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id ED1E9576ABF
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 01:33:09 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id v123-20020a1cac81000000b003a02a3f0beesf4956703wme.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jul 2022 16:33:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657927989; cv=pass;
        d=google.com; s=arc-20160816;
        b=WWK6Eyibos5jcWJUWyG++Zos4gLdx6TiyjhkG6/pbnvBOx+YytxJfgMBMgg9Mmn3QL
         hYF5hbPRLqCShrN/i57pzdM8QmJx4Yb2I85ciUhaohH1XWTEhkGLUQflVeZgyO2d64mJ
         rzcj+gq3DlCxkuF7//bx28Fge8eFwHxbX3ghfJJW2vrTpmmwps3xE2ROrf+Dn85Il8+l
         2jGLGq//yroIz6jDDcYP/vfIpGs0aO+faH2OcPF+UZCcGi5cQzBtkbHO0C6BrKjGDQuK
         hdhK48Ny9ZeA0kiWiJSKB53/ZiTIPcKbq7bzPXGYD+a5Q4zqwsDYDeC8rfBMtiqox/g6
         GAKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=srsqoqbdFe5iCOIAQACmsm1PqyELz49hkXWP3UyVbRA=;
        b=U4Y/oyPNZkL3CshC7aBfayOD8s5cM8i1p0oX4kUPV90bvLz9/E4vkGaaXhjSloPWbw
         fwoem2b4fAv5S9mZSrV+KGYMdYkQn7XyY1rvOvlsjh+UhJ8E+/d/V6ZsozK5YG4dlrcn
         f3mLJt/E8jRs0FTybexPVW+Fd687kxqP/K/OdaS6I22hkj5pOSL0TPCaYssQC1ogwzgi
         jgZrzVjohwCgF/oNaqq0bweNvnSr4kPrDnU18nxSugJHsKbuWQAVpxJpRRx0++w2uoTA
         MuiLkyXDf2gvGQ0p+V/khvDAHtKelilOvHpmQ9fNYpipV9xnc4cvBVmInq4Hz70ulIZf
         WoPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="FEnapZq/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=srsqoqbdFe5iCOIAQACmsm1PqyELz49hkXWP3UyVbRA=;
        b=Xlc0P69RWJb6C4iUgw9Pv36Zvd7RbjBaPuNDUbnllZHszEy5LFdxIKHKK7KzNAI7X2
         2FJlyinVz2HH5YA6PnMN3Sc/xXLyw0JfczWv08mP2316FSzQwFv2xJOTUp1nWkZEjORj
         gAl2T1vi4S+4O9N18w2LT9hZmlrbVgWxBkwOucjKCY+3DnHiR3eRPDtbDUxSKLVzmqSx
         RBh2RIMPsQYaN8carA3wnEcC/QD1C7rj1XoE2aUDg/sYcyTGdPBV1LQegUyvq6D/oqXt
         LI58mkJeUaSpR6+1Yq5EDGafHVDkZFVjtJKVpWyhBfQRRHgl4EuhlH6HTaC24OdVt4jv
         N3XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=srsqoqbdFe5iCOIAQACmsm1PqyELz49hkXWP3UyVbRA=;
        b=5+QhiU3qNImq8IGffiZ4A2ogWCtnFJz7WwarPtNGc8COGQDKebEybrY62ymxtGKz3b
         N/j2lqwyGB8DOCm7c9jSK4lUq7Zs54LMvdcqqZ7jIxFTwbOXgvSfC9Mv9eA7YMy3yQdt
         wMlpJ7TZWX2lkbR86sfU/LfSO/G6RyOxapFFG8P7XSiZPn2eYqAFgSiYVg3Ty4Tx5ZFw
         MlqGE6ZINN3TB/zFjDeZ1KbZMw245qwLjryxL5Qfsk91o0kAtvszWQRIXwkrrzqpTSoY
         0CO5/7rCqEDOVNi4A164JUkHVWX+Xzg5zOGQK1qAlEO6+V7LX+O8RRb1C6411ENudHTN
         gfzw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+OsXs/ZYK4Fn/AmROYGckg/IEhWfsmZsL/j8OExomY20AwsVuM
	UedafhncRPQffCW6296rlyQ=
X-Google-Smtp-Source: AGRyM1ukHtmmMXJ4KvTYQ4egLPjTFzMD8q9hCBWYmIiDBw8FFe7gWT5xjuPg/VPsvGlUm1hGCFUR9w==
X-Received: by 2002:a05:6000:2cc:b0:21d:76d8:1f2c with SMTP id o12-20020a05600002cc00b0021d76d81f2cmr14316427wry.471.1657927989295;
        Fri, 15 Jul 2022 16:33:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1ac7:b0:21d:ab25:25ba with SMTP id
 i7-20020a0560001ac700b0021dab2525bals350281wry.2.gmail; Fri, 15 Jul 2022
 16:33:08 -0700 (PDT)
X-Received: by 2002:a5d:6d0e:0:b0:21d:6d4c:e0e4 with SMTP id e14-20020a5d6d0e000000b0021d6d4ce0e4mr14947797wrq.355.1657927987988;
        Fri, 15 Jul 2022 16:33:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657927987; cv=none;
        d=google.com; s=arc-20160816;
        b=merHiqv5qxuQmMZzT1a5ZTFqGwh1qIu3vKV2riZDxDIso5uaVTO7LbEr/kpHfN+jYS
         l4gOzYEmhTrQX6bNxNS0uOGF9mmc2cKwZ7j1ASWHanXSQHjak4R2Odz84KoVe/BcHWhB
         CkBwtKJnL9r81zFTAooAxWupqINEBNEEWWvbARylfTWAlzGmwxTkp0QQ8jYhOizyhhGI
         pc9J/13POly225anT7nGNyDWrGFNIOqXvkS+3wkW6rQSLSeRpLRPD2aSEwGVL3bBvzI5
         IAqLjGTfIh0F7HkN2SeUImCAwphJDHjOJhY5ijLN6wiijVCeeiGVIhMXDqlJvtj6hlSZ
         ZzLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=wsCJf+W80m4JnOYQTNwvFXoXyL6yxh+A6mqqU7DJVBs=;
        b=OAh5Ml/M5CcEeUNwuLf9PclJ1+k8b6pJuRnk5AqimQJaWvp5iYmZ2Zk5i15fuWPHwU
         ker8mPYl7nMZVkslHIXZLFE4iXfY2LfDy9QztHJ9YWEt9cGCWh9gomrj2yadLyXDGlop
         4m6nt0l79gortDwjnxbj6K0i+1xQa8JPLOX8QZVxtSUKL3Vt8AdAh5Bk/NUP1P07y/4E
         ueJb7hpi0oPiiXfa1kgJY6KvNRSJO550TADOTWxXpGQn02QZJCNZX/OTNMUcCA1oWvgJ
         FglJ5iiXQMs3YJPVg0NR0xSSUp5k20higBqBRx6J3IfunC49f5tCQ+oH60gsqmaGksy+
         aeCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="FEnapZq/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id 1-20020a1c1901000000b003a301c8876fsi166730wmz.2.2022.07.15.16.33.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jul 2022 16:33:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 96AAAB82F01;
	Fri, 15 Jul 2022 23:33:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D5B59C34115;
	Fri, 15 Jul 2022 23:33:05 +0000 (UTC)
Date: Fri, 15 Jul 2022 16:33:05 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: yee.lee@mediatek.com, Linux Kernel Mailing List
 <linux-kernel@vger.kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>,
 "open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-arm-kernel@lists.infradead.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-mediatek@lists.infradead.org>, Marco Elver <elver@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
Message-Id: <20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
In-Reply-To: <CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
	<20220628113714.7792-2-yee.lee@mediatek.com>
	<CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="FEnapZq/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 15 Jul 2022 10:17:43 +0200 Geert Uytterhoeven <geert@linux-m68k.org> wrote:

> On Tue, Jun 28, 2022 at 1:42 PM <yee.lee@mediatek.com> wrote:
> > From: Yee Lee <yee.lee@mediatek.com>
> >
> > This patch solves two issues.
> >
> > (1) The pool allocated by memblock needs to unregister from
> > kmemleak scanning. Apply kmemleak_ignore_phys to replace the
> > original kmemleak_free as its address now is stored in the phys tree.
> >
> > (2) The pool late allocated by page-alloc doesn't need to unregister.
> > Move out the freeing operation from its call path.
> >
> > Suggested-by: Catalin Marinas <catalin.marinas@arm.com>
> > Suggested-by: Marco Elver <elver@google.com>
> > Signed-off-by: Yee Lee <yee.lee@mediatek.com>
> 
> Thank you, this fixes the storm of
> 
>     BUG: KFENCE: invalid read in scan_block+0x78/0x130
>     BUG: KFENCE: use-after-free read in scan_block+0x78/0x130
>     BUG: KFENCE: out-of-bounds read in scan_block+0x78/0x130
> 
> messages I was seeing on arm64.

Thanks, but...

- It would be great if we could identify a Fixes: for this.

- This patch has been accused of crashing the kernel:

	https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020

  Do we think that report is bogus?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220715163305.e70c8542d5e7d96c5fd87185%40linux-foundation.org.
