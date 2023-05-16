Return-Path: <kasan-dev+bncBDAZZCVNSYPBB4N3R2RQMGQEWIYF72Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 080527051C4
	for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 17:15:00 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id 71dfb90a1353d-44fcedec93bsf3777944e0c.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 May 2023 08:14:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684250098; cv=pass;
        d=google.com; s=arc-20160816;
        b=S0odIkYI3ixuHP8S+hMtuAbWbs+OpJRcBEKRdl7oCB856ItuH4sedpmWpFpCpu/apN
         MAHgiN9gfFZBswQrKPd3TugnOxLp8cJ/t9hNn7msd5wKrhwniOAq1BS6GIEmhIElGJIH
         Oi00Dj9AUZk5nO3vUpx+4xjJ0pVF3lYK0JmvB6WjIV2e9NetrPZ3SEvb3BJ5Ro9qBaG9
         cqDxItooiSy/IL9vfa9K6YkJEyXRISdEmxHoID0baLSfj4zgtjEiGpqU42bzzXtXtx/S
         cv2yXfVKcK+qo4ldlnoTUsnO0gqcC707mlZrNo/Rq7udMWU+1OyntR0phxmW3G7eB8ML
         3+Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SDALLN2c+dx+hWPe7OQLgXwRdVO/KMrHsz2O0YsEEnc=;
        b=fLY4LkIQ8Ei3Zpk9UtVw3lks+dYv5vp7uI3mFnmMWoNKbACcKfjFJd15d3gcSfvxqX
         hG8zEJIuljxbh9qkIDDRZIs8ZH0W+M9337QG/qn8aQRTZCGNZZi1nBWeXsE7XiK0tiZC
         rFyfWef5ccepqXrNnF1IrZpozS6A1sAVRjv+ANlHqz/R0fwxvV/15nzwY3wx0O6fPO9T
         OXoeCI8FU057OKPFFIt7b0OwbrjzI5JLfHxqB3Lu6Hxfj+4PqrYve9gkK0HCmmNmufEb
         gwQm9oltTONRqzqoejBlowFPA/IGjPJtQy7FyovIWvmmgPvTuqAQI8KWaKXhZszvUCtc
         qyQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MxdXQfp5;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684250098; x=1686842098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SDALLN2c+dx+hWPe7OQLgXwRdVO/KMrHsz2O0YsEEnc=;
        b=ZNBGH2kaZ3FclzY151yAZSoaxfq+D8SQ1t4vx3k2mDUlrGtIgc9tHJHSFEkHCJSpiP
         dUoAWrRa84bRaYoILJnWY56GXEwEOLgJh7aWDktuZeFBvTdZjk4E8ln4LT1va6/4/nyY
         GxMonjyWJF/FO1XDSRorJ5qLrUv8rRkLADsRVXiBqrjChLPwrI+o6J7LwsS1PE7RBRRw
         oMjj1dGzFm6Fa5ZFEAxjU2R5FCkbeS6gOv49mC7eOHnmNBsAh/rnPSkx//FaU51vjrx+
         lI7xfTzfP5x7EQhOf/myskutLWU/b39ry2J5fOLHve0+I1nXX4rR6+yrfFK/Iyokklwu
         9K/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684250098; x=1686842098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SDALLN2c+dx+hWPe7OQLgXwRdVO/KMrHsz2O0YsEEnc=;
        b=bN3AuTCQ0b5q1Xxvvi/hoG2CN5MnH8uog9YSNLwFzzYkYG7f0R3b4GhhcYs7gitMSB
         pb5BJSSPNbhCL4WE1zLmNO5SziiQ8ECIo8/ENDF27njJp+cTK4XiX8dPqrfBSmOJLyy9
         zhxFu/U3NWHH9QUlKbY6peltQocYQT4AwUJArgVhuAuWHdXiPrOFUcIPAedfmzF9vTp4
         0IaqDwYj8kgUTKJq/CwWhsMHRzstJ5ZZk5FzR2NLXalCBLJRRqdayhm3HGY/c/IJk/OP
         EOni09sf7dzPX0ij0MK9B1Bok9i2EvJOrl/HCy0iKoHqFsl4XrgcjlTvnASGamvGLRir
         jhrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwvkUQSyPvCNr78u4Ms4S+2iDM5EwjXj2fZRcwSIqTPqAWtibGe
	2d3RkTu9gI9fSWVu9yqzSxg=
X-Google-Smtp-Source: ACHHUZ7UCsRFj7LCtoPuVAyoOMLhLd4YqbBXkM5Up7F8bUr95OWGKWf2h3Ew3ikcM2EZp0s0M49kNA==
X-Received: by 2002:a1f:a794:0:b0:446:e444:a0f with SMTP id q142-20020a1fa794000000b00446e4440a0fmr11277817vke.1.1684250097968;
        Tue, 16 May 2023 08:14:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3347:b0:436:1e7:5141 with SMTP id
 j7-20020a056102334700b0043601e75141ls6033379vse.1.-pod-prod-gmail; Tue, 16
 May 2023 08:14:57 -0700 (PDT)
X-Received: by 2002:a67:fe14:0:b0:436:eab:99f4 with SMTP id l20-20020a67fe14000000b004360eab99f4mr11872221vsr.29.1684250097258;
        Tue, 16 May 2023 08:14:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684250097; cv=none;
        d=google.com; s=arc-20160816;
        b=L3WN/Wl0FwxMKZdeZe4b6Hjg0hr1q5H1s+96Cp/9mPCSOym1zG9C5vsEH9Zall9vO9
         cHskz7PZ48V9W378s/dFdfqSXNqY+XfzIZ4vPd2SxSUvAfmkK64LoWPbEcOCsvxufkXC
         97T8hcKsIFP8QhuFVHCGbymtlPF+0Y95I21gxxQyLMGs63jfeP2lOeaZaDOf7IjiZQ2W
         cpMdZ64fxoNkcOBug3dO7JOXFNYwe0H0gMcioBDCmr/QPZ9aJoq+W8u+p36GWrsRk4PQ
         1cBQXBWgF0e4SBmA7Tf3+jX2xPfDN0jrNj/noPl73LFIfyAOzdRhPRgniIw7Tiq6nUps
         xI5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9pg/NV3cyWxiUO0D5ryGLGo7gE7VnA/NsAGcEMnjMS8=;
        b=OqmkpFNUqRifAgd55oki/yty+icpmjx4BOOQ662NDlGibY5EGuaV5jiR2/fytp/oG7
         vlBsDCDZ6K9QR2zVdnIsGf6gWMsM4XPkUN6zLAWyax13p+HHZwQC9Zsmlf2O3YAyS7Eb
         jab4P2cObHtc3NAevzGf/cUw0izUMwDik72ddS8J7kDm0hwUWM27nyvgfUwUAM2V9BXv
         +QTiygsnhFLjBWPKSgymOnv4ds+U6tCw/y6EW4fphKGMY1vic953UlcEg5mWBvCxcTKY
         FkZm5LjOnJPLVwsszpmBMBpTKckuEa9RUpwhxMlEnUm+YcXxBWqFSH5ly4yDu3pm1lgP
         9WyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=MxdXQfp5;
       spf=pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id t12-20020ab03c0c000000b00783db9d50d2si281658uaw.0.2023.05.16.08.14.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 May 2023 08:14:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id BC6A562A54;
	Tue, 16 May 2023 15:14:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8115AC433D2;
	Tue, 16 May 2023 15:14:53 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: andreyknvl@gmail.com,
	catalin.marinas@arm.com,
	Peter Collingbourne <pcc@google.com>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	ryabinin.a.a@gmail.com,
	Chinwen Chang <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com,
	Qun-wei Lin <Qun-wei.Lin@mediatek.com>,
	eugenis@google.com,
	vincenzo.frascino@arm.com,
	Guangye Yang <guangye.yang@mediatek.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH] arm64: Also reset KASAN tag if page is not PG_mte_tagged
Date: Tue, 16 May 2023 16:14:42 +0100
Message-Id: <168424553500.607599.5644733830720198100.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20230420210945.2313627-1-pcc@google.com>
References: <20230420210945.2313627-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=MxdXQfp5;       spf=pass
 (google.com: domain of will@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Thu, 20 Apr 2023 14:09:45 -0700, Peter Collingbourne wrote:
> Consider the following sequence of events:
> 
> 1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
> 2) Page migration allocates a page with the KASAN allocator,
>    causing it to receive a non-match-all tag, and uses it
>    to replace the page faulted in 1.
> 3) The program uses mprotect() to enable PROT_MTE on the page faulted in 1.
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[1/1] arm64: Also reset KASAN tag if page is not PG_mte_tagged
      https://git.kernel.org/arm64/c/2efbafb91e12

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/168424553500.607599.5644733830720198100.b4-ty%40kernel.org.
