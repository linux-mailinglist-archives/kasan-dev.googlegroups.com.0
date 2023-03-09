Return-Path: <kasan-dev+bncBCT4XGV33UIBBZPUUSQAMGQE74RMCJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id AFBC96B18E0
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Mar 2023 02:46:14 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id m5-20020a2ea585000000b00295ba03f905sf95932ljp.12
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Mar 2023 17:46:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678326374; cv=pass;
        d=google.com; s=arc-20160816;
        b=dVJVhBlpMvzkAd74LdWq/2Zh87Pzhv2LsG0Pr+jtI/5qa+1sHx+AUHCvXqlrv6o/P7
         UxDH4/IqxOBMQ3x4nGGzWBDuyxzco9EdFCvyPI8/lwOpHKdu60LajjXCY1Z2qpnihN18
         ZsUK/eRBSqquS8Gv1Dx4mst2ZX5UVW6QBsDEhI+7FAaaC9AAeiNs5GJvund+RzAkzUDH
         vm5GwUaAXTLptwkgkmWBzIdoJ+zXytygYmi4MmGKp8DNZtLb8aeQczmLCfINyBaRIBNK
         mzsNC5G71BdN2CGMJFELM5Yl1LDIxqPANONKeria6iede7gn8p9lwaOZnkcVwjQaz2r8
         JoXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=5974A28zl8ZLn5lLC6B8nWsX3BLPFzSpJoRFnGdk/mU=;
        b=TLktBOL+tQxf+oGQdQPbLVAIn/rMUsx6Rf/2dHsM/e4OqKCtYMIQp1EV7qrf34F21+
         Zp2foJsDCCg1klnjjaDyG13qsE/HD1RVf2FMxOx9qhotrE+kGBIx7RFThmxmINPMGu1m
         +I6AdYx/EFbO11l57d43WJqwd1uIRSxTreMBuVdJB47gVI5WDtyjDoa+l7donxRmSk/V
         /8w+MrwJ2EPJg3TBNHgaaAmVY2gI+wd9Gg/4BZ7P1+K3nGGe7ZsOtnqEWoCBid6qbfOk
         /zuQGKQw3jqkn4iPO2FQvho+9XV5qJQQECotHbkmLY191/0Yc8dM/my+/WddyRGoDu0y
         n/tQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uL4ubQEs;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678326374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5974A28zl8ZLn5lLC6B8nWsX3BLPFzSpJoRFnGdk/mU=;
        b=SgG1WPUtBDmoR1swH2LAdEXQ2+R1SfpGzWY/2WNrHO+yF6qnfYj7bt/clCvZgyE52C
         G6n7olBa2vzlg6ZM/qdBEGpM5EKe8BY8MIwAPLVDP9zAdw8mzbZO9miSJI8Yg1a2o26R
         y8TIBEydbK8VcNN6Fv0GOMB9vmHoqV1zKZ2bFmUnlfOzibMzgsDdxlAsQKdf0eylifDR
         owT28jo7J+7fAVCyy3/IQkr54FL7FLI9CncUquajcMKGCqG8M/kapRsJHSiGf3RhTQjk
         hmx96B43r79dRq5juj+zATxeyPWbthPL0cG4RfAAfyB1DzG+gi+/HBDN09g+CkAVJxz5
         ugeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678326374;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5974A28zl8ZLn5lLC6B8nWsX3BLPFzSpJoRFnGdk/mU=;
        b=aKLKOAozH0Plv/1Uc1CxTtRrQ80pqx0y24RrODlgZvgTyIrKmUhKnV3erlSGtT6wvt
         iNryG4vfV9voesUeBUXqjXo3dlRlI0SK4/6duEdShH3r4C6eXo9GCTK7RFpkDvKW2j9c
         5kXoqlEU7Ii9LNsA2IRo35bRYDS9+b0J3+zNuwdTrFt6FBycLeH5GgSs5vUd9WOsYQ0w
         /JS698jTrrbrvhC4tfHJQurBUiNMg0waaNGsZL9nUdJCcnwkSX053RiL3ckFVcDfOgPK
         hNm28RCGxPNxw2gkIeKnX+1us2xy0TYEM4BsbJQZdvmuOd3BW4Q4XmXK8nnguyiBLqva
         J4DA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWRj3iJa9lS4zVQ/e88qao4irdhbuibmo6xUg9rKJnUzOaV+MTL
	lSDEnPMUtqmpSDMShe5tOVo=
X-Google-Smtp-Source: AK7set9CLPfqqMoedJILGHIoQT6JEBCjbeIIeGtHSn/yb7aVAL495dWMNeg67FUseF0AgFOGIiSBRg==
X-Received: by 2002:a2e:a269:0:b0:295:ab47:119b with SMTP id k9-20020a2ea269000000b00295ab47119bmr6244485ljm.8.1678326373790;
        Wed, 08 Mar 2023 17:46:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2313:b0:295:e6f:9742 with SMTP id
 bi19-20020a05651c231300b002950e6f9742ls87283ljb.0.-pod-prod-gmail; Wed, 08
 Mar 2023 17:46:12 -0800 (PST)
X-Received: by 2002:a05:651c:b1e:b0:295:ac11:4ca7 with SMTP id b30-20020a05651c0b1e00b00295ac114ca7mr9609089ljr.48.1678326372014;
        Wed, 08 Mar 2023 17:46:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678326371; cv=none;
        d=google.com; s=arc-20160816;
        b=pGJV8ggfzOy5AbPvg1PgDcR8S/2a0vvds/dgYsoiH35P1mHwvL0adXOpP/rkwgytms
         fV00hO8r+XEpt8nnpg8s9gnAENOuCK1oLr1yOT8OKtt79eU/PfGkdxO7Fj77scwTgB7p
         qtvEubg4a33MfbVT1LAlVS0jGnv7yjxswBclBIOTCs6h8lDNCxzhikJVoidWEOb7Pl1u
         ohLIjdU2JbY+DpnkpuSsHqWHMcwIeWP2yjCDpN8ayRsQMFyai/IEvOWn0cyEk9eO30i3
         hi9uMrdduUG6P7DDZ1sYa/+X8Rd6ygdTnEq7YIumTW4eHsMmdE+7x4ffiW02s0P/d/eS
         Kyfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=U7WssmwuYoL+mnLABjKnCya6V8qhxM+OdHYoo2RCgOg=;
        b=XqomcgnU7d/AVNAN2AYULbJw+An3dST3AEtKpUNT/o8WP4rv3JTtsI9OWx3ugbZCLU
         fe5DiwZtcKmaOF9x47HFIgX6PUVwryKmjex3Nxzfc/GhFnQF09L7FL/MgbeiUbbI1uzs
         iSDLiNVy8BtdjC/Viy17Bd9/du4APMeWJPWiX+Cd0A9by7qWpjjpmbBEPx+Nnhy4iXGh
         TXZKRb6hJ4ORykjfn+9Up3meQcGsCX3IQ72o61KQhFDRYw6FkeXZjo1Eh2hsrLBwPa1z
         StgM+QG9Ryk1k72T2XMzxwGl13ungbkv37OrnWcqDKkNi6ufVEzsIzHJj9oLd8u+RjGO
         y2kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uL4ubQEs;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id y21-20020a05651c221500b00295a08c1798si703894ljq.1.2023.03.08.17.46.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Mar 2023 17:46:11 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3A0D9B81E2F;
	Thu,  9 Mar 2023 01:46:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 96788C433D2;
	Thu,  9 Mar 2023 01:46:09 +0000 (UTC)
Date: Wed, 8 Mar 2023 17:46:08 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Peter Collingbourne <pcc@google.com>
Cc: catalin.marinas@arm.com, andreyknvl@gmail.com, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
 linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com,
 will@kernel.org, eugenis@google.com, stable@vger.kernel.org
Subject: Re: [PATCH v3 1/2] Revert
 "kasan: drop skip_kasan_poison variable in free_pages_prepare"
Message-Id: <20230308174608.e66ed98c97ea29934d99c596@linux-foundation.org>
In-Reply-To: <20230301003545.282859-2-pcc@google.com>
References: <20230301003545.282859-1-pcc@google.com>
	<20230301003545.282859-2-pcc@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uL4ubQEs;
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

On Tue, 28 Feb 2023 16:35:44 -0800 Peter Collingbourne <pcc@google.com> wrote:

> This reverts commit 487a32ec24be819e747af8c2ab0d5c515508086a.
> 
> The should_skip_kasan_poison() function reads the PG_skip_kasan_poison
> flag from page->flags. However, this line of code in free_pages_prepare():
> 
> page->flags &= ~PAGE_FLAGS_CHECK_AT_PREP;
> 
> clears most of page->flags, including PG_skip_kasan_poison, before calling
> should_skip_kasan_poison(), which meant that it would never return true
> as a result of the page flag being set. Therefore, fix the code to call
> should_skip_kasan_poison() before clearing the flags, as we were doing
> before the reverted patch.

What are the user visible effects of this change?

> Cc: <stable@vger.kernel.org> # 6.1

Especially if it's cc:stable.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230308174608.e66ed98c97ea29934d99c596%40linux-foundation.org.
