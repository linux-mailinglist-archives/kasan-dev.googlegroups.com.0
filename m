Return-Path: <kasan-dev+bncBDAZZCVNSYPBBCHNTKLAMGQEVDI4JHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5AE156A006
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jul 2022 12:33:45 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-101be2b197dsf11677935fac.4
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jul 2022 03:33:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657190024; cv=pass;
        d=google.com; s=arc-20160816;
        b=GyC1F/KPTplFhlX54THL0H1d61fpHbBEU28NInooEZChsdEDH2Kyj1JWKM0lLVsetl
         +AGfomN876GLxo/Q/W2ha4qihzv1WawTUPqFUisDfyf2Le92t05ApAqqRnXQvlEUydZk
         dcYpDLnwX1k51AlqRtb6/icJIpJQcCg4UPP0OO3wiNqGKaaocZ4p813xtEUZnVuLSB8g
         xoNt+SB1UTkwDCWKK1LHS3TwTiqdxo/SGMRquCdcRON7sjunA9AwuCgoNC7kzZiRGCme
         7T/ijTFM2nk8u8E2nulbuBoA+127IsMw9IBS2Ff0CgrItmq3J7ONGmv1FNsIvDsgQEHy
         M/Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=NM4wRZj41/n+xNB+uOb2hUiI4bk9JWlgvaDYrMuJ41k=;
        b=MWPFg4+vXR2m/iI+drXyaKpWl2fKiRm65tqL/mf45LiIW8ofIVqLU3N7XYiTK9z9MN
         y+sTXYA/aGpgsJw+1Mj2rtmDnGcGfnCZ4vwKgGf07U9xaiMXJ+vYXtHqpYGFrTFEtzzz
         8ElFSSYyjGWaF1nOxFIXzefu3YjmWfpflVI5Knfk+MRJ+kaEOBmoll6lC/aUM3/t68bu
         0ye1WlAxjUWQ0XoMP94V6TVARy8LIYzt9a1BssDDuypF+nB5fs5cIEfS8L0liAj/wIC6
         +mYMe0Wb5/Up1LV1uW7+sc7I3LfdHkX+DRKWUgP22XJHHoltBH19Le5z5tPjwiPZrdnK
         +LBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qd7VSRFA;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NM4wRZj41/n+xNB+uOb2hUiI4bk9JWlgvaDYrMuJ41k=;
        b=Hl4pVl3CXBWKk8YGfqWmSSCGn6M3zZ7anfA97kV3CC6eQqUGrEh0OYBDzoQEduKbNB
         soaJs79GrKoqX2h2QNMB4D7QJb+4gqfAqKD28JcDfHxTdkQqfmeLUB7W/gkrF4yv/5Wg
         LtG+d+Yr/ZSsM3J55eBTzhiRp7QcmHYYOqGsAggZ8V7n0c+TvOxp/1dvbbI48DLpk3uv
         sKzuGtmdisQWYrTXBARxlYWh/1LwA+Il/rosebCtrZnQZJpbkhhvyXsPEIDlXwIja3Cw
         YSBsJS3V487if4HWHkop98ZzjNHDqNC5tzVa8LilV0b+7mMYco/JPQjLTU8snh5S79Kq
         gS4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NM4wRZj41/n+xNB+uOb2hUiI4bk9JWlgvaDYrMuJ41k=;
        b=EiT65zWPide3V148s82f9qi0cEPVyB130s54RE/XZCN1uWfGOk0fcqovcZS1mhfTKJ
         fyRSqBF6WxecCP0HRgMFbbYaSOLmDpkwGASt1r9Z+g4ragf5mthkoN8bOzN0WD0SxQ1J
         oXyPqxwtMUoqBr5/ddKWCYdvJiYWY5kT7wSAS6VmeBgS4jjlIh58+hcVUxNV1GZ5VvCK
         ICuNG4A9TD8Ok2V8siuZPthH2E8icmFjwad7ccQeD5fHPqQpSE4WC+/zP76CQVQ285e6
         dR/rn3yMBVfVzAgDXWGfvaLSk47E2JHU79j3xbqxEZsKWk1wZfKErH5nfz5JKX5szVE7
         Q+PQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8+MuBPQsRd2beDjP3CPD69jtwOBS9I7RqWR8tKDggVpNLFGcgZ
	qkmiGeuE/tWDqs1njPxh5cM=
X-Google-Smtp-Source: AGRyM1sSX+3g0iZ3LUh3JTOz3xmtVo2BBOwvEKD/S7MKgcAyg8PuIbAvn1T78u5hEaRUmndkHK8djA==
X-Received: by 2002:a05:6870:f21c:b0:10a:305a:83e4 with SMTP id t28-20020a056870f21c00b0010a305a83e4mr2295372oao.286.1657190024346;
        Thu, 07 Jul 2022 03:33:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:618c:b0:101:b0dd:89d3 with SMTP id
 a12-20020a056870618c00b00101b0dd89d3ls19108678oah.7.gmail; Thu, 07 Jul 2022
 03:33:42 -0700 (PDT)
X-Received: by 2002:a05:6870:460d:b0:10c:27e2:1de with SMTP id z13-20020a056870460d00b0010c27e201demr2436321oao.7.1657190022475;
        Thu, 07 Jul 2022 03:33:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657190022; cv=none;
        d=google.com; s=arc-20160816;
        b=vDkeomc7bUS+bV3YEsRzJn1kcz1COzQjuy45xd3qK5+x11B1L9DK2/TEhDAJn+NylW
         532Caby+WVSF7ym4fUWQVZRuN/lD+dCjovjeOvk0IjW0OSlVMhCRA2+OCXsqrxZu+63J
         dbIkc57wpxn6RCfKGv/jr8TGovnOB0EXcx/nBtdcHHDkJAcsc2nxoU0vXA9/LGCM1YpA
         TczbK9kiW0kS5ayU6laIUueItMTKt4ahDONxzmxswAEUHFqrqFoaGW/a0gVepWfXteme
         sHEF+BUF2ytnpQ0SIAA7t40S3hqPpLgRMcu9tqN92+Qk8zpuIMEFlC7c43MMSWCf3YrV
         PsSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=thRDoE1LgHx04pp3d2de2M4bjneSix4nATvc6/hnzsU=;
        b=vDn123CaRRM4Ll4J8xRnVbOu5KnMJxeMEcR/ou4R40MggZaHe5xmc//R+SsB4iipi0
         24FS5M5h0IDDYxjtHhlry2HOldphdcsJQVGcCH/kMhhDa5lGvyFG4gDLDQ0SwvdPuvc0
         KAgcjjlm8lG9te5QYLO8CXo3TLLSDtOOT+9NbOVGO1o3URz5x6DwM+QEJ01Jn5uDxKnL
         rRSICN0Jfb+DAAz2DPbICb1zDMVIVcFDnedtwBPU8sAWv2zCG6vnOS9zSN++AmCv9dW0
         2fjjw+N+h0wtVhYqn1/Lv2HOLDZuX+65+t77r7/1uaLGHHtWiKJf2Wmjsm/5Y1o0CRi6
         Wgdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qd7VSRFA;
       spf=pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id s6-20020a4ae546000000b0041b88dd635asi1386408oot.0.2022.07.07.03.33.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 07 Jul 2022 03:33:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 2DC68622B4;
	Thu,  7 Jul 2022 10:33:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9F8CFC3411E;
	Thu,  7 Jul 2022 10:33:39 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and page->flags
Date: Thu,  7 Jul 2022 11:33:23 +0100
Message-Id: <165718731822.1443949.8673222178303126682.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qd7VSRFA;       spf=pass
 (google.com: domain of will@kernel.org designates 139.178.84.217 as permitted
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

On Fri, 10 Jun 2022 16:21:37 +0100, Catalin Marinas wrote:
> That's a second attempt on fixing the race race between setting the
> allocation (in-memory) tags in a page and the corresponding logical tag
> in page->flags. Initial version here:
> 
> https://lore.kernel.org/r/20220517180945.756303-1-catalin.marinas@arm.com
> 
> This new series does not introduce any new GFP flags but instead always
> skips unpoisoning of the user pages (we already skip the poisoning on
> free). Any unpoisoned page will have the page->flags tag reset.
> 
> [...]

Applied to arm64 (for-next/mte), thanks!

[1/4] mm: kasan: Ensure the tags are visible before the tag in page->flags
      https://git.kernel.org/arm64/c/ed0a6d1d973e
[2/4] mm: kasan: Skip unpoisoning of user pages
      https://git.kernel.org/arm64/c/70c248aca9e7
[3/4] mm: kasan: Skip page unpoisoning only if __GFP_SKIP_KASAN_UNPOISON
      https://git.kernel.org/arm64/c/6d05141a3930
[4/4] arm64: kasan: Revert "arm64: mte: reset the page tag in page->flags"
      https://git.kernel.org/arm64/c/20794545c146

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/165718731822.1443949.8673222178303126682.b4-ty%40kernel.org.
