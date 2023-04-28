Return-Path: <kasan-dev+bncBDDL3KWR4EBRB4PVV6RAMGQE4QXILZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E4E96F1D0A
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 18:57:23 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-18f16a11821sf13016484fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Apr 2023 09:57:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682701042; cv=pass;
        d=google.com; s=arc-20160816;
        b=jSqU8yZX2yZUQ4BUCSGVStGeQsJDjLuYOKHFTw/k0tXUa9p6yFzmTwX6GZFkxSCoEL
         orBWzj8ULVKk+Rn5gouNq20OxF4tKJi+eh28Omp/ycg4k3+TNcJOESUF7sBF96R3h5zQ
         XAl45D8X5uNtUzqxxb1LA1/xEZOTTMG4RPu2zSrRpQyDiHv6tVOdIeTx2vSreXBVRNqV
         ZAeaja/bgr8ep+4dtC4J74TAJqzt1b5tWcw84YpjGtvwupMgFCu9owZBj9n23deHDxms
         B+zAixM46aLR/6XYU0XOJZ/eeiRNPAyu5e9gGWxetgxIy9+OqbKELGC5Ml6frGWHUiHZ
         smCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/jCA/pfQnid5baZvK89d8XMfuzz7Kjth1H8CCxXIOAs=;
        b=DHaxoF7FUYAm/Tl9G9kUofYXDB6+3fgoG+F2A2SNE/XMoPo3Ux3YmrXFKAp46+jm1N
         6C8Fe3TjdKKZPhyhGBqD76PIyYMqR4jEuGiTiKdPq1a9uzxeV5r2vAr22qYreuihMA8g
         GdYCdOuMAkxBIs5kW4+YMcZdWzTNaBdalb59fZBcqqjyB5N2x0m+rQ5p72SIbx/3mN9+
         P1U6PEy4UbB99yDuGqSAi1q3syvv6skMe38PkGJya+8kKZWSpl6NheHzx0Frjli4Eobi
         NmnfnvGKsDR8/jEDfTLo2AKLoVTDa9bPENBeIcRz5Ji2kUOy0gNwN2cSBOkpjvTgOthx
         3mWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682701042; x=1685293042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/jCA/pfQnid5baZvK89d8XMfuzz7Kjth1H8CCxXIOAs=;
        b=sT0ETso9ZCWNbhlg9K5G/WJDpjWhg6VZuOICk9rpmAZ2F4Sn84Ub+yyztj9V06RXxN
         10rxDSGfZ8mV3SnG0AJdxIeqgKJk3AN1sOR0qcbyXh/K4UiL49vfWYk6FKC5k36eQesF
         mDK82pV8QoK8YazR+9ICB+E3OPhBkkqN6qtRy971Cj5HkRSlVhJ+ZrlB+Fyp3p0iJuJ+
         qeQH6hNJFNx80kvYCH+Z+oSK6w32RLyVLnyFntu3GFrt54nJ6ImNbPV5EJ0etIm6/dpe
         LuULJRWM3w+DkSoj6+UTzLiHxZvGk0ULSCRtz3NvMiAu3O5rJ8zJy+KJfneiZE9vX69N
         c0kA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682701042; x=1685293042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/jCA/pfQnid5baZvK89d8XMfuzz7Kjth1H8CCxXIOAs=;
        b=I4bWT9UE1SNJGVTP+IYM/YJn8JIuuApP3lkp6Yi7aJJvVEMabNZgjNJdUOh8lVkCbl
         yqM/4QeMHU/gcFvg2QdTd/hg9UerEBly1ZrRbXbu2CniuKAjJ7wVt7pG2/HrJWhkX0iC
         1AwNTkAuqQiXBerghcXYboQ7K0wX+M6Yi3jXPwnq//os//ebA3q4zQsu22N4eU3i2GDK
         rcHuDAhETsBttvDbQ+oFBboDp/jvOnONpkEK41UfNWq3VSMOAs9hIKYBp4+5HAj0r5G6
         at97djQV+jx8cqq6dGybsuICwARIz+w1BXcIh1xxpN9vCOSMrDBOaTLw6okgWFB8XXs0
         p7HA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwShuVno+85SBe8Y10nugdMdUWPFQYKHW42gw+6gprmqUonnNvM
	29Xnt0pI3DyGiUXebqoBTg4=
X-Google-Smtp-Source: ACHHUZ6OyEPAWHeu6AmaHfHUuuzUbsSHN7DqnkIwgS30YoPY1hbMWkZYocsh80EOoiPFIzYCkE9vmQ==
X-Received: by 2002:aca:a8d8:0:b0:390:933c:80bc with SMTP id r207-20020acaa8d8000000b00390933c80bcmr1262541oie.3.1682701041947;
        Fri, 28 Apr 2023 09:57:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6305:b0:6a4:2aff:59e5 with SMTP id
 cg5-20020a056830630500b006a42aff59e5ls854553otb.7.-pod-prod-gmail; Fri, 28
 Apr 2023 09:57:21 -0700 (PDT)
X-Received: by 2002:a05:6830:1bc9:b0:697:bcfe:43b1 with SMTP id v9-20020a0568301bc900b00697bcfe43b1mr2953876ota.15.1682701041360;
        Fri, 28 Apr 2023 09:57:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682701041; cv=none;
        d=google.com; s=arc-20160816;
        b=iYJngAS/7jXnYJmiNDmkKO4JfZPhydlgUmsdjHs28cKyzG22Nia2R+2VnfxToVOt5l
         ilenFQMUoiNpAkyojMilvtjpr+N5by/UpwvU2V7y6jjc7swwzY89Bm8muu23XvL7D+pr
         aDix21z6GknZdz5krpamJGrvDAkzeFFID8O84TNx8W/HVblCcQaI3JkkUyTtVpCAv3Y7
         WmGnEQiwbipPCJ3PIe+WOEUgPsl+cV4Y/abD+Not6B9HonpvVIjVnWC3hl59oU7gJ6xz
         Lp0SZVWBnM4u3Ri3epO+xfz7hUkzstPuMoQxXjZz/69EXrGduGok4E1SJpgsmnms0XWO
         q52w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=XcMJhcdwz9SdTlY3hewkIQP7+9SwMXkq+QLdtFEr/GE=;
        b=pl7ZG8VLivw6eytNuBfGxs2/R93CrTqU+TPypINOFgyBUDU9zxXba1brgqK6W4QWQM
         cdKdyBieQpIDk0drn9ZXTufuc+tnl45BvCivs86JXEMZB6Dymuvv5uRzqhPJSAqzJGJC
         LL7SJlM8Uxs3jjcW2eLHmDcR54kQb67Wm7l1aKmNXxyx9OK+XcWz4056g2xWvXLIBm2q
         HVy56+gojSPKOk4aAwh8hsw6KfLk2xl+EhbFKzO40jH5lT1By4GRrymuGylHcoAK/s9Y
         UZnPNF20klBpZpWTweA4ZiB4zx6RllNM92+aC2djzzkkYSDyVX262iD8bd1d+cB6kuPn
         q43w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bl10-20020a056830370a00b006a5f12c714bsi1949456otb.0.2023.04.28.09.57.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Apr 2023 09:57:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 22B4A6449D;
	Fri, 28 Apr 2023 16:57:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 5F523C433EF;
	Fri, 28 Apr 2023 16:57:18 +0000 (UTC)
Date: Fri, 28 Apr 2023 17:57:15 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Peter Collingbourne <pcc@google.com>
Cc: andreyknvl@gmail.com,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	linux-mm@kvack.org,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com,
	linux-arm-kernel@lists.infradead.org, vincenzo.frascino@arm.com,
	will@kernel.org, eugenis@google.com, stable@vger.kernel.org
Subject: Re: [PATCH] arm64: Also reset KASAN tag if page is not PG_mte_tagged
Message-ID: <ZEv66/xJQK1eNRpF@arm.com>
References: <20230420210945.2313627-1-pcc@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230420210945.2313627-1-pcc@google.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Apr 20, 2023 at 02:09:45PM -0700, Peter Collingbourne wrote:
> Consider the following sequence of events:
> 
> 1) A page in a PROT_READ|PROT_WRITE VMA is faulted.
> 2) Page migration allocates a page with the KASAN allocator,
>    causing it to receive a non-match-all tag, and uses it
>    to replace the page faulted in 1.
> 3) The program uses mprotect() to enable PROT_MTE on the page faulted in 1.
> 
> As a result of step 3, we are left with a non-match-all tag for a page
> with tags accessible to userspace, which can lead to the same kind of
> tag check faults that commit e74a68468062 ("arm64: Reset KASAN tag in
> copy_highpage with HW tags only") intended to fix.
> 
> The general invariant that we have for pages in a VMA with VM_MTE_ALLOWED
> is that they cannot have a non-match-all tag. As a result of step 2, the
> invariant is broken. This means that the fix in the referenced commit
> was incomplete and we also need to reset the tag for pages without
> PG_mte_tagged.
> 
> Fixes: e5b8d9218951 ("arm64: mte: reset the page tag in page->flags")
> Cc: <stable@vger.kernel.org> # 5.15
> Link: https://linux-review.googlesource.com/id/I7409cdd41acbcb215c2a7417c1e50d37b875beff
> Signed-off-by: Peter Collingbourne <pcc@google.com>

Sorry, forgot to reply:

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZEv66/xJQK1eNRpF%40arm.com.
