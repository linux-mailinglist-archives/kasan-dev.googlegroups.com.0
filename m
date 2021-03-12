Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7H6VWBAMGQE4XAGGKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2088A33904D
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:49:34 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id e21sf12269759oow.18
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:49:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615560572; cv=pass;
        d=google.com; s=arc-20160816;
        b=dRTkUZZjAEDS1hzoZiyGWXF6vq+FWLe/EjT3bt4kG4BXp5LdOUyi0enyyTec1/aQkY
         QmD3sGpcd+fsQ3RbG3tgfHsFxFi8A+cvQQO8oUKL+v0tXshdl9rYER2TxxOGMma962Qc
         l1omz9cY9gIK6hgvIEGZG4+wqJETtPDBl7zabFva3bZyp4UJL/w0zHAhoqDtVWN+ivDo
         YWtAO1w+tPZQCk7EnOfA/qS7eB6SH2FBuE6nju6PYa6kAh99mdXynL1oNIGuNOvitB5c
         GSjUOPfIN3jmHfd4CUPXd5wZUrlWh8lE3kqt0/pwaNHnwonN3H+/XvsTZ7NRjI/3Gmgi
         RYvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qsMnmdggsF0kcZBKGWTmdQOpYssExRcki55PY5dbHgE=;
        b=PVCVlGYailOxr+MhLaTAGd4Huy14zn/165RxBw1F1FV7sFAo6Z9lk1+Y5I/Gpk3MWG
         wfLYbbk2y2+JFBBnTeI0CFZLoQDLZXWyBW7+4mIH7MgJNCioG65XguCs+MQP/RJ3dNra
         tH+lq9hgfGZxlQ79V6asVloQZuYA6fB8Sy3xAr2yi6MdmhYVgm6sbiyYj/rC4SIly8DK
         0BmcJZDIrRH32WJHA2rDtxE25wgcJSmNDw2vNTyh6HDFLnedI+bT0puFXtXDUbNnt8JR
         bpQkUfp32UY9V5vVj/zfzxtKUSYRuPGEGVnzrVb6rIfed0yTOzv2Y8EwoLT+tjOoxEq6
         6yPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EnmQRw2L;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qsMnmdggsF0kcZBKGWTmdQOpYssExRcki55PY5dbHgE=;
        b=evhhW6fYlySqjOrd/WVTQhsoXROlSdy3Hl3X5JvbVy44CxLdgOxHEZxon3yBtGqVIF
         Ig+x/0n5cc4eypDrE/6NCY2AOaN0IDnHcuC/jWVIhsFfjXYdGWblZG/NdMwHthoA44nc
         r8KODmcxP2oKbb3jrX0Fd3Tt44XUXv257bPIKiOyL+zKV/qXY/zrbtVZ6SSgb4E+zXJR
         3RvBSmGKT79JjocknaPLB5JVLBirLbgU9OV3+GH5HQ+gckuJ8FRDiunUsiwva7UfPPqX
         bgIEItOPOIMG12jRhqfxnWpDajKBW0r0ok4UIlD9yo61xdH0Rkz2fkUfyQZQnW6KfnD5
         ouXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qsMnmdggsF0kcZBKGWTmdQOpYssExRcki55PY5dbHgE=;
        b=nkLwXKAu48TLYu5hhFn/CkNXOhZQ1Rz5KpBvx+E7xLsoQkvNZ2L3ZA04z/ZA70oOQE
         OiGHYohaPNoc+nzxcx7hzS6iUoMnXqm7dVQNB+l/F4AopgnH+V/+JS3yYb0k9DA8VVZF
         JS3kWgQa9bik2GcTt/JRDZGOpnE8eGO3q3TNgJtlJU7cPQxqgqw4vDuquOAB6VaQEdCm
         ZOmwhCvF4vSYtIVHEq41fPeUfdUfIiI2e8NXXT2sAW19e6dcWFBZwhPgRgFteM8Yuefn
         YgODFgeiRDZWR9vEbMpJH5I5YWkjABrpc5NzKkXJZOhp4JFIApmJnjv1uEUo6fF7oaNC
         tG1Q==
X-Gm-Message-State: AOAM530wOLVekVqOR2GoKu7fUkqQ9IV/h0yuszwob0XcJEQQipcRczky
	dypi8Kj+XhfoRousGFBXZYo=
X-Google-Smtp-Source: ABdhPJyr7/BzJFpCalS1O+TlJsaMZOONeT/ZSaUoQCMnr7xceB6e3xDCwXi8iQ2FrqDg7W40A+pW4Q==
X-Received: by 2002:a9d:6a50:: with SMTP id h16mr3608599otn.67.1615560572831;
        Fri, 12 Mar 2021 06:49:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4c55:: with SMTP id z82ls2025101oia.2.gmail; Fri, 12 Mar
 2021 06:49:32 -0800 (PST)
X-Received: by 2002:aca:5b02:: with SMTP id p2mr10193922oib.90.1615560572522;
        Fri, 12 Mar 2021 06:49:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615560572; cv=none;
        d=google.com; s=arc-20160816;
        b=Q6m8C0ZYbS3OVr4SBWuOApmh72L+nURCuCKroaxhS57sKXc6lpQuva8nCKBeqFzrMV
         JiLCSMQIcQQOSDXru0OBRGmpHoC9TZLKsfdhizUlG1rwjgrcd2Jv84t6D+MCMt7vxZN2
         3RMBdKmziK47ZhCcj/6s0weIe63xQlu0rzlEh1O2hLQsrMzJ95Xf9wCREDvPFqdZT1nM
         lfYm9hF10B6a+4s1gxCDY3+2y+7axbX97RG0fTYQSSDN82J7fqsVgb0tC5uThCDyUIrF
         KAnBetv7F71axiMD5GHGhEklFUcrElF0pcGEmiGObbpq8HxUXLZiHSE/9rb60NDacvS+
         pBAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vE6AFNK5NMZ2XRC6U1hmnn/pzLhXkxOhFssXJpRkl/A=;
        b=VwpYl5dh/3tElEK5d9KR0qLS3gOmTfzuzHTthLpIuf1QdnkFzAwXjJryacnbjrrkPa
         0oHvPaxnzMvUBH71jTUsvyOnnvGcZcAtMC/ku21i/VuliXByLJyf4FDSo0/HToYhKe9b
         Y8dM5N4LfxxzIdxzoWcljpPC6rb02eNjhci2GqXRERoNlbK2zSRjXJAS4codV3V+4KTt
         sE0jqsBLtKGqUGER39R0RVlD/Mkizn5TdxqfdjzB/8kAkm/5RmKMxb8wGfzVdF/0GCL4
         xk/jK7WvDMgG9Ad65Kivov8RvJ2BrRI3EYvV2c/5Bgx98zX1SvQiM81VQ14EpMLvLfew
         nP8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EnmQRw2L;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id j1si493143oob.0.2021.03.12.06.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:49:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id y13so2035294pfr.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:49:32 -0800 (PST)
X-Received: by 2002:a63:455d:: with SMTP id u29mr11894620pgk.286.1615560571751;
 Fri, 12 Mar 2021 06:49:31 -0800 (PST)
MIME-Version: 1.0
References: <20210312142210.21326-1-vincenzo.frascino@arm.com> <20210312142210.21326-9-vincenzo.frascino@arm.com>
In-Reply-To: <20210312142210.21326-9-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 15:49:19 +0100
Message-ID: <CAAeHK+yoeLfkztNCifJuZooBwe+9np98ch50-ToOGKi1swC1vw@mail.gmail.com>
Subject: Re: [PATCH v15 8/8] kasan, arm64: tests supports for HW_TAGS async mode
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EnmQRw2L;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Mar 12, 2021 at 3:22 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> This change adds KASAN-KUnit tests support for the async HW_TAGS mode.
>
> In async mode, tag fault aren't being generated synchronously when a
> bad access happens, but are instead explicitly checked for by the kernel.
>
> As each KASAN-KUnit test expect a fault to happen before the test is over,
> check for faults as a part of the test handler.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

I believe this needs your Signed-off-by as well, Vincenzo.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByoeLfkztNCifJuZooBwe%2B9np98ch50-ToOGKi1swC1vw%40mail.gmail.com.
