Return-Path: <kasan-dev+bncBCT4XGV33UIBB5VZRWFQMGQEZFY2DCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B954C4283DB
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 23:36:55 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id a19-20020a9d3e13000000b0054d67e67b64sf9382823otd.22
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 14:36:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633901814; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aq8xjiDq4+YDyQvq2UKFXOX27OWIPBs6sTsYiP1YtDB0IHjOItmHORchm/lXOEjgvF
         AO/YXWOk7qLYDKTe+7a4rjbcQfz9OYAPEK0Hsfo8cRMX/sOJGtC3di3JE7msOWIFzkUc
         Le2W1DvSRTCdACJ3CUI13WjB6VcfH5Wnt3o5Bgyqp9+2QZhxkFrGkmSLYnM2hzHrRLG4
         k0l1f0iLpIany78hU51JiPSuPTA+HdpuMYsv1BkGA0PKHNnVBQ8wRLLScNBaRoCLWm1k
         W896oVPUqNZxBQp5e4CwJIFqU5wMCf2bOWGleNuTExcQZgoaFQfEz+kCGCMnnziPvS99
         3TBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=qwazUQVLGkhHs0E0PBKpV/cUdyaOG5DLW1ZGfgdICHA=;
        b=MACmQtHkXiGPj6Ur/byxzCiqS3sX0Mku3DmOSZXsRtkNzgvgjlhYiDj2t4B+irZb1I
         8qktyovWy31Z9Jc32nS6491iX4pUfQfvw9N/ydvjmWMVVuOG1PpfxH+VoukEdz02DH3q
         B9G9qaq0E071xIzGRq39x1NZmLHKqjZ+gS4j8iHXXohaIlwzjQrJUnI68nY/5SLC9sAZ
         LYVHCKpBUOju4Ndyng/poanOT+sVdFPVt+GFwAofTsRsNQqxkoqc9uH0DDgQtHhpsvgT
         f0CFb0b/KmaDiYYK3EMVkTYmHayIDtRl93scHG2HPTmYzzl2AjtPiFOiuih7F811ilWd
         JTgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eFQKLwJb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qwazUQVLGkhHs0E0PBKpV/cUdyaOG5DLW1ZGfgdICHA=;
        b=V5x3g4r0muWAMLyjrGTGOTxKmx27i7XlPA0PPmOH27Hhr6vawGpcwW1gv9RGSsM+s7
         I+Nue99PDmZJo8gO4JVVEff0wdXhe+jCnHWKcESgY0/3iPQV8GhUoj5Jw3ssb96bUnFD
         KHUWCHQvp+xJMt9D1GB0Xp2812/wlSfXR4yg+PvrlHdQwNf+zyOPxyrPyoVnkVov2EfM
         EL7PhgpLGqQ56ws3RHjqduNavUvsE5tQnNrmBx8snsm/vn4axYYQD9apgLlhkdXtA9cY
         kRcwXyLUIABWS/ico06DXaru3C8RJIjnQdmNFTLcHIXqw2CSsjTQa4u7dbL0aOioayLz
         llRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qwazUQVLGkhHs0E0PBKpV/cUdyaOG5DLW1ZGfgdICHA=;
        b=4QEYhducyFugUFcFrdoinUCVIJpsP+wAL0bKL0ro6+8LKFZpAEwduqnhC8AmTanFM4
         jfWn9GNMIdXDbRxJm7iGwgLqLl2THS46EgRZw16ajvq+/Pt8RmzBnT+TTlGf9Za5svna
         JB6+ng4W1A/45ATy1VN32SoydXVx+VDL3G9jw9PNA7NhGEww/P+cyB8KHuPwHJ0T0gGo
         K63WN5FjWht4B5rRDXgFgLF0F1mvv2EdvO/36WtwBUSjNcEP8m6opAZx1PAV3h0NVw3+
         HBI4C7AWjxFUZxaW5q9+A45loWpYRHflfHCLgOZoGVCqBEDXueMfL76Mvq+LGknsTjNs
         2/pw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+xKIu9Cl180V0Bgjh3IwS/th+wefwSXkb0nAs5fCsS9M9qQd/
	WUVT6OyF0LwETbQaCshUn/A=
X-Google-Smtp-Source: ABdhPJy6dtypVxrgZm3uPfxO7KFlE+OPsIuQ1eter594L+qfdNWEEFH8NDWDv4MuNvV7vCxOV2GiRg==
X-Received: by 2002:a05:6830:23a3:: with SMTP id m3mr18080915ots.111.1633901814409;
        Sun, 10 Oct 2021 14:36:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:19e7:: with SMTP id k94ls2521156otk.7.gmail; Sun, 10 Oct
 2021 14:36:54 -0700 (PDT)
X-Received: by 2002:a05:6830:349:: with SMTP id h9mr3653370ote.349.1633901813981;
        Sun, 10 Oct 2021 14:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633901813; cv=none;
        d=google.com; s=arc-20160816;
        b=ahzwTCJ9L0zzkfhnPYVWUpDsFB6jndzvP4arywuGjjDW46ByIsoEGhK6stPJQVkcxw
         0SNXzBBYJgaek1ZUTZTrZiMj65xv5bnXZ6TQLtZ9f2GSQodBxSGR22r0ZDOGLwks5Ocj
         0WvWM4wb4CkfliANvdYX7bvfnNx8kRYQA3Pz/KxTZISojt2DlfTIkzacFLvf0iRYB9n/
         sMHae3C5XjDRm4J5rpdwLcVntY+GBdKwHdpQZgt28khkCI06GUJxjBNwQulWCkNJxfaB
         HsNWkg+kjtUAtsk6QtiS9UET9ZmlDqzbFhf586xKRWB2crHWZStdqhO8RzsO9eWT2Yrn
         N18Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=QL+RsBwqlX3tD2mYXVxdnUTUIdC8lATxg1GlCI6tlyE=;
        b=H+cT5iIrHPJGANOT2K6wgtVfYC2CiuqRQjiHAdTMAWIr7hkap87+RE6lApv64hM6We
         Th55TxSoI9M80IP/8Bkbm7yCanK4dxmbz/DjDGICkxce/JmUuxYEScd0ImaUOJDRbke7
         K2KT6lkHdNYwTAwGtG9s60Rs5W3zmyTfe7Zj1Ym/Pmob1Ten9AZ+sSfJEmFKHkcX6ey7
         35uHj0VPNznhZ9NNbu2BXJsh65H4afQhbWD44yYamjnoQM2/QGpg8fZjFgwBJEgr/eLU
         kC96kxFwktFXLp2zWzNHWvtFn03pPMl13jJq1J+UNV94bmySAahQl4HnMMd51hVYeb/p
         RPlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=eFQKLwJb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v18si19248oie.5.2021.10.10.14.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 10 Oct 2021 14:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C180D610C7;
	Sun, 10 Oct 2021 21:36:52 +0000 (UTC)
Date: Sun, 10 Oct 2021 14:36:22 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: <will@kernel.org>, <catalin.marinas@arm.com>, <ryabinin.a.a@gmail.com>,
 <andreyknvl@gmail.com>, <dvyukov@google.com>,
 <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
 <linux-mm@kvack.org>, <elver@google.com>, <gregkh@linuxfoundation.org>,
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v4 0/3] arm64: support page mapping percpu first chunk
 allocator
Message-Id: <20211010143622.18f491df5591d039cda8f7b7@linux-foundation.org>
In-Reply-To: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=eFQKLwJb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 10 Sep 2021 13:33:51 +0800 Kefeng Wang <wangkefeng.wang@huawei.com> wrote:

> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>   "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>   "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>   "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
> 
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
> even the system could not boot successfully.
> 
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.
> 
> Also fix a crash when both NEED_PER_CPU_PAGE_FIRST_CHUNK and KASAN_VMALLOC enabled.

How serious are these problems in real-world situations?  Do people
feel that a -stable backport is needed, or is a 5.16-rc1 merge
sufficient?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211010143622.18f491df5591d039cda8f7b7%40linux-foundation.org.
