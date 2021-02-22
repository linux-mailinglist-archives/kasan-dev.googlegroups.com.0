Return-Path: <kasan-dev+bncBDDL3KWR4EBRBSHBZ6AQMGQEIMVQZ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id C022C321EA4
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 18:58:33 +0100 (CET)
Received: by mail-yb1-xb3b.google.com with SMTP id 127sf17272533ybc.19
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 09:58:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614016712; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mpc42t2DwzZZ7QZU0we60KLv5yJDTQikXMrtZ0y8Ouvv8GaxOrut7GnyZqcWz35i+s
         hI462RVJINdtg9PW/QX/pByMjWx/BygdIiOAMm4cFta08W69NksmyZF/wMq4WDiKn71H
         rBlcqGltvUhM5Fp/BHjeubjZ8qUrdH402VjsK/6tNr+yb9D5vQ6OkJkoUJ2qqomwdaM6
         wlUatm1iYHV10uRpG7zI8YQCFzOCKyICfE3s9mM2hoT/CfI5ijRmrSCo6w6Jz+e+hTOz
         1UY5yVTaWdHIxolBYQx8iN6ZGqzqciNhkflCeNOxbzh1tVyYhjMe53vl2IjkGa6tkUVW
         5AbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3JNtf1JHhXgaBEpYPbWkDck34xgEy7kub0I9fDCULGA=;
        b=zI0lefMjTu++8RRUSHe4FlLPHk/881vMUqfS/ivhVryhi9CfkXa0subgBgUYHCULlP
         yV0u6WIQwtviFDp0PdTZ8KHWBeqx7cV8ogzJMGHcEkyewRgVa4T6UJmZOhwQ5HCDOzkN
         YTFLLbA/lGo5iwkdpy9JQuuVKX31wpk50Md6Ed/xpTBdJpDHPUi0og/VPZcAh5o91P9w
         D42irgLd0oud8d+mWuk5IVuIpyQIVGv4bCmpxQJxTyJby2A6rxaez7YjD7Bq6bQ9v+ZQ
         Xyo2Yn1kQW8yJmRaTCqT1ai8n28acfyla+ZZYuW85uPvK+lOi0dWEBazFDW8Z7A72yLx
         +Zbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3JNtf1JHhXgaBEpYPbWkDck34xgEy7kub0I9fDCULGA=;
        b=kHw+FU6s5t/sIzqol4EunC1f3MyAjO0s3QmamnfmtjdOC9CFFWJ48p+3XXDz2LbuwG
         JJCOOLhWFKG8fKsYIPX+1UU/oi5Z9GgZ4RlUS+69iZW7tXC05WdrTnTn5hDFGS26djyq
         oPnq/HFbuhHzdB8ofQaaRm9hSa2vlxeI22mPm2K9/HWMZsN7KCCTEKkdXiJwoOQD4LcJ
         zLyyDfDnWgp+0W+6qqLMMEdYRJqsxGIDQVD9r3/sXSJ3QcfCt1XyQK7XxRNIdqZYY+/g
         UonQuzZGmUv+qedNONVzP7cPjc82y6ITHOZV3J5MPGH879LhsETpfeTmpM0kX5jPRnhw
         H+FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3JNtf1JHhXgaBEpYPbWkDck34xgEy7kub0I9fDCULGA=;
        b=byDOqabdQd7q8obJB6xzWo+1WSXUDnzNewhAxDdLjI3VURtNfaH3NsUFo4Zg31TeyZ
         vyOBzJ7dNBv6q2i1pEngRrZonJE4HxFQO53IprmA/7ly05RDF/NHySFr0Q2UHuTwtj0E
         6RqqF/1DKGCNtR5m3E9xvmcV/SF3NVFdcVYRa+NZSfun/EzE2iomrsdiyvWk99zakIDV
         i9nmortkB7qsDAEgD8qESo6bfPSnLUIHLttBqxIxsGxnjp5Xn+tkLUCq8Z8KviC42Io8
         IF3tSE492STbxh7P9YdG9wujG+eKMmE0VlEMelBChfuSdhAuGjzOhmOOUwlb9ut5aEaa
         zfaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5336FlZi+ZmjU+7C6b1b18NvSi5ARj4qGfmeOYhEwL7FI+LMIdzZ
	E6VbWPpLmKgtlegkwjSW4jw=
X-Google-Smtp-Source: ABdhPJyX/4sDLIOpmzNse/Am8s90E2USBcWfF9lOTJfqVIg30Hh+B4U1qvuXjAp//aKYDNaytUGP+Q==
X-Received: by 2002:a25:50d:: with SMTP id 13mr36206634ybf.5.1614016712817;
        Mon, 22 Feb 2021 09:58:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d907:: with SMTP id q7ls8694089ybg.3.gmail; Mon, 22 Feb
 2021 09:58:32 -0800 (PST)
X-Received: by 2002:a25:9b88:: with SMTP id v8mr35337328ybo.338.1614016712311;
        Mon, 22 Feb 2021 09:58:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614016712; cv=none;
        d=google.com; s=arc-20160816;
        b=XQ6jIJjmsqUhRW+7AubSlVUMW/oBr31I4PAY42Hl7R0Cpqf/HmcWJpfVnwq/NG/7AK
         OhvW0Fkv3HUUjD9iVwa4mkWLvKqs6EYrubnMSmZMf81WyIRiugyu+CqOabY577eqhYI+
         zA4qGcGSFWfFZjv/4iHZcc2p9jnsaWuo4Z6MtRtUZqyEIS0bZvwDqDsOSOxkaLeh+snU
         zKVpp7DyDBsPs45FtJoU9McjOG0I1co5Ejvx5vaooyIuNXlcCBRiyeGKPNadoW+saNoj
         ta83owsIvUzkdllE7fABUxnRx3FdDk/5fD5Rbs5chB00KLwqMYfSpx9RqU5MdzRduu3+
         6nvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=sfiWuCiIXLZTeI5+enSjVk3QKDbKl6qmrk2H2KfQMkI=;
        b=aXqO8J7ont5zZf/Sl9YSZgD2u86HuoKHXOElLufQBFkL4YkyliULLBym6fkDazawXd
         C104Rv1dorqug+PgdhKNHA6vow/tJO31/iV5Ki6apJTGD+UZayUr9NIhKmbf2pKDptTc
         ayVJbXPLS4HnbQw+R7/qlqgcHCfxq3lJldtajklnorSkGUBfHeXa9gh1eaYWTMmCNIr6
         3o3Mprx9+1l44GG0XWFM4Zdo4nR0wXl3JeRCwvy9qwkZk0KA/VmrMBaHy9ZX0HPhpDvb
         uhr+30Fhk7v3ZS8U+WLBMeARCeR66hcRB8Cb4sdIX149FjEFLgjDZilzEqzEL8In5Rs4
         lGDw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x7si1361967ybm.0.2021.02.22.09.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Feb 2021 09:58:32 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id D238064E15;
	Mon, 22 Feb 2021 17:58:28 +0000 (UTC)
Date: Mon, 22 Feb 2021 17:58:26 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v13 4/7] arm64: mte: Enable TCO in functions that can
 read beyond buffer limits
Message-ID: <20210222175825.GE19604@arm.com>
References: <20210211153353.29094-1-vincenzo.frascino@arm.com>
 <20210211153353.29094-5-vincenzo.frascino@arm.com>
 <20210212172128.GE7718@arm.com>
 <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c3d565da-c446-dea2-266e-ef35edabca9c@arm.com>
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

On Mon, Feb 22, 2021 at 12:08:07PM +0000, Vincenzo Frascino wrote:
> On 2/12/21 5:21 PM, Catalin Marinas wrote:
> >> +
> >> +	/*
> >> +	 * This function is called on each active smp core at boot
> >> +	 * time, hence we do not need to take cpu_hotplug_lock again.
> >> +	 */
> >> +	static_branch_enable_cpuslocked(&mte_async_mode);
> >>  }
> > Sorry, I missed the cpuslocked aspect before. Is there any reason you
> > need to use this API here? I suggested to add it to the
> > mte_enable_kernel_sync() because kasan may at some point do this
> > dynamically at run-time, so the boot-time argument doesn't hold. But
> > it's also incorrect as this function will be called for hot-plugged
> > CPUs as well after boot.
> > 
> > The only reason for static_branch_*_cpuslocked() is if it's called from
> > a region that already invoked cpus_read_lock() which I don't think is
> > the case here.
> 
> I agree with your analysis on why static_branch_*_cpuslocked() is needed, in
> fact cpus_read_lock() takes cpu_hotplug_lock as per comment on top of the line
> of code.
> 
> If I try to take that lock when enabling the secondary cores I end up in the
> situation below:
> 
> [    0.283402] smp: Bringing up secondary CPUs ...
> ....
> [    5.890963] Call trace:
> [    5.891050]  dump_backtrace+0x0/0x19c
> [    5.891212]  show_stack+0x18/0x70
> [    5.891373]  dump_stack+0xd0/0x12c
> [    5.891531]  dequeue_task_idle+0x28/0x40
> [    5.891686]  __schedule+0x45c/0x6c0
> [    5.891851]  schedule+0x70/0x104
> [    5.892010]  percpu_rwsem_wait+0xe8/0x104
> [    5.892174]  __percpu_down_read+0x5c/0x90
> [    5.892332]  percpu_down_read.constprop.0+0xbc/0xd4
> [    5.892497]  cpus_read_lock+0x10/0x1c
> [    5.892660]  static_key_enable+0x18/0x3c
> [    5.892823]  mte_enable_kernel_async+0x40/0x70
> [    5.892988]  kasan_init_hw_tags_cpu+0x50/0x60
> [    5.893144]  cpu_enable_mte+0x24/0x70
> [    5.893304]  verify_local_cpu_caps+0x58/0x120
> [    5.893465]  check_local_cpu_capabilities+0x18/0x1f0
> [    5.893626]  secondary_start_kernel+0xe0/0x190
> [    5.893790]  0x0
> [    5.893975] bad: scheduling from the idle thread!
> [    5.894065] CPU: 1 PID: 0 Comm: swapper/1 Tainted: G        W
> 5.11.0-rc7-10587-g22cd50bcfcf-dirty #6
> 
> and the kernel panics.

That's because cpu_hotplug_lock is not a spinlock but a semaphore which
implies sleeping. I don't think avoiding taking this semaphore
altogether (as in the *_cpuslocked functions) is the correct workaround.

The mte_enable_kernel_async() function is called on each secondary CPU
but we don't really need to attempt to toggle the static key on each of
them as they all have the same configuration. Maybe do something like:

	if (!static_branch_unlikely(&mte_async_mode)))
		static_branch_enable(&mte_async_mode);

so that it's only set on the boot CPU.

The alternative is to use a per-CPU mask/variable instead of static
branches but it's probably too expensive for those functions that were
meant to improve performance.

We'll still have an issue with dynamically switching the async/sync mode
at run-time. Luckily kasan doesn't do this now. The problem is that
until the last CPU have been switched from async to sync, we can't
toggle the static label. When switching from sync to async, we need
to do it on the first CPU being switched.

So, I think currently we can set the mte_async_mode label to true in
mte_enable_kernel_async(), with the 'if' check above. For
mte_enable_kernel_sync(), don't bother with setting the key to false but
place a WARN_ONCE if the mte_async_mode is true. We can revisit it if
kasan ever gains this run-time switch mode.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210222175825.GE19604%40arm.com.
