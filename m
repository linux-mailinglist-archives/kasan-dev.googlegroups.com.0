Return-Path: <kasan-dev+bncBCLI747UVAFRBCWBQ6KQMGQECV3BNBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id D1433544B23
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:59:07 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-30c14765d55sf200864607b3.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:59:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654775946; cv=pass;
        d=google.com; s=arc-20160816;
        b=uzjRoolMGP59zLWlOK8K9un13yGExUHiPuCTGs7cItgGT/bIfrCmLUH+8QNNPpybhA
         1uROjbLxrgT015H5W+YJ/7WBEY6pGvRJo1F1yACOu/z/+8iFSdAmn7am1JYWFzh6KAVK
         NafEeGoXiodR6bHp1ba/VzlfoKYZHRg/dp+LwtmYd2SsnDJ5IGKgkxKluKWmnC2fZKbr
         l0e6Cd7THEhkPfb1hG6XdgxuNi4ozE6oAy8vDiCO54XkXSYpa63dBOcCL2gjwhyC7fB6
         bM7FLltgmyfqyba6JwXSkNs5u88nq1IDSiC/bjvrNvJnf/8qjbwuaUE6sb0aXzgvGnHe
         fWKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=MXw9GPYIMycicLU0xRA4N2XEjrx+5YpRlQpVScGDU7U=;
        b=QdpD9NB4a24CqT+o2fzH2StX+V6pXgi4NpvedSJL+jfTf482xwO2xP/uQSL7yHjTh1
         8ATjBaAZeOiuDXvF5QsQImqBtSEYgDXeQdOSxfa0DV+jz9bhqlvsZmWsEQoISd0NuHKS
         NHoMzcKjAsa0HYI3WCM7pjIKaYWfD8wMfvuJ8E5TI55N4Mbq/3ABH5pu3OO27XiFsbY1
         CYHEuOFs8umdHc/IUZ9PVhmMPMIlyAztjSwxD3NmQd8PGx4trRewEsggIpduFimbmRcj
         zLZHp9kmBH0VbKcslc4VFppX6vkStWXuKpWjoj0mkvB8HITfSsPyYFFBq7Dkg72rfatu
         0cwQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=qAkHwz2j;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MXw9GPYIMycicLU0xRA4N2XEjrx+5YpRlQpVScGDU7U=;
        b=PlCxNFo47TmSQo4vug2wks1LczdihWbGa7a9IosrQR8cQEuYAHV4UN2c7Ce62emOnf
         6P/iB7r8Ueo9EHZZqQNIWxvhDWtzZzXKXncTm5a/xWFf6z4gX15GzWT2/SErDAI4Vwtt
         W/dFA/ryo9/R18Jw4VqKs7kT4oRdVRM9izLZlVNtCU2TN8W8LaUGwnSL1O1mMB4PTP9K
         oetiCQLkrj7Klo+rzcgTMIVZCugRIzoP/TvTxVW2mrgnp6ASGODqgEkI3gYUqmGfpZAZ
         m4hV9M4wwVJwK3Frl75ld+Vaa2lKcBUzy0aS24g05YzG81ZT289EOWF1U8LZv1WmyiQ6
         vuBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MXw9GPYIMycicLU0xRA4N2XEjrx+5YpRlQpVScGDU7U=;
        b=mcB8BeTfNFWo+zfIYTF/nGVcYiLArczp2OoC4V/yiG4Etm+ZMOiGpAQXDUDhMFsxm/
         fpyMBlp2zYqmUfw6wEsof9yq8Df9pHLIMG+rN79OLDTz+krxciQwcW2cIvbVTwUCXL4p
         6DwHEw0djoxIYyltVSd9IlRU0hFWLBOgvsi7tR30A6B5UiymYuiyteKjmqiMkQFLBkdB
         CftzoaJpfnMNqDqFePrfelLFX5BS9WjzDRDxfYjTi0mGWA7fq4e5JGZPkALUTNrBUkNr
         N66UfgQGFvSPH5fIGKclO8mul9yjB2sbhJ3OS2rc4My5TMZRkX4bAXY8m2c5OzC8sC1j
         hfDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531c3xZKxC0BxyiPD1W9kDGjg6kkFUBUvKVFk6vjBpIv6MifLMoZ
	hxfzwzXfsWUbbNV5vO3aT0A=
X-Google-Smtp-Source: ABdhPJwcDk9ErKeIemvjNSgc98WvJtnSH+ExHIEWey1FvEIPCDabjtys/DAB7XyCtRAn1YMJ6WbIgg==
X-Received: by 2002:a25:5016:0:b0:663:fc34:a602 with SMTP id e22-20020a255016000000b00663fc34a602mr8141580ybb.272.1654775946302;
        Thu, 09 Jun 2022 04:59:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:340c:0:b0:65c:a0e7:bec6 with SMTP id b12-20020a25340c000000b0065ca0e7bec6ls3455039yba.5.gmail;
 Thu, 09 Jun 2022 04:59:05 -0700 (PDT)
X-Received: by 2002:a25:5545:0:b0:663:fdd9:76eb with SMTP id j66-20020a255545000000b00663fdd976ebmr7796837ybb.248.1654775945787;
        Thu, 09 Jun 2022 04:59:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654775945; cv=none;
        d=google.com; s=arc-20160816;
        b=Fj+8o2zNzpKn/nTPr7g9VktBucjYUh7eih8QniKQ4Qv+U8CPGu9ikEkZdy32y3u73x
         t5djEbmljHaGmgFtHzKW3Fp9EYWM0WMLibro/zQQH4Q47Uup+CJOwv23/Pzimz6Y9tMW
         KXba2PZHqSRA8nJERt0fThU9cRnntk+bE+mjssaebNddjq6SLBaknrVKUb8F93oco8mx
         6KWUx3OTbBvr929zex82NA3QmBumfpQ9UFluc+nccnxjxN8WSRj/7bSKzcEpLthguQW+
         LrWosAnGcbe0d7ZNJL5HH8Zt0k6ZUl8gZVALeR7zqnUjibPeBvg7OTU+wI31L2mqtHSb
         DOtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=RJORkAj3NYvpFmB7Va3TCC7yJxwVqGg4INvFsRsC1Dc=;
        b=MKVqAl+qhw0aP7twWSeBu4BHgT5VNbHUoyxBOcJqcWXq4mM/LbFSqsI8yBgtbSxo+H
         QB99jGtzTogaQFFyx/70LqT9JDFMyGNBCCA1sKwpHIcrnjwXdM1xT/0ukBjy3OFZXC2v
         e/Hk8l4UuctrGbmFGmctHnqjQkbtBOyly2/z0j9PzRW/2PUsOuEvO4bD0wfE/tlPt6oR
         zA5luVzvMTXNN9CpuCJwjCDXCKdIw2SWpR30o9Tw07J3FPJeAVDSnTo1kOgq1sAjCuTS
         +pgs8QyKDUgzaqu5D7fVKcMXXpAw3g0JGqOzwwdPhzWekpyNuREXh8bPF17343PtpM/0
         IgaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b=qAkHwz2j;
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id q77-20020a25d950000000b00663eb77d944si373358ybg.3.2022.06.09.04.59.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:59:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 5F7F960C92;
	Thu,  9 Jun 2022 11:59:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 56CF2C34114;
	Thu,  9 Jun 2022 11:59:03 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 5cfe460d (TLSv1.3:AEAD-AES256-GCM-SHA384:256:NO);
	Thu, 9 Jun 2022 11:59:00 +0000 (UTC)
Date: Thu, 9 Jun 2022 13:58:44 +0200
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
To: John Ogness <john.ogness@linutronix.de>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>,
	Theodore Ts'o <tytso@mit.edu>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for
 per-console locking
Message-ID: <YqHgdECTYFNJgdGc@zx2c4.com>
References: <2a82eae7-a256-f70c-fd82-4e510750906e@samsung.com>
 <Ymjy3rHRenba7r7R@alley>
 <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de>
 <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de>
 <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de>
 <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87fske3wzw.fsf@jogness.linutronix.de>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b=qAkHwz2j;       spf=pass
 (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
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

Hi John,

On Thu, Jun 09, 2022 at 01:25:15PM +0206, John Ogness wrote:
> (Added RANDOM NUMBER DRIVER and KFENCE people.)

Thanks.

> I am guessing you have CONFIG_PROVE_RAW_LOCK_NESTING enabled?
> 
> We are seeing a spinlock (base_crng.lock) taken while holding a
> raw_spinlock (meta->lock).
> 
> kfence_guarded_alloc()
>   raw_spin_trylock_irqsave(&meta->lock, flags)
>     prandom_u32_max()
>       prandom_u32()
>         get_random_u32()
>           get_random_bytes()
>             _get_random_bytes()
>               crng_make_state()
>                 spin_lock_irqsave(&base_crng.lock, flags);
> 
> I expect it is allowed to create kthreads via kthread_run() in
> early_initcalls.

AFAIK, CONFIG_PROVE_RAW_LOCK_NESTING is useful for teasing out cases
where RT's raw spinlocks will nest wrong with RT's sleeping spinlocks.
But nobody who wants an RT kernel will be using KFENCE. So this seems
like a non-issue? Maybe just add a `depends on !KFENCE` to
PROVE_RAW_LOCK_NESTING?

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHgdECTYFNJgdGc%40zx2c4.com.
