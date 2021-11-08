Return-Path: <kasan-dev+bncBDAZZCVNSYPBBEH4UOGAMGQEUPRMYAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 020ED447E1F
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Nov 2021 11:38:10 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id r13-20020a0562140c8d00b003bde7a2b8e2sf8784630qvr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Nov 2021 02:38:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636367889; cv=pass;
        d=google.com; s=arc-20160816;
        b=K6lFQgO1gioLl0IHa76Lu9Kw+5O+reV8stBSt9YCtwmq/+M7JGk/HMo92ZPyvmxdcA
         XoaV2HM7OFfcG2h/R0KbLZD3EYyXjY4Gvv7vhMw8Na+a+M1ZcZLHb7f0EmaUGUsXtHp0
         nV9/SmRNsIswfQ2cJwxMqQUY3sd/NGeK1XEw5p+XKGrr76Jaacz5wKQ1KwJs2jJ5SzpI
         yuc8N03gvoxnj4sVFArpFofgeKNH5mi9KfgNFeoc0bMHw1O0InszJmNqPkxYs6eGSueo
         cHaw4fxkxeNZDejU9ZqUT0OFD51Vz/NcXG0X4W4g8B2CP4Yct7L+3sPGU1XRmFt9Ujav
         ulYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=e3j2VFqhsuxPUkHTzHIK1J2mE+kCU3hrE2+xJdDfCzc=;
        b=ouZj7XsdRpd0LE09KVMFGUPhfpBNR+Dil3WjbdKN2fedBiS5nIRJl8I4+Xm+Zk7JvR
         Ezc5myp1/VH1hxUxk2EhrGLS0aVV1ZdZ0Dtry9VoYuUqjLCti+GGxo4HL+WTZ48UF12p
         QXWXH7EznFSmXJW0CmGBD0NbZb1Pg1SX23HFESep/gwH2b6tEAG2cW1hFe3AGkIkCwxs
         NldIjqFVqUXtJMmQM8Oly+3w5BAyi0IPw4Y4MdleTgrYXl6gvsLEd8tdeH6o4iB3TvxE
         FVUJr0YBmiCIcbVkcqzqmYUNhp2glJ4H75XAPscMSqp8MgI51XSasyOHW1cmU0VMWjaJ
         O7GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uTjpBMei;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3j2VFqhsuxPUkHTzHIK1J2mE+kCU3hrE2+xJdDfCzc=;
        b=UevV3zf4hlQ16YUrvwTTYSuOkzP4TBzFMTS3B2dp1x8c910fAAaDnJjXhbOOwK+j5l
         /530sM1a/sj8WOlEf0C66cDyEm/hRRy11X9lSvn6LfjLBp29OYOSW8G5NXkXU/Lu0NDX
         iocR+Y2zQpJdabrv8+2nlGvbO0+Ovuf+jBSRZhyg639ARnJejQ310H0zHn7Mj2azk7qf
         cioy8NBoIu10dwukN1FuXBYo2GJ4fFBprhK2yp4+uRyufvI/o4VRrrOgMnDGbggDCi4G
         EZaQfjNa3GouvOsHDXqOWyLtzbJlUSzo7fsxWEHFEIYEIu+eCgJrSUvtkQm90c8uhHPr
         D6vQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e3j2VFqhsuxPUkHTzHIK1J2mE+kCU3hrE2+xJdDfCzc=;
        b=fhcr18qyaFM6Wv7w3MKCFndiQHF7QJkKXA7Zfign4YlEhjk0YhIeheUKn0Bt2TizsG
         WpGnFFlwy8MkBaqFDIS/OdvoIbFRbC/Zo3UNrHM2AAVIqb6R8p58E+J2V9fVETzBdjg9
         Ymuvrpu+D3Pqgc84F7F/u+ZQSJR7JeRmvQ48lQa5szczb/pyzoCAMmy13/XbaS+JpqU5
         2q5ypH8KCQWvJWNN8Iy1mtcQT6+m60zbAVEgF99fhqOnSQXX2MqOLeY9IbVKm0DOY0hh
         CEAdA5xSBnnHUbsvFZN9UdxxGy17qZSgjPh4v1OVtX91ZyE0ipuwwjMAbV9YrmEXcNtF
         h1Iw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530x1Mk/OnqeF1+MfGMrCsV9fMsKD9Ci86nzxfMA1VPG9fjH3lh3
	tHTk7ENrjmNucnZtr+4bNHk=
X-Google-Smtp-Source: ABdhPJxHIDe26CWk/803wYnhbTxXEa3GfLJAsxs/veXtR637dBStr6UCl2yujyMsp9ZIh43+EnSJpg==
X-Received: by 2002:a37:b3c3:: with SMTP id c186mr62745250qkf.464.1636367888875;
        Mon, 08 Nov 2021 02:38:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:47:: with SMTP id c7ls4942798qvr.2.gmail; Mon, 08
 Nov 2021 02:38:08 -0800 (PST)
X-Received: by 2002:a05:6214:dc2:: with SMTP id 2mr73817636qvt.39.1636367888394;
        Mon, 08 Nov 2021 02:38:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636367888; cv=none;
        d=google.com; s=arc-20160816;
        b=LDQONNoeRopQmmfo7qwb5s+qgs0vjjFNkF6w9WM/IAPK6MEphm0KFCx/16jZvZ2OgF
         WFlSTcn56mzieAPcTHjxWumCUz7iP7/DnvYfHK6hMHuVdjAnijXPg17vVyGEv/8rGYLW
         +6q1+LlhN5lEiUY+ClCBe2lbdEOLtTGEs269pcvhrQCiL6wacGY7h7npqFmCFAmz2nag
         lIBodiyAZK7/bMfLLy2v+gGjXt7GlW8ukyZ+e6M9xtBLh0ZPj0j6f+0HuZ/82QwoJFu8
         eGXwTte5lUxUwTIQZ1/LoxnCeo/VTvHLa8KJoXnBV2tv0g6KXLcUlRRt05WYwFNQp/jr
         Wd3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EbkgDQM2fnA21BrEVhfKDuo2zjVQBo9KhqecpEgE+GM=;
        b=gElNX2C9ugKp5srgdHVmKrNY6l2nkm9gXePTGI7t/1JlqTTBYlmL91zCPbc7nEktSV
         lfh3WZ2EDaMK7JW9F5j0YbCM4RXDqNUkQRiUf4lLUKx76AM2g9wqlh+NFVy84disopyR
         8z8YpmsyWqKq+xGAbqNZK0n6gCOnWbQYP41dyT1SOovUR18sZF+eIfel++aIbuQ9MZSS
         0evmC/9ucFzWOBmHJu8i6Udntxhgp2Ty9A/nuswSFD21nVOQ1NGVNiJZN+YnFlSV987+
         0z2aHU9e0SbqFgjKLD8j/y7g8PPM3ZVm+DTrwHQRRGdt5Y0oaIAJMRkxqIeCRourGJ7X
         KrjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uTjpBMei;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t24si324570qkg.6.2021.11.08.02.38.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Nov 2021 02:38:08 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DF4DA61359;
	Mon,  8 Nov 2021 10:38:04 +0000 (UTC)
From: Will Deacon <will@kernel.org>
To: Qian Cai <quic_qiancai@quicinc.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: kernel-team@android.com,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Mike Rapoport <rppt@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexander Potapenko <glider@google.com>,
	Russell King <linux@armlinux.org.uk>
Subject: Re: [PATCH v2] arm64: Track no early_pgtable_alloc() for kmemleak
Date: Mon,  8 Nov 2021 10:37:52 +0000
Message-Id: <163636592237.15032.12831105402698814160.b4-ty@kernel.org>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20211105150509.7826-1-quic_qiancai@quicinc.com>
References: <20211105150509.7826-1-quic_qiancai@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uTjpBMei;       spf=pass
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

On Fri, 5 Nov 2021 11:05:09 -0400, Qian Cai wrote:
> After switched page size from 64KB to 4KB on several arm64 servers here,
> kmemleak starts to run out of early memory pool due to a huge number of
> those early_pgtable_alloc() calls:
> 
>   kmemleak_alloc_phys()
>   memblock_alloc_range_nid()
>   memblock_phys_alloc_range()
>   early_pgtable_alloc()
>   init_pmd()
>   alloc_init_pud()
>   __create_pgd_mapping()
>   __map_memblock()
>   paging_init()
>   setup_arch()
>   start_kernel()
> 
> [...]

Applied to arm64 (for-next/core), thanks!

[1/1] arm64: Track no early_pgtable_alloc() for kmemleak
      https://git.kernel.org/arm64/c/c6975d7cab5b

Cheers,
-- 
Will

https://fixes.arm64.dev
https://next.arm64.dev
https://will.arm64.dev

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/163636592237.15032.12831105402698814160.b4-ty%40kernel.org.
