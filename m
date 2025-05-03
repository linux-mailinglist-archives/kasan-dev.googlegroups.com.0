Return-Path: <kasan-dev+bncBD3JNNMDTMEBBAGW3HAAMGQEW7LMHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B8739AA824B
	for <lists+kasan-dev@lfdr.de>; Sat,  3 May 2025 21:14:09 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-2d4e42a2b2bsf2670565fac.0
        for <lists+kasan-dev@lfdr.de>; Sat, 03 May 2025 12:14:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746299648; cv=pass;
        d=google.com; s=arc-20240605;
        b=E5QSq3a2rX243g9lpUgP52sihfzefRPmrhITYIO9IQB4hEWpFpxQoT0gxSaLAs0vo6
         hWoejI3NP6ZYYvF9Bz7q/nuO3DsVFxERVUinbkUU2A7LL2ROb3fKdtsZUWJzH4e07sMv
         6mCNbwUC8UCz4aSKolc56mscT4gWAimaJTxUkDkhrCh+OLYJziK8oYj8lF4aiJFdeCHW
         4DRDL6PLDhCDx+kFQ0h0oPX5E8dFlL7mbnWbJSWoV5Ze+Ay/IC97tY4CbyXsNv1JuOEg
         cQG935vzw1kXz7WbjpH5u07U1hxE379BDJ+LpVUFmOrNTWNdyB1LlTzdSfPBYOnr4/sd
         k/Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=0oE7x5G/ANlAbxC4Yye+CNuNJ9rOTtFXxWh8vfciQE0=;
        fh=pTJHRip0oT/oCE3vwPNbdBNci05b3L4BueL+qIDGziA=;
        b=PJVNsir3GguGg2qwBE2nRXK25ccxrz60BNm7WaWuUHXvnUJcNY+HFHGyMXtnP6yZKr
         2y29N0p2sGCl4Zmzb2a/RQBlJ2ylHWDzvtdevWip4kpqX1PIDwmTJ+vJfvCA1ATbhBld
         ndoPxHQGBJ9FNqGYPhoHOn6PEcv7yuX/Tm5kED7/sym1qXUw6PNFYO76IRehLpkJAicC
         Fz5lyT6wLzsx4+JuuRuyTc4Ezg4px4yZ8PUWgyBeqkU1hljPJF5u7cwfhsez7ZIDRbLP
         gZmiA9zj7KpvM93IrJs67+tthWEzt67RWo9ZyQ1A9XO20XHw8kfwvRshQHCZpJTcvVVI
         Qx0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=RKuStUz1;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746299648; x=1746904448; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0oE7x5G/ANlAbxC4Yye+CNuNJ9rOTtFXxWh8vfciQE0=;
        b=X4VuKWIq54z2WdCtAFpmxqAcK3eT1i6d/87cmwdcmSkQDR5p2/rHsTzcfTuLS/gfrg
         onHvt0nyHgRiZTOd2qQdiFvl03JW1L5QOZLjBZuJ2fs5j7fMqtvXD9hcw1tLaBHbRW4n
         dKrL+ofvrLZca7ke5I2nUyRT6di2Lrivl8Xk5RxsB5RceoSxjkqbxNTxyE82ZKMnsmqj
         yyUQgidQk8p5sHfi9nOqU3Mvfifad8ttbZe0mNpE4AHz8d8xpW+S7mBWyP+zxIxtQ5IH
         SfQuNOvrAYkWSZ9nP2B5ziRfM+0FGOytHMSQfpxrCch9r8D5iwwkKQB8ki1BwzTeBYYh
         krNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746299648; x=1746904448;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0oE7x5G/ANlAbxC4Yye+CNuNJ9rOTtFXxWh8vfciQE0=;
        b=qTx/fEHb4DOQDPh+rDNB76C38qFQKIpKAaGF8II/QQFw8sLrGgHDZm/g7wexXSoAcP
         XiEbd6bsd9kiKTDvH08h+oxiuuqM5Spq2XU/g/xuq1Uv8syqRAA26HcGZ+ljq5aETJfC
         LRZnjoShHRpTcUzwD29qX/ghPPaBgSNyMa4CZxRnyWKEWxezuKo9lMaDxjhJu8FA4b2S
         S7OIYPT32oOPZy3P0lSA+iqW/Ybq7lB2pCjz7D0pSEKKFIcFOuSSnYtu+VnxyVYttt7l
         VTtqFEhV8hPWN86sK8mswuLABgjSMEGdEDUn6CXI84zkuR6HKviw7d8fnPWWAlxP2Yrg
         V4Lg==
X-Forwarded-Encrypted: i=2; AJvYcCWrKUQXwlTLj/e0BJm1ojrcfZcBHFyxzF9Kh+IHqZrwFW+bftLzR6Gb/SYIuV1ekRMjPwmpPQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywv/YMqGT+yEtjw04tdN6wj/y8o/6sjF876szVarSeOEwYE9n+b
	0xhs1nKDsKpi6GVwh2lqJhW1oqKeOXOLLpp+5Qu2HoD3SL4hPjI2
X-Google-Smtp-Source: AGHT+IEhMuIl/Qibk/xmh7eeCUGTOX/VuvbGsD+EzJ4NYxB97zSTmJR/LaPXb4S3I2dYH2vMCMAobA==
X-Received: by 2002:a05:6870:469f:b0:2d4:ce45:6985 with SMTP id 586e51a60fabf-2dae835f21bmr1016303fac.11.1746299648223;
        Sat, 03 May 2025 12:14:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEkTnk/L/jfb3Nvv1L9m7oByWJ/MMr+jCyndviE3dN8Cw==
Received: by 2002:a05:6870:ae84:b0:2c2:d749:9156 with SMTP id
 586e51a60fabf-2da89e1029bls82504fac.0.-pod-prod-05-us; Sat, 03 May 2025
 12:14:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVYKy6Pi6MAwceo220opSizqCsIlEdQigFv+U/YnInZjIo1DO/JZOxOqj2FTS4sRaehIEAbpnjL5H8=@googlegroups.com
X-Received: by 2002:a05:6830:6210:b0:72b:888b:27e4 with SMTP id 46e09a7af769-731ead9d7e7mr1316117a34.12.1746299647213;
        Sat, 03 May 2025 12:14:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746299647; cv=none;
        d=google.com; s=arc-20240605;
        b=X42ce9YZOTmfmoynMqxnKLeHDeLPrXsdYTY5lDT6wW3y5lSbig6lWtLGeNH0myqZ7n
         hFCBf/uwNjSDoTmD2HukisfoSw+r8nVDPR5ahoEPcd0N8dt83xOvg5wsXZiGKm2NVGbC
         hkWpb47KdyecE3jo/l2UgVNjiM7Rhkw3RPnyTXM33XcIu/9hQxUPa3wFP5v+5M7OV+Pt
         AndEo6vtYLpSZlO1F+cjQzS97EI2xg0AhzLLvjvuOhzFi8pmfgqsWCuvmvbSIjk1gOua
         qYGRo4lcLACMkMKSRD0d0eL2k0CeWUKraQ2qvln05teLvSyIB5qJoh0sNjLQniOv9Mht
         Fymg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=INtqWdF1ttpcGxLYcmEEmkHcr1sBjwlLz2bhiN/ZlGY=;
        fh=Pr8tyFlLjNwsXan1DL5gWDjP9txQeYBpEMA7JrUrKWY=;
        b=bck1l6HhZNDyhsmhtqC9hneDkfoYduUD5OBnnrNtX9T6TSAXBhsBFi7bj/kpGDQT7I
         XTAU7+e8M+LsZdEthNsEKCS8s7ACm4r/EWYX7Ey0+x8ni5O4SdxJA0PFHXYhG1HW/lGE
         09rmYA3FElAdDEp1PdDbWGOF3ye9jk9ROvuLpVJxP2LXAMEjJgtAqgiVhdaCMQVVmR5/
         UiZCwetZkk9HeRb5WwwIKs9/7ITIMVWnNfbuG0uhq6jXIcqnPjPEqzGneBwCF9omouBe
         dHseLOF4KsQSvsYw5BWfc7EDYBSkiSHr8SP8kdQZPR/bp5H1rvZVv89Qw9f1bETzlaVW
         xjAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@acm.org header.s=mr01 header.b=RKuStUz1;
       spf=pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) smtp.mailfrom=bvanassche@acm.org;
       dmarc=pass (p=REJECT sp=QUARANTINE dis=NONE) header.from=acm.org
Received: from 004.mia.mailroute.net (004.mia.mailroute.net. [199.89.3.7])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-731d34e7472si113982a34.4.2025.05.03.12.14.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 03 May 2025 12:14:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted sender) client-ip=199.89.3.7;
Received: from localhost (localhost [127.0.0.1])
	by 004.mia.mailroute.net (Postfix) with ESMTP id 4ZqcsV3dB1zm0yTv;
	Sat,  3 May 2025 19:14:06 +0000 (UTC)
X-Virus-Scanned: by MailRoute
Received: from 004.mia.mailroute.net ([127.0.0.1])
 by localhost (004.mia [127.0.0.1]) (mroute_mailscanner, port 10029) with LMTP
 id DqXzoqknLYju; Sat,  3 May 2025 19:13:58 +0000 (UTC)
Received: from [192.168.51.14] (c-73-231-117-72.hsd1.ca.comcast.net [73.231.117.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	(Authenticated sender: bvanassche@acm.org)
	by 004.mia.mailroute.net (Postfix) with ESMTPSA id 4ZqcrR2bKbzm0yMS;
	Sat,  3 May 2025 19:13:09 +0000 (UTC)
Message-ID: <08163d8b-4056-4b84-82a1-3dd553ee6468@acm.org>
Date: Sat, 3 May 2025 12:13:08 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH RFC v3 0/8] kernel-hacking: introduce
 CONFIG_NO_AUTO_INLINE
To: Brendan Jackman <jackmanb@google.com>,
 Peter Zijlstra <peterz@infradead.org>
Cc: Christoph Hellwig <hch@lst.de>, chenlinxuan@uniontech.com,
 Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>,
 Sagi Grimberg <sagi@grimberg.me>, Andrew Morton <akpm@linux-foundation.org>,
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>,
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>,
 Kevin Tian <kevin.tian@intel.com>,
 Alex Williamson <alex.williamson@redhat.com>, Peter Huewe
 <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>,
 Masahiro Yamada <masahiroy@kernel.org>, Nathan Chancellor
 <nathan@kernel.org>, Nicolas Schier <nicolas.schier@linux.dev>,
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>,
 Michal Hocko <mhocko@suse.com>, Johannes Weiner <hannes@cmpxchg.org>,
 Zi Yan <ziy@nvidia.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Juergen Gross <jgross@suse.com>, Boris Ostrovsky
 <boris.ostrovsky@oracle.com>, Thomas Gleixner <tglx@linutronix.de>,
 Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
 "H. Peter Anvin" <hpa@zytor.com>, linux-nvme@lists.infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org, kvm@vger.kernel.org,
 virtualization@lists.linux.dev, linux-integrity@vger.kernel.org,
 linux-kbuild@vger.kernel.org, llvm@lists.linux.dev,
 Winston Wen <wentao@uniontech.com>, kasan-dev@googlegroups.com,
 xen-devel@lists.xenproject.org, Changbin Du <changbin.du@intel.com>,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
 <20250429123504.GA13093@lst.de> <D9KW1QQR88EY.2TOSTVYZZH5KN@google.com>
 <20250501150229.GU4439@noisy.programming.kicks-ass.net>
 <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
Content-Language: en-US
From: "'Bart Van Assche' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <D9KXE2YX8R2M.3L7Q6NVIXKPE9@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: bvanassche@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@acm.org header.s=mr01 header.b=RKuStUz1;       spf=pass
 (google.com: domain of bvanassche@acm.org designates 199.89.3.7 as permitted
 sender) smtp.mailfrom=bvanassche@acm.org;       dmarc=pass (p=REJECT
 sp=QUARANTINE dis=NONE) header.from=acm.org
X-Original-From: Bart Van Assche <bvanassche@acm.org>
Reply-To: Bart Van Assche <bvanassche@acm.org>
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

On 5/1/25 8:22 AM, Brendan Jackman wrote:
> Personally I sometimes spam a bunch of `noinline` into code
> I'm debugging so this seems like a way to just slap that same thing on
> the whole tree without dirtying the code, right?

If this is for test builds only, has it been consider to add
-fno-inline-functions as a local change in the top-level Makefile?

Bart.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/08163d8b-4056-4b84-82a1-3dd553ee6468%40acm.org.
