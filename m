Return-Path: <kasan-dev+bncBDTMJ55N44FBBZEKXDFQMGQEMM3GTMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 01C0AD3A4B5
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 11:20:23 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-804c73088dasf2811638b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 02:20:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768818021; cv=pass;
        d=google.com; s=arc-20240605;
        b=ilB3EYtXk+X6gROv2LC94y9/FEJQa1PIcemm2AOPtCgYV88aLh35DVmVswoKLUG+Mr
         0NXu3cMYcXx4H4jnZqbnOGMT+ecIbWLhwMHP7kEt+kENIBqgaQ6VAvgO6CI1aOcLJqlp
         e/Ata0OWXPvtx2rjSfpjrmvBohQW0jL9MJyGo8Ls6xOy/Lp9hOHmPS5wutfL6FdKK8y6
         S6fBUvdEbBAKscL9rydSa2ixSj7dpL4OxIh/Z78AM5HQUXxgDp0i8bxOWsSWszwlNw3K
         TMjbgcpT32cOiYFh9g+GQuRUzr/fGxRSepFN6We/a8Txg8iOkNJF50pBhM9gT9qKv9kN
         d4IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=budXtWI1Z/0TnaqAvvdWBrOw2WpTRy0E6ujYDQwRSPU=;
        fh=Ugam6xJ+fwmxuOj7JPJbccDoS+uz3Ggm0SB9RXrds/8=;
        b=Exq+fZ5w0H7FKM3rTS95eyon/0uWqfpVAyCxV0Fm9yxSOsSPjh68xo2S4Hqy1ZjCqY
         zoNkeUsEKD/wyF4wFmSxKOfVxzgRWN9zZoeFXX50a2dgGMVcJI/UlqQcALfLIC3lWplF
         uz6lXviQe5j/Z/HnTsA3IcweuVL2jz/uKfynFaHiNsOsapW+YJMV9ipOCKROIbByM7J6
         VWqV6MZ62WH4Y5x+olTO98BDTJDxDfjzfcc19gB9ozLFWBcBQBpaZHVnE6HcgYqegwO5
         YIHriK3pY30QApVkJyDA0Fo/HqDtEJR2pmhtPBx8mNjCnbvdEYPODPf9kQDUZX/LDq8p
         jTEQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.44 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768818021; x=1769422821; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=budXtWI1Z/0TnaqAvvdWBrOw2WpTRy0E6ujYDQwRSPU=;
        b=hTrwsjLY6TEY4qsVIKzTmhwkfapo/yXnprYR8ETvydllMfAyXJS4ARGCXd3SOUOAJQ
         oX30pbPo9RWYvnQTu7Ujf2bnvRGWXskfmLs/QEVVHT7LSZjDzbV4fDpyhVsJeQEN1RZU
         zUAfrhElH3f5xB00TW7nJ1oX8DMC4II21BrhTEKH1HrVUxarjQxVzx0g1roq3TAZZwou
         zvmG3p557uQAurM4WRXmjtL4uYDmeOM90kVwr2XllN8tDcgHkKwlMcg3nlS0osMlc32Z
         kuuWg9CJH26Lv75OqDHuoq7fUwPxT71S2pVIlS4hwDDBbyygrrS8AX2zX4KQKbp6pvfw
         tJ0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768818021; x=1769422821;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=budXtWI1Z/0TnaqAvvdWBrOw2WpTRy0E6ujYDQwRSPU=;
        b=IGxB1WtIuzPxvIf5rnKSmhkAjcdqOPzL/vus8ku8hDvNJipQN5ZaF2GTS0P6DFISQB
         4Za4jq+fJo2WEj060E6wefIrePF0XaGkR1PDwidnrUoqWpkCOIBcR2r/lanf0JROH0il
         jOcaKnvhNBFlw25Nxe5Pv8Y6BDBHZ6Vta4125c3t016UXaoPoV1k/pm306MJ1XkurG3D
         k603RcCuknnJsFSsRo3Vh9kpYqGtUG1hFGt0MB54H+luo+SuO3DEznm+9LYaBlgrdoyH
         QCtLXWYz+4wFhBGELLJx5B8coK+feB27sqwl/kj4mFBAHmiu/CTc1f988lx91bACOcus
         cIpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW0v1mDUQexOaEa8R1feAPICjz92ITj1kko92ZdleK48YbYIwAxi263LizP14crc+3cTzyDMw==@lfdr.de
X-Gm-Message-State: AOJu0YxYrVYo9ZjGn+tVf01R7jZhz2TgAUYmor0hbiTjF9X/kb+nGtCc
	ZDjoDpfOHs2Yo35jwAeUpdOLnwf2mvoWOsX1V7Nf/LpIlq5U2cq+rOR+
X-Received: by 2002:a05:6a00:84c:b0:7ab:2c18:34eb with SMTP id d2e1a72fcca58-81f8f01d6c2mr14668967b3a.12.1768818021306;
        Mon, 19 Jan 2026 02:20:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G38jUyoW+PwpOKIh4mtN9gOgzfgzuXMsYWQvSuCIDAkg=="
Received: by 2002:a05:6a00:928a:b0:7b7:c95c:8da2 with SMTP id
 d2e1a72fcca58-81f807a1db7ls2767458b3a.1.-pod-prod-00-us-canary; Mon, 19 Jan
 2026 02:20:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX62MUXw8G5D9S+GetgJydYtM6rG1g6Eml2CioOypdIgv13sdUOmD9DqAEQ/wnGwdZ9cPMzGZsqRlU=@googlegroups.com
X-Received: by 2002:a05:6a00:188c:b0:81d:a508:f056 with SMTP id d2e1a72fcca58-81f8f1201ccmr15395214b3a.18.1768818019754;
        Mon, 19 Jan 2026 02:20:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768818019; cv=none;
        d=google.com; s=arc-20240605;
        b=A9XdWAOG/uLdstV1utyLsaTwn5+bPU9d9sOL9wyxW50/WQZBpF16AjO/wCqJE/JKTB
         5dNFA81pvXrWLISIK8q5Wg8y3nY9o19KlEbho+lmBoeLVZ/p0ihnmBFn1MtCstmrqCsc
         ltL3vwSRgJKa86og/R5NlmbSKqEXM29D+OVf/Zwi9N6A350RAgWFRYuZtzTuiYKv+T8H
         k2Br9xAnfvr5Mudt/2NzmJJxpQN/QCwhBgauQOPVXje/DoCH+IJ7kbmtETFjUzDhNcrN
         ciRhbwC5qnpGfBN2bcxVHxU6tyc1Cmgdd6cB6x7j0aGEzvc9rRTb1GHmG4eEVNo3+6MU
         b6AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=uufwEcA26X2L64ykZaFMsbyH8luZYH3uk+bytmn50hk=;
        fh=tBs4v0UatAvPKmsO8BTUK8ZWXsXRvbWTtKmjc7MQLRg=;
        b=EP48zPOPltTXUPCx6yqhaamGaOP6Bse24RKbxhNAgxHEYKBxY6NrnRUG0nsg+k6rDz
         q4s3Wv/katty846imqutLGtFP6wtjHpDzynhqRBOzU/Hxt/GA8i5FeBD3WmFAUfymV+x
         2BpYj0ilMRPv9CamJI/sdOzPuHD83+KClgHI9hARR8R+pKMpO7zkBlQQeiL0/zon5WWG
         tIWi2Y5OTf2zE8nocrQSmgnetExOhcR2HIR/K/G6GmMKazikJyPsJ8rHPu3UHnX2JOHa
         TsTB+jJwyFr5IYcNdrNptsQEAdYjh8Wixj3CmuR8HuoHcr9kNgNlWAhx5cF/v2D9X6P8
         PCmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.44 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-oo1-f44.google.com (mail-oo1-f44.google.com. [209.85.161.44])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-81fa125de30si290813b3a.4.2026.01.19.02.20.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 02:20:19 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.161.44 as permitted sender) client-ip=209.85.161.44;
Received: by mail-oo1-f44.google.com with SMTP id 006d021491bc7-661077c4d36so2849958eaf.0
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 02:20:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVhXyKu8Zp2hGIWC7G+CbLGyTkj1ew+AtnAIA90A2sVMLlIKi9qNeoMjyOCc8ztcu4mmkVLVr0WWJA=@googlegroups.com
X-Gm-Gg: AY/fxX5f0z3l8HIZ5CnD/eymKNyM7SGwb3UVR80gqcbssqbLrrlXSsb5DzII17sRZYe
	CThyxWw+i8KTMOurgZIdCNkbx+OMvC9njcdk8HFluomUCSojdb3Nbk/W2PK94X5yM89VHNlZjVR
	UMNAxB608fCvTUCjbZZMIqBUPjqHlPlNOQM+DaEIpJJoqa5F/Z8MJt0hshK7SRzZJoMh7RVSVqB
	fXtz3uyxguUd4WGgSey3PHZma+eU52mPXJ1IwyszUU2jry601bGo5iBQQ3Fxo+NUjJgfm1IAEaU
	vf1Hos04UNxo7Wy6Svj0FSgt0LoJiM8JadV15PlQBDfjaDkOvQ/j3gifzU8gigtyHKsv05JnAyw
	DbqjLjYU0TCp0sXcj/TqX2+/Xy6MraVfxgZLGamL4elljQnOES6UyMXr1YvGa5eA6y2ENNZr80s
	t11Q==
X-Received: by 2002:a05:6820:4613:b0:661:154a:c289 with SMTP id 006d021491bc7-6611812574amr4202939eaf.31.1768818014192;
        Mon, 19 Jan 2026 02:20:14 -0800 (PST)
Received: from gmail.com ([2a03:2880:10ff:41::])
        by smtp.gmail.com with ESMTPSA id 006d021491bc7-66289e3af7dsm3342356eaf.14.2026.01.19.02.20.13
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Jan 2026 02:20:13 -0800 (PST)
Date: Mon, 19 Jan 2026 02:20:11 -0800
From: Breno Leitao <leitao@debian.org>
To: Marco Elver <elver@google.com>, akpm@linux-foundation.org
Cc: Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, clm@meta.com, 
	kernel-team@meta.com
Subject: Re: [PATCH] mm/kfence: fix potential deadlock in reboot notifier
Message-ID: <i2slhi24qpy4u4mtb7edm3sqqcazjfiw52xnz44i4o3vrhvoqe@d2qy423tdjly>
References: <20260116-kfence_fix-v1-1-4165a055933f@debian.org>
 <CANpmjNP5R3ALvtuMyLVhHGZpyZ2MoR7hq07jJFcSAN62Cnig2g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP5R3ALvtuMyLVhHGZpyZ2MoR7hq07jJFcSAN62Cnig2g@mail.gmail.com>
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.161.44 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

Hello Marco, Andrew,

On Mon, Jan 19, 2026 at 08:00:00AM +0100, Marco Elver wrote:
> On Fri, 16 Jan 2026 at 16:49, Breno Leitao <leitao@debian.org> wrote:
>
> > The issue is that cancel_delayed_work_sync() waits for the work to
> > complete, but the work is waiting for kfence_allocation_gate > 0
> > which requires allocations to happen (each allocation is increated by 1)
> 
> increated -> increased

[...]

> Reviewed-by: Marco Elver <elver@google.com>

Thanks for reviewing this patch.

Andrew,

Please let me know if you want to send me a v2 with the typo above
fixed, or, if you can fix it in your own tree.

Thanks
--breno

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/i2slhi24qpy4u4mtb7edm3sqqcazjfiw52xnz44i4o3vrhvoqe%40d2qy423tdjly.
