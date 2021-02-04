Return-Path: <kasan-dev+bncBCCJX7VWUANBBFNR6CAAMGQEYFD7BTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EA9A30F6D1
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Feb 2021 16:53:59 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id b81sf2691509pfb.21
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Feb 2021 07:53:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612454037; cv=pass;
        d=google.com; s=arc-20160816;
        b=Py5LMOVvXlqfz48I06/H0y4gW1IM47+RV77Msd3RiEJhg27JTnK3cWZXsLalm+GL13
         UA9/EATu7e+t0mdheob9KF2XjyE4+l1Q52/w/tQZAHT0QkIfPInuuClr4qmCLFxC96o6
         q1wRQHVi186mhpIcrgje/D34k5EBpb4h8coN3Kid6G+qmuSYEZTYnh11mYJbhlvxQDDa
         WnH03/Q7fehdSMvf8+W+527/wGBA8C7JhTivrdPTW2ZQVAkTnRriTUQeXe3PCso0O2/f
         lmgQXA+Z6nVdbboDCixUw4kZZ0E5sYWdpdbKYQ5NwmVkXZOnVctsgKoTOuS3C3TsEVmR
         ao2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=L+IyvJvUES02N4dOTFE8Ro34uE2DnPFlPojSVgNeIg4=;
        b=URwGHWWU6BZI1VrhFfVN4M/S9UtIX1YdRiL6pOGADBKYS/VwHepoU2g5YnISB+mOQf
         To9T8jIYJITHou78QbHJkDc7cYex9beDthpDM9RE9+xXlFtdpwnq7HFon11eeVgTsJT9
         cZBRWFHUxVK7Frvzk10JSGYEaknr+7t/MrKjvDs0ZFoz0j5NvOx7ZTadLd74lQ6aXADp
         /+LWkIxiXFiKkN40pfv1e2yIsiYAUF8LXhzXY3rDGF4SapzV+zX/yWTzOyIzjPMmAOrP
         Nw19TZnywz1G4t+L/eVpUiukTeyb/ZYFFdc0npcMAcM9EH7Qpe33mlBbH6tT6A6KFB0v
         AO4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NinYrz5H;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L+IyvJvUES02N4dOTFE8Ro34uE2DnPFlPojSVgNeIg4=;
        b=IvjPoaSpjtce/tTaCgz2CkZP5DmxDpZe0b9/b7qMMMf7Am5kcU0vik8T0MLSPH/0If
         bJ4sP9eNJEMwoHMh3Xk7fEb9Dy+N2/Ael8cYBpghtQ2AaCg26XwYmXQp1uU+9NEY4ye7
         3b2tq+mSZtsHWCUchwCNaeYsIkw6x5zptBavAXR+AhSfD8ACQS9Mzd+zaKktM9wQL3MH
         JWS5Ocz6rFEv04yyAZMvQa8De3TW2HbvQmKcLWqwbNBuCYqDIvnPX3InBKcY2nxl7A08
         EehSMwNVHOBuWbZ9eBLRV9aPP5bgrae+HhrT5lXVQKoAQqfoczOuNfTWCI2WmEJDeVHr
         a9/A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L+IyvJvUES02N4dOTFE8Ro34uE2DnPFlPojSVgNeIg4=;
        b=lPlpuV3na1UVXB7QQP558SfI15qnJuNeKU1NmyhlfRb/mioWj8GNOvDKKS9A9ezWwT
         buxZrjaqJYWtLJTA2tAUyFRfigvaRxcVRC9yEGi7nhhtrBhhtNaLqKdGQmbdvGBx9p4Q
         PsvdYgRyNl8VtizvW1aeyZzVaFU2AsJuJiQYckooUXuQPXQ0dZNqz6ExIAHlCRtNefGm
         fg+ZO6anBJRaoThf7CXDIjQeuGzROWtBVurUlwj5Sr8gzwNU66WZKJAlhHlxuUFNZnNB
         e7a+X1T0hUtpZI/KKjosnEzbgsep0wmgvE4/fzx3c4Rk/5+e6dXMtU52heYFMFtdNjl0
         tFKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=L+IyvJvUES02N4dOTFE8Ro34uE2DnPFlPojSVgNeIg4=;
        b=P/0I6uZHm/QDiUxmyev015tsW19QqLQLWY9lEIYYkLxz89H9pCaAQdzIkbADrRBoDQ
         x6xaUXBbuWQxGbSZTKFptQUUwyc+jd6/gca945hhtvdXfoOze3v8xBo5faiZt279av60
         LyQg2vOK5261sjsj2aIjm9+vyzXU6EdJ2kI1V1oBxLjQ/WTGe6YuEKJFBpu9dnE7j5oV
         Y/PpR6ooLT6sPj3ZV4i95mzfv3zD00haLlweae8TbICNzIpSOX3Zd/bSakLQWLL0ZFBK
         Y3wTIAToJrLajeGxz2Y6a2q34MBHx/dNuF6wRZ5R+MYRu5kvt+FfLk+N6XZ6dawBgASx
         1Xtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531THt4eYTk+lqR45r83iWv9vMs+bCSEx3MLrBFicSXz0qA2QJQX
	LCb8IMP4zMSLj3im1WT2rFY=
X-Google-Smtp-Source: ABdhPJxVnjF7pOXRYJH2Y74Fx1JOeYBm2iLIl69sZ48WkeTalQV/q1n+1Lvss6SoBg8NpmfWeVR6Tw==
X-Received: by 2002:a17:903:2285:b029:e1:58a2:b937 with SMTP id b5-20020a1709032285b02900e158a2b937mr8671120plh.68.1612454037425;
        Thu, 04 Feb 2021 07:53:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4015:: with SMTP id ie21ls3090210pjb.2.gmail; Thu,
 04 Feb 2021 07:53:56 -0800 (PST)
X-Received: by 2002:a17:90a:bd0f:: with SMTP id y15mr125588pjr.141.1612454036823;
        Thu, 04 Feb 2021 07:53:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612454036; cv=none;
        d=google.com; s=arc-20160816;
        b=uElmLodC7T5PZeQeN4G8u/JRqLDG7rqfEk4G5Qx14E0jKckH1Z1Mu6LXZrKyYK1dsR
         TqOfY3Bzluo7wyvMw76s3DsNYzmu0ska7DCIFZ7Vf5RXPstNMHJcHiRmJMvFZlLMO6nO
         8lTf/M7QVmfpZBmTBYxkrvtZ+LPh4pwEQYFbJrAxOt2x5mUOOWpVEJGjv9EMoTIpz3iw
         jXSmJRxtEWpNwWTcSxiBexrjMjMvhQgkATJYIoTApr9jsr8c/v6fpS9S+d/+Sce+mnNe
         ij27nimHk2mS4lfiwTicHyrTw68hPbceePBQXmSGMkHxSsCP2Ob8fBUYJagLaSn4e2Kh
         9mbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=12TvnDbFoHozjXEBq3jhYOc5BE9nWZn0P3eT299I/9M=;
        b=IxVsMdJgSbCfYos1I6HzrOrqNaPRnqBq9Yv2IgtJdHXv+VzF0UAaNpNMwHr1v3lRpj
         UmKHLApdS8ERDN5tfS7SpVPhQ7KXJuvhgf2PLLMG8FHDwamJyVybw8hCiY8fNrn02uRN
         0LfLwpwFTmW3X1b4sW/PJL6XwY/eIDwotCyBVbb7lPkW62pi1kDq0jzY1kINEGcaM0FK
         H3/ijXjaZiK3QkcMi5tp8aUF8v/Ad9N0EyUcHVN5eec9IML3KqT23kNShkRIE6EGYP/N
         nb/HkcT1jwK+rN+emN64JrDQ0Jct+Ux5FT55z3ZT6s6d5TGG7/W2J2W1mA/qRMsf+f60
         Q2Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=NinYrz5H;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id w6si317274pgg.1.2021.02.04.07.53.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Feb 2021 07:53:56 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id x23so853825pfn.6
        for <kasan-dev@googlegroups.com>; Thu, 04 Feb 2021 07:53:56 -0800 (PST)
X-Received: by 2002:a63:105e:: with SMTP id 30mr9541231pgq.24.1612454036561;
        Thu, 04 Feb 2021 07:53:56 -0800 (PST)
Received: from localhost.localdomain (61-230-45-44.dynamic-ip.hinet.net. [61.230.45.44])
        by smtp.gmail.com with ESMTPSA id 16sm5580890pjc.28.2021.02.04.07.53.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Feb 2021 07:53:55 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: will@kernel.org
Cc: akpm@linux-foundation.org,
	andreyknvl@google.com,
	ardb@kernel.org,
	aryabinin@virtuozzo.com,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	dan.j.williams@intel.com,
	dvyukov@google.com,
	glider@google.com,
	gustavoars@kernel.org,
	kasan-dev@googlegroups.com,
	lecopzer.chen@mediatek.com,
	lecopzer@gmail.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mediatek@lists.infradead.org,
	linux-mm@kvack.org,
	linux@roeck-us.net,
	robin.murphy@arm.com,
	rppt@kernel.org,
	tyhicks@linux.microsoft.com,
	vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 0/4] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Thu,  4 Feb 2021 23:53:46 +0800
Message-Id: <20210204155346.88028-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210204124914.GC20468@willie-the-truck>
References: <20210204124914.GC20468@willie-the-truck>
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=NinYrz5H;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

> On Sat, Jan 09, 2021 at 06:32:48PM +0800, Lecopzer Chen wrote:
> > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> > 
> > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > by not to populate the vmalloc area except for kimg address.
> 
> The one thing I've failed to grok from your series is how you deal with
> vmalloc allocations where the shadow overlaps with the shadow which has
> already been allocated for the kernel image. Please can you explain?


The most key point is we don't map anything in the vmalloc shadow address.
So we don't care where the kernel image locate inside vmalloc area.

  kasan_map_populate(kimg_shadow_start, kimg_shadow_end,...)

Kernel image was populated with real mapping in its shadow address.
I `bypass' the whole shadow of vmalloc area, the only place you can find
about vmalloc_shadow is
	kasan_populate_early_shadow((void *)vmalloc_shadow_end,
			(void *)KASAN_SHADOW_END);

	-----------  vmalloc_shadow_start
 |           |
 |           | 
 |           | <= non-mapping
 |           |
 |           |
 |-----------|
 |///////////|<- kimage shadow with page table mapping.
 |-----------|
 |           |
 |           | <= non-mapping
 |           |
 ------------- vmalloc_shadow_end
 |00000000000|
 |00000000000| <= Zero shadow
 |00000000000|
 ------------- KASAN_SHADOW_END

vmalloc shadow will be mapped 'ondemend', see kasan_populate_vmalloc()
in mm/vmalloc.c in detail.
So the shadow of vmalloc will be allocated later if anyone use its va.


BRs,
Lecopzer


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210204155346.88028-1-lecopzer%40gmail.com.
