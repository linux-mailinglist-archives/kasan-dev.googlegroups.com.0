Return-Path: <kasan-dev+bncBDDL3KWR4EBRB245WT6QKGQEEZDHALQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C1512B02BA
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 11:31:09 +0100 (CET)
Received: by mail-oo1-xc3d.google.com with SMTP id x28sf2294818oog.8
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 02:31:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605177068; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZoSrrOgvUCf7lJL81hnb7FGd0iWhKzipe7qCk/DpZamzDLg0ofpc3LA95xyWqLpfJ8
         OzSVePltLX9DczcPLz/KDIkrZvmlpDFEp+zUNE6F3/hd6RZStdPi5TsqcVHOiiWm6sz9
         DiERiHf19fLbmVpwRDEKKUxe1Tb9MpH4pne52c8mrZ7rmZA59u9vd1T10vbD3ORCO/Nh
         2LmZ3U01S4MLSUS736187mDgF9tmJk8acsQuCRcR4u/CwXvOGBlrsktpRezWg9KlWDgD
         uI0dUF+oJmDcBiwhxN4GtlKzbINVD6kRPFYuJgkdYt1vEF9CY91WKs3j/RycOcM9iLNz
         /kyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fJ2KbD/lUBJYETulD+zdGOiB02M5QniZ4w82AQLDE/U=;
        b=OEjS24mC6G608LDH3q4YkZdvSpBtgGPQa+9i5DgVlrLlNeZ6l3xf+Z234NIZ3hMJVH
         9na+uIuo/zkQ6ZW4zmS9KmD7dwFnW0hDCKWTilBI5nPiav01bjO1+DH5VyMh3PjtFPxZ
         Dhsl5QxsQeV+gm3NqbkCmbPrQuP9t/i1FHQNAsioVLVhVimnKBG/SUoc9qKZvcfeMTMM
         570taaYqziuVnFA0WeUlxq/SELWUezavrBMWVE+CmbZQkZjJufqXRfJAtKHq8wIOF61W
         7bP9LcCFSowdDosXEoHc9zfbi/gOVb9yWY+KNrXQbeCvArEatnO7uMfqpFRoxk93JPVT
         a8mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fJ2KbD/lUBJYETulD+zdGOiB02M5QniZ4w82AQLDE/U=;
        b=oUXXdYrf8D2FFkLfIN+G+nHIRne3eGoZ8uNplXtKjE1jIpyb6rAXIBFfhdX8r0ZmH0
         /v5LA8TKyHbCcQRzW38M8ayfStkUmydT5nvpIVCi1ukYy4Wld4rZE50xCyKShpLPoyt3
         bQM3Gz4M0as014n/lxKiyQej7mN6gV5LIMei+AciMXHJ5Xsr/wVZYQkOSedo/5DH9sAy
         xx0LyjUEA9EBLjxcSbM8pyAhfXeSKYCAD2XkXPm07ny8XAuBXwpvc72e+WT+94ASut5f
         wYonP++K8sn6jSumfj8Fe8jdEDn8cmxkvzYOMJATPxNGmLBe0bLIvUFs87uQHPMPkfd8
         pmlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fJ2KbD/lUBJYETulD+zdGOiB02M5QniZ4w82AQLDE/U=;
        b=fzWVfH3O1e4z1vm+Eincmb/H0vG6Qh2I7uGVcWk7B06MnbEIkHZC1918CyF4QZWqNK
         roQBRMoK+C+HwDsQVu7VEV5TC3FjfMl52YBZCS2hObenhY5AzCQfzRpp15YG29EWizRC
         /uO3j0G9+VwQVcVagRFOw9OzdUOrfWp5OqVTMuYumJSfq4VDxW5AvagR+yugfQyyW3UZ
         SQRONnzbtgrould1aCN3uSsUolqzhKZRWEu0T3we/RDYRqvnmqDX6wRpJ2BjLCYHIL2L
         gPVA8RSl+YsvmgKN0dtZPqjsPva5ppS+GDk1iY0e0Ap0OvUHqokQI3irQvXzOTXJgtUv
         kvtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Nv1X1ViaAKGtUvB395nAtSTl9wPASGI+194UFzs/8eQH8V5Cc
	/qdXmdVrO3KVmiEgqR0lZSw=
X-Google-Smtp-Source: ABdhPJwYCmr+MR9GrUsxGxzgSyYS20kGAkvtUjaA8YHXHMjX2Ci1IjiovXySVWIzMbQdlFyf4/CdsA==
X-Received: by 2002:a9d:649:: with SMTP id 67mr21681747otn.233.1605177068043;
        Thu, 12 Nov 2020 02:31:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:198c:: with SMTP id k12ls615845otk.3.gmail; Thu, 12 Nov
 2020 02:31:07 -0800 (PST)
X-Received: by 2002:a9d:f67:: with SMTP id 94mr21313162ott.282.1605177067601;
        Thu, 12 Nov 2020 02:31:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605177067; cv=none;
        d=google.com; s=arc-20160816;
        b=pNzSl2o6Jtroe9j5+cyAoOnnQlfPli/Cli7C6UYE+GTEek97zs+SD7u93ClWAW6x+0
         RdB3eRxktL7PlOZu+DzYFr6CU6tDkxGA/KL7I8B9T1+If+bfoWmDqSsz3v/FqurzLvEi
         EnHP6NEeWmZzSDP7F0j2vZ2xe3fPREqe7OV0BfX1cBkPTDGOuHcvZQBQbBOXAppGZbRH
         hyzfAUwDCkrpVLc+vjRJjvLJN0Y0SZFM7rctzbiJoYa+qbMx53LJ8ZdwNpwpz8dhdass
         wSilK/MwQLHYeOBw73DdBxmgaU++OsJJbrCmP7KsNdUPJERWTBG8P/U3YZ1Cpo9HdjS3
         PjiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=ve9pymIDbJL8QvWmyE730dyF1Zz5dlq43815YKdTq7M=;
        b=MVWSV90/5lyl8NFvhPQ+gMp9xSXLPWHMydBEDBWcEJsr5DYRjKchAufyYDVpC85V42
         RqJYenS6hT1JPxV0yT3Dx19nu4pxHDQqC9dMascqvzuzxe/wmUGCymxqpBZ/+mzWk0nd
         wpxD8W+LNAUsh6TVwJo+ynTLhAj6VJFwknbZagXcH8GW3XlX8XmUa6ZX4T9D1XC/F6GE
         MU3TrD1Yn1o8mP+mT0aXnIVfXth8IT1LsmdxPz6n5mRUTm5ub6hB901neIXuBE08p1Ag
         yDcbl7kUg1526HuuCRzDVJZvkqRFiNyP9IiJlHLuucFL4EKflpfTGB7XNQ1T5EDDHRXi
         UDCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k134si241339oib.5.2020.11.12.02.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Nov 2020 02:31:07 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 10BF622203;
	Thu, 12 Nov 2020 10:31:03 +0000 (UTC)
Date: Thu, 12 Nov 2020 10:31:01 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 05/20] kasan: allow VMAP_STACK for HW_TAGS mode
Message-ID: <20201112103100.GJ29613@gaia>
References: <cover.1605046662.git.andreyknvl@google.com>
 <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <3443e106c40799e5dc3981dec2011379f3cbbb0c.1605046662.git.andreyknvl@google.com>
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

On Tue, Nov 10, 2020 at 11:20:09PM +0100, Andrey Konovalov wrote:
> Even though hardware tag-based mode currently doesn't support checking
> vmalloc allocations, it doesn't use shadow memory and works with
> VMAP_STACK as is. Change VMAP_STACK definition accordingly.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> ---
>  arch/Kconfig | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/Kconfig b/arch/Kconfig
> index 56b6ccc0e32d..7e7d14fae568 100644
> --- a/arch/Kconfig
> +++ b/arch/Kconfig
> @@ -914,16 +914,16 @@ config VMAP_STACK
>  	default y
>  	bool "Use a virtually-mapped stack"
>  	depends on HAVE_ARCH_VMAP_STACK
> -	depends on !KASAN || KASAN_VMALLOC
> +	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC

From the arm64 perspective:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201112103100.GJ29613%40gaia.
