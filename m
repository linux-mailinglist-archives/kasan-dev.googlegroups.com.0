Return-Path: <kasan-dev+bncBDV37XP3XYDRBSFTT7BQMGQEIRH7G3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D94EAF9465
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Jul 2025 15:40:26 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-23536f7c2d7sf15996815ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jul 2025 06:40:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751636424; cv=pass;
        d=google.com; s=arc-20240605;
        b=MYzE49XuckDtdkKmfJKFM2jQDkJM/iqZHbNE6YhQ9e80KK5dJ97JKpUOQMWTk1VfV2
         9jQ2Z7fZ0e93Uil0TJNlLjgy3kNuM99In/jJU4vf9Wao5ZEiMGJKd88yFTot7eEP1nWC
         EmOcyX2jySygH1QCpcsww5ZUxMoNaTxlKHNZEPoyFv26BZJj6xkgSrf7P7/eaIWzAMAv
         1CKTNOMNSbmI0LIIE4KYlH9Jy63yl/mkS3Cd8WQQms7R5nPM17ArQRPK5fRJ+ltcF2fm
         z47nESHceGfMW57Dx3NuoHQiGCtBzcv8GEtx1XtZsvAenjd9BuK5Hi3ltYsuv2ol9F56
         vTKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=W73Ty6kwcrMeANapFmIQIjD4yRC+PKI2RuRMQ4Pv4Yg=;
        fh=HK95p8nneHrWh/eYsFICAEKN6/DBVYh74w+IVxNyUnc=;
        b=HiYOTSLhSkXfSv6NhJ4XsXksYP7246AIBk3PvGPQuqDEbe4fBriGGxXVItgA3qPELE
         dQYq24Cs8ZTWXuQSZa0errmbNx7UUUyADymKKYDP0+8WyEOW9a/TljAOSw3CDrhZxlof
         0tnc0I3okG9RQOMejrvXcIXFMy2W24Yf6GbZkfrqio9hetqYsFDqfSJ1nhJiLPtv5a01
         fUrA5tfNXqmyGLUowAVP5TdT/FvRu2jdJ1kfoS+tiLBeBQkcozrlWk0qM5XllMDsUAhr
         7BcXxFpwWLhnhCsbEahQ1VkPFF7RIRN2IWGCERYIl2ogkuT+E5QBi53sy7w3XBGOxUKt
         HswQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751636424; x=1752241224; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W73Ty6kwcrMeANapFmIQIjD4yRC+PKI2RuRMQ4Pv4Yg=;
        b=pbPd4USSafwbdO1jaOnjO85cHlLB2ZmlDXxUR/vN+nkoHWfnYHg7Ys7oGBU2vOlPnd
         U7O+RjEF9EM/onPYeN+qO1KYcXhVJYXWR7c8onyBml4YPNIgnLx9BP0M3+lB23mzdxUg
         64Cr04QB9yFf1wMKLIqTvS0YKUJYCK96E2X092KdC4OBBAkkSeqrjAtzv+Ij/VmQ/Z9G
         aWPD9NqD3UxHxjfgDsD3MPbJsed6DKsiSA1MvXTwTUNolrYmbBcwQUfnHGS75K8n4HYI
         b177LExwIrT4s1x0Y1/6YY2YFGkwQrmAy0rLHEsUIlELY7fX5BUFxpcUjgr496WFTbog
         kVxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751636424; x=1752241224;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=W73Ty6kwcrMeANapFmIQIjD4yRC+PKI2RuRMQ4Pv4Yg=;
        b=PtL6z57cDSugcUUm95Ps7skwL911JFXsJCtT8QI/izan8jaycs+0434nvkjV3JOu0p
         tnimXPXc2pYdqeuCOsNT+fXyne8zyeneD9bbhqCRes6tPJd1bf0N73cunqy9DmSWI4JN
         TkEWfNp6KSfO28FaUJfpKnYAAK/6s7FvD6kx8QgcwmuGE6m7aJolG61yJovWsUySnqI7
         GXb3PpVIEP4wti/IpKB22Tzmr39K3xJ8TFcCk6QZGlqBHZy4+EA2DA3JFiJW/fCme+C4
         1HuGAnDk+Axw6N+wzoNHlAVNGSkSH44MIsC06HfqMtSCJXODMZCh/6MdoToOwHC2z01r
         kQ0Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkvP8ELwQzvroMmdYQKmiKuGJ2fQUs5Pq+M48gX9A4B2rN5xJ4n/FLzW/sp+C5HCPsjB7hng==@lfdr.de
X-Gm-Message-State: AOJu0YyPrIHIyHt0cTihew+Ba/4nDPIiE1rZ3iuulgfq8Sjfey39IUEE
	OP+K3SfifA+4x9hyat1258LUJmCK6UedMUqa2MmNiVZuQNKrKdyh9Duy
X-Google-Smtp-Source: AGHT+IHTPNG8/M4HC0NhCHT87ipfiHlGPWrKVaOc7ggYUH/qgBhlOOnxjrfjTziM2Pdgqzo7EfdppQ==
X-Received: by 2002:a17:902:d58d:b0:234:d292:be83 with SMTP id d9443c01a7336-23c8746ffe3mr42054785ad.10.1751636424584;
        Fri, 04 Jul 2025 06:40:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc/fHJPx2j98Lissx9q77sZAHzP3Q/GlFQejLECW9R1Jg==
Received: by 2002:a17:902:d48e:b0:224:781:6f9c with SMTP id
 d9443c01a7336-23c89ac246bls4886745ad.0.-pod-prod-08-us; Fri, 04 Jul 2025
 06:40:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWvknXIILFOe6bIzSuAszWkyDP7LKz5xKbbjW+SClmAl8dQBu6e1x78jWinjyllU9Znf88y+Y8ooO8=@googlegroups.com
X-Received: by 2002:a17:902:f792:b0:223:619e:71da with SMTP id d9443c01a7336-23c875da391mr31497205ad.49.1751636423253;
        Fri, 04 Jul 2025 06:40:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751636423; cv=none;
        d=google.com; s=arc-20240605;
        b=afjJ50WdLA6E/s343e7Qn5cqtfV7plEs2wSLumXWgcUiekLPtjLZ7KPSmNlZ8OunBP
         SBPla3RnnSf0wqrIfhOeG4uXwoeNTz1cod2m/xbxkGz3Xmae0E6ecaQRJ1Cr5MQjA2cD
         t/uSqg0VYJ7iwgSJPyoVoYLDJWzN+o45C0OEi2lfiHVbj5y+S5h+mqzi3X9nEs//hNgI
         7Dkt9AqOoYjFUMR2VxSHHmbvE3lO9t3TPceimxR5EwiDbwUUrIa80P4NcJIC++8lVqlb
         49oSNTBWe5vFt+RrW+JbtamXGdbwhatpgrpfBaLRHfsleDzEId4MJpiyiRfY79MWVGgF
         l9XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=zzKM1uvH98tOailuzjR5y0Fv7Qdo/RsLXHElN80NIZI=;
        fh=TCfvvQwElOQncuy53T0phIjaWmqr43jFgUTW2xKcZjg=;
        b=gQIx6COPXGjYzuSQi3w3WK2fysS01S9OR+JWKy7o8GdkUuHWVesLga5XXKP3UrkytJ
         Mn+49tnI8c+x4/+LoLTXkqhdwZD3QYkOppvc2kf7UD0yeC+ZmtyAFoyZz6ndhYEdROSo
         Iw0OXNJ7Rm3j6+5UZY8bs8eLQv3o8RL44IYggeEh1kxAGf1Mf4GW/k+VDZgXcahE1yDN
         cR8LqE9K1oW76U/V7hV1TUYyFblfYj9QGCFa7t64G9KEiF5028NeMhf60EW1yVesT7k1
         RoP6hr3IdLhur5I7a3rVmLwfBtO1Wfg5I3YWDA7ND6KXS2rTN8PQkaCZz7IfyON/SLYf
         z5OA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-23c8451995asi814475ad.11.2025.07.04.06.40.22
        for <kasan-dev@googlegroups.com>;
        Fri, 04 Jul 2025 06:40:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 22BA9153B;
	Fri,  4 Jul 2025 06:40:08 -0700 (PDT)
Received: from J2N7QTR9R3 (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DC95C3F6A8;
	Fri,  4 Jul 2025 06:40:19 -0700 (PDT)
Date: Fri, 4 Jul 2025 14:40:17 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: Breno Leitao <leitao@debian.org>, Ard Biesheuvel <ardb@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>, usamaarif642@gmail.com,
	rmikey@meta.com, andreyknvl@gmail.com, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, kernel-team@meta.com
Subject: Re: [PATCH] arm64: efi: Fix KASAN false positive for EFI runtime
 stack
Message-ID: <aGfZwTCNO_10Ceng@J2N7QTR9R3>
References: <20250624-arm_kasan-v1-1-21e80eab3d70@debian.org>
 <aGaxZHLnDQc_kSur@arm.com>
 <CAMj1kXFadibWLnhFv3cOk-7Ah2MmPz8RqDuQjGr-3gmq+hEnMg@mail.gmail.com>
 <aGfK2N6po39zyVIp@gmail.com>
 <aGfYL8eXjTA9puQr@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aGfYL8eXjTA9puQr@willie-the-truck>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
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

On Fri, Jul 04, 2025 at 02:33:35PM +0100, Will Deacon wrote:
> I would actually like to select VMAP_STACK unconditionally for arm64.
> Historically, we were held back waiting for all the various KASAN modes
> to support vmalloc properly, but I _think_ that's fixed now...
> 
> The VMAP_STACK dependency is:
> 
> 	depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
> 
> and in arm64 we have:
> 
> 	select KASAN_VMALLOC if KASAN
> 
> so it should be fine to select it afaict.
> 
> Any reason not to do that?

Not that I am aware of.

I'm also in favour of unconditionally selecting VMAP_STACK.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aGfZwTCNO_10Ceng%40J2N7QTR9R3.
