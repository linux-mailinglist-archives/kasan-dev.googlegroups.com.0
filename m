Return-Path: <kasan-dev+bncBDAZZCVNSYPBBVPBYTBQMGQEYPVID6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id E13AEB020A5
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 17:42:14 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-2e926f54767sf2804016fac.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 08:42:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752248533; cv=pass;
        d=google.com; s=arc-20240605;
        b=NACsGOcB1+QAUrLMClLGwbiseTXijb6twh5L7qZ0//K5SmzI7ZisKhEh0j5PE18qp6
         zGXX0EHnqL13D0FAX9p3lp5HTE1O1DNAfmQCFqCHsnL/nwKA+2ctMEcFCTP0P0ku1Xcn
         60PRolSEsOVDRVOb7iYDZPw2oGVzXDsRUi9268DYN42Kq5X6SoHmPoKDGtfX09ITGdCe
         8t6nlK7o+VIJCzOwq3F7XSWgv8FJ+OCdBIA8X8jQzN/BJIgooBghTsj/S4rUc/BW2Jiu
         ziFU8cBoxlR0ZCjhYu6revZcqhyn+1+Zpa6pXOC3GlD5nCac5wCrhum+w/JGYiLdeIbt
         03zA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=h2HlkcRhfJlNZ08q2MRghgNXSV/Cn2NrPAkfITqUSOU=;
        fh=XbPs4+a1RFkOVIsNBQAD9e9JPm/ezRZJCOLa78K2cok=;
        b=bOlTJ903TyK4zduaaC2ygi/9GeIunaw0Dq2XCUSy52GvCaqZ5lqV3oWPSrpML5B9kI
         LYJZOI0RxjuOSkMiIOPCQazswxxMZKcWwg1dweyXQy2mtYGnTDBHzoA3H/sMIOR5WbUq
         Gn+7247eRy0otwjel1JkmcfMjDrwmRPI6nLSlaUPOHQroYTK/t4q07h6X+xrqFmagR6X
         PzJ5xX1ihd8mHAlZQtu0kHJIV/ZNVpmtfyDzV8cwTmbPQGcQfWcoIwwDpX6C3mA2xrzA
         /49LMHMANO23ab9yPx+8adSbLjcdmRZzviyKpv3qR7G3xdSubVk9CBqbF4oy7mxZA2io
         WEAg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GyYC3N3A;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752248533; x=1752853333; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=h2HlkcRhfJlNZ08q2MRghgNXSV/Cn2NrPAkfITqUSOU=;
        b=V3souSOp6SWsPMz2SFpz8YJMjUlmXm8QbnUwcCMdlrbhdCc70iksRqMjdFoEy0IVTw
         p5RLZpmqAvUGwwhFM4cQUOMIrtbx+stu0kBTd8CfiyfmSquGJuK2jXZORcdX9ME12up3
         3D0nHNmMzjq6991wDr9d7TDjVsOTtJzzulrt5p+DRnV8FOTRo5rEHpiOHRCNVyKGaf3F
         91dIp0M7/SjdyZqdaEKjFTXoXZWf+5zRWbTlAQHoeGoRW/GEznRGZtrWRHBs0dYz/z0n
         E1pKP4ALPqSENY0AwHoMYC/r6NIVukz/pMTUZk5tp7YGlTLyOoI+2pkZJbBN38OyAgkL
         GD7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752248533; x=1752853333;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h2HlkcRhfJlNZ08q2MRghgNXSV/Cn2NrPAkfITqUSOU=;
        b=KpmUD3uj2yGxMjygHlnTunKdqsPl6BgF94mkNHX2UC+0xrac55b9cpwlByWXZRWqx5
         Ccl51BpUP9LrQ/Cp6ZremUgtHc+7LI6CA0HCqnoC81CaqFx6mVNwyn7IDbsCHQm93rwL
         by0r4yEYsws6ph2OJyFU8OiGwMSVgePrvTeSK4COhjQQxhnxpXZnNrUhqERllUmyDqta
         3rNMe7UrKcUv1C0bxVsoEMI+jWADecTBD9WuBKX2x+HRt6W4jyASCWyWWrRZPOHKr4E9
         v2h8FRnrLF35Vr+bHZ2d5qNOL+TwAHASi5TF3XhUFgc0oaESmqflAnjBBGJUbXJfzMp+
         pTzg==
X-Forwarded-Encrypted: i=2; AJvYcCUX4X+Kw6JtEyA7Zyj/UJNQ5BWtimJ6fAO8NtSvrpGpjG5gxw1RpbbSrZXhiVQWOnCsHrNH3w==@lfdr.de
X-Gm-Message-State: AOJu0Yz6ANsAwNAAo9pZRj57NBYgsx2UPyR35f9Pyutl6fqhz5OMLNXQ
	nobI+PwhM2w1OiapBSEcoElPcUrao0xMWxjgYFftIK0FT/qtJ5sd6wU/
X-Google-Smtp-Source: AGHT+IFXEYd9tkAjci77yVQOJTjra7LDP+XSGfxXSVca4LnMfKd8/4iUEwMoomjj6YOWUaHCDDNaRA==
X-Received: by 2002:a05:6871:727:b0:2d9:8f98:b0cd with SMTP id 586e51a60fabf-2ff0c77d0ecmr5956997fac.10.1752248533286;
        Fri, 11 Jul 2025 08:42:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdg710owmYqQ2O91Tj1azDZm+sIHRULhwfCUaoD51SAdA==
Received: by 2002:a05:6871:a219:b0:2d5:17b7:9f8c with SMTP id
 586e51a60fabf-2ff0bc369ddls934423fac.1.-pod-prod-00-us; Fri, 11 Jul 2025
 08:42:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUaYHZGwN5t5rRoODFM/Z4JZG0+wQOKyJjztCGT9E+Qgu8eDRR32k3oKBL9z2L6A6zGHidamTWMuKw=@googlegroups.com
X-Received: by 2002:a05:6870:aa8b:b0:2da:87a2:f223 with SMTP id 586e51a60fabf-2ff265c574emr2451727fac.11.1752248531929;
        Fri, 11 Jul 2025 08:42:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752248531; cv=none;
        d=google.com; s=arc-20240605;
        b=VrwYp+HG9Uydjzv5yqnOrYJKsaTKgVYn9N9OPz8NT7WRKlA1eacfjhFDlfhsRVyUVH
         zWyv15pJamWGPikSNQFxE86QLJEYV4+1/FY3SIn9vJYdx2BRyVHcrPnhIoykfViR9pyK
         jKSNqWC+vb6iw0NmnDfCieStgogBM43gStOsO/bMulBKa0CRxVrMXSZ3JAnelNTJ6Oln
         tS0BKAXsum09grW2u0pIc58swim0iu1gugvJ1KRnsJfHTUld0FyCszfuxLVgMqZBAl3S
         CsgHhHkf6NydnqmMU3BmnxZWeMY2VlHLJGbMGo/KN0c209P+DKQ4R9yEzb54i8QxPxS6
         yhEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=5Bh+EJq1eUrlDF5qFb56orBglILXN8HN0hoYDeEXxPU=;
        fh=KLg+pJ4ecnDVJ1gM5jMUFVr0Fqwe/dvP0z98Xv/Un6c=;
        b=dJEI43XIfLXOQaS6Q+O6tdMJrBsdLtDlCNOC4Xoc8KG3locYsx6+pAbJ+Tg/Komja9
         sVGRyx5OFzlBhtfIOs5oTB4Vu72fVNih2NVbhuB846qjRC4unfg5vxdSxuxOq85OO2CK
         hpTyKtFqvUl+DlCFng3kG91ctC1h205p6exvN7dZ9CRvS8mK4ywQ5VUs2d9lhsAarHmP
         QjT/ISGjrlCQyv003dtPqKSfae3qSejrRJ92y5kccyMsThIg7BuW5p4TGxbLd+Y+wEOK
         L8wd0zyqESS42yfiLDD8k7sOh3iMTArjdeccyzfM7YQWJki//spUD/8BD9WyTuGPBnju
         xfuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GyYC3N3A;
       spf=pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2ff1124591fsi190598fac.2.2025.07.11.08.42.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jul 2025 08:42:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 118BF45D66;
	Fri, 11 Jul 2025 15:42:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A48F9C4CEED;
	Fri, 11 Jul 2025 15:42:07 +0000 (UTC)
Date: Fri, 11 Jul 2025 16:42:04 +0100
From: "'Will Deacon' via kasan-dev" <kasan-dev@googlegroups.com>
To: neeraj.upadhyay@kernel.org
Cc: rcu@vger.kernel.org, linux-kernel@vger.kernel.org, paulmck@kernel.org,
	joelagnelf@nvidia.com, frederic@kernel.org, boqun.feng@gmail.com,
	urezki@gmail.com, rostedt@goodmis.org,
	mathieu.desnoyers@efficios.com, jiangshanlai@gmail.com,
	qiang.zhang1211@gmail.com, neeraj.iitr10@gmail.com,
	neeraj.upadhyay@amd.com, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org
Subject: Re: [PATCH rcu 06/13] torture: Provide EXPERT Kconfig option for
 arm64 KCSAN torture.sh runs
Message-ID: <aHEwzENaa9hNGt2k@willie-the-truck>
References: <20250709104414.15618-1-neeraj.upadhyay@kernel.org>
 <20250709104414.15618-7-neeraj.upadhyay@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250709104414.15618-7-neeraj.upadhyay@kernel.org>
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GyYC3N3A;       spf=pass
 (google.com: domain of will@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=will@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Will Deacon <will@kernel.org>
Reply-To: Will Deacon <will@kernel.org>
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

On Wed, Jul 09, 2025 at 04:14:07PM +0530, neeraj.upadhyay@kernel.org wrote:
> From: "Paul E. McKenney" <paulmck@kernel.org>
> 
> The arm64 architecture requires that KCSAN-enabled kernels be built with
> the CONFIG_EXPERT=y Kconfig option.  This commit therefore causes the
> torture.sh script to provide this option, but only for --kcsan runs on
> arm64 systems.
> 
> Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: <kasan-dev@googlegroups.com>
> Cc: <linux-arm-kernel@lists.infradead.org>
> Signed-off-by: Neeraj Upadhyay (AMD) <neeraj.upadhyay@kernel.org>
> ---
>  tools/testing/selftests/rcutorture/bin/torture.sh | 9 ++++++++-
>  1 file changed, 8 insertions(+), 1 deletion(-)
> 
> diff --git a/tools/testing/selftests/rcutorture/bin/torture.sh b/tools/testing/selftests/rcutorture/bin/torture.sh
> index 25847042e30e..420c551b824b 100755
> --- a/tools/testing/selftests/rcutorture/bin/torture.sh
> +++ b/tools/testing/selftests/rcutorture/bin/torture.sh
> @@ -313,6 +313,13 @@ then
>  	do_scftorture=no
>  fi
>  
> +# CONFIG_EXPERT=y is currently required for arm64 KCSAN runs.
> +kcsan_expert=
> +if test "${thisarch}" = aarch64
> +then
> +	kcsan_expert="CONFIG_EXPERT=y"
> +fi

Acked-by: Will Deacon <will@kernel.org>

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHEwzENaa9hNGt2k%40willie-the-truck.
