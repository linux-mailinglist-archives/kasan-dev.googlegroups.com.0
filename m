Return-Path: <kasan-dev+bncBDV37XP3XYDRBD4MWW4AMGQETCOIOWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 40F4299D494
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:25:53 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-717dbfe7ab9sf1050996a34.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 09:25:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728923152; cv=pass;
        d=google.com; s=arc-20240605;
        b=jzFAwWiqjI7+xcKeAtmeTJtJ5xLZRA8vl+82KY8eKjxAQHi/JUl++639iiBJiRsvDr
         Oc1rgx3swLmhr9u+mHfR0T7CVrS8iFfNAzYHPspJfm0QXacTp8Fwn28nGyy1nZw2gUeN
         DsZfQFdZlvJ/DOiqf6pLas9ybb7Mt6D3TEyxZ4rBBpRP5xb+ANJ71VJHbnxQeQSW7V/4
         e5sQ00/ygiQ/WPO0OUM9hzAzlq/WjvxdjxBdXpCVgTLhP1gK4a0M+O4tIBXgahKZmIFM
         0ik8RuB4EnR1Re0GntkdUAYnqYA0zeOwlQ/kBDH/GQOkUGdALeDpX5nq6lgxSuKZ1n5d
         IdPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=PIj5KM4WK0lLEoiF6MTJRShJck4wEs/y+HiqdKzMhlI=;
        fh=LMeFMfDGk8wXmeKVuHJDk9tcGoMvgBVyrd1ilLCOlsY=;
        b=adrr+qWZKaBXjlFSucMymJ4vP7wlv6ZfdBxMfSiHfEpsPSCgXYlWlfRcCCKZThj9fC
         zTsVaGyCzqoiXihAB+fhLYkSwuBGP2RKWI/Nfms/mO19tSMUvwJ4pJ5HvkOdzjQMZgj0
         VPis9WSTxT4LqrNEOlcWkzSGmQOouSjSaCGHXC1CLjTZdkgNK2nIZLL76AuYru6rQIPl
         4AAzMNFtXTpotvEc/G1dFg59LVTDVUE6hHxwPrxwWNVsCBlKhnAldzWI9Vaq0aMuWha8
         PFea8IAexYPpBaCLqKfBRpc/MGWk9GQpOzQgyZNTRpectITDbxBSGDcbRuonUMn9bZo7
         bDFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728923152; x=1729527952; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PIj5KM4WK0lLEoiF6MTJRShJck4wEs/y+HiqdKzMhlI=;
        b=MyZYRBn/qm3EO6784TjFzA/bEVXqKLofXQJaPHigKhacNlu+vluYeH/P+wGmzhZkYN
         aTtAu3DbAokNxjEEAOHEJ5fb9/dZXx4xoTkLp9uYXu/ZRMPpOGAPuCJaO1ESGIU/3yke
         4xi3xfUwOnw1gCVMJxGVDjbgWv09xWVXMXYYdrh/IHc1HkbPyLWnR122R5kz7itonmN+
         gOYmuzTxQ8NoaFAzLr7XXkOI/AQKfe547jQcS0rKR2MPv8XDiTTj14BOWdCfIIqbv6n5
         5fAFLCUc/Q8n0Td6g66ZzidgOUYUydEQ2RMJxhDX7OXpYMtXSNLcfqnqjxL9DjWzh2bk
         ML8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728923152; x=1729527952;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PIj5KM4WK0lLEoiF6MTJRShJck4wEs/y+HiqdKzMhlI=;
        b=lahnc64XPCrKoXSxqmb/0E6vR/qqO118QmworiW1UiJFFDRGE2DuxeWS2Xx2DJgUho
         pX8o+PZ6jXhGq0O6BuXMup/UjhEE45rDTU6W1+t2xOqqnQFaK+1ExGDD7x1xA/UcTPCF
         az0AUbSTsBxmeFwIhaRuPpTZn+zIvM8H64jIMG8QklCKrlyoVBs2fG8rlkwL+9fnUO2p
         wfk9wFSSEbsKuvVoPD4o5Fl5LUTBomDKm/P1FF6mwVR+FSuzEK8rGCpnyDuII3BEJczw
         liFO19vwGvWm0HBRg+HSNzYIzMYR16Aw9rPE/+ZMgmulBeicfsp0mx9SeuAZWglFzDf6
         eiAg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgN+j59SADvURW/Ouv/YNqLC1JJf6WWIuY6zByG9Y2X5E0/Y7Xrg6Q60r6YRWMa/1YGbw6lQ==@lfdr.de
X-Gm-Message-State: AOJu0YyBVl9CxyfWLhB26nPw0kklNKIWia8iAbBcj+ggpdOKGR8iOxa7
	pkN5qi/vpYlDa3m5N3aWlqLKgDflI55s7SE4P0nitTlnD6+sjuId
X-Google-Smtp-Source: AGHT+IHB4qDV3JV1hpVkqnwTWslvRBDlY01QQ0WrOTVhYS2fLkHHJ5t4GKR4Mv9F2DAej/cTDtfc1w==
X-Received: by 2002:a05:6830:6d1b:b0:709:396c:f295 with SMTP id 46e09a7af769-717df32eb41mr5988762a34.32.1728923151794;
        Mon, 14 Oct 2024 09:25:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d019:0:b0:5e9:8849:bfe4 with SMTP id 006d021491bc7-5e990b33c2cls1142045eaf.0.-pod-prod-04-us;
 Mon, 14 Oct 2024 09:25:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUQYzQNq2QiCMkXHqltwTHCFWlDhDJF4Sw7cInY7nHHMSRvdQ5EPfsGtpjBTIz8vsTcNwp8JvxWjV4=@googlegroups.com
X-Received: by 2002:a05:6808:399a:b0:3e5:de79:2d51 with SMTP id 5614622812f47-3e5de792d7cmr2813427b6e.47.1728923150866;
        Mon, 14 Oct 2024 09:25:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728923150; cv=none;
        d=google.com; s=arc-20240605;
        b=JkNd6Pv5+oCwa9GbKqBBAuc2ea7Cfw72T0VKeN/G39NyvMqqFc56GpV/GlxXbQevBz
         mHfBOCrs46HeSvoZhsSkq8S5qVmZN3dJNcKdc6pWxT3yhsBdKMOSJS3tcw6gQAsvFRh0
         FbNPSbEZt6gUjbJJ2TRMUs7exwWwyNV0kYsBdxHj/Sby0vF7LijhhgFK2LwFhE+4QCf+
         hTq/LQE+LiwY8JYUM8daYWmg35hdE06JRMOgNO5m/gb55udRoAGct4n59uPAEud2rcpP
         PCpXNg6AlwXMbdhkIRYV8rMfwpOe6TghxmP+BD3C6xf/zFnGC6G/oRENcUOwKpF02fLw
         rtZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=obfz6vImuh5gsn2aLaPV1gs91gXfXYMDiwQkl8kUJqM=;
        fh=vINczkVgwL4X3j8S45q2TK4+yujEinJ6K1Dm3esM5FA=;
        b=RynAOnhTxiSrdhElgjnTaGYqBl8mEYf07mkmp4LehypsyzFS5z5/V2hXlXeg9oEHuZ
         glr/2uyB7BaRRkNzt5CbZ5bKR4zPhJWt/LKEWT2VjgMKH2FVMcby+PRjxkqh9AJwDxgD
         Fa96Vag4R7Q+7jIHUuEDIXFoemPV7jQmNW9/b0yXbIuc0VoY2rAxN/AHctFi2fp4vQik
         +zNB1Ufw9/9ImTeK4SP0tqBCCJ7a/66TmRiZPVC7f4FXex2RZuIOwywxzjyhlFf8sD+r
         QRnaNCis3gdCxSfBzp2QD0bU1v8ANOwI3GQb8z9rpvB4X92r9WwuGTXb9y64erUPFEBj
         vZIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 5614622812f47-3e515038b90si391662b6e.3.2024.10.14.09.25.50
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2024 09:25:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9F51E1007;
	Mon, 14 Oct 2024 09:26:19 -0700 (PDT)
Received: from J2N7QTR9R3 (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 89B493F71E;
	Mon, 14 Oct 2024 09:25:48 -0700 (PDT)
Date: Mon, 14 Oct 2024 17:25:45 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Will Deacon <will@kernel.org>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	ryabinin.a.a@gmail.com, glider@google.com,
	kasan-dev@googlegroups.com, Andrey Konovalov <andreyknvl@gmail.com>,
	syzbot+908886656a02769af987@syzkaller.appspotmail.com
Subject: Re: [PATCH] kasan: Disable Software Tag-Based KASAN with GCC
Message-ID: <Zw1GCeNTnbbHE_Bb@J2N7QTR9R3>
References: <20241014161100.18034-1-will@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241014161100.18034-1-will@kernel.org>
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

On Mon, Oct 14, 2024 at 05:11:00PM +0100, Will Deacon wrote:
> Syzbot reports a KASAN failure early during boot on arm64 when building
> with GCC 12.2.0 and using the Software Tag-Based KASAN mode:
> 
>   | BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
>   | BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
>   | Write of size 4 at addr 03ff800086867e00 by task swapper/0
>   | Pointer tag: [03], memory tag: [fe]
> 
> Initial triage indicates that the report is a false positive and a
> thorough investigation of the crash by Mark Rutland revealed the root
> cause to be a bug in GCC:
> 
>   > When GCC is passed `-fsanitize=hwaddress` or
>   > `-fsanitize=kernel-hwaddress` it ignores
>   > `__attribute__((no_sanitize_address))`, and instruments functions
>   > we require are not instrumented.
>   >
>   > [...]
>   >
>   > All versions [of GCC] I tried were broken, from 11.3.0 to 14.2.0
>   > inclusive.
>   >
>   > I think we have to disable KASAN_SW_TAGS with GCC until this is
>   > fixed
> 
> Disable Software Tag-Based KASAN when building with GCC by making
> CC_HAS_KASAN_SW_TAGS depend on !CC_IS_GCC.
> 
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=218854
> Signed-off-by: Will Deacon <will@kernel.org>

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks for putting a patch together!

Mark.

> ---
>  lib/Kconfig.kasan | 7 +++++--
>  1 file changed, 5 insertions(+), 2 deletions(-)
> 
> While sweeping up pending fixes and open bug reports, I noticed this one
> had slipped through the cracks...
> 
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 98016e137b7f..233ab2096924 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -22,8 +22,11 @@ config ARCH_DISABLE_KASAN_INLINE
>  config CC_HAS_KASAN_GENERIC
>  	def_bool $(cc-option, -fsanitize=kernel-address)
>  
> +# GCC appears to ignore no_sanitize_address when -fsanitize=kernel-hwaddress
> +# is passed. See https://bugzilla.kernel.org/show_bug.cgi?id=218854 (and
> +# the linked LKML thread) for more details.
>  config CC_HAS_KASAN_SW_TAGS
> -	def_bool $(cc-option, -fsanitize=kernel-hwaddress)
> +	def_bool !CC_IS_GCC && $(cc-option, -fsanitize=kernel-hwaddress)
>  
>  # This option is only required for software KASAN modes.
>  # Old GCC versions do not have proper support for no_sanitize_address.
> @@ -98,7 +101,7 @@ config KASAN_SW_TAGS
>  	help
>  	  Enables Software Tag-Based KASAN.
>  
> -	  Requires GCC 11+ or Clang.
> +	  Requires Clang.
>  
>  	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
>  
> -- 
> 2.47.0.rc1.288.g06298d1525-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Zw1GCeNTnbbHE_Bb%40J2N7QTR9R3.
