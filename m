Return-Path: <kasan-dev+bncBAABBMNB5LDQMGQE6VLHPBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E7842C0364D
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 22:31:47 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-798920399a6sf2252585b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 13:31:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761251506; cv=pass;
        d=google.com; s=arc-20240605;
        b=RwLeNdGtqIsjbrVw1Si1zv4kDLVtkOcaTgE5RzqCsmlFTIV1bpNU5jhK54gS9XnsRJ
         h2MLyeex3V1+KO0lqplRNY6swQ42moy+e8FslOgNDQ3kC2yJ+Hjddlx8/NhEaFdHopRR
         2DTPBKVZVYlMQiJJSszvalpMyHqYsD/znRfsfc5gt8xPB/CBWRlqXEv4nlcQVGMuF7gB
         g2uugzrKL8mITN8zK1Q5/ZYlUqZ6Z1tVpfRp4MxLckQRXJOcesWt3+sKEUhYOa5kDr7A
         U0H+jYoKlKmgWocC+/zKdFqSqRBYgj0p02x+8DdddU6eJESEZVqFfWHAvCXPANZxrNTy
         ymSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=SQzdiWEnxuRKw+FwXgJGb48BCysWFjdrm9+K8g60/XY=;
        fh=aduYFbchq+vtt4sPyd5stqWM6eNhR+BHXNDbuOMJueU=;
        b=a/hPbhP1djCP+wJ60bpmMsVGeuTKtLy6u7/Lk1xF6r6BKMJTR2DFIfcKK4BLaRsmdM
         En2RbKDu1zJbh8SWdfmu6sNqYfjhn+GHLBMcKU1I6BFI5isMWs75NU4tT5C1y86PKBe6
         oxZHJPMjCVWaeJpSJGF5H1cC2TSgyaML+lhuKJiG39fw9uSO1NUC+tp/xXON0mI8N6fc
         HobAtqqANJ2HH6SgmfajXOQCYddm7s9Ylm3eZrS07lETRICf+iYLqCBXl25exhdeShEs
         4tEgsPWWU56UrZFgYQwWZvvs+azB6ncdD1PelOGI9BGj/Y7f5PUzdovkvvy4DiQgK97J
         OZbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N7akVhzN;
       spf=pass (google.com: domain of nsc@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nsc@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761251506; x=1761856306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=SQzdiWEnxuRKw+FwXgJGb48BCysWFjdrm9+K8g60/XY=;
        b=pjp2Or6YHfNlhkJ66uDayfB5I+H74wMd5Lea22zrS6TwkGGLxRZKhNF6BeWhc6MvOJ
         y4ngqoRQT18KDbvh2pNWTM8GgF7eveEhBPQXPVU3ppaEII1PoBXWIDvgaKeVIn2/liAw
         mwKzQ91UZqx62VxL9uwWkL7OYyfmRUKdCQhenSif2zfVo09NR2aB8z6vZegMPZKC+Zg3
         TU6NoeLbTGw0OnK2YN3+GBd13JSrvApqt4gT/94OoCe5WZgor7UN+CViWmFILzT9MCbW
         5M3BjGJCcZ5/dDG9kGuUfVpjfH8PvMXkXwCTz+9Aw8+M48aaXlwpUyjIGT8JTzWNLX8E
         hN6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761251506; x=1761856306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SQzdiWEnxuRKw+FwXgJGb48BCysWFjdrm9+K8g60/XY=;
        b=B9vJe502QMxb16cA4cMOmKSkMAi08YuaYQoiKQcDA6vVopJF8oaO5hkb63tEuyL6pk
         0/0CbiMGuqFUmIM4jeqlFPH0uouSdyx5OcAkDmN07V5hwdWb6fIOwhY+66/7sSNXxutK
         L4LdI/bd+ST/xiYfZbrg9TXJH44eOaXkyA2uqFKW4eF13z5O69F2xlDqc2q4O7ctw5xz
         PF2g9PXpw1uuGH+r1wUADUooWq5KaXa7B0CjndwBAoxViKUvpxIDajE9Z6/PBjZpIO7G
         QKp7xe/+9mkQf+A2T1KQFP7D9DVBqxFl/o0mKsmy/1SrGwczX3q00f93vKmiI2gdpcA6
         qqDQ==
X-Forwarded-Encrypted: i=2; AJvYcCXIeXaiMcZ393GHDp7Xhb6kQ0y84ZLBExN7cYhRZGLCTUTx4bu+MNl+zRKCrENSWqQi1szUUw==@lfdr.de
X-Gm-Message-State: AOJu0YxTzKhow+LHEmhidKnzupgIdxFUSybzMOtLvWS1TujKQySiqB3z
	PhT7mzAHkE3xrW52/GRR/GwQPFl8TYLZfOBTff0+iw2h/EWSO5O1AZwg
X-Google-Smtp-Source: AGHT+IE03F/bteCVdOHDCXblp9HfW5dXKCdeYNK1TEsMiumqIJNpc32pt6TjTacUjQURBNMB72k0kQ==
X-Received: by 2002:a05:6a20:6a08:b0:33b:20b9:d249 with SMTP id adf61e73a8af0-33dafdf9809mr387209637.0.1761251505920;
        Thu, 23 Oct 2025 13:31:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bSAp8edSUYLXLUB0kWN4xxDOEYIEPdTahIgu6KDL18cg=="
Received: by 2002:a05:6a00:3d85:b0:7a2:7ff1:d3d8 with SMTP id
 d2e1a72fcca58-7a27ff1d62els150796b3a.2.-pod-prod-00-us-canary; Thu, 23 Oct
 2025 13:31:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1Nte0pJUxXQMPHesUMJGwE/uIy6V8sf92WfkjzD5O/iDhza/bp9lVc20sKESapO6hgdszO+pG5UU=@googlegroups.com
X-Received: by 2002:a05:6a21:6d88:b0:243:fe1e:2f95 with SMTP id adf61e73a8af0-33db2739982mr402387637.6.1761251504710;
        Thu, 23 Oct 2025 13:31:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761251504; cv=none;
        d=google.com; s=arc-20240605;
        b=jHdElxjy5KusMcl79EocH7OO40NVKOJir1gE+8BHrCzTXecwaNfCojIGynG9xIYrcP
         aiw7nUJx2Bp68OG0uQdx4PHol+LHVHcbmSeCijRj0VThuHHRwxsEBb72M8VSI2WWNhNb
         Jl3ONAK/LZJgvRi5IjGtfFhRARf7zDtta9hxf3KbeCdD1PdJnlqG3CN6COgsgypWmb8s
         19im6+kTsi9FF38AMk7izh9iJDKXzGAKs+DLSsI0yzAfkdNjs3TOcCbsmc/TSvizg7Ie
         cc8UXg0ljs9ecB5u5BXRqfBdXL5cf/F60YG9bm9CbvYxWy1uL8FRrBECeYpBdoSdH08u
         ChIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QPfJdIo5ovqedHk2C/JfF1Ih2L0Ay+1E50xYAGVXtsE=;
        fh=UQrYhvPCKU95cdYsi6fpxgZMBKiJpu39GbrNBoxgBkQ=;
        b=VbjnEGUP0nWOAEDjZlYEQfxIReWSt1gqzsbEigJ4PIagi+S+XyTbCAYM4k7bUcTEZD
         rasO9VeM3SOOs1xfezUeVlgxCDSAR3YJ/U4riYd+vu9o6+xb4a9qS5pWbMqlnrJK58KK
         QDlsvTVk30a45MJNqsrry8Ht7y5PzeTBeG2/v2rqxh3ZMMiVBrvpKPrqyMTB5MhLLq5R
         yrR5vtLFlGvk/fMp3MK0/QiHrV0qes0M57vtqy4yG51KAXPCTkVFBXC4YW8ns6hiixU/
         jCEE9SK/Dt7uXQIClKAxzRfNt9AdDCEm2dpGSNKmHeTq8QS2IhjPMNS3tDACbMzPzxJV
         53nQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=N7akVhzN;
       spf=pass (google.com: domain of nsc@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=nsc@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b6cf4a82ae5si230100a12.0.2025.10.23.13.31.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 13:31:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of nsc@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id BB119611C6;
	Thu, 23 Oct 2025 20:31:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 11136C4CEFB;
	Thu, 23 Oct 2025 20:31:42 +0000 (UTC)
Date: Thu, 23 Oct 2025 21:50:34 +0200
From: "'Nicolas Schier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Nathan Chancellor <nathan@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Kees Cook <kees@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, kernel test robot <lkp@intel.com>
Subject: Re: [PATCH] KMSAN: Restore dynamic check for
 '-fsanitize=kernel-memory'
Message-ID: <aPqHCrC0JPwQynWd@levanger>
References: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
X-Original-Sender: nsc@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=N7akVhzN;       spf=pass
 (google.com: domain of nsc@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=nsc@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nicolas Schier <nsc@kernel.org>
Reply-To: Nicolas Schier <nsc@kernel.org>
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

On Thu, Oct 23, 2025 at 09:01:29PM +0200, Nathan Chancellor wrote:
> Commit 5ff8c11775c7 ("KMSAN: Remove tautological checks") changed
> CONFIG_HAVE_KMSAN_COMPILER from a dynamic check for
> '-fsanitize=kernel-memory' to just being true for CONFIG_CC_IS_CLANG.
> This missed the fact that not all architectures supported
> '-fsanitize=kernel-memory' at the same time. For example, SystemZ / s390
> gained support for KMSAN in clang-18 [1], so builds with clang-15
> through clang-17 can select KMSAN but they error with:
> 
>   clang-16: error: unsupported option '-fsanitize=kernel-memory' for target 's390x-unknown-linux-gnu'
> 
> Restore the cc-option check for '-fsanitize=kernel-memory' to make sure
> the compiler target properly supports '-fsanitize=kernel-memory'. The
> check for '-msan-disable-checks=1' does not need to be restored because
> all supported clang versions for building the kernel support it.
> 
> Fixes: 5ff8c11775c7 ("KMSAN: Remove tautological checks")
> Link: https://github.com/llvm/llvm-project/commit/a3e56a8792ffaf3a3d3538736e1042b8db45ab89 [1]
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/r/202510220236.AVuXXCYy-lkp@intel.com/
> Signed-off-by: Nathan Chancellor <nathan@kernel.org>
> ---
> I plan to take this via kbuild-fixes for 6.18-rc3 or -rc4.
> ---
>  lib/Kconfig.kmsan | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
> 
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index 7251b6b59e69..cae1ddcc18e1 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -3,7 +3,7 @@ config HAVE_ARCH_KMSAN
>  	bool
>  
>  config HAVE_KMSAN_COMPILER
> -	def_bool CC_IS_CLANG
> +	def_bool $(cc-option,-fsanitize=kernel-memory)
>  
>  config KMSAN
>  	bool "KMSAN: detector of uninitialized values use"
> 
> ---
> base-commit: 211ddde0823f1442e4ad052a2f30f050145ccada
> change-id: 20251023-fix-kmsan-check-s390-clang-190d37bbcff3
> 
> Best regards,
> --  
> Nathan Chancellor <nathan@kernel.org>
> 

Thanks!

Acked-by: Nicolas Schier <nsc@kernel.org>


-- 
Nicolas

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aPqHCrC0JPwQynWd%40levanger.
