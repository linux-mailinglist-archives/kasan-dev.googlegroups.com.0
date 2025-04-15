Return-Path: <kasan-dev+bncBDCPL7WX3MKBBUML7O7QMGQENA4UMWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 06207A8A996
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 22:47:15 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e8f9450b19sf1219856d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 13:47:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744750034; cv=pass;
        d=google.com; s=arc-20240605;
        b=L0iWAa9PAql2TGAiXLFldTaa/llz1ZbU1whLuN+7IEuDacRycxL1WkkYDLA9jzUPMp
         8QPsZ3NAMy642isbxQx09WuUbMnjayrRrKnQn2aB5kcY1pWoISW0sBOvi8PkjC3YKar8
         5J2ROtHFYRihENcxLTP2y0ScEG26JDrhKD6G9VJAiKgpzUlNGy0bx16E2MP7SF9f6Wr6
         TAsMdSHlqPtcobHCnOJ9LYJY8GkhGQRAkZPX22ArEJGd6V2C/PMbd22+r8bwobM/EdYW
         xnsetM36edRw0bixEnxac/HwK+FhYDBNH3YP9xcxdR9iSkzZa8hpempdeDNmOb0ESdXe
         bw/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YE0ZQ6rlukBwxCLJMayteb3EwvbMQt85C+e6N3RnNbU=;
        fh=Vf6ARIuoXgxKsjJLOU4cj8AKjcl0vWU7A9sC1vQxUo4=;
        b=AgOVmfoD4bh7esa0JSdd+dN6cBsrWyeiDSQwnwpl/6+3mWi18T+eqH77UK5QOmHZN/
         /16pHJn6Jy2kSP5/cBm4sNwNnlyybSMXQ4J0M5OIV943xLg4uhVX07iFEkGri0Ci3sud
         JvfaqIgHy4C5CI9DiuLObgpWCQt7qoqWdC1iGw/IxjBeH8Esv5RgCVm5PCTS6vfdxrae
         bplTm1Nk6o84Q8i4wV/nZ6z7qC8Jh3lfFrjNEH3dies9Tn6htgrSOPToB6dkayZxnSMk
         d07K7O8P+zZFP6bAHbZgBDkMDBz4tdrl6myy2sW6D4hJsQWDgkoy1FNvTCBWlI1WUf/z
         wxQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qh1G5a9X;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744750034; x=1745354834; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YE0ZQ6rlukBwxCLJMayteb3EwvbMQt85C+e6N3RnNbU=;
        b=lKj3x+7mj6L43ox65KZla92HpgF3l0DHbe+OPnT7dBDG910d+Rc6HTn+R7uQRTO/XB
         K1Lj85zaXvyXpld9iUwkGil9FUJ+UZoKNVGF0ZCZjmST/z7EpXw70bBGsUOSDO7ZJhBA
         MZK5MkBXg8eb8hYja1HVSaQo49wYWjbvwsoYc05WUthg8eNbK2Eggl/Cq8wYbSSM8deP
         L9ovkr8U46K6DyO/ECtYS8O45nkbX0TdgTzduRMYJv7vknW7jirDMe0XwE/0gkjlcSHT
         POpFpMlRcIkjFhgQm7nTbELj7QA/kSyyEgmtU3/BpCjTr3EH0vGPhrReqZUqGTzGnpTI
         OtGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744750034; x=1745354834;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YE0ZQ6rlukBwxCLJMayteb3EwvbMQt85C+e6N3RnNbU=;
        b=ELZ/5ZtcVhS9BOuFx0uDL8RKY/MQd5mp8LoE10T6ojbZYA8Mt6mvywV8cNBsHKxzm5
         SZoxFJNRoUfwWXwbGHWuTZPw+ZjKFeEUiLnKl8ZxURODsnM9qrmIyaURYheahVO1W8YL
         EzEEdRKuFsYEka0UVQHyCevOBYq63xam8fzNoIObv1r2Pe56yCnz3Xt2DVc+LqEvSkWl
         +pLuKxIV/CqpJTND3xiPH/sbkfaKwR96zqeQgcfRKyHhDXi27jIwTwOM46Yj28jiFqn5
         u+N6Enz0gXR4KiRPOAXq1yg85WrfxNofFX52uhaU5p7P9dZ/X4ojPMoZeemH4Z752zov
         hTeQ==
X-Forwarded-Encrypted: i=2; AJvYcCViu6DWmMCx9qI5Flkql1hR4pGgnPNGmQYXqCqYgVuhR2X/sxsCU9df6ftQCWBkCXA80lA0Pg==@lfdr.de
X-Gm-Message-State: AOJu0Ywy/YSXKieH8FLDgiiYgxD7KKk10ozXSW9ZlgmMAOn2rR/eTHzj
	apl1WtkwFVcOI3FqizwVfU+QVuORRSRpMpCc+ng/cF+ynpbneG4P
X-Google-Smtp-Source: AGHT+IHn51XxxSLUMiHdR1of9tcWro5r1J1O0C0NIxczgzPT3pBsC6ZzmoGC2ZPwqKGllbVxeX7pEg==
X-Received: by 2002:a05:6214:2f8b:b0:6e4:3478:8ea7 with SMTP id 6a1803df08f44-6f2ad86b9fbmr15349396d6.4.1744750033745;
        Tue, 15 Apr 2025 13:47:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJFtNKSXSl2Uxk1imp+HELYOZdo7dIE+HgRb9lViQg7OQ==
Received: by 2002:a0c:f981:0:b0:6eb:27fd:7b5e with SMTP id 6a1803df08f44-6f0e4983bf2ls4196226d6.0.-pod-prod-00-us;
 Tue, 15 Apr 2025 13:47:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX/H3x6CnFLWzcPDJkbpR/SPZzi5lpAIHL3VGwRekBVum8QpvXfDzVpdta7BZyGCrrliGSzliL0to4=@googlegroups.com
X-Received: by 2002:ad4:5aac:0:b0:6e4:5971:135d with SMTP id 6a1803df08f44-6f2a183a1b9mr77438856d6.18.1744750032410;
        Tue, 15 Apr 2025 13:47:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744750032; cv=none;
        d=google.com; s=arc-20240605;
        b=dg99u5p2P1mmWFmAcYjPNwcY26XgUpuZgEv/h3baHFWTtRLvr7fuSn5NUSPQ6N+VUr
         eTCEpMKKNgoLgG+TGlOZpBsKv80TXTD1BLNfObBnTfYJhlmnhDNfqVx/zdoy0qiKOAo1
         Tsk/4NpQ8+qZha1J3pTqpIBLYJjzmkYA1ejWtWluhhVwivMGfaeVgFX+J8XIpZRQjMdq
         nfyR8Wi4GZDLnI1BGDjyqSe+oWxC60oB7VXHIvZmlNSutaDSRbp0rXgHdRj5Kwudal0q
         EDiu1hZkMHOGpCRonwCiFtrspb/XQ2+Yvu66R0hMN7J8xg9f/mvudxuPJyG3th/2JQwH
         QSOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iUbXsJLgH6XFKUtbS3Upykl9+i8CcxwFyA1C+t0ERhE=;
        fh=RCaeLs57GGuXU+CztvnXu65qjN8vNX5nxg5JgNawftg=;
        b=GQ7KZY7Cemrqqb1XGChJAh3ko/p9WMzdQZiEWj0+8jDHfCwh77XEr7xeEdfFjr0Khq
         kl6J8qDRCtrD29m4iUwbujwX1sKfaU7EMSPWDLgutlmWBkdAg5A7gOcl+e76R2Qwc25J
         5YzY/acp3M77hxpYPmvvO8CRU8M+p1jgHACvH2sYTO9OWuEFA4d35yGaSbyYGYP7J+Cy
         ZJ/Da4FV6VEMuq4FdL0p5HVYABfo/sTFOLx8nD67/R+GwA1nVv1jlLqq+X+dY4A7huuT
         ZoECyaeuf5UCECSZTm+lKJgMxnX5+nrDHaLggPlzCfphQPfSmjc97GsCZoRHtbLDplmp
         Fs0Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Qh1G5a9X;
       spf=pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f0de839103si809126d6.0.2025.04.15.13.47.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 13:47:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4ECDF43F2B;
	Tue, 15 Apr 2025 20:47:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2CD6BC4CEEB;
	Tue, 15 Apr 2025 20:47:11 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Mostafa Saleh <smostafa@google.com>
Cc: Kees Cook <kees@kernel.org>,
	akpm@linux-foundation.org,
	elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com
Subject: Re: [PATCH v2] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
Date: Tue, 15 Apr 2025 13:46:51 -0700
Message-Id: <174475000897.3429336.4470350657359091880.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250415203354.4109415-1-smostafa@google.com>
References: <20250415203354.4109415-1-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Qh1G5a9X;       spf=pass
 (google.com: domain of kees@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, 15 Apr 2025 20:33:54 +0000, Mostafa Saleh wrote:
> Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
> kernel
> 
> [   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
> [   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
> [   31.648153] Hardware name: linux,dummy-virt (DT)
> [   31.648970] Call trace:
> [   31.649345]  show_stack+0x18/0x24 (C)
> [   31.650960]  dump_stack_lvl+0x40/0x84
> [   31.651559]  dump_stack+0x18/0x24
> [   31.652264]  panic+0x138/0x3b4
> [   31.652812]  __ktime_get_real_seconds+0x0/0x10
> [   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
> [   31.654388]  init_module+0x24/0xff4 [test_ubsan]
> [   31.655077]  do_one_initcall+0xd4/0x280
> [   31.655680]  do_init_module+0x58/0x2b4
> 
> [...]

Applied to for-linus/hardening, thanks!

[1/1] lib/test_ubsan.c: Fix panic from test_ubsan_out_of_bounds
      https://git.kernel.org/kees/c/7fd007c84e4b

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/174475000897.3429336.4470350657359091880.b4-ty%40kernel.org.
