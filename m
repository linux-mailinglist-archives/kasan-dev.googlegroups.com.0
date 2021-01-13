Return-Path: <kasan-dev+bncBDDL3KWR4EBRBWOV7T7QKGQECCAOG7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F67D2F50C5
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 18:16:10 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id bp20sf1969737qvb.20
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 09:16:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610558169; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ji9Xzva6HWXTYpHkCrF6Haq1XlvW2Q0zjIoMqI6GUmixRmEzEPDzaRcpWz1aGnIT6D
         U3ZyfCD/Z1umqze36zNCiIjk6eKdlN93FytqBhua1U+y/e3ytGRAVZWJ2uTzZOXds8zg
         6AMCjtnptjh3PkUqcreyktkURladjp3ADZwBH2cjkWL+NYcA/BQGNVTiGXnvpZur13rH
         /4siykGy7NTv0wYEALNhBJyfjaTQeo+dh1b5T37lk8jTBG/n7wmaGljBOTxypVo9Ei4q
         IuLaUfxrGxm5mtnJh2bykKu1hepUPopzUy45uksBX64TNb8jYEh/oWWUIxoxMB9/BtEg
         X0Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nJSVAeyg2p94zA40lDunKf2WQrEUTE9qO4mr1EU4n/U=;
        b=nfBrgY83OEU2CQGqS+uE8M9ITWBLjAxXXNSWaNB5rJis40DzmO+GkZYt4vdPpUtgIe
         QBA/ujTiZMuD4clIALuw8mCX5Kfo4d9Oz76FNCy/fau3n04JV+ntPNvX7rVXqKV6xLIy
         qqqyPuA0df753jynD10h8eTIHMi6BxoHeZh0l6P8woSkfauileBgrWtMiJEjSsi7Nr+n
         2cafvuiP4qfafWGK1qPuXV1oucVjxUs3VM2WASCEjghUdUYQzDJr6SkvolqhcflxFpzM
         Yc0ySMHJcuFSw7utQRWE/fzzO74M0zt8cknDN11uf/oGVMl6WrNk7LtSjZpsq4kFA9tD
         mYIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nJSVAeyg2p94zA40lDunKf2WQrEUTE9qO4mr1EU4n/U=;
        b=d/iQKVuk9gieBM4+WHUYkTVUD1wg3yuVHwvPJuIdI9S/rOZAEuW3+j2rYfWqXaGe0Y
         QAbBjJMyP0xTahSsX36IbHevSjFo+KFPxmmWXhs9Bn+f7C7Cbrawr9ZFJQYlSTEz5FrJ
         QgN9HiN37eiqyZ9Liywt5TkISAQB5hH6c8/HNUCthfME6rPox+05Our5l0vzG78SJDHU
         4NEmLOwTJ+AWA7mFYMveOPCTGdf245L9pdMl9XJOni/gH0eGLiPgwpQMvNJ4thXMLKXG
         6z4O5FmP4dR1axyurcPpl9TxEcbMnaIkD4ra99fPKwpiIo26fn3lrKgQya81igYRnr2D
         Km+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nJSVAeyg2p94zA40lDunKf2WQrEUTE9qO4mr1EU4n/U=;
        b=nxKR6XblsGqClNuDLS96L/y8L/wd3POeIjaAG9LwqRkTTDjlBF4hcNuRy6teDUkQ7I
         vD6kS0ohuLWDkkbjW/Ciu9t9s4g2X/bk0rnkPlCETiLpmDn52sZcaIhoYyToKbu5sUGX
         74P+xAyC6d+vr+zog3152C84JhL0Q84CEmNA/kWkZbwGq9meHWj7+Wrtkg7D4SF39YJp
         n2Y91isg8TSNZ64x+Crfwzb5yf8CJF95NuxWcjio1l06NMm7rOaY+hkXNAvxIaOPvhOk
         gKxDOfSlXBF7DthLj+M/REEDTuj4sCBX/8fQj6oNFqMTwzz0TPXf4NDTG9RXbYjgz67j
         ca0w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NozCI13ewqoWtZGLxKzDRZa2FFe149Arysqge4RaRzrk1uDBf
	+ZYNZWquv0nYE6nVzT2KzoU=
X-Google-Smtp-Source: ABdhPJz59Ei7HUA3/YRSIPj+4jzRTY0knM2S1IFFTByI0X8+Nbf46PU/zOsLxyLy367pMIBQs9tFpA==
X-Received: by 2002:ac8:120d:: with SMTP id x13mr3169551qti.364.1610558169440;
        Wed, 13 Jan 2021 09:16:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:f501:: with SMTP id o1ls1410654qkg.6.gmail; Wed, 13 Jan
 2021 09:16:08 -0800 (PST)
X-Received: by 2002:a37:9505:: with SMTP id x5mr2943482qkd.295.1610558168419;
        Wed, 13 Jan 2021 09:16:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610558168; cv=none;
        d=google.com; s=arc-20160816;
        b=B5qeMeQyOwWEAI6vI9Y/pIGMlwmEwMzdiklPp56eHT09NGVQoSC0VPoernn8/YqD+B
         MTulDYQNIpUjlioCXnKEIHnT+PiNYcPYZoAWQo8y3wGWezKXxtEB1JbTo6V1hGnyJrny
         YG6QUuqnqIwU7dFimE0eT0jXwErHdk3dFcdks4KK7xNQZ4PwnMQCXSlNMlSPMkACO+0I
         O9sBGFAV2U8AcZJ0kiLFLqhw+oZTyWShzPx/XJfeYQyjabUdDDf0pjbD8Tihx7GsnylM
         tjRx9Oz2nr/3bJ6fntH8Kxjv2wUDEEOiBYwTcyTUBUlIJDPNVfocafjdOCpRXV8ARpc3
         iFAQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=IO0TasIzL8KU1PRQ/S6k6cKeezYhbUUPP6JGpK8OK+M=;
        b=LWkVGOAqXpKL+YSTFHUtTib0Nt0//QsIG7zKST77rnGtQK+8ENJTEocReawKasnY5t
         uso2UyXp8OFzCoonq7c5Pc3q37WerItKLJXCZz57ST9Ls/8xkP+1u3XlxFkjnMqab5mp
         HVyLHa9qa5PA5xn4np1aDGBCmnGxxxb4+TosAFkEF4JVTf7lIm2Szx5yVPJd85rQGhk4
         t4zUyHsP/KJ0WFuRCDhmaiuvlgxLxPvsfPlEuBFQt13rCSWQ3HaryDrrk6Jna6Ys1K6a
         SmY1kwLFGSHGsEeCi99hbwAgAkJWp/3j1HhSX7mmJlslODSahbIg66bdM50AGqzurFrN
         BEhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p55si232385qtc.2.2021.01.13.09.16.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jan 2021 09:16:08 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 32FBF233FD;
	Wed, 13 Jan 2021 17:16:05 +0000 (UTC)
Date: Wed, 13 Jan 2021 17:16:02 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 1/4] kasan, arm64: Add KASAN light mode
Message-ID: <20210113171602.GD27045@gaia>
References: <20210107172908.42686-1-vincenzo.frascino@arm.com>
 <20210107172908.42686-2-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210107172908.42686-2-vincenzo.frascino@arm.com>
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

On Thu, Jan 07, 2021 at 05:29:05PM +0000, Vincenzo Frascino wrote:
> Architectures supported by KASAN HW can provide a light mode of
> execution. On an MTE enabled arm64 hw for example this can be identified
> with the asynch mode of execution. If an async exception occurs, the
> arm64 core updates a register which is asynchronously detected the next
> time in which the kernel is accessed.

What do you mean by "the kernel is accessed"? Also, there is no
"exception" as such, only a bit in a register updated asynchronously. So
the last sentence could be something like:

  In this mode, if a tag check fault occurs, the TFSR_EL1 register is
  updated asynchronously. The kernel checks the corresponding bits
  periodically.

(or you can be more precise on when the kernel checks for such faults)

> KASAN requires a specific mode of execution to make use of this hw feature.
> 
> Add KASAN HW light execution mode.

Shall we call it "fast"? ;)

> --- /dev/null
> +++ b/include/linux/kasan_def.h
> @@ -0,0 +1,25 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef _LINUX_KASAN_DEF_H
> +#define _LINUX_KASAN_DEF_H
> +
> +enum kasan_arg_mode {
> +	KASAN_ARG_MODE_DEFAULT,
> +	KASAN_ARG_MODE_OFF,
> +	KASAN_ARG_MODE_LIGHT,
> +	KASAN_ARG_MODE_PROD,
> +	KASAN_ARG_MODE_FULL,
> +};
> +
> +enum kasan_arg_stacktrace {
> +	KASAN_ARG_STACKTRACE_DEFAULT,
> +	KASAN_ARG_STACKTRACE_OFF,
> +	KASAN_ARG_STACKTRACE_ON,
> +};
> +
> +enum kasan_arg_fault {
> +	KASAN_ARG_FAULT_DEFAULT,
> +	KASAN_ARG_FAULT_REPORT,
> +	KASAN_ARG_FAULT_PANIC,
> +};
> +
> +#endif /* _LINUX_KASAN_DEF_H */

I thought we agreed not to expose the KASAN internal but come up with
another abstraction. Maybe this was after you posted these patches.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113171602.GD27045%40gaia.
