Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBYNIR6XAMGQEIRZFMAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D2F584D1F5
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 20:05:07 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-50e93545a26sf405785e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 11:05:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707332706; cv=pass;
        d=google.com; s=arc-20160816;
        b=DooOMOBvc4Fm3fPQkkt3Dk3mXK/hcq+Xk244tv/7vOouufdxdHSDqHj0QaRxTRp/mJ
         9OdbUM3pezIrwq3tuvk0zjgFjudketpVns+2sBtLq04EgxMV7Blg4m+VFdUf2W7ahMlM
         5jiws1eJhRTe5qC/z9lDFkiwg7JoMuAWwnDvA9Qt6NnJqMDpqcbT2CR9s0N5pvryParI
         BSf9XKlTiJ1Iytdoaf++MBx4OhPW52ZRjv8mWYWn66CxDxIS3UJ2m/GyHJqWIZqgNQmB
         wPaoq2mMfCaocKmZg/+5UWevz1GNDpnbg5axTu34y7A2f5JRncHQin+PvYdFb/2kvdEq
         OZCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=UlophrJmyLuuQzm8ajsgf/RRV7x8B0D6KjnJOPyGACA=;
        fh=YedoxULUudnTHY2VIUAfMeglPNybreWX4Upy6RdpZjs=;
        b=PGe/W9eM0UHQcUZE0498vKsOkj9BuHO+fldkInjsCKVxzQ57FyW7JC7XiODSFAW4B6
         JHfx1BdalvwbdcMEIXdPL1CqVlToM16Yq+h03Aa//LMRp+v+KHczvlO+BdWDVdcxx+me
         rakBAUKkU8DqKexfId/RTkfs/RSThZEUXpreU2X0hsyRYQoX2J5oETwdOF6QXUPS3Sqe
         NCyh64ZxVsTrXG1os/koI451f36FphR5RhEgSu0oejk8Il3ydWczj2btkH5e5gOy9iaU
         Mc3JIddMHjMxIqmVbK/+trmYQibNVSt0yOeasmdOg7nPl0NJe4c44XZ5sSWceONBb4Ga
         w3QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=aM3YhTH1;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707332706; x=1707937506; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UlophrJmyLuuQzm8ajsgf/RRV7x8B0D6KjnJOPyGACA=;
        b=oodIAiPGYanAUZx+Ug+SkHHoP1B+MKoEdEtny+SRnhjManqeJ4fkE/Sf8Bddjnelxl
         NvQwMDPrkuzz0sGjTRM1P99LCieFvZF/3uZAU5arj+eV543W77qDCZjePXRI92oQZ4jR
         BQnNrqPilZor6eQ0BsnErWOIeqkW2O9Ojgg/GDU4h9ih5nQ0XxV83kEeyPJqxuvjvK85
         lTa9LG5yAOmo+EDO4HaqbN8AqzNb4GUBUBavKNwmpm9Y7gJ1tKlHEyfrdyu3OmROv8e1
         uW0dFjcEmjRsO4Cty6eAUMOE39l6vLD8RfaT94UI55ZivJvsgTr8aBjqaA1aN8RP9Hjt
         Y4Gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707332706; x=1707937506;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UlophrJmyLuuQzm8ajsgf/RRV7x8B0D6KjnJOPyGACA=;
        b=DsTdidyQMJLFyupn0QyKSEYKjoM1JjgH3CgwhtgV3jgW0DhnrmxZtpq5E7bvG+dr6a
         NRfCWuP02CxpokJcjQIDolYDCWS7q4zzR9g4U921f3sL+8nOvm0IHWm0YPML5JfUzktR
         VOtQpg3GXosveMLUX+2zJjNF+hK7AhJW5xQhTHNiBzlOGL7n6W0QBn3cSEGw7Isz7lIz
         2qHOqsAEQxps8ePCHwJPZH039TPp2Ull2Aabz7f2wQdICQPl2w0IMsNzJqtvofZ1YsSI
         htfEp8FhsWWyFmh8pjrANzupiJ1QMImC/8ywQkWM/FP95+F4x1CqiptAgkG8cGYb812r
         HeSg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3nl6oxuXVZoyvzWC4K2vQDRYj6Qp3dFWaLi8+RjeGR3QQebKihpPMxgL2mMu72QNaKMxEBiUykUCLYxwl+meKztr9Z1+Iow==
X-Gm-Message-State: AOJu0YxRo4e7U8RMvWbE+MeFTGxd6YxgYTQvFxxD2nGoViF+cO0qBOKZ
	RHsg8cpORKYTiuosq7lTJC52aUVMMYwBLfwIhBAp3gf3X8U7hB/Q
X-Google-Smtp-Source: AGHT+IGv4eGrLdmA5BXx91lLnXh6pjo4+7OfzjBrgWOHExUG5zoad8f9qxOGM1hzV4vevb8ADHPS6w==
X-Received: by 2002:ac2:5b5a:0:b0:511:4837:9088 with SMTP id i26-20020ac25b5a000000b0051148379088mr4687476lfp.5.1707332705310;
        Wed, 07 Feb 2024 11:05:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3c98:b0:511:3a75:9f31 with SMTP id
 h24-20020a0565123c9800b005113a759f31ls428603lfv.0.-pod-prod-04-eu; Wed, 07
 Feb 2024 11:05:03 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUBZ/7aNwGgitZzOEjEpOshAB0mwVHtPdFaAU+Q8SARP1TmK9in56np1bx5w/b3O2Exb6I1w+j/9d6kV/w0B8oEm/P+pr2TMq60mw==
X-Received: by 2002:ac2:5b9c:0:b0:511:6158:498c with SMTP id o28-20020ac25b9c000000b005116158498cmr3517350lfn.64.1707332703362;
        Wed, 07 Feb 2024 11:05:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707332703; cv=none;
        d=google.com; s=arc-20160816;
        b=bkzdSlv4jeli7dct0Vxk7INKpFhJjc5PHZ7xWv2nvSPxXf3ZF8fsNl63jwzjlzBznP
         lU0NeLQhSDM4JVqfIRtpJ7bfFYivDAz2OUOeBNvFkKNt2Xzj+L7JJYnsfSksYo47tEnk
         FX7TcQVlRnjxFeaGUOj5WgFBhVEkSaReL5HgOiFintlbcUNsjo5dSnPfdWTBV/diFff/
         vtGPRyy6Q302F5j+g49CRwDzOHzahT9a5wZj1pnT76Q8KlKdMtg+iQgPSLrj1n/qJd/+
         6gfr/2IWocohPvMOfxyqlYQoFItyHVaVnIPBks+/o9Ct+FS+UsLU/e3ZQVl2fnd4Wtii
         8uow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=UG6LZTZwY5niTQVNIUufiW7MyxpaNkRl1LYv98YsuyA=;
        fh=YmbsN7fJgg6IQ+8rxSylAZsevEf11DIjea2wIITfvJg=;
        b=YzpNPfOZ7dhDmcH4FwSzBlSeGaQaSsjGayU/eXo43D+2OpJ+TfFFQzaATl6eiFLPv4
         gIqi97jz35KHHHEPaVqCfD5VxwLGoKo7E5PrItX5yrwmMcbVPPo8cVjxCoZ3E7fcYTuQ
         jCSj1lO8O1L0ldoXecxCZuksrwVxLq+EXgEuD7Kn8yCoV9ucgYQIDX4TZm9YqhppM688
         y3rFtW74K8175iAI21hIhAvUyAntngLkFRFhdDjH6MxmxjXyZuHdmq4TRbcSzA7ydXHZ
         B1aTxRvWTOlxYQW498FrcNQvJBmRD3m+v887v2M4yH+HuC8xG3IaXTxAICD6Tsh23yLX
         XbSA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=alien8 header.b=aM3YhTH1;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
X-Forwarded-Encrypted: i=1; AJvYcCUhsesNAIKYReHaM/MbPeRSQcOzAbHfgwB6gmD8jM4n/2rqzI0qtfhAenTntshd27a4jMKgpsYeuTmFZJ0VdJnKwNAx865UndfD/g==
Received: from mail.alien8.de (mail.alien8.de. [2a01:4f9:3051:3f93::2])
        by gmr-mx.google.com with ESMTPS id fc4-20020a056512138400b00511503f9ab5si139545lfb.13.2024.02.07.11.05.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 11:05:03 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as permitted sender) client-ip=2a01:4f9:3051:3f93::2;
Received: from localhost (localhost.localdomain [127.0.0.1])
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTP id 617FE40E016D;
	Wed,  7 Feb 2024 19:05:02 +0000 (UTC)
X-Virus-Scanned: Debian amavisd-new at mail.alien8.de
Received: from mail.alien8.de ([127.0.0.1])
	by localhost (mail.alien8.de [127.0.0.1]) (amavisd-new, port 10026)
	with ESMTP id GYY7a-CEVzov; Wed,  7 Feb 2024 19:05:00 +0000 (UTC)
Received: from zn.tnic (pd953021b.dip0.t-ipconnect.de [217.83.2.27])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-256) server-digest SHA256)
	(No client certificate requested)
	by mail.alien8.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 1A3D240E01BB;
	Wed,  7 Feb 2024 19:04:50 +0000 (UTC)
Date: Wed, 7 Feb 2024 20:04:44 +0100
From: Borislav Petkov <bp@alien8.de>
To: Matthieu Baerts <matttbe@kernel.org>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>,
	linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>,
	the arch/x86 maintainers <x86@kernel.org>
Subject: Re: KFENCE: included in x86 defconfig?
Message-ID: <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
 <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=alien8 header.b=aM3YhTH1;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f9:3051:3f93::2 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Wed, Feb 07, 2024 at 07:35:53PM +0100, Matthieu Baerts wrote:
> Sorry, I'm sure I understand your suggestion: do you mean not including
> KFENCE in hardening.config either, but in another one?
> 
> For the networking tests, we are already merging .config files, e.g. the
> debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
> can be elsewhere, and we don't mind merging other .config files if they
> are maintained.

Well, depends on where should KFENCE be enabled? Do you want people to
run their tests with it too, or only the networking tests? If so, then
hardening.config probably makes sense. 

Judging by what Documentation/dev-tools/kfence.rst says:

"KFENCE is designed to be enabled in production kernels, and has near zero
performance overhead."

this reads like it should be enabled *everywhere* - not only in some
hardening config.

But then again I've never played with it so I don't really know.

If only the networking tests should enable it, then it should be a local
.config snippet which is not part of the kernel.

Makes more sense?

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240207190444.GFZcPUTAnZb_aSlSjV%40fat_crate.local.
