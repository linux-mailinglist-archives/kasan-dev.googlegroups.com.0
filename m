Return-Path: <kasan-dev+bncBDL5ZOFA3MARBD43R6XAMGQEOCGVYNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7510984D140
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 19:36:00 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-363c06d9845sf7428755ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 10:36:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707330959; cv=pass;
        d=google.com; s=arc-20160816;
        b=owS/L7qU5OF/fbgDnZLoHqDEtyiQ0IDQlJ0RFmXOSMr3viVb94soJmBvkyTl5hpakX
         clnUKcCMKWtiGSQ/XS95J6Nbu5JkXHgc/uZp/3Uhhymc5Rg048v5bUCI2jUpyx/woKD7
         p8oLz/4B+leBJ8qlnMOIy8D4KDse3afQB6sMyO4iONuOkf3fmUzflFeVojaNUqAKMT7m
         ZKlo45ObcafCyOVJkC57wb+cSiw42gdAFkl+ql1RzHNz7sa84UmyoF9hj42bakqbCQQF
         8XXIz033FcFsYaPPi2pHz9FWHoErycZPd4F2Yd2GjgBXpcauQbIBoxe0mdtOrhhghxjj
         QJhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=oCV2z5BfPnUhk6O5MB7Z1EFtPh+3fAAL2WtSlxkSfbs=;
        fh=jV/w7OG2ZKYKRQ8/0YBIu8EhjUcg4nKzBt6SNzdhEK8=;
        b=rtZIz70XJj1eFGrXAReT1r5bc3xCfb8YUWHzHhYM0lBwsPcOCg9TLewjZXADxcvLXA
         fSZ4UbzcUDCeVqOCMvKJthhzTKDQFHV/nls8Bd/CBnu0/MZ9xXapJwyeP70vlCHYtZNI
         pQd8oFThjAi7lvSb3vSn7mrN5zUi0toAkJCgGZsjfBonAL4839bHlOn7ax7wVA2zDn3N
         RZs8uq1JH7OyoEcmnYUUDPoyCe26GrRlpr7b5LxJFuwqZHfWfiFpYiKcbu4uiPaoszqB
         7sXH/V8soYtnE9qj82GIvOnS/xHfO1C9Tg8lyhe6lQllvT5KGjmKKIYqwJeZiBQxxP3/
         gPCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o79YWp1W;
       spf=pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707330959; x=1707935759; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=oCV2z5BfPnUhk6O5MB7Z1EFtPh+3fAAL2WtSlxkSfbs=;
        b=OhU9fE0AHeQWLnCUpPHuRDV5QW/OVFpFiWxzCdnTPa0M0gaMejZ+npBTePBlvs7xeo
         xw+I4lgUXv2p9oPFp1wjj2xQi3L2EBDYOJEsKIPZ/bBnNFLqywnZQ7PWygNmti9uSHCy
         QdhV6tSbfyo648mIKCek51brZ46Ax75P7meQZTWdMFlTyVY3j87dKzzn1J5Dzl8NQsRb
         /22h6NToD3nBOtyfALCHN2s80t0yBhLxER4PZ9Ft7VC16HurAAxmCiGlcxP3GPDtHt1s
         2CGlRsfQCbUYr6Y4UQBDChWEvR6rdx2N/V9WLnfhV5Hg+LNMN6fxUiy7ZC9COLUmERA4
         cNiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707330959; x=1707935759;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oCV2z5BfPnUhk6O5MB7Z1EFtPh+3fAAL2WtSlxkSfbs=;
        b=hY9WFA4N6q5xp7L6uBP9fe2aUMPS1HtL3+JLF/Ach/ZAned2+6fLpHIG8BTwcNtYmA
         1rdsASRkw8W7svj1Sl2xE+ldAQQCyxBAv9nzNrKcQAsACxkoXjvAtj1jOdPe2bWlTqKo
         9/EnAhBU26UlsEx8QDriXbQiRA8Ti5ISSECQcvU+3uOnkzw8+H2J5eJeJ6un+yUtYMa8
         /je1MQ3xImttmLKtfIGyWf0h720N54g4yEOyeJizk3eWusrvk21TF3/xPpA9DSg+2y24
         ZrzcicPbXG+qbfjuIrJuIAxZjux58OASu1M+/7PkyCdqBmmD/VL2AYvJEpbxdrgjP2xW
         nO9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxPsjT8kGJyHuQLFl8zPU5d+N89ELw3d9ICJyvJlyXwDPKQnQVq
	+Sd7+y9oNX2unlyB6dQYInPEPMkKwsMStlDOXDrGOipJSeM16XPc
X-Google-Smtp-Source: AGHT+IGkylMRPVJLgbHslY5J3C42jPVGH20mdf1lqPDKrJUt0Y7rHWGvz9qdb21I7VRfcpRN7Y6veg==
X-Received: by 2002:a92:d344:0:b0:363:78cb:c1db with SMTP id a4-20020a92d344000000b0036378cbc1dbmr6678402ilh.22.1707330959233;
        Wed, 07 Feb 2024 10:35:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:3b85:b0:363:93da:bf41 with SMTP id
 cv5-20020a056e023b8500b0036393dabf41ls433249ilb.0.-pod-prod-06-us; Wed, 07
 Feb 2024 10:35:58 -0800 (PST)
X-Received: by 2002:a05:6e02:ed0:b0:363:6da9:2bc3 with SMTP id i16-20020a056e020ed000b003636da92bc3mr6336918ilk.11.1707330958188;
        Wed, 07 Feb 2024 10:35:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707330958; cv=none;
        d=google.com; s=arc-20160816;
        b=SARkYZECj3HeKR+DjplKEeZVlE8iQnzuDekXz1B2knZJXTzH2OODRKFdjgTHnm/qF5
         4HUn0G3/tq0+9YKJRSWeJr764YTJKAlU53I3E7rI6mDSx2y5DFvIvYd5chgejdr6CnkW
         rFchTKig6zu6n2ql4agn4Lu3KAV+tGXhVy5eQMixC3n4UCYZlC0wbiGyqzkSq09krvN1
         c4JN6/YgTaqA+kERTox2580k+Zdz02ahKfbNc3EdMwSDJCI0abeXfypMzjZi6cBdmQRk
         o+MAl4QtkmZzCN0n5ZKjvDujx4oopJLeTI3WYZARST6d28xqa1oR7amhxMd6RxFFm2AH
         KkUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=wzEOYIhf03ZdMaWQQd6VnuWRYx58Uiir9Ae/HjydUfw=;
        fh=jV/w7OG2ZKYKRQ8/0YBIu8EhjUcg4nKzBt6SNzdhEK8=;
        b=EHz0ndkm1clqmudN3CMpT1kUa4/K0dGJU/N1ePWV05xp3G5ci1tNcyLH0vJ0O30CDs
         5rgz0rA98Cp+QB/p9YtTLprNZBXlMS65wNmF46O2AxIvWGyA3U1lv2BJ5DwKXf7Jdbj1
         qg1cbIZpqaL/LZgJ7fnCIjo3qMPDN5gc7GEAkj2nqIYr6fDTTc/I2rEsFvL2pH0h2G/Y
         bw/KkDXLz1JBHotEMecX32bUoCG+oJmIHp8sNNBaXiPQSsYx9R8p0tT080xosVLDC+Wl
         VcPCMb31Aqg1rwtz8mlyweGdUCpBUyEKVZJVlSEDV/zOP+9WeGpmmI5Z22K6rHv7Moas
         6SuA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o79YWp1W;
       spf=pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCV1qJccv8A/Xq19dklu1j727KAu3kTJnKX9jGQtJSTjbYt+tmXMdIqoxugPLx3AZHFcKjqeC/SHt7smMZwY2qw7eqWH08xf4Rmhrw==
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id c17-20020a92cf11000000b00363c496671csi227600ilo.4.2024.02.07.10.35.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 10:35:58 -0800 (PST)
Received-SPF: pass (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id B6A2E6194D;
	Wed,  7 Feb 2024 18:35:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 438E4C43390;
	Wed,  7 Feb 2024 18:35:55 +0000 (UTC)
Message-ID: <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
Date: Wed, 7 Feb 2024 19:35:53 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: KFENCE: included in x86 defconfig?
Content-Language: en-GB, fr-BE
To: Borislav Petkov <bp@alien8.de>, Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>,
 linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>,
 the arch/x86 maintainers <x86@kernel.org>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
From: Matthieu Baerts <matttbe@kernel.org>
Autocrypt: addr=matttbe@kernel.org; keydata=
 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
 lzVbFe7fduHbABmYz9cefQpO7wDE/Q==
Organization: NGI0 Core
In-Reply-To: <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matttbe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=o79YWp1W;       spf=pass
 (google.com: domain of matttbe@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=matttbe@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Hi Boris,

Thank you for your reply.

On 07/02/2024 19:16, Borislav Petkov wrote:
> On Wed, Feb 07, 2024 at 07:05:31PM +0100, Marco Elver wrote:
>> I think this would belong into some "hardening" config - while KFENCE
>> is not a mitigation (due to sampling) it has the performance
>> characteristics of unintrusive hardening techniques, so I think it
>> would be a good fit. I think that'd be
>> "kernel/configs/hardening.config".
> 
> Instead of doing a special config for all the parties out there, why
> don't parties simply automate their testing efforts by merging config
> snippets into the default configs using
> 
> scripts/kconfig/merge_config.sh
> 
> before they run their specialized tests?

Sorry, I'm sure I understand your suggestion: do you mean not including
KFENCE in hardening.config either, but in another one?

For the networking tests, we are already merging .config files, e.g. the
debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
can be elsewhere, and we don't mind merging other .config files if they
are maintained.

Cheers,
Matt
-- 
Sponsored by the NGI0 Core fund.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d301faa8-548e-4e8f-b8a6-c32d6a56f45b%40kernel.org.
