Return-Path: <kasan-dev+bncBDL5ZOFA3MARBYEASCXAMGQENWXGR7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4B45184D58E
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 23:12:50 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1d950445c0bsf13839475ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 14:12:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707343968; cv=pass;
        d=google.com; s=arc-20160816;
        b=APacCc0WMBUtH8XvNZoDhGI0uEHBl6rbHMj1X/Sq96WaCszM8HWGLkwzSRIEX46eDo
         k1Gjj064gTNy2bjTIc1gqRMs3JvMqUYTnYssLbZebEnQ08k0K9TzEAomVkjDDpbNq/vl
         erYqOk/28nt6mtiuvwWGmxjGk8aApBkia9rkgKONVtso2IiCQYeHAJHUN4MizEA2Nqhr
         9dVJhae4A8ZbUSnQgEnUfbYD7yv7a5YcWGZStKjEy5xJyTGjHNFQwI6CSOHdtfzN/EP8
         Sk5XTCgr1EWvn75BYC9FpphuM/jhqvqKpvuFeDTuiEXOuWRn4IvacZXqmwN5or5SsZxt
         TRLw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:organization:autocrypt
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=Ehc4JuT73Q6H78jqkY/G3fpNtzlMikXvqSBEkif0Rk8=;
        fh=B/sesXPDWHAZtFDm6wJ/U1jhAFE0fc+r+X0EVZzM9is=;
        b=iEE+xjOlCyGx2M93sFNsvelJd9yWcPNv6a0I3kqPQp2v9AnB3OEtvEMHQfFa9vvLoB
         YdFSTRGN4UURWcgN6WAJTbA4CVFaH4eghlgXemN485U4dTXn6vYUlWFcQckIjCxDDg2x
         R3e3auSqPJEzesgxMu+Utc2BtItHGXOhFewSacaftF5K38gdrKkRnN0yI6RkkW8phyap
         1cGi80lnd9RMxTK5D5/kFYIYOXhabEPG78cgWpb4Y/2fBEGbhafNNy7ESG3/HrqssgFS
         soKNL+WaZAyoFDeb9XX4vVIdQxUCj7j5D1CGSTb9o2QYQtX2zyDinH9u9pq8+5kRR2kE
         ZqrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kfCOSaGP;
       spf=pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707343968; x=1707948768; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ehc4JuT73Q6H78jqkY/G3fpNtzlMikXvqSBEkif0Rk8=;
        b=ICqc50sOLVl0kniay8qIgOixQzmTV7oAwIRjW6JVS9EqpU1Ha43M8g8+/AAysx1uJP
         +3ogZJ3VMh5kzkhz7vSMNQaYjCC66XrTuxzBlVhO1B2R1EM7VuVPGYFI/dgBaRXOmPW8
         ewxdX9/NuACayI4avNMt8h2XvvB/RHQcNfgRSGAGvp3jhWvA/aq95/LuBb0wzg0G5U2j
         KJsFbmme9p+ZA1fDXh9vmzwiKJTr/oXSwexIauDe221KhmzketFHHlXewgWs2QwVZD6c
         Y1NFq8iHw0+xVC5IFiT+At4N2bwLFzcKxJ4D0Y5K7+NSaaZ3QhFS/VSMcJcoehUd2jvh
         R2mQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707343968; x=1707948768;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :organization:autocrypt:from:references:cc:to:content-language
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ehc4JuT73Q6H78jqkY/G3fpNtzlMikXvqSBEkif0Rk8=;
        b=kdNvomL/UxkK56frpay3UKVHThyAGjDX45LrTaLMbuluHi/VS1EZ3tGjqizm9EZ4Uo
         rvPdhb4wNlCNa1EvPwCInmlO3W4BwzhGBM0bfWE2aSHN0seSJ3eeDfXG9OJ2OLz6WDjh
         qevfvFQNwio0L3/c+agsxNCa2FGrJDJtFFjrNnnhkwzOMKPBup4qfW9w01Kxe4rUevOi
         kKNL/WGJNk9Hnq02ihYpIkEjArri12OSH/30ORe6T0gW220Ym2LrPTzJcQnx8tUba33f
         Yc1WigMHo6dPfkjgeAzxPlPJlL572mieEg5e8Ga8JVxFJBmek4Vq+08p5exF3yKZbOzJ
         c7mA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXroJvZkHoJFaRAabSK+AXDq98EVd1IiBCBGo7ZoMyY+Ug5sPccdWL9+rN0Z4QR9QRTTNej/B1aI/IJttxiqPlUfAtVhhZYyA==
X-Gm-Message-State: AOJu0YwRpuL7znyiPw5L3YmdCJRiIFi8LLatVE00oNT7qMF8nO7CJ07f
	Wx+lYZN2a9fq1C2GroKw8T2uiEC0OWI0RVsNNbYAPB0Zd+ZNwFsQ
X-Google-Smtp-Source: AGHT+IFCVsbRwSk2sUPZwcS61hOWUgt8ojA33BODPY0vtYwmPjFltcDquuIDeNKUr77cgz5DXAwglQ==
X-Received: by 2002:a17:902:ce92:b0:1d9:542c:ec01 with SMTP id f18-20020a170902ce9200b001d9542cec01mr7365532plg.12.1707343968229;
        Wed, 07 Feb 2024 14:12:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c145:b0:1d4:ab6f:a56 with SMTP id
 5-20020a170902c14500b001d4ab6f0a56ls628403plj.1.-pod-prod-07-us; Wed, 07 Feb
 2024 14:12:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW6zXZDf1XWjsEmtCqlDlJ/0N6vbuyTcw+xAQE05r5hlNykqUllOz1oy2OghBFhklvc0fxp5aFlGkvD5aVIaeQU0OlPmbJcJHmE0Q==
X-Received: by 2002:a17:902:74ca:b0:1d9:abf6:e50a with SMTP id f10-20020a17090274ca00b001d9abf6e50amr6065998plt.8.1707343967104;
        Wed, 07 Feb 2024 14:12:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707343967; cv=none;
        d=google.com; s=arc-20160816;
        b=TJfzQJSv1BCLBysgsZCzz7jcgtGtKvMgw9XrRow9tYcbTklV44wyR0tKASZ0V0MkdN
         kNEMZef6XaqBtA3Dt3itgZVrjfTigIGUi4Tb8AUjNdzSzNwB4NpcrX86XYF0Ys9g3PGC
         P6WA8rEy1C4hpFRRDds6YgtnyUqHma2OhdOnOXw6NzUcdExM5FYvG+etflWJe0NPrnVs
         iQ64GEYAUgo+94srIV160koj4B+nCyXI4YBhNegih6HRx7ME5e8EKjxPK/kwKqTHcvi1
         MCNzBzs0Fyha68LdwAYzJn6AoNWz/j1UiO7EW2VECZ2NXcR6Kah9RR93jHuI2HuaeWkQ
         hVCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:organization:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=TtiioQfv02ur6JTaedP4sjx+qtV0E5ZtA7D6lY9O7cc=;
        fh=rbVrpUQBiryAEp88q6g2KZjTX2Jxo/WCxlE09etsXZE=;
        b=qpLqlQSA3BoIZC2Zpn8EaU5UMy1sJy+59sIWV+rwDI73PyaEBNtEn30UEa1oLJu5NJ
         G2XNe1acPQTAeIogpCKYmQ82xdcdKRFeud9cuD9WeW5NOGZ8fOqyBcRYoUSSweTUjIFY
         wGsCGofx5P2HJ+ub64C/HaojoqKUn9kHsYybzNu2g6xUHNUUPHZLWiHE8wqo5k671PWy
         T1x/2na2VrnUBc5wXohU1Mz34xV1Epwi9lS7y2W7wke1ODLoUcW9Qu06fuW6MSLKepg0
         mWg3GDXVavIb+RfTNfIYG19j4PhAsz7wQX07rq5hiHc/EZIMPShLiW/+X6lihGf1eybl
         ucIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kfCOSaGP;
       spf=pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=matttbe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Forwarded-Encrypted: i=1; AJvYcCW4vsXybgG7LZr3lC9r5gJCikJ6sS3r8nLiWWJ2+ET3pHJjC2pHYAvDp8jlTKg0wwgh751IiaY4JI8hR/LggoBIYNC9QpfXlwDXJw==
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id kx13-20020a170902f94d00b001d8e76e7179si199430plb.3.2024.02.07.14.12.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Feb 2024 14:12:47 -0800 (PST)
Received-SPF: pass (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id DF440CE1B27;
	Wed,  7 Feb 2024 22:12:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A3B9C433F1;
	Wed,  7 Feb 2024 22:12:41 +0000 (UTC)
Message-ID: <7a3d2c33-74ce-45fb-bddc-9eceb6dd928b@kernel.org>
Date: Wed, 7 Feb 2024 23:12:38 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: KFENCE: included in x86 defconfig?
Content-Language: en-GB, fr-BE
To: Borislav Petkov <bp@alien8.de>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Netdev <netdev@vger.kernel.org>, Jakub Kicinski <kuba@kernel.org>,
 linux-hardening@vger.kernel.org, Kees Cook <keescook@chromium.org>,
 the arch/x86 maintainers <x86@kernel.org>
References: <e2871686-ea25-4cdb-b29d-ddeb33338a21@kernel.org>
 <CANpmjNP==CANQi4_qFV_VVFDMsj1wHROxt3RKzwJBqo8_McCTg@mail.gmail.com>
 <20240207181619.GDZcPI87_Bq0Z3ozUn@fat_crate.local>
 <d301faa8-548e-4e8f-b8a6-c32d6a56f45b@kernel.org>
 <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
From: Matthieu Baerts <matttbe@kernel.org>
Autocrypt: addr=matttbe@kernel.org; keydata=
 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
 lzVbFe7fduHbABmYz9cefQpO7wDE/Q==
Organization: NGI0 Core
In-Reply-To: <20240207190444.GFZcPUTAnZb_aSlSjV@fat_crate.local>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: matttbe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kfCOSaGP;       spf=pass
 (google.com: domain of matttbe@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=matttbe@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 07/02/2024 20:04, Borislav Petkov wrote:
> On Wed, Feb 07, 2024 at 07:35:53PM +0100, Matthieu Baerts wrote:
>> Sorry, I'm sure I understand your suggestion: do you mean not including
>> KFENCE in hardening.config either, but in another one?
>>
>> For the networking tests, we are already merging .config files, e.g. the
>> debug.config one. We are not pushing to have KFENCE in x86 defconfig, it
>> can be elsewhere, and we don't mind merging other .config files if they
>> are maintained.
> 
> Well, depends on where should KFENCE be enabled? Do you want people to
> run their tests with it too, or only the networking tests? If so, then
> hardening.config probably makes sense. 
> 
> Judging by what Documentation/dev-tools/kfence.rst says:
> 
> "KFENCE is designed to be enabled in production kernels, and has near zero
> performance overhead."
> 
> this reads like it should be enabled *everywhere* - not only in some
> hardening config.
> 
> But then again I've never played with it so I don't really know.
> 
> If only the networking tests should enable it, then it should be a local
> .config snippet which is not part of the kernel.
> 
> Makes more sense?

Yes, thank you!

On my side, KFENCE is currently in local .config snippet, not part of
the kernel. If it has near zero performance overhead and can be used in
productions kernel, maybe it can be set elsewhere to be used by more
people? But not everywhere, according to Marco.

Cheers,
Matt
-- 
Sponsored by the NGI0 Core fund.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7a3d2c33-74ce-45fb-bddc-9eceb6dd928b%40kernel.org.
