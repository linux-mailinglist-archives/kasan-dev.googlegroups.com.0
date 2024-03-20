Return-Path: <kasan-dev+bncBCMIFTP47IJBBNWK5SXQMGQE7LWCUBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id AB3E0881713
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 19:04:40 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id 41be03b00d2f7-5d8bff2b792sf59473a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 11:04:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710957879; cv=pass;
        d=google.com; s=arc-20160816;
        b=jzuRapAO1+CxPO1e7yxxK+Fyo4SGu5WOOE0mL8eZ9b/xLYKmimVagG5jq4bTxMe/m3
         yRTKqJqC9mcZtsJ3aoiTZUlsOIiAL2AEPK1sARPLUGzm+ppObY18Zg7rSnOqeAvXnv3y
         RU1wq7OgUrewaJx5JMJ09k8+i0Tavn1WxNNvSl+I7DGFB2S96NIdEUJoLP2GU9hDx8Xp
         Z76sBTa9ybotOCkbAZG2oxL/zhzHgAJ1UJIu6Vs2CJJLRj44esgdL9/z8UF4cwhigj7i
         lXtH/1H4rGRFcl74uK4xY/8rWyV03J1GvH+MLcA+0NOYoU40WZPBrpMhHYkKie23tC2q
         oJaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=j9UGKK3TaatzZelN/40GfTAIoIGA3n336H02qfUlcFM=;
        fh=pS4P45tLUQaiBSRpWqbmzUkKkbp7CcPh0b+XhoWpiGI=;
        b=MuSf0F1va0jXtZJ8q8NijBcm1VoY840dulIi0go8T0b40+mI0HVUmEhVu+hzAa2Uax
         xVRKfnNdOMDO6JHB+pYlNPTEGGo0amm0xdW+NjDmxSayEnGW7qY12d2KtICG7FU/mYxB
         7EoK+u8Gtux6I1rUbe/B7VpXXKYCfNmcnAzTG/ovxbB8FPqg2fWtIZXMs4A+ExA8/jpU
         5A/AXtxBjN5osSEcMrzrpp9SB+D2q8PxO1ZXDMetIPcGUf6czdbzN803/avQXU1lNfmd
         fu6pdBC5409wdOu/biG667f55RUlYigrBJTyFe9/zUpVeFemh2NuNZXWoBa+TOr3i64q
         b5QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jMuvaEPy;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710957879; x=1711562679; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j9UGKK3TaatzZelN/40GfTAIoIGA3n336H02qfUlcFM=;
        b=LMr6FgJv2tRsFmPFTkUy/REFHr7RzWhRXJkTG6z20OReUKeRgWaZywzczvY7mp6IoF
         r0/OiegqkroxvfnABnt3O4pcThVJ+957eYq4fDcLaq+Q4aX6Sh3irYqTZ/EnXuNXLD1H
         gluP6baVbdSAvKtrADdx8gWg254ujUdr88Xle9y00qVwPM6jRUA5SyezYmOgXsR9C/ao
         kdbQe3ryKt+zvDguzPEsi1sva9mUIbBqurg4FiY1f9FEZTkH4sgmYwiOf09K56o0iEGB
         hVFlRHF+PdyN1O3A/8tWtlrE8hSLdRvMa1DyzMzy0OPgJ0O9A/TBYowNKbUvIIkKmfOY
         jyzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710957879; x=1711562679;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j9UGKK3TaatzZelN/40GfTAIoIGA3n336H02qfUlcFM=;
        b=WxpREDOFKzrKt8DNRTT3ed+B9yKFrNxR8SeIb0Eg8cDwxPJc7bFRg5uUbw9pg2CGHg
         139wFy2BrJvZtVuYESJ4lY77tgpcEuwHXCcdNwBH7wU1XfGddt7/1ABD0PCtaLJ9migu
         l+/X6VGLLl39H8GsWV8WZutOagrCau4kF1/VPUj//zoAlXnj5LI7u6xl4ixqEa2d/oua
         g5LB3SJSg4FX5c+JUK5TAx3HiNYCSI/xL8uXoC5tz1nFBtbiqWX+x34AGLStAbv0s5zV
         2z95Z066FeRFP1gvvgM6Jo4aWMX76Ql0FJdaxj5jSwQQD2XUck90lWLyJsZNgaDH2045
         Wr1w==
X-Forwarded-Encrypted: i=2; AJvYcCXvbWV2uMGvd1Msw8axty5rCDB3+o6rlyuEbRy24matgQsKqDgmcMuJJmhW51cR8EUTUA2Q6r54U5O+xgVvYDA8otyvpM1wDQ==
X-Gm-Message-State: AOJu0YzVwoYcTf0ZmiEKg1fiTQOnROGc+7RCh0cqzPhEk8V+ob5KhqR5
	GxUB+QN5j2U7Wm6sZqUIyq220IIpgPrnaP0rypRHMhe0SH/g4sqs
X-Google-Smtp-Source: AGHT+IEt2/zoaXkBvc9oq5u+jbKiBHrNVwUs7PikEJoUFMv2htiTWcUFmvOPPYeAeKPxo9MHathIow==
X-Received: by 2002:a17:90a:5e48:b0:2a0:591:f52b with SMTP id u8-20020a17090a5e4800b002a00591f52bmr1741381pji.48.1710957878837;
        Wed, 20 Mar 2024 11:04:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a90:b0:29c:5a19:1c32 with SMTP id
 x16-20020a17090a8a9000b0029c5a191c32ls109200pjn.1.-pod-prod-06-us; Wed, 20
 Mar 2024 11:04:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKnPoKEcqtaZoGPFD1evV0uNfUFSnm0/2ZfEVNyvaZ7Oc3FWOxt0GqsUOV0cfyTwq6Lfy8gTIrJ6hR/9tvM76eu+UhNbNe2wdaKg==
X-Received: by 2002:a17:90b:4e83:b0:29c:75b0:de87 with SMTP id sr3-20020a17090b4e8300b0029c75b0de87mr2709910pjb.4.1710957877633;
        Wed, 20 Mar 2024 11:04:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710957877; cv=none;
        d=google.com; s=arc-20160816;
        b=Pv66QOKCvShSHFVPzY1R64S5PE+5AH4+MVTclKP6oywZe9YARSPiZ45KogKiymP6/J
         Lf5FiQ3g1604aAoYxlJbFjixHpWGAFfkjMd5luTt0YZU+T/2egMaT73sEja88RJqWHU2
         7z6qpH8EBsPDxIGtCjcAa4XMx5K+nh8ChaW8Uk8OKUzMuvf7eMi3ByBEZ3LinSX3KXKB
         Kaak/XT71mhFVPOGymez0qnGr0AXWJVwqLjWF2EcFXGvJFkEsKivKTtBiOVxJk3Dg8g0
         hrCDm2Lh18/QuhfKuis/8uB5e8ERs/o/zA99WgqlG795p2c7quBpJcmB7WUOxnC49der
         tKDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=6TmgB7TOmDIH1+NUxCse+KiCTmMgVy8/EkD7jAnjwO8=;
        fh=fqMTneBJATlWXzlu5n1vMqxW5Gb89LomLLnit8qJIII=;
        b=r0D2hHRqcPaKVrZTmdyY0C6+Q25kiDjpBtsPtEq2KxZTLMM+vNhMQc7hy8ddro6mpa
         NMAMkrHzPNalifrri7zVjO3wBvnTPSHwUbF9W+Namj92rJ2zV0tf5uyTS0Jev+aeSfXM
         Z2rzOkItxwMqAAXHAv21XleIo0bZhXR8Nr8YgJN4Q825oSgzyUNFvheNv0HxrgjxcgBh
         1gqrv+Qjndx0FHw80POrth7Ybiya5OOq1k/yPhYDYD2A6NSnilJ3cFqM59dFS3KnM1AY
         BLH285RxV2t5/53xIfes0HJKgPcTNVMexPW5po1KNDISopdb0odRPM4nCPkRW1HyjGno
         7vmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=jMuvaEPy;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id h2-20020a17090acf0200b002a005b22a6fsi166923pju.1.2024.03.20.11.04.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 11:04:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-60a0579a968so402407b3.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 11:04:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWA2XlEb/9ClCykTAqDPulbX3wGBggeTS5navlyLZoGqRY7BnMPJ5+tfivzE581ay3dM/G2wzufaQ+ax7lCBNrIBN+KbReEWcBeMQ==
X-Received: by 2002:a81:a50f:0:b0:610:c904:842b with SMTP id u15-20020a81a50f000000b00610c904842bmr2791022ywg.46.1710957876657;
        Wed, 20 Mar 2024 11:04:36 -0700 (PDT)
Received: from [100.64.0.1] ([136.226.86.189])
        by smtp.gmail.com with ESMTPSA id o1-20020a81ef01000000b0060a304ca3f4sm2832865ywm.19.2024.03.20.11.04.34
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 11:04:35 -0700 (PDT)
Message-ID: <1ffad954-63bb-497a-af10-0b319a0831b7@sifive.com>
Date: Wed, 20 Mar 2024 13:04:33 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC PATCH 9/9] selftests: riscv: Add a pointer masking test
Content-Language: en-US
To: Conor Dooley <conor@kernel.org>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, tech-j-ext@lists.risc-v.org,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>, Albert Ou <aou@eecs.berkeley.edu>,
 Shuah Khan <shuah@kernel.org>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-10-samuel.holland@sifive.com>
 <20240320-handpick-freight-ec8027baa4d1@spud>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240320-handpick-freight-ec8027baa4d1@spud>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=jMuvaEPy;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Hi Conor,

On 2024-03-20 12:21 PM, Conor Dooley wrote:
> On Tue, Mar 19, 2024 at 02:58:35PM -0700, Samuel Holland wrote:
>> This test covers the behavior of the PR_SET_TAGGED_ADDR_CTRL and
>> PR_GET_TAGGED_ADDR_CTRL prctl() operations, their effects on the
>> userspace ABI, and their effects on the system call ABI.
>>
>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>>  tools/testing/selftests/riscv/Makefile        |   2 +-
>>  tools/testing/selftests/riscv/tags/Makefile   |  10 +
>>  .../selftests/riscv/tags/pointer_masking.c    | 307 ++++++++++++++++++
> 
> I dunno much about selftests, but this patch seems to produce some
> warnings about gitignores with allmodconfig:
> tools/testing/selftests/riscv/tags/Makefile: warning: ignored by one of the .gitignore files
> tools/testing/selftests/riscv/tags/pointer_masking.c: warning: ignored by one of the .gitignore files

This is because the "tags" directory name is ignored by the top-level
.gitignore. I chose the name to match tools/testing/selftests/arm64/tags, but I
am fine with renaming it to avoid the warning.

Regards,
Samuel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ffad954-63bb-497a-af10-0b319a0831b7%40sifive.com.
