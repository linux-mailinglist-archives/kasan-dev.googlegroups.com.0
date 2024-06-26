Return-Path: <kasan-dev+bncBCMIFTP47IJBBZX46CZQMGQEVDHC5MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id BBED891870E
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 18:14:32 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-377150fb943sf21591605ab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2024 09:14:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719418471; cv=pass;
        d=google.com; s=arc-20160816;
        b=0GiQlleSl/5KaXcGSIMSmB2FvV9Q7gE9yp8z4h5IaDti9+VtEm/zxRMY79sNc6O5V2
         9XfxMbWzKYtM6b3Pm80lB16oDjmjssG9nDR5nA6/YzC2+ArgXY6eRNp90PVaeCWhsIY/
         cMwfBEY6yB+O/IXlxv/eJ5mx+a1AgP75xMf/vxkyMD843ceyjEXuZk1L0Y1iyvBj2g9K
         SRvbWZUf5LE5kcXTkCMi7z/S48H/UMRXVX5WrDPHcq9f9dXKJbOwHmT8pnSxxg1YXKgp
         NlWf8/ejMbEuemUJQTIaWYiFd1GuFmkkGzJ/Na3hkQhN4hxVoJ4rWGFI6laHOd7857++
         9wQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=LCAWhIBZ+Xj/En87E6Xit3AxUlwx2oy/nyBjXFJwNEA=;
        fh=yXrMtZN+avLGmMRQEFeGlU+MHLLAZYYoEcDASqZzyTg=;
        b=CAqDkpTk+9WyIzzOOCT3Vd5RbqIYyLmvlDnfsl3gNyjbVOOFCFpUp0i5IPuxsZaE2r
         GLWqHDCmX0E1yhCVJGzs3xcRxPxceKtyOk9sXa0iGLMkEHltlEGbjUfMDGbgMEiZ62UC
         GrT8t04dUQHltOYnLFeBFKTFgcmJ8+0e1Nida2v3NbMxi7EqoktO75nQsTtiU//uRCgw
         8f3TEIP3vZh5wKexqmn/BL8di975Yl1T8Gu4YiwK28AWYKdZygWqhXArW/SFeJ0q3ceL
         o8dPswlr/NWJycAh/5JgJgrwbWQFPUon8m5xosFfhTlpmbYuRVuIC8it/yLfelUTVJ2+
         G6Fw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Lg6BOJU+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719418471; x=1720023271; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LCAWhIBZ+Xj/En87E6Xit3AxUlwx2oy/nyBjXFJwNEA=;
        b=lqQY+ARU2xRMFs2XrDdbjlDhO5jlb5ExECHX/aOW/Cwem315uQXPqCrB/f6BBWgTgN
         renH5lOWvntrl28LFyZmKnr8cWsVmCkwmP/OvajcaMQry8TZXrQenXfrNff29lI0gp+d
         hWAOwIRm4bYS9DblNZLB+aqKH3ENQ8D585FGG1AZjD0sbMo4RYoiQ7FZF5TNOuSb+G+f
         Nh1Rr6S7Kndi73I1RI341H85VFLxsWLMPTVE/3ng9gBXC8VrhfZYhN+zG94qhhYCR9Ii
         08yIHBZUCwn57OGRuYFlnEvi6OxickSM2nn7r+XHc9+t+cix373bMhYmtv8fuFh7GrBw
         2PCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719418471; x=1720023271;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LCAWhIBZ+Xj/En87E6Xit3AxUlwx2oy/nyBjXFJwNEA=;
        b=LdWYC4Z/8pZ8mg1BfTuOanIjNVXkEFI9pgemIDVSbQp68j1HlcHkUEnTq3W+nnBn0S
         JKcrSl3WROU5wkiGc7n05KY5dtA6a8KItKdLdE04ZWHkIabXQxTLkeyLIiXU5nzMk5O6
         yQiDn7p/ZUgTbui1/3EVVgE6FNkfRrmdud/xhD/WyfZ1xJiiMfna4A8dv7FikAhpfiS7
         mPBRR3KoNnsDA9Tb3NK4ft5tpcju+F+chawompcDYBvGdjUEpP4v2Qi19ya5LKVxwNjo
         eg8Qo2WeJx+XLLmxDcscjusDrVQtUXxHrvzgQlWH9SB/YngtSChsjnU6Ug0crCfiVC1s
         xQHA==
X-Forwarded-Encrypted: i=2; AJvYcCXVHh2ndeW0OH0uURl+EP54twiiTLbAH7Se9GzeM6zxz7Yf34/9FERG87088hF28pV3j/I5h1xw2STlB5CarEXPRWY4ZrAUVg==
X-Gm-Message-State: AOJu0Ywy9YKjduADaHXT/C+rtJK9SzCyds544hBObettezcE5KulDhuB
	YgrSejP+jfDeddBlgti7gi0sX8nqUADXZ60qJsJ4FnmZ5TAOljN7
X-Google-Smtp-Source: AGHT+IGIJ1rYBpKMoCa+S5MRZwh+KQYnbYt4+O2jf2gwU5K6MD+7pr1FFwBPdk8d5CrcD0YwsdjHVg==
X-Received: by 2002:a05:6e02:17cc:b0:374:98b2:5a with SMTP id e9e14a558f8ab-3763df8d20bmr144583905ab.8.1719418471041;
        Wed, 26 Jun 2024 09:14:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:216e:b0:375:9d70:4e85 with SMTP id
 e9e14a558f8ab-3762692cc44ls53929405ab.0.-pod-prod-03-us; Wed, 26 Jun 2024
 09:14:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKVqzr0O6hPo7fVGtty5U7zZiqgLD9WFdegJP20BGu5bUIF81nu7roeGtbdbUPw4EowWZ2hDyIzXYvvo7427VKRrzXDuHQHvO55Q==
X-Received: by 2002:a05:6e02:17cc:b0:374:98b2:5a with SMTP id e9e14a558f8ab-3763df8d20bmr144582895ab.8.1719418470198;
        Wed, 26 Jun 2024 09:14:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719418470; cv=none;
        d=google.com; s=arc-20160816;
        b=Z+yo85tVTvfCouRHadmOdrfcw6VRfWnBdV4q0VZICQt3pUdV4QUPvSaIyGX7FuJjWV
         FY1ulJHi03ciG6k8hXRzFlAH+YWlLPiyGNAVnvpxueavridvaREzUMVwcYvtMG2g9thG
         jLuaNkjzd7fCs8uPw79rwYvIcBlbtTzOqYKsvXifsrcQ1MHOXsrTef14LjOIbwD0KSb0
         EAc8l6RD8VQC7hEO/zSyiZXM+rBpUBSqyHcMX9q1sOAI1GOKIPy2MzNFuhWHlx/p8dXf
         SpAIFSPcEaXPA6JXtBzGfe+9SCR5z8/oUC5vUJE8KtsXdfko2j584RkaUKCd70aQzYLI
         MPrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=kDDEvuft6YUbchcNAvdNgKui7TGEyIpJ9wmKFGBqMjA=;
        fh=O/zkIJxmlK15ca8x0V7mfEpOOT4FG5U0GaAAqkI/HfQ=;
        b=qSRwEljs0iG3KAnU0FzRnDvOWUTg1qpYLjWwcvP+Af8dCmXCKFgsqyYAPfbHSe/6TR
         dFSu3W4gouC2bi4cxmN9pOMLJlqx8gy0V5VD4HAUDaIcBLfWATTCvEwUuGwzydfV8OXU
         AAVQf4NcYw3LD5UtT39oKGheZ8yAK1Lo3GV1nwVwZLwq2UIsSmCQAS5x1Hz/3JxRJu3a
         MI80b7gEEq3rcpJFDeYs8uj9jSLVJLqIxq4SW3oQP8/mFi9d2WtSU5zngALVn8Mgx98z
         T8dQ+14erOsEdTVnLmssEm3vV5GWNTNDdWP74CuEyu3QOOS4EuQKycHa2r8luuBhiWi9
         ob+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=Lg6BOJU+;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-il1-x129.google.com (mail-il1-x129.google.com. [2607:f8b0:4864:20::129])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3762f3d60a9si5160155ab.5.2024.06.26.09.14.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jun 2024 09:14:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::129 as permitted sender) client-ip=2607:f8b0:4864:20::129;
Received: by mail-il1-x129.google.com with SMTP id e9e14a558f8ab-376069031c7so26377445ab.0
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2024 09:14:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURbm3ISy1PpNz9ozKetUqLrn3Wk0q69SQcUJ/cMkaJ+CPcUwDQOg50hs62CuQr0bCPEa9sVoKtg1zpfJwYWl37I7qOLgzc9umTGg==
X-Received: by 2002:a92:c569:0:b0:375:c473:4a8c with SMTP id e9e14a558f8ab-3763e166c2dmr137718185ab.32.1719418469797;
        Wed, 26 Jun 2024 09:14:29 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id e9e14a558f8ab-3772b4c8b06sm5483315ab.53.2024.06.26.09.14.28
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Jun 2024 09:14:29 -0700 (PDT)
Message-ID: <acd4c562-1f4f-4cd0-8ff8-e24e3e70d25e@sifive.com>
Date: Wed, 26 Jun 2024 11:14:27 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 01/10] dt-bindings: riscv: Add pointer masking ISA
 extensions
To: Conor Dooley <conor@kernel.org>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org,
 devicetree@vger.kernel.org, Catalin Marinas <catalin.marinas@arm.com>,
 linux-kernel@vger.kernel.org, Anup Patel <anup@brainfault.org>,
 kasan-dev@googlegroups.com, Atish Patra <atishp@atishpatra.org>,
 Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>,
 "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
References: <20240625210933.1620802-1-samuel.holland@sifive.com>
 <20240625210933.1620802-2-samuel.holland@sifive.com>
 <20240626-refined-cadmium-d850b9e15230@spud>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20240626-refined-cadmium-d850b9e15230@spud>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=Lg6BOJU+;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::129 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-06-26 11:01 AM, Conor Dooley wrote:
> On Tue, Jun 25, 2024 at 02:09:12PM -0700, Samuel Holland wrote:
>> The RISC-V Pointer Masking specification defines three extensions:
>> Smmpm, Smnpm, and Ssnpm. Document the behavior of these extensions as
>> following the current draft of the specification, which is 1.0.0-rc2.
> 
> You say draft, but the actual extension has already completed public
> review, right?

Correct. The spec is frozen, and public review is complete. Here's the tracking
ticket for details: https://jira.riscv.org/browse/RVS-1111

I use the word draft because it is still an -rc version, but I can reword this
if you prefer.

Regards,
Samuel

>> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
>> ---
>>
>> Changes in v2:
>>  - Update pointer masking specification version reference
>>
>>  .../devicetree/bindings/riscv/extensions.yaml  | 18 ++++++++++++++++++
>>  1 file changed, 18 insertions(+)
>>
>> diff --git a/Documentation/devicetree/bindings/riscv/extensions.yaml b/Documentation/devicetree/bindings/riscv/extensions.yaml
>> index cfed80ad5540..b6aeedc53676 100644
>> --- a/Documentation/devicetree/bindings/riscv/extensions.yaml
>> +++ b/Documentation/devicetree/bindings/riscv/extensions.yaml
>> @@ -128,6 +128,18 @@ properties:
>>              changes to interrupts as frozen at commit ccbddab ("Merge pull
>>              request #42 from riscv/jhauser-2023-RC4") of riscv-aia.
>>  
>> +        - const: smmpm
>> +          description: |
>> +            The standard Smmpm extension for M-mode pointer masking as defined
>> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
>> +            riscv-j-extension.
>> +
>> +        - const: smnpm
>> +          description: |
>> +            The standard Smnpm extension for next-mode pointer masking as defined
>> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
>> +            riscv-j-extension.
>> +
>>          - const: smstateen
>>            description: |
>>              The standard Smstateen extension for controlling access to CSRs
>> @@ -147,6 +159,12 @@ properties:
>>              and mode-based filtering as ratified at commit 01d1df0 ("Add ability
>>              to manually trigger workflow. (#2)") of riscv-count-overflow.
>>  
>> +        - const: ssnpm
>> +          description: |
>> +            The standard Ssnpm extension for next-mode pointer masking as defined
>> +            at commit 654a5c4a7725 ("Update PDF and version number.") of
>> +            riscv-j-extension.
>> +
>>          - const: sstc
>>            description: |
>>              The standard Sstc supervisor-level extension for time compare as
>> -- 
>> 2.44.1
>>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/acd4c562-1f4f-4cd0-8ff8-e24e3e70d25e%40sifive.com.
