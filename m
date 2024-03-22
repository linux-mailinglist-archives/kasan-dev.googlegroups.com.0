Return-Path: <kasan-dev+bncBCMIFTP47IJBBQ426OXQMGQERHE4WHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id B946D886445
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Mar 2024 01:13:56 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-42ee24bf0d9sf71941cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711066435; cv=pass;
        d=google.com; s=arc-20160816;
        b=s0lof1BuNDVmevYcgjbQiRd4RdB9iN+8fsuFfUHxfOPktwvXveaeMU7g/Czf+4WgvP
         KFUuSSy40lzZ7wqZYVRWfUboGbWzzjDPd/8A4LpoiUTWMV91qEt0nruexjpNRLhG62ak
         bJedrdkGzWscsdObboBCGM8niizU1v0GogXqsoNfCf5d94DiQKTdjXi+9JDduCShPg7e
         G7iLZaa1m69+psArzlD/0l/B6Jwxw+YYnVMU5k8zt3Bt/cXjXcxaJNF0DihIbSEOhWXg
         1Mz/uvawOkWdQEfwh/PE9/r2QVgWymCBVJLMsafhAR/WAGR3sLu557kN0eFXHUIzU3qu
         YBRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=VmNIKQ0bpkiBOVKggg3SD/ieMQWK2ylfrgL8m9AEslI=;
        fh=31Os06gUDRTvfGim6PxktUhPYHN4yrrLYoXBGDlJU8E=;
        b=W9TE6dQbSgd2nVh4+tsHK6i9N/jN790wA8QyzwRt59VnSSO6Y10ddkZnTjnohN3hrh
         yspmE9x5IoB7pujUUP0CpYrzS5q5LS6pnBfJWKt2lBpiuq0B6iPeK6OpCHd2nI2PVNua
         cWdcwimvT9yK7Zdl7snuMO5TUZTjUgO16l16qQTZAAoP8X9nF+X9e2tswBtmSnyg0jAO
         mybSbj/eZVLsdheaAQzRBU7nvJKvPl0k+TUQZcs2QueGCr3mG8lqNe1q1W1PUqj+TZUW
         ya8VtBOzXtB+oUUct4CrcUFQlKTGE25ZFOab8F+JXTXSC+GTuiL3AWdpSxdzFxHnfFW6
         F4CA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=NByKtgIq;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711066435; x=1711671235; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VmNIKQ0bpkiBOVKggg3SD/ieMQWK2ylfrgL8m9AEslI=;
        b=t+EBBmRI2d22LzGas+Uk262N7AU6oE2uDHqhBkgUgZtslhkfL7lt+5qx7ul0XfKqMv
         /V2wDSbB90ctQ+kW/HwsD5an9fN+5/m0PxYa04LLoajAjCtd2nFowxSJDDMLPV2YxrcW
         KUo4mQrYsHeSPDegtysuT26NMqQaQtLXywZpCLyZu/GgJGv/JqhQRnK6b6COnSrLGmRT
         HgGiYzYkFChbzc8+VZ+LSdu9zqcFP2nZp8EiARG4UZD5g6zX4/iHp3PylCijvBbdUVIK
         5kBQQwZtMqcoSFjOypu1YS4TkkHE6zuyEw36qQUhbC8P0o0Ir0gueQQ59EXHm+1aolig
         o5JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711066435; x=1711671235;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VmNIKQ0bpkiBOVKggg3SD/ieMQWK2ylfrgL8m9AEslI=;
        b=uRZKz8agXqCGvgDixcKt8vI8EtPjrSD3hxUmF7/C8xUeS0G/xqozcp6JOoM/QlIrs0
         aaxldqNYOl4hFpx0/nJVKZl53ePczPc3Ejdh0e1OIwvyzfiADTUkv8e1AW7PIhP9DYjY
         edYX1vLXQxOXog9mFmQeTFumETRyBokLctRphSkRqREpIolG24dz1E+sK3HmpW4vqeM8
         0TqXv06zg39VcVQUt2MrCBP3HBYpRvf/0VmZcm21jR8rFqEKJqo1N+PAZ7RMcoAr3svt
         vppgajWVHm6K4DDWsiBZLofln3Zue+tBwOF5RymOT/yRV/oGSJ2eJKargKTGEgV/htDK
         rp5w==
X-Forwarded-Encrypted: i=2; AJvYcCUGfJ7ID5A30Xg2jqAJjBCHQUA0SqDNb4a0OSliV/4iq+7lmKtqTiVZZNGKEDla/nyQQoiYiMx4EdsNj4jzU1T07Quw2dgHig==
X-Gm-Message-State: AOJu0YwCYNdHfHWLaJR+gJ9S1ub1wA4Pd5qVrhIIrXyvX9svbAs8LzE6
	itwVHa7HVdwX4JLpbnqTgtD2QSuZp3rlcC7BOSAZZxijCeAOlChz
X-Google-Smtp-Source: AGHT+IGGATPu7tmz1xbnSwM6PZIcIbqzrWiShhh4522x1HrP28cdG4Yk1HoZBCVgQtXDaCB/hNlK4Q==
X-Received: by 2002:ac8:5f83:0:b0:430:ebd2:20b4 with SMTP id j3-20020ac85f83000000b00430ebd220b4mr499890qta.12.1711066435363;
        Thu, 21 Mar 2024 17:13:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5010:b0:681:3006:a423 with SMTP id
 jo16-20020a056214501000b006813006a423ls2209742qvb.2.-pod-prod-01-us; Thu, 21
 Mar 2024 17:13:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZJEi0sViguYZ0hr9XtrfE8sj2ZxHu5pv818YY/sFEm6hGLOQEb4vXJPlqXVsygApioIGLXOmft0pCCaDTZYNlzlPLakwVirsXvQ==
X-Received: by 2002:a05:6214:410d:b0:696:57b1:1582 with SMTP id kc13-20020a056214410d00b0069657b11582mr730084qvb.5.1711066434739;
        Thu, 21 Mar 2024 17:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711066434; cv=none;
        d=google.com; s=arc-20160816;
        b=IKRGR2IYPLSGHutrW+jAV89UV/jVX14+2NK7jJUrz3mHH4b2ksJPuJjYcwKmDTwMOx
         J4Gp4vuuIkvuhiY/Z7lJVD2KnUd5Prcguy9xY7DS0pQWW39BwhpmUXuqy8tY+YUzpoYo
         wneNjIUIooGXSMTDdHi4Au+J84dYvuHTM9ZZmwKqmuxkkAacIwa1sG/1pfSZHb9CQIxV
         9fNj1gmb1GwkT8xCQfgtHUwGP+VMyBKy4H6v7AdiPrPWxBlo8cAtQlqRPFzmQEX/gLs3
         XtIHZ6MJlZbX5eVAXjWHf1Z/S4GjAkBt+2+wwZVSsHCT1BjWMJkmXJxEqMac0L2nV3YS
         fUnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=oVj0RTqijXF6fGHo7lvyifktNSlsSBmRQcPYhg8uW8Y=;
        fh=yYufAI/6dss9Guflz0jAp/3nZwj9gU/8odhfoow472Q=;
        b=UglQLOcYvNMnx32osgL8XEtFC4WLPZn3Ohh/lipZN0KzTWZoVeA8AdMIo0ak42+AfO
         37fUUwATQo+ebjohe1B6F7RnEYvgSIV/IsKbOSHGiaCUg13ukQY3vbOqIdr4+3HcSgA/
         YuGTaILdy9iYKNMvep+988pOHw0KfFiqVpEjPIDZfaW/xC5XoMdAnCJpJqtVHel4nP0s
         7QYBnnLtZABPsJHOGHRKlS8N4TgdWY2rTSAmXnEWAIEtRCXcS7LylLZV75+Wg+E9W1Vc
         SaZ67qLAYWBzxelup+IKlFlEU+OedGHoHTIZVXpJVlv40UyVqmOLk5/2ftVLXGapRzPO
         yQ+A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=NByKtgIq;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com
Received: from mail-il1-x12e.google.com (mail-il1-x12e.google.com. [2607:f8b0:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id w10-20020a0562140b2a00b00696419ee0desi70882qvj.4.2024.03.21.17.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 17:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::12e as permitted sender) client-ip=2607:f8b0:4864:20::12e;
Received: by mail-il1-x12e.google.com with SMTP id e9e14a558f8ab-36864f7c5cdso4602295ab.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 17:13:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXnCzFjhw4OR3d/nlD0y51RWCB4Kux/IGgwtvhRGMkwGTzYGED3t996xx9LRf4alUOJ9jNtYVFlTJ7SC3jguOlCPRix1FfEhiU3oQ==
X-Received: by 2002:a92:dc83:0:b0:365:29e4:d95d with SMTP id c3-20020a92dc83000000b0036529e4d95dmr966458iln.30.1711066434179;
        Thu, 21 Mar 2024 17:13:54 -0700 (PDT)
Received: from [100.64.0.1] ([136.226.86.189])
        by smtp.gmail.com with ESMTPSA id y18-20020a056638015200b00476f1daad44sm206727jao.54.2024.03.21.17.13.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 17:13:53 -0700 (PDT)
Message-ID: <d9452ab4-a783-4bcf-ac25-40baa4f31fac@sifive.com>
Date: Thu, 21 Mar 2024 19:13:52 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RISC-V] [tech-j-ext] [RFC PATCH 5/9] riscv: Split per-CPU and
 per-thread envcfg bits
Content-Language: en-US
To: Deepak Gupta <debug@rivosinc.com>, Conor Dooley <conor@kernel.org>,
 Palmer Dabbelt <palmer@dabbelt.com>
Cc: linux-riscv@lists.infradead.org, devicetree@vger.kernel.org,
 Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org,
 tech-j-ext@lists.risc-v.org, kasan-dev@googlegroups.com,
 Evgenii Stepanov <eugenis@google.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski+dt@linaro.org>,
 Rob Herring <robh+dt@kernel.org>, Andrew Jones <ajones@ventanamicro.com>,
 Guo Ren <guoren@kernel.org>, Heiko Stuebner <heiko@sntech.de>,
 Paul Walmsley <paul.walmsley@sifive.com>
References: <20240319215915.832127-1-samuel.holland@sifive.com>
 <20240319215915.832127-6-samuel.holland@sifive.com>
 <CAKC1njSg9-hJo6hibcM9a-=FUmMWyR39QUYqQ1uwiWhpBZQb9A@mail.gmail.com>
 <40ab1ce5-8700-4a63-b182-1e864f6c9225@sifive.com>
 <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <CAKC1njQYZHbQJ71mapeG1DEw=A+aGx77xsuQGecsNFpoJ=tzGQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=NByKtgIq;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::12e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

On 2024-03-19 11:39 PM, Deepak Gupta wrote:
>>>> --- a/arch/riscv/include/asm/switch_to.h
>>>> +++ b/arch/riscv/include/asm/switch_to.h
>>>> @@ -69,6 +69,17 @@ static __always_inline bool has_fpu(void) { return false; }
>>>>  #define __switch_to_fpu(__prev, __next) do { } while (0)
>>>>  #endif
>>>>
>>>> +static inline void sync_envcfg(struct task_struct *task)
>>>> +{
>>>> +       csr_write(CSR_ENVCFG, this_cpu_read(riscv_cpu_envcfg) | task->thread.envcfg);
>>>> +}
>>>> +
>>>> +static inline void __switch_to_envcfg(struct task_struct *next)
>>>> +{
>>>> +       if (riscv_cpu_has_extension_unlikely(smp_processor_id(), RISCV_ISA_EXT_XLINUXENVCFG))
>>>
>>> I've seen `riscv_cpu_has_extension_unlikely` generating branchy code
>>> even if ALTERNATIVES was turned on.
>>> Can you check disasm on your end as well.  IMHO, `entry.S` is a better
>>> place to pick up *envcfg.
>>
>> The branchiness is sort of expected, since that function is implemented by
>> switching on/off a branch instruction, so the alternate code is necessarily a
>> separate basic block. It's a tradeoff so we don't have to write assembly code
>> for every bit of code that depends on an extension. However, the cost should be
>> somewhat lowered since the branch is unconditional and so entirely predictable.
>>
>> If the branch turns out to be problematic for performance, then we could use
>> ALTERNATIVE directly in sync_envcfg() to NOP out the CSR write.
> 
> Yeah I lean towards using alternatives directly.

One thing to note here: we can't use alternatives directly if the behavior needs
to be different on different harts (i.e. a subset of harts implement the envcfg
CSR). I think we need some policy about which ISA extensions are allowed to be
asymmetric across harts, or else we add too much complexity.

Regards,
Samuel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d9452ab4-a783-4bcf-ac25-40baa4f31fac%40sifive.com.
