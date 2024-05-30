Return-Path: <kasan-dev+bncBC6ZNIURTQNRBXEO36ZAMGQEAAAIXQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F182A8D4256
	for <lists+kasan-dev@lfdr.de>; Thu, 30 May 2024 02:25:01 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4200e6650ccsf427495e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2024 17:25:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717028701; cv=pass;
        d=google.com; s=arc-20160816;
        b=szVwPjd2cYZscCsK2KqmJUjN+3Cv6COOXFsrc4HQXooj243BkOOX1wkj4XQqFd2NzT
         RttPUm7Xg7g1TvXNGMPadI1Y5dx8rlnUHzNqYfLYF93KUPn91Nc3GDTWqeYn4lAjXMDZ
         o7Fm9+nXr2MHF7qHVLIBAM4Ek6xoSHvxL9IFtiwhH7rzXwKxLQByOw5VQXaj4refMSfW
         owqCYccZC4L0Yv9Bpi8DOm1bhKLZsAAjM0l8ifw54alN8R/qja8em7LEfQ2f47HMOSqy
         GsW3cqqLaEaq9rnCCM2lAHU3oCSjuW0QXczkEDT1RwOwGnD3zLOyVDQEx97saajrzOKa
         pO5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:autocrypt:from:content-language:references:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=1tBr450dce8whZX1gcG6J4VF/4cA1EwQ3UnMdB7l7Y4=;
        fh=OQg6P5wAsV0ek1fXVBa5Cp1mfRtKLV/Oj0F5W3VGC6w=;
        b=Ic4drMCQ7BaOGfA3+wNQSYlauMx5SXMteHig2lfK+rM//LJiDtkmo0TcNF2poshPK0
         W0gc14MbFXmV4O6829DfN2pCE5VWeA6SSKBZLIQncOyQRJb69jZWMd9sj9HOIO61K3A0
         f7Ar4ImCpHRbhbMzJ9r2NTcX0KIQXYVWrJvTK8/fXO/fJou6MHF4RCTIB3caMSBcD4tQ
         ktOFPnRydf/tI3NKHP7Kky+7FAMLhDeOlLTiznshMn8QJg0dHTD9gmA7knFM/BXIrZXZ
         WRmw22Fx65kTrLO40R9IeaPvtVwHCz8cUadFAbE9+gK3YmkAUfoCOz2Nouh7GzTSi0un
         aTNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=j6ulsMLA;
       spf=pass (google.com: domain of andrew.cooper@cloud.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andrew.cooper@cloud.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717028701; x=1717633501; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=1tBr450dce8whZX1gcG6J4VF/4cA1EwQ3UnMdB7l7Y4=;
        b=RT0620TiuDHyYfhLIH+c+8WoeZBiqoiwbzmSY2Z1IPeGi8rreHf2zhF2eisaG9ma1I
         MYmELPwgDfI+CA8zfzWMiS6qHp+gOuVDpMCzMFBWaG3UrDLNA5zhK4LX22zdmPTlhvXX
         tu9Q+wO8CIrtUA2ZTTjPMMQ0YMhaK+DqyUiBVhpxVfCsL531gkmeAvAQO2OKaVfULtCc
         SIL6eaLOdyX+MORHQfljyl3zKKBxgR5sQME8bIvkSItN/SG5zmP9qNlSZsrcoxOXTC2q
         1lybUpESh6iyLmVSbTTWC9on5xenrXwTVTyhkcMSXMfOdk4io/DuyrQTuDAkaRMycJab
         TRrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717028701; x=1717633501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1tBr450dce8whZX1gcG6J4VF/4cA1EwQ3UnMdB7l7Y4=;
        b=N/n+pTtyNfsTWchcY84fenu/EvmTIL2SJlp4X/9m/RTDfCeKoqjRqXj/q7QAt+pqY9
         dOs6RWYd8lHa1RAgVIkAqHYwj1C4NmaXVE5QEkagVXb/XVxIM/+vcEjfTSQD59RTYWGL
         isktsZelc1whiHBkWM8iTZXTKDgcCBlqeTrDd3DviNLL5eX9AhI3k0fkjFXy+NUbCa8F
         F1PlZxl4s/r697T3EisabUWf5EmQ+xFOhCfqsWRHMVfhVkEm/DHgeQ5gwZZTssp+/Dom
         jhemt8kFe85dt+vAKnGIhUmfFRQZyllx0v9cpOvHuiOHz14FElvzHmjcXqAmvPfVqizw
         gHqA==
X-Forwarded-Encrypted: i=2; AJvYcCWHhTRA9fPmT1NQ6v5LY3+TYopjVJpy6YUY/6Aiizyefjwyq6clWW8KaIkamXFcYAl1T1UJBjFWrXnwymvoLUn7UXsml00oHQ==
X-Gm-Message-State: AOJu0Yw70bakRW8AJ7n9yDGrGS85lTVU8OtVGzwnmGtCgg3LSaamizSH
	0m/vd/teMTvkwxN7ixWaqvb+humje97uQh5pTE4lU9yF+brAFPky
X-Google-Smtp-Source: AGHT+IG/qE2JlwJkzYOfXjyT2ZIzH4BuajGCpDQ62IooChLT9gWcTi1Gx8azP6T/0WHrAj+W0Kk6bA==
X-Received: by 2002:a05:600c:3b85:b0:41b:4c6a:de7a with SMTP id 5b1f17b1804b1-42127ec7dbdmr531235e9.3.1717028700840;
        Wed, 29 May 2024 17:25:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:c6:b0:421:2061:1abd with SMTP id
 5b1f17b1804b1-4212683db3bls1498485e9.2.-pod-prod-00-eu-canary; Wed, 29 May
 2024 17:24:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIBpcDoJTSAGAQjwPza7eZ5yUIvEsbTtYQiby3XxOknsNRK7bQKORh7EDm0l1mQpvCeiojgXnFmDdJGf5sAIab56+WioLGQGvUmQ==
X-Received: by 2002:a05:600c:4f12:b0:418:3d59:c13a with SMTP id 5b1f17b1804b1-421280f293cmr2107765e9.9.1717028698770;
        Wed, 29 May 2024 17:24:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717028698; cv=none;
        d=google.com; s=arc-20160816;
        b=GC3WfEJA7WGBia6Pv2NoK6fUWk40azJsxeySoAhapqbmf60yOjp/hvV2/MgnqFmaMJ
         Cc2bZiqGks20giEvXNnUkUF0g05KFpVboWLQMhnnv3gh+4rim7SCzc/a6Inj17ODdmVp
         2M4zmRB4hdZNDWrOB+vKxy01oFvf8SGtY1k/VWSPDIytoKr2/GTg+xtOQtCHflgfklXd
         lsb8ADBSc0CYYmG+OZ8+71MT/Y76v3z68WzbDTr4llzsVDRPpR1tz5F4TRuAnGPDsUr2
         PfvphLQDgVDMCJp+zZMjD8YvyhcPw+6AQez06ziCq/s2jk7UFnS+QEjMqclmdac7ZsQV
         O11A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=8WU/Su/TdkCMJqoSn+Qk/ofrN8Qleakj9+qJnBXhLHY=;
        fh=g0BM+kEEkPWi2Ua+Ikl7uzt7IAzGxMu5/S3TSpn8nlg=;
        b=BRV+rFetJCGDpPQSn5cceL9AwWMviVdHkFebTgzO/V8CN1LRev7sop4LOkVWJNIRop
         lpGUriQqJryAcB+zm/fuNB0uVKw5vivmvRH+SmJcZe9Rc5L5QxxapsPzHjYyatNaxHnU
         rBVAm65W/TcdRyeE8tUjFJM4JZXRLItlYjNIKgbOIcqRDnn+A/qW9gXm4WX+ECRSrpY8
         KBQbW6uNqcftDHIYixxdXjV8MJMjSChP4y/oavig5TtxCacQuKSwVzzMJrAmAJbDzJX0
         Uqg19Cd/V8HXfdJUrK7YL1o7huhffaVhy3HoZmjCgyHBRn6YArI9ayXWvyNomV7PgETA
         iwJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=j6ulsMLA;
       spf=pass (google.com: domain of andrew.cooper@cloud.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andrew.cooper@cloud.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42122788dfcsi817095e9.0.2024.05.29.17.24.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 17:24:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrew.cooper@cloud.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-35507e3a5deso316349f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2024 17:24:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWJHY97FY6I8IpH8reIiYXQdg/1GNx+LgUNCSgLJz7bYN4z6ZCG99cb9rakVr1kxXnOfNIzoMVyrZZnsWLq+2Xh/Wnrh63AtRGgcg==
X-Received: by 2002:adf:ea0f:0:b0:354:f729:c3e7 with SMTP id ffacd0b85a97d-35dc7ec9862mr169890f8f.34.1717028698143;
        Wed, 29 May 2024 17:24:58 -0700 (PDT)
Received: from [192.168.1.10] (host-92-26-98-202.as13285.net. [92.26.98.202])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-4212709d378sm8137365e9.29.2024.05.29.17.24.57
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 May 2024 17:24:57 -0700 (PDT)
Message-ID: <c068193b-75fb-49d2-9104-775051ffd941@citrix.com>
Date: Thu, 30 May 2024 01:24:56 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] x86/traps: Enable UBSAN traps on x86
To: Gatlin Newhouse <gatlin.newhouse@gmail.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>,
 Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling
 <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 Andrew Morton <akpm@linux-foundation.org>, Baoquan He <bhe@redhat.com>,
 Rick Edgecombe <rick.p.edgecombe@intel.com>,
 Changbin Du <changbin.du@huawei.com>, Pengfei Xu <pengfei.xu@intel.com>,
 Josh Poimboeuf <jpoimboe@kernel.org>, Xin Li <xin3.li@intel.com>,
 Jason Gunthorpe <jgg@ziepe.ca>,
 "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-hardening@vger.kernel.org, llvm@lists.linux.dev
References: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
Content-Language: en-GB
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=andrew.cooper3@citrix.com; keydata=
 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
 6+ahAA==
In-Reply-To: <20240529022043.3661757-1-gatlin.newhouse@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=google header.b=j6ulsMLA;       spf=pass
 (google.com: domain of andrew.cooper@cloud.com designates 2a00:1450:4864:20::42a
 as permitted sender) smtp.mailfrom=andrew.cooper@cloud.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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

On 29/05/2024 3:20 am, Gatlin Newhouse wrote:
> diff --git a/arch/x86/include/asm/bug.h b/arch/x86/include/asm/bug.h
> index a3ec87d198ac..e3fbed9073f8 100644
> --- a/arch/x86/include/asm/bug.h
> +++ b/arch/x86/include/asm/bug.h
> @@ -13,6 +13,14 @@
>  #define INSN_UD2	0x0b0f
>  #define LEN_UD2		2
> =20
> +/*
> + * In clang we have UD1s reporting UBSAN failures on X86, 64 and 32bit.
> + */
> +#define INSN_UD1	0xb90f
> +#define LEN_UD1		2
> +#define INSN_REX	0x67
> +#define LEN_REX		1

That's an address size override prefix, not a REX prefix.

What information is actually encoded in this UD1 instruction?=C2=A0 I can't
find anything any documentation which actually discusses how the ModRM
byte is encoded.

~Andrew

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c068193b-75fb-49d2-9104-775051ffd941%40citrix.com.
