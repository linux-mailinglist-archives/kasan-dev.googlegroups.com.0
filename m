Return-Path: <kasan-dev+bncBCSL7B6LWYHBBP72ZDCAMGQEEYGIJCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 59347B1B92D
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 19:20:01 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55b87768966sf2586259e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 10:20:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754414401; cv=pass;
        d=google.com; s=arc-20240605;
        b=JmQz4+UOih/fxdtYX/5eTO4H0QJwWQ+8sXaYXHcb8S7Cvi7I0QNfHuU2iPJ+asm2Te
         yNTeKb5JC4a2FqKiCljXQOC9MCvK1U5LcNgy8Wwy8ct5IhpOUrN/wNjSGSlwrecifRK0
         p38YDrgw8rrlZSwRIcA9rKsuZbOd3GtwPrTfSbzO87zxrZw7rADzDWUoEel4pR5bx+5K
         /Tl8FEgHOTTnx5XCEzuJjH8X+RSRmmh8U9Po2fSwzp716eyjueusGr71P4qTx5ihHU+W
         VErW5CqVe3NrkbhD3tB1RxsBFZYeZsMMcm5FUKdS2MxfDd9VrSze/+IzzYhadMGqPs84
         X9tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=NjMs/w4jfzFZzA6+1g/tBQ4BbaZnWZRX5ldEcoo7Mcg=;
        fh=ND9hh/HkiQVFJd4OADL10Xqpo+4MOTsBy/c+IlF+ydk=;
        b=VjkDQDlKmDfk95w1v0GCtb9evn97ATJKo4zjhMP+9tSwTH9g9DhNwizCdmtqitIlPf
         4g/LpYbJsyfKrV+ZmvITAJXpLYjbWBSqt5YcnTlgexjMx+SMXWgF1ndCOJ2xDm6yMkvl
         mexIxKPN3mV8KqcGtB+pla3T0B87jEmAB15fSVUmazNngN1RQT9lvWSBm/E5dj0dVIBA
         N9PiQVoR2z6OA3tilnjCl4YP1Wd4ZOWGE/p7ZfwKvi1Fz2VquhM0+WuB4rT7bA+YpvzW
         Tz4T+7bWPBoWF4x854VQfcpPk7+2IBEuXxkkDCKT0KNPd0bFOBMHVWeInYSdlvvSEypM
         pOzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RT7lTckb;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754414401; x=1755019201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=NjMs/w4jfzFZzA6+1g/tBQ4BbaZnWZRX5ldEcoo7Mcg=;
        b=JmZAnpMRiizFKgIJaS3k2Ajmprdi6oj9SRdE8MK8irN+S+iw4SFF/DXEPf4gnOIUiI
         lnj7eWM456KOpRPVRf3CEZ4fWQYRWx7jHnaRoqJSTj8OK7onedok9YagCPrRZML4FXcx
         wdYnqNoXdgigYCyEvksE5v/UPXyvGbnyny48p4NHbgOPDl6lau98wEY25Oq7htFIzVC4
         7T/lbV0TgAFXiS4Ag/FoKaY2zvq/aUC+26Ot0fkMix8DAFqVa/tr0uxPrial66c2AbMs
         ddi2JvhzQiOkVhDRFe4kXWYNGa2L8vY1KYxLe7s3GprpQry7VB/sGLHgGxvgB/0VHOKg
         5cvg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754414401; x=1755019201; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=NjMs/w4jfzFZzA6+1g/tBQ4BbaZnWZRX5ldEcoo7Mcg=;
        b=d3VgDBRSbJkoiHAnA7zXIYQFGs23UCLkrmD4ndhySjArb4cJQwjBkdLGdWC7j9tS1V
         MJbSVZz57IgFnmyIOJ+kb+obCOlsHl65+w0CZu4zGDjKPrdOC9TGLsiEFuGp6h05fL01
         Qn2PQgO5VEvq6xKZaAp+9XtJBpv08FlLJvbIAEQuqskdetFJduoG2dKbIvy9+M6fcXkz
         xHjBUt9GJA6g0IVfdCjWJmLYVtjyh6jbmhTrEljyMoJ8NtdhBrD9y0l0ASEZV8SEEmwt
         XKDL8CaEbgY83kfIeRKpDBLn7qBFgXDQ9xUYDT97ZV2h+3URNJ78tpLH7qFv2yGKEDge
         lAAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754414401; x=1755019201;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NjMs/w4jfzFZzA6+1g/tBQ4BbaZnWZRX5ldEcoo7Mcg=;
        b=SL4wZv9+lDGt/nuGv3qzRzSS3magVb0V7CgK0zHPuggX9TTLTdECKhepZr5MV2bgjt
         fjt4Ahtn9Yk07Ni6cFbHvli6E6hpE3s8Jk4y7YXtBC8iuzTMFGcrRPnimoMqb97/7MeH
         7VFKIUX5/63woN86gJoP+7vwKvCIb6tEigYUPtPz/BRb2pFohJyX5xRArgzbvQ1b1i1v
         DQdr91wTz05qTnrxpMcYK6ZnM5uXO9DLmvIFKoLnFOpX2zN8EfslJjbjfGswcE1eoI8n
         EmyHpacxA3rQTGQfR/iZCKwFwr0rHfySXXRrsImb73Xips8jp/M7Nyg2o1xIQvpLUw6C
         6Qbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUwiyEzNGPX/FmSTI/2BRLQEXMLvfaAfQ6G10LGqAzgb0eu7YWSdL8ImN6ohCwtUCD2YmkDtw==@lfdr.de
X-Gm-Message-State: AOJu0Yz/Mm73TWNUJrojts3Jj5fwr04WwcEQDsCjyyiefx8qOczlAVtT
	09XV21TT1l8Epg/4qDDQDfZTQXxTC8Ue+KfWoskueEncoKJGAHjlTxJ3
X-Google-Smtp-Source: AGHT+IEDqwn7m2xdped+y8vpuerz5fjmZreZOvY62/omZRnVU+YgpDHDoOVvazJCeustnF6++W6/6Q==
X-Received: by 2002:a05:6512:3b9f:b0:55b:8a97:3eba with SMTP id 2adb3069b0e04-55b97b7a8c5mr4144763e87.36.1754414400348;
        Tue, 05 Aug 2025 10:20:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd5Gystweuu0ykI3apVkGrc4mN/8ybmNZ/spGDCTPaENg==
Received: by 2002:a05:6512:628e:b0:553:d125:e081 with SMTP id
 2adb3069b0e04-55b87b09f35ls1097311e87.2.-pod-prod-03-eu; Tue, 05 Aug 2025
 10:19:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVQeM4gmlp5ZOgqA47foBrtxWqu2QA6q5vAb6/DUEVjpoSj+ddGIT4MDAjU3rUsKISPCKHLZwYI4KY=@googlegroups.com
X-Received: by 2002:a05:6512:1115:b0:55b:76f3:2134 with SMTP id 2adb3069b0e04-55b97b3de33mr4377113e87.24.1754414397022;
        Tue, 05 Aug 2025 10:19:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754414397; cv=none;
        d=google.com; s=arc-20240605;
        b=OJEb5OsiK9aDqzfGNobVFGKcN0crLbHQ9ipHUiyAxM66z4hadIzcpcMOjJ2Us+P23X
         tybId2GX9zb91PEmMqUcE57VdL28dV0/tlkKr6pzHDgN4HEhhuLOZ1JqWsu1Wi2eT0IK
         1q8QbviQUXMDn5BUDT+EOSqvEf3quzpuFUBv9djJaJW9j9U9yCK0Se0xxv2AQ4rZlraa
         s8UxCZ8B1LW38lYRl1Rj0XwhrqhPw+CuCFS1+oOhh7APBWEhK0U1jr4RfFnaJhNFbfAV
         4vQGScBJNU7nqGWw7sAyD0woy4SAYAGrmJvPU1YZm7cBjJQHvTkndpRXBNuivArHduTY
         ZhfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=Q/FfZaSan1eV7HDF3Wa83lEa0xPcSUpZYrzYE5G9wjk=;
        fh=T3fGA86DLOT0XY9HZRw1z9t5v9Qa8yiU5/zZje/5mNY=;
        b=Kvm5cyZMt/eRi22wVGSPED2eWD/bayeeP1dP0sscG0HYZFFuYpfOq6y/gGaTDSuh1R
         oAxNRQnoLVqo3wI8k1jh4h5eoZ13QFEPP0Wjvi/W719rwTg6R7XVrdMv2fgKcEfaphBy
         +gv7jI5zimVsIgZfTc4WZ073ZZEBLicK+yoylQvxIPyfjZLVVZRhXEVf6ajLb15h5qV0
         NSQl4W2rzRWMlrubiKJHbona+cdhqrtkvgvDbFbquL55KFjIqr10bB303yPXx4ysrGJU
         DuhUIhmMYgps4gNkq0BemSTobMS5v3ew1BUqSkmGOM6RGx0L8IQb0pLMVR/9NBCq6Atn
         B2WA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RT7lTckb;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x231.google.com (mail-lj1-x231.google.com. [2a00:1450:4864:20::231])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b887deca0si312434e87.2.2025.08.05.10.19.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 10:19:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231 as permitted sender) client-ip=2a00:1450:4864:20::231;
Received: by mail-lj1-x231.google.com with SMTP id 38308e7fff4ca-332468a0955so5828341fa.1
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 10:19:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVZqCP7HCazq5cuhknETJUVLuL2Ui/Iq4KfkVD0tv9TlPIhVS8v5b0w8I7VC8+8rEWtJX/btDjnl3o=@googlegroups.com
X-Gm-Gg: ASbGncs2tJuLHTPntJxIbrwsZLSWjnlROFL9TcZ25X2S9k/pp++qhC/jReqyJqIGtAE
	TAUyBnzT9dXr/aoSu5feA5oTIjX3VlAA6yO0t9KkPlVw1TafMho/IC31uVX1AzkgIEbm8/n3uFi
	HhEakWJtd+Zp5m9gKYSXvIn79Rbr++0ihNUgXCMPnmvtbslqzWK/0AR72VbtqxMpPykHn5d3FET
	Ol7iIawXqmiO9hOp55V120MXGUW9XPyo+TDBG8xavOLm1FjVFDFy2dqjpaFYDEdpY+PLLeL7SMA
	jUMxabk36Z7FXUGb2aEcX1Hs5bAiqDXtpTRWcslJVO0gNOPwprMBR+h5ej4q6CLP9MSPAcYs71q
	yP9uGX08Ul+yVQh2leDNq7vMmn4mj
X-Received: by 2002:a05:6512:6d1:b0:553:2480:230a with SMTP id 2adb3069b0e04-55b979b819amr1540170e87.0.1754414396425;
        Tue, 05 Aug 2025 10:19:56 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-332382a9483sm19586481fa.23.2025.08.05.10.19.54
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 10:19:56 -0700 (PDT)
Message-ID: <60895f3d-abe2-4fc3-afc3-176a188f06d4@gmail.com>
Date: Tue, 5 Aug 2025 19:19:09 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4 6/9] kasan/um: select ARCH_DEFER_KASAN and call
 kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 trishalfonso@google.com, davidgow@google.com
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250805142622.560992-1-snovitoll@gmail.com>
 <20250805142622.560992-7-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250805142622.560992-7-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RT7lTckb;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::231
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 8/5/25 4:26 PM, Sabyrzhan Tasbolatov wrote:
> 
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 9083bfdb773..8d14c8fc2cd 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -5,6 +5,7 @@ menu "UML-specific options"
>  config UML
>  	bool
>  	default y
> +	select ARCH_DEFER_KASAN

select ARCH_DEFER_KASAN if STATIC_LINK

>  	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
>  	select ARCH_HAS_CACHE_LINE_SIZE
>  	select ARCH_HAS_CPU_FINALIZE_INIT
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> index f97bb1f7b85..81bcdc0f962 100644
> --- a/arch/um/include/asm/kasan.h
> +++ b/arch/um/include/asm/kasan.h
> @@ -24,11 +24,6 @@
>  
>  #ifdef CONFIG_KASAN
>  void kasan_init(void);
> -extern int kasan_um_is_ready;
> -
> -#ifdef CONFIG_STATIC_LINK
> -#define kasan_arch_is_ready() (kasan_um_is_ready)
> -#endif
>  #else
>  static inline void kasan_init(void) { }
>  #endif /* CONFIG_KASAN */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/60895f3d-abe2-4fc3-afc3-176a188f06d4%40gmail.com.
