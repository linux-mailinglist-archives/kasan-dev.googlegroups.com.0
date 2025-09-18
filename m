Return-Path: <kasan-dev+bncBCSL7B6LWYHBBK5XWDDAMGQENPZNS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 55A00B85542
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:48:13 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-55f742d8515sf608925e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:48:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758206893; cv=pass;
        d=google.com; s=arc-20240605;
        b=adCJb2TE6w44zlQ5pxmB26plqyjmLX+NwY+jior9jKpCG64WTGKZtFfeCbaKXBiAu9
         lrvoI0sjVYpcQeHwZ8DilFX1jMutHHebhJsi3zRunXXdWbbF9ulX6JSXmGbPQCKywbwu
         kloktFJP93su2FIjUq6PJE8aBVYCi/Z6jEDdq54/ZKhI0DzjFVplZpo+jkxtjLu/yxrs
         BzoB8LneNkRML/E0y5gkjHsPxBL95oA7VRw/NN+yLQcJbJ+NVdnGdxd9LKHaXYGEuu3V
         OqgDiZqMy8xfsTRz3l9YwumZ3qJuLXvGTps8kP8+vPQnsTYy9WmCvV7M/qIWPum/d6/F
         ooaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=c9Fp7XgPaiBdf/dz8ldYLCuOBfFsdcJS2yj4mV5ZQ/k=;
        fh=vzifQjBVGO2yw/sd5bYtr+4r2kRC9Huhkatesybms5A=;
        b=ZcXkMfeDe5V1SEOdqzMy945m/UXwi0xmGRnDKtXxIsCbq6V/Xo9/dywS05gWkZ2hP5
         wT1+i233AHVU4s+ChJTz1FIL89FL3Nhf4YamMo++f1P8pXLwcNhgiT2yJnFDYLve4aGb
         wKvNEI/XM1Wq8107wXzv74atkQubOi9LIRdXfaxrXG6AKOtLZT8umbgThmS8ZkzOlnzW
         A1xRAl5EkfVbey65kZ3Hg+C4tCnkMx8aBHfvFFfR0iIioQTgcGB+9xJKnIJKj8PjP6I8
         a+Ezsrode64t3XZ0+ah1FMTWB1snlLeMwmKrtFj08vBOrLDptB0SZtZ639ZhhCw+VgjM
         AK2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HnTE74dn;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758206893; x=1758811693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=c9Fp7XgPaiBdf/dz8ldYLCuOBfFsdcJS2yj4mV5ZQ/k=;
        b=w+ifJpzPOuw7+1+Q2uFihOdFirHYqn0Qfd4qPcCen9ggg+CObuppj2BZkxpWb261WP
         f+uUOl+HNAOjizHaS7tzuyp+N7XvoRkqI+QfBTmfkNVQeELXkypM7cHsuDJfMlVn2mON
         lWHYR282JqOqBDAgahAuTJh3EoJ3D0l+1soAgXRjVk9867JHN/APOieHyNiI3sIb843i
         I1Fvpq7TFdAbDRA2Ch/YflUiVjcAxp4U8gk5lDW57oNJglBCsH6BseIBtt9r/9/tTIyB
         gkiPUnpsFtyjK+YYFmdeGQ6JLTpzcE0IcIX7YNnpD5MK3JsSlB3CCf6tZ6xxxToHMr3r
         0XsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758206893; x=1758811693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c9Fp7XgPaiBdf/dz8ldYLCuOBfFsdcJS2yj4mV5ZQ/k=;
        b=MMppD/IkRSado7+lBkjQYb3n6dUwcInNM3Z/MqGJix7V+zJEZoKn+U+lQ538qzvHmu
         YP9bqkDdMFU8q+Vedt8/XCKd+hGa8Einc1/iOIi31RA/8JoMTj6MiLzff2fvNr8RKKv1
         8Ayzd9GAheFmmeUixEfnJHlr9aqqyPBCZDzm+KUbKxT4QUm2Z3H1zsBF4e061+0lGawZ
         8KwlkqdLC/Tto5AqzGRPdLpZZ9iMEhRw8vXWBAsKO6grMcullCdNekK46ZXpowVFdyLn
         bfpcFZMfk/e5CfCSRiRfmcNitt9PF3h7YB4ldH+aFiiL3EUMEb57SRAl18pALnAJVmsb
         29fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758206893; x=1758811693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c9Fp7XgPaiBdf/dz8ldYLCuOBfFsdcJS2yj4mV5ZQ/k=;
        b=XikZieU6C/yStH8WMJ0RAl+O0PAL/xAr0V4qmO6apa7P3tG0T/unYLulOlh3JF4f1u
         5F84fu6nHTwGMZzBteS/uB99yPAqAh+pA7tVurmXmyv43T5Tb0ekgBmF5javUEErDsMn
         QOWcE/2xSETCAAz8iXo+asbRh/QMP7/43A5NTKmxwm8iXapZrF4tYrAuuE15eil7WS0Y
         3+WiA4DxXfQW97Na35RXQQubLyrefMi029+vcBEEy5e/KuFXiQf/ImDK6ugjmBy8LsWm
         eSsKqN+rAHmiakSAha4xEoo8uxLD83bkNST2AiKU2jzBvh7J+SyeJcqlMMmGkASh8k1D
         7k/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVasxwbq/QXh8uoiYmAj+rxh2+cQ1s1981iNYn/M+7ly0lG6XodBAjhB9BPr+O9vWFidOubkQ==@lfdr.de
X-Gm-Message-State: AOJu0YzpWzoEJvbEuQgO7SL6aWIBdnmb0qCZNHEYpoYLP9HrnoHc6MBn
	9ibIj3/ie5xjkzuPLcpWBlSMl87nupvwqpWmsY7Ho41GggYESv1IJr+m
X-Google-Smtp-Source: AGHT+IE+NtVMKyjxq61yvRYzB6fz06sAzFwuxCxUhg4mtD14KoKTh4g/mr7e44ggVdfSyv7WZ7UWnw==
X-Received: by 2002:a05:6512:128e:b0:55f:6c08:a15a with SMTP id 2adb3069b0e04-57799115051mr2113911e87.32.1758206892490;
        Thu, 18 Sep 2025 07:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6NKdmVS+FqXDNKvtg+5QFHQ1J0XX/E4NMlIDvmFj2vQg==
Received: by 2002:a05:6512:24da:20b0:578:b22d:b290 with SMTP id
 2adb3069b0e04-578caf908c1ls344169e87.2.-pod-prod-09-eu; Thu, 18 Sep 2025
 07:48:09 -0700 (PDT)
X-Received: by 2002:a05:6512:b95:b0:571:3b37:a491 with SMTP id 2adb3069b0e04-57797ac833bmr2463195e87.22.1758206889394;
        Thu, 18 Sep 2025 07:48:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758206889; cv=none;
        d=google.com; s=arc-20240605;
        b=bC8K90GTfilIxLGqYEyuHFmYYvWi97GadYcbEYS6IwNZBk3VCrPestzfkueEe7dxq4
         vJFultotG5NMHpgyhqfDAK3ZSdc9IObHeH2DEyDdO+Cy10wA4LM/gD/Dcry6M7yk35+G
         aIe2/zgoKz4BI3Fd52jnY07rtk2MivoWzto+QvM2V7wE83btqWJLpmE09Q3fJPuYGQzw
         1mV/yeE8oLwrHR7HAHaxcxJd76ObX6T4jV4ipxZWt5Da0lKQIjwu6NXz1RzXdlaHco+0
         2pMM1WM+M5x3dCW6tKuOxTWCLa14JcH7Kch4NB34gObb8sBHsahWSrLN0rwMCFybNbhV
         qn8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=iAxT3fVcqeuUfVjtRTsWYQE3cdG0LYpzTMO+2TQXp/o=;
        fh=rwFBE99VPDXa/7mOBaqINSwNKDVTF369FkahNOFjaPY=;
        b=aGQMdaLzy8+TRDG7VLLdNqRLOgid9NoRUTYpRlBl8NQ0g7y5O1M8HHwPsrVGYWIqU8
         DO1t6ks3YV5ElUr5pgxJpQHEPdUexilYlFyD/bd+qfxVOoZ8rlFVhFaaFQ1bOQKlDunb
         zQq6spmCz6UXj8/vgmnFYh4gpXoDycXgVwBUpCInP66321w+ix7GEOoRnSUHlSf+u3he
         DuWajIE/WIBBqP12959eBjBQcSykZfh2LwrKRzgV6wtraI3CNTRaez0yZsXSt2jhUGig
         lTvbpCiOtGhrSaoSewtTA+pcbtweZGc2kBvjNZeCxjhCVBZivadL9m1asKUnJpJfdidN
         XTFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HnTE74dn;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a5f4480dsi54896e87.1.2025.09.18.07.48.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:48:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-577228eb9bbso181931e87.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:48:09 -0700 (PDT)
X-Gm-Gg: ASbGnctu22trsncpcV53vCpXLqMlIEh+U5TSDvL/rmJthPe8RHSrF0nfBl9fnqKW3y+
	/QB2oFUFuhyvi0HJgioi3Q+Lfu2mMkcnDLBUoZg0kSfjUZ+I9wlSHFS1wzTXfxPR5gvjJeHJUwU
	R4tjQQE9tPPXKAylYdtrd9usVsc3PoC41bkSF6Q6RYM5KtE7F5thecpSyNI7r/tdxqUgDcKaa9I
	gaW9TOAfnlFBHNflCO5uurK+VsTA6CFZKs3KW2PtJnQmZk2kWdDRSncZDxJRTeArppBbKvsZqD0
	6RcHaeaR9CwqznIbz3dB6UU/L7COFHhn5RwJfFKbH+ljx8fcAYFmqU4RJQ0kVwdZ57bZjJ+J4wK
	E5Vb7oG7GyJxmGcMIvYhankXnfZAhFJVARDFVpsRIsUjyloWbBLcdcRaeiA==
X-Received: by 2002:a2e:b8c5:0:b0:356:25da:89eb with SMTP id 38308e7fff4ca-35f64fef9cfmr8254611fa.4.1758206888768;
        Thu, 18 Sep 2025 07:48:08 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-361a1e07947sm6404731fa.12.2025.09.18.07.48.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:48:08 -0700 (PDT)
Message-ID: <9f332ea7-4210-42f8-b640-3135cdd808be@gmail.com>
Date: Thu, 18 Sep 2025 16:48:05 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 2/2] kasan: apply write-only mode in kasan kunit
 testcases
To: Yeoreum Yun <yeoreum.yun@arm.com>, glider@google.com,
 andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com,
 corbet@lwn.net, catalin.marinas@arm.com, will@kernel.org,
 akpm@linux-foundation.org, scott@os.amperecomputing.com,
 jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org,
 kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org,
 oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org,
 hardevsinh.palaniya@siliconsignals.io, david@redhat.com,
 yang@os.amperecomputing.com
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
References: <20250916222755.466009-1-yeoreum.yun@arm.com>
 <20250916222755.466009-3-yeoreum.yun@arm.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250916222755.466009-3-yeoreum.yun@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HnTE74dn;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::12e
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



On 9/17/25 12:27 AM, Yeoreum Yun wrote:
> When KASAN is configured in write-only mode,
> fetch/load operations do not trigger tag check faults.
> 
> As a result, the outcome of some test cases may differ
> compared to when KASAN is configured without write-only mode.
> 
> Therefore, by modifying pre-exist testcases
> check the write only makes tag check fault (TCF) where
> writing is perform in "allocated memory" but tag is invalid
> (i.e) redzone write in atomic_set() testcases.
> Otherwise check the invalid fetch/read doesn't generate TCF.
> 
> Also, skip some testcases affected by initial value
> (i.e) atomic_cmpxchg() testcase maybe successd if
> it passes valid atomic_t address and invalid oldaval address.
> In this case, if invalid atomic_t doesn't have the same oldval,
> it won't trigger write operation so the test will pass.
> 
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> ---

Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/9f332ea7-4210-42f8-b640-3135cdd808be%40gmail.com.
