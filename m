Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAEQXP6QKGQEIVG2XNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C7CF2B2307
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 18:53:05 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id v5sf4254644wrr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 09:53:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605289985; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtZf40eGT1aQ0AtxE2El5unWRuQ1Q4Su+vODm0aReiVqY6q5mnqQTDqiPBSoyHRh9U
         SUS7+mTRNgp7pQIVM4xZ2OUMM/8xdAVxJ6X8qBOOwvUDuoFSf08dP5/MbEvkETaozRTr
         isUP/ENLAT1IVuxdjKPidC11dbduVRnBJ2DORH8PV4N3qzV5B4Dw0k1vts4TDrKq2ZdS
         FfqY2u9zeSHZXkvsPMfU75eLCZ1akf6cPpPN6xIUOOTvB/SXpBpJr5RbNc5KSBY+bI9R
         Td1MCKZ0ooKB28UTJpeGnXH66umPJm5Txrk3AjULHSxbvVTFsu//JQH94Gm2YuszKeu/
         h5+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=TlhuybPFTQhQ8WlTmf/Zb+H4l/MYkD13EmQ1ZOhcFlo=;
        b=JTj2KSzBCPNWkWrDT5CPTX7g/MVq3ZRW/Ojcu3Zhfka8+CEnhaXQdfs596By/GUIY+
         8cyEEbByqpKZSrW+D2K0iJ6X5byw0giGdXLEAT0gFdGwWZEJNT6QR5YRfqfc+Lf2DTKN
         3/lpoO4aqQdnbO51kL8e3CrjXsiUu6wENvrM9/HOUHPXGHEzuenZ4HKxwky3dj40sYCS
         LgwPhEn6UFkKCB54+EVu4UFgjq8VGLgGKJNpPZpHizm7g+5HkQvyPkxbkIkQl5C9O1Lt
         B3RC1ahPEFXdu3XmsB+YJ8+38X/BACdA/wf3Vp26pSzSQR9n21jsmJsi0pT+oVVLmfma
         HohQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PDEdUPWc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TlhuybPFTQhQ8WlTmf/Zb+H4l/MYkD13EmQ1ZOhcFlo=;
        b=QUY1TCSNCZFrDyL8Uva+BcNwci39CgXGeJ5CtGGHmQzgitkOs8Sl+HQRqkPIuoLV1+
         r1m0CAREc/F3jYFkRpIdp0dcdFfh7fs8DiO4FlqjG1jJzhyDG1kZK0t/3txsFBAPntnl
         Of5ew7MTDCg3RJaGOKF3qaPJ4SFLP0ldCAYhVR0d+lKEjDG3wZPI4meNhStk48RNSrd7
         vJtHGTaxWYpAl1zHm7Qul5OujgiKCwRhlRsXKg9PkxICEJvVYLpUMczozJjAFoVC8+VP
         T54TG/NHBQe6CNe+J1qVV0btSi36xevCBMr5XdWdMSwx87p9QqQbQcmg2skNXI/a6obf
         HieA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TlhuybPFTQhQ8WlTmf/Zb+H4l/MYkD13EmQ1ZOhcFlo=;
        b=PJqW50HY+SLsHCIhHdlVtnvhYq5vzsQKnsbb9URJQPG8aj59Q3gok2SlEIV33/rY7I
         uwu31vSHTZGCPtA7skx0u5mReGW+mJ3l24enNSpzEeh17sijQEvLP88K8O1ZvdRXKGK1
         dG2Uz+MqGgyMCTtDeU1x4mVK/f46wAqZFcd8QYJmbtOrxIwq3IxWFTAxvThagCvwBb6x
         Hl0hPzY/Snw9W/n7ZKKgLcSLVLSdP7pLhLRkn9zyERfA1I3ylEiP+QoUhOZR5o4BZKJl
         54yDQwjuXnvu1GI7qe56ZKWyFoORGAW4RMNzXK9UU4KsjX3XrRdGKf/PumQosVYuHbnK
         dleA==
X-Gm-Message-State: AOAM530mIzSLb2Eku+pQzgxOx1Dey0YPEpw39pzf8xUP4E1H3br5RsXH
	iwSenq1zclYMFD4Hzl2Q9VA=
X-Google-Smtp-Source: ABdhPJxQduugsry2x54/JfC0frQgFIxxHgjHQ6awrDFL12l5JP8JV7CMIWQSK7xtPiLQPcZlQiP9xg==
X-Received: by 2002:adf:eb4c:: with SMTP id u12mr5154654wrn.73.1605289985018;
        Fri, 13 Nov 2020 09:53:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf33:: with SMTP id m19ls3490741wmg.1.gmail; Fri, 13 Nov
 2020 09:53:04 -0800 (PST)
X-Received: by 2002:a1c:f013:: with SMTP id a19mr3673158wmb.93.1605289984036;
        Fri, 13 Nov 2020 09:53:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605289984; cv=none;
        d=google.com; s=arc-20160816;
        b=IFdXZGCWjDgKWZtSiGPX1ekd6zbxXubsKzoetkh2GBrvNKeI6tlLJKWMpka33E74LQ
         JH963UzpmZGZ4WRIn3NAeJeAUtPCSsTJkhQlwFa91fTPmLKjGu1TZlsJoM9uCuvfpuLQ
         oFO//x+Nrl2gvVHup7BTcUineaLuqpExFptqWTQqsp0S7x9vTOoZcxyy0UzbUzw7Fb1x
         3FMoTamVTkcsmu1gWNHEc9QlRR3cYNo5rw8771qFPRnC/bHBqLGonMvYy5trcd1HdKW8
         ZUY476GWjeBif5vOT6nlQFLNonUnE7eegi5NemJ6do1MjuIXVDpof9p5lGrdl7AF7a12
         IX+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=zuo3X1dUSZS5dZ8jl01PZiwsfvErikn3kiTlWYen878=;
        b=jLsdsmOyxI2jZ9lg/DNWrcWpn3L082yiGAbMWK2gYkRersmoB9hVpKgUAN2FWe1bRD
         y7iIUeyiLAaDWGMAJIbViFnlkuJDdjaOy9f2JhFAl/JMzna8oDCz5Yw/sty8K8w5GrlP
         knRbxz2VGSITo46ugC0/mOyyzrlEDTzvjzDE/YVfGYAdCk8PErsfTKWkzWhTJW4napCR
         DRIsRIeO9bDYLsdFQixBy8xXTefkHLmIqpwf/lWNkOCDh/ZtVUra9oHNyWn+vgNYRd64
         RvXi1MC9vMlF+Pzwqb3g1oNBZjkcQSeWDx5D3Gu2ltmDZfAS0bw9qOQymz4ahPt7mscm
         6fRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PDEdUPWc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id t9si387140wmt.4.2020.11.13.09.53.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 09:53:04 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id c17so10821135wrc.11
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 09:53:04 -0800 (PST)
X-Received: by 2002:a5d:488f:: with SMTP id g15mr4844283wrq.151.1605289981187;
        Fri, 13 Nov 2020 09:53:01 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id c6sm12676849wrh.74.2020.11.13.09.52.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 13 Nov 2020 09:53:00 -0800 (PST)
Date: Fri, 13 Nov 2020 18:52:54 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 11/20] kasan: add and integrate kasan boot parameters
Message-ID: <20201113175254.GA3175464@elver.google.com>
References: <cover.1605046662.git.andreyknvl@google.com>
 <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <fdf9e3aec8f57ebb2795710195f8aaf79e3b45bd.1605046662.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.6 (2020-07-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PDEdUPWc;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Nov 10, 2020 at 11:20PM +0100, 'Andrey Konovalov' via kasan-dev wrote:
[...]
> +/* kasan.mode=off/prod/full */
> +static int __init early_kasan_mode(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_mode = KASAN_ARG_MODE_OFF;
> +	else if (!strcmp(arg, "prod"))
> +		kasan_arg_mode = KASAN_ARG_MODE_PROD;
> +	else if (!strcmp(arg, "full"))
> +		kasan_arg_mode = KASAN_ARG_MODE_FULL;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.mode", early_kasan_mode);
> +
> +/* kasan.stack=off/on */
> +static int __init early_kasan_flag_stacktrace(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "off"))
> +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
> +	else if (!strcmp(arg, "on"))
> +		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
> +early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
> +
> +/* kasan.fault=report/panic */
> +static int __init early_kasan_fault(char *arg)
> +{
> +	if (!arg)
> +		return -EINVAL;
> +
> +	if (!strcmp(arg, "report"))
> +		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
> +	else if (!strcmp(arg, "panic"))
> +		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
> +	else
> +		return -EINVAL;
> +
> +	return 0;
> +}
[...]

The above could be simplified, see suggestion below.

Thanks,
-- Marco

------ >8 ------

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index c91f2c06ecb5..71fc481ad21d 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -64,10 +64,8 @@ static int __init early_kasan_mode(char *arg)
 		kasan_arg_mode = KASAN_ARG_MODE_PROD;
 	else if (!strcmp(arg, "full"))
 		kasan_arg_mode = KASAN_ARG_MODE_FULL;
-	else
-		return -EINVAL;
 
-	return 0;
+	return -EINVAL;
 }
 early_param("kasan.mode", early_kasan_mode);
 
@@ -81,10 +79,8 @@ static int __init early_kasan_flag_stacktrace(char *arg)
 		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_OFF;
 	else if (!strcmp(arg, "on"))
 		kasan_arg_stacktrace = KASAN_ARG_STACKTRACE_ON;
-	else
-		return -EINVAL;
 
-	return 0;
+	return -EINVAL;
 }
 early_param("kasan.stacktrace", early_kasan_flag_stacktrace);
 
@@ -98,10 +94,8 @@ static int __init early_kasan_fault(char *arg)
 		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
 	else if (!strcmp(arg, "panic"))
 		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
-	else
-		return -EINVAL;
 
-	return 0;
+	return -EINVAL;
 }
 early_param("kasan.fault", early_kasan_fault);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201113175254.GA3175464%40elver.google.com.
