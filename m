Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4UR2KAMGQEMZKVWYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 65B6852A09B
	for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 13:42:12 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id m2-20020a0565120a8200b00473a809c6e0sf7860437lfu.11
        for <lists+kasan-dev@lfdr.de>; Tue, 17 May 2022 04:42:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652787732; cv=pass;
        d=google.com; s=arc-20160816;
        b=tBXohKWSp0Z6oGw2i2OuJY7/5WsM9/t/Ydu565JXv4Idxz9H9Uwi1ldMHTOqZUueor
         i4w010m5t+ib9lfTweKHp7ac0YoM2+2T2oImD1qxTGBYsdsm/Az9/FqkfRGKRx6sCgSD
         0alCC0m2VCn9ZUxHMrKIotVI+P2yx5s22r9vqG3EcPy5SgrLP3U2F94K6zBy65cPP66i
         zr+4NWdT8LeO0x1RicyMxV8ruuSDPjAAvfxEM7f8RWuxM9ULaT7zXSqBI2mTM+lkzyS/
         kEnObzzeeUQk3EJG2JDwHlRn/NSbCjf8ORVorq7iG/omW538OJ8WM8rmRcm1pS3/QEDt
         M2Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UKh2r4FZ3u5ztf95p/55LFan7P0QN4l72/He+gOSfBU=;
        b=e6vqdmOr51ISMxlYfeBRpVxf6xmwTtDV4y5PtTkA6pJAqYTUy1rsyE9yk6voNH9Qic
         98nCPOz90H2PYb3HJcKDJ/Vb2SFt/bDwAKD0ZF+Vxv6Kln8qePAZ9R4aDKRe7o0Dqva1
         d+JzlMHqWHd5iVFj/Ju8Bxyh1tvw740FeRJtyfjJ8zgpxuZJnFOK3ukoFWleUUwy3lkc
         tDZG79SdbvUqWEyZzq2cG7Db+Wk8eMVbQq4O0ZD/W11GqRZ0D8WtKUp3SHwcN+UgRk0t
         1wlsvc0erZzKmhDv80Kf1v6l2cbpBMzCrPXYrUza2+1T63qiVreFUsxEiQgGabVGSa8A
         QUpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IYeMCvyc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UKh2r4FZ3u5ztf95p/55LFan7P0QN4l72/He+gOSfBU=;
        b=BeRl8BTfKcG4ZkS5gHaXYbjCKUqOsvtUDutkGANxCEzpFMssqC+RGCc8cqL1di0wmX
         ZIsYE/JtQfTBnZFIMVfi1FJz5Bzo3bW3Ce8h1TAHZHbrb+kVJoe5NFJE33S5J6pqLwCu
         AbHFCFHhDcuLTyz8M+X2AvP/WCALEPqN8pVhibZVcJG3p644b72KsYcV7e0Kq79okuBj
         QNW7CSzmhZD4sL4Qj0xejAkO3gNkhAfGXPi/OorNbX1kc3kLXbFNM3KOqPJvj6AMoEj7
         6Y7VKgrOQGSzj5tXkmBwuIQSdFnXfkaxzknQdXFeli20Cmf7Xs1gKgnfM4oKgub/tYhe
         m3Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UKh2r4FZ3u5ztf95p/55LFan7P0QN4l72/He+gOSfBU=;
        b=8GFhYzmZgMDbSVK0/GDm8ryXcPEplhuUWppfZNghUc5+Qcsu85WO0AxFH/bLuk+zAB
         Pg1H6IHgG2T1kZ4wp8ReSRImyQU3KIiAlPBeNAh8nCNzakQ0T4LMVev5bZ2w9+h1jr2r
         XTpPMQ947hlzbqSHzvks/QwMRlajZvzC6c2EJkXiKpTqS9eO8R3o28I2W0Y9afu8y0d4
         O0A7tWQARyPDcpgQL/1UrmHtdNqcS1lVQgb3UzRolc/Jjgx21eXV7bkO7RjfA5gqU6EV
         jh3X5YMvkzxy+OyH5TG0NqQt4OyG7CAg8CGsjIsXCfRmiLFcSlwaG++YdvWDTSdM5YUs
         cZVA==
X-Gm-Message-State: AOAM5337Ym5MFu2FC5sgroTeXdveGjfwioQNZyzB5d7YeHg4ShA8+p2V
	m0K+rSgqGftOlySO1mWnwnY=
X-Google-Smtp-Source: ABdhPJzLZbUQck9nkBM+tzjid/AaOTf7bkaK1GNsdTSegVBdWvseeQm0z0g+95Ynm64uJ2pmD0o55A==
X-Received: by 2002:ac2:48a4:0:b0:471:fc7f:b54d with SMTP id u4-20020ac248a4000000b00471fc7fb54dmr16935194lfg.538.1652787731756;
        Tue, 17 May 2022 04:42:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0e:b0:477:a45c:ee09 with SMTP id
 f14-20020a0565123b0e00b00477a45cee09ls1379575lfv.3.gmail; Tue, 17 May 2022
 04:42:10 -0700 (PDT)
X-Received: by 2002:a05:6512:2a8f:b0:477:b0ee:8a4e with SMTP id dt15-20020a0565122a8f00b00477b0ee8a4emr487991lfb.482.1652787730289;
        Tue, 17 May 2022 04:42:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652787730; cv=none;
        d=google.com; s=arc-20160816;
        b=pPSo5S5mt10AdsFPq7amW6zw+5rqf6Ol1shndJq7ACiikau/jHPgmcSbOs3Lqu8gYZ
         2gkU6rocwNSeOTgNNAyjk8oK8MUwenm4zWf+ID+jl9SWWAyn1PTrR++ZaUuJHbCs92Dt
         R+PKZEgZKNNHzdUV4bOCIiTctjVR5p1XguVOcVthkoXcmloVHr8w/mNV2jCg5t0/EVju
         Y+4zTHeFw4alVc8fhIYP4+gvWZw6T+prLwEWCLhWOg0rTt/zUU9yn9j+6hlekAEb/pN3
         C/ZeHP2ywI0Hh88nanHPnLPzGFA35x9eQCERsDuW1rBLPn8lLDqed6vIGXKo1/F2ihA+
         qR0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cHqZzZFU2KlkZ0e38q0rPqPRXApRGQ0ABOWC87CWLJw=;
        b=iNVTF1TNBkMBR7uQt860XuRu8goztO3rMvy/CjJvOE9ghQvHiEn5MROJnM/2BQU5tV
         9SEPyZygvDLPsGvEXPIfHCOKDH7D2PkUSnq/Z2iMXqYFB4ZvtbZ/qHjYpKhgzqoKXT+T
         iOZp4UwhyllADF5y1k629CzGYOr/UMhNb27fUeg4Sv1bOJ2DD/BJxQgybtaAH5iq5Gnm
         RQ1m+avffbDh9oZw45CtOyEZfC6OsLEMHsGNy7VDy+0Yx5R5y09Q0k/OwnnIk5jnOGMg
         DrFovuefWi9EWn3jKXCL9e0NPI8QAiztWqK9L5cfd9BEthKJlzFIlQxFKJ0IkRA4tvGX
         gOWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=IYeMCvyc;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id b22-20020a2ebc16000000b0024c7f087105si572101ljf.8.2022.05.17.04.42.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 May 2022 04:42:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id j24so9114388wrb.1
        for <kasan-dev@googlegroups.com>; Tue, 17 May 2022 04:42:10 -0700 (PDT)
X-Received: by 2002:a5d:5541:0:b0:20d:a89:ae21 with SMTP id g1-20020a5d5541000000b0020d0a89ae21mr7386448wrw.176.1652787729545;
        Tue, 17 May 2022 04:42:09 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:c38a:158c:29c:8a84])
        by smtp.gmail.com with ESMTPSA id 22-20020a05600c021600b003942a244ed1sm1633888wmi.22.2022.05.17.04.42.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 17 May 2022 04:42:08 -0700 (PDT)
Date: Tue, 17 May 2022 13:42:03 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jackie Liu <liu.yun@linux.dev>
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: Re: [PATCH] mm/kfence: print disabling or re-enabling message
Message-ID: <YoOKC8oE7fbsWsyS@elver.google.com>
References: <20220517111551.4077061-1-liu.yun@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220517111551.4077061-1-liu.yun@linux.dev>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=IYeMCvyc;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42a as
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

On Tue, May 17, 2022 at 07:15PM +0800, Jackie Liu wrote:
> From: Jackie Liu <liuyun01@kylinos.cn>
> 
> By printing information, we can friendly prompt the status change
> information of kfence by dmesg.
> 
> Signed-off-by: Jackie Liu <liuyun01@kylinos.cn>

Personally, I've never found this useful. If I want to get the current
accurate state of KFENCE enablement, I just look at
/sys/kernel/debug/kfence/stats.

Nevertheless, some comments below.

> ---
>  mm/kfence/core.c | 6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 11a954763be9..beb552089b67 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -67,8 +67,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
>  	if (ret < 0)
>  		return ret;
>  
> -	if (!num) /* Using 0 to indicate KFENCE is disabled. */
> +	if (!num) {
> +		/* Using 0 to indicate KFENCE is disabled. */
>  		WRITE_ONCE(kfence_enabled, false);
> +		pr_info("KFENCE is disabled.\n");

This will also print on boot if kfence.sample_interval=0 is passed. This
is ugly.

We also have a pr_fmt, and writing "KFENCE" again is ugly, too. And
adding '.' at the end of these short log lines is not something done
much in the kernel, and also ugly.

So what you want is this fixup:
 
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index beb552089b67..de5bcf2609fe 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -67,10 +67,11 @@ static int param_set_sample_interval(const char *val, const struct kernel_param
 	if (ret < 0)
 		return ret;
 
+	/* Using 0 to indicate KFENCE is disabled. */
 	if (!num) {
-		/* Using 0 to indicate KFENCE is disabled. */
+		if (READ_ONCE(kfence_enabled))
+			pr_info("disabled\n");
 		WRITE_ONCE(kfence_enabled, false);
-		pr_info("KFENCE is disabled.\n");
 	}
 
 	*((unsigned long *)kp->arg) = num;
@@ -877,7 +878,7 @@ static int kfence_enable_late(void)
 
 	WRITE_ONCE(kfence_enabled, true);
 	queue_delayed_work(system_unbound_wq, &kfence_timer, 0);
-	pr_info("KFENCE is re-enabled.\n");
+	pr_info("re-enabled\n");
 	return 0;
 }
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YoOKC8oE7fbsWsyS%40elver.google.com.
