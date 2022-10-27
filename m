Return-Path: <kasan-dev+bncBD22BAF5REGBB6575KNAMGQEGAYZJAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id A705A60FB90
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 17:13:00 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id k21-20020a2e9215000000b00276ff516fa3sf841771ljg.8
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 08:13:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666883580; cv=pass;
        d=google.com; s=arc-20160816;
        b=LYMXFtF1OnkFVYgdcCUcmkIPUrgzjv1scutNzVUr3QqZVIrk/DMfxE6olW6bN7J25T
         YmaSu8E9AdIZbJkqA1UB0Pd4k0B38aE33nkuJBMl6wmlpJ0DNuU7wh6eoRHCZzey0+su
         DMP46ulAP+M/8oy1M2p283vGV6E1AxVgMV3Pgsfkb+MAg280tAkc9mCS/uYAaaMbhyA/
         z4MaKZlnqOShXRimSe4ipmxEOPdfDSZ0H/MpIvUKiCfYpVoKfkSiyF8Qu0w8v93xaMHF
         gtQK/1XrqzRIz/Esv/zPcyoXJ63Npma/9krVvqVXhjHSkkP0RGVyIJI/n91w2qj5WEID
         LUSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7CJKHgz7Ukb2Jztk85f66pBaqh4eHgpaR8ZvWktYCGY=;
        b=bxz28uEnd6UmziAr584xnuCthmYdzuCSbtXs4rUSYVwGsWkBSI+CtL2s0kTd6f76DT
         buSgm7sNC5JtbkggmB2dKN7Lb+mHMVILygb6Jpwtw3x7VqCsyZUo9QLTC6LYNH7abqn9
         wZ8AnuIC4I8rU89vTPliPgumU9AX4xtcGS8qX6Nh6b4t8Q96AHa+3c1XOq6lxJQ8Pdn6
         3GssjnHx5w6mWAVVFJ/EGs4eF1xlZ6AqDFbD0HzpdnNrPqdpF0JOCwLDzHfneK8hZxcV
         3HhrbWAc2qJ+feVMHH6eHxa4VwwMQzBGqxtRpCtK4wk7N0ttxguoNwsfZEqzY4/X1iDn
         KStg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NckikG1c;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7CJKHgz7Ukb2Jztk85f66pBaqh4eHgpaR8ZvWktYCGY=;
        b=KtGP4FD9JySpwEPlLHsgWrzxDSpcZqXChas0NDE0dD5U08Sfj6JiZ/5JZMYQAn0hBP
         T2RMvZuR50dRytSgjcEqE9vM4R3NIzYeG2SI4vnbfYrE6oSxy2yAHHSrUA9+14vuv2mq
         hfhiu7HXQEBSrS2h5zxqSiTJCypGr5AaiB+l1KO+0SkcDlVn5xFbSKwrw6bgzgg08Ao4
         1tgbIFoDb9soBe89LHRi93laKWKyeKYvCAlDf/clc594n0n/yStgBTvKyDgNjy95s6Lq
         zs8XYRYpKiAD3XLoNFGqtUuAikzcbaaODzS95EjK3L3K+cGkfHTMs+KD7b2lLmox2HAQ
         e9cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7CJKHgz7Ukb2Jztk85f66pBaqh4eHgpaR8ZvWktYCGY=;
        b=qYRhH69ptvUhwDCYtvfVvISjy7plaEjlTIz6kpP83DgJpFkIBUSx2xeoDy83ND3Gva
         AB+NzBJQsCC2BovT99XBPyGyduKkEe9y7iNkrrwJz2iE3XA3w53RKI/y7f1Ajb+5Yx1S
         /Bh0jBkF4SCyKqHrFgajYvqDCl2Q0wOakqtQpsaCE7Xk2gIL0RPOE9vKwtHDREjavuP8
         dVCQx6PCsrqaW6HygLtKF/KOt+gg3XnhZY6HgZEOCWe9Oio/FdUlQv3eP3D4JHWxIbr0
         6in3h1qURg0xkWlA6+1SlDQzL+ksMHWhFVM4YoD2MDRsSzCbsW0VB06eY2xh8xUfu5DG
         iePA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf08+jawV8Gf1cmJQD0b6cz4JFa65Zf7Bk865S9keJj5ZhGAyHFL
	9+FhpqntA4o36xDaKKDxv98=
X-Google-Smtp-Source: AMsMyM6On3PqFkkZvBMeaiCaXQ6Bxwvy0+cRFMvhDuoZjD/pMqUQQV9xgES1k3a0uTL+WxsmA/1wAw==
X-Received: by 2002:a05:6512:158c:b0:4a2:5cf6:5338 with SMTP id bp12-20020a056512158c00b004a25cf65338mr18385119lfb.81.1666883579856;
        Thu, 27 Oct 2022 08:12:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1186:b0:4a2:3951:eac8 with SMTP id
 g6-20020a056512118600b004a23951eac8ls482173lfr.0.-pod-prod-gmail; Thu, 27 Oct
 2022 08:12:58 -0700 (PDT)
X-Received: by 2002:a17:906:ee89:b0:73d:70c5:1a4e with SMTP id wt9-20020a170906ee8900b0073d70c51a4emr40836645ejb.683.1666883557684;
        Thu, 27 Oct 2022 08:12:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666883557; cv=none;
        d=google.com; s=arc-20160816;
        b=AqA1A6qw3G4coimAntE9nbcT882i5jsFvxjmdt+tu+HtAQioRN3GA8fTMx01NMSsT4
         hGTs3pw/ALo85x6stEjJuBs0iRAHdkQRzA9x0snTx4tzk0XwE/x6DYz2tBtcAJU5slr4
         ovhj7jLRSYyNMITB9xekwE7IcJfz484018jYR1ahfTqnewCznHnPCSrkdInI6EI3PkuU
         uMtAY6vSmfCngIN2bJYyFAbMmGu2s5aaIwFX9w4Vv5B4N4e5HzmS29BDxflyde4DEaRG
         j3NZHSoBesEWIvAxAMYjg7t8nNvz+QcwuBZqpkawxM2PK31+qwdvYq3CT4KzzOO4BQH2
         Xavw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=8KqoQPH6jkmmjc7GjwlfjtgdmvVkZdS0waBZsIzGd7M=;
        b=tY5G5ijCdSfsJdw2rNYwqSY5xwAwf06fFHJbYNYgksVdNQp0/aCqjgPofa4BBV9tPn
         Lvhw2xEaIMR7DnbAF0/Ku3FQW69RqfQF5lqx07Y61TcrNDj5S2wiw6Axiv0zsvGo1eCG
         6I7cL50FQ3P2B08+VWvf5idK/Cah3h5dkaE2perZWxMFW9RUEVXsnKzY0S2oz4gAeyA7
         LRfQOZIMyNvxPSYbprhVhVqOgpRap0ZNnTdzyrMwfBHqCKndP5XiIgfAeCLRUUmC3Ij0
         DGcyUlnFigv/a5S7LurWY6Nrh7wAEoX5vAcWdNz78CDDYSxMXUkF7Haft+h9vcMjSnZO
         OASA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=NckikG1c;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id a16-20020aa7cf10000000b00461ad0b1dc0si60243edy.3.2022.10.27.08.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Oct 2022 08:12:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10513"; a="309945963"
X-IronPort-AV: E=Sophos;i="5.95,218,1661842800"; 
   d="scan'208";a="309945963"
Received: from fmsmga004.fm.intel.com ([10.253.24.48])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Oct 2022 08:12:30 -0700
X-IronPort-AV: E=McAfee;i="6500,9779,10513"; a="701378321"
X-IronPort-AV: E=Sophos;i="5.95,218,1661842800"; 
   d="scan'208";a="701378321"
Received: from vstelter-mobl.amr.corp.intel.com (HELO [10.212.214.108]) ([10.212.214.108])
  by fmsmga004-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 27 Oct 2022 08:12:28 -0700
Message-ID: <864b4fbe-4462-9962-7afd-9140d5165cdb@intel.com>
Date: Thu, 27 Oct 2022 08:12:26 -0700
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: [tip:x86/mm] [x86/mm] 1248fb6a82:
 Kernel_panic-not_syncing:kasan_populate_pmd:Failed_to_allocate_page
Content-Language: en-US
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Peter Zijlstra <peterz@infradead.org>,
 kernel test robot <yujie.liu@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Seth Jenkins <sethjenkins@google.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel@vger.kernel.org, x86@kernel.org,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 "Yin, Fengwei" <fengwei.yin@intel.com>
References: <202210241508.2e203c3d-yujie.liu@intel.com>
 <Y1e7kgKweck6S954@hirez.programming.kicks-ass.net>
 <278cc353-6289-19e8-f7a9-0acd70bc8e11@gmail.com>
From: Dave Hansen <dave.hansen@intel.com>
In-Reply-To: <278cc353-6289-19e8-f7a9-0acd70bc8e11@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=NckikG1c;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 134.134.136.65 as
 permitted sender) smtp.mailfrom=dave.hansen@intel.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On 10/25/22 08:39, Andrey Ryabinin wrote:
> KASAN tries to allocate shadow memory for the whole cpu entry area.
> The size is CPU_ENTRY_AREA_MAP_SIZE/8 and this is obviously fails after your patch.
> The fix this might be something like this:
> 
> ---
>  arch/x86/include/asm/kasan.h |  2 ++
>  arch/x86/mm/cpu_entry_area.c |  3 +++
>  arch/x86/mm/kasan_init_64.c  | 16 +++++++++++++---
>  3 files changed, 18 insertions(+), 3 deletions(-)

Andrey, if you have a minute, could you send this as a real patch, with
a SoB?

Alternatively, do you have any issues if we add your SoB and apply it?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/864b4fbe-4462-9962-7afd-9140d5165cdb%40intel.com.
