Return-Path: <kasan-dev+bncBD22BAF5REGBBSEIQTAAMGQESNTNZCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id DCAF3A91E2F
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 15:38:17 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4767bab171dsf7572491cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Apr 2025 06:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744897096; cv=pass;
        d=google.com; s=arc-20240605;
        b=Btor4Lj6jVrrDv0fXzyYTRo0Dp+Te/iodBDIIl1BF5wIF8ChuTgGUMGn+Es37rnU5R
         xnsFyQq0y0er9pVVeI1sq8YTcn4o4g60muk3BkJnubXsSPNgFGaeZ42jh7fHk2s21OpN
         uVoDcgBC1plMUtFcADywAAknADqSFSN2o4Tx45+94BaWZajlO/XSvjdzrogDQEXIty9s
         jiOHRLyTynXdY44tOnwDFFSoDRz1PTARBLCYKsdk7RkVYoCPSsG0k3Yq9gEeAEW7GLHy
         odgSNHtn0dT5KHHMpbCGkAHYxx+kFEcw6zFlI2xlHSAQ/4Omq/zZ1Zq25B5YZy+9jKkf
         pCEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt
         :content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:sender:dkim-signature;
        bh=B+c3N9pbNIEWDzDacYEOh+++JHlny/p/BH+jIDZR8HM=;
        fh=SO0ApOmyB3WXrjViXujLngkSSsMuvAeqWj0PEB4G5Po=;
        b=KHsCd1FOqh1BOpBdMjKh/KLItKrli+zWrob/tlQ3AUOZK9LP2S9pf2eBTT7i1/ACmJ
         jOZOVPWNRq47QYdORdwF8WhQOft3A6qH0XyLlS6cXhCCm+YDpihTsK2nDVCJA5tWDt+2
         ArReeIFpvQCe278kCcyAcmPhtgm9nT0p6dq3cPaI9fjF9qodffGS9auvC9wbNBb1C+dg
         w/SVUCfaUIo7drQNlFBjlTpOH0DVxny58t7tZBbarigGccb00CgACLaGnoPSZ+tCwL9O
         6wrZ2SUvYtJH8s0k13lc89pA/L5XlK+T3u1D7acsucrzhRd7CnqkeGTzK8o+BGFCCzUw
         0s0A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=c+R6HWFH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744897096; x=1745501896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=B+c3N9pbNIEWDzDacYEOh+++JHlny/p/BH+jIDZR8HM=;
        b=cLMJXN+dUTizFmbYEA9v0b/kQmVRzXy6Vn0PhqWeBuKk85PQRvu2eGnUU4Gr4Sx9xk
         38ykyzor5sHaiEScDNf7mqCBMwuJwrMjaTG+teUijU4fnXWc9lii+9NfqtcvEzsUrCXM
         nXQNGwj4WS9FFKC/9rGGl5gdzcBJx7SWl21oSBsOehzjcEQjK7+978hByfq7scpdbaxy
         lO+hqZ2+X2DyqmnbWi5ZG70BF4cPzn7l0QaJJVjRgQLWCsEsXUh0GT6L3tMJqHfDB0j1
         DYBAYHc12IfjZW69Fa1EH79y41lSpkanhEfCYQ5oDiN/y2HmMsIPj00OClYddDf8t5q3
         YFAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744897096; x=1745501896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:content-language:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=B+c3N9pbNIEWDzDacYEOh+++JHlny/p/BH+jIDZR8HM=;
        b=cix8Mwnd4aqy14rHuLHoQYMWy2MoDtFDtnrNCFP1jzObkwVb4DkW6BWQHD+GWbMgta
         8S9ondu0Li8G8LtUK71T+Mx3Af9eFVJl2Z0RU5CT5h2rG1lEPargJZE+pmKuXLw3E/4Z
         S+iRQLv44IqwMhnh7er60O6gaJL9vxxboVzp2O+d2ex++oVpGj6//xuvsR4FoGPNrWSR
         vscTUO9VhFUrIsbvG2vtuUMq90BTTX9OL2d/6uRnDMWnF8m4sdhCPUXrKu8S8de6eYOO
         k0xQbvHlvF5csQc9ATJ3c4d2GpEDu/HLbr9yYENzQqTgVXHlK16s8YNez5Y1bSs0WgGL
         eiBQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9JCPOT/ML1JAR2uCrTMmHqHfU0HLATIVapwdZ5ROC/o4PrxKnDImQgKy3Mtw7addr3Ri7oA==@lfdr.de
X-Gm-Message-State: AOJu0YzKOyFncLqmmRHuMFwV2sfJ14pWIibXs+OQWv1w1m52R+RlAN2Z
	uvFHYKUZFoZAFQEJEeBtnKRFqVw9uW59PhgkqT12K+YmTSBdUymw
X-Google-Smtp-Source: AGHT+IGwNnMOI/Wsd0uqrZ1rFn4Jj1ayClWzYoFtI1G0XOZebapoOKO6mDhaw32YBNFpteBtBusTMQ==
X-Received: by 2002:ac8:7d86:0:b0:477:6fdd:c429 with SMTP id d75a77b69052e-47ad80980bcmr66454341cf.10.1744897096649;
        Thu, 17 Apr 2025 06:38:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJfuBBg7VfxBUbRzfNqQC/V5CPj56Ud6ch3hg5CV13JJw==
Received: by 2002:ac8:4818:0:b0:476:8077:3350 with SMTP id d75a77b69052e-47addd0e131ls10722541cf.2.-pod-prod-08-us;
 Thu, 17 Apr 2025 06:38:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXVzs2jCCFLTBeCZE4YHjJOoQklTSPdSfhW8m+QEN62u2q2u08OqS3RnbvqaluHN+KaswUP3WjwEPs=@googlegroups.com
X-Received: by 2002:ac8:59c4:0:b0:477:5d12:aa4d with SMTP id d75a77b69052e-47ad8129180mr97183261cf.39.1744897095738;
        Thu, 17 Apr 2025 06:38:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744897095; cv=none;
        d=google.com; s=arc-20240605;
        b=fPcpaLqjiHDaW0B7JhFHycvbt2yMZED6YIE1weMT9BffRNjj0ysZBEaz85tiK/Cw6o
         HhLCpGfcxWwt8nGQ/dI7lYSAoGK5dJ2snELbp6X5ESxeNZYGxITIxB5qMnLZYUMSq61N
         HbicDA/X3/s5V4lgQUj4tuM5Vgdcv1LWGNgvGSEpk1oobA/vWoyNZ4FOiWaT9mf0/iaK
         aDCv07wAeNRGUWYlUxXsTdg10PqJXKOI3PPkiXJFGYrXVv8xRvomQmROaDpM6v45FK3G
         TWhMrLPP5P+BJT/OhwrIDp5o4r8FDL5nvGpHr2ogUHb3SkNx99sAGTirwyx0rqk3LeA7
         TDXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:content-language
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=MrSwCFJpJV15nc/PvqHtSlkeqidskWY135XBeACnaq0=;
        fh=6yi5SdlfBMwgnPQ4Fs4jGeAAqRzh2vPXw99a1Raqwqk=;
        b=ZBpow11h/Qvw/nvZdO2jounHXAwbXsjL3ai8+Hu5M9Kap5M3Ufte/5WM2JS3hnyENM
         aIwg2CAfPgGv3xfYcYxmUN3zrm6ejofR7koOb0sEdyeGtDAsXKlorPej60DZGeuxcg/F
         ViBLdgUzL3qdFJLb8nljMonoBSfD9oRigqVHc1l8kO/eejEIKDiPH8AvS8VT1Qqv9dSy
         3rh4EWUvQzD8CR3iJjB0PzN49f/sKRD3krRmv0Ts0Gw7fB2yn025bDQ5eTcmIurX2lps
         sexJlRAnf9T0rSszIjcwnQaXMLmZlw1YGWDO/HwojUGazHr0NHWgWWfhT87vVriAWAFE
         e3Dw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=c+R6HWFH;
       spf=pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) smtp.mailfrom=dave.hansen@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.18])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4796ed86ad7si700561cf.5.2025.04.17.06.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 17 Apr 2025 06:38:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as permitted sender) client-ip=198.175.65.18;
X-CSE-ConnectionGUID: v8+FP2btRPGvlz5pSwauuQ==
X-CSE-MsgGUID: jPKFqg1PQhakk+/wM4Umng==
X-IronPort-AV: E=McAfee;i="6700,10204,11405"; a="46612584"
X-IronPort-AV: E=Sophos;i="6.15,219,1739865600"; 
   d="scan'208";a="46612584"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa110.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Apr 2025 06:38:15 -0700
X-CSE-ConnectionGUID: baR2Ov3SSwebyhDro9zGIQ==
X-CSE-MsgGUID: Vq9A87d6S3ymHTZmjv16Xw==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,219,1739865600"; 
   d="scan'208";a="131341801"
Received: from tfalcon-desk.amr.corp.intel.com (HELO [10.124.223.103]) ([10.124.223.103])
  by orviesa007-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 17 Apr 2025 06:38:14 -0700
Message-ID: <e408cae6-0c40-44e6-b66e-53dbd6a2d854@intel.com>
Date: Thu, 17 Apr 2025 06:38:12 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v4] x86: Disable image size check for test builds
To: Guenter Roeck <linux@roeck-us.net>, x86@kernel.org
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, "H . Peter Anvin" <hpa@zytor.com>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
 Linus Torvalds <torvalds@linux-foundation.org>
References: <20250417123627.2223800-1-linux@roeck-us.net>
From: Dave Hansen <dave.hansen@intel.com>
Content-Language: en-US
Autocrypt: addr=dave.hansen@intel.com; keydata=
 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
In-Reply-To: <20250417123627.2223800-1-linux@roeck-us.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dave.hansen@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=c+R6HWFH;       spf=pass
 (google.com: domain of dave.hansen@intel.com designates 198.175.65.18 as
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

On 4/17/25 05:36, Guenter Roeck wrote:
> Solve the build problem by disabling the image size check for test
> builds.

What _actually_ breaks when this assertion is in play? I assume upon
decompression that the kernel image overflows into the fixmap area and
then the fun begins.

Does anything useful come out of the kernel or is it just a fabulous crash?

Because COMPILE_TEST sounds pretty benign:

>           If you are a developer and want to build everything available, say Y
>           here. If you are a user/distributor, say N here to exclude useless
>           drivers to be distributed.

at the *LEAST* if we are going to go down this road, can we make the
help text more scary and tell users that they might end up with an
unbootable kernel?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e408cae6-0c40-44e6-b66e-53dbd6a2d854%40intel.com.
