Return-Path: <kasan-dev+bncBDSPNHNP2AORBZ7LQ2BQMGQES6DCAIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id D322D34CE84
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 13:11:36 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id g7sf5360924pll.11
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 04:11:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617016295; cv=pass;
        d=google.com; s=arc-20160816;
        b=o1HmmX7A3wlhFAQs8oNbCXpda5djVo55fxI70dBD6Toool48fCkrFX9eueLEI5MYJY
         DPkSMRpz+MhvDVCdGz+hzNYIVMRff+jr98BdYVoDFnBhP4UGnalU8n/R/YrBJWde00AH
         4Zr9UlYL3TYHF5ikGCFVtx5JcRYx4cIOazTSnlhnoliZX3A971J7PSQKX9HJBWj3sS+j
         zE6rgntAdKzxWGph9OGDgVYEtcKYn/qDPGfFM4tXghiH0aT6lUMNMiveVKrlIbNmMoBD
         bj13Ln6gY8BXs08CaDHKIy0zZJzhvQGL5K/aEIYWQdKKjqM4QFdKS+ka9AJNasNbMQwx
         rAgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:dlp-version
         :dlp-reaction:dlp-product:content-language:accept-language
         :in-reply-to:references:message-id:date:thread-index:thread-topic
         :subject:to:from:ironport-sdr:ironport-sdr:sender:dkim-signature;
        bh=WRyy5yebkGdEzx77RcBBozWMQYtjJfcbDq46nSYwX90=;
        b=sI8HefNSyJWYUj3rWowM1r1O7nTf3z8BjXqZfwXt5ebQjQeJhhtmUf9sHfLLbjXa3e
         FGeSyYfW5ZfZme1jwKgEpAmegifOKMfVLnFCyfV056PVpaJc5wP9EDyOoi4mb5Td/G7/
         FCOSEFKdTSVr7FijunlJj17vy9O+fMNtEWsZ8d7/+JIsOCYtvQFh2AD815E1VCpcrVb2
         J/R9kGERb1fBsAynJTEwnSdJQ+6Q/xXLrbZHubPeTNsz8uusxrBStL1F3hw2ayeoXrGd
         RtYR/izFUtZ9jr/yv1Mw9EL0yfNX/fLAz/1n7l//CiV94w+KZmVye0LYt3kVC6i636rA
         vp3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tomi.p.sarvela@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=tomi.p.sarvela@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:ironport-sdr:from:to:subject:thread-topic
         :thread-index:date:message-id:references:in-reply-to:accept-language
         :content-language:dlp-product:dlp-reaction:dlp-version:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRyy5yebkGdEzx77RcBBozWMQYtjJfcbDq46nSYwX90=;
        b=IMebHsn7+pXMqbA13EbrTLylM2mk83s+TfLvo2m51nvyq5JEYvLmP4R4BA/jw5ltjQ
         HTI5nNDjZTEQvABFABSpJxugahVwsJpeNsvDhgAgEWs7O3gk/Mr6tIFLgJdQFc56WMf4
         4IdW7CwZvPBzS+AJRqMCc5nH1lpm6prZH0RN7rsMFn2lfZKph9hW04xQP7NOhmRHQ2RU
         JYMS1sc48eFlo5TN4Fce8pGZk8nA2zxVHVvL61ewgimp/OU2Ks3tSuLspcob47YDVVIi
         jF9cq1epkPwF3se0xdiqUfP61ohG+IT6LU93NRs50jRusvbG8Co6raqgqKciPXsqaIaa
         JMkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:ironport-sdr:from:to:subject
         :thread-topic:thread-index:date:message-id:references:in-reply-to
         :accept-language:content-language:dlp-product:dlp-reaction
         :dlp-version:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WRyy5yebkGdEzx77RcBBozWMQYtjJfcbDq46nSYwX90=;
        b=DWPTxA6PZaM0UU5e3Kg5UB6wPhAb+Hfmpy+/jEa4Lr4ChgGM208Tbfe0+c2fW7lOKf
         vh1xJoqRrU2Q8qAB/IJ4BK0MA/GiYT5tq9XYZpsKbdPu5sc7F2Yofv+cj8UOZlR8JxN/
         NHtDhVetVInk1wsOglHQr6O8DyWT5u5nmbvONRNzRmYPoX9VgwKhrUp4A7KnJ2I3+fkZ
         KjIVKZJezN2aFllO9w/ko3bHtieXqro77Rq8+bwKUVbJkTfcSYwzEhmvEEEGDGAwJeQ+
         7mQZ5ZVgvSVqEMQcTYbvw7UyL/OmwwRJ8ehTWb1j2pcXtxts0dKEgHD/8PODixZuzPDL
         7tNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533PYflw6NNKZdvpHNAWjnAMjxg0NJK4MQBTVQr+pgJf5mNosDs+
	iFaNBknTjkU9ylb6LEWGKZo=
X-Google-Smtp-Source: ABdhPJzeeHwzlH1Ac4v9kLE4AAyfYoP4lEzRkZ+l7oCeJ/veaGga+8qqlrkQ5a6IXjPBzMiLVAcDYQ==
X-Received: by 2002:a17:90a:20c:: with SMTP id c12mr25563758pjc.224.1617016295323;
        Mon, 29 Mar 2021 04:11:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5f88:: with SMTP id t130ls2974895pgb.7.gmail; Mon, 29
 Mar 2021 04:11:34 -0700 (PDT)
X-Received: by 2002:a05:6a00:162c:b029:22b:4491:d63a with SMTP id e12-20020a056a00162cb029022b4491d63amr1254281pfc.28.1617016294641;
        Mon, 29 Mar 2021 04:11:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617016294; cv=none;
        d=google.com; s=arc-20160816;
        b=mcc0XgR+ydSDoYC5EktRpWmVefllxcc3GomcKykH0iNHahAbPwsFrOweIhdXWvn/ky
         YxyfA7RNEXyNhPqza3NGlna28nctLmSB7rreidX6yCx4dY0dX7Il00QZfVHPIrtNh0z3
         HvIYRpo19Vr1uD8Q4v29Cmz9QcqGays9z5r1XArQbttK//i9YCFNMneD8lRA/L8a0sxj
         8AGo+hwJ/sAyWyW9MEn99CgbkWg5wdNR+BW8BJLw+4Qn5S00IeV6XAEI1IF+wyDAazfR
         qpJVPsGNaHhE9xteNy6EzZFGfb8EkAy3P1IQwwQQZIKzs/3fFKzwAF+YTC4a3h1dARJJ
         lzUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:dlp-version:dlp-reaction
         :dlp-product:content-language:accept-language:in-reply-to:references
         :message-id:date:thread-index:thread-topic:subject:to:from
         :ironport-sdr:ironport-sdr;
        bh=/jFtTSwBJGcFsAAZ4c9ktV726lW7tiod+zJwLMV+5pU=;
        b=t/utrx0rII9fzWKEQ5Tr2EJfBCTcBOSfIxs5VwoFqxAh0U4Ir2b24oEw8t8xgflOf4
         uEcLvhL05kaVeGk6txBxpH2ass4nvMeUSsmYcpUgWsp1CbCWK0Ud5MC8UF87aA7uGWPo
         xIAd7wNObDoPr/yjWAyokVc0l0G81Cr5fdHMdNehs7OVw9AyEBk+zpgajvQ6TDEj9CAC
         Pls7nCF39eLSblC56cSKJPvkpuisJq+DiO7iA40a55MtqApHDq9q/xE0nQjvi4UaboNI
         krRuCExbsWF1qorjXWX9lwPy6W4CaIS6S1cGkg8CF02wzqErh5J5gOYoLQxQPBjA8VWO
         tDEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tomi.p.sarvela@intel.com designates 192.55.52.93 as permitted sender) smtp.mailfrom=tomi.p.sarvela@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga11.intel.com (mga11.intel.com. [192.55.52.93])
        by gmr-mx.google.com with ESMTPS id 145si892121pfb.0.2021.03.29.04.11.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Mar 2021 04:11:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of tomi.p.sarvela@intel.com designates 192.55.52.93 as permitted sender) client-ip=192.55.52.93;
IronPort-SDR: MlQTKcW6O82zcuFFZKC6jJhLwdZOVIGvhNY2WUQXHo+siVqGkCfoRRlfdmduFQHv9wsj5e0iQE
 Y4AhrMOMlj/g==
X-IronPort-AV: E=McAfee;i="6000,8403,9937"; a="188260210"
X-IronPort-AV: E=Sophos;i="5.81,287,1610438400"; 
   d="scan'208";a="188260210"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga102.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Mar 2021 04:11:33 -0700
IronPort-SDR: RRXnJ66ehj1dBrVWsl3w0XjdavaXRxJevZHXUgBDyLrTTN81FojZXdzaxDNEt+uyP6KpY7m+nL
 G2gPSwoPqapg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.81,287,1610438400"; 
   d="scan'208";a="411026403"
Received: from irsmsx605.ger.corp.intel.com ([163.33.146.138])
  by fmsmga008.fm.intel.com with ESMTP; 29 Mar 2021 04:11:33 -0700
Received: from irsmsx601.ger.corp.intel.com (163.33.146.7) by
 IRSMSX605.ger.corp.intel.com (163.33.146.138) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2106.2; Mon, 29 Mar 2021 12:11:30 +0100
Received: from irsmsx601.ger.corp.intel.com ([163.33.146.7]) by
 irsmsx601.ger.corp.intel.com ([163.33.146.7]) with mapi id 15.01.2106.013;
 Mon, 29 Mar 2021 12:11:30 +0100
From: "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: I915 CI-run with kfence enabled, issues found
Thread-Topic: I915 CI-run with kfence enabled, issues found
Thread-Index: Adckhav6PxBy9k/qTMmPKcbQ7bz5OQABgfQA
Date: Mon, 29 Mar 2021 11:11:30 +0000
Message-ID: <66f453a79f2541d4b05bcd933204f1c9@intel.com>
References: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com>
In-Reply-To: <d60bba0e6f354cbdbd0ae16314edeb9a@intel.com>
Accept-Language: en-US
Content-Language: en-US
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
dlp-product: dlpe-windows
dlp-reaction: no-action
dlp-version: 11.6.0.76
x-originating-ip: [163.33.253.164]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-Original-Sender: tomi.p.sarvela@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tomi.p.sarvela@intel.com designates 192.55.52.93 as
 permitted sender) smtp.mailfrom=tomi.p.sarvela@intel.com;       dmarc=pass
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

Hello,

I'm Tomi Sarvela, maintainer and original creator of linux i915-CI:
https://intel-gfx-ci.01.org/

I got a hint from Martin Peres about kfence functionality in kernel, and it looked
something we'd like to enable in future CI runs so I made a trial run on DRM-Tip.
We've had regular KASAN-enabled runs, so the expectation was that there
wouldn't be too many new problems exposed.

On this run two issues were found, where one is clearly kernel (GUC) issue,
but another looked a lot like kfence issue on old platforms. Affected
were IVB, SNB and ILK, with bug signature being:

<3> [31.556004] BUG: using smp_processor_id() in preemptible [00000000] code: ...
<4> [31.556070] caller is invalidate_user_asid+0x13/0x50

I'm not a kernel developer myself, so I can't make hard assertions
where the issue originates. In comparison to kernel without kfence,
it looks like the newly enabled code is the cause because the
"BUG: KFENCE" signature is missing from the trace

Can someone take a look at the traces and verify if the kfence issue
exists and is not related to the rest of the kernel? 

If there is an issue tracker, I can add this information there.

Example traces:
https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-ivb-3770/igt@gem_ctx_create@basic-files.html

https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-snb-2520m/igt@gem_ctx_create@basic-files.html

https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-ilk-650/igt@gem_exec_create@basic.html

Kfence-exposed possible GUC issue:
https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/fi-kbl-guc/igt@kms_addfb_basic@addfb25-modifier-no-flag.html

All results can be seen at:
https://intel-gfx-ci.01.org/tree/drm-tip/kfence_1/index.html

CI_DRM_9910 is recent DRM-Tip commit without -rc5 pulled in yet.
kfence_1 is same commit with kfence defaults turned on:

< # CONFIG_KFENCE is not set
---
> CONFIG_KFENCE=y
> CONFIG_KFENCE_STATIC_KEYS=y
> CONFIG_KFENCE_SAMPLE_INTERVAL=100
> CONFIG_KFENCE_NUM_OBJECTS=255
> CONFIG_KFENCE_STRESS_TEST_FAULTS=0

Best Regards,

Tomi Sarvela

--
Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66f453a79f2541d4b05bcd933204f1c9%40intel.com.
