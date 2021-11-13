Return-Path: <kasan-dev+bncBCSMHHGWUEMBBLVMXWGAMGQEAT2QCQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id E2C6244F1BB
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Nov 2021 07:07:43 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id jx2-20020a17090b46c200b001a62e9db321sf5587353pjb.7
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 22:07:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636783662; cv=pass;
        d=google.com; s=arc-20160816;
        b=n658kDpzAtK4bl7+Fuls8mzIXz2ipuhfYzghkOkcpkXpZnLMBLDC59VJNRTggZev+W
         PJ+zoKGE2jJjZ6fnBcpK2xrBqnOfnqByE6E4V9FkVr56FrT6nQrOKAtT2OD8dN2dmhHD
         5QqiIr+J9UCRZIgendhpAJd/Ss3JddL9UrNKwUxqm75kPptqf+7qMPlHz54B1Yzod1pW
         1dRjLckTDTESLkp73uVqfu9LjvVHKrhskCHvof6stGH+d6PQDJNEC6kllPcljJad0rJ1
         1t/FSSdLz20RE518RQdcxOeQnWxtlRt330lNr8w0yUTLKk1uAj4kLmFYg/9v8kbvsToV
         pVuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=lYYHH98VeEb4Gg/YyUr0rp98Vn45Qkcn76nHcBtiwa0=;
        b=pUgkjURIBhwtiFvX3muKJtscpOESCSP3M5p3fZV/Vp0JW/KuFjo1nlQoI3g1ZxRnEd
         fI/UbewZjkU/AUujp+2ir5BSa3/mlsOw+hyiPGHF2Z34LdyCMPDdEJAbEmeXO5KQvr08
         WgKdWFyaDIwz3euShI7u6dCpxPYgUvqh8k31fKurc33bsjhHL2IGhCq019a0XmMUPW2f
         ZRIsk7Wl0q7wwh5AkNc0QF156rGd/9OYnpQ2YspmZi8z0pw8W34WV9ieX3l1TmZeuMs2
         Rv1Wzyhlp/ki6CESkhQLAoItRRrAyEhbQ8oCO6T9VbdFAxdl6clMVXbIJ+dUd+EabwO9
         EyMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=P1uCqc0l;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lYYHH98VeEb4Gg/YyUr0rp98Vn45Qkcn76nHcBtiwa0=;
        b=ohqnH9FYL/taE3R2PJGHvz6qfyy7/AHpq0rwutGvieJP3KTjJheumFEqJrPqAh+zba
         OF1EQQVImjeXAkxA7o4k3yzVelMTxPqEmz3n0pqZEZmYHcOLUTFri18CLl8sFXlE1tHx
         R+X+S6/0hctm5zugVlMtzBSSWuiaLg2orTaMLOeG2Infb1Vhiq5DfDfbjIyrFi7j2Mt5
         b6iG6Y9at56i/UfR4P3yreMMl0v0C9hfPj7ze49p08owj5PgVaoOuiQt2bOSv+ngQQT4
         Reay/4pKrA6Fyt2KdF4qj6phY09meB7EOb3OfgtLCEYVbt0ph/wSGSdl9yS3GG4dcU/H
         U/fA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lYYHH98VeEb4Gg/YyUr0rp98Vn45Qkcn76nHcBtiwa0=;
        b=c+usroyLK8B2o/0klJeRvyC2iHdmJmLpKnUdbrEr3ldBZ3X/Qw/s3frzTgdCHTNibi
         bfU1esLKJ5PW/NoQz1x4I+Iswkd14Yf4IuXLaYjNtaZyufJK+nPuGv0rvPUWcCdHfFR8
         k5iGZmzvU2v+o4F2uKCjD/xx6K3wkoeeW7PC4AZyd20QWq6+veXddWANdh/le8/h8s2S
         hHbmTNBf4+KzcXCdvtM2QgR8XPlt8fZ9KIznUjo4xSEGydgRXG2CzlV61R9+I1z//SH9
         FPd2QYFG09tjHCIeIe8IATxaiLwqqzbpZvKw6EnBo/qPuerR74rns0bpU3FrGT4da9p5
         yOGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532s5c/0EY2zQU/IsirQklg0ygUz0R0KF814eWVuKEaN83LaQXjn
	F5E0kUb/6TihYXbyOabnoGg=
X-Google-Smtp-Source: ABdhPJz2CIaGiBiuIn6sKDXB08tW+tu2ptqY3pRM+SJRz2mYl211vqUKpOT2RkCOmcX2jOGNVIEACA==
X-Received: by 2002:a17:90a:8043:: with SMTP id e3mr26800489pjw.130.1636783662686;
        Fri, 12 Nov 2021 22:07:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:6002:: with SMTP id y2ls4399679pji.1.gmail; Fri, 12
 Nov 2021 22:07:42 -0800 (PST)
X-Received: by 2002:a17:90b:1b4a:: with SMTP id nv10mr24940469pjb.87.1636783662060;
        Fri, 12 Nov 2021 22:07:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636783662; cv=none;
        d=google.com; s=arc-20160816;
        b=FJQ0P8l+Zre/pYGkHx2i16LTH4k6EvocfA+4J0Wq+otmsFOrDmWwti7dl7DEHUiiaV
         /uxSEVwjaFKoHvoXjTezWTPRDGEXwdwP8piZ+EWreAmTzWo8oW9xuHVkONFfDdL3cJNd
         x2rfXMm18hcv+KLav/+xnBhjUptquu+3hZ623OKinAocNCZey9Dq7dVQsqUv/cp9f40L
         IPI9nsZZMBFQnwA/Qtu2c2x+2EEIYAauCC+Hlu+HuzlwV9jfknXGwvdmC59sCpWVb9IC
         htQ46kkKGshfd1YC6lcUJDVq9CmgSB7gmzzvbkACl3Jyp63F3qTuzLpJOP86eTLho+kc
         L8YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Pp8JfTGNCrtvO19aZcBYoe2ILjUc/Tzny+fyjlfwUzE=;
        b=Ci+bDshVIItongUy9B0KH3O6w+6qAqUGT/qerdWA+hCuPwAKqhmqIQ4dBj2+vXkqgo
         SdGyr/oEMi/dVhiMt94/gdSpGwiZGIUD/mJBClYYFZQX8R7TwiRzwkNEGQDymAEbdpy6
         PY+3lrARQZ6JlTwjJ4zLz/lVHlAmeGfGHSv8nKtIONck72KcjOOipnP6uVJNf9RSBqKr
         qLqtqudXV/osiaFdmXCCc8FdNQRme5dnRZW6s3lePFf6oc7wQgkr68mh4nghDc88Qn9D
         KIRTjaz6gROGseGu4mRCGV15n6QPXXHT57yKw4GSDuoXf9oULLVJWxqoGueXAf1lRg/j
         Drbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcdkim header.b=P1uCqc0l;
       spf=pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
Received: from alexa-out-sd-02.qualcomm.com (alexa-out-sd-02.qualcomm.com. [199.106.114.39])
        by gmr-mx.google.com with ESMTPS id w9si605478plq.0.2021.11.12.22.07.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 12 Nov 2021 22:07:42 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as permitted sender) client-ip=199.106.114.39;
Received: from unknown (HELO ironmsg-SD-alpha.qualcomm.com) ([10.53.140.30])
  by alexa-out-sd-02.qualcomm.com with ESMTP; 12 Nov 2021 22:07:41 -0800
X-QCInternal: smtphost
Received: from nasanex01c.na.qualcomm.com ([10.47.97.222])
  by ironmsg-SD-alpha.qualcomm.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Nov 2021 22:07:41 -0800
Received: from nalasex01a.na.qualcomm.com (10.47.209.196) by
 nasanex01c.na.qualcomm.com (10.47.97.222) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Fri, 12 Nov 2021 22:07:40 -0800
Received: from qian-HP-Z2-SFF-G5-Workstation (10.80.80.8) by
 nalasex01a.na.qualcomm.com (10.47.209.196) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.922.19; Fri, 12 Nov 2021 22:07:39 -0800
Date: Sat, 13 Nov 2021 01:07:37 -0500
From: Qian Cai <quic_qiancai@quicinc.com>
To: Will Deacon <will@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>,
	Mark Rutland <mark.rutland@arm.com>
CC: <linux-arm-kernel@lists.infradead.org>, Dmitry Vyukov
	<dvyukov@google.com>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Valentin Schneider <valentin.schneider@arm.com>
Subject: Re: KASAN + CPU soft-hotplug = stack-out-of-bounds at
 cpuinfo_store_cpu
Message-ID: <YY9WKU/cnQI4xqNE@qian-HP-Z2-SFF-G5-Workstation>
References: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nalasex01a.na.qualcomm.com (10.47.209.196)
X-Original-Sender: quic_qiancai@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcdkim header.b=P1uCqc0l;       spf=pass
 (google.com: domain of quic_qiancai@quicinc.com designates 199.106.114.39 as
 permitted sender) smtp.mailfrom=quic_qiancai@quicinc.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=quicinc.com
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

On Fri, Nov 12, 2021 at 11:50:19PM -0500, Qian Cai wrote:
> FYI, running CPU soft-hotplug with KASAN on arm64 defconfig will
> always trigger a stack-out-of-bounds below.

Actually, KASAN is not enough to trigger. It needs some addition
debugging options to reproduce. I'll narrow it down later. Anyway,
this one will reproduce.

http://lsbug.org/tmp/config-bad-14rc1.txt

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YY9WKU/cnQI4xqNE%40qian-HP-Z2-SFF-G5-Workstation.
