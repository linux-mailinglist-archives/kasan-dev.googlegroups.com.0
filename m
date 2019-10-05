Return-Path: <kasan-dev+bncBC5NVH6TWYJRBP6V37WAKGQEGP22HLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id ECD25CC710
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Oct 2019 02:58:40 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id z13sf5953289pfr.15
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 17:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570237119; cv=pass;
        d=google.com; s=arc-20160816;
        b=x077Pu8HZgPa57lejabbHezgwFBt6b20jSyW1ZVq6QbZz3c1yfnxfz61kf33taZ1Sl
         GBuMh26Qr0zsresrD4ywYyak3BLteFSjHzh9BX0OVnStjuIGAQLQF64bxRIlN3V5/F3p
         HcmQFMzhBCmpnKkXHuW63rG4nTbfoREPNxck98IKPgqPWQZwpu4ENjg0dCrAykprqd3w
         CVoCjT2NmsuznKQAyuzKc2qJ9fuGJCBPRnXrW9dRwPfkrXq71L0dsh/W1nbLLvA/ODpH
         EIvV9sveWxlErGlzNa9MEzbkEQ7clkqUeqO45pgtlvIE8deSKNtLzl1/xuCTlQfQ0a6N
         EmlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature:dkim-signature;
        bh=2Qt7vkcxU/Nl4HB+TfmzfmsInqMPC6JBknA0Vv7VMRM=;
        b=pun2XUbt/G2fgGlClmTQS0l8XcUtgPyOZhloX8B65VhheoCX6MXM4D6OnG80MYtVKJ
         ZakNWyo+akb4o4i14VZ97timtdZPZ7RE/SUwt5xn+tDCK6CZXcw7drT0YPc5ANXIeYLx
         ewqu5PtkvbWlspfnwRpM0Ee5anJGCxBGn5SKMIGrAGj5rAV+IUbiH6c6MtZqlRM6hgEJ
         DH/CUEnkAoYp8ycdMChSIyZC/gjL5k7lxwr8lAzVt8HHIH/YolJZtLNXngiE6CF/KpAn
         7R2V6vZkBA6PWbHgvXiVG4gffqAQOwCn4dmwTxSGZf0C9Od9znFQxgWhze42Obo/KXuh
         F3pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=S4Xe3j5U;
       spf=pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Qt7vkcxU/Nl4HB+TfmzfmsInqMPC6JBknA0Vv7VMRM=;
        b=pUzt0cn+3q8VPOy1Co6teBijebTZG19lPjdT0KK8OPQueW+kVzsq/g0KnN7rdMLGxy
         J2Ggx3z+L0HA4WBz4leQzRmRF/3pmd3gYP48i3ogUIppOjyZkV6LY7uqSw2B1g3LCpEc
         /4YVqqxfpzZFmbCZmWqYZAmFcP/VPTocl3Aqz+NM5oujPxV5S8vaZBHlkLBdJJGfJ4hp
         azQiRq53WfNL4buNH5Jg6ng8D8J2EadDHThAepeohF8PbJK7UPKvRez2nyvccrjyvyZJ
         Q5C/5ZpOYDMoeR4c6J8artKikESyVkAyXGwOP9Tf1NN0+AH18OC2URPZTAN/0j/3Zxan
         2OeA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2Qt7vkcxU/Nl4HB+TfmzfmsInqMPC6JBknA0Vv7VMRM=;
        b=YxsdHop8d7jWylbxRi3pWvXxyar2l78Ln/MQDXGAHozbKj2eqJLjFz2fomakPa34jo
         wBCCqoR3vbRGaUSe/6nZ4SidUE/2+i8Zjy9ym6WThimrcIBw4ROrGIPuzgNMjeRxXHvt
         j7qO95RkzfWwkvnl92mw5AhBMQ5XTlrtmuzkrL5204/YReMgPypMcVH8WYJz0Nox2UpU
         gOz2t1tO2SlCTrnhVjUMLMsBR4QTVOjaf0hehsmfagDC/QSXf1iA11+OmQf6ozp4xrT1
         b3BbwhoneYPg0EIKQwVV4N0xz44szWMlpvIyDCSAdiqpnBStkagtQ6MSkm1BkdbJAewJ
         YA4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=2Qt7vkcxU/Nl4HB+TfmzfmsInqMPC6JBknA0Vv7VMRM=;
        b=I9p4qXUyxKwUQpJKPDeDGkrvtUVnisa5Y+86TzMdwoqn1Tq/1/gbaVduWKgaZPJfuk
         IpcVCGMvTxK/cVdOUDKc+5zXGdiQTY4NSLwPDYaUF0KjQifelKAA8gPPWdLwWpDgml2R
         /LAOIi+68IzF260guizDUZR2hxua2v9+DMbsJUf5cmp1CIK1TK4UZR3CPWFqHzkCSpKd
         jMQqjVB71sGpHYQgHXfeQKruFI+B86CXJlnl40DvYfaZ5IA56hnv2FhbkqQzE4lBWu+K
         f6TbA6NIfXFTiH3LHzkxDySi2JvmyrZlXlIBoOWpUbaz6xQ5mxvPpFXho/O98WS9qMyj
         g7jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVv74iBbVtOdsuU/zEx0MrQrvR1QYp3EkPnQ/Q7ve0EPJPTIHEz
	ay9v3VTBco7xrddE6Ka+v74=
X-Google-Smtp-Source: APXvYqzIEQRSqUXT0uM/Ev5pNbnK0MB0CG5Aeaw6/e7lPcvhQS9kfcXER4uD0nBrpqqt/D+ZhqFPHw==
X-Received: by 2002:a17:90a:a404:: with SMTP id y4mr20276475pjp.62.1570237119433;
        Fri, 04 Oct 2019 17:58:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:5107:: with SMTP id f7ls2810778pfb.2.gmail; Fri, 04 Oct
 2019 17:58:39 -0700 (PDT)
X-Received: by 2002:a62:1e82:: with SMTP id e124mr20325449pfe.136.1570237118980;
        Fri, 04 Oct 2019 17:58:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570237118; cv=none;
        d=google.com; s=arc-20160816;
        b=saAYQFrbB1D/3LiKFWdS6OuBaDy3DURH35sAwKW+9Q5SvdS2Fto9imz0KRyFpIY3dO
         kYh4lQC0xPiWL3n2OjKySkgfl7vDtDFl5J/srEkdsZynM+dpBWVq7+FjhxqHN4eHXqwb
         XqbgKOuJq2vDyLP8tF4gyWqxcPFB5MQ/WwGPSJE6ZfHZluE4wM2SOCW+BSzN+X9pvQwf
         Q229UVoZhrYLgcxiVu7QZn6cQfp0jL3thytVPgnKMruERJuNFbG5hVBL0xSWlk36pVoF
         TNovzKElBK2cqNwX8BhKdUKvRZAbr2tNA/KDSyzLj/P+pFLucy2SbvDHHcjfe5RFAISQ
         mtgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=3GjI3HdpMykSY2+YmUKXAGRqWylFQzs02bDymLtXFRo=;
        b=ltFQGGzin/+7eEHwRr3/nYtZ4028lyHJRC4gLQwQ/nVcWGSJcG4BA4/RsrVwyQsJrV
         3GxBt5nF9FklsehoATf3SVanoDs6baScN+nge6eQH3S3GDN5dN32OevpEn76+DEZ7+hL
         ffGaSJiSXR0LIK1tOOuzws+7cGpAbKKw6W+IMX3BAcFCSwHDIeu9yoYukAzCEHwt0ed5
         UdflLWvpnfc2ExZ7U2rOq4Nh2wWZ4XvWhWRP1X6m46bCMC/9+FPyOvnf34KdeJPNmykJ
         wlRYWmH8WAcR9mMkjBJE+Tmg5n9ErJZ1zzcNqseK0VguSXIhISDOc39WFaAnNBV6nJVW
         1vxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=S4Xe3j5U;
       spf=pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id br8si890957pjb.3.2019.10.04.17.58.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 17:58:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id q10so4926893pfl.0
        for <kasan-dev@googlegroups.com>; Fri, 04 Oct 2019 17:58:38 -0700 (PDT)
X-Received: by 2002:a63:682:: with SMTP id 124mr18045104pgg.102.1570237117746;
        Fri, 04 Oct 2019 17:58:37 -0700 (PDT)
Received: from [192.168.86.235] (c-73-241-150-70.hsd1.ca.comcast.net. [73.241.150.70])
        by smtp.gmail.com with ESMTPSA id t11sm5611290pjy.10.2019.10.04.17.58.35
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Oct 2019 17:58:36 -0700 (PDT)
Subject: Re: Kernel Concurrency Sanitizer (KCSAN)
To: Will Deacon <will@kernel.org>, Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Alexander Potapenko <glider@google.com>, paulmck@linux.ibm.com,
 Paul Turner <pjt@google.com>, Daniel Axtens <dja@axtens.net>,
 Anatol Pomazau <anatol@google.com>, Andrea Parri <parri.andrea@gmail.com>,
 stern@rowland.harvard.edu, akiyks@gmail.com, npiggin@gmail.com,
 boqun.feng@gmail.com, dlustig@nvidia.com, j.alglave@ucl.ac.uk,
 luc.maranget@inria.fr
References: <CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu1eA@mail.gmail.com>
 <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
From: Eric Dumazet <eric.dumazet@gmail.com>
Message-ID: <0715d98b-12e9-fd81-31d1-67bcb752b0a1@gmail.com>
Date: Fri, 4 Oct 2019 17:58:33 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190920155420.rxiflqdrpzinncpy@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: eric.dumazet@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=S4Xe3j5U;       spf=pass
 (google.com: domain of eric.dumazet@gmail.com designates 2607:f8b0:4864:20::443
 as permitted sender) smtp.mailfrom=eric.dumazet@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 9/20/19 8:54 AM, Will Deacon wrote:

> 
> This one is tricky. What I think we need to avoid is an onslaught of
> patches adding READ_ONCE/WRITE_ONCE without a concrete analysis of the
> code being modified. My worry is that Joe Developer is eager to get their
> first patch into the kernel, so runs this tool and starts spamming
> maintainers with these things to the point that they start ignoring KCSAN
> reports altogether because of the time they take up.
> 
> I suppose one thing we could do is to require each new READ_ONCE/WRITE_ONCE
> to have a comment describing the racy access, a bit like we do for memory
> barriers. Another possibility would be to use atomic_t more widely if
> there is genuine concurrency involved.
> 

About READ_ONCE() and WRITE_ONCE(), we will probably need

ADD_ONCE(var, value)  for arches that can implement the RMW in a single instruction.

WRITE_ONCE(var, var + value) does not look pretty, and increases register pressure.

I had a look at first KCSAN reports, and I can tell that tcp_poll() being lockless
means we need to add hundreds of READ_ONCE(), WRITE_ONCE() and ADD_ONCE() all over the places.

-> Absolute nightmare for future backports to stable branches.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0715d98b-12e9-fd81-31d1-67bcb752b0a1%40gmail.com.
