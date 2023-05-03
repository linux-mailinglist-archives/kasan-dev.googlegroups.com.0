Return-Path: <kasan-dev+bncBCB5ZLWIQIBRBX72ZKRAMGQENZTMQTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F00276F5F8A
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 22:00:32 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6a5f7956de7sf4649747a34.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 13:00:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683144031; cv=pass;
        d=google.com; s=arc-20160816;
        b=xcquSwM620UOM2gKRPUxJa1e+qWPMVn6IDYWHQhAKCV0PEyUUMRMbuOQBgrr5fHZN/
         eL1jhwKwbMR6uUZHbVb7ndqx1FGR61nHVkSAlntAl2LJwdg3r5yFW+5J8fh74eIhg9h9
         VyobQMBxrgHn7dEzs401PumLhLPl9zOEMe3Ffq2Vcg4HwsE/FuNvVIOTXV1TBri1xOhs
         MWbNR0RYrVL8m0gARKQ0qt4NjLTjdpztNP1YKma6fyBY+whG5MsgSFLUPzl5ldiynTkr
         Iu7+Nqza+nRlnFbVmBzjkbU8/GSnxV23w7MxRWVd1b5AY8oMCTSKzCAyfUG7uGiM1lFu
         IwIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=omXiOFU0KSUdIC5oUKPlcPYOts4c9xhztGIJiTg/Xn4=;
        b=Iq6a1GmOqXneE/tIlNaq6kco8ceFWDJgadIBaEVw+68JRXwnMFZY0A13YRnoJpcAp0
         q9I6bK1iSOxghtWddWJ++3ojeeosCr7C9omhrLaas+vq6fpsi35szEmkGL1Ayv6R8KTU
         k1sAU/NY8DpLxjdzY/VtcsuAphdi0JkBBDikZL+PJsuOq5DXscJAEEF/iUx2z2XtHxHV
         sZJHeBYg4F15ihje3N/uENbhWKuwg4ufozicSDNM8GTKPVYEGfdSEz6MdXuBIEKfEArS
         KfvrECgWWKFtVCqCIz1WotJgOml1XX2qQltI9Tkdn8Vz1MTEh+a3QjmkC63fAM/ji0Ld
         YSbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=T5ytdzQZ;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683144031; x=1685736031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=omXiOFU0KSUdIC5oUKPlcPYOts4c9xhztGIJiTg/Xn4=;
        b=NYd9bimgvbfhinID6UKvYqseOm4/nCbUnco8/iMp44U5PXXdO913xDVcy7mY2qJvlK
         ZKt7KJ7hbb4c4Xx+OkfDq02xNTQ929Qqn0/Ak/jwSen5N0YkWA9jneWdFyKDV37z53ur
         1N1j+gWnVQR2ZBotMr9EG8ZMBrakDLn12P61hFUd9qZ0SEL3WwS85kjAGbiUeiqDpNE8
         B4ab38GzywIh0/F0g1j6fwQABfTAl+RcCMYnLY1MuBX4Y9zS9Qj/tpM9X3tSVcq3Lxkj
         9K2xuST5k4rK9esYjxM01S5vLw2JJ7pNOKXlaGQLteaYNVUZKgzqaBcPnWTgTqYh4W8y
         GMug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683144031; x=1685736031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=omXiOFU0KSUdIC5oUKPlcPYOts4c9xhztGIJiTg/Xn4=;
        b=lqZqPUQkMj97OPyLIiy7AiFig7RC53cDzKc+/vbAw2bCfRcu42DqMDJ2394r5k+3pn
         c87UOanHssNcY/C0JR6uo1Ba3IuscuEBU8TxQZPbNENQ41U3aDa/FtGP6o4KZCoto1na
         cC+FuBH58wDdX6EVSMp0CZ78QyYaMbVoVFsgcjI98STDic8RG0Kaup2ufUfjsRHe8sfm
         5QAEQl2Eqxz/2VlN7Z87C3Xp3e0EkTFHd6foWyRFgzwcYh4K+yKfwNnMV0t5R9lMgam2
         Plglb8DoYs3L6bCec4O026pS11Q15QQ1DQEJ4Bb8STFnNnjpwSfugxnTLcTrlObEdo5c
         fgeA==
X-Gm-Message-State: AC+VfDxFBrSu45GUK8PTk8xnF0WiWiZ43NSJq6ZxVaSE2HOEQPIKPJTx
	1l+MRm/5EFT2ndOmgDRvWjM=
X-Google-Smtp-Source: ACHHUZ4Oc3OWonOMIRVE7QrwVRAfC6sNqEDzXz7WIrRwo/xCPVCGOJPuqFYj8yU7l5D4xL/BIx3swg==
X-Received: by 2002:a05:6870:40c9:b0:192:bf67:bb1d with SMTP id l9-20020a05687040c900b00192bf67bb1dmr216603oal.9.1683144031606;
        Wed, 03 May 2023 13:00:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1206:b0:38e:2841:4685 with SMTP id
 a6-20020a056808120600b0038e28414685ls4244883oil.5.-pod-prod-gmail; Wed, 03
 May 2023 13:00:31 -0700 (PDT)
X-Received: by 2002:aca:dec2:0:b0:38e:cf82:93b3 with SMTP id v185-20020acadec2000000b0038ecf8293b3mr551584oig.4.1683144030909;
        Wed, 03 May 2023 13:00:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683144030; cv=none;
        d=google.com; s=arc-20160816;
        b=VTpnzNf+Ppn61OKyuqTz1Vq4Xxr1DhpRkGK17y6m7ne/8NOfxklEkS2MivltNLmMK/
         4l/jrrTZqySNunLaN2UWATmuaAiHvgms3V1Uc9DT5CnsGAmF+jJIZVPzXkVWwe9h77p/
         KcR4qcGB/+B5REpLUra+YtarrskXw36muVfG+2S6/3Smon/Y+uo7SLnrcht72wDRzkIT
         CiJBY94iwL7f/HM7xWWn0XCZjj0Kq41sfNidlUI7O4qjat9u/g7nulX+TC72aM4dzx+w
         JvQKbV5RF9hoqaBXUx0JmkTWop+F40kDi3TrHrl5vgN+fm28jySQkDeL/N3Phnxi+uiV
         E0fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=0HV83qXSxt0rJsxUhYqPsLXk4a5FBTNhGHWC84tLfFA=;
        b=S0lYsocTloUyao2bVW8pLXlZ1O3+R/LxgIic3PFbv1YztgvtU7yjdnO6pPosoSOi96
         Xfu7Ty/9Ptm5XCWxKCsSBVL3ZuuIbZoggXANBbe9UnHYFxmLSrYpQ6nwDblA2yaHh9Xd
         AWWN5f6jHDYxDEhD7J53LVZmYmNiIsxqMCFF0yzaSFs7Aim+QmPNuzwmlanew66Mi7XK
         reKzIGth+PtQAbNcfSnDITnzC8X3nL62yrLUlj0F+/73UAMhI0OcbaeuZIlJMSNUP430
         7Wax16fb/r8+E/30uiWlaUFCwYLFok0KFJeMn0unPeUT1igVAYgT7CGZfqGR3eCq3ID2
         O33g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=T5ytdzQZ;
       spf=pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=htejun@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id pa7-20020a0568701d0700b00187820f810dsi145114oab.5.2023.05.03.13.00.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 13:00:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-64115eef620so7568706b3a.1
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 13:00:30 -0700 (PDT)
X-Received: by 2002:a05:6a20:1587:b0:f6:592a:7e3d with SMTP id h7-20020a056a20158700b000f6592a7e3dmr3740358pzj.7.1683144030189;
        Wed, 03 May 2023 13:00:30 -0700 (PDT)
Received: from localhost ([2620:10d:c090:400::5:6454])
        by smtp.gmail.com with ESMTPSA id w22-20020a63f516000000b0052873a7cecesm3042624pgh.0.2023.05.03.13.00.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 May 2023 13:00:29 -0700 (PDT)
Sender: Tejun Heo <htejun@gmail.com>
Date: Wed, 3 May 2023 10:00:28 -1000
From: Tejun Heo <tj@kernel.org>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Kent Overstreet <kent.overstreet@linux.dev>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, roman.gushchin@linux.dev, mgorman@suse.de,
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
	corbet@lwn.net, void@manifault.com, peterz@infradead.org,
	juri.lelli@redhat.com, ldufour@linux.ibm.com,
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de,
	tglx@linutronix.de, mingo@redhat.com, dave.hansen@linux.intel.com,
	x86@kernel.org, peterx@redhat.com, david@redhat.com,
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev,
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
	ndesaulniers@google.com, gregkh@linuxfoundation.org,
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com,
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com,
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com,
	kernel-team@android.com, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev,
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	linux-mm@kvack.org, linux-modules@vger.kernel.org,
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org,
	Alexei Starovoitov <ast@kernel.org>,
	Andrii Nakryiko <andrii@kernel.org>
Subject: Re: [PATCH 00/40] Memory allocation profiling
Message-ID: <ZFK9XMSzOBxIFOHm@slm.duckdns.org>
References: <ZFIVtB8JyKk0ddA5@moria.home.lan>
 <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
 <20230503180726.GA196054@cmpxchg.org>
 <ZFKlrP7nLn93iIRf@slm.duckdns.org>
 <ZFKqh5Dh93UULdse@slm.duckdns.org>
 <ZFKubD/lq7oB4svV@moria.home.lan>
 <ZFKu6zWA00AzArMF@slm.duckdns.org>
 <ZFKxcfqkUQ60zBB_@slm.duckdns.org>
 <CAJuCfpEPkCJZO2svT-GfmpJ+V-jSLyFDKM_atnqPVRBKtzgtnQ@mail.gmail.com>
 <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ZFK6pwOelIlhV8Bm@slm.duckdns.org>
X-Original-Sender: tj@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=T5ytdzQZ;       spf=pass
 (google.com: domain of htejun@gmail.com designates 2607:f8b0:4864:20::435 as
 permitted sender) smtp.mailfrom=htejun@gmail.com;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, May 03, 2023 at 09:48:55AM -1000, Tejun Heo wrote:
> > If so, that's the idea behind the context capture feature so that we
> > can enable it on specific allocations only after we determine there is
> > something interesting there. So, with low-cost persistent tracking we
> > can determine the suspects and then pay some more to investigate those
> > suspects in more detail.
> 
> Yeah, I was wondering whether it'd be useful to have that configurable so
> that it'd be possible for a user to say "I'm okay with the cost, please
> track more context per allocation". Given that tracking the immediate caller
> is already a huge improvement and narrowing it down from there using
> existing tools shouldn't be that difficult, I don't think this is a blocker
> in any way. It just bothers me a bit that the code is structured so that
> source line is the main abstraction.

Another related question. So, the reason for macro'ing stuff is needed is
because you want to print the line directly from kernel, right? Is that
really necessary? Values from __builtin_return_address() can easily be
printed out as function+offset from kernel which already gives most of the
necessary information for triaging and mapping that back to source line from
userspace isn't difficult. Wouldn't using __builtin_return_address() make
the whole thing a lot simpler?

Thanks.

-- 
tejun

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZFK9XMSzOBxIFOHm%40slm.duckdns.org.
