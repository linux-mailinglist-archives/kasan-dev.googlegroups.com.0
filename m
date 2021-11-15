Return-Path: <kasan-dev+bncBDV37XP3XYDRBN6LZGGAMGQEMRYR4GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 45F364505F4
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 14:50:48 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id h13-20020adfa4cd000000b001883fd029e8sf3594112wrb.11
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Nov 2021 05:50:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636984248; cv=pass;
        d=google.com; s=arc-20160816;
        b=e5ZK3b2S7suOQg1pasNkaWKOOZ4u+6EbdvsracqTrkxomILHpsDDcfGauudwM3faFe
         NMjo0N4xIJ00Ya/9zoCGPgApkhV7h+KqasoSWxEVBttbYZfM9GBhtX+qw75Qb5z8srzK
         CvxdOyhC1oUbSsZRVcshGTgnozIRYcNCPzlgOqOCP7U0v0ao+CCHCPeisx4hr8ll3b27
         h3Wu7YSmmPuqXYvrP7AVv8WiKSXzs452/V+cpRH6YjYCMQC5vBAoNebBHJ8PE78FnNmu
         BduqFiUU6FhFLf44Q0CKZkccOatmv3Cct8zzz/sD3LJocUcNzG5cIG29y6COYryc/uKa
         l8NA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rudVoTcuGSGs6rIgQh6NG9z2fGXUbJbK6hB7/Uhj/A4=;
        b=lnivhi5zuPri6B4I2x25ZNJ7xblElaJalBR68l9n331pUlr0OJihjZhT3sQumShJSi
         pam4sWm445o1KMWkiHMk0Elb2o9S56Rxiga/nBbKy6Z40NAHZ4ChaAXFzJMn1SREoxNN
         xDD72B9WNF+363A+Am9NcYWXZKr3ayE/q8DgIoIjZDMe502c2HYGTdLLXN9mkpCNKgDV
         vZRObypgbkQM2krRGUv96oL7wTnZ3AtvaU1hDjc/oy6u/f99lsZWjV8D2ybp7jQlnt4Z
         uO08YDg9sL1/fX6bYvwz1ZsPfDR7+VKfG0Hz6a7SXhEYSyDYv5eR0C8zSmWPbKKGxxu2
         6KkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rudVoTcuGSGs6rIgQh6NG9z2fGXUbJbK6hB7/Uhj/A4=;
        b=d07fs6XxEZDZgJZ17Ruo/u9hK2ycUfmvHDxGW1jxoPwqY7Vc5GDt5eb5Jia1jjEcCk
         6sXrGMp9skIxa6oTjhzDZ+/38/RBFWlbbVtgeFwA8lEz1bI8R0MuJCTwVUs35ykfflN5
         YxQf60cyRHR94KZCfBoal/a0mY9rWTn+G1qnLw+d2Ypuex54sCgyRb+O9n8BGSR1mVml
         BomkIbPrLdHIY42NHYBkJG8wMTaJMuRqjEfbckx9Lj8uAKXMfEDNiCtzUVIL/AgN2YQY
         YC5OBpHxUgn/TBc3xoxU0PShq1hELbHLTfx+f/bYG6pzn1zuw+BnhuIXUaYAGNKOpC1K
         URKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rudVoTcuGSGs6rIgQh6NG9z2fGXUbJbK6hB7/Uhj/A4=;
        b=cv/Sw3IlgcgWMrMUv//+4brSWaQpOHTC0+heGYP9fi0dY8lr4MArwEhFSP/sjmR+hn
         BDsx2omb1rAn+6MpTKa9lv5A/m0eTs9ueC8HREMsS6okjjXxXBPXjl85/hET/gy5a8L+
         l/j7OOS3gOBvIHTiLjbMbTks3lh8O3VV3OIoSFWtgaGnaSKIZdQdp2Ejm3F1oHiFVQ2g
         wtYngMbiK7Zc51zAM16tnK3cMWV0cOwMWo+K8W6i0qkKkXTAlcNTDclBffIXndHcv6QC
         l/yC1Qlah9lFEBujMlAFLd3cOr3cZ78IGNCMPJqY/JJ8K6IOj4uFan27dSl4fyvY+nHI
         +6aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533u5PTjZHU22g72x9Tp/31RFhyy0z4xeBdZPb1R/WSu6jhyjg9w
	7Pe278tL5EMkAhu1U9cjwJM=
X-Google-Smtp-Source: ABdhPJy5I9Z5QOmiUKPSBdXpYc28lO5oLa/mgJIsu2mE+DyAHcwXNTV7ppDkBjtFtzUunae23dgG2w==
X-Received: by 2002:a05:6000:1862:: with SMTP id d2mr47407573wri.203.1636984248000;
        Mon, 15 Nov 2021 05:50:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls10453135wro.2.gmail; Mon, 15 Nov
 2021 05:50:46 -0800 (PST)
X-Received: by 2002:adf:db47:: with SMTP id f7mr46803693wrj.113.1636984246881;
        Mon, 15 Nov 2021 05:50:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636984246; cv=none;
        d=google.com; s=arc-20160816;
        b=KZEuh3Wwp+FwLsRDzTJiwfrov9A8uKjsJK4fE09lGHWS8D9Fuo6GEu4t+1Bn0nskmx
         wirCsE6upcKemXCxZSx0RECtwUyIz08fiLhSqzssduLFDWbKEA7xyglde9tanCXhvD1K
         e5PWlSCboUEEsjfvLg3V7NP6y12HJP8Koxz+y9kJCfDnv1UwBpHS+4A2Eq3G9c1melZ/
         Q18Pkb2IV1AvRF9qvGsOihHrOFHYQXz1VCZtwCurb07OhxCeR/GUAWzi35jFX3BVZRMh
         9AtiVTH71XQHfnPkyQuLCPzhwLBl3ohZDqMITxJmWJbQqv4PxAM3dX9L9EjFxszBPgoJ
         9gsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=Y67lnyoitQgYMGWiTLOuKFjBtHUS1zkO0T/JvLBxUfU=;
        b=Afio16EWfv9kigH96DhOtSqoVtmGOeeDlFkxUhXuDl4bn2jD8hsZNNiW9iosAHs/IF
         vPpQkVJESC9bO0qtDpU/7QtGGr6SoOVDx1HIAKi1PlOEiO4NgqS4Rz+sr7oJdHDd1Mm9
         RHG3dwFTFo3LQCh2dIMPmzoA1j8s7Ir+hMC/bbphstkdXxbxSH8fT9x7VTwW/1kdZ58r
         e24ZmERI2AG6KlLtqp7zO8TpJsONkIjIla0XV/vjOIZ636fJ5FOwYVjTI8gV4Y0PbPF1
         DaX3/fO4/YvEjPDN+rHR2WOiH1tc7xn/Epj7nAx68oi6KRSOX3hAg0UVQjg5A1Po1HKp
         V7aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i7si1185698wrc.4.2021.11.15.05.50.46
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Nov 2021 05:50:46 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 203806D;
	Mon, 15 Nov 2021 05:50:46 -0800 (PST)
Received: from FVFF77S0Q05N.cambridge.arm.com (FVFF77S0Q05N.cambridge.arm.com [10.1.26.128])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E57CD3F766;
	Mon, 15 Nov 2021 05:50:44 -0800 (PST)
Date: Mon, 15 Nov 2021 13:50:39 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Qian Cai <quic_qiancai@quicinc.com>,
	Valentin Schneider <valentin.schneider@arm.com>
Cc: Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Dmitry Vyukov <dvyukov@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: KASAN + CPU soft-hotplug = stack-out-of-bounds at
 cpuinfo_store_cpu
Message-ID: <YZJlr50XQExl7NUg@FVFF77S0Q05N.cambridge.arm.com>
References: <YY9ECKyPtDbD9q8q@qian-HP-Z2-SFF-G5-Workstation>
 <YZI5+83nxZzo00Dy@FVFF77S0Q05N>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YZI5+83nxZzo00Dy@FVFF77S0Q05N>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Nov 15, 2021 at 10:44:11AM +0000, Mark Rutland wrote:
> Hi,
> 
> On Fri, Nov 12, 2021 at 11:50:16PM -0500, Qian Cai wrote:
> > FYI, running CPU soft-hotplug with KASAN on arm64 defconfig will
> > always trigger a stack-out-of-bounds below. I am not right sure where
> > exactly KASAN pointed at, so I am just doing the brute-force
> > bisect. The progress so far:
> 
> From below it looks like this is on linux-next; I can reproduce this on
> v5.16-rc1 using your config, when hotplugging CPU0 back in.
> 
> We used to have issues with stale poison being left on the stack across a
> hotplug, and we fixed that with commit:
> 
>   e1b77c92981a5222 ("sched/kasan: remove stale KASAN poison after hotplug")
> 
> ... but it looks like we no longer call init_idle() for each hotplug since commit:
> 
>   f1a0a376ca0c4ef1 ("sched/core: Initialize the idle task with preemption disabled")
> 
> ... and so don't get the kasan_unpoison_task_stack() call which we want when
> bringing up a CPU, which we used to get by way of idle_thread_get() calling init_idle().
> 
> Adding a call to kasan_unpoison_task_stack(idle) within bringup_cpu() gets rid
> of that, and I reckon we want that explciitly *somewhere* on the CPU bringup
> path.

FWIW I sent that out as a patch:

https://lore.kernel.org/linux-arm-kernel/20211115113310.35693-1-mark.rutland@arm.com/

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZJlr50XQExl7NUg%40FVFF77S0Q05N.cambridge.arm.com.
