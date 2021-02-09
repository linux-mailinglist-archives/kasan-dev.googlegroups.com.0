Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPEMROAQMGQE4VQ64EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id C1EB631550D
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 18:28:29 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id d202sf4567707vkd.4
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 09:28:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612891708; cv=pass;
        d=google.com; s=arc-20160816;
        b=tWSWe+ZDHc2Nf1wxShWRu3v0Md+USHWxBGFvzbrih8qr7HTiWwFgBa4aaTxFBGKuDY
         FB//8ytPB4674Cgk5iRR96W3md5Pb4GxeoDsRTxIgPitShDaRiuA5iIU5Fhsf929PbED
         3Z8IMMU/a5EXTGW68r8TqYGuI97pQIBJ3tqhYQzTbgQ2WFhPVfvBxnGJbO0LpIz+/lW+
         VZo4F3XvUN2FAXU9uemkZfaMw3I/h+QmEPzJK2idLhVifw4FhiTAvve52zUkBxL5n0HO
         PcdJzPnEuKsjwm8xIQthpEDTOuy1uhq0XLsZMvBvfXkTJFg90uIprJoPRVqGoA1U2sbn
         Npcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=xor7YsPwLaw9UdpkVapW8XzQMxNosVyNoI3a8uJ7lBY=;
        b=riW5xBxnGMhB8cKQFeufvRPqaiwSpTnFSBw38kSKoFTxc79ZMrmkK7hGhbpx/QxYyT
         ATE0TCC7O4SBT1FnFRcHMD07NHZXHXqr8Ne0GHiuTR8J3/dvWDdIwpaa9QrBFiD9RirF
         Wsg0yP9RGsFCUudEBQ8/WgsdAzBkiw6QCwyIkOw3eyJAAvUI7T/O/BQOxJ6HYkxNjFsb
         H3GU2mBm9te64r1Xt9HrMgTzRVq1pQccGC/0CiOamozsHKAHf578bFPvcHGDA+R65Ywu
         /yMga1BWA0EpotRMWrlhoDPPGzNMksko+KZUwryWmjL7SxGn5QM1LBD65lEA+0RrxbDa
         cEsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xor7YsPwLaw9UdpkVapW8XzQMxNosVyNoI3a8uJ7lBY=;
        b=iYL1I1ce2xr6BtTmLt2r77CS1QYlu6++BF+gJg7eak9QenZwLzXj6b8J4pVk4U5P2s
         uwsyC7UjLt9I5EPVtqHHZjwgIm3QpMoPICLmcJYt0nME/9Z7eUri+utyGh5k0i7/P/Ml
         Dbjzg/128Wzq+Dl7kt9LhdnpU7ik0ZmX7tlQNKaJ1cBlZNX4e3TkGFfZe1MIU2MExKUq
         m4VtyS4z0+xIT92UvM/LJNdHbnTJAEvdfj0qXmKFVUfzWva1vEE0fyFur16KjdnXeU3r
         aShyTepUJbi/wFDqLORm9nITy0QzMlJ84a/T009vpawdKeTPUpsJuBo5azY2+bxu7raH
         jOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xor7YsPwLaw9UdpkVapW8XzQMxNosVyNoI3a8uJ7lBY=;
        b=Rzzy/FU2PjadWqk8CTZlGzRtkWfjnQWy9xMNmAdybNGdwaio45ogiDmxM9qSKSHOZ3
         uUGDNtyKnw3aPYQ+m6809FdwH+hx4mcSwLLLM/TiWJ+4UkPMcFYlG92wUEY0BOHOpDP9
         SI42E5p/FnimAhXg+Rz/mdj3/64CLCxLUQK8NYezbo4o3bBVs4O2cFSZyf+CgcyIUFOt
         S0NGW7PJzjDJsE/KHq48i/ZhcrVIXJmNh5erLVbFM5lprqJF/e1mE3oBILUsxGlkZc3+
         HpBiIx2o7dG3hcOykbb7pR2NPT02NhHLuJaaOLlOuT+ynK8E2cV/IUDeD/fFDWJdPOZ4
         /CVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533u3+B537NXEi9p4XV/ebEUow0YQNB7kvst/tB8hjddvUgISrmh
	TevPsRZBtbq/VxHf4Dr+n88=
X-Google-Smtp-Source: ABdhPJzqOGR2cJLq0GtgdgrEMlR8vnkYgVrfrXTaW5vNKhW55RR3QePTxSMvccwmrTL59uBcHscmUA==
X-Received: by 2002:ab0:40c3:: with SMTP id i61mr14065667uad.80.1612891708820;
        Tue, 09 Feb 2021 09:28:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:106:: with SMTP id 6ls1639702uak.11.gmail; Tue, 09 Feb
 2021 09:28:28 -0800 (PST)
X-Received: by 2002:a9f:2286:: with SMTP id 6mr13844866uan.66.1612891708273;
        Tue, 09 Feb 2021 09:28:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612891708; cv=none;
        d=google.com; s=arc-20160816;
        b=mHJYniLTxCELuMzZRaYyEwQy9OS7/hFQUJbsBRl3f+yUf6LT+O1I8hqyTBQmbUVSzg
         CY170SCOXnrqRFnn0hCja67zgVpKn6IOpyhDL8CYsY8qwVdwrw6evhXDL/TivA8QfTYZ
         yrdJEVD3rlKL5qpnC2FQWuwnUTuE6U7f0UcZVYnKjztFYNivaA26IaobRrpkv4RT+tfr
         JWCQ/OBSN+EzcVhEhvDqA8UdhB20hctGFNSfVnxpydJjDfsv6GnNu8ScUx+X1kFoYTUF
         1HDY0xNFQi9zT6Bhjs2wxGKCs9BbgVxY+cu+JGydYGkmgd8kXP1Lv+uYP3DDddI848nb
         OUnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=y3Jn7vUyJMqJR+8ePjV2FthkaY1io0EJOa7ZnDuK/TE=;
        b=PX9yzdSBIj2dzlWOd5UWWN1/rnUY6ft5QKO/SBnFp4y3EmU9JaNw2OhARn2Pfi+QNc
         sYx5otX0ukFNldAqHJjpOxcOesDTfWvUR0rwMCu8JKELT3+RwDj9jtIpkymCH6tVjYE+
         kMnWaZU/9TGHIFkhOp+ksvDkTBunl0bYSYEZPR4j9mb+Y554ncIKG3sd6ouz+6rdBxfi
         WNseNoInBGoUqpR3FQCsTmxeKLiN6ycLcgNDhdFs1c24/6egpomIkZbfziymhq75EyBw
         F0MoyMj703UgZVcPsiTyiXzKmfI9zQHdDtMUBSbaQe6gAo876whohVJwN4ahLnN0nEvz
         y4Fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q1si1357786vsn.1.2021.02.09.09.28.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 09:28:28 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C72D964E9C;
	Tue,  9 Feb 2021 17:28:24 +0000 (UTC)
Date: Tue, 9 Feb 2021 17:28:22 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
Message-ID: <20210209172821.GI1435@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
 <20210209115533.GE1435@arm.com>
 <20210209143328.GA27791@e121166-lin.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210209143328.GA27791@e121166-lin.cambridge.arm.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 09, 2021 at 02:33:28PM +0000, Lorenzo Pieralisi wrote:
> On Tue, Feb 09, 2021 at 11:55:33AM +0000, Catalin Marinas wrote:
> > On Mon, Feb 08, 2021 at 04:56:16PM +0000, Vincenzo Frascino wrote:
> > > When MTE async mode is enabled TFSR_EL1 contains the accumulative
> > > asynchronous tag check faults for EL1 and EL0.
> > > 
> > > During the suspend/resume operations the firmware might perform some
> > > operations that could change the state of the register resulting in
> > > a spurious tag check fault report.
> > > 
> > > Save/restore the state of the TFSR_EL1 register during the
> > > suspend/resume operations to prevent this to happen.
> > 
> > Do we need a similar fix for TFSRE0_EL1? We get away with this if
> > suspend is only entered on the idle (kernel) thread but I recall we
> > could also enter suspend on behalf of a user process (I may be wrong
> > though).
> 
> Yes, when we suspend the machine to RAM, we execute suspend on behalf
> on a userspace process (but that's only running on 1 cpu, the others
> are hotplugged out).
> 
> IIUC (and that's an if) TFSRE0_EL1 is checked on kernel entry so I don't
> think there is a need to save/restore it (just reset it on suspend
> exit).

You are right, we don't check TFSRE0_EL1 on return to user, only
clear it, so no need to do anything on suspend/resume.

> TFSR_EL1, I don't see a point in saving/restoring it (it is a bit
> per-CPU AFAICS) either, IMO we should "check" it on suspend (if it is
> possible in that context) and reset it on resume.

I think this should work.

> I don't think though you can "check" with IRQs disabled so I suspect
> that TFSR_EL1 has to be saved/restored (which means that there is a
> black out period where we run kernel code without being able to detect
> faults but there is no solution to that other than delaying saving the
> value to just before calling into PSCI). Likewise on resume from low
> power.

It depends on whether kasan_report can be called with IRQs disabled. I
don't see why not, so if this works I'd rather just call mte_check_async
(or whatever it's called) on the suspend path and zero the register on
resume (mte_suspend_exit). We avoid any saving of the state.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209172821.GI1435%40arm.com.
