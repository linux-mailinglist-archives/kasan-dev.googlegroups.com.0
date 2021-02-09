Return-Path: <kasan-dev+bncBCXK7HEV3YBRBQF2RKAQMGQEFBGGCMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id AF4753151B5
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 15:33:37 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id j128sf11510544ybc.5
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 06:33:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612881216; cv=pass;
        d=google.com; s=arc-20160816;
        b=tybIAxrjLKygmhSujS+6mli4a6jyfEwSsYzgPbdjD4wwwz1RmSbfOLxQVgf/KPNe0N
         qjO5QaOJLfngucHYJgnRGhWtkRrC2auSzaMwttWBkSKkZUBq8pD7eetEm0BQXsKc0fvo
         kUsSF62t4hctg4ZOMmqzcnBt3A/MPNClwndHB6Z1YMgM2MBmnQB87FAmm+mXzBoHpuxV
         okkG3zkTWVNs/aMxLuNm4/CiEI2NdwMS8oCo0ZOfoMTEOMgjWwH23ZXoDZj5vsOdI8FB
         pfY9+eTQgfDqs8i5rVy9idENbs6cd4PxK9VlfVTyGIavWYuXHCaUL651hA1s0vBMImDK
         UQ8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=MvsrpqnmRrSs/2iPdEYei4mHWLjPBBvFGnnW+Ek6Vms=;
        b=p9OzWBR8Lo+RVTmhdfASbEjAjGLPiXVJYYAz4P2XR15PJynucpOklUE2sQtUOzfD4Z
         xqsbVRdLEU9JbKQnD8KXPKuL4elc9zu4Rw25S6C3r5+Bg/2q+4H6FRZBkZWErX+ICgMO
         2AHvBI7GeP15kB/+3JZ3V3/XYagpQnAhk9sPq8Qcz5P8NnndXIbSnCsRDSgXNeHhKniu
         0D1CKqBy8u61FYHXHddURHm/664U0oOrw2aFiB8D/beNs0rz4koW7+8q7P33Tq8IHkfv
         NO7CylKrMXEkGA2vDDayvhy4O1PCAkZTGRx3IX4gYSs3WpfsB1ofwZK8nTZKY/ohd9eN
         knfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=MvsrpqnmRrSs/2iPdEYei4mHWLjPBBvFGnnW+Ek6Vms=;
        b=ecYXPDLvvIFhWMx/Z0OhTjtWaNxCNjnrCY6XX/Fhfw+iaf6OVdpN5qJ3H44IpHC0kx
         T7Pq6zjHsGLp3J2C0XSPIUaw8SjpYfKYCmzMVRezMKM7UA41bCX1MY6UnRT7r4ZY9MFw
         yhorPuWOUp63qCjbrK8Pxg2JWILtyISiktg+rvtt7ddscicuYMVoSE+cVJJg6QOJOwxz
         lD7T9WIS7AftVLKMkfCcJOuH45kfLVG9HjPewXYNcH5FUP4wtwtkF7f/mEp4cAztNKDE
         bFKl/R2g4N9bk+o/4TjF4O0sbtHUDjgwl8ucVoRccGY0FpAm5/DGvOKvlpnSmV+myuFp
         ubkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MvsrpqnmRrSs/2iPdEYei4mHWLjPBBvFGnnW+Ek6Vms=;
        b=OixjI8T6Ihn7npMGAzr4roOfkBPsaG4dAn75cP/yF0iFfjw6pKq9fJ2ZyuspZIYYlU
         pY2pkYBt/w80Y4mmJ7xfTrIMej+bywWdzAU0asghizn229uP6LMTMiEEE5128xB7ppuN
         dFf08xmjQPM/bswqdChnO4SP135w+Y68CALSnVJqDCmmv8lOFTB7Z15A1OyAxz3COcsh
         TB+Vqzt5kRBNUodqLhXZ4rIW1HQvbDZV+O1N0jzwUctLD81xj5zJ5kqz0TiM26gKwqHq
         ooEJBjhmqEL1MhWIR2IEmUzQstLz2vmd1oIMTLMeLDSw3j22Wkyr8D3KRO43dDlutxXk
         PZXw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5304gDzPWbV+RDAetYuXDr9ZL4jdyWuqFzQXc29WCWGMp849vCf9
	VyEtguvhCZHiA9ZFl/bX9Sw=
X-Google-Smtp-Source: ABdhPJwH4muJWX4zUc9euVbbJ5xI85Fe/E9IolKXxI9Wn2F4LJOaqFOjch41KuS3lY4cDHhRlSPSxA==
X-Received: by 2002:a25:5cd6:: with SMTP id q205mr10114965ybb.489.1612881216546;
        Tue, 09 Feb 2021 06:33:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3006:: with SMTP id w6ls10347746ybw.4.gmail; Tue, 09 Feb
 2021 06:33:36 -0800 (PST)
X-Received: by 2002:a25:7dc4:: with SMTP id y187mr34664200ybc.477.1612881216179;
        Tue, 09 Feb 2021 06:33:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612881216; cv=none;
        d=google.com; s=arc-20160816;
        b=DWtnergpn3ZAg0vBK3ldP5ezbTvMBeLV2K0iGIA4g3FJU0VG9X5aQNPMWcaHoFQzkD
         buWzJtf5hsHqAY5LE02S18WKhlMromlZGbUBAyPyEpPYmG5Ew6NxyBITBl1uVmlHnJbA
         DqrRVgs0ijpSkTMY41rEAPdfG3bM4FO4n59RIW7HYgz1zzI+u//CCe/+Uw0WAmwggB8G
         dUjPCkOerYq0TJInRvKLR2CF8MuJaxiDolg6euU154bf5RPFcus/Yqwwy4HSwlSdLm1/
         LJtF1Pwrrj5gZbG9aCV5F80MO6uN252rTI659W0Iaj/lyF1gNnd4WGKV6qgkoQFOTGgJ
         8pUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=iAdkpyrLgGypHgLpEScWPIWY3/J4g9r7HTApTMXI8Uw=;
        b=i+z7BawsudE9KqtQowpHDL6TI0g2C9PpPRwhPowzjSs6v6jQ1424zprHEgI+dCjKFa
         3VnbdIZUTAiYXz9ojiDaTkDZJj8lIN8dbRTsq5JDIHKVTEfPqAmYCXkOYXfq6KiCBIrE
         mxR1lByqEBUpG+EnqlXhL4cG5Ky1dk/ErYrkdQR4jzJcoyJ/8Ia3G3UGOP56N5pjamIE
         JKBpAM12DRMIroofMxZKXGpmdzxMFb1OUK4WWRp57QewKHwJ+opCzsgNm/KfHa3we6Ya
         93ikptGet3EFQbsk8iFcTnU1npuTZKimItwyHWIrWY0sVO3V0SKWv3PmCshk1FHKTDBP
         iFhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e143si542806ybb.5.2021.02.09.06.33.36
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 06:33:36 -0800 (PST)
Received-SPF: pass (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 9A7E5101E;
	Tue,  9 Feb 2021 06:33:35 -0800 (PST)
Received: from e121166-lin.cambridge.arm.com (e121166-lin.cambridge.arm.com [10.1.196.255])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id D1B7E3F73D;
	Tue,  9 Feb 2021 06:33:33 -0800 (PST)
Date: Tue, 9 Feb 2021 14:33:28 +0000
From: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
To: Catalin Marinas <catalin.marinas@arm.com>
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
Message-ID: <20210209143328.GA27791@e121166-lin.cambridge.arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
 <20210209115533.GE1435@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210209115533.GE1435@arm.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: lorenzo.pieralisi@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lorenzo.pieralisi@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=lorenzo.pieralisi@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Feb 09, 2021 at 11:55:33AM +0000, Catalin Marinas wrote:
> On Mon, Feb 08, 2021 at 04:56:16PM +0000, Vincenzo Frascino wrote:
> > When MTE async mode is enabled TFSR_EL1 contains the accumulative
> > asynchronous tag check faults for EL1 and EL0.
> > 
> > During the suspend/resume operations the firmware might perform some
> > operations that could change the state of the register resulting in
> > a spurious tag check fault report.
> > 
> > Save/restore the state of the TFSR_EL1 register during the
> > suspend/resume operations to prevent this to happen.
> 
> Do we need a similar fix for TFSRE0_EL1? We get away with this if
> suspend is only entered on the idle (kernel) thread but I recall we
> could also enter suspend on behalf of a user process (I may be wrong
> though).

Yes, when we suspend the machine to RAM, we execute suspend on behalf
on a userspace process (but that's only running on 1 cpu, the others
are hotplugged out).

IIUC (and that's an if) TFSRE0_EL1 is checked on kernel entry so I don't
think there is a need to save/restore it (just reset it on suspend
exit).

TFSR_EL1, I don't see a point in saving/restoring it (it is a bit
per-CPU AFAICS) either, IMO we should "check" it on suspend (if it is
possible in that context) and reset it on resume.

I don't think though you can "check" with IRQs disabled so I suspect
that TFSR_EL1 has to be saved/restored (which means that there is a
black out period where we run kernel code without being able to detect
faults but there is no solution to that other than delaying saving the
value to just before calling into PSCI). Likewise on resume from low
power.

Thanks,
Lorenzo

> If that's the case, it would make more sense to store the TFSR* regs in
> the thread_struct alongside sctlr_tcf0. If we did that, we'd not need
> the per-cpu mte_suspend_tfsr_el1 variable.
> 
> -- 
> Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209143328.GA27791%40e121166-lin.cambridge.arm.com.
