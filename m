Return-Path: <kasan-dev+bncBDV37XP3XYDRBTNPS2AAMGQEYKKRELI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 031162FA2A4
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 15:14:39 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id bp20sf16685915qvb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 06:14:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610979277; cv=pass;
        d=google.com; s=arc-20160816;
        b=BiqZeWGllf13n23RBOT0qbhlKAcv/Q2atVzWIUvAK7fihrmq/SZ2ipzn8RC1Bz4jeC
         KxY56K7+tyXPu88QX7l1pbZuf/RqE5f/Gz37r4bvmH3831bWiez/7p3PdYqpRr4RnE62
         PmVjokg22Pbc7hyPasGpjdPM4wxmUFk1/F4y2ic3NnIhZtnZnt4vgQqyQCkmXQHSyLZD
         tNiuY0jupZdVdBTnGjbHWGdlTicXuGN5RCu/ut1zpPwu5ouwPJ/H/m7eIZw87FlBWlkc
         am1yP+6xwJqrfGzGJxH/KBqRUd0paao2DO8YfkKronQK1g1vjBS17ey760LY45itMjFj
         oSWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=z2YZq2dtPOD4u+/d8jpkxrC/lh0gly0lH0/2K+iB+tE=;
        b=u42EK/UnO0ahYnJ0ZHyGVmKhBQUx3NDqKEGNIkKJcfeLlr5RbxiW6OryQkCUwQw1zp
         D1Pjlcmz2a1qucygNmUnV7UCnfRSJE7WRjSQYbTV1J44B4C1qpFvdZ4qwBRJUbANPhdS
         mqZoBMmLohkHcoCkNO+20bJaRNAYLjRHDvEkxzoWHR1+Rd67XjJS2C4RLGFIPupazHVE
         jAIkpV91nld3UQrGTCMG1TrzZ7zBaFK7KD2Z7kp40gWxnR6cc6QEBOqfipCUdKz01Z8C
         hSi3QndpMSi/FkdR7qQqxLONNUnhVfQAd/VvRZLYQHo25m4I4FCVhASjEIBKzas8ymgC
         9gNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=z2YZq2dtPOD4u+/d8jpkxrC/lh0gly0lH0/2K+iB+tE=;
        b=YKArZ9Pp17nMDxEvT/TTfJHd6uEx8fFUn21PDvTi4js1Cv/1PZxXX5UnZOANRmP6J/
         sl4/01M65I5eJQfq0obabNWv6xNMxhhcoB8h2KwvXO9C0AL8dzLDCPY6NAQIVxRKk03z
         7zZjnPeZnkDBapQJ3WLnEALEGtUJXcXZlZ8HtEErwjjiRTrJmftigmJzuG9bcW4yRnvX
         Hnht9zllOxpfhyDECYJ0iW+nN49EHppdGt5dtf4IaVwpp3Ty8wI3ob6h5ZS/jFPn4+fC
         7S6l1dtvZlmHaobiMDG2L/DbJfRgTiXYFMwCfEcMQi5fEmVsmS2YG0vPEEpVDS9+w2BV
         9fHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z2YZq2dtPOD4u+/d8jpkxrC/lh0gly0lH0/2K+iB+tE=;
        b=T1tGM3rVJ+ma5YWwOa+tncsKDR9/eFzDwTOuf3lm+96QshuCX0MTqct8u7RWIR0uAt
         Dge/Z+zwQsFLByputwGXWY+N86S2zqMp8Im/ugsibUTaEz1COgZKyd/oFdq7uwK9x0rI
         T9PKvDiK7+ZjkOwCl7b4JMlEAMitp/exfScKr8VCim7ya3PYt/KN6Zs/vObECiUgMXq9
         c9h9gCTcfG3PBxmTbrfawxGdQz585okPI615jb2l5Mcc3xzHIjD39GsRjgKLwNkfGP/e
         2kgqfgTjkYm/NC8O97eYrZij8Z069+Qpxfc7pWYjjMS4Rm5MatGFLG3NSzYOEYFcxP9Q
         5mrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531IAQRjNhN/PEZ52Wn8Wss0BMcaFMZKBQ1RW0TZUQ+5RquhM0bR
	BaoWtfsrPBktaixCWXxSBtA=
X-Google-Smtp-Source: ABdhPJy33LwwMucxVOV7fU3W/9sxn7Geaqr9Gm2sHSvpsGaOsG6mEy6DUF2CxS3Uk0LPcByAhIaVcQ==
X-Received: by 2002:a37:a342:: with SMTP id m63mr24900378qke.120.1610979277730;
        Mon, 18 Jan 2021 06:14:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3bd4:: with SMTP id s20ls1922983qte.1.gmail; Mon, 18 Jan
 2021 06:14:37 -0800 (PST)
X-Received: by 2002:ac8:4d93:: with SMTP id a19mr7358097qtw.28.1610979277241;
        Mon, 18 Jan 2021 06:14:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610979277; cv=none;
        d=google.com; s=arc-20160816;
        b=EFcYpYhnukQi4xPOlfx8eKxxA/tj+V7Qzyr17AYJs107LIyWK+2s25PL/yKBv2UDlI
         uw1crVZRUJXo5polFiJ43ZwrsEkICHnJ1U2b+PHCB/lU33suQMNjAdFWVu8junvd/yqy
         2f+RR06Q+axuFUkottyRThbNx+BZbl16vKsiGPt8IkoiNyakm9GxfFTpi1wy8k7dekZ7
         KcypxTEokb3FZ0qw+OGgE2lPIrQJfwAK3NFPIF9SOnq+iaNmqDqjUCv00rt2HbwidR2G
         TEqPjqVLXzjKdrG/hV3DgcSltlAlNeCrSeKktRrExVNE9EwRP/5zk9Zo3T4/frdjig4J
         kPiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=rFsGnbLj5d30iF5P5QXxcMWBmZFi7baEHg/44bhLWx0=;
        b=ITYVtNwCNczEEwHkf/DDxl0HpJd7vh/sYZ0HuWAH7x4Sg6LbxysebP79JMuc/olx2x
         XGGgWXpcHLhtPsFcYH8EZbwUPsRbzvbgEpzl1D+7RpDDX1LDS7C/8OrlhcbhcSu4ZSiR
         N4hA91yGMe1LKmpjvpzseW/nqbEMPut+biMT8rx23Ag521Im5wjBx0PrxgvmZpmegwGE
         H8bu86RxWY9BzQ1gAzU8WRo1htz1sOv3BURsDyGTeBTZmUlNk0En78w1oS+X02K4oqLu
         IGUHnbPoENPY22NX8nCoI7eUlApZ21EjqFoWEFw5zCO/hGQGQOn6YF9fXjESfzzcrfNC
         uxlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g51si424783qtc.4.2021.01.18.06.14.37
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 06:14:37 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7772A1FB;
	Mon, 18 Jan 2021 06:14:36 -0800 (PST)
Received: from C02TD0UTHF1T.local (unknown [10.57.39.202])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 08AA53F68F;
	Mon, 18 Jan 2021 06:14:32 -0800 (PST)
Date: Mon, 18 Jan 2021 14:14:29 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v3 3/4] arm64: mte: Enable async tag check fault
Message-ID: <20210118141429.GC31263@C02TD0UTHF1T.local>
References: <20210115120043.50023-1-vincenzo.frascino@arm.com>
 <20210115120043.50023-4-vincenzo.frascino@arm.com>
 <20210118125715.GA4483@gaia>
 <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c076b1cc-8ce5-91a0-9957-7dcd78026b18@arm.com>
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

On Mon, Jan 18, 2021 at 01:37:35PM +0000, Vincenzo Frascino wrote:
> On 1/18/21 12:57 PM, Catalin Marinas wrote:

> >> +	if (tfsr_el1 & SYS_TFSR_EL1_TF1) {
> >> +		write_sysreg_s(0, SYS_TFSR_EL1);
> >> +		isb();
> > While in general we use ISB after a sysreg update, I haven't convinced
> > myself it's needed here. There's no side-effect to updating this reg and
> > a subsequent TFSR access should see the new value.
> 
> Why there is no side-effect?

Catalin's saying that the value of TFSR_EL1 doesn't affect anything
other than a read of TFSR_EL1, i.e. there are no indirect reads of
TFSR_EL1 where the value has an effect, so there are no side-effects.

Looking at the ARM ARM, no synchronization is requires from a direct
write to an indirect write (per ARM DDI 0487F.c table D13-1), so I agree
that we don't need the ISB here so long as there are no indirect reads.

Are you aware of cases where the TFSR_EL1 value is read other than by an
MRS? e.g. are there any cases where checks are elided if TF1 is set? If
so, we may need the ISB to order the direct write against subsequent
indirect reads.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118141429.GC31263%40C02TD0UTHF1T.local.
