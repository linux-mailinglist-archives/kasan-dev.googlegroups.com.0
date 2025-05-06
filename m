Return-Path: <kasan-dev+bncBDE45GUIXYNRBIMU47AAMGQEQ6GLJSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C97CAABD6A
	for <lists+kasan-dev@lfdr.de>; Tue,  6 May 2025 10:36:51 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 5614622812f47-3f7ade514c8sf1770360b6e.0
        for <lists+kasan-dev@lfdr.de>; Tue, 06 May 2025 01:36:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746520610; cv=pass;
        d=google.com; s=arc-20240605;
        b=XzjpnZS+AmH85oh0qyXJN5u1mwmG3caoSTBCGyoIF4wGl2jL9SZ9eiuMA5MImbp6/4
         B1LyL/+JT85icaIKSd9flRZePRMLrVOhiEjJ2WR0tc+XRsHczc6jH5b+UdxL1DV44vdU
         rT8LHTFGxMGHonJD+cfvnGMnv4oGCRgGdn8xAtnP0mc8PAZpKKEqQFTYUu7ec+moBusg
         Khq/0SqjEBNccq889kxl2qIXE1+LUw3+jvq5O9bfz+anSWbU0xu25xALOuaW7j12jDqQ
         hj8EwFEz1t+0Sx4y92UYBhz/Mc3j8GLIlsFibiOu7IUMyKl+cntCi8L4RMdQp5eve9vj
         6Iow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=MYjtuoY3032HrOVPOWRZiR8V8X3PMAWCAfZcw/QEAZo=;
        fh=Zh61rRMLgdXiqu9s2XUHb5FDt5u1iyknpcbbkv4EfcQ=;
        b=VhF2KNgqWb/djirmfHdJpZwSIQvrieGn1I7h22eQnJMoYsPJLzvhdEc9VXvos6RzLH
         Hx//ZFSXm87uUEBJNr9LTFsadqMEue3SjAJrvaApuM1PqSnkvsa77J/ZtvQJJinpXvRy
         0aq5uxLPkFp8/h6X+TmqXmF3nxH35DWw0sZS5wYfnprv84ZKJvawVaxvb/M7dwBDiNTR
         a7uf1mjFNv2xv0QiK8e4MJusmq4Iq4CvixOvueCni9cjX0wP092nWcFZC9wJKGDgyCh+
         baKws6ko5GAZ/xSEL3+7K18ON80+koJkyRZmWcmUfY1emRFe0IK3fvX5qDN1vbEWAB50
         VL0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G2RqhqDT;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746520610; x=1747125410; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=MYjtuoY3032HrOVPOWRZiR8V8X3PMAWCAfZcw/QEAZo=;
        b=aXEfYaGa9e7rFW8WM54+abPFI2EwYnft3rbVmbTUCCE5n1RRzJau051lv2dGdxO+A6
         i6nIwnwWHZI0kUfmj8f/yaRY/uiHetoka3+N9Ny7hMsgka3OaEog8o4lAUOZmnjVqj3D
         FUC77dF2B2MeDvGk8hQno/JlBNwzsYUI8afXmupkNckNi9pu2HTgViLaRuhStxS3tK3h
         1Ke+xd6WVX7s0tUARH5eQfQ7f4+nxWT/qos1qcmYVmETSdCpg1PplknUHfzj98hkzeEa
         oPniMUqdnuGAfM99uRJoW3KF2cg1Wdc84TIzRoqf2TY/o2owqxZfb9Qdtd0xPJVoSyXL
         py7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746520610; x=1747125410;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MYjtuoY3032HrOVPOWRZiR8V8X3PMAWCAfZcw/QEAZo=;
        b=KySlP6gw8uGSIRVS/ClxDjaFlK8/tvAsXVoWB3FeslGzvP+ebt7TavHZ6kCE01Sby+
         RBf1AsZGTde3+qG1g+HwhKuw8HxvzNo9NYTqosKIZkFxdrukz8MBypEBV3VD6rTt6+Ix
         02CArOsqgFEd8zZ44XgCj4TjHOZInpCKvEUTESIV7QslWq5/fSbeasJz9eO3BOErG42X
         aC7S/2vZCtwK/Ljp9SlSuflnVhgTbv+XDbgdchWbhvocFFloJGISV761t1HKfLJUhGB6
         AZYvBS3HYXVmRQ/7aSjKfUUoTjyN/ynH0lOIFlitFLPMX1Cta4bDSrEUGzaR+Ey36ylM
         KLcg==
X-Forwarded-Encrypted: i=2; AJvYcCWVFZx1S1YVy9MPqIrJKO7WuhjfrwKK9MB9yhwm/OcVi3W6/ftlyeT50JHGbssF7WJxjDF3zQ==@lfdr.de
X-Gm-Message-State: AOJu0YzSCMIZlV5oKfZWKYBBVYeCg96kgvXKnfUEy/BvCvZFt7xM/2jn
	FSDRZHppzOHzujjlkymqSGHknuE3S2jylrIHhFyQ4MJdAuDqFbBH
X-Google-Smtp-Source: AGHT+IH/gMC61DOjvXQ/46s4uOaYUCsALluPqkzqJ545F674HjTK3bS2GQXQLPP4d5PhG7RvbEqskA==
X-Received: by 2002:a05:6820:4b17:b0:603:fada:ac53 with SMTP id 006d021491bc7-6081e6d7c3dmr1122619eaf.2.1746520609732;
        Tue, 06 May 2025 01:36:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEkIywPdC38uQh7+aZVxmjfjwZ3hy5Pq9kPkGOfGnkfiA==
Received: by 2002:a4a:c802:0:b0:607:f7a8:4be6 with SMTP id 006d021491bc7-607f7a84c1cls712918eaf.1.-pod-prod-06-us;
 Tue, 06 May 2025 01:36:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMas3A5k/gEZ+CbP2qisO1g/hiphJJawsK+jyQiK4/0vblMEe2cYd3BPFtcp5wverovJVA3eXAYDY=@googlegroups.com
X-Received: by 2002:a05:6820:1514:b0:607:6268:c0a5 with SMTP id 006d021491bc7-6081e56daf6mr1252395eaf.0.1746520608459;
        Tue, 06 May 2025 01:36:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746520608; cv=none;
        d=google.com; s=arc-20240605;
        b=gtTKAXywfBToWQgclwFwzdyYV7jGnFHYXP9uTldhAcbvww4ki/BJ1sz72Wt7E2UVZ1
         7GIB3n46HzeG+Ubn2ofSatoqO8z7sCpv5na+JrlY0eN06kwnoG4ugMEGv4+Hu8hgPJYA
         zD1kypurM48aleFj6b8aqzXpSSwOwIFejJCH6PEQYRLb8gKNsPyR5DPZTcMgPzcV1hcD
         zfeGOSDtrUCghMuA69T1v60hg1iOqXYrhcxwNytPemSAmYnS7NQZEh6//1ySsCszDgqM
         6FrnzJQTT7b+FBnIu9lHmSCQdT7Pe3q0OvAbkRT/017vN61nnBObcYh+ZQP4xDqaM610
         SghQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=an+GqkMwWRiWls+VnBZYO7mRYXnOHnpY++0emr944SM=;
        fh=o22x+YlJB85YMf66D8nPiPVLGivwEc6c/9SdpebdfC0=;
        b=XUu7yt225oP4aBf6Aca6W5k/2TJqlg53E3Te0Mj1AQ8atJe0NaLD1k/nco/oQtYhyp
         89UxD6VCc50uSusReQsK1554usuS9IiPsoRSmIh2c+pdGpFYvJe2Q0dqyvvBtfXWlNKV
         SCAjOTf8UsivqGx2rNqvrwQsWzuUe2p7BEq0p/sW5HJ1/E++7aF8oPjAW6hLXsckP9e3
         AAvIbHnDY5miPahjgFsVlfQ3zltFFqUOycDocdvgAeMh1208nQ0KJ1Lrvmgdlq1k5LQO
         R/WHx07k8wmW18S92cQiN057M8hA5Xz/BAtb5YFKoUprVl/qeckIiFbAkwkBpd/w7KIF
         9MHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G2RqhqDT;
       spf=pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-607e7681c00si382976eaf.0.2025.05.06.01.36.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 06 May 2025 01:36:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id B457860EDF;
	Tue,  6 May 2025 08:36:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65BFFC4CEE4;
	Tue,  6 May 2025 08:36:47 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.95)
	(envelope-from <maz@kernel.org>)
	id 1uCDnA-00C97H-GY;
	Tue, 06 May 2025 09:36:45 +0100
Date: Tue, 06 May 2025 09:36:44 +0100
Message-ID: <86h61ygmoz.wl-maz@kernel.org>
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Kees Cook <kees@kernel.org>
Cc: Mostafa Saleh <smostafa@google.com>,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	will@kernel.org,
	oliver.upton@linux.dev,
	broonie@kernel.org,
	catalin.marinas@arm.com,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	dave.hansen@linux.intel.com,
	x86@kernel.org,
	hpa@zytor.com,
	elver@google.com,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	akpm@linux-foundation.org,
	yuzenghui@huawei.com,
	suzuki.poulose@arm.com,
	joey.gouly@arm.com,
	masahiroy@kernel.org,
	nathan@kernel.org,
	nicolas.schier@linux.dev
Subject: Re: [PATCH v2 0/4] KVM: arm64: UBSAN at EL2
In-Reply-To: <202504301131.3C1CBCA8@keescook>
References: <20250430162713.1997569-1-smostafa@google.com>
	<202504301131.3C1CBCA8@keescook>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) SEMI-EPG/1.14.7 (Harue)
 FLIM-LB/1.14.9 (=?UTF-8?B?R29qxY0=?=) APEL-LB/10.8 EasyPG/1.0.0 Emacs/30.1
 (aarch64-unknown-linux-gnu) MULE/6.0 (HANACHIRUSATO)
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: kees@kernel.org, smostafa@google.com, kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org, linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, will@kernel.org, oliver.upton@linux.dev, broonie@kernel.org, catalin.marinas@arm.com, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com, akpm@linux-foundation.org, yuzenghui@huawei.com, suzuki.poulose@arm.com, joey.gouly@arm.com, masahiroy@kernel.org, nathan@kernel.org, nicolas.schier@linux.dev
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=G2RqhqDT;       spf=pass
 (google.com: domain of maz@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

On Wed, 30 Apr 2025 19:32:23 +0100,
Kees Cook <kees@kernel.org> wrote:
> 
> On Wed, Apr 30, 2025 at 04:27:07PM +0000, Mostafa Saleh wrote:
> > Many of the sanitizers the kernel supports are disabled when running
> > in EL2 with nvhe/hvhe/proctected modes, some of those are easier
> > (and makes more sense) to integrate than others.
> > Last year, kCFI support was added in [1]
> > 
> > This patchset adds support for UBSAN in EL2.
> 
> This touches both UBSAN and arm64 -- I'm happy to land this via the
> hardening tree, but I expect the arm64 folks would rather take it via
> their tree. What would people like to have happen?

I don't mind either way, but in any case I'd like a stable branch with
that code so that I can merge it if any conflict occurs in -next.

Alternatively, I can take it via the kvmarm tree, and publish a stable
branch for anyone to pick and resolve conflicts ahead of the merge
window.

Thanks,

	M.

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86h61ygmoz.wl-maz%40kernel.org.
