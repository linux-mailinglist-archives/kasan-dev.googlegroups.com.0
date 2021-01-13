Return-Path: <kasan-dev+bncBDDL3KWR4EBRBWGL7T7QKGQEFF4QQNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BB1EE2F506C
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:54:49 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id b26sf761913oti.17
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:54:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610556888; cv=pass;
        d=google.com; s=arc-20160816;
        b=XhY+Ng30hxmiWzywRrDQUZJa2Yz7uSDKa8I+OtkrCgKeS8yAL9KxegVDKQ0y+jhhHD
         G+xuSoKjuN67mV/mL5zHHe0A8BuEmNS7hsjXyYRdk37t9cP/jUyunuXv0dnAVMFH+w1X
         ysJjUs+U6rRoTIyQEGrk5PxEeg6pNJJrid+6NaFiTYR/oYraVRkfm2rgxIb7SJeTdSdx
         WjO800z1zmfUbMcZL3/3XdeRkkleIfDLYLIRN3olY4mL5aUOSd3xpnzf5eO0kGqVhNJk
         StflyGtaaaDDuu+GszjvbsWJ65B8Nf0kDANayf5+fxLZCUJX+pjwb/tK8w/Nro7VeDTa
         QhEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=yelOUgrrKlYTdj4SxEnPAHtlL4KXinw5VGa0n+2c6yo=;
        b=PL9L1lAM/RaxkDrMNf8KyYGmlrn57joKeUmTDdIiAN1ca7Y1vKju9PNoyGk3DMUxOo
         kNg+xIgFo8tkUtk+RDeDRK1qBsaqTsND3vx988KRMbTA8CkXKtTJbjZXghvsUQKOpFXP
         QDSN0mcBK6fjapq75IDfc5bPza68Ktsed/eDBOPgL3ysZRO4ZXhp5NRe8nkEQsSdR9Ri
         nlq4uYZWXJLjT1sbQU2qU0sFq1itEcitubot3sAOD0G1OKWUdoPSv3ObV402TGGPrs5Q
         ckYXFGU5hWVbedm7SFQztCIp1s/zXJslytuYJi/2ynJq8F1rvCt8x7XCbtmuXLqx/LT9
         QoPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=yelOUgrrKlYTdj4SxEnPAHtlL4KXinw5VGa0n+2c6yo=;
        b=Q0xX8zFMsRSUYiXSc545eabbtPeooH1PzxeJFZgz6bhc1ElY1T+Ibdmvi6MTCcGikh
         UReuBoswcC3+cbgnZ3M51yG9KE8FVP/4EVgiLSPiOiNn10ibQTdD77I0+H3bSsEX3v9t
         ekTKrZQgNZubLKQHe82BHiVI6iDhZwX3aiMbtpVc6zLJVgpOenc3dNt1EspN/gQVvTgA
         bo2f1AjtliunFMz3vZcyufhfuDprn6+JQZy434jSfH9VXsZvB/ILpNab64OIl7kfsURa
         paixpfNEoZIZvk6blyRF0o9DdKNMjJP3bYh2nC+1iMoGn+kE2ardtFrg9J02+QLn7od9
         rb5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=yelOUgrrKlYTdj4SxEnPAHtlL4KXinw5VGa0n+2c6yo=;
        b=TjoBcyWBmkU84DEu54d72dq+8nhTsjRpX8mFXdaFWcvd3xrbshrbrV8I6d3OQEe2VC
         +A4lkScTVHm6Pej8ysBNEeuZU0pu61ckumoXk0jTztHXHu3rACPL0Cw+tpKFcjFXZ6Nu
         W9z65P1Zl4kqRpHMNnHMFchpWXkWLbgpAMMFvEi0h9RKX+rrzNhwT5cjLNOnl7rXQY/F
         fMe7An1zlvPlBjERhfcuKRS8LKEYkpbr2iHEIy3FcQ99RYLRRRNK/uomSFF7QJMgyZTP
         ZXkKOKz2lm+Vh11RbT1ndNWdYhEpd/O1ZFPdwNwXCOIhHl0sU/EMZF4ASSfG0upXb1F1
         nOsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5308uFQa8ee55Ws/88OfE5TwFMLyJ+J5L+E9AXa0dumTSnTqxHVE
	BSzqKr88HnlO2O8PcfsgtBA=
X-Google-Smtp-Source: ABdhPJx3H55oawZOnsmECgXXGZX/TCvDzKJmlUbYu6x1MEJC8uQ8fyusFTW/0x5oCNd2EUZBR/bAqA==
X-Received: by 2002:a05:6830:19da:: with SMTP id p26mr1786225otp.80.1610556888750;
        Wed, 13 Jan 2021 08:54:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2119:: with SMTP id 25ls687763oiz.10.gmail; Wed, 13 Jan
 2021 08:54:48 -0800 (PST)
X-Received: by 2002:aca:51d8:: with SMTP id f207mr133115oib.20.1610556888121;
        Wed, 13 Jan 2021 08:54:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610556888; cv=none;
        d=google.com; s=arc-20160816;
        b=Rx7HSvmvzfrLLvGBc8GK9VhsXBLGVWm+baYxdXfa30X46gz6n2OkOFD/QAKSYq/ZzQ
         h+l57PplflqueSo1Ej+Lw8rYL6ytOMuGYcqOyXObA2txqyMtxmOyzwTwQwh9y1u7Wdpw
         2sMiSx5NNy9QxyjmfzI7k/B9+vAiyxXn+CYn5NpuA0IAYtxqnEdeE9rCbkEM9cBAtcW/
         kP6i6eVU3v+PsrCgMzy4xm5SF3vd8vHKnkHQqpkOTb/hoOHkK0Dh4iiwyOGPq9iY59ME
         MMc5o9IzxyVxQ2vpbPbjECo5BYTbFH2U65RzPGXEtMPAKvetHqypBGofhGjhOF5u5aZS
         KsPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=wpG3dAnEa5sqbvv/+TXx12FWQqczDl06B4JG3AziZpc=;
        b=syKmjSzvrvSX5Wg4r84mayN06AuP2WWn0iVDWXC1f2qjXsdOeLCF9bVUk+07yaNb9l
         RqlwXyPpZ5K93X8FpOknakjGsCwNJ61P1zXqP+Xe6V+qz+2Q2qNat5mips56OqfCxrVj
         Hcw0pNUn5GBvqKr9qZMZVl3DUjVOwYCpPX8gg9y8HUKbTbYB1QSF4+qPtQC7SvrOFo5b
         +kCd+YVElQjOMV2OOU5UDPO0kme4jPSEWMr3QyLqpQ6z0BIBihaFWircG5Vo8L2yrq+t
         9JF6J9doQu5QIVGv+a2f3mQ6shx+tNojkhlwDKgiYM85MKtSo3g3Xg7H+10y34jgrv6u
         Wplg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s126si205153ooa.0.2021.01.13.08.54.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:54:48 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7DC072339D;
	Wed, 13 Jan 2021 16:54:44 +0000 (UTC)
Date: Wed, 13 Jan 2021 16:54:41 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
Message-ID: <20210113165441.GC27045@gaia>
References: <cover.1610553773.git.andreyknvl@google.com>
 <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
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

On Wed, Jan 13, 2021 at 05:03:30PM +0100, Andrey Konovalov wrote:
> As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> while KASAN uses 0xFX format (note the difference in the top 4 bits).
> 
> Fix up the pointer tag before calling kasan_report.
> 
> Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
> Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
> Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/mm/fault.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 3c40da479899..a218f6f2fdc8 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
>  {
>  	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
>  
> +	/* The format of KASAN tags is 0xF<x>. */
> +	addr |= (0xF0UL << MTE_TAG_SHIFT);

Ah, I see, that top 4 bits are zeroed by do_tag_check_fault(). When this
was added, the only tag faults were generated for user addresses.

Anyway, I'd rather fix it in there based on bit 55, something like (only
compile-tested):

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 3c40da479899..2b71079d2d32 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -709,10 +709,11 @@ static int do_tag_check_fault(unsigned long far, unsigned int esr,
 			      struct pt_regs *regs)
 {
 	/*
-	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN for tag
-	 * check faults. Mask them out now so that userspace doesn't see them.
+	 * The architecture specifies that bits 63:60 of FAR_EL1 are UNKNOWN
+	 * for tag check faults. Set them to the corresponding bits in the
+	 * untagged address.
 	 */
-	far &= (1UL << 60) - 1;
+	far = (untagged_addr(far) & ~MTE_TAG_MASK) | (far & MTE_TAG_MASK) ;
 	do_bad_area(far, esr, regs);
 	return 0;
 }

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210113165441.GC27045%40gaia.
