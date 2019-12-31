Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB5XWVTYAKGQEVVMCXNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id D26DD12D88C
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Dec 2019 13:13:42 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id be8sf6612770edb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Dec 2019 04:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577794422; cv=pass;
        d=google.com; s=arc-20160816;
        b=LTFYxPUgyM03h3s5nA2s0bGcJMqSZEiIVh/EArKHO8xYKx6NpuCjJtD8Ma+GlHkd8Z
         xjcJ0oW5PfwD3QOy2hfhpjUyKC6mPk95zZ06z21VSU1gwHD/pycjXoTOzH1aFy9lGfMC
         gXhnHJUyOZ/Bm+Sfz+7/6tiJUnj3sfastd+nahyO9HB3IuzHzQ0YlroVEoZS89I6K40D
         06nIL/1acGSziAR93MG/4Bkq0dy4Mtpl2Wox7c1ulJ0QJjLJOaR8pL2l+CExP/Gvj2P2
         vmRZ2uWA/Q6qGHV0PKfDYfvjOneb9lppBcTZ0mtuCa0hQD/dT7Tpv2hGAuufLPWKpB8X
         mezw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=dK9SD15rya9sLJQj9yEnDaFhOOsI319Z0kVPZi1sSPA=;
        b=a92Y+32DaQGi+7uvDiVn+khXM+KSH3NTewPNTw2TRj6mDFNKx5qS+qvDgpS75gXIKo
         BSTaFn3qUgazQGOju4Za5vdfPXxAmXMht88h9qeBo68EFODV54oiMD/cgwMun7vfWCii
         Vcm+oBbnrSsMa4sjZMvprHofbEGNsgXQadZyrzyxxXSkku3dr7A31TC/ztFNK1xvQNGs
         C7onoK4pI6R8rNMub+XeA6kOOdFFx5DJaT9y78f4uKaNEeOJ8Yh3JtJlldXtjG0OZ/Vt
         +SsY6ecyXGo4qt6JWXPyvobiWeEabkHwXoypEo6QaKdfz/aDaYj+vbIHCt793FtaPT7l
         WubA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=L1M0d2Mf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dK9SD15rya9sLJQj9yEnDaFhOOsI319Z0kVPZi1sSPA=;
        b=nuqK5QS1vkCYX1M3Om7fAGzRHst8bvgE96QnCf79S3O1UXXfvxZojscICMTxoteNHE
         0zyBBl2DLQtysjdKv1MY6L2iZjhkebttF4ySQ1fvFXIHOF3YfEkg1vAYfWcp4hRd5gyv
         QxyHqMtLGZz9TJetB5xDAfTi8PVZCJhjsLu6Vtd/xlIO8HhxnrD8HF2HSUfhTl/Uv4XL
         MNtaER+WI67PLJpkivGkTp7+gj1Q9M4aBenqb0wlEe3M3IkATew7ARPiZ/jyyziVJXVn
         tcs94TAsMpaJz3n5zgnNQ+PFK97BaHWFIVxkeSntpWiHCfU2bg2+PenMMgqERF44PIFS
         nCJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=dK9SD15rya9sLJQj9yEnDaFhOOsI319Z0kVPZi1sSPA=;
        b=FCZpxmDDA99h32EyW4fga4HzuWWEu72Qbt+fgL6NtSzbToNfZN2OyqD9JCAZWMRcri
         kBejFyqBDp3VqC3Bu9gMA78yplBNLNlUrTcn4x8OfcDxeKL6MP0rrLELnEGGYGisP1kk
         hPvfMiWBENdcHjntGqh7a+kWJWoVSYawIAV3eezbYT2EeuHC3BkQDWC4znXf5uiGwNl7
         jjnEWQIFFOhRNma+A8xKkMcPemEhFLfuuRUtio8YXM9ozpKALIp9k3UIEjfAsV1uVa7H
         xbwqdljMpPEFHF1k/GgnCpTjK2EaHeBLoG5fkU+8vdqKhfVRCXHS3fwyquaJG7Zg95cH
         Ryng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUVaBIQBbmMZB1FVBSq85KqNTc2EfrdagWOtkYdERJUuz8qUmrM
	CS2Q6YrOTSYq2yb0O4tHCQ8=
X-Google-Smtp-Source: APXvYqxBkEI18VB0Ed142sG6EeFQdykybdd8C0l+1Nx7PgegjVLALCPheCQGSFDZS7uxWFb/BBu3/Q==
X-Received: by 2002:a17:906:bcf5:: with SMTP id op21mr74555247ejb.160.1577794422444;
        Tue, 31 Dec 2019 04:13:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1f97:: with SMTP id t23ls11421691ejr.11.gmail; Tue,
 31 Dec 2019 04:13:41 -0800 (PST)
X-Received: by 2002:a17:906:3793:: with SMTP id n19mr75000808ejc.85.1577794421633;
        Tue, 31 Dec 2019 04:13:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577794421; cv=none;
        d=google.com; s=arc-20160816;
        b=EYcYecX/EbvBuztvdlVYj9uMnvySqZysRaBzul5o9qR5xKwUjx4FzjTkCnXOcwOyrn
         cJ+4rBarYtJH2Ctblpl7u9jwP6llnczIcUBUMCu9T7h7IKnU6tOfgtYBNDtTcQ4lsLJF
         crRwExES+SRQH44WY11w5O7vKQwwsYYeVcdJb/jvlMdvM2bdq8SJqYXTXZhFPuXoLLAq
         HUG3HZrfQ+M9QjmK/rSqnEiYcp1aLd+i/7nBinBDuz9vIWbfYBo5os7SA9DjZNmzahQk
         ildFYubR8tT9mN3fonZCPXYMF+hPD7CbP66VATUUiGV0jwz3cWpW8UG0JEVD2uFM1v5g
         kfLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=oR2xbj0U/pPGMoJ8gZOuKTnC6YknArbdAxhM7IvzOgI=;
        b=G2bUXAAAOxbQ25NwAX3szLSm9mnn2THrWLmPqVtsOBlwZNUODU2HMs5r6LJIBoCzcf
         T9VyB0ygeMo8XBLG9g+tgN3CG2WyBf1L4w1qq8/bh3ILiEGO5Vq7Fi54RQe7kciEN+Ma
         ckZHsrwrIgNfkOd84gihWkat9borhTie+akBO4GHPivXBWD6ScZ8FTIT5MviZo1cZDVD
         cY9eo1ksyOFQPPw/i+vWGqETwKKjdvql8xnQ7FVgszCyrOyo189lS93tVE8PjFCiT3Y5
         uKZl1kaH2UbRPbVDpi9XyVGF9GNTCKklhSuRvFd2OFrOWgLGPsE8AMb5+A8AONmE1ZTo
         114g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=L1M0d2Mf;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id cc24si1641373edb.5.2019.12.31.04.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Dec 2019 04:13:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p4FED3FEE.dip0.t-ipconnect.de [79.237.63.238])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id C266E1EC0216;
	Tue, 31 Dec 2019 13:13:40 +0100 (CET)
Date: Tue, 31 Dec 2019 13:11:21 +0100
From: Borislav Petkov <bp@alien8.de>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: Re: [PATCH v7 3/4] x86/dumpstack: Introduce die_addr() for die()
 with #GP fault address
Message-ID: <20191231121121.GA13549@zn.tnic>
References: <20191218231150.12139-1-jannh@google.com>
 <20191218231150.12139-3-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191218231150.12139-3-jannh@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=L1M0d2Mf;       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

On Thu, Dec 19, 2019 at 12:11:49AM +0100, Jann Horn wrote:
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index c8b4ae6aed5b..4c691bb9e0d9 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -621,7 +621,10 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  				 "maybe for address",
>  				 gp_addr);

 
> -		die(desc, regs, error_code);

I've added here:

                /*
                 * KASAN is interested only in the non-canonical case, clear it
                 * otherwise.
                 */

> +		if (hint != GP_NON_CANONICAL)
> +			gp_addr = 0;


otherwise you have:

	if (hint != GP_NO_HINT)
		...

	if (hint != GP_NON_CANONICAL)
		...

which is kinda confusing at a first glance and one has to follow the
code into die_addr() to figure out the usage of the address argument.

Thx.

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191231121121.GA13549%40zn.tnic.
