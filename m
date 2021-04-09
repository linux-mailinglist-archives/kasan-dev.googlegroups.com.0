Return-Path: <kasan-dev+bncBDDL3KWR4EBRBJUOYKBQMGQEC6SJ3SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C6E635A418
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Apr 2021 18:56:07 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id x11sf3698501qki.22
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Apr 2021 09:56:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617987366; cv=pass;
        d=google.com; s=arc-20160816;
        b=AJwVu0c2ghiKqfZ8qwaWRcT4TM7bLZlSgZSd/CBfALvVB/S7s8n9kHqiLUg32nTli4
         m+7kVHKHoY2VoAbX6DC5bct/0Jka6+W8AcBJFfKBYyTiSHuI0bw6eU0feQ0Id+Zwx0+r
         cvi60ebTXaDoL5BLoEUVjuG7cgPGVPXKmjHnhgKOIwzabB2UvDblZxgCgtPtr5oeFQiS
         oGIjuUiRPc7Asfy0Eqgfijoqv8ZWMRsZecxbFcfPkjFw2vvFWlKaNSDQlWvFTDkT8sZQ
         zFzVyRqYPlUM+ei2oodzASp1lNYn54p4IqrywThqCCet3FDeRzFM9CvuvojtdGmul5Jf
         xWvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8keGZEpyIWfCaYUNr42do9wLVNo5C/jcUpt3htSNGzQ=;
        b=aHUZCfF1E/GbY19RJ6Feof8FecVN9Sc/vC5JjHcfvMRS3R27SLPXsLIQKSlPXheD2+
         TeGNn9iwyaHLjiVt0s7YzBcBdk6ndBDDN0GRWcwrsOw5BnFbB0NJeUzuWmUJMTcGLL92
         cRnyEtfwEZGwcFGiVSzA1Bl/FztEin6rE9lZFwweVKjHslsgmSiFeqxtpjs7rqefzT6N
         zwupBUmVZ3w+lOa/Nmpg1PM3JZS9DKCxWtlUhuJ3RUHtHmg2Sish2GV5N9ylLjCC5B5K
         WxkbllTpKnnobRLdxyrTFqG8CR/PCPs4HRUBto5nOqBNeAp30rKxSovGPLm2JyDc9Sca
         X/mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8keGZEpyIWfCaYUNr42do9wLVNo5C/jcUpt3htSNGzQ=;
        b=GGNA7jjv+GwySk2HJHgyJkNHKpTmutZfMjZJfXxp8K4ja/pFpN1sQn38M7eVltyuOx
         BMdqiUZMuwFb1FfWpKrWua54Jcr/R5fS3lYHkTArGBZI/pUPJH3FQCmPQAsVKB+3+vRI
         8jIiyO40XEY5lrstuxnHV6pKqyaZEKVl+vIG+bFfUPv+AnwOmpE9PgNU1TgCR7V7D2Yg
         G6G0OVlYtWhXzj0JfIe8AKen5tvMd99GwwkvhCbvfDtVPnrOs4bhNBKE/PZaFYsNhf7k
         MSj4fiuxW4cwW+ppZnBbUgvWSeB1v7ZDxrrALyTGUawsM/P2xnx/1aSRlemNfnrZO4Oo
         VFCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8keGZEpyIWfCaYUNr42do9wLVNo5C/jcUpt3htSNGzQ=;
        b=KaJiiPAWLVfXYQHEOaBnzwyPNbiSLJKl7GzlfxWFjQop8kLFdz/ug5btkd0FL2SCr5
         lesTot7cmVgGhUlPzQUHvfiUy02NSrTYYJ3lqbA+M0vGDVELWhc6LiAJVpCIsHZKLzNs
         8tGXy3UoCwe7sh4JGfUrNVLdC1/WTPBM3bLCbiqH3wyHJ0H7TbT/imJOysCq8NQvrJpa
         lGxtIjve8kQzgc92ki4PhONqTCt9dgi/oI3S058Zh0yyQ/SbFVVS0jgWk7Qzyi7Ep3zX
         dCz/+FjKqwd8qCwGK0VtJ+vnpy/yF8ppznQ2Db4wzyfX5i7hFazSK2Ab8Oo1YTkg0ofJ
         MW2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bnEcAjbfffneTEpT0PINZrXxs0VtIpzojJ9Ax3uYKoZUDPHjj
	d6fVzBUoEAgrHaIK7tGvDP0=
X-Google-Smtp-Source: ABdhPJxYYYiK9n8Ar5YC9iKlyD4zMO/yAj1EQ9RG+r7x4MSr6IILNYNi2xziEEskQhv6KPwMQNpknw==
X-Received: by 2002:a05:620a:16a1:: with SMTP id s1mr6556599qkj.109.1617987366731;
        Fri, 09 Apr 2021 09:56:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fc09:: with SMTP id z9ls2724522qvo.4.gmail; Fri, 09 Apr
 2021 09:56:06 -0700 (PDT)
X-Received: by 2002:a05:6214:dcf:: with SMTP id 15mr15152581qvt.28.1617987366333;
        Fri, 09 Apr 2021 09:56:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617987366; cv=none;
        d=google.com; s=arc-20160816;
        b=XidRaZj3VVsLevXMI5btlnIWiSE5f8a3KMwY2MocLWvOmCAGJB7f8HJVozGKkJ3TmW
         Qo33it20SIbXGDi0AoHg7FvoSIqCJ++D8OQ7I8B97ye00M95DtG+I067xkgp0B8Baq6B
         hFVYg4SikPjnKvWmSoahNVNf3bXwtzDXmC3XDRjWfqQuxjj2ufXTlB8yxbLPumlT1R7Y
         qRNM8q/4uSWOaoNk3ewlQB/gbfYagXb7D8AB31Km2KR/0welcqDErag1VXcuM6iiD0TY
         w6Pjy2486nMxNvNjXMNl2U+mmzXwT+6raus3brhazrCyto9334ve9s/gTE18rENHBSuT
         d8RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=NYmt+HOlCvRYg6jL6VbjogYBYrcTiq8Xzb5tJM6LQ/g=;
        b=LLwCxDoTEGmUSS06yzs4IEuQ4j0nGybTfYHCsiO4OxtT7CC0ylgjCZq4QuuEB2qqwv
         R1mp8OcJM0ZB2GHm77dbpSZLZ9DRLAyqKXHnpB9XpunPwCwQSQsEOxLVbXmnPkxcIQVn
         e+ws/KejVTUIsNX+gwDLbDxHGH2JpKY2Sl4BgRGxyYddSbPw9Slv42FGJJoquujBtf7H
         U/I88idjPetfYGNhHvWDJZoyC+IfoRPsGc+knuWyi9RwX79TqMnwEk7cY3k6/eUn5NDB
         MZ0ghH5e4LA/im2m8gQA0SWA2XEX0ATpKNzCOkuixJC71B6p7ka+TW/Q5dep2hlcxROg
         FcsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r24si375629qtp.1.2021.04.09.09.56.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Apr 2021 09:56:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1E8A8610CA;
	Fri,  9 Apr 2021 16:56:03 +0000 (UTC)
Date: Fri, 9 Apr 2021 17:56:01 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
	stable@vger.kernel.org
Subject: Re: [PATCH v3] arm64: mte: Move MTE TCF0 check in entry-common
Message-ID: <20210409165601.GE24031@arm.com>
References: <20210409132419.29965-1-vincenzo.frascino@arm.com>
 <20210409143247.GA58461@C02TD0UTHF1T.local>
 <20210409161030.GA60611@C02TD0UTHF1T.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210409161030.GA60611@C02TD0UTHF1T.local>
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

On Fri, Apr 09, 2021 at 05:18:45PM +0100, Mark Rutland wrote:
> On Fri, Apr 09, 2021 at 03:32:47PM +0100, Mark Rutland wrote:
> > Hi Vincenzo,
> > 
> > On Fri, Apr 09, 2021 at 02:24:19PM +0100, Vincenzo Frascino wrote:
> > > The check_mte_async_tcf macro sets the TIF flag non-atomically. This can
> > > race with another CPU doing a set_tsk_thread_flag() and all the other flags
> > > can be lost in the process.
> > > 
> > > Move the tcf0 check to enter_from_user_mode() and clear tcf0 in
> > > exit_to_user_mode() to address the problem.
> > > 
> > > Note: Moving the check in entry-common allows to use set_thread_flag()
> > > which is safe.
> 
> I've dug into this a bit more, and as set_thread_flag() calls some
> potentially-instrumented helpers I don't think this is safe after all
> (as e.g. those might cause an EL1 exception and clobber the ESR/FAR/etc
> before the EL0 exception handler reads it).
> 
> Making that watertight is pretty hairy, as we either need to open-code
> set_thread_flag() or go rework a load of core code. If we can use STSET
> in the entry asm that'd be simpler, otherwise we'll need something more
> involved.

I hacked this up quickly:

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 9b4d629f7628..25efe83d68a4 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -1646,6 +1646,7 @@ config ARM64_AS_HAS_MTE
 config ARM64_MTE
 	bool "Memory Tagging Extension support"
 	default y
+	depends on ARM64_LSE_ATOMICS
 	depends on ARM64_AS_HAS_MTE && ARM64_TAGGED_ADDR_ABI
 	depends on AS_HAS_ARMV8_5
 	# Required for tag checking in the uaccess routines
diff --git a/arch/arm64/kernel/entry.S b/arch/arm64/kernel/entry.S
index a45b4ebbfe7d..ad29892f2974 100644
--- a/arch/arm64/kernel/entry.S
+++ b/arch/arm64/kernel/entry.S
@@ -148,16 +148,18 @@ alternative_cb_end
 	.endm
 
 	/* Check for MTE asynchronous tag check faults */
-	.macro check_mte_async_tcf, flgs, tmp
+	.macro check_mte_async_tcf, tmp, ti_flags
 #ifdef CONFIG_ARM64_MTE
+	.arch_extension lse
 alternative_if_not ARM64_MTE
 	b	1f
 alternative_else_nop_endif
 	mrs_s	\tmp, SYS_TFSRE0_EL1
 	tbz	\tmp, #SYS_TFSR_EL1_TF0_SHIFT, 1f
 	/* Asynchronous TCF occurred for TTBR0 access, set the TI flag */
-	orr	\flgs, \flgs, #_TIF_MTE_ASYNC_FAULT
-	str	\flgs, [tsk, #TSK_TI_FLAGS]
+	mov	\tmp, #_TIF_MTE_ASYNC_FAULT
+	add	\ti_flags, tsk, #TSK_TI_FLAGS
+	stset	\tmp, [\ti_flags]
 	msr_s	SYS_TFSRE0_EL1, xzr
 1:
 #endif
@@ -244,7 +246,7 @@ alternative_else_nop_endif
 	disable_step_tsk x19, x20
 
 	/* Check for asynchronous tag check faults in user space */
-	check_mte_async_tcf x19, x22
+	check_mte_async_tcf x22, x23
 	apply_ssbd 1, x22, x23
 
 	ptrauth_keys_install_kernel tsk, x20, x22, x23

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210409165601.GE24031%40arm.com.
