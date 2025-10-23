Return-Path: <kasan-dev+bncBD4NDKWHQYDRBUHH5LDQMGQEQUFG2DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id C43D2C03BC3
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 01:01:38 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-430ce62d138sf19930075ab.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 16:01:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761260497; cv=pass;
        d=google.com; s=arc-20240605;
        b=j/y4ibVZXUJFjeWfiLbJIg23fwnZEiatfrI+fcNfB8MBEcduOcxHmgRwPJhmrLi1kd
         QHnHzrW+DPqelvSdCrWXUmJ7x27eyoekJKV9IMHDZzx2dFKTuVyAkaEC9ZnP8bpV6GPh
         LFDuTHlWUYyHfz/jjPEbcE0QKHOXIYcLv5O7zBtc8oUEOQrag2Ln0AwbZKdpSdSzrmLy
         qMFHQPwZisR2JUBQZVkFTVOtN7EpBCdnxAsq5LHDzcD0Z7Q7k8nW6Jm+zDtLvMBbIcBF
         No+MLp3K1stvGTcWehTqqbZmMsAGRvFCUkE5nQKX/TYWw4i6o5hLdX7NGk36znMCh6Ae
         xRYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=xV8AHjfesBy+3BIlvd61ydMZAaO9Nr+mfurOKh1evkA=;
        fh=gm5m1QRlgmTrjoosUOrMhH26lgmaL7sgfmyTKD+7mRE=;
        b=bm0wrmQcsrEIP+9R2SESRMIpywcpU3mLOtCfswF9ujJ0zmGMYt5a02FzXylHD/ehh7
         6L/veuxqsfGTrdHMHi0ZCQ1+WsQ/lgZmlveFugocbOdnPJy5309A7pXgm++TDY+zaStc
         6TXLHgiU/TTqDWPfFLLL1z80H3Pzs5LnjOzP+Js/POk6bhUoXuax/o9fhsR3la3wZTL2
         20oUQqdzlmkORTPY07evUHVbBEVF+cFtxQ2nhsrOFmmLM6bKniVEPsC54WWG8hE0TCCd
         zNr7wVOX52y5ZGq5bTp8jDYMrBAPirdogjqphHKbbClei2naBJLr/pFEljjl4Fa6kFln
         OQmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gjmvcGOS;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761260497; x=1761865297; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=xV8AHjfesBy+3BIlvd61ydMZAaO9Nr+mfurOKh1evkA=;
        b=PKGL19GiAntMy1jsI9Q6XcCjMTPv0P/veX1m0OcsIP+iG5AfeI5UNmJnf3bMmjZPIx
         3QiGaa/pSPg3C5jC5C84nmGEvybyR2DrmRtVaWUo8kaBTCvcSnFnlZXwItop8fHDyCQg
         Qyu4j2gZPCcggXVp6BOnCpP1iWBXz4/thgV05bB9qQJ/VeCouYMpKOVGuvmP4hrkPeF7
         KjdXN2niHwIqk7yWJy+Gvy53iB4E39zBcUyS6S8wKPv17J89QCulUW+JAyG8Q2slZSEs
         ixNv2AG1++t7+WNBJHp+3PXabbOcBVRTk8DvO7VipnDsuryAh1mnN6tSBnuFJjCjeSk+
         WXKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761260497; x=1761865297;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xV8AHjfesBy+3BIlvd61ydMZAaO9Nr+mfurOKh1evkA=;
        b=pDoQFAxU1VN8x/2HRdTr257zFJ4S4d1UUdxWxzd/ej3Nv+4SQ0sdMp9rQjgD1joYSX
         lUpTVRrbywKf53gpjHmo+9TrwLIx9lWtmWWbdmKlU6gV/9NBdK9VGWrLCMcFAUaU/yjw
         +RUgbOS31C63TF39J1zCMnGK3Sn2xvnTTeBLkKMlH2W75X3rbwENFuDRvquebcm0fFtC
         GNbKNag2GZzrf+lI4kHPEkay9tuRaxsAeAOYOy5KWwLG8/06VgrnNpb0haJx8Z/uqb2X
         O7xMKMZ7GUK0i8UxC3Ar8ZjkoPjl25iLcauhpmIIxuUji1Xj68VkG1sJRKwJMjNFNhtK
         nT7w==
X-Forwarded-Encrypted: i=2; AJvYcCVTyi1T1dR2ulDVBQxNdyZhbNBlp+dllZCce/r3rPUYxE3fEF+q0ONdf017eSe1pA26i21rJw==@lfdr.de
X-Gm-Message-State: AOJu0YwmBaIUkS9Lkys4Wrp/f0myrvjjDA0M66rhv9YIoBa83RHnK9kH
	w7CV4pn3y21Ky5sCr8gxyv3RsKYQ+UYwQnDpRmRU0QGbDWmru/fmK39W
X-Google-Smtp-Source: AGHT+IE0ZzdrzaoUc7cPx2jnFOSOoBdVAGBw7iKncQqDCOnjatr8X65iiYxkSooDqoLDlWvpjPNrJA==
X-Received: by 2002:a05:6e02:1947:b0:42d:8bc6:d163 with SMTP id e9e14a558f8ab-430c522f3a6mr350079545ab.9.1761260496750;
        Thu, 23 Oct 2025 16:01:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bx52wLhZqUXTV25L1I8zCCCbPIgitWmH7D/kJIXN5pFg=="
Received: by 2002:a05:6e02:3993:b0:42f:896f:764f with SMTP id
 e9e14a558f8ab-431dc1cf790ls11801465ab.1.-pod-prod-07-us; Thu, 23 Oct 2025
 16:01:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW3KEyXon+OYrjW29OgrZWnvr1OV1Av7NiDvuGPQX0fEa1/kdCWglNEdXNQaAVxwjGWBkGvfGdLaMc=@googlegroups.com
X-Received: by 2002:a05:6e02:2708:b0:430:adcb:b38d with SMTP id e9e14a558f8ab-430c528dbdbmr293818025ab.24.1761260495700;
        Thu, 23 Oct 2025 16:01:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761260495; cv=none;
        d=google.com; s=arc-20240605;
        b=RQtDM+6yy15h7DuH2gszhb/0CMlrsnTv8Ytk25KtfwBXtfbk+9Q3P8J8Lll4CCh9se
         URtM8HWDjFm1qGt1KD5lwnxsVgBTdD3BgPgZsPuOUMGYgV29vqOUQKm1bSesE/Fvs9FE
         JSsH/dxHeSZR/NEogBaZh5tiIbcY4szH32XJ/IbfwRh5ZFJXVvkBMSpwibCQHSe1uPvv
         WFy7jnRA/V05lFi+UBWDl8TKxrj0PjTCxxtHmebr3s0EpeQTaR2miAkZj0pqlxWaWAem
         gM08KAvyqiLwosZtxFcNW3mKIVThCSxjhy1127JXldvmIvwvHhIxFDBlw6iNL19XO5o0
         ihCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gT2hfaa3//lm9kEw/X4XhVSMx6jZjQQ10cjw/bqRIis=;
        fh=zS2GcnCo4KuOHOX5RpxRdacTAeJDaGOm2WTZjX7SXvk=;
        b=dK38KavcMTE8ea9RKEDnoV3AC1oqVzmlqWDnl1loerYSIl7DcpUOpG2Mq+tujkHJLO
         0Dx6qRCuOqOg49Q46Krc8+QCdGt79GbWotUSkMYXwBGM83oSF/AwXBzmR/2ZK2ohfq6t
         zQoyko4o3zTZe51VAZJf6XbUVsk+IE8UBDyfWPybfyKw4SVrQEeq4JYOhz0aPoASNCdl
         uSTBmHUrUYWKtCOiH2yJpsNVlHB3oHUs+XOjzDg5mmKxHm8udsmX8B5OFEZxVYT+pdSB
         CPD8RMc3/IrTX/LQ/Ca9hxBDc1b8xuGme1KbHBgEx1tkoSJD4GneW+wxmtBbifXUMY4n
         Xwow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=gjmvcGOS;
       spf=pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5abb82d1c03si143900173.6.2025.10.23.16.01.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 16:01:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 0E5F443652;
	Thu, 23 Oct 2025 23:01:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8C5BC4CEE7;
	Thu, 23 Oct 2025 23:01:32 +0000 (UTC)
Date: Fri, 24 Oct 2025 00:01:30 +0100
From: "'Nathan Chancellor' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: Nicolas Schier <nsc@kernel.org>, Kees Cook <kees@kernel.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev, kernel test robot <lkp@intel.com>
Subject: Re: [PATCH] KMSAN: Restore dynamic check for
 '-fsanitize=kernel-memory'
Message-ID: <20251023230130.GA3006010@ax162>
References: <20251023-fix-kmsan-check-s390-clang-v1-1-4e6df477a4cc@kernel.org>
 <176126007537.2563454.16050415911756189258.b4-ty@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <176126007537.2563454.16050415911756189258.b4-ty@kernel.org>
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=gjmvcGOS;       spf=pass
 (google.com: domain of nathan@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Nathan Chancellor <nathan@kernel.org>
Reply-To: Nathan Chancellor <nathan@kernel.org>
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

On Thu, Oct 23, 2025 at 11:54:35PM +0100, Nathan Chancellor wrote:
> On Thu, 23 Oct 2025 21:01:29 +0200, Nathan Chancellor wrote:
> > Commit 5ff8c11775c7 ("KMSAN: Remove tautological checks") changed
> > CONFIG_HAVE_KMSAN_COMPILER from a dynamic check for
> > '-fsanitize=kernel-memory' to just being true for CONFIG_CC_IS_CLANG.
> > This missed the fact that not all architectures supported
> > '-fsanitize=kernel-memory' at the same time. For example, SystemZ / s390
> > gained support for KMSAN in clang-18 [1], so builds with clang-15
> > through clang-17 can select KMSAN but they error with:
> > 
> > [...]
> 
> Applied, thanks!
> 
> [1/1] KMSAN: Restore dynamic check for '-fsanitize=kernel-memory'
>       https://git.kernel.org/kbuild/c/a16758f0142ab

Whoops, sent the applied message for the wrong change... This is going
to be in kbuild-fixes as https://git.kernel.org/kbuild/c/3423b2866797c
for -next testing but I will adjust it for any tags I receive in the
next few days.

Cheers,
Nathan

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023230130.GA3006010%40ax162.
