Return-Path: <kasan-dev+bncBC5ZR244WYFRBE5P22ZQMGQEPMUJPYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 716049128FD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 17:09:29 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 3f1490d57ef6-dfedfecada4sf3968238276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2024 08:09:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718982568; cv=pass;
        d=google.com; s=arc-20160816;
        b=jKM4G8h3tlscr5wfcM54AlOG/RA1OQ0rYaaIHr5u6L2QB6xx+abaPIARoVfo1k7m0f
         N3lKr+ljEq8P7UHpmiORmi5I3WalePR14F/IS8sPX5EmHKhIcuQhDjkeGEQ2w2AD0wgQ
         0ytc7mBS6guGie/tzJm78//WzkFS0V1WJ6+G47a7xZN/5vl2sq+UarHN12ujTEU4n+CX
         LB9NFAxOBCQ8Ea61BMmsei0IUW+Rv7dSrD0ZiF1J+TIZgwxhaYvNgh8Tws1I/zi/F7P1
         jD0XLcFUuZuDowmXT7pzFTGFySoZawaG7D5O6Or04/zai2UiV1DtYiJIR7HU6Nz7Y7Hk
         wzvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gyG95BeiBaZlf8vbkAcTsq4xNx6Khk36B9sWf2D4hkw=;
        fh=NBGpv/J5+SAj2wB4CcGlbG17J0x6CQlgUtZhc/6x6Mo=;
        b=O8E/QDHGnGU5xXrl1KwiyZzPXdiI8w+Wpha4pZyFEUuW0G3UtqLRHVk/xihPtXj2Ws
         2g/aqtOk+XxClagMHZ/7jLpoedVL1LSXOScFNlJcGmSHqDcleWG6TRyNHeSTxoZQqMsg
         qHbrzfcvdWZ1K7Q6IhLPoZAUJlOCxgdO/dP6wA2aNzTwU/6sGQeQPLgY2jJ4iLoBJPOA
         rGdPLPFwKkaO8Ugd4ppB0eK96o/VJWs9Z+FtBIrlWhFftgi+au1mOHpVLSrA50aOdN8S
         yAHeDQiYExLSZ2NKJla6m+dREpbrqBlQbKyNGeT/IyYuu8fiWdGV0pdhODwE0bN+XPZI
         mLUg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fQ03HZSo;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718982568; x=1719587368; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gyG95BeiBaZlf8vbkAcTsq4xNx6Khk36B9sWf2D4hkw=;
        b=Xv0E+TzLk8S505TIDBH/WnNUOiG1AeVsGoaAM+kfBasU5YO6CgxKUb759hIXUsgAI3
         5NDHsYT8yGYLcgOcIkAnr/F9fF4qyxy/GvbGh7RUSJD2Y4pLI+fPq9F/b5aFMQt1QpNb
         k5w4neyvgCd2joU/yBpXzZBxeRxkkFqRKvulrMplh4QUgG+2NoZHtPMBceQeiSH9Afi0
         fFZqgqleIyPuOeVD+nmcoYFmLR0xBbRZ/sUzUWYn/NanMf30NCW2qbay5aAO94a32TGp
         /+62BtHvDPs3NgqZm2ChD8oV0AeHal5ZMeSoGGuk6/RoIlLVHilpyYndlqaY7zD3cBv9
         n5TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718982568; x=1719587368;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gyG95BeiBaZlf8vbkAcTsq4xNx6Khk36B9sWf2D4hkw=;
        b=QJSK5QOfPQepRygDUOYOIR8bb1Zo/87K7wj53zXfL3OIiBvp9STH/xHplemeOYhHDc
         9vg9M4SZ6fVkBB+CMHaXBqgBwZ26sWpYu3mDqmn31jLgdgYYf9aKH7l6pkwVAN5S0Zkw
         m6KR7pynW4DgQE/PmscYa+vu2IWeIxpB63HWCar1Fqlnwi5xUhWY1URoBUE0KIBhz9uY
         7idpjHFjsOLx3IfwiqfChGc6gMpQ8jMRedCY9WDeiuyfwxGnOjt+8MlvpQE6dCHs4wo+
         VLKxWaL1ng66GVVtHxXKWhu+zUhGRKxk0pqqxCcao2I0dyL1DIbCPNUf6cMRx0MZvL0h
         5alQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUokwuj5+UQuYAy2eVdekB7Bgnzc9kliqgRrF94vTRK6ecU3xncxRXKg6/W/JBtM5D1C+32v7iiABpeDWS/IR8X+erB8wqx8g==
X-Gm-Message-State: AOJu0YxPcIsb1pit4X3cvssJq34j1yCEcMc0E528TIVhVhZqGXmDrrE6
	pBmkXDmepy8fbA6gqR6xM+cesc0nvQ94InVZqY5xiyRzc2h8Q8/I
X-Google-Smtp-Source: AGHT+IEbmUALCgVlbT6UMSGGy12a4OmwHuCPdhQhPdP8HtuypFm3KGPnTtigjVN7AYS2gGLHTpJG+A==
X-Received: by 2002:a17:90a:a00a:b0:2bf:ea42:d0c3 with SMTP id 98e67ed59e1d1-2c7b5afc1b9mr8356767a91.16.1718982547832;
        Fri, 21 Jun 2024 08:09:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:194a:b0:2c8:1a7f:5bc3 with SMTP id
 98e67ed59e1d1-2c81a7f5cafls546464a91.1.-pod-prod-06-us; Fri, 21 Jun 2024
 08:09:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWSMTX7FLOxksEvRKbxD+dQaZmXADEcmULoN9tISQCBF0ain5XKNuIgMcXxaICBDnrfQ4xcSJOWVXKBLiyrj3f2cTpFcFfP/4b75w==
X-Received: by 2002:a17:90a:a892:b0:2c1:a9a2:fcea with SMTP id 98e67ed59e1d1-2c7b5c900bbmr8217871a91.24.1718982544804;
        Fri, 21 Jun 2024 08:09:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718982544; cv=none;
        d=google.com; s=arc-20160816;
        b=YtGS7s77VoLv89G2kg1r3RimE36xVmP3APXf6uVexOUTdqKsVe1lUBKrTcDkwqBe6n
         hSMCqHuPQPkF/nAR6ckaJd7rnjzbCoAmXqyXOrHaxv/H6pynMLPfzaGFhBEu6mIztIg2
         Cr/AbWe9r07BSEJAZaf5CPJESbUY5DRtwk1Pln43VaWVBUYx7UeQRj3uult2TPlCSLz9
         5JgOnvAQANMBUjCTmCjnU8ME0gOBwAVSd5TnHp8ZnSCxA7XCmRvYfTpCGHjgrRudFruw
         airYWuxO2r74LTAGoYUCUa/3EJ77WLOsdJOM6xO9+g7d4TdHpuAT1kTHJ5mnGFlSaLGS
         qtZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gARpTxiAVnDgQapmNcRYTahDxZXG9wxyA8wc6PSSB8o=;
        fh=Rd0eMmseSGMPh9TTSECG001hqBGCl4V7ITo+N5A6yGE=;
        b=cqTAWVt2H9l/qBEJBlLSNn/MK2OiBOSgHdxgIYm0D1uaWVDDJ5/1zzqhnH49oEfJf4
         hmmwaJpV17g+x4gS/HPEtvy1qlEub2jnL8qh3H/LAF1aOc/kM9TGWewh/jQ/3tQUMZGN
         o4Y/DkOmeNCI5eN7mqm2C5mnYWbQdpbtrj0Ad1ynoE5E2nH1n4FahKeqeBgVZ8Npqx2W
         z8sdW7vQpUF9AicHNUOgrgYNuOklP0YumiZEZCrp0T8FVRgPAJnOPvvuqSRXY1gFQn+E
         yfUTxQmAp29cYoC/8qt9DRJeowfIlMFtEZK5DXGCiVtAEnyNGP4pBhGvAKbXI70EEtNO
         g1GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fQ03HZSo;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.15])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c819dee8d7si73726a91.0.2024.06.21.08.09.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 21 Jun 2024 08:09:04 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.198.163.15;
X-CSE-ConnectionGUID: DTfG4RrZSfecMjLfGVUJ2g==
X-CSE-MsgGUID: AunlguhESSSmXPP1UbufLQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11110"; a="16165394"
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="16165394"
Received: from fmviesa003.fm.intel.com ([10.60.135.143])
  by fmvoesa109.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 21 Jun 2024 08:09:04 -0700
X-CSE-ConnectionGUID: YbU7dMI6RI+u4QDHK8umag==
X-CSE-MsgGUID: ZklpEeAzTBiJdOjc2iQKEg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.08,255,1712646000"; 
   d="scan'208";a="46976933"
Received: from black.fi.intel.com ([10.237.72.28])
  by fmviesa003.fm.intel.com with ESMTP; 21 Jun 2024 08:09:02 -0700
Received: by black.fi.intel.com (Postfix, from userid 1000)
	id 9E8421D6; Fri, 21 Jun 2024 18:09:00 +0300 (EEST)
Date: Fri, 21 Jun 2024 18:09:00 +0300
From: "Kirill A . Shutemov" <kirill.shutemov@linux.intel.com>
To: Alexander Potapenko <glider@google.com>
Cc: elver@google.com, dvyukov@google.com, dave.hansen@linux.intel.com, 
	peterz@infradead.org, akpm@linux-foundation.org, x86@kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH 3/3] x86/traps: fix an objtool warning in handle_bug()
Message-ID: <l3fpuot4mubvhlr2zmioc7rzz3akk2fafptfdwmcmwphyisan7@7mojjgo5ovae>
References: <20240621094901.1360454-1-glider@google.com>
 <20240621094901.1360454-3-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240621094901.1360454-3-glider@google.com>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fQ03HZSo;       spf=none
 (google.com: linux.intel.com does not designate permitted sender hosts)
 smtp.mailfrom=kirill.shutemov@linux.intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Jun 21, 2024 at 11:49:01AM +0200, Alexander Potapenko wrote:
> Because handle_bug() is a noinstr function, call to
> kmsan_unpoison_entry_regs() should be happening within the
> instrumentation_begin()/instrumentation_end() region.
> 
> Fortunately, the same noinstr annotation lets us dereference @regs
> in handle_bug() without unpoisoning them, so we don't have to move the
> `is_valid_bugaddr(regs->ip)` check below instrumentation_begin().

Imperative mood, please. And capitalize "fix" in the subject.

https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git/tree/Documentation/process/maintainer-tip.rst#n134
> 
> Reported-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>
> Link: https://groups.google.com/g/kasan-dev/c/ZBiGzZL36-I/m/WtNuKqP9EQAJ
> Signed-off-by: Alexander Potapenko <glider@google.com>

Otherwise, looks good.

Reviewed-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/l3fpuot4mubvhlr2zmioc7rzz3akk2fafptfdwmcmwphyisan7%407mojjgo5ovae.
