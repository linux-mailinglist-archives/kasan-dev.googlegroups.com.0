Return-Path: <kasan-dev+bncBCT4XGV33UIBBBFW2C7QMGQEZ6E56UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AFEAA7EA83
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Apr 2025 20:35:50 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6e8feffbe08sf119512016d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Apr 2025 11:35:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744050949; cv=pass;
        d=google.com; s=arc-20240605;
        b=PPE5SVAmTr+IGkrhiejJRNggZrgVncrzQ2EIoCcvDqv5r4KQU4myelQAPjIecNbL9N
         JtkGmFqs1dozM4IAGz5qeB+XhJ1zD1ekcOBDRslYgLxfrp6yk0ON6+3nxNqz04En7Ids
         bqQRdngiatTq7DZfm8TFNw+IfeNKh1v8t9RXnB0X7MoN9G/jwuH3Ye9srYho0C5AAPZo
         AVF5rxw+dMcvarTKWmtF3bQKt+fRH4YNb3bpeoHmPzSPEno1nciQHC7W8Jm+q/fDKCHg
         ZQ3nzIcs916nCMporj3zuTceLZhEno9hPgbmBCdB6KitMyYL3cyXDVzQcUY2wXQXpF5u
         zK4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=3iGvcdl/QVlSrU/CvPbmKqqoUCaSxxlRUaDOWa5Wn/g=;
        fh=338qfaciOFr1DcBoxx3zH9L/OCw1eIUx76mkKlnAI/s=;
        b=RCKZC6fS4anqChWA3/1OeZA6cnuMJM+U27UV13NnoNifCOtSbfIBLU6jPTwYOdJXSy
         TRFh5jCfIHOBRA4CnbYG6EYRv9rjwl89pD4TmSk3UslHVE1uD6u9ZNm/o7r/eG7LehhH
         +ycGtExpcb0rzCGcYo24TiSdD9vtXvngU24mZi+V8WoBj7+bnqF+Le05Rp86SIv1GxDW
         z8/VX5NvHRaoIbsYgBbCJzpUzo/g+foo35qt2p+sh8sL0njrTxDXptttvgGxPll2vsd/
         OTIGzdunBW1Vn5SBFxgJ7bt8x6d2OidHHDSDuFL5CU4iPnV+b40HkYCzFLHkN5hY1uIe
         4MFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="kwvaeD/a";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744050949; x=1744655749; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3iGvcdl/QVlSrU/CvPbmKqqoUCaSxxlRUaDOWa5Wn/g=;
        b=x2KcfO8gU7uKDSVtN13VINPipWEofdXOyCXHfwokGXGHx31yEMwnFAsCwZVYMYbUHe
         wnPnyA5+Dqc8zQaGRVu89gArGtJDWPMgtWjrYA1s7r0Pcr6AdZuRnrP8SdGDLacRCgoc
         PN3GQO7cScDPqV79kzBac2d2VVLjS8wyKJeo7A/t/AzRe4kbHV8sWeVlrTcjX4jFVCYG
         IdZ+CZLoQgLnb99KY6hiP4s2akbNUHIPpqHZyMlq/qMuCl24gt4w1KN/bSfq6YgnpOjB
         vPhVUKyM1dDiz+oWJ+PAMDNwar4ZY2Vk8nvJNpAMZCde6Vvvm2pD54qf31xpbsfypV0V
         ZJ0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744050949; x=1744655749;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3iGvcdl/QVlSrU/CvPbmKqqoUCaSxxlRUaDOWa5Wn/g=;
        b=BdtJ0qdMfnoMcg/n+4A34VDzzaYSquIJxMo+hC1GZq7/mvUHmdS3H2rHZOpze+3ihQ
         o5Ly/FpMkvNgMv4fbT4SEsIWKfBtKQ8gslxhK7D0w1MEKxIx1vlw+DHFToOR+n+Xab+S
         yPBaWrQH7eQnizvngI3zG8xOxZLgx735LJP3Rp8uMkvwXAnUTtvtfN9kc4VM3L9u65mo
         Bg0bGKqKxH95lw0HIFugISfDi8cEdHihSkU8IWxf0muos5emI+XwiGsB7gnlyu0Zqvmx
         vJRfma/nK52XxQV3MN8SABpgY6NmQM4jRVSVHU+lnDA8cYns5PR/rdDr08QCUJOQpa5S
         NEGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsInkr2rnmChgTYniXyy2LM4F8LneytYST/yAA/oSecj+Eh1u7cRJFb0OQGDrqnoY9AD/JlA==@lfdr.de
X-Gm-Message-State: AOJu0YxzTHtan2Qho4a1PJM577GRsM5fGS9I9IlouSMzn8V6qY364D5L
	oDr0M7xb2vF3cUxg31MWpQMuJQutbJ4r+vLBvdPQjZtBsEV4/gSm
X-Google-Smtp-Source: AGHT+IHtePWXkormK2w3vuDUPkwvBHm5Ai/0H53tdBnFkSiO9cfs2GDZ2MTe9SBuX4451hBE1zj1EQ==
X-Received: by 2002:ad4:5b86:0:b0:6e8:99bb:f061 with SMTP id 6a1803df08f44-6f00df552f9mr176160516d6.18.1744050949131;
        Mon, 07 Apr 2025 11:35:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPALXOM6CTvZTDUBndNLCRVTnfKWKO5+20aqpxXN96CHs3w==
Received: by 2002:a0c:c682:0:b0:6e6:9ec8:8bff with SMTP id 6a1803df08f44-6ef0bd6e8d1ls12518476d6.0.-pod-prod-06-us;
 Mon, 07 Apr 2025 11:35:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUZgeiqRNyAF/3fsgAA6uZywuVcMbByinErC0JlAZc1r7viLaxwNiPyRQYZQWeR1xq39g//RonueS0=@googlegroups.com
X-Received: by 2002:a05:6122:1349:b0:520:5f0a:b5a5 with SMTP id 71dfb90a1353d-5276452c8b9mr10987287e0c.6.1744050945660;
        Mon, 07 Apr 2025 11:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744050945; cv=none;
        d=google.com; s=arc-20240605;
        b=NF9Wow7YK0YyuSUoN2EEWJFqBp6pJPZKeQJ3xkIVXqkC9ESQ6zqlufpt7h4DqWM3Qd
         Pnrf3RScSTvxhwRTC36jjmFaiy6rwwqvf516/v1KkFMLfaLk6cov0cILRJmuCZMf7gxk
         +g4WPtZLHVtpfGGeI43HA8abHsoosgEkb4x6yioTB+Iy5THBLwxj7bQZixSdGhhfsktP
         gRtgwRx2UtGvYreGWO68JyWpS42zQCftAiVCxsWIlQ0ysgnZhwceE4PTri6IOecmZOp/
         OH/Tzru2Aj0l3/C6PEbuESYaGdzGb0bUoCSPcBbnS/sfZIltoka4nsWfsvH/eCew9Y3h
         JDWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HVIx6+rqr4ZJl0FP7/CBLnJxACqBspcG+IcI+UcewN0=;
        fh=Q3BDqjLOL05lb/y4wCrrPN4pB4OmhN5VgxjDrLj25UE=;
        b=lopRReWPd3tTZA8mFVBc4GInM/Oh2rGvLMR+YjynwPzNs03rHfWBNVhmFYfVi2u/pB
         PCmEqfLP5gItzkVl+rdWCjLSXxOo5ReJ5udyOW/S9B6XEyAz49hSTqltbSoF0QeALUuA
         HCjKRiZh43Gdifsqn/4oQZ6pCyAc0QzRSdnjJKskYig82ixjuAQzpOki26xnwZxwsDZu
         Q8ruSIGD3Q6S8YBqaCAdmqrKIAzq3Cj9yu17wNKQ3DgxM3mQYp7XdE43d88uJ2dKbDPc
         drEYnK2M9XcYIIOz32JNlfUHzpAfc/3Ur5ExkUrMKwB6oOUiL5k9/9dTJNuBV5ZSC64K
         0TRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="kwvaeD/a";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5279b63a14fsi11614e0c.3.2025.04.07.11.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Apr 2025 11:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DF9495C276A;
	Mon,  7 Apr 2025 18:33:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3B551C4CEDD;
	Mon,  7 Apr 2025 18:35:44 +0000 (UTC)
Date: Mon, 7 Apr 2025 11:35:43 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Gordeev <agordeev@linux.ibm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Hugh Dickins
 <hughd@google.com>, Nicholas Piggin <npiggin@gmail.com>, Guenter Roeck
 <linux@roeck-us.net>, Juergen Gross <jgross@suse.com>, Jeremy Fitzhardinge
 <jeremy@goop.org>, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, sparclinux@vger.kernel.org,
 xen-devel@lists.xenproject.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org
Subject: Re: [PATCH v1 0/4] mm: Fix apply_to_pte_range() vs lazy MMU mode
Message-Id: <20250407113543.6a43461e397d58471e407323@linux-foundation.org>
In-Reply-To: <cover.1744037648.git.agordeev@linux.ibm.com>
References: <cover.1744037648.git.agordeev@linux.ibm.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="kwvaeD/a";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon,  7 Apr 2025 17:11:26 +0200 Alexander Gordeev <agordeev@linux.ibm.com> wrote:

> This series is an attempt to fix the violation of lazy MMU mode context
> requirement as described for arch_enter_lazy_mmu_mode():
> 
>     This mode can only be entered and left under the protection of
>     the page table locks for all page tables which may be modified.
> 
> On s390 if I make arch_enter_lazy_mmu_mode() -> preempt_enable() and
> arch_leave_lazy_mmu_mode() -> preempt_disable() I am getting this:
>
> ...
>

Could you please reorganize this into two series?  One series which
should be fast-tracked into 6.15-rcX and one series for 6.16-rc1?

And in the first series, please suggest whether its patches should be
backported into -stable and see if we can come up with suitable Fixes:
targets?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250407113543.6a43461e397d58471e407323%40linux-foundation.org.
