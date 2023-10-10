Return-Path: <kasan-dev+bncBC5ZR244WYFRB5WMSSUQMGQEVYQDJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 521A77BF884
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:24:56 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-4066f75ec23sf15365955e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:24:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696933496; cv=pass;
        d=google.com; s=arc-20160816;
        b=mDi2koH4xudokZBrinKxLNiGKPNwgXJ2Iqo6g1LsSBqgilbuXuBjmhDsFf+umFuKn9
         LQIGgVkbJTDLV9fLVEkHQlTua41JJamaHRHnl6XzYridkEqBtsy6T1byk0pSFT+ToLKF
         n9AwrEkJ6FzXKjXH2U/cdPHxfxaVZaJCIi4AUZHBFzkHnAD9vic01n8JI91VeppaL2Xz
         gaP830da7tZyxQQgO+bgJvLKCWFDtgpIo7DxRWccGk58qiWtA/vMf9xl0hnMRSZZNAVj
         JNdghP6KR0jiPqEjk5s7T+Fm+cedg24ZmhAal6ZBJ60Z97HrfWqI1L828ATWBSCiiZL9
         YvKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3r0Ast0EPI/i4tlNCdFm/6DyVFksS/JlwD8Fv1/Ir9Y=;
        fh=Humky4e+hth+m5LjjwqZefHA/L96cUXUrx8t/v+3zX4=;
        b=HwfEMsfNTZxtOopz+lhhuRGW+KBAd/vKmUujADPluvh3g6WX/8kVQZI/0MlHGg4Fcb
         Crqx3YOOpB1/4Zu+xWPfX13GGKphZi5aBEkvJ8YZtbXtNE+qFSzeDz1otdLHtz2ZP/+D
         U9OpPIvdL/7SIfLHrwPGQQAWt63VLkCIPSEHJXE2gRqZmlHR01c1vYLzncRpVeZRUc5A
         NNO+6sbJhtwkL1y4Kpevgq33Od+fw5i5fguctS3AS9sAG0/sk++Ll8QE7il8nkfwHw7f
         wBBBcwAU/8DgjuwV4aeojBD4FCuvzEs6rDTBJ8auElZuOhiEeQpJRtByBGC1rXcWwIJi
         O+Uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XlPsIIme;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696933496; x=1697538296; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3r0Ast0EPI/i4tlNCdFm/6DyVFksS/JlwD8Fv1/Ir9Y=;
        b=iYcjcS5hFlTtIp15pQCwbmyPuF9WRWUqR8QLHM9TLd+1QmThS2/zjvGp6+xzzONTxy
         ZADczXBpSgpy58hdQrEi7jy/mnk9mG+CZjZ/jJ3XwBzWIEhlEcotQyKn9lLtg7+Z8Yyw
         ZvZkL2ihky7X5Ar2XQtOkmgx8vf0dlSHdd83dy6hSQpMRxEgay1CQXYRnDNd5w2bxVUN
         EBAM2YV124uIhQxzzBo815pj8OZGeuzNX7nVyrfHCtA8TjDvK0dBuq3sLP9Ml6mllrTZ
         FGPBa35AvaI2lh8dbyOnWLD2sx8h/qbY2lj8aLhnbd0xIOgZH1bgpePMBzg8ntIkTdsH
         0IGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696933496; x=1697538296;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3r0Ast0EPI/i4tlNCdFm/6DyVFksS/JlwD8Fv1/Ir9Y=;
        b=R2HG6pOZLO/DaPi/6djUWQRgHarJlzmDJ5rIuF5fMPnqcfHt19vbLxe10wO75tClwQ
         9gRBSH/C5Xr909JCs6MREmBBYoU3EO5pEmme0ZRt7zM2dW+j+z7qENarrhImSLIK7uTi
         ikapIeFZMwLM7yTeEuCfDL4OnXWb1YBBfRGg47MaIstaBKtG7EJxB6UtPQ+OUOxLdNe2
         rc/sJg8NVVPTwg0KeV6yG7254yfrc1rI52RhFXHV0a39xuUgkxLzkKMFoN9wvNeHQ3Yd
         v7OVwiLzOouc/8uCqQtVoOCIgMSq6kl7uzBFn8RNHiBf3PL584pEV24ajToq/n0MvDVv
         p4FA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw3S8J4YYEQCqHEWiocliCUAaIAJmIQqvevFwfBpdgk7+81HoKu
	zx4K1LgLkHFlh3WsE5UBurI=
X-Google-Smtp-Source: AGHT+IF/E57CYeWH89xaA6C9JJwQxPDh/bCQMFyW93ys1rnZHBUcu9TxZn9zZJzHHpHXVgg6MrotBQ==
X-Received: by 2002:a05:600c:3ca1:b0:405:3cc1:e115 with SMTP id bg33-20020a05600c3ca100b004053cc1e115mr16105446wmb.3.1696933494460;
        Tue, 10 Oct 2023 03:24:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d9b:b0:404:77ae:53ad with SMTP id
 p27-20020a05600c1d9b00b0040477ae53adls1125394wms.1.-pod-prod-08-eu; Tue, 10
 Oct 2023 03:24:53 -0700 (PDT)
X-Received: by 2002:a7b:cd8e:0:b0:406:45c1:a657 with SMTP id y14-20020a7bcd8e000000b0040645c1a657mr14875892wmj.6.1696933492877;
        Tue, 10 Oct 2023 03:24:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696933492; cv=none;
        d=google.com; s=arc-20160816;
        b=FPKn1dPWMpavJZHeJKwvCiJZpWHK6xtsSnuBMWnPWf/8EOkDVBcP+3QsoUyxE8ES14
         ZTcY3qKQpI8x2h1ambFLC79/RslMVmyQzycjYav/puA79KtrneAs/f26JBZAgVILxKZd
         beM2fjpWl/wFvUstk9redAYsQ7YuGTvpASzc2nZ8ywtj7mhGhb+2emLiAeW5vPU4UcF1
         2G5SLGWRwRVjBxmvMdhMJH00uIR2aaHfsrqGXtTww2Mj41Ae7E2Hms8bWCdnPPNt8u6p
         sp7WxvWsyrcWwdhrm+vsCJt2hmDnIDxZrcutyKHwSaVnbTGCxZ64mQpyyJmoVZ9944r7
         aTbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=tKh8x8oY19PzBwcSOoxnn2dS2pp/W/rE1Xb9IqE8P3o=;
        fh=Humky4e+hth+m5LjjwqZefHA/L96cUXUrx8t/v+3zX4=;
        b=OiI24+/0DcLrVt9RH4O9vlogeKn6JM1AuE+aM3Q3LXAHmlCNqYNTC2jG1mK7aCkTwa
         Bfr7pMshiBZqjgl6HfRWk6l84JMLOZ5vWSckr4dSyPRjZEs5GZfIXBtToNdASn2NBCSA
         xEfzJgTaJXWgVmBvropcb7F//clSC9/QOtrmw1Jdw8JhUkFP1Urpv4gvZVXm97tG7vtq
         tjRhEeMeQ8u9FxJj1chPMKZL11NdCSQcMeRSs06Xfzd5SsZd/0u0wuInqRSUKpkV/uob
         HSy0OlwQGWXpg9BWRW52Mjq2ghPhsJZbEShhoJCJkcDlht1RMwuen9OIYfD8Kbt9jmqC
         WmOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XlPsIIme;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.151])
        by gmr-mx.google.com with ESMTPS id bg36-20020a05600c3ca400b003fe1f9a8405si442396wmb.0.2023.10.10.03.24.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Oct 2023 03:24:52 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.151;
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="364654353"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="364654353"
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by fmsmga107.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:24:41 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="927087670"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="927087670"
Received: from albertmo-mobl2.ger.corp.intel.com (HELO box.shutemov.name) ([10.251.208.38])
  by orsmga005-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:24:37 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id CA51710989E; Tue, 10 Oct 2023 13:24:34 +0300 (+03)
Date: Tue, 10 Oct 2023 13:24:34 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Borislav Petkov <bp@alien8.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Peter Zijlstra <peterz@infradead.org>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	Fei Yang <fei.yang@intel.com>, stable@vger.kernel.org
Subject: Re: [PATCH] x86/alternatives: Disable KASAN on text_poke_early() in
 apply_alternatives()
Message-ID: <20231010102434.ncn3mxk7cesec6s5@box.shutemov.name>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010084041.ut5sshyrofh27yyx@box.shutemov.name>
 <20231010091235.GFZSUVgzTetLj2K+s8@fat_crate.local>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010091235.GFZSUVgzTetLj2K+s8@fat_crate.local>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=XlPsIIme;       spf=none
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

On Tue, Oct 10, 2023 at 11:12:35AM +0200, Borislav Petkov wrote:
> On Tue, Oct 10, 2023 at 11:40:41AM +0300, Kirill A. Shutemov wrote:
> > __VIRTUAL_MASK_SHIFT used in many places. I don't think it is good idea to
> > give up on patching completely.
> 
> Have you even looked at boot_cpu_has()'s asm?

Obviously not :/

Okay, as alternative, the patch below also make the issue go away.

But I am not sure it is fundamentaly better. boot_cpu_has() generates call
to __asan_load8_noabort(). I think it only works because all KASAN code
has ASAN instrumentation disabled.

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index de75306b932e..bfe97013abb0 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -12,8 +12,15 @@
  * for kernel really starts from compiler's shadow offset +
  * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
  */
+
+#ifdef USE_EARLY_PGTABLE_L5
+#define __KASAN_VIRT_SHIFT	(__pgtable_l5_enabled ? 56 : 47)
+#else
+#define __KASAN_VIRT_SHIFT	(boot_cpu_has(X86_FEATURE_LA57) ? 56 : 47)
+#endif
+
 #define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
-					((-1UL << __VIRTUAL_MASK_SHIFT) >> \
+					((-1UL << __KASAN_VIRT_SHIFT) >> \
 						KASAN_SHADOW_SCALE_SHIFT))
 /*
  * 47 bits for kernel address -> (47 - KASAN_SHADOW_SCALE_SHIFT) bits for shadow
-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010102434.ncn3mxk7cesec6s5%40box.shutemov.name.
