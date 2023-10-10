Return-Path: <kasan-dev+bncBC5ZR244WYFRBTOPSSUQMGQEHJK4WWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FB267BF8AB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:30:39 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2c1886908a4sf48316451fa.2
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:30:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696933838; cv=pass;
        d=google.com; s=arc-20160816;
        b=FTLorMgWrHFHT2KI034Hcba+1I0uNo3kyEguS5+NPteJ6gG9ks8b2wTJnJKbycON6s
         tLNEV2AIgTqlDGtBxZfpIhBGLrD0cpYXiWiHZFpBBpqTDC5kydISCDmfOFFCFcwTWTqh
         pBWdCSHV0bdl7DsvPbhQkwrcGOA+71XBxho26jxEifkEXSzXzKScQB7yrAi226pYDFPw
         AvJpJzMbwJD/w39AYX/5rsQiDn5UArCTXbNlFOu4zTk+yIl1YzpbiRpaiPTfI634+MpO
         Oyr47T/5lzlryRS0ldllrJcIrDFq8xTsX8XnKTQq6JJnxbhaHpcFRr05iWRkrHLE69Bb
         /o7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=JcrWuqZj8MGrVo9QJ8PHNbHh8Y9jBDeubkfKl/UyWQs=;
        fh=j6gH8MVd8SXUPRBQKuaUs95IQ8SMKFlgheGW6KdVuMs=;
        b=o4qbkT302Nv5Syl4SwONicH+2dMO6WT6c4A9H2p45zseUvHAoQmS2wxfmYIZfW9g86
         YWl9xerGxMUJTZC44Ff/sYwecTvlcD6VcsOBoe38jjWF7op9I8TLFGWg9sJq9Ocrsk/I
         MgpAjV/BxLgwyHWkgrAPwRsTf6EMdO7QtQ74HI7vsMdy+JbbYdc2QAzO73cfwu7mHHqA
         f1TdDsVSmdrhbhV3mk7qq+TMcLc3MXlqjGT6b86URqsqm628RxWAluwAj/2pBGzQnswH
         j8NsZknjHwAMutBobQmqWZXqSlu51gESoa1/GDpaMy4kr/aisgZGQyYIVLVK2q32AKrd
         vsNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Kn2pLDqM;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696933838; x=1697538638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JcrWuqZj8MGrVo9QJ8PHNbHh8Y9jBDeubkfKl/UyWQs=;
        b=rEQNTIeC9iK15jUxpHQL/BWrFFffvZrYPh4Abgs3PUt06WFJWnCuOC8o9Q+0gFL84I
         07EJxBHstNLlRxOnE+M/DBpSxxkJwAbOZkR43P4xJI2POCf+7d91QFI42fxRQ1f/AsGd
         02o9+vbcZ8b/TMBKudiA2YSrpsPu+0gCfYJGKkPHkL9gwB68bOH9zcAxZ5vVpvcN9pfV
         OBN0TH2U3MdZ58yu5eQRBPwPOoEyF++weimuvD+PqwEU+w+GiU8GDBHjwdu2GhP4Vcwr
         WGz1dVMLoqaYuDE3ZuhsTSCukZXcMnosKOJDqh9QlCFH2NLaC5bxdcPkN9HK4QaLrImA
         yYrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696933838; x=1697538638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JcrWuqZj8MGrVo9QJ8PHNbHh8Y9jBDeubkfKl/UyWQs=;
        b=brRAzyKHM0Ebpq80gdXaY4AuNC7MJvUqqGhGkHSI6FdXBQtUvJs7OISWRtSn5Qp+ZO
         Ef81cvcIjQiCnG3unBs1MVNiR5zn5enDl1f7cNdIKfKoEEYU6aQkrLV/XBB7uLteh/1C
         WetIs8sTIOXsj0fvyZa+xAjqdxa/h4rUOPDm/9idWAGUJ/Ny/GFK+qZsG0ndEckeBV47
         xpsV9+Dd8htXLfUjFlJWkksh7oxEjJb0itkUMp49CnzOWvv/tw/Dr8aICJUJG3Cak76N
         VqNmrDh3moYmkFYdzFS1CB2hg3/vTAK4AltxXGl6/2K5/EudEi1Vzmtkne5bbgiwTzZS
         6NfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx7RlrrcGyfcyo4M2+fTMy+5Ge+mLMGt6VgtX8IRNxOhCBvLTFz
	zPO/Dt8jYKPNJESkIsxgLEA=
X-Google-Smtp-Source: AGHT+IHoFB6eZ7HBIKXXxt6vZFGMp2ntAGYYmjZDKa3D//O/nr9o9OG+3cN7XlO+bAbfmt1VuD4lkA==
X-Received: by 2002:a05:6512:3f27:b0:503:74c:9446 with SMTP id y39-20020a0565123f2700b00503074c9446mr17536053lfa.24.1696933837475;
        Tue, 10 Oct 2023 03:30:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:8c14:0:b0:4ff:a03f:71a3 with SMTP id o20-20020a198c14000000b004ffa03f71a3ls961469lfd.1.-pod-prod-08-eu;
 Tue, 10 Oct 2023 03:30:35 -0700 (PDT)
X-Received: by 2002:a05:6512:4002:b0:504:369d:f11c with SMTP id br2-20020a056512400200b00504369df11cmr18021327lfb.34.1696933835720;
        Tue, 10 Oct 2023 03:30:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696933835; cv=none;
        d=google.com; s=arc-20160816;
        b=awVmacEgEuPeK8EeYrkQ1Pil/08wcDELwJ0sxH2uSGFVSFdUhF6yi7koDIfpPHPzJS
         7hh9UAucyG+tuGP4eYC4+W0UUKoQKXioKH8RqUZhBQ54qjnlYoYBqlfTYljljrCSRy5Q
         B/zr+4U5+ic1qMnf3HqhT9+fR/ExHXPN4YOd26KU1UjGhtp0p3REvy/NhQiF0Dm9bgeQ
         hEfb3oVwUX6plH9tPhvyzI3nnpFRkoAfhdb7NzxmiTY7/GAzj/0OQf95LOph0ntbaAfy
         cj41s4+QsEwNSz3OTOuM/GDC3Gd2EL27IjJT6FnoDUUu8ShFY20NZaSd3pILks28zkjP
         iMGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=iflXojYnSpFgKJljaLougO8F8G9RONmWdqmx611sL8o=;
        fh=j6gH8MVd8SXUPRBQKuaUs95IQ8SMKFlgheGW6KdVuMs=;
        b=qgmy24Py4lPMAPMrAbCVr7yLdI5gcQLrWRAN7ogCZ3R6kFKcbRqfLV2ht8pDmKkOT1
         Ei+jMXRbRR2wOEqjWWRk8e1fi2JKlhc8FX7dMXjdhEPBMw46KSg3gOcybNYpjMbb6+AK
         x25mN8B4jpDElz8ikAqzEpzSrXyXKUkO6xTop8O+30Spto5nNUYNNG/CUrym2pGQ6/aP
         A8NuAOo0QWFxgPpS5/9S9dpT+/fWFQnrjkciUR0u4FeAEvcUDOQeBV2bd1zP1kVLf5V7
         ivsBnYcGXQDICymKe74UXUVdhvHdBsmBSlPb8kv5PsSDlaZtdzcKio+4WpkIDgjdoixt
         LqLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Kn2pLDqM;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [134.134.136.126])
        by gmr-mx.google.com with ESMTPS id q3-20020a056512210300b0050446001e0bsi374404lfr.3.2023.10.10.03.30.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Oct 2023 03:30:35 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=134.134.136.126;
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="369423608"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="369423608"
Received: from fmsmga005.fm.intel.com ([10.253.24.32])
  by orsmga106.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:30:33 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="1084720804"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="1084720804"
Received: from albertmo-mobl2.ger.corp.intel.com (HELO box.shutemov.name) ([10.251.208.38])
  by fmsmga005-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:30:29 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id C523910989E; Tue, 10 Oct 2023 13:30:26 +0300 (+03)
Date: Tue, 10 Oct 2023 13:30:26 +0300
From: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
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
Message-ID: <20231010103026.hcjn47kvjqesxoqj@box.shutemov.name>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
 <20231010101621.GG377@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010101621.GG377@noisy.programming.kicks-ass.net>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Kn2pLDqM;       spf=none
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

On Tue, Oct 10, 2023 at 12:16:21PM +0200, Peter Zijlstra wrote:
> On Tue, Oct 10, 2023 at 12:10:56PM +0200, Peter Zijlstra wrote:
> 
> > That said, I don't particularly like the patch, I think it should, at
> > the veyr least, cover all of apply_alternatives, not just
> > text_poke_early().
> 
> kasan_arch_is_ready() is another option, x86 doesn't currently define
> that, but that would allow us to shut kasan down harder around patching.
> Not sure if it's worth the trouble though.

IIUC, it was intended to delay KASAN usage until it is ready. KASAN is
functional well before apply_alternatives() and making
kasan_arch_is_ready() temporary false for patching feels like abuse of the
hook.

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010103026.hcjn47kvjqesxoqj%40box.shutemov.name.
