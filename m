Return-Path: <kasan-dev+bncBC5ZR244WYFRBLONSSUQMGQEBCPKERI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 70EF37BF887
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 12:25:51 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-5362b33e8ffsf4476343a12.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:25:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696933551; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yh98yf1rtYfyaemYZBRBmcicRv5jv4KdYOlMX0WkvEvgdi+pDb7Kqxq8sPRqulKHv9
         NhKrmWoxIjRWh/vUptT6wYgYiYGOvx3+1wypYolTmm4Yd+fPU1dybQbIs4Wes9SmitH7
         f9+2J0hE9sUgjRpF7DA0MondiOv8v0Ky/lQzu/kFC2oruMg0H6x/IDSjgk3rBIT2x3QC
         TgozJP/3nswBwp900sAhPESZ9gIKN2pphLz+g5FnygP/b0DKb7+FLbMji9ZK8EqR+M9N
         5wOK9aarDAXgyS4H42s6ILMKfNO8dM6jO3J4VxJLfqjtP9tDhaYxWdjVVaefdHBrDj/U
         jzNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=tVKVsJ1BO2VuWMOByFQE8gsYcBkRtHizeoYGe5A2NJw=;
        fh=j6gH8MVd8SXUPRBQKuaUs95IQ8SMKFlgheGW6KdVuMs=;
        b=M7+ID6qiYZuqsszn/LeZ41XCpJw7Mems8o7waWGSKO54QwKXmIFYROnPuGRnql23kX
         YlSC0IXXy5WpQc7ZFoSDESDiTjT5I0KmjfHCRGb8qYM1PpU6EAS18dcJvpyz5ABVj/io
         xrZFv3MtsgBuFisjJfORiTFaoAEY4Q/DPaL8NGwREDaHySTfQExYJI09qnJ3EfOH1tDO
         3Y3tEPK6I50C5OlJxNeBKj0b3d8EfzSu/EqlIwcQCTIHcwHVU+GhwzENmuTbueES0rXJ
         JjLP8jMoKnBxLJMPmZgFLCsv/opVwxX2W6hlzUw3UDDMTxU9vTctjgSecEk4HZvV/Opp
         +sOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PkhQaQ3y;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696933551; x=1697538351; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tVKVsJ1BO2VuWMOByFQE8gsYcBkRtHizeoYGe5A2NJw=;
        b=GnWoH6BvFgmaVJTlnoOXK5hfGaDqUclMA3UzcT0+BAQ2/qy6HlW2uDpBlJJa+avUCe
         ig14yRt+7OdoVMgdILFAnb09TG1pjhHEQjgrMXN5sMiRwawo0azea9xvZpjLkMxuDm9e
         gtRw4J6OFui7u4QteoMSI4Q5A+8Gbb33d1TV7NatASXKBrecDcJdVh2lSW0A3ha80Hbc
         pAdVyn5LPODiPRcPr6hTdLJUfg3+urWdRuDNKQ5lPwcGhaPQRSvOyqMOvNUf/Fv/1fOB
         vzvdojFSAiNLEC0N5tjoCMPDGLpItUMfVRsamQ28wenVcp6/3pNkKxP1ScHLIItOCp8r
         vQuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696933551; x=1697538351;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tVKVsJ1BO2VuWMOByFQE8gsYcBkRtHizeoYGe5A2NJw=;
        b=fbYWWz0nY0adEaomBdb5osVvfmtgo6riehU1faDO+YBQg6MjGCIZNcWigzBO6DrK+2
         aiJA/bmblY2Ku8wGOwyWfGAIiHBMacs80r/Ha2BWJxglaSq5HARVgU5QEENDuksmvOr5
         NGbMTeR7OPEM/pEG6JG8pW8DuEqdeavwdy8m0JndUNcD9GG2p8obsMTSngvBFspmMf+m
         Q58sTtsENXEhJM5dssSRDVO69NDGLBv35+TQcol5JUPZ2hiKlqOPWoO79v1kCAexQ//v
         Cs6ja5FAwp8lMaPL/juLrX83Z2IrlgFrM6hF3S9niD4pH434QxW+UuwyW2llBHLPrbr6
         xexQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyxf9rC4TX/eO4ItC31iaM5/s3VpcpYS+2LgfMWe0HOUrOHF7Bh
	i4P2CV8UN0R/0i02Nv3kuUM=
X-Google-Smtp-Source: AGHT+IE6Z7x9uQwFd2ytVGoiCK6euOqNNdjmPtzgavKDrtCaHHXNO0YL7lko3kAGZMqEhe7Cp1T7UA==
X-Received: by 2002:aa7:c3da:0:b0:534:8392:879d with SMTP id l26-20020aa7c3da000000b005348392879dmr15814326edr.37.1696933549559;
        Tue, 10 Oct 2023 03:25:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:db8b:0:b0:533:cc3e:9ee1 with SMTP id u11-20020aa7db8b000000b00533cc3e9ee1ls261131edt.0.-pod-prod-02-eu;
 Tue, 10 Oct 2023 03:25:47 -0700 (PDT)
X-Received: by 2002:a05:6402:4308:b0:53d:983c:2672 with SMTP id m8-20020a056402430800b0053d983c2672mr1030535edc.38.1696933547846;
        Tue, 10 Oct 2023 03:25:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696933547; cv=none;
        d=google.com; s=arc-20160816;
        b=NjSktiEhDGBnN8gPDz3XBbSoeYQbjxNzVkNupdN1QpyRVef2EF9xHk8jsKNYjvpklU
         NB1lBRcaHrczuGq3fctDFj8x56ApcSlvnCu9rNLVSGXOSP/4DWBQl19VrzMBSO5BF9J7
         GVn+iasA8xdVcrQlAVG6SVwJZpBCvQE4DDkZ7kNCsKa6KscqOEnpSGeaGlP4a0hFYtfY
         IY9w30zTbSUApymJXA/MfPskMBiW0LtxKIaRx5MygB4GTKuyI6CCVIWqc329BqMj72qw
         RiMDAFpkkw/dQXhyMYViTTVJI5Fo+D4IRdL8KOW0cpT2fkf/OFSs0gPcKFyHzyz2eeoe
         Mlpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=8NMaAzm2KJMkDwvzedLJ+6AziWa5HWEcT2zpFFsyaCA=;
        fh=j6gH8MVd8SXUPRBQKuaUs95IQ8SMKFlgheGW6KdVuMs=;
        b=lhnD9AShs3piarGJ8o9C7gvuawEJ/x6bYwTJnJGJ0z2GmiipqBnjVHmrfCkhI11YNs
         wKr2fpzFad+UV7xje8G4S6IDwTxR2yZ7yGMEsfq8j5f6pU+8K/nSks9tm3ttPXOuyN2T
         +t+9rduy09xoTcZuHyEPMALbtIPg9oiWTUzHshVbgPYdapA79bXZ7w26a38g5LEsuksN
         J5iwHd1evq//UXjr97h7DnnYfE/cPn5aOaZM7/XcphQ6OoBl3c6DZOgDPZ1oDgvprst9
         hmP+5KxUn+h8hm9FihYGrQpBSV1JK58f+5yJssHkQTGBYyDN3bBSkkb+KZ5xuAIQ7MQQ
         UzJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PkhQaQ3y;
       spf=none (google.com: linux.intel.com does not designate permitted sender hosts) smtp.mailfrom=kirill.shutemov@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.55.52.120])
        by gmr-mx.google.com with ESMTPS id i16-20020a0564020f1000b005381936ef68si632945eda.3.2023.10.10.03.25.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Oct 2023 03:25:47 -0700 (PDT)
Received-SPF: none (google.com: linux.intel.com does not designate permitted sender hosts) client-ip=192.55.52.120;
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="383235949"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="383235949"
Received: from fmsmga002.fm.intel.com ([10.253.24.26])
  by fmsmga104.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:25:44 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6600,9927,10858"; a="869633637"
X-IronPort-AV: E=Sophos;i="6.03,212,1694761200"; 
   d="scan'208";a="869633637"
Received: from albertmo-mobl2.ger.corp.intel.com (HELO box.shutemov.name) ([10.251.208.38])
  by fmsmga002-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Oct 2023 03:25:40 -0700
Received: by box.shutemov.name (Postfix, from userid 1000)
	id EBD8410989E; Tue, 10 Oct 2023 13:25:37 +0300 (+03)
Date: Tue, 10 Oct 2023 13:25:37 +0300
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
Message-ID: <20231010102537.qkrfcna2fwfkzgir@box.shutemov.name>
References: <20231010053716.2481-1-kirill.shutemov@linux.intel.com>
 <20231010081938.GBZSUJGlSvEkFIDnES@fat_crate.local>
 <20231010101056.GF377@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20231010101056.GF377@noisy.programming.kicks-ass.net>
X-Original-Sender: kirill.shutemov@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=PkhQaQ3y;       spf=none
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

On Tue, Oct 10, 2023 at 12:10:56PM +0200, Peter Zijlstra wrote:
> On Tue, Oct 10, 2023 at 10:19:38AM +0200, Borislav Petkov wrote:
> > On Tue, Oct 10, 2023 at 08:37:16AM +0300, Kirill A. Shutemov wrote:
> > > On machines with 5-level paging, cpu_feature_enabled(X86_FEATURE_LA57)
> > > got patched. It includes KASAN code, where KASAN_SHADOW_START depends on
> > > __VIRTUAL_MASK_SHIFT, which is defined with the cpu_feature_enabled().
> > 
> > So use boot_cpu_has(X86_FEATURE_LA57).
> > 
> > > It seems that KASAN gets confused when apply_alternatives() patches the
> > 
> > It seems?
> > 
> > > KASAN_SHADOW_START users. A test patch that makes KASAN_SHADOW_START
> > > static, by replacing __VIRTUAL_MASK_SHIFT with 56, fixes the issue.
> > > 
> > > During text_poke_early() in apply_alternatives(), KASAN should be
> > > disabled. KASAN is already disabled in non-_early() text_poke().
> > > 
> > > It is unclear why the issue was not reported earlier. Bisecting does not
> > > help. Older kernels trigger the issue less frequently, but it still
> > > occurs. In the absence of any other clear offenders, the initial dynamic
> > > 5-level paging support is to blame.
> > 
> > This whole thing sounds like it is still not really clear what is
> > actually happening...
> 
> somewhere along the line __asan_loadN() gets tripped, this then ends up
> in kasan_check_range() -> check_region_inline() -> addr_has_metadata().
> 
> This latter has: kasan_shadow_to_mem() which is compared against
> KASAN_SHADOW_START, which includes, as Kirill says __VIRTUAL_MASK_SHIFT.
> 
> Now, obviously you really don't want boot_cpu_has() in
> __VIRTUAL_MASK_SHIFT, that would be really bad (Linus recently
> complained about how horrible the code-gen is around this already, must
> not make it far worse).
> 
> 
> Anyway, being half-way through patching X86_FEATURE_LA57 thing *are*
> inconsistent and I really can't blame things for going sideways.
> 
> That said, I don't particularly like the patch, I think it should, at
> the veyr least, cover all of apply_alternatives, not just
> text_poke_early().

I can do this, if it is the only stopper.

Do you want it disabled on caller side or inside apply_alternatives()?

-- 
  Kiryl Shutsemau / Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010102537.qkrfcna2fwfkzgir%40box.shutemov.name.
