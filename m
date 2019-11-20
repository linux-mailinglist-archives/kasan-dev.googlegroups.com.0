Return-Path: <kasan-dev+bncBDN5FEVB5YIRBGWQ2XXAKGQEGPZ7OAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D85D1040A6
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 17:21:48 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id o5sf1433501qko.12
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 08:21:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574266907; cv=pass;
        d=google.com; s=arc-20160816;
        b=dU+9gOQh+hyx1BCfCglQ0IExRS4AkZ25FVUfgAEvHc0pUETdcqFoTvz+Hekyzy4YnS
         6kXSMkT5k0Pr1SiNKyeExzyoSkRso60wWH18v6IwEdothBpF+ZoL9O3JEpOwoERfbNq/
         hZIz83iUQPNNiwUDpTdjl/cHEiAq6HEqebpCDwDNdC1nPU1TDxPR3jXaqbAy4qIHegI4
         7yFcSgJS5DhY31uP8RZvnHw941RMEsgbl8GRLz2sGqdVWaOOUM14ayVOKQ4zy1vmG3od
         1q3A5oKuEMRAQHjznycz2kml8vtdVuQfVk5oJVzDLWbNa7WNwPXZ091ZtkCHgXEliDZ4
         +kag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=iTrL9/cxraqEvwLWROWPOqAifyVMLsvUDyi+byq6elY=;
        b=0N9cf+SBicOxTbbGB8+BCaKX0xBE0qtRFuedfGj+wf3qfQSN32XJhL/fm1yEeRXCXm
         5RUprbtGZ/0FTSLsgEg9B87bfDZdmhRwFQm7io0YLu/C6KfaKgeiOkiGHVg6V2esOP9E
         57aUwIwNDLyoFCt/iPRzEaA4zZwuO9xOfa+n4mik5sMV+gq/VrQq8r1mt1ugcDb206Sp
         CSsKHS5PdZH/WpA9spe43xwfZ4bPlsrM2iiJ6p31qffYYF2A7FInIkCoew7EOGfW9/2v
         8Wa4ePaUszkRIC2vXB33An0QCQajTZTvnVhV5U0OpxRE8RtzIwdDaIjNRntbmI+BFbMq
         O0xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iTrL9/cxraqEvwLWROWPOqAifyVMLsvUDyi+byq6elY=;
        b=lUcs4cScRp3FYAqfcaQ4hUo3xwVGOpYtYWXzEOUq8fCVhJsAMtI7fXQeYmCHgukB7n
         5mWZjJ+O3piuWL81twEy2uFufeDNz0yW4/bxYzWs5YNk9vRl8oZOvXgvqo62HRGuTk04
         uyEcZKoJlSovgMgCGE/wIAYVLwKqiopda3//Oq8qW7msh9kmOAm5dEvKujPTbmNpHugu
         lrEoyYwvAY3M0BavKkmSneKJHZib6WmOLDRVzYYw3y7SWG688a5lvI8ePITZoC7mekvY
         P4Q5YstqHwFaqIKTo5XZM1NB8nLka9OMCp2H8vhJus/bn+0wj3+azCdz8eM78nlJo4xh
         6tzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=iTrL9/cxraqEvwLWROWPOqAifyVMLsvUDyi+byq6elY=;
        b=LaqNXhyWLDvsSkgRbRjX0gbip29nGNHc1PbS1m6kdV9Fs2WG0pynXBG6cJ1v6gvItB
         oVpGM406BPxes9TmHYHpcNtYHf+WIv5uZbMsBoJSw0+5DKaTDaj229PNEpMyeJF2t6Vv
         skp2zLZhaSMPbMTk8TXWSW8urKx/EFjk1nK8t5VpV/G+IahcuFuAwxLHGpK4DCWF+Zz4
         apM9d0dv9XhG7wjMEdqBc/5u8C4cWh/IHrNYrInNXPKDJ25SirYy8sYZejNNDuuVALKy
         7Mjc6zOKa2jpiCVq2xykUsFj9935627/HJvZp5/7jEjg+K1jvmpUp0ynzx1jHHRm7feC
         l8ng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWYkEJDQzKlHakvmdHAyIEIJ1MHrk5oOCawEjuN8tKEaz+Kdlgo
	QQLOb0v24EcFKfes7rLJvWA=
X-Google-Smtp-Source: APXvYqxu++hCordGwEEv2xRdkth8HblRY2bnW80/9Q++EE0XXf5RBNxayA8PWo2WpNeF8TwQmss0WA==
X-Received: by 2002:a37:a70b:: with SMTP id q11mr3274913qke.350.1574266906865;
        Wed, 20 Nov 2019 08:21:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6d3:: with SMTP id 202ls923263qkg.6.gmail; Wed, 20 Nov
 2019 08:21:46 -0800 (PST)
X-Received: by 2002:a37:9e41:: with SMTP id h62mr3274210qke.85.1574266906402;
        Wed, 20 Nov 2019 08:21:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574266906; cv=none;
        d=google.com; s=arc-20160816;
        b=F4LfzzIp73nB9ZzmjK/qUu2f91SfUA4JS69FSD2+c7wXpFf4xzYkeP6xErQY9gKfqY
         vpUGrYSMOKogcE4bHOaqSVyRI9k3s5ZV5op4m3FYZaAFUlmoP8jDv2MUkEbV32u7Wgg1
         rN86QZxaYszfoTs+ceLkqaK5Q2jP8Anf2i9/Fp26yGDvXpww2FD2vRQgz0ObhNhAf9c2
         hRMNqDns1ZKDIJQj2K1lE0+gLu7v/jI1eTljHN68D45is1v2g32RD07RcQLGzu6jVDPT
         yzgkzewAlR5zOAO/J6dUYkEkMI96Rjl9lyoL1F2HvpO0vVJJgwBEq0IpbWlzlkftsfLg
         BWvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=JZ5/HEhKbpgWU2FvFNdd2zJCQ3oklPprPtth1sImktQ=;
        b=czV8radkPmPQqb7OPJ15wjXtOVlFz8XiLMnDfwmlGtOZfEAaP8o0UaD09+LPEVf7LJ
         BxXTDkFlDXe+k627qW5TOYnlVEL3BerZpPO+NwYpK0TkJIh8ksyud2KJuuO42tZvEJzr
         hrKDWHI+sdz/jljpqB6qx1LOGPJ0uSUGBnQAuF+tyZA9FLVbLEbfZRTFV3xzLHEMgDxh
         tEeAQ7wfN9wa+sYTELhnOKxZYVdAIcOFTGOnz1sG1BsDQHN6YrVZn3He9+/IVbwWppJA
         +xYSPiK5O8gOA7+SRkVpPDrcbOurv6Su6/riPH6nb4y7TsHo56GrEXrq96ttpTFo0eVs
         0FIA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id j40si1708346qtj.4.2019.11.20.08.21.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 08:21:45 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga105.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 20 Nov 2019 08:21:44 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.69,222,1571727600"; 
   d="scan'208";a="204775025"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by fmsmga008.fm.intel.com with ESMTP; 20 Nov 2019 08:21:43 -0800
Date: Wed, 20 Nov 2019 08:21:43 -0800
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Borislav Petkov <bp@alien8.de>
Cc: Ingo Molnar <mingo@kernel.org>, Jann Horn <jannh@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, "H. Peter Anvin" <hpa@zytor.com>,
	the arch/x86 maintainers <x86@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	kernel list <linux-kernel@vger.kernel.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Andi Kleen <ak@linux.intel.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120162143.GB32572@linux.intel.com>
References: <20191120103613.63563-1-jannh@google.com>
 <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com>
 <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com>
 <20191120123926.GE2634@zn.tnic>
 <20191120132830.GB54414@gmail.com>
 <20191120133913.GG2634@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120133913.GG2634@zn.tnic>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 134.134.136.100 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Wed, Nov 20, 2019 at 02:39:13PM +0100, Borislav Petkov wrote:
> On Wed, Nov 20, 2019 at 02:28:30PM +0100, Ingo Molnar wrote:
> > I'd rather we not trust the decoder and the execution environment so much 
> > that it never produces a 0 linear address in a #GP:
> 
> I was just scratching my head whether I could trigger a #GP with address
> of 0. But yeah, I agree, let's be really cautious here. I wouldn't want
> to debug a #GP with a wrong address reported.

It's definitely possible, there are a handful of non-SIMD instructions that
generate #GP(0) it CPL=0 in 64-bit mode *and* have a memory operand.  Some
of them might even be legitimately encountered in the wild.

  - CMPXCHG16B if it's not supported by the CPU.
  - VMXON if CR4 is misconfigured or VMX isn't enabled in FEATURE_CONTROL.
  - MONITOR if ECX has an invalid hint (although MONITOR hardcodes the
    address in DS:RAX and so doesn't have a ModR/M byte).

Undoudbtedly there are other instructions with similar sources of #GP.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120162143.GB32572%40linux.intel.com.
