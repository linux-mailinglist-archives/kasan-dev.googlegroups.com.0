Return-Path: <kasan-dev+bncBDV37XP3XYDRB4OBS2JAMGQEK5BQHUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id C92474ED9BC
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 14:39:13 +0200 (CEST)
Received: by mail-ej1-x63e.google.com with SMTP id gx12-20020a1709068a4c00b006df7e8181cesf11450474ejc.10
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Mar 2022 05:39:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648730353; cv=pass;
        d=google.com; s=arc-20160816;
        b=lSAS32fMYiSvt9b2pe+jq4eW+idEnD85ve9Mbkt1aW1g6/7zjslpWueLaZsp6hGLrM
         HoSISJjQ95mlx3t80lhAdJm/oF+r4zy9tWbbGZJftfO2PnzIGZkcoQb9GNAhj8oPpVTB
         Wq3SZ/3+6FgYM+BIhY/ykBOkV5czoeNE7vaYV5yPiHwQ2Yk6xo5f64s9173lgIgO7Fue
         wZzdEjIKMAjR6hqxwOw21qyoFdKVfvdukqZ6iBFBfSTBY+5hdQfSWJi2ZyxwztmG0EqD
         +NFJSyfl8n0eDjIRoXq3Iia0pTSKpJDvoZmC9cKN3of2vkrednKlnjUtPsBrMwCLiydW
         a+Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3rmGV1juGuHMpzetzG3qopScitn8AKPDUXKsTZQralc=;
        b=HnRcL/Wg8CVbk0UARWJjyqLw9xZbPoupsgu7ED6MF77Wmpc0hXjkEIl4WcJBcuFppW
         5sRmzAdxRbOTb8/+7+JQjfKY3t4xGx0FkumCzPrM26dJVvY8IlHLn0yL8MPc9E8cKsKT
         YX7Tcg5XLbSWFKN4lw/v9B7YPYaak1xIBCCpbFLPoRgLbsi5tOf+ch6+D9bAaJSg4+Qd
         Tjx36mPCz8pF0GzqLbSggPmePc1p293MO0U1ipZ4Wq/esyxzXEahz1xnHVn9S85V3NtT
         mHnfAf5nT1ttjd9+6TwS4Xfr0OR01afT3tBCw9pOGIqXWBK4N0PknQWngMG+6zeeetnD
         t1dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3rmGV1juGuHMpzetzG3qopScitn8AKPDUXKsTZQralc=;
        b=PRCDvIFjfsv6PCZuNqqgJkS3BSRigRudSqVKM7wK9oDLUS0QKf7Kg6YBLANnH4bFFL
         UElkWBfnNQ0T3x90gsm0p0HFK5efxUIBn/i5Bl/CzQVFOTAnM9OVRvMr71bXIG1YA8BX
         mCf0ZMiQTYBMzhBvr8CWy4DRYtNe53q5XJZNW1T67QdT5Edf8gZmYQ9vekTIUuiEUwzs
         j5SxhUdI3FqJ84FF0OTR7tC/YieeWTh+yl9u2Z5WfIZ/gCiCwECKlETTZ/mPDRg6Tcj6
         ZM+3rGul+BJSJkKtYMXyoAaz0iojKIbnxLuLI+zijulo8fKbcxUBv5Bj5lvsYq5OMiG2
         TGrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3rmGV1juGuHMpzetzG3qopScitn8AKPDUXKsTZQralc=;
        b=KqP7IaMEuc7hzcfLfXqvdGJbmpRvph80QFVAkdD3q4wg1Bvw2Ckp69UrQjRaqGwVbE
         a+ECY+ohatDSLJ6gEidcohUz6ysheI/vzjxbPXfJdslBjKY0fsfS8JJggeWCtQML/O3B
         iqMqrM44VcPaIVaic9mS5XmMyeBLjFk/DvWrFjFxj0fHx6Hnsak90W6V6sCrGVloKg2a
         wJGjWHaLPtzfq2UtCIaPQm+kShCyFakmHWgSHeIpMJ5jr1ir/MdXPPIxu68gKVts/ON9
         c8dbjRHebvuEhOasT+Gf1yO2BGImPDZiCjKQF9Q2hJsfy2m2SnYSahN3Gv52uEtJN9gu
         m/0g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532v3p+z3ZjouJpSf4SOyTdycMhYwZslFVW0liJoreVL2OY+rfpQ
	FbjXjo50HzmDPucyB6bdxUc=
X-Google-Smtp-Source: ABdhPJyljUPRiyQq5EB0KpVJOXCCvcTRLVLiBdVUm5do7sR7l9HlFKAEEn7aCR91xVSCldK3LCaUug==
X-Received: by 2002:a05:6402:280f:b0:419:4c6f:a91b with SMTP id h15-20020a056402280f00b004194c6fa91bmr16140438ede.84.1648730353448;
        Thu, 31 Mar 2022 05:39:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:7e8a:b0:6e0:47c8:10dd with SMTP id
 qb10-20020a1709077e8a00b006e047c810ddls2948134ejc.7.gmail; Thu, 31 Mar 2022
 05:39:12 -0700 (PDT)
X-Received: by 2002:a17:907:2a53:b0:6ce:e4fe:3f92 with SMTP id fe19-20020a1709072a5300b006cee4fe3f92mr4755356ejc.389.1648730352430;
        Thu, 31 Mar 2022 05:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648730352; cv=none;
        d=google.com; s=arc-20160816;
        b=unZ9c76kBlkipsn4fMOcUiHyhuMRyv1jmSegATav3Utq2ih6Z6xV5lQsvGiMruhg4l
         DV2K2MNR1rgsShyqYfR16O7yDJqvTaoA7bJ80Ga2nLitqXf+KQgt2jXq5r8G3TQaHpq0
         7HXqSVt05Lraq1k2kbE61ujENeZLWUlysGLMXLSZAeLhOurrMbMUH4C5hwzWW432kc/G
         FnRml+KGtd9aWWm1x+xEKy8ALOMnjRgkembZ6FU88sZePOTHzg9ivwLjDfLo1EZT8FjB
         L485LD6scSAUnQvtxETPgTu4sCduFdKxtbu8QHTn9r/cW4B60SXZkcjIbfjQTrfPpbAn
         qg4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=uimB3CbDpS0DUMhyGl7lXwsqLbLRgTTv+8wuN43Tu1A=;
        b=Gw4+vOiIvjXmIvW3RIzZC4k6riq5FCp4TunDxm50jdU5KqX8VikZIz7dxXq67awmoG
         oe+xt1HH/E8Ejc7MhTZAY01pqh608F0NR4nLmlKdA1L1eYpDsfKDtd9kjzGejm67If8J
         qSOcPmKOTzrzcndZrpVGf8hblSl9WXukYpV0Id9ZZ7cwYteH6DU+6acacSHqJNpN+duD
         sbUwMrvK/xsEMv71VbZq7BGLu9Db0eCZoI/WthGch6a4hG7TWrVKbaW1IM5Gk62NhqVn
         ArN9KRSX3e118HG+kzel0KNH3f65bZ/6EbmZ+hld7hkGtqho6VLd049etUZLleduIzVE
         7npw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id v11-20020a50c40b000000b0041b5ea4060asi317222edf.5.2022.03.31.05.39.12
        for <kasan-dev@googlegroups.com>;
        Thu, 31 Mar 2022 05:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B975123A;
	Thu, 31 Mar 2022 05:39:11 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.21.81])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0BA223F718;
	Thu, 31 Mar 2022 05:39:08 -0700 (PDT)
Date: Thu, 31 Mar 2022 13:39:01 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
Message-ID: <YkWg5dCulxknhyZn@FVFF77S0Q05N>
References: <cover.1648049113.git.andreyknvl@google.com>
 <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Thu, Mar 31, 2022 at 10:54:08AM +0100, Mark Rutland wrote:
> On Wed, Mar 23, 2022 at 04:32:51PM +0100, andrey.konovalov@linux.dev wrote:
> > From: Andrey Konovalov <andreyknvl@google.com>
> > 
> > kasan, arm64, scs, stacktrace: collect stack traces from Shadow Call Stack
> > 
> > Currently, KASAN always uses the normal stack trace collection routines,
> > which rely on the unwinder, when saving alloc and free stack traces.
> > 
> > Instead of invoking the unwinder, collect the stack trace by copying
> > frames from the Shadow Call Stack whenever it is enabled. This reduces
> > boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.
> 
> That is an impressive number. TBH, I'm shocked that this has *that* much of an
> improvement, and I suspect this means we're doing something unnecssarily
> expensive in the regular unwinder.

I've had a quick look into this, to see what we could do to improve the regular
unwinder, but I can't reproduce that 30% number.

In local testing the worst can I could get to was 6-13% (with both the
stacktrace *and* stackdepot logic hacked out entirely).

I'm testing with clang 13.0.0 from the llvm.org binary releases, with defconfig
+ SHADOW_CALL_STACK + KASAN_<option>, using a very recent snapshot of mainline
(commit d888c83fcec75194a8a48ccd283953bdba7b2550). I'm booting a
KVM-accelerated QEMU VM on ThunderX2 with "init=/sbin/reboot -- -f" in the
kernel bootargs, timing the whole run from the outside with "perf stat --null".

The 6% figure is if I count boot as a whole including VM startup and teardown
(i.e. an under-estimate of the proportion), the 13% figure is if I subtract a
baseline timing from a run without KASAN (i.e. an over-estimate of the
proportion).

Could you let me know how you're measuring this, and which platform+config
you're using?

I'll have a play with some configs in case there's a pathological
configuration, but if you could let me know how/what you're testing that'd be a
great help.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YkWg5dCulxknhyZn%40FVFF77S0Q05N.
