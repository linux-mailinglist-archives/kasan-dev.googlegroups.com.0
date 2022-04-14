Return-Path: <kasan-dev+bncBDV37XP3XYDRBTGI4CJAMGQENNSZUOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A6F500FAD
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 15:40:28 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id n4-20020a5099c4000000b00418ed58d92fsf3079909edb.0
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Apr 2022 06:40:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649943628; cv=pass;
        d=google.com; s=arc-20160816;
        b=dr5bUD9aFASb1YAe+1/5HKAW40ao2mx3Rli8Ex6zQmN4Z1XsaPdDYCHkx7I0g9R8Cm
         fntZ2cRfNnMAB5k/RoLMggaeaHfqvuRPGDo1tqAi+HRTAV9/X372xBj7FuXCYwejKWtm
         0PA4Q0fPElNjJhGs/nfYeexgNeaiV3Vzu2LpWkSX3yXBpAZe6P7Et3DBfkEnAEdo+0nB
         6gNZVw6zOSDEJUAXSoPGc4K5RGwUmKpfOeQjdYyqC92l4vwcSX8Lk/8Y5vwjubcqht6r
         +6qMJ91sDykljM82+coxdg+NsPEmv/qlauD10LlgJPX1ZVDot+lHotMmUP6+GxWde/fc
         O7DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gAv1JQqVoi5OnjIOX1gorQyBwqQ3xkgD7lys5WHqXdw=;
        b=tM6D1Ld11MHbLNvToA+BzBXVZft+1JIGPDJFHgo3tO6v0anqi/5NIAZh35iY+mowav
         WRBoc8wzryTF7lHgYrqoHh0AZXf6N23Lz5377ixujJMy7+Yu0gXsaz6i+leEPAHXHz8t
         cQqdtk4NdCKBUco0BB2lhYsQj8KuEPdz6tRgww7nj1g3HzgBmnhUrPSh18HjYYq+n6QC
         Mhcx3PCW0F7LgJgkqsufjBElNKstfQdlPhqGCnPA8LPfiTJvljCL7o2JKS2MUNBZ+Iqh
         d0pHI5+Xe7SF8KTFaKSKERAFSGnL3SI86Pwt4LYDQ8nLhw/rZQubKbIlvipurCl+uL+8
         kaFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gAv1JQqVoi5OnjIOX1gorQyBwqQ3xkgD7lys5WHqXdw=;
        b=EWEqoHQ8yTWLS+unRKUndqTjsIsq401yMGIPyJrU2VqmXJrNmD+DRm1awmWhaLo8Rl
         apqfIuKeSP4p2OUu3zALLhhzpNQ0vmt8oswkYvnQNMbBdRyDRE/1pMERA2kJcIbDNXXO
         Hp2KEQPJVAlGUBwF/5DmZSZXCQfX60+uWvCqxHRWvzEWgkMRza6oFNLyZ7edHwsy3s/r
         FP1OK1yK8Q9H94bcMZZ7YboLG2Q0UPUH1mbKrOS5CHm4KK1DWBOcAXKG1BqakBPmbPTe
         wP23A2X7WTpK9jfAVzk34w0SnxsH7ng7W4V9S6mOefuvBVk+IA50vjIbVFk1GFb+cnuq
         WVlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gAv1JQqVoi5OnjIOX1gorQyBwqQ3xkgD7lys5WHqXdw=;
        b=o2MIUx9jjR6aK/8Whue1+pO/kYZcyR3yy8sTrmPh3iX7C6Vv5A0RbO72jiDSZHEku2
         PmuqiQuPjdmuw/guObR2mFIi22FKkHYunKGz/Lx64lgwZ3CG5aqlHCdhIDOA7qFCBhV3
         f+VE3/hegKR9UEhyvU6QdUoPvmMonwHtR/orpqDDiL9/kb2JOVhc7duZA/Id5cfB1phd
         Q4HzgHw+SyZ3Jb/ZRE6O4Vk3fMHA8GeecKctvTvRSYYbErO7752nA+QO0YzVGgyz6V96
         TGHQIkzaK8qMN1XuTjF5tMw3NC707Go38j9HYvBM/g4Nn1UZfycSAKH1kTJ1lRtDDcad
         WlfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DZ/5IpZjNfx+muhvWQ2OB0gCVINnYXcT4l7IW1+54+XO8MjlG
	mZcdJrjeIaMOPdLp5QSwEXE=
X-Google-Smtp-Source: ABdhPJxS3XZUoojxD7IkIAIrQvK6yjxfAZ5TKf8OgaUp+4XX8PbsOSpcZ4ICnPqcUk8CsoYwTk9kQA==
X-Received: by 2002:aa7:d497:0:b0:41d:6fed:9f90 with SMTP id b23-20020aa7d497000000b0041d6fed9f90mr3070548edr.325.1649943628368;
        Thu, 14 Apr 2022 06:40:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8a0d:b0:6e8:c7a3:5746 with SMTP id
 sc13-20020a1709078a0d00b006e8c7a35746ls2640066ejc.6.gmail; Thu, 14 Apr 2022
 06:40:27 -0700 (PDT)
X-Received: by 2002:a17:906:694f:b0:6e8:b720:594 with SMTP id c15-20020a170906694f00b006e8b7200594mr2349235ejs.404.1649943627189;
        Thu, 14 Apr 2022 06:40:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649943627; cv=none;
        d=google.com; s=arc-20160816;
        b=vBc4VZTF1r4cUccVGPoSDkSxS03AIxNRImSeMwtJdF+6QyhjY7KBsBytSTKi13/iG9
         nZ51B96WecGd7s+PQ2o5Mpy7cyDt6wPp2LGTJMqpB4Py9whsgVZj9STPI8ETJs/+7eRN
         CR4sLSYL1AJ4lTmIZuO+yaGu4vyoLlD7zIULPO9j1FlDh9FENpn8a+SUQ8AbUNsRsO+4
         4ZSVG3Bco0ja4xYIjjz7OiN2cnwGs2zgrh9Arpc3FggjIAKQl9NH0t2iEtHlEaBeunjX
         2XPjFOiNJYGs1rGCxzQHrWIPEwIZ8FzhwDIdO5H036u/LC3yVX233QObtoG1YDJFA//I
         qZwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=2VuuKot0bT7dX0fRQ2vxJZG5Y0C9VmUmWbJPaW2UK1Y=;
        b=QRVaw49lo+D79NoPNGMuKGE5MeqBNuawN3/ZKGPbR2/QCAWiGNv9Qx6oL8t4CeEYx2
         l0IRYCmVjYKNO2WqE+3gOIq+fObTlHWEpxMjWUKTN+UPHXcMwyapM9b5N8DxlFkMMkQd
         9Y7GCtZVZV3lNifmNcKJ2p0Vz6bFiB05NGFkgjOQ7W7FMhI5P6ERzILpctvI5pVCh/wm
         /y4IFy+V3Zg1JisbIlL7Pe9Zng0p1oxEKY2RESXUgwFOuAqbf/oh2HplpSWHx1mnUKzN
         GAhwuSa7qoAhjprzQPJIVxqwpGTbvqeKAdZcAinR6kRN7+lo8gV7uvCOrC5gDocPQVIp
         g1fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y5-20020a056402440500b0041b5ea4060asi267912eda.5.2022.04.14.06.40.27
        for <kasan-dev@googlegroups.com>;
        Thu, 14 Apr 2022 06:40:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7E8F9139F;
	Thu, 14 Apr 2022 06:40:26 -0700 (PDT)
Received: from lakrids (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2CA933F70D;
	Thu, 14 Apr 2022 06:40:24 -0700 (PDT)
Date: Thu, 14 Apr 2022 14:40:21 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH v3 0/3] kasan, arm64, scs: collect stack traces from
 Shadow Call Stack
Message-ID: <YlgkRXkCLeQ5IcaD@lakrids>
References: <cover.1649877511.git.andreyknvl@google.com>
 <YlgVa+AP0g4IYvzN@lakrids>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YlgVa+AP0g4IYvzN@lakrids>
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

On Thu, Apr 14, 2022 at 01:36:59PM +0100, Mark Rutland wrote:
> As I suspected, you're hitting a known performance oddity with QEMU TCG
> mode where pointer authentication is *incredibly* slow when using the
> architected QARMA5 algorithm (enabled by default with `-cpu max`).

> This overhead has nothing to do with the *nature* of the unwinder, and
> is an artifact of the *platform* and the *structure* of the code.
> There's plenty that can be done to avoid that overhead

FWIW, from a quick look, disabling KASAN instrumentation for the
stacktrace object alone (with no other changes) has a significant impact
(compounded by the TCG QARMA5 slowdown), and I note that x86 doesn't
both instrumenting its stacktrace code anyway, so we could consider
doing likewise.

Atop that, replacing set_bit() with __set_bit() brings the regular
unwinder *really* close to the earlier SCS unwinder figures. I know that
the on_accessible_stack() calculations and checks could be ammortized
with some refactoring (which I'd planned to do anyway), so I think it's
plausible that with some changes to the existing unwinder we can bring
the difference into the noise.

> generic kasan w/ `-cpu max`
> ---------------------------
> 
> master-no-stack-traces: 12.66
> master:                 18.39 (+45.2%)
> master-no-stack-depot:  17.85 (+40.1%)
> up-scs-stacks-v3:       13.54 (+7.0%)

master-noasan:            15.67 (+23.8%)
master-noasan-__set_bit:  14.61 (+15.5%)

> Generic KASAN w/ `-cpu max,pauth-impdef=true`
> ---------------------------------------------
> 
> master-no-stack-traces: 2.69
> master:                 3.35 (+24.5%)
> master-no-stack-depot:  3.54 (+31.5%)
> up-scs-stacks-v3:       2.80 (+4.1%)

master-noasan:            3.05 (+13.0%)
master-noasan-__set_bit:  2.96 (+10.0%)

> Generic KASAN w/ `-cpu max,pauth=false`
> ---------------------------------------
> 
> master-no-stack-traces: 1.92
> master:                 2.27  (+18.2%)
> master-no-stack-depot:  2.22  (+15.6%)
> up-scs-stacks-v3:       2.06  (+7.3%)

master-noasan:             2.14 (+11.4%)
master-noasan-__set_bit:   2.10 (+9.4%)

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YlgkRXkCLeQ5IcaD%40lakrids.
