Return-Path: <kasan-dev+bncBCBMVA7CUUHRBONXU2MQMGQEZZIEHIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 51EF75BE3CA
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 12:53:47 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id u10-20020a54438a000000b003451c5e52b2sf1242972oiv.10
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Sep 2022 03:53:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663671226; cv=pass;
        d=google.com; s=arc-20160816;
        b=wZLY/C7/f+h775KudI4FrqYoJKssBhofl1UVINEsIk6ucBbxQFGtzh/BDKADHRV8vV
         9vWFiGB5SAaww4oL4Q86bT/iLeX3cRmysVkYBCWbPF0xkF4za/U1HiqNtIcXDuWNxKKZ
         W51M9GZEnE8mVm50CINX32TMzOwOz9uxKMmAEgkpNequ8R4rZXTV89nQyXZiYghpE4rM
         4ye6nh9pNldbNQRM9q9vfpG3dzdIJyLtC3dCRZ4ANZ3cUKvfj4oqb0Z6+X4yEMiOjXbS
         MWscox0kqvH9eC8NoWuvnmcIMF8vApLMI1qhdR7Yt4JDGL1faVmGlqCI6JnLsBeRup9r
         yZmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=sFg3X4FaboKggh/Ww4H7PhvvRbS0OhAUdvS6oqmpOlM=;
        b=gF47kt45iq//s+8crnCtOgMigzI9muk48vgoZbNLElpreKySC5NaScIz+K7vm7Hlwg
         tts1dJql3TKY0Y8Dx2epZzR8QNYHfw309NvX6q1JMykDd3c5jPb9lVi7fYnGycZF+W6+
         hv3vPBcFGK1UoxrB8euO0kbQzTCmpPh1hF2nx4Q5zwxkku0EiYUpdtU/zZT5jBNZzWxV
         K8uN8uu9E9E15RqL2ITWecLalDOJ2hncJQJLeoGcVchuTDBpO+BFt/hGW1qYWuwraN2B
         EOmqKD8iUuT30VsjYk7cXBhPUGAKj14ceZFWroX1bw4TNafc6+s+UV3ioWAYXqgOfzM+
         7Q0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kwUuVl6q;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=sFg3X4FaboKggh/Ww4H7PhvvRbS0OhAUdvS6oqmpOlM=;
        b=CxuqEzjPJ3SZ8OPs+LVwkiQjtpAEj/MbB0NyiOAp2BOQMjS99w4dWbfmHkFHfuUG9l
         yt24yYKVpDzV/w4Txh2WaK4OYVopzZL/+dbTOuouSMOp5Y3AzqxMkN9J9SNJktvMbIdw
         I3zRal7gUE7io3AXU1sdQnQGJr3Be7fxcL+3SDQDsqKU59lDct+UoruhPm3q4ziVqCzJ
         K8TXEPUXpWQM9t162kMkDALwU4h+8+/5sEAjQ0lDhsU/VBZYkcEtScr7df1ZcIIpii7G
         0NQzUefQcTgKIkz3uGH2frQRWvKvFZz9E6wZ5+QsZNAWwlKz9YvuiawouvILKjuZQt36
         0svQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=sFg3X4FaboKggh/Ww4H7PhvvRbS0OhAUdvS6oqmpOlM=;
        b=4I6f5+VClHgQ6ozDmXuDwHVMINNVcK8tDpEGYuATURuQD+0/3SkQuL2nsIetz9OaxI
         PGNlZDA31x+MraMLKjyF96tfUSPdirg9KIV5FwWE00Cufp3zUD7DKsbMIlDO4JK741J/
         K1jDYmuRKhFdVfsa1PJoImwMNayX2CoANI78dHzWORRoC2jSp7yLlFRZw1sB+aPh7mQT
         c/KbCVttHjAkPudXX05R1i6Lv6Sxk77A6Cppsm64lPd83PDsq4/4nM+oNG7CazUOxQf7
         FJE6nuaAAjV01oMXunSRGV8JT91sYPrR7XSNG9LvTI8XsYYMsytFmat6t+Mc3mw7h6Zp
         j/cg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3G/BBekm9u7pbpTcZepS/+ZxckZmMbr7z9lCZEl6utkjx/EdJi
	a+PeNm0prbq/8zi1heO4eQc=
X-Google-Smtp-Source: AMsMyM4cZTJu4+QtWDlpQ8FT8+m0jEk8F+YhyQedaztn6gyaRyxiUHcNN6XoDVnRCIU66zXkd1Jgzg==
X-Received: by 2002:a05:6808:9a6:b0:34d:8a96:714f with SMTP id e6-20020a05680809a600b0034d8a96714fmr1241869oig.255.1663671226018;
        Tue, 20 Sep 2022 03:53:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1706:0:b0:342:fca9:5e23 with SMTP id j6-20020aca1706000000b00342fca95e23ls2948466oii.11.-pod-prod-gmail;
 Tue, 20 Sep 2022 03:53:45 -0700 (PDT)
X-Received: by 2002:a05:6808:1b08:b0:350:26e2:36c8 with SMTP id bx8-20020a0568081b0800b0035026e236c8mr1190370oib.149.1663671225681;
        Tue, 20 Sep 2022 03:53:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663671225; cv=none;
        d=google.com; s=arc-20160816;
        b=XsFD4iV97LZRvdyxXq3VloBFFgjin+/FwtWXFkeVHOuyS6qDYIYzlVjLuJPq3eqnrp
         46hXybRJWxAGO+2PltRx+kCKnGTksUmkczdjcQg0KvCwZ7THECocVSSrwM7hkUwOz4RM
         NFf1AjHHZ0Ub1Y6+aXdqtxsdBCtyj/cT9UPItgSfxvdzJN4finJXDB/vBNNXboC4tjWH
         CpyFOBISLZz5Ofp24s0jnftWzwfBZ8oFHdGKL38AqTT7gc0/Qz7ee++xBFmBtv2vZqzD
         vPoQ3lCnxsqdgIncL90GHcXgaERcHrOlmUyPRgaduK1BvHKyc5/MFcy/koOA/wLvuYQh
         5Tvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1QWPtJW7T0OwnEsYCwgHRB3Ll9gyuVVtFGxKesNHmvA=;
        b=pwS/AW/X/rn6TPy2zirPoVBT1yjhD00pkmaKFd0To2Oz01A7hja2aBpnwg+N+WVKvk
         0kOxVg076J5Q/j3sEy9TwDlFQEaqS7i0DxFZ8TwtB3Fbr+rP6QevapOOJPEYhldct5Ke
         kkjUVdd3gxg7e0XzNWkhcG+liw9VjHBKhwnjm+2dgnTY8Iki4HgWOpkWkXCGk8WkPyXj
         0YbFA/W0TlW/1CvPyyQqCYg718VzmN8NzX28DN6J+vwAlNOmBFtHVjCOTVBMuOS8CTl/
         w9dS6tJxTEj4pZ8NiQiBGR68Jwu+Vp2LCyHpMqhmajK+/XwLUiN0KwkEyBTPyjdccQn3
         2QKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=kwUuVl6q;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z42-20020a056870462a00b00101c9597c72si217274oao.1.2022.09.20.03.53.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 20 Sep 2022 03:53:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 47081622DE;
	Tue, 20 Sep 2022 10:53:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9AB41C433D6;
	Tue, 20 Sep 2022 10:53:43 +0000 (UTC)
Date: Tue, 20 Sep 2022 12:53:41 +0200
From: Frederic Weisbecker <frederic@kernel.org>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
	mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
	ulli.kroll@googlemail.com, linus.walleij@linaro.org,
	shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>,
	kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com,
	tony@atomide.com, khilman@kernel.org, catalin.marinas@arm.com,
	will@kernel.org, guoren@kernel.org, bcain@quicinc.com,
	chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org,
	sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de,
	dinguyen@kernel.org, jonas@southpole.se,
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
	James.Bottomley@HansenPartnership.com, deller@gmx.de,
	mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu,
	paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu,
	hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com,
	ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net,
	richard@nod.at, anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
	bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org,
	hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com,
	alexander.shishkin@linux.intel.com, jolsa@kernel.org,
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu,
	amakhalov@vmware.com, pv-drivers@vmware.com,
	boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com,
	rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz,
	gregkh@linuxfoundation.org, mturquette@baylibre.com,
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
	konrad.dybcio@somainline.org, anup@brainfault.org,
	thierry.reding@gmail.com, jonathanh@nvidia.com,
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
	andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
	dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
	pmladek@suse.com, senozhatsky@chromium.org,
	john.ogness@linutronix.de, juri.lelli@redhat.com,
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
	bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
	vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
	glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
	vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org,
	linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org,
	linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org,
	linux-ia64@vger.kernel.org, loongarch@lists.linux.dev,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	openrisc@lists.librecores.org, linux-parisc@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
	sparclinux@vger.kernel.org, linux-um@lists.infradead.org,
	linux-perf-users@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org,
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org,
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Subject: Re: [PATCH v2 11/44] cpuidle,omap4: Push RCU-idle into driver
Message-ID: <20220920105341.GB72346@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101521.072508494@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101521.072508494@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=kwUuVl6q;       spf=pass
 (google.com: domain of frederic@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=frederic@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Sep 19, 2022 at 11:59:50AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, some *four* times, before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Tony Lindgren <tony@atomide.com>
> Tested-by: Tony Lindgren <tony@atomide.com>

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220920105341.GB72346%40lothringen.
