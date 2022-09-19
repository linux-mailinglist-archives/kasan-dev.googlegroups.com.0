Return-Path: <kasan-dev+bncBCBMVA7CUUHRBLPOUGMQMGQEJWIYJ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 05E6C5BCDE2
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:05:35 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id bp17-20020a05620a459100b006ce7f4bb0b7sf13572190qkb.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:05:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663596334; cv=pass;
        d=google.com; s=arc-20160816;
        b=I1/F37jJgTOMOOpgH9ACZ/esyACJQHu0TALL4nHiFLDAIZunL+euwA6AfbkiLEeXLu
         n143jKlv7oQQlTDym46u9zELwLlzTRyJLJTkUGbz2glEDCEPahhnTL1frBlXqYPGaZ2o
         q5LRvIbk+EJcjZ7hMeVbgIjtuJ/idHhjg+bGOA+he0lSzsKeviDf8ApE99bJZwUKajqH
         Z5etyDEMN6ffxA+atCBLZWoc4WJYRHFKJTaNV6e10wXSx+caLg02uk2HMKz/5j8Sj1ii
         k+GP4LEy20NJQVmeZl5RS871nqGt19Hd1FgSzGrWIR3AD3sYOPBWXdMxiIek2FpUkfLE
         Nc+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=qQIIftcyFox5FEHVZQ9P1b5jmg0hjmkhgXslGfLAc6A=;
        b=xnUeQU3Fw5X3GfZ+qyuphmQWm7305RsahV17457g4cICkK/2PTmpZ9oPHlGLzqm31C
         VmpqRoKwVuvS4g0MmhWGrJ1aFfR3xZv9grlecEKkYlO9C23ZKunKfD2nIRqN+pWpwmQG
         oTDTSIK3lRBf8v6pkyw5KRZF94PdLMJ8wzt/lgMY820nAARpS03eRRwcBaCCboxh5X0A
         0eYriH71+VZI6bOaPB5HlX+LSxuTbX10aIPD51L5V6MjF23DA449OoPhHfFZ9LwXHG7v
         2v5fc25w0bz6PaFScNNIJurCErHv11PKQz1DJGrmrVzHJ2etfon4gYFm4myxfESInxnt
         /lAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GHvlWwU9;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=qQIIftcyFox5FEHVZQ9P1b5jmg0hjmkhgXslGfLAc6A=;
        b=F2f04meVg3d78sNtREWIS6xO0cN88ZGi27fihsEwpjqvWOO5pze6MOxazGzoiMCpjC
         Mte7K6IvJ1UwKb4Kiy3zYcvwINVch7oeKqINSxRqT4W9mJZtt6WuWEGPMGnCsZAd2n9q
         7ypmvhy3EtlnpPs7gjBYgdQiC8km+YDlmGrtn8tTzExgb2acw4zkgbgt212I/GnV58Fm
         OrMAv46rXNPDL7FLmHvhze18izMhgbZQ8JDGLUvnx6t9ZH+n/Vf4Gba4yGIPs6ue+PvA
         INcMV81XJOuupEhDCndcIXAMlNmkbYlqq0585fcOnjTLY94aR1kcsr9u+5s3AkAobOp8
         oArA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=qQIIftcyFox5FEHVZQ9P1b5jmg0hjmkhgXslGfLAc6A=;
        b=EU/ZJ8lqm2V7100Pp9RiAdotXDbsxmo3G1aNYfPpuDbjOQEoPE5/2usgZAgWOuKhC4
         D3o6i2Vz2ModISHiyk0WKz0u5EAP6lFAm9PZyeKp85Nk7OdQftT44p3JtemyhnziwwH7
         dbuDbPlazbi/NGEJ5kE60488C8gRKRspprmhJlvlXwKmMQd9pXMbs0u0sJJ/ICx48T5m
         jFm3q47xK0gt62JWJHWiPERX6m726A4HxkoaIqFUaJGZH6MO+Jv2VHYFUZJW40wLHIN8
         CeLRrhBWUid9E71P7rUTsxOdCGSi+vdx4MUjJ21pE0BCxgMHb8Vtv+EgmfmShmc4BUw6
         lIyw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2gvJGALYp0we6JhLXySQSGSb46UrhbV68su19BD3Cb5LVbI5fJ
	UmqCvdYQBT//zvBR0kcI3XU=
X-Google-Smtp-Source: AMsMyM4x1SfFQknGiKlUJyycaV3PJiUewipmnHdwxV/4KELtrXSXiLYVc0NFYe4ceTnXfS4VOqhoSw==
X-Received: by 2002:ad4:5c63:0:b0:4a8:a722:3296 with SMTP id i3-20020ad45c63000000b004a8a7223296mr14518474qvh.23.1663596333805;
        Mon, 19 Sep 2022 07:05:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:9799:0:b0:4a4:8d60:8e5a with SMTP id l25-20020a0c9799000000b004a48d608e5als2871467qvd.0.-pod-prod-gmail;
 Mon, 19 Sep 2022 07:05:33 -0700 (PDT)
X-Received: by 2002:a05:6214:2243:b0:4a2:902f:2a70 with SMTP id c3-20020a056214224300b004a2902f2a70mr14309395qvc.58.1663596333284;
        Mon, 19 Sep 2022 07:05:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663596333; cv=none;
        d=google.com; s=arc-20160816;
        b=wGNHrQhRYlhb8RRkmvO4mr1iDdUtz4pSo6xQSVVvTuPpr9y6GH2tLbRUM4efIQCN97
         TPq7jVB140G1d0Sulk+cyr9O5tZvoyCFOBw8CZXdmngmKwIy4sFBHj/5/fFhsmIGV2gK
         NSOiKIEsGA+ihRIyttGU042s0SfreilmVYX6lZPEvN7R4/YLWH+CBGTFOusMUdKdddB1
         MUIntef3JqwzgKXFMR62jsELHeGPPJ8zDlgsGamX8vzC3immbrMv8Yczjz5trK+kCP1Y
         yZXTyV+D+rH6sD6v++gaxdVY5y/uQ470QyJph1XWlci2RK+o3T8oQW1yeEypwv0N4y3A
         C/Kg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=HrJUwaCmX8Lvg9xF4hB8aqMqZfruhNh4qHRzAv8EuxI=;
        b=oqpuHEAnvGvUtxeNLh9chQ+1EEeQRiCuLMRecyMsNz/FRFxNg9D3EHjED32UlaHZ/1
         ceFdndWHcf3nlS/lRkTW5VvhNH+Jz7k3HouvVXbU4vMUcFquoP1iFkpLXhfiV9fY9E50
         uEPtEGE7xjoOMWMqUD20DsXXX+SMmhI0dHga5TTkA9IUjxLkZzmFG9mNq9OFeXLntGLT
         OB496qpr+IOGQkx8qDwZMGGEfLVNxf3w3hETheK9+JFxovDhuuo5IFREi96Cotwhqg5T
         iBPag2KFSCNzvyvTgjdSqg/hICV4d0RIIKBJU3eOxgtElLvgd7zII/h0umSPK6lxTtb0
         iTYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GHvlWwU9;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id a22-20020ac84d96000000b0035baff34f83si661644qtw.3.2022.09.19.07.05.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:05:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 0943461CFF;
	Mon, 19 Sep 2022 14:05:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 61C24C433D6;
	Mon, 19 Sep 2022 14:05:30 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:05:27 +0200
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
Subject: Re: [PATCH v2 06/44] cpuidle,tegra: Push RCU-idle into driver
Message-ID: <20220919140527.GC58444@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.736563806@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.736563806@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GHvlWwU9;       spf=pass
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

On Mon, Sep 19, 2022 at 11:59:45AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919140527.GC58444%40lothringen.
