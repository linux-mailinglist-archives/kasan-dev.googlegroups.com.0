Return-Path: <kasan-dev+bncBCBMVA7CUUHRBEUAUKMQMGQEVDJEFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 09CA45BCF5D
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:43:31 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id c188-20020a1c35c5000000b003b2dee5fb58sf15258765wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:43:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663598610; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+k3z/et3ieA1dJ6i5q4PWNWLERsIu/OxiwND6sQ6X6/eKcnYB130LfKD9ruwtnxC9
         AuRKSd6MDNJDZ591A4ekAtsMg4qKDBhKSNoxbAJmkOJkgYbpw4Wl27AE7bHl54aAuhMX
         rrjYw05GmC8xipbo9oUoJ/KRkYhHV/WgXJ0pLoPXxnMqi+aOL++vE/rkw1ENcUmrEAEd
         gHp9vzNi79zDK7suYbpF8z81TQ40A+Up+67/2nyCuPmqacfZfneqL68jxNNgg0ChZ2W+
         hDsFfyljejVqv2ENXRroFAAgwtX4QlrD4ZOkqz/GzuJE9BmYw8YnLXRiVhJYlYsxTL9M
         yMHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=yUm0pS748q62MToCw9/fcmd1Fq1CilNv/mKG6jCF/K8=;
        b=Df7Et5X9jcDcB5YbaU6oh0nGEoWsLvkmSKTGrCyJ138F2bE0lqce3sW6vjjHMaOilQ
         m6Vwpv/H/A9JIS/2+zWkOCbWZKi965s0RXzdiNc/+yhDWZAgC3LkaJBsW9Vlb2qo21X9
         j37bVm6rkcY94iC1r8A6WGKS21Wx61XdkrM5p2wBrd2Oxddh1PqodQ5/9QZCsGj7GsQd
         tjYf3avgBCOVVont90sQA1wLC5wNw4dzZHZNmSuhhiwjsW9B5B0Tu0aVy8kGX81MrUJo
         id30LYgexAX80pVElCEXWuFY0jaHvnp0fRwBDVn+OJgSg9vPLlBOirUCsQ6CsyX8B55t
         kPhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f2RIwdWt;
       spf=pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=yUm0pS748q62MToCw9/fcmd1Fq1CilNv/mKG6jCF/K8=;
        b=LiyJ6Z8IyRo0F8e/3bzMoYZVg3LDHYECzJytIoBV/Ia3UjdsFEvzB0Ny314GXg4ASB
         VCtuNxjh7S4LR86jgdwaQwiG5QBUZ8b+W0SmE/SpJ0N50Hvb5VyvgGXUbeUfhyILd2Hd
         tL4amdocMzr9AvJDA37i5eFweZyjxdB5TJ9xYm04N4M6FyyWpYb9D0tt2Aqwi1sHqcBx
         DDTU4QDMrITlT4CbiGhWXPw1L+PUlO6wzbyeVsRgUDdT+A4qFaLq6aY7j8tQG3IfLHme
         90YppMwMD8sbayraEzZcFNoEpkiNyaOETXpOxcxzz1KQ0I0psu5WZn+gjUoXCsGqQms5
         Ue7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=yUm0pS748q62MToCw9/fcmd1Fq1CilNv/mKG6jCF/K8=;
        b=zgy1ZAQThWWNbA2o7DZ5QqEM7AFTYDcp9NhszgU9b744Fl/cEQZHWLD0IIyRVljqqY
         OnzYB53Vi0kETXtpM3XiuMUFBdihVOMt5vAmmYsd9++FbujVpCfIaBbiM/Hoxj5Fp0KR
         33AnnismNlBSyrRF3f+B5oYhh+P/u7PLSy2b/TB4HfSGmREH4nWx5XmApCLjkUtTpYEb
         R5buGV+/HFexjzrqHV1iYyz90/vWnMMCSlMFlNaJZ0mTtEw84IjKyScJ5HQ5d72Bl+9j
         ZKhWcWoHdO4cdxFVJ0R6Yc8C7IiFaU4TuAUIJAGP5HnYrMnwq7LEepfIZxwNAdj3rt37
         zriQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2/besqcOW38KFEJoIqeTVnncpe4kAUIBxj/y3QYnOGWasqOYmw
	CpLMtX80NZwndFc2qhB0txM=
X-Google-Smtp-Source: AMsMyM5cxI6dGNENZ2D0MOj1dNUP7yBMjcsiptxZ0hdFxyqa/0XaVPZ8omrxprY1GyCmBA290AEVQg==
X-Received: by 2002:a05:6000:1786:b0:22a:6470:e454 with SMTP id e6-20020a056000178600b0022a6470e454mr10801637wrg.565.1663598610590;
        Mon, 19 Sep 2022 07:43:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels3973353wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 07:43:29 -0700 (PDT)
X-Received: by 2002:a05:6000:178a:b0:22b:87b:c995 with SMTP id e10-20020a056000178a00b0022b087bc995mr1782779wrg.715.1663598609643;
        Mon, 19 Sep 2022 07:43:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663598609; cv=none;
        d=google.com; s=arc-20160816;
        b=a3Dnlu1QdVIhPzW+8eI936bBnU0IsImq+Cb2j/jQH+qwTBiKuBlkRDdUXhFwagXNek
         +CgujT4CHxtTbPIOlNmz7YMsrrGBKeM10/9VP5UlI9O/fR07BQPX5hshkkIVf1Qa3Jor
         aTrblsFKY4arFf+0UBH2MxkV9I0BAy7Ktwnmr+6KYbDNZnaUrbI/m2ouboC3tr08a9oA
         26LTGg/9fv0iFiPZW0StR5BCRgexhAHBSRLyXNWCOVNdYc+TR4NMqHXCmzqc94UkoKsH
         XArX0hNqlmHmUBkkOyQjY1hpupV5/sTqR2tYFchoA9rBAn1rgF0NHy4sGYdQFO/gwO4F
         9FIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uNDCKjoo/jd+jf8fc+pVveC6b+j5kegscumLEig1l0E=;
        b=kCoKSz7Xe0t4a3MWIjZ16vR1zDmV4dEAGvUwsWiWpQxaZ+hG9LRGrKsmyE2SYbN0LR
         tfNoGhbllbNF/Vrax7Awpxx145UJfymK6SjK101cvyGs/aP6gfsoPPVy+IZGRBvt9Lca
         frP09hrjIFEXl/23GY+EezQ4jxI2DSHX0KFLvMWy357MFUll26o6X2oWwCtcERp/vYF5
         tI+/wHLXwCIw65n8TVW8aeWeZT1XccgwdWEsbhnEiZrU8ahmt90EeM9GetxIm+OjUh2+
         CyCpOnine6y9jsgiOWDTez1690w5tvdDSpFAsdgHaUBoi2ujdovG1Yie/lO9wau0PRXl
         phbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=f2RIwdWt;
       spf=pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bz7-20020a056000090700b0022ad6de79d6si373257wrb.3.2022.09.19.07.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:43:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4F491B801C0;
	Mon, 19 Sep 2022 14:43:29 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 05DF7C433C1;
	Mon, 19 Sep 2022 14:43:27 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:43:24 +0200
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
Subject: Re: [PATCH v2 09/44] cpuidle,omap3: Push RCU-idle into driver
Message-ID: <20220919144324.GA62117@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.936337959@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.936337959@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=f2RIwdWt;       spf=pass
 (google.com: domain of frederic@kernel.org designates 145.40.68.75 as
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

On Mon, Sep 19, 2022 at 11:59:48AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then teporarily enable it
> again before going idle is daft.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Tony Lindgren <tony@atomide.com>
> Tested-by: Tony Lindgren <tony@atomide.com>

Ok now with the cpu_pm_*() informations that makes sense:

Reviewed-by: Frederic Weisbecker <frederic@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919144324.GA62117%40lothringen.
