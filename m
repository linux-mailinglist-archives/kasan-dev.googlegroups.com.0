Return-Path: <kasan-dev+bncBCBMVA7CUUHRBU72UGMQMGQEEZLGUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7FAAC5BCED2
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 16:31:48 +0200 (CEST)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-345188a7247sf255804577b3.22
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 07:31:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663597907; cv=pass;
        d=google.com; s=arc-20160816;
        b=0rPLts+1gAruI+VnZ1u4B1ncoxlW9F9y7jIcpV3Dveaqoloe/Dmq7QykD+r7r85vbm
         v9ecoQ4tlnhT0J0+C//KKRcjFKRZ5hbXrKTs8+JJ5RO3HqE8buiSjhr5Q4rsOcy0HkcA
         jn7ew3SNdLqMwwnlUS+2MeIy90U4n8qXTGbzKBBsWNwI9q60e8Z9F2YF2N5RFQYcKQZA
         HcNQEg03Xc6cBVjti4myi5qqfoy1rtvkmY3HHogJ6t0Nbe4n7pgLXoZyA4lkBoSgrOV3
         48+zVFinz9MUZmJkgXSljgfp41dadRRqzVXDN9BppYfPdPRj89Y+XoXYSJQqyuRAniiv
         4qqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xbx2zlGLZ75OSZnKmROmXIJuamcDSYztOJBPtIwR164=;
        b=m9bBTpun/8EbGs07bHKyjBd1PTpygJOl6l+vHnhmFmBN7JMhnZ6SerJdUm+IlmE38t
         zwDTYly2kWMU7jFSfFVcPcY4mrjfv5sVl99CcEBmR+U/1U23Gg/kbT19oG33r/BlP/cB
         IH+ShoKABWZP0WWGc3dC/zAhXDPJS3m8y4EjA844/MONMY/NzV5mkHhFjOYeO1W6OS50
         cneDT/bclRX8NiLaT+d8jTOTdM9Gz2jDI6cXnqnkurUoEOrbohtaoSK6ai1ADGSCDQHv
         dSnBz9AXfHIhbhjqqpP+HKI6oECKQc1MgmoYh4tl8Slq+e06RGQ9TIknRGuLetx45rr3
         /saA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cPr6ORIk;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=xbx2zlGLZ75OSZnKmROmXIJuamcDSYztOJBPtIwR164=;
        b=pAsIvVNthtK5qFGBAASWG9hxtTo4lE4a0QjI3XgBES5Uy6zEDbtptsv7VCn4+an8X8
         FbaQb5u367JZPIbTwHvpo6ZvaJYBlgYa4PYtMW5aAWNA+ZoChb8PGI3SwVMVd9LVWBDs
         WrfP3DgZCJ3VNKsauItjPiSQW63vXGkIAHy6AtJRNnvZGZQCrds7a5cEgE9yHC3wBWss
         Q2dsUNR+BEbyfDy26YLmF2uf3iY+F8uBEPRl6uyFUaMxWUC7a9W0VWZdzb4HvwPxs2Dw
         0yGBscgSXdeeB6EulO6wxEwGdF4qntqAv+6EXRFqvn2XHMdQFr/SMQlCKeO88G8ZSmjU
         Abwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=xbx2zlGLZ75OSZnKmROmXIJuamcDSYztOJBPtIwR164=;
        b=07iKZsr7H5mCJSXv36n//z5z3XRxKfHhELr2CMUGKzLQSodJNXSLIgizXQqinD4dfY
         nnAjyFNuxaROKZP2sOc0RWhNmWihvZ4hdZeTmOAmkpUb9Tyws9/SYqLTPIbiCEBFDTMP
         K8o37DP/i6ByvUWZpsEybfH0wRfk1iuknB/6ZzAEEncUXen9McwQnYwDd+XfXM5DgwlY
         B6Afn5mbKM7iRm0CvfjdSfgooDgr+IRclfy6BVwkjLExfddJsmZxQwxazZSRHKPt0iFt
         4VGUYjImkglUHwzq4tVgLehpJgfhErOhrKqw8oPumnBBCsFXi5FUNRX0fEfIgMfAnYrz
         J48w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0445ZfSCUzFDymGZf9pvpFopdpbMP3s/Oq4+mj+La4F6qrq4ui
	yPP3cfYJQtgU4VBpXdbvZBA=
X-Google-Smtp-Source: AMsMyM6RqPVK6z9ZMmaMUayg/WAypZw1JqAQwHr+LDl5Vc4MQf0ooU992x4hotuvgxaLDgTir2dSsA==
X-Received: by 2002:a81:67c2:0:b0:349:ee79:1ae2 with SMTP id b185-20020a8167c2000000b00349ee791ae2mr15224469ywc.164.1663597907314;
        Mon, 19 Sep 2022 07:31:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:dc8a:0:b0:6b3:e91f:8e6 with SMTP id y132-20020a25dc8a000000b006b3e91f08e6ls1424677ybe.7.-pod-prod-gmail;
 Mon, 19 Sep 2022 07:31:46 -0700 (PDT)
X-Received: by 2002:a25:3307:0:b0:6b3:b370:4495 with SMTP id z7-20020a253307000000b006b3b3704495mr7662455ybz.122.1663597906808;
        Mon, 19 Sep 2022 07:31:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663597906; cv=none;
        d=google.com; s=arc-20160816;
        b=CmK/H0UodxZL37775bl/wBNH9CFw3flzqi7Yt9sp0HRaoKeKWkFZTGY1TIvrJsddxc
         wd5xJo2aPYYWyUgmq+5VXfObSrkabILe8XzXNZG//+Zls022SOIeV2GyBVLWlJUuplfi
         TAmcy2LT5IG/uOZal0IV5QT8dH6OwmYY2o8p84eJieBZrzqM7a/JQtWrrfqiRapDcmyG
         PpaKJkwDGn+wolRuSgU96ccApvsTtRbHaT4TacYhLk7OBmEzUXvjpk3YlvknPjZ885kf
         Hvfd+26BoLTKQscmDO1Isk3+xMbFi8GTJfp221Ds+w2JPVAoKgYjCHpMSJqHUhScY9+p
         IZlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=NkXCfQm/FLpDP/QLaoePbhdmGTT1By087FmiZ+g8tK4=;
        b=AtAY5Ht4CVzDZ2mg7CG+OJruPaa5lmH7cUgK3tD0gqblKQjHrjFUonbeAC9tGe3DN0
         H3IIKQHD4OOAcwj1gKWIJkHbhhyzAFq4quC8CgixahUnb9n3wVS9tWFO8BSXvRd4M7so
         +0huxKu3rT5ycpl5+pVcs42EcwbE7LkAITH/ese/V2U14Y0q76AQjoj0ptwsQOQYrA7F
         xYHYxkrGUUmlQf27kXpym0SInxazk8Aah7883um+pMU7cqOL5H63T6NK4ztOi8yym4r/
         bAXWS592r6DcfoLHxmk/LWkqQtF8aELiIrX8xnl/3OiVkqRHFiQxFcOnUB0nWBTzp9xI
         I9Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cPr6ORIk;
       spf=pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=frederic@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id o67-20020a0dcc46000000b00349f81a2957si705323ywd.1.2022.09.19.07.31.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Sep 2022 07:31:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of frederic@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3E7CA61D43;
	Mon, 19 Sep 2022 14:31:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 884E0C433D6;
	Mon, 19 Sep 2022 14:31:44 +0000 (UTC)
Date: Mon, 19 Sep 2022 16:31:42 +0200
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
Message-ID: <20220919143142.GA61009@lothringen>
References: <20220919095939.761690562@infradead.org>
 <20220919101520.936337959@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220919101520.936337959@infradead.org>
X-Original-Sender: frederic@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cPr6ORIk;       spf=pass
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

On Mon, Sep 19, 2022 at 11:59:48AM +0200, Peter Zijlstra wrote:
> Doing RCU-idle outside the driver, only to then teporarily enable it
> again before going idle is daft.

That doesn't tell where those calls are.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919143142.GA61009%40lothringen.
