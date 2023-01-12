Return-Path: <kasan-dev+bncBDJ7DEXEZ4LRBAG3QGPAMGQESR7OJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 86E61668411
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 21:28:50 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id l3-20020a056e021aa300b00304be32e9e5sf14293474ilv.12
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 12:28:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673555329; cv=pass;
        d=google.com; s=arc-20160816;
        b=s14YEOLLtUAgmDTqBjS0+f7GMyg7dleiv3syQWSqpZNshnqHpLWuFXgOM0PbytT6/w
         0Cb9uwdx4AqC+79vgyBqFiX4tyA792cOVS3DWPrcRynkCUzVNA3suRsELPllZhv/C5sl
         Cpg0BXF7/VGRSW1bQL4BN+mvO08ZXQ4VTtXznL/cRwDe0LSLaXjQCTXrUfSwQakHSRFA
         CEKBAbVNeQDiCBNSco45ti/Gi2KIRDF73/xS99kzBqgUlkEUvQcGPSHi17cufTC1ac86
         QVePMLR9QKtPvKRo1aoF25wbj98nbiLzqNO7gXXpxkjkUq4THetsrZJaoh5NiHNoNabf
         SWkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:date:to:cc:from:subject
         :references:in-reply-to:mime-version:message-id:sender
         :dkim-signature;
        bh=8GZZhlugcymhwLmcy15dnLefE+U2aZPWA81O2OBNSao=;
        b=b+1IRvbyjfq81l2dTvgLVcK8Hp8Y+wPmej+cI8y73bvRRqnUYpZh/YN8kIglqZXFlL
         lHfd9aPBdleqCe9Sh7I13CvL6AEgsXh9vgHcqH6iE5zGhS40J451PC1vOLHkRAM9rC+Q
         6UcNGMXGOQCPZrXNVvokpy2Q/VtI0fQkCQ9L8P6Kgni0SYXR07Q/JcEjYAwvYG6Cs81P
         MFioGzDlAAhOklh5TmjjojY4Inu2wJignF2x/AgPX6FPY2hfeo0DYHIsbg6egVskPgfh
         JkflIUssDBT/npzo32ZUPI6O9wtsPnCt64oL03fZ0c4De5pxSpd+sGQuVgj01ti9dOUk
         XW5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=Ew9S6ssy;
       spf=pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:date:to:cc:from:subject:references
         :in-reply-to:mime-version:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8GZZhlugcymhwLmcy15dnLefE+U2aZPWA81O2OBNSao=;
        b=H/Tg21HHp5xS6EWYZ9Uj7oF0GR0KkYUqCk6F9CPCMZ+eHWf5JdI1b0RJ2rnMWdgMO0
         CNIJkukHe2vH9841c1kRPR29AbXqrHj2iagHOpYDBOwuVeabWFnT6SsCiiyUxKmU3uME
         PjtUD9ns1JYNlkahFxs4uhYJqgosceaIT5VX//mx2mcSc7fDEUsYKGWMvQL82BBL5DVk
         TkP4kotz51UXdJlVX4Od1zcQ/SmZvq9YRHoxGVwbFW64Bnf+HK5Z4CxL+mRP3YBL2ysy
         AzRDgVhxFATd3TNb/70v7uf2LuP4gurBnrO3+Cbw2tg+rb/cxlKSfdQ7twB0kOcXirdF
         HPqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent:date
         :to:cc:from:subject:references:in-reply-to:mime-version:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8GZZhlugcymhwLmcy15dnLefE+U2aZPWA81O2OBNSao=;
        b=It3EAM1m4q4Ypgnd56thimQMF0Js3nJ2WWIWJKA6OqJ/pV1I9q70hvrem5BbNuNGGs
         erOL9Q8iQTy+qlpkgOkzVGk1yNKJvMAkeRqU1Ru2g4O/0bSMlq7YLg8c7aGUs232NCWt
         9O/bN8Oyav0dmJBJFIi6MHnuQYBRb5FN7r7q25UQzsbeWhflBp07mGyuJ90AvM5Lk+Zq
         dfsrl6Yf+UedYVzV8O1fIanNkIoSCUBaq7SEM1TxayLrg6PB9fKrZ1ghQb0gewe5pOdr
         VxUHF+N0+7Zf0CZXUX+C+SeaQwuuQlK1HeWNG7DRQBCnhDKktz+KlEjg0VQ/gejpNgoh
         eeBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2koXbW3sgLyw57yEHGP1YLIqpC9Y/i8L10IfgLhjz7TLNh6c4wpb
	gIPTXHVuAEHrS3QO26FGm8s=
X-Google-Smtp-Source: AMrXdXvUMxsIz9xD+Jyq/kDxX9dtsaISNXalYN/1YBA+gTqGPK21k3wPjTQZmAckC7dVAloISa9amA==
X-Received: by 2002:a02:6643:0:b0:39e:5dc6:eba5 with SMTP id l3-20020a026643000000b0039e5dc6eba5mr2878642jaf.115.1673555329019;
        Thu, 12 Jan 2023 12:28:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:6814:0:b0:6c0:1c0e:f3d0 with SMTP id d20-20020a6b6814000000b006c01c0ef3d0ls567847ioc.11.-pod-prod-gmail;
 Thu, 12 Jan 2023 12:28:48 -0800 (PST)
X-Received: by 2002:a05:6602:1789:b0:6bc:d712:8bbc with SMTP id y9-20020a056602178900b006bcd7128bbcmr57164307iox.4.1673555328579;
        Thu, 12 Jan 2023 12:28:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673555328; cv=none;
        d=google.com; s=arc-20160816;
        b=tB5fhnSDkyqfI6W1Dyu2Gs8CTMmuvy7btUmcuh+z5xkhlJhgORddHaOsmdniYKeFxL
         DE8gNhy/q3nA+VmfZP7LtOLBunPBsMlM7B+pDUcZgShOzjLsKdoF3UgAQ1N94Mvhi+tr
         BC1WywgLr2Ifwo7iILhFxNrWzBf33W6BhBgFt8L+Vs67n3/kOh3DJNrwAHWQWMEhScr1
         HwyitX1HBnZznH4J6a7zQA2XLmAlf97ZB8SF3ESEkVuMzRRcl9qfKhLbdKMW8NtOMQs4
         PasIrFWi/W/Ib2lxvYii7WbbGWLl5C43/tuWUljru628MM+PqCCDTmSWOenTe4IYPrh8
         iTvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:date:to:cc:from:subject:references:in-reply-to
         :content-transfer-encoding:mime-version:message-id:dkim-signature;
        bh=ZbPNLkIUkQwHXCbvQoI2XLaF4ww/POIlS320Sa4a75I=;
        b=pxFC4Vlal/DTt5VShGpzxp3q30+yKMbdHHwiSg6L04maiI8ZoW3vePkyF208ez3N7p
         Gm2rGUK3r7noIQxZnx4oSmC1h2uyA5Zdw6csCnfy955d55Vtdjrz9ZpFQ1AwTiq2QVU1
         I3ubxg1dcGSmAZmR56O8XF7N3qwxhwYwmcw0HQURoGWsFdeJA31b58CYCwxnK1Bh4DCW
         eameRDdmshaMx3DKcXbDlPxWAACSapxvpPAzgIR5tZVgCYsjLPIj6AG705FGBxF2+Yk2
         /Eb74spYpgjNChnljB+rMPsC7ZGWhgIfUaBoS5smOtxB53bb6ZNv/BjvCUf1Pat1eAR/
         1EtA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=fail header.i=@kernel.org header.s=k20201202 header.b=Ew9S6ssy;
       spf=pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sboyd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id t10-20020a02c90a000000b003a05e568358si259477jao.4.2023.01.12.12.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 12 Jan 2023 12:28:48 -0800 (PST)
Received-SPF: pass (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E628F62177;
	Thu, 12 Jan 2023 20:28:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 08847C433EF;
	Thu, 12 Jan 2023 20:28:47 +0000 (UTC)
Message-ID: <cd75c97ac883283fb0764f5862a6377f.sboyd@kernel.org>
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
In-Reply-To: <20230112195541.844982902@infradead.org>
References: <20230112194314.845371875@infradead.org> <20230112195541.844982902@infradead.org>
Subject: Re: [PATCH v3 41/51] cpuidle,clk: Remove trace_.*_rcuidle()
From: Stephen Boyd <sboyd@kernel.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk, nsekhar@ti.com, brgl@bgdev.pl, ulli.kroll@googlemail.com, linus.walleij@linaro.org, shawnguo@kernel.org, Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, krzysztof.kozlowski@linaro.org, alim.akhtar@samsung.com, catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org, bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name, geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu, tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se, stefan.kristiansson@saunalahti.fi, shorne@gmail.com, James.Bottomley@HansenPartnership.com, deller@gmx.de, mpe@ellerman.id.au, npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com, gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.
 com, svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org, davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, daniel.lezcano@linaro.org, lpieralisi@kernel.org, sudeep.holla@arm.com, agross@kernel.org, andersson@kernel.org, konrad.dybcio@linaro.org, anup@brainfault.org, thierry.reding@gmail.com, jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com
 , linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org, mhiramat@kernel.org, frederic@kernel.org, paulmck@kernel.org, pmladek@suse.com, senozhatsky@chromium.org, john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, bristot@redhat.com, vschneid@redhat.com, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, Andrew Morton <akpm@linux-foundation.org>, jpoimboe@kernel.org, linux-alpha@vger.kernel.org, linux-kernel@vger.kernel.org, linux-snps-arc@lists.infradead.org, linux-omap@vger.kernel.org, linux-samsung-soc@vger.kernel.org, linux-csky@vger.kernel.org, linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org, loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org, openrisc@lists.librecores.org, linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, linux-riscv
 @lists.infradead.org, linux-s390@vger.kernel.org, linux-sh@vger.kernel.org, sparclinux@vger.kernel.org, linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org, virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org, linux-mm@kvack.org, linux-trace-kernel@vger.kernel.org, kasan-dev@googlegroups.com, Ulf Hansson <ulf.hansson@linaro.org>, Rafael J. Wysocki <rafael.j.wysocki@intel.com>
To: peterz@infradead.org
Date: Thu, 12 Jan 2023 12:28:44 -0800
User-Agent: alot/0.10
X-Original-Sender: sboyd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=fail
 header.i=@kernel.org header.s=k20201202 header.b=Ew9S6ssy;       spf=pass
 (google.com: domain of sboyd@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sboyd@kernel.org;       dmarc=pass (p=NONE
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

Quoting Peter Zijlstra (2023-01-12 11:43:55)
> OMAP was the one and only user.
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>
> Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
> Acked-by: Frederic Weisbecker <frederic@kernel.org>
> Tested-by: Tony Lindgren <tony@atomide.com>
> Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
> ---

Acked-by: Stephen Boyd <sboyd@kernel.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cd75c97ac883283fb0764f5862a6377f.sboyd%40kernel.org.
