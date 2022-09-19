Return-Path: <kasan-dev+bncBDFJHU6GRMBBB6NQUGMQMGQET4IBIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 341DB5BCB1F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 13:54:35 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id cg13-20020a05622a408d00b0035bb2f77e7esf16650424qtb.10
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 04:54:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663588474; cv=pass;
        d=google.com; s=arc-20160816;
        b=wZ4/16zRysyEXOCCZalG2C/5wmYNIN1sjX6VV7AanrCqYTn28QqLJvdL6cABgl4U9I
         RDA/NaNncjhSKOlutjx9JhdVIOnRTY66Nd7QYVQj66VRRCuQtL6Y+kFrBPlR4vPFqXGz
         YI27Wut26QLfR4n21FS37EvvN4XU1V3jJcQveBc+bJNY0uCUhLnmp0esHl3hlZM/cpl6
         Ar8KAuVve1uPju3fNMWg52mhfjFSk0O/ZWXJjiiU/zZ1O+FfAxY8czRhAKRQ7GNDBYji
         QyYgnM2IYKT4i9JKIf2vp6OEUxeqkX6HIExah88ajNWsTAP3j9kwcQtEe1NWXGCNYYQV
         SrdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=0ajI44Ii2t+J9jNKNfKW9F6mK8rieUByR8XE0UcGtqw=;
        b=X3aMdpfcGMu/mBUJ6iLcZD8ZffOh8ACLwiZGLLEpA/BEp3Teth/aX56ON5bpDqEvlx
         73fgYKzYoTXZ7oI2nCjVE5qfkY4BJlPOIJoxNcL7y0XGSOihEfUpZzuby2138Q3yDR55
         BJisdMKM3xY5ZD2rOIMC1uFPWzGqKnO+p57wiBbG6PHkLtSp/Ksu4/wzka7/CuAwmStb
         RK4zNnAkPh+hob4HF+83qxW4XhzQt/WjcORNu0I9eVToi8rkCmYORt+OTh8iUhEmQJ88
         xJp47NQKO+4ypOT5c62AGk6Av0OohJXQuBWzUwsRVq20uNljcQuhbqcY1zp056jsZZrz
         /2kQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b="6l84clV/";
       spf=neutral (google.com: 2607:f8b0:4864:20::12d is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=0ajI44Ii2t+J9jNKNfKW9F6mK8rieUByR8XE0UcGtqw=;
        b=awUFNU3dwsQwLkEHAJmyTJs7UrqUSfdaP6ML8A3bKMlGs9GicD1HyDMHa/e+Z2zRRx
         oD2dWkTPufmdmoCqFEOkrFIkNmS9Wgrx3f81FtbTKklf2GD4UeTSN8eDcK4j2XEUZs2x
         Ybndv1O3HQny7q0KkJX4kUpwTMTx56Y3UaJIL36b7a4uavOQEtFYaJM9Jx10WVY52Cr0
         xY2nM471xnSJmy05yhVXtGnqL4xXaLuj838w3Ot/Z6v96OJUP7lAVQRnzINxyi7j3iZe
         CMASeXi8+AG997/UvMOoMBJJsmV5D2Hu4W5luVWr4gD/Txrt7SPenZxvzirxbaUSX1RI
         rQnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=0ajI44Ii2t+J9jNKNfKW9F6mK8rieUByR8XE0UcGtqw=;
        b=7NM06p0uAg4cfzWUvaYkoB0eFsgfyKjoV5skVNZvu4IFPcaiKHAwqfdwNgBO3V6mRZ
         /AgGsf3as8mwl0WeisPdp4AxM5xI0uC0Rr5OqYMt7Kky7s0e6ysEhavZkk3etekXRzK8
         ZkybKTrcQLp1tQXiUbCJJdBk/7ySyIbtaaqV5GbDinL1q42Xw+M21o9rShd9i/d2z/K+
         oWgDnzlcmbJkjzLd1cIloHYXUXWQ0ygy1EyXGX8VwVHj61GU/as5+bJn9AWArvt3rCPf
         PioWnvx7qFWjK4dWyyAjbtg95Pr5IjcjHKIjJlnmWM/PwtHIJI7i7L9ERoHx5KX4vOTu
         70Zg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf35lsx0RzDr2oVJIMe9kZsjQjQ+cGn0L7N1C5rVN+Mr5+umDAkW
	BW1h/irGWu0uIiny+9T+jgA=
X-Google-Smtp-Source: AMsMyM6yljBQytjbaM72opJ0RovCCiK0aKjE4LFiPPAa+/wWNMJKSwUpIWVKo+3xf8H/Q8kzYpKgCg==
X-Received: by 2002:a05:620a:290c:b0:6ce:6686:109e with SMTP id m12-20020a05620a290c00b006ce6686109emr12384984qkp.741.1663588473803;
        Mon, 19 Sep 2022 04:54:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e48d:0:b0:496:439b:1bb9 with SMTP id n13-20020a0ce48d000000b00496439b1bb9ls2673003qvl.9.-pod-prod-gmail;
 Mon, 19 Sep 2022 04:54:33 -0700 (PDT)
X-Received: by 2002:a05:6214:23c6:b0:491:99e3:80ce with SMTP id hr6-20020a05621423c600b0049199e380cemr14155721qvb.111.1663588473354;
        Mon, 19 Sep 2022 04:54:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663588473; cv=none;
        d=google.com; s=arc-20160816;
        b=Z9Irj/eJcy6TGjJ0TiAQ9EUad2Jb2lMfvrY29XKw3x9+FvvFNzg0XT7UzQ4U70eL6n
         +EEEys+X/ctTZDcd4QXqpjI09SBBhHOgfLRnQmRW1nRXI1IIzXxunCwmEcHDYzirDrU/
         CBV7HYe8rzAgyl3OYERonC31TuVrFa+XBXCguQpbdIiUVJUGMBUDtYgQ8vwsXsPyYY5R
         8vL9wHpvPNvLQCW8WhhXVXqN52wqyhxjc1XVaMS6ozHN/kO3onRm5agBUME4om6t9xt7
         dprfBPDHv/EpG26lgzFaTS03TtrVe8WYzcwDu0xKq0ZdB/3sdglgBXIFB0KY559gZ/W0
         W/ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gUsv6szv6dsUeM9asVJnwaGmSGG17UchvxqwxLA3h8g=;
        b=Z8c3LT7TOITlf0XobzovGol2OXnzyV0s76sNIC7tLSpUHf6Cfy2S0YDVFlVGH5D8hu
         FC+l+u+q3Y/cP8kmYO08/T5ZdSyvWTENkXzxQz5MCJYA1wlt4DSAPVbUVpu8GqTEUPsf
         2lGvl7CbfzLowbgpjd+33JGAKnBrDFCWNYz09kCyOljDqbh1/lnO7xznfG2l8OyxIEUW
         LqkLK2ZeSp1Z6Z90ST0xLGhvTQyka+8dAD6ou1gjUEY0F/WFBAXSibvIK6s+c75nxsYO
         bjYs1JKvIiVsbKJovtvFJNChAXPyG+pEsoKvN8/CJ+ogOC8HESUfJ8Gx+n2DTn9vnhgC
         SYig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b="6l84clV/";
       spf=neutral (google.com: 2607:f8b0:4864:20::12d is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-il1-x12d.google.com (mail-il1-x12d.google.com. [2607:f8b0:4864:20::12d])
        by gmr-mx.google.com with ESMTPS id d21-20020ac84e35000000b0035c9fda218dsi683327qtw.2.2022.09.19.04.54.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Sep 2022 04:54:33 -0700 (PDT)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::12d is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2607:f8b0:4864:20::12d;
Received: by mail-il1-x12d.google.com with SMTP id l6so14634990ilk.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Sep 2022 04:54:33 -0700 (PDT)
X-Received: by 2002:a92:c04d:0:b0:2f5:1175:c7a3 with SMTP id
 o13-20020a92c04d000000b002f51175c7a3mr5681407ilf.165.1663588472670; Mon, 19
 Sep 2022 04:54:32 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101520.669962810@infradead.org>
In-Reply-To: <20220919101520.669962810@infradead.org>
From: Anup Patel <anup@brainfault.org>
Date: Mon, 19 Sep 2022 17:24:19 +0530
Message-ID: <CAAhSdy004HaNUNYRD8tcn24LZWdTmOVkF1QN14uLmSw1UXuXqA@mail.gmail.com>
Subject: Re: [PATCH v2 05/44] cpuidle,riscv: Push RCU-idle into driver
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru, mattst88@gmail.com, 
	vgupta@kernel.org, linux@armlinux.org.uk, ulli.kroll@googlemail.com, 
	linus.walleij@linaro.org, shawnguo@kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de, festevam@gmail.com, 
	linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org, 
	catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org, 
	bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name, 
	geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu, 
	tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se, 
	stefan.kristiansson@saunalahti.fi, shorne@gmail.com, 
	James.Bottomley@hansenpartnership.com, deller@gmx.de, mpe@ellerman.id.au, 
	npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com, 
	palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com, 
	gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com, 
	svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org, 
	davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com, 
	johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com, acme@kernel.org, 
	mark.rutland@arm.com, alexander.shishkin@linux.intel.com, jolsa@kernel.org, 
	namhyung@kernel.org, jgross@suse.com, srivatsa@csail.mit.edu, 
	amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com, 
	chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org, 
	pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com, 
	sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org, 
	sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org, 
	konrad.dybcio@somainline.org, thierry.reding@gmail.com, jonathanh@nvidia.com, 
	jacob.jun.pan@linux.intel.com, atishp@atishpatra.org, 
	Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com, andriy.shevchenko@linux.intel.com, 
	linux@rasmusvillemoes.dk, dennis@kernel.org, tj@kernel.org, cl@linux.com, 
	rostedt@goodmis.org, pmladek@suse.com, senozhatsky@chromium.org, 
	john.ogness@linutronix.de, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, bsegall@google.com, mgorman@suse.de, 
	bristot@redhat.com, vschneid@redhat.com, fweisbec@gmail.com, 
	ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, 
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
	linux-perf-users@vger.kernel.org, virtualization@lists.linux-foundation.org, 
	linux-xtensa@linux-xtensa.org, linux-acpi@vger.kernel.org, 
	linux-pm@vger.kernel.org, linux-clk@vger.kernel.org, 
	linux-arm-msm@vger.kernel.org, linux-tegra@vger.kernel.org, 
	linux-arch@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b="6l84clV/";       spf=neutral (google.com: 2607:f8b0:4864:20::12d is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Mon, Sep 19, 2022 at 3:47 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> Doing RCU-idle outside the driver, only to then temporarily enable it
> again, at least twice, before going idle is daft.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

Looks good to me.

For RISC-V cpuidle:
Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup


> ---
>  drivers/cpuidle/cpuidle-riscv-sbi.c |    9 +++++----
>  1 file changed, 5 insertions(+), 4 deletions(-)
>
> --- a/drivers/cpuidle/cpuidle-riscv-sbi.c
> +++ b/drivers/cpuidle/cpuidle-riscv-sbi.c
> @@ -116,12 +116,12 @@ static int __sbi_enter_domain_idle_state
>                 return -1;
>
>         /* Do runtime PM to manage a hierarchical CPU toplogy. */
> -       ct_irq_enter_irqson();
>         if (s2idle)
>                 dev_pm_genpd_suspend(pd_dev);
>         else
>                 pm_runtime_put_sync_suspend(pd_dev);
> -       ct_irq_exit_irqson();
> +
> +       ct_idle_enter();
>
>         if (sbi_is_domain_state_available())
>                 state = sbi_get_domain_state();
> @@ -130,12 +130,12 @@ static int __sbi_enter_domain_idle_state
>
>         ret = sbi_suspend(state) ? -1 : idx;
>
> -       ct_irq_enter_irqson();
> +       ct_idle_exit();
> +
>         if (s2idle)
>                 dev_pm_genpd_resume(pd_dev);
>         else
>                 pm_runtime_get_sync(pd_dev);
> -       ct_irq_exit_irqson();
>
>         cpu_pm_exit();
>
> @@ -246,6 +246,7 @@ static int sbi_dt_cpu_init_topology(stru
>          * of a shared state for the domain, assumes the domain states are all
>          * deeper states.
>          */
> +       drv->states[state_count - 1].flags |= CPUIDLE_FLAG_RCU_IDLE;
>         drv->states[state_count - 1].enter = sbi_enter_domain_idle_state;
>         drv->states[state_count - 1].enter_s2idle =
>                                         sbi_enter_s2idle_domain_idle_state;
>
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy004HaNUNYRD8tcn24LZWdTmOVkF1QN14uLmSw1UXuXqA%40mail.gmail.com.
