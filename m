Return-Path: <kasan-dev+bncBDF57NG2XIHRBUFK6CMQMGQEYIUYXOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id A12B35F41B8
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Oct 2022 13:13:26 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id h10-20020a056e021d8a00b002f99580de6csf5828493ila.5
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Oct 2022 04:13:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664882000; cv=pass;
        d=google.com; s=arc-20160816;
        b=tBedaPQI7de1rtXUnvJgM8ki9kmyxc+HdEheuz+/LHOUBVRhSwdMeBVHoIHmlL+E1L
         NesApkr90d7amFQwJe1ZRoxIsYczTUuBvrUEzEbmIfLIJ9uaglGv2JDtCFojpkL2IpYc
         k8PgN1qO+LmPAHmDOkDbbdV0lZSmIRAjLU8537V+LQZ1JCGJL0zKGZw7E9MiTG0S0DF7
         1LOQWrm1IKP4r+LP7aBDpEOhYf3+a4Q5qCLFF07cPvwKh4h5iYK7QkVrTJbrVTWIonia
         2vukeOz+TDnalt9LcXrHZatiukCebJIlbukhfv7Hjb/8Ow8DkuoY5Suv9I1QP8MqyTxM
         A4fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=x7W/Ng+ckfSmQBaNU7EaXuO/gsshQPswAldqszT4mc8=;
        b=el459zP/DzNZ1OjXcYc4IA2HBZcM0wosD3N0D6Uc2R9LNzsjtU3wwcY05K/Yiioel1
         28GQfz7H2OjAo1I4p2VBF+wcBH6IYYUBgrTCQnu6Esn1mRxKyPdvAOlSeYsZ7HsbxL/6
         Mk7UyjzS9b1RCarkXT+LKgp4HoUzWft0mwV6TCjcngjEoVTKT2iI0Z+C1ON/Q1RKtd8r
         SgB1xXHjgk90OzBY4J95qQ6veseGUS2H2eL0jOWgExlPT5dr57VMPE0ZpIR1LrMu7sn/
         JC7/tMhYY9swpRNtugX510jdt8+1906hLr6BBbgUBLahL0LnAEDeOLalIuar7NWMUuTY
         9/Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=DQ7AqshQ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=x7W/Ng+ckfSmQBaNU7EaXuO/gsshQPswAldqszT4mc8=;
        b=LfXCBjW587Z9ykjbj9yMu+U0NMIEzVQKGbX7I9dXrclwFNgFqbSSoAPSAnnXwzsGaV
         /DoGMRojO5b3mkd7tbaFTlAklKmJNSkUMWNCKGNlS/x2KLRgUI2Ow/Ik/TbQKOC513qY
         1ajJMqNOMp7FBTUYR0nPzczgfrEHAbCrxEWkjh9iPyaqWUl18eJj7k4i2ywrkQ4Y1m2W
         sGWMDswLbK8scBQL/+WTfv9f8UpgJz0aTFkXgBJ8yjW9Ii2aHWKCDLd4ARVVtyr1Dt7b
         pPwu2Ir3hYRFdRlLz2e84dpXe3/3lDbCkU2cpd/WmWWVaqWLR3QiUMLioQ2VBFxXxjJJ
         dDnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=x7W/Ng+ckfSmQBaNU7EaXuO/gsshQPswAldqszT4mc8=;
        b=QAAcBxXhGNk1TSmv6bXd+5/A6lA6HBPTy4q8L9lTmMfpaJYtXrTpKZE8bO1gn3qwR7
         X+ER1RMLWY/WLwYMxboeTTvdBDxJLJgpBDZNAVEPf6Px1uJtJdy9mkA4cbLe30UeF3Jn
         wLHx3/vDhv8/XAMO8HtoTQ8dDgI2oEg5ofHXKl0cPcNEWcEjEXbEHXcYwZouWEupvCNJ
         Fv+IIwrSn7csTi7u3yg2RMr2Dj4LvSoFF07gjkVHiuUhP+N6vj1TyNSrTNhiPjDNRMDQ
         iXnFoKyLR37CCaxGUXlFJU9r71Q9yZeTvVvV4V8bUr3wHYLJDFq6csG5uuT5s70UPPXw
         W5Og==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2tpV0Wb7CqZmkAzYkgV8ENbX7fN0uoJqDu3uynt6ikUYvYmVeH
	OWmNoLtcjmTMTCTJJOfXoeU=
X-Google-Smtp-Source: AMsMyM6t/bNmcDHdCXACIYcNtGWdcPzkr8ZZzDfPAuuZBvbhWqrRXCNNN4RWW+SkrmDi0BlQnEfUrQ==
X-Received: by 2002:a05:6602:2c42:b0:6a1:6e51:690d with SMTP id x2-20020a0566022c4200b006a16e51690dmr10757615iov.146.1664882000493;
        Tue, 04 Oct 2022 04:13:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:dec:b0:2f6:1ab4:f214 with SMTP id
 m12-20020a056e020dec00b002f61ab4f214ls1705722ilj.0.-pod-prod-gmail; Tue, 04
 Oct 2022 04:13:20 -0700 (PDT)
X-Received: by 2002:a92:c264:0:b0:2fa:11ca:f695 with SMTP id h4-20020a92c264000000b002fa11caf695mr2138708ild.58.1664882000037;
        Tue, 04 Oct 2022 04:13:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664882000; cv=none;
        d=google.com; s=arc-20160816;
        b=skPqZeBo1+fZimnQOe24dRi9XmpdaP7lMa0p/ozAyEqlfIXFQRbKKlLqBHSyO1fNxG
         q5cBVcvQOVe/A59h8VLlA4VGYPiR33ecuC6rUOMuswyCKMU/hZW8pMARRMVjrIJ+S6qR
         6xxzXYaVOTxSNzepVvAy+11XWBV6cIHJp2O/5l2wN0/3aKP5xDwxqXF14ykKJNZVbdg0
         zbKZERqID9Wsn5scSAZ2T+XEYJtb5w3H2omh3oo1DQ3zl99Gk/lhc2+uJiCKt19EYcue
         Bh3tA3GRHCPWelYzGc5J7Q6HrhZFzpwgbPtgm+63H4xg667HSc7xPGaMlHuq0HCD6KTo
         V0yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UHE2x7YnT+avJBdJRK8fICu4tqbTB0zv1A8Jd5IOhrw=;
        b=ZW5w0w1YwYzc+bLtokoiy+XT1f0fYrqjKGZHHxO9NT39aFGhV4KH5GKNxdYBMtiZ9+
         nvVnMZ30ixcW35PHTC//qDTb+erC/t8p/+s9yL7aJkOzZ5nFCc7xAZPxsRwS4F3TM3Rn
         /G9QHhFGM8kLqLturU4umHgUU6WPednItwluxcR+W+7vyqlMRV59lwwg1zC/9O+RW8ue
         Orce78TUov3B8skgj2wsy9UR1bEHbMqc9KrCtqfUQCmrbNIBse0g1P4cotgCtbThkJp6
         r60XKfL43YlQOP93jfHDNr/Vgdu7XP9MrfqD0mdljNGqXxtGQoP5SmGwkHHXbC98qtv9
         XYzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=DQ7AqshQ;
       spf=pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id p25-20020a6bfa19000000b00688fefa6d1dsi551711ioh.2.2022.10.04.04.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Oct 2022 04:13:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id q99-20020a17090a1b6c00b0020ac0368d64so3526138pjq.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Oct 2022 04:13:19 -0700 (PDT)
X-Received: by 2002:a17:90b:4d07:b0:1ef:521c:f051 with SMTP id
 mw7-20020a17090b4d0700b001ef521cf051mr17237644pjb.164.1664881999182; Tue, 04
 Oct 2022 04:13:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220919095939.761690562@infradead.org> <20220919101522.908560022@infradead.org>
In-Reply-To: <20220919101522.908560022@infradead.org>
From: Ulf Hansson <ulf.hansson@linaro.org>
Date: Tue, 4 Oct 2022 13:12:42 +0200
Message-ID: <CAPDyKFqDiqXSi5Gn9eyvhHhqHxJAPAt-HzmEDwYWaGvso2yn=w@mail.gmail.com>
Subject: Re: [PATCH v2 38/44] cpuidle,powerdomain: Remove trace_.*_rcuidle()
To: Peter Zijlstra <peterz@infradead.org>
Cc: juri.lelli@redhat.com, rafael@kernel.org, catalin.marinas@arm.com, 
	linus.walleij@linaro.org, bsegall@google.com, guoren@kernel.org, pavel@ucw.cz, 
	agordeev@linux.ibm.com, linux-arch@vger.kernel.org, 
	vincent.guittot@linaro.org, mpe@ellerman.id.au, chenhuacai@kernel.org, 
	christophe.leroy@csgroup.eu, linux-acpi@vger.kernel.org, agross@kernel.org, 
	geert@linux-m68k.org, linux-imx@nxp.com, vgupta@kernel.org, 
	mattst88@gmail.com, mturquette@baylibre.com, sammy@sammy.net, 
	pmladek@suse.com, linux-pm@vger.kernel.org, 
	Sascha Hauer <s.hauer@pengutronix.de>, linux-um@lists.infradead.org, npiggin@gmail.com, 
	tglx@linutronix.de, linux-omap@vger.kernel.org, dietmar.eggemann@arm.com, 
	andreyknvl@gmail.com, gregkh@linuxfoundation.org, 
	linux-kernel@vger.kernel.org, linux-perf-users@vger.kernel.org, 
	senozhatsky@chromium.org, svens@linux.ibm.com, jolsa@kernel.org, 
	tj@kernel.org, Andrew Morton <akpm@linux-foundation.org>, mark.rutland@arm.com, 
	linux-ia64@vger.kernel.org, dave.hansen@linux.intel.com, 
	virtualization@lists.linux-foundation.org, 
	James.Bottomley@hansenpartnership.com, jcmvbkbc@gmail.com, 
	thierry.reding@gmail.com, kernel@xen0n.name, cl@linux.com, 
	linux-s390@vger.kernel.org, vschneid@redhat.com, john.ogness@linutronix.de, 
	ysato@users.sourceforge.jp, linux-sh@vger.kernel.org, festevam@gmail.com, 
	deller@gmx.de, daniel.lezcano@linaro.org, jonathanh@nvidia.com, 
	dennis@kernel.org, lenb@kernel.org, linux-xtensa@linux-xtensa.org, 
	kernel@pengutronix.de, gor@linux.ibm.com, linux-arm-msm@vger.kernel.org, 
	linux-alpha@vger.kernel.org, linux-m68k@lists.linux-m68k.org, 
	loongarch@lists.linux.dev, shorne@gmail.com, chris@zankel.net, 
	sboyd@kernel.org, dinguyen@kernel.org, bristot@redhat.com, 
	alexander.shishkin@linux.intel.com, fweisbec@gmail.com, lpieralisi@kernel.org, 
	atishp@atishpatra.org, linux@rasmusvillemoes.dk, kasan-dev@googlegroups.com, 
	will@kernel.org, boris.ostrovsky@oracle.com, khilman@kernel.org, 
	linux-csky@vger.kernel.org, pv-drivers@vmware.com, 
	linux-snps-arc@lists.infradead.org, mgorman@suse.de, 
	jacob.jun.pan@linux.intel.com, Arnd Bergmann <arnd@arndb.de>, ulli.kroll@googlemail.com, 
	linux-clk@vger.kernel.org, rostedt@goodmis.org, ink@jurassic.park.msu.ru, 
	bcain@quicinc.com, tsbogend@alpha.franken.de, linux-parisc@vger.kernel.org, 
	ryabinin.a.a@gmail.com, sudeep.holla@arm.com, shawnguo@kernel.org, 
	davem@davemloft.net, dalias@libc.org, tony@atomide.com, amakhalov@vmware.com, 
	konrad.dybcio@somainline.org, bjorn.andersson@linaro.org, glider@google.com, 
	hpa@zytor.com, sparclinux@vger.kernel.org, linux-hexagon@vger.kernel.org, 
	linux-riscv@lists.infradead.org, vincenzo.frascino@arm.com, 
	anton.ivanov@cambridgegreys.com, jonas@southpole.se, yury.norov@gmail.com, 
	richard@nod.at, x86@kernel.org, linux@armlinux.org.uk, mingo@redhat.com, 
	aou@eecs.berkeley.edu, hca@linux.ibm.com, richard.henderson@linaro.org, 
	stefan.kristiansson@saunalahti.fi, openrisc@lists.librecores.org, 
	acme@kernel.org, paul.walmsley@sifive.com, linux-tegra@vger.kernel.org, 
	namhyung@kernel.org, andriy.shevchenko@linux.intel.com, jpoimboe@kernel.org, 
	dvyukov@google.com, jgross@suse.com, monstr@monstr.eu, 
	linux-mips@vger.kernel.org, palmer@dabbelt.com, anup@brainfault.org, 
	bp@alien8.de, johannes@sipsolutions.net, linuxppc-dev@lists.ozlabs.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ulf.hansson@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=DQ7AqshQ;       spf=pass
 (google.com: domain of ulf.hansson@linaro.org designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=ulf.hansson@linaro.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Mon, 19 Sept 2022 at 12:17, Peter Zijlstra <peterz@infradead.org> wrote:
>
> OMAP was the one and only user.
>
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>

There are changes to the runtime PM core as part of $subject patch.
Perhaps move those parts into a separate patch? In any case, the code
looks good to me.

Reviewed-by: Ulf Hansson <ulf.hansson@linaro.org>

Kind regards
Uffe

> ---
>  arch/arm/mach-omap2/powerdomain.c |   10 +++++-----
>  drivers/base/power/runtime.c      |   24 ++++++++++++------------
>  2 files changed, 17 insertions(+), 17 deletions(-)
>
> --- a/arch/arm/mach-omap2/powerdomain.c
> +++ b/arch/arm/mach-omap2/powerdomain.c
> @@ -187,9 +187,9 @@ static int _pwrdm_state_switch(struct po
>                         trace_state = (PWRDM_TRACE_STATES_FLAG |
>                                        ((next & OMAP_POWERSTATE_MASK) << 8) |
>                                        ((prev & OMAP_POWERSTATE_MASK) << 0));
> -                       trace_power_domain_target_rcuidle(pwrdm->name,
> -                                                         trace_state,
> -                                                         raw_smp_processor_id());
> +                       trace_power_domain_target(pwrdm->name,
> +                                                 trace_state,
> +                                                 raw_smp_processor_id());
>                 }
>                 break;
>         default:
> @@ -541,8 +541,8 @@ int pwrdm_set_next_pwrst(struct powerdom
>
>         if (arch_pwrdm && arch_pwrdm->pwrdm_set_next_pwrst) {
>                 /* Trace the pwrdm desired target state */
> -               trace_power_domain_target_rcuidle(pwrdm->name, pwrst,
> -                                                 raw_smp_processor_id());
> +               trace_power_domain_target(pwrdm->name, pwrst,
> +                                         raw_smp_processor_id());
>                 /* Program the pwrdm desired target state */
>                 ret = arch_pwrdm->pwrdm_set_next_pwrst(pwrdm, pwrst);
>         }
> --- a/drivers/base/power/runtime.c
> +++ b/drivers/base/power/runtime.c
> @@ -442,7 +442,7 @@ static int rpm_idle(struct device *dev,
>         int (*callback)(struct device *);
>         int retval;
>
> -       trace_rpm_idle_rcuidle(dev, rpmflags);
> +       trace_rpm_idle(dev, rpmflags);
>         retval = rpm_check_suspend_allowed(dev);
>         if (retval < 0)
>                 ;       /* Conditions are wrong. */
> @@ -481,7 +481,7 @@ static int rpm_idle(struct device *dev,
>                         dev->power.request_pending = true;
>                         queue_work(pm_wq, &dev->power.work);
>                 }
> -               trace_rpm_return_int_rcuidle(dev, _THIS_IP_, 0);
> +               trace_rpm_return_int(dev, _THIS_IP_, 0);
>                 return 0;
>         }
>
> @@ -493,7 +493,7 @@ static int rpm_idle(struct device *dev,
>         wake_up_all(&dev->power.wait_queue);
>
>   out:
> -       trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
> +       trace_rpm_return_int(dev, _THIS_IP_, retval);
>         return retval ? retval : rpm_suspend(dev, rpmflags | RPM_AUTO);
>  }
>
> @@ -557,7 +557,7 @@ static int rpm_suspend(struct device *de
>         struct device *parent = NULL;
>         int retval;
>
> -       trace_rpm_suspend_rcuidle(dev, rpmflags);
> +       trace_rpm_suspend(dev, rpmflags);
>
>   repeat:
>         retval = rpm_check_suspend_allowed(dev);
> @@ -708,7 +708,7 @@ static int rpm_suspend(struct device *de
>         }
>
>   out:
> -       trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
> +       trace_rpm_return_int(dev, _THIS_IP_, retval);
>
>         return retval;
>
> @@ -760,7 +760,7 @@ static int rpm_resume(struct device *dev
>         struct device *parent = NULL;
>         int retval = 0;
>
> -       trace_rpm_resume_rcuidle(dev, rpmflags);
> +       trace_rpm_resume(dev, rpmflags);
>
>   repeat:
>         if (dev->power.runtime_error) {
> @@ -925,7 +925,7 @@ static int rpm_resume(struct device *dev
>                 spin_lock_irq(&dev->power.lock);
>         }
>
> -       trace_rpm_return_int_rcuidle(dev, _THIS_IP_, retval);
> +       trace_rpm_return_int(dev, _THIS_IP_, retval);
>
>         return retval;
>  }
> @@ -1081,7 +1081,7 @@ int __pm_runtime_idle(struct device *dev
>                 if (retval < 0) {
>                         return retval;
>                 } else if (retval > 0) {
> -                       trace_rpm_usage_rcuidle(dev, rpmflags);
> +                       trace_rpm_usage(dev, rpmflags);
>                         return 0;
>                 }
>         }
> @@ -1119,7 +1119,7 @@ int __pm_runtime_suspend(struct device *
>                 if (retval < 0) {
>                         return retval;
>                 } else if (retval > 0) {
> -                       trace_rpm_usage_rcuidle(dev, rpmflags);
> +                       trace_rpm_usage(dev, rpmflags);
>                         return 0;
>                 }
>         }
> @@ -1202,7 +1202,7 @@ int pm_runtime_get_if_active(struct devi
>         } else {
>                 retval = atomic_inc_not_zero(&dev->power.usage_count);
>         }
> -       trace_rpm_usage_rcuidle(dev, 0);
> +       trace_rpm_usage(dev, 0);
>         spin_unlock_irqrestore(&dev->power.lock, flags);
>
>         return retval;
> @@ -1566,7 +1566,7 @@ void pm_runtime_allow(struct device *dev
>         if (ret == 0)
>                 rpm_idle(dev, RPM_AUTO | RPM_ASYNC);
>         else if (ret > 0)
> -               trace_rpm_usage_rcuidle(dev, RPM_AUTO | RPM_ASYNC);
> +               trace_rpm_usage(dev, RPM_AUTO | RPM_ASYNC);
>
>   out:
>         spin_unlock_irq(&dev->power.lock);
> @@ -1635,7 +1635,7 @@ static void update_autosuspend(struct de
>                         atomic_inc(&dev->power.usage_count);
>                         rpm_resume(dev, 0);
>                 } else {
> -                       trace_rpm_usage_rcuidle(dev, 0);
> +                       trace_rpm_usage(dev, 0);
>                 }
>         }
>
>
>
> _______________________________________________
> Virtualization mailing list
> Virtualization@lists.linux-foundation.org
> https://lists.linuxfoundation.org/mailman/listinfo/virtualization

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPDyKFqDiqXSi5Gn9eyvhHhqHxJAPAt-HzmEDwYWaGvso2yn%3Dw%40mail.gmail.com.
