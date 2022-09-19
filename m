Return-Path: <kasan-dev+bncBDB3VRMVXIPRBYUQUGMQMGQEIJUSGFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 998325BC9B3
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:45:55 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id v7-20020adfa1c7000000b0022ae7d7313esf831294wrv.19
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:45:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663584355; cv=pass;
        d=google.com; s=arc-20160816;
        b=pd/g8VIYzo9niWbGvjqKfho7+D04+/X2NFVAI9GIsBKBUU13OmZEQU7S3ZA33t7EVe
         gGLrOV2hdDeHDCBuijCCKuGNSG+E90BXMw70Dv8AGhjUlwT4SK8cnog8SNfjNL8GixXp
         uQIqJhZdlNW7FPH2WlXW6J2hyb/AsLbJyFT335jWP2hAFeOiRZuNxPuih0VfuIPUPMZX
         H3POkZHzpiYWWfpM4KjfxIopq0msCMg+GLK5h3d9uH8+i19snz5xYXHWTkc3mRI8lUyF
         dMc66swhLpGvrCSj6LataEzstv6kqAYD5gxtlizDeXJGaB8tYmouCpzBuqZGEba7yrpk
         9D0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=hjZ+E6yU+AQIi4ynpp75SzzIPa5SleGHz6gxSFVLMsw=;
        b=By46xPL50AtmO8XyeFeOWfFJ4zouKXzKb2+QiNnypELbag6t71UN/ju3HCv7qrPDDO
         MbQQIWkne+VoDu5LwQY1WyKCHmfNnGG1YMy1p2UD5BlhYZMVcwEf5hB6kU0ZQMxoAHk4
         toVfd0uSZ+MG/wNBFmkeAAdL6IXuummh8kldCbe4HUJ+ScjCl5e7Y4XTNW7XuGCPZohQ
         Yvg7QQpu4mcnubw41pim5Dtv6x3nPFqKnZSpj///QueShpc1ry/igYmrjEgM4BCADB7o
         6lVCEFAq3MQypakCWt1osG5sWurrO6pHfsybjNeilZRBexu+c0fzE3mpOiN6+nJerWWA
         psQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pcs8WC6C;
       spf=pass (google.com: domain of jgross@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date;
        bh=hjZ+E6yU+AQIi4ynpp75SzzIPa5SleGHz6gxSFVLMsw=;
        b=esTPUj1ooxpos+QoesWO6e+poP8MEHNt8PZ2IEkUlPPaoVKCivQOMRH9FXfOIkpT+Y
         QQrhmo/3gyyP7+YqcgKAHqkPmV+yOZUbFUKifyyLP0Uv1TNng/3TYe8GXHPmKcWL1+46
         dI0AjtySxjdObf7ng5V37MMqCYA8rmXESMU5a/RUqN3FGyweYHYgvimPto4eHo6mH1LA
         /hK7dvCPnd529Q7rMGXVVuyTUYccIUk9e/36K/yex4PhiQJy+VQu1A+g+IeCdGcEghvI
         lSK356b3TUXwu780yHPRAHOXCI+6tGegHl6Ej827ifkcQ54eMRy4tpVkhsheZt0Cp9I4
         9DWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-gm-message-state:from:to:cc:subject
         :date;
        bh=hjZ+E6yU+AQIi4ynpp75SzzIPa5SleGHz6gxSFVLMsw=;
        b=dHifuLlb6nb8HPI3JD9r4Efk6CBpSz0Gd0V+dLDeNb92kmgGjqhk+yRxF0k3wPJpNa
         di3sV+TbB2KUKMRl0EYH13X2ktifVarayxvqn1vC1l6LDhXX470plMbDIiKTHwO0wlWM
         NkY6PegI55fUQNUnG5qQlGR7mQohRZPAoJ5CO91CeshQQKiPivVgbtu2Md10rAUHcgGx
         B5pgHYuU9ZXCXxdGiZyl4JGApszSvCHxoWoz198tqE/hw9DWhCgEp9nknwF1Oj6Ra9xz
         tD+Uj458wI4ZitDYoK2/aHMcbEe6n8nPaWk9lIxVxUEUMYj+1BRZ4Nv7ZOk1fcRcC1Vh
         +o9Q==
X-Gm-Message-State: ACrzQf188fyihqFzqbfCt6gVxFI2sWzT754WHLqWp6iKb1oCgSquVcPI
	w00SjlR6V49IImwxGHVuLzU=
X-Google-Smtp-Source: AMsMyM6e9oSBkhwMbAH2sVMyLqJiO14fGlSHf2ZngKm1uQJ5O21Pi9UKzPvJ0RcfqvGWP8XN/M7qeQ==
X-Received: by 2002:a05:6000:1786:b0:22a:6470:e454 with SMTP id e6-20020a056000178600b0022a6470e454mr10130762wrg.565.1663584355312;
        Mon, 19 Sep 2022 03:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2987302wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:45:54 -0700 (PDT)
X-Received: by 2002:a5d:6c6b:0:b0:225:dde:ab40 with SMTP id r11-20020a5d6c6b000000b002250ddeab40mr10409441wrz.690.1663584354039;
        Mon, 19 Sep 2022 03:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663584354; cv=none;
        d=google.com; s=arc-20160816;
        b=FKS6AAbxuSK0DwZqO0OraJq3aiDEeSrcVovOgplZB4CwlIvmWDol6//n7isWmAjR2C
         DRH3L5JDqIl5iUO8g1svzb1hAJDQvdYqBVHVNQ62vw23R/404ZHwPtjbnSQojgMB9TLr
         mu4jrdeUzA/m584pg1j5b4n6C8y1RYt50uXKJf3npv9QRqWu/l6QW6s2i06J9DcdrZ2m
         6nklJOWSSdEEj/3gmhS9d7FYyLgqCPt2kU5YYminaicMPPPP/sNOa/EC4Y3KokmKuzkG
         +0GTRvTVECiXLdaturHOqZDQFaN9A2T/K6WNkqJTKLZI9x4NLQa9g5yjaWZ5EZhaEkP+
         WXVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=TPY7EEFMWVrZdYCxqqnTs3va11awHySIxzPGii1FR0M=;
        b=SndQTpxUhS0qIFnaSMirchvqUwWdRDqW/bbFYYjmb9gyk/iqdhO26CfNEifkd+hav/
         e4IsvPb4cTC6A/IqZaQbstaSQZEhGGqgWCr5N9kX8Xac7V9twFlgd3r2vGlZp+9cOnWv
         yDsHItFEHG0aSoOL8lzMJ0tTlfA1I68grGL04ksLc7EoDKuOJVsI5QqGMTgB6QWb3pik
         qbHajlGvCjO2g8zn4UdM84KNqHmUTfcFCEYbaULBCwdce0ZfJP0pN/heShEck63qIjqX
         BOSiOzQjXiRj75PUt2EkH39fUo2rHpv/GfcfnvpntgqettpSsKHWuaive8HLg5hSNI04
         HNlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=pcs8WC6C;
       spf=pass (google.com: domain of jgross@suse.com designates 2001:67c:2178:6::1d as permitted sender) smtp.mailfrom=jgross@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2001:67c:2178:6::1d])
        by gmr-mx.google.com with ESMTPS id n24-20020a7bcbd8000000b003a5ce2af2c7si333962wmi.1.2022.09.19.03.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:45:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 2001:67c:2178:6::1d as permitted sender) client-ip=2001:67c:2178:6::1d;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 456EF1F8AB;
	Mon, 19 Sep 2022 10:45:53 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 85A4E13A96;
	Mon, 19 Sep 2022 10:45:48 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id T0GyHlxIKGNkeAAAMHmgww
	(envelope-from <jgross@suse.com>); Mon, 19 Sep 2022 10:45:48 +0000
Message-ID: <41916640-cf05-c00d-95fa-1e0099741f4c@suse.com>
Date: Mon, 19 Sep 2022 12:45:47 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.2.2
Subject: Re: [PATCH v2 30/44] cpuidle,xenpv: Make more PARAVIRT_XXL noinstr
 clean
Content-Language: en-US
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
 mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
 ulli.kroll@googlemail.com, linus.walleij@linaro.org, shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
 festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org,
 catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org,
 bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name,
 geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu,
 tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
 James.Bottomley@HansenPartnership.com, deller@gmx.de, mpe@ellerman.id.au,
 npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
 gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com,
 svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org,
 davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
 bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com,
 acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com,
 jolsa@kernel.org, namhyung@kernel.org, srivatsa@csail.mit.edu,
 amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com,
 chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org,
 pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com,
 sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
 sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com,
 jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
 dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
 pmladek@suse.com, senozhatsky@chromium.org, john.ogness@linutronix.de,
 juri.lelli@redhat.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
 vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org, linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20220919095939.761690562@infradead.org>
 <20220919101522.358582588@infradead.org>
From: "'Juergen Gross' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20220919101522.358582588@infradead.org>
Content-Type: multipart/signed; micalg=pgp-sha256;
 protocol="application/pgp-signature";
 boundary="------------uN7TNqTnDntgyCDMTfJPdXrr"
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=pcs8WC6C;       spf=pass
 (google.com: domain of jgross@suse.com designates 2001:67c:2178:6::1d as
 permitted sender) smtp.mailfrom=jgross@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Juergen Gross <jgross@suse.com>
Reply-To: Juergen Gross <jgross@suse.com>
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

This is an OpenPGP/MIME signed message (RFC 4880 and 3156)
--------------uN7TNqTnDntgyCDMTfJPdXrr
Content-Type: multipart/mixed; boundary="------------bVxl0sFTg1HlWc0dYJ02yXYs";
 protected-headers="v1"
From: Juergen Gross <jgross@suse.com>
To: Peter Zijlstra <peterz@infradead.org>
Cc: richard.henderson@linaro.org, ink@jurassic.park.msu.ru,
 mattst88@gmail.com, vgupta@kernel.org, linux@armlinux.org.uk,
 ulli.kroll@googlemail.com, linus.walleij@linaro.org, shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>, kernel@pengutronix.de,
 festevam@gmail.com, linux-imx@nxp.com, tony@atomide.com, khilman@kernel.org,
 catalin.marinas@arm.com, will@kernel.org, guoren@kernel.org,
 bcain@quicinc.com, chenhuacai@kernel.org, kernel@xen0n.name,
 geert@linux-m68k.org, sammy@sammy.net, monstr@monstr.eu,
 tsbogend@alpha.franken.de, dinguyen@kernel.org, jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi, shorne@gmail.com,
 James.Bottomley@HansenPartnership.com, deller@gmx.de, mpe@ellerman.id.au,
 npiggin@gmail.com, christophe.leroy@csgroup.eu, paul.walmsley@sifive.com,
 palmer@dabbelt.com, aou@eecs.berkeley.edu, hca@linux.ibm.com,
 gor@linux.ibm.com, agordeev@linux.ibm.com, borntraeger@linux.ibm.com,
 svens@linux.ibm.com, ysato@users.sourceforge.jp, dalias@libc.org,
 davem@davemloft.net, richard@nod.at, anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net, tglx@linutronix.de, mingo@redhat.com,
 bp@alien8.de, dave.hansen@linux.intel.com, x86@kernel.org, hpa@zytor.com,
 acme@kernel.org, mark.rutland@arm.com, alexander.shishkin@linux.intel.com,
 jolsa@kernel.org, namhyung@kernel.org, srivatsa@csail.mit.edu,
 amakhalov@vmware.com, pv-drivers@vmware.com, boris.ostrovsky@oracle.com,
 chris@zankel.net, jcmvbkbc@gmail.com, rafael@kernel.org, lenb@kernel.org,
 pavel@ucw.cz, gregkh@linuxfoundation.org, mturquette@baylibre.com,
 sboyd@kernel.org, daniel.lezcano@linaro.org, lpieralisi@kernel.org,
 sudeep.holla@arm.com, agross@kernel.org, bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org, anup@brainfault.org, thierry.reding@gmail.com,
 jonathanh@nvidia.com, jacob.jun.pan@linux.intel.com, atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>, yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com, linux@rasmusvillemoes.dk,
 dennis@kernel.org, tj@kernel.org, cl@linux.com, rostedt@goodmis.org,
 pmladek@suse.com, senozhatsky@chromium.org, john.ogness@linutronix.de,
 juri.lelli@redhat.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com,
 bsegall@google.com, mgorman@suse.de, bristot@redhat.com,
 vschneid@redhat.com, fweisbec@gmail.com, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org, linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org, linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org, linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev, linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org, openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org, sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org, linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org, linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org, linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org, linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org, linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Message-ID: <41916640-cf05-c00d-95fa-1e0099741f4c@suse.com>
Subject: Re: [PATCH v2 30/44] cpuidle,xenpv: Make more PARAVIRT_XXL noinstr
 clean
References: <20220919095939.761690562@infradead.org>
 <20220919101522.358582588@infradead.org>
In-Reply-To: <20220919101522.358582588@infradead.org>

--------------bVxl0sFTg1HlWc0dYJ02yXYs
Content-Type: multipart/mixed; boundary="------------DqMcUwZmmixeMRf078SIWWNm"

--------------DqMcUwZmmixeMRf078SIWWNm
Content-Type: text/plain; charset="UTF-8"; format=flowed

On 19.09.22 12:00, Peter Zijlstra wrote:
> vmlinux.o: warning: objtool: acpi_idle_enter_s2idle+0xde: call to wbinvd() leaves .noinstr.text section
> vmlinux.o: warning: objtool: default_idle+0x4: call to arch_safe_halt() leaves .noinstr.text section
> vmlinux.o: warning: objtool: xen_safe_halt+0xa: call to HYPERVISOR_sched_op.constprop.0() leaves .noinstr.text section
> 
> Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
> Reviewed-by: Srivatsa S. Bhat (VMware) <srivatsa@csail.mit.edu>

Reviewed-by: Juergen Gross <jgross@suse.com>


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/41916640-cf05-c00d-95fa-1e0099741f4c%40suse.com.

--------------DqMcUwZmmixeMRf078SIWWNm
Content-Type: application/pgp-keys; name="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Disposition: attachment; filename="OpenPGP_0xB0DE9DD628BF132F.asc"
Content-Description: OpenPGP public key
Content-Transfer-Encoding: quoted-printable

-----BEGIN PGP PUBLIC KEY BLOCK-----

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
jR/i1DG86lem3iBDXzXsZDn8R38=3D
=3D2wuH
-----END PGP PUBLIC KEY BLOCK-----

--------------DqMcUwZmmixeMRf078SIWWNm--

--------------bVxl0sFTg1HlWc0dYJ02yXYs--

--------------uN7TNqTnDntgyCDMTfJPdXrr
Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="OpenPGP_signature"

-----BEGIN PGP SIGNATURE-----

wsB5BAABCAAjFiEEhRJncuj2BJSl0Jf3sN6d1ii/Ey8FAmMoSFwFAwAAAAAACgkQsN6d1ii/Ey/T
hwf/eGOkDCDy7F9Ra0L0GOLdv4GeCljWmcvbdITwnsuB7hQz/+M0V2k7PvSN/ISQ4Vf6Jn+jdWqe
BIXXQbgSPEGvf145/zXXKI4Z/CR603o4j00ul4vrymonw4oMQfSU6XSgHQPxxoPF3hdqavHf2w48
1DJPJ8whPxq8qCNOIZt3O0NWTtIKi2fdc7Gpw4aouzNtdCNdCQKzLjhN1LpTcokA22BVdYBG2wMF
ZkBuZgDmH0auDXsstAEU8aSublQibxzVadACIUCRvtXxxTSXCujB3IoT9CgcYyav5uxi9nNvOEsp
f9YTwuEzNv1IhRffytywrjyBDZdbHXFDZM0kU7zKkA==
=9mzX
-----END PGP SIGNATURE-----

--------------uN7TNqTnDntgyCDMTfJPdXrr--
