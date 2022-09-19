Return-Path: <kasan-dev+bncBDBK55H2UQKRBUEDUGMQMGQEDVCR2TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id C95335BC692
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:17:52 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id x24-20020a0565123f9800b0049902986c6fsf9190557lfa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:17:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582672; cv=pass;
        d=google.com; s=arc-20160816;
        b=MHZX1xT1LSqTgWvehXCfNaHZAyADXv0kNt2JGVfJ+uR+VbRxgti8zRTGlBIhgj4Uwp
         9+2crUA1CD+XzqkLr/MoBYI1wj+nXEvzTonvp1pGMW0L4x/+zAAXOFOzyZT3QdKnaJgf
         qkksbwyDSGIgcCZkXhfG2mgkNATFDMJE6TVWngpKxKZrluSDnpIU5PlyCibSHvTxrt0l
         9FaJGNWnE8Oe/g+wMq2hvTx9hN+rB88Wb8P1IRSvGYKBTntLu9mxLIrKEuM5usSQ8haU
         XjW1AF6ySwYMb2gaY7vahXMIKMaB2Q1Sh0KX4h2ohSe6VJ7b2gWn8YtKRQS3dEqyJ33L
         tjpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=5RmbcOAr6H7bAxY3HL0BDWEKfd3IMT3R1qUQxxnYNI8=;
        b=ZBE4NnQjFkw9a7Y6vzHRLYh1sUJj7PED5fawekKnr3N5jljr9F3skbZwHsO/H8Re3h
         rX7QTxT+SpURj6/Y2Z8wU7Tz33Zfb8JhhIR1eYw2NPG9/a4OXEN8WpXq9P6mxT1Rpwi3
         Gdpje+3bLHZazGtbAYjZvVxxDPF3IoCb3KBwm4BYhyK3CB0Bk2aMI2xmaC1Dt0sjYJQk
         As9evNNqIwypuyod3dJe7qlD+sKnvqRrYXAzPSr+7WZbrH3ufzqbcr8g6D14+0z5mxbu
         HFXBKy2+UorKCbR7Yuo9sR9fPc3ZVu11Q4GwXFykzNO8M1q/UOyyIHhGL64waFETGo46
         +m8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tx+6XVtv;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=5RmbcOAr6H7bAxY3HL0BDWEKfd3IMT3R1qUQxxnYNI8=;
        b=ic90k+3OUOo+ybaWk0mUR5hUwQ2Uo4HnEOrCLM1t12uFgor/p8qIGAjnjLncR/CpKh
         prG3ZBYuwlUsz+tSLkXfYfuIR+K+qctJcaMNFeEH2/iOLsjelcT4Jc6e8RSzTQ65onkj
         WHic2gHgnlHx0T0BWEWnyX3Mid+ZxW5wXy7wPXt8D+aRWt1JbIpvp9ZMN3he7PXGGSBT
         s73DtYKEAabpDObs9IQj/TdX4jrjtwHUvrdw/1ZuRp8M0rQbe8gg+itF2JtjREVanvvL
         oY9Z5z2gclItkEz+Bae1XQDNMUzf/DnsuwlR2qdKluuF2UVdPYuOxUaYkgp+FFvIdTRr
         wPrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=5RmbcOAr6H7bAxY3HL0BDWEKfd3IMT3R1qUQxxnYNI8=;
        b=W8YxxkXYCpWvDcoT37KBwf5daXxmju2juPRm6Adm1EJsQSj80QFt1d/aDd+JyDd8zD
         FJocdfuDhqsvplpcA4DVMQwK+j8PFLn0sFXd0fZSis86aOkFSFSjsWyPW9dZKSnWqgMo
         QBLtG1lIbJRcSW/+DLx6Zt0ZKmNEizgvFfaStjg6z0M2nKFLfcMNz/Z8NWhAZdxqAfYy
         6zMTmmWE/TvzffpjFAWWuq2x32J1qNG4LwpxEoS0sdy447x1X5xbJdpInx4q6t4vdZCR
         D6NBl96Xn6qOchdgJSv2JPc8rJvDRT1xtWRdBwJmL6AYwjksBrfO8XUtdLY/VHpwv8nZ
         fsiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0qAFL+pvHc/MOqqpUejeZtN9h3QZLViuJyhuwlGbFsTza9AxuQ
	sDkuTKsGEW3aJdaP8lfynoM=
X-Google-Smtp-Source: AMsMyM5PRcl7sOV/gAPAOAH0g01Mi2RNLhNobNOwMy1ITWNeaZu615d6eHuEHieA5jYdk5lEu9ivsg==
X-Received: by 2002:a2e:a7d5:0:b0:26c:27c3:14d9 with SMTP id x21-20020a2ea7d5000000b0026c27c314d9mr5198095ljp.480.1663582672356;
        Mon, 19 Sep 2022 03:17:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5f7a:0:b0:49a:b814:856d with SMTP id c26-20020ac25f7a000000b0049ab814856dls555774lfc.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:17:51 -0700 (PDT)
X-Received: by 2002:a05:6512:694:b0:498:ff40:24e with SMTP id t20-20020a056512069400b00498ff40024emr5441893lfe.265.1663582670991;
        Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582670; cv=none;
        d=google.com; s=arc-20160816;
        b=JSRYL1nYTVhTXiSWXlSGLUHKUL7Fd2Dll+xwyL381OCUiVhhPAzJLLmeFFc5t/bJyy
         w6EWMkJJjQorsjpH6czsxbuXFv3Djyya4lXXAbUxFmOBWZwdwRE9sgoJfSQylTzwfb9z
         Hn7TaV3J6ci5yHjzetgl9g53JY0gpinbJOt6mq/DlQeZC2ALLcVPhqMYfkqQJJjGKn7C
         EWBArYXbA4aElVVfpTYhgBBWsq/smZuoxyihirlwqZhUcp48Pzs9V9wEqEZAlyeZ5ICt
         6yZI2kykQGr5bpHUZjL+sgqf11Dt2iphoNTuFGoFmJcnmAXKpgf0PoiaAztlIH68sCc7
         h99Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=G+s8KeYPo3DKU8KAsFzI9EuTHpElgTPxlXfQAuxRCYE=;
        b=PZLP7sELALVJc0a6Gya6kztw8XMWmztsVe1g4GPDa+FfHWAPucqzRkzH/Cnvl9CrQ0
         u7db+adQ3gBhTZZJmBXRJ2GrX1GWalGWBmLAFlkCIzi2vFYNL/0YYVtYKbjeABB46Y/u
         RJp0VYTsL+Fn2F2xV0Qczc6YViC9IxqTxikZ+YCtGAIPnjO9he4W7K+0gNhssGvvCfJA
         bX9s08MpqQwnI7vIYyZlScJGQubjvKpJXwJuXf67UqsexFY7HM3tJHePHAVBeA9fNzQL
         9Sw+NcpjuVC+cpoCeqC5YEEUbAS0ce/CguZR+XWgj8mp22CJTUGTWgdEtgEbpY9Lqo4C
         NcSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=Tx+6XVtv;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id i4-20020a2ea364000000b0026bf7cf2a41si618728ljn.2.2022.09.19.03.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:17:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDqA-004bDN-A6; Mon, 19 Sep 2022 10:17:26 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 81F24302F6D;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 9D3F72BA49047; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101523.043382530@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:19 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 catalin.marinas@arm.com,
 will@kernel.org,
 guoren@kernel.org,
 bcain@quicinc.com,
 chenhuacai@kernel.org,
 kernel@xen0n.name,
 geert@linux-m68k.org,
 sammy@sammy.net,
 monstr@monstr.eu,
 tsbogend@alpha.franken.de,
 dinguyen@kernel.org,
 jonas@southpole.se,
 stefan.kristiansson@saunalahti.fi,
 shorne@gmail.com,
 James.Bottomley@HansenPartnership.com,
 deller@gmx.de,
 mpe@ellerman.id.au,
 npiggin@gmail.com,
 christophe.leroy@csgroup.eu,
 paul.walmsley@sifive.com,
 palmer@dabbelt.com,
 aou@eecs.berkeley.edu,
 hca@linux.ibm.com,
 gor@linux.ibm.com,
 agordeev@linux.ibm.com,
 borntraeger@linux.ibm.com,
 svens@linux.ibm.com,
 ysato@users.sourceforge.jp,
 dalias@libc.org,
 davem@davemloft.net,
 richard@nod.at,
 anton.ivanov@cambridgegreys.com,
 johannes@sipsolutions.net,
 tglx@linutronix.de,
 mingo@redhat.com,
 bp@alien8.de,
 dave.hansen@linux.intel.com,
 x86@kernel.org,
 hpa@zytor.com,
 acme@kernel.org,
 mark.rutland@arm.com,
 alexander.shishkin@linux.intel.com,
 jolsa@kernel.org,
 namhyung@kernel.org,
 jgross@suse.com,
 srivatsa@csail.mit.edu,
 amakhalov@vmware.com,
 pv-drivers@vmware.com,
 boris.ostrovsky@oracle.com,
 chris@zankel.net,
 jcmvbkbc@gmail.com,
 rafael@kernel.org,
 lenb@kernel.org,
 pavel@ucw.cz,
 gregkh@linuxfoundation.org,
 mturquette@baylibre.com,
 sboyd@kernel.org,
 daniel.lezcano@linaro.org,
 lpieralisi@kernel.org,
 sudeep.holla@arm.com,
 agross@kernel.org,
 bjorn.andersson@linaro.org,
 konrad.dybcio@somainline.org,
 anup@brainfault.org,
 thierry.reding@gmail.com,
 jonathanh@nvidia.com,
 jacob.jun.pan@linux.intel.com,
 atishp@atishpatra.org,
 Arnd Bergmann <arnd@arndb.de>,
 yury.norov@gmail.com,
 andriy.shevchenko@linux.intel.com,
 linux@rasmusvillemoes.dk,
 dennis@kernel.org,
 tj@kernel.org,
 cl@linux.com,
 rostedt@goodmis.org,
 pmladek@suse.com,
 senozhatsky@chromium.org,
 john.ogness@linutronix.de,
 juri.lelli@redhat.com,
 vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com,
 bsegall@google.com,
 mgorman@suse.de,
 bristot@redhat.com,
 vschneid@redhat.com,
 fweisbec@gmail.com,
 ryabinin.a.a@gmail.com,
 glider@google.com,
 andreyknvl@gmail.com,
 dvyukov@google.com,
 vincenzo.frascino@arm.com,
 Andrew Morton <akpm@linux-foundation.org>,
 jpoimboe@kernel.org,
 linux-alpha@vger.kernel.org,
 linux-kernel@vger.kernel.org,
 linux-snps-arc@lists.infradead.org,
 linux-omap@vger.kernel.org,
 linux-csky@vger.kernel.org,
 linux-hexagon@vger.kernel.org,
 linux-ia64@vger.kernel.org,
 loongarch@lists.linux.dev,
 linux-m68k@lists.linux-m68k.org,
 linux-mips@vger.kernel.org,
 openrisc@lists.librecores.org,
 linux-parisc@vger.kernel.org,
 linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org,
 linux-sh@vger.kernel.org,
 sparclinux@vger.kernel.org,
 linux-um@lists.infradead.org,
 linux-perf-users@vger.kernel.org,
 virtualization@lists.linux-foundation.org,
 linux-xtensa@linux-xtensa.org,
 linux-acpi@vger.kernel.org,
 linux-pm@vger.kernel.org,
 linux-clk@vger.kernel.org,
 linux-arm-msm@vger.kernel.org,
 linux-tegra@vger.kernel.org,
 linux-arch@vger.kernel.org,
 kasan-dev@googlegroups.com
Subject: [PATCH v2 40/44] ubsan: Fix objtool UACCESS warns
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=Tx+6XVtv;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

clang-14 allyesconfig gives:

vmlinux.o: warning: objtool: emulator_cmpxchg_emulated+0x705: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: paging64_update_accessed_dirty_bits+0x39e: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: paging32_update_accessed_dirty_bits+0x390: call to __ubsan_handle_load_invalid_value() with UACCESS enabled
vmlinux.o: warning: objtool: ept_update_accessed_dirty_bits+0x43f: call to __ubsan_handle_load_invalid_value() with UACCESS enabled

Add the required eflags save/restore and whitelist the thing.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
 lib/ubsan.c           |    5 ++++-
 tools/objtool/check.c |    1 +
 2 files changed, 5 insertions(+), 1 deletion(-)

--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -340,9 +340,10 @@ void __ubsan_handle_load_invalid_value(v
 {
 	struct invalid_value_data *data = _data;
 	char val_str[VALUE_LENGTH];
+	unsigned long ua_flags = user_access_save();
 
 	if (suppress_report(&data->location))
-		return;
+		goto out;
 
 	ubsan_prologue(&data->location, "invalid-load");
 
@@ -352,6 +353,8 @@ void __ubsan_handle_load_invalid_value(v
 		val_str, data->type->type_name);
 
 	ubsan_epilogue();
+out:
+	user_access_restore(ua_flags);
 }
 EXPORT_SYMBOL(__ubsan_handle_load_invalid_value);
 
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1068,6 +1068,7 @@ static const char *uaccess_safe_builtin[
 	"__ubsan_handle_type_mismatch",
 	"__ubsan_handle_type_mismatch_v1",
 	"__ubsan_handle_shift_out_of_bounds",
+	"__ubsan_handle_load_invalid_value",
 	/* misc */
 	"csum_partial_copy_generic",
 	"copy_mc_fragile",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101523.043382530%40infradead.org.
