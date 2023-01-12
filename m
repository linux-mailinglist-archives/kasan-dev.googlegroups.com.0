Return-Path: <kasan-dev+bncBDBK55H2UQKRB3OMQGPAMGQEUOPKHTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id AEE68668002
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 20:58:37 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id i8-20020a05640242c800b004852914ce42sf12838535edc.6
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Jan 2023 11:58:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673553517; cv=pass;
        d=google.com; s=arc-20160816;
        b=ThcoJ+xvzWBxciDSZEqrqUtZoUKYSVKr2gNOA1aCQPPYOPD0u9kkX9yl+12hM0Ddog
         52uoin/QMtAXv0ZHpoUYDbfVEunz3iiaCdSYHxtkF299HPbSmXjYX7LxzIN1qywQZHEu
         KGkxZldIU9HaXMQXeM5oj0HRsbv38rJC53SuFr5oHksConO76oczYEduVWyyiPYmSQts
         uUtxw2iSf97987kRMW22PX1HKGLEVjC9zY+VMIYBLo9f2sUbwrmlUlkPa8nvTgALIkKp
         IdXSyInqUhmR0p2ZQ01PFuXN8cgiGRUhp+ZrK3fal/N8cw6K7GFSGaRqYoSlU9ZnB2S8
         go7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=KNduRLB5Lf09heyaIgUcyxB4J+oPjQeBXwjTnYCr6u0=;
        b=vpW+NSamT9TMXq4Zl/cjY3ZzLNFqfxasMUctg6u83JClN9c5a9Joq/rj8zoOdE5S02
         rC/1xrL4mZzz5j6z18g6FQs8qoyAIZGJwR7/0r5Bk6xAwivj25GQzX6O1Ats89zB3OIV
         pzcCOYFtw7cvzznVO9QYBzrcVNuDE900GIwTFlrA0lMOMfkOJHpYiUh1j73+wCI053r2
         JS7kVVrPqqHGXK5at7Bz8dG/FWSNbaLQRqIfFJZJ5V3fiBJ2wKNzDoHFPvUKWMO3Zosl
         7ukxQmhK1luMjrtKWhXmO63NqG4/gj8GOYVAeV8qULr0v/PEHnFiXOhdLIhLL1NHfIZp
         k80A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UZP1WhwW;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KNduRLB5Lf09heyaIgUcyxB4J+oPjQeBXwjTnYCr6u0=;
        b=MnqugV5H7oGSYXQbx87jQy3X7wwZproaLcXU4pfQiNr2dDAGXgDL6Q9NBPGMexrh/G
         4ZH3yVukLN6TiF9X24ZN2YVhPRK+qxXWjUSSWAHX/xLpLJAROpkz6YGevakMpO6LKwWU
         D0E9dscxkSyi0H6Sok6TxB5lK87y35R6sG66o/4E2Cg1sY6QgP2utx7vvv2IT3TKpDFh
         k6yHl4eEvDekk9A7pTLZGe9QrQ8ZMq6rAhJLgd3vCxq6u1AJbf3TSnTEzqdNjRMDF1Pd
         6TVZyDbs0UwhNSVdltfj6JpgPyhNmO95vOUqKgOg4FyNcbVfBBFnwQ909+duaXiZLHaS
         yhdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=KNduRLB5Lf09heyaIgUcyxB4J+oPjQeBXwjTnYCr6u0=;
        b=lRrQzZkrOJA1/B3xfVzeOFa3o495/TXvCuVyY0xSnbQYGdTTQKb7SZ8jkOpi2Zj6VF
         UsTHHNxOaHEP+Md7Coq97hC0ej3TBGNZ+zU313LVfJGtOfwLRei/qLdAJq2flnZuJBqQ
         ScORrfICjRnp3iDWRDL0W4zsubOzdLvdkeUajAfRh/pcFPiFxvbY5Y/W3nqChIoXz/L8
         5BT/n2ONkyMMFNSPV3LODpqIHLwSXZeMbHjt6uGNVuwSRhLDqdgZapF5+/KZE6UrfZsO
         a7EDphl7l7j9H1fZR05jH163jFtXaPRHXTEaDrs1ITQieGF7el60wExbNATrxAPebCQC
         k03w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpqFJGNFFuAJXmHUIPmCdpQNmYQJtdNoUsOaNIX++F3aLSleBv2
	PXuQUar6qg0lnzVL/EmTC+w=
X-Google-Smtp-Source: AMrXdXsIwJBXykhSRoBYckXsZvlSeI+U+JDprgA3wibcNP3gGKgI1YKBAsx3VPirDIZvsPFlKXS3uA==
X-Received: by 2002:a17:906:59b:b0:7c1:4e70:1f96 with SMTP id 27-20020a170906059b00b007c14e701f96mr6128454ejn.277.1673553517267;
        Thu, 12 Jan 2023 11:58:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:40cf:b0:488:1679:c417 with SMTP id
 z15-20020a05640240cf00b004881679c417ls2361656edb.1.-pod-prod-gmail; Thu, 12
 Jan 2023 11:58:36 -0800 (PST)
X-Received: by 2002:a05:6402:3712:b0:499:70a8:f918 with SMTP id ek18-20020a056402371200b0049970a8f918mr15424570edb.16.1673553516060;
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673553516; cv=none;
        d=google.com; s=arc-20160816;
        b=Fizl6LqzBSFO/jOwZ7LcDlj1AXC7kFEWquQkRicV+w1x+Z7Wqx+5ND3dFZZU358VWo
         JgJsqEq+2ekxZdBZ9gaMOhl5vnvc4CzdWdqKApijjjOwPxg37gnEHzfdxeTMANtSvK9B
         zDhONzKV4Kr2/vFtEb2BN+wUO93XgKH7QaZSOrUTGJ6C9GEVbeiWVcVAq2e4eYpfDMw0
         r370Vic6NMP6toC6uKHgxUvApIiy/Vz6KUYiJ8tdRVysrE4PUni0rdMVUQHieHcdRnIv
         tGaW5rQrtoNc5f8AF+5Q09gYi5H5dbdwmq9Tf63hlS97XxiPvsZlJhXIkj+yxBB61aFh
         8wVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=GvwbGFmvCEUlvMDtuRKKain2RkezywAYf/go7N4onKI=;
        b=d7WdhXYSTV4XRPZL/1BYqBummLzpdbC4Szr9/msdbYLrGvsLmzEd+jPD5Y5Nbb2+yd
         UZzStSIogljdNsXvKE/pgV3nBeYAUH1UofWoXu0zhP1cKdYlOISwI/ynQlKgCKm3FdlS
         5Y+iKIAqFii8650tUfkytmamCXZX9PwKcIanO+I8k080VT3mJauvfVFoLJ23uog/x5hP
         jPUc8thD3F8d0AP9oF3/+0OuMr82Jw5ifNsH3Mkokeg79LymmRYC1W/brUDRCvXrHGDo
         9fQAHbBzJeGsTzxncRt9eLAX2sRFWiG3T2Ec6i6/9hFMuw2R6RWV/qV8Ejm7e5YeOc8u
         HSzw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=UZP1WhwW;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id k20-20020a05640212d400b0047014e8771fsi776644edx.3.2023.01.12.11.58.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Jan 2023 11:58:36 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.96 #2 (Red Hat Linux))
	id 1pG3hW-0045tz-2U;
	Thu, 12 Jan 2023 19:57:30 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 20B33303472;
	Thu, 12 Jan 2023 20:57:14 +0100 (CET)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id 5F8C02CD066D4; Thu, 12 Jan 2023 20:57:08 +0100 (CET)
Message-ID: <20230112195542.028523143@infradead.org>
User-Agent: quilt/0.66
Date: Thu, 12 Jan 2023 20:43:58 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: peterz@infradead.org
Cc: richard.henderson@linaro.org,
 ink@jurassic.park.msu.ru,
 mattst88@gmail.com,
 vgupta@kernel.org,
 linux@armlinux.org.uk,
 nsekhar@ti.com,
 brgl@bgdev.pl,
 ulli.kroll@googlemail.com,
 linus.walleij@linaro.org,
 shawnguo@kernel.org,
 Sascha Hauer <s.hauer@pengutronix.de>,
 kernel@pengutronix.de,
 festevam@gmail.com,
 linux-imx@nxp.com,
 tony@atomide.com,
 khilman@kernel.org,
 krzysztof.kozlowski@linaro.org,
 alim.akhtar@samsung.com,
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
 andersson@kernel.org,
 konrad.dybcio@linaro.org,
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
 mhiramat@kernel.org,
 frederic@kernel.org,
 paulmck@kernel.org,
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
 linux-samsung-soc@vger.kernel.org,
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
 linux-mm@kvack.org,
 linux-trace-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com,
 "Rafael J. Wysocki" <rafael.j.wysocki@intel.com>,
 Ulf Hansson <ulf.hansson@linaro.org>
Subject: [PATCH v3 44/51] entry,kasan,x86: Disallow overriding mem*() functions
References: <20230112194314.845371875@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=UZP1WhwW;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=peterz@infradead.org
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

KASAN cannot just hijack the mem*() functions, it needs to emit
__asan_mem*() variants if it wants instrumentation (other sanitizers
already do this).

vmlinux.o: warning: objtool: sync_regs+0x24: call to memcpy() leaves .noinstr.text section
vmlinux.o: warning: objtool: vc_switch_off_ist+0xbe: call to memcpy() leaves .noinstr.text section
vmlinux.o: warning: objtool: fixup_bad_iret+0x36: call to memset() leaves .noinstr.text section
vmlinux.o: warning: objtool: __sev_get_ghcb+0xa0: call to memcpy() leaves .noinstr.text section
vmlinux.o: warning: objtool: __sev_put_ghcb+0x35: call to memcpy() leaves .noinstr.text section

Remove the weak aliases to ensure nobody hijacks these functions and
add them to the noinstr section.

Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Acked-by: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
Acked-by: Frederic Weisbecker <frederic@kernel.org>
Tested-by: Tony Lindgren <tony@atomide.com>
Tested-by: Ulf Hansson <ulf.hansson@linaro.org>
---
 arch/x86/lib/memcpy_64.S  |    5 ++---
 arch/x86/lib/memmove_64.S |    4 +++-
 arch/x86/lib/memset_64.S  |    4 +++-
 mm/kasan/kasan.h          |    4 ++++
 mm/kasan/shadow.c         |   38 ++++++++++++++++++++++++++++++++++++++
 tools/objtool/check.c     |    3 +++
 6 files changed, 53 insertions(+), 5 deletions(-)

--- a/arch/x86/lib/memcpy_64.S
+++ b/arch/x86/lib/memcpy_64.S
@@ -7,7 +7,7 @@
 #include <asm/alternative.h>
 #include <asm/export.h>
 
-.pushsection .noinstr.text, "ax"
+.section .noinstr.text, "ax"
 
 /*
  * We build a jump to memcpy_orig by default which gets NOPped out on
@@ -42,7 +42,7 @@ SYM_FUNC_START(__memcpy)
 SYM_FUNC_END(__memcpy)
 EXPORT_SYMBOL(__memcpy)
 
-SYM_FUNC_ALIAS_WEAK(memcpy, __memcpy)
+SYM_FUNC_ALIAS(memcpy, __memcpy)
 EXPORT_SYMBOL(memcpy)
 
 /*
@@ -183,4 +183,3 @@ SYM_FUNC_START_LOCAL(memcpy_orig)
 	RET
 SYM_FUNC_END(memcpy_orig)
 
-.popsection
--- a/arch/x86/lib/memmove_64.S
+++ b/arch/x86/lib/memmove_64.S
@@ -13,6 +13,8 @@
 
 #undef memmove
 
+.section .noinstr.text, "ax"
+
 /*
  * Implement memmove(). This can handle overlap between src and dst.
  *
@@ -213,5 +215,5 @@ SYM_FUNC_START(__memmove)
 SYM_FUNC_END(__memmove)
 EXPORT_SYMBOL(__memmove)
 
-SYM_FUNC_ALIAS_WEAK(memmove, __memmove)
+SYM_FUNC_ALIAS(memmove, __memmove)
 EXPORT_SYMBOL(memmove)
--- a/arch/x86/lib/memset_64.S
+++ b/arch/x86/lib/memset_64.S
@@ -6,6 +6,8 @@
 #include <asm/alternative.h>
 #include <asm/export.h>
 
+.section .noinstr.text, "ax"
+
 /*
  * ISO C memset - set a memory block to a byte value. This function uses fast
  * string to get better performance than the original function. The code is
@@ -43,7 +45,7 @@ SYM_FUNC_START(__memset)
 SYM_FUNC_END(__memset)
 EXPORT_SYMBOL(__memset)
 
-SYM_FUNC_ALIAS_WEAK(memset, __memset)
+SYM_FUNC_ALIAS(memset, __memset)
 EXPORT_SYMBOL(memset)
 
 /*
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -551,6 +551,10 @@ void __asan_set_shadow_f3(const void *ad
 void __asan_set_shadow_f5(const void *addr, size_t size);
 void __asan_set_shadow_f8(const void *addr, size_t size);
 
+void *__asan_memset(void *addr, int c, size_t len);
+void *__asan_memmove(void *dest, const void *src, size_t len);
+void *__asan_memcpy(void *dest, const void *src, size_t len);
+
 void __hwasan_load1_noabort(unsigned long addr);
 void __hwasan_store1_noabort(unsigned long addr);
 void __hwasan_load2_noabort(unsigned long addr);
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -38,6 +38,12 @@ bool __kasan_check_write(const volatile
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
+#ifndef CONFIG_GENERIC_ENTRY
+/*
+ * CONFIG_GENERIC_ENTRY relies on compiler emitted mem*() calls to not be
+ * instrumented. KASAN enabled toolchains should emit __asan_mem*() functions
+ * for the sites they want to instrument.
+ */
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
@@ -68,6 +74,38 @@ void *memcpy(void *dest, const void *src
 
 	return __memcpy(dest, src, len);
 }
+#endif
+
+void *__asan_memset(void *addr, int c, size_t len)
+{
+	if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
+
+	return __memset(addr, c, len);
+}
+EXPORT_SYMBOL(__asan_memset);
+
+#ifdef __HAVE_ARCH_MEMMOVE
+void *__asan_memmove(void *dest, const void *src, size_t len)
+{
+	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
+	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memmove(dest, src, len);
+}
+EXPORT_SYMBOL(__asan_memmove);
+#endif
+
+void *__asan_memcpy(void *dest, const void *src, size_t len)
+{
+	if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
+	    !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
+
+	return __memcpy(dest, src, len);
+}
+EXPORT_SYMBOL(__asan_memcpy);
 
 void kasan_poison(const void *addr, size_t size, u8 value, bool init)
 {
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -956,6 +956,9 @@ static const char *uaccess_safe_builtin[
 	"__asan_store16_noabort",
 	"__kasan_check_read",
 	"__kasan_check_write",
+	"__asan_memset",
+	"__asan_memmove",
+	"__asan_memcpy",
 	/* KASAN in-line */
 	"__asan_report_load_n_noabort",
 	"__asan_report_load1_noabort",


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230112195542.028523143%40infradead.org.
