Return-Path: <kasan-dev+bncBDBK55H2UQKRBYEDUGMQMGQEZVUFEAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id C86CC5BC6CE
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 12:18:08 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id f14-20020a1c6a0e000000b003b46dafde71sf2423185wmc.3
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663582688; cv=pass;
        d=google.com; s=arc-20160816;
        b=jS5CfaE3t9nlSKbQN+ixTHrThWiz91MehimxOfuXkYYm77lATNO1eYVTfmdpj4cvwi
         xv2XjVAZPJ4jA/Nu+cEBfXS++T+Ccme5XEXwEDe7yDf//s1Akr6vSk3DqPwbdjbliAPu
         nAhRO9bNukIyxE/Hg4BYgUWxKjp5GSS7iWpOsuElR9KzNGpHb6wzzQ5NkbFGRz1N15PX
         iiEtxpu5gZguB8aCeoL4R/vFJ9Ig5CzZjJRKxbB3IhrTnJm5dm7YVjYzchcFWPa0YP8j
         vEjAOnEBtTiUUTLyzVTN9bwXavW7/aAJ58/8DNuHyx7J/UqhlfMmUZk5/E6x01uPf+XE
         u5jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:subject:cc
         :to:from:date:user-agent:message-id:sender:dkim-signature;
        bh=FCYWFv695gxtJ7lU2JgLnpQd6Frnd0IFJEwu1P5IOZk=;
        b=yNeJ5Eo2gtv+IRqzl62z52/bRJZbPUZ+no8OtiHQ2m86AnKO1IhrFwLlc3f2jIH6Or
         IeDwCw+6x2Lh/CsgN/o1pGPT3i1ULdgevWjz86Zm/tBTPclY4FxHVyv0Kstsrj4JhGTn
         vUsrhiy6BsrBho6gYpkqIzTvtDyweSG1C9H7CnvGbVZCvyetUI48tNr561qZzHtrM4Cc
         KGkwO9neKYqqdaXttYriVmgd08E7vqVBOQnd3cwf3XiemxnMbgoABtTbaACuqTW6VQTE
         E0RGHsEB6+1e322Uuimh44OTtiodiX/v6jIC2UkHxjEkMFE6atJnIVrlv+32h2k/sdjj
         tEuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=QFBxPfuZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:subject:cc:to:from:date
         :user-agent:message-id:sender:from:to:cc:subject:date;
        bh=FCYWFv695gxtJ7lU2JgLnpQd6Frnd0IFJEwu1P5IOZk=;
        b=spoXwySCqDuaclKwVgafSv+kyTYkWC4Ls12IpbX2jnI7KK5sCU9ZH3ydndmi0ALNJK
         1NNkqRllK+UMnAKQAAqbXo0fkyW2OR90SV6lnUYKnp/fGbv9c6u0TRsrumdEqsdmhuTw
         tCsMxzu4HHr3EwinTOfGdEflCmu+ECR2rWDfQI+2fTtIIs6xpv/YNKQTXStwubQoK/hX
         oJACZV59/zjY3+lrWzfyh2+hMzOzH1/i2VBEQSUhyTVNmdruBcPVhl0tcss5ILRju8ej
         ezCST/T0mHFuyEsBe842GFG7342R7mN0XDfs8MdEraBIOG7xcyyK0XdUOAHYHDkc9E0O
         Nv0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:subject:cc:to:from:date:user-agent:message-id
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=FCYWFv695gxtJ7lU2JgLnpQd6Frnd0IFJEwu1P5IOZk=;
        b=bgVXyHITqhBVaRuBYjswgU8AWRm/VyhdSJ18OgppWbTa2KgwNmXgNe139ovL3+45vz
         Ti6RFi2uugQ0zEMnA1wk9CFDCvyfWb18DaOEAIpYfd7BGJQBNOpDww0oD0FEVzNYGz24
         Ago2PVjq7KNcF9gR2dUxjgVMANWVF3sytqMP9x+Mk7wFTCXfojUS7cGbTenDlNxWC4GO
         MpzQLi9Cv/xQ+j16oNvVCOdxLKjQmW6vELqEbJqjRl3hgm3eXmW1CLno7uwuZbylTf+x
         5KdSy5kNvdjYoOc5a6V84bDfl9tEa9fnJULb189/+XsBBXwzjYhf4yx48xkQJ+rxu7yj
         0v7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0hTeNqJ8STHYU5MnQgrL4O/gcp6SBTUSDU3rEMTmIcnTM/EmuL
	1MZwcYIwo6ER9QF4+nYE5Kk=
X-Google-Smtp-Source: AMsMyM59RcublUu8xxIamryX5c0a50ZUaQAlWHg2D97wJjE0lte30agWj4a/cowUCqAq9Ni5F1JggQ==
X-Received: by 2002:a05:600c:255:b0:3aa:2150:b184 with SMTP id 21-20020a05600c025500b003aa2150b184mr11792461wmj.138.1663582688436;
        Mon, 19 Sep 2022 03:18:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:695:b0:22b:e6:7bce with SMTP id bo21-20020a056000069500b0022b00e67bcels2883546wrb.1.-pod-prod-gmail;
 Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
X-Received: by 2002:a05:6000:1ace:b0:22a:c9a6:e203 with SMTP id i14-20020a0560001ace00b0022ac9a6e203mr10549086wry.694.1663582687298;
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663582687; cv=none;
        d=google.com; s=arc-20160816;
        b=iTmUj+ZlZHcbKNBEsVxLnIFQDrb+fHv4itgQlYtStxPLT8pTHpnZM8lgJ7FgVAlHOk
         zFZQSCz9DhoByarCpGpPsV1dNozbOifBkkY+6/My5ZY8I9+VizQHXvDqZ0QZxAG+02Jo
         VadTgytEveLzBh6qv0DlMLfM2q0Aql/NdZ2YnbFYhvnHgsktTv41ywxnpCuWbMiQnCdY
         r3Ad+4W8snGDMyx2KB3Ha81lmVSGoYNPxOJ4ssV2eAANztwycOxE6SBgZiJetIU0OcZg
         5AXdzbKaih3DYVamplD/d2skBDvQSzB1coVXiF09A21fgLguot7a0pFv5lzHBWxRVFOK
         Lp1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:subject:cc:to:from:date:user-agent
         :message-id:dkim-signature;
        bh=E91useHlyUUQoMsCvOSeJGEyanvxTuAtV3Y/d5ylPRM=;
        b=0cjcbEB/ckvFcgwhwX47e/xnLF+mvELqbGcr7XVV/yVIvFKRK9xIrciT043j+04bwj
         x0S4OqDR1no9iaNxZTT0EK4MeATRS/cB8VBC86q/ucE3z25a8z7WQ1FMJ+4OmtZi4Hi9
         jWBz1iH2enVdYO32lWQHwK9ZpLrgb56RiKKHIlibJGwBWpIto+ZmMRpVVyvGnnDX2Sic
         mzyJbdytiN6hAYKXDIaZLE1vV7Kgzvrw8IqDaccxX12UrIqhtRo96mDKAjK8l8HlMOk4
         OWratHcX14CfDPeICkQ3R1v3qWfmH3ABFPVBl57V2I8clGIE7BEqEbY5jcQrBz2fNoqL
         bYFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=QFBxPfuZ;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id bp13-20020a5d5a8d000000b0022a48262c0bsi374840wrb.2.2022.09.19.03.18.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 19 Sep 2022 03:18:07 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as permitted sender) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1oaDq8-00E2Bv-GZ; Mon, 19 Sep 2022 10:17:25 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 9D2C5302F7A;
	Mon, 19 Sep 2022 12:16:25 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id A6ECA2BAC75A5; Mon, 19 Sep 2022 12:16:22 +0200 (CEST)
Message-ID: <20220919101523.177759249@infradead.org>
User-Agent: quilt/0.66
Date: Mon, 19 Sep 2022 12:00:21 +0200
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
Subject: [PATCH v2 42/44] entry,kasan,x86: Disallow overriding mem*() functions
References: <20220919095939.761690562@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=QFBxPfuZ;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1:d65d:64ff:fe57:4e05 as
 permitted sender) smtp.mailfrom=peterz@infradead.org
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220919101523.177759249%40infradead.org.
