Return-Path: <kasan-dev+bncBDCPL7WX3MKBBKMTQ7CAMGQEVLZT5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DF04B10013
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jul 2025 07:50:35 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-306ca683dcesf1017758fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jul 2025 22:50:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753336233; cv=pass;
        d=google.com; s=arc-20240605;
        b=QT3Yd3oFcEUZ57riV2uarH/Ia/NJs2xIVhgq317s65D5m2Vg/l+wmKwVVDaftZYqYg
         QV3jon5v9B3MpTnHfHF9k/z6SEPpJKRwFuYnl0W/tyJuo/3y+54kC3BoJjtJmhgm16D0
         hsj/MpnkFDHka8Co0j6L3by7z5t5LsO0KeNluE+6CkR9CfYcNg89wEvuTWuLQCGVngpn
         4JQ78rakNlmXqCCT+UlpwmKqDFZj9a7vfO4r9jlixy2wfT7gzWEx+nY/+tB4DZQf6+gQ
         PSd+ssTA0ZaWNBQ+W2xhLEG+WFVhTQhKLIg45E99kiK2fWXS4f1qNX++z2v9hltqQyZL
         mW0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=snN9AvyPAmfzORtN9mwpK3KoBPwJnudT3NOhL1eCe5A=;
        fh=0iCP6JkghRNkd1ypuTDXTYM1VKesRGOotD9ch8MKLow=;
        b=C5ja+UGvdvhJt06zpYHX8wWcmY4G8LLqo5EAGUruY4ZXmXZdrrOBnSrHasdxjEB29M
         CH8mWhQePVeSqALHckJ46LnQjpmpULkdAKukG2qjQTI9etPACrceMt0W7f298AntabMw
         2Z26y9C1iHInHqC3oovCjwu+EiN7lLy1u/D8XPP+ajhiqYA5toe/x9RYgOBlSpE4n0mh
         D74AOAkTAbrqv4IVWIq1vGRRzMNIcG1rqKeOT2HeQvaGJivZEdIE6ub0aYl1aQ7PUN1g
         kPNjbklTw1v3J+lVLDD/Mqm8GKlxVgio4azvMtMNeZa5j/M76TlIPBbrbmOW3/KFahJe
         Lfxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QgWgAc1Z;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753336233; x=1753941033; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=snN9AvyPAmfzORtN9mwpK3KoBPwJnudT3NOhL1eCe5A=;
        b=OgJdIR9Aswi8YmvRdnzntP6Ty5ROPjt+TAIEXOhqt46YO7LpV6wkQTvI9FZMiNVak6
         epVv1meLcxD5gH4ReIa9ll9DckH4QmdBnjusHtVIeEoAZcHnEDgszD03q6g8V8zEqeUN
         OOKL75VQJ+8WxLGUW1SkSL27n/0ADcC/7CNEev8kW2lsugO45O1KnH7cDswHmdDqT3Mj
         deS+twNsOL/Apf/vCSTPWyr5dKHuYHXmSkbxbRnmKzrEB5++mFgnAAz3VZ5qGNdM+QBI
         MMd9oRTST83IwSkF5IyKs+X7ESFoZsrePCP8Fng1eEGufS1Q/O6Nb8XOFf8YUXRtkttA
         hhJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753336233; x=1753941033;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=snN9AvyPAmfzORtN9mwpK3KoBPwJnudT3NOhL1eCe5A=;
        b=w9Lk3/z4LlcjKTtup1kZG3O3srRhu0zN0ji+J5pED6yN+qSwHGQn+yenjrc4vbKVGB
         G6RUFQqCqxHKixfXku5kYaCQtyaeqadphFUGZdPi3WndkRAmpzQICtK2Ppl6iejB49LV
         8dCl3nCoA23ZSRtf5HI7N/0J8Nfcr5Q6+dA3ccx2SEqihM032nhF14gdXy+euuStuhJB
         VthuLj6/AAAQ0sBc28Q3g9ZXA1kfa+AnjvVwwDQ+zcRL8OlcvaGC89uknA+lpLIHvzBC
         GkJvHpYOFeueQmCRDudokJpD0ljtT5VzOhfaltWKNvK6fzZZo3TthdnKtJxMjtwBgmOe
         ryYg==
X-Forwarded-Encrypted: i=2; AJvYcCWB8m1KoHU93n9qCu/ZyL2pi6KDt3DRdeXlhvKTbTt7gyyxneD+FhkdSjnkbXaQhlXMfT7ELg==@lfdr.de
X-Gm-Message-State: AOJu0Yy2a/efIUQx/Qqb3uFtfv0HyzyaU+iZO4Ljzhk3HEWqajatKmyB
	bO2jGb48DKYmDfYIhuNky9tWffJX1eV9ULamtJBsi6Bc3ZxdOGxFY0ZQ
X-Google-Smtp-Source: AGHT+IFDKwqiPJpv+QFtG4u3EV0BmJT5mQihNkK3jhy7W56krpCD7+uYgONnJxC3ZSfsAyvGPCl8lA==
X-Received: by 2002:a05:6870:78b:b0:2e9:95cc:b855 with SMTP id 586e51a60fabf-306c73546cemr4427440fac.34.1753336233542;
        Wed, 23 Jul 2025 22:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduwmoFTIXnNJtGtX7xEf48Wq/bKJIT6qygVAH91Llj1Q==
Received: by 2002:a05:6870:3124:b0:2c2:2ed7:fb78 with SMTP id
 586e51a60fabf-306dd71b007ls689115fac.0.-pod-prod-01-us; Wed, 23 Jul 2025
 22:50:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9X7s3UowzHHltbeZ82UdSutDYYkAFje0UcWprW/oKD66qc3DikEnrACsIxXIo11NaNWusz6uzndM=@googlegroups.com
X-Received: by 2002:a05:6870:d629:b0:296:5928:7a42 with SMTP id 586e51a60fabf-306c7250dfcmr3480470fac.22.1753336232375;
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753336232; cv=none;
        d=google.com; s=arc-20240605;
        b=jN7/e+reOUzhltRon/iCGidTUqIqVJbltXfIM5pjKjo3QOXO1sdEV6ocFCX3tihGso
         a5dDhhqYB1974WXgqn7csjyo0owWvUNC3lFJZCX3CqjacfTsNkrcIOzsTEo+bYj2noBQ
         zrQQMnGupdDXcsNkt85n3jLzOE5oyyWwV6BrvKf8b8DKCq4JoAu9SBO1ttbYNUtu8JZe
         bzfk2Gzbuj3ucVb1AYnnTW4N5polk2eEKcZUcutOUpmPNf452nt/qCdlJulO71IJzDaI
         CViO+CHApFhAVKTpvYY40Fiac/qk5qtVS+6sj20XgbcRuNxHS0vRAU5nQLuMPdBTR9jn
         MgmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4j17pn+//SHkaX8ONm+HlhNEvqzcDQ+QNAUfr7A3lEQ=;
        fh=sdm5Z2TnP2dG9IZ4WGJl1bGjmOz24FfNTpAU+6OkKMw=;
        b=Dy5GygUEdKHJKcgu0zaioIrhBlcK4dFzY867LnWqOoWuslzucCn8FrPKotiQsFPvha
         rV3EBst6BTA6QWnBaRzDrDJk9x64pDBNl/FTo8ateJLKwZE2P6iBlHEkSE9xAPnlCpsg
         vrYRzWOe1/guxqlrVRUbQnI2n/Jgew3M+eWP/q32wvCChvIGUSbY/XZbzHdBpyhVpuyW
         tcuTs5/4yr4GUugYXSnpjHlZ8Zqsw2Rx5qZ7Ip5zVubPqPipwG53Qz7gPZhO0Orhge0e
         GaooNOrMbkiC5qvwc+j2T7qXCY7+d/Gxu7kvz5a2uFAz/ufojIUlpuDNeU9Og0wr2uz6
         sTZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QgWgAc1Z;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-306e1d4c57fsi55433fac.4.2025.07.23.22.50.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jul 2025 22:50:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 68FF46114C;
	Thu, 24 Jul 2025 05:50:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AC523C2BCB1;
	Thu, 24 Jul 2025 05:50:30 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Arnd Bergmann <arnd@arndb.de>
Cc: Kees Cook <kees@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Nicolas Schier <nicolas.schier@linux.dev>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Gavin Shan <gshan@redhat.com>,
	"Russell King (Oracle)" <rmk+kernel@armlinux.org.uk>,
	James Morse <james.morse@arm.com>,
	Oza Pawandeep <quic_poza@quicinc.com>,
	Anshuman Khandual <anshuman.khandual@arm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Paolo Bonzini <pbonzini@redhat.com>,
	Mike Rapoport <rppt@kernel.org>,
	Vitaly Kuznetsov <vkuznets@redhat.com>,
	Henrique de Moraes Holschuh <hmh@hmh.eng.br>,
	Hans de Goede <hansg@kernel.org>,
	=?UTF-8?q?Ilpo=20J=C3=A4rvinen?= <ilpo.jarvinen@linux.intel.com>,
	"Rafael J. Wysocki" <rafael@kernel.org>,
	Len Brown <lenb@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michal Wilczynski <michal.wilczynski@intel.com>,
	Juergen Gross <jgross@suse.com>,
	Andy Shevchenko <andriy.shevchenko@linux.intel.com>,
	"Kirill A. Shutemov" <kas@kernel.org>,
	Roger Pau Monne <roger.pau@citrix.com>,
	David Woodhouse <dwmw@amazon.co.uk>,
	Usama Arif <usama.arif@bytedance.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Thomas Huth <thuth@redhat.com>,
	Brian Gerst <brgerst@gmail.com>,
	Hou Wenlong <houwenlong.hwl@antgroup.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"Peter Zijlstra (Intel)" <peterz@infradead.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Sami Tolvanen <samitolvanen@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Andy Lutomirski <luto@kernel.org>,
	Baoquan He <bhe@redhat.com>,
	Alexander Graf <graf@amazon.com>,
	Changyuan Lyu <changyuanl@google.com>,
	Paul Moore <paul@paul-moore.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Jan Beulich <jbeulich@suse.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Viresh Kumar <viresh.kumar@linaro.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Bibo Mao <maobibo@loongson.cn>,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	kvm@vger.kernel.org,
	ibm-acpi-devel@lists.sourceforge.net,
	platform-driver-x86@vger.kernel.org,
	linux-acpi@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	linux-efi@vger.kernel.org,
	linux-mm@kvack.org,
	kexec@lists.infradead.org,
	linux-security-module@vger.kernel.org,
	llvm@lists.linux.dev
Subject: [PATCH v4 4/4] kstack_erase: Support Clang stack depth tracking
Date: Wed, 23 Jul 2025 22:50:28 -0700
Message-Id: <20250724055029.3623499-4-kees@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250724054419.it.405-kees@kernel.org>
References: <20250724054419.it.405-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2299; i=kees@kernel.org; h=from:subject; bh=p+7YUBTmffdnZ8pKAPuZ2rzC3Zvp9P0MFRgY7Xz1ydU=; b=owGbwMvMwCVmps19z/KJym7G02pJDBmNJ5fsPnPUwKQyTLv6YDRX59942Z9pVg4x/Z3tr6sPL i8Lmbqoo5SFQYyLQVZMkSXIzj3OxeNte7j7XEWYOaxMIEMYuDgFYCLbGRj+55xsNLv8fgpvz+zJ 97Q2v1jyfM6aXx5r3h0o/XvrBVfaBhWG/34taus75nNe6jl2+9BH9ihD5yM7dLl817dcaviWpVx +gAsA
X-Developer-Key: i=kees@kernel.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QgWgAc1Z;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
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

Wire up CONFIG_KSTACK_ERASE to Clang 21's new stack depth tracking
callback[1] option.

Link: https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-stack-depth [1]
Signed-off-by: Kees Cook <kees@kernel.org>
---
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Masahiro Yamada <masahiroy@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>
Cc: Nicolas Schier <nicolas.schier@linux.dev>
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: "Gustavo A. R. Silva" <gustavoars@kernel.org>
Cc: <linux-kbuild@vger.kernel.org>
Cc: <kasan-dev@googlegroups.com>
Cc: <linux-hardening@vger.kernel.org>
---
 security/Kconfig.hardening    | 5 ++++-
 scripts/Makefile.kstack_erase | 6 ++++++
 2 files changed, 10 insertions(+), 1 deletion(-)

diff --git a/security/Kconfig.hardening b/security/Kconfig.hardening
index f7aa2024ab25..b9a5bc3430aa 100644
--- a/security/Kconfig.hardening
+++ b/security/Kconfig.hardening
@@ -82,10 +82,13 @@ choice
 
 endchoice
 
+config CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
+	def_bool $(cc-option,-fsanitize-coverage-stack-depth-callback-min=1)
+
 config KSTACK_ERASE
 	bool "Poison kernel stack before returning from syscalls"
 	depends on HAVE_ARCH_KSTACK_ERASE
-	depends on GCC_PLUGINS
+	depends on GCC_PLUGINS || CC_HAS_SANCOV_STACK_DEPTH_CALLBACK
 	help
 	  This option makes the kernel erase the kernel stack before
 	  returning from system calls. This has the effect of leaving
diff --git a/scripts/Makefile.kstack_erase b/scripts/Makefile.kstack_erase
index 5223d3a35817..c7bc2379e113 100644
--- a/scripts/Makefile.kstack_erase
+++ b/scripts/Makefile.kstack_erase
@@ -8,6 +8,12 @@ kstack-erase-cflags-$(CONFIG_GCC_PLUGIN_STACKLEAK_VERBOSE) += -fplugin-arg-stack
 DISABLE_KSTACK_ERASE := -fplugin-arg-stackleak_plugin-disable
 endif
 
+ifdef CONFIG_CC_IS_CLANG
+kstack-erase-cflags-y += -fsanitize-coverage=stack-depth
+kstack-erase-cflags-y += -fsanitize-coverage-stack-depth-callback-min=$(CONFIG_KSTACK_ERASE_TRACK_MIN_SIZE)
+DISABLE_KSTACK_ERASE  := -fno-sanitize-coverage=stack-depth
+endif
+
 KSTACK_ERASE_CFLAGS   := $(kstack-erase-cflags-y)
 
 export STACKLEAK_CFLAGS DISABLE_KSTACK_ERASE
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250724055029.3623499-4-kees%40kernel.org.
