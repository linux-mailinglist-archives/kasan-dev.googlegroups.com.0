Return-Path: <kasan-dev+bncBD53XBUFWQDBBH5JZDEAMGQETIH25AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F668C47FA1
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:36:49 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-88233d526basf48728996d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:36:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792608; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZuIHwTeNexQ7PTMzuZ09UT7Oy7uOtMXcgV6t9Q11rhVjEzwuhc8O8j6SeoJslZJJQo
         ByXFThJtrMu7JMlUHLfWJb8xKPykawKiVCnVIDDINUVm4zPTlr8tlsTUhY2kBvbnyWlq
         4IBmjwr8+lwecGcX7+zTh84qwmyq/7ZxBJf9p6df6ucrHXpnuAzB/X2k1Zg677QOkufK
         r5eIek71q9Lpp7YTcMhDjdHN1maVwBW1bXmQo1l8YhMpsknucrY7aUGcCDZjmpBufoie
         8rs34yg3ZTl8eJaq0rRJFHsdDoRxbrvwsENMZztkAktMkdVGJPz9f0EnfqfMFKpzzrOx
         y05w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=hiEqbsazyTkOukIOYf2ZT60l1HMaVkMF+HYSQf3UXAU=;
        fh=PpnyFDoTVmChldHsMsk798fk7TFBtpFUX2MaVOdnU2w=;
        b=QXxVLEOMu1aC5Fsk8suaOjDufi3v+ujgMYmHWt2C+98ylKwB7K8QxwRVbBQN3k1zws
         gsAQDZffCV2U/QxnYSMHCBgGsMNty681dJJlNeq9Wa7xlvhyTdtSGdTo8eLXsqQzJPca
         bmGBjeQdAlWcoyIY8/tPMFAElpYJbLRvEamsMmZ1E9nBDzYZrZKr9vLGjLZGZGqO93d2
         yDqJWr3dVPJLnl/Y2IR2nnhoupp/7Sjifsf8HB/wZLc6pPBnZj6vp4NxKFwWG9JxJG/p
         kC+7YWM7HOjdsN3Czd1LZPloDU467XKousbvLyMbLc5XgZfnREjl5fIeMOz25dpj4gbV
         w+mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="R9lIY/VV";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792608; x=1763397408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hiEqbsazyTkOukIOYf2ZT60l1HMaVkMF+HYSQf3UXAU=;
        b=B9pXuzWesPxil0zypmp9YnSMpCRuM5IxidfF1Xr+29CkE/PELBnsvvIzXubnrefa5m
         bvO47SmIFt+hHrGBua8gqlgB1/opZUEd2tvi1rR036bH7esTppjIisg54jh7C8KhX0gZ
         o41tScJOjkjKNlMox8KK158ND5QJAtsUxoCPZQkzz9qxuOtbQhGVYWZZNm1g9Zx1X4X+
         b5mC57Klf1z7kNWRAA9d3r60ooAIBFeM4ZZqcTsBwwSO0P48Bh3Go11mPT3vIb2ptU6M
         nUc+9hbcJnzxoPDbB+KS7RlSMV4kPUnaGyCZA1l5Imm5sA0rjNxuX6dke+xi9qcd1fFX
         DTgA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792608; x=1763397408; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=hiEqbsazyTkOukIOYf2ZT60l1HMaVkMF+HYSQf3UXAU=;
        b=Sl1DTirN5A/tf9QhV54+vmPGnNuuKqDGSz9xhL/dR5FZhZBWixQrRFMndv8gSrd6dr
         1Relc3yrmRuHoKfCacrdid+ESohUULcf6QBu12pI6ipeorMTZGVIkMGXIpuo2K3N7qCC
         83XsfYQq0Y03smeGpkRBeoGjyFofdoxef4Yq3F0a8op7u3WejrDEsih1TOF1jZSJAxH9
         TIxsbiLaVTGCKULNFmdg3gZUGIfj/9QN+OMuJEBYA8qR/FcHPde9B7UQo2JSK8QJ7if7
         h1lRhkESaD0fabwGvkjp1jJ5jpu1zMOSOIcBlgO4ZLy+ZR0eF5nc5DrI3knljkiHUxlz
         POPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792608; x=1763397408;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hiEqbsazyTkOukIOYf2ZT60l1HMaVkMF+HYSQf3UXAU=;
        b=aByoljmD2h7Lz9zcQR9B69MATCX+/L/2T6aj0Ap7EQeJ+P9KiIKbXq7tkQSlvsgCvG
         KvK+VEY1NzVLXReT51jaSVlKanEgFbi73eogZlz/ZjPqPZ6rpcA8yIkziQH27u6KyVuF
         u24fUyVP6x6NFxHf28aKzImIgVxFnVF0M57ecLeJHZQWkMr9iW3ZAACEGeEoEUCSIgh6
         8xbmR/TjfJpsAahhgc+R9N3g0hLalLmlHP6FHzu0u+ebxBmDuFUnzRJm1K4MZ2j/8eav
         NqQl7XcJStD42grmCAKL/KkMqnbACP4D7CXbZ/Imny4q0g56Ia6jFGPBrEiFB7AyNqhS
         1geg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKN7TLdxA1LK2n5FrTPbBqG/mArlkc5ApEnTEKzuYOgiV51FAtC+AqCJO/QO1NobbXSdW++A==@lfdr.de
X-Gm-Message-State: AOJu0YwhflNV7fZMnJ/KI0P+44dJwB6/BazJNLZ5pW6t9pQKmTL/SsYR
	UuzE6z8fZPzyuuTZJThD6JUXNYdljDVRVnhkqWBpyfl3gu82SX7Ig9Ve
X-Google-Smtp-Source: AGHT+IHiB/selPfsrV8FGtfk11QBiGFjJAqWBHCqvydqhUwJw3zjJGhfXM+4gW0wpgkTW5y57ycC2Q==
X-Received: by 2002:a05:6214:d8b:b0:86a:7c95:126f with SMTP id 6a1803df08f44-88238613ea8mr129253546d6.27.1762792607393;
        Mon, 10 Nov 2025 08:36:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZSUIb6Ay9yGek4wdoFs7GkRpDKWEQ255tpBfpx0grP0Q=="
Received: by 2002:a05:6214:f64:b0:87f:bff1:289 with SMTP id
 6a1803df08f44-88082ed1021ls28986836d6.2.-pod-prod-06-us; Mon, 10 Nov 2025
 08:36:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWGDI38QebltyIDLqkXmG/vCQE3xS3bokiIXsudklMf0Sh+gAqykERiZETMDLj8EU0hY7fisNm7S2A=@googlegroups.com
X-Received: by 2002:a05:6122:50d:b0:559:7a19:9bd9 with SMTP id 71dfb90a1353d-559b328d263mr2980945e0c.10.1762792606654;
        Mon, 10 Nov 2025 08:36:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792606; cv=none;
        d=google.com; s=arc-20240605;
        b=eJBBQPiCHEWJyOvPVQ9J4YTB6Yi7ShuC5RySvhJvoCsE9AkGrGjtew+3KrJi7cvvTU
         3rIOwd+gZQ0Sq6t+WjYeTc2R5P0OtGADM1I8Nz4FsS9Kppikjj8CXEb6om5YBvGCZbgG
         tmiuriWd+JV1aXNueNv5FbhWygsblqvQtN24JJC4PHzmeWGDwBGqWvBmjti9kCKyC/jf
         Ty5ZL7U7xn67b6JT5qa/GKV+iglw7BDHQVmp9f2JOIXvClYtKd9sr7enHMiDALpoARvV
         8zHSjtfhgKPB6wYxSh6ofZsZSP/vHqN/S4CwIytfFOiJV/b34fd9PSJGwhaRxj1uFEin
         nyiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=kk8QwiK6ueKhbPm+iybiDp/pMjWX1cNh1XEGnvIxiQI=;
        fh=zz0tKFsMqiuh0cGFFOi1/RVfeYmoRiwNEUd3Ank5x+U=;
        b=YRBL4onJ3qWGCryPSW7GwPBOt9iJhonip+5IcOEsC+gT9d565n5KgbqwN7+VEv9jZ+
         jHIzJkIHDmbVf9UYyQHjIUn2huUFk79e+pphakOuobPpmAws7yvKK7L4sf6ABp/NK5fD
         iTETgLRU/xobE2C3y/dLlAJGOgbLWdl0JPSKncTaIQisiazkugKMgagAaynCEwwWyomD
         vlzfx8Opz09GAMAfO+WZ2l0WvEMndvFigY5ZDCsZontqpT+hrUKS6e0D5wk5osbKjSma
         Hi/lRyc0622rrk+apsldyiSc3zRZTe1hi81HsJZBW4AxLSH1OUaVB1al3qUWLcJngRCn
         39lA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="R9lIY/VV";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-559bbf6c4d1si201063e0c.0.2025.11.10.08.36.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:36:46 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-7aace33b75bso3345718b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:36:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXCVfiNHRvpgCQmvQDQp0b6eJ/Mj5eX24bUNgj7H4nOcnDUiO6U02STXGzrGqzbFF9tUYpaojdR8h8=@googlegroups.com
X-Gm-Gg: ASbGncsWL3Q0yebWZZSBPCO6KwyAd32Rk+53UUHg+RgZj6hg2G9EGitCt/ktqVHQFqB
	nn6pq2iIRtbGFnQn4Ap5dIyYBxpsxTyZFoDuYVcP2HNfautrVXnZl8Td3Z9IU01wlRw7J75CfMv
	ryONo2DA+vqgx1inGPlkLLMNN0N7f57mroR2wodp3WmBCAUJJZRX2AmQzG8GwKIaXLznYMRHNoN
	cSKyvcOerxY9fNUQo/VwEG1474fjaXU4S68RdOfqctOpqehvD1vV+eIfAXCesvJBG+MLOjONWdc
	b1kZsVCY4EDNYVi3PFb2rdEU/Psv4fF+Qz7h6yYKWANhiD5P35s09WVwa5k9X4zRx4NdB+OBge9
	cdvDroya2qUyjBolDDLfjHHWcxe5Z4EIuYBHVMtk2WzFnh9WDFSnmAf7Zlr8diVtLqRQJIG8UUu
	m6b8jFK3y8XOM=
X-Received: by 2002:a05:6a20:6a06:b0:334:a901:c052 with SMTP id adf61e73a8af0-3539e635fd9mr11647011637.0.1762792605556;
        Mon, 10 Nov 2025 08:36:45 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-ba902c9d0d4sm12765118a12.36.2025.11.10.08.36.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:36:45 -0800 (PST)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	"Masami Hiramatsu (Google)" <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Alice Ryhl <aliceryhl@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Ard Biesheuvel <ardb@kernel.org>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Ben Segall <bsegall@google.com>,
	Bill Wendling <morbo@google.com>,
	Borislav Petkov <bp@alien8.de>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	David Kaplan <david.kaplan@amd.com>,
	"David S. Miller" <davem@davemloft.net>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ian Rogers <irogers@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	James Clark <james.clark@linaro.org>,
	Jinchao Wang <wangjinchao600@gmail.com>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Juri Lelli <juri.lelli@redhat.com>,
	Justin Stitt <justinstitt@google.com>,
	kasan-dev@googlegroups.com,
	Kees Cook <kees@kernel.org>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	"Liang Kan" <kan.liang@linux.intel.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Mel Gorman <mgorman@suse.de>,
	Michal Hocko <mhocko@suse.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nam Cao <namcao@linutronix.de>,
	Namhyung Kim <namhyung@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Naveen N Rao <naveen@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Rong Xu <xur@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Suren Baghdasaryan <surenb@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	=?UTF-8?q?Thomas=20Wei=C3=9Fschuh?= <thomas.weissschuh@linutronix.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Will Deacon <will@kernel.org>,
	workflows@vger.kernel.org,
	x86@kernel.org
Subject: [PATCH v8 01/27] x86/hw_breakpoint: Unify breakpoint install/uninstall
Date: Tue, 11 Nov 2025 00:35:56 +0800
Message-ID: <20251110163634.3686676-2-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="R9lIY/VV";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

Consolidate breakpoint management to reduce code duplication.
The diffstat was misleading, so the stripped code size is compared instead.
After refactoring, it is reduced from 11976 bytes to 11448 bytes on my
x86_64 system built with clang.

This also makes it easier to introduce arch_reinstall_hw_breakpoint().

In addition, including linux/types.h to fix a missing build dependency.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
Reviewed-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/x86/include/asm/hw_breakpoint.h |   6 ++
 arch/x86/kernel/hw_breakpoint.c      | 141 +++++++++++++++------------
 2 files changed, 84 insertions(+), 63 deletions(-)

diff --git a/arch/x86/include/asm/hw_breakpoint.h b/arch/x86/include/asm/hw_breakpoint.h
index 0bc931cd0698..aa6adac6c3a2 100644
--- a/arch/x86/include/asm/hw_breakpoint.h
+++ b/arch/x86/include/asm/hw_breakpoint.h
@@ -5,6 +5,7 @@
 #include <uapi/asm/hw_breakpoint.h>
 
 #define	__ARCH_HW_BREAKPOINT_H
+#include <linux/types.h>
 
 /*
  * The name should probably be something dealt in
@@ -18,6 +19,11 @@ struct arch_hw_breakpoint {
 	u8		type;
 };
 
+enum bp_slot_action {
+	BP_SLOT_ACTION_INSTALL,
+	BP_SLOT_ACTION_UNINSTALL,
+};
+
 #include <linux/kdebug.h>
 #include <linux/percpu.h>
 #include <linux/list.h>
diff --git a/arch/x86/kernel/hw_breakpoint.c b/arch/x86/kernel/hw_breakpoint.c
index b01644c949b2..3658ace4bd8d 100644
--- a/arch/x86/kernel/hw_breakpoint.c
+++ b/arch/x86/kernel/hw_breakpoint.c
@@ -48,7 +48,6 @@ static DEFINE_PER_CPU(unsigned long, cpu_debugreg[HBP_NUM]);
  */
 static DEFINE_PER_CPU(struct perf_event *, bp_per_reg[HBP_NUM]);
 
-
 static inline unsigned long
 __encode_dr7(int drnum, unsigned int len, unsigned int type)
 {
@@ -85,96 +84,112 @@ int decode_dr7(unsigned long dr7, int bpnum, unsigned *len, unsigned *type)
 }
 
 /*
- * Install a perf counter breakpoint.
- *
- * We seek a free debug address register and use it for this
- * breakpoint. Eventually we enable it in the debug control register.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * We seek a slot and change it or keep it based on the action.
+ * Returns slot number on success, negative error on failure.
+ * Must be called with IRQs disabled.
  */
-int arch_install_hw_breakpoint(struct perf_event *bp)
+static int manage_bp_slot(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long *dr7;
-	int i;
-
-	lockdep_assert_irqs_disabled();
+	struct perf_event *old_bp;
+	struct perf_event *new_bp;
+	int slot;
+
+	switch (action) {
+	case BP_SLOT_ACTION_INSTALL:
+		old_bp = NULL;
+		new_bp = bp;
+		break;
+	case BP_SLOT_ACTION_UNINSTALL:
+		old_bp = bp;
+		new_bp = NULL;
+		break;
+	default:
+		return -EINVAL;
+	}
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
+	for (slot = 0; slot < HBP_NUM; slot++) {
+		struct perf_event **curr = this_cpu_ptr(&bp_per_reg[slot]);
 
-		if (!*slot) {
-			*slot = bp;
-			break;
+		if (*curr == old_bp) {
+			*curr = new_bp;
+			return slot;
 		}
 	}
 
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return -EBUSY;
+	if (old_bp) {
+		WARN_ONCE(1, "Can't find matching breakpoint slot");
+		return -EINVAL;
+	}
+
+	WARN_ONCE(1, "No free breakpoint slots");
+	return -EBUSY;
+}
+
+static void setup_hwbp(struct arch_hw_breakpoint *info, int slot, bool enable)
+{
+	unsigned long dr7;
 
-	set_debugreg(info->address, i);
-	__this_cpu_write(cpu_debugreg[i], info->address);
+	set_debugreg(info->address, slot);
+	__this_cpu_write(cpu_debugreg[slot], info->address);
 
-	dr7 = this_cpu_ptr(&cpu_dr7);
-	*dr7 |= encode_dr7(i, info->len, info->type);
+	dr7 = this_cpu_read(cpu_dr7);
+	if (enable)
+		dr7 |= encode_dr7(slot, info->len, info->type);
+	else
+		dr7 &= ~__encode_dr7(slot, info->len, info->type);
 
 	/*
-	 * Ensure we first write cpu_dr7 before we set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 * Enabling:
+	 *   Ensure we first write cpu_dr7 before we set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
 	 */
+	if (enable)
+		this_cpu_write(cpu_dr7, dr7);
+
 	barrier();
 
-	set_debugreg(*dr7, 7);
+	set_debugreg(dr7, 7);
+
 	if (info->mask)
-		amd_set_dr_addr_mask(info->mask, i);
+		amd_set_dr_addr_mask(enable ? info->mask : 0, slot);
 
-	return 0;
+	/*
+	 * Disabling:
+	 *   Ensure the write to cpu_dr7 is after we've set the DR7 register.
+	 *   This ensures an NMI never see cpu_dr7 0 when DR7 is not.
+	 */
+	if (!enable)
+		this_cpu_write(cpu_dr7, dr7);
 }
 
 /*
- * Uninstall the breakpoint contained in the given counter.
- *
- * First we search the debug address register it uses and then we disable
- * it.
- *
- * Atomic: we hold the counter->ctx->lock and we only handle variables
- * and registers local to this cpu.
+ * find suitable breakpoint slot and set it up based on the action
  */
-void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+static int arch_manage_bp(struct perf_event *bp, enum bp_slot_action action)
 {
-	struct arch_hw_breakpoint *info = counter_arch_bp(bp);
-	unsigned long dr7;
-	int i;
+	struct arch_hw_breakpoint *info;
+	int slot;
 
 	lockdep_assert_irqs_disabled();
 
-	for (i = 0; i < HBP_NUM; i++) {
-		struct perf_event **slot = this_cpu_ptr(&bp_per_reg[i]);
-
-		if (*slot == bp) {
-			*slot = NULL;
-			break;
-		}
-	}
-
-	if (WARN_ONCE(i == HBP_NUM, "Can't find any breakpoint slot"))
-		return;
+	slot = manage_bp_slot(bp, action);
+	if (slot < 0)
+		return slot;
 
-	dr7 = this_cpu_read(cpu_dr7);
-	dr7 &= ~__encode_dr7(i, info->len, info->type);
+	info = counter_arch_bp(bp);
+	setup_hwbp(info, slot, action != BP_SLOT_ACTION_UNINSTALL);
 
-	set_debugreg(dr7, 7);
-	if (info->mask)
-		amd_set_dr_addr_mask(0, i);
+	return 0;
+}
 
-	/*
-	 * Ensure the write to cpu_dr7 is after we've set the DR7 register.
-	 * This ensures an NMI never see cpu_dr7 0 when DR7 is not.
-	 */
-	barrier();
+int arch_install_hw_breakpoint(struct perf_event *bp)
+{
+	return arch_manage_bp(bp, BP_SLOT_ACTION_INSTALL);
+}
 
-	this_cpu_write(cpu_dr7, dr7);
+void arch_uninstall_hw_breakpoint(struct perf_event *bp)
+{
+	arch_manage_bp(bp, BP_SLOT_ACTION_UNINSTALL);
 }
 
 static int arch_bp_generic_len(int x86_len)
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-2-wangjinchao600%40gmail.com.
