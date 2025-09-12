Return-Path: <kasan-dev+bncBD53XBUFWQDBB7XDR7DAMGQEGGNBTLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8C1CB548DF
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 12:12:16 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4b5e178be7esf50879381cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 03:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757671935; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cf3HwpXU2JNMgDny/fgCUisv2hWUkqSrdNfx+pRy9AN6Rf9QJ+LuKx1Kux5NxLOE5A
         TwKsjZTEhUxUeL0L6F5JNhbc+7hukDXHwvFcO315FAXJ+EgowyNcR6hHdfxkh2eNymSZ
         BxjtNx1UbOzp7IsxOxnjs5D0pTRi/292pY9Abx5RS+5s7ktVRQuqspyESQNqW/0Aeu0W
         aITd1GJ6ZLq/T7kt70vo5VJt5WL88qInnJ4NuZaOC2XnwPJVCHFAk1e+vsn696g6l1Cl
         B1EFiRrfT7GGLT4bzALTQgYDPOc1kdrKLg4+T/a63ZxHDv/9Pe6+HrZOAzbEcRHAiJMk
         EMzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cAgoIxpRp7XESXkOQND+fDvkxbvk8L1LGGvKkteA5sU=;
        fh=GbEG1piGg4YqGq0GPQ3aCA61nsbbvwYsKjX2jBliyvk=;
        b=YuM72r408NBE6hBRmdlKhBDjsddxk0/LyfGVeY2j3TVH+yKWwUT6KS9IMakhmfGF59
         BWhk4pviTew65K9TdQ8giLHxsWDaPy+zaiewnICyqJin42UNC6S5QUB2otqkkgwNiukB
         ZlLMRGn9vhxtQbA8UplC8UIFr+Vy7NTbBCk8KzmRJKllxXP2XkA6ZYsYTCyUyUipZmzx
         PxMndPGtaedf/xg+wCy8F59/H9TYA2GoarVrp1bNCDtdoyRhK+QPUrW7RETrTZ7vaVp5
         Ibl6uataj9cj8dKRGRzqVyJOZ3TZVxXXTg7Gu1KUA2R8iOCLcrbH3VPRCyHm55V4pKBy
         3jYA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YXfErmpC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757671935; x=1758276735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cAgoIxpRp7XESXkOQND+fDvkxbvk8L1LGGvKkteA5sU=;
        b=OWQqyMrvllHffsnh8K+LNM+QsAIzKkv23nl7NJzvldxY7hTlA59wvdNOI+if45e96a
         vrQGRWLvgNFfGw/w+HwK3fa1A2uVqeKKe7iGuPEcL1onEXYEjcuo+2R2xxqTt9TYbpwQ
         Bn64NOe5WWTpXsec/lUhaAz5dAe1QKdrOhilK06d4zdQHtcBPVLuoynrydpCLVRe/sz/
         +qkvrFKaXUX38YEYortYSnIniGysP3QmlI2B6e+2EW0SbX6OGVN4IUkFQo8Y1aQUcabD
         iDgA//uWK1aCHYO1eKm/dIs5s+ndzWZ4iuSvxzenA1WYQ3yMCewAqggHYiHKxNO/7wCE
         V4Iw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757671935; x=1758276735; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cAgoIxpRp7XESXkOQND+fDvkxbvk8L1LGGvKkteA5sU=;
        b=JQMRLaji6ekz+Ltfkycf+WJH0cdw5nYfc7oABOdH5x4/5a9KSl9ry36qlFfzyiNyIq
         7VV3wcmeQdWx7o7aq8P9g+W3aEISUUUb4PYFDsiogde8tzKnM739M6ipE544BarQ8Vip
         xcEZnb4po4xHXonlQttWHnxAecweNOmNeSKIijw3M4/NHZQP8qoViWqbDIp6LZ8KtPzs
         hfG2wcCREF0iv3brOBjrYXsCuOJokIWDb0I0coz9LFislAVpcoU+StXaNnTEAb4WQ22c
         xbSXESpJHQ7oSAHRc/buZuckAKkv9mWUK7h+QNP8Qu0a94CzYbAs/59vGnAdy/si5BRb
         jCOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757671935; x=1758276735;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cAgoIxpRp7XESXkOQND+fDvkxbvk8L1LGGvKkteA5sU=;
        b=ZlyNDgAGgHXIpnnRp1jzAUvBWakJpz/p8mKKd8bmp3nw1nPiYX6xTBh1bWx+HYE1dP
         S1n1YcFoTvgKEv/HhhuUAVmx5KJGxFgkMZqtF9whPFWbjGJ9QUomeUzc1Ql7YrfnUyML
         3hu0UVCrDrr6I8tGh33EnrNrFyaVAwdtneWr7/5/jBYfljRqtdGfSwHDk4eAEJfP70Kf
         mn50VfF4nJo+GCqMWjvx0AvcRl/hImZjBaYAi8soNeU6yRf8Ntw48PYdtRHxfzAiQv/4
         J8qc5F/TSwNgqAKzDkdq5yJoXrhyHX9x6mHJ5Fi5sqikBg2M2qD4EjIh5wzeSzLAxcNG
         eI7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5uZYAJC7e5NmMWLmby1L/TIWi13QvGRoyv9XJckLiAWEEKDo0Wh7Swr1fJmS7PluLDgN2Kw==@lfdr.de
X-Gm-Message-State: AOJu0YzR8Aoqmib0YglEz1OxPv8aa5cbT15J51WG5XZQFlXNSNj/jfca
	cxa+1MyQfusI4wKEhc8oWekbfb2LETToF9PcplQcQyI2G5wl6DYvraH0
X-Google-Smtp-Source: AGHT+IGN9qdJwx0PDjxTtpa+7thOLnNHBvJC/7INr8lyeE2yx7XnMVoqy9HnG29Rtx4yA4w2Mr2tDw==
X-Received: by 2002:a05:622a:d1:b0:4b4:9169:455e with SMTP id d75a77b69052e-4b77d05e8cbmr30704021cf.34.1757671934777;
        Fri, 12 Sep 2025 03:12:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5cYYdchU4eyF/QYQN8CKXfZJHrDQNIILSPhGzt/Vey3Q==
Received: by 2002:a05:6214:20cf:b0:70d:ac70:48d7 with SMTP id
 6a1803df08f44-762e46c43fels31130266d6.1.-pod-prod-06-us; Fri, 12 Sep 2025
 03:12:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz09av70VPasWTgcAOBOBpH0aNipeyAHzMkIApbXx8ZwqdwDx5pInuF8AhkeJ/L6SOEcQAF3wvE/g=@googlegroups.com
X-Received: by 2002:a05:6214:e4e:b0:71b:912:c2 with SMTP id 6a1803df08f44-767c49ada52mr29106306d6.38.1757671933571;
        Fri, 12 Sep 2025 03:12:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757671933; cv=none;
        d=google.com; s=arc-20240605;
        b=bcKL+jlEBW9nJZ+xIAGl47JySB7UtiZIcrEKeiqkLWKUVxz4wgSFDDBC+NXl1nGDG0
         IuWbSGP25sqzTHhmSmbe5ADnwoQCv8RrACW8jyI2A+Utw5ZJIgh+3ldlGXD7WMjw8b1M
         IHOqp4S4wLNIb3NHNGkkUNKHoM9NzQHjgUL3nA43ptbx1+6P+IWJKEcsEAoJEbbEv3Dn
         qAo2SYe1NsfiGO6G8/OgIYOAh7oBIjXSPwrFA2zHOAo+T9YTskAuIqUyG7XBh0azN2Gw
         +TLhwmoMWBZoHBr/C1M4HlNOfHjtngyuJaRy3p716Hg/B+d9Xzsu8fmbll2L1bzYhYy4
         aS3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MAwazreHf5k9GgDRW54pld4eDw+UAZx9M09yt/sAPVs=;
        fh=3cxPcXQiKyJAljfxqn2uxBMQ3egxPPRBBIQO/MsctrM=;
        b=D5RJ0WEm4j4cG9lUyswKbD97LhZjnMe3zDNsA/XqBsKT3iqu6gx0CmhIOjH3AMvuDa
         vXkiYcwmEpepQ4Q+nns8CZ5jIhc390AYGLzNGvOc3QOMazWQweg6qqGX0h3Q22aDeyfR
         CBrZW6os0n3pmmLrhzZbIUq+J/s/BB/BLACT+ew+sFrCKKkhkjOyMoyH37JELMu+BsJ2
         PNZex9J4NUjTlR9ZCVMVC8Md/h3/bfwSno4Y/4/mvdqu19H+Y0nAs8vy6uoE411wi2bf
         FP2pnLxCHzbDBWqJyRtDT/D1g9aJjRQPFB3chTEtFxvqIxKROeOw5hbqork0TvYI3rAd
         DaZA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YXfErmpC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-763bcfcba45si1614036d6.8.2025.09.12.03.12.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Sep 2025 03:12:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b54acc8c96eso499487a12.0
        for <kasan-dev@googlegroups.com>; Fri, 12 Sep 2025 03:12:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWml233mtcek5j4EClYHNWgC97DYBMDQ0tDXNqB44bvlXm4iAfggu632OT8yJowArldHGzTQpA1vpI=@googlegroups.com
X-Gm-Gg: ASbGnctX7FIpl4jD0eGb0LifO1rYZiSPp7OptQLxL69Eg9Adnj4pF6JN6+2Tr0FsNE6
	CYErdJWMWplwtHqm26mf0a8oGOVoOfhXxjr5Y1QLQ2qjDKIAI5q0j+GNAiQy+KnNUnl+mNfCl8u
	/hLGAXhH0jFmvtrBOhGBhLPoPF/veG/mplRR0wANOzGDmBDbozrpXLVqUShIP+OEYCPjxrL1JLz
	aFB2uLPw75Ud4iZMeK/Xu1oqAFPXr4kUQ4CuItzc/8OL8zHpx2JgamGLqBch1+2u0su9eUldlQf
	5yCCwVvjzxuJSe4KvNLywaflgCcAr2EqL5gSTWHr8hyW6ZbALqXRZ42Kx89ASynLHu0p/Q0i57x
	j77CxWi73QXyGj5TO84TTVdSO93o6tpEmpXPHGnSETMu6Dm9MdA==
X-Received: by 2002:a17:903:41ca:b0:24c:e6a6:9e59 with SMTP id d9443c01a7336-25d245dd6f8mr31272915ad.6.1757671932903;
        Fri, 12 Sep 2025 03:12:12 -0700 (PDT)
Received: from localhost ([185.49.34.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-25e8ed36759sm6102435ad.142.2025.09.12.03.12.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 03:12:12 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Valentin Schneider <vschneid@redhat.com>,
	Arnaldo Carvalho de Melo <acme@kernel.org>,
	Namhyung Kim <namhyung@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Alexander Shishkin <alexander.shishkin@linux.intel.com>,
	Jiri Olsa <jolsa@kernel.org>,
	Ian Rogers <irogers@google.com>,
	Adrian Hunter <adrian.hunter@intel.com>,
	"Liang, Kan" <kan.liang@linux.intel.com>,
	David Hildenbrand <david@redhat.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Suren Baghdasaryan <surenb@google.com>,
	Michal Hocko <mhocko@suse.com>,
	Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Bill Wendling <morbo@google.com>,
	Justin Stitt <justinstitt@google.com>,
	Kees Cook <kees@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Rong Xu <xur@google.com>,
	Naveen N Rao <naveen@kernel.org>,
	David Kaplan <david.kaplan@amd.com>,
	Andrii Nakryiko <andrii@kernel.org>,
	Jinjie Ruan <ruanjinjie@huawei.com>,
	Nam Cao <namcao@linutronix.de>,
	workflows@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	"David S. Miller" <davem@davemloft.net>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	linux-trace-kernel@vger.kernel.org
Cc: Jinchao Wang <wangjinchao600@gmail.com>
Subject: [PATCH v4 03/21] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Fri, 12 Sep 2025 18:11:13 +0800
Message-ID: <20250912101145.465708-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250912101145.465708-1-wangjinchao600@gmail.com>
References: <20250912101145.465708-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YXfErmpC;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

From: "Masami Hiramatsu (Google)" <mhiramat@kernel.org>

Add modify_wide_hw_breakpoint_local() arch-wide interface which allows
hwbp users to update watch address on-line. This is available if the
arch supports CONFIG_HAVE_REINSTALL_HW_BREAKPOINT.
Note that this allows to change the type only for compatible types,
because it does not release and reserve the hwbp slot based on type.
For instance, you can not change HW_BREAKPOINT_W to HW_BREAKPOINT_X.

Signed-off-by: Masami Hiramatsu (Google) <mhiramat@kernel.org>
---
 arch/Kconfig                  | 10 ++++++++++
 arch/x86/Kconfig              |  1 +
 include/linux/hw_breakpoint.h |  6 ++++++
 kernel/events/hw_breakpoint.c | 36 +++++++++++++++++++++++++++++++++++
 4 files changed, 53 insertions(+)

diff --git a/arch/Kconfig b/arch/Kconfig
index d1b4ffd6e085..e4787fc814df 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -418,6 +418,16 @@ config HAVE_MIXED_BREAKPOINTS_REGS
 	  Select this option if your arch implements breakpoints under the
 	  latter fashion.
 
+config HAVE_REINSTALL_HW_BREAKPOINT
+	bool
+	depends on HAVE_HW_BREAKPOINT
+	help
+	  Depending on the arch implementation of hardware breakpoints,
+	  some of them are able to update the breakpoint configuration
+	  without release and reserve the hardware breakpoint register.
+	  What configuration is able to update depends on hardware and
+	  software implementation.
+
 config HAVE_USER_RETURN_NOTIFIER
 	bool
 
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 58d890fe2100..49d4ce2af94c 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -247,6 +247,7 @@ config X86
 	select HAVE_FUNCTION_TRACER
 	select HAVE_GCC_PLUGINS
 	select HAVE_HW_BREAKPOINT
+	select HAVE_REINSTALL_HW_BREAKPOINT
 	select HAVE_IOREMAP_PROT
 	select HAVE_IRQ_EXIT_ON_IRQ_STACK	if X86_64
 	select HAVE_IRQ_TIME_ACCOUNTING
diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
index db199d653dd1..ea373f2587f8 100644
--- a/include/linux/hw_breakpoint.h
+++ b/include/linux/hw_breakpoint.h
@@ -81,6 +81,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context);
 
+extern int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+					   struct perf_event_attr *attr);
+
 extern int register_perf_hw_breakpoint(struct perf_event *bp);
 extern void unregister_hw_breakpoint(struct perf_event *bp);
 extern void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events);
@@ -124,6 +127,9 @@ register_wide_hw_breakpoint(struct perf_event_attr *attr,
 			    perf_overflow_handler_t triggered,
 			    void *context)		{ return NULL; }
 static inline int
+modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				struct perf_event_attr *attr) { return -ENOSYS; }
+static inline int
 register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
 static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
 static inline void
diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 8ec2cb688903..ef9bab968b2c 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,42 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local cpu
+ * @bp: the hwbp perf event for this cpu
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of HWBP, just reuse the current
+ * slot on local CPU. So the users must update the other CPUs by themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the cpu fails to update debug register
+ * for new @attr.
+ */
+#ifdef CONFIG_HAVE_REINSTALL_HW_BREAKPOINT
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	int ret;
+
+	if (find_slot_idx(bp->attr.bp_type) != find_slot_idx(attr->bp_type))
+		return -EINVAL;
+
+	ret = hw_breakpoint_arch_parse(bp, attr, counter_arch_bp(bp));
+	if (ret)
+		return ret;
+
+	return arch_reinstall_hw_breakpoint(bp);
+}
+#else
+int modify_wide_hw_breakpoint_local(struct perf_event *bp,
+				    struct perf_event_attr *attr)
+{
+	return -EOPNOTSUPP;
+}
+#endif
+EXPORT_SYMBOL_GPL(modify_wide_hw_breakpoint_local);
+
 /**
  * hw_breakpoint_is_used - check if breakpoints are currently used
  *
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912101145.465708-4-wangjinchao600%40gmail.com.
