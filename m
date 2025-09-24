Return-Path: <kasan-dev+bncBD53XBUFWQDBBUVWZ7DAMGQEJEYFMJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id C245DB99A82
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:51:48 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-846f089463esf808014885a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:51:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714707; cv=pass;
        d=google.com; s=arc-20240605;
        b=bFIEOzLDj0gWGyAMKqV6cUn+InPyGH5jt1o9XxIjapS6kAIR5FTSMWEL6rtWOnseX4
         uSdc+uobUeWC3J+zxaQkQ5Ha075SDaB5BDolRXq2HSveXu1Idm3WZeo1LDBZKf3Q8JgI
         VOUgSSFPl/frDDscN06wkiaaVHB1tLtXncV12cNTGP04XqHbdI+ERkX0bLYdTIDUL7hv
         rWO8r9Cd14sA7QCxMdDPNlKbL5k+ItfRYyh9yoId7RBoeehZULK6ns8uILZo1nwvppQ0
         yeomxHoQprQUILWtrOwCrPmfVBj3/plimJRugnbeGawJLXnHIaLrj+aNdVcPVUNVw3+1
         /XPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=5n4eOqbFsWgML8COycZVj+FNGM18DagmpI9PSC+OJkc=;
        fh=WXj1G3V4pKl3wva58LkjcqRtwFgji1PCPXNYHQA222w=;
        b=f2azfjVse6RdANwlvzRyT7N9/gmbBO0ge2BG50AtDGOdGWm7BFcRbO2ynGZVeQFXO2
         SO6XzUrkoKBA33V6YSq+Kp8POb4Gww0p4cd7dmxw6+wXoLHpHIJW2ND9PN5VQF4Eu77L
         ZKB+grb7LxYfMZzOe8zmbiArs2kF5u3yOeQbdm76z9+hD89wj3g/lakbyIrZqg7+gSuR
         aik0BxgH63JxX1gLFciXSK2bBBmd6H2MNIy25IuJxJGse9bQ9ws6cveBT+QzikzsJxYY
         S+Te2AOo5iYRB/oguz7viEJHp0ifcBD6+fVNPTnvrqyxWA0D602p73lEmPycBUo7YNRP
         gzmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="N/FqpiG/";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714707; x=1759319507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=5n4eOqbFsWgML8COycZVj+FNGM18DagmpI9PSC+OJkc=;
        b=lbj7AAC1e/X6V1BhivSbOe/+aHq5dIoPhYLMeXzvrPxOFNGzI/n44eVxbuNqdopY8N
         VY9GCNqhuBuKyaKGQ1JwHecyc4dvXBrlK2bS/+Adz7vBl4s7F0p8Md310ILQ5tVo4IXv
         yqD+Jc+4ySFlTEbVDfJSMW5zjPfh6aiOqhdI5x4zWDKW4dUVzbWoG8XkHrwiEy6zHht0
         4vpyJJtay1u3HyMpNBtX8HA4Iig/gENDhlBW37Z+XpqMSi9VcGSVaCasR0tN8FtCzwQv
         IqLw+YcZzgC1ZEGoF9zXzguocHgmi2zpA98UmJzS4LdoMJOmNv8FkipVO8lUSnzKNyqC
         Rgqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714707; x=1759319507; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=5n4eOqbFsWgML8COycZVj+FNGM18DagmpI9PSC+OJkc=;
        b=aKSym0TFOAikoZ/6QmKEWnI2sk6ZTaH+/4sU7V1B2vBnf5dJDor80MKJHoOw9BEnKs
         5iQ5nwB5UdqUUo2HtNslOhw9MSBf0qsEuiK+7CDUrM+vTtqDUXx/VF8KmOYuTvk7I0zZ
         OvcosLOjHw0sB9LbmRRDBQX6SKz7EEgildfa8MU2A6Vs+fBPLE4l1D8LkOFZ2Z1UWprg
         8OiuKZAtfQXjzOGRz/Oz4lYZCSHEbG2jRyzgFnDRW/SStQQsbr6NSnmK5t86q3/4fx6G
         pUYDPg8G4OLwUkqI7wu6uDfMl+9k94taVfpv9/pTh+VhDpQwKcU1+XDRnrsXB2LqRO2F
         LU7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714707; x=1759319507;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5n4eOqbFsWgML8COycZVj+FNGM18DagmpI9PSC+OJkc=;
        b=sa4wdmziR0XzqCoHOplhUM+1xkJ5WQeuT5uunFHiBFMCnMq7p8CyyCk7EOnOzQP2J+
         8oSVlNg7l1ZVMpLEjSeIM7PMP0vfDSRtwGJUPdR3zyJ2AE0r6R33Hkmt/QVNJe0TCw53
         FVVKIQame56xs+kx1mbbznLZztfPbVa+NSLiJgrrH9UOLcOw8oAK3XksaGFXHw/sFvns
         HSEVGln3NVXk2E+jaWQBH+2dHCcDe2VaEk3WNLKNxFVGU+Q3RHtuRS6YLnXzcdU3Qicm
         CjDsz94Qk+gq/rxJeerqnCSPWyeGXR9vMxT2FpPiTY3rY35vaauzw/OlOZRMRUFiGjsE
         jwmA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCULTwTCTiy+FuvH+Ycipa1GKoZB0wf5nOrZLVy/Q5KF5ZWxZ+33KUKDM+RK0ISCbUjkdu/5mw==@lfdr.de
X-Gm-Message-State: AOJu0YxXRd4qwcjtL/ae7cbXYcotCWlZYqT/2IWGBJuzoo7lHNEnc6y5
	g23znPjzbT/lTWlzKvR1yjcmBeKYW7WEpIyJFgpFkkKvf301nWDBiX3I
X-Google-Smtp-Source: AGHT+IHR8urVrR2MDdu+9Ks+YGAAdKnFxrTzRWpMvHhvmasSZgFjjQVIewWgdLW5woYU65rKuvIWBA==
X-Received: by 2002:a05:620a:6605:b0:855:cfe0:b6eb with SMTP id af79cd13be357-855cfe0d2acmr387019985a.75.1758714707160;
        Wed, 24 Sep 2025 04:51:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6ICNHXXABkh/sFXuGoWiuuwQsLgsTmCA6PMUwNiEMsLA==
Received: by 2002:a05:622a:4b0b:b0:4d6:c3a2:e1c6 with SMTP id
 d75a77b69052e-4d6c3a2e875ls19568071cf.2.-pod-prod-02-us; Wed, 24 Sep 2025
 04:51:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2tNfHRrjdZVtbLx/g+aMZyIzxCoIKv5fPcam3qjffoo5SFg7nHBPqQOGbdxPpF9nYsZXRDh0j3fk=@googlegroups.com
X-Received: by 2002:a05:620a:29d0:b0:829:2d2e:4558 with SMTP id af79cd13be357-8516d7230e1mr724772185a.11.1758714706287;
        Wed, 24 Sep 2025 04:51:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714706; cv=none;
        d=google.com; s=arc-20240605;
        b=FQwo1DunxI3tOxQqW3K/h2iU6i5k5fOB2MDhnhMbQAJIdb3naNJC0o8/gKGkwQ0euK
         XmyPyZT+ASskT9J7+UVuNie1Lseo8ig8qHqzdGA4dilDOjVnoAo8BPlq/0//BAUMzNb/
         GMbNQDQGwJDx1TeEzvYFZdZ7he9alMnubFN6jYzKTyb5zLyJzVkbZ2wwTscn2J8dG95J
         ybBd5GrJ/FKo5qzqzSi3uW++bE7UMTTf5380JtqUHujfeOQO35meNTm9ftL5JojES2cE
         d/YelNqZxzl7kq56rEKfZrZL3GzPRZnCjPSg520ljqQH7GzmWmgsGUuYNHFal5/MxcBW
         lOvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=l9dguoBkY6LX1N0DOj75LxFoPgkZue82QF3pLTyVov0=;
        fh=JG/giwj1gHH+eOMgbQBKDqZn+bAEo1wKfsWouJdsI2s=;
        b=jX8b+Ua7FXYVoVlE8GaThnDKtlLyGP41wGp1mdR+I2vb6FupwDiURAeqjmy6mmVI7m
         JhzzMvpVTl8Fz4YZvlqAXeeMIpL+0E+neyaTvyrFBNLuRD/kzRDzed6nU5YdiQk6ujYM
         i6+5le5xBJW2yV0N4XPQwZIvpe2zAthuFaAVRpwsCYFh41F9FEsD6Uq9IjAqOoMmssDT
         i1j4q1djyscJ1HQ9HfLrNfKv62WH7TLSYDUAVWZKkxeZwbxJx/T5kzYd095IyXK6XpA3
         y7/TKK5YQMgGc2PJ/jUAIaKC59Xah/gyUqwnVcu01S+49/7p9U4x4Rg53CzKRaN/Sj3U
         cfhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="N/FqpiG/";
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4bda02b2f2asi2364721cf.2.2025.09.24.04.51.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:51:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id d2e1a72fcca58-77f41086c11so2863656b3a.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:51:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5BEnHm+dJ7CxtnMu1TUM6XGiQUYtqT4zTICMTMuVy3IP8/RtktVatqOo/JMYImqfSpkQ9FThCrVY=@googlegroups.com
X-Gm-Gg: ASbGncuPRKxAM68IEZu/eX4EFfMNnJ/l5CFeSjNJOp+Sr2O+44Z7wB9bh5dEGD/uHSc
	+gI6kpKv/xZsZuV7MsygZw3MxDcttMMf0Wx2Ccc3vwIvgc3IU4WCeIWBwd5GgS+0VEpkbVJ834G
	nev5VdrsBRk6ckA32zIXUNlfs5mdEUpK88mzA/iMYrcKyVqBC0VTQekc6SFrxOXjZrUIs1lfNPk
	wVYJCqVTR0eTJEgpTk6wbEo2p0rWu1hetz/K+W3mW1Kkf/uJ1m3Fedcocaqy8IFhtRqNqrXglXr
	adOyU0tmIs1BpXDvm8KQBiaW6rvtHIrBKyMgjROR1swGfKb/b7ir7eReK+yUegkmvPwqmQWvcV+
	MHLKGWv/RjD+vrbODkiIpeMaw8w==
X-Received: by 2002:a05:6a00:228b:b0:77f:50df:df31 with SMTP id d2e1a72fcca58-77f53b0ed0cmr6348588b3a.20.1758714705264;
        Wed, 24 Sep 2025 04:51:45 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-77cfc2490dcsm18664494b3a.36.2025.09.24.04.51.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:51:44 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
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
Subject: [PATCH v5 03/23] HWBP: Add modify_wide_hw_breakpoint_local() API
Date: Wed, 24 Sep 2025 19:50:46 +0800
Message-ID: <20250924115124.194940-4-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="N/FqpiG/";       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 kernel/events/hw_breakpoint.c | 37 +++++++++++++++++++++++++++++++++++
 4 files changed, 54 insertions(+)

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
index 52c8910ba2ef..4ea313ef3e82 100644
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
index 8ec2cb688903..5ee1522a99c9 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -887,6 +887,43 @@ void unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)
 }
 EXPORT_SYMBOL_GPL(unregister_wide_hw_breakpoint);
 
+/**
+ * modify_wide_hw_breakpoint_local - update breakpoint config for local CPU
+ * @bp: the hwbp perf event for this CPU
+ * @attr: the new attribute for @bp
+ *
+ * This does not release and reserve the slot of a HWBP; it just reuses the
+ * current slot on local CPU. So the users must update the other CPUs by
+ * themselves.
+ * Also, since this does not release/reserve the slot, this can not change the
+ * type to incompatible type of the HWBP.
+ * Return err if attr is invalid or the CPU fails to update debug register
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-4-wangjinchao600%40gmail.com.
