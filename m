Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7HGSXFAMGQEKNZWNSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 15C44CD09A4
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:10 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-5942ee3c805sf1318738e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159229; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hv2HBUy2I/D/ne7C44GpqVrcuc37SGcjPL28p/AQEBqq7l376L6XppQeK00wxdGM6W
         tsPDiKzzris7VOvK39Ks9Eqp8TO4OiAWpfMtdexVSZCWFxYFrLybQmI7IZMPfgEKP7EI
         buNds7gix/3pxuC1yFR4l7/5lLcs1+T//cqM4FDIV0jK2E1ZrOPhxbm3kwrGWgx/Iye/
         LUzGiAON05YI/f0x+/vchtS6onzxan3qh180bFde2fKUfb6LgBtfU3HdxhSuzVx8QB+B
         QsAwF2tV5LJ5tbDB7c4MADKHfe3G7qpa1ztEaL9d8hjLTKijrwlNId2OpuBWSAN7PLSn
         HKqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Ia/44q7vK/3w79L8ZAn5SJ9IjXCPpRZ1ZAhBYMwqxVw=;
        fh=XTZ3782PjiRhWM514EBa4H9WKsDjl+dS4ld5bET/fEw=;
        b=JmQ9N5PKzf04HAJjbDgDNS47VIHCuCm5PA1/gwpjcQtVrDVBLpqHcPqAH+GXY1en2K
         scv7MGsUc2uyqLBYsODYl+itnntK0cM5BtjVRyEAGAUU0qhh1h3yuPuzHKwK9Kx2Is9X
         8LttuDNsAexrkDipyOQGWPG5QOoT9PQIfn1rxz0UM0HmVI/QjVkebhh8zIIji1LCDMXB
         E5fT2MolbOHKpMD62D1X1cqat/PMBP3qul923YupETnJyFh/B8gzbAT38FYgTME1aonD
         ulobW8l967jcVRR7I4cvFLuHlzJThht9b17x8VQWs4z7JQsDVAZJiyBmKhT9QJy64w70
         Oicw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C0FQCKzj;
       spf=pass (google.com: domain of 3exnfaqukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eXNFaQUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159229; x=1766764029; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Ia/44q7vK/3w79L8ZAn5SJ9IjXCPpRZ1ZAhBYMwqxVw=;
        b=xK5vaDuBMTD1alcY6Bo8+hV/Lqo6sJ8Sm1E9NfQVEDATFiHB/gB4+I+S96kgOxU46x
         lfG5ls3RsfdXd2gbQL7Ubg2mXe2W68LjrujgjZ9HLZ+4lVemwCLtRKo77lE9Xx4bAFGT
         ltcuQV7QK5EMje+DernwREtDsflO1ljlup+aIVgFd1CrEFe+FoXKcTXF4BsBm2OFcZZU
         0A5GrML9/VWzaiPZBLo1OmuK2717O/8erJU0A3us+r+AOwKUzt0R+UTYDHq4xvNtMpmI
         yhe5OGRcSTYOKdQByodziqKG3MYR/+a5ggCEfNIM5yEgfq1Hn8a9xMr8b250EG7YXo0f
         yAhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159229; x=1766764029;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ia/44q7vK/3w79L8ZAn5SJ9IjXCPpRZ1ZAhBYMwqxVw=;
        b=jFhTPivV7Xk2j6TgPWMrRG/TxTUuQVCpViAI8ajXGdBu4jGz+SnZSloJB6N353A1j6
         +cfnIFWjw/EESUg10T2mjJiFR5Jd9gVQuNq8BwYi+GygN8Th29xGMhVb1TLOyfkGQ6/u
         i3SorWYue4eaY/ilrf/GDTwEN1Dkix1E1eBAO7Rr6lHAdjMGs6ML+QaJiu+1Ah4aIHbm
         oYWKBGYDBgt4rClAeyH3hdeogA4KPiP+8uHihxTijOmYEVpezqRK4bknKgC/F23B9zj4
         PSJwrGxzNyUoahYRLqMjyLawf6rr/QB9TfwnThKXKRMmq3UqIduTKdBt1D3zqwS5cN2i
         p6mA==
X-Forwarded-Encrypted: i=2; AJvYcCWOM2YzFQLIVOHOjhnD69RL34fkLH0SwopeZMe37NFL0Bp9c9ktiZoJ9xjxynBVlW993MaGow==@lfdr.de
X-Gm-Message-State: AOJu0YxvfFAiFVEHC0m+9El5SwWNjK+nZ/A21cJGay5penvO+CkCucru
	gk0JZ3We5932svtPBuC+TJ34HtQNWU6CIUSCnRHG14ad1LjzFXKqLZy0
X-Google-Smtp-Source: AGHT+IEU7vj4zO/4Z59pVvDmXElngwKJ0mM6W60yrX8YSi3uD9SFbv1ea7BSLq7arbUzUGn1GTa2Uw==
X-Received: by 2002:a05:6512:e88:b0:598:fb09:5360 with SMTP id 2adb3069b0e04-59a17df5ec2mr1089783e87.53.1766159229189;
        Fri, 19 Dec 2025 07:47:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYDU/BFXL7BlWszxJT84ZWClyWnC2APF602B2B8A0d4nw=="
Received: by 2002:a05:6512:131a:b0:597:d6d8:7e76 with SMTP id
 2adb3069b0e04-598fa385bfcls2569008e87.0.-pod-prod-08-eu; Fri, 19 Dec 2025
 07:47:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUS2Nfh8LgNVDfhxLfS7B1l3Jb/qpW77es9yUJyJha6KaQ85hVCSO05oMC1XkuhLTiX7RjIP/DeE8A=@googlegroups.com
X-Received: by 2002:a05:6512:2304:b0:594:cb92:b377 with SMTP id 2adb3069b0e04-59a17dea461mr1343967e87.42.1766159226523;
        Fri, 19 Dec 2025 07:47:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159226; cv=none;
        d=google.com; s=arc-20240605;
        b=lrpxFQqbIp/Spj/Dm+JWenJS3pdlFMAHVLzJW2JXTLlmIGAEHQDxTKTeKGTYI63FUq
         HkHFj/lJ2YO4CsSSnyUFuHlIhWAqSWpGpQpclSbb8qXC2aLNk2iwwhPdLKH7BDOfoxmy
         tjXUm/YgeEREZ3C5/jT0wdM0L0v+bYNdyVIXy610x3H1/Ko7odwavj4fqoR9HPAP08lc
         Oof6G5b59WMXfBk0kCxvSE4IVr6iyaANWMvU7RYQH6YBb6+stM/nt3yYhzBNpBFHPfPD
         dvMwaCMm7qOX09SrywftlAHV0R+Ghm6OfUKqASbWwZImAFcvYEgkWWy0tF4JYwDbZM1A
         7zfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nTy18ZdTqK3/SC0lGMdEXuAKkcRsuvgQuaMHd3BFX3Q=;
        fh=nE1a6ZSgoiCWFLOt5rcSCLTrjUW76Suol4CAD1R40Q8=;
        b=LjPGhljOHgZB9zq095oooiZVHuQ+pt6HIJ3j8GxA5OR4OFfGQ27DMLkmHXrGmCR+Sd
         8OePEhrVJEcmvhpRSkzfmRZv6WU1+eN959r5Ju0crA8ahSG7dDlQkQL6IDsTQikTk9H/
         z0/c/0aEvUV7e7xJaxXkXeT4elFdOfbGCHKowxRxh/KCT1yoaWZPep3ZdW0cu8a0rg59
         27Wc+LS5bD7fr6dLW3lLE56L5x91iQJH16YAZbBPhvQReWGkd7U3/hkUhewvTzRi/43j
         oxserRwLl9X5pavvWsxA+0OyGJYynjPylZVdUwW72DKxLKKVW7loWGcEhEnpvmxiH0ag
         G6DA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=C0FQCKzj;
       spf=pass (google.com: domain of 3exnfaqukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eXNFaQUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a185d65d5si67105e87.1.2025.12.19.07.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3exnfaqukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-431026b6252so1818696f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUCxfykzBZg4bBPJ5tTAyTzNjhmw4ZjStKFhVtWosJ36uaDXlWnNz9Gv7fU+o5VrN5u6GJjOZ+D6fI=@googlegroups.com
X-Received: from wrbay2.prod.google.com ([2002:a5d:6f02:0:b0:430:f3bf:123f])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2886:b0:42f:dbbc:5103
 with SMTP id ffacd0b85a97d-4324e4fda18mr3897372f8f.35.1766159225487; Fri, 19
 Dec 2025 07:47:05 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:14 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-26-elver@google.com>
Subject: [PATCH v5 25/36] compiler-context-analysis: Introduce header suppressions
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=C0FQCKzj;       spf=pass
 (google.com: domain of 3exnfaqukccyqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3eXNFaQUKCcYqx7q3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

While we can opt in individual subsystems which add the required
annotations, such subsystems inevitably include headers from other
subsystems which may not yet have the right annotations, which then
result in false positive warnings.

Making compatible by adding annotations across all common headers
currently requires an excessive number of __no_context_analysis
annotations, or carefully analyzing non-trivial cases to add the correct
annotations. While this is desirable long-term, providing an incremental
path causes less churn and headaches for maintainers not yet interested
in dealing with such warnings.

Rather than clutter headers unnecessary and mandate all subsystem
maintainers to keep their headers working with context analysis,
suppress all -Wthread-safety warnings in headers. Explicitly opt in
headers with context-enabled primitives.

With this in place, we can start enabling the analysis on more complex
subsystems in subsequent changes.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
---
 scripts/Makefile.context-analysis        |  4 +++
 scripts/context-analysis-suppression.txt | 32 ++++++++++++++++++++++++
 2 files changed, 36 insertions(+)
 create mode 100644 scripts/context-analysis-suppression.txt

diff --git a/scripts/Makefile.context-analysis b/scripts/Makefile.context-analysis
index 70549f7fae1a..cd3bb49d3f09 100644
--- a/scripts/Makefile.context-analysis
+++ b/scripts/Makefile.context-analysis
@@ -4,4 +4,8 @@ context-analysis-cflags := -DWARN_CONTEXT_ANALYSIS		\
 	-fexperimental-late-parse-attributes -Wthread-safety	\
 	-Wthread-safety-pointer -Wthread-safety-beta
 
+ifndef CONFIG_WARN_CONTEXT_ANALYSIS_ALL
+context-analysis-cflags += --warning-suppression-mappings=$(srctree)/scripts/context-analysis-suppression.txt
+endif
+
 export CFLAGS_CONTEXT_ANALYSIS := $(context-analysis-cflags)
diff --git a/scripts/context-analysis-suppression.txt b/scripts/context-analysis-suppression.txt
new file mode 100644
index 000000000000..df25c3d07a5b
--- /dev/null
+++ b/scripts/context-analysis-suppression.txt
@@ -0,0 +1,32 @@
+# SPDX-License-Identifier: GPL-2.0
+#
+# The suppressions file should only match common paths such as header files.
+# For individual subsytems use Makefile directive CONTEXT_ANALYSIS := [yn].
+#
+# The suppressions are ignored when CONFIG_WARN_CONTEXT_ANALYSIS_ALL is
+# selected.
+
+[thread-safety]
+src:*arch/*/include/*
+src:*include/acpi/*
+src:*include/asm-generic/*
+src:*include/linux/*
+src:*include/net/*
+
+# Opt-in headers:
+src:*include/linux/bit_spinlock.h=emit
+src:*include/linux/cleanup.h=emit
+src:*include/linux/kref.h=emit
+src:*include/linux/list*.h=emit
+src:*include/linux/local_lock*.h=emit
+src:*include/linux/lockdep.h=emit
+src:*include/linux/mutex*.h=emit
+src:*include/linux/rcupdate.h=emit
+src:*include/linux/refcount.h=emit
+src:*include/linux/rhashtable.h=emit
+src:*include/linux/rwlock*.h=emit
+src:*include/linux/rwsem.h=emit
+src:*include/linux/seqlock*.h=emit
+src:*include/linux/spinlock*.h=emit
+src:*include/linux/srcu*.h=emit
+src:*include/linux/ww_mutex.h=emit
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-26-elver%40google.com.
