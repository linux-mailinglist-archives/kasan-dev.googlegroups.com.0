Return-Path: <kasan-dev+bncBD53XBUFWQDBB6FWZ7DAMGQESN3ATYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id A0F50B99AAF
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:25 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-738a1926b60sf70802247b3.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714744; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nb8GX3mvqm+snACwYPeorpP5MSs77pkt/y3W6gQyzQ5LWYb7vO1Hh0mcR8OeziDN7q
         pvJDlMrPBp0SziyStFd7KAi7PC9qJsU2iF+tR1Azh81v/HxZmCg8wH/b9clpPM4Z+tgL
         UBKJFU6TnI1jSWurt0rRAuGQVPUZ3OpKiBle385j/WzUK+KDaILkM8iGqo0GjPIOtyuZ
         aY4OkcL9Br1tM3uRv6t2/LxCIhYYi70uA9Ru7uyC1xmKE0r9RynF8l1V3IF//GnPBwsl
         ulfl7G7y12Sit/vACDMppvkXiPOAq/fxgBiuDgzTiwav+m6VojrmXneKPvyK1TFXLlWJ
         A3mw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=hn863aQD0Rg32bRX6PTSLhtOX9h+DTgiebuYOE3lT+A=;
        fh=iEnF4vAu0VzxG4343OJfEk8cwdlKJwaI+aUYyzIv1XE=;
        b=R9lA5gMG3KSiwUQreqODfH82KwSqTKSdDSu4Mi3q4M1oKQWUcnAGuR7ZGUIJr3MNwK
         cZxRU7FNesbw7kcYUibbL/ZIbYie2qrlHgV8Di0YgMI32IQ2fAeXCuj2PZH6aN3Ni4pi
         cX0zYA1RzYZjJM77vpV96Lt7EJ4CLHkLQqQk45g69CgA3+Tzi41UOyJQ4W8V3rIfg57K
         I+gvomAt2lcW/yPPLqWHBW9DPtaIqJLwSRnKmYRDM1QjB5qTwm3kQs5W3+7Xxv/7oUYU
         KZ703Dqj1xsUaebmb2M7W0K2QOeD4MvGCWynd5t/pyLabsYvsMdsHXraXAcMDBzrr+Xh
         jKwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fYK4zhP0;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714744; x=1759319544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hn863aQD0Rg32bRX6PTSLhtOX9h+DTgiebuYOE3lT+A=;
        b=wVxviGAe4guYGcCcXVCNLoPqI4eTWUrosMBMOsRA/r4FIF7seaVJe60yPQ7QlMR/YW
         buxQl00DHpdoPG0KIX4EGe+MNiJ9DPwkdUTeAojstwrmlCRutjPVgXyjWlM3GCDLTuob
         s8C+8Y1p0y2r9by++mx1tJ6rgndh30pHR+EvKVeD+kHmItqUpN9ZqIHDULWPxzKPhzfx
         mmt0Xq7RMKqksBht3GK4sIE9jjo+5d4dSUAopXZzlr6B0irSX40AI0AR0L/1hWRDQfDx
         8rkAec3/4lHh0mOyghJLu+hXRM+wlxCFgS5WwYpc6KVJDR1ZjXoXnsNJhAqR6yBvaINj
         sNqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714744; x=1759319544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=hn863aQD0Rg32bRX6PTSLhtOX9h+DTgiebuYOE3lT+A=;
        b=bBF8gYG+9EOI0KLLGfKWsSbhjAQQTs0in1u7FUoRCQRzVzKVGU/zBet4r15lu6dklh
         Vns4Kcpag5un7TkS5oftj1Hsq7nXqYlR+Vbrzz8i3F93NO+AbTbUBNx1wpzOYqJv2xfK
         lWCaTik8DASPxD6hoIsJTYBFiHSTuZ/rUM8R0HjWXLaPC8vM9364S3XTRIG+fahbToCD
         BXVVjnkRy/zm2ffdeA5W5dQzTLt1HMkaVPspoE77RJszdVZfKk1BFdUFoD2rNlkf6YJp
         SYZD9VcGS0Ufkrw5OSyFs4hAtLDfq8jV0bVJtCcTaqs20U9HUMaDBUg0nEbqLRJa+Jor
         oFLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714744; x=1759319544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hn863aQD0Rg32bRX6PTSLhtOX9h+DTgiebuYOE3lT+A=;
        b=C10pqucWyVML0eMXstExJbIJvrXA/6SEMT+XFmBfTiiFlsbMvQSLj0p7DkTUUT7uID
         xdEM95ztee5WDEfiXMU0m65Y7dHxCdlssQyICaxLIsc8A73oCxI+l4Fm1uRX5ekSuXiU
         Ui1KD/PBT6XohWN8HxKAaoLdde1+DIGRe/AyEIfns2DEkvBNWob/MDXxw6z2LVcmztse
         xiz++NTq9SUqCNnsFZDYIoTSehNOwZ9bsROZGfg6ZxKmiHpTxUyTc3CqnDcpfIFF3CvP
         BAUMfkK6JVZuM1ht90HNnbj0wHCOaw+c76WiET5rJ4t4Nm98YwXJqzbigYsIiUMas/N1
         ghTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuFtdEUaiqejlvoijD/2BuqMKz+IfJBVtPMozOPzncADcMTu+H/4zlSNuqaCagKEsrwAWxVg==@lfdr.de
X-Gm-Message-State: AOJu0YyqdY3ItHS5QAC5ry5HOE6+9zsT7JNH4/3Ul+QZG/3p7WENm7ok
	gh4QHWJVBeaCDJYPlYHrRx3cKGwS3c/aaTCvwsUjRqd5qRYnRl1Rovqb
X-Google-Smtp-Source: AGHT+IGBwfncpsv/Ig4bZfUf37TgWa2t4RceSI+VtNOeZnwY5tipdM1uTzgx+z4ighJ68I+57/ARpg==
X-Received: by 2002:a05:690c:3703:b0:739:ca5d:d97c with SMTP id 00721157ae682-75894870285mr45947237b3.15.1758714744332;
        Wed, 24 Sep 2025 04:52:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4Kp1e1HTEIs64jUJ+TzTJ+yfeIA8D3h0SWjk/54SlcaA==
Received: by 2002:a53:d017:0:b0:61e:b065:c897 with SMTP id 956f58d0204a3-6354ac25389ls2195323d50.2.-pod-prod-06-us;
 Wed, 24 Sep 2025 04:52:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPJ8bhBLzmMKIH6Cjv7HhzDxQKamLm6oqXEXxeOotnfpLjCBnPZ/bT4zOTnxYk+M838JCfTTOLK2Q=@googlegroups.com
X-Received: by 2002:a05:690c:6802:b0:731:76db:a5e0 with SMTP id 00721157ae682-758a24620abmr50010827b3.25.1758714743504;
        Wed, 24 Sep 2025 04:52:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714743; cv=none;
        d=google.com; s=arc-20240605;
        b=bR7LcJhrKFY8uRw/icaDYUWwq15Lc38olV4KvasYaHlAqPibZf4KT/1VHcKtkuU5EK
         0UGcWNT2pogoSAikeRM5mIBuK7qUU6yH0f5GD15qFjdgK898TTLEZ8CG7Pr/gEdT/Go9
         /+N1ZRbArz2ETF81TCg6+hz30/dPhJNkVQ1gzAAkKwaIVNzjwm/TfNueVhaoZCKJq78I
         00gdwMm4aqkgm2Nx1Gqcelq6VfEr3R0qJp9nXDLM4j4Kb/5Rgd8wpc3eUkZRtefFNZu/
         /tnjs+C3vwpAPF3WnggdHoIPKBQoAV90BzUjEbRyzjMHQA+Gis9iP530vMPkK59NAep8
         UOfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sX4DcHmKN6k6jLli4BcDyPNAsEAGb3ORwL+dRbW7euA=;
        fh=PkYZ8muQXrRYqUpUzJg44whOWyxpSBHlocGToLvGGE8=;
        b=QI2ors0zdH6UX0VSiIA3Pi3OqgrfNILqJSbp43kWdS9uP3a/JF/xrPZW00fCSM6w7W
         +jfsWSE8qt3ndZ3aS3Cwj9SUpwOIk95JGMklKajDDG9U9XbknaxcVjUpBt/uULvRrQim
         3V71Pxy5MBinVR+m3L0YvknLzq2rUtJUqqvHi5xvr1x8zwrXPI4qzm6apCNeWROzShkX
         q7KRLOxlEgxnRovBtkY8ajegunPzeUe/tqH30JD/wqi1puBk82+TnZDrX1rD28aMgj9i
         nVtq0pQddFmMwljySauukxHD94E67Sm6q96/3wifx43hbvu33l026+UB5ZKZkBo3Hi0s
         fllg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=fYK4zhP0;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-635380b3cf5si147055d50.1.2025.09.24.04.52.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-77f3580ab80so3800364b3a.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:23 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUPXCQQhzOBfALodow7wx7/4P6GbBveSS645KrLHIDPGMATSO3hn59Jc4DSHpPYgtKarL3iEDxZ85U=@googlegroups.com
X-Gm-Gg: ASbGncvxVgfZ4jyEcvE+1TEx0PU3ehqyja8kCx67WtT6baaWBeAvANpKooFtj0EYX+i
	82Sh2QijHy76QAUTLf+u3HaUDcr9mJUqQjJX0fmZLkqjW47DDPWcvBVkrXjs3A0zT+40tkfzsQ5
	uYdc/yZdnDlduJ+6xQQaEham0FxDZxTKSP0IUkJKS0cgR6kJUREKMC+mU4N43/4CS4GkrRRrhA4
	sWd4tQCAg1vKOQJ73FgK0QgKfBP3Y/C0c/ODY228QtRFM9jJTSlHaIHRDij/67ErXeMVlM0UloR
	Quc+bar5f18g/wGZgqP4n+n/C1qLmnZbrZ8aq0DzdRBc9p+EiG86PdT5P7xG8E9sHZXLhtsooJY
	qULp2Fuxm7jOn2eXd2kAvYwjl6g==
X-Received: by 2002:a05:6a20:e292:b0:247:65a0:822 with SMTP id adf61e73a8af0-2cff1c61c0amr8760157637.40.1758714742579;
        Wed, 24 Sep 2025 04:52:22 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b551518480asm14947563a12.28.2025.09.24.04.52.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:21 -0700 (PDT)
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
Subject: [PATCH v5 13/23] mm/ksw: add per-task ctx tracking
Date: Wed, 24 Sep 2025 19:50:56 +0800
Message-ID: <20250924115124.194940-14-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=fYK4zhP0;       spf=pass
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

Each task tracks its depth, stack pointer, and generation. A watchpoint is
enabled only when the configured depth is reached, and disabled on function
exit.

The context is reset when probes are disabled, generation changes, or exit
depth becomes inconsistent.

Duplicate arming on the same frame is skipped.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 mm/kstackwatch/stack.c | 67 ++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 67 insertions(+)

diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index 9f59f41d954c..e596ef97222d 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -12,6 +12,53 @@
 static struct kprobe entry_probe;
 static struct fprobe exit_probe;
 
+static bool probe_enable;
+static u16 probe_generation;
+
+static void ksw_reset_ctx(void)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+
+	if (ctx->wp)
+		ksw_watch_off(ctx->wp);
+
+	ctx->wp = NULL;
+	ctx->sp = 0;
+	ctx->depth = 0;
+	ctx->generation = READ_ONCE(probe_generation);
+}
+
+static bool ksw_stack_check_ctx(bool entry)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+	u16 cur_enable = READ_ONCE(probe_enable);
+	u16 cur_generation = READ_ONCE(probe_generation);
+	u16 cur_depth, target_depth = ksw_get_config()->depth;
+
+	if (!cur_enable) {
+		ksw_reset_ctx();
+		return false;
+	}
+
+	if (ctx->generation != cur_generation)
+		ksw_reset_ctx();
+
+	if (!entry && !ctx->depth) {
+		ksw_reset_ctx();
+		return false;
+	}
+
+	if (entry)
+		cur_depth = ctx->depth++;
+	else
+		cur_depth = --ctx->depth;
+
+	if (cur_depth == target_depth)
+		return true;
+	else
+		return false;
+}
+
 static int ksw_stack_prepare_watch(struct pt_regs *regs,
 				   const struct ksw_config *config,
 				   ulong *watch_addr, u16 *watch_len)
@@ -26,10 +73,22 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 				    unsigned long flags)
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
+	ulong stack_pointer;
 	ulong watch_addr;
 	u16 watch_len;
 	int ret;
 
+	stack_pointer = kernel_stack_pointer(regs);
+
+	/*
+	 * triggered more than once, may be in a loop
+	 */
+	if (ctx->wp && ctx->sp == stack_pointer)
+		return;
+
+	if (!ksw_stack_check_ctx(true))
+		return;
+
 	ret = ksw_watch_get(&ctx->wp);
 	if (ret)
 		return;
@@ -50,6 +109,7 @@ static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
 		return;
 	}
 
+	ctx->sp = stack_pointer;
 }
 
 static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
@@ -58,6 +118,8 @@ static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
 {
 	struct ksw_ctx *ctx = &current->ksw_ctx;
 
+	if (!ksw_stack_check_ctx(false))
+		return;
 
 	if (ctx->wp) {
 		ksw_watch_off(ctx->wp);
@@ -92,11 +154,16 @@ int ksw_stack_init(void)
 		return ret;
 	}
 
+	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
+	WRITE_ONCE(probe_enable, true);
+
 	return 0;
 }
 
 void ksw_stack_exit(void)
 {
+	WRITE_ONCE(probe_enable, false);
+	WRITE_ONCE(probe_generation, READ_ONCE(probe_generation) + 1);
 	unregister_fprobe(&exit_probe);
 	unregister_kprobe(&entry_probe);
 }
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-14-wangjinchao600%40gmail.com.
