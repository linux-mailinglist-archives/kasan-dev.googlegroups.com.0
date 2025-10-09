Return-Path: <kasan-dev+bncBD53XBUFWQDBBOFKT3DQMGQEYSR4SWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3358FBC8A17
	for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 12:58:02 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-42f64261ab8sf44809145ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Oct 2025 03:58:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760007481; cv=pass;
        d=google.com; s=arc-20240605;
        b=GmPCGj9Uw+GIpu7JOLCZrtCNfYsG0MkpcgP2LaNJyFC5i7/qz48F32u52OicU9dMu/
         u1USgwx9thm4FhbER02zqwMfzr9LOyjG45COgezGWIMZDDa30WyctpuEvwhrPhFtTcsB
         5rb9jy+P/o8zoduYppZ0EPafR2cIeMO2kVtwc3k+i7aqd1rcquqvQEIlpsUIaexYX1uY
         LjWhK6m/u1nwMzolZdtPexSYZpCWUksmiMSckke+f7KDZOQo7JO58udY2kCUnNMxxVlh
         sa+NGKaBpwnpIZ5sorHKi2Y9savwxTvG35m6lfuaB+AWXGXxMwyqmgP/eGREGSTmJ0n2
         TFgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=/oId2qto3mqOtuTV4gm5MLdqulYTcbDB+m7I7Fhump0=;
        fh=patRr7h9axlRPG5B7M0/XJ12HjyX0pszj/I8HATlF/Y=;
        b=UUa6W8JARe16GWTzmjqbSJq64+jouFdQrYsuxISNRka4DtAF21I40MytjfZqKUs4O7
         ry8fyVTSI7r5ig4SGsK5dpWhAbSURqcw128XAJPW4NAPcB9YI3hs0xpv92vCejJNGHua
         bW/Fdy5rlgYsWtVWF0TSJBRq8B9JquuzES5ytRwHk+W+obY6L/fFDyDGzOjaVNyZcjgc
         8rBKTeRw1GyY83xitlE2XAYasXxeZ8d0ZVXoRDN/asfeKEMqDCPSE4cWEaiHsMmLN45Q
         uFdiIUA+a04j6QLLHsA4CNrngdyNAnurz50xbrCJNuTx+JRe1+DnZHXpxUUK+nIAktnW
         weNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W807n6Ga;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760007481; x=1760612281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/oId2qto3mqOtuTV4gm5MLdqulYTcbDB+m7I7Fhump0=;
        b=tq7JPWpMVlbTF4scSeYYRczDm+fpw5/WWEIWDPbTNhiSO/kwlDRFnvHHg7AOOLxMlj
         Jq3tp5UAu/s8Avu/WMa3wqYmKtnhjuHwNO5OjuUURrva0P1T5AtvEPE8/2fLAyBSIyUL
         Pbv44h+3uwxiALiekDJErQvmLJ12llEYWIIo8FDcmlCQyTqeH7b/nmrR5IGSXzYVbFr9
         9wpIBlwzLpVELSQcqLBG6LNdUI97EenhMTwQD4N0GdU8CK3AUjklnvNq+dwakTjK/oWl
         5fiK9Z3dCJ+SBxWdNeuY/st3LfT1v2hsTgcA4WtvC0H9dOOSTzIMYdkUI3Z6jzGzW/OZ
         r9dw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1760007481; x=1760612281; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=/oId2qto3mqOtuTV4gm5MLdqulYTcbDB+m7I7Fhump0=;
        b=AKYI+E9VKA43BAj3qw5MjGGbVcUm/WnDqknWnxakA0Idg3KAo3r+utawebxOdHJR1T
         u+d5LtauFLkiOU+bxKlX0nHNF2zMWMMhCf1gQ/CwZDGlv9EurQ+E3Kfzc566rQz2fS7W
         NAbybWJbfiVPJil1gxxbghAHFPFoa+834zb+frZXJK93Za8JpgNz638tHI8Htl+AT/ZD
         a0ScqI+Wrem9mmW4EdpINbCVoMb18JyVfESTt+ePNeM0EJAXNh4SJP8DR/TxuNdJ4Dzk
         4nacV9nG2nhAMKR0S2Az3SlaN5J+BEdEr3IbJqnbcN8LKA/P/7s+XAgcx3HITOhlviOj
         Tg9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760007481; x=1760612281;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/oId2qto3mqOtuTV4gm5MLdqulYTcbDB+m7I7Fhump0=;
        b=wFzWUxwN1kEDhuoSDAqZtYn2YOiIphyvZCwVhLh4KjJ+64ZpjquinFMW0rIXxkinML
         YA7QHZcTDo9HKumwgXKEdZwjHcgMZCNaJNMOeovl43ix+4jYYyp8YvKPfbd4vdch04pP
         B7eqRUCi3RMqCbGaxhZljdPB6hKf4Kef2fpaAGebAJP39MDWUGc8IGKnbvwRCeM1mUR9
         /74hFc3w1Ol0eNab/r/+OzaEiOwO2aLTiN9GO2oQJg3JsCUimTcYIWoQBawvLrpxxCaX
         XEIyzob+S+hCE1rMRVd8i/cpghXYGaeo4AbI5+ENlO60KZeEAGj7+2HYMPRrb6YlIamV
         bt1Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV043aFjhSg1ixWVlqj5+umEN09H4WJ3+Lw3F0+vD8Y9+2ErlRVeexc9q1K8A5KC7HooXrsvw==@lfdr.de
X-Gm-Message-State: AOJu0YxxTtXByrNsq1CwALlbm9R83j4Soa/PcQfBlKqe6UX341Au3TCf
	JSt1ob3iLJVUS9UbxW4xLZ853HvAxyETwfxrcj8EkkVowkSNVdHuMFlp
X-Google-Smtp-Source: AGHT+IGw/8Gp5GzuFPPWubZ9yfOZiZL/qicy8GixqSh3Z3z08/H4gKs8wsK3TvONe2PavJmaMLnEQg==
X-Received: by 2002:a05:6e02:2143:b0:42d:8c07:70d2 with SMTP id e9e14a558f8ab-42f8736905dmr75472565ab.11.1760007480812;
        Thu, 09 Oct 2025 03:58:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd6yk6GUJmfLO5SIR+esa1kc3qFmXlQcFC4RdLfKLkhh9g=="
Received: by 2002:a05:6e02:cc8:b0:42d:a925:aa25 with SMTP id
 e9e14a558f8ab-42f90ac8641ls7219165ab.2.-pod-prod-01-us; Thu, 09 Oct 2025
 03:58:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXCU0i48+yXuuQdno2LlvP6D4cxAMpbWUcJJ+4pvPjXU8rVZnxykEZyRp4zDq+W4fUq8BcwHG7X7T0=@googlegroups.com
X-Received: by 2002:a05:6e02:1d89:b0:42d:8695:105 with SMTP id e9e14a558f8ab-42f873fb8c4mr64861935ab.28.1760007480033;
        Thu, 09 Oct 2025 03:58:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760007480; cv=none;
        d=google.com; s=arc-20240605;
        b=NbcToLRToMKTwi0KTyYaIRgE/7i7Jm53puacPu649TDamduSV7+aIGM1HW9zN5u3Vu
         4WlGB0rpBV7EFuLCXO0YtxpwIGPqt7IClsqxAJyuGz5PiTGYnEdCE2BbiIS/Ok1oJgzV
         +W+81yMaRTfRD6KSO4S4mWilgsih5Vds/XIKkLfDCP+PWTJlE5a8w6qkF5CkbrzWEYw+
         X/xS3otKIUy6P8BlasS7ziRfDXJ5N8dWQkBNJLDhzE5JdaWLTbBK3kSI9Dfh9vosU6kB
         Z+thFinkxPTxByHyxEqAImx8My1q/mul8H+2AL40rb8+OfEgNMtT0m0V4kBh2b7DDgG8
         YvJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sX4DcHmKN6k6jLli4BcDyPNAsEAGb3ORwL+dRbW7euA=;
        fh=l9/qYRsjqIpmvr5Sp1jDxZEm4XN5AfTV/4KQIr9qryY=;
        b=IzpLHxaGzAWjknAeaj1odXrDJ2Gg4KZceMg0pEqiOCNEnwU9fDGSl/vIiZY4YsPmVI
         RzRQGQrkBzSvW3Wl/Nj311LOeTjNmI2j+CNAKhPXU555rcSdKHm3qLznS1RvIGfisVxR
         2Nn0lFg9+nsjipsIXZLZCq0f/K6IHbuof1Jh5+HMc9fU5tlKUsgKlzQ9bExMiZHXTtSE
         YnjiZByueG8F9tIj2NYray00X9B5pSmRmW09B/LLdxggSm3iJ+knFx/+pJXSngj0qJMx
         dsWM0Pt56RVn0zOK1xLUpeKNqsyy+yWkqL+DGZ2sW7W1Wki3TwFiqSC0xGfKId4rDL1v
         8CkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W807n6Ga;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-42f9025213bsi831315ab.1.2025.10.09.03.58.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Oct 2025 03:58:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-27edcbcd158so9307405ad.3
        for <kasan-dev@googlegroups.com>; Thu, 09 Oct 2025 03:57:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUUiiHA1XROS4QMHHziMVWEkscOZA6AgjgeLefwkRanSqMc5e4QZptqZ2IrTN5TWTV32FJKwGyvkk0=@googlegroups.com
X-Gm-Gg: ASbGncv4BjilAxUZfnsVztYzxP5dd7AVxDjezNNarWLBD46MpebdLqOU6HRV41SW/lA
	XJEocke4mvlnJJ/tulMHDvC969nYHH1kZEQAllh7yc8Ny8lK0kUUg2xiTI8nRZMFpFu7+jcLfVy
	pN/0U35Rqnale7kIdRKu5MT7ZJvF4dG1lBGCZ+aCHlwwnncQZlfq5pZg0KmU++ev+gfNswQmKXe
	ag92QKdfVRS4EAloZqmlyhwPtX6H9MZAlTCmLqV50rux6mxvqsuxP/pz99ItRwHW14AGkmUdIOZ
	HbvkP3gOkY5GsAXwjHcTp5GQASbrG0Wi1XxfQ7L+srSJ86tiadkKOo3Pm7RroFvXwHe8u/d3CMa
	xywqtcWvursAshnr/6tcMhBqO+uPQyWKKVxEMbe7amStGWyivG3pxJEvvr30A
X-Received: by 2002:a17:903:2a87:b0:24a:d213:9e74 with SMTP id d9443c01a7336-290272dfbb7mr102338975ad.49.1760007479177;
        Thu, 09 Oct 2025 03:57:59 -0700 (PDT)
Received: from localhost ([45.142.165.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-29034f36408sm24973055ad.91.2025.10.09.03.57.58
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Oct 2025 03:57:58 -0700 (PDT)
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Mike Rapoport <rppt@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Randy Dunlap <rdunlap@infradead.org>,
	Marco Elver <elver@google.com>,
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
Subject: [PATCH v7 13/23] mm/ksw: add per-task ctx tracking
Date: Thu,  9 Oct 2025 18:55:49 +0800
Message-ID: <20251009105650.168917-14-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251009105650.168917-1-wangjinchao600@gmail.com>
References: <20251009105650.168917-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=W807n6Ga;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251009105650.168917-14-wangjinchao600%40gmail.com.
