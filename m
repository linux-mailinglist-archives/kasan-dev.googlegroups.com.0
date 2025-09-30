Return-Path: <kasan-dev+bncBD53XBUFWQDBBSUI5XDAMGQECJW3HQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D2D2BAB0DB
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Sep 2025 04:45:32 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4de2c597a6esf124655581cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 19:45:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759200331; cv=pass;
        d=google.com; s=arc-20240605;
        b=DKR3ziTdIG61xeGpEdTTNHIKmKhrq0Zyjdsv3Lw76M2Smii8ILaiY4hKD6CXghTJV7
         6uH2qf2bDMurkvdian/1WK4s63ZPxLWUJzwBbj+gze9GvjXolrZudi4P1hVNJwVTo/Hz
         eKtmhlU3eA4TDFPE6p4muXWpkgacAMFi6dCjv+uIzBs+SSOo91aZRxGaeoe3yO3RaEU6
         fwGBpEeighKSVoiR0ob2tIFY7VpxWMYAjFDZJ3jU4IILTL7uZ4eoRewmrmnghfGgwQF6
         mGWfnVZB9BA2WkQknKq/atki6u1HawT9KBto+TfvHuNT2EYhKbJfKCI8JJBSvOyMapjH
         vcCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=6BBvMovBr1XkaTU1zFrH+YBao7S65ZotWOYWaolXDFQ=;
        fh=5QrLWKU+Kp5LQTpZS8DffUvzw4/faINw6/clw5UaZKI=;
        b=gQwT0gMuZ0xkxdqjyYFyFH0TwI6GSfCT5NbxqT3Vsfzqj5eyCzUhKeDgGZPcYHexwf
         vOb/Nj951Dn5to4iQS/AAtJhcqsCVHQqyi7R/VZXsFYkgFp6RbrC/MnL82L20KadUpOc
         /9G4MWbdXpqzQD5yVwlNuhMABLp16Gxjm4vUpFSEvBMqZ67obr/DgFLxmugA0MMv+T5t
         FY1gqwqtWOBTeJ+fAa44Joq73XY4aNaU6/UBysCvrnlYZugEiaCiI510uu6PDWfLZKul
         WeSchyYvXfmkfBkzCW73CJta5nOZ0vK+DqEz927lfb6SjDkELzkgOryB+0jKuHD7zsC6
         i+wQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LLfCoqH7;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759200331; x=1759805131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6BBvMovBr1XkaTU1zFrH+YBao7S65ZotWOYWaolXDFQ=;
        b=jnLmvIQSl/CzOtSCgCH2ujAxILCZ7y/ZT4KEGvbxmnNN0qc7LNLAds5gEV7l8Ivp9D
         VakyxiXuY6n9z8ed5k7oEdKwM09Y8VfM77nnP9cKVe4e9165zAl6crS1bqYFHiYRyTmN
         7ZCLgz5iEpcVEmdhwHt/Rnef8gkgNMBotlmBqqugoYfq1+N3MsWw0bQ0Rd/LOT3YqwHo
         CT7rZo1ecg4BD09MVeZ07YMreJU5gusy/OzIWOmHOEmFr+wJrxUwhvU/4eXIhBueJG0p
         A665wTX0MlTXkVF5nO2/lQkUukmtGSa9RVh9Ek8kpY35e87S/x8IRsuQ2IKeZGtiWwtu
         DfNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759200331; x=1759805131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=6BBvMovBr1XkaTU1zFrH+YBao7S65ZotWOYWaolXDFQ=;
        b=BHl5mgXUtgbeQRmRf94CZpBkg+451iIZpSND0/T0jpNTzU6pzIyZp9XbbCnpnh+nXq
         4GaMFi0j/7wMMw5cjSpIZPANaNUsI413MxZv+wIwP0Q0qxfwCx/CkuT6VjkVU0iEgxTA
         lszxloXWX9rXn4wD3c07EaOQbTywyYFnvLBwGwIuaMxToV9HLHK7xEZwEd2h84Wp2Zpt
         JbUu06OFz6uRhThGYMs4KPy6kB9RM0K9hvELg/rztsJh9OiaHMHhIVcQMqDtiDzSN0Kx
         zHZIb3spmH1SYdzWvHLHiUNPxtkAS0AVZ6y7JvtE4+ql4wqY8O8z66Bnk9qYk9jiarwB
         D3dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759200331; x=1759805131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6BBvMovBr1XkaTU1zFrH+YBao7S65ZotWOYWaolXDFQ=;
        b=fVD/VeZV3qKo7lARolO+m5wuSiJ77BRDiI/etvsuZ8+QeW29j4gkJLBJaKzDoklOx2
         hVP1KHuXzyRQFp+rW3RrOnarxqGFzoUoJ2LlYvI3TlcTKTqor62ov5y/XEICiGt3aOhN
         YN3iTXYrZgW1iX1XqJVKAh6fXzu1baCgfviKku1bzMsf8XY86HUWYLj2TEWVi6kGPP8W
         WFKz/QdN0z+nyGFZWdpaW4ItNUS2vqxpFXUUVwtl6IucnppLvfvEnR0/trk4L7o+8Y0/
         cMxmMRejYi/ipv1/LveL14RgG0D60qh/6rXC6haygYO6pVqTmKVUIqQP3BEbnuENVmhW
         hLpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWYB4oO/TPEtqVANqyTcsv4kpPXyC6drRdpjcTlkoqj/XiRpohn6ePQvRRXj6KxBSzjJEVJwA==@lfdr.de
X-Gm-Message-State: AOJu0YzjWGBvtvy4mjsw90DW8qkPOAohTXlD+3j3RxnFMzAH8Z0NoIjp
	vewrLv8tFYmXxOaM92YzRbmpyFV9FHNM8lco+6UwuHOKr2Q78zP79s05
X-Google-Smtp-Source: AGHT+IFB7EhZzCiqRPUS50HZ9nqKPUJdAr+tibPW4k5yGdpz4eBfpB5hXpiu13RQGK7g39E33I3Yyw==
X-Received: by 2002:a05:622a:2598:b0:4b7:a304:edee with SMTP id d75a77b69052e-4da4782d9cemr218718991cf.3.1759200331013;
        Mon, 29 Sep 2025 19:45:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7Ci+0IpYuA5Iu+h1QvQ1JMEDqRBDmrqJ/BJwTQwx0+Lg=="
Received: by 2002:a05:622a:768b:b0:4d6:c3a2:e1bd with SMTP id
 d75a77b69052e-4da78d9afe5ls75386511cf.0.-pod-prod-04-us; Mon, 29 Sep 2025
 19:45:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWRZJ8PmsWaCD2E5UR9rmTHq3axt48+d6t/OJODrh2F5CwRLROK6ft3ZEb0hIHxwCqy4ufcwiMq75s=@googlegroups.com
X-Received: by 2002:a05:620a:4096:b0:84c:1d25:890d with SMTP id af79cd13be357-85aebd00dcemr2135252785a.57.1759200330273;
        Mon, 29 Sep 2025 19:45:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759200330; cv=none;
        d=google.com; s=arc-20240605;
        b=AkQMMUCX+xIfR3AdtBvHAEDiUJ+DX5GdJ2ZYgisSi/J3KcZCY+B1/D1snf7YH7KKMO
         8KOo1KeFcM9jnrLVQWbedOx+h1L/nOjs/Wjck90jhitR80ROTmEo/6zQb/gHV7R5qnNS
         8XXJaRVzwEPx+XbFnVGE6aTaHpfJ9o1uAmE/xshkNtqV/zCtRSXAm2QHU181vzvkkHd8
         mV0Q+jCj3V9oWAI2eAvduXAwNGus6SrkgpLblwBbTktjmGMwtQLzXzuftC6fD6DmZ+yE
         p0SB114koROhgCZ9ZL6Lr9Y04aW2UZ75Mp85FurVAZO6E7cN6EJsyKbJsqb5M11BUyJI
         MaUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sX4DcHmKN6k6jLli4BcDyPNAsEAGb3ORwL+dRbW7euA=;
        fh=NWKjZaHn+cHN6viXpdNXiC06wRwbh9sEx4hspBSs3ss=;
        b=A2mllxb5YrnBmXIyTPt7QdyaNJmfsAgMlk8AV4cdx18fKFVjJA9P89/OMKbKJ2kQ18
         75/F10ZjJf/z2DX+dSrIMn181PGdXxNPOJGtNXRWrW8iM/JIzTXQjsfcYyh6xg/XqXvp
         dmhdaI19YGaIVa2AMhftG23HRRYTto/vy7FhwjURiwB5oGxZ/YsDqxvRwdaqzDW7mt1e
         yPQgGkuGm4G5Np73lh8lDzE7LR/GThotmiT5zBKM+/G+i/6mbxV/7278nXRk+pLS+iZ3
         8QSKQntcvSW7+oZHQXCR0pA9VIilgTQc9LVs4NR8M6scbuUwrpB3j/RTaNhVwJcV3Uu5
         ujYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LLfCoqH7;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-85c2c904122si52499585a.4.2025.09.29.19.45.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Sep 2025 19:45:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id d2e1a72fcca58-7811a02316bso2897086b3a.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 19:45:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkRxIIq6tvsdhwgGNMXTIV6epVekZ5NPbH+Z/9oZlT1jm95cFe4PZ2pGtGZS5pXm1xj+j8b5eGnX4=@googlegroups.com
X-Gm-Gg: ASbGnct6MChNpL3lDxmfjjHT0dnJnQKVOftmhmjAqUOnQhpsEkR9rDceWTiaMG9ACoa
	a5J0Ue1jn2YA2poLdRM3DNOa+LVO0iUUDXnaVz/Orve07Ger5Li60vEqPm2cn8XSudWA7IOBdFr
	PE9muY7p8krEtLqFD7bJ51NtjomzFl5qm3o7Aqu40akO+/bz70eajNThI3P85o5QUFiG+J/7LAg
	PF7V00LVqnE2/HrEjb14RCiWiO4rlFR9ilMDfRvcNQym17Czns7Z3rRpNU8wK3CMFkkwsdgoEWM
	J7uqjA/dqhuOYc3v45M1TCnUJsysb8qL4YUv5Y4yTWZXHqKrbjFteqPHRJuDtWLsED9lJVMvH9F
	mnMWscGSdbCUPdoYTxAUseeP0LIgL6anAbvXGvFsqckZ6Fb4QJE7z8s7tN+g6P69Csf1kyX4gwQ
	GOZCt25M8fB2A=
X-Received: by 2002:a05:6a00:b53:b0:76e:885a:c332 with SMTP id d2e1a72fcca58-780fcf080d2mr23371738b3a.32.1759200329155;
        Mon, 29 Sep 2025 19:45:29 -0700 (PDT)
Received: from localhost ([45.142.167.196])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-782e36c803fsm5830819b3a.38.2025.09.29.19.45.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 19:45:28 -0700 (PDT)
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
Subject: [PATCH v6 13/23] mm/ksw: add per-task ctx tracking
Date: Tue, 30 Sep 2025 10:43:34 +0800
Message-ID: <20250930024402.1043776-14-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250930024402.1043776-1-wangjinchao600@gmail.com>
References: <20250930024402.1043776-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LLfCoqH7;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250930024402.1043776-14-wangjinchao600%40gmail.com.
