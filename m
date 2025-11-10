Return-Path: <kasan-dev+bncBD53XBUFWQDBBUFJZDEAMGQECKDHTMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 15A1AC47FD4
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:41 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-432f8352633sf92927215ab.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792659; cv=pass;
        d=google.com; s=arc-20240605;
        b=Vp/IJiKIyOz3bcThGLmeGOioLLtbJVYbCLJKBTJ6IeYt3DWspf8mMY+4HHiNZJtg8t
         HKRebMiFiSmefYGmjp3VgwBtD++aibqGMdfCYuRx4fVWLXWF0TNUKqaPaHR0//mj/gxm
         LdcL9aJqQsf0saj8WPzszdmI+r/dnTPMCHWYpRaQ8PMSUb9t7DIflY/42P3iLpspT5Ab
         fwHthvr9BOHdOADycyDOTOx+mxSLliG3oTyQjGad36Pet3qhFEWYcQ1dR3WuOiIqGnVH
         VPg72dp6D4IiymmywNGhnpn7L3vZ13Xb6qX/K4qVtSUkPfO/9xh/UL8f3LkKalYdz0ux
         Nx8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Tf0mer40P55ECHtuGa2WkVOvWbJCteT6SJQnv5mBO/o=;
        fh=cTvlaahLsVg8vnSeYyhsq1jBT2r4jc1lbb5OLalNvS4=;
        b=WN0DeVDHMuij2TzGhC/uacBrogPtNhvlZBT7uGcv+w01CJA0ktlwVhkKPHyn7Y68N0
         cBp4tSaVUAkXn2CHLEXeDFpE22j2ngpbhDRtM70J6c8QeXsSocjJH6PxiGlt4AUPcfeK
         ey5uhK4WrCx4yDt7ILdLM4yylwa7RiJOgbePVUVTp18bjuumyeGT4NqoNTfbMiJztHsa
         6V8JxGtLiUEU2p8iOcQLiiCjrOXT/HXTieql9FjK5ZUGlSi1ynfZPHriHMw/aKAaKu1T
         AkDhM7FI19Om8WSsqlMGmQq7SINBqKYyi/QuLWVAXw/wAlgf4NfQh13xkYDlmNJCk0ma
         uH8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I42V1Fpw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792659; x=1763397459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Tf0mer40P55ECHtuGa2WkVOvWbJCteT6SJQnv5mBO/o=;
        b=OIB7h6Rxn5bFWDSXEWYyCu1rLSON1UC9Dq4XBdg+GtNS0wgMrpQrNyRn11r/1qC6cw
         L8VWoYEngRCTVmewEFWduVGBjwZ5TEv9gz/b9kOVBQy9TQ8w393eZheOHxVBw8+HUuR/
         CyhTaV0V93aPRp+d905qqwZDVXxQK4pUaG6vSodubqow4oexdUM9o/0+aNapyU7T04xN
         CNgVNzQwCw0B0l0uzIBuxfgcUd9hHNpGBttO8g5tovCwimFRy6Vd6WrpJmllGU8pTGjl
         BXx+UN1779kfkRkQF1YO5syzwxHdm0JoKKLwncjoXHRvMdJgt8T6eLNIYrHUyAbttH/k
         EcuA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792659; x=1763397459; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Tf0mer40P55ECHtuGa2WkVOvWbJCteT6SJQnv5mBO/o=;
        b=Pm5BI+oVPTjKybIIpU2WNqI/BYLB7ZTRtO10XciTLy0A1vBQK5ujKbUNLAGHj+do6+
         eyUzUvkqV/Ka93fw66Z8oUbe4r+cLTOvDyjOW0KVRxB9oiNoIRroxP0En2cCr7F71BsH
         SDputlX+mjAu6sRmyUq/jaeVzlNsG1qA/w0hj6X+X2FQEjSLEIdbXhsAWCGnoIizwst2
         OYjeUNTxGlkCbqPTmr0z8u9T7bgp6c7Zolr+Qm2TQq5AwQmgEfH6UJ0sHoD5K6XRpXDZ
         tiLkbzAXrlUazml2Crwd9bUK8DMk24KhvORUYAmA07ZMiZ8/T1G9eDmDDflz0tQbXqDr
         bOOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792659; x=1763397459;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Tf0mer40P55ECHtuGa2WkVOvWbJCteT6SJQnv5mBO/o=;
        b=VnoIYUMYYYQZR53eZaf9lRlSC7yknY4WOC5IJccDFmJhUOt2q4qqfrTDED731jUZg2
         KAIwCgfuwRVX6fop6ElZtQQzeV96JUd6ckkbeFtKS6Ut5K4pevFWLC5sjF3B1fFRygYB
         s7TzeE7qMS+BgirvXkUJTD+8f3NUo3LEVoCigPvg1ixezJTcuVSeMNm+/L1hDQkn9JNp
         zCsoisBc6p6Ya9QEZMubVvX3C7opMOPQT1mgkdxKUPWLpLEhp904xzg19Hf++s04YfAG
         5g35cV08CJr1er24rbKJaiXzslmevmZA20mOAACEafovRL0kPd6q7mXqt2NELXFm+qzX
         o0kw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXKSSTFS4SiWCI93Mr3vhBs24sTbnggQFjGVNOaZRB3K3lwXS0BRzEzwtnYI9MYeAMVy4ravA==@lfdr.de
X-Gm-Message-State: AOJu0YwNf0fbw9+4bGP6CHdlzBUgdtV8E5iDsn/ded13vjq2h28KH6S8
	VMTHlVrNRXpoitM3QiJQzFqw23RTbQuQQKU42AnDKKH9IAIfT6RQKyeg
X-Google-Smtp-Source: AGHT+IGm5gn7eU4fuh03q6YYCzn2GL8w+QR1SdEzL8J9GldIiHdO1TB2miG1wn5R75uH9Luy6B0k6Q==
X-Received: by 2002:a05:6e02:b2a:b0:433:8a7c:7750 with SMTP id e9e14a558f8ab-4338a7c7912mr15630995ab.26.1762792656614;
        Mon, 10 Nov 2025 08:37:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ajfdVn2H2yjOs+9KKY/12IIsmPkRVlWpTulgGGUL+ASg=="
Received: by 2002:a05:6e02:1a4c:b0:433:8a74:2890 with SMTP id
 e9e14a558f8ab-4338a742ab7ls3508515ab.1.-pod-prod-05-us; Mon, 10 Nov 2025
 08:37:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV3U/o3n53zXw2GOC1MAX4IEefXPFZia7rYhoxC0o4My0s3EaxyVdR8MqN3/ZLnXvH5bK9dC5P1Dew=@googlegroups.com
X-Received: by 2002:a05:6602:6b81:b0:945:9f86:a1c7 with SMTP id ca18e2360f4ac-94896041a2fmr1177344139f.19.1762792655575;
        Mon, 10 Nov 2025 08:37:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792655; cv=none;
        d=google.com; s=arc-20240605;
        b=TwnDh5/zezHE6TOPsevWztGUfyTA5bKehBEJKamGEeFO8SFp3Z3meAEtZJb4Esi9tC
         RfVQvRqbrIAiWIBlBZM0lHu0DGIxg9cbWt736NET88D1LHGmTf3GUOoDg8J3fnpXsaaa
         QKC/U4BZeMO5JaotuVxngQDnDBRG727U5SUrIow1vio2YvNYhAOEL7EI2veLHDQNrEKa
         QQzXZc9Z9GoeNrbS1+xHcZz5iTwDJhSRmdibh7xICiOvDSDUi5RkL6usiG3ynaXG0s/j
         qNtGW8e75TqTemM4tEt+Y6xCyoR0wm5CTIJdfu//WzcDWFqCbs2iJTIaH8UMptiEfD1v
         yikA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=j+iVGEpI5Tg4S20J7P4CCPxNAttk2LGvwxP9Ue3oAtA=;
        fh=UKGG/+ZPDNjyY7Fb1UI+/EA8FMl/LVtZBmAC22NQxTs=;
        b=lAL/2MvFJ4z556QhmmSV45cCN7GI8z3ODFNWXCDaOmSTdcJxOWIH1Kzt+rVTjECA0q
         uShafHZiQt3MVhaM+x5k/WRzPZ4a2/nYNIoNq9OObtvGpEoKrNvhq43IHrbXVk6dwcp4
         3PcJdVGcbnCpqhGg2wADVW5ZWyR8dyxJAuZXkX6akdSHgQE1aUxlxQSzYCe4a5Ir6ZP2
         ZBO6NvYdDKRCfdZSjdBdqupknxWX+puXBe41vQ+qhAH8MkiLgD6vEAQy2eYEnB9yYCmr
         bCuWDwLVljuawE4PYVc6xVrJWxXAtZf3wqQCB16yrK2f3j7hYSLpFp5K98w/xmQfZzmi
         ibQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=I42V1Fpw;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-5b7467d99easi463795173.1.2025.11.10.08.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:35 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id d2e1a72fcca58-7b22ffa2a88so1367896b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVl98ez+m8/IkvQa97mJ9slnX4XSYncQIcDh5FrVhWMj1P7YfWVfVkimqxChNqZzVpQUXuJPMg/N10=@googlegroups.com
X-Gm-Gg: ASbGncvIj+Jz0bdiM7eAcRzMw8sbt2hUyLXpAjb+9fiWvJf3iMCgMXYHWMcoudvEbIs
	S95deUZz3IyGqda/83Kv3RHO4zJEDLeH0HFEHMXaNs2ANAUv1V5EGzeDlDOP1Xi33KoV4TExb+0
	E1qltY3dn5pa+vbh9o6fCnp/IDiQgHwjgUis4ZxRaj9B2shXs2xjTmg3xQ/gnERrNf+kIIolWik
	jU0QlqHGdvGeiSM8xVURTgMYOlg9llOYbUl315veL09jed+E/jBDv18ooqAHERVYfDPtQka3m8a
	qhv690eGyXd1Wrnpa+LiiVW5n0fwp9WHy38v6lTCYGL2H65HTjDZayWQwG1m7lTcFrassEt8uHD
	JNuYra4d4oiYAcwDQdH9uav3HtxwqpOc0GFCN91hBfwYWhYhdEiuf8Vf12ubbvRcs5xpU5hjGUJ
	SzLCGFmaOFlm8=
X-Received: by 2002:a05:6a20:72a0:b0:342:378e:44af with SMTP id adf61e73a8af0-353a39633e5mr12501946637.41.1762792654931;
        Mon, 10 Nov 2025 08:37:34 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-7b0ccc59de7sm12250750b3a.65.2025.11.10.08.37.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:34 -0800 (PST)
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
Subject: [PATCH v8 12/27] mm/ksw: add entry kprobe and exit fprobe management
Date: Tue, 11 Nov 2025 00:36:07 +0800
Message-ID: <20251110163634.3686676-13-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=I42V1Fpw;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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

Provide ksw_stack_init() and ksw_stack_exit() to manage entry and exit
probes for the target function from ksw_get_config().

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch.h |   4 ++
 mm/kstackwatch/stack.c      | 100 ++++++++++++++++++++++++++++++++++++
 2 files changed, 104 insertions(+)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index d7ea89c8c6af..afedd9823de9 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -41,6 +41,10 @@ struct ksw_config {
 // singleton, only modified in kernel.c
 const struct ksw_config *ksw_get_config(void);
 
+/* stack management */
+int ksw_stack_init(void);
+void ksw_stack_exit(void);
+
 /* watch management */
 struct ksw_watchpoint {
 	struct perf_event *__percpu *event;
diff --git a/mm/kstackwatch/stack.c b/mm/kstackwatch/stack.c
index cec594032515..3aa02f8370af 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,101 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/atomic.h>
+#include <linux/fprobe.h>
+#include <linux/kprobes.h>
+#include <linux/kstackwatch.h>
+#include <linux/kstackwatch_types.h>
+#include <linux/printk.h>
+
+static struct kprobe entry_probe;
+static struct fprobe exit_probe;
+
+static int ksw_stack_prepare_watch(struct pt_regs *regs,
+				   const struct ksw_config *config,
+				   ulong *watch_addr, u16 *watch_len)
+{
+	/* implement logic will be added in following patches */
+	*watch_addr = 0;
+	*watch_len = 0;
+	return 0;
+}
+
+static void ksw_stack_entry_handler(struct kprobe *p, struct pt_regs *regs,
+				    unsigned long flags)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+	ulong watch_addr;
+	u16 watch_len;
+	int ret;
+
+	ret = ksw_watch_get(&ctx->wp);
+	if (ret)
+		return;
+
+	ret = ksw_stack_prepare_watch(regs, ksw_get_config(), &watch_addr,
+				      &watch_len);
+	if (ret) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		pr_err("failed to prepare watch target: %d\n", ret);
+		return;
+	}
+
+	ret = ksw_watch_on(ctx->wp, watch_addr, watch_len);
+	if (ret) {
+		pr_err("failed to watch on depth:%d addr:0x%lx len:%u %d\n",
+		       ksw_get_config()->depth, watch_addr, watch_len, ret);
+		return;
+	}
+
+}
+
+static void ksw_stack_exit_handler(struct fprobe *fp, unsigned long ip,
+				   unsigned long ret_ip,
+				   struct ftrace_regs *regs, void *data)
+{
+	struct ksw_ctx *ctx = &current->ksw_ctx;
+
+
+	if (ctx->wp) {
+		ksw_watch_off(ctx->wp);
+		ctx->wp = NULL;
+		ctx->sp = 0;
+	}
+}
+
+int ksw_stack_init(void)
+{
+	int ret;
+	char *symbuf = NULL;
+
+	memset(&entry_probe, 0, sizeof(entry_probe));
+	entry_probe.symbol_name = ksw_get_config()->func_name;
+	entry_probe.offset = ksw_get_config()->func_offset;
+	entry_probe.post_handler = ksw_stack_entry_handler;
+	ret = register_kprobe(&entry_probe);
+	if (ret) {
+		pr_err("failed to register kprobe ret %d\n", ret);
+		return ret;
+	}
+
+	memset(&exit_probe, 0, sizeof(exit_probe));
+	exit_probe.exit_handler = ksw_stack_exit_handler;
+	symbuf = (char *)ksw_get_config()->func_name;
+
+	ret = register_fprobe_syms(&exit_probe, (const char **)&symbuf, 1);
+	if (ret < 0) {
+		pr_err("failed to register fprobe ret %d\n", ret);
+		unregister_kprobe(&entry_probe);
+		return ret;
+	}
+
+	return 0;
+}
+
+void ksw_stack_exit(void)
+{
+	unregister_fprobe(&exit_probe);
+	unregister_kprobe(&entry_probe);
+}
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-13-wangjinchao600%40gmail.com.
