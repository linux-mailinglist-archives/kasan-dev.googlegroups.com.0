Return-Path: <kasan-dev+bncBD53XBUFWQDBB5FWZ7DAMGQEXED34RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id F32B1B99AAC
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 13:52:21 +0200 (CEST)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-6353258f5b1sf4048374d50.2
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Sep 2025 04:52:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758714740; cv=pass;
        d=google.com; s=arc-20240605;
        b=eywNCslEUzcn4/txKYqYupkC/P6gakaqMwjPPbRqGJL2MINZ1uX1PZDktP0K5n8lPJ
         cU0ro2WeV/Kuo9lP5JE2LFIBMwCysLdW3CfLiphsUzlSYqUyfUf/WUb+981mzyQQKciR
         4o1q0CP98Ii4UxR0rla72ruS6fvLRF52h7OCU7bs8NIcWQG629kL2t6A4ozmuNcKs9TY
         Yxg2ZvTTrhYOg6pLEIq8tv7uSRi0p2zUvLoZ36KQU+iFRegHffIgPa36u2LLNmJ3wKO2
         GU9fjIVU730JkRJPqLfed1/AC/8tRacFJdbM6vb9KiGNRr8mqOJhVS6i9Ky/gnCowJ3U
         aiiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=cTQxZabMzRpuoq5WhkVN+Bnhic7cWQ4a6jq6LIjTfQk=;
        fh=nJ55ysq99AEC0nrYaNzwTU1WDfhuvKHx38QSK6k+VVQ=;
        b=jU7f4iFJw5XE2eaugg6+zc721UNWaNXIKRjhY3XGXPPRTR/mYikTFP+Si2aTKWm8E1
         sZtzCOUgN4RrkTmsxbbZD+QEqGcTGlI4t7j23w/hhsJk9bXV+1CUtwHCJQt/8EfNd/Qi
         vBi8TgYA1TaObXbPF+KkgRb8CzD4Bw78Jgk1ZtCAViueWq+SfLb3sWF0sA6zpmgcSj/T
         PRJjcndqac8cXFkt0pfiPxnB6Xx/5uqbzp+iPAwGJ5Uh+o3rvj3EWGKUcvPf+6733hWd
         ns3TQ2WARSr6lJGzPHIXVVwqMR0sIueyuzadTaxjNO5EJ6VXxuawrM44QQFrDz3UPbgw
         JedA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gvelMqxd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758714740; x=1759319540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=cTQxZabMzRpuoq5WhkVN+Bnhic7cWQ4a6jq6LIjTfQk=;
        b=qtDOd8K1hrlKrgOscF34CYwz/AUm/rTzt8qifgzLZ4iJWiyz2MLl3fPmCDsDFJUx4A
         QkuYsuxxDO9IpJS2ZaZ4OWLbsUyUPNCGpk/CbN4we48VUOm+1AHCty/oMJWAZej4KmCw
         5bBcFWRCtiWQCCWLfoUKchduA0K5m7BjsF2gyV9iWrJzx1PkJtB3IePdfkhEBYw37gxR
         OoQpaIUsZpCGRz++pMSjqGlsM1g91dyOYRwl+1V9dAAwntFxUdqHYSbahD2mcsiwvKBW
         F1wpcD1hcQG9pf5RINP5j3Xq5OVf8OwbijmagBPKrfecynrF8Aap3Jed8gBSyVMbNinr
         KIfA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758714740; x=1759319540; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=cTQxZabMzRpuoq5WhkVN+Bnhic7cWQ4a6jq6LIjTfQk=;
        b=f7xeqgJpjKFVXNYML83mnu3TAeJmM9vSp5Msb6qNDkDZp/jirnDCJpgMTjYqySC1cY
         fUqiFRKgeOZMYX8DR8K8D+VNzLUWF6P87ttfl185jo5awa+UYUrpKH8bJX7+8ynFy8qC
         x3rTDInGfpR6E4fgRNjZ0KsIWZqENkxj5yN/qGGqFFkNe8PFyDjGHP/QqzHTbmWleR+f
         Cy99TjWUe/dc9gxIvIBQnmZZ4eIaz6jiypjkSopkdpRyINv4EZzliUQ/eFDstkEHiKFh
         LHrsvCo9ku7qSTIkzBzM1SvcqFMqKHOHWrvjARFG7IUi+IA5dwX7I0sv9Y8iKYMMByFw
         0Sbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758714740; x=1759319540;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=cTQxZabMzRpuoq5WhkVN+Bnhic7cWQ4a6jq6LIjTfQk=;
        b=wcfaBXid8F1sl72U+3SbQ+Nyu1vHJDdaL21MFkmcnT31DLduOQUQSkrLGS2/TU8+Zn
         6nzroFD6mG2m3bMZhK/10AfiobfcaX++oyvZRnQKQoP4SEEfJjNR7SoepOKl3mkRDV0l
         g28XRNt5t8VlvwH4Yh8zjhTqVnJcy/DAuahPkBRRp15Jn2ygYn2SIUILN3VHrINGWTt+
         P9Fc7D/p6zlqm5YllAExLonX0vpsQqMmtLPAT4sQxJD3dNE9fpofmOjUWXpun5g+gnbI
         OBB2TAwlrQd3YIomI97dBGwV7AUBGszux/c77tTOtQGbCiMSovxmS+SNE9iR28wkv4bL
         HWFw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3VMgfWgiWdlAzDPXKIZNe+vcL/Cn6voAqn/1IMwp/4Dbzgx01xkj76epi0Yi24gg+64+ULQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz6B5ke8Dk9Sij8r8XVr7y32oV2qlzUgeMXR0exoT0KFpEezF9M
	dDJv21uHrTsIgm73VmbPSAOdVZOEFpZ/avxpXmgFA1olMzijgl3TfaTt
X-Google-Smtp-Source: AGHT+IE0N57uQ7aIgEpslCJblDBv4YKHp1To6QLN9Anujy/wuqFzemUHtcyE+DOQEFE9kvc1dfwIaw==
X-Received: by 2002:a05:690e:4348:b0:635:4ed0:5759 with SMTP id 956f58d0204a3-6360479280cmr3464318d50.39.1758714740605;
        Wed, 24 Sep 2025 04:52:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6/l71ZWboyNs++mTzkGGf2swglubDOuV62o+A6YIRQ9Q==
Received: by 2002:a05:6902:3102:b0:ea5:b8c7:537c with SMTP id
 3f1490d57ef6-eadcd9f666bls2742238276.1.-pod-prod-08-us; Wed, 24 Sep 2025
 04:52:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWX4d1Xzzh96gFh+vIQOTrs5BnPS08j2G274Wf/3LJ8VfgPn9Zt+FsirlwyyC9HbB6xI1Q3kE+10Xc=@googlegroups.com
X-Received: by 2002:a05:690c:dc7:b0:739:7377:fdcf with SMTP id 00721157ae682-758a432938cmr54909987b3.27.1758714739532;
        Wed, 24 Sep 2025 04:52:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758714739; cv=none;
        d=google.com; s=arc-20240605;
        b=X9NiVsN0CkipKDOz/G8XpjpQfRBaPJifWCHJM6Ppo3kx/4ZlkNNELlyoce1Y6I+wa4
         UYOPaxTyizCCML03+BONaVCakT8FOcrcl2Px2nC6GkfmDpjy9K3+HJF0UJpTe7ZPIZ+9
         EglGHMgB1WGJepJSMuABAAx8xiDA4m4DnO0d/E9VNGxRmZSBRQXL7zURinLyDYAjfCwO
         B/XwAtFLacTnCjCJIXp2h/bI2kR8ZEf1vM5i6NTJ2I2yL1FplqWWd511V0dtVumo2Iwr
         kQ3e0/lO7nusWCGMsaiaw5oFMSEWBjtclGfhFf/vtk7HcU1bNRtrnWJWzPuKM2leU0eK
         l/Jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zjvk/jwcgtCF9TRiT6Fv94jzQiYOsdOhmjAblUevyNs=;
        fh=/PCXJO0696NSqlVrN7u8x0LB3Cl4nMsgWKrS2upibss=;
        b=UV1YnHtAUcsX3Cey4jHDsFnfQDnzPIKBJQVImedHJ0Q7oN6c5ViTeWB1RtJv95mLcO
         1stiVGyb6wubL8MUSwFd1UZDlJqQ1BTkYOZ+M3qbNt9Y25ZhP1AvE7f2YxHhLPiHarGn
         BwSojKYgwJs/0AVa2KPKvmnLwVzPJvo/GGGvtz9bLGW4+ADKCJ9eEGyD6+H1LKHw5Q23
         IcZ1hyLc5rej+Av029GGfGZrZkDegmcNOtRZfy+LNxN2XXo1vec+YzJntURn9HGtkx3G
         jRpbKBr4riCBcIl5CoqbV9VCUaJGY5m4fGYeaIvbdrIvIWIMwEDg1C96TnKl8AcfrV5x
         KJ7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gvelMqxd;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-635380b3cf5si147039d50.1.2025.09.24.04.52.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Sep 2025 04:52:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id d9443c01a7336-25669596955so59534675ad.0
        for <kasan-dev@googlegroups.com>; Wed, 24 Sep 2025 04:52:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWlcRPXF8DjkXqFUWvKTuYJN1cwK1VkR2V7rUr+orY3OIuCDGG0aLGfYdfCtbj81dKGF7SStKRtP9s=@googlegroups.com
X-Gm-Gg: ASbGncuH/bCd4ppBHQF2UwJi8tTJnE43SLjq/LGC+Gb9KWRqhRMS5O4AC1efWJto11/
	pwzvd/Tt5Te7qs5e2Vc9Kc70eGIyNKWg6OjCO99oMvNmEy2lHphgQjBdLJkZFHgVNHYxw0y5iIz
	GC8faRYqM/76JwmNK/CX8e2FALrKs4X6Sj4BWiAEL23rJB902YIWrAFX8gdqSEYtGCWQdfo/mwq
	ZRzAWmANhc9WdvExGkk/4vBwYdHOdV4cDbBuflnD55hvDuThvRJ5/Z43xjnNz6Bl6WMGN+By/6K
	PHm+YjqvZw/KdhTu06ZQA1oJ+zgvk+YkwrZt4Ir+aQ76uEQV99z/G240xXe4h3VjWVqk0e+H6so
	Tnbo5KOaYZJ8NbxRlhqKyYj1wjw==
X-Received: by 2002:a17:902:e78e:b0:270:ea84:324a with SMTP id d9443c01a7336-27cc5624e4emr73742285ad.38.1758714738650;
        Wed, 24 Sep 2025 04:52:18 -0700 (PDT)
Received: from localhost ([23.142.224.65])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2752328629fsm101241105ad.106.2025.09.24.04.52.17
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 24 Sep 2025 04:52:18 -0700 (PDT)
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
Subject: [PATCH v5 12/23] mm/ksw: add entry kprobe and exit fprobe management
Date: Wed, 24 Sep 2025 19:50:55 +0800
Message-ID: <20250924115124.194940-13-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20250924115124.194940-1-wangjinchao600@gmail.com>
References: <20250924115124.194940-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gvelMqxd;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
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
 mm/kstackwatch/kstackwatch.h |   4 ++
 mm/kstackwatch/stack.c       | 101 +++++++++++++++++++++++++++++++++++
 2 files changed, 105 insertions(+)

diff --git a/mm/kstackwatch/kstackwatch.h b/mm/kstackwatch/kstackwatch.h
index 850fc2b18a9c..4045890e5652 100644
--- a/mm/kstackwatch/kstackwatch.h
+++ b/mm/kstackwatch/kstackwatch.h
@@ -35,6 +35,10 @@ struct ksw_config {
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
index cec594032515..9f59f41d954c 100644
--- a/mm/kstackwatch/stack.c
+++ b/mm/kstackwatch/stack.c
@@ -1 +1,102 @@
 // SPDX-License-Identifier: GPL-2.0
+#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
+
+#include <linux/atomic.h>
+#include <linux/fprobe.h>
+#include <linux/kprobes.h>
+#include <linux/kstackwatch_types.h>
+#include <linux/printk.h>
+
+#include "kstackwatch.h"
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250924115124.194940-13-wangjinchao600%40gmail.com.
