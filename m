Return-Path: <kasan-dev+bncBD53XBUFWQDBBPVJZDEAMGQEGDMXG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CBDCC47FC5
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 17:37:20 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-4337e3aca0csf17737885ab.1
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 08:37:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762792639; cv=pass;
        d=google.com; s=arc-20240605;
        b=f/+tIOour3VJ1xL3lDXH1arsOKyRnBtFZC/KmmwQ/A7/FpUrOoE3nXVCUwcAuEiqBv
         2+Zt233EiB7lB2I4aXPnT5UNYQGzitjJ60CNsGb+p5mGoKFCXcsBPIVfWZq4GFCfqfIu
         06mm/xEzFSwq9zn7tVd68UdSt+FHlMj5n8ICmHkXCvtYEhcGdCMoVdx9ms/gEQwYJOOo
         sCTim5Kvzjg7LzZ1viiEG4fWUXz3GC8wDNqy8gMfc88GA8xTI3SSdKGOB0/fnJlve2Dx
         qRZNmNm2GIWBSPWCPWVaVI4KsfUQOVI5wMir99V3+IeokHHjla0HlyOLi8WrmNNS0ulH
         bUbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:sender:dkim-signature
         :dkim-signature;
        bh=Ie/MH/zx5LWiVBr/fWU+Z8Xw3pZInNi3KRI9J6aHFho=;
        fh=y9OBqP56xvrzPGV2LibbakfmT8P6jD3r5vRFdol0Agw=;
        b=FRFhzr4ztqSOLGKrVeeXJKVMsmWMOoWCz4TmO6LPhCQVsGIycuWcoIrhapaiMPia/B
         FriAEaeeevI9IrWjmXMg6zX0T2gOIsRWB58q7EHlonvRnpaYursE5P8Jv/1ujSrk4UeK
         dYX0j19xY6uptj27v8SSzPSdRHWOC6rVYDOE3y7LzM4jRSE9gTsl6ElHufAb5w9HOr7D
         T4OE426BLkSbwj4Of+bEDUEBp8jY2f28BXHe522HSQEVg1utZMhKytbm1UXru1ya/d1E
         CLIAcFHFdav2k5Pomg8mDtR2Sl7s+HThKo7K6zlWr2Nn7+paf043SDOaaSTtUNAY7oXw
         bDHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CrOrXcLS;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762792639; x=1763397439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ie/MH/zx5LWiVBr/fWU+Z8Xw3pZInNi3KRI9J6aHFho=;
        b=jUfEsfTXZmdj2n1z6V7DvulqACIkzMnLJolYXbvBYgkzUgMDHA0VKy0zdbfrhYzNnd
         XkciDdO9rgzVC/fF7S7jJc4vKjS3eFqOc/wMtagJzwq50THKoJTLflXU0rYXNTn+pxPn
         bXJY2mvhJYWqRJc5slSl1Vw1q/NeVAiYgskVByAlH0vctsNr3Pq1UHF+jDcbMo8BiWN6
         1Ao0Ivz3lLCcfEE5gvTR+9lrMg3CxjI+C1QLnUZtVe442OtlpIa+rYuS3QGLfGT/kTTf
         98KO0Vdkr+zv/sqci7reCOhvvBSfMdLy3Zu5FyElm8Amg6kSUXnpdlZ/v71SX+yixUsU
         0z/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762792639; x=1763397439; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=Ie/MH/zx5LWiVBr/fWU+Z8Xw3pZInNi3KRI9J6aHFho=;
        b=P9jnit2MBn+tFpvOsHFkPhgF4lUE+4+tvmufCVsPpH95DApswJlbl/3qRlToIOqVA/
         VdYeZRYVfuow4PsNpnibaGXrK2BfEW0xY8IENgSViHeXaPVoEKIvRTXh7iN0k/jMfMUg
         F3v7yciXVEuaVObsl1NNmbnRxMoTjjE6eT7mMeZVlhKMU1e++kkzRYCAce91toX1gz3i
         1aklbvfY6ZGt4ctybH9aK6+6VPet/jDB3cwxg6KWoqSB58Lo3pPids71b8PEJ+6HQehQ
         BmsaBsRhwW9oYwMOIC03z9ToErNkn6ENLKlXtz8/NtwU3AZb9dWgIunZRjwUKdG2iPyk
         LS2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762792639; x=1763397439;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ie/MH/zx5LWiVBr/fWU+Z8Xw3pZInNi3KRI9J6aHFho=;
        b=NbFP2yuswFrllRu1aC3RXJ1HycuE1g0PvGgMDs39TU6jvnm9T/1wgkP6Jo7OVz/Xa8
         KXJX44a4uxQK2tP9G55gCFobzdO5dFynPfk21vGn8JshmAsBUbuGHqYp6KXLAOBRvd5a
         Bm48Oa5mVG43WT8JZ6ZfJ44E9bB7TZCi7yc2eUN7LkgzdWko6ceoIqykp71e6CE1Nzrp
         +sZIxFb5mAtg9cEw58bQz1diE9S1nKzZRU70PTg+I8lGB+XIS2ODlbqv0/n6tzXqw9op
         jbWi5kh+Sesoqf8dJ0y6xIHuPkIaNesgtdWOudNySagjbYkf7ppXnSX6ONRw4/EX+d3q
         C5UA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW6pqa3IbmtxlrQsJtA1oSrj7E95BgpKYlf4xOwNgmMHOk3vNzEkC3ojjy4wPpSREHUOckoQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx8IEwHLJBpxaY7wVAMrN8dGI26sdiDUYMQDOR32UT4e8i0qC+Q
	DC0a3GdMobAMfqc7KGCSVA7lv0PbuSZM4myH09KOtuW5sz2wlth3Qsd2
X-Google-Smtp-Source: AGHT+IHKLZ3B4C8czHztjkwP5VXAHfH71B6i1xI0S0f1mIRwJ0zVSQ18jZn0X5usR41DGrwmCulu7A==
X-Received: by 2002:a05:6e02:190e:b0:433:7b82:3077 with SMTP id e9e14a558f8ab-4337b8232a8mr70643565ab.16.1762792638729;
        Mon, 10 Nov 2025 08:37:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YbQusA/F1ShDbe17Q7skRRIDcQ4cG3Z5YevPFMJrobcg=="
Received: by 2002:a05:6e02:4619:b0:42d:a925:aa25 with SMTP id
 e9e14a558f8ab-4334eeca6b9ls25992875ab.2.-pod-prod-01-us; Mon, 10 Nov 2025
 08:37:17 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXOigLaCbnJ6wIrB5FmnMZRIKg/rsiDG9Krzq1PXXM25h3CAAeMR4+XgIiF2Hnzfx3y2toql5N5QKI=@googlegroups.com
X-Received: by 2002:a05:6602:2b01:b0:945:a95e:8843 with SMTP id ca18e2360f4ac-9489602f28emr1061503539f.12.1762792637371;
        Mon, 10 Nov 2025 08:37:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762792637; cv=none;
        d=google.com; s=arc-20240605;
        b=No+ZQwp6zu2Sc6DZ8akhL+/AAqSeQGj+WFYyt2sD2nEXNzuicvcfmwiGAVYFnaBDQn
         A2s1/jGmPAhE/N87iNOo9wSZNQG3n7TiZB0DSFZFpfnOG3EM28Aab+XRFDjigMDWtlas
         jozHfZvy19r/4Y6uoM7KEwXkmzcT8VymdfDZVfxtMN71rAwbkQrfqiWk0wn4CY/rH6+z
         m+iaQlv17shnZn9YPEuAU2bxxo9WowlByV1dSWR3uwCdeRRfLMDN4Y/kZ7QTMRY2Eo8S
         T55qWh6dKDhjNBV0VTMd8Eb1KBzBa94US6s9kHhDE2qNzhx901bwm/AIBEvkbKo8znO7
         KDQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:to:from:dkim-signature;
        bh=Xci1h+5LLX8h0ueKKgEGcPTmlGP88Cc5ZUWnC1Z7B10=;
        fh=o4XfRUSMQ5wJimztLaRmzTBQBeg627O3VB6WS1rLrSA=;
        b=Kza/h7DUB5DV+E6hkoQ2PFqA3sJ5hNf7rGPT/xalmIPasUISH9WFkog3FNUOPuVXgz
         CIw5WfAv02G9butk0kKF4IzNXv7z6piPMXeoyN6mqIhfbKgToUITwXQVb2e0CnuwpHvX
         eun9RIZwMZ9zodO3ajalnsSwgj3p1FnI3/FX03J8tnbpXpFZKHA3uY2W8flzTUZ7rQnk
         5sei/rwXqR/tWgD5LPeE5BrWImaiDznbqMgdzfkM6Bp2YZn63sC4u8mET2OlUNAk1Ja2
         bmy0HG32dYDl5Zljp0i8Fcwbc5HdjOzRGpQFqUm15t6To5PT4mZEllpEDyBTps5j+MRF
         Mhfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CrOrXcLS;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-948897c407dsi29119839f.0.2025.11.10.08.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 08:37:17 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-780fc3b181aso2714508b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 08:37:17 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+WZw9OjMa2fB06o6JKEycOHM/lRrbJaYjsaVN9PpBjIWkpN+XcBqWw6UZ5hKpKRZgUrEToaaUz+Y=@googlegroups.com
X-Gm-Gg: ASbGncuwjwQT/OJhaIdleWQNOM2+p9YT/qxdZlkqTdB+siT5HhFjSuScDZ8pX+944u4
	3tHZMKhs239Wl28abyvCwj3ZnY7DP3dTMpmulU3nS4HqJap98PKb7JXCsy1FEHyY71/zjvJ0qiQ
	4hMUyrPuH8VwW5kzF3dIHBrlPhX2zLF9v6hig4daDmx9mK9VdZs3r8YSy7xdR63Zetdst+ik5pA
	alMN+veS3R2bfx+NSXaxtqkVEyCdO2WM4Y7qH5A3Nwkgnbw+i4CMmF04dlvWQAtMySsKoCVxwLY
	aokxy213s3ZOwa/+IZv3lyMIv6f+xp5QN6XLpgyu3Ukm+bPlh3eoywOYI2vm/yZ6euK8bjuVGGo
	rGfEhObg67DkbEFuxvonctuYaPgiKC9VQavOBoIZ2urLfQ/j56kc+nxgai0tTsbuyNc4F5pQuZS
	a+wqQIwAc0lvgyCNKVgOzC05A+lUGMsf+x
X-Received: by 2002:a17:903:1a44:b0:298:68e:4057 with SMTP id d9443c01a7336-298068e42a0mr86330195ad.59.1762792636805;
        Mon, 10 Nov 2025 08:37:16 -0800 (PST)
Received: from localhost ([103.88.46.62])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-ba901e312a2sm13029584a12.31.2025.11.10.08.37.15
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 10 Nov 2025 08:37:16 -0800 (PST)
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
Subject: [PATCH v8 08/27] mm/ksw: Add atomic watchpoint management api
Date: Tue, 11 Nov 2025 00:36:03 +0800
Message-ID: <20251110163634.3686676-9-wangjinchao600@gmail.com>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20251110163634.3686676-1-wangjinchao600@gmail.com>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
MIME-Version: 1.0
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CrOrXcLS;       spf=pass
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

Add three functions for atomic lifecycle management of watchpoints:
- ksw_watch_get(): Acquires a watchpoint from a llist.
- ksw_watch_on(): Enables the watchpoint on all online CPUs.
- ksw_watch_off(): Disables the watchpoint and returns it to the llist.

For cross-CPU synchronization, updates are propagated using direct
modification on the local CPU and asynchronous IPIs for remote CPUs.

Signed-off-by: Jinchao Wang <wangjinchao600@gmail.com>
---
 include/linux/kstackwatch.h |  4 ++
 mm/kstackwatch/watch.c      | 85 ++++++++++++++++++++++++++++++++++++-
 2 files changed, 88 insertions(+), 1 deletion(-)

diff --git a/include/linux/kstackwatch.h b/include/linux/kstackwatch.h
index eb9f2b4f2109..d7ea89c8c6af 100644
--- a/include/linux/kstackwatch.h
+++ b/include/linux/kstackwatch.h
@@ -44,11 +44,15 @@ const struct ksw_config *ksw_get_config(void);
 /* watch management */
 struct ksw_watchpoint {
 	struct perf_event *__percpu *event;
+	call_single_data_t __percpu *csd;
 	struct perf_event_attr attr;
 	struct llist_node node; // for atomic watch_on and off
 	struct list_head list; // for cpu online and offline
 };
 int ksw_watch_init(void);
 void ksw_watch_exit(void);
+int ksw_watch_get(struct ksw_watchpoint **out_wp);
+int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len);
+int ksw_watch_off(struct ksw_watchpoint *wp);
 
 #endif /* _KSTACKWATCH_H */
diff --git a/mm/kstackwatch/watch.c b/mm/kstackwatch/watch.c
index 4947eac32c61..3817a172dc25 100644
--- a/mm/kstackwatch/watch.c
+++ b/mm/kstackwatch/watch.c
@@ -27,11 +27,83 @@ static void ksw_watch_handler(struct perf_event *bp,
 		panic("Stack corruption detected");
 }
 
+static void ksw_watch_on_local_cpu(void *info)
+{
+	struct ksw_watchpoint *wp = info;
+	struct perf_event *bp;
+	ulong flags;
+	int cpu;
+	int ret;
+
+	local_irq_save(flags);
+	cpu = raw_smp_processor_id();
+	bp = per_cpu(*wp->event, cpu);
+	if (!bp) {
+		local_irq_restore(flags);
+		return;
+	}
+
+	ret = modify_wide_hw_breakpoint_local(bp, &wp->attr);
+	local_irq_restore(flags);
+	WARN(ret, "fail to reinstall HWBP on CPU%d ret %d", cpu, ret);
+}
+
+static void ksw_watch_update(struct ksw_watchpoint *wp, ulong addr, u16 len)
+{
+	call_single_data_t *csd;
+	int cur_cpu;
+	int cpu;
+
+	wp->attr.bp_addr = addr;
+	wp->attr.bp_len = len;
+
+	cur_cpu = raw_smp_processor_id();
+	for_each_online_cpu(cpu) {
+		/* remote cpu first */
+		if (cpu == cur_cpu)
+			continue;
+		csd = per_cpu_ptr(wp->csd, cpu);
+		smp_call_function_single_async(cpu, csd);
+	}
+	ksw_watch_on_local_cpu(wp);
+}
+
+int ksw_watch_get(struct ksw_watchpoint **out_wp)
+{
+	struct ksw_watchpoint *wp;
+	struct llist_node *node;
+
+	node = llist_del_first(&free_wp_list);
+	if (!node)
+		return -EBUSY;
+
+	wp = llist_entry(node, struct ksw_watchpoint, node);
+	WARN_ON_ONCE(wp->attr.bp_addr != (u64)&holder);
+
+	*out_wp = wp;
+	return 0;
+}
+int ksw_watch_on(struct ksw_watchpoint *wp, ulong watch_addr, u16 watch_len)
+{
+	ksw_watch_update(wp, watch_addr, watch_len);
+	return 0;
+}
+
+int ksw_watch_off(struct ksw_watchpoint *wp)
+{
+	WARN_ON_ONCE(wp->attr.bp_addr == (u64)&holder);
+	ksw_watch_update(wp, (ulong)&holder, sizeof(ulong));
+	llist_add(&wp->node, &free_wp_list);
+	return 0;
+}
+
 static int ksw_watch_alloc(void)
 {
 	int max_watch = ksw_get_config()->max_watch;
 	struct ksw_watchpoint *wp;
+	call_single_data_t *csd;
 	int success = 0;
+	int cpu;
 	int ret;
 
 	init_llist_head(&free_wp_list);
@@ -41,6 +113,16 @@ static int ksw_watch_alloc(void)
 		wp = kzalloc(sizeof(*wp), GFP_KERNEL);
 		if (!wp)
 			return success > 0 ? success : -EINVAL;
+		wp->csd = alloc_percpu(call_single_data_t);
+		if (!wp->csd) {
+			kfree(wp);
+			return success > 0 ? success : -EINVAL;
+		}
+
+		for_each_possible_cpu(cpu) {
+			csd = per_cpu_ptr(wp->csd, cpu);
+			INIT_CSD(csd, ksw_watch_on_local_cpu, wp);
+		}
 
 		hw_breakpoint_init(&wp->attr);
 		wp->attr.bp_addr = (ulong)&holder;
@@ -50,6 +132,7 @@ static int ksw_watch_alloc(void)
 							ksw_watch_handler, wp);
 		if (IS_ERR((void *)wp->event)) {
 			ret = PTR_ERR((void *)wp->event);
+			free_percpu(wp->csd);
 			kfree(wp);
 			return success > 0 ? success : ret;
 		}
@@ -71,6 +154,7 @@ static void ksw_watch_free(void)
 	list_for_each_entry_safe(wp, tmp, &all_wp_list, list) {
 		list_del(&wp->list);
 		unregister_wide_hw_breakpoint(wp->event);
+		free_percpu(wp->csd);
 		kfree(wp);
 	}
 	mutex_unlock(&all_wp_mutex);
@@ -84,7 +168,6 @@ int ksw_watch_init(void)
 	if (ret <= 0)
 		return -EBUSY;
 
-
 	return 0;
 }
 
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251110163634.3686676-9-wangjinchao600%40gmail.com.
