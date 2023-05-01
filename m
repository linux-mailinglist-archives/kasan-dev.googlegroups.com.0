Return-Path: <kasan-dev+bncBC7OD3FKWUERB4O5X6RAMGQEG52JN6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id A83986F33B6
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:14 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-18f16a11821sf27826334fac.0
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960113; cv=pass;
        d=google.com; s=arc-20160816;
        b=i1qjEBalVXsno7rRmU+5nHg/OsCZMWsXkywIPYUuIYMBCvW/0+ZiFG/VMOmAnE/6kw
         5tG0/FGRAbEAtMK0U52FhO1ZAcodbJx7j18HYVVkwDfkk6buX2O5WAF3fM9wJ8Idt7BO
         HCRcSUeOrjs0z/33rOyEPo+wUfgqwIHOhpgaQiplhMllOXLvKCAVvLWzTd36Dusb+68/
         HpNx5oLY3NiqzRWTLMQyDF9KSe8gPYwhdpeTTVu1WU0Ly0bgcoWXtGIQOrcFEJ1uCJXd
         znFNTVuzxm96j+w+sjuRmFvYfjg6CcplklxuUVXJLpAGdzO0Bo2RtHwZDlYKOOLBbCit
         faew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VBs3USUmFsYOEg4FyhhOUmBPyLFSrgZlplKbuivSPzo=;
        b=AihCMwQ1eatqVBMd0NlLSSVbl6saKT/ixn0cA+/k4olVVTqV/Zam0mGNqqm8hnj6fx
         sO62RhPmol9l7FAAGL7mXmHrvn1HcljLOHVC0N+QjRFDF3lyrhQNi+l4fg+x9YqCbtZz
         pFhbCzpTYriR2btYV+FSR8zldnn3icEtv4/0e3IqM6q5DSyz1dZKgyM0mKexI/qC4WDq
         AyQcU+7ZcVp5C4Ta4fh5cQcK6X68IoLNVtqRfiWFkhrFxl1cMX7BetmrBiILI87XkgC/
         NrZAidKkMfyxsxaE1n5jYuEvIgzcgrGtu0rW2XbvuoS2A/O8EnqC2RqBl1bTtsqNdfIA
         gCbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ym8bWqOd;
       spf=pass (google.com: domain of 38o5pzaykctclnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=38O5PZAYKCTclnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960113; x=1685552113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VBs3USUmFsYOEg4FyhhOUmBPyLFSrgZlplKbuivSPzo=;
        b=UXWah/XcVYIyJcD0Lw1aZ0c9h9YFVfosGersTmiz7xjuOJfJ0Ja0VYIC2giIUbWt0k
         esTKqQyglu1dKXWcnkxFgVk8dbYIZCyLTDb6vNyrB0Xy/QnBWAaN8qjuH2X4sLXiLqJn
         usGIkReaISqlwyeAC2+kUBQmN/TRGQoRgcq51wDrZCOx35f+2DFrMMKGu4C6fI1isye2
         QZIgRWRKZfa7VA6d/BI/JSBMe/GO9RtuSsjpV92ndPR0E7mlMlMJXxcD1IHef7nZK9LD
         aT2FTqgSM95TUrCrZwsmxojIruSaYik6yJypLVankYm+SLSvXqQTUpwnTjZLuAH2SC8F
         +DWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960113; x=1685552113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VBs3USUmFsYOEg4FyhhOUmBPyLFSrgZlplKbuivSPzo=;
        b=SBK5IdJb3UZsYb2unNNVnd62YJxhhrJvzDooXCEuhDYxtzySKjd8KRhVdaC5s6UUK3
         OEWrZootlzau3LJ1cntj41Gfb473tJMfcrXdXlI8hD9IwcX1ZTOYAIBfQeWohrB496xC
         0qLKrjQNnlhC1n7ldwXahypzJWAZRCTnXkwO3p/zFVlwrLNzcNPgSfhtPqPOQzTzu0oV
         w2nhhKErr+krzvcfVjIhdI+T8gJORgjl7g9ygKC1Ae9ZZ+JiKXNF7+SZrGzeEiLlXkl8
         Ey6UlZiy2uwtbBbsgF8G9mDaFe1un8mhXkFYHNShcdcDgBUziXo1T8YOoWATHqa09ZUC
         RwsQ==
X-Gm-Message-State: AC+VfDx61Bk7hbHEzQZYo5uu3eBgTonXN172gTAa92GYQ0PZtwdSNwn6
	D/FWFNNqLZZKXrBflF0rdoY=
X-Google-Smtp-Source: ACHHUZ5GJ5rfXKqaJOr31aEyF3iBWleByLTPYffnVW9XQktAv9tV7/s/sAMb9oJmfLWvha9CvQ3PmQ==
X-Received: by 2002:a05:6870:1f05:b0:192:5ed8:9dd7 with SMTP id pd5-20020a0568701f0500b001925ed89dd7mr960878oab.5.1682960113219;
        Mon, 01 May 2023 09:55:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:1206:b0:38e:2841:4685 with SMTP id
 a6-20020a056808120600b0038e28414685ls2708350oil.5.-pod-prod-gmail; Mon, 01
 May 2023 09:55:12 -0700 (PDT)
X-Received: by 2002:aca:1014:0:b0:387:1a46:8317 with SMTP id 20-20020aca1014000000b003871a468317mr6707783oiq.13.1682960112783;
        Mon, 01 May 2023 09:55:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960112; cv=none;
        d=google.com; s=arc-20160816;
        b=DuXptk1ubn/99Z29TIujHZ9KF9f4YeGX72lqPs+iZ/wUaGh2xncxlB7POG+XDOg6ee
         KHX3OXr6JyzDRDKa+xdhmJ0yBRsw3TeqGhLQc+j09XdJ4ag5Ax/KCOivWemj59ENr7Y1
         u1yWAB6E7rYAkAyAP2hmILQSMzcNRwpKBk1Sl3O23RSTKL5UnRej7yfTOLKig20wpd3O
         IFOhI6qpYLnSa5afcRaRjdcfHJ7Ht7GIPqg+/tFWIzFUrmUFp+BQ75D4sJzU1gtKSLcP
         u9fh0P6EaJE+uf9wACOqCEnFH7aomgHt1t3oRgOLNK4QarSAUohJu7oURYaPJCqJhsxM
         9mSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OgbhlQnm6N3CIqx+6EXURMMvow4S1KQvuNCpohSnl08=;
        b=WJZlkm0RKrBAsvj5ajDfVLhia+FdOiWXYLeJNSnyiJn6eBqb0HDKjOdmk0URi807zo
         NDicXuGkzLRDYgVkbwKiChlEcHNK7IO8wKIv5+ZgKObdWVmvgu4XxhVdvBlhBCwQzYpu
         3UCprTxOnGykITzIxARtpksDFGSEHsvWj8VzR8Jg2kXOiAY2IputVkvNeiaveCeORx7l
         99/5VHbWjWEWiJ1tez62j/hahWaqPQHjPwMdfy8mPwb71ob004p6a0GNqpP7YtHXfPFe
         I0c9zy1iXPfBa4rmE5doluiL41CqedfPHB0WKxFWxWJZp35zNItMjpR8IW/37UkBFrq4
         e+KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=ym8bWqOd;
       spf=pass (google.com: domain of 38o5pzaykctclnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=38O5PZAYKCTclnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id gy16-20020a056870289000b0018b18eedb62si1829045oab.1.2023.05.01.09.55.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38o5pzaykctclnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id 41be03b00d2f7-51b67183546so1423992a12.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:12 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a63:24f:0:b0:520:60ac:fb30 with SMTP id
 76-20020a63024f000000b0052060acfb30mr3551005pgc.1.1682960112196; Mon, 01 May
 2023 09:55:12 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:12 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-3-surenb@google.com>
Subject: [PATCH 02/40] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=ym8bWqOd;       spf=pass
 (google.com: domain of 38o5pzaykctclnkxguzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=38O5PZAYKCTclnkXgUZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

From: Kent Overstreet <kent.overstreet@linux.dev>

These symbols are used to denote section boundaries: by always including
them we can unify loading sections from modules with loading built-in
sections, which leads to some significant cleanup.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 scripts/kallsyms.c | 13 +++++++++++++
 1 file changed, 13 insertions(+)

diff --git a/scripts/kallsyms.c b/scripts/kallsyms.c
index 0d2db41177b2..7b7dbeb5bd6e 100644
--- a/scripts/kallsyms.c
+++ b/scripts/kallsyms.c
@@ -203,6 +203,11 @@ static int symbol_in_range(const struct sym_entry *s,
 	return 0;
 }
 
+static bool string_starts_with(const char *s, const char *prefix)
+{
+	return strncmp(s, prefix, strlen(prefix)) == 0;
+}
+
 static int symbol_valid(const struct sym_entry *s)
 {
 	const char *name = sym_name(s);
@@ -210,6 +215,14 @@ static int symbol_valid(const struct sym_entry *s)
 	/* if --all-symbols is not specified, then symbols outside the text
 	 * and inittext sections are discarded */
 	if (!all_symbols) {
+		/*
+		 * Symbols starting with __start and __stop are used to denote
+		 * section boundaries, and should always be included:
+		 */
+		if (string_starts_with(name, "__start_") ||
+		    string_starts_with(name, "__stop_"))
+			return 1;
+
 		if (symbol_in_range(s, text_ranges,
 				    ARRAY_SIZE(text_ranges)) == 0)
 			return 0;
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-3-surenb%40google.com.
