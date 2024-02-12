Return-Path: <kasan-dev+bncBC7OD3FKWUERBGVAVKXAMGQEBTQ37BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id D00C3851FC1
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 22:39:39 +0100 (CET)
Received: by mail-ot1-x33c.google.com with SMTP id 46e09a7af769-6e2bdaf7aeesf3525759a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 13:39:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707773978; cv=pass;
        d=google.com; s=arc-20160816;
        b=GfcC7R+gtYMvU7ji/8VB6gTvFARh1PEAMmkUxTEP0bJvogwcx0SxjnTkElXgYo60JS
         ZQOlK9RmxVdF3hOEX9GeXOcRvPLPPRCZrFyrJHrRv8AxdJ/TRSuAKgr4ONPP4u6FbVDs
         ebrn4ilwg7Jwp21yI1hDaaV4KCzgtq+AgmmN+OvFqGgBeKetdkUWq1kG7vqRS23XTNRU
         DRCr/CbgqBF0LVCgwcheq2dOqy+9X5iZx36XNmRU/aFnaAyCCHp+xu9lwp61FOFi2vBA
         G7ztAkXoR3bRG+kozBcG9M3coET89eWdZVMwf265GtFef7Zw5TlIlOVg+yE6i8lp8Y03
         B5oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=iYWM5KmWfJw4y0J/fMpjxVg9UmmWjoyPwfCGewSWdyE=;
        fh=U6ZWRLv8GNjz1LlKR277BZlp6RUfLPYifvGebgxUmNA=;
        b=gAad2krs9VhGUdD0uD8bbdqLBe6HiHXHT7Hnyas51566nL4bxAYfy2JaEQey9/eTew
         8/mHzlj2TusCAnOQcyIdJC9eJVBv2RivayVKKD7ntIVE5uIh1k/xUImuVXMfByxmEKbr
         MTCCefZorP1FgYqAjX/Fgwtk3BneRENTTucr5j13PtQRcNi0NiVAUH3UHIpERRPYP9uI
         bjiAHhltWWDUoC7W3Y0wWyjwI9opgz5BdRw28GV6glaZLl0W0akVeT9Du5E098lZRhIQ
         y03JQQkeG29KodCi90uSrLoxZ3MjwRHXGrx7nz9oAeVEmdGfmAKMNE+92HQsmQWGT1KI
         6mMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WACOdAJa;
       spf=pass (google.com: domain of 3gjdkzqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GJDKZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707773978; x=1708378778; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=iYWM5KmWfJw4y0J/fMpjxVg9UmmWjoyPwfCGewSWdyE=;
        b=LRR14qv2B8H/BNmxd6pq1UMkBnLNIvS+gEpWKKSJQFLOyj4hC4XlhBl0fqAm/UPRfv
         GSsSRA/1pEuZpYPua4UkHOKsrw2gNZyybgTWDZEXsSzjmcfordN3CJemevSfKkqX36Pm
         31S20dXfjEp2w2D9oeKfAV2Gzm3Cr0Pj/E1U47m8ypoD2AiIzeQVXM1lCQ1Lqj0cWBLi
         6wW1xFkU+fgSXCke+aX2aY/+UVTKib1NxX3xhORpl3qMu4GP61odzCZysxho+rE5OskN
         dzFjI5koXylDlWnHmo7lsWuPFiEOXPmq4Zb18uFv9CLIiHAFsgX5sSkeFOuJ/0CgVUAr
         9pGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707773978; x=1708378778;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iYWM5KmWfJw4y0J/fMpjxVg9UmmWjoyPwfCGewSWdyE=;
        b=gXa0T/STjbwXwPpsxTN1ZA2HHtePIwuHqtF8hLDQZQ+lBjMiP51jZrRhSdQhqOHRfn
         yR2JDiXgCarTh/DTu0POezSdR1jiejBiwtjFyOdFHOohop/ooqxMMeh+aoqcKPZd/6H9
         VVQk6clD/4TlyfjmlMtUlgoZG+YxZTgfFtMdwJQJ5acig+4LmLTeczFmQSLoF6arOY20
         jLvMB0VoYf40UDwbCmgHnSrGFGK5D/6ckTfA3bPBrZXh8pxAUiQoWz1G1axugurn4PB1
         HGNqi1SLhzXoLXWxDD5WjPIJd/EgAMeWn6P6dzCJMmqzkYvHWuGNqYCS5TvpisJP+8o6
         vjJw==
X-Forwarded-Encrypted: i=2; AJvYcCULiOxKkhrP/yRLtIGojB34dUab1oLQ4PHtlCwSEakT0AP5eWCj8co5dCaCpnNYuIfdYIPeCInQdsQcC8clQ3sVIMsEt4PUdA==
X-Gm-Message-State: AOJu0YzVnINz4R3TNSB05Y/aJ7mHCWufXlDd3lum28EUiWIeN+Rm12wJ
	OQ5ECMQqXusNzVFwZF6C8U0x5/bs0k8CDytG0CZ2vGh1jETW8UXB
X-Google-Smtp-Source: AGHT+IGVDlWddCczFrHteXDYWmv0DtyXBmMkan4/X/ZcvZwhl6Ifv6o/O0gcv02PkWnQQeB+PA0mCA==
X-Received: by 2002:a05:6830:3289:b0:6e2:71d6:c2dc with SMTP id m9-20020a056830328900b006e271d6c2dcmr7152772ott.25.1707773978318;
        Mon, 12 Feb 2024 13:39:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5087:b0:68c:3663:a1f6 with SMTP id
 kk7-20020a056214508700b0068c3663a1f6ls5627743qvb.1.-pod-prod-07-us; Mon, 12
 Feb 2024 13:39:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX3kLB1TyT6aTFSKf6fHLMi+6Sen8vTAOM6CaOyW5ZAU/pzvQ5gMISYLFZIiSMpwSorruN3q5QBU2jH8aH9Yct1btabathbU0h5jA==
X-Received: by 2002:a05:6102:c91:b0:46d:4090:6ac2 with SMTP id f17-20020a0561020c9100b0046d40906ac2mr7190382vst.11.1707773977343;
        Mon, 12 Feb 2024 13:39:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707773977; cv=none;
        d=google.com; s=arc-20160816;
        b=GFfWgwJncMLbjonPTvO/pJRcMNBP8APgvSkyWQI7kvi0NApA3w3MvYDxURFEhYnLWE
         Xx7FAmF7p/PmWzSmKTtnF2/jPGlZlSdcuE5IdvlB7mxobEKDrmM60nXGc9LvVE8isBWu
         S3+N06778PFmxCZLAdlvJUiPlzxe+EkkYHiRki/JG5ooHXz0NYClk+raBhVdNpxhaO/1
         O2CEsh+X8dNmhFDBj5MLeOPapRK3FK6vkZe8b4yJhE5pjI8LyWfK4OAENoErm6b/PCbo
         J7dtFNDFsoLr4H3UQLSmnWitpQUHs86s3vwe8v1TFW1FPmU0Z1ytIVResTTXyxJlwNRy
         8Nww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=G9b+4SdACUtX02zckFp4W9j//70BE65Et6Qs8xfY7vk=;
        fh=RJqqWHGW03NkI4Qj78hbc5FSQ1HJEWZY7K7qboc3t9g=;
        b=lMdbnStjR1bQT/kIRgREV14Wqxb5IcnnmKrRN2WFPVS4fa6crS84wdzKK9DueS/RiI
         4Fwc6LT90We4Ym2HS7/2lIUAXf+HK0UrfRf63yJ9ufc/Xd1n+PdiTgAOgeJAdLdMmXle
         efdpVWncbohMIIjaUGxwsyYNFsRhYgceUoaWa/E5a8d0FrFtKXe0uamnTdr1O0fJzNWx
         fPnIiUyXMhyeDPRdYbGUZW+eSBRY69WoTyZdTWh/aIC5Zbv+4jU+Ymms5yGmfwxnK73D
         0V0d530PdUQTNg5bDrUavEjHURC2AULxnNNoQfKTFhJie/I5scV1E43FxlYoYqPBY9if
         hEaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WACOdAJa;
       spf=pass (google.com: domain of 3gjdkzqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GJDKZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCVWHKOCemI6UDfnDW6nEz7luBXW4pKdG9ndBRkpHIMxlMxiR8gfpqsB0z8TdNDwNENt+2KMA1uSIcEfVmXmP9/xuLpmWvHBXe4+fg==
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id k6-20020ab07146000000b007d6e93f4d42si509071uao.0.2024.02.12.13.39.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 13:39:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gjdkzqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-60665b5fabcso4468687b3.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 13:39:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWo3yBsQsJwUlmyXj4/qInA8c/5Sj6XTD8Y+JeAvabn8N8OLZa37UArvbIn5Wd4KY0QYHRouU+VtHl5auHtmhSuLtY2Oyrv3VhFcw==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:b848:2b3f:be49:9cbc])
 (user=surenb job=sendgmr) by 2002:a0d:d495:0:b0:607:7f86:dc24 with SMTP id
 w143-20020a0dd495000000b006077f86dc24mr109272ywd.3.1707773976926; Mon, 12 Feb
 2024 13:39:36 -0800 (PST)
Date: Mon, 12 Feb 2024 13:38:48 -0800
In-Reply-To: <20240212213922.783301-1-surenb@google.com>
Mime-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com>
X-Mailer: git-send-email 2.43.0.687.g38aa6559b0-goog
Message-ID: <20240212213922.783301-3-surenb@google.com>
Subject: [PATCH v3 02/35] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, surenb@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WACOdAJa;       spf=pass
 (google.com: domain of 3gjdkzqykczcjli5e27ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3GJDKZQYKCZcJLI5E27FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--surenb.bounces.google.com;
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
index 653b92f6d4c8..47978efe4797 100644
--- a/scripts/kallsyms.c
+++ b/scripts/kallsyms.c
@@ -204,6 +204,11 @@ static int symbol_in_range(const struct sym_entry *s,
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
@@ -211,6 +216,14 @@ static int symbol_valid(const struct sym_entry *s)
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
2.43.0.687.g38aa6559b0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240212213922.783301-3-surenb%40google.com.
