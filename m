Return-Path: <kasan-dev+bncBC7OD3FKWUERBQOE6GXQMGQESRSAFIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B9FBC885D9E
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 17:37:22 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-5c5c8ef7d0dsf777672a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Mar 2024 09:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711039041; cv=pass;
        d=google.com; s=arc-20160816;
        b=afK4Dc12VVFU8nUatl4rE8hrsOMhkZy/8DVZlrwxYwrolVxi1+QFPjU8kg8F+TRKyY
         EWqcdS/RNtTMTziFRLcQzK5VaPy7TZjLWLb7HdBaeXFzbv1Gsp2TKT2pvSwTZCkPhnC+
         OhzLs+8bLutylCEcqOamNQzlifIN4uK/yUOTiXzNBcqV1GdHiJCphSWERx8ugk0jWXUK
         gokcUQafX37I0JsKHmt172FoTqk+NMFBvxHI2cD/hYGtOt8+O6Uqm66D9axqObv9qY4S
         MOpLXOX7vMMDTQQoL1OX7khfMx5J2a43lHnh4O1pzAAwCWjz7sKAF0vqntUTR/asVFCJ
         N9+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=6NMeZDRFwsLnhL2/USydPZQt8tDw1oWlJwI6eVjzN14=;
        fh=EwR4jRsUMPluNUJ2ejhsVkg+BX9IG4ES9ikHzCNd/PY=;
        b=vGYYMzx4gs5z78rvV2nJTokkCDoyfWPThGYwyphEmE779w79E2TSQ4FqK+KMnED4cq
         xny9GXNLuyhvxaDcjiO+Ope23DikbEWMr5Urx9lN/Xio0lM+rE5PWkbPuS7pbB1YAluX
         7wpBoY5wbZqWTO4h8f/GBkEczyqfGXV/tBlfNsOKKY7I4pxP1+DVEOS/ExKQz96zxIbe
         AWOj6TqomL6iNYpqV9fuIms37gq1/Flc6zoCLS9pwYF5bJZL0kulw74IjW55VEEFtgrb
         N/nt/09Ylz4NLc6KOYM0bKba25XuLZ4yAjaIVa4U+K0Fd+aR9w+l4AJt6++YSngl/+am
         bATw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jMVp7wgy;
       spf=pass (google.com: domain of 3pml8zqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PmL8ZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711039041; x=1711643841; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=6NMeZDRFwsLnhL2/USydPZQt8tDw1oWlJwI6eVjzN14=;
        b=HSGjeHjBjCaK3AmWrYolqlRLb7u2XL0vHv6kDUoxbjc/c/RoEvXToQe+n4NvQ5IUVC
         1kxCzGTWYbhr3xK4NEM61tjBhGUnRU+W1sPdkV/IbqwCewiWHceRkPdS+bqNOSBmzJYD
         2+sJdmqSo5quEk88XTnNHNHC990xIYBQl48h0rL1ChvsL56dp+jMZXqLCTXG1lYGrkC6
         RsyQFnc05SsG3oUv5MtJNkTyYM9JfX6U34f74JadUhRuSn9KUSR6xe6zv9ZdcjmhwZ/9
         V8rQqvFJ0DpfcQEgG2/yo2OgC25Anrrb9cHFmZkh2V8ZetjXXTS/W4bj5SnP0wDVHUlc
         zmWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711039041; x=1711643841;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6NMeZDRFwsLnhL2/USydPZQt8tDw1oWlJwI6eVjzN14=;
        b=lIE52TEOKuAhfl0CiU1wQ88/zXywxYIHSv/PiHjOiwbKHQSWLE/2EFA/j1nD99tmKW
         TA20Z75IjHg/nq0eKnDbN6HFuqJdHlKNQpRj9DTo0aYsl9JI0A7VzCvuJ6Q1yL72YZ7N
         AI42qR7joQZf+tkFFHyI6aXZpVjmOjmOw6L7Dl9M3/AFTHL9o5eGEEx/FiVIMpKV+wUb
         9j6jRcBPXmw41nT16D3ztW4jYmU0o5kTFms781t9TmVb8gQERMa03z1R+7AeEbtC489j
         Bq6OSO4D6pROjwrWMf/ydMO3QrPT8rLwpLWvUte6l9dLWv/Zec39QtuC2jDf9P/yGiwG
         qnJQ==
X-Forwarded-Encrypted: i=2; AJvYcCU+xDm11fK9pxylaFIhreYCfdH+mCoJ9CVp3J4UiJ42ALywN58nO5un6QS6gh8oJVmygOraz+kDK2OlnavaSqrfgq688sL1EQ==
X-Gm-Message-State: AOJu0YwFusvLWnvvdic8vkRYKzUFEEX3w1ZUEXkASrajpJ2oPwZvXG/k
	kn2VUYDwR2HY4xZzS7vyYe5AqrKmrSt+dj42VUitgyf1teVPA5cc
X-Google-Smtp-Source: AGHT+IFwa3KEDRabO7Qq0lXzZ4jZ5we22hRGehOqh7LlfJd4C9RrmWHPOL6qFKTdOoOGVIzxaEmviA==
X-Received: by 2002:a17:90b:3118:b0:29a:e05f:3f55 with SMTP id gc24-20020a17090b311800b0029ae05f3f55mr17076706pjb.2.1711039041151;
        Thu, 21 Mar 2024 09:37:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c45:b0:29c:38ba:70c3 with SMTP id
 np5-20020a17090b4c4500b0029c38ba70c3ls576745pjb.1.-pod-prod-01-us; Thu, 21
 Mar 2024 09:37:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxhMF0Dpey09If380DTKAqyOjbyQpS54EZvcCqJ7uZu3KY8Ktzzp0B6xyH3iKBSsd72eLTc69xyupDxozam5rL+wXUQ1a18/VFjQ==
X-Received: by 2002:a17:90b:4ac7:b0:29e:343:76c4 with SMTP id mh7-20020a17090b4ac700b0029e034376c4mr14417780pjb.4.1711039039941;
        Thu, 21 Mar 2024 09:37:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711039039; cv=none;
        d=google.com; s=arc-20160816;
        b=F+mdDzHwdr/C6txm55HEghDHpf1ft204x87xTkT+EjipJVNAIMDeGkgEPqtE8UTYlL
         mLI9IGiVEmfmGuw5xikryv6EbRIMywKWJUJC5ZCGYFwxuSrH0aIUYbj/hC333oP6SmQ7
         3cIa+1LNZgck/xMMNBPUwX8Fpif9aZ/R4E41vyJ7fU8VcydDexytHYghDqQugsZ3f5Zm
         jfcleopsH0e+aZXnwkPTDGHG6YZHgxCUVMTten36CFPMbJoqYjbQoI7WA4mV733tcgOI
         Y/2A995+wDVn3fEl3ofClHF/gkLfSQAXhXaGtoyYFNcqWBxJ7MbcaNZnXXyu7Rg6iEYy
         8LOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=FcsF8xuW3B4rJ7bvWaC3URPqDGHFVTOJU/Md9c+vki8=;
        fh=wLDj8yVFCc8xQuYDlRQCwediWXVXxqMXq6aJMEaOazE=;
        b=qM7ebUkReFLztZdMmW8gvQIcOO8tKad/Bd7x7nDxcF3kG2OGFfT04jUSYrM7/wodQR
         0W5skK03BhywUkbRZgFHyknG/Vbi4K6CZmV8bI+s4nrQ4bofmlwNWIlKMrcFiNbHXBex
         yFaL1pbinON2vAIKvVLDYUAohGa6z4v7VBAT+NQ1phAJNM6R1RgpL0S6IYqdFWgTmWCX
         qNifnA/oCbcfWi0x6IDsHFpmwi/D2VYuL2htIyiXegqZPWfbsCOoShmjV9+R+OgBEdc5
         weDcOQVTtMQs1r19aQx9RVQmbbSlm1OVtDu89XEqd6m2Ih75BYxmcquOI+xEsQOPkP59
         Tf3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jMVp7wgy;
       spf=pass (google.com: domain of 3pml8zqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PmL8ZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id x20-20020a17090aca1400b002a0251d08e8si155685pjt.3.2024.03.21.09.37.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Mar 2024 09:37:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pml8zqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-dc6b26783b4so1365432276.0
        for <kasan-dev@googlegroups.com>; Thu, 21 Mar 2024 09:37:19 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVMTEFhGLj2t5oPhhByFc00B0i2tyTKXKbcxD3zTj/4kh4sdgcv1j7UeUSWI2CVOuJAwo78XVcDAASw+nZVtqKMyRbPPvRlg+KGkg==
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:a489:6433:be5d:e639])
 (user=surenb job=sendgmr) by 2002:a05:6902:1207:b0:dc6:b982:cfa2 with SMTP id
 s7-20020a056902120700b00dc6b982cfa2mr1182860ybu.8.1711039038760; Thu, 21 Mar
 2024 09:37:18 -0700 (PDT)
Date: Thu, 21 Mar 2024 09:36:26 -0700
In-Reply-To: <20240321163705.3067592-1-surenb@google.com>
Mime-Version: 1.0
References: <20240321163705.3067592-1-surenb@google.com>
X-Mailer: git-send-email 2.44.0.291.gc1ea87d7ee-goog
Message-ID: <20240321163705.3067592-5-surenb@google.com>
Subject: [PATCH v6 04/37] scripts/kallysms: Always include __start and __stop symbols
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jMVp7wgy;       spf=pass
 (google.com: domain of 3pml8zqykcsszbyluinvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3PmL8ZQYKCSsZbYLUINVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--surenb.bounces.google.com;
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
Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
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
2.44.0.291.gc1ea87d7ee-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240321163705.3067592-5-surenb%40google.com.
