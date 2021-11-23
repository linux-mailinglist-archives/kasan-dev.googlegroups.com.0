Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK5B6OGAMGQEH54P5UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7A7745A180
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 12:29:47 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 138-20020a1c0090000000b00338bb803204sf7547024wma.1
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 03:29:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637666987; cv=pass;
        d=google.com; s=arc-20160816;
        b=cPSXWjIYoN2+oeDZZ44FxDbqvHXfbNB2qlLuRQpuaCGFvORiREyAnlypk17FGKq9Sq
         1/da+I7QlXEfIbKJ43fJeZvd3rCbbM5OyOqbe/LmpoHxTb5m3FfuAKVlsoGGg6SGAu9g
         saNuywqB2rZf5C90FStXwCaVq8F4G3VbhSWG5lKwr+a503VqWGBlxcTlRPFVL0037kVD
         OQh5NBrwYXOS/fe1qHcm5APUlxTgJBJMWeMGVOOlTUWFZhFiVfYYoXw5vQdX5pvlALaQ
         vTabD4E11KbXzEwXPo4QaMlsFR35WL1QuGWUTYfIihrHyvrjkRy+D2wrKyEfZxdTCHJc
         ZTcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=hjEHZoTOP4PwEQl04x8mpjhvItdPdbRKlkFNEvkM0ZE=;
        b=nmSN6qd/6g4b3j+GXJQR/CVVL7Se6q20REV5lbfVmH1UwvPFG76oz6WQ1rdh/XZGsu
         N6GF+SbpE8d4ZuB/VIJ15wQuy6UXbqnF8c5przYIGEL3yZY3W9P1FOdb3RDgboaxkr7i
         1TmXKnsp9cEM29+7tjZDuPHXfKXiWd52JB+d+9uyOveffnePsoNBfwAcO0GGu1h7Yi8S
         HF/SxOG672l4AW3zo4VDVi2t15lkSj3y9klB4o/WkZQaYPo5QhzIOGPPHUTs/fFYAkXT
         mLOCEo4EIwJyapLp5FM1CxWyzTbeca+4txBK0Xr2ADZMSKToPZG6bSlAbWHwTOSgQPla
         OIIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iORsK4eh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=hjEHZoTOP4PwEQl04x8mpjhvItdPdbRKlkFNEvkM0ZE=;
        b=EJrfO6qTuaGaMb4JtZGZ0rfBm9bCjxiCJ5G7V/XhaL1I5bKepyfsHNLvBe+dRVif6p
         6fgNgzZyj57NjvC0OPtGYoMbM2taITNxiiIe1BHtdkauytXCFck+MAazSZIJ59cGAYm+
         J91vzI0CQA59enbyomDBgs1fL2/QzK3ogIXFAY0pMnx+iETHsex38Rev5aotQLiCpXHQ
         2qrLso062dyQG4nSWwbMDcAWgunZGh42jmGyC53A/KYecAtPUp3HQCdeow5lUQyvxCzz
         BEJYWsvZhKndW6EtnfrkGLUBVeTMsm49hPMt/ywpvX4STuComEzOb3n/F//+5l+bykef
         fihQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hjEHZoTOP4PwEQl04x8mpjhvItdPdbRKlkFNEvkM0ZE=;
        b=h2jw30c2Uh8pnicQi7TeKdUDu7FuvbGUDSVaxInYVTTJ3dy8nKY4re6BpMDGxfo/Xr
         +dGp5ycCNgScldK1SI6UhX36o8SmmTeBNUwK9JJSCamsAmKQi87TylB0ddhqgTXfRPJa
         CBiig7k5zFx9hHeWcl0oCaHaMW/cYrPbihEl9FRi5n8M18ZIFkG+xGfRha8eidKlv/Tq
         9WwtnMevjZtBRyFu9PXGd5rTLeUk9tS7Cy15BOmAPgRtpeKfs0RLTiTMeAkZbCDroslL
         +iLYm68CKqK4Zwjwsrkh9CQxquQATO6tr+dLYvB24dAAej3uBTevp5V3vxIfqYQ/D6eq
         QTfg==
X-Gm-Message-State: AOAM532uTETlT6j59YmOa/5BnwzdHJFRtdPm0Nh/kuE73/bqLb3Ys6bm
	seESmY7yc6gY/Hsmn/k9+ic=
X-Google-Smtp-Source: ABdhPJxbx/r+Qq97O2ugDkBXmuBYoeoStlwR5KSvsptcniTklfPetYaGBh2+59YrZcsYyFyY/ZWQzw==
X-Received: by 2002:adf:f6cf:: with SMTP id y15mr6773524wrp.56.1637666987470;
        Tue, 23 Nov 2021 03:29:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f1c2:: with SMTP id z2ls2808778wro.2.gmail; Tue, 23 Nov
 2021 03:29:46 -0800 (PST)
X-Received: by 2002:a5d:4d51:: with SMTP id a17mr6179028wru.384.1637666986415;
        Tue, 23 Nov 2021 03:29:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637666986; cv=none;
        d=google.com; s=arc-20160816;
        b=wMwi1N7SXZvZLxdLubU9NERXOse09dXMP9OeWRgsVOhNkV+97znpeBt4P9s05gspwa
         STonTvz5ypCXQIBgWnDTOo5C4vNnki9oztPFRNLmos5B5pbvKDbKtP+PguA5C5ruHkJz
         S3kvSBx2pHDnDVv5IyRy1PLmF71xhQRB5Jlg4QAu2oEh87dTH60Jfwp14Onsed0J/CYk
         ljpXgZJoUBQ8pmB905VohciL4MxGXrvjiblLMggx9sqClOm9mbyaz0YvmmICCvPo/Y9o
         r+eMHc+tRgxD3uqP21Y6lF/pIvXxPxccTenEP8s3QlJl6kBr4PEJ1kR0V/4DGBPIgQni
         SazQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RCz+vh2bGRc6vOt1cmcyty/tcvje22f5Ps81nyvaJl8=;
        b=pZhKI2lPkJldzZJoUkL960jxJJIUcHqVQ/HJIPFwIdJajxtNLjTpBs9qoE3ElKwjXT
         MXve53pU1Njai5IW8Bhm+0wvbFH8P0+jQN1Zi5SWYE8MXMzAgPh8fX+1Op2VGFYxCs4U
         2y4H6vqvUcDSx2o8LlfILBAwv/0BDsXXxVEkLuIrWsDSqSqbeIlG0cde5T4fUolKh0Ph
         YAwYE/0ZDXrx6w952/nZX1HZgO2N78B0PGOMc0wQHWHVFsg+Zx+mXkB4n0OoYWoyUtwT
         0SyPrnOrFv4nGml7zSIB+5BmfN+wq3q/dE6euovsGQJkQgWBKrvftLTkxSTjpGhWN2po
         NZ0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=iORsK4eh;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32f.google.com (mail-wm1-x32f.google.com. [2a00:1450:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id p5si125735wru.1.2021.11.23.03.29.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Nov 2021 03:29:46 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as permitted sender) client-ip=2a00:1450:4864:20::32f;
Received: by mail-wm1-x32f.google.com with SMTP id 77-20020a1c0450000000b0033123de3425so1958513wme.0
        for <kasan-dev@googlegroups.com>; Tue, 23 Nov 2021 03:29:46 -0800 (PST)
X-Received: by 2002:a05:600c:1c20:: with SMTP id j32mr2110302wms.1.1637666985890;
        Tue, 23 Nov 2021 03:29:45 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:1444:3668:5c57:85cc])
        by smtp.gmail.com with ESMTPSA id k27sm1041180wms.41.2021.11.23.03.29.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 Nov 2021 03:29:44 -0800 (PST)
Date: Tue, 23 Nov 2021 12:29:39 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Josh Poimboeuf <jpoimboe@redhat.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Boqun Feng <boqun.feng@gmail.com>, Borislav Petkov <bp@alien8.de>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH v2 23/23] objtool, kcsan: Remove memory barrier
 instrumentation from noinstr
Message-ID: <YZzQoz0e/oiutuq5@elver.google.com>
References: <20211118081027.3175699-1-elver@google.com>
 <20211118081027.3175699-24-elver@google.com>
 <20211119203135.clplwzh3hyo5xddg@treble>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211119203135.clplwzh3hyo5xddg@treble>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=iORsK4eh;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Nov 19, 2021 at 12:31PM -0800, Josh Poimboeuf wrote:
> On Thu, Nov 18, 2021 at 09:10:27AM +0100, Marco Elver wrote:
[...]
> > +	if (insn->sec->noinstr && sym->removable_instr) {
[...]
> I'd love to have a clearer name than 'removable_instr', though I'm
> having trouble coming up with something.
[...]

I now have the below as v3 of this patch. The naming isn't entirely
obvious, but coming up with a short name for this is tricky, but
hopefully the comments make it clear. We can of course still pick
another name.

Does that look reasonable?

Note, I'd like this series to sit in -next for a while (probably from
some time next week after sending v3 if there are no further
complaints). By default everything will be picked up by the -rcu tree,
and we're targeting Linux 5.18.

If you feel there might be objtool conflicts coming, this patch could be
taken through another tree as there are no hard dependencies, as long as
this patch reaches mainline before or with the rest.

Thanks,
-- Marco

------ >8 ------

From: Marco Elver <elver@google.com>
Date: Mon, 9 Aug 2021 12:11:14 +0200
Subject: [PATCH] objtool, kcsan: Remove memory barrier instrumentation from
 noinstr

Teach objtool to turn instrumentation required for memory barrier
modeling into nops in noinstr text.

The __tsan_func_entry/exit calls are still emitted by compilers even
with the __no_sanitize_thread attribute. The memory barrier
instrumentation will be inserted explicitly (without compiler help), and
thus needs to also explicitly be removed.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* s/removable_instr/profiling_func/ (suggested by Josh Poimboeuf)
* Fix and add more comments.

v2:
* Rewrite after rebase to v5.16-rc1.
---
 tools/objtool/check.c               | 41 ++++++++++++++++++++++++-----
 tools/objtool/include/objtool/elf.h |  2 +-
 2 files changed, 36 insertions(+), 7 deletions(-)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 61dfb66b30b6..a78186c583f4 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1072,11 +1072,11 @@ static void annotate_call_site(struct objtool_file *file,
 	}
 
 	/*
-	 * Many compilers cannot disable KCOV with a function attribute
-	 * so they need a little help, NOP out any KCOV calls from noinstr
-	 * text.
+	 * Many compilers cannot disable KCOV or sanitizer calls with a function
+	 * attribute so they need a little help, NOP out any such calls from
+	 * noinstr text.
 	 */
-	if (insn->sec->noinstr && sym->kcov) {
+	if (insn->sec->noinstr && sym->profiling_func) {
 		if (reloc) {
 			reloc->type = R_NONE;
 			elf_write_reloc(file->elf, reloc);
@@ -1991,6 +1991,35 @@ static int read_intra_function_calls(struct objtool_file *file)
 	return 0;
 }
 
+/*
+ * Return true if name matches an instrumentation function, where calls to that
+ * function from noinstr code can safely be removed, but compilers won't do so.
+ */
+static bool is_profiling_func(const char *name)
+{
+	/*
+	 * Many compilers cannot disable KCOV with a function attribute.
+	 */
+	if (!strncmp(name, "__sanitizer_cov_", 16))
+		return true;
+
+	/*
+	 * Compilers currently do not remove __tsan_func_entry/exit with the
+	 * __no_sanitize_thread attribute, remove them.
+	 *
+	 * Memory barrier instrumentation is not emitted by the compiler, but
+	 * inserted explicitly, so we need to also remove them.
+	 */
+	if (!strncmp(name, "__tsan_func_", 12) ||
+	    !strcmp(name, "__kcsan_mb") ||
+	    !strcmp(name, "__kcsan_wmb") ||
+	    !strcmp(name, "__kcsan_rmb") ||
+	    !strcmp(name, "__kcsan_release"))
+		return true;
+
+	return false;
+}
+
 static int classify_symbols(struct objtool_file *file)
 {
 	struct section *sec;
@@ -2011,8 +2040,8 @@ static int classify_symbols(struct objtool_file *file)
 			if (!strcmp(func->name, "__fentry__"))
 				func->fentry = true;
 
-			if (!strncmp(func->name, "__sanitizer_cov_", 16))
-				func->kcov = true;
+			if (is_profiling_func(func->name))
+				func->profiling_func = true;
 		}
 	}
 
diff --git a/tools/objtool/include/objtool/elf.h b/tools/objtool/include/objtool/elf.h
index cdc739fa9a6f..d22336781401 100644
--- a/tools/objtool/include/objtool/elf.h
+++ b/tools/objtool/include/objtool/elf.h
@@ -58,7 +58,7 @@ struct symbol {
 	u8 static_call_tramp : 1;
 	u8 retpoline_thunk   : 1;
 	u8 fentry            : 1;
-	u8 kcov              : 1;
+	u8 profiling_func    : 1;
 	struct list_head pv_target;
 };
 
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZzQoz0e/oiutuq5%40elver.google.com.
