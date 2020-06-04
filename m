Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLUX4T3AKGQEXCIQGRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id A927A1EE70F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 16:56:47 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id d145sf4743619qkg.22
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jun 2020 07:56:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591282606; cv=pass;
        d=google.com; s=arc-20160816;
        b=QkrcV+fv9VVcZA/Vt0MH8vFzHfy+97YGXXPjCj5Lur6DtLjDdzMM2Q4RWaPOypj1/n
         YlfWSvHwkdg3xQePnTsCN6eOWdkAipcERasuhM6MPspQUlG8iMUMYZ293fq/se9STcsr
         G0g5q7i0wbzaRtLFadObfZha1N8saphuImmVJZ3paALwDOlQ9pUC6c8do3wbh6EsnnpC
         y9BSW8Ahfy0+iw0bsLbTiwQ41w+rIdvLBk/vGp+mrUWIRcJqJsAPg0tKsidw7vF/uVP7
         Gg39LtRbrWSUtlEifsUOdLNDNifxor7K9OLVN06N8eM9f9e8mZosiSBPcnoUqWkLS69k
         OWMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=zmav7cMLZPBmB5KgTwdkueJtOVKldA93kG7MeVAfXlE=;
        b=dC5osyGRdMTWXOrGz7jDrIk0rbr0c9OJUN7vtRt0Sgj6MwHmy5YRxFi39biOMLJMj6
         PGn5jjQet8OpRq/0YPHVV3EN5LiwJznQA77JwxfA6BC/kwnpdOODCubTYsz3uwCNF0Je
         v6TKf/HVC8HIzkipCGuSveTKKjxAcljGwfIMlItpkxr1dZ7DMgoZEaaEhjljzfVp3KcX
         c0RuUvH5UrgJ6k1mEj73VQFRQAf++4MAVNWBfx79FzqbNwJ1N5GlriPShSVo7B2ZMbGn
         0hk3k0PHiqD3EyFFkgsQb5H9K1GeB15nDHIWHiYV5YDei2yxFwnXlPxG60FeLI0GLiog
         KE5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WdAR16zY;
       spf=pass (google.com: domain of 3rqvzxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rQvZXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zmav7cMLZPBmB5KgTwdkueJtOVKldA93kG7MeVAfXlE=;
        b=idCaS0yT9lfpR03nrg3D23/xe+H8vJgdu5hk710k4+VyxH9qVXG5vz5Yn3GrPx4fMl
         7UJEbe0AxekBZ97c7w2kJqEZjBczo12nGIL8O5/9uTyE/DNEnzlvAxislLm1RXBaS0MK
         gIHTZc2NZBUYjHTu0kwYvA3hiHkeZnT7C0vRFv/qiye21M1XYVQj0A8XfyaBWhXMS2hB
         IhbPLlzfueqBJSvB6xXMlSwI8OBKwcg+JW7+wiA9BwLyhY0OniEjlmfqJdTMm6T9OGGl
         YJtsHJms0ZGbK2xblsu6f14HlcBJu9AjOnkzFzDI1ii6b/++D49LJnA5dxmPG5LgDpbx
         /2Qg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zmav7cMLZPBmB5KgTwdkueJtOVKldA93kG7MeVAfXlE=;
        b=HTsXzlh6IXFCvfD2V1HoCtllYXTVoxMAuI9XOK6Wvfjir2HpeEj/ZU47cls40n2trM
         1BFNPSaTMWBv8M304ipeBmLgLQ8K6O28a5SK5lWSG7HoA+f7/TU+ph7cjE4mlOT8/SEi
         EWR1m8ehPdNYK1Lq5NriEOPscTer3KJyFGFXWEvO9lurAuz5CAFy/SDNV2OKL4nAr+6q
         rX5UQOPKh1MgDZkCJP0hHdIvNvp2JZDC5FptqlBwRfqj+D13i0H10SPRN0PHI98VC5JK
         iZup/0XmVucpxbUyCmjc2Pa4qjVRY1UQiEnetMNpBlwiyHywA3BDImd/ghdXtmHeAWq3
         aeTQ==
X-Gm-Message-State: AOAM530cWWViSQRoFsQkukIohfX0C2WgMotJTDgh28oX7mxihT1t8Q7+
	Ba9iHqfS0QirAlbg6vJ2EDw=
X-Google-Smtp-Source: ABdhPJyRar4BO+aCfDjDWIMYLHADU2zRtbmcMLU2FjuEDldIsaDCiuxnojQzqUQkibQJamgGPYltIQ==
X-Received: by 2002:a37:a89:: with SMTP id 131mr4965476qkk.92.1591282606739;
        Thu, 04 Jun 2020 07:56:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:2978:: with SMTP id z53ls1996723qtz.1.gmail; Thu, 04 Jun
 2020 07:56:46 -0700 (PDT)
X-Received: by 2002:ac8:842:: with SMTP id x2mr4830226qth.233.1591282606364;
        Thu, 04 Jun 2020 07:56:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591282606; cv=none;
        d=google.com; s=arc-20160816;
        b=rc4EQz2FV0nmO1yb+Xv4BP0gK47E7sZ4lXK3rnU8ad5YItnP7UZbvS+qk369/T6vJ4
         rKMJBJbI0VQQPsIkpcq/7IZXfCVY5mC2B8Z3jk6ygX4YNyhKcHg5aMHCH7VIGymlIzw7
         JBxkrusGQe+S9txv/yaOR+s3Sk5GJsg0eCZefv1BCRTN74QfFoHbJXCS1d1vQY9I5+jo
         +/pwaaU+cPUjiPKhasIs8rSBlGSWigap6FlxbZ5q1DNY3AR3mh2KJMEygCrxCoHgAA6r
         uAJOymwq4/QPcHxosfbdYxqtHKfWwCq0tEy/xVmvHMqK1iAcmVq3wlZCPgCew/Jy5a3P
         NiKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=I7c54UO+jBDB8Mu0xGlRZFnGkQOtoIXkr80oIo5a6yg=;
        b=MEJ3rVktTe3iA18IQf42jHFpHINj7l3r3MAvFtermtzij/v4JAKvVBgTbTOLPEgQ0k
         R/2BLnGkD8yB+wBL4jRdvj42hYJKI8pqkwHf/C3NJlTwHuBh7Q5zinHZjRvsL6lcMEwe
         5XXLKaDa4ORIzCxsHFXOzrEHF31W972iPStgMdXFDFRw6Jtb4q4wgVeKlBISRgY+sN5+
         CJ7B36H4oMSmWFvWaVDl5ZzRmeztC+whz86retYpN2RhDFmS2bFpwMcv/fN5J2Y5MSkf
         Ahr8dFLgySFUZi3bjYjIbCIz+DXSjctcN5AYi8kJeN7Ih1ZsCLPJ8koqdIq8JIx2RAcp
         NQ7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WdAR16zY;
       spf=pass (google.com: domain of 3rqvzxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rQvZXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id d64si294238qkb.0.2020.06.04.07.56.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Jun 2020 07:56:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rqvzxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id l6so4776858qkk.14
        for <kasan-dev@googlegroups.com>; Thu, 04 Jun 2020 07:56:46 -0700 (PDT)
X-Received: by 2002:ad4:556b:: with SMTP id w11mr5001166qvy.171.1591282605967;
 Thu, 04 Jun 2020 07:56:45 -0700 (PDT)
Date: Thu,  4 Jun 2020 16:56:34 +0200
Message-Id: <20200604145635.21565-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH v2 1/2] kcov, objtool: Make runtime functions noinstr-compatible
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, mingo@kernel.org, 
	clang-built-linux@googlegroups.com, paulmck@kernel.org, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WdAR16zY;       spf=pass
 (google.com: domain of 3rqvzxgukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rQvZXgUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

While we lack a compiler attribute to add to noinstr that would disable
KCOV, make the KCOV runtime functions return if the caller is in a
noinstr section. We then whitelist __sanitizer_cov_*() functions in
objtool. __sanitizer_cov_*() cannot safely become safe noinstr functions
as-is, as they may fault due to accesses to vmalloc's memory.

Declare write_comp_data() as __always_inline to ensure it is inlined,
and reduce stack usage and remove one extra call from the fast-path.

In future, our compilers may provide an attribute to implement
__no_sanitize_coverage, which can then be added to noinstr, and the
checks added in this patch can be guarded by an #ifdef checking if the
compiler has such an attribute or not.

Signed-off-by: Marco Elver <elver@google.com>
---
Apply after:
https://lkml.kernel.org/r/20200604102241.466509982@infradead.org

v2:
* Rewrite based on Peter's and Andrey's feedback -- v1 worked because we
  got lucky. Let's not rely on luck, as it will be difficult to ensure the
  same conditions remain true in future.

v1: https://lkml.kernel.org/r/20200604095057.259452-1-elver@google.com

Note: There are a set of KCOV patches from Andrey in -next:
https://lkml.kernel.org/r/cover.1585233617.git.andreyknvl@google.com --
Git cleanly merges this patch with those patches, and no merge conflict
is expected.
---
 kernel/kcov.c         | 19 +++++++++++++++++--
 tools/objtool/check.c |  7 +++++++
 2 files changed, 24 insertions(+), 2 deletions(-)

diff --git a/kernel/kcov.c b/kernel/kcov.c
index 8accc9722a81..3329a0fdb868 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -24,6 +24,7 @@
 #include <linux/refcount.h>
 #include <linux/log2.h>
 #include <asm/setup.h>
+#include <asm/sections.h>
 
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
@@ -172,6 +173,12 @@ static notrace unsigned long canonicalize_ip(unsigned long ip)
 	return ip;
 }
 
+static __always_inline bool in_noinstr_section(unsigned long ip)
+{
+	return (unsigned long)__noinstr_text_start <= ip &&
+	       ip < (unsigned long)__noinstr_text_end;
+}
+
 /*
  * Entry point from instrumented code.
  * This is called once per basic-block/edge.
@@ -180,13 +187,18 @@ void notrace __sanitizer_cov_trace_pc(void)
 {
 	struct task_struct *t;
 	unsigned long *area;
-	unsigned long ip = canonicalize_ip(_RET_IP_);
+	unsigned long ip;
 	unsigned long pos;
 
+	if (unlikely(in_noinstr_section(_RET_IP_)))
+		return;
+
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
 		return;
 
+	ip = canonicalize_ip(_RET_IP_);
+
 	area = t->kcov_area;
 	/* The first 64-bit word is the number of subsequent PCs. */
 	pos = READ_ONCE(area[0]) + 1;
@@ -198,12 +210,15 @@ void notrace __sanitizer_cov_trace_pc(void)
 EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
 
 #ifdef CONFIG_KCOV_ENABLE_COMPARISONS
-static void notrace write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
+static __always_inline void write_comp_data(u64 type, u64 arg1, u64 arg2, u64 ip)
 {
 	struct task_struct *t;
 	u64 *area;
 	u64 count, start_index, end_pos, max_pos;
 
+	if (unlikely(in_noinstr_section(ip)))
+		return;
+
 	t = current;
 	if (!check_kcov_mode(KCOV_MODE_TRACE_CMP, t))
 		return;
diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 3e214f879ada..cb208959f560 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -2213,6 +2213,13 @@ static inline bool noinstr_call_dest(struct symbol *func)
 	if (!strncmp(func->name, "__ubsan_handle_", 15))
 		return true;
 
+	/*
+	 * The __sanitizer_cov_*() calls include a check if the caller is in the
+	 * noinstr section, and simply return if that is the case.
+	 */
+	if (!strncmp(func->name, "__sanitizer_cov_", 16))
+		return true;
+
 	return false;
 }
 
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604145635.21565-1-elver%40google.com.
