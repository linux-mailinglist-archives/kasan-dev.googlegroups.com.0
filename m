Return-Path: <kasan-dev+bncBC7OD3FKWUERBEO6X6RAMGQE7NMFVQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id EA5516F33D8
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:46 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id ada2fe7eead31-42dd4ad1590sf397044137.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960146; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wqd4aKlKv9l51ET6V6GBOCPbrLuPHrWDySKdZ/jwP8VpfzBudllstcCGgL6A2xE6rM
         uxVOLw7NWn8txX/rre5/e1OgdU4kjqmJ7OmhT8tECl2Bc2vM+iMuxay3Broley3yB79U
         Zz23xx+anAsQSst+jG+iIyU4+zp/LN0h58M76nLDSX6eGaS7yAzZ866nO4FIiZU2MW/7
         HKDiyEzAhRc7LN960UFjs7Rlx7b+/rT1qiYjVEQyIwqdpfXOkrJmLTJpabg3HLUUdevL
         z8M+AYmkc8fKzvw8kMV0NSsXxzX0jZ30D2SU2aMxOJL1gfIw7RTWqX97i5Tp57r0BSCj
         jGDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LItKGITBI0FJhpcNaB7NGDtVAGDCbHYl8//exZH7AJw=;
        b=Bqdh78tCNP9s0xpprM9nJf9ejlRaqyn5fkhXHCfPX1kM68d49uAp+OooVd6NAkQhZk
         wFqJ0oDyfxWTwyuoMlCHXB+ar1f5ysnrvgMPQzyXXHwkxZvEeVoMR7mHQeiHyFga2l8R
         8+gO6nRHU+V7dF7ost+gsdj/j5bOogtkn7iQ+gtX7/i8YKSizspk9sFT/o5kvDGoF537
         WAxZuZgWKWDyxEV5GeSHwt9DAXx/yKzQBxq0mUAoLbnn66XfXJGWEOMQQz6WtWpXVUc9
         LVnh7cD1KI70ZaH1uvPZ8rCDUn6rhLROlxpFdcbarVhNSyoSe5ZgtfD2Pet71Dsr/HDA
         cfeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=7DF+QMYA;
       spf=pass (google.com: domain of 3eo9pzaykcvchjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EO9PZAYKCVcHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960146; x=1685552146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LItKGITBI0FJhpcNaB7NGDtVAGDCbHYl8//exZH7AJw=;
        b=g5CvLXDSC20o7joc58MEoMQnAcG3I0tN9ycQ8Ch1JQ8J3nSeAZSWKMq5OdgClud4Zm
         a/G1ak4TYGp0zEKzhGxp5uo/empVQxicTTt5PFUiFXJzjDx0kG5Wiof0UW5qgTqfe/Pb
         Bdq1pHjVyd8V0T58AU+QpgZOn5Yo3EtlN01xSd/zexXF56Wjh8wBQeYT6SvZT2MCQE2v
         P7t4AeyogbxrprpMAr9uXtxZf97YWcXJTpDWZ1bH9LkWEhKRg8Xsa1uZk1OVkXBOLy/9
         o3DlbTvvSrgdee9Ejwb2pLuqPtoq+AnpVctOcBteTG4SieUhezDU7f+fiVZCxaEFtzJs
         rSoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960146; x=1685552146;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LItKGITBI0FJhpcNaB7NGDtVAGDCbHYl8//exZH7AJw=;
        b=BOASUbZJREZI61pJCds7Cd2WbJEB3UdllVgaBn85Bmqd4bdZhQm1NB3/YQYK621LTC
         wN5MIEX3EWtxERkZnsqkbhOPQlIL/sBPWiGtV/COy7Z2Vtqgb14txVOB5OsG+jasmLSe
         b40rTfOBsz7UKZ1IpKQbPKOqtX/HJI/jCHo2c38Gfx/M+XmcvTbg2XWzPk2KcewHl+U7
         hkRDJBhl2VF4GejEFiAqnvhWEircUbteXPcP6ZzQ9yDGvCnr6GHxx0OA/QcNtvoPB0Ze
         6/Y04k+oOGW8oW1nacshUDjY1p5FSSTAZNkWraZy4iq51wCeRn9ghEwe3lvI+3nKwyS/
         oF0g==
X-Gm-Message-State: AC+VfDwcRtusNQHt9uVgBzoBZqDxRcYN416rRrflQTbYM02fROIS6QMB
	Is2DBwAnZHbcGiguJuCND+E=
X-Google-Smtp-Source: ACHHUZ78oPw06FyIBUgd/1jQd8Gi8sbcCnygmGpyxjFVrAvZrWYkVRubc58SjcZ2t6q6K7ZIQZQHxg==
X-Received: by 2002:a67:e19b:0:b0:42c:8d9c:80d3 with SMTP id e27-20020a67e19b000000b0042c8d9c80d3mr6844056vsl.0.1682960145965;
        Mon, 01 May 2023 09:55:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6122:d88:b0:43c:4909:450 with SMTP id
 bc8-20020a0561220d8800b0043c49090450ls1219093vkb.9.-pod-prod-gmail; Mon, 01
 May 2023 09:55:45 -0700 (PDT)
X-Received: by 2002:a1f:4944:0:b0:43f:c650:acae with SMTP id w65-20020a1f4944000000b0043fc650acaemr4885075vka.16.1682960145320;
        Mon, 01 May 2023 09:55:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960145; cv=none;
        d=google.com; s=arc-20160816;
        b=IKE4FGPevqVscRKprQFqIYFTZqiCu7I2TNDw1Np5dpNrm6ac6JzhO+fQtz1Jqi0k+G
         mrtqLlPXvyS+1fc3eVG7UGlRKW8Y8L2sbwXoafPlkTsXwWWZ8JlujLaNu82iIzjJnOtd
         xIf3d7LMDtLM1th+Cu+Qv6MZpHpUKzwvzW/1kfEt4q3r9Fc2uDSkqAQxKbt4fd9DjScr
         RdufPW4kr3b4XF3AzbmMEIQmMOM8BsNyyrdPKV519gk3ebaCq6qA5/W5RE16jXNjTl7u
         Qw3SXL289A5xZF3SMtZMqbcqGZ3aZt881CYJwwBXP28iMioBvYmXk8xqf1oI2oNDZBS8
         Iysw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cfU8v4uljuDyceCulpsszZZ0MEofJFrAynDM4I2qv80=;
        b=IlSZaYVGNDbCpggy55xDZgrHllOBp3gQSG1MwWq9x4o39Sq2CjKmYR4rX2umKpTp4B
         OPyEfrXPgl5Z7Cf09U7QF+RYiR/W99tyxI1Nr6YoZbCbetY+BkpiiG5QtyvruTev0U4g
         SmVaQt6k6Gt6wFR/6tkfHBB7Do+HotwKc5LSylv11to/qYOq1fDTSw5Exs4CPm/Rj9vg
         gaYEWANEI4PdqMMJKpf5WTUP0l5a3ScYXgQgrw8vwz9h3P4fmdkFhaxLvNbC932jtbia
         pMvHdBEAK74cfPGKSnskZXqC8Qc3j3hq/z2YE2MYOmjyrkmPLPIZEmFX7Qp2TTKYcT4r
         kByQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=7DF+QMYA;
       spf=pass (google.com: domain of 3eo9pzaykcvchjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EO9PZAYKCVcHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id bc35-20020a0561220da300b004409ac628a3si23668vkb.5.2023.05.01.09.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3eo9pzaykcvchjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 3f1490d57ef6-b9a6eeea78cso27814711276.0
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:45 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a25:3482:0:b0:b94:6989:7fa6 with SMTP id
 b124-20020a253482000000b00b9469897fa6mr8599498yba.4.1682960144921; Mon, 01
 May 2023 09:55:44 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:26 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-17-surenb@google.com>
Subject: [PATCH 16/40] lib: code tagging query helper functions
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
 header.i=@google.com header.s=20221208 header.b=7DF+QMYA;       spf=pass
 (google.com: domain of 3eo9pzaykcvchjg3c05dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3EO9PZAYKCVcHJG3C05DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--surenb.bounces.google.com;
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

Provide codetag_query_parse() to parse codetag queries and
codetag_matches_query() to check if the query affects a given codetag.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/codetag.h |  27 ++++++++
 lib/codetag.c           | 135 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 162 insertions(+)

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index d98e4c8e86f0..87207f199ac9 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -80,4 +80,31 @@ static inline void codetag_load_module(struct module *mod) {}
 static inline bool codetag_unload_module(struct module *mod) { return true; }
 #endif
 
+/* Codetag query parsing */
+
+struct codetag_query {
+	const char	*filename;
+	const char	*module;
+	const char	*function;
+	const char	*class;
+	unsigned int	first_line, last_line;
+	unsigned int	first_index, last_index;
+	unsigned int	cur_index;
+
+	bool		match_line:1;
+	bool		match_index:1;
+
+	unsigned int	set_enabled:1;
+	unsigned int	enabled:2;
+
+	unsigned int	set_frequency:1;
+	unsigned int	frequency;
+};
+
+char *codetag_query_parse(struct codetag_query *q, char *buf);
+bool codetag_matches_query(struct codetag_query *q,
+			   const struct codetag *ct,
+			   const struct codetag_module *mod,
+			   const char *class);
+
 #endif /* _LINUX_CODETAG_H */
diff --git a/lib/codetag.c b/lib/codetag.c
index 0ad4ea66c769..84f90f3b922c 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -256,3 +256,138 @@ bool codetag_unload_module(struct module *mod)
 
 	return unload_ok;
 }
+
+/* Codetag query parsing */
+
+#define CODETAG_QUERY_TOKENS()	\
+	x(func)			\
+	x(file)			\
+	x(line)			\
+	x(module)		\
+	x(class)		\
+	x(index)
+
+enum tokens {
+#define x(name)		TOK_##name,
+	CODETAG_QUERY_TOKENS()
+#undef x
+};
+
+static const char * const token_strs[] = {
+#define x(name)		#name,
+	CODETAG_QUERY_TOKENS()
+#undef x
+	NULL
+};
+
+static int parse_range(char *str, unsigned int *first, unsigned int *last)
+{
+	char *first_str = str;
+	char *last_str = strchr(first_str, '-');
+
+	if (last_str)
+		*last_str++ = '\0';
+
+	if (kstrtouint(first_str, 10, first))
+		return -EINVAL;
+
+	if (!last_str)
+		*last = *first;
+	else if (kstrtouint(last_str, 10, last))
+		return -EINVAL;
+
+	return 0;
+}
+
+char *codetag_query_parse(struct codetag_query *q, char *buf)
+{
+	while (1) {
+		char *p = buf;
+		char *str1 = strsep_no_empty(&p, " \t\r\n");
+		char *str2 = strsep_no_empty(&p, " \t\r\n");
+		int ret, token;
+
+		if (!str1 || !str2)
+			break;
+
+		token = match_string(token_strs, ARRAY_SIZE(token_strs), str1);
+		if (token < 0)
+			break;
+
+		switch (token) {
+		case TOK_func:
+			q->function = str2;
+			break;
+		case TOK_file:
+			q->filename = str2;
+			break;
+		case TOK_line:
+			ret = parse_range(str2, &q->first_line, &q->last_line);
+			if (ret)
+				return ERR_PTR(ret);
+			q->match_line = true;
+			break;
+		case TOK_module:
+			q->module = str2;
+			break;
+		case TOK_class:
+			q->class = str2;
+			break;
+		case TOK_index:
+			ret = parse_range(str2, &q->first_index, &q->last_index);
+			if (ret)
+				return ERR_PTR(ret);
+			q->match_index = true;
+			break;
+		}
+
+		buf = p;
+	}
+
+	return buf;
+}
+
+bool codetag_matches_query(struct codetag_query *q,
+			   const struct codetag *ct,
+			   const struct codetag_module *mod,
+			   const char *class)
+{
+	size_t classlen = q->class ? strlen(q->class) : 0;
+
+	if (q->module &&
+	    (!mod->mod ||
+	     strcmp(q->module, ct->modname)))
+		return false;
+
+	if (q->filename &&
+	    strcmp(q->filename, ct->filename) &&
+	    strcmp(q->filename, kbasename(ct->filename)))
+		return false;
+
+	if (q->function &&
+	    strcmp(q->function, ct->function))
+		return false;
+
+	/* match against the line number range */
+	if (q->match_line &&
+	    (ct->lineno < q->first_line ||
+	     ct->lineno > q->last_line))
+		return false;
+
+	/* match against the class */
+	if (classlen &&
+	    (strncmp(q->class, class, classlen) ||
+	     (class[classlen] && class[classlen] != ':')))
+		return false;
+
+	/* match against the fault index */
+	if (q->match_index &&
+	    (q->cur_index < q->first_index ||
+	     q->cur_index > q->last_index)) {
+		q->cur_index++;
+		return false;
+	}
+
+	q->cur_index++;
+	return true;
+}
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-17-surenb%40google.com.
