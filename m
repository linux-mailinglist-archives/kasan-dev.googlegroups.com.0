Return-Path: <kasan-dev+bncBC7OD3FKWUERBFEMXKMAMGQECC7Q3EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 20A9E5A6FA0
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 23:50:19 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id p123-20020a6bbf81000000b00674f66cf13asf7571016iof.23
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Aug 2022 14:50:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661896212; cv=pass;
        d=google.com; s=arc-20160816;
        b=ASkTRu22IgAWHXipCutJ2LuvUaihXGO5EDZIPKfJxqJjK+3ORPGn2v4BuIkVGRM5Ma
         Taq7th/G366Ylh9Ukqva7vZDKM79XFRPhnijDuCImntcxwu5lpYO5NBIRgx4/urAZZmo
         9HcJLmFPT+9V9quAAlq+bbmD6o7RFlmnilKnZ5O6vKZJqQoK+YvQUOjd67xo18335e/o
         vV0vX3fxcfTsNrwFyzw4ewz1XFSUSKa6MJEHu2Mr2Y7xQcmdWbNZISDgBZdtiTTDAdwQ
         4QeU4h3U7Cqku6ACG/4eRoyFDPFrrP1OjgNF0FDkxTFjPmlzsJ/CK9mhZi8Le7qDGySN
         McAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=hyIPYmpiXNC37BnAHtlaWmee7T/xPHQp05LH3vUG1Ro=;
        b=yo7O9nMVMZvIcvTUpNtCinY9Y4cK1ic08E+IpHrGOn+ZSQl7bZ2Wjq3VxLoYhvUz3f
         WvpsCz5avDlamzSFF8khfkLm5YqMywCzuCkiqu/06hCmYTR3skeIjPcyqjgXi5LuRFlR
         lSQQjM6WuiTen4P3/bSpJcHLb3mERZKByCFt3llW0meghoVTqDI/UJRBEb5yXK1aDRW5
         3DB5IYW/Q9wRWFVM1NqvGMuoIEYhBgZ+MspOTAadGf3hicuMm5ZWw2L9g7ug9Xn3doQO
         f2iANG6Qz63R/POH7OtD2ncO3PnqbBEW/hf2T1GI4aBuViRHCdXI/5OqoAOOPhrqnmIi
         RA5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="VGRf/84i";
       spf=pass (google.com: domain of 3e4yoywykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E4YOYwYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc;
        bh=hyIPYmpiXNC37BnAHtlaWmee7T/xPHQp05LH3vUG1Ro=;
        b=Ko3T56eMrlFd4rPIKFeN/J4c5Hb7v06pnVvlJ8WJFa6nCScEZaV38v+rjDOCIZgZrI
         dBeYVAXEaxN6shz5e4vaaTHii9uDngUkqJUUapeZhw5/d6s+kgP54AiEhHOQp+sbKF+f
         9yia1X/QG3Oomg67udaMUcVya5bNtj4M1Fdu0QKo2AZ9XDo9d/029TRy3oBWbxd1h5r/
         shAox1MqxGX1mzEjX6fnEsiwQ2kOI6ez+Nnf11UU+5b5LVTJg90h3KOq7laJzDATU5ya
         y76pss4jPVt6NNPPgMJJA8cwq+Ur0sNmjvYeCcd1QxVcdUDyXSbrIavGLv8+Q1V4COEW
         MrxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-gm-message-state:from:to:cc;
        bh=hyIPYmpiXNC37BnAHtlaWmee7T/xPHQp05LH3vUG1Ro=;
        b=5oRukVyLaGZOF645VEL2T7W26Z+1Vrg+3apzJTjdJtY9N41KA21km3l6gaX//YZyTq
         B49tNAa9mYI0bTI34p9z9fxeRpEISorM7wOTYAYHWa5eHxPg4F4QbToykUI4BYJIgYkA
         smjnLiVvgLdlSpxXz7sgIpq5Gz45IH/sVfqU4pTf0chwI5GghzCVP8QcJ540wSlQZFwo
         IJAqYLje8wEekqOuHKjJNUcHfsyZTzcKDXif3uh1xpOgnEmeJxSxi9RprCNNObjvafwe
         zqDyRA5b/FxBsrCc/W8D7ZDtMGu74LB5nBKwg3iylK5vsq9Nqx/WTInomk7T+kyXLppp
         rfJQ==
X-Gm-Message-State: ACgBeo0yx7iJFRdk1lRTd4RngjO+lx3nxlGNQqu5SkuLhX3vzw8BzFlx
	S5wTNMXi9BDwiNBEQrNvNv0=
X-Google-Smtp-Source: AA6agR5+lUsiclxW2g64FfURxnbEzSgJLM+8jVyRMZ55j8gloAM9us13zN/qbpQEvrB72Z3ruxYdlA==
X-Received: by 2002:a05:6638:537:b0:349:b5d2:9182 with SMTP id j23-20020a056638053700b00349b5d29182mr12976088jar.5.1661896212625;
        Tue, 30 Aug 2022 14:50:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:230d:0:b0:332:109e:3b77 with SMTP id u13-20020a02230d000000b00332109e3b77ls3353300jau.2.-pod-prod-gmail;
 Tue, 30 Aug 2022 14:50:12 -0700 (PDT)
X-Received: by 2002:a02:94c3:0:b0:34c:b5b:4e56 with SMTP id x61-20020a0294c3000000b0034c0b5b4e56mr1171702jah.23.1661896212182;
        Tue, 30 Aug 2022 14:50:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661896212; cv=none;
        d=google.com; s=arc-20160816;
        b=jukKlbMcz07jE1aHrjiop56QV6hyBmWrQkTtYTAFVJNonVzKGOG10KSsYwP4Y1Uk/F
         e1bs8f8w63xrF8lx495gaP0YjUoTfbRx+sDX9mnq8cWByKU2b06f6vRFI+dGTCs7OP16
         5HV2mXqUERKC2cZ6P1qbPhcXtv2X4lI0lVYdLaHIcuX5PUAGxHpdTV213tcv8IEvO9YA
         kJ6uJqngSdeWfvKjAuzHy3aScSzlyBYu9oodUMPuIpcDV04OZAyV2PriZz+mneIYt2IL
         tlbxk7+d3cT6PVAXLL6afzIxU0aNmhQDGcGymPZm/YKqllTZmIyQ10POaXtAVyr6Q7Hn
         EDtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ofrC1PqNoYIKnyKYWjHD7inVuacSGBJJLHypr0RookE=;
        b=tQWy44Pt4zZ+tJ1eJtxLvJnVaflD/qpW4+KY7yApjJycbpmZ9YaZ5kwBfXV/qKZD6w
         NS1l33tMj3j71Gv5sfw9r0JXH6eLignHJac4Vi4uiicbc/GPDufvc1WukWeXoSmqT55V
         Uyg83f8NYh8oK6pngZmnZe3IlkY+9DsxXZHqiOhJjCRl7I/ej4wYFqP+O+4f+jPF54/d
         tKhfL5s0FCmQOiQ53tcqaIUSFoP28srOpWzXoPUiviw56LkujA6Z91di44FnpalMHCW6
         KVtyxgGooHoDidb1U8RosQH0/IKMNNZomaVVUlLtjAuwcHsC9UCliclxTX6fS/Kqen2G
         /eXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="VGRf/84i";
       spf=pass (google.com: domain of 3e4yoywykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E4YOYwYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id b18-20020a029a12000000b0034a2ee4c7bdsi428011jal.2.2022.08.30.14.50.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Aug 2022 14:50:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3e4yoywykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id bu13-20020a056902090d00b00671743601f1so709553ybb.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Aug 2022 14:50:12 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:200:a005:55b3:6c26:b3e4])
 (user=surenb job=sendgmr) by 2002:a0d:cd43:0:b0:329:febf:8c25 with SMTP id
 p64-20020a0dcd43000000b00329febf8c25mr15393402ywd.90.1661896211649; Tue, 30
 Aug 2022 14:50:11 -0700 (PDT)
Date: Tue, 30 Aug 2022 14:49:07 -0700
In-Reply-To: <20220830214919.53220-1-surenb@google.com>
Mime-Version: 1.0
References: <20220830214919.53220-1-surenb@google.com>
X-Mailer: git-send-email 2.37.2.672.g94769d06f0-goog
Message-ID: <20220830214919.53220-19-surenb@google.com>
Subject: [RFC PATCH 18/30] codetag: add codetag query helper functions
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
To: akpm@linux-foundation.org
Cc: kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, peterx@redhat.com, david@redhat.com, axboe@kernel.dk, 
	mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	changbin.du@intel.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, arnd@arndb.de, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	surenb@google.com, kernel-team@android.com, linux-mm@kvack.org, 
	iommu@lists.linux.dev, kasan-dev@googlegroups.com, io-uring@vger.kernel.org, 
	linux-arch@vger.kernel.org, xen-devel@lists.xenproject.org, 
	linux-bcache@vger.kernel.org, linux-modules@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="VGRf/84i";       spf=pass
 (google.com: domain of 3e4yoywykcxgoqnajxckkcha.ykigwowj-zarckkchacnkqlo.yki@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3E4YOYwYKCXgoqnajXckkcha.YkigWoWj-Zarckkchacnkqlo.Yki@flex--surenb.bounces.google.com;
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
---
 include/linux/codetag.h |  27 ++++++++
 lib/codetag.c           | 135 ++++++++++++++++++++++++++++++++++++++++
 2 files changed, 162 insertions(+)

diff --git a/include/linux/codetag.h b/include/linux/codetag.h
index 386733e89b31..0c605417ebbe 100644
--- a/include/linux/codetag.h
+++ b/include/linux/codetag.h
@@ -80,4 +80,31 @@ static inline void codetag_load_module(struct module *mod) {}
 static inline void codetag_unload_module(struct module *mod) {}
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
index f0a3174f9b71..288ccfd5cbd0 100644
--- a/lib/codetag.c
+++ b/lib/codetag.c
@@ -246,3 +246,138 @@ void codetag_unload_module(struct module *mod)
 	}
 	mutex_unlock(&codetag_lock);
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
2.37.2.672.g94769d06f0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220830214919.53220-19-surenb%40google.com.
