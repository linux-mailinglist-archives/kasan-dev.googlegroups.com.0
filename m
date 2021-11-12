Return-Path: <kasan-dev+bncBDAOBFVI5MIBB6HPXKGAMGQEWVLYAMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0017D44ECDD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 19:52:40 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id f11-20020ac24e4b000000b004001e7ea61csf4337809lfr.6
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 10:52:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636743160; cv=pass;
        d=google.com; s=arc-20160816;
        b=IKCGmjq4YOQLbTvuZLPjygMyiEUDWsOUjKQhImnJnwhlaPd8ku/pMZ8ZV4Sd3bLi+e
         u28ICygNw2Tg5F9hqCCxIGa2Q7Vul1qn0kLu5YfUzVh5mJq0i2kcxxwWpqVwFxVYiH+G
         rgzG2I7o/hVQ5qYRc+JzWxuw22qGKgwTSxkF3vRt5w2XeqvUo4vkLosSEOlPY3Orx699
         ztB4DUtKgAadq73jiGRXcILkyOcYoOH8Lkl1Z1BmfYmzO4ZHmYUjE9Aze+tLPatnaZgb
         85nywWxltsOX+M37NzRK3sd1dV1DvuboAxsqJ3Bcy5S0OqXqeuCn91YN3aPfNsO8JBsc
         jmlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TMFNNCJXThrNKXFp9lvLxHUPPBbKUDsBUC56yP6stTI=;
        b=yyiDRqGXm/pL/TQGIK81wH31w9R6YGGqKrLgzCYS4WyajHbk0zdih+RJyahGIZ2F+e
         Kmwn/cBsFYU3VhiFWm7trG4v2ODb6azU+f8AZxoXQvPNfJtXAlDqmuqghfhwyV1iOhor
         hlVTQQGdHEvX6BDvkL2oNH02n8IHhCvzRR/hJnBLRuBv+lP8hNqA+FqV0jmfI3VUjtId
         U2aZgsVwi0NdxIehC/LSFdeZy4pd6MBwjt5jBxu6sRgtwWoNhPy6qZaLLUMzbZ6Ab5y9
         jdxR4pQdUHk35XXC70MhZy027+Mh1fGW2fll4fcvfl9ZV5wpBKADTJJDraCrNDbR5jjH
         Rl9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMFNNCJXThrNKXFp9lvLxHUPPBbKUDsBUC56yP6stTI=;
        b=gcPcRSIC+C+XtlPcsVVEUZTNv68x7YcKRtP8niMRsklX7AXWmj1sPAqkqtq2qEbMQw
         aSmcH5NydlbtnFIQ6fLwGHJtlQwQbHAIRBK3jLVL82V+DodD8LO8ehvXjfS4fcmh6l5K
         GO+YkPbVRlWrD2SAJhmVQ4X+UGcSKN8692m674Lrt9o9MChzv4zDTVNYZEMnbZDtgYCm
         3F1jgRSgEBYs8z4Vbls+5xIbmWFPJwCCsF/8lAfkzfSTnfcYSPMUGZDeDdkc4DTGgYd/
         791tVjUOIIkD92alnuX/MydtDKWH9kE4gEnYnS0DxEefv4cKmviXeO/7E0JbLV8Th1C1
         3h+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMFNNCJXThrNKXFp9lvLxHUPPBbKUDsBUC56yP6stTI=;
        b=pbLNFoQM5oFRJmOi42lHLQSJT5k/5sNIJ0MOWjw66X76l0O/33sYfGsIkD/8GNMSfn
         R38+i3AOb6mvYM5RlEeDbGNm39Nb5+OmUi4ccShjAJ/9DfQf71hpkOp8rFeXF7a71yT+
         LyUwh6tz9GH4QK/LN3pXrBYK3UAi+VU7r3Sry8BmfVwAexkj6WLnWbn0j4/7u7aXS7Qa
         3tknCnX6EhRxP+6T2NaRkkDAKODFXmpPGv8YUlNdeITZpABC868vTw0ktKTmdAZgV5Qj
         vMclffOciNAlWIOyYDwWPLoPvldUxQFiyG8671PNxJqGJHybIbTIcf6B+AyNxw84XVU5
         llUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V8vdIWMWLeifrTdzHkCQTiSxhjNQrDp5ASYw+OLtYi1wQC/+a
	rL9L3IdJTMBXJbzAfbZ139Y=
X-Google-Smtp-Source: ABdhPJzbPpBn1zzvRHvgbjPFAHtBll9IrmcXHNeKvNWXaECd54Wy6wyHFsJMcr5uG90x2yJFrfZAww==
X-Received: by 2002:a2e:a361:: with SMTP id i1mr17420033ljn.32.1636743160557;
        Fri, 12 Nov 2021 10:52:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:b1f:: with SMTP id b31ls1354019ljr.0.gmail; Fri, 12
 Nov 2021 10:52:39 -0800 (PST)
X-Received: by 2002:a2e:b001:: with SMTP id y1mr16736925ljk.139.1636743159610;
        Fri, 12 Nov 2021 10:52:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636743159; cv=none;
        d=google.com; s=arc-20160816;
        b=YUL4QjvyLbCJGn/GKCis6ZFrUp+6BELEhVHa/r3NmzVpKnwLcVL9fS9cVqozbpkQCP
         3QLElbJZ0rjSp7BzN9j95FnKnKDF1UNJ/1LD5gB9YcYtL9i5kgUxMqbZBBItqR3b+EKw
         d9YEghWn/bHQL1g1FoVIIB34Tt3d+MoHkS0Vq+vYeSsCs84DC/SkKUHjGAbk9+OXm7xt
         mjvCNFB4asvXx+Os3KS9H3dItMgsIq7EIHZKgemchJkm3ebG+2AEY6+joEZP3RMPkHsA
         e6HjzXXe9Mm/8/DnWpfaaO79vz4N0NZF2QTc0Nn2PIC5IhBrGD49d2fqfjL0jr9vvR6G
         UEgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=Yf2b+OFSYaY4ZAUtudo1dVPf3T642M69TGbWOJ30jyo=;
        b=TQmtzeIGRi8kdqDKt/PMPoPdc23Au6PSZjrmpnEgV/qZXmbMpRAGrIhWBWMY+CPump
         531UUxhFzSMlAwxX3BmRSD4Xk7OfGO2d7pcLMwHIQkwe0YqPxXZDh/7SMsQ+qAFwpA/C
         n1PySpYkLZ3hnUUEN2fqRKwpVYcIkSswYxUQCnKrXSVcDWXJD28FUaKEYSV93Tri4uIV
         ZB7Yz0h31qHoAZI9IiDq5n9eTZ5ZOPzY6EfkHtnG+OR8bijjFGwak831GEhogr6ozBKE
         gXxcKCWo4FGYbdCRA2XhbZA69OKjrQAwSRp8BWHgwlFxltWIZxKGI3OEn0v9pHnuEA7P
         i91A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o25si483958lfo.9.2021.11.12.10.52.39
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Nov 2021 10:52:39 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 71E871474;
	Fri, 12 Nov 2021 10:52:38 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id A05873F70D;
	Fri, 12 Nov 2021 10:52:36 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Cc: Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v3 4/4] ftrace: Use preemption model accessors for trace header printout
Date: Fri, 12 Nov 2021 18:52:03 +0000
Message-Id: <20211112185203.280040-5-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211112185203.280040-1-valentin.schneider@arm.com>
References: <20211112185203.280040-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
preemption model of the live kernel. Use the newly-introduced accessors
instead.

Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
Reviewed-by: Steven Rostedt (VMware) <rostedt@goodmis.org>
---
 kernel/trace/trace.c | 14 ++++----------
 1 file changed, 4 insertions(+), 10 deletions(-)

diff --git a/kernel/trace/trace.c b/kernel/trace/trace.c
index 7896d30d90f7..749f66f96cee 100644
--- a/kernel/trace/trace.c
+++ b/kernel/trace/trace.c
@@ -4271,17 +4271,11 @@ print_trace_header(struct seq_file *m, struct trace_iterator *iter)
 		   entries,
 		   total,
 		   buf->cpu,
-#if defined(CONFIG_PREEMPT_NONE)
-		   "server",
-#elif defined(CONFIG_PREEMPT_VOLUNTARY)
-		   "desktop",
-#elif defined(CONFIG_PREEMPT)
-		   "preempt",
-#elif defined(CONFIG_PREEMPT_RT)
-		   "preempt_rt",
-#else
+		   preempt_model_none()      ? "server" :
+		   preempt_model_voluntary() ? "desktop" :
+		   preempt_model_full()      ? "preempt" :
+		   preempt_model_rt()        ? "preempt_rt" :
 		   "unknown",
-#endif
 		   /* These are reserved for later use */
 		   0, 0, 0, 0);
 #ifdef CONFIG_SMP
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211112185203.280040-5-valentin.schneider%40arm.com.
