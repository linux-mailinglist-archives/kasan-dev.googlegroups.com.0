Return-Path: <kasan-dev+bncBC7OD3FKWUERB6W5X6RAMGQE44U4GTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 13EA86F33BF
	for <lists+kasan-dev@lfdr.de>; Mon,  1 May 2023 18:55:24 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-545fc6208e1sf742223eaf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 01 May 2023 09:55:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682960122; cv=pass;
        d=google.com; s=arc-20160816;
        b=J5QhYmkoDZC7YXpM/+J6b71tl6LgF14soL0T2z68/erh1E1zdoQwaFJq47bhnGsemX
         8yhHZblHQKBmibbV07HKRQXuCpVZCHaOUt8J8148v0TfgOn+QfpCYORPH2isPszlzzGi
         ZSei5t3/yC4I3kvu+kReJAy4L/OfQsAU1X/7r8Oac3XBVvxKnWSO+hcjUgi+10acXJPd
         UnSazI5fKWyU+kxH+it6GWydhKWi3IM8VIJif0XrFG+e7WdX5Ew43SODbXQSv7nZuPV6
         xcnefNfXd0oBU80GvXIWn8qi6OKYvy8SvR5cc+So5dS4bFKgL5ENqybMEbsvZFvPZPXv
         w8NQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=j6G1oLK9gpaGD4Gvc62+Me54pzFgeGPVeHelF20vqbk=;
        b=rNlvfotTQfpJsyRX/kqGebp0MMGKL3xZKM+8Sj4qcHoP4WnyfThqKYEu3SbrSHndHW
         pZ2CJx4VWrXswu3Y2EQePJHMZpzVbZGr7hovWbjeZzy/EOJQScEGwmewBXgijgZC1FZc
         bJ8NGBmePAVC3L8dhJTIkPHraHU1yb2rJiQ+2Rb6KjcB9AKLJ5yM/A2aue/tqej6w+p9
         hP0NlCara/3TXGK0APAXyFl0zD9zYxaDy9ygu8u0iSBDjNnuR4OCPakCh2zY0I33VDr5
         tFwMdYbYhVJymBg3oFTS5t0YomV+m2P9zr8OaUZg9Ci0n0k4waHVSXKbuPVlUggG3rjA
         1ijg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FUEHKTcj;
       spf=pass (google.com: domain of 3-e5pzaykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-e5PZAYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682960122; x=1685552122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=j6G1oLK9gpaGD4Gvc62+Me54pzFgeGPVeHelF20vqbk=;
        b=WOcwx+aecq5Et0ru4RKadPM+tx4PeRtYoHhzI7QHKPF0de2eKiKyUDzGymI6W4pffm
         Ra0xGLwG13efcHdyWSQJPIQ6qqRt9ZP3fIQeEEudDtywuQbYj+l+ATakhLVzSGpjNGS0
         0aqDr5sjfQqAwze9isylrlLoaHmLNwTkbuiLU6X1GxlRp4a+f3L4puBQG++v+oqJfQcf
         GtjKfovXstoDvijZROT1Q4rBiZwPM+mjvOxdvjqLtjdE1tNSpUV3hmXPz4Qgtg47V62N
         QbjS4S71wR1V0iUD4d8cfqQ+ZYxG7FOdGgeeV817t+ltudQ3Jnzw96yi63o6935Xt0nG
         lOUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682960122; x=1685552122;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j6G1oLK9gpaGD4Gvc62+Me54pzFgeGPVeHelF20vqbk=;
        b=QomsndSt3kBCAoJO/9+bjXjrCvj98c7gh7At0tFjzlg3pTzDeOjw0hiLIRuKPKoUwm
         eXHT80HmZ/b9c0Pm0vQS72bmGznFezFPfOqcocWBXluBom6+DegxFa7y9G2ehbJAmH4u
         ru9/exsZ9H8W/dgY5d21bYBMQiLU1x9AVx0g7Anss+TIM69camdaL6IsNoaAELIsRqUB
         1kqd64Pome0DY9cCcL6DcdRYxrFoM+5zuoNu0qJo8FofJwM+4fAdCjE2CYUamd0r48iS
         1ZQJ7I9z8HhwZp2ASdiTkkuVAI6l88KZ6EbZwD6lwFYA/jMHrrDfAR4+MI/qN9vZclCZ
         xLdg==
X-Gm-Message-State: AC+VfDyIVmWgbkkgYz0+a44ZdQptW2i7eo3jTTleU449u/WkokR9x/ts
	sXKHrjcqlrTmQ2OjVJgS8lQ=
X-Google-Smtp-Source: ACHHUZ6AXmvdQdifEF4t0OZpOMHOB448KpPWWWaQfmC2m2V1qcLd80WY5uXtQsIQumtPZMO/2Jr29w==
X-Received: by 2002:aca:a952:0:b0:38e:c90:a748 with SMTP id s79-20020acaa952000000b0038e0c90a748mr2455047oie.6.1682960122777;
        Mon, 01 May 2023 09:55:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4b98:b0:184:23f5:48cc with SMTP id
 lx24-20020a0568704b9800b0018423f548ccls3330833oab.2.-pod-prod-gmail; Mon, 01
 May 2023 09:55:22 -0700 (PDT)
X-Received: by 2002:a05:6870:8226:b0:184:4c09:a1fd with SMTP id n38-20020a056870822600b001844c09a1fdmr6316315oae.46.1682960122339;
        Mon, 01 May 2023 09:55:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682960122; cv=none;
        d=google.com; s=arc-20160816;
        b=PsgTAb5lrjYIXZybra9vuQMvXBv2ULFBrKRPNTDbJzfjx8FAWE0PAeaHFMTU9UNPYx
         qlGKKNQKetytn3S53rUKiNin/qdK1wCCAYe8rSzwnIkyIdZxtiaLHX99v/L5slSSGT3g
         RXBbM6gCFdTNqBpsA8Xt34Tn1aiVN/byhDY9yjK+dp+hxgDWNA8IUayTU8FVv7Gb0DmC
         +Ou7Q7JTJ+tVd4Z+QdOY0xkkSDsxaMaGmo6RFFdumUl1KMbJ/6pwbyDYIUxHzd5ZKCU+
         viSpEgdl0C++TU6+8FJbzE1GbaZbjPpiLUy2+Q9mT9fy/EomzQGlSbPW7e8OgsiKnRyJ
         8IhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=AsvePdIIpK1hSWiMR4JNg9vJpL7RbQEpCCaVPwkxl+U=;
        b=y5YCPAvBxN96iDTkNGSF09yt2gBusFvu1IYq2Gtls0ZqmYj71Ik6DK1DZkoRuGNccg
         OxR6pLxMtaAsAE0Vmwrn0AvPBxjdt1R6o/PSQp4vdyG93l+TdgVJLFCEI7LUVzAkXrXn
         +s6zgSlBQ4Z2TyrRM34Gdh5ohU2hsl1jLxcBHFAvMI5MeiIWM3eSB7r0PMG8Sp0nYTv/
         BMzrlcf8pOmB3uPAedNDPFWoPuvyB22JSfdm4lwEkLoYWxHMEl2FcefRBxisUnQpyOBh
         9WLuzt/TwNwguuexeKcJAtOa84iioZJNd8MiqU2wTUrjXG7jSwkG4vFALJTmcmTClU51
         a4OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=FUEHKTcj;
       spf=pass (google.com: domain of 3-e5pzaykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-e5PZAYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id cr12-20020a056870ebcc00b0019272996894si95974oab.2.2023.05.01.09.55.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 May 2023 09:55:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-e5pzaykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-556011695d1so45692367b3.1
        for <kasan-dev@googlegroups.com>; Mon, 01 May 2023 09:55:22 -0700 (PDT)
X-Received: from surenb-desktop.mtv.corp.google.com ([2620:15c:211:201:6d24:3efd:facc:7ac4])
 (user=surenb job=sendgmr) by 2002:a81:7653:0:b0:54f:a60c:12eb with SMTP id
 j19-20020a817653000000b0054fa60c12ebmr8139444ywk.1.1682960121808; Mon, 01 May
 2023 09:55:21 -0700 (PDT)
Date: Mon,  1 May 2023 09:54:16 -0700
In-Reply-To: <20230501165450.15352-1-surenb@google.com>
Mime-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com>
X-Mailer: git-send-email 2.40.1.495.gc816e09b53d-goog
Message-ID: <20230501165450.15352-7-surenb@google.com>
Subject: [PATCH 06/40] lib/string.c: strsep_no_empty()
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
 header.i=@google.com header.s=20221208 header.b=FUEHKTcj;       spf=pass
 (google.com: domain of 3-e5pzaykcuauwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3-e5PZAYKCUAuwtgpdiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--surenb.bounces.google.com;
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

This adds a new helper which is like strsep, except that it skips empty
tokens.

Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
Signed-off-by: Suren Baghdasaryan <surenb@google.com>
---
 include/linux/string.h |  1 +
 lib/string.c           | 19 +++++++++++++++++++
 2 files changed, 20 insertions(+)

diff --git a/include/linux/string.h b/include/linux/string.h
index c062c581a98b..6cd5451c262c 100644
--- a/include/linux/string.h
+++ b/include/linux/string.h
@@ -96,6 +96,7 @@ extern char * strpbrk(const char *,const char *);
 #ifndef __HAVE_ARCH_STRSEP
 extern char * strsep(char **,const char *);
 #endif
+extern char *strsep_no_empty(char **, const char *);
 #ifndef __HAVE_ARCH_STRSPN
 extern __kernel_size_t strspn(const char *,const char *);
 #endif
diff --git a/lib/string.c b/lib/string.c
index 3d55ef890106..dd4914baf45a 100644
--- a/lib/string.c
+++ b/lib/string.c
@@ -520,6 +520,25 @@ char *strsep(char **s, const char *ct)
 EXPORT_SYMBOL(strsep);
 #endif
 
+/**
+ * strsep_no_empt - Split a string into tokens, but don't return empty tokens
+ * @s: The string to be searched
+ * @ct: The characters to search for
+ *
+ * strsep() updates @s to point after the token, ready for the next call.
+ */
+char *strsep_no_empty(char **s, const char *ct)
+{
+	char *ret;
+
+	do {
+		ret = strsep(s, ct);
+	} while (ret && !*ret);
+
+	return ret;
+}
+EXPORT_SYMBOL_GPL(strsep_no_empty);
+
 #ifndef __HAVE_ARCH_MEMSET
 /**
  * memset - Fill a region of memory with the given value
-- 
2.40.1.495.gc816e09b53d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230501165450.15352-7-surenb%40google.com.
