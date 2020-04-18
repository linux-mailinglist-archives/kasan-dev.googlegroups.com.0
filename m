Return-Path: <kasan-dev+bncBC6OLHHDVUOBBGXD5H2AKGQEJIG4AZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A7231AE989
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Apr 2020 05:18:51 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id v185sf4139576oie.5
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 20:18:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587179930; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGncokWgezyoBr0H/rwXihqUX2LI8M6nMqCEIV4Vn1qIHEPv0GNtE74bHlh2Q/o0WS
         wIUCHisrXaG2D6iSbZrIap7OFSxWZgCqATlrhLkU1823pU8ZUElfB0WSy7Ne6gvK/UAW
         hcCz5bsRQ/lrfq66nqRCHyyno68snp5iHHoIQ6zpmyC9cA5EekFQCpqPWBXuVjMufRdM
         f8EhwVCE6wAL7wny9fCI4z3K0e6zpRDPLJ9va+Fg8fjWaLHoFMrIlDipxdZq3syr2oaD
         r+62oDR0lsgIc6hu7Hj8AZt90B6AFOprA2+y2sA2rDVnD77JJZBsHXG8htvfesEEU1IR
         8Exw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fFnfKb9+KpI+ffhsQXLP/qZWsbd3K5Il7veQUJil7XU=;
        b=0V25FckFDrCajOMxgpkep+uJWASJ2FVxhkNxneSDamnVIEkvcq4Gi0mIP3OvBEnZ3r
         HX2RtFo/Af5Y6xdTPR7Nl/hMH5cDvfQaNoKKrkJwzEgJ36mfTMqVK2ydp4eINCD4OdXZ
         jmmP1B8XMshqrdKs6FpBY4KPSf3WrXeR0K554GjfBxawftMXip9GGPJ4CGCPqrkc3IOC
         f9w9w2MIkywAs1gzB8uqsUPYpNWAFQC/hbmXpmPT8RodIINg9n4YbvE7b7Q4IrnVUQVv
         gggMz4za3EHa+im7reogZEHmg+YOv8sClJY5siZRHw04NHkniIbg2oebTehk9+CDW6AD
         zb2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ajelyZbA;
       spf=pass (google.com: domain of 3mxgaxggkceafcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3mXGaXggKCeAFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFnfKb9+KpI+ffhsQXLP/qZWsbd3K5Il7veQUJil7XU=;
        b=fxwRM8xD/IZ5C+ubv3ffyG4hF8kN/QvGf5v29Rhd5sPl4/tdyjqOMXmyaih31uSueR
         OZZHOcJPh2f+ceEGolyI6G3q9Um3BU/Pi712p6dG2TuCjdri2bpT+pVm6lDzulVZ0u5R
         yPAPLfUkkqIdGB1qz8hh+acoHOlvXfs1OrWMyUuZEWKO7z5n8wVIIaTgvmNMe6c9qDc7
         g0m0/cSybpgYmoDrzF3K2N+oCysgs5CqJfXtdcOo+M063tevIfBaLZzYX56a9yM4xUx4
         Kuu+5HmmSPxCtEs7HG1lWwvAMSDKYuDx0+GktUAEAVZe4lhZA31NU02VUazb/uIdluVc
         qwkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fFnfKb9+KpI+ffhsQXLP/qZWsbd3K5Il7veQUJil7XU=;
        b=iTV1uf724X70YFwxK4oe8hFhoHAPE2KV+4whK2deTMfW1DomfRxds4OTMXscb1Kvph
         1z6tCab4kTE14/ZkXoKojDnHpw3lHBhIzfFXGvwM0OMNQiUhLKGwawG0qY3BSHLr/Np8
         I69ANoLecNwx+KyrUnpuxWDJH29XMkXvHaDcGUvcOBJAArzttoIPmg9HkZquGTF6lIHc
         6TWKYDXUVQriP15ydDB49r83EhmwBTQJBrNCzOJMQLi8mwyPCHJkPVKwUParwupNkGzc
         uQW11dBZdHEMigVzCjCXBmVz46sJkAglfhQDCpjsAhWon6pLQ05Dte2pGwtwgk8j6YzE
         P8ag==
X-Gm-Message-State: AGi0PubOzCX61b6Fyn3cah5EIAmqY3cN4ywKhvQ7RmKnRGZ7nLGgPmxo
	WVdtcpEPNOuEDVw/TCXqQEg=
X-Google-Smtp-Source: APiQypK2f5pgwgI/xJkryPtpV8Niz4Fg80+WpWWRK3GOg1mdKkdvErTRFIQlSVXrOXOHv98cQIZnlw==
X-Received: by 2002:a05:6808:24e:: with SMTP id m14mr3377567oie.116.1587179930118;
        Fri, 17 Apr 2020 20:18:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:49cc:: with SMTP id w195ls1065035oia.10.gmail; Fri, 17
 Apr 2020 20:18:49 -0700 (PDT)
X-Received: by 2002:aca:abc6:: with SMTP id u189mr4394853oie.30.1587179929789;
        Fri, 17 Apr 2020 20:18:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587179929; cv=none;
        d=google.com; s=arc-20160816;
        b=UyYiBQXkgvlR1c0qckM2viVfYqy3U+Sz1W3cBhvIkTKZx89EoIG5MjsitU3QyMuFL3
         0QJNBZOuWXcL6jhihgQIwGLcLWEZqe7FMj8zM02I4xhGsih0Um2LuUbLsinBtoPxkC3b
         mKnur+xBaODOPcC7FzOg0nmCmSg5w8qcjHXjaLlKa/mzi7XJY8H3MAHRIx8jQFdjtgi8
         1LtnZxE+FBwV21V2S5WEaFFY51cP9hkj+VvzRk9Us7rGbOLKdVQLmgr83h1O0ckUOiY4
         gd5CzM6xyxtKeNCNeUJLyEcMtp/e5FvM07hVYe4+rBWRpS5JnnAHw6Wwp+BGeoIm1Iew
         DGIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=CRqxf8T5bRxo/T712v0WU2H9pMxqHzrv9yCZKsRJO1k=;
        b=SLJqh+AeojpZNlHCltWuxGkFaGWK8qFjfVsqIdnlbBSAt61Y9f4bJO7iUD08SYrwyn
         4hPcyH5J371/qocU/+SenhX48Tj3PYJ80XjWa7EaPin4x3qevR54jrRSBSi09kYx33DO
         j3NvxepQv+/MJnni+AaJtrGa7OjHEcorwGXnXdLfvt/HA82ftmdxQPZk/hQnEqAdGTOB
         CyDk53KyNWcyBs1w7iw7/PuGGDX7QUlpYQN4M6ppP/xx7H+b3Qh5u6PWU/Rz9G8+KDLp
         uNOYOpRR5NqVSKt15KGgyMBtYknxYN8NpAHDyoSOxrjAnFFX1LRVuEEjrJHTcfkh3s+3
         Ssrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ajelyZbA;
       spf=pass (google.com: domain of 3mxgaxggkceafcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3mXGaXggKCeAFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id q18si1271230otg.4.2020.04.17.20.18.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 20:18:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mxgaxggkceafcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id y84so3949500pfb.7
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 20:18:49 -0700 (PDT)
X-Received: by 2002:a17:90a:30a5:: with SMTP id h34mr7674332pjb.171.1587179929037;
 Fri, 17 Apr 2020 20:18:49 -0700 (PDT)
Date: Fri, 17 Apr 2020 20:18:29 -0700
In-Reply-To: <20200418031833.234942-1-davidgow@google.com>
Message-Id: <20200418031833.234942-2-davidgow@google.com>
Mime-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH v6 1/5] Add KUnit Struct to Current Task
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ajelyZbA;       spf=pass
 (google.com: domain of 3mxgaxggkceafcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3mXGaXggKCeAFCXKFIQYIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 4418f5cb8324..e50c568a8dc7 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1188,6 +1188,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-2-davidgow%40google.com.
