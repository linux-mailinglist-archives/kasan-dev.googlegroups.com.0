Return-Path: <kasan-dev+bncBC7OBJGL2MHBBU4OTO7AMGQEQ2YSCDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E92DA4D82C
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:44 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-439a0e28cfasf29750695e9.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080404; cv=pass;
        d=google.com; s=arc-20240605;
        b=klU8UB+VoMoz0NUsG7J3C+DY4gvtHbVlZo9OHjE0voHJLezjNjqO2carsxKp3p9XQ7
         H1Z2tWXKSmKHtAeX9mxhFFWGeW8Za/8UskvcN+h8GmCXmnrgJB3i2srSjY5M8bqfEaeE
         yrQfAydxSMzORSG1/1GWhGLkuhiL30+XtAcEFW0sgIZjnXcz/CrK+/CUhUA8eQQ3tJfn
         XHsKUYAihOmDDcRy8LiCgugR0lIi33Pf2CYQSeC5N16K9I0WvswZv74ZPDDMNWqldQV2
         OKwi/3kpe+ZVpwf5cFXB83GpzNQ6wi4WfZnNyc1cFrOvkqgolrqGVnefpvYPb4SVU00C
         7Wvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=JMcXN/xXI1oHPOZpM3u6QLPEw1sENM9ULuNpG8J3je4=;
        fh=x9/ueVHrBYPy86ACVv50JAUjjoattKMfNnq22i0qTj4=;
        b=JGBsOtH45tAsDz8/VQSAPw8KxGuliO7z4lX6M2ZeLTNJTzB7uNWFdRduN4xLT3nr2a
         Hr1nlM4aMk6oSteAba6TeClSuhr/0ux7zGrIGgMXlE3T/6HYdVdHLtpGDtWP7wmElgPb
         R/GWv110q59QY1cHI3B87gFIzVAAxXYwL9F+XTrOGw4XHWfE4eXRe5g2gKF6iHMVMzci
         nkNHmbLeLi53V8SLk8NpGJG/HoWkjp4IRF3vKPvd4TP1G97zVUskRtW74Sz/1XaHpbb2
         f36rSjISirbQ9l/TbXmCGYoEik3J4uLMeoqZPr6oGqKB1PHu9K0SrSj+yAFnV55VBtrE
         capg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1fPrsvyJ;
       spf=pass (google.com: domain of 3umfgzwukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UMfGZwUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080404; x=1741685204; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=JMcXN/xXI1oHPOZpM3u6QLPEw1sENM9ULuNpG8J3je4=;
        b=TvlGPLLbfN2fJEjCiIbewt47hMGLjJ40WAfFsE9WNVT6iW3xjc8mJjswGMhd/0EZFk
         43wbnsVjXJbBqqMvHqgxsPbOMS+MrhBm581hN8Co8r+QY6VO6cx+LkyQErYdwXxDPjA1
         b5I/oNSW1ZlJecz1Oaix+8Hs6VaqMxDICA2SJcDNQ5tMwvApNSkwRgtp3xscW+ah3OyK
         wYC849Q7yTVj/HuHK7vFwJAgSqk9NHAnomgqWVsOHlTZ9ASaAMkYTZTmg4VjVrjxv0LO
         ZHwxP9ylZ8ui4QpGMpq7UjOI4vV6wvSS3ghafKTNUjZAA77KPaQqyPaxH9UHNh9wdR2E
         YpLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080404; x=1741685204;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JMcXN/xXI1oHPOZpM3u6QLPEw1sENM9ULuNpG8J3je4=;
        b=RhaN6lrNae94Z4q7IIimmH07BGlJkhVsleib3c0n+uT0xoxjQDeiwikE+3+qNlpZCv
         umK7JYMu9rrrOBCqZ9BZFCukOAwpwktL+29DYM26c0Pbq7M8qSzUzp3IaWWzLc9eGQaD
         bsMnBQbY8twiWvF+w6PFiHgAH2IgByzSvc07xNgCkX/4B6eYH+wjF9Df9m+YKnb56Hn8
         Aw38L/6b+ZjApzPzjfiljJn3S9fTEpheqHmwZ4/Wctqcd4sWTXRZW8W4dbsKBe2s1QQ9
         ul7sSwx/OJqQlhKcZmpZWj+Yt4zTQNgAkV9aYDqCl38QrSBLjwf+2o4NJn789YKo/F+P
         fqpw==
X-Forwarded-Encrypted: i=2; AJvYcCU9xBmtbywaIlZJSNPFc+ygxlS1glrk0eAruSoL3jLlopaswRIW4g86XBY0bifMiNry1aFJcA==@lfdr.de
X-Gm-Message-State: AOJu0Yw5JUBQFEDUHxHWRtD09iWbLWYjQy1+xjPnvRc/jCL+j/gJ6qAx
	FFx+TWmwCafsntaMIWFNI77zCz2HiaE/JfI44A/rxvXIyMqwmhf6
X-Google-Smtp-Source: AGHT+IFEsQyNMu+l+2047a/Si+aXYb2npwvl65wn7sh/JunNp7eNLpki6YSCqqD1gTMYWb9SmmMJ5A==
X-Received: by 2002:a05:600c:1d22:b0:43b:c390:b78d with SMTP id 5b1f17b1804b1-43bc390ba52mr40991085e9.24.1741080403729;
        Tue, 04 Mar 2025 01:26:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGojyH21Fq+GuMsK+L8ZNiIuaG2GtlUKe6K1E9sntKi+w==
Received: by 2002:a05:600c:28e:b0:439:9891:79df with SMTP id
 5b1f17b1804b1-43aed4c8fe6ls23592545e9.0.-pod-prod-06-eu; Tue, 04 Mar 2025
 01:26:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUqXickQrfCWu5jAOa1SOTrQB7qkPhiX9fPeJ+bhSZz+SytqqCaLmSUV+WLl3n7tOjnRIRKFWA0QNE=@googlegroups.com
X-Received: by 2002:a05:600c:35c6:b0:439:a88f:852a with SMTP id 5b1f17b1804b1-43ba6766afamr127632375e9.23.1741080401368;
        Tue, 04 Mar 2025 01:26:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080401; cv=none;
        d=google.com; s=arc-20240605;
        b=Hlig0mOb52C2A6xiSmqLly5AAeCeV8WrTL9TmxfKu9TIlCn4igxwSuXbynxi791yoF
         gmBaYSmRgWS3nnhzMAiISjOA0FVvzA2+2F8+oQCKrLj/pDZt4GPYnhuLf1TVY2zZ+V6X
         iM7k8kFquvBgtSwU4C5vY3eRhY+B5NUW4/9b6+k4DdvotD81Y4dQBm7/OQnpillGUUfy
         CIWUVqHAc638UpcUZvMu2M7+Kfe+RkAcSwqOMuD5qaAfdhKYI/sLAlK5WE2+Pn3BW+vv
         OXn3jimn0VWmip7tDYDblm7REhigHKnQ7aVlEvTC9c+9eFXWBRI0ZmExoIFr1CADReBY
         phlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Vumk0HTnchdldWRc8wT0cAdQjFLn1MfJ3/QC5i3Nw5Q=;
        fh=Oa/TVBqS2Mj8OP0JyqtKBYfMD8qHUzQdVu4ASsm11L4=;
        b=AorfH6Q9sNURkvzZ10I8vFJtcpU2vyGIQuna5Z8JnuUWTDkHcSrwzdJxEHqhoFr+AO
         2SPqIid2k2oPkBQcsBUbVwdVPMYOdWyJzvGlubZ4jTgCk+5rrE3TrMuJkgnJ2ygraIoN
         nTmzdNJnxCyiL48ebCJY4DDcVYvsfW8UocT79Y2cOzQQrZO1BaKgnL4+IINMjBvvcW1g
         h/YsrkYTjLr+I5Xu/NOa5wcEBPOJTY2gJhuW6Wyc/KvJ+c1A97efdpDjU0Th2ypfNumQ
         fFjbnsEjqrLpmk9mjqJzwJxZe0W3sWG3wkkKukejp3movYhJzZM0gTV4SKmtjOBHICZH
         Mh4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1fPrsvyJ;
       spf=pass (google.com: domain of 3umfgzwukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UMfGZwUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b8a9si395495e9.1.2025.03.04.01.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3umfgzwukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id a640c23a62f3a-abec83a498cso522432066b.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWMK6NDoFaMgKFPtAB8kMtbBkSPXhSHHFhemmxk45zyqUA17aXx0dstrzcktMD5sWN2Jt1Z3mnwKpw=@googlegroups.com
X-Received: from ejckt25.prod.google.com ([2002:a17:907:9d19:b0:ac1:ed2c:ab54])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:7fd6:b0:abf:46cd:5e3f
 with SMTP id a640c23a62f3a-abf46cd7414mr1245962366b.16.1741080400857; Tue, 04
 Mar 2025 01:26:40 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:33 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-35-elver@google.com>
Subject: [PATCH v2 34/34] MAINTAINERS: Add entry for Capability Analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1fPrsvyJ;       spf=pass
 (google.com: domain of 3umfgzwukct8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3UMfGZwUKCT8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Add entry for all new files added for Clang's capability analysis.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Bart Van Assche <bvanassche@acm.org>
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index 8e0736dc2ee0..cf9bf14f99b9 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -5638,6 +5638,17 @@ M:	Nelson Escobar <neescoba@cisco.com>
 S:	Supported
 F:	drivers/infiniband/hw/usnic/
 
+CLANG CAPABILITY ANALYSIS
+M:	Marco Elver <elver@google.com>
+R:	Bart Van Assche <bvanassche@acm.org>
+L:	llvm@lists.linux.dev
+S:	Maintained
+F:	Documentation/dev-tools/capability-analysis.rst
+F:	include/linux/compiler-capability-analysis.h
+F:	lib/test_capability-analysis.c
+F:	scripts/Makefile.capability-analysis
+F:	scripts/capability-analysis-suppression.txt
+
 CLANG CONTROL FLOW INTEGRITY SUPPORT
 M:	Sami Tolvanen <samitolvanen@google.com>
 M:	Kees Cook <kees@kernel.org>
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-35-elver%40google.com.
