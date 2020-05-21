Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGDTH3AKGQECIFMB7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D13A1DCBC6
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:13 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id q5sf4875014pgt.16
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059412; cv=pass;
        d=google.com; s=arc-20160816;
        b=WN2g9ui2Sd128WCMZGy/Xu8Son5c22MEJztwRJ24TDKUiZUZHPpfqNzevzj83NTFqp
         naLc10KjjDj4Y7NgFKWwXqOri96CEKfGHLNGK6j4Ra1HFhNx1RQnHDkejTAIdBzBPdiD
         7Rk7MzukB1hrFe7WTApEQNM5AJQ/o5XYdsOYuhnzlspVbFHrTp/QhRU7klu5w/Qf9R48
         dA9s0hGX9YhcXne5Mmp2Sm7p57Rq7bhSVKao7e0xI8Qx5/JNidG2SssorhwykEDypMHV
         GskGMAMUzAGxktg/avu5F4OdMiO2wQIB/qlz83xtWMjvXJMO/fgcVacpiHyu1LNhYKfJ
         5Duw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=34XLR+R+OCz2AmOd9EbbqYDbQ3oiKwJ9Zbito+6p/bU=;
        b=YJvM3tHl3rz/xegOAMOwx53XU+jpTAxQ2kP3Nzf2BUKHoR/rvVWZGrgcBjo8077EYl
         DMvKHDhFLjJOJWK8CYDjaCAPRL4ioJHoAq3+GGfo85I6EZdAILU8vb3N4C8jzdF3bO7C
         ViggTCbNtEKtEly+2QG3qBG+izQsWJYZ/u86h9zbBuxSwTswu28bsf+TMbZVAuHSR+Pc
         pqEYnPQFUS7JCl78OUOKYULEGwsNaj+KoUq4OnQENuKDDsElmpK+wpeq6SMYHRDiQDX5
         shq1QedjLokMa0+N+APkCvrzVa+C0myawy0ouTrZoa1P/Tf+mma72PIzKEXlha49BQ2+
         9WmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LW0ey+ZE;
       spf=pass (google.com: domain of 3kmhgxgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kmHGXgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=34XLR+R+OCz2AmOd9EbbqYDbQ3oiKwJ9Zbito+6p/bU=;
        b=ek32pHjfIU61g977N+cM+GAPiasfQ2KT2gekklinl2mUdbgu+mnip3WFU2yzRoFIRR
         EQWwgu+3VFSD/maFVuRF3xLaPwyqpAYI5dgrWEX2S/WeXwnwSvzJMzLqkNvobsdu1tEB
         dRjk/GDWk8A2eH8w9lboH54CCWxuZQTSQDRvWNeAeigbToSkw3RMbwEgEEJJYLwTDfOl
         I4L0BH+c5PcMZSgVbU+8JrCa8BoxmlHt9INrKe7B1KJP0KdxuKfY5X+FMTX1OO3IHHnj
         AlhwUPowpS4vDUVuz5NyZ9NBP4f20cJQ30XJE1+ESV5qbnYj+Nl1cBqJfm+ulh1iU2tH
         b35Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=34XLR+R+OCz2AmOd9EbbqYDbQ3oiKwJ9Zbito+6p/bU=;
        b=lqEYPIMbYVe1Fauu/dPvc5USaonZLLoTNlftrauHH8KlZ81sTQsycSRu5ddlb4kV25
         Z7SwKJuUCs3byehCniShT/1AK4bFvAkiX02x1mIhneoio7TQwNAATlwuP5qr99TBPa2V
         iilKPXMyQVzg6nUbD3OXI/r7aFV690hH4fpMaaMzFFesg6buSbbsejHnloCwYMtmJutQ
         4D4L+hY9Xx9IXA3tGcO1IPb20TG9bw59wr+s/4UqP8SOcSOZF9cvJCJ22M9HXuRrLIjk
         SPe6Uk/sE66hvPIHh3Q1jJbLAzuVBzeTj2Jlu19+RMCvLHNDQPa2ojtfd3dKt+w7/AxB
         cuPA==
X-Gm-Message-State: AOAM5327g0VScDMd6IvfMTooIctyJL6LdA+uz1r+oOaZtHSHnwHQyuvL
	YfCzMqr4AH/5WUVUsfkMlc0=
X-Google-Smtp-Source: ABdhPJy1JihvH/dtjf+iU+JfUQF0P1a3i2FEoMRAo8eXWrBcxU3V85WYrj1M5XFHNol25LtPIye+lQ==
X-Received: by 2002:a62:1d48:: with SMTP id d69mr9123150pfd.27.1590059412132;
        Thu, 21 May 2020 04:10:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b82:: with SMTP id w2ls745336pll.1.gmail; Thu, 21
 May 2020 04:10:11 -0700 (PDT)
X-Received: by 2002:a17:90a:20ae:: with SMTP id f43mr11112499pjg.29.1590059411719;
        Thu, 21 May 2020 04:10:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059411; cv=none;
        d=google.com; s=arc-20160816;
        b=PMWL6qXjkzLUhn9xp8enNPYfKMvWWrmjbSr3dYsaci/mPRQ7/WnCwcS5oquyN4L7pa
         DEO2nvKUN29bkDFqjjTU9LhRLee4+z9LhT/hTXaIUSAwmtzHGNFq3hm4w4Jynpxr4+vM
         3t787G8SCfVf9noVgLSSE59sXsPcyQrzY6V0H2ISHw6SABW1H4GZoCPG9fhuxdE8fXJX
         6y6ln+VGy0njEXBBESSB5VlrW03FZ6PZbo3PvVohALb41dMd2Vy9XBxXbn4yIwL1E3U0
         9u/b8LdvTSgdU33ZvO0VxdlTil7ZAn4o/AbAiIua/qfeNQ7nCihfQoqwug6SMvZnoKEE
         /crQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YxAJO5zjAlDcESQjL2hotUlRyCYCv27YW58n87FzjMM=;
        b=XBhhYIOJWYZLwS1P863XbcjcKcBGBYT5smRf6aHkQT8Vt7SJNIO7xheNIIIyCY5Arj
         +aDF+UTHC2cezU0ewwiG+bMZz9GjB8U5gsRI5C+4hwW7U0nnwigerGOQBem/cPQyC7uv
         n4LPKgp+btYlFBhqquzPwQ2IEBJbUMnqrPwX7j6wOTBfFcCQl1MAH9+49utFj35kXdrF
         UOABQMnV312bpVyJtN+qhtwP7TGaBundPR+Xuk3g8ttHSNxswplCilqBVJjXsFWj55x0
         VnTUiKtDwYznsz79GQ4y3t6Ug9Y+rL/g5ceGTLnY/X6F2Dn74PFkncDI9ecuxS4zQtju
         Reaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LW0ey+ZE;
       spf=pass (google.com: domain of 3kmhgxgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kmHGXgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id e13si410484plq.3.2020.05.21.04.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kmhgxgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id w6so6807126qvj.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:11 -0700 (PDT)
X-Received: by 2002:a0c:8d0d:: with SMTP id r13mr9507280qvb.53.1590059410838;
 Thu, 21 May 2020 04:10:10 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:52 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-10-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 09/11] data_race: Avoid nested statement expression
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LW0ey+ZE;       spf=pass
 (google.com: domain of 3kmhgxgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kmHGXgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

It appears that compilers have trouble with nested statements
expressions, as such make the data_race() macro be only a single
statement expression. This will help us avoid potential problems in
future as its usage increases.

Link: https://lkml.kernel.org/r/20200520221712.GA21166@zn.tnic
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Add patch to series in response to above linked discussion.
---
 include/linux/compiler.h | 9 ++++-----
 1 file changed, 4 insertions(+), 5 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 7444f026eead..1f9bd9f35368 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -211,12 +211,11 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
  */
 #define data_race(expr)							\
 ({									\
+	__unqual_scalar_typeof(({ expr; })) __v;			\
 	__kcsan_disable_current();					\
-	({								\
-		__unqual_scalar_typeof(({ expr; })) __v = ({ expr; });	\
-		__kcsan_enable_current();				\
-		__v;							\
-	});								\
+	__v = ({ expr; });						\
+	__kcsan_enable_current();					\
+	__v;								\
 })
 
 /*
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-10-elver%40google.com.
