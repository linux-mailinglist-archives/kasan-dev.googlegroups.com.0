Return-Path: <kasan-dev+bncBC7OBJGL2MHBB445TCGQMGQEDR6H4EY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 689C64632F9
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:45:56 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf7749519lfh.14
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:45:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272756; cv=pass;
        d=google.com; s=arc-20160816;
        b=uhZiVp3e9KPVgrcX76u5s9RpPxSuur53LKqTi8B/05cvk3Mog99Mg3Ocl+HItHLlaI
         LG8oxQ5MlLVmlIs/bK5ad8TWvxfEV7CgdM+xN3OfipCPVkUu2t+6qv/dfQad6eiIUk5E
         sTjRH3celELfo8FQmJNCSyFd/FBWrnoAsVuqi749zEEa/HvrbdbD9Rj6Xc5dHWt5s9PQ
         FSHjlPa5BbhOSoYLP9/cNzZpup4lgurNYPtP7KWWQth9qcOoEGR4exE1brWsQqG9FTji
         xTSYBmpYK49AxJrtVvGs+b7vYDvjYBKohw38o1VTle4rVNJZwh6yqvHDKLbOSQ7OSQLI
         bMXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=4H2zBhBYu7pNrCfvjdhd6Dg4wH2T3ZdCjWMK6kpyk4s=;
        b=MHVgo2e5eBWP58BZogzT/w/RE2xHi83SfwACXNyKtkA1vEErUmmlnrFpfPqEkPcdyP
         CujeD32aZrjF4sRslIjR6u83T4mc9BZV0ZSSzgqfAyaM4r2R+GLxVO+LtgjQePAa1PWa
         wrwXfRvAO6MYjr2vTIYZsMj8DgWHK4cHB4nWhvPIxMQpLrTeYoxqTGGk4CBfg5lfRZXh
         1JYaPRQkff2QAHnqxPEFmPb2lN4Woj+9mDp+LzbQ8pCv2v85+C1k4OErLIb16irDM21/
         xEY6zesZ7ZfJSOI39aE9lQRy/LQWlnwh6hHBiIG9I2A2FvJPi04zj8H1cYMRDQHj3DdZ
         oy8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YAPrqaSv;
       spf=pass (google.com: domain of 38g6myqukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38g6mYQUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4H2zBhBYu7pNrCfvjdhd6Dg4wH2T3ZdCjWMK6kpyk4s=;
        b=E5v02XBm/Fj1mN5aTTH9lzmewLqHFqmPDWYyPskWCmugPwZIE0S7pBh0TCNOUnDZLy
         hNAR3vN2dH8FF+sCRJs7CPQkHHsBbRXrg1umKtU+ozlEoGTaCh9ziBa7xq3tHFcPv0dn
         AO3ugbT9rO1KWXw8L2HzaKIoiKrdQxy+r2r+rJaCFslslp1Tm5OMn1Npr0ePl8J/23ic
         Gh7i48k2FgmRXwsxId5g0dyS/564z8Eyxe4vPQNfd78qYkT4ick4aytpy694YU8vF92T
         0CNEefwuN7B8bR7WNrLfqjhV+2jXASljDMLl4PmCFkaS8eaxMmAvJ+qlCDT0xPQsNhHI
         TfZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4H2zBhBYu7pNrCfvjdhd6Dg4wH2T3ZdCjWMK6kpyk4s=;
        b=cJUpWb+BdKeOgaqjOQnZlBEQ0BdAuhO2XcvYpZSH3UsKmJ18QQTnsqYbiXs2o1eEfe
         Pv27gdV7hu+6g27/mXrHWe4gB/Ad/+Pxcm3HesiuA8WTwI4RwWZzMu3sPazzaqX3fEUp
         R32ELRMVAc5WJswNTvzSzCPKvWHBkjcrNojGcuK6uHxkhlAFR6PkCyYToQlU91241qAn
         xYWDRLZ+AB8FfSoj3RqX2J5ab0Mz+DZ0O+T/uNWMg2VMuXtt1Ic6RYVqcX7myKsg2NRY
         QUJ9C3quRUyo4ZoLsKL/wyxVwH1WGMH4caj0wzOOnP6xbdoC5WEkudAWxJ4r0NYYQuEY
         JYAQ==
X-Gm-Message-State: AOAM533+76fzw4KCityVSnP905RGKuC+4EgRGDRGshT7r3bZTonxQQjN
	+QPj4X1vf8BkbSDA73GLccQ=
X-Google-Smtp-Source: ABdhPJxE4Tnj3MJaplCCmxp1IZWBKQ9bvIzUvHWWLrIWPMj/U6cSC0FjTLZPguHFXxa/ZDFWUvYc0g==
X-Received: by 2002:a2e:9b17:: with SMTP id u23mr54755419lji.258.1638272755991;
        Tue, 30 Nov 2021 03:45:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls454591lfv.1.gmail; Tue, 30
 Nov 2021 03:45:55 -0800 (PST)
X-Received: by 2002:a05:6512:12c4:: with SMTP id p4mr53497319lfg.274.1638272754954;
        Tue, 30 Nov 2021 03:45:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272754; cv=none;
        d=google.com; s=arc-20160816;
        b=I+Q5tC1rE+rsJKQRJ25FqW5shoiRa7ecrLhmBjj/G6FiMr2xXkUuBBQCxaYwzSiTDl
         asVVYCOJqjHytX0JMLhwy50ftpqyiGRlPhALBrsjGO+UYLQ1sridj2pV9bUvT2OeFeX8
         /nn/wL4EcMk+c0d4DDhVgq97AxT7EyKneeKT2b0MDo53ATkAv7N7MadkpJt79YC9aDgL
         WLxKRd9AbrGWCNGVHKkS61FteGibhJdKeGFye1e0FPi3WU1KaAy5Yo6DTWRE+m7lGQdQ
         BfZaJuJavkCWj2nC71eYD0YlEdDLKsXY3nW9m5qkiu/1wEktrQu7Pxrge4LWxhevYDHH
         rnpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SnYVQxLC6YSHg0QBspCa3KEICf+BvvptqJyS2cHTmDQ=;
        b=WA7c4t5eBWZDnaVljTjwLctsfAbf9KAC/vUqzL+U0VwU+DdGKWKiWXFnVcZoQMAclh
         O+U4yxZozc/WdZQ+Yvlpi+EmjZqswkqGVn/NjvG7k7/ZCGI35O07/9FLXDWVaUXQWsEw
         T+OvZTELMUBmtUn8/UA8cHvZA/AtiyUg3pixIcWrIQu51U7exzXSNTmEKV4Vb4zDlRLR
         YLEne+9rakabofalaGxP/dsD5ghazk+ZaH7+q6CSZFZLOE/qLi9Kigc6h1AT8FhWxSAX
         2ae2RXkHlhoPOUE0IDCZC/VcYQeLhmVniWGTuan6NShGMWxu1IwtXplR5IFYvNsGUvRE
         2T5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YAPrqaSv;
       spf=pass (google.com: domain of 38g6myqukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38g6mYQUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id d8si1481051lfv.13.2021.11.30.03.45.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:45:54 -0800 (PST)
Received-SPF: pass (google.com: domain of 38g6myqukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id h7-20020adfaa87000000b001885269a937so3536510wrc.17
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:45:54 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr626057wmq.0.1638272754116; Tue, 30 Nov 2021 03:45:54 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:29 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-22-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 21/25] sched, kcsan: Enable memory barrier instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YAPrqaSv;       spf=pass
 (google.com: domain of 38g6myqukcbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=38g6mYQUKCbsfmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

There's no fundamental reason to disable KCSAN for scheduler code,
except for excessive noise and performance concerns (instrumenting
scheduler code is usually a good way to stress test KCSAN itself).

However, several core sched functions imply memory barriers that are
invisible to KCSAN without instrumentation, but are required to avoid
false positives. Therefore, unconditionally enable instrumentation of
memory barriers in scheduler code. Also update the comment to reflect
this and be a bit more brief.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/sched/Makefile | 7 +++----
 1 file changed, 3 insertions(+), 4 deletions(-)

diff --git a/kernel/sched/Makefile b/kernel/sched/Makefile
index c7421f2d05e1..c83b37af155b 100644
--- a/kernel/sched/Makefile
+++ b/kernel/sched/Makefile
@@ -11,11 +11,10 @@ ccflags-y += $(call cc-disable-warning, unused-but-set-variable)
 # that is not a function of syscall inputs. E.g. involuntary context switches.
 KCOV_INSTRUMENT := n
 
-# There are numerous data races here, however, most of them are due to plain accesses.
-# This would make it even harder for syzbot to find reproducers, because these
-# bugs trigger without specific input. Disable by default, but should re-enable
-# eventually.
+# Disable KCSAN to avoid excessive noise and performance degradation. To avoid
+# false positives ensure barriers implied by sched functions are instrumented.
 KCSAN_SANITIZE := n
+KCSAN_INSTRUMENT_BARRIERS := y
 
 ifneq ($(CONFIG_SCHED_OMIT_FRAME_POINTER),y)
 # According to Alan Modra <alan@linuxcare.com.au>, the -fno-omit-frame-pointer is
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-22-elver%40google.com.
