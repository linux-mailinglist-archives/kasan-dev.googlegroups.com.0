Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJNOW3XAKGQEM5EWGVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 42F76FCC97
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 19:04:23 +0100 (CET)
Received: by mail-yw1-xc40.google.com with SMTP id r138sf4135114ywg.12
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 10:04:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573754662; cv=pass;
        d=google.com; s=arc-20160816;
        b=WN7csrkj4M0d45IFf8rCoFc2UP8ZCR2t4EwDw8g1A7uWoF8v7G9TGFV+mnvS7Ni7vV
         OfUMuNzoKwlegwPgC0W/1HXrHQ7TWN5NKtbHmBNdvo3P1m8hbH6Cbt3G4ZxLCjMB+0K3
         nMDAKqxAGuXyMeTBFJd4m+Xr1OPHyYTxv6VbfHuuFQFSS3RfCmZm3bFPolTWBv9HGh2W
         4VAcG6MiHqpedWfjMEAUi1M6AXGitQ1fe7/pX2ld4EE7wuyZKsEU+TOQW5dqYHF6R27w
         8Kjm8FYyByu0DqsWFKAwowYTC/yslzs5Qs4FXjdyKs2BD4n3rKd04uRkfx/Mc0wjXcx3
         UIaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=U6wiT7I1TE+T7kXCeRBT8B90qPb0dhULpdac8WKS+mI=;
        b=G1xwN4Ve944e2dbwYb7n9AQbm0SLfCIps4M4Ly8cE7ATehBPrlBNiex698n+WmTwBr
         ZUd7X/fSDNY2TBXEG/OTgMRPBp3iM9yugZP/nXBVdhfoEZHaVAXY3cLDeKzNNjg3R2JE
         kByYtbYSd5OwzlWIBpMWvPKb1MGItBzbOoLXUnUZOQpW+jM6r/gEZO76KEaPMAG8I31z
         gCzxgfvmPqgRzu1Qw7kfH5dQha3zmRKJCe1cTzGuVg+qMeq7UAtL1C5j2pbW8nvtYJFZ
         e43/ZzTbsvvV3TrmSd/KBPErcNUqDyqtUhTfm5U4/6iVVOrQNO1eSkrGA2+joU/fbCwF
         8Bwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJoHEAo5;
       spf=pass (google.com: domain of 3jjfnxqukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3JJfNXQUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U6wiT7I1TE+T7kXCeRBT8B90qPb0dhULpdac8WKS+mI=;
        b=IPAgFaLr+hyRFteFKgpmi63PZz9ob5RAJHFlFOzKLzsKUiXbuvzSKqi7pyjyJhbw4A
         h/86B3+/Df5EEaT1rLkWLr3wCfkPyUy5hDkck5jNpgPbvjolMMFcODqBa02y2ePrTDOD
         sGX/nTuLeR4dil3qHTMh+EDh/tpWxbUI9T8TXLht2ha6d7wutlfrI/pxDXgiCPp1G9uK
         RRTYAKfHb/MrytwPl7EHv3NiXKFWOnP+tsgJNUFWJ/P3VYp27yGaXc2tryFv2UGSri4n
         nJKoyRLumtQfunHc3ZLU7MoghT1Xxjs6EftWWs+hCwtPp6pfrQgbthjXa2yPqcry/z3W
         81sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U6wiT7I1TE+T7kXCeRBT8B90qPb0dhULpdac8WKS+mI=;
        b=iTD/V3w2EUEWtuuAB2zuOmH8yHSFUHZWYOa9/JGzKQ6UrbksTkDOpNEOU8//XfxDcF
         zxj6U1wDd0V/P3IDHZFGcjpGHJzjIkLFhIWxM1OIsqBKPUtwjzgGvVSQe6mziinbdLKC
         peE1A+nuO7FE1C7gzXPvY6chHdeYEPkhppjI7MtUmkviXcbYoBfjEl5nE88wy5JMCKbf
         t8ZVLl83KN4Ymrnoauw564My6RjHWFargwm3VZThQLk2AtLqciHoVCE6OF4lydX4h0Qo
         oKRMs0y9bN0rMM0LfI3OOTb5ZaP/0PaJ3kwK62aBabAklkTklVwUfyce3HycvZMMkTmh
         4/4A==
X-Gm-Message-State: APjAAAWqN46ODPznwtmyKkA9sDRpWWr0NR2G4ezHLGDYAFXq272wjluM
	0iorkI26a50XJTpyp5EjsLA=
X-Google-Smtp-Source: APXvYqxoDP8En7quUeZqnkGqYxiK6SvCi+BN0It8icgOlwzx0LYRqF/k32rqa9ePQLT02Jt3FXWOng==
X-Received: by 2002:a25:4688:: with SMTP id t130mr8380885yba.515.1573754661953;
        Thu, 14 Nov 2019 10:04:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:a046:: with SMTP id x67ls441647ywg.1.gmail; Thu, 14 Nov
 2019 10:04:21 -0800 (PST)
X-Received: by 2002:a81:4fd3:: with SMTP id d202mr6985936ywb.333.1573754661468;
        Thu, 14 Nov 2019 10:04:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573754661; cv=none;
        d=google.com; s=arc-20160816;
        b=bnrZzBQGFcHxUWbODFXAQGA0UqZFDR8dba0/Gi3Lnav8BSqxmbszXuZJQ9NWw92zfb
         y+DdTmpBkSgoh0cbW/b549VN8jJygnf4XkqfFFBGpxuhmtkTFserISIwEJv5VgDT5gN5
         Kq3otJZI1vSt31kZfIiMIq3DYjZDV7Fqo2G9thIAkIE+iGwkO/JfkUhpEiFmGr7IukPu
         dOZiaYWnlyfnuoC60yUCRxXZJ/3F6H4izJ6xBCwFhMskySMmibCvf+8+VHUUc4qb53Ym
         NkxphGR7qJ9RklJvj/6+Cuo/VKof2rOeLdIqQnR1icchvkb7mmGuWmt3QJYGlJaUJQoo
         vyZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=A8ALfglUAafCNqhIvaCjHjdAel0vCMD5ZtmY0/3TtjA=;
        b=DGC0TjFrlqmapD52nEYn92TwmfHCGBS/MIxWym/EuBKyHiKuctX9bmks0Js7u0tUwd
         RazPxFu5KbON6Cmt+jbK23GFTaPtJBTPTewKdbWX8hX/fDnbl3szPBUEW67ch6i5UTWH
         TMnvG6ma8zoCPZWGRm0B9dDueG7GeJFlKD2BbgSo13olMvRLCbYa9AkTJIT6zuh0iUgN
         CBD2q5KIXDZt00TYs5aFZgYqFZHK58MWR2xg/hJ9rZJnc12N80K3GXTbIKG7ht35Gapn
         zURgzNGJR2lIH10+CFrO5v8vmClACsFtR+nZBOraJXdDa3AR0U8NCsFTBWRz9Nx6wve6
         Rs1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJoHEAo5;
       spf=pass (google.com: domain of 3jjfnxqukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3JJfNXQUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id r185si371923ywe.2.2019.11.14.10.04.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 10:04:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jjfnxqukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id n6so2944629vke.22
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 10:04:21 -0800 (PST)
X-Received: by 2002:ab0:2395:: with SMTP id b21mr6064758uan.122.1573754660635;
 Thu, 14 Nov 2019 10:04:20 -0800 (PST)
Date: Thu, 14 Nov 2019 19:03:00 +0100
In-Reply-To: <20191114180303.66955-1-elver@google.com>
Message-Id: <20191114180303.66955-8-elver@google.com>
Mime-Version: 1.0
References: <20191114180303.66955-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v4 07/10] seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@kernel.org, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, edumazet@google.com, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mJoHEAo5;       spf=pass
 (google.com: domain of 3jjfnxqukcx0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3JJfNXQUKCX0fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com;
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

This patch proposes to require marked atomic accesses surrounding
raw_write_seqcount_barrier. We reason that otherwise there is no way to
guarantee propagation nor atomicity of writes before/after the barrier
[1]. For example, consider the compiler tears stores either before or
after the barrier; in this case, readers may observe a partial value,
and because readers are unaware that writes are going on (writes are not
in a seq-writer critical section), will complete the seq-reader critical
section while having observed some partial state.
[1] https://lwn.net/Articles/793253/

This came up when designing and implementing KCSAN, because KCSAN would
flag these accesses as data-races. After careful analysis, our reasoning
as above led us to conclude that the best thing to do is to propose an
amendment to the raw_seqcount_barrier usage.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Paul E. McKenney <paulmck@kernel.org>
---
v3:
* Add missing comment that was in preceding seqlock patch.
---
 include/linux/seqlock.h | 11 +++++++++--
 1 file changed, 9 insertions(+), 2 deletions(-)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 61232bc223fd..f52c91be8939 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -265,6 +265,13 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
  * usual consistency guarantee. It is one wmb cheaper, because we can
  * collapse the two back-to-back wmb()s.
  *
+ * Note that, writes surrounding the barrier should be declared atomic (e.g.
+ * via WRITE_ONCE): a) to ensure the writes become visible to other threads
+ * atomically, avoiding compiler optimizations; b) to document which writes are
+ * meant to propagate to the reader critical section. This is necessary because
+ * neither writes before and after the barrier are enclosed in a seq-writer
+ * critical section that would ensure readers are aware of ongoing writes.
+ *
  *      seqcount_t seq;
  *      bool X = true, Y = false;
  *
@@ -284,11 +291,11 @@ static inline void raw_write_seqcount_end(seqcount_t *s)
  *
  *      void write(void)
  *      {
- *              Y = true;
+ *              WRITE_ONCE(Y, true);
  *
  *              raw_write_seqcount_barrier(seq);
  *
- *              X = false;
+ *              WRITE_ONCE(X, false);
  *      }
  */
 static inline void raw_write_seqcount_barrier(seqcount_t *s)
-- 
2.24.0.rc1.363.gb1bccd3e3d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114180303.66955-8-elver%40google.com.
