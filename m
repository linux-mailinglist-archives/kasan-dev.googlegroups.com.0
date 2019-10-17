Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFXOUHWQKGQEVWJ4BFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 46606DAF66
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 16:13:43 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id o92sf1573350edb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 07:13:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571321623; cv=pass;
        d=google.com; s=arc-20160816;
        b=F8OHZg4LEoAMc4LbaIqs6yObRZN9IjyR7xmzs5OmEtAuj9PdA6lX6627SkbO427ajT
         5yUhXbLgyGu2H7ARiARZViq6fQAqrMF2ROMvIN+yLCjnQ61MZQeiGmhBklDc45EqcKMf
         p0FrzuBPAJpi1+5MVB/BoV8ZArd+/OlkCfykg2Rv0yBR8DeNnUmmIijAABHFTbdMvBn4
         z2ZO1rvmMWrmJLyItqoP4DzOG38l6tkonSZraOUEBObH+Y4X48r0f7PnCqQhvnO+Ibrm
         iLdiBgF70ovbcxJkFhQXgwclgLMVaf00HUs5aInNNP3Hru5RDK5JihK4ZjDBWFYSFnLq
         2DSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=i11zXgLPF+OlSc5/3n460GlZXqvqpi6MmJv/wHFFQUw=;
        b=ticKk73y6Xo8K11mhmxW/YI9+fjT0DPfmVOtXeB9hTwh2cybGkHDoJSrGG1fXhIN+x
         Ur6M098oAo19+kKlbOnWTZph1QLDSWUVc0Sp59BuMr16Eg5Hs2GEJhyt+HvHwBBgDlbe
         jm0fZnYoIb3N6jlnLlwY6wVjRaS5vS6Zhn/pMalmFyDrHEe2Xo4qAvyDZr4YnRPrX9Eq
         cbFQNCYPUIqi7KO3OYhw1DdWPYbIwwZni7VfCGQnCMHY9DXjRbLnAyv1+riy7feZHJbQ
         YaMZ4MD/dVOXEj7bdtH8cFXrYnWYRDpwxT73vZ3mFfZYsruUbSVIeMXHTkRAmF8xrLuk
         KusQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nw1HzU4Y;
       spf=pass (google.com: domain of 3fxeoxqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FXeoXQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i11zXgLPF+OlSc5/3n460GlZXqvqpi6MmJv/wHFFQUw=;
        b=CyeeYFkRd46oS4VUadXhZskx4XWg0UaO9AGJrxvYp0MjJ4ivbTUY2drFXVN8S0phvE
         xR/fr+h4Jbq3XTCsq7719nF3LIUSBOFD2j173vkkkCIT/I2ItKIuLIYQP4D/o92H55G5
         vcjYNX1SjK1UWm6T92be4ZjWydYFsUKHMmEpy6Eas9fBE7jF8OgEsd/TIgRTwMHYPQwu
         UWzlxjwBDQQ2oS2bajJ2fIJKwCqE+h34t7Rzwg8obHus5VwK3V5vSF4y9SK5SfxidZWE
         nhfrg/88kNjOvsK0lAs6YwzEqvpTq+zbzJg/C8gvgHwh+KfzgGV/xIwvLSQj3+YrBtuZ
         PLuA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i11zXgLPF+OlSc5/3n460GlZXqvqpi6MmJv/wHFFQUw=;
        b=d4RnS2eJLa2fy2pv/hQXAhQpTtV5ylns+3kRCfU00WEqJY3a0RUNBurMHCpa3VT43p
         KoxOkR7lmaqmHytr0I/fTKP9tI/MMyT/sMw+468et4S7R+SYHy5bfb3MwlrHmPqmdcTT
         K0oWb+VXeAGYQ+XYrb8SfOahYq9idyRNW+S1ktQch4ddkHP4vzovMYkT2gH2gSRVKXls
         5fDDzXybOSbrVy9Q7/6D9DjrMFNMgX+TEJpK+TVBN8t4UrAbg/nQhkXHPFYqi/i5HkvP
         FQCel47xIBTdAlzOHtF+w9FrFuFSNIlWwH0iwWZnPxdMSmnje0DlbvCU85diWftKiE03
         RsvA==
X-Gm-Message-State: APjAAAVp/3YQ7HtX5kkvjIg1k+AOCLR5nlddbCH1VejBnWeCddrlIwR3
	HjMs7s/H72hbg2NeKBEJSIY=
X-Google-Smtp-Source: APXvYqzvJeVOr8Sq8538+7kxwL8ahrRYELpPdQigrZu7Qn9vacqangHkSr8/nms1ga9FPYkvWvH3Yg==
X-Received: by 2002:a17:906:f2c1:: with SMTP id gz1mr3662280ejb.51.1571321622933;
        Thu, 17 Oct 2019 07:13:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:69c6:: with SMTP id g6ls599933ejs.10.gmail; Thu, 17
 Oct 2019 07:13:42 -0700 (PDT)
X-Received: by 2002:a17:906:54cf:: with SMTP id c15mr3732966ejp.202.1571321622363;
        Thu, 17 Oct 2019 07:13:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571321622; cv=none;
        d=google.com; s=arc-20160816;
        b=dar4WwmBzv92myb05Hx6ogx5X2oGQZuoxIgFlMdr1NtMMVHYa8lVER7c5OYM/tA2oA
         ArZ2jTjGcX0HfzGDV4cn/x9bplghboPq/134FFscUdlucf/o2qG/6+k1gvZAZoL3/xUR
         uauZUoUyPPzdGcLH8lSIKXjuC2pNkhdJit11KJ8Z5brcDBq3N8tBylQPz7iO2cCn3AWK
         ZgVixtf1L1efNUxE4NdIJaOrHGq7l/joaHmVc5XIjoyAdxCJlsjbz2gNY16goPaosMpU
         64B6gn7uej5i0N16eQ9i3MuVo6tP1NRiXWCdWy9lvyIPOABpl1nsdzPrwowct8LMZo46
         j4Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=3gVtAYjAise6qkpXvJpnBc4+Dg01VPHxIztWXKyEDrs=;
        b=pnHpLARMPA+TWxNZv1CRpIfF9nRW1IQQBv7bYQHzC3LjiIciVQq+Oh5WS6uNxKKeUq
         e1vJBu5OKLOt8Apor3Z4H28nNEFI2iSY2Qq3XaAbFNtdZPoXThCgkqzvG08UUnDwztwH
         DH2P/RVL5d71kUCRRxi9hzFwnB51vPE5bit8gfZIHipJZubGfpJ+cJuhVJ5Qo1X9YylU
         wHphyOeZw/6mR7xQUytnc2DTwqikFeguhI98TBKiFR7u0DuK2W7WueYfLtlbNSwBWB2o
         uV0J1SQt+EN10sr/0s185Zvu6wYbbx7Fuco/GhVRF0jMpV7HKaza26YHW3W+88DEiGpl
         heCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nw1HzU4Y;
       spf=pass (google.com: domain of 3fxeoxqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FXeoXQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d14si140912edb.4.2019.10.17.07.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Oct 2019 07:13:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fxeoxqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id k2so1027089wrn.7
        for <kasan-dev@googlegroups.com>; Thu, 17 Oct 2019 07:13:42 -0700 (PDT)
X-Received: by 2002:adf:b102:: with SMTP id l2mr3493651wra.269.1571321621593;
 Thu, 17 Oct 2019 07:13:41 -0700 (PDT)
Date: Thu, 17 Oct 2019 16:13:02 +0200
In-Reply-To: <20191017141305.146193-1-elver@google.com>
Message-Id: <20191017141305.146193-6-elver@google.com>
Mime-Version: 1.0
References: <20191017141305.146193-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.866.gb869b98d4c-goog
Subject: [PATCH v2 5/8] seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com, 
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org, 
	ard.biesheuvel@linaro.org, arnd@arndb.de, boqun.feng@gmail.com, bp@alien8.de, 
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com, 
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com, mingo@redhat.com, 
	j.alglave@ucl.ac.uk, joel@joelfernandes.org, corbet@lwn.net, 
	jpoimboe@redhat.com, luc.maranget@inria.fr, mark.rutland@arm.com, 
	npiggin@gmail.com, paulmck@linux.ibm.com, peterz@infradead.org, 
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nw1HzU4Y;       spf=pass
 (google.com: domain of 3fxeoxqukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FXeoXQUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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
---
 include/linux/seqlock.h | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 1e425831a7ed..5d50aad53b47 100644
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
-- 
2.23.0.866.gb869b98d4c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017141305.146193-6-elver%40google.com.
