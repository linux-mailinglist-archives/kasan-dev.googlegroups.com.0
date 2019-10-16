Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNNPTPWQKGQEQSFIONQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 034E8D8B52
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 10:41:27 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id z12sf24251139qtn.3
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 01:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571215285; cv=pass;
        d=google.com; s=arc-20160816;
        b=MEJvyIrITEc00f1MSKfKPxs54MopuR31/leTtEQA3Tnu3l7Qu8gHIYMGY1v4GOexuT
         BuCyQph2H3tq8uNZdLDCfRF4IFMlBCIw8XWwnl56zuZ7YZ1gCxtA7+akgwtmQ4na1hEO
         YCRnMpmGXWLmkTb1QRrKfgwfWe8Kf5IUeUL9Duuc+OV3drm9Tynnep2BJsLZXcPxI+OS
         fJPetIJoGTzhVtfHY1nT6u3dvYP9IwvVfbhyABxilsZn2cxwj9On03CGZtlhaq2vWS4u
         ysrUIqLS9ZGx/b2eMXHOHGGtuO55XBJ4FQr/W5tWr55cfHuYa7yerNAJ6TAxsP/Id0yJ
         fkXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=K8t7KPLFCxn49lM6lGACWMffN3CUW0cdXtyZBm/cqxw=;
        b=oIpgq1uU9qeDHC9qGu39PJarCo9PiRXY4pOerbq+FuAvneVUm6NCtHY2aDTYPau+G3
         0BZqvnOogpMeeQawIjLJXdxg+V83NY0PUq/Mj+9BYRH72yXij4k3CJAzgGks8laSiYqW
         lqJvVbx5SdGA8XO9reuAy2O83LAFKiLkNwe0IJfWA0222oDaMSrcFTTv8lbvueFSGFCI
         aFxRDOZ9r70ceGj+fK8jX4QGwM45j9rm8lkJmbBFMvuqXZUXkmVm1Rp8XVfQ27ZOJWPD
         MISyoqmLZkCSfIGUX7osHtDMSxA9jfmb6Z0m+n03JnbMhEGuCOw2PCx8M7OWkgBnRYrm
         njYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmKyjAi9;
       spf=pass (google.com: domain of 3tnemxqukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3tNemXQUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K8t7KPLFCxn49lM6lGACWMffN3CUW0cdXtyZBm/cqxw=;
        b=sFNZQQda4Iq9fmWDuB+Sfvu6d3CjwEHseFgqQZev+1LRkGh6jVxsjfLrWXzoCU4Z5s
         8zQ70vXMNXZa7KgzprcEQ0uKkxdg8o6SvhqdyYkFLIYzscmIRdSGemdgcD+U9tmPNUGD
         wMO1Rn0iVjhxnANgRB6i7vQGfgLkexeOgxk2rUxDsNUdOfPgAzAhnHHVJ50b+13WhllN
         iKELtra1WYwVHAPRfLeVSQ8P+xF1Ly4gMXHpwH4IR1WwYlRkfwJCzYGvlmpWF48G2r/Y
         aa0iIVluNQepKiksfE2vJiMRZ1Qaokla5pI12QII7EzBnpS9xYslrpWWFZ8DD178QReJ
         zp8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K8t7KPLFCxn49lM6lGACWMffN3CUW0cdXtyZBm/cqxw=;
        b=UFfKh/QYjYkszBk3RjwWdJomCWK06apiVWCSbIO/uW0gTbpI+pNIhPt0nn6ajkVGhK
         wOIJ8d3zGYyibRZxAxWZnr/3yqkfnk1IK9JCm/B8fRpnYNRTEwueC/6NZsuprvpbvjJl
         2CEOffKZ6t/4xa7m3fTGd0fovdIG+8u47uG/IIsn2MN/9jB80g+miVsC6i1/SypDZF9V
         AYBK9n02xIfI61wOgYLX6bbajc3bDFOesULt4vBCE0/B/mF+cTeYDODVJal3Mz78zUKI
         EG9LJap/CaOF2CWgujT8SuXSTX6E0ONIvzSEE7ZYOe2NrBQyO3PzyGK+0xdPGsHm+KrW
         +BhQ==
X-Gm-Message-State: APjAAAVOV0Q/Qy8j7AWx9A+3wt0y5IO5jpvx9AyKyasFC9HAbfErm3qj
	XBEWakqkUsGnWx3/ntj62tM=
X-Google-Smtp-Source: APXvYqzorEG10Z3lnoEx+ATOWpKI6++YsZp5hvkjBPxJ1hSm8keadv20P9XFJqBT1rKPAZGdKYvJIA==
X-Received: by 2002:a05:620a:2158:: with SMTP id m24mr2491094qkm.250.1571215285695;
        Wed, 16 Oct 2019 01:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7587:: with SMTP id s7ls529140qtq.4.gmail; Wed, 16 Oct
 2019 01:41:25 -0700 (PDT)
X-Received: by 2002:ac8:3215:: with SMTP id x21mr6803218qta.172.1571215285333;
        Wed, 16 Oct 2019 01:41:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571215285; cv=none;
        d=google.com; s=arc-20160816;
        b=wClXScSIjk0rB561wafOTEvETNf4bxT1830sgl0YZVahDn9lZx/zisWFgd6VzAPQSM
         CaKrB6WZ8mWdiXhTyWmslJZf8FkgrmGvsTuGb8NLFyUY/cBQe9gxuqpjzEB9mNVAZ+no
         QY3NKK6FGqlpH52Tf5sR5T7SUgKlx8/rvQVqIGgIu2+uYtBvMYjbn0xterbO91NKd8u6
         jtgTI72Kl99I0Wns3klmZdwKG015zk19apQn3lhiwsNLgIt4NI+FYGhmfrFBgVQyF0Ub
         3duXK3wqSzIJQPSF17dnMSaXye1+s2xNqTXUcndJbTovapHMLcLu/vPiV1OhWJkHR5K1
         wUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=6B6hVR43CAiybn1r8unXu0YGQ/l4GfBcUZa3qNay/Lg=;
        b=Mi7lE4pP0NPvcFXh5orThuqJ480jG6JftoTcwCcPbKFjcDvdMQ4TaLUaV8Q4t5OfMO
         lfIBTulQ+CQwDwTZrD3y9PTMwFIJqWip+XK99BRHpd/kXbVAFHwTEKrMndfzDyH9oOio
         lCF9cm+hOJ4PIN21OaAF88K/kjNGQi/y/Wsf2fEnQAR6E92egPgQNAC2VuF8k65O1BtB
         V5un0f7cDO6UBTq+jOUVO8lL0Y3phDYvCmB99de+KoYFPl7P0mnXRRTdpXpeCdx/l8bJ
         aDY+aUL+6eZLK8fOAC3CWggafWCAf3cPecn6sxdh28Btk5wu87RWaLNJ9deDxSjWwwP2
         roAQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmKyjAi9;
       spf=pass (google.com: domain of 3tnemxqukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3tNemXQUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id l189si1722585qke.6.2019.10.16.01.41.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 01:41:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3tnemxqukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id h10so24184212qtq.11
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 01:41:25 -0700 (PDT)
X-Received: by 2002:ac8:3724:: with SMTP id o33mr42240619qtb.87.1571215284755;
 Wed, 16 Oct 2019 01:41:24 -0700 (PDT)
Date: Wed, 16 Oct 2019 10:39:56 +0200
In-Reply-To: <20191016083959.186860-1-elver@google.com>
Message-Id: <20191016083959.186860-6-elver@google.com>
Mime-Version: 1.0
References: <20191016083959.186860-1-elver@google.com>
X-Mailer: git-send-email 2.23.0.700.g56cf767bdb-goog
Subject: [PATCH 5/8] seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
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
 header.i=@google.com header.s=20161025 header.b=pmKyjAi9;       spf=pass
 (google.com: domain of 3tnemxqukcfexeoxkzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3tNemXQUKCfEXeoXkZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--elver.bounces.google.com;
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
2.23.0.700.g56cf767bdb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016083959.186860-6-elver%40google.com.
