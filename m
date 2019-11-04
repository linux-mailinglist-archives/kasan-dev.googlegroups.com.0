Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNXLQDXAKGQEIQWQBTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DEA1EE260
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2019 15:29:11 +0100 (CET)
Received: by mail-vs1-xe3a.google.com with SMTP id b3sf2797930vsh.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2019 06:29:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1572877750; cv=pass;
        d=google.com; s=arc-20160816;
        b=qFYYrKGjTqG2ZxLQ+u3RRdPBKdYEuxsItmUnvruBj+hMK/NZTvBdxpFTS249SzjL8F
         /XaZpZI05I9AWSqV9agYJSD+55/YZPXM5diUikBLv+Qk4WqsXrDFVbKxii+BErMRokby
         TJI9TOQdhRorb/tikoTnaDkqpgxdVyree+iWEhmVN6j0EuZ1m+72GM9avxUau35+BBqL
         zkMSroN0BTt42h4y7UjDbuGU2HekQtwUa9xYbKtKprbQVdagTak8/GCvIzDaxtPEqBes
         /Xn0MFQRSuAw3bgueVpHLzYK+rTQZa8HBYuJx/eDrvzqZxERmuSXzMKWxsDo7rCaHX3z
         kmLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=A4PBEnaKXp0iTF1aGSNzrvNOsAtj3lB8iU6voRx8DwU=;
        b=bN/jeLqkLKtlcrKDIFZyBPx8P5jG9T3xVEWXHvWcLYroSIM/5ETKXRQB9uj9O+Jqfw
         uZFBhW+mWXU/szzCyd77MsIGyG1JoiJf4OjY1bRG63huWYe00xLbuQbe6RSgCg7JMCrc
         eSCcG5kBjj0JOSfHcsVqcLcpBwt+4gyxDmr4EGrR/2xWuB8BVGuh3wMynsujO03mOIsk
         HBoj5aRNMjvCsGDlwDkA2z63vrTIJblBAWLG7i3EgLhtt3ym62CQX5HokusaLNzf7gMu
         h9sPbS/GYutuITdqF2t11TajNQANgMcCgzfVRe2ov6X/qDPdK+GDf5GciQ0oq5sURO0R
         gNOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FhPDq8Y8;
       spf=pass (google.com: domain of 3ttxaxqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3tTXAXQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A4PBEnaKXp0iTF1aGSNzrvNOsAtj3lB8iU6voRx8DwU=;
        b=WX0XxFmEzSf67Rox218wVYJjwyprwk6xq/Ldjzrwe9RRIozQ2OfITYjgHBHDvt7hKE
         bT6YdtJkUdAcZ/TT1glqXNtJGiyq0cvMC7BXSAYttG66mGCsJhAoe64H2ppAU8Y+K7Qe
         125i0vO1pMWx/SRTUK4inhHspWpTWO8sicYUIDe5/7GgnpDkrM4GibzCP3/kBMj0CHbX
         F6FRni6/Ks6SRrf5QPZidYgu63qF2FOCxHrJlM0l9QVybdQ/tLn2Ax8bE+LXHwvZrlwM
         bKcfOJUxgDh9+PaajRLvq+2+aR+a1UVJGju0UHKYComfpYqanFoqk7nZx7wxNf7RVD6x
         H2Fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A4PBEnaKXp0iTF1aGSNzrvNOsAtj3lB8iU6voRx8DwU=;
        b=WKKRqjlHNFG9N7d0MWpSd/fseWQ34lSwqIknd2hkJ2ksxzxtbGN+QdRlHrqcxyTXN4
         UH18dbPF7i+ewHZGi2yf9BukiQbYxdDG3leubfb4KK6XC2tAO+ASicvOwPwo5TMjamPY
         PhWy9FwOhwHuRw7j5f5hC0MHbtqGPd16GkFTldc8gSEvUxzyyArpzBlEYmlNHXxEaDdO
         09tr1uyjwyqbvbrjEMqbG/3Ky7YVSaOjaIuhcbb1dP6Pr7OqwRRX6IUX1FC+bwBjucL/
         w4TpD5l1tpebWkQ+LiUlsYE8cbsd5kuHI9teUk7ZqTB6JQsDOhIfdLwp2WSoqNMwVryJ
         8vCQ==
X-Gm-Message-State: APjAAAVRvpJDbiNLdSN87X6nGu5Pl2Z86pEX+6pM5AJEUNon8qmbWgWZ
	KsHXLe+U1zaKixGDxoTVGt4=
X-Google-Smtp-Source: APXvYqzQ2SJO3BoUHPrEydmTWizGdjZnHeBOR8AvvMf+4CKeUcwUJUjEUID4+CvybyEq0jhU3HylWQ==
X-Received: by 2002:a05:6102:2375:: with SMTP id o21mr12325793vsa.90.1572877750126;
        Mon, 04 Nov 2019 06:29:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fd08:: with SMTP id f8ls155536vsr.13.gmail; Mon, 04 Nov
 2019 06:29:09 -0800 (PST)
X-Received: by 2002:a05:6102:1010:: with SMTP id q16mr11984031vsp.183.1572877749742;
        Mon, 04 Nov 2019 06:29:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1572877749; cv=none;
        d=google.com; s=arc-20160816;
        b=F+kH1CYLGUenqTibofMKV7/x2grVS7GXF195pbX1r4+u8khBdEl/6HzB5+M+LfUlmO
         y6tyvkRE6D8g+FbhBWLQguBOuTag9/jYlvg3kPRioa0SfFi7pK/BhPScbkSIe75sPQqM
         losNfkU5DxYIXAN49sV8sTTUY5gQXGXDfZ0etU5ToeJ2djsHigAIdA8BonqRcLSACYRW
         wljMXWwo729o2Cd++gGAfBotUUR2xhyd4uE/AQuSc/kv48cONemtK0zTWO5YqjO+YNfu
         XV+9HcNPZkqIFdLn9167T2NR4DX23SJ9F0rIRj4TRSVaAvaS62yXS1cjkyKPWsCZ9/di
         y+rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=sQU0jAVefneuTdQpIgbUF6GdSN4TcMOiQRxRVI16Vls=;
        b=RsFcC2xWNRNUhC7CbCp54p4mBj59iYf9IrqAzzQXXNFYYiUi0W656TuHSyPA4DX0LK
         CM6DATv3wRGm7p3OhNB4ocda1JApCbCivxLVSMr2WA1y4/lp+bkSnp98qLPg18AC+Vco
         myf6lWH4OCes18QbWzcJ9fFQ97MR7mM+EY3kaEV1VOsCuqD+HYzV7spv1qv39PrDEbnN
         tLKySW+byDu3Uoj8i08lpSr2CyzMQHBCC2RxC4pTKg1e1RADk8Dj7H/6Ivcp/cWB4JpH
         FbQHWdhPSJQt8gD8I+fhg/6lk+4nEjRBH7bjnyqb2x2yY6VCUPay/9rfw0YgPck6Khbs
         lolg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FhPDq8Y8;
       spf=pass (google.com: domain of 3ttxaxqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3tTXAXQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa49.google.com (mail-vk1-xa49.google.com. [2607:f8b0:4864:20::a49])
        by gmr-mx.google.com with ESMTPS id s197si742140vkd.5.2019.11.04.06.29.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2019 06:29:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ttxaxqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a49 as permitted sender) client-ip=2607:f8b0:4864:20::a49;
Received: by mail-vk1-xa49.google.com with SMTP id z23so7965825vkb.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2019 06:29:09 -0800 (PST)
X-Received: by 2002:a05:6122:2c7:: with SMTP id k7mr10982783vki.97.1572877749135;
 Mon, 04 Nov 2019 06:29:09 -0800 (PST)
Date: Mon,  4 Nov 2019 15:27:42 +0100
In-Reply-To: <20191104142745.14722-1-elver@google.com>
Message-Id: <20191104142745.14722-7-elver@google.com>
Mime-Version: 1.0
References: <20191104142745.14722-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.rc1.363.gb1bccd3e3d-goog
Subject: [PATCH v3 6/9] seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier
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
	tglx@linutronix.de, will@kernel.org, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-efi@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FhPDq8Y8;       spf=pass
 (google.com: domain of 3ttxaxqukcry07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a49 as permitted sender) smtp.mailfrom=3tTXAXQUKCRY07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191104142745.14722-7-elver%40google.com.
