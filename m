Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW6X4D6AKGQE4VNBLOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 379E629B026
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 15:17:02 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id e17sf923454pjr.2
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 07:17:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603808221; cv=pass;
        d=google.com; s=arc-20160816;
        b=edYbqIJvcfz5CNZvedsyCeTIqaVKWPH9fEeV3IZ2np1qeQC/pmKNq1ufWYRH81lM+R
         3PL6HPAYSACbkbRI0PbplFSyWyQ9UZidiw2oG6FyNxvTmp6B2kP3IGbBW/M8uPQ+MCdZ
         rXRmUGdX14l4x0pATWyaE0UC63510Ex9Tvjc3aRpdxtz+PACXuCsBIyaR2FvHrkP87A5
         N8Ds32iiWw5PW8fqkUxHaxg7jde54k/yhhMmXptTWiPg5VQjOPxIlkq2ed8mqbc/sgXm
         N11v7NNJfmsPv6rcaBJ+kO7hFy8TYdbrsDa7+3GA48caLcOg81dFOnhlJ2OvHEuik8G+
         eHYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=auAJ+AbiaA7r7cmSeEM6BJdJAlwfmyv9sjHIyYmn+do=;
        b=h6w1uNqgosz/hmfJjyL2Wso9eAZuHUq4BJhqnxgysT8iOCOqIcCz3arbE7iB35IjSE
         zHb5d2TogzJjEndk4fo9gDlXH9Hc+Mae0xT/tAaTkGJCX6fd+4WeMUNgDOgobxw0twHa
         DyCByfwEWAVLm7CqdkI7cetXcnFmboVEG0ZooPqW3TsNK2+vcjRqqpwAFCQ/5yFBKWep
         moAUQJjl3u3duFv4KIWKcJ/1MtilbnyLu0H/pkdW46OTF8wg5V/xbT/Afito1U3JhLgL
         GvRBmZrHYippVA1MrFn1jVNK86puUqwUGsiXR/s5uS0/GzXpH5J0+WBR/do2+isD2841
         lrwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOg6ccVg;
       spf=pass (google.com: domain of 32iuyxwukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=32iuYXwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=auAJ+AbiaA7r7cmSeEM6BJdJAlwfmyv9sjHIyYmn+do=;
        b=EJt9uOQMgKffuKFlhlgMsAN0bEeIvzx2kyYnGyMTANETD+j+/sfMduKbYIBU3Jyk84
         gN7smTmrm/UNyWnUXMa6v/Y8VXgck6JSrJ/OqmJ1kGugR44D34OoYxT2vM1Rp/oYy/RB
         qHzPTVG9jZKHNXhQraYhIy7frE9LPsg3awunyxpjkj31EHKSezEyfsQfU78Lrdr10SuL
         nxBvBL4J8g3xe10kFlP1m4i1w/eTwPHFooBLhxTwYZL9dMdilRvW51BFRNiEC3pjrD78
         Lq2JBCmICG5AUhC8szfDsCEmXxN/ssXlkA2mvMajM8ifX7ybSRtZAOEw/oF1cZDHFos3
         MfYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=auAJ+AbiaA7r7cmSeEM6BJdJAlwfmyv9sjHIyYmn+do=;
        b=SYaLtko2jXMibz14QC0eq+BfEOhOVHBKykPgKrHO2/gydQ77XBu+PumyNQynQWixYN
         T0mFJv962dA0lK8ErLk8HbVJm9RKN72XHCE9L7UKi9GfDY2FsdSLo7u8qMGo4+hqDeZs
         ZTH8bhXPpKX9qFq3d+Kki59cUlRlrTkSOVAJfW2kVzKkpMc4sL9QXZhvHUN2h/rrY7sE
         O4aaVv94Q0azkuV7Tg9eC8FLb7KuAqjiXXpje3Ww30UgFD8TFuPuKuauf9rLKtrOFcHj
         pnybUzfs19H+GQZbeepy3OEOG1wR7AryU97kqVszS2qNeAtb9zhHJoZO+ENvOvVFcfNJ
         c/mw==
X-Gm-Message-State: AOAM530xDqnmepUk/fhshq6dy32mfBSRQlIpzdeXHyjMUDUnd7OuFlVf
	UE6FlGNgUsuaD8vFNpKRmlM=
X-Google-Smtp-Source: ABdhPJyLSiXavpvWIB/lfOgTdmUnTO52R/CjLnzbYTZPtzgUPOehr3cLAeZT2UdWPq2Xh1cEE29AZQ==
X-Received: by 2002:ad4:456c:: with SMTP id o12mr2824087qvu.48.1603808219303;
        Tue, 27 Oct 2020 07:16:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:454a:: with SMTP id z10ls63819qtn.10.gmail; Tue, 27 Oct
 2020 07:16:58 -0700 (PDT)
X-Received: by 2002:ac8:5b8e:: with SMTP id a14mr2314485qta.326.1603808218777;
        Tue, 27 Oct 2020 07:16:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603808218; cv=none;
        d=google.com; s=arc-20160816;
        b=E11Ux2cfH0lsN0Z3edsDcLf+d3NfeBKk/3aFzwv4Dx4tFuDizCWW+NxTK6IHoSOAZ4
         EP4akHNeaxSKAgjxuGQeZpjWxbRnhPPYDGZLqTyV18L424bmUFuXG2sVymrzj81m1Pp4
         UbmKT4Ao0D9S5SCKdqJIRIF9NzYQ4vytcH0JAEA0+7LmwRq4wcf4UUDHrUVllHFsV3ck
         Wwxfz0Ke2n6e4WUoKSeofd7J0hYaDT/5KPWa6afMzJG/j7b3Lc9Rgh9Fd99jdgh0CvUj
         /9rhuKM+8rb2V9mYhy6egqAs2BECa7HaEK157ozRrilyeAKLNhf4xsWmT8IBbLd0HJ+3
         EddA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=wCJj2niDD0UYdNAX1uGcFN6Y0ai150vISrExHKtf6C4=;
        b=mjLmQxDO3dC2Ach+D3+iW4IUD0nvBhbg/ZBcwmCx8Jy9lMu9EWhro1qIvS3kIx44/G
         uUjgBbFVfIIcHB0Qd1W9N8mO66lDzHEuDyRyctwywyrg6tpEATxwcs0M7jj8CsBoasMY
         uIMWk9qFJvufVQI3Dj+6hLEeNLBR018gbNQ+zLQs4mk/MUdL2TC2ezF75+R5pCr015EK
         AEX9b/1DFAfEe8x+EQDnthebIw4nbZTP6d6QfOrZAbxXtFBowlwpD8MXKFU5WbpgkiEN
         y/l+lJLrh36eGGG+yWG15Ew8DHvMZVk1nHwOtffy3jTH/l1aKRgoi1CtY8re/INVFr4+
         X8uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SOg6ccVg;
       spf=pass (google.com: domain of 32iuyxwukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=32iuYXwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id x21si124534qtx.1.2020.10.27.07.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Oct 2020 07:16:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32iuyxwukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d1so819009qtq.12
        for <kasan-dev@googlegroups.com>; Tue, 27 Oct 2020 07:16:58 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:f8cd:: with SMTP id h13mr2597150qvo.10.1603808218321;
 Tue, 27 Oct 2020 07:16:58 -0700 (PDT)
Date: Tue, 27 Oct 2020 15:16:06 +0100
In-Reply-To: <20201027141606.426816-1-elver@google.com>
Message-Id: <20201027141606.426816-10-elver@google.com>
Mime-Version: 1.0
References: <20201027141606.426816-1-elver@google.com>
X-Mailer: git-send-email 2.29.0.rc2.309.g374f81d7ae-goog
Subject: [PATCH v5 9/9] MAINTAINERS: Add entry for KFENCE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org, glider@google.com
Cc: hpa@zytor.com, paulmck@kernel.org, andreyknvl@google.com, 
	aryabinin@virtuozzo.com, luto@kernel.org, bp@alien8.de, 
	catalin.marinas@arm.com, cl@linux.com, dave.hansen@linux.intel.com, 
	rientjes@google.com, dvyukov@google.com, edumazet@google.com, 
	gregkh@linuxfoundation.org, hdanton@sina.com, mingo@redhat.com, 
	jannh@google.com, Jonathan.Cameron@huawei.com, corbet@lwn.net, 
	iamjoonsoo.kim@lge.com, joern@purestorage.com, keescook@chromium.org, 
	mark.rutland@arm.com, penberg@kernel.org, peterz@infradead.org, 
	sjpark@amazon.com, tglx@linutronix.de, vbabka@suse.cz, will@kernel.org, 
	x86@kernel.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SOg6ccVg;       spf=pass
 (google.com: domain of 32iuyxwukczu3ak3g5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=32iuYXwUKCZU3AK3G5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--elver.bounces.google.com;
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

Add entry for KFENCE maintainers.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: SeongJae Park <sjpark@amazon.de>
Co-developed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Split out from first patch.
---
 MAINTAINERS | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/MAINTAINERS b/MAINTAINERS
index e73636b75f29..2a257c865795 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -9753,6 +9753,17 @@ F:	include/linux/keyctl.h
 F:	include/uapi/linux/keyctl.h
 F:	security/keys/
 
+KFENCE
+M:	Alexander Potapenko <glider@google.com>
+M:	Marco Elver <elver@google.com>
+R:	Dmitry Vyukov <dvyukov@google.com>
+L:	kasan-dev@googlegroups.com
+S:	Maintained
+F:	Documentation/dev-tools/kfence.rst
+F:	include/linux/kfence.h
+F:	lib/Kconfig.kfence
+F:	mm/kfence/
+
 KFIFO
 M:	Stefani Seibold <stefani@seibold.net>
 S:	Maintained
-- 
2.29.0.rc2.309.g374f81d7ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027141606.426816-10-elver%40google.com.
