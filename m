Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEXIUO4QMGQE3GCFY7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id D8E179BBA1F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:32 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-2e789e56af4sf4447407a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737171; cv=pass;
        d=google.com; s=arc-20240605;
        b=MbeMwagFAyAXtWdmP4oyKcjtcEvmfAIFQkg0WAXBkE1s6uruoxCADFfkYSLbQhS/ZK
         oGRgz+ofG73NiKZST8GYHA8tEmxOnSnW7rsRD9Z3yq3SOogTWEhOB9j4TYwZdWeiZfO6
         DkfCuVqIddWRVreoVaxeegRoukyIjxBX32yrdgfAXHumZfiiPhcYbhx6fHD44eXv7+KY
         0dQToY2vi4nisdD19AVc2z+ripQBYftmnYPkBucRdunStiIYbfh3kHjecGoNSSoe1NAY
         4JlQKfdMAxKoq5SByg1FXUq/KkF6dDZZuJ967PTvxfTTVDteEVMXV+pvM2xPWfpaQT6Z
         5H/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zHMOPXE3cJCQEaxPlqASHx5pLO9l7ZvtpjFGnfHvdFY=;
        fh=3on67OWeNkEdJH+llSt8VSNz3BZJtdR1l3pqAx3iEi0=;
        b=aZcD4wEKFHJ/9aPmK53fxz/FE10p37+DrAROe9VBkvXDMTLbb1G/D1bbfgx+g4WofW
         q/OmglTHC+9uPG+52XkIWEZMqLr2y5ZICAvBsokMfRj4/6QJrcuDoW/KhNc4kQvBVAY5
         FKp/pdrXR166+0QeaoVgZ4RjUVJbLXIEQQqLMQ6c5aXrs7h3SzlGuyL8w5uzs76SchCV
         Z7+7UN8/uwCw4G9iGMC9v+TecE+qka4vRfo+4b90umik1VWDkiDAFbYMPsUflYGGalaF
         gth611A/cjA96bvovPPGn5/9S4C8DaBAQaKFMu9Xy91TjRf+nNEiM28ED60fTiliFV4p
         5f/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RykxxRTZ;
       spf=pass (google.com: domain of 3epqozwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EPQoZwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737171; x=1731341971; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zHMOPXE3cJCQEaxPlqASHx5pLO9l7ZvtpjFGnfHvdFY=;
        b=HIgAp2LGhCw7162ShBDdmceEQPmrvcuamcy7eTu1QbinM7nhdsISZujA3MoaSMfveL
         dn+9Pt5wtv53HaSXK7QumpENKG3t+36nWXUQmqP0s6t8Xz82oOHSno1oKHImsWwIq8Uo
         AziJzSzawxfsVKliFOL4xg/nORGdGGcbphdT+hLJNUY1jQUIVle7RZxIYOzt71yolVnL
         JeYxAbC0bVwMX9lEC4ztgRxdkaIs0vPnCWSeuiiqRwL0Dc5X5ZX8O5S1Ll26uT9BB35i
         v+cAotp9diujP8P0bPBqBE2kBwWt6ZhqAo6IGT2kDQmidLA+uXNXILoPOx1RTybHN5pF
         izBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737171; x=1731341971;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zHMOPXE3cJCQEaxPlqASHx5pLO9l7ZvtpjFGnfHvdFY=;
        b=wRExJdQYd+D3R5cxwVvLWLXKRmkQgbBbVzu26YUvJzJ9NAh2ChzzXYSYpTzdZhX1Rw
         HL4Lsp9msWelVTTnURJ+OlYVQtXqRo16mU/tkScs/NNWdgW+q+CAh2rwPECY+p3MIj8V
         UPmy7QcujZkTkSp1u1CQZY1gPsC6y9XlPBXlRXrcgWhRMuU8v7gNix9H9hTjPE67kYH1
         Tc8YP/wtLeCy3vZ7id/SV+5wI7tcXKhLjJN61JNd1Ob5hcs0gqVgaFjicq8xm9MFzulf
         /9VgzYcCKi3pytBJMNzrXxoa55nAoX9+Gc8yuwQBQsC4XxLR5j3pFX05uPXOiF0IkQaM
         iehg==
X-Forwarded-Encrypted: i=2; AJvYcCX87MoHgdp20d2XWD3FHjdrE7xXUTyTiiQvtYFXl7fWGa/ePJVTyKvlS4SWq94zxZALVeobuw==@lfdr.de
X-Gm-Message-State: AOJu0Ywox3aCHh/L9sk7yxM0CaBysYzr6Z3AgU5eFkUC0O5nWy9/U2sL
	k1HtS2wT25HecFFREppgXGPg8eN+tHOXX1Kf523fIu27IknUG4Ah
X-Google-Smtp-Source: AGHT+IGYs3BRwvMWY0Pd9kmvJgvM5ePpznh7Z8Mz8j0oTWgDlhB0y4QeRjYhh0iuPvDhVBwualUNGw==
X-Received: by 2002:a17:90b:17cb:b0:2e2:c835:bc31 with SMTP id 98e67ed59e1d1-2e8f104ca34mr35923358a91.7.1730737171136;
        Mon, 04 Nov 2024 08:19:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d0e:b0:2e2:c421:c45 with SMTP id
 98e67ed59e1d1-2e93b1210b1ls902961a91.2.-pod-prod-07-us; Mon, 04 Nov 2024
 08:19:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUhJEW8LNDhRcGC9K4cMKc2yQIFJWKgAv4H+0e9Xhirm9dAVkBCtV9EZiO43QiS3q/FjfMpAWxUBto=@googlegroups.com
X-Received: by 2002:a17:90a:de01:b0:2e2:991c:d796 with SMTP id 98e67ed59e1d1-2e8f1061649mr36141118a91.9.1730737169747;
        Mon, 04 Nov 2024 08:19:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737169; cv=none;
        d=google.com; s=arc-20240605;
        b=PS16SkP+p7rfB/rfi5ctLsT0zLABYhRNB0vKFwxyWDVwqsVXLN9l7knjsiPpQsXIkZ
         KZHwA1xVB0Z1q7JD1wwhJGUhG94rdOuQhMPf1HH+z5ZoQ3FMhpxzV8X1yqWrj0W5m3n7
         oCTzwUbH65EhluhpURJdbHsihN6LGuu25Auj7NU2Sw+yKqGfTeoIlh6GZzOlMQGej+o9
         C5AK79AezADSpegjHu4cblHLYtiIiuEQMYu0W1fOkzBLv1xZf1Ljf/W91qTQI+Pu601t
         6ykCwG1NStxts55Hf6PVxdXkulfgflQIfC0gWX6XtWYIG0h4yN2K/n32sNGcP6+h6xDj
         c/nQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=F81a+6CGvKtmngjrkoxGzbhKVD48308MotgDbr+zIK4=;
        fh=xxqlryHHYfByzSHIMfjoTFwpG5Ry2+yepKaolLC/aWA=;
        b=SY37f86L8ZS63qBtutWBhvw0srdwKGTL4eUnCClA1zqNxFC8Tt2GcTGG+ZZENL90zb
         r4BYxt6KeCzJV4aFllLKcy3Pox8I0syv8yAGsR938gkdA+IxNAsZrnPG+21ROtosqohN
         2C3ruPwFyJxBzbXEd47iIbAGWkruBNnjMA46ZHG8FSBN8zPQ/xzaRJ7+ZATCmMpv+HyQ
         OB51jxbw1TvkZXLNQSK4N0M/6kSRFNLhRoD0iih8sNYRVCUWF7gOm5iiu3hoJ9sQOy4S
         13GUgTe70aFQWjYXi9p09Y3iKoaETlQR3uFVktmXrmezaslNzmyaOfIRMnSGnasYue1m
         OeCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RykxxRTZ;
       spf=pass (google.com: domain of 3epqozwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EPQoZwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x1149.google.com (mail-yw1-x1149.google.com. [2607:f8b0:4864:20::1149])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e9201b9b95si696782a91.0.2024.11.04.08.19.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3epqozwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::1149 as permitted sender) client-ip=2607:f8b0:4864:20::1149;
Received: by mail-yw1-x1149.google.com with SMTP id 00721157ae682-6ea8a5e862eso19102757b3.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUWtdbPAbIfn3bniBfbHqGnkf6MBBQaxX7SjpMPmiyChUOmQvrPb6Cjj2Xu9eAj+bNuZqQ2MCU2fCw=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a0d:c601:0:b0:6dd:bb6e:ec89 with SMTP id
 00721157ae682-6ea55787f6bmr1375427b3.2.1730737168609; Mon, 04 Nov 2024
 08:19:28 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:06 +0100
In-Reply-To: <20241104161910.780003-1-elver@google.com>
Mime-Version: 1.0
References: <20241104161910.780003-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-3-elver@google.com>
Subject: [PATCH v2 2/5] time/sched_clock: Broaden sched_clock()'s
 instrumentation coverage
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RykxxRTZ;       spf=pass
 (google.com: domain of 3epqozwukcdsbisbodlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::1149 as permitted sender) smtp.mailfrom=3EPQoZwUKCdsBISBODLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--elver.bounces.google.com;
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

Most of sched_clock()'s implementation is ineligible for instrumentation
due to relying on sched_clock_noinstr().

Split the implementation off into an __always_inline function
__sched_clock(), which is then used by the noinstr and instrumentable
version, to allow more of sched_clock() to be covered by various
instrumentation.

This will allow instrumentation with the various sanitizers (KASAN,
KCSAN, KMSAN, UBSAN). For KCSAN, we know that raw seqcount_latch usage
without annotations will result in false positive reports: tell it that
all of __sched_clock() is "atomic" for the latch writer; later changes
in this series will take care of the readers.

Link: https://lore.kernel.org/all/20241030204815.GQ14555@noisy.programming.kicks-ass.net/
Co-developed-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 kernel/time/sched_clock.c | 16 ++++++++++++++--
 1 file changed, 14 insertions(+), 2 deletions(-)

diff --git a/kernel/time/sched_clock.c b/kernel/time/sched_clock.c
index 85595fcf6aa2..29bdf309dae8 100644
--- a/kernel/time/sched_clock.c
+++ b/kernel/time/sched_clock.c
@@ -80,7 +80,7 @@ notrace int sched_clock_read_retry(unsigned int seq)
 	return raw_read_seqcount_latch_retry(&cd.seq, seq);
 }
 
-unsigned long long noinstr sched_clock_noinstr(void)
+static __always_inline unsigned long long __sched_clock(void)
 {
 	struct clock_read_data *rd;
 	unsigned int seq;
@@ -98,11 +98,23 @@ unsigned long long noinstr sched_clock_noinstr(void)
 	return res;
 }
 
+unsigned long long noinstr sched_clock_noinstr(void)
+{
+	return __sched_clock();
+}
+
 unsigned long long notrace sched_clock(void)
 {
 	unsigned long long ns;
 	preempt_disable_notrace();
-	ns = sched_clock_noinstr();
+	/*
+	 * All of __sched_clock() is a seqcount_latch reader critical section,
+	 * but relies on the raw helpers which are uninstrumented. For KCSAN,
+	 * mark all accesses in __sched_clock() as atomic.
+	 */
+	kcsan_nestable_atomic_begin();
+	ns = __sched_clock();
+	kcsan_nestable_atomic_end();
 	preempt_enable_notrace();
 	return ns;
 }
-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-3-elver%40google.com.
