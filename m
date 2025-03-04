Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIUOTO7AMGQEYCEEQCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B441A4D80B
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:57 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-390de58dc09sf3669414f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080356; cv=pass;
        d=google.com; s=arc-20240605;
        b=JFjPKw9czq6fVikn2G8wuGRqr89RHkqumCpKnB+Bqj0fRd2pJcHr8QITBTFbQe+et9
         xcKh3lAPLCB9kXP9PTFfhCGCgvLnDzHN+4y22UEvJLmic/WFC/7/JxAMzfB19YZweudQ
         Fa0MXO2TzmdtlYO27l7HtXf+1lrO2QzWYxPIYQRVsZQnFCn6XIUJ1/08fuOXra/X636J
         96UQm0lalTYNlfudbx0soXd7Szx/B8e6ONF7vKONm6jrB8cL5GzExMvezDpFdSsfLNux
         TXpbQHWlPwEcjOfm+8g7jIwsYEeSikJ+KV/MOFVwClsGHczBzD3pCnafW+brgSeudFEn
         CZOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ACqaKiigH9RZ7MsL017L334ubFDVyuVg2ZDFCiHIewg=;
        fh=l2xxCB88nV2xxJEy4mrwRY/5IQuWXkpQkOE5SZ9QHTk=;
        b=IV7k0aUywbfmefvvcTJsinmd2ak3gUWq3M/oGyVwi1ooP4Njsm3rEqaOYOpBrdyM/d
         R7/Xog8zFP8pw3ghQ23kqHwEYTZunZwFgx+dE37dj5EoxJtm3hYXsQq4KlbDHAPQ6EMN
         ZFKFjeHOy2JI5Pca+gwNpETOF5luLVMMQuCuxB/cNPWSvgozJTMPUGYMPkJrEhcJh/bL
         3SgtqK+VAC8NFyPNrpATJeKbcVaIqFL1pR2QVOvJJuOfCNmJA4D94M1JSPC5w0o9lJRb
         qEtV+EDYlNmaEIx9qCemUaDlidcLTZRs4vJkhi6pVPwmSQj0b4sS2Fc/+h6aVHsvE7mL
         zL0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dfruzich;
       spf=pass (google.com: domain of 3imfgzwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IMfGZwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080356; x=1741685156; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ACqaKiigH9RZ7MsL017L334ubFDVyuVg2ZDFCiHIewg=;
        b=HDrCmVR1T6WlyHP08LROoqKIRY+dtIljSYwsI4VEiCQ5aEgbH9878ch6H59v5gF6sZ
         g3WR+9AJ6JEvZAPgzCSNgQHM0gaiafMSiG4WvPJEzKC53iuvcIPX9w1Cv0cMvhEXbHn4
         TMr7HbkkbUFadwzS8Lo3raAZlaes0M3yxcj5O5Z+Gn/WM8LqjjqQsQ4/0jpwHUwO8Tcn
         oAniqSRbImffd59EPmce8Qdk1UGCHdDCO1B/ev90S6c4cF/wB8N2Fxepj3MIPSHAKRqt
         3KaFVF9BwtWbVikDmaeHK40JVUOwjC3Qc9PIbcS+Gbm05dn8/Gy9qOubmFni8kpJjrk4
         401A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080356; x=1741685156;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ACqaKiigH9RZ7MsL017L334ubFDVyuVg2ZDFCiHIewg=;
        b=ejrGQc+gwgff0/qLukIgOOcuE7Wb6Wx9+m1DRto+7oUSgm19AaJIuYvGvYAI+fCU8N
         rz6o0mY7AyP7wIXaPItxifSpAmsBI1d0ZeedcBLgGrzMVbO46V3WV3zjru+UbjTscTjO
         pORH0Z6R+GNi5uRTl6AC/yygdvf3d2ldP3buNFup5SSKBhJO8KQZI/jRNMRSjpT7hdEz
         rfCw19XuT9UAPcGm7FfgzXMdAlPxQ4Wdf8yPQV9WPag0xhTOd9cZywivHeMqH+pqmGNc
         frzEKgucbg+OVAQZbdbTRyJyH8xCUBCCaUxM+OAdCZ4DmRA9GzYnMDZ/5IuObCig9z0v
         FMpg==
X-Forwarded-Encrypted: i=2; AJvYcCVgbSuUXl+wBVS5Ke27Kt1NW+IYp6MvR6Vnxg6S+xiB2OsRAToHZcv1ddw6UThHfo8Cq6NXUw==@lfdr.de
X-Gm-Message-State: AOJu0YybFJwGBtRYuN3ncxboE3Q/dh1hKIVPtW0D3CNWI/PlxwSOasEg
	PByD8zuWxcAZO3VPBbW9lIIqWMbmoePtGY8L6OgvZ5X4+GJFgtGU
X-Google-Smtp-Source: AGHT+IHSnhAgIq83RwGMQS9kAlUelGKoy3vU8PjL/7hfflZZLGhQB7WRN3EgJxFJIb/kU7fwBzyuWg==
X-Received: by 2002:a05:6000:1f8c:b0:38d:e48b:1783 with SMTP id ffacd0b85a97d-390eca27761mr10917955f8f.42.1741080355249;
        Tue, 04 Mar 2025 01:25:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGMzBGDnCY6/0ZDqfF9/OIN2LEWLubJtwiDO2qwEsReRw==
Received: by 2002:a05:600c:b4e:b0:43b:c5a5:513c with SMTP id
 5b1f17b1804b1-43bc5a553eals7257085e9.1.-pod-prod-02-eu; Tue, 04 Mar 2025
 01:25:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVTxtvXBOmK7JmvsklPd4zORtuhpdtEC/rHpuwU6WThuBgxJqeYD/6WF/K/DgNfFzKfR5vKzI9/UYs=@googlegroups.com
X-Received: by 2002:a05:600c:511e:b0:439:9aca:3285 with SMTP id 5b1f17b1804b1-43ba66dfe1amr131646445e9.6.1741080352780;
        Tue, 04 Mar 2025 01:25:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080352; cv=none;
        d=google.com; s=arc-20240605;
        b=H5XPG3Ci8Vk6xdX9lU4OnkC7C3IZXzMgfBaTn+2K0lQnZqJnGtCwtbfvBl8y+5q/XO
         GqbAYlbIM7nP+AxxOwDLVBMmlDRSP4oxOLG2b/iir/RmFjow8Jd25SzuNvcOaKRgzqK4
         NkAbrxMnSTirZCDfBm3in4sAikAVQ+XcKiGLpHczsdzG6VlfYa5720l2qKEaMPpKHmb6
         6Le0WMJrijLGcS3235MPkr2kyaTWK9CNLwkVqf3yIH+TWw3L7k7K9yv3DdNBo3fwnSYm
         07w3JhZkRGE8rWc/ceBV6TGLt0+Jf5HJphZCzpuI9J8Z1HzIZSl4oMBUNqtZJCf+eh1d
         zifQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cDlOE/N8Ae1M5H+4yLEwuBDz/LRLExYZEp/cosJZ8Bg=;
        fh=alH9Iv6QYu6iOygLUPXIT8hLwQxX9BmRSvVYLFij33s=;
        b=EU97VzFezFge5p1OHDdABnp/o0yTOpW1MKMZMnWJzYnAOocPihEjKtLUs0aOCj63qb
         VKnZFlbr4hJjo6Gv5HUyC9Rw7SvrUmROxSENMBMBxrcSEEEuzFsQ0DJEivTiNR5KkvW3
         Qel0uikO364LAUOHYvvMmlK3wUAE88YsPSMz+NCvo+UJ43BGIh4hd8irWYaxpFneVjGE
         uMmR2tru3uP0Cisj3WShIc2jHkEIsnAgUalK6aMDaZxZI4CbZpRsKVlTzKXqxmYGhXAL
         u8BYytOyUvdlfHRAfzAyOtpLoIiR810mYnyvAh7jmAmtKJVxPYLFHGRdGfJXxooqxzv8
         yxQg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dfruzich;
       spf=pass (google.com: domain of 3imfgzwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IMfGZwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b167si570695e9.1.2025.03.04.01.25.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3imfgzwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-43947979ce8so21212075e9.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUVX5WiA5R46Co/b8LyBMhoBovLEf1GLRtoumNLdJL8mPPrC17tCvo3z5VomPWh0inxLALKklQ97io=@googlegroups.com
X-Received: from wmqa13.prod.google.com ([2002:a05:600c:348d:b0:439:64f9:d801])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:190a:b0:434:a4b3:5ebe
 with SMTP id 5b1f17b1804b1-43ba675830emr110121215e9.24.1741080352374; Tue, 04
 Mar 2025 01:25:52 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:15 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-17-elver@google.com>
Subject: [PATCH v2 16/34] kref: Add capability-analysis annotations
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
 header.i=@google.com header.s=20230601 header.b=dfruzich;       spf=pass
 (google.com: domain of 3imfgzwukcq8t0at6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3IMfGZwUKCQ8t0At6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--elver.bounces.google.com;
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

Mark functions that conditionally acquire the passed lock.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kref.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kref.h b/include/linux/kref.h
index 88e82ab1367c..9bc6abe57572 100644
--- a/include/linux/kref.h
+++ b/include/linux/kref.h
@@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
 static inline int kref_put_mutex(struct kref *kref,
 				 void (*release)(struct kref *kref),
 				 struct mutex *mutex)
+	__cond_acquires(true, mutex)
 {
 	if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
 		release(kref);
@@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
 static inline int kref_put_lock(struct kref *kref,
 				void (*release)(struct kref *kref),
 				spinlock_t *lock)
+	__cond_acquires(true, lock)
 {
 	if (refcount_dec_and_lock(&kref->refcount, lock)) {
 		release(kref);
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-17-elver%40google.com.
