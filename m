Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHHA7TEAMGQEAEJ7MOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 832E2C74C81
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:33 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-5942fa88e0dsf518807e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651613; cv=pass;
        d=google.com; s=arc-20240605;
        b=lnFQWjKyHybTAZAZHOLSVVbAIDWUaIZadCVtzDB8wJj4adLIPmYeZSs9xcnpOFk6sX
         pDWcYj5pkHb/yfOMkGoYFSTH5BlVR10iAby2osBq1cnYwlbde+4h7HJCEt0Sd18p0f08
         yz8Iq+RGQGgdKkNaAmZ4URWozR/XK6xZqk51IJ6pLn5CaDcU0RSAN/6U5WTNJnV0Bbfw
         aKcjTgf2ZkQt4xpkvC+BqLlNPCqKGDAY9bBpMgtVz4YJv/dpAtyM0/ks14UDi2rspdRA
         lGi6kBQIeV6K6MDf6abcTbNQA2m3cJMCqxq3y3qci6IHUxWHlF0xryqt8bSTxGvYf840
         qQqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+um+AQEpuNFMgm0fapxF3icgNCwuPpaIz3sl6rvWdRg=;
        fh=lFJsHixZTTzsiB8cvrV2jQQX+s4Fs4tRh32dY//mbG8=;
        b=V+fZro1jNw8Ju8TkmQUQOZF5txlIBKj0Ats5XuaWyk1ReJXjJjzYQAwxF6Sn0Bw+jc
         8SZTTOIkJfH9CjDSIGCqTNngfzuoQTH5tqYAdXoNu5LQHriB4lhCv1npFx2ODlHMvv04
         C/0UVM67lrd3tGAoE6L8pGzLH1ARtpMev/W+HIrZbJTpQZvV1bFSS7jCjwRAnmmj/f/H
         HVu1nzT9KDS6GLtr6WGPdvmjZCpf5v048y5JNs4nbgYBvT3o4h7yI7081C29tHobCHbx
         Z4PysjBH16Kt6ApESjXu4xs5q/inlq4fm/nMOLuK880oHVr8CxGteq4D8qJG0FwXqtSX
         mHQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fPuZWB+R;
       spf=pass (google.com: domain of 3gdafaqukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GDAfaQUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651613; x=1764256413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+um+AQEpuNFMgm0fapxF3icgNCwuPpaIz3sl6rvWdRg=;
        b=XT8gLoAWXCUT62Ksg8pg+SWPx47VckhPhc/dNWWAMieLl4AYGFuQDhCN94oGhx8z8A
         50V8opTv7Rjtic4vxqQ+HQIFiievKZxynkUnsA8bdiLEjQI/yzOjCTCiFWt/W9aT5iBn
         66tifMHFnsbFbNuWRh2GKj1/jQwZBYkNXJhN4t7Rirc6TE1Yl/566M0TM7FkU2022zqp
         3cHisut0bh3sJTlMOpkG96GnSo8iXuQvsp3xcj2JXqSy+3hjU1Ut6U/Fw3TIQvrAdiMo
         sdLXpQbCqwViq9AOGjfcVJNobHEyAodwO1yEz/5NgB4/lvXS3tpFqGnH1CcPA+UCEsvm
         CBKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651613; x=1764256413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+um+AQEpuNFMgm0fapxF3icgNCwuPpaIz3sl6rvWdRg=;
        b=wh1DvYzphKuDTjl4OPrzjjVTLAd7aMF5LsJrEmCv+mfemGV6dr+Wje0upkpuzbihCV
         W4wdqmFgnowqb674QoA8qB2/eLvJX4MagqHFJ2LQifwGzTbMRQnLW/795eGj6r+pIVpp
         noP4OXGqvRceNjleazDpAvA5xxAFzDYDmHYrKbj0M1Zi5RtruDWLjsVvlE2Ch27HgAXH
         gPqnl+i95x3/kpJBZaT0KQw4t14qX0K1z2QOtGPoKiTR4UIGV/xmCGfh2qiIpM0vXemA
         R/OWxRdSO8BF0RrZCHSGybbjuALhQF0EsMwVJaA1ZZY7U0SBswI8nUPghi4M7uHMAcAM
         T3BA==
X-Forwarded-Encrypted: i=2; AJvYcCUH995R4zt47n0H3gJzRtLMv3zLc690g6SsCOK76MwCpYHSZX0LiNbAiRDuwlCGx2sZN+LfGQ==@lfdr.de
X-Gm-Message-State: AOJu0YzJ8o6dS7HqDDYBzh2Lus4JKcJ34JzIO3PhUlYh4XuOfMdmbcex
	FerzekXdCm+a5tnN2OvuXqBrolSWAH/+wL1Fvu8PlI4HPFSCXTai7VsO
X-Google-Smtp-Source: AGHT+IEGcUciTQi+8PqXgwKH8Xx3okqvh6iNVwxWEPGCfjiRMsNK52HmbOrsuerT4jqbSo6owdO41g==
X-Received: by 2002:a05:6512:2256:b0:594:2fec:ade1 with SMTP id 2adb3069b0e04-5969e2c3493mr1177993e87.11.1763651612621;
        Thu, 20 Nov 2025 07:13:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YRw89QXMgsXmTeF6rXZG4iKdvI89UZQ/qs/AwWYxC84w=="
Received: by 2002:ac2:5688:0:b0:595:959e:ea9f with SMTP id 2adb3069b0e04-5969dc5cc34ls256327e87.1.-pod-prod-02-eu;
 Thu, 20 Nov 2025 07:13:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXg5W1u4cRjhUEB2p9INyb5IVEZ/QGr24XbVo1qbwOWLF8+CtF4QSKSHfwP6j6E6ia+0K4WlUFXVZM=@googlegroups.com
X-Received: by 2002:a05:6512:3e19:b0:595:81e7:3daa with SMTP id 2adb3069b0e04-5969e2fca2bmr1273133e87.27.1763651609342;
        Thu, 20 Nov 2025 07:13:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651609; cv=none;
        d=google.com; s=arc-20240605;
        b=Dlm8h/1/6YBOUqYqgxxzmUPKhXf9j9RTl1kz5picZhOjc7Z6or7+4stywf5biP+ICp
         mi5xDGbBGkMFprgUC/w9PCT370I7N111OcJtzsvMrl7tevqSTYjssnTO5iQYnNmDb3sA
         f1FrIUwAgRMXIB0CKGaIZDTkJUOWzDxk7Ybh7jyP48VphiyuVFaoW9iUKvdMvoS4NHxY
         iyRRMYr2uLnX0n5Dl08/iq+0pF2O9NygNvzQBMUhjydFOx9v1lQQWKoueqqpgmYeHcHj
         7sRgWFxU4+APt3so+cPfQ9jYF1JHKabGDs1E2cHCkkriC3Q04mHyxFe+eY6UmLxaD2z3
         uYNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kN628sGqwThlti0A3ZPE5fg7KLj/Ov6I/vXTKugeedg=;
        fh=G3ko350RXxvqaLk0Ez/Mm1QtYBgEpngmJJbge7Z98ZA=;
        b=bKe83gK9IS5PkBAlPKj5Nzn4krJo/4Hyncd8IEtUPQvfNX4mfAQ4xa5KDvKnmTq5EB
         S35zNGTHIP6lc46mUTpCzg96kyAiq/TyIiKN60S9fd8c552c6+XyowGbbqWKdiee9Trh
         tumwZaYV+/mMrQqb2k7eQdbPA8MeifJJc7Iv1n2j+ZLa9UP1bWTEQgw1brQps53RSWZW
         Kq5pPTDqhVTZBka42iSN74Tus1b3KCaUv+Am0azOYD4QpH/MFk7UOrvgQ7VYdMGNx5o7
         G7BBA9zMYiY4y4Mgteuc8W22X4i9seVcWX9GRGekD52hmrkqhSJGFRPi4GXLwVkIE1q7
         CQGg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=fPuZWB+R;
       spf=pass (google.com: domain of 3gdafaqukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GDAfaQUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba0852si45664e87.4.2025.11.20.07.13.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gdafaqukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id 4fb4d7f45d1cf-6411fc67650so1381243a12.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXa6Hw3+gpm3hojTPCq3N7K1Us6zFMWKI6WNGADV6i3pb3C1ptHSk0wJ86JUV3zgfd/FCWJzNfYj0w=@googlegroups.com
X-Received: from ejcwe11.prod.google.com ([2002:a17:907:d64b:b0:b72:63c8:2878])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:906:6a0d:b0:b76:23b0:7d6f
 with SMTP id a640c23a62f3a-b76554a515bmr362722666b.56.1763651608428; Thu, 20
 Nov 2025 07:13:28 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:50 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-26-elver@google.com>
Subject: [PATCH v4 25/35] compiler: Let data_race() imply disabled context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=fPuZWB+R;       spf=pass
 (google.com: domain of 3gdafaqukcuuls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3GDAfaQUKCUUls2lynvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--elver.bounces.google.com;
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

Many patterns that involve data-racy accesses often deliberately ignore
normal synchronization rules to avoid taking a lock.

If we have a lock-guarded variable on which we do a lock-less data-racy
access, rather than having to write context_unsafe(data_race(..)),
simply make the data_race(..) macro imply context-unsafety. The
data_race() macro already denotes the intent that something subtly
unsafe is about to happen, so it should be clear enough as-is.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v2:
* New patch.
---
 include/linux/compiler.h    | 2 ++
 lib/test_context-analysis.c | 2 ++
 2 files changed, 4 insertions(+)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 5b45ea7dff3e..8ad1d4fd14e3 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -186,7 +186,9 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 #define data_race(expr)							\
 ({									\
 	__kcsan_disable_current();					\
+	disable_context_analysis();					\
 	__auto_type __v = (expr);					\
+	enable_context_analysis();					\
 	__kcsan_enable_current();					\
 	__v;								\
 })
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 522769c9586d..4612025a1065 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -92,6 +92,8 @@ static void __used test_raw_spinlock_trylock_extra(struct test_raw_spinlock_data
 {
 	unsigned long flags;
 
+	data_race(d->counter++); /* no warning */
+
 	if (raw_spin_trylock_irq(&d->lock)) {
 		d->counter++;
 		raw_spin_unlock_irq(&d->lock);
-- 
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-26-elver%40google.com.
