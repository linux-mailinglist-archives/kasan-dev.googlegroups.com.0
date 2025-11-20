Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5G77TEAMGQEYMWXHPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 52B0AC74C4F
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:12:54 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-36cc5d00795sf6926611fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:12:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651573; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZH5UunSc1eQtordGpOlNjmsal4Bk2ZZJYQ1NWL0GNUKMDsKTSSMYZsaiZJS4/syJFT
         PgpgZbLha45ffOaY0FDmIpecZUpPuFab5lCmqX4N5hdwAZI1NqyTK2FnBqa5PVXVH6j+
         nm83f0pCxFO3eJsIAp1Xatvwzw8bu6gFn4nCrfdgRzeWNE2c3qtjs+Hkzm4jf8Z1vXH2
         iR+8fwDDH13EvyUA4Dl9E+D8m9NzKrpyE58/6H+N7jWl53Fy1kFW7Q7ASxKGBaVQMJk+
         MvjOA6l65GbUwankb0ZkzBzeBfBh7mQrDdpUh2lcE6TFAFNly2OwHR1+5nWhyBE5bVpw
         kAPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=0hX+OJTLJdtuCC6V+b5LoEr7qmcpbQ4JkDJESJFHm48=;
        fh=TDRa5T/v0ZykemMEPoMPkP80ublxldOK9vLMUdSJIDM=;
        b=NSD4kWYsDbEnjBcOjAOQlm+AgQHCH35OcVz9/n35lZtza7oIhIAb8nYoImEkhAp8bP
         dKl8Iq+DppuglxAqUtVWgPNcqFH8Mxp2WUWLTxuwN62PI9inPyE7kIsaLmctk6nbIPnq
         H5SLLnFUEjU/iv4bKWKNEyk0u574sqzJcH6FpyDN/NnfWIXCbCwnQhuVIPWp5Z8Vyvrv
         QxGN0rHQDjzl6VCI83gdb0uBbEB3NQ7jjLBPZRE5s5ajwuAKA5BsEQ5Fn7N515JxQUIc
         LflFcdoJAx04RQyGz4wkn03dFiHWyKbWhoF0TmrSNJqy4MopgUrGCqCWBmEfeR0Urw3+
         SsMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dxAwyLB+;
       spf=pass (google.com: domain of 38s8faqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38S8faQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651573; x=1764256373; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0hX+OJTLJdtuCC6V+b5LoEr7qmcpbQ4JkDJESJFHm48=;
        b=RlrAhjZvTV/Lr8dJgHk+nxjdZ8qzrZj+dSyKYN8g4W91+ly2Ygk0DLj6fphh8ouzwK
         OP9EjsCVBDKKrLRDN0DMKvs7tvx37HVfyFQhx3Du2q8D7h9eDAak1WY97Fp1icCmNCa8
         hRit36sEyjQ/hoBNAABdG1oKEk5Wd9sy0/Ep45h1BGhixUkyyRooqU8qgKUPDr0DLnNZ
         gQFeJf6KnoG42fcNdDJCagnNioSBVxClj8MgddpvZzgYITR1THaDzRZT1zvjdXTOLPwi
         RN0rYPxOU/Z3W+muTAfaZnhGwdZVDGnGTsgLyOiw1SqKR1RxjKV4tmffw6U/SoxEcJ3z
         ePoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651573; x=1764256373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0hX+OJTLJdtuCC6V+b5LoEr7qmcpbQ4JkDJESJFHm48=;
        b=V1wPLGTQ6M1w+2HG6WqF377oWQvI2xTGo+9QSD+Q/wtdeOUSlpCzWKwvPcEE6tOct3
         EDBkYvuUQZW3848VZGJFJWOcFWpoK40SLthfeDZYcp5jdFVfq69e/pDZCoCze2u6N1Rp
         655RFI9hTleUHND5mSmq582CBJsTyC3zNvT6Jk2wLHxhAOOOMRS81H0kbeT58dP1yOIX
         0Gs5bfIgAgUg3GAlC3ZbYK1j0wbeGH/Q/sXxDxa3s56mFWlOT+cF5YCyyR1x8vGBO4R9
         evPQ0759pwfgvlke80kIstjZpmROZ1+RjFMnt12M+qGhFZ4oreOqZ6PlCJXfFzhi9pR+
         gRsg==
X-Forwarded-Encrypted: i=2; AJvYcCWi91K8u6JGtq52FTfEm8bdgJcuCsDKJrc8xX1zrHr5GS1EmWtomcGeHgKnLVYBs0hkv4sJtg==@lfdr.de
X-Gm-Message-State: AOJu0YxIEDtggsZWLd03qft6LWk8tzmHxd2tA7TxcjAT5fP5wX4sDfxq
	ug5uoFWVnfOrLahE4dxomAnt7tD/FDqYm9G3pOTjs5yj4sTMFDpVNtXd
X-Google-Smtp-Source: AGHT+IFTv7PxiNBLglekNRyPTWqjjqcqR2G34FXW0b/KH5QPkzKhsVdeExH3xWaEorLQ53OfZ1l8qA==
X-Received: by 2002:a2e:b04a:0:b0:37a:95a7:335e with SMTP id 38308e7fff4ca-37cc67bee36mr7620191fa.38.1763651573513;
        Thu, 20 Nov 2025 07:12:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZYJFEvWB0IDVAxk7RvTYUFNMVdn1s8RR8z6cxmfw8RUg=="
Received: by 2002:a2e:88cf:0:b0:37b:97ac:627b with SMTP id 38308e7fff4ca-37cc69f16e7ls2776761fa.2.-pod-prod-06-eu;
 Thu, 20 Nov 2025 07:12:50 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBqg0Cebs66JUASRCag7H6tDIpZWOOF/d5KrBjWeFdNMLToqYY9+t6khiy+tdzaZcLkZa9Uh0twn8=@googlegroups.com
X-Received: by 2002:a05:6512:3b23:b0:595:8fee:fd8c with SMTP id 2adb3069b0e04-5969e2d5835mr1530169e87.8.1763651570436;
        Thu, 20 Nov 2025 07:12:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651570; cv=none;
        d=google.com; s=arc-20240605;
        b=LNxXOeqrtRGthpGitkRmlcx2Q+ye98BlQjjlhvsYWZh4Ii2l+CJP9VUsGj5lsXwgAc
         8itVV2FIse3MI9sJqjvnCZblYVf8qEwODww8FDJ2T3Eo+k6/++OoXuAhJq0CCgIbomS+
         yQUpjJFxovoOmTnuV5MeaHdr4+6OR/eAG4nzEtkq+FU3OHaHPkoQrDIKlaYyTku8lkQO
         ccZY2nQcH0q+zcxyi7+4hDBQh2muzi8vx6sT4bDv4n21YMxxoecsaHrNZmKcxNLn36ak
         +8mIJ18Sn36pp4IzFpOw2SEy5YY39FcYPUp/swbzSLJ1y4lXy+VZA5heNxQK8gE/6eZY
         FHTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=nc/agqhZHpBZo5pQd3t3SIT1Qnduk/rx/3xksUJM3vo=;
        fh=00tYGrRx/U4miLs3B1SL1De9XMFFPwJ0EvB+XRGwOvY=;
        b=MdwgGTwKcET+Ufzj3c4E25Oa9IPOXRU6gMlN+c+9fffjVKN2AVCpGzCv4EH7h6MvCg
         YO4QA/mxPsC+ChTiaO3uWlTN1N6bVEZ3SGKXLLHvhVQM3Vyx7/xR8+R/KpECYCODJYNC
         DlTZ2/gQdnfOEVvimGxCzqeciWzC+f8hzXE7kzfJnofe5cTZkh/Zhm0C8bNlZWWfnGCM
         /nOSem2YZI/IohPncU+/zRuR2r5ZjPDAavK8SJpVNRIX5f8vrRkndJxOoB62fqVmPDY/
         AHPNjUBzASExvWVQZCMcsnNUvSYTpvb3TXGYjSq8ngpB6T+z+LJzQB0Hma5JbvWh/cNA
         5B8g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dxAwyLB+;
       spf=pass (google.com: domain of 38s8faqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38S8faQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dbb6b0asi45252e87.8.2025.11.20.07.12.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:12:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 38s8faqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4775d110fabso9557685e9.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:12:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXzzhkuEg5RO+NslTObA9NbIq6Ezug+OqCbFIY3PyLLjRK6Og2YbHmMKIV0u5QQWvsXbjEtZBKF8To=@googlegroups.com
X-Received: from wmd10.prod.google.com ([2002:a05:600c:604a:b0:477:9c68:bd6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3590:b0:46e:761b:e7ff
 with SMTP id 5b1f17b1804b1-477b8c92773mr32595725e9.28.1763651569512; Thu, 20
 Nov 2025 07:12:49 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:41 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-17-elver@google.com>
Subject: [PATCH v4 16/35] kref: Add context-analysis annotations
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
 header.i=@google.com header.s=20230601 header.b=dxAwyLB+;       spf=pass
 (google.com: domain of 38s8faqukcr48fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38S8faQUKCR48FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-17-elver%40google.com.
