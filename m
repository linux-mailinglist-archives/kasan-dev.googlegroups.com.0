Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW7ZSO6QMGQEL4DMMII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A4B5A2B051
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:08 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43623bf2a83sf9961075e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865885; cv=pass;
        d=google.com; s=arc-20240605;
        b=OKHx4lP+C3thoqKbyRhsPg+hKDMt44i1sYFo7u1PuWptgb/vORWXeZsYpKQVlK8sJE
         YdTNvUOmFZ+UvVpDZ49dWGeUdns6MJNsojS3sT6HAVznFa2m6hjp43UaXiYN4NVeI+/v
         SurTI1H5dCQpAxIMLiSgyaxRZn1TENk0ZiJSmr530ZkFCWqaCztd3TOpQT3wuxpNQfTj
         fGTOqzxWN8C/zoSZ0aZrKCnRsjmz5R08AdZSmkfy6NqmcIs81YUj1mTZcSMCrCzllqcN
         absl47hHvh8rSFkwJRewKRu64d2BZesb51yLnpBdCQgeYA6nOlPu8Zg1EYC/8VMWC0Yg
         2+ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/enZWuuyoms+xAkI0TtMWX8UeOb5ETkX4rkQDGgP1a4=;
        fh=rzLEgCyR4YECZnhmXK5Yvgs84slHe/hmg9ism2ZCYGU=;
        b=jBabGExntZxH0jrmcUpN8zOhKxBzVGk7j3b0TMx+yoLcZfs1Qr6TnDhfB/fwan8NFy
         S98AqAnovqhapiH+BpRHfGrc2XANY0NsjQFgSzyU5gmXgbjduxKaLki9sLZgzItfUTD9
         iZV88VZD4BH7A6SYCd6t5N0upcNewtJ5RfoZW5oq/YBkuFkW503JoYEboZfIOchVTG8z
         ETKcnYvTP/i29UeXxugmhPfUVVFSDV91WghguXZbF4Cgex4whkkuH/IjQg+Rr5luSeFI
         amafzFDfvj4E2tHLFTyWkC1JjIac94itUj4ngP3Mbx3EtFzsACCWuaAZg6BOGdqr5k4A
         9xGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XeO0w5CB;
       spf=pass (google.com: domain of 32fykzwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32fykZwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865885; x=1739470685; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/enZWuuyoms+xAkI0TtMWX8UeOb5ETkX4rkQDGgP1a4=;
        b=TqGjDPHevQ04OOy8tYNRRGmICX+SewKMPtt5gAKdMJSVQgn0/zeBI3SR6Mm5g4zQ1N
         UpZpzgUf3xNyuVq8kKCs8CGOLCLplha3Ek4D+ea7Top9mTJPEbZ/UsvdYJn78ep6nqHN
         h+Cr9voiC9P81n11KMIvOuV4d+WZnYQf5dCt/RXXTi9P1QnR4GoZnQPSuM/d2V+0k4GL
         W2W7tEu4Vb5pQhxmtJn4AVdSQ5zoubMqHUcM60CYKmPw+ZWg907XqQPeul3XyU4mDJDc
         L/cFL6tb5bqJhNHW10tfMoOt0k7NDjZBGtjbceDcvJxQ/1Q7nQAwX0UKBbIMStOkJOoE
         WNrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865885; x=1739470685;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/enZWuuyoms+xAkI0TtMWX8UeOb5ETkX4rkQDGgP1a4=;
        b=mXuBiLJhatOs8DNryz0+6NVxGMjVo+NE45bIOMSWUtlfO/kVZPaIkVqw7AqXKt1Xs4
         2tlkTmFFLn7Y3n6KEGMeUJbj4xGOs2MEO7L98Y8S/AzDk4/jkMx2uM4PmjG6m1QtJLEE
         JAPpw005yAg9C58Ci+LA8sMiV7CbZqdkkgaTigGxGRVgBqET3G+drfDJEMkWAb8hOo0D
         ajLtU+KE9ZGxOM/6XgQDp/y3qksR+LL1t/H1sLP/l/7656H/IcWPuG0EnM81YQDiTYHN
         pJzhEkEUyD3gGIrjeX3bT9Iu1DYZTUK8H3E6OBcrUMOOXHSsA8QZJvzmh1HrUezXkffH
         hzYQ==
X-Forwarded-Encrypted: i=2; AJvYcCW9y9h2DtPbE7bw7FJSbKa21nsty6B/B+aGC55Fz2j9ld34jrXLmVSFBAf+bKegAl+ejbymjw==@lfdr.de
X-Gm-Message-State: AOJu0YyPSQSwX+NWTgSiswH1SuxQPPnuhAV931o/oUhj0zyV72MlojjS
	KoeIFOJU2cd8Ih1+9QG3usb665Ck6oTYssbWT0QvB6Ll0looG20W
X-Google-Smtp-Source: AGHT+IEqxZIj6jxBpC76L100UieHGkyMo3t0zLx1y31Z1c1qX9BcOpTcWEWACYL6Qd+yUeQ6K9Jnpw==
X-Received: by 2002:a05:600c:a00d:b0:438:a290:3ce0 with SMTP id 5b1f17b1804b1-4392498b72emr3766295e9.8.1738865884073;
        Thu, 06 Feb 2025 10:18:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e1d:b0:436:5165:f202 with SMTP id
 5b1f17b1804b1-43924cdb291ls213645e9.1.-pod-prod-02-eu; Thu, 06 Feb 2025
 10:18:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhBk4EC7BYpjHKUFYo1rLmVIuAstN7Vj4ZRDbjzUrLNQn10OBpOPD+8DoVWVytfGNA13lRpth8awo=@googlegroups.com
X-Received: by 2002:a05:600c:a55:b0:434:a684:9b1 with SMTP id 5b1f17b1804b1-43924980942mr4113415e9.4.1738865881538;
        Thu, 06 Feb 2025 10:18:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865881; cv=none;
        d=google.com; s=arc-20240605;
        b=fhO8FyjzOQu4JVptU3EB06Qq+uNKK1m+CG4pq6IV/sI7hZHJKNtKF9sZ7qAZtAGjRu
         B8kvBH3rJZw7mVyr0zcIjOXJ2XGrs8+XXmF5pbqChZMVTzbAkFPHStjFoHmWto52Kp76
         L63Q66kAuJJh94T/t6WHW/DZPGlMXiQiDin/u5pGQpQ08aGNTrEcZbhabkWizY/W7uU/
         QhMsr7R9uqQdjghmYb5tBnKMjpm9C02KXcIL9SopYJUC4VISDxCoxDiKodiMMy/gD37I
         K1x869U8kden4rf/b2q13ELVy43NvMmmUrdzbEOBmYKBhniC6cLTuYCxlvZ66Q6O5DYt
         /rsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=VsoCl0Fwo1Ic1mnwHNM6zvZdMp3PVmxgZxLwt6H7/D4=;
        fh=6DGWHjnw4XNrnEiwQN5lKfdFP649cphYHClqjDzJ7Ac=;
        b=fasp6sVHFxhQmckTpB5i9LJmRoBhWmDj0NnUkzZY+n0h+cXVfiH6luXhvXi1DmnZAP
         EuBQPR7LyBQW2fIS0iY+S2jxesefZl1v6y06Jkgji1qzRg/nsqIn5vBjNyD/s2JZS8zL
         0udIPlU6bfM4OhG+WdvlPfRZ08rvW3gCesD8FEiM2WVQvJmGRegH0otHs3KQyZ7FwNBy
         /n3xZ83c27AkwBTKFsVSGQ17igLO42njT7nE8xhGZHp0fFwKDhRLtHyCpuP/xMG3Cm6S
         8lnaqeaj3+Vx2XVpaoYzbaF3iVEpc4lFW6zBvgM+GKZADi1Ipa8PxvJlPU6jpJ02bmN1
         ZIHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XeO0w5CB;
       spf=pass (google.com: domain of 32fykzwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32fykZwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38dbdd2478fsi35363f8f.1.2025.02.06.10.18.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:01 -0800 (PST)
Received-SPF: pass (google.com: domain of 32fykzwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4361b090d23so7141755e9.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:01 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV2RhwtxV9gvGvduYAN9tzII8tSulUdKYWLvSCKc5wnCyhZNhmlR49l6FFE9HdBYT4+h3fi3n2iy20=@googlegroups.com
X-Received: from wmbeq14.prod.google.com ([2002:a05:600c:848e:b0:434:e9e2:2991])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4e15:b0:434:ff9d:a370
 with SMTP id 5b1f17b1804b1-439248c34e9mr5139685e9.0.1738865881193; Thu, 06
 Feb 2025 10:18:01 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:00 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-7-elver@google.com>
Subject: [PATCH RFC 06/24] checkpatch: Warn about capability_unsafe() without comment
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=XeO0w5CB;       spf=pass
 (google.com: domain of 32fykzwukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32fykZwUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Warn about applications of capability_unsafe() without a comment, to
encourage documenting the reasoning behind why it was deemed safe.

Signed-off-by: Marco Elver <elver@google.com>
---
 scripts/checkpatch.pl | 8 ++++++++
 1 file changed, 8 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index 7b28ad331742..c28efdb1d404 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -6693,6 +6693,14 @@ sub process {
 			}
 		}
 
+# check for capability_unsafe without a comment.
+		if ($line =~ /\bcapability_unsafe\b/) {
+			if (!ctx_has_comment($first_line, $linenr)) {
+				WARN("CAPABILITY_UNSAFE",
+				     "capability_unsafe without comment\n" . $herecurr);
+			}
+		}
+
 # check of hardware specific defines
 		if ($line =~ m@^.\s*\#\s*if.*\b(__i386__|__powerpc64__|__sun__|__s390x__)\b@ && $realfile !~ m@include/asm-@) {
 			CHK("ARCH_DEFINES",
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-7-elver%40google.com.
