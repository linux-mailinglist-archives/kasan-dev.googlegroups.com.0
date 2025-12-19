Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKHGSXFAMGQE2ZNMMOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4DEACD0944
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:45:45 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59436279838sf1547096e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:45:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159145; cv=pass;
        d=google.com; s=arc-20240605;
        b=Jc2QwVPOKqiLbFCYeVWywKfFBTgSionmYEGm/XhS2i7HWtUNJwTPPXpcyHeWygyw+I
         flWP2hftSCm7u8ObQvFbOyprpTele9jZmrgXBD9lH77WXC5PVAv5kmuLrK1/M+Bn8ii2
         35VgrsYKuAK2ONFd1BVSTy1dbAIWiDyE7F2JDmyby/9J9T86mQ6uvh4mIn8poGcq/DrC
         W1QrHUecIYCWEMzyoRPpdZdow8ZaPj4HD+20vTs5gOjBNyDS2xHYZimXnquuBO0ZeFC8
         8uGJIdHS0Hy8ttdPdZDnCBZAVDIaB4GE0M0Sq8XYGJuOHurID50R98/4Krsy14Wr4cHn
         ScIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=mHcIx9Jbkfk+m7aRNnYX//PO97BdnRvvIZ83fwOm++4=;
        fh=YJd51MehWpX3F6xkva8K/sZZpyn1WQSvim5E5/vQp6Y=;
        b=IuC/Otu12kQlPQV8hgibA//Y0gBE4JR7+qqiySG+maDrDPMDqqyN8X8GYs6W2Y8HBW
         V7dnPfImCOggNWjrxEGGf8npuWaAmBn/BNBLGNDkjcTWGYJNoHYXIxEDqZObSlDfSi0M
         9K3Ssb5A5azdoUQjHfSpCz0dPLkDV8d7CqgA+eLBG4Zij1qFdeMecDSNtBUiMl3r7x5E
         GyiJDtfidDGrxXlQIemnUVvMQJ569d7WO0hpEBbm6n1oEZLmh28QJooAH5amG1oh2EEO
         sU6v0NFRaygo3n0Ve1cFS0rhDUL1iDMZUV67DiV2NJX1ggBNsWI9BzYLr6dSluAjTysq
         pNLQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="evv6/V0G";
       spf=pass (google.com: domain of 3jhnfaqukcxetaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JHNFaQUKCXETakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159145; x=1766763945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=mHcIx9Jbkfk+m7aRNnYX//PO97BdnRvvIZ83fwOm++4=;
        b=WfoVkE519PUadD7jekf6utADdxvx2I+FlhA5asLiiXsvblcva5ytL/svDtHIQR2gN0
         gwKLx6c/xxvY4U7uVh2rJQWd/G+TDCouuzZqw1Ws0p5uSIPGGPD3TDIQ5H8U+G+jThVL
         ymvANZkzShYY9v+ZoYmYBQ2kPWLByFMNaHCzXJMY+o9Loc0Dktr7Q44DolmJXJICs8LN
         Iu1LBA5U9BNAHgDrJEyBP0ic0f18trK+jMjR+op8BU7ZqM5pZPId6m+NglDxuiChyWYZ
         jdY21Imfzl/yu71jkZqkzS/AQTkOEuDbIfICgGQOUHKiKziJDFXRW1xW7EG+FzeMkw+C
         iUfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159145; x=1766763945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mHcIx9Jbkfk+m7aRNnYX//PO97BdnRvvIZ83fwOm++4=;
        b=k11PtondjPIIMlN+ZJbtR/N7s+lDWDC6bgeTZxva7SZn/0FL0yiNnCA/ixayTJNpF7
         k/yMu75mtlxZd4Vo7XAVAV8ObYLUh3C4uKJXaINNUgxGFD3Yk7nQ9pLQGlcC6m2fwVhT
         TqZNtamJH/MuRdo2V5VLNh2/VOW//WW0LBq1kye2EIT/T1kWedKeZbUtPj3Vh+YCcbYp
         IClw8uSsFXRsxUa9/0YE19CuBtyM+ljIXyl4dTqlSnQv3A66d4QGdIQ5gS0VMfzg5c6s
         JVbqpGPszCX+G7mTOBKpDjUXeUJV5jOgiUak1fERhvu1vduuULHGKNhQN5Bf5cwK3Ar0
         rTQw==
X-Forwarded-Encrypted: i=2; AJvYcCUUPbiuL0vqxhxabiYigATzJhCMQCKEaInuXgimvRbtqGQBrEVImR6kh4RaM2nV95q8RSgEZA==@lfdr.de
X-Gm-Message-State: AOJu0Yx/ntJuh0WuPdUmGbyDu78YSAs7tRO58zlomXefZFL+BN3GZ9Is
	NKt1d9aNqhHu/+TDx9KYq9nfi68DagO5B5mMGGtK1OVS7q2MJrdM0OFo
X-Google-Smtp-Source: AGHT+IFp+Z+arH9LPGxzdWJ9O0cWxbXzEE3PS3dKXYSyaxVYHUKLj4rU4zsETGWTQ7n610vnxgh3iQ==
X-Received: by 2002:a05:6512:ac5:b0:598:f361:68f7 with SMTP id 2adb3069b0e04-59a17cff3b6mr1437879e87.4.1766159144703;
        Fri, 19 Dec 2025 07:45:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaCDL3SWIaEgIm5YfQ6mK6H09rFI2khUl5lzXfD/IAuEA=="
Received: by 2002:a2e:90d3:0:b0:37a:7d5e:db6e with SMTP id 38308e7fff4ca-37fcf057229ls10002671fa.2.-pod-prod-05-eu;
 Fri, 19 Dec 2025 07:45:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXngQ8qq9CK3YA6HHDWERgyE167GJTmFFKddP7AykgbHoE80ZarPnLSXKQL4Nvn1YLZ3LUNHQhx8gI=@googlegroups.com
X-Received: by 2002:a2e:ac13:0:b0:37f:cb34:211b with SMTP id 38308e7fff4ca-381215ab664mr9029891fa.18.1766159141119;
        Fri, 19 Dec 2025 07:45:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159141; cv=none;
        d=google.com; s=arc-20240605;
        b=ixEyJLzfw9vBnPeLdVVNRX1LkH+XcW3ZazxiT1btiRtagzu7cY/AEm7HHOw1ekepcY
         OnRSWsxuEfAL36k0zqvOz357kYAa76BBD1FOoy/OcgugYceBdvTlhURogI5q56FNEVaj
         eZjT982iPLbqd5AMQmBSVE/wXsZdXVCvAQ3omB6Owa0M96YmH2yZeKc1T9WNa7JYs+Qw
         yHd8uGNJgYWPg1E6rW2e0SWKewrgJ0WKVPuqaAZ43g4izGcjnLS3X0acFkGjMTqwRKiM
         XumOyg5TjBdTn8IyE4vRYi5GQO4nQskZk+S2M2q4vUpNSKBXC897+voY9L5mvP1DoDAv
         Gpyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Cp89rZHQypoAlOCNHCyWU3ytuEytNXkoLr0IcNjmOds=;
        fh=wXWK3UynicpWrAWeWv8oeM9VLMUNyh1eQbJaN0y3wrQ=;
        b=JqRbuRDNeZi1sklKEiiB5Met/f11w4fodD2jQCVkppUVlwRGv31PGwZj3Lkp84zG1H
         Vr1JrBCnLVcaUlitXpBg8tMywqbm2gAmdCIHTH4NFIxNO6rnwQd82bPsoq6K3OT8ys6z
         zeQr6MbK7DVCUDHXD4suTcZh9vUtFSG52ub9IhA6rshXvCv/mBq8zdyzM6zhpVrFjlmQ
         cWT8/DjJSEFgI84rrpLA6V4WD0UZPFCCejsojim6E0EFjhXAN3YelJa94blXTI/oKdgp
         99kQqwy4H6l7qQsPkZlzvpmDUfd11dXnO3HzhX4Wu+HEbWZ2hDU3uUGIuaRRWJJmh2xE
         /rNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="evv6/V0G";
       spf=pass (google.com: domain of 3jhnfaqukcxetaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JHNFaQUKCXETakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-381224efdc2si386251fa.3.2025.12.19.07.45.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:45:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jhnfaqukcxetaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775d110fabso15677545e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:45:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXrNM9GTuj8qv04HFt0uC7QUwAWwuD7rj/7zkq7dV9gpBj1Uvlaeh9kF+82WcveYsY33mnkq0kiVSc=@googlegroups.com
X-Received: from wmpy33.prod.google.com ([2002:a05:600c:3421:b0:477:103e:8e30])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:a010:b0:47a:80f8:82ab
 with SMTP id 5b1f17b1804b1-47d1957f71dmr30483175e9.24.1766159140325; Fri, 19
 Dec 2025 07:45:40 -0800 (PST)
Date: Fri, 19 Dec 2025 16:39:54 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-6-elver@google.com>
Subject: [PATCH v5 05/36] checkpatch: Warn about context_unsafe() without comment
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
 header.i=@google.com header.s=20230601 header.b="evv6/V0G";       spf=pass
 (google.com: domain of 3jhnfaqukcxetaktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3JHNFaQUKCXETakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
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

Warn about applications of context_unsafe() without a comment, to
encourage documenting the reasoning behind why it was deemed safe.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
* Avoid nested if.
---
 scripts/checkpatch.pl | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/scripts/checkpatch.pl b/scripts/checkpatch.pl
index c0250244cf7a..c4fd8bdff528 100755
--- a/scripts/checkpatch.pl
+++ b/scripts/checkpatch.pl
@@ -6733,6 +6733,13 @@ sub process {
 			}
 		}
 
+# check for context_unsafe without a comment.
+		if ($line =~ /\bcontext_unsafe\b/ &&
+		    !ctx_has_comment($first_line, $linenr)) {
+			WARN("CONTEXT_UNSAFE",
+			     "context_unsafe without comment\n" . $herecurr);
+		}
+
 # check of hardware specific defines
 		if ($line =~ m@^.\s*\#\s*if.*\b(__i386__|__powerpc64__|__sun__|__s390x__)\b@ && $realfile !~ m@include/asm-@) {
 			CHK("ARCH_DEFINES",
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-6-elver%40google.com.
