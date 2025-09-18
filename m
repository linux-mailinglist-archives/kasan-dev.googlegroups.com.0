Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFDWDDAMGQEIBS6KDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1691FB84FA2
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:07 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-35f5e462848sf9556361fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204366; cv=pass;
        d=google.com; s=arc-20240605;
        b=hKQStwX/rHDGz7BWJ9Q8Vjb3rz/tbymNSRDHXLLz5YtqWkLppUr18LKMviJ4TOblsM
         nP6w5Z/bLzGTBTsp/0aLp1v0abwOdX48MLxpz62h1SSocEugVA9iDAnvGCN7y5vf3xcc
         h9nvBE5iA2mmioljPucrPcC4iEdc2bMTyWvcZNN/KS3zvB5GrnkXAz+z+Ul5koH9iLGV
         9VsMao+HEC6n2ijOGwADnuZuFID8iy27nQxL4E1YV+zb7QK7rk0IQbNmMQtbBLihflju
         dMvFCSqHhMridgbQCO79AoWYrW6BF65K/0V6nWIuelnub4ppkHm5qMd+c3Ra3NwAvgtt
         sVnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=SWPkPQi5BPhv+NNkXDimZ6RsnNFXTzxvvSZYeZYBEnE=;
        fh=Cs90FxGHEHE8Vd0yUA2FlSPLl9y8MKPtjjo6BOfwDS8=;
        b=iQaiucz9YatA0BmFHkGoXAvof1rf8cAW5vKMz6mHZIrZW+nWeQH+KJKj2WRUfYyAni
         Wicgt3udHrqcLtI4B8UvK0TeF17oL46SvqXEhETTTdEI5XZUhmxCzEvkrC2HfN36IX5X
         Dqbwln3NTfRkUg0Fn0kRntd6vTtEINApYjt6I2dyiHB/lMrZMaNbGDnleZfEa1prZoMV
         CiIGomZhxnAcJSHFn2+604D4r3/flYZjQCsNVLU94G4nbtA0kU8yBQyTQq6qn76p8/Jo
         7cxmpE8+mxiqJ6DqxFV2900hKtJ9kl2/jWeU3429kzECooW9yTNs8eUrE6JaUaYk2Mf8
         u82w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="eqC3/36S";
       spf=pass (google.com: domain of 3xxhmaaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xxHMaAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204366; x=1758809166; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SWPkPQi5BPhv+NNkXDimZ6RsnNFXTzxvvSZYeZYBEnE=;
        b=DXm3DCIiFHLlSG36g5c4Qh4DjKBuuHWVcTzQy4PezR854ZbjmxI2O3B33zPG3hsvbx
         tr5gKRzmFXVjY3gvrG3LJ5hlPsf3VAmZ+B4CbtyfDJ2kXg4zct6Fa2cJKMw6dZd27KP2
         VgfermK/HhzhehMef7Ze4dwmH9JZj81PCLRBYENJmjmW3sdXg15AcQVmx/NL/fMy59TO
         kY72JZwvKXQ6NegTXstn3NBCQASSFPkzGm/gYNYV1UVYgjAz4s1eZnYUyb6SxbQbBfbY
         2Xy50y6cU4xwRBpqHCv123jjfJ8afBHUPbnSkPw9Ay5r3Tf09LVpqAuDKp/ADCOwS2x4
         xZ9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204366; x=1758809166;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SWPkPQi5BPhv+NNkXDimZ6RsnNFXTzxvvSZYeZYBEnE=;
        b=uCnlsnaGMfH1hKXUxVkOtNzi1o/jc0heggLLGDcMJSFc11gCQFvVPgzqh3TMH6VOyV
         uN883lfZ4GlipmRv5OB1i6/E1Ph4lqAkBFJfdGS0k2+HJ71Q8AeBb0UclLzoAryf3fGk
         7O9NNeBuGU5uwS3j6gHA/Ua1awuSmSPMojQ+y3L5WXqXukYM82T6PQbXPFboY83fGYfC
         08P6n8HMG5GMrAfS7HN+eiPDIa5ftNFnxzBhRFyBzirgBZh8Bt/ovS/RJ2Znm9X4RcvG
         CjPJfQ4HdIgG+divEQfSMxUEayR1G5OIXstUM7KsNXyWWOjayAP+c539idWamDOBK6pR
         GzDQ==
X-Forwarded-Encrypted: i=2; AJvYcCWM2JB29Sxs4wa10Su1saaZPs6MiK3pm/ZlpcfovauYrdEB/4DOCkAI3NJw1kqTn+1Pd8QXRw==@lfdr.de
X-Gm-Message-State: AOJu0YyAcgzSn4SAjMy+PxhbeUpYJ2B3ivFIkt+O5We3kE4l0S210iJ1
	RYjOMRDiz19WfZaWFPoz/Bjqom+y78heDTaYr/JnhkXPmsfOzKOtzy/z
X-Google-Smtp-Source: AGHT+IFoheyyhEny5MiIbvItJ8DgZUsj8UGwUBm4DVk0dE+2Z/GUJMbLoHM160eqkEOYF2u9hH3S3g==
X-Received: by 2002:ac2:57cb:0:b0:55b:83cf:b260 with SMTP id 2adb3069b0e04-57893c6c8bamr882146e87.11.1758204365551;
        Thu, 18 Sep 2025 07:06:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7WJTEyeXcd0v9YmTU2LyIeNLqXUZDKuk+jTkLI0X3ybQ==
Received: by 2002:a05:6512:40c6:20b0:578:366:16bd with SMTP id
 2adb3069b0e04-578c9f3c6f0ls50345e87.1.-pod-prod-00-eu; Thu, 18 Sep 2025
 07:06:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX8LzBaSZsExAduw8tRoWPw/xxILNeTOkhv7zRIj3xm0F+vyg1OTxUGisMvPfC0vP9jqBP8C9ohJ1I=@googlegroups.com
X-Received: by 2002:ac2:4bcf:0:b0:55f:42fa:694f with SMTP id 2adb3069b0e04-578934b40aamr1298428e87.10.1758204360444;
        Thu, 18 Sep 2025 07:06:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204360; cv=none;
        d=google.com; s=arc-20240605;
        b=jK3lDWsVYCVZlxISBGYnvXUyVwUi9QuDynQLZKKSJp1wFddJYTlVdaKsVfX1PoS3Ce
         V0yQ0yYD9fYkFHayBIhiwZX+01YkCVrrgFzcr/csrLn8plDa1nxqYvKI6DSxr9iuXfbf
         sY8Azb3mdWfof8/k7MsVyvVWgEnKk5IEPnevjujTvLIJkGmNaQ79Spg9e4tx/A/azRs/
         UAhDh/ZTuktqEqwsC499uHC6v/0AlFGaFVaMYNPSysmm8CgppHOFpM+NoG6rZuZOgTJB
         Df8WMMxzdBRxemN+TX6FPZaDljy/C9mxR4Z4y2FKcdfixdL/+0yObaPSAVE1fYFefMt/
         F1sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=5lBqaGhUvOv+7EeFvUiY/U7KvKRahgMMUHhFj4QhTCc=;
        fh=6eMVdcDOF+lW1/g+9McpI3gnSTFjrMDuPan26LtGX8c=;
        b=OE1d0aAXrePa+Fbspxn09uHmeUCYY1nAUU9pUBAN88WRq2Ax5GoQiwbPnFvJ5ceOWZ
         YzIaBJlXBHHbJ2EGlxdDERlwbXiMfu8VMZrnqdq/qZT/8VVd0oOscNw+y0hSEDiDGr8q
         vvyY/P9EdBkahWkbeppNEnfQfKLRi/ZholR0WZE483p+YSn0ELkLZkgx3W4mTFQgg5UD
         m6GTlRfsLDvl0Ns37bawXpUuZN1RrDzQ3EP8tukk25TwsZ0pzHc7NR/graqskaQ4eLEO
         YiKSn+DGtJVHnveFnX31yPU7UQG9gCFjhEkTJz4mn6DqCLKt8/OWViy/p2xZ3/07jgbi
         amzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="eqC3/36S";
       spf=pass (google.com: domain of 3xxhmaaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xxHMaAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a8bd4644si17911e87.8.2025.09.18.07.06.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xxhmaaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3e997eb7232so453690f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXc7OL8ea1RytRL1f8Q1HXArpA1YIGnwkfXiyUS8yxafIDkrpCJdhXryOD9ZTVkaqCLxVZpgZSeO1s=@googlegroups.com
X-Received: from wruk7.prod.google.com ([2002:a5d:6287:0:b0:3ec:da84:10a4])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:40cb:b0:3ee:1461:1659
 with SMTP id ffacd0b85a97d-3ee146119c6mr1267126f8f.31.1758204359630; Thu, 18
 Sep 2025 07:05:59 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:23 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-13-elver@google.com>
Subject: [PATCH v3 12/35] bit_spinlock: Include missing <asm/processor.h>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="eqC3/36S";       spf=pass
 (google.com: domain of 3xxhmaaukcwgkrbkxmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3xxHMaAUKCWgKRbKXMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--elver.bounces.google.com;
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

Including <linux/bit_spinlock.h> into an empty TU will result in the
compiler complaining:

./include/linux/bit_spinlock.h:34:4: error: call to undeclared function 'cpu_relax'; <...>
   34 |                         cpu_relax();
      |                         ^
1 error generated.

Include <asm/processor.h> to allow including bit_spinlock.h where
<asm/processor.h> is not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/bit_spinlock.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index c0989b5b0407..59e345f74b0e 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -7,6 +7,8 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 
+#include <asm/processor.h>  /* for cpu_relax() */
+
 /*
  *  bit-based spin_lock()
  *
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-13-elver%40google.com.
