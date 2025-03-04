Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGEOTO7AMGQEMOBHRIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 941F7A4D805
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:25:45 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-4394040fea1sf26657755e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:25:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080345; cv=pass;
        d=google.com; s=arc-20240605;
        b=ROfk7ZYQhO0Eb8aqst3prrnM5Pshf4FMYvqegzQtRFVN00adlwCT9upODHrSbtyRVx
         7SgB5IvqYUiqE+/EizpnQl7mpBp1GQs/ueiWk2KqdvjMIwhL7kL49DCStzT8xHF68fss
         HbJ1OenTkm9nWs+fhqWFQuul4bEbH3hPq+WRwui3hxUFvNnkQZNNCAaGvHgaaomN2vwN
         voZUWImUdBvz/s9WMF1V9MfdMdX89yQuOvrhxhBUz1P7gm4ID8NuzoBG2PecYJLOccZZ
         f2dIwuCsbn52nlxh/W9QMmBVhT6JinhfALmVzVQc1RN8yA/rdgkLhGAU5F9wf4rEfnxK
         du1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=DvGf9MbNTNLMVT1gej+BnPNEJdPFiKx80DiIk/SPOGY=;
        fh=lGCvCb6sgmguXTuLfL02kWuBLzyqv+jaAZUNmfanJBo=;
        b=DwfzYN+5yYx61fZpXC39bvxEdfwXRKfiKsg/AFyNuPdsujLzbphvuvzYfoCM/vV3xy
         O89lPzG7/Ud5M4GC7CbJsrpiofLsOrD6WbONvn+FU+14kLC8RYPOQaDzfgJ96ckegrjm
         9uxj2FI+6JADEyrRJUEnfidwpEPLI2jM4JuYFPZikA1A9e4p2x0PxeAHf8J5oPOYGRhl
         8RjbZaT1/vKv6QyUEztcr81jYwSOJBu46SN/V9GgnACKy80Dl1wgLWFaX0QVpunM9ZeO
         wf28LoFQ3RJ+5ehiwQT8BEmGBqG1XrK11g7ren58qeosuc+XzjPw1TcuMdPyZ0N+pqqR
         UbRw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OnoQUK+O;
       spf=pass (google.com: domain of 3fcfgzwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3FcfGZwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080345; x=1741685145; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DvGf9MbNTNLMVT1gej+BnPNEJdPFiKx80DiIk/SPOGY=;
        b=O17G8r9USWkIjCe0JOM+nsAVjH0zucrbjd6cyzOwV5LAnTPaxBXXGrQwccrkAkAx5g
         iwj7ARm+5Qg1zFfu1Ga2jpu4eE9wS7mcEwo6uvTiSSr68XyR4l5SesDCS8Sf+NIvBAOP
         7lPe/sO5B+ujOaWjKngRwqLmyLtOUKEYT3LY/CEe7P+trnDKyAQn3/Avxjs2WU2WKfXr
         IFg293CD+zNZyXUWgoIYXCsY0xytrsW/iCC00d9GJsrjn1lJzbQ0PVFubA5WcinsNGJ/
         1mTmYteMraC+pQVeU7sestYLTAdV08JcjzwocrfCIvge8D1F1SDZ9/bv4Oc8HaExD3oC
         /csQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080345; x=1741685145;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DvGf9MbNTNLMVT1gej+BnPNEJdPFiKx80DiIk/SPOGY=;
        b=Y9fF5fPOytZROaRqfF9wpM+xaFFoof4n3ITU08jFrytNo5W8MQB+Glorc7A17OB8Kw
         9OFXSz/RvNyqI/4RNBlP7aqVaOQGEsZyjnRnuKTWYtrmiaMPKHPHE/KXZSdolwlSQvK4
         zwH9GI7gn7HTdyw0CpPHLh1nd6fEjSS1ZpaRRYqKxOHriG0OwZZXXPoU1FjqM4F+fhhI
         aYFG5Jk5tFZauHbOjxe+RE4LLcswKjqhux9eiBrafzVNx0CyTz8WE+NS0nyXOQaI0zNP
         sBNaKI2IeiPb6NCbIlsllz2eTtZzBhP/0+S+I1wFtqJ7jgIxnKdsLFVAcSg4M5zeYpRs
         5/sw==
X-Forwarded-Encrypted: i=2; AJvYcCUvdh1TUM1aStPbX05ihR00CyXDCX5ngxWbCHd0XVN6gjX9KDLPryb3JFM8G/sf/hiv1fFd6g==@lfdr.de
X-Gm-Message-State: AOJu0YwmGnZkpPYSz4zrLaOSWeNdSOTGg7D4o3IfNtrdTVLYqgamYbpk
	xwdItKQl4FTQFpm0zC7fIKhIhFaU5mGmf9tlWtWvRQpGA5ZbEpxf
X-Google-Smtp-Source: AGHT+IHVc8fx/xIH94JliX0ANe14YxTswAsSkJm8KFRULssKYeJz3OawLn+kp0ckqPLHpTjg/ZCZnA==
X-Received: by 2002:a05:600c:1c06:b0:439:9434:4f3b with SMTP id 5b1f17b1804b1-43bcb02458dmr18107295e9.8.1741080344640;
        Tue, 04 Mar 2025 01:25:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVH0FT/MEQhUC91GzAtDc8SFuj8IuFufkoimRWAkkO1Y8A==
Received: by 2002:a05:600c:5798:b0:439:ad97:3e6a with SMTP id
 5b1f17b1804b1-43af79306fcls6858905e9.1.-pod-prod-00-eu; Tue, 04 Mar 2025
 01:25:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFw27KPeWaRrMx/wyF9l8v4ad8iciss1gZGZW1VXe7yk8/3+dkeyLEBaoSih4hltNn6b4gI/cn6Ek=@googlegroups.com
X-Received: by 2002:a05:600c:4f88:b0:43b:c857:e9d7 with SMTP id 5b1f17b1804b1-43bcae29404mr18016165e9.5.1741080342172;
        Tue, 04 Mar 2025 01:25:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080342; cv=none;
        d=google.com; s=arc-20240605;
        b=HNArONVbQPUYglAJjqsBS78VYqwY7IES4liI/XpApnDzYPySbcLB8wl3VC/8RW9sMl
         gfLEzW7/Pk2VTrIv91Z3gorV+r7SV01HCTPzlMFEKXVAH22mId9sBMZSa0aYhHUJOWda
         KKwjhEaVSG8EwveUtaTKV7FIqCWHgKvJBAz3Ubwzc7jcwkQPhrYBdqBNs9AFZnCSpoNP
         7n7IwrhLcaMta/zVj3lPDAvf4gCXljYsC/MUyWDd+Fz8+DsfXhaANqmp7Zg80VTdI4aR
         c278djCE7BxI9E19BXeLPuCwfVeZIXJ4N1DzctVLaZZAj2Dtld0DdDvLw/f+SpexQX0l
         tB8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=4NsOo3OXCYTu9WQHyv5ORZtwu1IzgjlVv8TtoKqxnnY=;
        fh=yMGqOhB3nXw943AGUQYv6hLjkErB4rus9L5ne8TSvBI=;
        b=i32uoG8ztqNt4hmPFCLeCnvqnZpeQQMNwsRwWzBX45A6WZ1KjnjGLxCUtb9q9zfXTn
         zl6UN/KzSU9yV7+410maoY7XsLEFodmpnckBfkaQvWm7Xcir1b3y2BZfWxgRiRbmUqZ2
         KkjCSlTsIeNhBimlRVPoEl8QIBMYhWwtq2PQNAfaF/wfufYdfYQ38MROfTybQ3/GGUxM
         4ojcgsZSB2cBux3e38HcDv8nunq15tOfA0UEhYogkGzmQEca3cR9RhLV5odF/L6GbTzm
         LVnBauz58ozjd67JkQilVW77qL+YtmvBJcSlguoLPjiK5kiIsE9vk6ePCRuBQ8WavU77
         neDg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OnoQUK+O;
       spf=pass (google.com: domain of 3fcfgzwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3FcfGZwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43bcc13b8a9si394825e9.1.2025.03.04.01.25.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fcfgzwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e5810f84cbso1237320a12.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:42 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWSK7CfYrz0BibkxRfA8wzHoFL7gU9eIU8AaRWVnYRwBJg7Xtn1ODEfxd9gCh/8q64DzdRr+NI6tAk=@googlegroups.com
X-Received: from ejctb11.prod.google.com ([2002:a17:907:8b8b:b0:abf:60e8:559])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:43c6:b0:5e0:7ff3:20c
 with SMTP id 4fb4d7f45d1cf-5e4d6b0cb67mr18149547a12.17.1741080341679; Tue, 04
 Mar 2025 01:25:41 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:11 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-13-elver@google.com>
Subject: [PATCH v2 12/34] bit_spinlock: Include missing <asm/processor.h>
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
 header.i=@google.com header.s=20230601 header.b=OnoQUK+O;       spf=pass
 (google.com: domain of 3fcfgzwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3FcfGZwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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
index bbc4730a6505..f1174a2fcc4d 100644
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-13-elver%40google.com.
