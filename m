Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKMOTO7AMGQESI26QZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B07A4D80F
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:02 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5495a1c0be4sf1742453e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080362; cv=pass;
        d=google.com; s=arc-20240605;
        b=Eh3GFwkLik2kj+GIz19fEc216cL03bhLBwVXkH83Zi4Dw/kaHcciSYavr0BG4EdsRk
         eauFAgyjNCnj+RJX11SU05hsMjCYQDC2pVqeeawLBDzePrSFL5IVsfGeEaswn9IZHrk0
         iwQ3tf5doyRjdCg0mCb4PW/rqeVPK4/b1VEk9HXh3QNDVyeDA3++QOSK8HfW3MBMdL1/
         WQkT8AH6/Pg2tYpISXV5a3JBxlluTlvq0DulV0319a3Cf1W+Welw2btvrzRWvY5POSdv
         keJOcaDgHTpfkF3NlI7+ZQUd+83FY4NAKCYKAL21yRpONEUKBpS+7FCqtcOGI44SUOYq
         i1Zg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=B/0O/9BK60uQ6MGR02QGTUYbFqUF4BC6+kw+d614PJk=;
        fh=g9oB5MVAL/1KsS+B84unBfKPB2o/N6E4lD+CrXeJS0E=;
        b=CdefOAiUVOBoYZ12lC2vmC23Knn0h76L34iuNlpZB5Ouzcn9MOU4tI+Udthu2xJGbG
         h70A3YDjRYIB0T04D3YCSl3BmmI75W/t9BOmMrJe3zunDpFnZzMvoO+1E0N5WGrinHHS
         WoljBTkZn0BxOV07QS568uImNOvig92krmGaQhHL6Mx8coO4fOGLu8KicsEobtl+0xiz
         A+KxYYidHIdufI8RfOdRw0WDGP9aenT16UfYOxYYGCGppdGnmHC3hU+8MzeHkd/RNWXb
         DSLkmaMb6zrqh3A5Kc1846wZFaSwYOrLIFfshRkZUPnMHUAqK9XMClPYYMaFOxeFZeAw
         IqDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eNo3X7BZ;
       spf=pass (google.com: domain of 3jsfgzwukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JsfGZwUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080362; x=1741685162; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=B/0O/9BK60uQ6MGR02QGTUYbFqUF4BC6+kw+d614PJk=;
        b=WDrW1eGAfdH84yGtlqFFSob+XG20/IQMt9GtbI/nfhQiCR2WNj1TPfb8MoyAaUjOLh
         2dnOLXsvBC6YvxjThnnOxz2o0i1Vgu8y88hYVq/herysvvuNzEOs+Sg8vZVLnh1JusCX
         tnq/TA9Q3aqxhUGv1bwVV1aNqcyZ/BHbyV4tHQE//yZ0v53CTqPHtx3H2EDDifTFFZRe
         Ykou9Q8NFuOGz2KrxApGREYO57+I6LmwQtMipDHl4nhuyOlWZVeOIxFmbXsDkqlIB0A+
         Y+vHoD5+mb1vAor5IMYts6TIY5hhWVud/uLqh0J7o/xSCtPUY5J7INqXkNvC9gXkz8hs
         79Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080362; x=1741685162;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=B/0O/9BK60uQ6MGR02QGTUYbFqUF4BC6+kw+d614PJk=;
        b=hvdc1XrgOYage2ATvZn9Zee7utpCGmjYTgHbJiFTex6ad5sneZ9X0hPgaQipGCkq8z
         ei2ns3ffNsDwIfC0RTiDmioZ2XBAnwSfYy6te57RH30mtmpBVveZjK48IZulXGGviJ7d
         P4OE8mBWkk1sFhJ5NO/Rm7jjrvEGJ3RI3Jaf7ppEHPnIVRRDexdxIP95KgjYPU63INBd
         n8cCc69Gxl4YjwRm4qsxBqyiIuR094blsv0G/TCVcBqsh5jsCJ3My8GvXNgW0GMjbwbk
         6VykCbbHF9Jxj+k/uO2yKhy566yILRsMsvrEhULIhjGr06pJSQyqGqmWsGb/pR2bwjtR
         AwZw==
X-Forwarded-Encrypted: i=2; AJvYcCX6Sk9lGhUtSuUtDEp35HbkQvwOWBwy9ZEUe8bugO8d5IUiCgbFcCUHWdHlDlfcvSgBSMq7mg==@lfdr.de
X-Gm-Message-State: AOJu0Yz9v7PJwGXXspEc3w2D9Spbe7qdjepYHUiF1XPsUutzfAw3HNxj
	JRIKJGHU3r5pWPymXj93TnStRah9/3LPeI8W1YFOUJVparChw8N6
X-Google-Smtp-Source: AGHT+IFvCYXIez2ZHWqP3RjD2RtxDCwMddhyZzTccJOatK7RqTs7oZWTBrjqVxFcqHnSGQnfn29mvw==
X-Received: by 2002:a05:6512:3f29:b0:549:39b1:65c6 with SMTP id 2adb3069b0e04-5494c37f6admr7112405e87.34.1741080361522;
        Tue, 04 Mar 2025 01:26:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEBfBXOOpVIrl32pNSkWtmPVyuJvTAWXcSPTK3iVutP+w==
Received: by 2002:a05:6512:3f0b:b0:545:256f:9b6d with SMTP id
 2adb3069b0e04-54942e6e667ls247361e87.2.-pod-prod-06-eu; Tue, 04 Mar 2025
 01:25:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXb8fnkGBhCo5q/ikYyIVHG8unTHuHMoP2FXsCKez4ZfP/n6qLl6GXkR3voxA7zdWtgGFYLs7Zrq1M=@googlegroups.com
X-Received: by 2002:a05:6512:3f02:b0:549:38d5:8853 with SMTP id 2adb3069b0e04-5494c3287d3mr6545246e87.17.1741080358775;
        Tue, 04 Mar 2025 01:25:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080358; cv=none;
        d=google.com; s=arc-20240605;
        b=iyMrT3l2lUNe0bse6nmw4+hecDezzLSUb6kGKSCu54Ib4egj4zjOhBBbHo2qirw8N4
         4RYyL6r8h7Mbtc7b1hkXz2UrYT9rT75/nKEbJucBBT7M6ECK2zzuk75EJH4Zl/BVl7il
         ohV9c7b1emkd80iiUcgXYD0Ig6BwUDS7m9SFzJOOSUIGlvjAgbXyYQ9Qy+GJt32pGN/U
         xNgyzWviO3FPkTvzFXGlwwDFllqaLPuv9vZYJ7C75JkIBn3S6DSoZwNWjeAjbVpvFc09
         1SZTDkFKYfsyRLtpg3mw8LUCcuLWaUeI08Sw2qA/p3+efln4wL9udW9xPdaV7O8vbONt
         U77Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=PNf/nM4zXVueSeYIgASkm7nQo4wF4e7ceuZttNxifgI=;
        fh=Zo53tiBHmmzGI+diXdJmE01t5vCasUnzBV4q7xnTffk=;
        b=I3ZXdg8uZQIiUdBWJNfszhHH7PyOLWL01zXmpSL9eszbFT1bwe3qhm8Pkpq3zvF897
         3ank6fM0RxWvPuG+IEtP7XVGrg+wENMCI0u8+gqN/PKGmYe8QH813i09eInc5hOqqUEd
         XxokpwZmIuFo7Uc29rOeRX4/RlrPvLEiTVwM/9fo4bVtYch2eRC7gp1nH7ftuWpESJqQ
         meENdNKupQ45cb35Ur2TSM6nXUfLV4gm1NG1dYDCbFRY/RHO1XSUDHAd1sH3/cjRQVcI
         +bs2m4PZzVRyJQricrHUgfQXqaSKeLkJc1iIIfvcnOjOQTPuaEccmErwcIjYQnFRoPBY
         w6gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=eNo3X7BZ;
       spf=pass (google.com: domain of 3jsfgzwukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JsfGZwUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54954f95ee1si328545e87.4.2025.03.04.01.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:25:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jsfgzwukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-390f729efacso1223711f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:25:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUU0xxplNEY6RJLynIGv+mLQT8FYdyCxRTXYz4ikpKwx874/U5ytDhYRcBCtATI5JvCIRH3eEMGNgA=@googlegroups.com
X-Received: from wmbbi24.prod.google.com ([2002:a05:600c:3d98:b0:439:8c33:5ed6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:4022:b0:390:ffd0:4138
 with SMTP id ffacd0b85a97d-390ffd04350mr7740206f8f.24.1741080358018; Tue, 04
 Mar 2025 01:25:58 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:17 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-19-elver@google.com>
Subject: [PATCH v2 18/34] locking/local_lock: Include missing headers
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=eNo3X7BZ;       spf=pass
 (google.com: domain of 3jsfgzwukcruz6gzc19916z.x975vdv8-yzg19916z1c9fad.x97@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3JsfGZwUKCRUz6GzC19916z.x975vDv8-yzG19916z1C9FAD.x97@flex--elver.bounces.google.com;
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

Including <linux/local_lock.h> into an empty TU will result in the
compiler complaining:

./include/linux/local_lock.h: In function =E2=80=98class_local_lock_irqsave=
_constructor=E2=80=99:
./include/linux/local_lock_internal.h:95:17: error: implicit declaration of=
 function =E2=80=98local_irq_save=E2=80=99; <...>
   95 |                 local_irq_save(flags);                          \
      |                 ^~~~~~~~~~~~~~

As well as (some architectures only, such as 'sh'):

./include/linux/local_lock_internal.h: In function =E2=80=98local_lock_acqu=
ire=E2=80=99:
./include/linux/local_lock_internal.h:33:20: error: =E2=80=98current=E2=80=
=99 undeclared (first use in this function)
   33 |         l->owner =3D current;

Include missing headers to allow including local_lock.h where the
required headers are not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/local_lock_internal.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/local_lock_internal.h b/include/linux/local_lock=
_internal.h
index 8dd71fbbb6d2..420866c1c70b 100644
--- a/include/linux/local_lock_internal.h
+++ b/include/linux/local_lock_internal.h
@@ -4,7 +4,9 @@
 #endif
=20
 #include <linux/percpu-defs.h>
+#include <linux/irqflags.h>
 #include <linux/lockdep.h>
+#include <asm/current.h>
=20
 #ifndef CONFIG_PREEMPT_RT
=20
--=20
2.48.1.711.g2feabab25a-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250304092417.2873893-19-elver%40google.com.
