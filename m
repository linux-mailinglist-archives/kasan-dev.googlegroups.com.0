Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW5DWDDAMGQE5KCL3EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5583AB84FC3
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:20 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45f2c41c819sf6664245e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204380; cv=pass;
        d=google.com; s=arc-20240605;
        b=bdAlN+7xdBSIZQ3ywLcphBYmuTYCQtnQP+c4Qi4s7xCAXjpjJckCZHFA+evIMuBA7z
         VQ5iiw/ycO/O+mWpGOUk6/mYKqDQAyino6kdyrInox7Ch+4NWeoPEpJmTeSyQbfW0Lrs
         6RpGHdwMR2h6pyCu8XcGGBcUidPGI8iIUNx8AtiaiyuCrNp/ks/ON66Z3d8CEXakSKxk
         KE//LuU4hbnf2SlKwf1rBb0Ndt1WIOQU/r/gd1a8rHjVwzNibNgOhTv3rCrEBwqYLBnp
         KuQ8GGbh5h32iZO0hJY/YLEE4AAsRZ/wXOUo/l9pwHpLaVkh6ZNEqTtR5FD7Joxh4Fol
         JkUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Gxmd05QxWAv5AZBon2nFsDBkCrHnunRA3INr2Ej/pP8=;
        fh=ZpwoqHMDIpdZbroVcdPdnA4A52eFzXXxRqU9uUqM1Zk=;
        b=GBaHWNUm8Tni2VKoh8L4k2o1ykuHXJW9wmWVuVUYhdqc4tXL9Sq/GtqVl0fi7l7Sym
         JUEdl54m4XVSV+f1JC8AvdQlfMNzUhFxjhOjr9GQD70Q31HaQpycFkvp+8LXtwaj+iWT
         JnMWAmC0rqO/SxWT9x5HBM3/gk9nQGG7w9VB5uawz/tl0h2+LyLiuXRfuCIlzt1+CLw6
         yZci+zXNjhGttucqW4GwFFbbi4VjqrE1myxUBvzBx3+nVahtrECNi/a4H+LispEgYjS8
         3ZGB5ByD3vONEqNkWAKKrEpoHOwSAIglBP5bSrXkdPd2t4putKZK7/4wG7MdvXNC+KoX
         bZkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xorKFmcr;
       spf=pass (google.com: domain of 32bhmaaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32BHMaAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204380; x=1758809180; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Gxmd05QxWAv5AZBon2nFsDBkCrHnunRA3INr2Ej/pP8=;
        b=KjyL6YNeSpJInn0m8PQ7KRVOcJ8PTkgitJ6hZ7Uhjl3agm400QDBY6mpjx7Rno8WFp
         lIoAaZbqcn7yQf2SUhGadHgkVuBEYi47G4MLgwn22xdZeKiObXuV2Lg6pKNdiDkFsAa3
         IMzi4dbRELgIoGHjqO+gRfEVXx0JEnho5DaGNmSfM5sl4IGfqLmMG63olynzkk9o501W
         Jkmahvm6YXxyVdzl9XKFGdJ7dGg2/go8HHD/USF5jUSYRqvVrGVL1dQJlBExhzgr/nCA
         cvRWhNDBKW7cHGxjTWfBRrgDSxqEhR2dxOYAjH+7k44LAfh4FHzZfWZ7V5d3utRwwyl2
         2BvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204380; x=1758809180;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Gxmd05QxWAv5AZBon2nFsDBkCrHnunRA3INr2Ej/pP8=;
        b=UsCf8pm64PZfS1f+zd2yvfsfXKpSSqvgLI0uvw8lkr4t5aMhpwdEB5/rLzQSXNTf3z
         S3S//K0KL+ijSkhum6Bdzefr9iFKwQYy0DlkLbkCXt0tWVuN84H2PWd1Vfd2fQr3JV8P
         LXi9xIuqCeotngLp/OUwrfyK71QgyJzHPtxbOD2H1V18n0b5j8Zu82aJddsqv06LCWb7
         2aSNkN0zL0xwpbQB4CLYk1vFe/wJHW411pvEbsVvY1w6E18HKLWg182IogG3s7R7iT1b
         EZK28sEI33MhsKgXttq/ZRK9seATesHDmpEDWjnFC6uKHjNUS7QRnUerEZAbpoIJyt/m
         04fw==
X-Forwarded-Encrypted: i=2; AJvYcCU4B+PkjH01L9cUMRCbLkJCPdFDhPJau/764YFAPAHIuOu/Bvg+XetoGQYexJ6ovFuQ0Tmg/w==@lfdr.de
X-Gm-Message-State: AOJu0Yy4tug8/hxRmcXenzObSOtVF6yx8r35FfPLQmc2iABo7+wyJfHM
	W9LTvbxd5lbbugsA9NsJRdxJLx2i2eSRGI1SUIHxhxHGoWhZskqkTCLZ
X-Google-Smtp-Source: AGHT+IHcigOaZeDcN5u2dIPYayLhaAmItigba6nOkv+shxaFlSN3bGp4E4gEMj1e+iQGcB4Z4ZBtEQ==
X-Received: by 2002:a05:600c:470f:b0:45b:615c:cd2 with SMTP id 5b1f17b1804b1-46201f8a4b9mr67966415e9.8.1758204379746;
        Thu, 18 Sep 2025 07:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd59tnPme0s9n7qMga3nyWLidmxKsFDNz9FqSE0yAd61Vw==
Received: by 2002:a05:600c:4ed4:b0:45b:990e:852b with SMTP id
 5b1f17b1804b1-4654317201als6384115e9.1.-pod-prod-03-eu; Thu, 18 Sep 2025
 07:06:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV8DfjXiXENJR0Nb2wngTsQlbSN2Tg9q15cKnA3tdOnO1sJlB+NrWZoYdpE1mwUhNw7Ay93yD7jThI=@googlegroups.com
X-Received: by 2002:a05:600c:198f:b0:45b:9961:9c09 with SMTP id 5b1f17b1804b1-46205adf769mr68462505e9.17.1758204376794;
        Thu, 18 Sep 2025 07:06:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204376; cv=none;
        d=google.com; s=arc-20240605;
        b=QnA4CpYWNz7mdYvctF0LtD9r6oOLrN3HULdbsVxKtKppa4LnWTlTSSQF1JtCRlFWbR
         aQVZbQCsXfzCGncBR0sLtIRFuVfVUNHKl8nkofBo9g+ZJZ8/PdQ6jIKLtga809mbsdhy
         zrUHucl3P/FZ/fb1H1gWhjNPEmcOf80Bnqm24Nhm31BZ/gD47K59SjH8v5ltPTEWSpz4
         8Qco/g7yZN3iGUMLEqKr0fAOK0IuJRhYICD64t13GMOW+QqhJteEwyHqBNWLdTOrJi9g
         AD9t30gpBVBe5PBF4SM0Bn/wKus7Qp3ZqbqeRstmDNh6xILeljYiiErgt5Dlsyq3As6v
         KZuw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:from:subject:message-id:references
         :mime-version:in-reply-to:date:dkim-signature;
        bh=YPOyraitAoGllB7BsvSWOoZaTAjW0zjsOFJLH9vcrlI=;
        fh=0N4fuEhIbTTl1kdy9dZb/YcN03Lbs0D0QOK3cg0E7Aw=;
        b=Nodv+kZh7KCyAyyVndv48woPdPAieS7bbfNgb+NV+WbLTmmgaGu42/1wtnZaO6Rgbi
         xErnWunbkaf/vcEEBphB/1v3gkr+Y9sfKpV4kb4f5RLyBwtXsftrebD2dEZwp8zs7eU4
         XTYoxooV2kQSxy9kFYnil9s9Bzrdp8bzjiCsOmhUT4kIxn32mHfl8fNA1xU7nz+XdsiJ
         P1t+yP7xalJ99TgUjh6g+YlOf8i9fbcuV1OOHNe1z7yVd8ULNnzH4XpsK34GTZo0OaUD
         0pnb/64J5zue1Wa9wr1VjlpcanSqSL+CLpQOMqsIdbcaCxXOkRgyCUBBgnj0MKB9DAiB
         YCQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xorKFmcr;
       spf=pass (google.com: domain of 32bhmaaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32BHMaAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4662b08d9eesi236745e9.0.2025.09.18.07.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 32bhmaaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3eb72c3e669so654340f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2pR6MaHgTtfXcQ0L/7zmI/P0gnVqjeQkT4FWjiHbzQv82sOiXGHdiy+tAwLtmmEjoilmWhst4d+0=@googlegroups.com
X-Received: from wrd21.prod.google.com ([2002:a05:6000:4a15:b0:3ec:defc:12db])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:4284:b0:3ec:b384:322b
 with SMTP id ffacd0b85a97d-3ecdfa3d37emr5318506f8f.46.1758204376079; Thu, 18
 Sep 2025 07:06:16 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:29 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-19-elver@google.com>
Subject: [PATCH v3 18/35] locking/local_lock: Include missing headers
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xorKFmcr;       spf=pass
 (google.com: domain of 32bhmaaukcxkbisbodlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=32BHMaAUKCXkbisbodlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--elver.bounces.google.com;
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
index d80b5306a2c0..4c0e117d2d08 100644
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
2.51.0.384.g4c02a37b29-goog

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0250918140451.1289454-19-elver%40google.com.
