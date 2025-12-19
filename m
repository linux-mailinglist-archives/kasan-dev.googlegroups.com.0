Return-Path: <kasan-dev+bncBC7OBJGL2MHBB27GSXFAMGQEHTT6W3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BD17CD0995
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:53 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-594cb7effeasf1369386e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159212; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZUGrEGnbbVX7O6DovWjQ8FoIkusOaWeMK3Conx3+9LrgBToSaVX0+LT/KE/nc1jRmA
         rMIqbtBHdnH5j+nndPx389+BQ1hy09csjpKIlCYLs4776PVbWo1uWoLvyYlNXsBF2GoV
         m4wFU5YiPGKKWzHg1d0f7wJhXr6MTh6P/Tdsddu+xhi4iIE8iircqoDarYoLP//xzPxV
         x8qaAhpwVBMqjsWSu7sj2CyRcC8AiBVMe6IFJ2caRvAvGWGe61PDj5fxWV6uzm/iYiZN
         BLNTiez7HHXZTlYPADkdh8jnD3ZzaBOcKVDVjbmlBcFJBcd60h/hO+LSq1S3BKkHGyF+
         sf3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/b+KWlFPrSz9y20Vv0f/UTp8Ab1r5HHvMUbYnCaNAWg=;
        fh=1/xFUQq8gz+HQYdjPkCJTgbL4I1fzHVIrx0j3tY8N4s=;
        b=NZi+3bMvVxmMMmoDPQ+NFpuygXEAsSErd7EqnSApfEteEz8DZbQzHjW8+R+khFjHJJ
         JLMoF62kwAlXVwOhbIHKqAQV6y4rRauURh6GX/ClBxj+F0f6momH0wtIqfr3rrnA4y59
         zkXonAqOvTCUzHbgbMQTIT8kqTqTJcQSM8oKnEroTA+c9BlL40n/mwnVsyPARVtLC6q9
         bMuIHu+qWycCL6hzSuCvXqcBqEiuVzVm6aQk8QhKCMXhWqV0KnWIvalf7xGOb7q9cDqt
         +ulsT66pCwbonN1l7mGYUQrfHbOEIuIEWfXOdoxT6P6xpIhsM5Mwn4QHf9Gv7WYau/al
         ORVw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0YfRgd8t;
       spf=pass (google.com: domain of 3ahnfaqukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3aHNFaQUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159212; x=1766764012; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/b+KWlFPrSz9y20Vv0f/UTp8Ab1r5HHvMUbYnCaNAWg=;
        b=bePCVqj272OZkGg6SmMwZeFZTSbsnPQOXzsm3LSLZ5uGV+jeBoQN69dlptQa9ZwADE
         9Yn87bwymesuCya9KxRfSBtgvrDNu/a5XiDbHt16B99Pz0gFw6gts0mibpD8Om2zYIlA
         tQHN5OVeUrq6LHGDJNUW3zgCinfwEYYW5TgTwCci/ONJooeEcpKndNAPVmmL0YJolSJK
         ITHFpNBv2xnn9KPleezv1pp2G6h6KSsu0WEbpniKadJ0a5/Wqvtzk3OhMGrLp9/2wd1p
         SE4Be1b3R0HbRe1L8gw69Dd25wN0rSvjdR5n+WDTm7u9QdRpmcNK6S9Pbr87ceHrhS0I
         /Cvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159212; x=1766764012;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/b+KWlFPrSz9y20Vv0f/UTp8Ab1r5HHvMUbYnCaNAWg=;
        b=KCBEMsa1RyD5fRcFfNvQH0D2w/JXAXCY8nwjyWafhFl/0GMwFeVRX32BiNt6ewrKfs
         vRPrzspjYRtbKA+eosz7OV3w/pkCoDe6pn1aeAQChpQOZUPY5h+xseP7nicD7VQD/yEN
         0Uy5Xogdt3S7EfLbz2+7ro0exvC8R22HH7q084AaOvuVwOFBUPYft1iNNFEH8syxm26I
         dnTr1rY5IgYp1nKkgO1P2TaresVnr/5ks/a7z1WcgXFAx4SZzoi+RmFp1f+f6QrmeQeL
         vDml3YKgTMn066VZtpWbfPr0rIg7k7ee0fll69vEndkLuARsibwU7HwlLSXkfwNSo9Lu
         G/EQ==
X-Forwarded-Encrypted: i=2; AJvYcCUNpaNjLlWLCS8f/6cu3d8WH6Ei9k5zWbM4Fs2rRSxW9XG+Dupia3zFKacoXpOcbeyqpvnKFQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywa+n26QgyWmHOraqdO0FY/ch70lbtKODsd6s29xPMvVag9L3Hv
	AldVOBkc47xaaN/s9IwQsYHJr0YgYzBj4ZeIAE7cnbHcoahAeHeiHCnN
X-Google-Smtp-Source: AGHT+IGATWIv9dIdN8szIyopxTrQECiIeUTPULFblSCnT48rmmiArWU4QpTZiZ2q3/3jJd/RD5eZUw==
X-Received: by 2002:a05:6512:31d1:b0:59a:10df:7ee4 with SMTP id 2adb3069b0e04-59a17d57a7fmr1335929e87.33.1766159212151;
        Fri, 19 Dec 2025 07:46:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbEIQNbcfQ5PVnssU6c/+o6RFZ1UnMYRLGLCavQdYBoxQ=="
Received: by 2002:a05:6512:b12:b0:598:f8cf:633a with SMTP id
 2adb3069b0e04-598fa413205ls2667451e87.2.-pod-prod-09-eu; Fri, 19 Dec 2025
 07:46:49 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVoAThbfU9gITvMffou45LzV/YCYZmqk7EmUs8GFzS69s7poT+PX5BsmsB+kBzD2iYCpshsjEx/MLM=@googlegroups.com
X-Received: by 2002:a05:6512:12c7:b0:59a:1187:6670 with SMTP id 2adb3069b0e04-59a17d34db9mr1262910e87.23.1766159209111;
        Fri, 19 Dec 2025 07:46:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159209; cv=none;
        d=google.com; s=arc-20240605;
        b=UGOTgFJBkaWHFnwlBUGNp3AerJ0CqUEejl2yg9EoHAoeWEBk71UbUfTcXuSJQomTfR
         L827i6RcYYAEuHK1wQIIeKyN0nvA8F2S+W8+txwLQLt+PG0mI4AojM3OJkcmzh/lw+YO
         MvVYZGZpBx8eIymXnZ9ANVPKNcmY+5FxahF7rvz2twYO3x2JQBnETl91eePgQ7W69Ncu
         RRiXy6JHZV9/3/84Au/0QuXFjDJ0MA9cnxJDcaU7aLWKZom/Bh6Je2B+SHS7v44BEtEH
         2OWM1ps1+A49m3+OJsJB/VEInl3ro7lv0eG2KDUOGqeUZfwDh2MQqZRO/J9TsfPyv8ws
         0M+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=iwJwFE4RR+G0qPj93NacKXfc9Bqs8f3KUgfNaIjFSIY=;
        fh=6r8XOxqG/I2FghHEO1WdXHDljutksWmjPITnBk8sdzA=;
        b=YweBpxQ4ExG9hq2Hyti+3ZprsSmNAN10xZ6EgMzLXf1ndKxzV5NV0Cx+k1f2GxqWBd
         hpEhZzw5T9nz6epXKA0xk+GFvUuH4SejBBFUR9BpZLCv9V3cLzagMD5JCB/Ztw1SpSPx
         NKjyD7yrt/sJ3m0eCu6gQ1UPBVP4id1upBF62NbXVbETdnYUINnP6ThgTt6fEU62l+Fy
         Kjc6ezBXRJPbz/OLiAVETqqLbMUsqQ+2Po3IO3QCRk7TTCUfuUsRRDzU+tQLYkrNybSE
         9QTqq1673FDGedc8Lg9LCAG14r/XhOjk0C/+PluPicmXjmfcXXjQ8F5ovdABxmMQyfWe
         Enrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=0YfRgd8t;
       spf=pass (google.com: domain of 3ahnfaqukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3aHNFaQUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860d04bsi83496e87.4.2025.12.19.07.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ahnfaqukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-64b7907dd42so1740554a12.3
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:49 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXMhlN31AElmS5SUmiAtGn4+Kgb/Rf7NEtp3hSEZFaJwHRcnBKVuEYTV5djcmZmTiY1n1XgPVtwVJ0=@googlegroups.com
X-Received: from edwv2.prod.google.com ([2002:aa7:cd42:0:b0:643:8c4d:bca0])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:27cb:b0:64b:46d4:5d5c
 with SMTP id 4fb4d7f45d1cf-64b8e9379dcmr2970087a12.5.1766159208169; Fri, 19
 Dec 2025 07:46:48 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:10 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-22-elver@google.com>
Subject: [PATCH v5 21/36] debugfs: Make debugfs_cancellation a context lock struct
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
 header.i=@google.com header.s=20230601 header.b=0YfRgd8t;       spf=pass
 (google.com: domain of 3ahnfaqukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3aHNFaQUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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

When compiling include/linux/debugfs.h with CONTEXT_ANALYSIS enabled, we
can see this error:

./include/linux/debugfs.h:239:17: error: use of undeclared identifier 'cancellation'
  239 | void __acquires(cancellation)

Move the __acquires(..) attribute after the declaration, so that the
compiler can see the cancellation function argument, as well as making
struct debugfs_cancellation a real context lock to benefit from Clang's
context analysis.

This change is a preparatory change to allow enabling context analysis
in subsystems that include the above header.

Signed-off-by: Marco Elver <elver@google.com>
---
v5:
* Rename "context guard" -> "context lock".

v4:
* Rename capability -> context analysis.
---
 include/linux/debugfs.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/include/linux/debugfs.h b/include/linux/debugfs.h
index 7cecda29447e..4177c4738282 100644
--- a/include/linux/debugfs.h
+++ b/include/linux/debugfs.h
@@ -239,18 +239,16 @@ ssize_t debugfs_read_file_str(struct file *file, char __user *user_buf,
  * @cancel: callback to call
  * @cancel_data: extra data for the callback to call
  */
-struct debugfs_cancellation {
+context_lock_struct(debugfs_cancellation) {
 	struct list_head list;
 	void (*cancel)(struct dentry *, void *);
 	void *cancel_data;
 };
 
-void __acquires(cancellation)
-debugfs_enter_cancellation(struct file *file,
-			   struct debugfs_cancellation *cancellation);
-void __releases(cancellation)
-debugfs_leave_cancellation(struct file *file,
-			   struct debugfs_cancellation *cancellation);
+void debugfs_enter_cancellation(struct file *file,
+				struct debugfs_cancellation *cancellation) __acquires(cancellation);
+void debugfs_leave_cancellation(struct file *file,
+				struct debugfs_cancellation *cancellation) __releases(cancellation);
 
 #else
 
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-22-elver%40google.com.
