Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR5DWDDAMGQEMOMH24Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 04591B84F93
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:01 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3ebc706ef7fsf268517f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204360; cv=pass;
        d=google.com; s=arc-20240605;
        b=VgBIPKwqgwCT01sfPjpZSDvXA8lsg3peFNVc10Epw8pU0DQKUp3igII7u9U9FczH9s
         T+t4lj5nEpwmeZGCNjHOqi/xlwlRoT6vHXwwjPthpK2CRU4ZPLP2eMm7K6X2YubWItzy
         swDqeGDShGsOZN+0Vo4DCtPKv99emGGzW5kJKf605anmJxWFVsS0PF0gZVq6A8c7Q0UY
         y6VJDzp4pxyRrT2ZmIk+nhLxvswsmtLYVoYDD9cqPOh8Ix/JR5p2BOI/UoP/RAJnznFi
         nuu1iXeHbo6/svQ9S4oKEbgMyjxSpUzK8llNtM06Speqq8wgslmaJpIrDUh1ZL4Z82Wo
         wu7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=/CHf51WJmuSnBbUNO7sbt6oPCGZTXO8y/euysQN6cEc=;
        fh=3mXge0KmNUF3i+RgsJKcYI/w0VNWHzxPADYNtpeYj2c=;
        b=XsQHvCHokYQboPSkesf90YpmaChPlrS5LPfT7tej9QvkHJvUNzqFkR5x0LvQoVNoL3
         Qt5nKuVwzPvnpAZr5KNtZUnIO4a32j6Iynvh07pSpYWtE3GGnsi7n29c6pLanfBzjRR3
         QdudLSCMuuNMcbr38L1kEvOOq/u8p1wEg7WNMXRj8gCsAvGRBOm6x8bzAzSU5Du2iu4a
         vFEy/QHclxcaZN6I4Xcw+bBjMyFNDxMrI36e5FWnKEaFOeqChbZgjXM86qGfomaJOnxd
         bP6sjtrkigdxtsQO9tsJWthOM0okXwX4swNp/5wsumCV3u11HXpu+x6632za5iiT2SiW
         3U8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Sq1z1Ah/";
       spf=pass (google.com: domain of 3xbhmaaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xBHMaAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204360; x=1758809160; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/CHf51WJmuSnBbUNO7sbt6oPCGZTXO8y/euysQN6cEc=;
        b=ASecxqXJ0kCmpAQP96VXOs09QU/WRCBP4Svli1QlOc0zlkvbYhkmYJnzCfXhUM3MXM
         1+hiRbeUPdgDF1ZokWfSkBRNtuMPdMlbK5cGSiCsZWReCURq84sDRZ5kxa4++mY4bF5Z
         0HJAGVkV85uQy2y41L4HZMFJZkeLUyGCFF5AnqS88UnwH7oDiWnuCYMB/SZCcvZGh7k3
         WtSqj+sKAWHz1n2LcUvhn9pN6Ov7noj9gYcyr7SzXAzHHRJVwOKmXLQrsHlQC2yTCYmR
         cQqPyg6e2E+w52IrEALIsi/OO5wg/HS89RmT99pXDgkPaPftVVOjVge3m7cp2aHVZ740
         gHWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204360; x=1758809160;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/CHf51WJmuSnBbUNO7sbt6oPCGZTXO8y/euysQN6cEc=;
        b=R2mELE84kZ4TjUd/hkxA/8VuGqGVWx1Fa3+0tpzYxWF3NlisBv5nXEulQSRU4o8/Rp
         63aEvNIIhCi76QR1SHdVay7qNRNuRvQ4kIC34f1UK8jzABwfZyC5znbTyQKBaTaYZWHI
         zg9Fs6cWa2we/2FLhk6CPyq61Kk7/N2ao5txn+bT+yFhC+1IuLXCQNLTMyA/9GM1cmp1
         6/1DD64NaX1XmDLwVzOeNsVA5QviIFTtHiYVZovA8g9pcs0DZYq/aelIZLwSyfYVoilG
         Mr8hAv1iAlT8XrrGy+dNWQHYMSV1Cjz0kR43/u1Yu8tz0/NmtWkYaI3OPso9Khjq+RHy
         jamA==
X-Forwarded-Encrypted: i=2; AJvYcCUFhQYDxgPWISTKttE6d1MEFrSsI0lkiTW/ydXyisi1gscYpSfg3SHnYLZbYkKEZumYtVweKw==@lfdr.de
X-Gm-Message-State: AOJu0YxWb1R4ryoLNbL/DghE9awt8T5fFcrNUYd9ArgHGOmXahUsuXe0
	zM+KMk9I4P2Zhy2ugKhuAKIPbagenPXvyc7kvRgmcfEflQKX9GN3DKrm
X-Google-Smtp-Source: AGHT+IFVGL/8pQ65xAfUHFtLsYHBkw6j48Y6l2Khi1kQPx7HznIYsBuY9M/usFKtiM/klmqLZ7cAww==
X-Received: by 2002:a05:6000:400a:b0:3e0:152a:87b2 with SMTP id ffacd0b85a97d-3ecdf9af8c6mr6348838f8f.13.1758204360360;
        Thu, 18 Sep 2025 07:06:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7kIYShUK3WwvdAJxmskg15OegQggXiz0iV/Mdgoh29cQ==
Received: by 2002:a05:6000:1aca:b0:3e1:d1b0:66c9 with SMTP id
 ffacd0b85a97d-3ee106b0ccbls579147f8f.1.-pod-prod-09-eu; Thu, 18 Sep 2025
 07:05:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXadPIgnT6TqKWKF7jqMB3dZelKc1bDChffn7eHS8lJ+SLDSYdyX0I9aly4g4Qme2FKJvS9eCeapVY=@googlegroups.com
X-Received: by 2002:a05:6000:1842:b0:3ec:3cac:7dfd with SMTP id ffacd0b85a97d-3ecdf9caeb5mr6204872f8f.26.1758204357499;
        Thu, 18 Sep 2025 07:05:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204357; cv=none;
        d=google.com; s=arc-20240605;
        b=Enc4m73YIPBU5rnmNa20qIiB2BZORmySiPHUuUnNUIV7ZJIE3BhUFsXx14aNTZi1Hj
         9Qdokyh5pRb7AxikZvhaGsZ6EroiEOkEoic1g+97Uwjk1nype0c3NUKvq/XxbEHBPVaM
         hKfzUsChEF7HEdDFzeLV3+dstqb0sdxm7x+OVDuWvj/SYEtlFxaS0ba13/HuYWyahtMi
         3AKpfv4U29Kb4EEqVWKeXkDXkBeu5cjx86DmIRYdk3iu1RdYeVG0jcsEdm9QoGrHmMkr
         AMzH9PvgHsx7duzhBMZUG3uppcIN92JJGM5IMttXAgV7V+odoF83V4rnYRN46S1Ox3AL
         zghA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=O/41QdXex1hw7P5cbsCaPm8UfRqOpbfD5EoaOmOtrFc=;
        fh=euprQqPbSNYcYQxD0S9aOZcCIcp/cn+k1JunrSqULSY=;
        b=JWgdFk7rDTVe/2OEhsVMWzdZ1OL++WqVrZC3gC1qE5qasZhxoVvmTuO3OZbbSs4nJ6
         f72RA6tjCLFJjdUbbccEfHFqggztiKM7gg9jw7QMDOI5/mPNj+NfDNGz1qMq2SZ/LK8R
         o5BjqLAk1kowbTj8ow2Ad0BRhDMKZ4HVO+vcxn80hgSX6vNcyiZEeBivgGdV8YTLTqim
         pbcBTX/tDv5y8jZocngfVSULUMl9z+w5rA5E8/lJf05IJXxITSRefYsPJQp3GzebNJCj
         pUCl0HTYBJlDs9uwK8Nuphfegx2xGRDbUUz58qFNrb5XptzEZ0/496o24dKq9PfzCX25
         FuQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Sq1z1Ah/";
       spf=pass (google.com: domain of 3xbhmaaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xBHMaAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3edff885cf2si50013f8f.0.2025.09.18.07.05.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:05:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xbhmaaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45de27bf706so5593565e9.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:05:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVR1eSl2Di+9Yt+8T9E44GCq4hLgAt/ieymD8QlAhgpcwVLmDG14Ia+2NWMd2e9Af+ZaooADWE9Vgk=@googlegroups.com
X-Received: from wmlv10.prod.google.com ([2002:a05:600c:214a:b0:45b:9c60:76bb])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:3227:b0:45d:f7e4:7a9e
 with SMTP id 5b1f17b1804b1-466ce515027mr10992405e9.5.1758204356910; Thu, 18
 Sep 2025 07:05:56 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:22 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-12-elver@google.com>
Subject: [PATCH v3 11/35] locking/seqlock: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b="Sq1z1Ah/";       spf=pass
 (google.com: domain of 3xbhmaaukcwuhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3xBHMaAUKCWUHOYHUJRRJOH.FRPNDVDQ-GHYJRRJOHJURXSV.FRP@flex--elver.bounces.google.com;
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

Add support for Clang's capability analysis for seqlock_t.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* __assert -> __assume rename
---
 .../dev-tools/capability-analysis.rst         |  2 +-
 include/linux/seqlock.h                       | 24 +++++++++++
 include/linux/seqlock_types.h                 |  5 ++-
 lib/test_capability-analysis.c                | 43 +++++++++++++++++++
 4 files changed, 71 insertions(+), 3 deletions(-)

diff --git a/Documentation/dev-tools/capability-analysis.rst b/Documentation/dev-tools/capability-analysis.rst
index 89f9c991f7cf..4789de7b019a 100644
--- a/Documentation/dev-tools/capability-analysis.rst
+++ b/Documentation/dev-tools/capability-analysis.rst
@@ -81,7 +81,7 @@ Supported Kernel Primitives
 ~~~~~~~~~~~~~~~~~~~~~~~~~~~
 
 Currently the following synchronization primitives are supported:
-`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`.
+`raw_spinlock_t`, `spinlock_t`, `rwlock_t`, `mutex`, `seqlock_t`.
 
 For capabilities with an initialization function (e.g., `spin_lock_init()`),
 calling this function on the capability instance before initializing any
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 5ce48eab7a2a..2c7a02b727de 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -816,6 +816,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
 	do {								\
 		spin_lock_init(&(sl)->lock);				\
 		seqcount_spinlock_init(&(sl)->seqcount, &(sl)->lock);	\
+		__assume_cap(sl);					\
 	} while (0)
 
 /**
@@ -832,6 +833,7 @@ static __always_inline void write_seqcount_latch_end(seqcount_latch_t *s)
  * Return: count, to be passed to read_seqretry()
  */
 static inline unsigned read_seqbegin(const seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	return read_seqcount_begin(&sl->seqcount);
 }
@@ -848,6 +850,7 @@ static inline unsigned read_seqbegin(const seqlock_t *sl)
  * Return: true if a read section retry is required, else false
  */
 static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
+	__releases_shared(sl) __no_capability_analysis
 {
 	return read_seqcount_retry(&sl->seqcount, start);
 }
@@ -872,6 +875,7 @@ static inline unsigned read_seqretry(const seqlock_t *sl, unsigned start)
  * _irqsave or _bh variants of this function instead.
  */
 static inline void write_seqlock(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -885,6 +889,7 @@ static inline void write_seqlock(seqlock_t *sl)
  * critical section of given seqlock_t.
  */
 static inline void write_sequnlock(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock(&sl->lock);
@@ -898,6 +903,7 @@ static inline void write_sequnlock(seqlock_t *sl)
  * other write side sections, can be invoked from softirq contexts.
  */
 static inline void write_seqlock_bh(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock_bh(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -912,6 +918,7 @@ static inline void write_seqlock_bh(seqlock_t *sl)
  * write_seqlock_bh().
  */
 static inline void write_sequnlock_bh(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_bh(&sl->lock);
@@ -925,6 +932,7 @@ static inline void write_sequnlock_bh(seqlock_t *sl)
  * other write sections, can be invoked from hardirq contexts.
  */
 static inline void write_seqlock_irq(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	spin_lock_irq(&sl->lock);
 	do_write_seqcount_begin(&sl->seqcount.seqcount);
@@ -938,12 +946,14 @@ static inline void write_seqlock_irq(seqlock_t *sl)
  * seqlock_t write side section opened with write_seqlock_irq().
  */
 static inline void write_sequnlock_irq(seqlock_t *sl)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
+	__acquires(sl) __no_capability_analysis
 {
 	unsigned long flags;
 
@@ -976,6 +986,7 @@ static inline unsigned long __write_seqlock_irqsave(seqlock_t *sl)
  */
 static inline void
 write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases(sl) __no_capability_analysis
 {
 	do_write_seqcount_end(&sl->seqcount.seqcount);
 	spin_unlock_irqrestore(&sl->lock, flags);
@@ -998,6 +1009,7 @@ write_sequnlock_irqrestore(seqlock_t *sl, unsigned long flags)
  * The opened read section must be closed with read_sequnlock_excl().
  */
 static inline void read_seqlock_excl(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock(&sl->lock);
 }
@@ -1007,6 +1019,7 @@ static inline void read_seqlock_excl(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock(&sl->lock);
 }
@@ -1021,6 +1034,7 @@ static inline void read_sequnlock_excl(seqlock_t *sl)
  * from softirq contexts.
  */
 static inline void read_seqlock_excl_bh(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock_bh(&sl->lock);
 }
@@ -1031,6 +1045,7 @@ static inline void read_seqlock_excl_bh(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_bh(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_bh(&sl->lock);
 }
@@ -1045,6 +1060,7 @@ static inline void read_sequnlock_excl_bh(seqlock_t *sl)
  * hardirq context.
  */
 static inline void read_seqlock_excl_irq(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	spin_lock_irq(&sl->lock);
 }
@@ -1055,11 +1071,13 @@ static inline void read_seqlock_excl_irq(seqlock_t *sl)
  * @sl: Pointer to seqlock_t
  */
 static inline void read_sequnlock_excl_irq(seqlock_t *sl)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_irq(&sl->lock);
 }
 
 static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
+	__acquires_shared(sl) __no_capability_analysis
 {
 	unsigned long flags;
 
@@ -1089,6 +1107,7 @@ static inline unsigned long __read_seqlock_excl_irqsave(seqlock_t *sl)
  */
 static inline void
 read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
+	__releases_shared(sl) __no_capability_analysis
 {
 	spin_unlock_irqrestore(&sl->lock, flags);
 }
@@ -1125,6 +1144,7 @@ read_sequnlock_excl_irqrestore(seqlock_t *sl, unsigned long flags)
  * parameter of the next read_seqbegin_or_lock() iteration.
  */
 static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_capability_analysis
 {
 	if (!(*seq & 1))	/* Even */
 		*seq = read_seqbegin(lock);
@@ -1140,6 +1160,7 @@ static inline void read_seqbegin_or_lock(seqlock_t *lock, int *seq)
  * Return: true if a read section retry is required, false otherwise
  */
 static inline int need_seqretry(seqlock_t *lock, int seq)
+	__releases_shared(lock) __no_capability_analysis
 {
 	return !(seq & 1) && read_seqretry(lock, seq);
 }
@@ -1153,6 +1174,7 @@ static inline int need_seqretry(seqlock_t *lock, int seq)
  * with read_seqbegin_or_lock() and validated by need_seqretry().
  */
 static inline void done_seqretry(seqlock_t *lock, int seq)
+	__no_capability_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl(lock);
@@ -1180,6 +1202,7 @@ static inline void done_seqretry(seqlock_t *lock, int seq)
  */
 static inline unsigned long
 read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
+	__acquires_shared(lock) __no_capability_analysis
 {
 	unsigned long flags = 0;
 
@@ -1205,6 +1228,7 @@ read_seqbegin_or_lock_irqsave(seqlock_t *lock, int *seq)
  */
 static inline void
 done_seqretry_irqrestore(seqlock_t *lock, int seq, unsigned long flags)
+	__no_capability_analysis
 {
 	if (seq & 1)
 		read_sequnlock_excl_irqrestore(lock, flags);
diff --git a/include/linux/seqlock_types.h b/include/linux/seqlock_types.h
index dfdf43e3fa3d..9775d6f1a234 100644
--- a/include/linux/seqlock_types.h
+++ b/include/linux/seqlock_types.h
@@ -81,13 +81,14 @@ SEQCOUNT_LOCKNAME(mutex,        struct mutex,    true,     mutex)
  *    - Comments on top of seqcount_t
  *    - Documentation/locking/seqlock.rst
  */
-typedef struct {
+struct_with_capability(seqlock) {
 	/*
 	 * Make sure that readers don't starve writers on PREEMPT_RT: use
 	 * seqcount_spinlock_t instead of seqcount_t. Check __SEQ_LOCK().
 	 */
 	seqcount_spinlock_t seqcount;
 	spinlock_t lock;
-} seqlock_t;
+};
+typedef struct seqlock seqlock_t;
 
 #endif /* __LINUX_SEQLOCK_TYPES_H */
diff --git a/lib/test_capability-analysis.c b/lib/test_capability-analysis.c
index 286723b47328..74d287740bb8 100644
--- a/lib/test_capability-analysis.c
+++ b/lib/test_capability-analysis.c
@@ -6,6 +6,7 @@
 
 #include <linux/build_bug.h>
 #include <linux/mutex.h>
+#include <linux/seqlock.h>
 #include <linux/spinlock.h>
 
 /*
@@ -208,3 +209,45 @@ static void __used test_mutex_cond_guard(struct test_mutex_data *d)
 		d->counter++;
 	}
 }
+
+struct test_seqlock_data {
+	seqlock_t sl;
+	int counter __guarded_by(&sl);
+};
+
+static void __used test_seqlock_init(struct test_seqlock_data *d)
+{
+	seqlock_init(&d->sl);
+	d->counter = 0;
+}
+
+static void __used test_seqlock_reader(struct test_seqlock_data *d)
+{
+	unsigned int seq;
+
+	do {
+		seq = read_seqbegin(&d->sl);
+		(void)d->counter;
+	} while (read_seqretry(&d->sl, seq));
+}
+
+static void __used test_seqlock_writer(struct test_seqlock_data *d)
+{
+	unsigned long flags;
+
+	write_seqlock(&d->sl);
+	d->counter++;
+	write_sequnlock(&d->sl);
+
+	write_seqlock_irq(&d->sl);
+	d->counter++;
+	write_sequnlock_irq(&d->sl);
+
+	write_seqlock_bh(&d->sl);
+	d->counter++;
+	write_sequnlock_bh(&d->sl);
+
+	write_seqlock_irqsave(&d->sl, flags);
+	d->counter++;
+	write_sequnlock_irqrestore(&d->sl, flags);
+}
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-12-elver%40google.com.
