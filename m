Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMEOTO7AMGQE2GBERTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 3837EA4D813
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:10 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-390ee05e2cesf2499477f8f.3
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080370; cv=pass;
        d=google.com; s=arc-20240605;
        b=bCS9k3xYLdHdDLK4ydFALWDTV2pFIoLA0b7tDCks4y9vkkoh9+G9JlA6LETd+Ydqix
         DV62a7bfAlFW/eb1xyFHnNXF4Wqgu+EIDHzB3jBhmunCJV9wCXaGCZXApRqEphJTFpeE
         epTHPFGUt1go1lA2IcU+shgRTS6f0ht6jQLd/J8W4ySWWyCR2gDY/oqOheBV5ERPG93k
         UefTUDA4fC0T+7GOzKaP9tRGOUyY8W1W3DIP4oFR7V7i5NyYqmUa5Zk9jh9EbkpTIti9
         kL+BETE9UQdqj/+piisG/g/ELBFR+qE9H/7vrzUkfRhuhnHQh9FzjNGxTquhjpD+0Q6T
         Bclw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=zjw1Xzs530ZsxWV/aCKzEClgkqtq1O5kt10crWWMaUg=;
        fh=GXQ/7gVyK4FxKyb2q9isnPLB7FsY86J+8g6EMrRGuds=;
        b=UJgvqTHRFTdbNlkZKYLY8nkN94VKtJYaTnVk3mBtWyjpeOguhzXINTZYpK8XuadDiy
         aMy1y9nEYk0SfosGnFEid43QP9ayO1xqUWSbQ1muh2SaFKCuEePSTEDlaCdaVwE/iMSj
         1puxCjbSBg2RtMCQmUzwm5IIPeUm1bg7ESMd65mq2kZ7q+9/ufRaTePEWQAYvFSRQ2Pw
         G/jpp6LViHKac+0HOiHzWxHTNsGCEH89KU8s1bqphf5e066ByMU3fZBkn9080HbO7hGZ
         mWuE3WjlAOUQiFGfrTl3tpo88eY9LN+CWeA7uyqPzcoC8YliKHKF64zs6C2pBuBZPxfr
         oedA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JUscbCWc;
       spf=pass (google.com: domain of 3lsfgzwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3LsfGZwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080370; x=1741685170; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zjw1Xzs530ZsxWV/aCKzEClgkqtq1O5kt10crWWMaUg=;
        b=DTkxFXSjYDncNNmjNu0wX2BjvAmFkrx2FcMHYIwliYGMbjzYMdwUjL2TcKO6TgE0j/
         f9JL/5r06bfiHH1CaTdyy6mKuMhxNgkLn+1FCY/WR8eS8cku3WE3PMnwFVgZDNYpFwil
         fOJ7lI/O+PDt3qwAJGzhHcjs+f0DJY/8TpMs3PmS/eB1X106FT25yHSMJf6Wh6GScwDg
         O17wiCej1V21QVnRcsZRaFTRuBqD1zSuZo94llpbBSlbQomLMcZM5ikbkGvppwncP7xM
         ol95uhLLLG2GWwlpdSvKnLhywfsCn11JEte6xCuWdFxcuEW0fqKyXr2cXF9BuK9y4N/f
         qs1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080370; x=1741685170;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zjw1Xzs530ZsxWV/aCKzEClgkqtq1O5kt10crWWMaUg=;
        b=CzZrZHYo6Puh5GLb4n8P8ssEqv+nj9nCaSfY4zaGrcQnOIS5M6VLsxbu0zpwnPJXsr
         O29YWfwCltxk26vDvuPqiVbEHMUwswXudHOO6LyTxbLYCIuE++mAhFadTyBZOQkdyA45
         J1ZE2b7vZBfuJ9BdwQQVU0gBStjBnXLePf6cCtBRaTK4N6MqFpQhHFewYYiuMSTkQFEO
         HdrNnV89M4C1ksh69EvHKtTQggBVBNVSibRw5OBIESf2RDkJUWKDPEfKlL11Qnlj+OrO
         gPE27kdw/tPqipONI5oLPulWbRzMvPtA1MUlffbKvX2S44SAPGsOWWZDH/u4DwkOSXJQ
         EHrQ==
X-Forwarded-Encrypted: i=2; AJvYcCUBArK0kVg8d1zTu8JmDWJN4suCqzaYX0CxfiEjeGnmtffjhqRoPp+ofrdihJeOHTgSAaaPtA==@lfdr.de
X-Gm-Message-State: AOJu0YwClsFa5hgZH6p1oF+g7ohctXtdb99Kki5rPW5onCQWIL5Yv2jN
	ETH9e542tV+cQ49a+sIaiDcEUSOHxt2Ixl9ZQnGccIS8VwF0Tp7X
X-Google-Smtp-Source: AGHT+IF9Gjt4MpNm+5BFbu9heMo/BIvvRCgkrAn+68He19xHv0NwIQUA9EzceVE9H4qV1EoOhvyX5A==
X-Received: by 2002:a05:6000:402a:b0:38f:2efb:b829 with SMTP id ffacd0b85a97d-390eca815a6mr13495434f8f.50.1741080368956;
        Tue, 04 Mar 2025 01:26:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEW7uqvg+cO50WIGs7ym1D+HUDgUinoI5zAVK7JCImCvQ==
Received: by 2002:a05:600c:468c:b0:439:8202:ee83 with SMTP id
 5b1f17b1804b1-43af792f5c5ls979105e9.1.-pod-prod-09-eu; Tue, 04 Mar 2025
 01:26:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWkw4H/UCQrJ8lI0XNbuPJpKczpFKO96iXVoPunkYAb/sma2koVlMquKfHpfEap9952Kc1XrGIdV7c=@googlegroups.com
X-Received: by 2002:a5d:59ae:0:b0:391:10f9:f3a1 with SMTP id ffacd0b85a97d-39110f9f4ffmr5843535f8f.35.1741080366639;
        Tue, 04 Mar 2025 01:26:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080366; cv=none;
        d=google.com; s=arc-20240605;
        b=IpvySDFg7DFlhpT+RdCPsbuAZMOH1RknH3RTd+no9rKJ/I3CHx0gHZBL7DfBIjxgIj
         dG6b3N7mUXjz4CPGKdg68OlipD5UuxheP+1KW6MVRJLNl5UuscXk18ZXdBxIITNI42X5
         iSemOAz8CrqGB1CY0r4pqqaGM9cByJ0OwFIE0n+JQkZR9W1ftNcCQJXSqPAzDifOwnQv
         8zSbRm2m9Q9LSGrmZk/KDndzc13toW2SAKbNBXXhIf09i3KRFwbJaoXmiRVKlnfK2Axo
         5DlgP1v/nFq+0v5IRDan05q4KWsTdYb00d14a749F5nPEmA5nwuAci7TkzGX2AIm0VMo
         hmRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ljSfvhYh8x6xwHsInA1Gu+wF89bLF/D0O2qs3l3oGhs=;
        fh=0SJyz29rjmHQFM5ER6/BIyqdcdyNt4GB2CWDqiGfzbM=;
        b=MsszgNuU1A/zExL17eVG151xDgyvzIZqbVr1FCitlZKdH4ML5zboNdWrIEW0ljHUFj
         1nog4YdHt261etWpf8jR7/cPDmxV4Y0aBWNdSBfErKSyxYD71g+L6jsHvikrealugttO
         GNcZUgY7edPMA30LIqjnTFvWn/bUBqL4/b25v0wKd/7/tko8vbjoN72AgTigelfgTInQ
         WY0aRl3iz6x2SVlMzpt6FRyDxzmmRITr/NsZUDII2bMy88mtbc1hAyjZ1MPXO+auXaOg
         YOJ5i5sIrl+3MUGv9C8HVASqgXIizH+ebwet+TBJ6lew9X0SRvPiNQVpbHxPciXRjtwB
         wnGQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JUscbCWc;
       spf=pass (google.com: domain of 3lsfgzwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3LsfGZwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-390e47ff679si387024f8f.5.2025.03.04.01.26.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lsfgzwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5e54335bf7fso2867076a12.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXA8PWXIIyPz9QR6CPI+kTvwgHMn+zzQuH48wmsXOhRG2mZEDtsBBFF9Hc5WMJ23mcrwXfB1WM6yFo=@googlegroups.com
X-Received: from edbij24.prod.google.com ([2002:a05:6402:1598:b0:5de:504d:836a])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:234e:b0:5dc:80ba:dda1
 with SMTP id 4fb4d7f45d1cf-5e4d6ad7afcmr43438170a12.9.1741080366105; Tue, 04
 Mar 2025 01:26:06 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:20 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-22-elver@google.com>
Subject: [PATCH v2 21/34] debugfs: Make debugfs_cancellation a capability struct
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
 header.i=@google.com header.s=20230601 header.b=JUscbCWc;       spf=pass
 (google.com: domain of 3lsfgzwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3LsfGZwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

When compiling include/linux/debugfs.h with CAPABILITY_ANALYSIS enabled,
we can see this error:

./include/linux/debugfs.h:239:17: error: use of undeclared identifier 'cancellation'
  239 | void __acquires(cancellation)

Move the __acquires(..) attribute after the declaration, so that the
compiler can see the cancellation function argument, as well as making
struct debugfs_cancellation a real capability to benefit from Clang's
capability analysis.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/debugfs.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/include/linux/debugfs.h b/include/linux/debugfs.h
index fa2568b4380d..c6a429381887 100644
--- a/include/linux/debugfs.h
+++ b/include/linux/debugfs.h
@@ -240,18 +240,16 @@ ssize_t debugfs_read_file_str(struct file *file, char __user *user_buf,
  * @cancel: callback to call
  * @cancel_data: extra data for the callback to call
  */
-struct debugfs_cancellation {
+struct_with_capability(debugfs_cancellation) {
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
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-22-elver%40google.com.
