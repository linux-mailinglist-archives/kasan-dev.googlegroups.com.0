Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY5DWDDAMGQEN64GB2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id E776AB84FD2
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:28 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-363d8068599sf362611fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204388; cv=pass;
        d=google.com; s=arc-20240605;
        b=DzAasMDx50DAZifjsuPScav4YsGqsH7/lAVVQ5tHs7sfvWFkhZ6Pae+e7kvvjtt/Ov
         4jYVgg6XdZoNgmQxtDhte+/0s4ZAl0aAER+i6Jrnvu132d6zb787tvMbqc7/YexgZsCa
         zg7DfGYE2wRe8OJSHSJefS8PbBHmJYtCSnjvKWxKz+zNIzYNTesljrHyQV6YOnfeuo38
         6yELULCb4yxYWDqHImz0n6qfp3M9ztCFHX3XC1gMdK3v3NGTn7YDBtak7Gq5+7KXGCrr
         dI1ABkzMQkG08T+dyYJdP7eNLK2m1i5JhoiYfOWinRr+ADfgGblHbaKcY51FBUDWLqh1
         bMyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=OdygegiCGtIfVPPvwtyJUUPwEDThQFWBNNHrJDJ+Iv4=;
        fh=RVjIdHTsK/+XL+fVr5QoO/BJobiwioRn63JxokI7BGU=;
        b=X9ObJWYAez3g4xYoUoRUdhmSFpn3g/Vlhisumcg0zTTTF+vgU6+D3rsATJJcCJnqgD
         yIGZbQwM7BxqeIpm/bJjHSlraYNvxZJyUf8nS5QBXQ60MwogmBc5AlIwT8OgLhcrkjAJ
         zaE49dIc7kYuuHBNAhF5JzLtQ44GGPbzi5yfukoLG3caasWw996gTGkirkKxLQI7MIns
         9lh/Zld8EZ4bzIJyNa8PHXPP+eUm91pk1ezMcqc9mNxCyfqg8Fz6LR1vrJ470xk+DgZh
         JBvxEEbqFexexUGhQtYSXRvpZsNLPaN6Oeqt4ZmF9Gt2FMZyo0RiGZNRLEKmgTp/Ahvi
         7VYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ge0kL8pj;
       spf=pass (google.com: domain of 33xhmaaukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33xHMaAUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204388; x=1758809188; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=OdygegiCGtIfVPPvwtyJUUPwEDThQFWBNNHrJDJ+Iv4=;
        b=tWCbj4XEHbWt+32aLo7qpgPtXacwFpO2mePfjDg4XfF+q1V40ZmtOokBLNwz1h5ITD
         k+F8+q/N3NtVn8kbdbW0MRyRXsOA6xanNmrGYh+P6LGuBEEowYrl7efWjTBOsdSlFXrl
         2ws5Vf1fYmQy/Sy053Io3QizxAB/KZJzHCLJyhuKIz84D5s4eTNwZjqxQ9PQLY1uyRkF
         aW3p68RMz+FMRHOCQUmlw+0vkN5gfxGTsCdvnG1OqTKTv1/vkFN/vTbofZkjWoau1UMr
         BPiRMi5/saEQyHssCGS5A9kBFQG9ppsIvY5qTyO1u3woIY/iwQi2/k60CvNgUC0CktBg
         sJGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204388; x=1758809188;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OdygegiCGtIfVPPvwtyJUUPwEDThQFWBNNHrJDJ+Iv4=;
        b=pt1GwZRYmfZwvjF5HlJ+5KFFHrmhFfqP9QnP6+yHaZDfljs0x07aiqDrqaCXk7ABVe
         TOCU/31dXNxqaQznrNMVSjsVU+H1g4z/nCPBHNIylH0NAtecC2WoZjSHa7ceRcwbjABt
         ygBySUTfJVpL6c7P1gKs29JWA4EV1c6eaq/2gu/rigrLwzlmqHialIlUYeELCZjUFDHN
         rg5uPpF59OMGDQhQB1s/A/1DKzIPtNUFU3+c9uSCXlAiM7E17SmtvtfIHoAdxxlfNp6k
         up1QUuCjPg4xjUFmEbL1otQRZ7x+uCIkNMUd4ooGxD1ajvpAQ6moWbk2evRwQGlJbv99
         yowA==
X-Forwarded-Encrypted: i=2; AJvYcCW6BNsKItp88x6aW2SCGxTFzR2gfDZPMHu8jIx1wzvuLNldDbvbnuMC7ZctS2zkKcgAjSBT0Q==@lfdr.de
X-Gm-Message-State: AOJu0YznPMWHq6oybNkxR5z7HzCXu48e/byODRhkHkObJGrKyfCW7sc5
	6RWGyncVYJjmz9BfMxT+eZLQsYNEen+2PTJwYcfLgTihJTEJaZsDpzev
X-Google-Smtp-Source: AGHT+IGwlyNcvlgumcqfAD46FoKfZ8yV4TYgdulB6fcqDIVhWjHA5ubZevZoeZKLSVgOlEVOklRC3w==
X-Received: by 2002:a05:651c:2129:b0:336:ba05:b07f with SMTP id 38308e7fff4ca-35f63f7b5famr15969041fa.21.1758204387901;
        Thu, 18 Sep 2025 07:06:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd64aX3xEPiA6SEtwMAQkjktyQT699drXhD+zJdzhghnoQ==
Received: by 2002:a05:651c:25d8:10b0:336:ab71:15ca with SMTP id
 38308e7fff4ca-361c70c536fls2917141fa.1.-pod-prod-09-eu; Thu, 18 Sep 2025
 07:06:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW2h8g+YGn6y+eOvAaMG9La9DIUe3e1KIEffUxPd7cKqcxpxLXyynMCLEGVTE2fN7FmSiSODqswltA=@googlegroups.com
X-Received: by 2002:a05:651c:23c4:20b0:362:fba9:d17d with SMTP id 38308e7fff4ca-362fba9d574mr4238151fa.23.1758204384782;
        Thu, 18 Sep 2025 07:06:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204384; cv=none;
        d=google.com; s=arc-20240605;
        b=h+Iy7Xu5jOT14v5oEZfhzo6EI7gYUUR+XaU+Y9O05RLoRDPWiAA0d89Wy50lmCP53e
         8OYGqDJXdHQWXO3ic5JCS7jEGChjOq2BF5VLupa2xhx8okZ+53Oby9Jtli1ephm1y9Hw
         Ex8hWs9mEFI5Dft0EtAIIarQuH6m2JkkHVDE71VVBimj87X2dD1uT7qXzHjU8aVhpqPr
         pgKErIwy+QkXW/krbTufpqTB+nvtINo50YwFQFr+bfy7IpT2Fp1M/sUCgDpL1b16YU+1
         x2kU9Ul9TWhLKPfMzHT27p86Mh9tujIpc66VGta0wtEENdDptR4aRjTeu7aziFmOrybN
         GyEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Oanwb4AvefPzztLhk08gBpEPn5bxbhzZnwvICntunHw=;
        fh=iV+cvH5MgvMdoOKvig5PegQ7Q6dH1bFtBXpUqJduiLE=;
        b=Pktt+NVL6xjCm9w5ghTNzhk6CuwAN3MlFQtGIKTLIFNrqomQzYcPCYselwgNgKAQyu
         cKROCgv56vmWIdSP5RxWC17kWooghykIcFbsn70865xrM0h46jK8o+UCdeXSeXowxC0L
         vzw/yBI48ZzXPwUk8lkFtxFG8njFTkwAq7pM3dIfSBioNxjS3w2uQiVeVpornER12KRZ
         14Clsw9Sr4raVaCgHOkUed8CCXjNG4M8A8K5KTXl99m8GylY+FeE1zvmTUc5wgryhWeC
         65fmAYX5/QN2vf0+Ixy1F2eVFerBrV5zidlxyd2s8uVSW2nFNIbklkLOTYuii43KzqrE
         GjgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Ge0kL8pj;
       spf=pass (google.com: domain of 33xhmaaukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33xHMaAUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-361a2c9b26fsi438811fa.1.2025.09.18.07.06.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 33xhmaaukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-3ece14b9231so561592f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWl02WYYqli4Irhy63U7J1W/M2fjgRFslV0GsCOeeY/19z01lKBT5HQfWrVO4lP1o9vgveuOZWZgIQ=@googlegroups.com
X-Received: from wrbcc13.prod.google.com ([2002:a5d:5c0d:0:b0:3ec:df7a:666])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:438a:b0:3ec:db18:aa37
 with SMTP id ffacd0b85a97d-3ecdfa4b7camr5826204f8f.60.1758204383884; Thu, 18
 Sep 2025 07:06:23 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:32 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-22-elver@google.com>
Subject: [PATCH v3 21/35] debugfs: Make debugfs_cancellation a capability struct
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
 header.i=@google.com header.s=20230601 header.b=Ge0kL8pj;       spf=pass
 (google.com: domain of 33xhmaaukcyaipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=33xHMaAUKCYAipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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
index 7cecda29447e..4ee838cf4678 100644
--- a/include/linux/debugfs.h
+++ b/include/linux/debugfs.h
@@ -239,18 +239,16 @@ ssize_t debugfs_read_file_str(struct file *file, char __user *user_buf,
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-22-elver%40google.com.
