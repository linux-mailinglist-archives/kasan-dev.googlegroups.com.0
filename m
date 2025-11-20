Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC7A7TEAMGQEWHIXXZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 781E6C74C66
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:16 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-477a0ddd1d4sf11820285e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651596; cv=pass;
        d=google.com; s=arc-20240605;
        b=Whp26j99l15GYCRAU3kzrcxVlET9od0gYYl0UWyLfen98blrgj1yB4s8Y4y0nRJkUP
         maLZTJNMxPMjFyXBSUQVTcoqMLfqHXtrSJXpEWHLrnTE0k4neqBmgSRk/6Vw42JXtKce
         PWKAUDgC31fFcmuRqQGS10fvA9xVdBPNe3hsIZ6sSB4GqO9gLuY50MrHaQKk4jQBgKFT
         QCVGE/GHBEXpfx94zuQRhyV/QrY63L16b7RhHof6b8+96sSfYE8gtSRS8cG2a1gQPoso
         AQzN1NEhvmmItIVqc3lsLQXdHHmbRq5vYTQUNNrSJw1jx76Kba4scXpUqpCUqe0E/tcR
         fJzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+zsu9TiP5YGL6OmxPYOn4Dk+26I8N8pknmLV2MWXBL8=;
        fh=TwpadCcIFl1bf8GZyts6Q2vEiKteEwyylT6IE6dTBD8=;
        b=cFoRMMlxqNGDNhZzvQhzan+TVtoqNAa+BA+Nhk2nECpni/9EQ35TdG200TOjuWwVZN
         BlNcH0LOio1vPdtCrdhf8a58W+KlKEnL857rd+pw+lnr0e1+cu1U8KIGIoT5XsDEvfxa
         NHdJDDegL6qtfXPuP0DecL3TtPUhwMkxBPEOE1r0W0f7sAUf5dsXSVdpl/zBbFzOK2Yb
         lf8alvBMGu/2Rc+tvm/TKOrI8cZTYHZavrauT/Y1gZf3peoDsULTqD4WKRJTpQrefswJ
         tG9QhLKirXrG08E10ycQSMw2AT4q855hb1DCJns5oiQ6wf9z8J/d0lFnSCI7Zw+YD4fI
         gp0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K+1/w3F0";
       spf=pass (google.com: domain of 3cdafaqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CDAfaQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651596; x=1764256396; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+zsu9TiP5YGL6OmxPYOn4Dk+26I8N8pknmLV2MWXBL8=;
        b=tKguPzawAn3K1aw5RUHpaAMw22+PzwF+cLKihTstJBKW0/OTLO1PBkALJyM8WFJ1Pe
         te5KClI1PS/C2IBesLkPF64ayRZQLNGtBl9M7MToIeQjgKWFHXeNChd0nfOE68JW6H4O
         Ic7fLpc/HeD8Tjx1105XbpgO1INtd2cch2ow5UcGyUsqhY5RgoUZ/Jx5bNOAwCRDc8Js
         djviNPj8R8dFQqLurWDpvUx6Z7R9hyay/Rowpm2h4MWDaXpX5c/KYdxL8JlAIexKlthm
         YFX6+iiLUfc6OiaPVu2XnctSL93lJjz5xFj976DoIY6/bKMjkZYXp2eR4lS2NX8HVVvN
         Xb0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651596; x=1764256396;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+zsu9TiP5YGL6OmxPYOn4Dk+26I8N8pknmLV2MWXBL8=;
        b=lThPd12kzcPE8OV5wNbVksmgXogdE8lYrbRqp8r4d0oyXct4cMyFDdKmHCzLsPQR8U
         uReS3T1q1GWljTkduiUEkR4h8G+iHzCJV4GN5bDp9823kaNGPIsZq5HVjkf6i92ueo9m
         fcJTIoobQYYOhA3fKVX8bH9ZMzWAelJUl7dsY+FMEaU3vWQIvqyGrDBeZGOIgtTY87r1
         S4E7Uv8HhP4gyiOfNQrsLhjh5zfawjeHk6uC0jlhbL5t7lCTRDhI9x8P67wUS8L/GS1C
         dS0t7vMYq5e7V9/+p2/ieMU7D+AFkqBjy8VrklvvvyUjw01GIPW4Jj0KlNO3ze/zLkrB
         fStg==
X-Forwarded-Encrypted: i=2; AJvYcCWSpaAkZ6t95Gllkj/j1XwNyhQ6InUHjXaSr6H0zSB8Tw5lhdFY6WXo0N0KO9FsUT65l+VLjQ==@lfdr.de
X-Gm-Message-State: AOJu0YzH3+9rGyWdURIAivTd9eXjExkmnO1s56inct4KgEgSWIgsrqhM
	1QObfEMm7blLxwKW9YXukSkGBcVM27Htg4DXLMxbMG1+IdV8vc2YWhYv
X-Google-Smtp-Source: AGHT+IEEO090+cB9FZ8Z2D3OAdTBMB2XfgULN07q4HEsFIAT0OVgWWXMIkPiWj7+6jmzx3f6mSuDpw==
X-Received: by 2002:a05:600c:3146:b0:46e:4b79:551 with SMTP id 5b1f17b1804b1-477b8a9d74amr43021965e9.31.1763651595723;
        Thu, 20 Nov 2025 07:13:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+awGvMs4q35nNNk26t41UVEBIh4Xp1QMg/zCYjgS6B31w=="
Received: by 2002:a05:600c:1c26:b0:477:980b:bae9 with SMTP id
 5b1f17b1804b1-477b8aa37afls8049455e9.0.-pod-prod-05-eu; Thu, 20 Nov 2025
 07:13:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQB+wC5eLeBjnn8FuM5jVbXXFH7rjPo/DLxKPI4qazlxu5oAok9Pqp4WQ/1Kwju7AWGS5kXHjvFWQ=@googlegroups.com
X-Received: by 2002:a05:600c:4eca:b0:477:fcb:2267 with SMTP id 5b1f17b1804b1-477b8953f77mr37108715e9.8.1763651592847;
        Thu, 20 Nov 2025 07:13:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651592; cv=none;
        d=google.com; s=arc-20240605;
        b=iwTqSJV1vIKj1fTeNBHU5qjyQBbaYi74VZi0e+ZoiAYvkBS9xiIvbMCZu3zXGB/9Vy
         n8bZ1MUom2sGAVNuC/IMoc2G64GuCx+e3teGN2sscX6dv6iuM74I0pYzxaNNPuoG7fbt
         KlY8Bjntd7RnotHglrsIxtq1L5zVWtXn1AIQoqqnA9S7ahwslpL3Oo0Tq8zLwHwmTI6c
         Uj0joupfq6oravq3UC26cogYoGwSCQegZdb7DFlMVR4He89FMMy/8XLGDlOfRcO/3OSL
         8EN25XXwDBFTEhV9vh9awh4qRkkZL5+f7IOqIuBT7mGl+0FIQC4sCFyGPe9zR1sZVCUQ
         xHEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P8aLbx9Sl47RYxftyEseQjhVT7SfF+KyN6wsDyYV/tA=;
        fh=eCbgYCbD1jKNRMaO86DaaDB5TsMeL9q/MSu6IFv+guM=;
        b=ITLijLk4GOr0lFanYpPcKBwtXiG27xFzwBdHz7Qfa5PUXIhW3B9kSk2hjklQNaNi3n
         8xya5BXCZ2AkG24u/Lb1MDsKPfEC8ZNMuZLUSKdP9lwtz9b83s0Om1VwXjNG4mf75Rz/
         BJS9WRwxV/4SUYYqXUqPmlpEWe/k/yP11h4k6zYEJRMh2FoMgcbE6XomzCdB3bJrsiDa
         lJCcsKUEojh1xg56qXOmQ0WrSaQTAfdbgDR6x+Pbcc1iRe5iVBCDQKSteeClpWAzpo8y
         ml+LVU6fyNkSZNrsarhwt49loQtKJl0VHZ5/GI3q/Gm72epghelCeGuYI9tHZdAdiNBK
         fXNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="K+1/w3F0";
       spf=pass (google.com: domain of 3cdafaqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CDAfaQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42cb7f8ba1fsi53469f8f.7.2025.11.20.07.13.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cdafaqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-4775e00b16fso6917665e9.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUNmwC/QfNa46TQ2WFfFJSFZXKXQs9nRn3Zkn53YtjVOlYTqS349zbOnyRTp5FAL4BWo7rWZOr+xG8=@googlegroups.com
X-Received: from wmco22.prod.google.com ([2002:a05:600c:a316:b0:477:b15:2ccc])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:1987:b0:45d:d97c:236c
 with SMTP id 5b1f17b1804b1-477b8a8a5damr33384125e9.21.1763651592065; Thu, 20
 Nov 2025 07:13:12 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:46 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-22-elver@google.com>
Subject: [PATCH v4 21/35] debugfs: Make debugfs_cancellation a context guard struct
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
 header.i=@google.com header.s=20230601 header.b="K+1/w3F0";       spf=pass
 (google.com: domain of 3cdafaqukctuvcmvixffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3CDAfaQUKCTUVcmViXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--elver.bounces.google.com;
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
struct debugfs_cancellation a real context guard to benefit from Clang's
context analysis.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.
---
 include/linux/debugfs.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/include/linux/debugfs.h b/include/linux/debugfs.h
index 7cecda29447e..43f49bfc9e25 100644
--- a/include/linux/debugfs.h
+++ b/include/linux/debugfs.h
@@ -239,18 +239,16 @@ ssize_t debugfs_read_file_str(struct file *file, char __user *user_buf,
  * @cancel: callback to call
  * @cancel_data: extra data for the callback to call
  */
-struct debugfs_cancellation {
+context_guard_struct(debugfs_cancellation) {
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-22-elver%40google.com.
