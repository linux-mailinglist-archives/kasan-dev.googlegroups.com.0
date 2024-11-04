Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDPIUO4QMGQEV4K5GMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D3CC9BBA1A
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Nov 2024 17:19:28 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-431518e6d8fsf28625785e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Nov 2024 08:19:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1730737168; cv=pass;
        d=google.com; s=arc-20240605;
        b=E8VxFQqfL6SKgT2UhW8Na0ObAjdrY2nVsCHxqCq7afRbkOp1bn9ih+8iDqhzFZ3Kef
         4iUMO9cn43CEmLwX/wij+QO62zprxZzav3Nfr71esJsWnyRQRA0RkSX6yX6yAOQTekIp
         3IpnEQayFGj1xfvzgE/vUB77iU+5p95bLlbW0UANy0NfmCVdT1witFu/DzOOJPxdM/Pa
         LN6lkdR+nD5VmypF6fKdbTnQfoZb6SvsFNRU7zFXEPnx2Gwek8JY+P4QQl0fEZnIVQiB
         d+ki3LiROUc6GQJpsNfROwuBS/deDrOweX9/NY26vUzuu23ObJYupfC/ABmM4jdmsR27
         q+pQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=uzgWvyp3+VSYb2xMrXcSgr+aDAFo8S4IGWHMLRw3UaA=;
        fh=7HrDugFI9YWd+vus6Rmh7GZzCTxUdO9fKvx7nVgcFbI=;
        b=YpG7hl023MZVv5rnmqH6gqCKwPyHKUxRtkk67TxTaMML3A7kj6Umt4qmhU/LoLxeqI
         qvFmE27wtZOLX0YtO/qX/DCsmtVDcKmyMxJ+cNSWB/W4ahTGMNpQQ6IhArleQpKizcbN
         ym3VLlGpy27N0b+ofSUDUb9zd0JRJ/roRZ/S/XcLsleo+1rNrVlt79Z1i0glChoUKEau
         cEh9XImSgzPvhE/uCL2hOJ5lotqoHDMEr0FoV9aQpvnCZkjTv2ItpM1ZnN+kuyHKrIxE
         vcD6txENe1bT744IYWvNKYBBbTILZlsDycuCm25wLcKmw/MQdUbGuRJyQJK9Lhp+cP0R
         KDEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=daUFxva2;
       spf=pass (google.com: domain of 3c_qozwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3C_QoZwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730737168; x=1731341968; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uzgWvyp3+VSYb2xMrXcSgr+aDAFo8S4IGWHMLRw3UaA=;
        b=nIz3tcw9yl+y7Vt1NELVy57PvqAGdnU04K1FwLIsPEmOCPW44jPa/uvIYJv8uGsFJ7
         m2f1/XEDgVBeSeMM/dWQ+cWS8tmu0ewRyvjfJvEAXIqKdWkW/5jutnAEnCdJUhLNEUon
         N6sGv2N6lIZnl61j1hJSfBr6DdN6xoEG/kKNoFL0uH4c+2rH5GQMyxMcTIj2VdcjCjWU
         RF16PZU+F6UuAyjJgKnelIVF5SQnLdVlmCQhJdVtBUoNK4JWHFHbh5nLE6zgakZWyIZO
         UgZmno4J53NA+h0eBGui0UH62nfWUvKbog+7l1RXeIq2/ehyXpvrYU6SCeY4biSpUslO
         2g1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730737168; x=1731341968;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uzgWvyp3+VSYb2xMrXcSgr+aDAFo8S4IGWHMLRw3UaA=;
        b=G0L6hAe4wx1/73hx/AJszdhzID0CcwWsN0Asuuvqe9amNlkBJeSmYutTYAns3K6YrE
         b3RxrIfId4jobaJOyFHnap1nBHkoYhHVs+nqNZYi4xhu0JBbQyRJ2vCOMJvUy9XV3mnD
         FPFicRMVgd72GaEJxbbDwfIC+qGRU7S/v8UFmBj2r8A5zvQSKBAmRlkk02FdcklxifY+
         f66PgaUPurICsGZV+U3aR249ijIl2hAMS+kFQvAZYzbbV0rkgtFzsXTtz4vQCPa8p6dq
         mKUS/aFYPn2BJfUSWszTW0Tvq5fW39mFDNLLOxjMNd2dwg3AYgTXJl80FSjuis4iibi5
         Sswg==
X-Forwarded-Encrypted: i=2; AJvYcCU+guiBzyVtsvyOVaWSn62HD5Mbw7QOI/7O4s9/M1EuiZvbvBpsSS1d3500g5M60WY4g9EDkA==@lfdr.de
X-Gm-Message-State: AOJu0Yx2coccFC7vepiFDmgZt1SxiKOJnGZy5AdhE4TVQlPX1MM7gqAv
	9zmlef/1dypVzw9+aRo/66ZH4Gs7TSdq4Q8a38zs8flD8gHxD2PQ
X-Google-Smtp-Source: AGHT+IFF7jPTBxIy0p39PadUUqhKmhxmqokJhZJuxUSMD3KqGJMJofj+cFEPcjEFSrHBMolWXXJeRw==
X-Received: by 2002:a05:600c:16ca:b0:431:5847:f63f with SMTP id 5b1f17b1804b1-43283246cb4mr107174425e9.13.1730737165887;
        Mon, 04 Nov 2024 08:19:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f92:b0:431:55bf:fdf with SMTP id
 5b1f17b1804b1-4327b6db020ls16367815e9.0.-pod-prod-04-eu; Mon, 04 Nov 2024
 08:19:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUUns4w/NHNBqb2Y5XM3yeOgDO/uUb78+PB9NItkSifqkppd4FV2PLht5nZD74C7Mwb5cGaB1QoJi8=@googlegroups.com
X-Received: by 2002:a05:600c:1c14:b0:431:57e5:b245 with SMTP id 5b1f17b1804b1-4328328492amr100592715e9.23.1730737163730;
        Mon, 04 Nov 2024 08:19:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1730737163; cv=none;
        d=google.com; s=arc-20240605;
        b=UkzxUbMUKKMHhtpTSuDHeh7rbLklxhrW8cl8yMgkOF+AMriV9gBiVYOFzCI5KXen1h
         AbEyG3vz0tocubYGvPn+scwr2gmCYaNXJokMhJaYtNUc2ETYgaG4536DXhEuGdqN+IIk
         oP3bAtCWPYYv56K2zsxGlHXrhJjHnTDJorNsDc6IYURht+ooWphdAsUsnsxtJglLrqQW
         D9CAPp5HJFrLzfZZVpdaPArNafVSlSi7OUjSReHeLgqnvFfB/gZKsoJAe10kSgQMyrTi
         zxLjzlZTrEKTU6DJ0SYT7tOICcvGgfWh2Y++nBq0lC8ansN0TsLYcU7ksvlCmgtfuEQv
         fl4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=N1OEU5djaBFZZONmKjr46m7cvs5PfysB7luuY22l5uM=;
        fh=lBZS4cMh0Y0GnlMaltYiX/+uf+ErJzYsVVICjFB+/qo=;
        b=CXjP5Fd9P6i0GkD2S34cGvc4aBOo0RcG5GGuTpRlqzY09ODxUQ6dSbReOJd7YZn33i
         ntekl+WRvRZGEMGvoXfEViMDSUULzRKE06JmU4ifTyMOyfeKUMJzZD8RNaUQWWB9or7r
         CFj7UtDqV1F6TJABmCqH2HoTF2bUTvgfijVA/CDAYPqvWSiR+e7bKoH5aPKgJDRJdHUt
         mx8K7y052YLTfNhmn+pcqCALPMr2rFJbWJM3ndXfstyi5m/XtnOQ2E26Qs5jphnl2yfx
         i9w9dK2vmWB2C8jTHIGmXzhdamN8HLRJ/9KnGdtEOCOGkpqnhUvHXQTJm3brI0ElKZjj
         YkZg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=daUFxva2;
       spf=pass (google.com: domain of 3c_qozwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3C_QoZwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-381c11ba0c3si163241f8f.7.2024.11.04.08.19.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Nov 2024 08:19:23 -0800 (PST)
Received-SPF: pass (google.com: domain of 3c_qozwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5c94a70a3f5so3268120a12.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Nov 2024 08:19:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUiuCX1MAh7RtxDxB1akGfmP/D6oJAXks80sDkbNqEY3lkM5+oiACyFqiBQObzKfY0BYOTBW60oo+E=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dc4d:3b27:d746:73ee])
 (user=elver job=sendgmr) by 2002:a17:906:1753:b0:a99:ec71:a131 with SMTP id
 a640c23a62f3a-a9e50869b05mr391566b.1.1730737163168; Mon, 04 Nov 2024 08:19:23
 -0800 (PST)
Date: Mon,  4 Nov 2024 16:43:04 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.47.0.163.g1226f6d8fa-goog
Message-ID: <20241104161910.780003-1-elver@google.com>
Subject: [PATCH v2 0/5] kcsan, seqlock: Support seqcount_latch_t
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@redhat.com>, 
	Will Deacon <will@kernel.org>, Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=daUFxva2;       spf=pass
 (google.com: domain of 3c_qozwukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3C_QoZwUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

While fuzzing an arm64 kernel, Alexander Potapenko reported:

| BUG: KCSAN: data-race in ktime_get_mono_fast_ns / timekeeping_update
|
| write to 0xffffffc082e74248 of 56 bytes by interrupt on cpu 0:
|  update_fast_timekeeper kernel/time/timekeeping.c:430 [inline]
|  timekeeping_update+0x1d8/0x2d8 kernel/time/timekeeping.c:768
|  timekeeping_advance+0x9e8/0xb78 kernel/time/timekeeping.c:2344
|  update_wall_time+0x18/0x38 kernel/time/timekeeping.c:2360
|  [...]
|
| read to 0xffffffc082e74258 of 8 bytes by task 5260 on cpu 1:
|  __ktime_get_fast_ns kernel/time/timekeeping.c:372 [inline]
|  ktime_get_mono_fast_ns+0x88/0x174 kernel/time/timekeeping.c:489
|  init_srcu_struct_fields+0x40c/0x530 kernel/rcu/srcutree.c:263
|  init_srcu_struct+0x14/0x20 kernel/rcu/srcutree.c:311
|  [...]
|
| value changed: 0x000002f875d33266 -> 0x000002f877416866
|
| Reported by Kernel Concurrency Sanitizer on:
| CPU: 1 UID: 0 PID: 5260 Comm: syz.2.7483 Not tainted 6.12.0-rc3-dirty #78

This is a false positive data race between a seqcount latch writer and a reader
accessing stale data. Since its introduction, KCSAN has never understood the
seqcount_latch interface (due to being unannotated).

Unlike the regular seqlock interface, the seqcount_latch interface for latch
writers never has had a well-defined critical section, making it difficult to
teach tooling where the critical section starts and ends.

This series introduces an instrumentable (non-raw) seqcount_latch interface,
with which we can clearly denote writer critical sections. This both helps
readability and tooling like KCSAN to understand when the writer is done
updating all latch copies.

Changelog
=========

v2:
* New interface, courtesy of Peter Zijlstra. This simplifies things and we
  avoid instrumenting the raw interface which is now reserved for noinstr
  functions.
* Fix for read_seqbegin/retry() found during testing of new changes.

v1: https://lkml.kernel.org/r/20241029083658.1096492-1-elver@google.com

Marco Elver (5):
  time/sched_clock: Swap update_clock_read_data() latch writes
  time/sched_clock: Broaden sched_clock()'s instrumentation coverage
  kcsan, seqlock: Support seqcount_latch_t
  seqlock, treewide: Switch to non-raw seqcount_latch interface
  kcsan, seqlock: Fix incorrect assumption in read_seqbegin()

 Documentation/locking/seqlock.rst |  2 +-
 arch/x86/kernel/tsc.c             |  5 +-
 include/linux/rbtree_latch.h      | 20 ++++---
 include/linux/seqlock.h           | 98 +++++++++++++++++++++++--------
 kernel/printk/printk.c            |  9 +--
 kernel/time/sched_clock.c         | 34 +++++++----
 kernel/time/timekeeping.c         | 12 ++--
 7 files changed, 123 insertions(+), 57 deletions(-)

-- 
2.47.0.163.g1226f6d8fa-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241104161910.780003-1-elver%40google.com.
