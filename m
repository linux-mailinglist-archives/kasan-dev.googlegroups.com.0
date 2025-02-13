Return-Path: <kasan-dev+bncBCPILY4NUAFBBZU7XG6QMGQESY7LEPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BAD7A34EE8
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 21:02:48 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-471baf26492sf35056261cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2025 12:02:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739476967; cv=pass;
        d=google.com; s=arc-20240605;
        b=LFwwMgxmWPEXoziEB08RtmdX8B7fdUfCVPO71AAGCMvn1iqM4stuLlIksgpI1oazyw
         Mq3qJ7UaYqYmHCUeJJaoe93zmtdoaAEmWK8o5F4dYf3yEcT+3UIZskU7uPN1q7fQziVS
         yCcPce/DaQFWT+Tu+OyGXKycGmo3Gd/KGnZsFlrKwxNM54o6wdv2LJaTTsKfrPJKz4ta
         N+rZzfByM9egGSTQNcukK9yxCOx0liW9h5Tfuos0JvshbjSTr9N6F/wHc4kEU7NTMI5p
         9/qdt+/kliLz39GCKU1JrNhupY4m8cR+huHi6s29st4TvLEoGvtgxuQ881SZ+jhAzTbs
         aG/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uwvQ3OnLw2puz1uEd6a1M7GjVURO4bd7FZfkXJ8Gz4s=;
        fh=TIiQV8volOAy2kM653+p3GZnCZ3i03/zBX48MjhsaIY=;
        b=FZKsMgy/PnUkP4BWnmDsKUUfw1/ZAyFEBqJcK/9xC8oU1XaErnyl+aL3F8bvG3UY3/
         bqhMHnSy3qMbGWRg4uvsIxfbFWnqAkwL3aBVvM2vGxY+XjM+BXH5zZGMn0BhEYl2Ra1J
         F4skZ1ieMsuCEnc8tXWGJcZWU3+p2sfRGVu9eawerUxm8JsgCawds28gWN4yYNijHow0
         tThbiMmJBU/nPAZkg6mqsMvpjYw983We+7AjvhsgJXwQzUNt3bbjmvl9pnWrAqiV/aKU
         0/3vc7TqOai68Gsy3UNUnU1aRUdL0mgnPZ/j+dM89lfm+pONeWWdKBiu4PmQ1fq1QpP9
         hkuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KyG0bTr2;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739476967; x=1740081767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uwvQ3OnLw2puz1uEd6a1M7GjVURO4bd7FZfkXJ8Gz4s=;
        b=aFGpfGn7gf3u7z7j7M+4zt79RO3nPVGfOAEIJXamqXUDhjvbr3vHJGNnObqoNhkGxx
         h1+H8i/VguV38LNJG3SVqQaWU3ObDcHPQ5ZAfO1KSrULjM/ACIf78Ls9wUq9g6pZUHnf
         896xB2TH127z+jpKm1hgdlduxJsdsl3zPurw2tD8su3q+gs0V5an6XzM1wadhazYrRNf
         Uraz4hxuIoVLUf21waQdi05hhhB0dA8Hj85c+G6a7Dg5X2rF7qZddoyQ68rqrF13/epS
         FWnXWdeWuiEq3ZBZadoXWGkGUzRU43beC8QyyHZLIJ6bLmThhtB0RP91e75dOTRFNSGD
         /kOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739476967; x=1740081767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uwvQ3OnLw2puz1uEd6a1M7GjVURO4bd7FZfkXJ8Gz4s=;
        b=VBdvN0kkkScYx+D2Bc+oS2wJSvtALHTbKScAwEBbehnEHOu22bmxWfaes5fPbF2xMB
         7QuplpThfnME67uXhzHv3yOKLIiTdSGsl6EhhF1GyQDI6YROGpsZo2V2281S9jKFd/Sr
         W2D0dZgAera5KgBpUC50K8AJ+sDsazYVIc9lnZnCF2jh3pu+o3987Kqorq1DJtkKGdjl
         ZINM1OLi8lS4ENQUJm+Cn8qNEXOLGhMyyWGdcyr6Z+5OkLpUk7kidkytx5zL7qr4oMZN
         h7GD4TtRyAPl/7gXhS0YOiui4mRZ6gOPLo8DxYjvUYHvozn3Lx68MPzvkiprOUpkgvHY
         0AdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXvghRozFHb2R7jUSfvqNX9QGlaVa/Y9IKKmhVMjvCQqj10mQGcR8c76tybARZv2D+xdOTRWQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx77U0hxUcd5zm0Wcz5VpUlnYVsFG/MmT0pRTvzzOXKsMwkxZjK
	jYYd4fNzOvQrIM2nm7LdcZXGvngamCUs9UlTSkx8++E7RqxC8Rds
X-Google-Smtp-Source: AGHT+IF1f4E0CPA588TvMD9n1n3CtUggAvhkE3yK43O3pZD+ATXoFVB0a64+nIHCCa/1U0pvzvaDvg==
X-Received: by 2002:ac8:7f0e:0:b0:467:6b6b:fc1 with SMTP id d75a77b69052e-471c0440e26mr60602301cf.16.1739476966483;
        Thu, 13 Feb 2025 12:02:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHhbMg7rynezNPrBBFXBLgmWDhluE549akXR2shOA5qZg==
Received: by 2002:a05:622a:60c:b0:46e:55ee:a375 with SMTP id
 d75a77b69052e-471bf25c9eels9789331cf.2.-pod-prod-00-us; Thu, 13 Feb 2025
 12:02:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXGNSBXjeBg3N+O4D4qJ3DA1OnIaV/zp+jtd3GS9ZeMnX3LC7/Or2xDngUn1rcmjAMSxrH1YJDLLZQ=@googlegroups.com
X-Received: by 2002:ac8:690c:0:b0:467:82b4:d7a1 with SMTP id d75a77b69052e-471c01dbce2mr67727601cf.20.1739476965276;
        Thu, 13 Feb 2025 12:02:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739476965; cv=none;
        d=google.com; s=arc-20240605;
        b=ZjCwo1vAmyTybydj/oTQYwpRUpRPIyEGAKk7ZWuSroakFN2+xVXlhfj3eEY503xnOT
         XcQ+8ILjXYuhDVQglb7pjl3SZ8S7Hco4Zv9SdaJCDlnWYwbzntsFYzNw2tbCoUv8zZ39
         VACy6v6etyk0Znz86DBiBwNMi08RyXgHpZpQZpvghZ7e6KdgSpOj+w964UwlwEAxtk73
         +FXJMK7ck+Yc4nbrSgYmsgr8VhpYs83R0OvlNLa8NinwZvcwWyktNe1RdzCYeWSqoMLb
         kOx0+PiV1S3DDwtVapzPvO/5H+zs+75JLv6nDlW5rLXH1Y7z/ojM5HnLQs6I1Dc2xoU1
         lK1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hlf6x/2m+ZIY8uOQVOMDgFdeACA4Rc/2FVHmDJRTfuE=;
        fh=lQv1AjbPVKIvQPz9UUOSn+HIjjyR/F37iUMUXKbc//M=;
        b=ACHfIEihtb2q4BfUGEqCb/ls7ifbKyZpjQSBO3ewwQmD1/8wcddNiNJyA2RTtGCRdT
         wOqZVNFOKovK+iLSxFV1NXtKSBjvMZdD860jCxXVigYKH1hjUZfznyuW0lGo9EKWsJTP
         qBcIwfZ4FyTdd/X21FXZ+KoP3Faf8EQFdNzqqHeEDgBr+tH8av1FBZlTFBA4pSIqD85X
         YBhNy4RsF8/M/gC7jL6CHo//y3eQue2QsZQMYjqozy0E1qe1ocmzyrAz5pIyIeaO5oO3
         pHBwGBe4Ev6KapiGrM6BQg+oH4wCMX6C+BI7Dg25qThlE8G1x+iSjgsyj3j6w8QLRKmX
         Uo5A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KyG0bTr2;
       spf=pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-471c2a15410si954691cf.1.2025.02.13.12.02.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Feb 2025 12:02:45 -0800 (PST)
Received-SPF: pass (google.com: domain of longman@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-687-7NPXp59oPO-5ALDO5t9JgA-1; Thu,
 13 Feb 2025 15:02:41 -0500
X-MC-Unique: 7NPXp59oPO-5ALDO5t9JgA-1
X-Mimecast-MFC-AGG-ID: 7NPXp59oPO-5ALDO5t9JgA
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 095201800876;
	Thu, 13 Feb 2025 20:02:39 +0000 (UTC)
Received: from llong-thinkpadp16vgen1.westford.csb (unknown [10.22.88.174])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 17C4C1800872;
	Thu, 13 Feb 2025 20:02:35 +0000 (UTC)
From: Waiman Long <longman@redhat.com>
To: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@redhat.com>,
	Will Deacon <will.deacon@arm.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Waiman Long <longman@redhat.com>
Subject: [PATCH v4 0/4] locking/lockdep: Disable KASAN instrumentation of lockdep.c
Date: Thu, 13 Feb 2025 15:02:24 -0500
Message-ID: <20250213200228.1993588-1-longman@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Original-Sender: longman@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KyG0bTr2;
       spf=pass (google.com: domain of longman@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=longman@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Content-Type: text/plain; charset="UTF-8"
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

 v3: 
  - Add another patch to insert lock events into lockdep.c.
  - Rerun all the tests with the simpler defconfig kernel build and do
    further analysis of the of the performance difference between the
    the RT and non-RT debug kernels.

 v4:
  - Update test results in patch 3 after incorporating CONFIG_KASAN_INLINE
    into the test matrix.
  - Add patch 4 to call kasan_check_byte() in lock_acquire.

It is found that disabling KASAN instrumentation when compiling
lockdep.c can significantly improve the performance of RT debug kernel
while the performance benefit of non-RT debug kernel is relatively
modest.

This series also include patches to add locking events to the rtmutex
slow paths and the lockdep code for better analysis of the different
performance behavior between RT and non-RT debug kernels.

Waiman Long (4):
  locking/lock_events: Add locking events for rtmutex slow paths
  locking/lock_events: Add locking events for lockdep
  locking/lockdep: Disable KASAN instrumentation of lockdep.c
  locking/lockdep: Add kasan_check_byte() check in lock_acquire()

 kernel/locking/Makefile           |  3 ++-
 kernel/locking/lock_events_list.h | 29 +++++++++++++++++++++++++++++
 kernel/locking/lockdep.c          | 22 +++++++++++++++++++++-
 kernel/locking/rtmutex.c          | 29 ++++++++++++++++++++++++-----
 4 files changed, 76 insertions(+), 7 deletions(-)

-- 
2.48.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250213200228.1993588-1-longman%40redhat.com.
