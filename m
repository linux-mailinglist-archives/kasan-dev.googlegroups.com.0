Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMP5S4QMGQE23KZIRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ACB09D0B89
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2024 10:23:40 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-539e7dc83ecsf2292589e87.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2024 01:23:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1731921819; cv=pass;
        d=google.com; s=arc-20240605;
        b=bZlaXpV6zXuuGDGcRd5j1pJ/z/8wal60ZMMgPfLWiYYmtS2rE3qYJ4ktPwKU5jdtwI
         uVtEShmGhEd73DlP1XIRwus22rSwkekcfwyUDGkAdcJLl8jSnHLgiLzaWpUWkns5XvFX
         PquALwhJmsmLOKKY536UE6IAxMkiy76WA8Y4MubsGZrtQHJVsu1L5IKr8KRSJj9iTq7w
         GGXeZVsVvnJXCTnp26dlc5ZVvlz1Sf/AcOEPcZtYLkX10PGnalF0Unp777BES2cD4p9c
         XzXFYH8nhfaYsrtpVy2Mcq+whI0wFsVPCU5OybBe9haz6Bc3OSh/GZ4d+tNpe70SxZM0
         Y0Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=P8vqn31DcF9dg6wB7m5YNLaBiBkBsPnyKqIZXwPgR6s=;
        fh=/WSsZwVI+kcHtNfaD6f1yKJ7noUo568aYFWrn+sS8vk=;
        b=Ac772+7HHKZXYRyPenDS5nXC0U6C+jfBYvXBevyMwNrdWHe7cj6KjhMqr1XQsdrPd9
         tRecrlHti0aAK5Urjpqpu9VBiTuGodiZW3qh9o4Pm/JEWe3oQtuXfeE89C1e7VoaFWDc
         AKxrQFB8u7V79X38W8Xd2J22pG6zel9KY66f6ZnPr5k8KhAD81bMUsAWZGdql6NOWmjz
         cQVDRUBW/ozasy0zui095hqbPKDu8ttkcojvjB5fcIr/MVwOP/9kcxcdNhpk1XDJj3yU
         OHWh/OMsq3rqkHgfreQC/Kyz4qnlSp7lcdZlOHeywoRHuloF5Jsk/hcA9EIFPLl2rX7M
         SBIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NN6KVaw9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1731921819; x=1732526619; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=P8vqn31DcF9dg6wB7m5YNLaBiBkBsPnyKqIZXwPgR6s=;
        b=TJy1Fg/AEr+KWg5/WAv/pIZwQGwhUBwyTOBvopiwm0cBGX9k4dzmw+kVh2KptezIL/
         5GAdCz7DEiILhjWnSpgBJLEzYLNiT6jnmcJ7mfIeYiyBCPuMNKBnn6e3R9V7TJfbuU/J
         bmXNo6PozhzEOXLX4TqX/zXAziEoP7twjTjXQFiJEvFLdcv92sDC/R0L1aqQLjsuLgTL
         RjRwTPNO1zmS8o+ujGIxHfLXj/LeD1Y9GceJu7mpyv1haBzwQXfg2FewDU94X9pDPawF
         SKhk5nKmk1jrhqoZ5tRlVxCJXNOLZ7iIiYjIcZriylDvGQEz7uB48/2RUk0ffhsiRIcS
         rIhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1731921819; x=1732526619;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P8vqn31DcF9dg6wB7m5YNLaBiBkBsPnyKqIZXwPgR6s=;
        b=PSCJctYtVD+mshd4Qks40bIImojxrjS9RiP/g3O8QN0v6arXvzCR1+UEdYRT1Mhc2b
         kk8N04ci8PuQJ8fL1Gi06VY2qXXsd3Hqr44AbS9R4hECdwThRXLP3EPWkzDQZqvdu8/H
         T0yRBaA0wF7OcIu+uA6giSRSFb8Wk1gxWFya/m7lJIHBHI5xwV2P8N3frVB1xOqI3kzt
         vFmlvFOvCcDQX0WI6XLszMEuriAdzP33H8oeDyFW8sYPcuZ+aZWaspfhR6v1N+/zY6G9
         TwtDCKuRVS3qCjQuU/5XKIw6aT8q/upizo9qN6Z2UByE4btmOSc6e0ZbSOkYdkwM7j3B
         aSkA==
X-Forwarded-Encrypted: i=2; AJvYcCVzTgBJu5rV6oDli6h8fUM5EUv3IhBfNkwbGLhxXZE3oJZ0HIPFPlyXEqtPQQ1XECfvXD9J9w==@lfdr.de
X-Gm-Message-State: AOJu0Yzd7lpnV4okz3Z0vqof11m3XBKzsyqKXO1P0injKxwn70B/uwE8
	XuseEEf7j70vZIzS3GS/NLZBhWtmhXKT9+Ju6kNUhss/jGo9oG22
X-Google-Smtp-Source: AGHT+IHPEMdyMsveRu0p1rYn7ib8yuehrzEBmeBvcAkTV/Rpxnjo/8KfqzPNNru/ydMdXCwCEUGVkg==
X-Received: by 2002:a05:6512:3b08:b0:539:adb0:b91 with SMTP id 2adb3069b0e04-53dab3b9961mr4559201e87.57.1731921818516;
        Mon, 18 Nov 2024 01:23:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4e8b:b0:431:9388:1f54 with SMTP id
 5b1f17b1804b1-432d99c752els14250405e9.2.-pod-prod-09-eu; Mon, 18 Nov 2024
 01:23:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVcRM0EUr5e1NIQUeL7wm/fa/HZtTchs1+eH2CaV9vbsPxcpov+l743PoADXkwwWHKg883C//MerY8=@googlegroups.com
X-Received: by 2002:a05:600c:c08:b0:432:d735:cc73 with SMTP id 5b1f17b1804b1-432df7411bbmr94119025e9.11.1731921815731;
        Mon, 18 Nov 2024 01:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1731921815; cv=none;
        d=google.com; s=arc-20240605;
        b=AFwS/NCYgHb6LWf2uz0enUwfz0OqDT3Lm9D4VgBG7A1oQummtRdnzSeLykH6O7ZlIE
         KKczGRarbalUKV1XnwAI9gRGQl7wkTR2Rcj6FcbFXIQExclxAuGA+kHSxLVZBqKmjmKA
         b6LFYE/7pQvbnH0namiQhq5jKpkExn/yHGGcNlESeVqmmICEpqWt9YRGs6JTx9sEArx2
         qBBvLnC1XIcEnfAFY8nU9O3Fd2BfR/+QGsc+wTQYgacrKvjgiig5DLu+D9bnDNLOcu7B
         AU8uBOg3WBs2teYlNYo9dKNkQgQExSJq8tU2utWkYUZPw0SLsetzcAeIiNJ3we47wwZ0
         pY8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:content-disposition:mime-version:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=q0WCXW20r9F4Yc3BjAdp9aLtMAOi2W5sVlPv1lj5qmY=;
        fh=uKwdf94nrmEJ0ifmWxLBWqhPxCj+9I4ZiVOcr9C8z1E=;
        b=WQgdLEX9eVAYoQU2M8+bHQKSzSb06xrq19pj9Vq6mCI8RexTwv0/py8z4HqPMFqF2E
         iJTSoUrG4AwJHrNVbagkpcIewfMofyq2E/rmKPeAALW2jeRkY+TT8SxYcNyabavqXw/Z
         7FWQ7sadD8XhtC7vW7vxJIoa4tyk2EdV+0FW+E+2oEGqgxxwAZi87WbZSfRGLpWO5xlI
         5mIQUKG/Bzx3OOgnxUv52Jo7dgIdqmJYuU1LCcNiDydbPgd0Q+keft8KbotfZcEY4mQb
         WKGCB9UagQGd6wxYCBjs5JzZTGrCadIhfI/Nwdxdog/w1ZP+crLs9q2TImvMrDyD8RxY
         CAmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=NN6KVaw9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-432da23c35asi1659105e9.0.2024.11.18.01.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Nov 2024 01:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-432d866f70fso34380675e9.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Nov 2024 01:23:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVgQi+o7hmpOv5XT6qw7210Uzwz3sTboUgjv2WinpftKYtRXbmx+W+I1HXU4F4edbOeQ3zYjsEfXAw=@googlegroups.com
X-Received: by 2002:a05:600c:46c3:b0:431:40ca:ce44 with SMTP id 5b1f17b1804b1-432df7906e3mr103909215e9.30.1731921815158;
        Mon, 18 Nov 2024 01:23:35 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:9c:201:7c0:adae:af6a:2c2a])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38246b7db13sm2752243f8f.91.2024.11.18.01.23.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Nov 2024 01:23:34 -0800 (PST)
Date: Mon, 18 Nov 2024 10:23:28 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: [GIT PULL] KCSAN updates for v6.13
Message-ID: <ZzsHkNopkQpY2nwy@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
User-Agent: Mutt/2.2.12 (2023-09-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=NN6KVaw9;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

Linus,

Please pull the below KCSAN updates for v6.13.

Many thanks,
-- Marco

------ >8 ------

The following changes since commit 8cf0b93919e13d1e8d4466eb4080a4c4d9d66d7b:

  Linux 6.12-rc2 (2024-10-06 15:32:27 -0700)

are available in the Git repository at:

  git://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git tags/kcsan-20241112-v6.13-rc1

for you to fetch changes up to b86f7c9fad06b960f3ac5594cb3838a7eaeb1892:

  kcsan: Remove redundant call of kallsyms_lookup_name() (2024-10-14 16:44:56 +0200)

----------------------------------------------------------------
Kernel Concurrency Sanitizer (KCSAN) updates for v6.13

- Fixes to make KCSAN compatible with PREEMPT_RT

- Minor cleanups

All changes have been in linux-next for the past 4 weeks.

----------------------------------------------------------------
Marco Elver (1):
      kcsan: Turn report_filterlist_lock into a raw_spinlock

Ran Xiaokai (1):
      kcsan: Remove redundant call of kallsyms_lookup_name()

 kernel/kcsan/debugfs.c | 77 ++++++++++++++++++++++++--------------------------
 1 file changed, 37 insertions(+), 40 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ZzsHkNopkQpY2nwy%40elver.google.com.
