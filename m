Return-Path: <kasan-dev+bncBDK3TPOVRULBBAWCZ3ZQKGQEBKBIQ6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 68AAE18BCDF
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 17:42:43 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id t12sf2060176oih.4
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 09:42:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584636162; cv=pass;
        d=google.com; s=arc-20160816;
        b=fpUap/EglOZm4kYQbBrRrQDaYi73OYan8iBWEZrKUO+QjcUk5AxqO0xobbh28SAsWB
         cSG9cgyIseG0XjdWEWmdU6vpUkOdCZU0hXpKrt3+mGul00Yq8AzfVX3+7ZzMViMT8pXn
         jXQiKRIIX25Qok2guEZK9knGWg8RK/rdyouYq7SIBdjfWPyEKf2tC7ExvqmxWPUhsoKY
         oemdG3T+NNaPiF9UTXTj3/rLsLyl/8f3WmtqjbTGAX65G7PKT7Zs9gyD3YFfWFKJodlt
         RAALq18WEvBV4nqap6dEAwyq1pHarh8A1peNR0qtEmOTUDklV75/u0OQsRykcuomRnKL
         8PEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Jb5Co+5AvUP4TCzrlFaV/0tKfPa2z3AVsSoTRsnS00M=;
        b=mQEVUaXQs+holN6lKhO4SR1s+vj1oYqlHB9pIpHvP43IDJaIy9RGKfYtiEa/SkyHfJ
         k3U65soU4SX7CxuCnF0I1VEl+U67zsZ+Uinz/KPyL7l1tGtk342+RjGsVGPqIAgO+Rjf
         cQVk2lWnhuJ26d8nW7SIkV8Wt/epXKk8EUwecS2JCJVIO14qoBd2HwMTxbJWdaOjCqqY
         gfqNjAQ+bVr4ue7qL2Wl3ZpR4ueqKtRd6Y8evJELK3k8ewtE2+A+9HiNBHe4gY6J0JV5
         3pvKKBJxRz1lsJP+e29WwPqfZqGPiu0fAGvzdv4LD8kzOc+KSypMe8BXD13T/ePgrz9M
         7wgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYcIxAhV;
       spf=pass (google.com: domain of 3aafzxgwkcqw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AaFzXgwKCQw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Jb5Co+5AvUP4TCzrlFaV/0tKfPa2z3AVsSoTRsnS00M=;
        b=S1j6n7cmv8lWBK3S88TxEEaJqmJcTnJIW3D1lII5vTOQfta6OCMJEdb2qvhVleGqWJ
         6hxdXbekm/s1KsFwamUudb7vMNQH6hy6nVoCQXl17cprJkbtxpLh0he2YkL2OX9EfKYI
         gWbUGaHQIDw53xX1YTCUnDXOO8r+EYMAXZ22a748ri5wH1gX5sAzIanzYlpigN+ALUcU
         sw+rIGIBFQlD22xwJXR3V1AJCTAgKv1hBjBF/MXOYsErmlvg3ByVz6mAtXxiWZg+f75u
         97XHu0j9IVeTuZRIhoAaeTwlLRj7q7kA+7QXl/N27XXh5JsU/0IuBCNCq91TciSuhQ1R
         EM3g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Jb5Co+5AvUP4TCzrlFaV/0tKfPa2z3AVsSoTRsnS00M=;
        b=hIW1hkIbu55UZg+OKSTptoCx1zwLGj+pHsEa35WuSNHlk6kZjS2B5SAbjDMsRA4znn
         54AFaUhyOosiUHI9KXGuYBQbzsMxEMI7mSAW91u74W9HhXiIwpD/r/Pe+Jtlw/LrbYz4
         CYbqpjWLlwxAPikwS+u/cI+3467/+8+iYMJOIluZ1Sf3Pv3i5IkFUxF7ortNo7pAh9eo
         JQrKQHr03i49xpogz2wYVtMbE4K6MP4yeOPL/8nQ8kkc/CtX+7OpP+uiOsfBeuAOusq6
         BgtAN3WJBUFyabdCEWAC1sXJRuovcQemBHNVP3rg9sRC2PZs07d8npUY5YSLJlnX0NWq
         nfnA==
X-Gm-Message-State: ANhLgQ1Y7ifZ4PusfqC1MkSfD0h1eowkloSklU2qm/pfOAIx+iSAx4RM
	Mtf2gTKBY3VaRi+Htke8MDM=
X-Google-Smtp-Source: ADFU+vt7Tc42t3CDhILf34TmqCJzBlS/k6Ja4QW18epe1/8vu9jugPE6fgszz+VGLyCUjcQ44MIWrg==
X-Received: by 2002:a05:6830:4035:: with SMTP id i21mr2875061ots.348.1584636162325;
        Thu, 19 Mar 2020 09:42:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c441:: with SMTP id u62ls1085642oif.9.gmail; Thu, 19 Mar
 2020 09:42:42 -0700 (PDT)
X-Received: by 2002:aca:4243:: with SMTP id p64mr3053126oia.21.1584636161986;
        Thu, 19 Mar 2020 09:42:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584636161; cv=none;
        d=google.com; s=arc-20160816;
        b=H574gePE7wTqtY9yg5WxyYWaRRr+JYKt63eFSC+k+8wnKc0AoLoxAjTBGrVoOKAdEf
         tulgKWvZd/gqffELiORGWQGnbiTc7lHuOwl7eZhPC/Z2FzHMfQjBIXWQuypxdCiik572
         KalNt4LFhkedOZAf1osQ+ZhhwVCK0yvLZBIIyj7SZQ7434hzPjHG+cUGxFnjiN9SPBbr
         QdRkiJpH3SsQVoRjM7Jf5bc08CD6IhIvdtY5IvQUTiy7F0gQr3yHwSYeD3mu2asSzPPX
         /HNjcPKp/8A6boQ003HK6QUNUIqhrpkwKnnqu/jHSKx4uotjuKlXrSkfcKOIj0xKnweH
         0Iow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Dz7alAscI1YvV+X2ok1ND7NhQJcsBO33MSW+QX9MTto=;
        b=hpuFUPbnG1eK5fHN9J5rgBeXbUWWllFGHQNTu99tx9DqOGKYHepUbKWaFTgkudDhRV
         wxDqPUQlMGtpFX+MtOxPEcGcTa7ax+b0J7SHSajbTa9c+6LKW4YFdnYJ4BdVxPr96ToN
         OaoEdtxFRKP8ptsH3uPRPUOxF5M1oux4BYLyTIeptwphkeVaa7iE/ksEUUtYfa0m+BiC
         EEu/G5CK/dDXmJHXyq8+NamCj80DzDznyQWGWhaIQhiwDrSXlJHcd2MO1o+jgfCCe57y
         ezvzBZ95ibKKCCH/Yp3PpE7+WuMRQOgTOEyUeU0CtwmhWbqfLun7apn5gTChRFcwPIrm
         h7dQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OYcIxAhV;
       spf=pass (google.com: domain of 3aafzxgwkcqw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AaFzXgwKCQw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id c24si165390oto.4.2020.03.19.09.42.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Mar 2020 09:42:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aafzxgwkcqw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id b1so1077476ybk.21
        for <kasan-dev@googlegroups.com>; Thu, 19 Mar 2020 09:42:41 -0700 (PDT)
X-Received: by 2002:a25:a281:: with SMTP id c1mr5753816ybi.327.1584636161413;
 Thu, 19 Mar 2020 09:42:41 -0700 (PDT)
Date: Thu, 19 Mar 2020 09:42:24 -0700
Message-Id: <20200319164227.87419-1-trishalfonso@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [RFC PATCH v2 0/3] KASAN/KUnit Integration
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OYcIxAhV;       spf=pass
 (google.com: domain of 3aafzxgwkcqw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3AaFzXgwKCQw53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

This patchset contains everything needed to integrate KASAN and KUnit.

KUnit will be able to:
(1) Fail tests when an unexpected KASAN error occurs
(2) Pass tests when an expected KASAN error occurs

KASAN Tests have been converted to KUnit with the exception of
copy_user_test because KUnit is unable to test those. I am working on
documentation on how to use these new tests to be included in the next
version of this patchset.

Changes since v1:
 - Make use of Alan Maguire's suggestion to use his patch that allows
   static resources for integration instead of adding a new attribute to
   the kunit struct
 - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
 - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
   test_kasan.c file since it seems this is the only place this will
   be used.
 - Integration relies on KUnit being builtin
 - copy_user_test has been separated into its own file since KUnit
   is unable to test these. This can be run as a module just as before,
   using CONFIG_TEST_KASAN_USER
 - The addition to the current task has been separated into its own
   patch as this is a significant enough change to be on its own.

Patricia Alfonso (3):
  Add KUnit Struct to Current Task
  KUnit: KASAN Integration
  KASAN: Port KASAN Tests to KUnit

 include/kunit/test.h       |  10 +
 include/linux/sched.h      |   4 +
 lib/Kconfig.kasan          |  13 +-
 lib/Makefile               |   1 +
 lib/kunit/test.c           |  10 +-
 lib/test_kasan.c           | 639 +++++++++++++++----------------------
 lib/test_kasan_copy_user.c |  75 +++++
 mm/kasan/report.c          |  33 ++
 8 files changed, 400 insertions(+), 385 deletions(-)
 create mode 100644 lib/test_kasan_copy_user.c

-- 
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319164227.87419-1-trishalfonso%40google.com.
