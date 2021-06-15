Return-Path: <kasan-dev+bncBDQ27FVWWUFRBH4NUCDAMGQEXQJ2OXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4FF43A7371
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:12 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id b9-20020a4a87890000b0290248cb841124sf8149508ooi.4
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721631; cv=pass;
        d=google.com; s=arc-20160816;
        b=OSRlI8zwcdr5SOkeamZ2HBgQVDJCN7BCE2tfG7DMFhFP3wZFZ0pk+abvXzKeQksxQa
         oa6siwJj40T3xmhZ4OcXjJYQkZYODqXcEDZBK1VVh4FD1mNgxFsDWZ4q/fMExGGeRGNi
         Yg3aW8e0d93i7ugQYgA2WD75iEgBBjxN4OnycmMJdEhV93dvAxgjTtwr4jUKelRCGgdi
         pmKeDdVuU0mhziAn09ISujUs1+CK54fV3tJ2+ACKyFgvDKJZA0Acng0urBuGbMVqx3xd
         3Lff3CbmI2ElLHd5c2IZ51TkvgmBJ1By0YJ983BaXRbsvTHsQUbZ9g73S13eBSqW9SLx
         7qKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=VBBI8T3/iBVlZbQ6zqHd9fjeH27JXt28q5tPlkj5N38=;
        b=FlE+OwiyceJMQsk80BAIPsh2Q4WfjjD5u77RJ8BJzKfdnyKs41DWI+qNQq+GHZAv7U
         Ug8Njm5Bgb4qxCVLrsr4CAvLmKDaRMy5iTWj7yDMx1M62WU1fVtP92SsPbIg+mEjF6DF
         H+NcHgp30VLo5zCjzCn5gP/EGK7hYsktqCplnL+a08de80p680tkVreALb7ec6GhtWQY
         dzjyAAz3qq7xG+RTPx7vkAH/QNt99cUHe45ozFchJBrZbVwaGhu3NwZL8Wm7gUtM1dUJ
         kAqJB0jHXe2OZrrlScDIvg+JKM7o3hmQjOLYc5TRfkF1iCSqNNtw3QoMnBxfVnX/JxwC
         TN8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=H4VDtuCl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VBBI8T3/iBVlZbQ6zqHd9fjeH27JXt28q5tPlkj5N38=;
        b=sX0UB8I8DfohY/2vGqt/NC0JjKMGh8gjUbtIbGKErM0GMB/qBUHuwpRI9eNiyab29T
         5iO0DQljpbpFL/0TlEm/rQwOMFjuUff/Sfhv/5Xc9f4JTtcEWCNdr+bq+7kKBR6bcDuP
         HzbF2QKfPrHoopHyVk5NoinLE53C3phF7K0itwYXzesEjniAyEGGm3Apyqld9rQ5RQxw
         BZoTAV7RNQeXy1EbCOL/uaQ1FTRNGMNkkh3ZFcHbH4b+eY7+HzEDuT/OAak+Q09iQ9W8
         IA6ouHsTG1PjsAyPpsZkpg8oKP790+k8TLxbvKZ0qhDVRzpT5YXDGPYwGRG2fKcgBKQT
         RVjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VBBI8T3/iBVlZbQ6zqHd9fjeH27JXt28q5tPlkj5N38=;
        b=Cm10x2cLIqzE5cNmRiGPvlHojfKFGbekmgqqoPcJivKUi11/OUCRfpFOyniOHaq4Rr
         7N31R5LQJLlhl7eMSNPiqV3ylI+cgy3a7uFZUgo400dxph0wW3m8FfOw6SSvqQXT3Sw0
         rYGFs4dX/0uK7snoPiq2ZepgZE/0eQF8xcG8xXPOkBdguuzl2VaDq9IrzWzPaHVwEv6t
         kBFB5pap1WBjhTnhKoGGph3x+quizRz5rbyR2ZWxvTPkDrYweN+6vPOhOJUbx+7U6xqn
         dB6AyvGFugICkHArFEcAudKu/1/EzXtHG7nOk8RYrP6rEiiy5tTxgE/lRoCV9CvrFWUz
         Zw9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RNNo9ON/+47kZgTVaU0ezNVXWr9PzrnH9q6f9KS6VmL9cJGqq
	Y1eVrHIr1/2JRmJ+KGyIqDs=
X-Google-Smtp-Source: ABdhPJxlw9PJ7akwGM8yrmh/wSecpldQzXvF+qXidAxwNPgysPiurRgFOuHGTHJlJG6oxMG51+OfFw==
X-Received: by 2002:aca:1005:: with SMTP id 5mr12134231oiq.85.1623721631720;
        Mon, 14 Jun 2021 18:47:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3807:: with SMTP id f7ls5729689oia.10.gmail; Mon, 14 Jun
 2021 18:47:11 -0700 (PDT)
X-Received: by 2002:aca:b784:: with SMTP id h126mr1365292oif.98.1623721631331;
        Mon, 14 Jun 2021 18:47:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721631; cv=none;
        d=google.com; s=arc-20160816;
        b=SsKqg+/jTdeXVezfzCntLMBiDPaTg0S+vT1oz+ylgS4hnW2Wkn+gZnxravLDd44ZWp
         JRYfDVkcSKPAIwAplhZtZts9uoMXTib2fE01KGKKyO8tK++/gQGXRpaOxA/qrUEmAscS
         MzskrrcDwG9kZVkZG8581y6E2fnT8mOx8K4ryY88YjzdqaD/egy+olHt551V+E9s47OR
         NATrv30/VwAihSgWy+pshn51zW5eYD7ECU6YNkIX9j/bURia3N6T7a4nixFZgstfPNPM
         ZGrrvaHKpf+HZFyU3EtX9fU1ImHAhnBsxlfhyMvj24T0wU5mDq4te/mu3oXJsu25Kuw9
         blZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Ok1AmBf91H6Q/IhwbEd4jKqOoWLU/Xv6mOEECK2NByo=;
        b=Fv/jw8JsG40oP5nJuAI6uTm0kKledxyULn575wRxOxvbFbh3AEUecAIZY0iZy/F2Ke
         AJd1Ce5mtX1PFpGXTITi+PZQxxTEDmWYRQeV+BYas0Us8RK2fpMcowHompgdjpHBXYQ8
         xb9+lp91mKWgoNJFR0CNdEpU2VtD6hov19kAK3ETg6oYkV8+ZvaNhIF4kfc64C/ykESh
         T8U0/vrpyAcoYXZazf7OXF9BV/StMQMBkKtwMChIxw/Jv09V8LhSPFXBBeceetYixwHt
         hUB9BhrKpD3kfXNquMr7AIpV/RaGdp7t/QpOFnHZygto3YMF6sDmgusjCmBPyIE83UGs
         ++3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=H4VDtuCl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id d12si100864otu.2.2021.06.14.18.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id fy24-20020a17090b0218b029016c5a59021fso804225pjb.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:11 -0700 (PDT)
X-Received: by 2002:a17:90a:8546:: with SMTP id a6mr22237711pjw.128.1623721630780;
        Mon, 14 Jun 2021 18:47:10 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id gl13sm628913pjb.5.2021.06.14.18.47.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:10 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 0/6] KASAN core changes for ppc64 radix KASAN
Date: Tue, 15 Jun 2021 11:46:59 +1000
Message-Id: <20210615014705.2234866-1-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=H4VDtuCl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102b as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU.

I've been trying this for a while, but we keep having collisions
between the kasan code in the mm tree and the code I want to put in to
the ppc tree. So my aim here is for patches 1 through 4 or 1 through 5
to go in via the mm tree. I will then propose the powerpc changes for
a later cycle. (I have attached them to this series as an RFC, and
there are still outstanding review comments I need to attend to.)

v12 applies to next-20210611. There should be no noticable changes to
other platforms.

Kind regards,
Daniel

Daniel Axtens (6):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  kasan: define and use MAX_PTRS_PER_* for early shadow tables
  kasan: Document support on 32-bit powerpc
  powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
  [RFC] powerpc: Book3S 64-bit outline-only KASAN support

 Documentation/dev-tools/kasan.rst             |  7 +-
 Documentation/powerpc/kasan.txt               | 58 +++++++++++
 arch/powerpc/Kconfig                          |  4 +-
 arch/powerpc/Kconfig.debug                    |  3 +-
 arch/powerpc/include/asm/book3s/64/hash.h     |  4 +
 arch/powerpc/include/asm/book3s/64/pgtable.h  |  4 +
 arch/powerpc/include/asm/book3s/64/radix.h    | 13 ++-
 arch/powerpc/include/asm/kasan.h              | 22 +++++
 arch/powerpc/kernel/Makefile                  | 11 +++
 arch/powerpc/kernel/process.c                 | 16 ++--
 arch/powerpc/kvm/Makefile                     |  5 +
 arch/powerpc/mm/book3s64/Makefile             |  9 ++
 arch/powerpc/mm/kasan/Makefile                |  3 +-
 .../mm/kasan/{kasan_init_32.c => init_32.c}   |  0
 arch/powerpc/mm/kasan/init_book3s_64.c        | 95 +++++++++++++++++++
 arch/powerpc/mm/ptdump/ptdump.c               | 20 +++-
 arch/powerpc/platforms/Kconfig.cputype        |  1 +
 arch/powerpc/platforms/powernv/Makefile       |  6 ++
 arch/powerpc/platforms/pseries/Makefile       |  3 +
 include/linux/kasan.h                         | 18 +++-
 lib/Kconfig.kasan                             | 14 +++
 mm/kasan/common.c                             |  4 +
 mm/kasan/generic.c                            |  3 +
 mm/kasan/init.c                               |  6 +-
 mm/kasan/kasan.h                              |  4 +
 mm/kasan/shadow.c                             |  4 +
 26 files changed, 316 insertions(+), 21 deletions(-)
 create mode 100644 Documentation/powerpc/kasan.txt
 rename arch/powerpc/mm/kasan/{kasan_init_32.c => init_32.c} (100%)
 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c

-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-1-dja%40axtens.net.
