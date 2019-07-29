Return-Path: <kasan-dev+bncBDQ27FVWWUFRBXMB7TUQKGQERJ4XW2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D47478DAD
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 16:21:18 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id p19sf6392811uar.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 07:21:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564410077; cv=pass;
        d=google.com; s=arc-20160816;
        b=hpylZgRz6+NnxU80cTmiTGEq0t9rXlE6GQZmcIXtsv5lB1wELM8sm0sZw8aLs4H6vW
         GuNWFXFvVfmWuzTqh+k9s1d9iZtJUYvDimiA8qz9SK2qn+2rRsQsooZvTnB47SFml5vt
         XbLgbceYtfxbFQcVjySIO87PJTLscCJpMz5Lx95nDYdU3UVngNMB2GcB/w/K50mfA7wT
         Z8hVEuObD1UU/8rtyqXdveM/OGgxzspo8JukbpQ5LSzY/He4ooFAp/tX8mPBWjI/j4TP
         tvWlws4FTNpHWm9Ww3Sxvr4Kgj72aWW1I4PgjCrM9TrFkM4GxTPtx42vcZOa+w0dFo20
         od5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=83rlO8ij4Xb7dNSU9vr0EaVbKQJ/tUIyPc+2t1pHBgs=;
        b=zPvAeVMDT19NotubVL98eASIxmpyRGxD0W1D1jwrPp/35+lvcdpl39W7s6nvk5n9TC
         lhVm+REzi1jT7y27Z+D2+IZG+6RcwPdXLBRYirE/7l4T0u4CILSKDsYkYqfDsRp/B/xM
         mLhN/BiVAgEsgUfmzKnTt/qwJ5JRsImhPo5aQFaDl01peGSNA9W5jua2yryscG/NbNm8
         SLj59n8d+FKzbgPBGIa3YbBUFxuIKmDPMU7AayE/UvTVAEtcdo1lAYMk3s7cXrW2qpp2
         vsk0MX4lIID123xEj13bdiM+NsYgTv5Hfq4xcAv7Qeecs7pU9C9novk60DU5jouETdjp
         4bRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=h0ssI4U9;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=83rlO8ij4Xb7dNSU9vr0EaVbKQJ/tUIyPc+2t1pHBgs=;
        b=rYfA2QKlcqJIstY91Z+DhVO+xxf8JcYZRyz3lvrVemRENhhpHyUfEpKWh3SlCDY9KL
         LwoiA+EwVBjS9hddaVgrVOa2W/4dhcqRsV8/tCNiO+AurKdZXBVlT1cECIDUcUP4rSTe
         WDdJ4eVI4B3Ay7YQzC9lX+YTM/f10grOPMFJ/wo5kfMk/Xt5CjWtnS5uq9xND7fcWxt8
         c4zp7Xwk9m6Ni2kagn+489qksXdZqghvjzWxRxdzovoH0OGZI6J3M+mCabeiYZ5SDHhR
         JeOyPmB5dd4qzu+UUYVjsFJas/dM4+9aew5ICbLIkevfkA3NorS0S4TRMy3ws3/f0jOy
         I2TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=83rlO8ij4Xb7dNSU9vr0EaVbKQJ/tUIyPc+2t1pHBgs=;
        b=DZthQxo0YfkU9w8lWIAqoQVdaiXFLbVTBS08Swd3q1CBxbxCaKApqxB+ZA/BVGAd32
         FJ7gAmgCbhYKAzyqg+mW9P1MeEnMFP12p0ITGuf7maSN0QkeBDqeoyXKA7nXVC86w+ot
         /4yC+lhByZQbrsvlXWM6q/HORniNXvnyL6A1LGy2Kc2+vE7kjcfcIPGJSGZS1zhjEVtb
         fBdZWP4NjRPqfPUdwZe8OAPIG4xFFOKgOYvKb4ZhkHubLn59eVN60KjCty/4LjdQEUOO
         Zhzbtt8xAg9+TOreQLR9NOhZ0HVR/psZO4DTUPQMhpoKM2zNFRuSPsaUyMGIRSnGu+yr
         8aHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX0H/b4a5otXdenzegKUW5DUaJLS0VcKPdGtkdkHR1BAr9iTps9
	wpPyXizrlAK4mpGNNq5WMS0=
X-Google-Smtp-Source: APXvYqypft5QiWLuRQ0fD9ofKOWapqJPCemxul6Ie8dQ6pXDVDaDlJakpZoEYbkvr9k1q4j3vRTENA==
X-Received: by 2002:a67:8d03:: with SMTP id p3mr67466369vsd.173.1564410077130;
        Mon, 29 Jul 2019 07:21:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fe99:: with SMTP id b25ls7707349vsr.16.gmail; Mon, 29
 Jul 2019 07:21:16 -0700 (PDT)
X-Received: by 2002:a67:cf05:: with SMTP id y5mr47404160vsl.18.1564410076801;
        Mon, 29 Jul 2019 07:21:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564410076; cv=none;
        d=google.com; s=arc-20160816;
        b=ksCkOVp7td5Jp4H2dRWvLgn2cvObZjaSXZhMnZztx16Ww4L2C0ml74beKEHvj08wdr
         x/wOYnjdhrfialYoLGn98X8xRY+514s1kWDglUAHqdlPUHUHKweG/dEX+DTeAQEYhQtk
         M2dI70wV0ftqn91i4IQgxUdtjHkZ5rxLeloeLkhOAWP71NC7at34WwdZ0zBynbhthIHU
         n8nRDZHeSJEjztX9e8sNxCDFTfcnKcOWq9Yg0TIsfhsRE3KUddGerQdqzKDXrsSQn6s5
         vpSEyH4mkKcqYmuY305Un1rpPpPCa+JJ72UiNGn8UwqjFaCuUfakcw5Be+QjxwI2pEKK
         0K0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=MR80kuJNJTZu3hsDXBNA4q0a6EH0Ziu81Ow2DeGUsWQ=;
        b=r0hknZOg8wVX/rI466ZzWUT/GhvrYbJE4Cnr7DNcK/p3LdYn1ar0V4kLa+Ql45Gq+U
         F6K39mTQjtbKTqZ1X+ZEC5PYC6QwjikZ1jHJ0ORsK55o755Adnk70iyG7gUYAZop9kB3
         XfxjlGbpms/MyAnk8yWCvJGl8hTY7wKEvscMHx50lfe6xxRC8DOBenx1Gak4TfHJ5P2t
         BrOm3aUyNpYyCci0+rQVnU3vMwoOS+MT6WWvM78ut5ckv/PUMpK7XhFSMve1/bI1TgZu
         FfStUivJjhyt5RpyrPMcvV5W6j8rMO8CmhyjqqUoMQtWD7rqPs9GJQn+A9yW26qHgJjX
         3MAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=h0ssI4U9;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s72si2814565vkd.3.2019.07.29.07.21.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jul 2019 07:21:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id m30so28133461pff.8
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 07:21:16 -0700 (PDT)
X-Received: by 2002:a63:c008:: with SMTP id h8mr102953637pgg.427.1564410075414;
        Mon, 29 Jul 2019 07:21:15 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i3sm67061225pfo.138.2019.07.29.07.21.13
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 29 Jul 2019 07:21:14 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v2 0/3] kasan: support backing vmalloc space with real shadow memory
Date: Tue, 30 Jul 2019 00:21:05 +1000
Message-Id: <20190729142108.23343-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=h0ssI4U9;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

Currently, vmalloc space is backed by the early shadow page. This
means that kasan is incompatible with VMAP_STACK, and it also provides
a hurdle for architectures that do not have a dedicated module space
(like powerpc64).

This series provides a mechanism to back vmalloc space with real,
dynamically allocated memory. I have only wired up x86, because that's
the only currently supported arch I can work with easily, but it's
very easy to wire up other architectures.

This has been discussed before in the context of VMAP_STACK:
 - https://bugzilla.kernel.org/show_bug.cgi?id=202009
 - https://lkml.org/lkml/2018/7/22/198
 - https://lkml.org/lkml/2019/7/19/822

In terms of implementation details:

Most mappings in vmalloc space are small, requiring less than a full
page of shadow space. Allocating a full shadow page per mapping would
therefore be wasteful. Furthermore, to ensure that different mappings
use different shadow pages, mappings would have to be aligned to
KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.

Instead, share backing space across multiple mappings. Allocate
a backing page the first time a mapping in vmalloc space uses a
particular page of the shadow region. Keep this page around
regardless of whether the mapping is later freed - in the mean time
the page could have become shared by another vmalloc mapping.

This can in theory lead to unbounded memory growth, but the vmalloc
allocator is pretty good at reusing addresses, so the practical memory
usage appears to grow at first but then stay fairly stable.

If we run into practical memory exhaustion issues, I'm happy to
consider hooking into the book-keeping that vmap does, but I am not
convinced that it will be an issue.

v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/T/
v2: address review comments:
 - Patch 1: use kasan_unpoison_shadow's built-in handling of
            ranges that do not align to a full shadow byte
 - Patch 3: prepopulate pgds rather than faulting things in

Daniel Axtens (3):
  kasan: support backing vmalloc space with real shadow memory
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC

 Documentation/dev-tools/kasan.rst | 60 ++++++++++++++++++++++++++++++
 arch/Kconfig                      |  9 +++--
 arch/x86/Kconfig                  |  1 +
 arch/x86/mm/kasan_init_64.c       | 61 +++++++++++++++++++++++++++++++
 include/linux/kasan.h             | 16 ++++++++
 kernel/fork.c                     |  4 ++
 lib/Kconfig.kasan                 | 16 ++++++++
 lib/test_kasan.c                  | 26 +++++++++++++
 mm/kasan/common.c                 | 51 ++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 15 +++++++-
 12 files changed, 258 insertions(+), 5 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190729142108.23343-1-dja%40axtens.net.
