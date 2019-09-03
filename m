Return-Path: <kasan-dev+bncBDQ27FVWWUFRB375XHVQKGQEUSMRA5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 91B77A6BF0
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 16:55:44 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id e2sf19198296qtm.19
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 07:55:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567522543; cv=pass;
        d=google.com; s=arc-20160816;
        b=O4LdW0J+eO+LNUiKwcQzodDDkJX2UKQM0yIOyNztv3g2uGpYdWSUnEYJweVNY5l7Bi
         lFuTkU0rZeVXi2KbWoNncWYm+gL4pshb7Rs+XCSMoi1t2pxIOfL2hNEgfMjOIsJluUDI
         1rGLXRhW7pJ8jIfIIlf1SBlqrJ3JWHNIvkPKXQVtHtcO4lKldsI5nRh/kR7Cncnqt83Z
         WyH0+uTQ+a3b5mTnGYi7l+md0CdVIe4EAKQpy8jl9S64PCdhjCtWer3KXtNNAfXPinVj
         ld8wjdSd0Imb5ZPniDvtZbqrOzq1uorclYaPQQbJGGr4BPmeLRGVGekIPAwOSGxYGFvN
         hb1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=XwOSEOrggW6iiMgWcI/f0OEov3E8yjni+AJuDxvaalA=;
        b=PKQ3FkPSnYJN5ltaCSVLR1jgL73Z0iICfd4qm8ziYJHD0FlN6MsDdeIPm6ssjCFIh3
         r2Z1d9eGmkSj0gTfsbp7YeL08R/Bo9BTYxk0aSjRFVfivMsHxxpbhWAC1LkAEdeFxiY+
         wOchlQcdoJoCYppSlB5OR/paX16N7rGdzAdmo69pSAHyRgpEkEIdOlffdFAZNlEcMze4
         I0NTIQIJ/+NNrtbZD+2P74DFSszHNCV96+pWiHeUUvDTArMZdPfkve1vsUpzAyPk3ps8
         8h+qTjbudMiPyD2MC0zKGNeKMkDyV3JjTtEnfDWbQjhhTZYny0sIekhvpiQZphY73Rc7
         ILjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TdUwLWei;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XwOSEOrggW6iiMgWcI/f0OEov3E8yjni+AJuDxvaalA=;
        b=cxa14jBlDkfhmaSq+kNnyFzLx/OfS5oy7SMk3OYNVPKIFmEsUrdFGLCPztd8pR8gpe
         59Xc/U/1bXR9z3KNf103WenuwGsYjvORnPNwYIcZvO6vpLs6USX8nnimZbsbR4IzYviI
         PlJ30oQ3giPYvmMkmnN7S8NB+nnKF91aWDEz8HkKy+n18L81zjxrJ1Lt46QqcN+UiJ8C
         D9BA4WCbPmwxaln0Y/hgGLETjTOKPMTRo947JxObvJc6aYZCaNpKcGMXOcy1KKZ9XNDX
         +1E1zRWl5tFzTo4z55O0SB3dcHqQ4EOSo9el+0+xIRONm9cSiz0XbqPZl8oJScTeRggq
         DoWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XwOSEOrggW6iiMgWcI/f0OEov3E8yjni+AJuDxvaalA=;
        b=EWaYv+3O+6ijXN5w0S8rzisaX7YgVUOks3pB+VZbwUPYlSfw2PCicZqqWB2meh9blF
         f5COlPx3Nu7O96jrAJcxTfNBizxw5E0BQtqcCZR4CDe7aKLIVWsfqNokzU8R0MiwszFF
         1YCblWyVKODTDgA5iLc2hgFOF9H/zIxfTIWzWqjtxbVVb19p/cBvAGq3+OLZ346dUtKf
         7OfMJbP9cgCP2AqdZ6eEFKoJC2mE8sSloIzzag1jIPtw/w8Q+NrAzGyfR9g8Fiix0axt
         XsP5a+Jldmt7pArhiMdqls27/f2L+1XBtqsJ/ioCdQ7cuMi9j0Vdvh9rTPeMUX1NBmV7
         Tsmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVWSNWh8IcMPZeD9Q+GHhESCAJpOVfyY6iIMie8gAPeOE7PgEhm
	6fMZmrGQmyjP7hAZV5x7iRU=
X-Google-Smtp-Source: APXvYqzrfATQA+t/Lk45sk2lOvP5CltuB1eDJ+iVRKt7oAIxx/Z0XM1eUewec4VEAP7S5+1+9GfvMw==
X-Received: by 2002:ae9:ef44:: with SMTP id d65mr30491404qkg.241.1567522543673;
        Tue, 03 Sep 2019 07:55:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4dcf:: with SMTP id a198ls3539994qkb.7.gmail; Tue, 03
 Sep 2019 07:55:43 -0700 (PDT)
X-Received: by 2002:a37:7cc3:: with SMTP id x186mr34695480qkc.169.1567522543415;
        Tue, 03 Sep 2019 07:55:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567522543; cv=none;
        d=google.com; s=arc-20160816;
        b=HYFzM7ikN6AohLXSNucYe7uZWzjj0A8GxNnqMUui4xTVdKQLKo56KCzYoQNmL+mKol
         JX70d7QRg73ZD1E+Gce5tXqClTF6jfTIiZ/iBxkYu2X8L2+L2UHxcFk1rD4cYSMSLReh
         uZq8VXglGrFtwdx+9XhRLopSy0gSlSPjdxZ9xLh10/Z67g2auGZEsp/SToHlttj7fI6c
         QwjKFTsQ9JBl2WaZ22G/fUhypsahVT8BH6fLB0pcYu9kGbs6W0evaXmWgKUeiXI4DPUH
         qGXD7/eNxn4p79YgUvuaQMESqgWAntZqWC+4mrCEbvZoUFuV7c5p+vav/qobzjF0o2iB
         Tlcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CZ8tuOmuka1RKOh9uZYxX64asskdg/IRNCGvFNDvGIA=;
        b=crflffj72ahZupTCMamfrAxjh+Go9zNyfhODrBys7ekD3Ml0RPP6wP6CSIGKvR74tJ
         T2oklEwwg3BibHjZOQqRXkZOA4LfXDQtE9sEJcFZWBiIUhOBZfBLz3rn+qi43NZHApbj
         jAOGgmRBU9iiRYovrUwugfBzs/UVgr/gDsvx9gmJZGUA+pBF0Hg3MFF2Eh9FxQ2+qUYH
         aJlYC8hAVThvtgsUfkaphzXvUDjiYJrbDIj03i1dBGkrQcRllN8T3fH+TdHg96FVmeVP
         Yab/NSqk/jf2yUAsZxxXQRMih3Oh6Z+xR6aBDuVmEgsB0u9Cd8HusEljy66H2cn3RXFP
         1saA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=TdUwLWei;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id u44si387456qtb.5.2019.09.03.07.55.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 07:55:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id f19so8001652plr.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 07:55:43 -0700 (PDT)
X-Received: by 2002:a17:902:543:: with SMTP id 61mr35725696plf.20.1567522542162;
        Tue, 03 Sep 2019 07:55:42 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 65sm15600780pgf.30.2019.09.03.07.55.40
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 07:55:41 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Wed,  4 Sep 2019 00:55:31 +1000
Message-Id: <20190903145536.3390-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=TdUwLWei;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
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
means that kasan is incompatible with VMAP_STACK.

This series provides a mechanism to back vmalloc space with real,
dynamically allocated memory. I have only wired up x86, because that's
the only currently supported arch I can work with easily, but it's
very easy to wire up other architectures, and it appears that there is
some work-in-progress code to do this on arm64 and s390.

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

Instead, share backing space across multiple mappings. Allocate a
backing page when a mapping in vmalloc space uses a particular page of
the shadow region. This page can be shared by other vmalloc mappings
later on.

We hook in to the vmap infrastructure to lazily clean up unused shadow
memory.


v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/
v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.net/
 Address review comments:
 - Patch 1: use kasan_unpoison_shadow's built-in handling of
            ranges that do not align to a full shadow byte
 - Patch 3: prepopulate pgds rather than faulting things in
v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.net/
 Address comments from Mark Rutland:
 - kasan_populate_vmalloc is a better name
 - handle concurrency correctly
 - various nits and cleanups
 - relax module alignment in KASAN_VMALLOC case
v4: https://lore.kernel.org/linux-mm/20190815001636.12235-1-dja@axtens.net/
 Changes to patch 1 only:
 - Integrate Mark's rework, thanks Mark!
 - handle the case where kasan_populate_shadow might fail
 - poision shadow on free, allowing the alloc path to just
     unpoision memory that it uses
v5: https://lore.kernel.org/linux-mm/20190830003821.10737-1-dja@axtens.net/
 Address comments from Christophe Leroy:
 - Fix some issues with my descriptions in commit messages and docs
 - Dynamically free unused shadow pages by hooking into the vmap book-keeping
 - Split out the test into a separate patch
 - Optional patch to track the number of pages allocated
 - minor checkpatch cleanups
v6: https://lore.kernel.org/linux-mm/20190902112028.23773-1-dja@axtens.net/
 Properly guard freeing pages in patch 1, drop debugging code.
v7: Add a TLB flush on freeing, thanks Mark Rutland.
    Explain more clearly how I think freeing is concurrency-safe.

Daniel Axtens (5):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC
  kasan debug: track pages allocated for vmalloc shadow

 Documentation/dev-tools/kasan.rst |  63 ++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  60 ++++++++
 include/linux/kasan.h             |  31 ++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 ++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 +++
 lib/test_kasan.c                  |  26 ++++
 mm/kasan/common.c                 | 230 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  45 +++++-
 14 files changed, 497 insertions(+), 6 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190903145536.3390-1-dja%40axtens.net.
