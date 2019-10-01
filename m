Return-Path: <kasan-dev+bncBDQ27FVWWUFRBIXSZPWAKGQEBWOQV2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc40.google.com (mail-yw1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id A66E1C2D9F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2019 08:58:44 +0200 (CEST)
Received: by mail-yw1-xc40.google.com with SMTP id n3sf11302163ywh.11
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Sep 2019 23:58:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569913123; cv=pass;
        d=google.com; s=arc-20160816;
        b=Sz2eVF8e813h1F1uUyHf6smr6BMAtdW5XM1/QqZffNZHoDDo62dX8uTyX5WLjQFPKX
         wE9ZaQqYOWALiIGmKBuK0RfzuyJsOqUE1NFW5W4bFypkcJM5rPMtOvWFnpji/vcvv++V
         +lqXLvgameIwg13Tvf7JOp4z5NOCeMIn0kbbviqeJ7YaWBzKE17OTRrBePICE3pexVV2
         CuHHFkAar06Z9+/GqWiYKV5RXYtwBLRPa2m1vIqjSXv4N2N3F6E9qqQRQvLi0OAuWZ3L
         OKpVQ0dGDX59F11tnaSOjcKqJx2IAMPsPHvZeYo+T47Cchj8vbFfYjKlmnNArwVjv3VV
         bCfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NtH8MP/F0Mgjber1eHpkW5MwPshsO4KFSyaBDAav7Kc=;
        b=yqgo92iHE8bvVM59VTZ5Z2HVQIcGBhfpOvd60l4sNEzyrZ0yaHqDS/QcPYIQaGo0NT
         TsS3cH5y8hBivUuetL0vag+xMnzVzKtyJi3G2yXbmeoG31MzuXC/KNO7ta7KHkSt7qqd
         Qv6LOmfJT3hafRiZCdtLFWGgEkCZH1syWQjIJ63WngFupF3+XbPp+Md+6pWzZwCV2fv7
         wtr/9hhIzgBVIZ/KRg++coshB38ijzCqFQSPAAE3rvo1XIatEDBtaQxE1bH5T0FuBGv1
         fuZ1857dDlxJQtBJJcOC7UAnindy2+GKr7+VaUHCWfuj0wWHqxSKBdl5vag0rXYsSTDZ
         1XYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oq7mxXzD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NtH8MP/F0Mgjber1eHpkW5MwPshsO4KFSyaBDAav7Kc=;
        b=gDp+bsiKgOmB+Ek735j7EwzIFbXHjYsSwG5l8wQbEFRzjqg2/5A9h1r6aKs9M4PxF1
         R4IBiK/ffJGLqy32vpPDPVSeIg35IpxR3nFBv1Cr2SWXhcD7CS8I+eTv2UmW8dRyFyeS
         y69PR2gNeuE/GwFFDqqp97lTwtXe/IKmN0HSQllUlOOWGrNBD/LH+EDaxgqMwp130DqS
         EXEIugjQk9dlbbWjkBYeJb3mpllvhDTV6Z2xn4D5Ym96U1Yh5gA8lZHqVOL6vGX4V5b/
         hwxKJAY76bg4Rc9aC9I3gAyRu1gfdlQcl/TRL8NPKmxeEQVySu4CfGltD2kfHnradzUr
         avGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NtH8MP/F0Mgjber1eHpkW5MwPshsO4KFSyaBDAav7Kc=;
        b=DnI/yGpwqpj1AUVbuw9jLprS+5X7fFLLITWFO1UMiWRpyCv2NIHIM4vlbAZ+WCH30F
         Gge8P0dqrOlhVjpWt37tHprktZXZIbuA4cPHWUxTwgpamDSKug+O8fbdEBPNRzelgnri
         GeNvg7sWqYKZjvGMfx7GsrbDMWO0mDdBhv6ENuMe73iw6Kk/WjtfQCtqT28CQil31n8R
         djFABsinHmE47INLHkwivF8styzOO0FlKjOTfgiVrs8vrMi8ljqfaf8Z3ALhpGwYXOYW
         S4qqJDHWkzIfjMPXyBOAzG4ZP2AaPf4QzTyxw+ci4CGzC3Z3rl6VFQfLjydkMDKJsC5A
         C6Sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV3sXf3fUPFVHEiQ7nnRlz7e9w0NyNO0W7tampjimCznILk+f5F
	2VCmDGV9UkSZXN+nBalVYDo=
X-Google-Smtp-Source: APXvYqx8XeuTjzQdI0kT6QGAJ0M2nUafengOaqxWhO4oN44HParDC1G8DVymWspQvbG79x8xxuSwPA==
X-Received: by 2002:a25:8290:: with SMTP id r16mr6194804ybk.351.1569913123020;
        Mon, 30 Sep 2019 23:58:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d3cd:: with SMTP id e196ls2404774ybf.12.gmail; Mon, 30
 Sep 2019 23:58:42 -0700 (PDT)
X-Received: by 2002:a25:6fc1:: with SMTP id k184mr18130497ybc.8.1569913122665;
        Mon, 30 Sep 2019 23:58:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569913122; cv=none;
        d=google.com; s=arc-20160816;
        b=R2fnunJ607bFcP3hAWgbz3yAVwGujEBR+72TVL0kbD7Z8YJykXCMke0ZlHWbxekiTN
         xlWzpSJiUEsh4k6LLp7T9Vy4bitv/xQKoV+qzPzu/lxJrgzW93IifseQGBQxIZCowUmo
         TgrqkHrmPmn/JoeGvecpWEQJCmvfGi+JxyFi5vi9FLeCnhh827MHqolABgN+PybAi+Du
         jia4c3tXI8VXSeY0tN28B6xA0nXvjHWwZRTjIUR1xaOAtI1d2iW3Xr1TgYmZhEbUmSsR
         DrlFrdAzxLpuWsE3m0/teCYrmLNtUu/yU6bcElw0BZsJCr0coUAld2k99x0lK7j1nlgd
         iucg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=b5QJN2+41L3WFDMkHvmVhhmne8r1m1bjlvikNn9ZaWo=;
        b=QltiJkqxzjQQ4SmxIqAclhfVT6ml20FHcPzhVYm3927q+wufI9Vb3b5ALMb1AJ2kvT
         ktYoC54jJn+sLEgr1YlE26CaZ/8Zb4T+0W8LJDQ4PDKnI3WoQa0MrDl6rAGOXOiqYKbU
         WpM/rojTtZMGHqrh8ij47Pj0kNQ1Edz2Af39MdDf7ntcUlewvUEhuRpXaVjGvnUqpb/d
         lyRNjfkV5uI9Yc5QrVmxcubdNcf3Bo2yKgdvQh3D0YAm7FysBOGcNaPp0ASEetxDEUbl
         Q85eGkr43OLYbQeIkpXY8bU6ydP6PF3Ja6fnJaSVxvSHIYYzKJXg5a/GwenXmor+yvII
         jrbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=oq7mxXzD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id l10si1036700ybq.0.2019.09.30.23.58.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 30 Sep 2019 23:58:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id u20so4989694plq.4
        for <kasan-dev@googlegroups.com>; Mon, 30 Sep 2019 23:58:42 -0700 (PDT)
X-Received: by 2002:a17:902:ab82:: with SMTP id f2mr24901353plr.220.1569913121508;
        Mon, 30 Sep 2019 23:58:41 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id l62sm21800452pfl.167.2019.09.30.23.58.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Sep 2019 23:58:40 -0700 (PDT)
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
Subject: [PATCH v8 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Tue,  1 Oct 2019 16:58:29 +1000
Message-Id: <20191001065834.8880-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=oq7mxXzD;       spf=pass
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
v7: https://lore.kernel.org/linux-mm/20190903145536.3390-1-dja@axtens.net/
    Add a TLB flush on freeing, thanks Mark Rutland.
    Explain more clearly how I think freeing is concurrency-safe.
v8: rename kasan_vmalloc/shadow_pages to kasan/vmalloc_shadow_pages

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191001065834.8880-1-dja%40axtens.net.
