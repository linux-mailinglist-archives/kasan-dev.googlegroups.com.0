Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNH433WQKGQEQCYOL7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DA49E7F1C
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2019 05:21:09 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id y6sf9730772ybm.12
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 21:21:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572322868; cv=pass;
        d=google.com; s=arc-20160816;
        b=CocYK1nHvOAUkhZ+Lq8UQ937ss3CWRNKuHgDDbfKWeB6Jt9oXnYxWOHlr1qkRYSgXy
         4Y3PVUS0zDYFt8l1zZcpFysLQDasdUtYldoG/vz+qNBGuy9497zCXiDltreHbrQuAKVI
         XVogmH14Rg3mVFfHXLT49u8JVeNguITX+iCshDZAAjr7O5sNDSYUBl6aH9eE2pkOjTAN
         VfQ4lTPtx5/1l/KLeOGHhqiXpdMNdQujqM6s5BUBz+B8oIxr8Vx5fPf3qsqv+vPXJZOx
         K7qut46zcLtdWSJvC6OcIsWizq44B1DtIbJlDk/kWRI/fEMq2Q7K9b/lXqEcOVfYvCT/
         Y8gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Su4xDNdwGThVPvEEgL3n5gyzhfao3q/7S/hAadcxupw=;
        b=gO20VA7dES1Sd1pyTNoZmU83dAsrCnyMp/VxrHuPE67esBZnCH9+FdWoqi5pbyRhjj
         nT///9C18z5zjccy5jADYfO5GaH/SyOWU+JfygtWDGIncxYj/Johwu5a8V5G0WvDUb6j
         8pyGCjZazUSxwldtc1drDYtTyTRbINOWCBuwfPmNXgIyMvT+YyoojzTR7q0UICVosXjd
         gX65HK65ZYfVB1G3Uv5hfeolcVVltsw/Zd3H4tbOOhHzCWdjQfvfi9yXUhw1wOHGgvYD
         W3i8qvwXUoS+tISLS0jS66Km82G8+lPf7EokQFPc3kaeD7Xs7ianVmj4LZSMC0owtHRF
         jsDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kjSFsu5l;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Su4xDNdwGThVPvEEgL3n5gyzhfao3q/7S/hAadcxupw=;
        b=DDt6URHxBZyQIpJHWWzf12jhhtlA30N9sioSmP0S91S9SA8HoGR1GNPjCgcLN2v334
         EVLbDbfZIcMCNMbf02g0C+KfFiCk2VkM94TwZLawcHkvEztbTSRbvXFC1bZy04uUBCyg
         6BM05E4/0b5rGgxuHe1kcJdefFix9ZjhI5GKdbuvvzoEG29U2op4O73YjiK4abqykc22
         XmOZLg6TX8S9h8J3KhuHaZGeNBpibkZOzY1Ik9eVDHDs4OOJ667RNejG5XwLukoukK8q
         DbaNZIAZ0eB0dz1fZZyExYjF/PvMjTm+9VLyDu06fAGxYxZm+HVeI3plS7fP+opGlzCq
         BT8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Su4xDNdwGThVPvEEgL3n5gyzhfao3q/7S/hAadcxupw=;
        b=gL0k0yuI1McMDkY/ZO2Y1Uz77UpOaKuobOL1acrViFL+yJxpI78KHNYk8tIrAf6jJ+
         zhbJP146RyigQTkH9b7pxDPQX6hnivxQd9xqjFQTjOU6jK+hNi7ACm9bfWhPC2FnV6cT
         /OugNO4+dwKaXHBQV1B3FSUBYqJ1Rl1bmRfnuZGGGmMIhVS762GkDWsg+tb2sMJtKaAk
         DDh3G49lY+9D23mPNZn76DxpLHpTpvCh7BrLkNXcXncY84FHLTkFk5yyjaNTqhHtv/FO
         kiPW/BwDfDUAngLnNV/Mk8fkK+BgQzqEHsSFMIW9IZX4WJg4liTAGWwxyWHA1eJ447Wl
         uSfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWiLpbTs0XjQLxHQx+MOCJ7bP6o31u66TQk5+d0f2TxDi5eOc3I
	h6ZRTbuzBNfF41ElnSQgZtI=
X-Google-Smtp-Source: APXvYqx+1JVvgWXdrMaVXESX1QLnUXvJSiCWBYUphhUcOqHc2o0q62Hy+4WhzSN5IksSplcE3jgkug==
X-Received: by 2002:a25:600b:: with SMTP id u11mr4077552ybb.437.1572322868217;
        Mon, 28 Oct 2019 21:21:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5986:: with SMTP id n128ls2371438ywb.7.gmail; Mon, 28
 Oct 2019 21:21:07 -0700 (PDT)
X-Received: by 2002:a81:1a92:: with SMTP id a140mr16083374ywa.241.1572322867596;
        Mon, 28 Oct 2019 21:21:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572322867; cv=none;
        d=google.com; s=arc-20160816;
        b=eGslI7gvx8avef8NOWUkLfknQ6Cy5AGH1GzSG2Zu0AuWuC7NGQrdxQI5ngUrtK0Ca/
         0fVfNa/mQvbfIMtl8/QEq8e2m+1zDUq+Qn8F41qd3oLbBsYybr9qaQlpR+8hte7azBG6
         FBcYTY8Cc01tMuxatPOI6CilWp+xaI9zikzzW40oQ6+pt4sgqvkV90C0MsB9aV3RMBka
         YEWsa89mNi3zNbhvdaTICgbx4Bj+eKwiwwNCfKqVi0089LRcE7Q0NKiPndc7A7Tw/tjB
         JViyNWe3721POsStjPSr2wSUTt7TgcOppbiIgaHtFYmmtXFYPvW4dnpqEXk18k1tWDZ0
         vA2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=YQ4pMzGN2GdDuONqdL7jGr9z3ckVwTP2I22ymxPUf70=;
        b=c09rTE2A5JmdpRSCBlOY0ZUvTdmRYNiMLBX3dZySu879o0MGUQxlK2o/ST1cbkVJTr
         f9SG6qwuCB81B8BckMzzBnS1Sf4GX2fWj9OnbM/+QFrlUz+GjddnzcFs0NIaM25QsVwx
         Hr94XeNQMvugGO7IZU60D+nTuOWVjI5QrnYLClaVVwZuyDfJZT25EeNVv+Q1d78CJD04
         A4hj9gtecgRPO7NLeJqDsnZincIvxsBRvceYrOedQ0/aFlQChEnB2uiRl5mUt17mpR+Q
         uwAZJEi0WtjyD+jnP3CGWlZaTITj7OMKyPUHFQiNBpnp3+q3a9My4Z3XxcSj6OLYzAqk
         EvQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=kjSFsu5l;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id p140si90886ywg.4.2019.10.28.21.21.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 21:21:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id r4so2907120pfl.7
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 21:21:07 -0700 (PDT)
X-Received: by 2002:a63:311:: with SMTP id 17mr24417658pgd.327.1572322866102;
        Mon, 28 Oct 2019 21:21:06 -0700 (PDT)
Received: from localhost ([2001:44b8:802:1120:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id c1sm1013409pjc.23.2019.10.28.21.21.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 21:21:05 -0700 (PDT)
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
Subject: [PATCH v10 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Tue, 29 Oct 2019 15:20:54 +1100
Message-Id: <20191029042059.28541-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=kjSFsu5l;       spf=pass
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

Daniel Axtens (5):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC
  kasan debug: track pages allocated for vmalloc shadow

 Documentation/dev-tools/kasan.rst |  63 ++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  60 +++++++
 include/linux/kasan.h             |  31 ++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 ++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 ++
 lib/test_kasan.c                  |  26 +++
 mm/kasan/common.c                 | 254 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  53 ++++++-
 14 files changed, 522 insertions(+), 13 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191029042059.28541-1-dja%40axtens.net.
