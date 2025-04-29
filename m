Return-Path: <kasan-dev+bncBCD353VB3ABBBOVAYHAAMGQET2Y2CQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 64ECCAA0110
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:20 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id ca18e2360f4ac-85b41b906b3sf636449039f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=d7YZU4ayvgQeHFVfyAw6844RBICC09HtLT0dl3AhFonysAuciF8lwbjb7+1geNffGG
         WVmSo9pmjWwqm+SN498/0yWaxpVKq8yYHRQy0+pqRK1W0L9Xdv6AblSQU4F2jf2XUrjO
         zaI51OTccBL4J/OFtRyiQ/LT61nLal8s466eRi3gRa04mq1U+BeZmppfqEep/gDSSl1W
         BPiO7eQBAfdwUqIKjFd8JYKBmzeT+tAkFgjyqWv+aVHdHX9dcbude9p7OHPqWEG25ENL
         ORq/OFIkD/QrAu5uaeao93aDE5X/g8SJcSL1EuUsEbfrmCbONI5swSqKJS8+fBq3QaO6
         P87Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:mime-version
         :message-id:date:subject:from:dkim-signature;
        bh=em2o4ppPvtg8PHsBnT92WIwCpGpgAGm2/DYy3BT5BT4=;
        fh=F5GrIUallDbegApYB97gWlwBLkenE5uNqocVn3zZmtw=;
        b=cAJ0DT3YGsdTkYt+Tcah2I6m73Hh7PQ8CmetAww8qNYGfxngoQ64nKXBdhlYsXuKk6
         qHx8PNNUI73YSVUYvOpxsFUZmWadmfAgIvfvNYLNVEXUgJJaxmvgeEudjbIU6c3dyJpr
         qIO69zBolBkgcp75tLmHLXQnriZ50X1ZZlj/SxPRpgjPyyIJjXMbbLYwFbbAbiAcNn81
         BY8iFnLt5WqW6qdl7qooqJdmjcx22xAo9Xto2+i55bPPkm2vCoigQ6cGmlM/x0jjmLWP
         YJZR3a3DnPbeYqudfO6GLckPVd/83nTK9Wld5yEQElX6MPysYEdBGlmKa4ne7o8sUedw
         b2AQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JrpjRytR;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:mime-version:message-id:date
         :subject:from:from:to:cc:subject:date:message-id:reply-to;
        bh=em2o4ppPvtg8PHsBnT92WIwCpGpgAGm2/DYy3BT5BT4=;
        b=EICSIZM9Qqa1SPlJs+6i6MM37EKtmB4GdWKS+3y2E4+KeEfab57MycbZnS0ZG03wsT
         5rcmD7YF+0IYS7Z7a8z7IHvgXq4bvJbxYX5NQsKgeH65JsWmMbEsh2wpUdZgrvONzt8+
         V5gY6k0KMxGpaI4si3/3ewpGihFgdwpESshb2rzf7D8pUiyb7kUO5dYYvROmE285tn9n
         nceIXyPqnffi9q9JAQMYsbJhMgZEhwfjqONk16PqFsIMd9nbnIwFvt3UUMqul7npbUSD
         CK1i66hIyHj/igd6nXRhDXBxd2V4HFsJTaI1gWVtO2DDo7DL2LS6o04CQHtLWOKuEC/F
         JCCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :mime-version:message-id:date:subject:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=em2o4ppPvtg8PHsBnT92WIwCpGpgAGm2/DYy3BT5BT4=;
        b=m/fghK2F2QnMg7fl34yoRMeZBuoAKP4wNF+94TU0cl+H8vx0ykcf0y+LPGjyYbum4J
         AJIb7Mwo1kobrtwg/v8heibU61tFSxVsK/Gr8exIfsGJSRdtAcaursv8JT3yjjRXZv7A
         nZ2TPhBJacPUl3lLBFPEMA/XDi5ZPasrjw63iW0yYrBwHKLSVdnFLSBeYSrkkRePQ+ye
         KFcMi7U5Cp2eBKswpxFpxSRb19ayJ37sRk9aDnw2m+IDOLYwpbS1BYBh2ICyxj4xfFTx
         pinvNxRA/Uyc8nuPzJSu4Lw5NvwkfD52h93A+ph97fA4si0WQbqrUJyNaZcV0Gr90xJ9
         sSxg==
X-Forwarded-Encrypted: i=2; AJvYcCVSMJgWDHiBceDyF8X/CyM2L6fcnecSUYNqePi5YU84mU6D6ZaShIrQ15vOvnjLwekMQuigOw==@lfdr.de
X-Gm-Message-State: AOJu0Yxt7NT/UK9HHq4jwyC3G/224VW6kNi/8Iot5O4hY0MKWQpRS6LM
	tNaye/2+BvQwYmn+OzsZrGT6xBRn+BtYEfDgl4DXP2knABo9gpRn
X-Google-Smtp-Source: AGHT+IEOOrZ2tdylLjz2AVIO9zyA3LIZnt3HIiuov6x4DiJrM7lqdvt3nm9jCQ2q2+GdzAxp/xyPfA==
X-Received: by 2002:a05:6e02:2195:b0:3d9:24d8:8d41 with SMTP id e9e14a558f8ab-3d942e05c9emr115284645ab.16.1745899578524;
        Mon, 28 Apr 2025 21:06:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHU+ZrZNNNZufUkScWLayWXws4CVk0L45xEmbdSX5V4nA==
Received: by 2002:a05:6e02:1a08:b0:3d6:d838:8f38 with SMTP id
 e9e14a558f8ab-3d92eb322c8ls39550655ab.1.-pod-prod-06-us; Mon, 28 Apr 2025
 21:06:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUH7mWMR2PwLUYfdI+ZcOsMH+VSuqVFxZAzIcWOVcJen4nXSTg1BJc4px5NTevP//hY1tl8uWJYJDw=@googlegroups.com
X-Received: by 2002:a05:6e02:214b:b0:3d8:1e50:1d55 with SMTP id e9e14a558f8ab-3d942d808b9mr105760305ab.11.1745899577723;
        Mon, 28 Apr 2025 21:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899577; cv=none;
        d=google.com; s=arc-20240605;
        b=Mplmo/YmsUepsMjkCPowdVW7Z6H+OH0GI/WRMz+oePJH96HrP6qLSXOUpkYG1DuFH9
         6Ic+qoymhR7S3NlQ1yt2ODxDQuUqPIQUur8tXKOaWUlSDyWT31EApW/jJ8K2TFJOx3G9
         P3qMCg5Hk/nBnl5h/9wlY0zwgEsSpRPtPLJgSfivdHkvVKK7NntZewDjGkRyfLtd0qjR
         LzJUVvyTV0n+vA68889qlE6XZhX5DrqzYo96XGyY/qiGkvWYtwzLmlXGGoVZUkiyyDfx
         TYVTTwodgf4FCRv/qX4JWB5Hpk9bnts5rxQmlVlKwLlvsgHByPSxlzhFPX6BLuWzaoTn
         la/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:content-transfer-encoding:mime-version:message-id
         :date:subject:from:dkim-signature;
        bh=Tq73bW0DEf6H7EJrqTGa0NkGW9/PD4sBLDN7G7TJNFE=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=JgSVGwXHKPbdS7f6CQbIscmIOWTTiT/nieDT7SDTaM+TbnJ44Cdu4Q5iVU64NrwjL8
         QKGZT2TwCXc3VBEyeVxZPmgSJTYBO3Yn+QKA7Z6o+ThG6S2/YFIT5L4H5/1W0/HETYbg
         B0KX5GOX9Lm+W6THSLsb8XhwRV2KgHGI6TevmzCdj4j7sX6tBvO3YHAxP9C4F37FWxdM
         C5Rdc2Qlrbx9Z4tQFfBn/Klq0Je6pxyaYY8zkeFwpX2sB2qgq7PenhDIWKyJdIhciJyg
         LSwhfKW+RMtE1CPyhA3MwmpqqN1sl6T52a0LvQywi9jfQDVOb3LAPD8SrbTmRc/fwsfV
         AQkw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JrpjRytR;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4f862dcc1fdsi21361173.1.2025.04.28.21.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 841A6615EF;
	Tue, 29 Apr 2025 04:05:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id AF344C4CEE3;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id 98151C369CB;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Subject: [PATCH RFC v3 0/8] kernel-hacking: introduce CONFIG_NO_AUTO_INLINE
Date: Tue, 29 Apr 2025 12:06:04 +0800
Message-Id: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-B4-Tracking: v=1; b=H4sIACxQEGgC/22OzQ6CMBCEX4X0qiXdpQXqyQTCA3g1HhBXaaKt4
 S8YwrtbG0/G48xkvpmF9dQZ6tkuWlhHk+mNs14k24g1bW1vxM3Fa4YClZCQcuvqcXDG3o0lnpM
 +a1KJkgqZrzw7upo54I7sUBXs5M3W9IPrXmFighAlUEksc5BQlCWWYvPFAwgFEuNco0458Kalz
 9A81nY/Wn9toKaNG/cI4AkD7P+1CbnglOoaM8hUIq6/gHVd37l4dtL+AAAA
X-Change-ID: 20250416-noautoinline-8e9b9e535452
To: Keith Busch <kbusch@kernel.org>, Jens Axboe <axboe@kernel.dk>, 
 Christoph Hellwig <hch@lst.de>, Sagi Grimberg <sagi@grimberg.me>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Yishai Hadas <yishaih@nvidia.com>, Jason Gunthorpe <jgg@ziepe.ca>, 
 Shameer Kolothum <shameerali.kolothum.thodi@huawei.com>, 
 Kevin Tian <kevin.tian@intel.com>, 
 Alex Williamson <alex.williamson@redhat.com>, 
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, 
 Masahiro Yamada <masahiroy@kernel.org>, 
 Nathan Chancellor <nathan@kernel.org>, 
 Nicolas Schier <nicolas.schier@linux.dev>, 
 Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, 
 Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>, 
 Vlastimil Babka <vbabka@suse.cz>, Suren Baghdasaryan <surenb@google.com>, 
 Michal Hocko <mhocko@suse.com>, Brendan Jackman <jackmanb@google.com>, 
 Johannes Weiner <hannes@cmpxchg.org>, Zi Yan <ziy@nvidia.com>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Peter Zijlstra <peterz@infradead.org>, 
 "Paul E. McKenney" <paulmck@kernel.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Dmitry Vyukov <dvyukov@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
 Juergen Gross <jgross@suse.com>, 
 Boris Ostrovsky <boris.ostrovsky@oracle.com>, 
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
 Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, 
 x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
Cc: linux-nvme@lists.infradead.org, linux-kernel@vger.kernel.org, 
 linux-mm@kvack.org, kvm@vger.kernel.org, virtualization@lists.linux.dev, 
 linux-integrity@vger.kernel.org, linux-kbuild@vger.kernel.org, 
 llvm@lists.linux.dev, Winston Wen <wentao@uniontech.com>, 
 kasan-dev@googlegroups.com, xen-devel@lists.xenproject.org, 
 Chen Linxuan <chenlinxuan@uniontech.com>, 
 Changbin Du <changbin.du@intel.com>
X-Mailer: b4 0.14.2
X-Developer-Signature: v=1; a=openpgp-sha256; l=2639;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=V+YDfvUyGy5qM6nqWNSGKKulp2fwuDLB1gLxIkj/Hno=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAt1A5qQ0LESAzipTR7awHbnQPj78n5atow0
 tiwIctZ69yJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQLQAKCRB2HuYUOZmu
 ixgVD/9iV08f+Vs6eS/LbQDJ7q+zM9yfQ97NvSrbN+MQtFOdOOX/B9DDWjz07bMvwZeoSrnuWD8
 Hp2NCMdUMvn/XAg8tY/cC0FeuznQPAg5DIqOw8e+jaILOgWNROimjgixLuhTr6WiaM0KrcZDHBL
 OCFiXr8cJEoV5nmHDZpwmsRyfhwIkYxKUiqVZvxYPnX5Mq0jdE9cE129yrf++c0rJHV7tiA9m3m
 3Dgfo4EYCqhLMhujPTgQnqrtD260ZB/BDOIDT/4pmvjfuO7SVexQMqaZ6VD9Zv6g3IpgG//tHdW
 YqgmY8n2rOMhJaDXULwLGpK32HY5uEPSykT3U8ytrJs1vPonlNQ+Yl1jBUOMiJd28s6gMWhAfNF
 7DhrCdUVPQITzQ3hp7+hMavCnibw1bsO70Q1Jyoe/HbpVw+jgqinhhqNY/q95Z3kUEjgZ70wbQz
 J4+fpvQceoLTw3aPUBwT4AgmFYItGhMG/oWciNlmNPDr/PkMdez2OuxVUBnKvMvmy4yNtOyF82f
 vhAi9OSPoii6ldf1OcZLCU7qEMXlU9dM1KhX437xOQ4ZbW31J0vPnuqxW9b5BE8+hsNfWWLyt/z
 sTJSwkwcY3PBvFzx6dDyI4Q7JC83rCdQ6Bpw8f+o9IgK2kSIMrG0t4mrxG3OSfZB8NXalFg40yK
 bumZ9NWzca7x0hA==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JrpjRytR;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender)
 smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chen Linxuan via B4 Relay <devnull+chenlinxuan.uniontech.com@kernel.org>
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

This series introduces a new kernel configuration option NO_AUTO_INLINE,
which can be used to disable the automatic inlining of functions.

This will allow the function tracer to trace more functions
because it only traces functions that the compiler has not inlined.

Previous discussions can be found at

Link: https://lore.kernel.org/all/20181028130945.23581-3-changbin.du@gmail.com/

This patch depends on

  [PATCH] drm/i915/pxp: fix undefined reference to
          `intel_pxp_gsccs_is_ready_for_sessions'

which can be found at

  https://lore.kernel.org/all/20250415090616.2649889-1-jani.nikula@intel.com/

as well as

  [RFC PATCH 5/7] RDMA/hns: initialize db in update_srq_db()

which can be found at

  https://lore.kernel.org/all/FF922C77946229B6+20250411105459.90782-5-chenlinxuan@uniontech.com/

Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
---
Changes in v3:
- Fix some modpost and objtool warnings
- Try support clang as Bart Van Assche suggested.
- Remove architecture depends as Bart Van Assche suggested.
- Link to v2: https://lore.kernel.org/r/20250416-noautoinline-v2-0-e69a2717530f@uniontech.com

Changes in v2:
- Resend via b4 to correct Message-ID and recipients.
- Update commit message following suggestions from Jarkko Sakkinen 
- Link to v1: https://lore.kernel.org/r/31F42D8141CDD2D0+20250411105142.89296-1-chenlinxuan@uniontech.com

---
Chen Linxuan (4):
      rseq: add __always_inline for rseq_kernel_fields
      kcov: add __always_inline for canonicalize_ip
      x86/xen: add __init for xen_pgd_walk
      lib/Kconfig.debug: introduce CONFIG_NO_AUTO_INLINE

Winston Wen (4):
      nvme: add __always_inline for nvme_pci_npages_prp
      mm: add __always_inline for page_contains_unaccepted
      vfio/virtio: add __always_inline for virtiovf_get_device_config_size
      tpm: add __always_inline for tpm_is_hwrng_enabled

 Makefile                            | 16 ++++++++++++++++
 arch/x86/xen/mmu_pv.c               |  2 +-
 drivers/char/tpm/tpm-chip.c         |  2 +-
 drivers/nvme/host/pci.c             |  2 +-
 drivers/vfio/pci/virtio/legacy_io.c |  2 +-
 kernel/kcov.c                       |  2 +-
 kernel/rseq.c                       |  2 +-
 lib/Kconfig.debug                   | 21 +++++++++++++++++++++
 lib/Makefile                        |  3 +++
 mm/page_alloc.c                     |  2 +-
 10 files changed, 47 insertions(+), 7 deletions(-)
---
base-commit: ca91b9500108d4cf083a635c2e11c884d5dd20ea
change-id: 20250416-noautoinline-8e9b9e535452

Best regards,
-- 
Chen Linxuan <chenlinxuan@uniontech.com>


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-0-4c49f28ea5b5%40uniontech.com.
