Return-Path: <kasan-dev+bncBCD353VB3ABBBOVAYHAAMGQET2Y2CQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8668BAA0111
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Apr 2025 06:06:20 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-401c6c3a66esf1845868b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 21:06:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745899579; cv=pass;
        d=google.com; s=arc-20240605;
        b=fFmkSPiuU4Y2vGN5WLe01HC3ZELrgH7W2ZsE2w/yyv50Cuk1GODkempjZ6WhpSHlCn
         ZllpuZpm2cdfM7dDXxOBkhntSsR4IoCFubGOOMLdVudQdLhpddkMmn8QrS/CDlKRFMec
         JPLyDwePAZLMtpiooy4idTCRNC3T1Djy0YzKkRDUhk1v9fcjVy+DoiyVKlz/G3jk9Df8
         10GWrId50IXJnkKfXggqpOD/JnQAYAjABbbKf+5l8HXcDbyVbaUJgc8sthfEOMPSrdjU
         u9UT8SROjrw1oMmrhokfWsh4+SlAOe2J+8XYN8pOqDh2iMNxi8c0KNvh7BT6AHH1/8e/
         6QdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:in-reply-to
         :references:message-id:mime-version:subject:date:from:dkim-signature;
        bh=r1Rtsce1uCAod1pkasf2YUzxlrbGy6ZGd+be8FDQvSc=;
        fh=XKTyub4Q47J5TmVq3SOROLJEPXX4kW13lyWx0QHav+I=;
        b=KN9gTBoLi/87xsuoQB5mMO59XPjkRY2LQ4PieV6wyEEJbx6y9rFl+/IIEt6iokf2WK
         ENEsgZ1DXo/Dha9uSIXWoqnrhz7boUWoJyltBV3M7uhP+vElZ1rS82z9MnpRzpX9DF+v
         5Lb6He5a7jcBwHZRkONlqBRLS8fxTmPRBaG8Zw8o4hNHvOHbqeMOjBbuSzmn55M6I3Dh
         ZoxN8ABBaHf7zKgaKzLvVG9UT8s9YTe5xydKcL33C6wXjZxPkjHaoyyA/ynME0vYuh2J
         CQQInCHZwgFkvHrxTfQegnmffSICNGRuLs0Kss8PwkipHBZLzNC34w3ISfhTOdA/C+D9
         Eu1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=umnHgPjx;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745899579; x=1746504379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:reply-to:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r1Rtsce1uCAod1pkasf2YUzxlrbGy6ZGd+be8FDQvSc=;
        b=FlyYnuPVhX1JN98rmkBSnNfk6efsSulSAsxWj5YchYEZ6sbKec03WlD9iFhAKQegRw
         JpyhzUUml4PU2xiJrt7jv2dsgcHLFTCPtWXJMgaY8LVlf0v6qrrDPYE2Z4WfJYaAlf3a
         a78+Rtcee4ApGqj43iCkaN7o5xVkOJtmqb6pL/gDQQI7CK2vw8Fiz68J3/WWERzmQINO
         jCsfgPbOMdr1yNERdeujfZZ4f9EnEQJ4SyXZjd5rwYlNg3hgwPlhScg3ZQHWKO33nel3
         t+d1BOpLR7MXQ6SynKvT88tqatXCNvmx7xmAkm2DIxCs+98CIMqLVW4CjRVDW6bToZbL
         Bqbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745899579; x=1746504379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:reply-to:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r1Rtsce1uCAod1pkasf2YUzxlrbGy6ZGd+be8FDQvSc=;
        b=rd7WEjxbcJyoYs2mweCC7Xk1dtlUtMyOpTOgv4TrSEBb+TNljBoAaGykNWgG3mfgyS
         aonVPxVDGMK/hRU7BsNxPmd3lT9mPW+ljFuVaQxUjd7Z6nPAfPK/iCxKtMQ0zTzQi9Ry
         Vo+OrYQolZKl7UfNYF+utiDZayI9rUTiffznEUHbiDykm7m3Nfiw2qbVv8Nl+asJIWmQ
         kqiQYBYvxIvPsk26yjNFZnJ3Eq6zjB0QryHuO4qU99+guBySAmLNJKqKDzopt12oRC5S
         tXbh8BgSSOZKhV9wq9qjMfsxaSpu+T2Na6fsQzbAFhqqxXc7WzFf4pwilc1n3S5KSZRY
         iHzw==
X-Forwarded-Encrypted: i=2; AJvYcCUAUqjABu2q4+QJS7frBap/VRn3Fpl3K/1w1FPUmHro1AASbohSQ1Qz1OY+4mgsDBuAPT5yXw==@lfdr.de
X-Gm-Message-State: AOJu0YyGhY6SZcRSvEpUZ2MAztOgMu2+R/x8eu/WPMnuLl/8KMIYOMds
	ewLiwi7Y5SJPOMHKXhbr/JD6fLZTrW39nWejcgdnYKoNauubpZ6z
X-Google-Smtp-Source: AGHT+IFg0bUV2wId5BRmHBnvH644fWSjAY8U2hk1wZtcMWQtnq6KguMaF9rJIrisew72+ffrDBfYkw==
X-Received: by 2002:a05:6808:80a9:b0:3f6:7cbe:32a0 with SMTP id 5614622812f47-4021154cea3mr884615b6e.4.1745899579039;
        Mon, 28 Apr 2025 21:06:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBFB2xqbJb5QJ5MxfcbzqOaBGurWv6GK0oMXzctyygCb4A==
Received: by 2002:a05:6871:8eaf:b0:2b8:f3e5:a817 with SMTP id
 586e51a60fabf-2d965d524c3ls1764639fac.2.-pod-prod-02-us; Mon, 28 Apr 2025
 21:06:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVygdLcGH/iRILF+Jqx0vueBkAOd2x92IGAo5wIuJTE/crwlFtIqPmX0fBv/6pO4mBxLerS4T6YjsA=@googlegroups.com
X-Received: by 2002:a05:6870:d689:b0:2bc:75aa:aeae with SMTP id 586e51a60fabf-2da48490978mr660622fac.10.1745899577988;
        Mon, 28 Apr 2025 21:06:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745899577; cv=none;
        d=google.com; s=arc-20240605;
        b=b/mC4ANZZL3Cmq4/wblD1EU7TE662H9BM9+8o27DogNqJLb1/9U29tWw0lMQy+F1Ba
         Ob+N/Og9hnk4wjS/hGvrr14bAuD/Ucw1vKUPK33v3ZFbRtWWcGF6t/CnGyH9eOJ0gYaD
         pQnDexd2PnbA7zGVGJ80NKzSdeA3dNNkf/p3Oy30ffQtlS/msOQgY2MPfaKhqO9Ut91t
         32rCBI8ilj76ZxTmLt6xeWPFgeJL+QXdv7E5PY8Rx5upkel06H68nQF1Xk5Ee8OapN/R
         6KYSi3tl7VwMKEx4uwe/DqqK5AXPr/yvwQTBvxrGkS7IOUWXQVvMhtmaXM1l+lqUKLQ0
         bQTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=reply-to:cc:to:in-reply-to:references:message-id
         :content-transfer-encoding:mime-version:subject:date:from
         :dkim-signature;
        bh=xrhMzzLIHTdVCC3mv+/FwPsHGQdx15A5wVwExQY5NgA=;
        fh=/bs3vO5UrVqo8T78tIeeq6rdQWrwj5Jc7+dDXJAvsfQ=;
        b=E3lEM0rz1V0185gxWmO1OyHmaeMb//vFMybYEYBMGNp5ZjR8H2ZGg9RNSgLX/bDQsB
         xfqjjuck5yWhpa7IxOf8Z7XnpAC8FA4sTN66ZXJMKFS8yb4AVZC0j81va4CZY1RC0bcI
         tBAE77Tcy/XxOd2JgusK/OOIy41p4GFJedc4oKiKD6dB33akJy3bZuQ7d6CKWYJQZqfQ
         Z37zuaC/7j/aEaopzB9Yge2g6et1GMUg133M8i96F4YU2BqqmeyRDncsWJ9JNqd5aeJ+
         47S36gbNqZefoWRwA1Nzl1fUAifMhtbnxLUb0cf6y86Lre+GaDnW2zOLLYqBpbzSRxel
         k6yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=umnHgPjx;
       spf=pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7308b0e9f6dsi34412a34.1.2025.04.28.21.06.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 21:06:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 77AD9A4BA30;
	Tue, 29 Apr 2025 04:00:49 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id BF675C4CEEE;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
Received: from aws-us-west-2-korg-lkml-1.web.codeaurora.org (localhost.localdomain [127.0.0.1])
	by smtp.lore.kernel.org (Postfix) with ESMTP id AC846C369D1;
	Tue, 29 Apr 2025 04:06:16 +0000 (UTC)
From: "'Chen Linxuan via B4 Relay' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 29 Apr 2025 12:06:05 +0800
Subject: [PATCH RFC v3 1/8] nvme: add __always_inline for
 nvme_pci_npages_prp
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20250429-noautoinline-v3-1-4c49f28ea5b5@uniontech.com>
References: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
In-Reply-To: <20250429-noautoinline-v3-0-4c49f28ea5b5@uniontech.com>
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
X-Developer-Signature: v=1; a=openpgp-sha256; l=2975;
 i=chenlinxuan@uniontech.com; h=from:subject:message-id;
 bh=Z0QiTYLHzEeebaywUqCSW16Ny4EMqCsjjX+KS5KBMNU=;
 b=owEBbQKS/ZANAwAKAXYe5hQ5ma6LAcsmYgBoEFAukhIgTV0U3xfinuIjd2L0FB1AExqdCchlv
 A3ri9QFLWiJAjMEAAEKAB0WIQTO1VElAk6xdvy0ZVp2HuYUOZmuiwUCaBBQLgAKCRB2HuYUOZmu
 i9PbD/0bxMLZB/tZ4Ta8gMq1WIv38DYhUP3aWnHRrfHrBmcZmF3pYKgj7U3bQhz1rGgW21/5jLf
 O6iQHC8JkszMXt7z43locXuD3D2XLaMzfIjJ4SYSBJJCUhLDwTO0hXO+SgM8VdRdhmjZUc1WhnK
 MotrwNb7+YScOJV7UKO27QZ4mEX9QtP1og5KDtG4fX2A4elJ/oUz5VyPu1ZVWaZIPGpR6UfQu2W
 3V96onZcmtcYOTu7m+Q4YYn57iocabwdiYGXp9u6+muG1V36fqjgCWLFdJ87b10fBGpqSdLd78K
 Np/ZrE3r79VyFTS10nLQwcH5emDVtRsUooPidOTFB5RbtCiWZVwNXbzPXeUAOlpo1fud6r4VWu6
 qQumY8DgxrRS5yYkJuqNuYsyMje5EqNF0cT9ACHUWaiTx2mc4D4GMZxmlK0Gb/i6H6b5Nn2r2Xj
 wAaoImxclHPRalFdhXU+KjoIiAQ+6sz9E+8WePUUrBdVGKfCKQPnIoZrmz83bxpZtjB8fQ0tEQM
 iAAaovwAWgBfxfbUHIa8VeSzTs5I5aHhO+aY/5Sd1k2ttkBswHZJumET7aNiQoPsJoewmJYilGQ
 jL21aH2TLLnbAvvZ8tf8QpXJtxzRSYrmcdb8wsQqvI0rVPoHUhioggOtX3jm+SKC+ApmPIpQr8u
 b//ZkECSNX3jkKQ==
X-Developer-Key: i=chenlinxuan@uniontech.com; a=openpgp;
 fpr=D818ACDD385CAE92D4BAC01A6269794D24791D21
X-Endpoint-Received: by B4 Relay for chenlinxuan@uniontech.com/default with
 auth_id=380
X-Original-From: Chen Linxuan <chenlinxuan@uniontech.com>
Reply-To: chenlinxuan@uniontech.com
X-Original-Sender: devnull@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=umnHgPjx;       spf=pass
 (google.com: domain of devnull+chenlinxuan.uniontech.com@kernel.org
 designates 147.75.193.91 as permitted sender) smtp.mailfrom=devnull+chenlinxuan.uniontech.com@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

From: Winston Wen <wentao@uniontech.com>

On x86_64 with gcc version 13.3.0, I build drivers/nvme/host/pci.c
with:

  make defconfig
  ./scripts/kconfig/merge_config.sh .config <(
    echo CONFIG_BLK_DEV_NVME=m
  )
  make KCFLAGS="-fno-inline-small-functions -fno-inline-functions-called-once" \
    drivers/nvme/host/pci.o

Then I get a compile error:

    CALL    scripts/checksyscalls.sh
    DESCEND objtool
    INSTALL libsubcmd_headers
    CC      drivers/nvme/host/pci.o
  In file included from <command-line>:
  drivers/nvme/host/pci.c: In function 'nvme_init':
  ././include/linux/compiler_types.h:557:45: error: call to '__compiletime_assert_878' declared with attribute error: BUILD_BUG_ON failed: nvme_pci_npages_prp() > NVME_MAX_NR_ALLOCATIONS
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |                                             ^
  ././include/linux/compiler_types.h:538:25: note: in definition of macro '__compiletime_assert'
    538 |                         prefix ## suffix();                             \
        |                         ^~~~~~
  ././include/linux/compiler_types.h:557:9: note: in expansion of macro '_compiletime_assert'
    557 |         _compiletime_assert(condition, msg, __compiletime_assert_, __COUNTER__)
        |         ^~~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:39:37: note: in expansion of macro 'compiletime_assert'
     39 | #define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
        |                                     ^~~~~~~~~~~~~~~~~~
  ./include/linux/build_bug.h:50:9: note: in expansion of macro 'BUILD_BUG_ON_MSG'
     50 |         BUILD_BUG_ON_MSG(condition, "BUILD_BUG_ON failed: " #condition)
        |         ^~~~~~~~~~~~~~~~
  drivers/nvme/host/pci.c:3804:9: note: in expansion of macro 'BUILD_BUG_ON'
   3804 |         BUILD_BUG_ON(nvme_pci_npages_prp() > NVME_MAX_NR_ALLOCATIONS);
        |         ^~~~~~~~~~~~

Mark nvme_pci_npages_prp() with __always_inline make it can be computed
at compile time.

Co-developed-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Chen Linxuan <chenlinxuan@uniontech.com>
Signed-off-by: Winston Wen <wentao@uniontech.com>
---
 drivers/nvme/host/pci.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/nvme/host/pci.c b/drivers/nvme/host/pci.c
index b178d52eac1b7f7286e217226b9b3686d07b7b6c..9ab070a9f0372bc6595c29a884ee9f2ffe5ae8e9 100644
--- a/drivers/nvme/host/pci.c
+++ b/drivers/nvme/host/pci.c
@@ -390,7 +390,7 @@ static bool nvme_dbbuf_update_and_check_event(u16 value, __le32 *dbbuf_db,
  * as it only leads to a small amount of wasted memory for the lifetime of
  * the I/O.
  */
-static int nvme_pci_npages_prp(void)
+static __always_inline int nvme_pci_npages_prp(void)
 {
 	unsigned max_bytes = (NVME_MAX_KB_SZ * 1024) + NVME_CTRL_PAGE_SIZE;
 	unsigned nprps = DIV_ROUND_UP(max_bytes, NVME_CTRL_PAGE_SIZE);

-- 
2.43.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250429-noautoinline-v3-1-4c49f28ea5b5%40uniontech.com.
