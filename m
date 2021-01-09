Return-Path: <kasan-dev+bncBAABB2XK4T7QKGQEGIJEBVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E4D62EFDD1
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 05:47:40 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id y2sf7906860pfr.12
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 20:47:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610167658; cv=pass;
        d=google.com; s=arc-20160816;
        b=cZNwp6kfJbxdAtdq8FbQyyx93PTVuhNoFYSPCsn44+qi+0Bl/xWgGhDQ/39Z0+qDN2
         JRBO8qpalLAVAknIdNhX1Tiiq96tUayV4b3g7ZRJxOotRWS1oH2Fztko2uMLJF6+xoKs
         6E6rIsWuK2o7p+lZmfwJregCqXsSho4S53+TzlTB1+UWamsIUMttbY18H78Xc0qygUUJ
         baVcJMhcSF92aiNcZMZP6B8B1mqwNDrl3BC2WXt5ilx3nFA+ep9vAr8L0P2G8KWN+wIK
         ToZ0X0XNDMNVvJgbBogSfLS6qMtmRnAL7WwEKKry8PWCie6PW48dr1zq1qJjcB18ZXtf
         E7JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=LqUKESuIcPT/DuWaT+p9xkc9zNtoj+5sgxgCzFjAqdw=;
        b=eXu7tiM7D6AIHGPy/w/3ENxNkU6NdrAnkO1AoYlDQmbTmQ+w2tjoK6dobiy5n0W7Y7
         Ru2dCOg6MhJscMJ4LdfkkwQ/Va5L1C0Pe43SlYeB1PdrvXoZYRqOngABSLjIDDufpjrT
         Ro4LVp1WCf5K/xoJveCdFS0O6SRKEChSH9iZffp5QHjJXiOhDsl/1DIcOVRMkU7TSG9B
         6Wjyf3VONUH70Llp7N+RxbrYIaNUGRqF9u5XGw7aqqQIyXr9V+zvOFWyLZPor6djWptK
         kww+tF3r4ZAWPOSTQLhvzk6klxqa9OmmqLOIawbpYuwe/hPn4GMYNb8q6fGojAurnUKI
         Ekyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@yeah.net header.s=s110527 header.b=hWfNBooH;
       spf=pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.132 as permitted sender) smtp.mailfrom=hailongliiu@yeah.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=yeah.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LqUKESuIcPT/DuWaT+p9xkc9zNtoj+5sgxgCzFjAqdw=;
        b=Rv8qpxmNqUEdXPIYxUwDx6+yuiY+/ouPQanboflIDy9YHrz+JXEEZHmnV9Ow0H/5f6
         L8xtSsCsGisgYoDwa1Eocuh1xNEsenhoqkFpqNdq969IxsKbeuupbhNYA8s2p6KKIIxE
         DSBb8uijbEoutFyD/VZ/v+9Z3HBsSZys8mxMVMq6P1bp3jbLNFoBvtU72AkinXz3N6hR
         vtBxUJtRx08g3VqtkmbVduIEuvR1ZU18gxI/eYmwL4pmwHPQYcY/4fhQbRk+0MrSnJJ7
         41DMnUlfP0v01QODAgCNphQkD289NWTo83MimOAXYba2fn4AXN/dxHqmSsxL9AQeaVUY
         vxmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LqUKESuIcPT/DuWaT+p9xkc9zNtoj+5sgxgCzFjAqdw=;
        b=pmjTwkYwMSwluH/k65sQoNODMvDfXTbuxnvLsdsEXhYxRH0X3BlzFlrR6itI4ogXZ1
         NeapCv0pNq0qB6mgKRxKN/CPsu8KLsw9D7lyWuw0gPwP8xxsfznZngbBYuGgx5340LQP
         dCg5rYFU7HjWUt7sHsbf8snQbjICOxSM8RCTRp6eeGvv5Src5J2L70EL2LhuLZK7L4hG
         Dnl3d9nNqzytRV/cDIf/jbFxQsy8yfWAb6G0TMbbcgWgnN3KtqCpuihDtk3QKbGnV4QU
         ypeYK+no0Q7xRccW5A7Lk3SMu1FqajNbLjqykZxsvG59arXLAwjGImvit+7NEYTc14hM
         oc/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305iuuPki/PlniLvdcV4XgPtBq0E3KIyLmUelv5V6xZuv3/tSiT
	RsumCC1Ej3RXyof5Lav9sRs=
X-Google-Smtp-Source: ABdhPJwufPA8aSpPzJdtNYOajqDQdgGiA4guMPx/ADtc7g171cKvEe5WZxi5EkzDQRW6Fn0Nl+6Haw==
X-Received: by 2002:a17:902:a512:b029:db:cf4c:336b with SMTP id s18-20020a170902a512b02900dbcf4c336bmr7123152plq.17.1610167658758;
        Fri, 08 Jan 2021 20:47:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b782:: with SMTP id e2ls5722684pls.10.gmail; Fri, 08
 Jan 2021 20:47:38 -0800 (PST)
X-Received: by 2002:a17:90a:ae07:: with SMTP id t7mr6888757pjq.115.1610167658261;
        Fri, 08 Jan 2021 20:47:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610167658; cv=none;
        d=google.com; s=arc-20160816;
        b=gTSclz4ZPobTmn9zhniuD1Hym45SGYDErSw+HmdbtiIBiFd0Lgko5xwK32GEIg1s5c
         EcoVshpiF20+YV0UULGUQlMLlw7b+wzDuANANd3DKfDQLWDSW7/s8lltr2stmdU8ZTCZ
         hTxV68R6YruhOVen+2XWJABwSDz/AW5eFmt1nRcxalfces03wsV5R256NtxM3NRUkal5
         Bi0oxkmjpLhoEUKt3z1prHyFN2fhemyLP896gt7Hu75peSlCZsVu2wl+sNScmo9LAT3t
         OT4dn4TE36J5NJkrhq1Qiv0xI34lEivbPg+l1Q2P7aao3/R3ZsZU3tz07ZfsgOiA4dGl
         hgBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=8u5igeF9P2tWvHHZTcGnBzv/d0gnIJMobD7YOWJEPso=;
        b=TkfXYzyylCcRDftC948hbTKmEnuPQd1LF7xRjkaWklZOGSKLnvRT2pUW6UdcyWWVsA
         2jWJlvUKuyFBFr3dVXqGhsEpcL5j1IU/FI9NJ6YwFI83fk4Kq4195geCGlSzOu4iL3rg
         uRCMPBYYimtSXMsrgjF4vWIcQhbT85V8eIGLXQUy97Fyju6kK46od3d9ngc1buBM/TAf
         +kHaAN6RJixot9HC6/CMCUoAM7+nP2hR5bmvoP5KwlHCqWYQJU2HQHE2/mfQQVF33+eA
         7GDjutQ/2mNXuF/Ilqe5q9xFZMo4CyyQ5smjhflxmihQkFWMUTZNueWXmgTyDsHtptH6
         nsdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@yeah.net header.s=s110527 header.b=hWfNBooH;
       spf=pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.132 as permitted sender) smtp.mailfrom=hailongliiu@yeah.net;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=yeah.net
Received: from mail-177132.yeah.net (mail-177132.yeah.net. [123.58.177.132])
        by gmr-mx.google.com with ESMTPS id ne6si683447pjb.1.2021.01.08.20.47.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 08 Jan 2021 20:47:38 -0800 (PST)
Received-SPF: pass (google.com: domain of hailongliiu@yeah.net designates 123.58.177.132 as permitted sender) client-ip=123.58.177.132;
Received: from localhost.localdomain (unknown [117.139.248.191])
	by smtp2 (Coremail) with SMTP id C1UQrAAntuEhNflffZAPLw--.57202S2;
	Sat, 09 Jan 2021 12:46:26 +0800 (CST)
From: Hailong liu <hailongliiu@yeah.net>
To: aryabinin@virtuozzo.com
Cc: linux@armlinux.org.uk,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	hailongliiu@yeah.net,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Ziliang Guo <guo.ziliang@zte.com.cn>
Subject: [PATCH] arm/kasan:fix the arry size of kasan_early_shadow_pte
Date: Sat,  9 Jan 2021 12:46:22 +0800
Message-Id: <20210109044622.8312-1-hailongliiu@yeah.net>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-CM-TRANSID: C1UQrAAntuEhNflffZAPLw--.57202S2
X-Coremail-Antispam: 1Uf129KBjvJXoW7KF47GFW8KrW3tF4xuw4fuFg_yoW8tF4Upw
	4DAFy8Kry8ZFn0qa43Cr13Cr1UWwnFkr97tFW29FsIqay7G3s2gFWq9r93Gw1xWrWkJa4Y
	vw48tFW5Gr15Aa7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDUYxBIdaVFxhVjvjDU0xZFpf9x07jpZXrUUUUU=
X-Originating-IP: [117.139.248.191]
X-CM-SenderInfo: xkdlz05qjoxx3x61vtnkoqv3/1tbiDQIV6FszTMgUAAAAsK
X-Original-Sender: hailongliiu@yeah.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@yeah.net header.s=s110527 header.b=hWfNBooH;       spf=pass
 (google.com: domain of hailongliiu@yeah.net designates 123.58.177.132 as
 permitted sender) smtp.mailfrom=hailongliiu@yeah.net;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=yeah.net
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

From: Hailong Liu <liu.hailong6@zte.com.cn>

The size of kasan_early_shadow_pte[] now is PTRS_PER_PTE which defined to
512 for arm architecture. This means that it only covers the prev Linux pte
entries, but not the HWTABLE pte entries for arm.

The reason it works well current is that the symbol kasan_early_shadow_page
immediately following kasan_early_shadow_pte in memory is page aligned,
which makes kasan_early_shadow_pte look like a 4KB size array. But we can't
ensure the order always right with different compiler/linker, nor more bss
symbols be introduced.

We had a test with QEMU + vexpress=EF=BC=9Aput a 512KB-size symbol with att=
ribute
__section(".bss..page_aligned") after kasan_early_shadow_pte, and poison it
after kasan_early_init(). Then enabled CONFIG_KASAN, it failed to boot up.

Signed-off-by: Hailong Liu <liu.hailong6@zte.com.cn>
Signed-off-by: Ziliang Guo <guo.ziliang@zte.com.cn>
---
 include/linux/kasan.h | 6 +++++-
 mm/kasan/init.c       | 3 ++-
 2 files changed, 7 insertions(+), 2 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 5e0655fb2a6f..fe1ae73ff8b5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -35,8 +35,12 @@ struct kunit_kasan_expectation {
 #define KASAN_SHADOW_INIT 0
 #endif
=20
+#ifndef PTE_HWTABLE_PTRS
+#define PTE_HWTABLE_PTRS 0
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
+extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
 extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index bc0ad208b3a7..7ca0b92d5886 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -64,7 +64,8 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
+	__page_aligned_bss;
=20
 static inline bool kasan_pte_table(pmd_t pmd)
 {
--=20
2.17.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210109044622.8312-1-hailongliiu%40yeah.net.
