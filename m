Return-Path: <kasan-dev+bncBAABBDG7Q3YQKGQE5UJRV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id DB38D140A4F
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:58:52 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id n18sf16314909edo.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:58:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579265932; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkPzfHjLyglFY0/tpfORIdHaNFAG+I8xAJnX8Ui4GFQkzxb9Nm/A4EsXXoSV11r3hp
         HyeTrgSNmo8vN6z7e+kOa6U9guneIv83o+s5ZGcng5VRxfd38iQC9jMhC3Vb46xBWaZn
         QTVbemqWaBEtma4KbKb6HiRwHDvxkBTddH5HJij8QW9PdkkOKd2Kjk4RthKFviwVO9P1
         0IOfCD2kY1O22/1XayRGUy3cp6F2h5jS6vWnrqmam2AZPLq/zWUMznVVqiWF6wA8l538
         f2rEhUWmfla0CpIL/sbFdJXSTgdFZdF1WkzGUGMYPH4N6XwRoluzHaYD3/frgBeHbOph
         vcGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=7ccrVogRIZZrpyz1fuqPx9TTdvxvrOeKrZk3B011/Ck=;
        b=BKs04HqFgENzQ92xzzOU9ZkjsKK0TSwVY+7vcgBbHglfJ5onRrfglDf1/SwQYvhSgV
         RxlUTB0swAJ27Z1wmzT/Jgs+NNRBtra5UjfXxhLQVNk5qPGCywlaQUDBSwrmjzyBOA8N
         /Tog3VR0f2vwvptBiLibACgLj6wIQp4U/DSK7CH+sffR2forcWpI0C+AvsqGb3ExS/fb
         0iMijaBGZt/vN57S+O51NDCL/asfBRjpS7cLR7nZwUUGwLuLioYC89nOrDKv9z74GNUx
         DjTxQEcPiMXrTzb/ms6oX5teecmlQqNd592+LyTBrPakOvt4iy0ePrekjT47DStnFX39
         4KcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=e3pjZcCw;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7ccrVogRIZZrpyz1fuqPx9TTdvxvrOeKrZk3B011/Ck=;
        b=DAqRzD32tzVi4HQufrX6IW54wI0MGdq/kcOLI8Cwu7o4Tmt+qYdFk1YjQ70VR3YG+g
         clyB8H+RxQYtLUwQ3M2/M/G0i2/dJZvg254AaBcVSz+ey7lwLgbJ0z16810wP2otPpif
         WQTG51j2vjk9N9ELtkJwyy07SJWBm6vMNeldn7StXs6mOiYLU1aVYX/YkeIkqO39ng4I
         ye+V8mHLRnEueZ2FNF+iSRpVK7TlWS7qwUFeXkaI7DLXlSY5fJdiDVELX0iChyzmhqDG
         WphOdgVPKs+5R7dix5eAQucoXwUy5DCYsy/sNjuXCoS1Wl6fZlE5cS3EtHfdogQaYQgE
         9pog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7ccrVogRIZZrpyz1fuqPx9TTdvxvrOeKrZk3B011/Ck=;
        b=AfRWO6cGGSSrOhxnl/+MgXmafPXivlDsZCxwjvhhQ08uLA2LuQrbKm55U3JWbHTQOX
         DU6ORN46TirsqeRgGZ8oU4bJ+pnRxTfwvRNJ4tp6pdQio5SQg1IKW5VAL8FNEgG1wd2O
         nDFUPEa4Q177LsJy07hZ1kj8a7nxSLnqbByFQUlNEoOPb7PDxLX4UBthsQopIiEHPzTE
         CihObrS+Mk9cctDr7B/OMM3GLMUAZ0wgo3fGhiweuUHccQpoR0NL4duPT/GTD70YfWF8
         thfAQz1tR/UhUz5mECgUzxvnIXqMjd5E0AQxHuOF1lygWBxauvGVvtXPMGD1bWMhs7S4
         yzbA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV7uuIuaR6CXZSBmXz4IA+Rq/FMWI9fz5Ai3EB0zKkzeX48OhKU
	uQoAj94dDBFKsTVQ++jiB9U=
X-Google-Smtp-Source: APXvYqx7856c+v0yBJ6BSOJpA6vAfpH6+krdw6FYMEpmytxdYhQzgxS9kHnhOlUAGyto9oJTqUbAlA==
X-Received: by 2002:a17:906:4d87:: with SMTP id s7mr7593923eju.221.1579265932531;
        Fri, 17 Jan 2020 04:58:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:897:: with SMTP id e23ls6090154edy.12.gmail; Fri,
 17 Jan 2020 04:58:52 -0800 (PST)
X-Received: by 2002:aa7:d294:: with SMTP id w20mr3642640edq.134.1579265932196;
        Fri, 17 Jan 2020 04:58:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579265932; cv=none;
        d=google.com; s=arc-20160816;
        b=JwoSNji9mAldm5NUbyWVl5Y7tdYJwOjNBejlpcQmyocUqdRzwe+HKQK75I1Xbt/kGZ
         Qu3mz6fEdOpzKKN6mM+Q4WbfoLnc5t8VqTebNKkSMKC5DXRJF387uWl2T95/roSAjB1Q
         /aesdvc2w0Pz/1kNhLXf5RIJ81ltQ/ZZknYyVJo09IBjcq1LI5AygAlNWbGWyZIJDGwv
         ko20vgspAClkKiTVbtnNj1KzGgax+iBay1s0xtRRxuhAIoNvbb2cgnDLuy0oU6UM2uDu
         bro1e99EERwps6HCN2D3trsd42ZLo5uPyVnPy6iSkgkO677LrNNuARthlVwX3Sn5WX4i
         ms1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=E59EpItN/iMs+5Rk3MNIWYVcxR8hRcjKoUCNevJ3mfU=;
        b=Bg+iWglEPskSKuzoP4ft72d59GKfOSC6FVvxI92eEZ1fpto+TYhNO9rx58RBdpG6Aj
         0c9fUIvkR8SmYVNVc5dnbpfhOdgDXj+E5yGHsx2pclvljNRN6lopdQCpqfqey36fixuf
         JapiaHIjG2XDmzY3qB6l793D5C4g6zTv//gprU2GNXQXxAdeCA8ej59fbnFEHRkAIw61
         ka9fBIjSOE8rHgsrYSa9cgbBKAvJfijG73c5bgQpfrKR+Sw9Z9M62KQwbJOfsvKVDkXQ
         Op9SyDSJDuX6FuYtcl2KueW/jGyfafDpb3AkEfCg9UKot0TvirV6PbbxpTz29O1iMo09
         5rtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=e3pjZcCw;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id x18si1066763eds.2.2020.01.17.04.58.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:58:52 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) client-ip=216.71.155.175;
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa6.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa6.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa6.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: zD3guFlkH9JhD+uSChmLcxdihehn1gAY55V0yNOLmfd5xHNkkyjQkaG1rNe8JDLriMbXtqsdj0
 81dpZI705lNPF60X/LSI9Zed8Ipu/jX3FdGD0/VCa2xZQHYWL1ajeD5dMTEwtRTi9r2yF6xi9U
 BWpJr6wpKSm7udaVNwywU2OV5nt7AoxiT6BZueqhYAr6rFhXtL4h856U0/kqypBQmHvOBz7pSc
 dndcgglECoHTuRJtrokHRkSL/prOB0icVkoTw4UuoGG6SOWAn45h1sm75ZIutyTQgiKCbBK8cc
 FgM=
X-SBRS: 2.7
X-MesageID: 11502055
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,330,1574139600"; 
   d="scan'208";a="11502055"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Andrew Morton <akpm@linux-foundation.org>, Sergey Dyasli
	<sergey.dyasli@citrix.com>
Subject: [PATCH v2 1/4] kasan: introduce set_pmd_early_shadow()
Date: Fri, 17 Jan 2020 12:58:31 +0000
Message-ID: <20200117125834.14552-2-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117125834.14552-1-sergey.dyasli@citrix.com>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=e3pjZcCw;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as
 permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=citrix.com
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

It is incorrect to call pmd_populate_kernel() multiple times for the
same page table from inside Xen PV domains. Xen notices it during
kasan_populate_early_shadow():

    (XEN) mm.c:3222:d155v0 mfn 3704b already pinned

This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
enabled. Fix this by introducing set_pmd_early_shadow() which calls
pmd_populate_kernel() only once and uses set_pmd() afterwards.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
v1 --> v2:
- Fix compilation without CONFIG_XEN_PV
- Slightly updated description

RFC --> v1:
- New patch
---
 mm/kasan/init.c | 32 ++++++++++++++++++++++++--------
 1 file changed, 24 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..7791fe0a7704 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -81,6 +81,26 @@ static inline bool kasan_early_shadow_page_entry(pte_t pte)
 	return pte_page(pte) == virt_to_page(lm_alias(kasan_early_shadow_page));
 }
 
+#ifdef CONFIG_XEN_PV
+static inline void set_pmd_early_shadow(pmd_t *pmd)
+{
+	static bool pmd_populated = false;
+	pte_t *early_shadow = lm_alias(kasan_early_shadow_pte);
+
+	if (likely(pmd_populated)) {
+		set_pmd(pmd, __pmd(__pa(early_shadow) | _PAGE_TABLE));
+	} else {
+		pmd_populate_kernel(&init_mm, pmd, early_shadow);
+		pmd_populated = true;
+	}
+}
+#else
+static inline void set_pmd_early_shadow(pmd_t *pmd)
+{
+	pmd_populate_kernel(&init_mm, pmd, lm_alias(kasan_early_shadow_pte));
+}
+#endif /* ifdef CONFIG_XEN_PV */
+
 static __init void *early_alloc(size_t size, int node)
 {
 	void *ptr = memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
@@ -120,8 +140,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 		next = pmd_addr_end(addr, end);
 
 		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -157,8 +176,7 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -198,8 +216,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -271,8 +288,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117125834.14552-2-sergey.dyasli%40citrix.com.
