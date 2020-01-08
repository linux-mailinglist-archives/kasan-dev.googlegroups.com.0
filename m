Return-Path: <kasan-dev+bncBAABB27G27YAKGQEUYIYHBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 60746134600
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 16:21:16 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id w3sf1900014edt.23
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 07:21:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578496876; cv=pass;
        d=google.com; s=arc-20160816;
        b=oXpVY2VaUBBLYBXPCMGOsz7bW3TtIJc3TmMtMwJtQiS2eE6OU6cAKq7HmnJBmcXiYp
         kOT6SZaDcNbi1dSnI7Kpf9icHuVTxqMBo937YknhQE/NjiItKWp/vGT2swOwRDbZYRZa
         0aTvlEa2OGK2xy3+aa5KBSuTYtw4xItk2XoIPI2xMuHW1YkSQpw0/E14gDSo0rv++pnH
         yp0gG8CGd0Ns8mRMqfIIHbH2OwB36+5K22GdGbScaqbN2AmAIDe/I2EUoxSapK3IPtKA
         D5qqL3irx8UMRMYmgyW4GXRT6fRA9xwmEtemebV4ZyBIAb6v6wP+xEtY3KitaebYY1rP
         xngg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=7i5eYMw4lAx6CbGsPegzP/zNkkHFec7LH+6Zj41xgiU=;
        b=Ic1zT6h/DOIXCWXrjr2r8Y3Iqj81U7IjG05L5UDfa0oM/ChyCq1B/SJaJdgARWxNSI
         hydWI5MnYHSdZOVP8n7ybTmcPpdCiv1gosh9fCbRHUvrylOzwqIymUO7Ajqh8eUmMqau
         260qYO8o2KFrM98IUGFrWkAqywMrhygFC58z7ZWb95LYYg+XUlEq3FdHGFzzwdqM3lkj
         XbTw8jD64nDOWO57CY11NpPIO1jWnyR+HW9n8v8Hpwd/eWNeFodsCWAo1j1rlDrUvDRD
         mWg3+qJOPbxheyEGFSZREJ6P2twp504jBTyLB0yJCDYfQNlO4S3J4lkKAV/GvRRP+CVc
         uXkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=C6H2lFMh;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7i5eYMw4lAx6CbGsPegzP/zNkkHFec7LH+6Zj41xgiU=;
        b=hQ01ph+YaJeb/dUvfPOR0JHGhgXkV6+ac/tAKMGvRJ8wJEogsKtUUMEjycXGa6OUkf
         xO/L8vrmeVFTIGP0Ji2IFc13qUhfanwcQ/C1DXDBlX3m4ehb/BKvosjAYLJM/QIsAKG9
         1ZcVZpwBdrKZeV2W5tEXJzy0Se/hPIqYmvFCt84tXT3BddQdJk5oJHIfiWr7Gp+Et6Nt
         K3fpkDC+Pyik1W55ppGjNXnvrxK4et1Tgxei1d49zbPtf/tlLpJwomiX/gcgieO5qphI
         7cvect4OjlfEVLKJ56+nx0txrno04LUYWqB7GMS8cQgASO9xv4MNJ1lfvwc340Bllfbb
         5r6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7i5eYMw4lAx6CbGsPegzP/zNkkHFec7LH+6Zj41xgiU=;
        b=A+RKyCSJn50XVTRNouIkwUC+gmC7MHtqavAkHyXL3PDDnKrAmM2hgZrjMadLT5lm3g
         Qhes/nEslO0vgsgHAHU2hN1AFL/ygvB6UZhqv9Ul577czEkMdkzstEvhK/EJRberpRLK
         tpD4FU1Yx9zb0zFJ/fz22oXvYtR8uNL9RvlshA9AkngtTS7EjGnGGFMvmDGWsP1QXCm0
         rNO2oxY4QFiCNAIO9hM2w3g270H40B2Fe7MzLz+RzA7EbZ2OGBIKepsJQgx7Z79bfj5W
         GHFmouuGrd508iHUkjt4627Ty7ah7REbKMNfiar1IS8oUZKkiMEzGXn6Xr5mIzmbQVAB
         DBUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOJgOxcMSgGdEy4/8u5TNRKgcpwqYofoB3uODKZz7GARXkt+bl
	u8ps1EodG9zUglE4N7xVeVM=
X-Google-Smtp-Source: APXvYqzNSP6ecyH+4B3IH4Q9BfC/oETioUVmsHcdwdVpj3ymXEnpnOooBNaG51uwnT871RWbBDbSUA==
X-Received: by 2002:a17:906:c35a:: with SMTP id ci26mr5458318ejb.133.1578496875997;
        Wed, 08 Jan 2020 07:21:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:385:: with SMTP id ss5ls790124ejb.7.gmail; Wed, 08
 Jan 2020 07:21:15 -0800 (PST)
X-Received: by 2002:a17:906:20c5:: with SMTP id c5mr5488963ejc.330.1578496875225;
        Wed, 08 Jan 2020 07:21:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578496875; cv=none;
        d=google.com; s=arc-20160816;
        b=B3g4lJtm7MIOuZLY++mvouP0JrT0EbhUbz6DfQJfkwDARU5dRmRfba2fsWIy1PuLGN
         r0VEiM0dhYNwXm+ixe3+uTd8v+KNdX2mISQgijx4G18MgkiSDkiIE12PcuUdU/7LKNI8
         ibblFgm7ouTRUm2hqDVziFGfq1ZkB1DgVl13yIAcawhTh/YEJEUEdE3bK+sc/qGiKNQW
         dbbeJ6OqEQvjDP78z5QPQR4fEqMwUMdJlTvmK92tVZ+XWHVuq8umopDm5I0mtZggYLz1
         Y4JpMdvJ58/YHq9hYtb5yPaQrrpBF738p0ZeEMpzfLlO25FGdwLRK6zteBkDmFmGbO7O
         J0Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=LtdPnrcsTw6Dr/fClAbuyIX4XALzyf8f7Vy6o/q2R3U=;
        b=SpMpDQ+Nwx0UZQa2RXUMIQyABoiw8a379rRdD8hjGIDU5lm39zebPAjofzkdE7XVoJ
         lEtqK4xhxxm+UQ1/EBzHKOYbsjlBzYkAXvsYyaWseUj1V4Ycodzx/P//LNrFb+j3u5ge
         /3NyPZC9Okk5FpY92K7dGvmAHsWbMVrS5brHamWwEg/wQhQ7bmD5xekUsD7vwwqwyld2
         EQ4ntyPkoyxzBdCCcUjp9fXFhW9wDIo5nq2h7UTMSWE/7MpOYKxHdiYgi0PNPU5DeLxE
         NM2baQ4Q2eRgy3IajjQ/gi/OrrsvehrvDp4o9+DXHjU2YLxKwNK8nx4vz8QO0ES+3JC1
         /BRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=C6H2lFMh;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id ba12si148870edb.3.2020.01.08.07.21.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 07:21:15 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) client-ip=216.71.155.168;
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa5.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa5.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa5.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: NbrdZNDy/8773XZvZO8zNVSrjuBIlAMLf4M6CL+ejqbSJOqIN86OXwZR2Ps3f9MnAat1eXt5rL
 I5/hb4LebArVQjJXBOXfAtGECD78VXz6jBVCYi8lUug0bg+ZZEhfDnvYsb8fP9uyUSmZDg0AFT
 jKOSB2BDBcfGoWQV7vQbwBSL5PachzEw22NTcMg9xW7eIs2jH1J+/mNaxrn7xe2G3nVPLqdX7z
 xjzRnNNqF5pxf+YhbmBJeCEuBX4Hv89CfiDNTkbDZc3hXN5yEmJGTM/EOf8PjvYbiT2GYU9wZ6
 6Qo=
X-SBRS: 2.7
X-MesageID: 11004135
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,410,1571716800"; 
   d="scan'208";a="11004135"
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
Subject: [PATCH v1 1/4] kasan: introduce set_pmd_early_shadow()
Date: Wed, 8 Jan 2020 15:20:57 +0000
Message-ID: <20200108152100.7630-2-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200108152100.7630-1-sergey.dyasli@citrix.com>
References: <20200108152100.7630-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=C6H2lFMh;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as
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
same page table. Xen notices it during kasan_populate_early_shadow():

    (XEN) mm.c:3222:d155v0 mfn 3704b already pinned

This happens for kasan_early_shadow_pte when USE_SPLIT_PTE_PTLOCKS is
enabled. Fix this by introducing set_pmd_early_shadow() which calls
pmd_populate_kernel() only once and uses set_pmd() afterwards.

Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
RFC --> v1:
- New patch
---
 mm/kasan/init.c | 25 +++++++++++++++++--------
 1 file changed, 17 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..a4077320777f 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -81,6 +81,19 @@ static inline bool kasan_early_shadow_page_entry(pte_t pte)
 	return pte_page(pte) == virt_to_page(lm_alias(kasan_early_shadow_page));
 }
 
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
+
 static __init void *early_alloc(size_t size, int node)
 {
 	void *ptr = memblock_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
@@ -120,8 +133,7 @@ static int __ref zero_pmd_populate(pud_t *pud, unsigned long addr,
 		next = pmd_addr_end(addr, end);
 
 		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -157,8 +169,7 @@ static int __ref zero_pud_populate(p4d_t *p4d, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -198,8 +209,7 @@ static int __ref zero_p4d_populate(pgd_t *pgd, unsigned long addr,
 			pud_populate(&init_mm, pud,
 					lm_alias(kasan_early_shadow_pmd));
 			pmd = pmd_offset(pud, addr);
-			pmd_populate_kernel(&init_mm, pmd,
-					lm_alias(kasan_early_shadow_pte));
+			set_pmd_early_shadow(pmd);
 			continue;
 		}
 
@@ -271,8 +281,7 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200108152100.7630-2-sergey.dyasli%40citrix.com.
