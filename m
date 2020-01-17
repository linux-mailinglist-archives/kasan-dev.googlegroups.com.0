Return-Path: <kasan-dev+bncBAABBDO7Q3YQKGQERTAHMRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AF6E0140A50
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:58:53 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id n63sf16315844edc.20
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:58:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579265933; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y56OlBdq8ol4nTCDf/vUd9rYQvMIqYBFHST1i8CyCAotkedP76LVxYfNA3JC7G6PHS
         3CuvMlAes/k9dZUcX7egkHp4IwIFrmZU+xzrf78YS+Y7fTU8h1+hi9N+e/7CvFGLzy0x
         kXbOmMtm+VBmOntgS0OrNIA7lt6H/aWG33YZbVnJx7h0TFR4aA7+FK+DOLEd2tPb24g5
         l9zK+JgJuqIMkLfyVPrMyUDLX+wmTrw01awWNplCuG5ngFCEnnkAMMgmDqUXscTNrgc/
         ndkkfSfI4bmeL1xKvTc9YOXbnic7R5i9BsfZZ/M5NO/zTsBZ8ehoNL1YdHaTIqOq1Hgp
         gj0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:ironport-sdr:sender
         :dkim-signature;
        bh=1Q+vghCNcI/RG88fxB3mAzBv0fC9yQFMrf8IsFqNM7Q=;
        b=bUln9u3s8QvmCZ6WfllHN6r4mA9S5poR02nft/6gvXHdq6B2hWOSGnvif8+lAc62Is
         AhSKwmkXCblX5yeDCzgfTQ2NUiQztr/tMaUuQMbLj+VUPwbdJiTZ+UAmZS4D2cTC0jVf
         wZoA4XPkAB2Kc289g1Y7uBtLtRN6GXRSliZ92v+C/PkYle/dWfGtuRcO7/UYg2fxyFik
         PdvE9Io1Fo10xoVNPEhJgZJ+nCJe6ywRvb0wzekHHD8Fi9PJOYZbvi8hbFvFYz6jkxhR
         sM3mOxBVClq2jCYPUkWNsFKT+p6XUB2MDC7RyKqXCUCAEGsSuqTZUJPC83ezEurakeuy
         wp7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=ShXCR+e+;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Q+vghCNcI/RG88fxB3mAzBv0fC9yQFMrf8IsFqNM7Q=;
        b=GM4pts5oytE5lGPKQ5YHehHva8RRj4rlG8ohWibp7uVcYWRF0YwmKgmek/1wVOA9S9
         Pz15vl9ANcAUS7LfoYayPijL072NEXUF+0X5wn08egcvY7T4bFNa+2zYi6TBAAVJVQmc
         z23Q0n2O/CnwBxNPf1yP/j2wDppElw6V5fCRG8/AyrOtY93wpfcemntFga8OqNpjIdiF
         Q6FmrpHjpIE+9jxZHEepcS/dnd4pd1W/NMQeSMZwziYJIT8RU4GaF8XMiRRBj+mvqOgJ
         UPa0ycD/85bKgvO7jpF2ycWn+5bPZ/KUYI6k3w6izqKsdeGYYV5UpH5sluW4Ej/hBeZO
         SwLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Q+vghCNcI/RG88fxB3mAzBv0fC9yQFMrf8IsFqNM7Q=;
        b=XKNgi1xLUYX683Spr50fx+wWBfY1J7chC2yULYcOPF5xBc5mRHaMJzNYQSlgQLPjXG
         WmsGEHs4/xdnFiRQBeRJ0bfv3cFDXYVB9dNj1l/RVbtJatGjlgyGWrAUUrR4OMYysd4a
         85Bs/HyE4xUp9Z9xqStFaYlrDwXLh8+noRP7TRjw3Mp2UxiOP/bFMebAVwVDg2GQPTJy
         5YZ13PIcufUjfk9Yhy9dK9GsSmZbbkr6+wiRqqvtGU2EgP5PssOJLT0itzzYdxbPEgVS
         WcvWlleODaoEC5CmSrk6T9t52RaZF1MDVcrOEO3EN7jH8FQ1Ozg3HTpJDJwv933LH51k
         7V5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWi9otCutIVkRFvEaYVXq01/K1aU5pHoRxZV1LR96hTWqS0y5T9
	ns/mDq9/quWgImh/YjcZRxs=
X-Google-Smtp-Source: APXvYqxu6JFZyuoasjkGEd7VarTA1UjtotErSniu/SernuO6BceFRLmgJ/nbrj0RUAQ6PmM7MXFhsw==
X-Received: by 2002:aa7:df92:: with SMTP id b18mr3703281edy.13.1579265933443;
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fb11:: with SMTP id d17ls6093417edq.13.gmail; Fri, 17
 Jan 2020 04:58:53 -0800 (PST)
X-Received: by 2002:aa7:d793:: with SMTP id s19mr3573312edq.327.1579265933093;
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579265933; cv=none;
        d=google.com; s=arc-20160816;
        b=rcT3Xe8lfNndaZdvWROHro15IVL9nbmAJPHDQw02K1m/F2WjFYZfMgTfF/DQwwlBAy
         6xNLwHGYvLVXAMYKF3bVkiwfYbYrN1Fx2t1H9r/zCZ8sj3atxAi+U4IIiDxu6RsaOnBy
         YwFcLEDMMP1bTVghBUBYVek1WyQ4XPmxoOOBv9J9Inq4+iMiHu0aby8O5k5nVXOnjSPa
         ozs5BprvTTKdvSNCRkwrjug6UUa+sI+2VyHFE3g58BWgCGxxoNPC8hoky2+OrY8Qxagl
         ZCL+Ut70R1U7wnXEHAPxS8k/eYs/IdN8yrJcWFRqq5AwpiFx1AUKAJqbfXm8X5D34rMX
         8vRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from:ironport-sdr:dkim-signature;
        bh=BpMa88UdbMreFPQop6UOe2rZxyuWrO7VzoeaQEAJnj8=;
        b=YuyM+sRJstW2kbglL+iEW5GuDI2jK4dnM2gJg2OqBJXJARKAPLRZjmeeTXcXFgmg7V
         tXjPbRIJ2+gsk1yoYK1+OQghlkXFzGlrB8QgjPGD1a7wvrIfi/zXXlckHHY/b6RpcFrt
         Qez16mSZlBN3CoMfS98p6AaeHuIAr6MiscVunzAV78e2FB8OyBWK3Vy0byg4TR21vs/0
         1VsYFk6RA38T/4OvvgoMKlob+TqMmnKu7h+XRcw635EU9t/57A/KmqWsd7nGoyKGD7CD
         Eo0et458cs5vFlTx/6G7fb0p0d8hlv2f1vlUdOwXy2dfXX95qwn60C5Iud9yduekdeLx
         CWLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=ShXCR+e+;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id x18si1066763eds.2.2020.01.17.04.58.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:58:53 -0800 (PST)
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
IronPort-SDR: 4K2b8rhSn6Bty/2FeakfJIIEi9epWLUPjincSgeuRAu5pyL+OY4PJyunZoqDVPeYO09GJ/VK4K
 narFurd17xBXf16uWXwA7fBa1ckrXq1fVu9EkdKeYrgeo5RCSdbtBsOkBpYi8BCq2CfnOi1egZ
 ib7LB64xnr0247GhQMXkV270Qsn70bxOaLGssXupnyoK4PdmGod153bQyC6h8gHO0+rb/fwvXT
 6QIHgC+JsxI9y4yOi9lBCh5sI0AkUSuFtz55BMHzP7MuI8Ihy2HqETn/QJzleCS5hP5D3Ybis9
 aJ4=
X-SBRS: 2.7
X-MesageID: 11502056
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,330,1574139600"; 
   d="scan'208";a="11502056"
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
Subject: [PATCH v2 3/4] xen: teach KASAN about grant tables
Date: Fri, 17 Jan 2020 12:58:33 +0000
Message-ID: <20200117125834.14552-4-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20200117125834.14552-1-sergey.dyasli@citrix.com>
References: <20200117125834.14552-1-sergey.dyasli@citrix.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=ShXCR+e+;       spf=pass
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

From: Ross Lagerwall <ross.lagerwall@citrix.com>

Otherwise it produces lots of false positives when a guest starts using
PV I/O devices.

Signed-off-by: Ross Lagerwall <ross.lagerwall@citrix.com>
Signed-off-by: Sergey Dyasli <sergey.dyasli@citrix.com>
---
v1 --> v2:
- no changes

RFC --> v1:
- Slightly clarified the commit message
---
 drivers/xen/grant-table.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/drivers/xen/grant-table.c b/drivers/xen/grant-table.c
index 7b36b51cdb9f..ce95f7232de6 100644
--- a/drivers/xen/grant-table.c
+++ b/drivers/xen/grant-table.c
@@ -1048,6 +1048,7 @@ int gnttab_map_refs(struct gnttab_map_grant_ref *map_ops,
 			foreign = xen_page_foreign(pages[i]);
 			foreign->domid = map_ops[i].dom;
 			foreign->gref = map_ops[i].ref;
+			kasan_alloc_pages(pages[i], 0);
 			break;
 		}
 
@@ -1084,8 +1085,10 @@ int gnttab_unmap_refs(struct gnttab_unmap_grant_ref *unmap_ops,
 	if (ret)
 		return ret;
 
-	for (i = 0; i < count; i++)
+	for (i = 0; i < count; i++) {
 		ClearPageForeign(pages[i]);
+		kasan_free_pages(pages[i], 0);
+	}
 
 	return clear_foreign_p2m_mapping(unmap_ops, kunmap_ops, pages, count);
 }
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117125834.14552-4-sergey.dyasli%40citrix.com.
