Return-Path: <kasan-dev+bncBAABB3PG27YAKGQEVTVCC7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 78519134602
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 16:21:17 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id j6sf1903705edt.21
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 07:21:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578496877; cv=pass;
        d=google.com; s=arc-20160816;
        b=tOUbdVgvJYidU2SI0xsLVB+Ix/0SiEOgwF6oBrJaCeD1XHMVJno1j5Ys5xEAjWOOFQ
         86KNbMGMj41l96G28CInR596rI6dB8WWjW1mjMoSEB2OdUQeCmIdoxyDr7jZIx1pS5Q/
         ZBK8GdptvPoZuQYnoAPKkb75g0nlr/Wc2MTDHbouE53JLhEH2F1HAtzA6tnjUizcyALY
         6D/SpC30CQQ601ZSjj2EMu+p5de3Md7F7Euw8BBL6b3fhW4/eC8NVirkx1YQUkoOcvC5
         pLrGEr1OxRPjMMqCPP2LnSAGpIKrJPCY6P5AZGR7qUdQq5THUT9Xebk5yRfVGov0qLt7
         EXIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-sdr:sender:dkim-signature;
        bh=RBlboRf0mnFypsPD89Ek60vOGEqiCTxSkRM02fiyslA=;
        b=x3dVmFUM63da6uQH1YjQ58hCE5gUTDLSVPecVFeebL6+avjQ6+VrVnWqPamoVZXwcp
         yHT6YeLAhOSjoRYnGGSOGIljsogvU63Fogp3iW/lpWe2KddOyvq+bJ+MWnIO4lW0ewos
         hSqyZwVqwwFn7U8conOjFZAlGiAPN2q8K+yo7NP10WKwn5glcIF5iuPhpyvpCgdby7rL
         /LXVVnMThbMwQySs9vhIz7n2wpqVA7JvVSJOqotznljkc8c2eLF/wQdWRubTY0Qzx5jD
         +By/k1xDWoYUnysHYfONsABTgshxaCYAoZX3ZrX0Eq+zUQCBleCgmikU297Jut19TzWV
         AVVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Wbed+Rur;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBlboRf0mnFypsPD89Ek60vOGEqiCTxSkRM02fiyslA=;
        b=idHPL0yPCS0zEuErBO21KQ7tYk1NaJAUNXsXY/zPAISLr7HYMh6Ij1OeI9y3FJUw2k
         +wCf5TsV5GF16jH3zaFCL/KEMgKQXyh3tRXIIuazni26H73c2041PMf+LJRYl+i75+iZ
         /b9DoTsOBDzdcyzdgKtoMunujns2THMJJca0echgmLdW2ZzL6oHRZa96KvYau7GEKoyF
         ZV+ErUIkHGDFz8zoX0pxfqSrxAu6omon6JoiEZNFV1hxd+Kjg4CjvT7DE81USYgdm2m4
         9LzuLnBRaWTSUJiJCHtrJNO7+MHcc0XoD+B7jG94n/bGRKXmQhq1njvJpKkjJF6o0kH5
         AULg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RBlboRf0mnFypsPD89Ek60vOGEqiCTxSkRM02fiyslA=;
        b=ts8D8PnEvliKBfL5v+eo5HJZQQev4WRXmz3YBzrcsrdwlWhkFybFpPvqXuWgSppItD
         PfCztm17YNK+rJ1v/esXd94JagaAwXQrwzSn4+wBvGfkoMezGOdZ5QMnl1sRV8IR9iE0
         ZRHN2vaWJiNodxCFTDTaYBux1Xrx26RWEbf/ZqNKBkpTUBRM9fupeTu6V5dc2NFMYy3S
         9iFmE8UYvuT9HdWXIM1NY6eRg4q1UyklTNSk5b4jyS5jZ2dLco+rkfq2+q0HKOsADXRD
         s5aonS+O9hl6HAsg6qq+I06jUfk7avb3GCDA+VOjC68MvhwglNaZhn4xWQvjDuFVWLoP
         z5Ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUDGXEuFZ7BD3Rdox7bHXIucxr8ZG0K0lf/TOnqE5ZW9YWGtsH4
	PQFyo4a8BCczn/ZgXVZ3xKE=
X-Google-Smtp-Source: APXvYqzEE4g5GB/qzRFDg+3GdbVv9qhxaJDULUKd7IoZnf098F1NkNCfUZQdzWw0RXhosd4RYvVy/g==
X-Received: by 2002:a17:906:b850:: with SMTP id ga16mr5341103ejb.232.1578496877197;
        Wed, 08 Jan 2020 07:21:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:3614:: with SMTP id q20ls793811ejb.2.gmail; Wed, 08
 Jan 2020 07:21:16 -0800 (PST)
X-Received: by 2002:a17:906:4089:: with SMTP id u9mr5428263ejj.205.1578496876827;
        Wed, 08 Jan 2020 07:21:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578496876; cv=none;
        d=google.com; s=arc-20160816;
        b=YsV584+AKnJ4cXf2gfoHClfcR7R4/AeTnOFgfeHH6lMvFSWa8iwWz+KuvYIoSA2v0g
         n4QTwTDVLVNYf9di4lUKM05DdqVAcgVLRdWgvVC0cyioMP1/KkQmKEwzZkoVlFhMFhND
         L4N+6g0d6gL8aTKj2xM5tl8d35sY++acPFmZexhLNdydSdkOQQEhBpFuVLA+G4/XV5GO
         TVeQli0+ZS9I+zPuHXI6q3nN6dJhC976axMN+aJ8W/W/lbh9LcKI0lN1sOM+p08hvng8
         A0BW1Qp8a7jWBlNpdEw8a/dD/KK/JPg17uag+2ggVNwVeLO1oiWs+AmZQA6GxDM4NWZc
         aPzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:ironport-sdr
         :dkim-signature;
        bh=T90N6M0/jg2EUM3Vw4qlTMYFloCXIcO0ZDMCB0pbAfA=;
        b=UJNzsa1PB6D6agLtZ5hdrr7Ej/zktJcyES+OxjFMGqKx96H6Sm9yN9oDSMo2Qs9nHI
         IgFTt/6yWbAAdRzPJxYLnChOR0wOc29lc3B3WWMs8HT+8LvR5g+5EVUbExiriY6sUXBI
         6MxXVArOF5nq1nlrPXavILi/zwY35NCX3m3Lo0ZcQHJwmIX7cJvBA0p5Eg/8aBh6Yk/j
         8Wfm6og89AsA/9xyFqO0L1JhzvGqL+zDLzB/PC8Fy+ETHbYJF5sJMEIJsofEfOo2t46s
         B86E1F2xxIuKd7zU1kEZL4NltCSD25IEAixfvACCr7gUmzbrchTMcbID4VIn28FuHJTA
         Zh9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=Wbed+Rur;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.168 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa5.hc3370-68.iphmx.com (esa5.hc3370-68.iphmx.com. [216.71.155.168])
        by gmr-mx.google.com with ESMTPS id ba12si148870edb.3.2020.01.08.07.21.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 07:21:16 -0800 (PST)
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
IronPort-SDR: aV70Ec38LNGJHPyjmtz3ubeiTnr6mtH+1TOCC+rUdQpsyHfc0ycOuyMkNd8LI/THZ/TU7JqOOv
 J2EMt9YDA3dz5/DokVaJH6CTl/S0dcoWuwQeuBL5EH1lDvJUBxJqjLZyyVNAI0xRXUYaVc5/zQ
 J7xZ4F3n5EcB47TJwb3p9tdkRo8vRuUyZJfApAh7tNh38bQRzOPlTFDSL0Yg3gR6ny8iCS01/a
 4leaynRNcoOnKITm0n+jg6lZkAlEuZPd30A4iqTn7Uns0uulDWrjpKs47Vvht/MLdLQUgcxrLU
 Eaw=
X-SBRS: 2.7
X-MesageID: 11004140
X-Ironport-Server: esa5.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,410,1571716800"; 
   d="scan'208";a="11004140"
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
Subject: [PATCH v1 0/4] basic KASAN support for Xen PV domains
Date: Wed, 8 Jan 2020 15:20:56 +0000
Message-ID: <20200108152100.7630-1-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=Wbed+Rur;       spf=pass
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

This series allows to boot and run Xen PV kernels (Dom0 and DomU) with
CONFIG_KASAN=y. It has been used internally for some time now with good
results for finding memory corruption issues in Dom0 kernel.

Only Outline instrumentation is supported at the moment.

Sergey Dyasli (2):
  kasan: introduce set_pmd_early_shadow()
  x86/xen: add basic KASAN support for PV kernel

Ross Lagerwall (2):
  xen: teach KASAN about grant tables
  xen/netback: Fix grant copy across page boundary with KASAN

 arch/x86/mm/kasan_init_64.c       | 12 +++++++
 arch/x86/xen/Makefile             |  7 ++++
 arch/x86/xen/enlighten_pv.c       |  3 ++
 arch/x86/xen/mmu_pv.c             | 39 ++++++++++++++++++++
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 59 +++++++++++++++++++++++++------
 drivers/xen/Makefile              |  2 ++
 drivers/xen/grant-table.c         |  5 ++-
 include/xen/xen-ops.h             |  4 +++
 kernel/Makefile                   |  2 ++
 lib/Kconfig.kasan                 |  3 +-
 mm/kasan/init.c                   | 25 ++++++++-----
 12 files changed, 141 insertions(+), 22 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200108152100.7630-1-sergey.dyasli%40citrix.com.
