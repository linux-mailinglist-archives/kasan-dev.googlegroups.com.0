Return-Path: <kasan-dev+bncBAABBYOC4PXQKGQELNT3XZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 13801122E15
	for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 15:08:35 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id v130sf1534634oif.18
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Dec 2019 06:08:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576591714; cv=pass;
        d=google.com; s=arc-20160816;
        b=bIEwoIEeBFMhAaF5kQuQL8SPEMNRk6mtgvNxdrWlMDTxMV35EzAioIznG1O8JMfd7r
         NkSNWAdCK6RqZG+OisKWdLJPMqDlrCd8sYNBYe0r4w2Ns/Sm6PZtvqw1mr2ybAaSnbPv
         lv781opT0qqHF52jFIjCU8DZYnFER2d6O417Bd1W2C3zpmfclSIQ6iF0zC1sKO4BGTYY
         rPiARu0Lwmq6Ikzc7DIDMuR7tNlMUrw0bglae8tipAkV4pjXXUrL+jHOZEcwh6SkgA2k
         f+a+AjDUA7+vvBDD6J+iH+JxYFd4QIrAPZ1po+sQQdsoww2EYOotc7tQmWgqJjUB/jAR
         chaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-sdr:sender:dkim-signature;
        bh=sJlsYsi8PhkEqyWiimN9KcmF4mlsjuqwM24wiTkVqYY=;
        b=kcpnHxLSNMs1d4stgnTAAM9Ip5b5RTMFnqgetJq9b2At0SHdeGiHS2/MKGMOZbyQOr
         yrET+86sxvchgAanNdh08SSWYzBss53ryqqZ/zgps0tdCt2+QwasSRVIcm9opbqLIFrv
         Ts+r1m037OnvDGGqnyNAD++PK28AKCJqUrrmSJAcQBmhRNPUSz8MGopy8M79+WzgRiRS
         P89e0LKUwytO2F61Tha4v3RFzQCZtlIiOQBj2FOQKATenfWitcZYPPgNihahp6WibyPN
         YfMcnRYl/N2J3yicHSiUR1lr9C/UxZZi+zxRBKUlLITWSjzZ0GqC7HuMgqJ6cZ+sKQ35
         S6uA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=N1stjRVo;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJlsYsi8PhkEqyWiimN9KcmF4mlsjuqwM24wiTkVqYY=;
        b=UXjNXQQELcFnn71eX1Ysd4mZptH4yCoE9KdWzTCeWMywYZpN8012T/xUhdo5FplluB
         4M87S6W6ESwgl/I7caG0nc7/ovyCes/g8vWSYMGn9IgNLcKuEEFzrf4F7CTgKeyYfNgO
         Rgy3HWzA+oQ0iSGRGKJiPgmIn2CtshWe04Bv08b/WHI+U9gcntrR21IaZAEYdHg6I9Fp
         Sd5Bmg+xz836QrGEl2hRBcCli1HD/iarruSALyMFgzoPH6uf6rbPxnZhzghZWA6xNrnY
         q4zny1eJjkdlyx/g0CsBYyf0kPOetw2tTDqDX1oloHoetDQH0XmuE1Zc2MoxnVZid3CO
         JmCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sJlsYsi8PhkEqyWiimN9KcmF4mlsjuqwM24wiTkVqYY=;
        b=UZ3CnC222S3wJgdcdspu/n19yDUXuSsgHo6w+K35woq5OltsIj0HCw6oMc9hO+8QH1
         yoEg4HdxeicBN8ihkneEOOha4QO14BKFIFwQpHUDX0w8/bVxsLmH/JneYeW2wemTj8Ds
         RG8yEeRC4Bm2kE2Lj6gocSakjJCjJspwr5dg/WRx9+EHepi8t3CBPHyQ05+77ewAseeQ
         Ow4iJrxWlC/b+xbLmjd/8enwvhpBc3wVMPIvS5iXCTArErCoLhmfRZ5nW41TeN64fOxJ
         uF+7xog5lUAkMZNt0XXrlN0oBes36hg9g+MX94V8M0kpY3wsT3dtUU42y9auu384Am7w
         PXDg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUjMtuJTijf6SYyFJFOwKLfbuDFi+aKE6Dyem4NvWa/pB+0+tNH
	zYJZ5SHHD51imjPAOO65Zyk=
X-Google-Smtp-Source: APXvYqxLRuaiT95RNT0V22tmMq+ZN0IjcenDtOPp1NdCeHEhR/AHPYMRJ4nDhPzusySO85yIN0taMg==
X-Received: by 2002:a05:6830:16d0:: with SMTP id l16mr39031580otr.176.1576591713557;
        Tue, 17 Dec 2019 06:08:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:687:: with SMTP id k7ls1548121oig.0.gmail; Tue, 17
 Dec 2019 06:08:33 -0800 (PST)
X-Received: by 2002:aca:5f87:: with SMTP id t129mr1644514oib.36.1576591712199;
        Tue, 17 Dec 2019 06:08:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576591712; cv=none;
        d=google.com; s=arc-20160816;
        b=KHEMsrVRZk2rm91XaHrQpJXhogKdR3cHPmU4+j5G5/WESVl1WZstyLopS+H5Yvgh+I
         KKqoQJJvp+XvOyDCHI+5y17TgaN1atCeFzyroohEsrX8s+ai2BHqTt30vOXfzwXHzLKH
         5yKP38/BUTfLQLWuOlgO2ARV/P1vDyL4V+1g8gUik+Sqb+Mb9/QmzK8yrEhc8WHrvD3a
         OnxlH3lkxrG99tHf4TP9LUpsu6aKi1HWH667PwjRJPI+cEctKKTkqFOaAGj13qF3PO9C
         XzEZ9PdLcpJMRsiJcayzfY8UW1yh9iSRpyYIKF8ee+c4n6KSmRm6ShddiE4trWIAy2bi
         El7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:ironport-sdr
         :dkim-signature;
        bh=6tWNXuD4SJ4SLnKLJJoYz9KNKg2VuUQy+R5YftPhmno=;
        b=EOd2b/cIsZImYOfShSScUaFWS+whBVKI68RLMORuHkgA+g3tT5YXwiTA+6h6YdS1CD
         gAHhsJ/ANPTqQpEOBx6Aljm1TovRBe67VCFdkyvNrualCGAd/FOTU9x0BE0eJFCh6EEa
         cFtj0MXfr7rKhNirFcGoYrSN+PZ6cWkkraO222g598YkkIRmpFE/oKI+UPFiJmkXvPcP
         ogfq/+67q6aar4FZFMo9tnINcOsMHHg+KJFJAbPcBPqnw0BmVYhmp/ieKE1HiWBjO0gU
         TEgAjJ/z6BYklYmuQ8AYQzKmt84RUZP4VGHb0tEEHWxoXVq7Tz9uFUNrrj6G6WKEcXdb
         afsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=N1stjRVo;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa2.hc3370-68.iphmx.com (esa2.hc3370-68.iphmx.com. [216.71.145.153])
        by gmr-mx.google.com with ESMTPS id w63si1023058oif.2.2019.12.17.06.08.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 17 Dec 2019 06:08:32 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as permitted sender) client-ip=216.71.145.153;
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa2.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa2.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa2.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: Qz+c6mG1vz35ZJwUvyQJelqy2kgveD6KCcxwLp9FNQnAHJ1QazmJmY/dh1yXGSem3ftegBTm4h
 Cnoa+vMuS7jASwz1gwns4+0Ooh/Q4BdRskCgKFwt+mke0Kfk536ajFrYOAQ3wrQ/+TMZYB+swF
 m51kFtVRpixwwoen2tlLImLf8fjkYvCZuV9i+PAXJHKIlqbQZrssD8XfDLDXAuytnAwHcs/pK0
 f7ZgAKFYGsHtJvelXFOx4cqa2Q32g7tKRsSAxDY+Bi13vI1wQjAtg90OkDjradGyUnpdYPXrR+
 DZ8=
X-SBRS: 2.7
X-MesageID: 9817027
X-Ironport-Server: esa2.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.69,325,1571716800"; 
   d="scan'208";a="9817027"
From: Sergey Dyasli <sergey.dyasli@citrix.com>
To: <xen-devel@lists.xen.org>, <kasan-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Boris Ostrovsky
	<boris.ostrovsky@oracle.com>, Juergen Gross <jgross@suse.com>, "Stefano
 Stabellini" <sstabellini@kernel.org>, George Dunlap
	<george.dunlap@citrix.com>, Ross Lagerwall <ross.lagerwall@citrix.com>,
	Sergey Dyasli <sergey.dyasli@citrix.com>
Subject: [RFC PATCH 0/3] basic KASAN support for Xen PV domains
Date: Tue, 17 Dec 2019 14:08:01 +0000
Message-ID: <20191217140804.27364-1-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=N1stjRVo;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.153 as
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

Patch 1 is of RFC quality
Patches 2-3 are independent and quite self-contained.

Sergey Dyasli (1):
  x86/xen: add basic KASAN support for PV kernel

Ross Lagerwall (2):
  xen: teach KASAN about grant tables
  xen/netback: Fix grant copy across page boundary with KASAN

 arch/x86/mm/init.c                | 14 ++++++++
 arch/x86/mm/kasan_init_64.c       | 28 ++++++++++++++++
 arch/x86/xen/Makefile             |  7 ++++
 arch/x86/xen/enlighten_pv.c       |  3 ++
 arch/x86/xen/mmu_pv.c             | 13 ++++++--
 arch/x86/xen/multicalls.c         | 10 ++++++
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 55 ++++++++++++++++++++++++-------
 drivers/xen/Makefile              |  2 ++
 drivers/xen/grant-table.c         |  5 ++-
 kernel/Makefile                   |  2 ++
 lib/Kconfig.kasan                 |  3 +-
 12 files changed, 128 insertions(+), 16 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191217140804.27364-1-sergey.dyasli%40citrix.com.
