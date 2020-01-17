Return-Path: <kasan-dev+bncBAABBC67Q3YQKGQE7STPN2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F592140A4E
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 13:58:52 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id u20sf16387295eda.7
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 04:58:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579265932; cv=pass;
        d=google.com; s=arc-20160816;
        b=lNRpsQ8bZYKfjc9ihiZCsmqax50nAN1K5vVgU4xTz2Rq5E+3It16MWU+JutEah8E4p
         h9F0CjUR0Fpa91pymSFB5XL38aQhaUROIPkTCwhGXB+YA4rGyfLcMeRrjkCGkTx8E2yZ
         3vMGGOZRWdxrTwiYQOLWUZ5TEunwexuDhQQk7X9Nn9OeEHXn7VUw97HJZSZMiUVeLL8g
         8LtTA2TCZs/LYi86d/mwLksL0Sj+2ISL/3xStHuqM8Il8AO9zkjtMyIL7Bql7uNR5URF
         Xwi55PV1f3KbTpUuDS/qTpTOmnyH+zx538/Q8HS8kHlMdACDw4Cb3ixSSqOLEBuHm825
         R7PA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-sdr:sender:dkim-signature;
        bh=/G9BqZvkJpLHYml9xsae8MM+uvUyScEFMyRyll102WY=;
        b=VXSIk+OLS/aidmYe/Y8SuCPxA5ZrnJAKuzbK0vXM/52hFOo9NmCQJs6HVhJ3XeNVC8
         riLo6QmVvBq1Al3Vnfbj306eBcrTLxG1XvNybK9XGe/F8XleURzTXC923WPmUjjdsRpw
         dUh429fBMQE5bbgr1jG8TS9VnAy22xvRUsUjcJvWlnfSD+qiMWDOkiweyINQKCASUsnt
         ZXG9nMTsGuzVOs2hCyhgZyNq8QW+Hv7UGReEaISkFcAi6im4mH9GzVtbbMz2guFTJPa1
         4CLoKa/pnOW/W35jo6YsUBHnVUV33kKc6+dGIclrxO5+BwVyElmvzOnMmBj8XUabxhqt
         QgBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=N559xTvb;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/G9BqZvkJpLHYml9xsae8MM+uvUyScEFMyRyll102WY=;
        b=EW9miSzwyG5K+B728VuQhwXfg2bzVy5XBk8WpjTw+m3ScwYq7TSVT7TSoTfDAp0z8G
         SpjE95t1EhpgaJLLPwwGH/SyoszdKhdECsMIPkkjI9l8UXIknZ6mJ5atKjC2xhp8mkgi
         QqqRkDUJXHeBadlvX1px1wUZwOlD2GFy/w3nJMDUQ8jZVMd+qwKrqsQh/DE4UfEh9N2u
         kjRMATueQSh/hUwT7erUo7ssW8EYsF8dEiN4A0ryoe2SCd9RHKF69LAyCFJwuE/Sdx7M
         Z2BpppWXEUhJwtMALKnzDrOmAtwbGkg5A/rx+gf4pxVC7uAXB+rruIxG0RZfeyEI4DFc
         fjhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/G9BqZvkJpLHYml9xsae8MM+uvUyScEFMyRyll102WY=;
        b=eDacpK5JV4Y80prz2Gx1F0hbmI0zNov5E3o7puScAf8NEeJ5ZI07/lU0R80uyk7VrT
         yzkrzuu2DAe68yqdi5IuayiN6Gp5YozYB74tg8hAyD6RljzcslZ4V5SDbP95t+96ZWuE
         GLppE73UqENDUBBC3nZzKZXXUQNDlWAHaUpJ0JQAT7VMJ3ZLUSGw+pl5H+ri/nY15oXk
         M0OnUxJigBkJNHujXgJxguQ2MzOu3NB9G/EwY7j0Qry5Msf14aeA+gw96tZQmRi8aZaL
         CyPdy2h2SUPQD0stcH/cEO0h8krJ9E9u5Bqyy70Npw48P3PZ87N/OMFifyNMk4ZfCR/T
         4KiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUnlbgAhgTECjgvDxtYJFdqZrXfVs34ZCgBun4l4ttvayAeYMlr
	54P/3MNpTy7LfHoFZYmN4YY=
X-Google-Smtp-Source: APXvYqwgy46B3EDDr9sDeMYo9vH1MnKiN23V+mAd9CCW61YeQ9xDzq8zpHi+BqUJm2mlknGA2Ubl2A==
X-Received: by 2002:a17:907:20a8:: with SMTP id pw8mr7568211ejb.248.1579265931798;
        Fri, 17 Jan 2020 04:58:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bb47:: with SMTP id y65ls6088993ede.1.gmail; Fri, 17 Jan
 2020 04:58:51 -0800 (PST)
X-Received: by 2002:a50:83a7:: with SMTP id 36mr3718171edi.173.1579265931467;
        Fri, 17 Jan 2020 04:58:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579265931; cv=none;
        d=google.com; s=arc-20160816;
        b=ZESan7QJpFfAKhoiFrdngfIQqyyJRWDRG2QuhE2S+F6u/kN3kTcAC9/eAdMSOsUx44
         8hXw6gpNv2OFuM2Qx0+aU8emT/n/Fd41FRKyIY6/XNA9J9EcfbXtQSoYtI4NKe/Ss6i+
         MW8Fn6kwdv+kntu1Fo72FT+UEhBoH9naEvKSBB/lzLyJpcSDdSShh1TjKevVGwzwHmsx
         6R9ruGhT++EnZiG5UbhnsNSitlNvt4/6o14C1cfxu1y6I5MGYR58k1XHIWSCXXEEDJsm
         Z7uMyLA1sTHJlCwaBCuOOX5PH2uOzYoWC9Rl0zuwSEP+IFLkCKIQaxApSCkxVAC0GkLe
         ulHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:ironport-sdr
         :dkim-signature;
        bh=xJkxSj8ajjg5hQlpkBELQMheqGYcU6JJiykfJT7UkBs=;
        b=diVxVFM36AkuAhb5cA3p5aA7f9BXEWMurAQ5Zi62E+vvYzV8VEMcDp4uONbNS7suJ0
         jm3FGR69rlLLi7BbomIqMqe+ovPWMqRFmbbwBLBAn2+gIbu1JeKCdiUL2LWEwy8I7crC
         YNzuQMgAPE3Blidiek3+xbcdqfzX0+VsNXRewWDeAjjPpqzY3CAyjQO5lWrAOHCscxB+
         JZbIuY0HMx1OcdCqREqu5PbcDc8XM4Tuema4Jwuc/XmmUULRwtB7DLsXstBW5hQfvwV1
         NlLCBBvt6COLrBk+2IhCThk3b8avqF8oSL0D9o9KCEJkfekVfr12xnbvgbhw6trsAJn5
         gysA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=N559xTvb;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.155.175 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa6.hc3370-68.iphmx.com (esa6.hc3370-68.iphmx.com. [216.71.155.175])
        by gmr-mx.google.com with ESMTPS id x18si1066763eds.2.2020.01.17.04.58.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 17 Jan 2020 04:58:51 -0800 (PST)
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
IronPort-SDR: cYJtGt6LdwnYC5653CHAMVVeanmloFH0E67hIHUgcoEZSsvCeioxQxxsBrqjj+K978/MaI/e/l
 0J6GlKAajUQftwzwGGBHrSj8NAWktiZYEAKXYGHyNfwtpBwT5jmqun2bgFtRIAG3cIlaw1nC8V
 r2bjF0mqnViaII8Tb7HRhu6yPIUvp3LYgE1ttmVwMSDjpx9mjnJXhYYSSp7bKeEIzOMtm0VtNR
 7zLfUwPEeCg7d0EhuOqk5VYtlpn6j2y/MicWZ524RsZvrLyKCqewKNMeWmyAYCzU+qFLZQ85A1
 5XU=
X-SBRS: 2.7
X-MesageID: 11502054
X-Ironport-Server: esa6.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,330,1574139600"; 
   d="scan'208";a="11502054"
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
Subject: [PATCH v2 0/4] basic KASAN support for Xen PV domains
Date: Fri, 17 Jan 2020 12:58:30 +0000
Message-ID: <20200117125834.14552-1-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=N559xTvb;       spf=pass
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

This series allows to boot and run Xen PV kernels (Dom0 and DomU) with
CONFIG_KASAN=y. It has been used internally for some time now with good
results for finding memory corruption issues in Dom0 kernel.

Only Outline instrumentation is supported at the moment.

Sergey Dyasli (2):
  kasan: introduce set_pmd_early_shadow()
  x86/xen: add basic KASAN support for PV kernel

Ross Lagerwall (2):
  xen: teach KASAN about grant tables
  xen/netback: fix grant copy across page boundary

 arch/x86/mm/kasan_init_64.c       | 12 +++++++
 arch/x86/xen/Makefile             |  7 ++++
 arch/x86/xen/enlighten_pv.c       |  3 ++
 arch/x86/xen/mmu_pv.c             | 38 ++++++++++++++++++++
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 60 +++++++++++++++++++++++++------
 drivers/xen/Makefile              |  2 ++
 drivers/xen/grant-table.c         |  5 ++-
 include/xen/xen-ops.h             | 10 ++++++
 kernel/Makefile                   |  2 ++
 lib/Kconfig.kasan                 |  3 +-
 mm/kasan/init.c                   | 32 ++++++++++++-----
 12 files changed, 154 insertions(+), 22 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200117125834.14552-1-sergey.dyasli%40citrix.com.
