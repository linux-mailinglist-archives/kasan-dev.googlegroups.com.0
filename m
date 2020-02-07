Return-Path: <kasan-dev+bncBAABBPPH6XYQKGQEASRHVWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B9615594C
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2020 15:27:11 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id x16sf1360876pjq.7
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2020 06:27:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581085629; cv=pass;
        d=google.com; s=arc-20160816;
        b=b2EIOwd/m3M2OeJ6GOYocXrP9jHaIH0TdxrfeNa27zhVBukFphiAdTr44MI/dSWG9J
         d8bi7+RzYKRDe7KxbnulLs6mog1Xrpz3YTJOBIku9a2dmVVazK0oaRd2diOk2oEnyrbi
         OaqBmAbiWwkGlXB2zq2GLOPwwke2ApeSWqu1vTodIEFpC6h5lVyL78L2LpvWGmTtVvsq
         3V4gDZAekqLPczFV+vjisjRcgeyk3tysrMLkK9m1IVb+0fpUcM5gfST8Vu01PrIBTvK4
         uFLPccvhyjDxVS0oFjEXlqjWvGaj9XRJwF815+uZln8J5AdrPvsduBRYYf65UM99UTZQ
         7ilw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:ironport-sdr:sender:dkim-signature;
        bh=UgIh+4rApjHaRecAFUldfx0J4raLFIOtf13qDGCykX8=;
        b=EXiYGk12jm1SG2niZRHsrdaOW4FDS+6E2BvwylUxxVUctTJVEu1HfqtZUYzGCzO966
         +zFv44GJivv5S302pQGnsNG8CV2AV4Eq2d6TiHhvZkjdYa7MtqiOjKeM1smo8avF1KYR
         gZj0BiqGVC+gmm2dYDzPnlLxWg5xffARXHvYSNp9buxvpzxBUtem/0CXckvxFPayovdJ
         Rq7c5QEV+jpyG/CxmVkktligN0ug7nmU/rRtRHLlvGxTvmf2rBDIMaavyipvcSMo4kfs
         VJzs3jnTBy9HC5ZiENwcKuoQsSz1wtD3i4HySSc6HZgNfjzH4KVJX3LSL5V3EBfkakmk
         dC+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=GQkJS9PR;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:ironport-sdr:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgIh+4rApjHaRecAFUldfx0J4raLFIOtf13qDGCykX8=;
        b=e2nxas2R1UTmPxoZ9/HIxe2/YwfJX1Xexg0znNgI/0OlgnFBTB8SIkV7cSwrMVQ+jR
         dVEwyUn25Bcx0taBjOJE08Kzjy/aSLiDqAehkjgPWTLHCstPbcUyKW0wZiqWIDxV9NRS
         OUfj6bJXcZKYhJq9D46VMQTlHjTXYEN40AM7ldJCTfF80q1YPnDQHkuAypKvUj/bI78H
         kf8MrXJEohC2/0VOxxeDqR2ab+p800MjDvVlBVhPRzqS9B3mwTnV68hC2Uv3cQXmbukr
         hbyVCrPAlZvyaqTJNUeqBNm5j569J615HvZ7qek7m5cCfSZK7bLWGMeu7sEKhzpZ39vT
         wYBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:ironport-sdr:from:to:cc:subject:date
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UgIh+4rApjHaRecAFUldfx0J4raLFIOtf13qDGCykX8=;
        b=qO36p0kUd3+lX6/BNJ+IDLPDO+ySkri9tuwDULhCKGaDgieuQWkMm5dRuyteoeYLiC
         yDwEVMtzgrrjoUxXe0wST1O7tItggHiz9mBMWozP3T6lxjwAj0uQorCIYWtBy3tAPzLv
         O5esXRyKQzMSW+lkGIXo3EwcGrsksJU4BGETwKQ5UAxozZYfBrIOco2lL2eF05RhyqkX
         VX9aUR7dS9uVVwPI8MRfBFx8bgbV4ekKqLNGWoDdCQfCPLkic9QPICv1q2FuK+E8g2y+
         J2sc27k/RCB2EfSpLVhcr6VAOBxNeDtlulekCHwYYYgPIKbBpedp2iAkjZdBppl2c/5o
         6qng==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVB8zwi4bD0kKsA/1ZGBDALOW0fgbIHXi5F++VVZ8QyLDWEixqX
	rISYfWAX4AgJ1axheBZ2JLc=
X-Google-Smtp-Source: APXvYqzCFNYdLMKDtPKUzE9kH93m230iLj9Mif7UF3/5XsbYi3QitZlMv3GCbNOKXfAiuAlxMgWQ9Q==
X-Received: by 2002:a17:902:904c:: with SMTP id w12mr10337950plz.35.1581085629218;
        Fri, 07 Feb 2020 06:27:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:253:: with SMTP id fz19ls5456355pjb.0.gmail; Fri, 07
 Feb 2020 06:27:08 -0800 (PST)
X-Received: by 2002:a17:902:9a09:: with SMTP id v9mr9673626plp.341.1581085628872;
        Fri, 07 Feb 2020 06:27:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581085628; cv=none;
        d=google.com; s=arc-20160816;
        b=ztKegRtXTvk8cVQFurUrQtFI8OAeIG74bT7vEaDeeJtW9INUcgIqVm9BsRKIAgBX14
         rBUw85IgCVuEzHskwcRKFOLyPrtxr5gtLqZetA1Xz4Wv4grF+TThpnY0GtreiIBNemAZ
         T1gybKuevQdspyOxBM7RwR6CEqLnorkqt8Ola7lkmcHiZqWAHAvi8b8LhCMpPAcqwu5J
         pXo4eccliZ/k61cgU3RSuHZP5ngxr6H9S84Y5YCdW46kw52I4XJL/oIwUm4OnpGAc1vN
         UGi9B6Oa0iLVudS8I5+s59O6Su6A/oq06zs0VVJYt1988lR+0xq9GjR1dMJpNBqFQG8Q
         PUnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from:ironport-sdr
         :dkim-signature;
        bh=DqY7nH/3yVl6lwE8fZQCSSOTcPkLftMsARarf64OxZo=;
        b=zeOyv2UVlClBnLAnx65JxZt9NNFr0iWpOdNAPYCKpnMsrAZsY6LKzx4luD1u8jg6MO
         nRWrolIEPnSLEGfDoHct5uDmME15LGKqe/HyAREgwhW2kP86Fr9LIp42jztD7IcywuYQ
         DvJBdERC/L5DtCIGNSp8suMaDOO5TtbY8EO2WOgXv8LlA9fdbNRnJnryac9tgV2fwe07
         4gwvg+vqwbdjXdLTRNn0eLY2/LiWqvOuQ/3t98pm/TYEN1/3rngFZ1kqlH5OkG0gO4xr
         uKXbAdYdD+8apJSDW10rG8XvP+/eCkY3cmje0YpxvnQfkacw07jgGUMKtnGAAf7sf3Zd
         I4dA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=securemail header.b=GQkJS9PR;
       spf=pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) smtp.mailfrom=sergey.dyasli@citrix.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=citrix.com
Received: from esa3.hc3370-68.iphmx.com (esa3.hc3370-68.iphmx.com. [216.71.145.155])
        by gmr-mx.google.com with ESMTPS id h18si398938pju.1.2020.02.07.06.27.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Feb 2020 06:27:08 -0800 (PST)
Received-SPF: pass (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as permitted sender) client-ip=216.71.145.155;
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  sergey.dyasli@citrix.com) identity=pra;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible
Received-SPF: Pass (esa3.hc3370-68.iphmx.com: domain of
  sergey.dyasli@citrix.com designates 162.221.158.21 as
  permitted sender) identity=mailfrom;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="sergey.dyasli@citrix.com";
  x-conformance=sidf_compatible; x-record-type="v=spf1";
  x-record-text="v=spf1 ip4:209.167.231.154 ip4:178.63.86.133
  ip4:195.66.111.40/30 ip4:85.115.9.32/28 ip4:199.102.83.4
  ip4:192.28.146.160 ip4:192.28.146.107 ip4:216.52.6.88
  ip4:216.52.6.188 ip4:162.221.158.21 ip4:162.221.156.83
  ip4:168.245.78.127 ~all"
Received-SPF: None (esa3.hc3370-68.iphmx.com: no sender
  authenticity information available from domain of
  postmaster@mail.citrix.com) identity=helo;
  client-ip=162.221.158.21; receiver=esa3.hc3370-68.iphmx.com;
  envelope-from="sergey.dyasli@citrix.com";
  x-sender="postmaster@mail.citrix.com";
  x-conformance=sidf_compatible
IronPort-SDR: cA4RYOaIu0S9s9ta9/oYmLKI0oPWh8qI67vWbWeID51CDJsqQPd92KqbQrXTSHxA52oIpyOEin
 mjHe3Ta8qJaLx6bWxbhkPfPX//GfH+LroBSmBFGi0coygnCqe3s209HCh5UBZXXmyCzAXVuB4O
 PGUH9uKK98jiE79sIwKNB4nDDtzDQBnEmUwfWuGxwwWQ35uDItVmyc/u6tx2xPf8HNSoFkXGUx
 LpxcLAHAu0+2zobEKKVhvS7bVrz3xR0/Fu2/Jn5GwUKtqlfFilhnqbj3ZzAl+TvbJrHpp+Ujfc
 aFo=
X-SBRS: 2.7
X-MesageID: 12106635
X-Ironport-Server: esa3.hc3370-68.iphmx.com
X-Remote-IP: 162.221.158.21
X-Policy: $RELAYED
X-IronPort-AV: E=Sophos;i="5.70,413,1574139600"; 
   d="scan'208";a="12106635"
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
Subject: [PATCH v3 0/4] basic KASAN support for Xen PV domains
Date: Fri, 7 Feb 2020 14:26:48 +0000
Message-ID: <20200207142652.670-1-sergey.dyasli@citrix.com>
X-Mailer: git-send-email 2.17.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sergey.dyasli@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=securemail header.b=GQkJS9PR;       spf=pass
 (google.com: domain of sergey.dyasli@citrix.com designates 216.71.145.155 as
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

 arch/x86/mm/kasan_init_64.c       | 10 +++++-
 arch/x86/xen/Makefile             |  7 ++++
 arch/x86/xen/enlighten_pv.c       |  3 ++
 arch/x86/xen/mmu_pv.c             | 43 ++++++++++++++++++++++
 drivers/net/xen-netback/common.h  |  2 +-
 drivers/net/xen-netback/netback.c | 60 +++++++++++++++++++++++++------
 drivers/xen/Makefile              |  2 ++
 drivers/xen/grant-table.c         |  5 ++-
 include/linux/kasan.h             |  2 ++
 include/xen/xen-ops.h             | 10 ++++++
 lib/Kconfig.kasan                 |  3 +-
 mm/kasan/init.c                   | 32 ++++++++++++-----
 12 files changed, 156 insertions(+), 23 deletions(-)

-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200207142652.670-1-sergey.dyasli%40citrix.com.
