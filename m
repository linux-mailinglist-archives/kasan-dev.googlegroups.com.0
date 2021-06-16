Return-Path: <kasan-dev+bncBDQ27FVWWUFRBKPAU2DAMGQERIQUXYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 68DF03A94A1
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:02:51 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id l13-20020a9d734d0000b02903db3d2b53fasf1091637otk.6
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 01:02:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623830570; cv=pass;
        d=google.com; s=arc-20160816;
        b=EoMhI2uz0Xd5f1SsVMt6toq6FdcCVCoD9WaI8C1qSM1vDXOxU0+KvWDr9UPSm2xYk9
         OgQCtKZvdQCEnNS1srO6xRxvHtiWpgwIFlEiQi5Lqj4mAPbIsYuSrJtUu3tY3+CNrMw6
         sTiW8w0OZ4679UZBWnc2LLorCIX0A9X/WdhokkRk4hMEzjW9a1fLYUAPQ+4XQndapWTU
         9iZrZQJXJfW3A22nhgYt78t8uyR88k/f8DBSFpCULkvmkBLKcRG/UhqetmupvDMMXGbl
         irWbyPlkdvFEN8iJmyNJdXZfc0fb4hRGm5v5wiP25XwP3BolMtdnSknrZ3cNNjW79667
         CiGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TZ7k6rjkpVOLI/xfbDl1pwSiXU5BEa8vPd5Ze4KJKd4=;
        b=wQhllpSlcvuXL5o2DxBDvzwaUzaddNs+l3ua8VKsK71RUhoQaXkWHRvd3MhFOhIsb4
         Mjq/pP8RvlRzy8K0jZwp51E32sspo4BZWd5YfeNgPPT49TSfuA2nVbwnwyt1P94ROV+0
         SrgI59BtFpM2bW4ng39oh53p1tp9yOaNsPt1NVbFW4k7uhTuwC8wLKtdG/UI3oKw6ojF
         Jgfx3PH/jtSu3fuZA/tHlLOI6YIbMXLh+fm82PeKuZzdWcgzaahegL+5Rj4SJXYd0GOx
         hveGzdUfIaZhDNqnrHAjsmuLlHYUZmKEpUtwK/k7u3iiq4p3mcJrjMG8LKdah73D27RS
         rYGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="QPnQjC/i";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TZ7k6rjkpVOLI/xfbDl1pwSiXU5BEa8vPd5Ze4KJKd4=;
        b=qf8s7qoeZf/ecG11C2qXFXBKViHlqkV5sDCXc2JtbkDJwGeOxgTgR/vqFDwrMwUgi2
         dq3mtIHu8ozpbqnp7TqOdtvTCMFgGjtvPqaM3TZ1nAwmJryAHBVg2FudcPngCt0L/Rpa
         7/NQ7EyUHReeiFTaDfoCNJSgjm4Q8p9Y6HuCQaI/4/sDD4qVVWOvuzhOxLiHNy3W9ve6
         2gegTQ5TpCD/nA7MZYI6Ydy6d3O3sOUyCjvSyPUxTKjlgp/m91UN0tlmV4Zdc9cNyo5m
         U7DBPBpu3tCspcxuGvye1dM19nISYh8ZlJ/bKSWX1hO1zAVMxjsjZHolyYMauTWfuFu/
         z18A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TZ7k6rjkpVOLI/xfbDl1pwSiXU5BEa8vPd5Ze4KJKd4=;
        b=Y897BYiDOzsmOydnlyizHMe+7dmqFUmLNgRMThMwJwb5XcMrEGuwrUTSzuM6fE8ks6
         iS02IXkA0A2Nj0GpscTaLUoPTLmZ3FTbaYx0q/vbsGvkJqDrpBaT1PCbxCrpdEi1ZtWi
         eJTIEUt1J/f4lQlZgdmkyxPIfkrfyi+V7XCcN0QLW5uHOzC0EM0YpiZiFH3TpFQcbvhg
         LEecP0h2lgMdWyPDO/PtWmhijI9vMzLUy5gy3BJf6PWFXAuDk3IXVQbEuAaGRL2uUGMW
         +3eOf+whseMx1J4UxBZRwIgz55CRtHqk8zWSjKGv8lO1JPh/HGiABjXYYrk7fk05Tsqd
         sbWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327Ha1I/RNUz+DEWbBZAQiP4QgF9xA9EshjysbGRsNwZ7+fRXxT
	3i32aal8cb0hR97zFvTPTVc=
X-Google-Smtp-Source: ABdhPJz72hCJzkbMwwzkMBERfcUHg8mx+C32nBx5ZkK7aDHnzqKyiJy8jr1Ke/ob84Zu5VwVbpH73w==
X-Received: by 2002:aca:4795:: with SMTP id u143mr6088056oia.165.1623830570030;
        Wed, 16 Jun 2021 01:02:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5903:: with SMTP id n3ls550432oib.6.gmail; Wed, 16 Jun
 2021 01:02:49 -0700 (PDT)
X-Received: by 2002:aca:bc41:: with SMTP id m62mr2235062oif.19.1623830569601;
        Wed, 16 Jun 2021 01:02:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623830569; cv=none;
        d=google.com; s=arc-20160816;
        b=FEquMTMx0nIfwcgGaB1dgcJmTLNB5aNSaPy2OqcV2t9dNY+GmE5Ec2+ApV1ARa4xeh
         LxEC1J4lthWHKlTCORAChrJUoI7gFXiflS4mKRXS1FOe9Xm//uSvu3rXqnZgWhwXw/2g
         9FfzFWP/vl8rl/biW8MaWh18jvyQ1o4z8h+lW+p7fn8IT6sn7YEXSvDVDlSNK2hmkOy4
         8BlcgfKwEHGkTL6dkttJiLxwqENVce/lLtVASiHud9+ybHMYof6H3zTLCwwgquWTmVsX
         ZtG28AnepXZWHsmKyA26dJTXvcDyJeb/RIx1RfzAzOBvJSyR4/3HYU8VgMryte6dUtcA
         H5rQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=cw10uFtM6j6ivpIAHKyfGYAPjF+AZvHLGbY1I1Cvnes=;
        b=TBEL1Z59tq3MVmJM72Yzrga0kV5aYMwEN4aG+GInSHs9qau/K8TKniZjMX5aJpetds
         znmPU5RmSBszAMwwkUkyMzXqlirIWGjpkikk85/1jxwZECLu8PD0zqMYu5BHSgSPKWsl
         A5b/6/hwuwtNQzR5D8o/AofW8p56vFMUBcJJ8h2RA4/iO/HcAxbd8QFnfEIh0BmchyEQ
         F2LfHmfPePAYxYgP0w7+PE/wkkGp/Qh1aJ2KWOxEEleNpfn9ns4cZfeOaNX/+0ITRcw8
         WHVqfcb+2cbWGVzC0l/szEGFSggoQXSMsxAkQOkmlCUFmrwKIHrCy3S2rmlVBMV5ao/P
         hYYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="QPnQjC/i";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id a17si99732oii.5.2021.06.16.01.02.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 01:02:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id t13so1294754pgu.11
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 01:02:49 -0700 (PDT)
X-Received: by 2002:a63:a805:: with SMTP id o5mr3777437pgf.328.1623830569286;
        Wed, 16 Jun 2021 01:02:49 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id k19sm1408921pji.32.2021.06.16.01.02.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 01:02:48 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v13 0/3] KASAN core changes for ppc64 radix KASAN
Date: Wed, 16 Jun 2021 18:02:41 +1000
Message-Id: <20210616080244.51236-1-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="QPnQjC/i";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Building on the work of Christophe, Aneesh and Balbir, I've ported
KASAN to 64-bit Book3S kernels running on the Radix MMU. I've been
trying this for a while, but we keep having collisions between the
kasan code in the mm tree and the code I want to put in to the ppc
tree.

So this series just contains the kasan core changes that we
need. These can go in via the mm tree. I will then propose the powerpc
changes for a later cycle. (The most recent RFC for the powerpc
changes is in the last series at
https://lore.kernel.org/linux-mm/20210615014705.2234866-1-dja@axtens.net/
)

v13 applies to next-20210611. There should be no noticeable changes to
other platforms.

Changes since v12: respond to Marco's review comments - clean up the
help for ARCH_DISABLE_KASAN_INLINE, and add an arch readiness check to
the new granule poisioning function. Thanks Marco.

Kind regards,
Daniel

Daniel Axtens (3):
  kasan: allow an architecture to disable inline instrumentation
  kasan: allow architectures to provide an outline readiness check
  kasan: define and use MAX_PTRS_PER_* for early shadow tables

 include/linux/kasan.h | 18 +++++++++++++++---
 lib/Kconfig.kasan     | 14 ++++++++++++++
 mm/kasan/common.c     |  4 ++++
 mm/kasan/generic.c    |  3 +++
 mm/kasan/init.c       |  6 +++---
 mm/kasan/kasan.h      |  4 ++++
 mm/kasan/shadow.c     |  8 ++++++++
 7 files changed, 51 insertions(+), 6 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-1-dja%40axtens.net.
