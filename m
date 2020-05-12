Return-Path: <kasan-dev+bncBAABBL4I5H2QKGQERRW2CXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E2351CED15
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:37:36 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id w15sf14542392ybp.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 23:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589265455; cv=pass;
        d=google.com; s=arc-20160816;
        b=H4vpZ8cSfhSmEyIc+GQOY06eFf4Zn8LMqYiGqzR0e/4giOLoaH5yc8wQiy8GboBYs7
         X4zVyoZ6o+ze7IXczLC5PUnXAkZjwWmMcq2Fo89MOxFYeJyUpB8QeuoOZECLJAbMOcaa
         4c8g9hNMS+spUqO8AfwOaWyzUnogd/68iskvBXN2B5hVL00tifOYbCdas4DgVnETFHcC
         ESjcrqf8yPNAKUdeEhXnoITF0sfjzndSmDbeg4Imwx6b4NC4YwyxmmYsQ4wCWxgM8poi
         FamOE/Tzuk16J2XbHYHlTEygu18LxHS+K8+H8lYB2HcT2R70y6nOaPa54L7SdVPEfi2p
         e4Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=M9ahENxMdCsbSh8Pzi62QZzMZN9INmnWeZWnPRtf8WY=;
        b=hZe2e1t1hyhMtiR9abL3Mge/D95lO7XNAFlpbAe46tvP6Oi/9qNdMrEltzAowOUePF
         LmZDoEHtK+Q7WwdWQvcsurytspB/4qpxSDaOCZbfCeg1MiI04KzqTI4zZ0el9UGaDjgt
         mNRX9k9+UFti3poGp+bPIk9A8XFEntTd1KeUoiSF+GV7pFBxjQl2xh8yBnSbNy9p+0KP
         4ZgWTZ7M5R9oBoLvexapnEQikkFzofKqpp5cXaNdB7YNt4e1vxWIWOErE/R/ehjy5y6t
         r/rF2fkQETXKhiCgDuUmo1tc4VDuNT+PzOs21E1PKI2kbdqmWDetv4wpFLYRFeNHu1Ey
         GsZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sojiTnRV;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9ahENxMdCsbSh8Pzi62QZzMZN9INmnWeZWnPRtf8WY=;
        b=qSb9Koch2vk/Ut710l2AdpZzK7TaZvcFBMaHaP9k8GVI8stbbnsWwKCDcPHDKsetQv
         zkhmcPveCVze8NvQcrRBMi0yMsMlWl6PKoJDBa61P6ZrZ1GIxgJsitIRZy3Ys0akRza0
         YcY4cFs2fy2csr63xDsoBzV1f6FMJ9WERKbPSh815+62gSaWPmFJkUxoiWI0ce2H5Qn2
         WExr4V9+p3AgaBDyNA5k4RW2JCjGTq0pS5KWUMvkkA0nc/8Hg0X9J4KY7NPFXUSChn3W
         /xPM4c/zJnhlfIrQmk+AwGhMY5GWcPDhvBcqiLAWtL0umwV/uOHBlmtw6CP6YujReTyF
         JfKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=M9ahENxMdCsbSh8Pzi62QZzMZN9INmnWeZWnPRtf8WY=;
        b=GZlAlwX10JEYoki1JhgNSH+qA95s2Fz2IudyQ3s58UatIr1rPf60jJkJSYYkhU/GxQ
         hkGhamYMJRcN+zTpfah72ipqQQtQ+NkeXugn71ghLYxPQ1GHvx9JBSiGZFeNXrOK/8GK
         QG+RA0JAX/8fh/atOcMr3u5OXccDuwKm7kUJZStxhTk7eQJwnWYmoDcundXgAu3xq7a/
         Exo0jcq3HG9N900CfvuLfS63qc/ZOuq9ES2xRumVnCcgKB9XTve8QcJXA2VDej86NSKY
         maqpT88u26+lkA24N48yUaB0mJiYkDqvzYDLZQkHZ62DJGgk8jqKVjHDjojAJojAn4o0
         dEaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PubsY00wtTdejao01DCBRODpitvhtf77zaAmMi6nCHThxZdpKIPA
	SWycfJDXv68KePUZWo2Fkcw=
X-Google-Smtp-Source: APiQypIJeKYg/WDlr/07a/iWEp7Q/VHLG1eHsYY54Ykl6IbsiglDYioQt2ChqHCj0CGMNrUJzgJqsg==
X-Received: by 2002:a25:aaa2:: with SMTP id t31mr32445763ybi.352.1589265455689;
        Mon, 11 May 2020 23:37:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c751:: with SMTP id w78ls4441057ybe.4.gmail; Mon, 11 May
 2020 23:37:35 -0700 (PDT)
X-Received: by 2002:a25:9cc8:: with SMTP id z8mr32597708ybo.473.1589265455404;
        Mon, 11 May 2020 23:37:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589265455; cv=none;
        d=google.com; s=arc-20160816;
        b=KCRftHGgTF1gm1XnL2RSdxZWdFz7EMFMeNU5aWKeErhlG8Xap2KIZI6reKCEPvkCyK
         jT2yWWeSO8K+lhe6A+IZPD3gIlPzYE7B1dL6tOyt2dLUmxipOiNd4xOQM9SMNkhD9QZE
         UPGe5Ha0qxoDNBOSSnznb4KEQ5sBwJm7vcUqKLlq0WxJZi+yLMDTc6ZqpnGGRRJ4J6i5
         aXjshAq0fp9zO8exD09UBgrnJOFRrtvTNLusNDoEt/0i1vUnCiXNzO1qH1tdnS2GXhLn
         01njPhgnawYPupAcfZMtV4k1lY/Enea+uokhleGrSdlUmDi3zCYhqKikw56UDvaiR8pU
         /3hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=1651hml94itcBwsjvtTWaV0HQzrkLzDlegx9TLq/qRM=;
        b=MwiOwp4H+VDR670947H4USjQFethR+9tZHdDslu9FOxnplj4DYZkvMlZmHHxxh4kEy
         QD7E7fKPaWEwSiKwpHzfQFxzbSNdKxPo02LPoj01zpq42DX4Cv43xknHRTvaoEhBFmgX
         8pwrm5DCN6d46W3dtIbJMa2RpHcTn1urIXB4UdIA7q7A6ml2XaUpkRZdkbtcIdtUxm3k
         JQwrQFrgQ6ZvNoXVcz1ncHG2U1mXsdu7KNKctMQXtEk7lSlAGW3s00sFicM4iuqDUqTc
         dGBEoHXZ2YoaP5G6Bj7dVDUycxTzuCFM3QFM9dVhAU6FwWLUXQ/VXajElwqV1UKqCXKQ
         BtWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=sojiTnRV;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r11si580806ybk.1.2020.05.11.23.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 May 2020 23:37:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A45AD20714;
	Tue, 12 May 2020 06:37:33 +0000 (UTC)
From: Leon Romanovsky <leon@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Leon Romanovsky <leonro@mellanox.com>,
	Ingo Molnar <mingo@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Michal Marek <mmarek@suse.cz>,
	Peter Zijlstra <peterz@infradead.org>
Subject: [PATCH rdma-next 0/2] Fix kasan compilation warnings
Date: Tue, 12 May 2020 09:37:26 +0300
Message-Id: <20200512063728.17785-1-leon@kernel.org>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=sojiTnRV;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Leon Romanovsky <leonro@mellanox.com>

Hi,

The following two fixes are adding missing function prototypes
declarations to internal kasan header in order to eliminate compilation
warnings.

Thanks

Leon Romanovsky (2):
  kasan: fix compilation warnings due to missing function prototypes
  kasan: add missing prototypes to fix compilation warnings

 mm/kasan/common.c |  3 ---
 mm/kasan/kasan.h  | 15 +++++++++++++++
 2 files changed, 15 insertions(+), 3 deletions(-)

--
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512063728.17785-1-leon%40kernel.org.
