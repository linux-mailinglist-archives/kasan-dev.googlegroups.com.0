Return-Path: <kasan-dev+bncBDTMJ55N44FBBZFP32PQMGQE7DXIRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AC0DD6A0E24
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 17:44:21 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id b1-20020aa7dc01000000b004ad062fee5esf15495866edu.17
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 08:44:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677170661; cv=pass;
        d=google.com; s=arc-20160816;
        b=LGn3Otqigy9p7CXub6RaEeaXUrx7D94rBdrbOC/kwIelJ4J1mw0BepBo7Nmyh0dNzi
         lQXavKgiA/dGxAT95IEO4FztwJsBxQLECneRqtbw/7mZaMd1Zpx1rWYC8eflNyABT2Ka
         dcZ5ePqSI7w4rJjgHvwDxEt9sRfkZMiCPmXdUVvYr6pu4v2E47neMZYTCpQvJVurKwki
         z69Rx5T6CF4DSLsRmlEF8xjdyn/O5xtO4+BQEcQetMDwDbnv1uIC47nQ9GSV2txrVSX+
         dsptAyn9rMR1M/syo/29zXAMeJwAlEbXuEhubiltM/09kWVcGqNqsjnNlVgDyTweDfKQ
         a75A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2O9vYrWwdUNq2pBSVAWtyWbWiLZ2n0TLzWpMvL0GAac=;
        b=CPWQ1xSezg7fuLmLXuRPWm8TKuklGJIoZzyD1xaR9lU8RuTZ1m4iL5yWxRd9l/hp1a
         HNPQsG8B5EdAoLmDjsVMYBCBE1Nez/Vt5A6H68H20gEm+39/+DfTQrTBe/f/9r6rQnQK
         mtOsJvs+bBydFpGnfMqjP4YPk1zKx47+1a5tXTKuLDd3uqhrgmsr+SHUKViGYpmWd86O
         j3MjElayR+5DnCCSl0oAoXHy5/R0Ylqr6lQy1MfSghiVGt3x4STHTLoUYGepyUAqgWik
         HmSpCRjImX8YxMsjgIa8U62ZWxT6wu4RryvcepTcvU/wwp5736FJp5MJbZADo5G36HNq
         ny4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2O9vYrWwdUNq2pBSVAWtyWbWiLZ2n0TLzWpMvL0GAac=;
        b=gLeZ/gzjM/lXsO9ACekwcK8Qyi5cNvCLRSJk/eJVGBz4ethNvCHJ+vD7j4c/KgreuS
         miifSPbOGrqWhU87YSKf1SQ/3U27dNiH1irDSiTGetEKT/Ft5FUkUqKyqAWSxETKJI6S
         bBl6nKd5lExFN12uz8BeQCZVBgnJHHdjujd7/R9kLHrS3uCvSQ1EOXeFd60r4rlckVY4
         XKui5BpNokpSzmnpsRrcURF04DnCrTtLjmuMQrzMLnZp6WNMtJxHnZHTwuS/v5yvbnOa
         F7NmcUO80+8zldVruHoyZMi1FPUGsnQB1dRMTCNEtrGmQW9f4EIRafOlelKN1WVs5OTL
         56kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=2O9vYrWwdUNq2pBSVAWtyWbWiLZ2n0TLzWpMvL0GAac=;
        b=TGFH0ZbVZGatcP7xU9++86qKBncY6oVanhvblXvyRSczUYTkmfq99Kok0Cm0ieFD9W
         985nYvd+mLBVMJMVDXlN1kDbHrCUP55kxmkIGt1KZVp0Co4v61+oIeakzsYIgNrtg/qf
         gn/jGjXprmmKvq9YI/GFJ8p+N/+7QYIj9p+wqHSMxxWafklSceKiyCcWINa3zKD+Rxir
         v3oxIPwMb+x1/WykmKdLRtZYTwOMIOek9/fwLDr/pa5s3q0Azks5HtpzMTMd39tdil5a
         L2HOduIzeJk58CuPwqacgSGhCP66kfNhcFvPVZNzWV4CZTUA0gjgAu+cqmk8KgQ7a19g
         SLzQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWXa00QBjmYaSlwhUOTyP4dcYAQfFyIzMXHpGRIo12VNU0BlXZi
	hzJQxeAfqWfGfymd7Y6bVN8=
X-Google-Smtp-Source: AK7set8ZQ1LhqumeLO+KeuELiEHnOSzcMRVVa02HyfcH0rMSkAKTLMLzBYghMFENj2lAu6vdEuiO4A==
X-Received: by 2002:a17:907:1dda:b0:8b0:fbd5:2145 with SMTP id og26-20020a1709071dda00b008b0fbd52145mr9298499ejc.15.1677170661130;
        Thu, 23 Feb 2023 08:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3495:b0:4ad:73cb:b525 with SMTP id
 v21-20020a056402349500b004ad73cbb525ls172597edc.3.-pod-prod-gmail; Thu, 23
 Feb 2023 08:44:19 -0800 (PST)
X-Received: by 2002:a05:6402:755:b0:4ad:6ca7:6134 with SMTP id p21-20020a056402075500b004ad6ca76134mr13126120edy.30.1677170659469;
        Thu, 23 Feb 2023 08:44:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677170659; cv=none;
        d=google.com; s=arc-20160816;
        b=Zj2ps5zuAlLSAAbms788s0LRHs6MqIwGelHYGS+zxescPn4sj1MG7e8DIN7W/Fvv9Q
         ZmyK57kuxWPWEaeCGp3K7ARO9tePlKOQGHQecKih2ic5v31EimVdUlnXksrr+UPu0dkT
         KlOW1RYlYQFtVxAbm9eKDfWsQXYuNzPYFg4sH3f+fmDppsUUpKqxrcOCKyD/hk0dgzbD
         +BpjorONYW4m8VOVbUwtHBQllxgsBk5NkEsKE7grvwHcCDCS78G5v2mfxfyn97rb0gM9
         Eg3qWbejCGOFGLdVIPxaK62+Qz3EKyewiNMQxB/S47lw61IOxV/tLg7jH42hKs498BkR
         /52g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=eruQWB2/18nDotnnWoGStXzb4aFnYUrYHZ3mQIMO230=;
        b=iPV80zFa8OsJpt7iP4def+t9Hm5RGgDjLf5FM6H5gK8LYY/LeL96p01qpucmrUVdsW
         HHaUJcXbfYbOoJq+fWZmzDlrMCAilsIQFu3aYeYuvgSzWbqtwTyJpBPTCgkWBJ0qDSvP
         Eo+ZdqtY1PYV9PvUKZTP8bGpZsboJUrzrVVIn4FWtkuX2oVw2vWbUjhE9xUvrvcc/H2X
         ylQms5mF3oCA+Lo6NKwElEBL0T/YnpbKDgip+cBpnU5BaJMWeVPZIZUt7JREMxm3wGAM
         9Ax4agTCV+Vdu21LtB+LNbsCN8yX5vLwY1UU2T5An2/epBbXGyqdvWmU43pmffpQVmnf
         nIrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) smtp.mailfrom=breno.debian@gmail.com
Received: from mail-wm1-f52.google.com (mail-wm1-f52.google.com. [209.85.128.52])
        by gmr-mx.google.com with ESMTPS id cn28-20020a0564020cbc00b004acbe86bdb6si342322edb.4.2023.02.23.08.44.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Feb 2023 08:44:19 -0800 (PST)
Received-SPF: pass (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as permitted sender) client-ip=209.85.128.52;
Received: by mail-wm1-f52.google.com with SMTP id p18-20020a05600c359200b003dc57ea0dfeso11225654wmq.0
        for <kasan-dev@googlegroups.com>; Thu, 23 Feb 2023 08:44:19 -0800 (PST)
X-Received: by 2002:a05:600c:331b:b0:3dc:4318:d00d with SMTP id q27-20020a05600c331b00b003dc4318d00dmr9262047wmp.11.1677170659002;
        Thu, 23 Feb 2023 08:44:19 -0800 (PST)
Received: from localhost (fwdproxy-cln-013.fbsv.net. [2a03:2880:31ff:d::face:b00c])
        by smtp.gmail.com with ESMTPSA id m6-20020a05600c4f4600b003df245cd853sm14739855wmq.44.2023.02.23.08.44.18
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Feb 2023 08:44:18 -0800 (PST)
From: Breno Leitao <leitao@debian.org>
To: axboe@kernel.dk,
	asml.silence@gmail.com,
	io-uring@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	gustavold@meta.com,
	leit@meta.com,
	kasan-dev@googlegroups.com
Subject: [PATCH v3 0/2] io_uring: Add KASAN support for alloc caches
Date: Thu, 23 Feb 2023 08:43:51 -0800
Message-Id: <20230223164353.2839177-1-leitao@debian.org>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of breno.debian@gmail.com designates 209.85.128.52 as
 permitted sender) smtp.mailfrom=breno.debian@gmail.com
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

This patchset enables KASAN for alloc cache buffers. These buffers are
used by apoll and netmsg code path. These buffers will now be poisoned
when not used, so, if randomly touched, a KASAN warning will pop up.

This patchset moves the alloc_cache from using double linked list to single
linked list, so, we do not need to touch the poisoned node when adding
or deleting a sibling node.

Changes from v1 to v2:
   * Get rid of an extra "struct io_wq_work_node" variable in
     io_alloc_cache_get() (suggested by Pavel Begunkov)
   * Removing assignement during "if" checks (suggested by Pavel Begunkov
     and Jens Axboe)
   * Do not use network structs if CONFIG_NET is disabled (as reported
     by kernel test robot)

Changes from v2 to v3:
   * Store elem_size in the io_alloc_cache, so, we don't need to pass
     the size when getting the cache element.


Breno Leitao (2):
  io_uring: Move from hlist to io_wq_work_node
  io_uring: Add KASAN support for alloc_caches

 include/linux/io_uring_types.h |  3 ++-
 io_uring/alloc_cache.h         | 30 ++++++++++++++++++------------
 io_uring/io_uring.c            |  4 ++--
 io_uring/net.h                 |  5 ++++-
 4 files changed, 26 insertions(+), 16 deletions(-)

-- 
2.30.2



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230223164353.2839177-1-leitao%40debian.org.
