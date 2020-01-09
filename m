Return-Path: <kasan-dev+bncBC7OBJGL2MHBB54K3XYAKGQE2EHEYWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 831CA135C9C
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 16:23:37 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id h2sf1636803pji.1
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 07:23:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578583416; cv=pass;
        d=google.com; s=arc-20160816;
        b=na14LwiFos9T5NfRDNz24mafUhRpquzJ4yE7uobrfnZ3CgWSDF9D2KA2bvZs/8q7Gj
         r92kAXDUBbpLU/mW6Zbql2ALbwagcao9nRvLTIIBMxDN9fmJ7NCUX/Oa2OxO/4xO3PoW
         sGmXS/L4UYnhszTjcBvX3XYtE285NM8N9GR7l3/K26vSPwOgEyihHQ/XX22Q38mmV25Y
         v27rAkGbWvcy2WiNXmwOAnV3QEsVRpdpT6hm0JIEU6YRASTX91ubmgjcSgji7R9vuQYN
         cwMWPD6zx5w52Zmwveh7en/2m/Luhr906WrMDHmPwO4WTWXX6AoL9yPzNXBL0EmviSt5
         d9lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=coxBMohhKENXmx2EFsF1guKiWBjK8Jd6/vkTL8fR2O8=;
        b=RA+ktIRofyrDVd6u/g8BmR8NVVV0wgrRQhh64TitZ7nbHC03ildu3D0v5lqUX7wWon
         VQNtYhcns3OY7RA+DR56O44T3QVRTHbFJxnqLSlsPreM7ppYszfM6e8zAWKg8e7oIZN0
         ZFx3wdU/WyA9e/Foth93YXK85GjtIXzGGZkL5duH1p+cnP4yBIauQ5+/M3eH8RYq9ZVe
         fly/ZAdDMkHLrz0WxzEPZAd6VGS4z9lMTM75iWqnYlUMr09Jz3jB7X1X8LKcVjmAUzhX
         nVodS2iMf9jFVRiaAaeHvYpRAYbTOFA0UQB8HgyOLEWHeGRvft2RqStOzBhis0Rih1z0
         XFUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d4yYCqe1;
       spf=pass (google.com: domain of 3dkuxxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dkUXXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=coxBMohhKENXmx2EFsF1guKiWBjK8Jd6/vkTL8fR2O8=;
        b=jIlY5FQ5xkM5u//BEDvpQftwBPme/68mAmauLFEDGNaaOzK7Tjz+lOMfNN364BWqR+
         BNQEG3npAbt4JyyDFIBsDxjiEiYrJ4KIU1r+jjPS8BIC/8CTHv0Tg80uxrrPNJ9oN3it
         +ZSBU6VHlhzBC0LKcU9nlBuLprgiA8CdvzOBbHfTqKXncPapjHY0IpYcKfmiy+rCkefo
         a+VUMKVOM/YdXHEzE/u7WdvUUYCFVM6YdsB967iWe+UE1TOcLHIupdkuAUzfoWDBRldS
         ET2SCy8vEfAG60iJYkXaYjNX5zZw9VTUnZcsPjhgIISyv+3chHg5QcwDIhXAjk3uWzvo
         wHEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=coxBMohhKENXmx2EFsF1guKiWBjK8Jd6/vkTL8fR2O8=;
        b=joghWAOmw0QGz97R0s62rQ67Zm/fYSoZ876SSyrUtVYqOQ6yFpZerUsY+PDIfa+lCI
         R+siv9kmbrt7Z2HDJ6MzCwLNX4PScV+cP5HVv3fqo1UpJOc+5cS684pQmPympmANqWDV
         tps8+8wXHdGYoj0b0P75Zx5AkHbu0RIPDBPsng9iEdf0xv2a+jBOgmbl33vPm9j/l7fw
         l20Sm+qTszixMI+pnwvfexCSG1L5gtsAvzI1mLdtbQVXEOsREupIEZm2NtzXBiEFRKSJ
         7vPPvjY5ZaEa4oqVIcq3WwrlvQZpBIKRHytZESt+/+lUdwMcLSYlkRlc0/PJ6EWfkDqB
         Di6g==
X-Gm-Message-State: APjAAAUffLV960l9uSKw1WQymSx2rq34OB/9t+T9mNHgzCugm+qZRciC
	0ObMYfKjl6hyJVVenKx6TiE=
X-Google-Smtp-Source: APXvYqw+aSdgeUpMx6wUqfGyqWsb4Jh9bP82b5eWUZSSt8bUqqdvpx7ZwemqPt4M1jxN96Ds67ls7Q==
X-Received: by 2002:a62:cd81:: with SMTP id o123mr12157311pfg.110.1578583415784;
        Thu, 09 Jan 2020 07:23:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:37e8:: with SMTP id v95ls715742pjb.2.gmail; Thu, 09
 Jan 2020 07:23:35 -0800 (PST)
X-Received: by 2002:a17:902:ac97:: with SMTP id h23mr12499546plr.237.1578583415335;
        Thu, 09 Jan 2020 07:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578583415; cv=none;
        d=google.com; s=arc-20160816;
        b=KgWVUjcrHuWzzy9rTus4nbbLPWLxxIszFmlBGs6hqbtX7dxWHCZVrqVnLa30VpAZaI
         tl1gMHyDbNpyFRUB5FNzc32CF4lvcuDvwb2L685MWz2FIcDyUEzPGSU30DCVZQPtMyEK
         MLe01N1rd0/QXhr4YykyoADu93NWP87Vlx1wt9NZ8zT7mBGwZBeaAAaszi9bN6k/eUgj
         hHmVqiAbH+FFrBn4+l1O2RO66EHQjc2nxGBjb9ayBZq9ZJPqu82sSKN8vcYwF4zivcPd
         r7nlfyxvrO414Q6X0mhDGjGmTXxyATGWIY2ape8LEWA6HHYl/igfOM4v3yvc5OU2dgrx
         5HxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=HNy7hZEHqrPvuhZduQmJRe1uIw5w6ITq0q+7c4RSDGM=;
        b=WNlz20w2oWJ5fgGh3774lQMdNoUWiZH68cBSkQDfGEgkqhP+I/wKyCZmUGr9fSXfsK
         7IqCn6QCSFqRPKjTD8+8oH/kr0WAH5Q7gA8nFYxuCNvraqObchBRytj2VeURKazCroz3
         d84OV6Mn2xIzvkqMpOFS+v835S+Mrl5XypCV3QGKEQAXvvVCjk9nMQOqScbCYmWuNDIh
         rZKYy1gpN31hwzAEsYf8uzWNKBKmcTQIiaq6h1boa8PbMBFUs1jTZpMRT4326+lg1uTC
         HtGZPp3UiJdue32zA80auu7RLjCQtwF7Iv7on2GIDQU8Df4rK1wFIOqZOMkZbHqbXQGb
         +yrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=d4yYCqe1;
       spf=pass (google.com: domain of 3dkuxxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dkUXXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id d9si298887pls.5.2020.01.09.07.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 07:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dkuxxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id j10so4355166qvi.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 07:23:35 -0800 (PST)
X-Received: by 2002:a05:6214:15cf:: with SMTP id p15mr9367520qvz.140.1578583414433;
 Thu, 09 Jan 2020 07:23:34 -0800 (PST)
Date: Thu,  9 Jan 2020 16:23:20 +0100
Message-Id: <20200109152322.104466-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.25.0.rc1.283.g88dfdc4193-goog
Subject: [PATCH -rcu 0/2] kcsan: Improvements to reporting
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=d4yYCqe1;       spf=pass
 (google.com: domain of 3dkuxxgukcvu18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3dkUXXgUKCVU18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Improvements to KCSAN data race reporting:
1. Show if access is marked (*_ONCE, atomic, etc.).
2. Rate limit reporting to avoid spamming console.

Marco Elver (2):
  kcsan: Show full access type in report
  kcsan: Rate-limit reporting per data races

 kernel/kcsan/core.c   |  15 +++--
 kernel/kcsan/kcsan.h  |   2 +-
 kernel/kcsan/report.c | 153 +++++++++++++++++++++++++++++++++++-------
 lib/Kconfig.kcsan     |  10 +++
 4 files changed, 148 insertions(+), 32 deletions(-)

-- 
2.25.0.rc1.283.g88dfdc4193-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109152322.104466-1-elver%40google.com.
