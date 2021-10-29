Return-Path: <kasan-dev+bncBDQ7NGWH7YJRBM775WFQMGQEEIFAYKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id B8CDD43F666
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Oct 2021 06:59:31 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id x13-20020a05640226cd00b003dd4720703bsf8061054edd.8
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Oct 2021 21:59:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635483571; cv=pass;
        d=google.com; s=arc-20160816;
        b=vm1/mZb+dJhN2N0Gk/F0DkzQ9Jmg7KMG1CTUojj3qV8T5tLJUey3PKoakw3UThzdLy
         j8JovgUYPymCu2heWS1WE+KBp2rzt19KKxertrTb5nQXiQNg02Khb+bAsLY2kK03hiXp
         SDNI3c+jVUG6bwETtcDdyyd5zT5KxDkhNCtMOyDECQI5Lb5+3E9kfH3cIMqcPYb0ziV2
         GP5gwp/k2wfknJhaOrU4sQG7OCNixsNa3wgJsS9cHV9Kpsy/KkoQ8t04qm6rpc8K2fDz
         ruyDa8sjPzF71HfbyUqCPOCjzV0MHxbyPrazXwVkTwhBXMJjxcZ43RVIpwnyf0meElbl
         1Dww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=rkgDbSkGK0to8aYCC+ojPjJnzo/Fxm4jVyVyY7VVxa0=;
        b=F+LgyigyY/ZE6hlDLDfEABPOg0Rqn1WV2IKwCTsvgITTvOKPFPLHvn24YXyU3d0ryJ
         OW7hksDiKv1SGr88iNMJcwNk1DsS3gVlFZ8fZ0nXit7Z85vXMCqGoKcspcRsfFHQqs+z
         F6yO+cwRzYnY/DqWptaeX5u/c3rGx5P+xpsb/yDtxzLrIuR8r9WSp8uW8htJUquo779/
         eZYws4SzoGyOWSylwXHTvkkYZ4LYNrXXmlyxOkwTdg+6bB43hlCYLRpukVg2M6wwXFFW
         0mXyIM7EJoF4CqGOHMnGK0JK9uRZreNHW6KvJvb+m38XqULHXROw4U2KJcJ4p7VZ+dV7
         EE+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Ojjjrddc;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rkgDbSkGK0to8aYCC+ojPjJnzo/Fxm4jVyVyY7VVxa0=;
        b=bP8IfkfL7UV0AXuwO7XPkuZJOZrr7ypPIq2y0xzahW9bad9YXUUU22qeVfVehGA43h
         xwbgBeEr1qWlbaoPMlPFTn5QOw3ZnVP+PdkK9XNYjZ0qbRxhag18b3hSo2DLHPwPFThn
         MEDiRXXkZdTu8Mq79V6LvzH5+o5Hcph5Dm1LrQcSC8JcVZuKa1NNm/Ah5bAnZ/DpzSQD
         symo4omZCXOZE9lxzkHUvEk5gUzTdUg4niX3u7O/ndmWIWv/iRgFNrSsUKJPrgFpTf9h
         i0aIGkl+bJ2ta1+GYAceP6bXkb/NOyQtzkqD9GNPk02OJAVuIEm914fktgVYjpWg86Tj
         V/sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rkgDbSkGK0to8aYCC+ojPjJnzo/Fxm4jVyVyY7VVxa0=;
        b=Tlwh6UqUx3RB1xcflqPDeR5fW3/beLVAp/C328mDwEX/bhU6c3SOy/wEdruWKGSjzo
         KYb4QpF65Ip2j3vrBHtnjkDSpKvVX6hvSnhltwLhgB+zU+LGg+rQ51nAesX6Bc8Sl/Mo
         qttzGOcDEdl7TtF1R0PvohdZryXKsNTgO3r9mAITg08UJk7AHrulkc026c7xHlelrIKy
         ryCzwAzsr2T1XyvhBQK+QF5wIfXq1Nrbk6jbvJ6u7mYGHorIY00EoJGAz2s5kFiLQgXo
         //unVcMnb3gklPYJjt6JS/JReKw4MvCoNlKmS5JHhLIFm3fEYaDe9oBZfcf0n9nT5J79
         NuJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MiQEKHxEdQ9G58nLYoQ670CdHNaY3FwTH9mn7g7Rmgi93wI4h
	teDHUWSFDWhYcCapTVogRH4=
X-Google-Smtp-Source: ABdhPJxsImaqSbB6EqESjNA9/PCv3Ivmj6qQxmlc/ITYOkksm98Lf5zEywoh96jeHcwaX4BSm+qvTw==
X-Received: by 2002:aa7:d2cc:: with SMTP id k12mr8946809edr.243.1635483571527;
        Thu, 28 Oct 2021 21:59:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c944:: with SMTP id h4ls2700605edt.1.gmail; Thu, 28 Oct
 2021 21:59:30 -0700 (PDT)
X-Received: by 2002:a50:da88:: with SMTP id q8mr11967013edj.260.1635483570645;
        Thu, 28 Oct 2021 21:59:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635483570; cv=none;
        d=google.com; s=arc-20160816;
        b=KdZC7WOjt8KkQgQPuDFHd3XDg8BXZqPS6ioGMiToD791yHIPRhlbptBq3YeIX7o6eH
         gjl96TOd2/1Swfmd9V1xnIEBy2SRzKKjb7YHlt/6i+BD3b9eKaUdHATBQHnf9YmQTpXW
         OGP6HNm8fjgWVxwq5AF1hhU2KW9dhfP+PiUxBePcAikMhlxFQb4T3gG0eEqz34/ssJJs
         v8c75IFfkl2VXKR9j3l98MSm8WLuauxu+04jBRLDu60VT8JiF0nyPws3mr0uruMhPJI8
         5SjC57+DLchIEEu/eALQiZJLYU59WREc8QOSsGm7YDmNo/uHBeDS0Hxiwh48Ztla7qZa
         QGvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OJg5Riv5SEPQHw6GUzsRnRLEnZCVPUrqTKYKL32qSlg=;
        b=NPe2ycsXA6E5dJWMeQq3Bql83X062Hq32TDkIzr/1LKk9121x8POaaBgzVZdWC4UbD
         fsppjH6RWPgt+ceMKQyKbJM4cZAuehFfGQ19ilSDsR/ZuYAS7lD2bzLgAg+YA6hu0ikF
         wD2D50m9DcunkhqJ0qUUjFPVdcs70ifkPcsDVZJejunbbJl6vwyngSYf1r3Y/ZVNiLD4
         C09BdwBwrMCmQoUP5qBdqVJ8BCN8U+nP8uZgR+CzeoksPLCMS07zW6tkjlwK8KOxBPtB
         8v+cV2Y5ItlEPNLMSGW5pkDb8r3hMciiFJSvO3kGg8wCVDaG1tfh6AJqcGfERAnCiEXf
         pJyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=Ojjjrddc;
       spf=pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-1.canonical.com (smtp-relay-internal-1.canonical.com. [185.125.188.123])
        by gmr-mx.google.com with ESMTPS id cc18si303282edb.2.2021.10.28.21.59.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 21:59:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandre.ghiti@canonical.com designates 185.125.188.123 as permitted sender) client-ip=185.125.188.123;
Received: from mail-wr1-f72.google.com (mail-wr1-f72.google.com [209.85.221.72])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-1.canonical.com (Postfix) with ESMTPS id 49A723F191
	for <kasan-dev@googlegroups.com>; Fri, 29 Oct 2021 04:59:30 +0000 (UTC)
Received: by mail-wr1-f72.google.com with SMTP id c4-20020a056000184400b0016e0cc310b3so2976166wri.3
        for <kasan-dev@googlegroups.com>; Thu, 28 Oct 2021 21:59:30 -0700 (PDT)
X-Received: by 2002:a7b:c441:: with SMTP id l1mr8777199wmi.69.1635483569951;
        Thu, 28 Oct 2021 21:59:29 -0700 (PDT)
X-Received: by 2002:a7b:c441:: with SMTP id l1mr8777186wmi.69.1635483569839;
        Thu, 28 Oct 2021 21:59:29 -0700 (PDT)
Received: from localhost.localdomain (lfbn-lyo-1-470-249.w2-7.abo.wanadoo.fr. [2.7.60.249])
        by smtp.gmail.com with ESMTPSA id n12sm376620wmd.3.2021.10.28.21.59.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Oct 2021 21:59:29 -0700 (PDT)
From: Alexandre Ghiti <alexandre.ghiti@canonical.com>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Alexandre Ghiti <alexandre.ghiti@canonical.com>
Subject: [PATCH v2 0/2] riscv asan-stack fixes
Date: Fri, 29 Oct 2021 06:59:25 +0200
Message-Id: <20211029045927.72933-1-alexandre.ghiti@canonical.com>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: alexandre.ghiti@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=Ojjjrddc;       spf=pass
 (google.com: domain of alexandre.ghiti@canonical.com designates
 185.125.188.123 as permitted sender) smtp.mailfrom=alexandre.ghiti@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

This small patchset fixes asan-stack for riscv.

Changes in v2:
 * fix KASAN_VMALLOC=n
 * swap both patches in order not to have a non-bootable kernel commit

Alexandre Ghiti (2):
  riscv: Do not re-populate shadow memory with
    kasan_populate_early_shadow
  riscv: Fix asan-stack clang build

 arch/riscv/Kconfig             |  6 ++++++
 arch/riscv/include/asm/kasan.h |  3 +--
 arch/riscv/mm/kasan_init.c     | 14 +++-----------
 3 files changed, 10 insertions(+), 13 deletions(-)

-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211029045927.72933-1-alexandre.ghiti%40canonical.com.
