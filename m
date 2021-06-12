Return-Path: <kasan-dev+bncBD7JD3WYY4BBBFP3SCDAMGQEE46E7AQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id AC9B33A4CE7
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 06:52:38 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id ea18-20020ad458b20000b0290215c367b5d3sf20269886qvb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 21:52:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623473557; cv=pass;
        d=google.com; s=arc-20160816;
        b=jHOSdBlPBq2Z3H2MgLjWZxTBE9TW0PkR1GzEldpaLJzGjMZ4DcxzP+rhP+kQjuDnJP
         BxQl3vcP8vZmczgLbeE1BvaBNCWCgbES8sBhs3UOLO7GlphrqJTpe0cvO83Cz/y9lmqp
         3otQumDSBQ2vnAlqyYkq3Mw1/rV/UbSRvK/KPysE2zqlnOC2W6VFbskBh0YkeDWaDeyv
         XQJ1VaytL3Jv/08K8TinLgTtbpIjBGMUvMr8ltOlO1Mr5jyGSRz3KH/OBd9Tl3i6f8ha
         k2y7kmXRaeeVrMQ+S2GFfP/UDKetrnb9MYJHUCFumyWY8LvQBYuwHMnensuwpJ9SVXtE
         F1gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=A3GIaKltu1Iw/Xx1RyQt2yWoZryUmVgGHP/4qX9rLWk=;
        b=zUDEu/P5nLaG99ErmwlUgUxOvWmH6P1OgL0ra5jU6RE0hyBwKC/+iMFeNc/PKySx0j
         pHN5e6pQziNY3bm7qCrL+kRwLA3pi1YWToMpSK77DCzwi20nvdrTze7ZtD5TnB1UzsiJ
         JCd3uMdjNZLr3hGlO4C74PGOU1qZj9ggOjhvpNbML73j7laaEhvZVUTcnv6XnKCzImHV
         Iv+X/I5bZzMH5haeQp9Pzw3lvD+VteBYYAt2l6nUfZgTFNwmnaCbV7rT0TCiSxT+Ochy
         S3pHy6zzN4C5NTzT3WZKX8gAB5nT+8k9QSLLmsnkDTl8dkCCfyHf91bdUY299Xg5WWPH
         GItg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tqNr2p4X;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A3GIaKltu1Iw/Xx1RyQt2yWoZryUmVgGHP/4qX9rLWk=;
        b=i4rWKWXt328AoU7KsrER3Pzd/nAqGgzwxPxBgr+JV8dD73M+77fjnaarZ+ovQIRUw4
         cJre9aHacY0YpLllgcBbww5+wQDv7yakIgElHTLIA4sqW6I20C515YJO3jUrfkGm9gTG
         jOcq0h6sOJZPc6TVhJLGloFhsqv2cWsn9TgwCq4YNExODN0rjLmUW9HwAhdRzNJT39Uo
         Ir9NN6V2jjNBlTsMLyaExsjsZ0NOLJf9mhr6hU3LD/kAmStECBmXmSu/AA9QPbuZX2t2
         dPX6jfjWT8pQx/wdgKiuDPtPzgpAZ7wms3V6NR4eNFb+1eZTED8DA8vxOEsj0n75U3BX
         1zWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A3GIaKltu1Iw/Xx1RyQt2yWoZryUmVgGHP/4qX9rLWk=;
        b=mVUQtQUEuKEihccAl4RgcCp1ISB+YKxlRHqbWznSG7ax+skLwLG6hsLGU8iy+3pnhY
         kqkpkvp1GlB1tTSravxbS2GZndKZpdJsqHqEMPXZZE2oVBqR+Qu1UjrkelQOY7p3/JPa
         d8Pm/Y7/ab+9tahAWQ0JVbxYOIRkPWPGdS3n0cXJ5CWelw/IOf6/TxNMtxsaHeGJCoQL
         +0URvUi7KkC6CAb1as7jNYljoIEAfRi5b6nnCVRUbMsUDCFC37Tig8v3lS2HxzBOpqkC
         Cb2Py7CCThSzYcmOpTnrQdUXOqBf+o5KnPNFiIEcjJs3MIzoipIVzw8GWarg4IVC3fPJ
         CuUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A3GIaKltu1Iw/Xx1RyQt2yWoZryUmVgGHP/4qX9rLWk=;
        b=hy6pWZ38ECQi/WVmqiAYwa1EdzRAPSTyeP+i7RTJcL9/J1LTPJKddPOGDzEgodNRKy
         94edkE0+Cb8lzPZt7l3Q1VGAmrolf9flgxmG5WD5gHjbaH3xiPa9MYWw27m++ApyAPw1
         gV1dR2N/7JTu3yOtSjDTxprQypoRYWnvtV1F1NkvTyTkHpxgw5mAt+yEgbppxN465/0R
         lLn7o66/fbpdZ8wKPH046HCMQ0tTDNLQH5JtlEzHOblRXakHT0Y0rZx+kiXxPWVIoxjY
         c/3WrFGNU/Sj0jVTic2vBz9Xy3Ao5QvZHt3dBKyfGIyiOr2mbIChJy/G28NA0pjPXtZp
         L6dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5335wUFsW1fHf0WMQNtBb0xg1/9JlQqb98kE/VaWe37Qrq2YShWA
	SdogZayLh822A/IikxBjP2c=
X-Google-Smtp-Source: ABdhPJxrHma/WRW1vgcT8ZDKPLiO/5/PoEREwXgGmLWeL6R0B/DfBZSxZ+5XYcv3fxLm+QeDrH1sAQ==
X-Received: by 2002:ac8:740b:: with SMTP id p11mr5433653qtq.372.1623473557340;
        Fri, 11 Jun 2021 21:52:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7fcd:: with SMTP id b13ls5304658qtk.9.gmail; Fri, 11 Jun
 2021 21:52:36 -0700 (PDT)
X-Received: by 2002:ac8:75c3:: with SMTP id z3mr6963819qtq.308.1623473556922;
        Fri, 11 Jun 2021 21:52:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623473556; cv=none;
        d=google.com; s=arc-20160816;
        b=jRg74sgvtdWxwdouSeDE8aw33OExFX5ps0fEvxx8uzcwfaT9pTrQSDBjQjKP+wwlWU
         /J9PgWGtK0WnGYx6Xugi8Y1NdXeq9Uf2HSOn9cGAsS/u/T/J1XIxOo/vcqJ19K9YQIDA
         pfwGsu5CTqoP5toW4nVA2gicYaukj5G/43uo+wefdWEIkq0RohczkUd6nhX6BA/2N3KJ
         xgcb1QKCHbWkGvD15AK7eTLAE7w9GvCSTHYzwTcmhpB+Gtry8s/W1bgEubqCOYb6MZ65
         /POXlbpTkvsKTkbdnd7IhqgUxO6cYxSvuVZ1qGfCEZTqUVIzpYtEA5grGyKYFqg3xD4Q
         LjIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=CSf/plSIB/2hiYtwZfEusso9z7qFI1Lu/J4EiHpSzN4=;
        b=h+cRiDiz5eb2a26ySPmXXJNd1EnKwR/XnbFFgR4uxwubh2gvMrBpMKtYLIUCQHI1mF
         LLcOrYOpQ+ConLmJJ+28Pa2TsxGhMNPT7tbrEboVGZW9e6T0j5CorYVJ82s0dMlhAFHa
         4UfYazFOpAvgJ3H8FxlTBUDwv+kXnb8OYbEnn8zfyFNancnIU1wbKCbFzbndcgdt1Qf4
         RY5WDqv4iAhHU02q2dR1eQ5F8Stga548pdMwBfuHNWW3kN53osImIVDcn/nMOF+qUCSp
         6TwBhT+ERrffBuWu8Xm0ZsCEW5wlLOgQDvV2kFa7dQJfl+/ogNj9LkCxUFWvYKxCUhly
         /YQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=tqNr2p4X;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id w16si787480qtt.4.2021.06.11.21.52.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 21:52:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id e22so4086947pgv.10
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 21:52:36 -0700 (PDT)
X-Received: by 2002:aa7:96e3:0:b029:2ec:e8a1:3d66 with SMTP id i3-20020aa796e30000b02902ece8a13d66mr11484855pfq.79.1623473556125;
        Fri, 11 Jun 2021 21:52:36 -0700 (PDT)
Received: from lee-virtual-machine.localdomain (61-230-42-225.dynamic-ip.hinet.net. [61.230.42.225])
        by smtp.gmail.com with ESMTPSA id m1sm6076572pgd.78.2021.06.11.21.52.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jun 2021 21:52:35 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Kuan-Ying Lee <kylee0686026@gmail.com>
Subject: [PATCH v2 0/3] kasan: add memory corruption identification for hw tag-based kasan
Date: Sat, 12 Jun 2021 12:51:53 +0800
Message-Id: <20210612045156.44763-1-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=tqNr2p4X;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Add memory corruption identification for hardware tag-based KASAN mode.

Changes since v2:
 - Thanks for Marco's Suggestion
 - Rename the CONFIG_KASAN_SW_TAGS_IDENTIFY
 - Integrate tag-based kasan common part
 - Rebase to latest linux-next

Kuan-Ying Lee (3):
  kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to
    CONFIG_KASAN_TAGS_IDENTIFY
  kasan: integrate the common part of two KASAN tag-based modes
  kasan: add memory corruption identification support for hardware
    tag-based mode

 lib/Kconfig.kasan         |  4 +--
 mm/kasan/Makefile         |  4 +--
 mm/kasan/hw_tags.c        | 22 ---------------
 mm/kasan/kasan.h          |  4 +--
 mm/kasan/report_hw_tags.c |  6 +---
 mm/kasan/report_sw_tags.c | 46 +------------------------------
 mm/kasan/report_tags.h    | 56 +++++++++++++++++++++++++++++++++++++
 mm/kasan/sw_tags.c        | 41 ---------------------------
 mm/kasan/tags.c           | 58 +++++++++++++++++++++++++++++++++++++++
 9 files changed, 122 insertions(+), 119 deletions(-)
 create mode 100644 mm/kasan/report_tags.h
 create mode 100644 mm/kasan/tags.c

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210612045156.44763-1-kylee0686026%40gmail.com.
