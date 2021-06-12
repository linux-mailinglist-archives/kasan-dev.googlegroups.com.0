Return-Path: <kasan-dev+bncBD7JD3WYY4BBBJH3SCDAMGQECR5EG6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 388403A4CEA
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Jun 2021 06:52:54 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id b9-20020a17090aa589b029016e99e81994sf791022pjq.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Jun 2021 21:52:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623473573; cv=pass;
        d=google.com; s=arc-20160816;
        b=a7WSpS/M26auO+mKmDGiOXRvtkslRQWiXdyXajjWepAlIW8VGjZmHr5UpOh3SfAMId
         wbYpGOlw/RWsZqHdQv+BVH5/V7GZ07+2kD/AFAoUlYg5ZUf0inGia6wBhsn6ak3fG15e
         DV75Nf7zPfnqCMb1ypHeUGmr3trVdgZaMQekcqVQDplJ+N+7vzdI4vYeGWUwnKWj9tcF
         kMftUi+zbCUtX4gxuyYrxe6PTPlhFJ/a54sLHQFuPK6tcKZZh9C55IxgMVJIDi9V7yZE
         rovnBdX2XIytHp32bLce9lTcmSUunrMpGoL5H0lTcoQEJh3xYmvB89ITBWEd+rxJ2ets
         2Q2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=+6+UU+4rD3YockEQMpPMGrXB2s3gsn+LNlTcpescJm8=;
        b=JBIVaCho//j+QtPQrxFthC/4ALIvhsKP39xUkd+GxB/MtxWcdL3sNegOB2zqC/Xb16
         7NgpYo5Pc0iYWA+CmQTorqKVVrqbBkccAfTuNg3/LUvHNLfAYfAKpu7vhnWEPvS0487Q
         ppPcGZqJLM7eRASTJXhzaLEnOhV8r6jZKS0A89I+dwJUDWIbYoKeh+B9hQ9h8MjVGH0C
         pTWydBPi5UaymoQFzXW309m2OaV24CTaQadV8hDK8g0z3YpTaw0U7WXyf+52SufomXGp
         YGsgOP6om/eKrL19Rz7KYd6Fah8Ms7Cgf40WSjJVBdCNxLeAFP/+XvHL50vdrGHd/19r
         wL/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=n0uBf4U1;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6+UU+4rD3YockEQMpPMGrXB2s3gsn+LNlTcpescJm8=;
        b=oi/MSVT9mmxBf+UOp2qXcMY0sBmk4NoLXwBkUeqWFul8fQezqsaX991I7Z0+1JHnvz
         82DJHQp2tbnFLzKkr4BVrTrJ78S8pk2UziWJ9R0wkguHbo4yVTpJcvnsFUpnVDqQFAQ4
         /6qFhato0HSkO3ofHwtVhlZrD1OiKAFDpHDFIGjnkNvcAMXcNEQ5/jB3FuitHYtFp6Ji
         ymblxK9Huc8SIzSncjw89a5t5IRkdvmXRmdKpwUMSu+9Va9gBP8Od25DYf87nUx+sSIA
         QDwo9e/erDT28WD3u4kIzURjXN0J/BDHg/geSqyxrBR2gK867rXVdixsHWjP0vMePAfP
         Di3g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6+UU+4rD3YockEQMpPMGrXB2s3gsn+LNlTcpescJm8=;
        b=Xnev+++BXrzhAa4kJ7EQf0Ww6+FLeSHhFC/tIinoHt/z58/fSbGx2rgy0H+OWwhfap
         RluPme7KRv7i9XSt7gWxTpMKUnSgJIFgJqs+kmUR3f134y6cMRqyKe1Cxj3E6VOoNw/M
         mcFmiUFRd9Q8EHh2jkizoNMVOZIE3l9hRBS1GNBli1fC5CQhCHxQeLRMaL/zun4eVkgU
         UPNnwKl/5v+aNTFDHClFMI3OaFIXQXCWtz5VOJYeXypjONjlbhepuHUd7I+R+kgOw6uA
         w9hFUkhXMDQKBRKrtp0CpzOG5s/8PMo2/dsRgDjUIO0bC2HocIQ81XNnvsq2hdV9jWhc
         DXYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+6+UU+4rD3YockEQMpPMGrXB2s3gsn+LNlTcpescJm8=;
        b=peq0XIqSsBZjEgLFp5MBweZNhMOQaUdtZTVbCChDmBdpqlAFqaUDXabURThsJim9hK
         /iQ6DF5Q3pxCQ1cYUdmR3ORsBgUdckYuJ8P6PkuGVPSO/fsOY5bBjoMyajfr1mYlEbhe
         vCBYH1iPph2WBNDLi9f4EkR62wTuG1ZkgGn2tnX39Mhg2inw0/FKrJ6MJS3qrrEWngrJ
         N1MHfrQ2OD+gi+5TXrw/coU3Fxi0IgmqnhWpnUK+pzC0pZg1WGb5t8Cz39X/NJIAEoak
         Va6bFRL0zfC9lZr7ZCfjGgiZf9OqcRVZjoDvw35810IZemNBMDw8CELztPOahivZcX4G
         jGug==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Ef9+LLxUCA8bi0iob/Lsvsrz9eSO+HS/D0AInG72n09+bOlKd
	Q45yK1BXqXBC2pnQEyLDWeU=
X-Google-Smtp-Source: ABdhPJw/EVraMzXvM7fwmgGfEB+eyri1CnTFh58Q8AywcxQ4UA3rL76eqniVWZcfSQNaEKf8KM5mmQ==
X-Received: by 2002:a17:902:e546:b029:114:6677:ec2d with SMTP id n6-20020a170902e546b02901146677ec2dmr6961904plf.72.1623473572984;
        Fri, 11 Jun 2021 21:52:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:501b:: with SMTP id e27ls5256083pgb.2.gmail; Fri, 11 Jun
 2021 21:52:52 -0700 (PDT)
X-Received: by 2002:aa7:9ab3:0:b029:2f7:e053:f727 with SMTP id x19-20020aa79ab30000b02902f7e053f727mr1317639pfi.74.1623473572490;
        Fri, 11 Jun 2021 21:52:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623473572; cv=none;
        d=google.com; s=arc-20160816;
        b=pYoEsmYI0ypt48fg4PeAQ3PweZdfZ6JOsUTemm/lZfI+Q9rw2RQKCdusjsERi4T2Lb
         g5XA3dsecwoUkBu0bsDZndxuSo767tfsWwO5mhE/O68rUnOFKrX2+9Xjlh/+qkOCAYnH
         wbym+NLPiJCT5BruHtnt/BES51Tymb7nCSv2LAu4xrLkRZ5JOb1SaXZy9R7Iq4ogHWDG
         lZfqTuQhDGWUpA75eldsEK452B1JDHO0iZlhmM3skmk5I7mHmrCpIfLpQv9wclDYPiZQ
         /b0OMM9ws5/I2Swr/GSa2bQ5hRrhfqijtNLxlf4SDRiVue5wQPA2x4kyGWkC4ib1kFFU
         iXFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MnfTyPm3bgkOaqftF6Jo/n40i23c68ZJNhoFhLCQROQ=;
        b=KYpsWNy6lOrYEtnjq5UZub4pGWLlx7f9nU8w83HKIcd93pIvplF1JwENqDKLEWfhtv
         SDAJW+zAPGtxDlIg4dQ0boYeL2Mr5PYbhZP3IPDlVbESnKkioywzd64aYyiHaev/Ihrl
         EmrVYTiLwSFHgAbgVuHz8aSQvEjC/0KhauNJbyOz2tlCpk0KYNuvogNjfRNGKAunKgTJ
         Zwd/rSJu0uGkQlRrDZ2CbmZJKgeX4YvD45HK2nPydJMkSQho0lBXf3m81bTTNumH32xL
         CXzX5NJpS3KkkP67CdxcXEJASKZfqKqXWlmb8qa+cvPmOCzHAZaCsWskSW4XiwKZBVdM
         2aqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=n0uBf4U1;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id y205si1035727pfc.6.2021.06.11.21.52.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Jun 2021 21:52:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id g24so6774815pji.4
        for <kasan-dev@googlegroups.com>; Fri, 11 Jun 2021 21:52:52 -0700 (PDT)
X-Received: by 2002:a17:902:d305:b029:10d:c8a3:657f with SMTP id b5-20020a170902d305b029010dc8a3657fmr7008127plc.0.1623473572326;
        Fri, 11 Jun 2021 21:52:52 -0700 (PDT)
Received: from lee-virtual-machine.localdomain (61-230-42-225.dynamic-ip.hinet.net. [61.230.42.225])
        by smtp.gmail.com with ESMTPSA id m1sm6076572pgd.78.2021.06.11.21.52.50
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Jun 2021 21:52:51 -0700 (PDT)
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Kuan-Ying Lee <kylee0686026@gmail.com>,
	Marco Elver <elver@google.com>
Subject: [PATCH v2 3/3] kasan: add memory corruption identification support for hardware tag-based mode
Date: Sat, 12 Jun 2021 12:51:56 +0800
Message-Id: <20210612045156.44763-4-kylee0686026@gmail.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20210612045156.44763-1-kylee0686026@gmail.com>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
MIME-Version: 1.0
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=n0uBf4U1;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::102d
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

Add memory corruption identification support for hardware tag-based
mode. We store one old free pointer tag and free backtrace.

Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
---
 lib/Kconfig.kasan | 2 +-
 mm/kasan/kasan.h  | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 6f5d48832139..2cc25792bc2f 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -157,7 +157,7 @@ config KASAN_STACK
 
 config KASAN_TAGS_IDENTIFY
 	bool "Enable memory corruption identification"
-	depends on KASAN_SW_TAGS
+	depends on KASAN_SW_TAGS || KASAN_HW_TAGS
 	help
 	  This option enables best-effort identification of bug type
 	  (use-after-free or out-of-bounds) at the cost of increased
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b0fc9a1eb7e3..d6f982b8a84e 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -153,7 +153,7 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
-#ifdef CONFIG_KASAN_TAGS_IDENTIFY
+#if defined(CONFIG_KASAN_TAGS_IDENTIFY) && defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_NR_FREE_STACKS 5
 #else
 #define KASAN_NR_FREE_STACKS 1
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210612045156.44763-4-kylee0686026%40gmail.com.
