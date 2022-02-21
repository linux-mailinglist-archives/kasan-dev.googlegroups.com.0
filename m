Return-Path: <kasan-dev+bncBAABBMHOZSIAMGQE2REHX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id D98824BD61E
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Feb 2022 07:54:41 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id a12-20020a056214062c00b0042c2f3fca04sf16185238qvx.21
        for <lists+kasan-dev@lfdr.de>; Sun, 20 Feb 2022 22:54:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1645426480; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q/vkysPal2zJqScDMDlUpGc8ZSeeGf3ysquP32wk6MIgQkwLsymTE/aq8TqFPrgQhE
         Zr0prjgZwURtCpxkEG4ff88dHUp0bOrbnskTuBaU9KA5+l/m5l1ZGaBM0I3sYcdkHDfC
         3zH0uCAE8Ve2xedfc2OrPAc2Isr4ImQH4bdVjCZl+2va8dktqLgnuxWFWZG/ld2wiZgT
         ZDSkgkdtBQPO4UkRWeIKyHB7PQnnvRKs878z7bqiB7BvQNge4WXbOY7mVWDikmVGpZAX
         me7wbxmNHVni3gs6JyYFAGkBNODnn+mgT0ZwlAoaeVraWqj6Glhg5HophRs33/vEDV7w
         GYHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:feedback-id:mime-version:message-id
         :date:subject:cc:to:from:sender:dkim-signature;
        bh=WhZgOcHgdl5nmEV72mFpoBNdgaiKcXQsC52kqjW7NgM=;
        b=iUTgJnM6UpszNrHWppHxewKslEUS+Uzeu1gXhGL9BTfB1EbcBzhIRx7QAWUhOjPGfZ
         YhWm2m9tC5CMi27kaK1zvMCb97CJ4ZWtdjeDfHekWNghjDPx9CztsHDaB+h1k+evU6v4
         4UxtTTQEKDY5Pjjg9SW55qBau6IKn9WbRs1d7p6qolQWZVpyz+nGq3Rhj4XYmjk9fCuA
         8XGpOwKIBvsqhMruWyYHIeXL0wBSbbUAjF6bevRy5yf6BZz0u7Uh4SgF3iuIYn87eO5U
         DbuvbaTLDvJQpaB6DQseJttSuYRW//fiJthQB7GqBeE6uwVicSJ8XLLsTGyXAjvGT080
         Gptg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tangmeng@uniontech.com designates 54.92.39.34 as permitted sender) smtp.mailfrom=tangmeng@uniontech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version:feedback-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhZgOcHgdl5nmEV72mFpoBNdgaiKcXQsC52kqjW7NgM=;
        b=bdvQODf8HMdteCmeqWarbQ3HjU8Kytnqg9GnDkoGXmhkkTT0kl6zFjFsJ/a5lX6TS/
         hFyZZiTjcXjk4199G41rvmRVUeYmW0kDmltZtpcnmFN2NLSqmIERf+3Oq/KubiLAZlFl
         hoFqmRST1ZEyugkFIwOH17VO+G5hJV83TXzk1Q1xUtj/2EceClu1Dk2UYp3gKoNNrg6Q
         gbA6p4UaMzYhMwgUKA4pxQctxH+3a2ooH1074s2j/rGOYC+FeSpOuTd8IxrX3fY1wSrx
         SJmkoiNfcKcIuqEtwC9VbdhOxzPfQ5/AnU1pDKIT2MlZ9RTNZLXDa4kyefOrNLZLGpiL
         idLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:feedback-id:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WhZgOcHgdl5nmEV72mFpoBNdgaiKcXQsC52kqjW7NgM=;
        b=7TjKIMarajrZQfEvBagmKctGssl/2lsSOCduBcL/wknU2FKU8MjZnhs/u6GJc7afbj
         +SZflOyvhdh6mBWWdJRIGGKnWMk0hsp7ahfaod4R3DhmVGW0K9jWBduan02Oe24z7P+G
         3HEFBW+AZ+YCxHwq5bERXD9cm4NgaPZP9eTGRo60Z7xAfZcToE84puqZqU06f1Ivp75C
         bX2UWe3RTWstQEn9tru/zJ+GIGAO2kRr/xg5r69YH97Db+gypgczjhlcUGwlAZaWK+42
         yh6l5rIysKIKlJaYxxLYg5249N0yyv0jvNlQ9WDsOEwGZxT5RYhkwV7wl41bmGd79OEC
         Vpiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533lXPuR3BWO/g5yWgnyPTkCyaLjG2tP7SoffXoC1I3EbM5yiM18
	3v0aFiQzuA3m3UOIXICY2Ws=
X-Google-Smtp-Source: ABdhPJyUXyIfq4GpkZIuJ0MCqTI1aK5uaBg9eBfpZkVRAoYyECjBVv+ewAAWQzM4EIFOm5SsdogKdQ==
X-Received: by 2002:ac8:714b:0:b0:2d7:fbb2:eb05 with SMTP id h11-20020ac8714b000000b002d7fbb2eb05mr16512041qtp.380.1645426480528;
        Sun, 20 Feb 2022 22:54:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4562:0:b0:42c:2e61:5e0c with SMTP id o2-20020ad44562000000b0042c2e615e0cls5064369qvu.2.gmail;
 Sun, 20 Feb 2022 22:54:40 -0800 (PST)
X-Received: by 2002:a05:6214:27c2:b0:42d:adf:ab1c with SMTP id ge2-20020a05621427c200b0042d0adfab1cmr14057133qvb.83.1645426480141;
        Sun, 20 Feb 2022 22:54:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1645426480; cv=none;
        d=google.com; s=arc-20160816;
        b=W4uiROIbm6YpYWizRpgn5cYzKUF/WJPPd5zdWMLqdQy/x1MWL+YCGL5lJx0DxXF/QW
         ehCiRVno3SoDvDFHlzdUXJB4xOU/YIOaYTefXmGtTOl+13FUE2jvesDpGH4r/1HOjfvw
         IDUuvgBgr0IHeQQqIVGyHSdcQVyJxnVzgSWMxEdtW6IRqnUCHHL4DjNeLGXsjewpPUxi
         MErkAqsm24LZ+G6ZO3HWL5G6GtSMpIl9hcSMHuw1Mk9NJVa56RyAcJ7zCYljdsK6oyfu
         0yDSaUDh67akuL3DbdDQhm4tMmCo5fvjPfdfD6G9yEN0OQ8sflJVBQH3W6ekzTQyX+py
         GrGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=feedback-id:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from;
        bh=ggZkfDlGPpp9TVy5fP8ptMzqczJ8/QYBMafWemSn8mE=;
        b=uo2kbKbOa+HuCqxX4R0ZWnEL7iq7yNdPnEl5N3OE5/tgmFxdho/azMEv4zT9RVCcq/
         tj+op1VWcnCl0AUYSo39f6mKDhSE3VW/FgrgKJdiIEVt2THMWmkYlrvDeev7ZnjdQFCx
         MMiTwqb77tViCyyzfdO1y+8HCCwE6vPIzBdcGxhamIEgVvh+IDOok1IgSB8nsKW+/XzG
         iD2xO8q50OmuANIeH1lsC4KYCTK/cbt/PreJDQmZ6EJKiLp36lC2wZI/p0sdDUFSCqhE
         ZvN+SHw6aNr9HxWJ0P1wP6Dpc9jH9EPRggdRsV50Nilpx19SGlz1mjjGLxUkf3vPCzb7
         sI3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tangmeng@uniontech.com designates 54.92.39.34 as permitted sender) smtp.mailfrom=tangmeng@uniontech.com
Received: from smtpbgjp3.qq.com (smtpbgjp3.qq.com. [54.92.39.34])
        by gmr-mx.google.com with ESMTPS id l9si829926qkj.1.2022.02.20.22.54.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 20 Feb 2022 22:54:40 -0800 (PST)
Received-SPF: pass (google.com: domain of tangmeng@uniontech.com designates 54.92.39.34 as permitted sender) client-ip=54.92.39.34;
X-QQ-mid: bizesmtp65t1645426468t8ck3ryh
Received: from localhost.localdomain (unknown [58.240.82.166])
	by bizesmtp.qq.com (ESMTP) with 
	id ; Mon, 21 Feb 2022 14:54:22 +0800 (CST)
X-QQ-SSF: 01400000002000B0F000000A0000000
X-QQ-FEAT: Y/4E1fKPEOoHnnNVc6AB9rh2DW/GRe7QnuF/5RjEkyjLmBpOyu7pxCD+MgaYi
	edrAtbETZd5L0Qq2Gjwbi0RuPROK0agkqZzt5Pp1YvKB8//rYoEzvriBtAHlRO45nSk7G90
	kH4A2AWEiDU1OQshBVQHQL79KYpQMb+Ly4T7IxJGcNkGJCzht/36xS4IpixCpzPotOGNVkR
	4vI0ryjjzuD1gVuvh93fahVS497MDBslCX/K6UCuv6sorJeFMVOb2vfNsG0FaDCs6IEf77m
	q8lIdumnsG+0DOSy7qkTCRuC4z4ybtewhec/EF7mGy4kiwmz0W8QCYLG9RrZ2u06eK38Eab
	MGoj5OcAD8rcA49FON/4FY15NHN+8OcsXUonupheNvw4jSLvFc=
X-QQ-GoodBg: 1
From: tangmeng <tangmeng@uniontech.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	tangmeng <tangmeng@uniontech.com>
Subject: [PATCH] mm/kasan: remove unnecessary CONFIG_KASAN option
Date: Mon, 21 Feb 2022 14:54:21 +0800
Message-Id: <20220221065421.20689-1-tangmeng@uniontech.com>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-QQ-SENDSIZE: 520
Feedback-ID: bizesmtp:uniontech.com:qybgforeign:qybgforeign5
X-QQ-Bgrelay: 1
X-Original-Sender: tangmeng@uniontech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tangmeng@uniontech.com designates 54.92.39.34 as
 permitted sender) smtp.mailfrom=tangmeng@uniontech.com
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

In mm/Makefile has:
obj-$(CONFIG_KASAN)     += kasan/

So that we don't need 'obj-$(CONFIG_KASAN) :=' in mm/kasan/Makefile,
delete it from mm/kasan/Makefile.

Signed-off-by: tangmeng <tangmeng@uniontech.com>
---
 mm/kasan/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index adcd9acaef61..1f84df9c302e 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -35,7 +35,7 @@ CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_hw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
 
-obj-$(CONFIG_KASAN) := common.o report.o
+obj-y := common.o report.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
-- 
2.20.1



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220221065421.20689-1-tangmeng%40uniontech.com.
