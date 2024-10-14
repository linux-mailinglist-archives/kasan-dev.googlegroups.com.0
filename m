Return-Path: <kasan-dev+bncBC7OBJGL2MHBBB64WS4AMGQE4IH2RPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BDA799CE64
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 16:43:21 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5e987736f9bsf3305599eaf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 07:43:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728917000; cv=pass;
        d=google.com; s=arc-20240605;
        b=eq2WjOZBHnK//oMScpPJS8z1cLUY3SzK8Y3UEIe/NNCKOU6FxZ9shhpj9miydxv3qK
         E7agbIrKLcfx/NlJGvNsdMyyBu1I+FQcEAEevALeVg69vNsDxULhYlxlrqpcMjSzTsMC
         ZDcEnyvD6ynvQUFtkoRnlMU6zHv0f+SFD7Xmiuc15fUFBrq6QEIvh9h2wTG2AltMGARs
         Y9VWa1sVN89klW9QHFt8QxOr72Gv1oLqbV3DBXQ/O7Vpfs5Ljfec36/R7EGQA8J/3NOR
         kIIlvO/wjBeMmlYCbo4x5f6JFM7bTFpGrC6mqhLrfinZHEPaW6Ba3HoWSprhCEG6b32V
         kRTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=gKMuT44UIguWl6QKtV3oFDv7g1tO6A544W+6nhDiTZQ=;
        fh=qQl6tu/oK2QQrldCrFXOA0zgBRG1Z97AY9jqAFcVWsA=;
        b=H/yf/pTx1YEPkgEZ8BeItZ2f+oTp3kXMxuOY9CcqztTWEHuydoigzhVHo6jMi720ap
         CRBUSJARNcFLQ2UI+X5Vf0UimmO7/4140cylUHSqMCPodcPvPeKmS/wSyxmvcbP+0ksp
         1ReTNLHjysDTZakEazYNQUw+8LFgYYPGx4NRh5eP9z01sPet3kytxFcd4bQqToAOHNGS
         yruViCcob+l0cxYMZa4rPNnz3JcuwzcauiIfTt2yJ79n3NN1CrW1lm0xRqn4VBRj0tyZ
         gKyNESot+kMObP5+CoHVsEhryVjc1qHFxDL1kW5Cq1ZjZbaiVuQkkTOv+zlxbi0iwaOh
         V/YA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RiaR0729;
       spf=pass (google.com: domain of 3bi4nzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Bi4NZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728917000; x=1729521800; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=gKMuT44UIguWl6QKtV3oFDv7g1tO6A544W+6nhDiTZQ=;
        b=oIzj5TiXQsoxtIPllH7w7jX+z5xe2IJ/lhV9Q27xl0nWBqp+oOAmsXqaetrwGX78nh
         zK1ORlnPjGCXK5FDJtFsQAi4WZXcu7meuO0/Byp5WG5OAkfUCOaIuAwK3GEkdwSoW362
         nC1IY4qOpIZtXeSegYkars0FezJgb3LRAmW9RNV8zzfcfq1HXzqYZTrYG3/eJ5DK7/Cx
         kgyJlKXBYE6MqSxyk2C8ApnsC/fihY0XVvz76XeGozBDhIUCP1GrIqTMhhoBaHzS5nyV
         SSQ04arrdeqBHvrKkl3h8gkJks/Q5XnCDibnseyGGX+5+rYKNRiK+fS15L8w3edYW0gL
         2YfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728917000; x=1729521800;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gKMuT44UIguWl6QKtV3oFDv7g1tO6A544W+6nhDiTZQ=;
        b=py7vaTzAestUsbsVgjMyUMfA5R4rylM6zvHUdZqR3GewpNKHFuyJq44EkTW4v/ePRF
         DtWEkpK5wXPmlW4PHcVITLqzD/kvaZGYH1Wu1K87wAWUR3YRD0uw3s38JVSnIskSQUbV
         XUZle6rkvq2VaFejR6AofSQDdLxeklcWj64KHatOqfhMJ1CcoBnUlSq4acZrkvxU4S+p
         KHOHlbVNf5Wgcr9S8Ca5yRlVHFqojBTAWgoQj9ljlvW4c0dcuypvCDmu8syETrPLaoLB
         gacMI/i1k8zR3rnUgBsZFMyWRS9m4ut7cXtP/vL0uFecKH9tHd9jONd7JlnX3FfPd4nX
         Pz2A==
X-Forwarded-Encrypted: i=2; AJvYcCVCBQS0AAi8JYuvFc0MTRBGjQMrAxMp8l4WQbNs4TFfZ82Qb6V23+ByJrQjaovJl+aT5nmFdQ==@lfdr.de
X-Gm-Message-State: AOJu0YyV//8WHzO4TsBDfvz9TDxuNpA3Dpg72fQNaGlkb+GcWUGZEROM
	BQ2Ms0xVbuJ3oVWxpT5bso3nzFQ2MH4d0jQ5uHCx/TJ1UOOnafS9
X-Google-Smtp-Source: AGHT+IEauoYqnf7bzV/1kAxsGSx+R/mzQHiOKMdsy9gKbgTq9cyE5elHhv9fBDErhPzew+gNyp3UlQ==
X-Received: by 2002:a05:6820:813:b0:5e5:7086:ebed with SMTP id 006d021491bc7-5eb1a2d39acmr5942148eaf.7.1728916999787;
        Mon, 14 Oct 2024 07:43:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:bd85:0:b0:5ca:fb51:9553 with SMTP id 006d021491bc7-5e990e5f863ls760948eaf.2.-pod-prod-01-us;
 Mon, 14 Oct 2024 07:43:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV38Y8B144KhEwTvteGott918vmO+cNUaWUo70mS+poN/eerPiXJSyAMcHf7Flz++5JHRBWA9pxhAY=@googlegroups.com
X-Received: by 2002:a05:6830:f8d:b0:716:a667:6cc7 with SMTP id 46e09a7af769-717d65d6c14mr6821820a34.30.1728916998912;
        Mon, 14 Oct 2024 07:43:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728916998; cv=none;
        d=google.com; s=arc-20240605;
        b=DhnDWf9BY9y347FkHiNhoGGJ0gBpdcC7+LiS6rM/qz6snixWEPKo8eVXxIjmIfi6q7
         uyEMP9hdeMvGtWwgw7lnFS40rIb81EyB4OZto6HkiF7oT+hZOyqWbNUYxCnl0ViHAgt2
         9wRZPoe0FtvVFSd6/iZSRlJMitqwK9AOBrz+F0gEJogZ9GAJlvfzJEdfEky20zgYkKJv
         wxGPkn+LrhhdABLkpPuSlcHGVQClX5RPPyH/fiUw5gydC20STTy34HqiOrVXp1Ast7nA
         +vXgl6Lj0SIJ18N870chzfdUramc3yYU0k0X+6jw5h3PQSspzj/ZRKKF5/0xxmiFURwC
         lkHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tkrU2MksDek0g6FFQZ48XdTMy4B6SNmPFuBaH6YaEgk=;
        fh=rYwwlueLr5xjzklDRmdVO4sNXMVevaDRjfU85b1kKMM=;
        b=XnBk2vrqAATL9k0zd97ZmNJmGVeTZBccOidvYF9THG8rmj8dG0NrpQN9bOX2i8Qn2M
         mD/yvI63I1kj0T/mDNqMU5pPgnk9wFX/yu06mbAacbDJdtlQ+mrau4AzcGEMGeaZBFTW
         umsW5/BB4s/drN/VAQJfR6cvz0QpLP4woxofRM8vS/ZsUmAum22F7bFEWOCqJeM6T43H
         ZD1QZcaUCiDG5tTAwXHirsa1lnw+3yERhYOTCGCtajpH7EtLbt/2bZU03RkQLmQLrWL7
         43NoYoJ+Bq/cfCimBnGzRf9Pb2nF1WLOhfZPJwH3ezgBDNOodJ3JWupjBjX2peMjGcS9
         61yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RiaR0729;
       spf=pass (google.com: domain of 3bi4nzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Bi4NZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yw1-x114a.google.com (mail-yw1-x114a.google.com. [2607:f8b0:4864:20::114a])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-717cfb4c15fsi353468a34.0.2024.10.14.07.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 07:43:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bi4nzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::114a as permitted sender) client-ip=2607:f8b0:4864:20::114a;
Received: by mail-yw1-x114a.google.com with SMTP id 00721157ae682-6e35199eb2bso41952557b3.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 07:43:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU2514lfT3g8Qf4yexcMnxIsqjhsFJPqmCnUGo6uPoDC4SNKC31ZVLq4txKbk1k3Z8vH/7eUmoZ8f8=@googlegroups.com
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:9a7c:c6fa:d24e:a813])
 (user=elver job=sendgmr) by 2002:a05:690c:4449:b0:6e2:2c72:3abb with SMTP id
 00721157ae682-6e347c85db8mr2957767b3.7.1728916998286; Mon, 14 Oct 2024
 07:43:18 -0700 (PDT)
Date: Mon, 14 Oct 2024 16:42:53 +0200
In-Reply-To: <20241014144300.3182961-1-elver@google.com>
Mime-Version: 1.0
References: <20241014144300.3182961-1-elver@google.com>
X-Mailer: git-send-email 2.47.0.rc1.288.g06298d1525-goog
Message-ID: <20241014144300.3182961-2-elver@google.com>
Subject: [PATCH 2/2] kcsan: Remove redundant call of kallsyms_lookup_name()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RiaR0729;       spf=pass
 (google.com: domain of 3bi4nzwukcdu5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::114a as permitted sender) smtp.mailfrom=3Bi4NZwUKCdU5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

From: Ran Xiaokai <ran.xiaokai@zte.com.cn>

There is no need to repeatedly call kallsyms_lookup_name, we can reuse
the return value of this function.

Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index b14072071889..2af39ba5b70b 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -179,8 +179,7 @@ static ssize_t insert_report_filterlist(const char *func)
 	}
 
 	/* Note: deduplicating should be done in userspace. */
-	report_filterlist.addrs[report_filterlist.used++] =
-		kallsyms_lookup_name(func);
+	report_filterlist.addrs[report_filterlist.used++] = addr;
 	report_filterlist.sorted = false;
 
 	raw_spin_unlock_irqrestore(&report_filterlist_lock, flags);
-- 
2.47.0.rc1.288.g06298d1525-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014144300.3182961-2-elver%40google.com.
