Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5PBYX6AKGQERO3F2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 60458295DAD
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 13:45:58 +0200 (CEST)
Received: by mail-oi1-x240.google.com with SMTP id o17sf638416oic.11
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 04:45:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603367157; cv=pass;
        d=google.com; s=arc-20160816;
        b=wlohbZtLco+g2t98ImA9kyPBL2gNTNT+6izMcL+xcyb4gvUzhYJO1uWK1GYx4yXX2u
         fv10IJTUj9WT8HeXWrxdn7FKNelswux7UMkUxNF+WEX4cH6cBjYuG5kMpobO+ZtTNifh
         iHG0Cg8vxdjItTWK6gQo15Igi9R+oeYJK7hxdeZplv3JExQNVLvDGj72zZXXLgaWPhkv
         Sgfls8vHXI98Z7P654tsn6KHxf8iQOUT1PJ4/fAaFGuBfkAArl2MJ1Eo7v2aM9eOgPUI
         MOejRY5oQTUD9rhtW+7DYgf1le11NAniXQxyjc2Myy0XpkXIKQ+iGA+mCFKdTamL4Mnb
         tKcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=ib5fQcnFNt06IEiu6EKnCtb2aydlmIvIq5YIXRBYgPc=;
        b=k8zJO5480wWTeIuBPn954tPcqoCf7awAfbXZdMKdCfiARM+cNCP3KpKZP87f9b0Yv+
         Ie3TlMjnanCTZKCMdTguN518wyRAtUl377vcbDELuDNdiYcOj6xHZErtr1mTNP2t+8P+
         xV6i8oem7NjCpQ6nTMhqvQTFJUGB0gNGTwBxOSXv4hXzxF38zzOKMd1+fdTk5WYRCWIY
         47UmQRvR4yLolToBiYuQ2w2xQs99U4cvwgNdR5KCqYkwkjHIC9pGNYdN1ybguf4oHkes
         v8Oq2JcZDuUxzCZ60Pp/cLoIzfjC1LJbARRtu7dJKY98BYp5WE7lH/pQeRVSRSTt+s2/
         U4sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=llBRAaxs;
       spf=pass (google.com: domain of 39hcrxwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39HCRXwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ib5fQcnFNt06IEiu6EKnCtb2aydlmIvIq5YIXRBYgPc=;
        b=ITfCfpOefoEwaDeBxBFN+j2VGOoKRRsniEytkuaYngybRmEJ216TFJzJgPFVzYkAXK
         EPFN13cbjepXIUV+J23Le/RPYav7FZeyj7ziZovJABkMMcD5DfTc7l5JTtRUgznqYaWd
         cJquAty67qYm2SmxdqGi1E+1Aeak4dHDgBB2q3pdQwN+Fvu5+BdAP+EUMqMQ/fYKqDGJ
         iw6HzJhc7Ay4HDkVgacnnqUU7p4t589E0P5QFkZdDt5zJxxlOcYD4XWUNft7larclz0c
         XPAoNHS3p8Gi7+P++uRBL8vxN/dbOcpesGsFnlKIUsG4DhSIxTo8xbOeUwv/sIbiW4Qa
         7Cag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ib5fQcnFNt06IEiu6EKnCtb2aydlmIvIq5YIXRBYgPc=;
        b=qTWEqUytjbAJx83jFoYsVW9DzJMZWIXoCsnVCY1eptVQ2xZXVfCx/dYBmsqNM4fUHZ
         vgjgQlLReIuonBv6r3y5HXQAEXqw7BurnxLw2S5iFp+l3RBytB7esesmyLECoeI5jVnF
         +/0q4gKujaJWeTdJDQtgw0jI2aWdg0rXa2ZbybcL5mxIyCje+zK3W3qIXVjXVjmIcmYW
         9zuaqed5oIJqRr7rTDXM3D9SYBQNPEBa7qoiHuJAcdYpXZSvgTu8oGMEDjydbEsphKZR
         FuF/UMlFaZ2XsrvjAxqkIizdDPRbkPmcdnfbbxW+IqlVKYeUa1P1XQow5wVcydc2bSfe
         g/MQ==
X-Gm-Message-State: AOAM530X0fR6B+Wnx2gsGKvDkTDEtWbGFWBETCymhfc4R4+lXtJKHitw
	ttXRM3Xgwsbgys6GGj5zXug=
X-Google-Smtp-Source: ABdhPJxIm07z+RzlC/zAEIobZ9HNGIxC/2ev9Ov2odM6JuWXkHQ4Ze7DWBhBhklISxZSKhk5kaWwSw==
X-Received: by 2002:a05:6808:10e:: with SMTP id b14mr1291894oie.152.1603367157099;
        Thu, 22 Oct 2020 04:45:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:26f:: with SMTP id c15ls83210ooe.2.gmail; Thu, 22
 Oct 2020 04:45:56 -0700 (PDT)
X-Received: by 2002:a4a:b34a:: with SMTP id n10mr1729809ooo.46.1603367156698;
        Thu, 22 Oct 2020 04:45:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603367156; cv=none;
        d=google.com; s=arc-20160816;
        b=Lj78kzjEfjqxNLL2EUl766FyWCJ7QMAI/haf2IHf9q3mBuLFxo7j5gLVwXAHxlGkkc
         dg4U7rbLcMCvWowbrGHbJrj5C+YYo20ayWPxA+FCgsVsSE82UEQ6AzqkW5OLyFXamclu
         fDxE+zBU0USCUAEZNwOhUcn2SIxTOzqSxLxM5xAP0hqD7gSX5UqBYQHkyJCls4bmT6+C
         VXf7RY34QgFcNu0gqPT8ADUnjV1xcMFDBxMKwjkbwUbrC5mohlZrPibA2DzqMzMOAq75
         uL92ztY08RlIJ6Hw8lxxEPhDoCbz2IHvorzC6t2QL0TdOqfGNIYk0gdWcFIuRtv8RJNO
         yi4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=WwVpVCl4mVaLx/Y9kggr1s7Fduh1lvdItvOpC6doLlc=;
        b=y2BeROxMHtN63BnzFpoCL4cV+HyRungGZioxgGJhoZWUVSl47vklo9fg0P+gqLChYp
         mvkNY8hCCT/HpnC4YQ5apOJv8ERUJnECzXdKWVRYB+2Mzi1Vm7r1SWzALEyN2Z7F1sqS
         dKULT1hwGYR3EECONHKoyGHn9WMLIow6Bdmjmcb5sSsafAiV7+iyDf+0ydxPrrEJ2dbB
         cPY1nZMuB74KvA3D3KIMUdyzdszB3GjPsORSmdmTOHYQ8wkfjQVsXc/ezbMlQZjWR5/g
         BKxz77J0LdSw1vWRPEjlRZ3V32Vc79IhIbrT5ulu7Y+xNnag1qo/2awqcFkV2dVsCMEA
         8N2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=llBRAaxs;
       spf=pass (google.com: domain of 39hcrxwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39HCRXwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id d20si112646oti.1.2020.10.22.04.45.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 04:45:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39hcrxwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id a81so799743qkg.10
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 04:45:56 -0700 (PDT)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:ad4:456c:: with SMTP id o12mr1978035qvu.48.1603367156174;
 Thu, 22 Oct 2020 04:45:56 -0700 (PDT)
Date: Thu, 22 Oct 2020 13:45:52 +0200
Message-Id: <20201022114553.2440135-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH v2 1/2] kcsan: selftest: Ensure that address is at least PAGE_SIZE
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=llBRAaxs;       spf=pass
 (google.com: domain of 39hcrxwukcr89gq9mbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39HCRXwUKCR89GQ9MBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--elver.bounces.google.com;
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

In preparation of supporting only addresses not within the NULL page,
change the selftest to never use addresses that are less than PAGE_SIZE.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Introduce patch to series.
---
 kernel/kcsan/selftest.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index d98bc208d06d..9014a3a82cf9 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -33,6 +33,9 @@ static bool test_encode_decode(void)
 		unsigned long addr;
 
 		prandom_bytes(&addr, sizeof(addr));
+		if (addr < PAGE_SIZE)
+			addr = PAGE_SIZE;
+
 		if (WARN_ON(!check_encodable(addr, size)))
 			return false;
 
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201022114553.2440135-1-elver%40google.com.
