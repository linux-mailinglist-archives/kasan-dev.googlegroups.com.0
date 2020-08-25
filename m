Return-Path: <kasan-dev+bncBDGPTM5BQUDRBKXCSH5AKGQEGXGF5HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 87AB5250E7E
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Aug 2020 04:02:19 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id q3sf1674157uap.13
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 19:02:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598320938; cv=pass;
        d=google.com; s=arc-20160816;
        b=wuDBd9+eFGn0GKkbiIPHQ7WVRjW4vnRWbXKADBu2BtmtMqzqR/4ISMooCP3EXCAJ/G
         troSBlHP/EkXkPPCxGUtPzF+YMc3HDzibYV0esRz1vO0JIUojQzUsxI1Vh7nzsfPcwZp
         CyMvzkgAD24+Jgp9IeaC14dOPpIgbCQx6YFZ5Dcn4XEwKpJPiet5Nz147SugzybXg4rX
         Jw71GU5aM9bBRMytns1BEvPtMmM6duMJgw4T1POazFZvfwdreaDZXHOn5AP91JOEEZCT
         bNB7+Zz6KvErN+qAskTlZSjULUg+Dv0SpycPHETIv9KxtYV7MZEr17T9SMziBYyQ2CUP
         jqQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=fhv3F6qWezT59vIPNFF1ponSs4WEH5ZucNMykxuKIKE=;
        b=ywTpouuJzcBM/swApQUX02qPUXXBpfW6Beu0LFdTQJ/tc7hwTR9Wk6LWn1cSosrWAW
         QasDupqNieRKdxMEaMiuymRRz782yPBJnFtokR+HOAtE5WcihxAYMtKj2dXuV1lyMWIu
         6pVCL5jADGIx8Ojrm1wbKNUQbWNNWnw/1krBffW1NtTGRU/o+3X5cuigVZbboJHN/HvW
         BlIcTeTNQywpbn5v4o3eo5Gs/WHWGh2WSOzsDXLSn9O4+2jmKjAfRItXz/FQlBPHuliN
         UlVsZqWQLSH5bwG+Htn1/RMKMU8vlnI6czqzaA5iGNDI/zi+2Z8YgHJk1m59Sl/GEBpv
         HWXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="eS/4hTLS";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fhv3F6qWezT59vIPNFF1ponSs4WEH5ZucNMykxuKIKE=;
        b=jnjPK+BaKyt3e8DJ5/UxUGAVSOhi18jtvqhf5RHspAFMWjWn2K5sY3ElzcKOofnQeO
         Jd1vHtqFgA8iTdT/UMwRmqboPs/Gi75ia4//LD2cjWlu5PJ6u1uyMfqlBgzgwPWqY8fP
         fmIiIjLmaTUoUjrulbjRDZhQhelaNmwIRlTOjhY0OcHeN4rdjvor32ZNfMv4AKNtWUNY
         IBlzpj9feFAdewBSCe+U5FEPRaPwNZtF62yVIz/VZS6CXiXl8AUQrJOPGD5XXBtJ4qH9
         WdYyOMyBC1HaVDOjj2RGTLfwyCVmr06AEKpmvLkEd+yiwp5DIdgl7LQLNBd/zKiLqst4
         s3fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fhv3F6qWezT59vIPNFF1ponSs4WEH5ZucNMykxuKIKE=;
        b=OPJtLJ/TQHdavD/fEkcR4jH3gQx16wytqzLE6FfwIPCEIXcOr5GuOeU/3ZSAct/3zW
         UCF4B6HpxuDksPPtCH0gXu2DEpcq8l7k8kodO5Dxmh8M8s1eyIhEK63Wdk1mFapDl4eI
         X6lOxkijvbPO++UHuyKv/OcN+eGCRqwW7A36zqyY+BUkxm3lAl7hLHMLGmlIDwyZTLPc
         4ZOq7Fn38MZ1wGYVNI3nDZZ8qFz7lxCEk3e/eTasDjjiMJNjhlQ9m+jL9XWjgFHEeXmx
         2iugeBv/0BlbP985DkSz4m5vohq+yVCiBGZydy3V3ujhs1Rlhdo80a4Out98uQqyjuz3
         U5nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532e1uDY2QQcsf0DQW4EDMTXohW2RcxfPbh4cTQ6Ych+OuxniArS
	E4nnzLUxL3q5rKCagqzysxo=
X-Google-Smtp-Source: ABdhPJyOszsNWV7hN79kMPXYJ1jTjTW0Rmz7j/I/+t16ylnPQ1dEP6DLfBQ+lNGnodjU1JHlUDz6Rg==
X-Received: by 2002:ab0:20d2:: with SMTP id z18mr4386126ual.14.1598320938384;
        Mon, 24 Aug 2020 19:02:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c797:: with SMTP id t23ls1235870vsk.8.gmail; Mon, 24 Aug
 2020 19:02:18 -0700 (PDT)
X-Received: by 2002:a67:f550:: with SMTP id z16mr4387643vsn.94.1598320937984;
        Mon, 24 Aug 2020 19:02:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598320937; cv=none;
        d=google.com; s=arc-20160816;
        b=Ob9jsOoiL75tVzoARE15yi5LlMijdho+lsepQt2yMmCYxLm0WOohTy60WFlJtYc0dj
         1hKtYEWruKI+eN+Vy1ipfkxKh3HTBSOMsTFeiwNn7w0C5rbf3qBccQavk0RPuAOHIMcJ
         KZl8Iec+VNvgo3Y2+ZYj+qqS0w9wGeHKeZJwyW39xWTPLVBXTxtqfOigGm/ACKwhfjEU
         woIY9JwhmsjqykokEiONNmxzCCrdnVHD41/bSICBZGcA2huoYASU4xUxxAK2KaypdkdS
         XXqqOcxfzGnbizc24J/fjFJKzvD2aKXZkhmbaUdj445fFIQyXN47VzVtuqzEIAY1rkoI
         h8xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=9sZ1Q2VJIj3D6DYv93PbNUEMzsMoXEFwRyYq2J0814A=;
        b=mywezlMGBT8mDGq2qrlMaMV5mQw9SyJAsm8Oh4gZ5Muc+jda8rWUxGw5ZteOnI++sf
         NhcxQLGo94EbPpjRajwK+Z3kRtvV7ngKWZiXU1iqwbBZlHfv6OgfF5Zo3UzorScjhasF
         jiOqYF1YEBoin7JYmMM+k4ZhrI7X7WRfnxeZ7ckuXNYz5MbJg2iAXYPGUIKF2+PVIBLf
         yfvve+9zi5GeKAn2Pnccn6jzb4dDMVQwUL7HG7jdAi9qxFdGuQfK+3DL4taNlhx8kwuZ
         I+U8UUI8xl0K3HoIOjsl/9TEUiVtzZsLWRFt56v6yGdKLeV1kWCj6uP4ltPzuryrOodH
         OunA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="eS/4hTLS";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x20si683vko.5.2020.08.24.19.02.16
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 19:02:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: df1774462e404d7ebe32eb71e825ac0c-20200825
X-UUID: df1774462e404d7ebe32eb71e825ac0c-20200825
Received: from mtkexhb02.mediatek.inc [(172.21.101.103)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1653110723; Tue, 25 Aug 2020 10:02:10 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Tue, 25 Aug 2020 10:02:08 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Tue, 25 Aug 2020 10:02:09 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Jonathan Corbet <corbet@lwn.net>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v3 6/6] kasan: update documentation for generic kasan
Date: Tue, 25 Aug 2020 10:02:08 +0800
Message-ID: <20200825020208.28950-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: FF79C89B95B5EEC808E61E9DE96777FD0981D12178444CA2009311433735FC3A2000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="eS/4hTLS";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Generic KASAN also supports to record the last two timer and workqueue
stacks and print them in KASAN report. So that need to update
documentation.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Suggested-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Jonathan Corbet <corbet@lwn.net>
---

v3:
- Thanks for Macro suggestion

---
 Documentation/dev-tools/kasan.rst | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..698ccb65e634 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -190,8 +190,9 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
-and the second to last.
+Generic KASAN also reports the last 2 call stacks to creation of work that
+potentially has access to an object. Call stacks for the following are shown:
+call_rcu(), timer and workqueue queuing.
 
 Software tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200825020208.28950-1-walter-zh.wu%40mediatek.com.
