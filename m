Return-Path: <kasan-dev+bncBAABBC4GUCIQMGQEK2DS7BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id BF25E4D260B
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 02:29:49 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id z10-20020a170902708a00b0014fc3888923sf300534plk.22
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 17:29:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646789388; cv=pass;
        d=google.com; s=arc-20160816;
        b=duw97qaaXdqAcuIh3SyJL1ZtH5c5uSm9iQNVqU5E7eW+h/a9Z8kWaUvw8kHLqIa97x
         48JsaOZuewsw4/fGcCr6bwyWhUq7KpmP721o6BMyofhW89FZ4avCTvfzywUBp0fINHwa
         ZaX+IrDZDKOTOPtPdXH3JAFoNBLkjndwjSrYXOFGbiNNq+RdEu7ffH/xxGfpqjD0g9Ok
         JFLNYWBoT5ZESoOLBYhqPMevG8EV+oa25g/8v6bwMNsj5GJu9CYsFCx2i0hz+m5rYiQb
         duWjSC8MqN+ybBj9qMrtn4eP6ys3sDY6/91jMrOxx6OQM1zjHLqgo4SN+ci01JHLyxPF
         yRdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=cugeV01RyKaZlK6Gqb07Ts1pi+t0KXnFzEsYK9WFMr8=;
        b=iYJSSypj9EjegEa7x8ZDjRrUWn01g4KguliEukCyBLnlyN8f1B5aF2HkYlPRf2YoAI
         T6kYxMaDQh3FFnTUIME3Thw9ciU/OzmxOTefq7k56xpSm8rmuDxf71NVLi2uIPjgBJ4x
         +sQwXi7SjZhSGKZOqUKc51+won69HePNxGEvwSNC8tRuRJIMtp62RT3TxO12+CTCle63
         i6SZ5K6dQoQ0zvAyIbQnoP4tD10RSWPxTsaTJtQX803ENv2X7c8LB+htYK1YIsTSBT+3
         tXrp1ljSF6hRQ1rIiAndnCGlCzXVXRDZv8wJJ6aQ9cTBGRxP9FfUXKN3AANkiH2fhNBq
         VkfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cugeV01RyKaZlK6Gqb07Ts1pi+t0KXnFzEsYK9WFMr8=;
        b=OXtNn75j3mU1oTMqQ3tLNVEKVIzdCoR9kEpv0K3/kyi6sBATRCl9/vDlVtQUNS1N+j
         ZhRe8RSt7tQZMP24pF/4F8gggiB4rTw9yPkxsXbV9bJ8jijF1uBAtf948smi5bLwYP+4
         XJlDLwAn45ncei1v8BLTQ6ncLjZYIb9UB/MWqVdNNM0YeQm8dRkhWMyMoQFNJDjl00Dl
         2uJgXC5hT7wjJI8O19SKpKXlW3KbNvXteSEVWke/G2TVuyX94J6SXbcQGFSMnGHHY62Z
         gG9RKVg463BOa9k+tcxfYNJjoCUIICPMbMj1JwI45x9SDHmkhhxa/F1QQV94KLnosL4u
         QcwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cugeV01RyKaZlK6Gqb07Ts1pi+t0KXnFzEsYK9WFMr8=;
        b=e6pDwRYt8POhKkOWEePl3CgswBki7r9CT1I/mjFox4a9ycPJM6VNyQ/rwowiSUbUxN
         Xa/fwM+zaqYBaXh+F9nDto9gSs0u8YwtWCHyAnJ03Q2wzyCNTls1F7h6m1MZT+cpNkg1
         z5k5BGfaw6LQ/adiXdcOUvTwjqN3KIzFrfPrWU1uZpLDA/xKS1nvZigT23EXGP4FjlRy
         fECJCb8Lhs0xFOzCGBiW4FNutkqNVYF6Fmf4kQDAGQCLjIr9zxw2Era60i3zKmuEmQ4k
         tK6pnnaBnCc+CHKruSTQ++o+4fY+gNHoo6xHN3y/9yVTZguoAZq2F8xqCOFDQt7w/Qfs
         NINA==
X-Gm-Message-State: AOAM530Ni/kQsLVR24pfW5KBYOCd7OkH9+E3vXQYBUwsHJDuLxGuYEC7
	nMR3Wzfl12G1MwjqH1gjIS0=
X-Google-Smtp-Source: ABdhPJy5vC/r4/fV0+VPg9DnBfiiPlyaUn3zMlWpIDhab7tqFBgVFFwSxonmhhFH8nLJ6fYpAkNfdA==
X-Received: by 2002:a63:5207:0:b0:380:7ee:e769 with SMTP id g7-20020a635207000000b0038007eee769mr14894599pgb.620.1646789388040;
        Tue, 08 Mar 2022 17:29:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c38a:b0:1bf:a46:843 with SMTP id h10-20020a17090ac38a00b001bf0a460843ls383730pjt.1.gmail;
 Tue, 08 Mar 2022 17:29:47 -0800 (PST)
X-Received: by 2002:a17:903:24d:b0:14f:84dd:babb with SMTP id j13-20020a170903024d00b0014f84ddbabbmr20898410plh.47.1646789387533;
        Tue, 08 Mar 2022 17:29:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646789387; cv=none;
        d=google.com; s=arc-20160816;
        b=WO7BJ9nwpM+m3cqVWMkGC4nYjZbelTYmtbeQcSE5V/lLzOLI9p55PlfBWAZBpyo1RI
         85k8OMkNfH1fr9qCHx89Wy2hd9TRA6zNFn1P8D0q//NFAUEgysl0FuHH+kxztY95ifEk
         0AZtTBq6L43JGBng8ptgheRdrYkLjkWeXqEa9KxRWd9iaAdmvc4bzgBniGcZfww6OKwG
         JIdg1Zj+GN44HTxzuLp05WvMGNfXKwVtX/wJvF1nhqo9OoQnf11S2NgdHVzRrFN5LJtu
         6puZ1BshkHP3JBAgLbrEbjBMGzYHlpn+68JsEDWivaS/lBJfl/9q6A5uenmezuL8iUmU
         g80g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=b2HSySulLWgIp9qaB8j1yeAvSfujy4pWbxa5UrRVS2I=;
        b=SJVRaWlNaxWbM63LjHOgHIvNDPKMevI9UnQVrM4tYiYht0um398gjZ6hD/FQxyeUsJ
         OmmjsV8iZXNQMFHHfcHCR7zGqB0xkanN6kCdTBQ9YDnhv6x9qY/C+z9vKPU1tAKG1euW
         rCZAOYNsENs/Jg5d2Vt1J0ArJC9eNsd1KfdqKQMTMBVF3DBGlHEjnzLKS+IHIPEXsl4z
         UQlqVAN/tE6vr+ixF7QSCAeFe5wg6FjtqNyaj0Yik3+lABn897pjSBMOdAet7yUaV4hX
         YN9Y5eCRmgxEH6YFrDjbCG1cLF87joorO882A6kieOZ9Uospi4htP+CgYhDjcqBF++TM
         GFgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liupeng256@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id q3-20020a17090a2e0300b001b9932741a2si299557pjd.0.2022.03.08.17.29.47
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Mar 2022 17:29:47 -0800 (PST)
Received-SPF: pass (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from kwepemi100014.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4KCvj30fh4zdZMk;
	Wed,  9 Mar 2022 09:28:23 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (7.193.23.234) by
 kwepemi100014.china.huawei.com (7.221.188.106) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:45 +0800
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.21; Wed, 9 Mar 2022 09:29:44 +0800
From: "'Peng Liu' via kasan-dev" <kasan-dev@googlegroups.com>
To: <brendanhiggins@google.com>, <glider@google.com>, <elver@google.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<linux-kselftest@vger.kernel.org>, <kunit-dev@googlegroups.com>,
	<linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: <wangkefeng.wang@huawei.com>, <liupeng256@huawei.com>
Subject: [PATCH 0/3] kunit: fix a UAF bug and do some optimization
Date: Wed, 9 Mar 2022 01:47:02 +0000
Message-ID: <20220309014705.1265861-1-liupeng256@huawei.com>
X-Mailer: git-send-email 2.18.0.huawei.25
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-CFilter-Loop: Reflected
X-Original-Sender: liupeng256@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liupeng256@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liupeng256@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Peng Liu <liupeng256@huawei.com>
Reply-To: Peng Liu <liupeng256@huawei.com>
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

This series is to fix UAF when running kfence test case test_gfpzero,
which is time costly. This UAF bug can be easily triggered by setting
CONFIG_KFENCE_DYNAMIC_OBJECTS = 65535. Furthermore, some optimization
for kunit tests has been done.

Peng Liu (3):
  kunit: fix UAF when run kfence test case test_gfpzero
  kunit: make kunit_test_timeout compatible with comment
  kfence: test: try to avoid test_gfpzero trigger rcu_stall

 lib/kunit/try-catch.c   | 3 ++-
 mm/kfence/kfence_test.c | 3 ++-
 2 files changed, 4 insertions(+), 2 deletions(-)

-- 
2.18.0.huawei.25

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-1-liupeng256%40huawei.com.
