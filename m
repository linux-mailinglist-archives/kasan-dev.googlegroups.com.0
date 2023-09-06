Return-Path: <kasan-dev+bncBCRKFI7J2AJRBSXC4GTQMGQEKS3TNDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D87C793CAA
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Sep 2023 14:32:12 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1bf6e47b5efsf38331295ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Sep 2023 05:32:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694003531; cv=pass;
        d=google.com; s=arc-20160816;
        b=TOcy445WOGlYJBEzqdIIpCAjEmZsfbewDdqm0CHtHGZn1wJE5xKSOLlaylO9llHI/n
         wvTgZenNoYrhnPHR7ecyeeZrh+LvvXyJTzffs6I9NFsLM5wopaP8vnll5yC/rRAT/IG7
         YzFwPhHJiX1O96opzO48rXXwv7yIMMi/5QrqjQV7s/MDmmYaRpSVA4jYWRCcGXvYHtav
         ef2x97HFAB4pzgusuKVFdJbGFTmt36mppjfGe7SIxj/vK8wQXWXdelQ3YNmqeGpHotVR
         QEOlxc0a+BlyyGnkWmDhFAw2G9n6LMXkudaECL3bk+SwEu9agRh/m4j3d/vfOboWiSZq
         hwRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=mIG3BCeWnW8ybfsn9HM7CZ53r6khE/GUlBEGjfa8JS8=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=0AlX+J5DC5lGEb10d44njGDTHAOg4cLpFby93SAOBNHVs3fbjWItpWnUnjEglikNvU
         MCxXskjhojAwyN3bAOTdO9rJjpevPVDMOYsSuf3V2nT3+s8IxBzbarr4egY9akF3WdG8
         CnCj0xMNjQVvl+H8Iil91gVU18B5bg7EOJwu8sLWgz0awShVYWgC7j00oK4PApHXaKc8
         NGsNBdb2jFJjrLRSItIblMzzdEPsIaEpHjcqgVdMfDbougFIDk55LVcMOoCk4p5H6cO9
         vsmmSUQrxZ1XyBNtYaRCx+b9xG32AUzPH4BP9pjHIw3js0LJeegK3yNt1ak4T0LN6vk2
         IcSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694003531; x=1694608331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mIG3BCeWnW8ybfsn9HM7CZ53r6khE/GUlBEGjfa8JS8=;
        b=C76LeEH+NDhTJjs3vAFjpvTWHRjNlCahh8dAinWU4H3hWzmPgzUunxGEXifzTpaV9i
         Nb3G1E/0mvhHlIktgqHY/HBDBGAkviqLDOw+OpVWw/QF+zkvspnXdxy2W3S0satyyHj2
         zblV7Kbw5yji75jY3K+s8glFWznWBaR8cpBlm+q9iRNkLhqc8FkDZ/j4YYX0AUvMlJWs
         5wbhduCD00gmYVzTUAq57MxqGWj2kJ4VJqnmikKafs5OxvMxIeeGNd250YvNN1yPH9dQ
         jheSEJdGCWiZjxtVX4wk8tmSmX9PE0nJIGz0sZ4eQfmO1jNdXJucW8X5KGzs+TFY0nR4
         PgYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1694003531; x=1694608331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=mIG3BCeWnW8ybfsn9HM7CZ53r6khE/GUlBEGjfa8JS8=;
        b=Br5Z9WQWnQ6dlx1KMQUwm4U7RIK72o3Vip2S+rOPWLtMAthLSYbBhqvFmBphUi8htb
         WyyLV9bdwMoxNXRBGMJe6k0E+mszLx2rGprmyGLx9h8MboFoWS/aLbQc6aES9NOPTE9W
         Bh0/DwzLSanuIZHVtXLr+7jEc3pTkD9vZ7IZjH/BbW9oHrCUccioQmSvxq0aDhzVVbrJ
         Vrvafm6AK8D1EzHgJe4DXDvwdMwlX01xObuqKbjNc/eo76KhlOFwbwaNX458xME0Xk5H
         ggQLljvf7tcMXmoYjEQA0BRIwt+27KIV1wMjnzmWq/BTmG+3CPM9zjRE7uuvGlDzn4EN
         SaFA==
X-Gm-Message-State: AOJu0YyQBYmOuLss0Yy8PKhVRLhDTPxmyfLkBOgL2j9p0iyWi1YUqB1t
	Qfru7WE2McpcBqo7BQtmI5Y=
X-Google-Smtp-Source: AGHT+IFCSdmkifwfc0Wdo5mzr84CfhlRmfLZEzeT5t3JPjFLQaVAfyYcFtNAL5FNpH/Gx+UM+N4l3Q==
X-Received: by 2002:a17:902:f687:b0:1bf:1052:f28f with SMTP id l7-20020a170902f68700b001bf1052f28fmr15149573plg.52.1694003530808;
        Wed, 06 Sep 2023 05:32:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:680e:b0:1bd:c972:493b with SMTP id
 h14-20020a170902680e00b001bdc972493bls3410723plk.2.-pod-prod-04-us; Wed, 06
 Sep 2023 05:32:09 -0700 (PDT)
X-Received: by 2002:a17:902:e74c:b0:1c0:ee60:470a with SMTP id p12-20020a170902e74c00b001c0ee60470amr14486418plf.66.1694003529122;
        Wed, 06 Sep 2023 05:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694003529; cv=none;
        d=google.com; s=arc-20160816;
        b=Eukpidb+uKcg4Umt6Wl6apoFmBNqu+/lsz5SlVe2jDwvgZAAFCylzZPq5uVRHXcZAq
         h+b5ObbTqvwxXGtBUKbZdNsmlQcfEkf8GXcA2ilT6ifQfmCowQwm7ISQirSHfGOW10tJ
         nH/hdGhTdcZKM4vCa+SOhgeitjyvzCzoG5hGFQ0ZvEfwDaG4l5txvJTtqXZLI+COg+vS
         0DpsQ1cf/i5R9FxaJ0HawdT+0/ip0Svb5KeVIZ1qohtruaHf8CrAceim+9I9V6V+YKZp
         tuHRF3SOpXXnf8ka8UelkH3zY3MzkeNJ3dcPEsVWNKSbI6QPuWHPrxxu2BxP/vyw7AvC
         7cCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9Vvgv1vIG7kkGfRmw8EhBEN2k5bfFytmCIvvz5mImE0=;
        fh=yzysZ59oPk5DLEE5rhyc9UX9VwoFZbo45R1txxQt+Oc=;
        b=Ye+seDAlQMhQ8Rubkxzsblx1lGeg0JuvFRAMIQa3C/RMc4a2j0LcNH6xdaGsR2ewvJ
         yj9GFsTLJVe1VnbSWnc/r3u7ZFom3qpwzLit128w0+Xx2BtrOHpRk+Oo6T2VPSptuSdu
         o6BZzVwKPToq2WBiULhrC+Z90Cg32WIrKqcv7gL2vqcttj+C4AqMJWiRXFwvv5XAFI5x
         4WdA7HIk7ZBmFkhCoPhPrSD4ZghG2iadM62l3HE5WNUYCOplSMgGfeC9bmZzSqPGlFxc
         0T3JQgV7Dd/J4vaUyOX+kaLiNcCt0NctbO1FFZAsdh9q7TGkK2lbYCPx9l6PwkCo98HX
         2nvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id kr3-20020a170903080300b001c3523b5577si359377plb.0.2023.09.06.05.32.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Sep 2023 05:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm100001.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4RghVH6GYxzhZHX;
	Wed,  6 Sep 2023 20:28:07 +0800 (CST)
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm100001.china.huawei.com (7.185.36.93) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.31; Wed, 6 Sep 2023 20:32:06 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew
 Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>,
	Christoph Hellwig <hch@infradead.org>, Lorenzo Stoakes <lstoakes@gmail.com>,
	<kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Kefeng Wang <wangkefeng.wang@huawei.com>
Subject: [PATCH -rfc 0/3] mm: kasan: fix softlock when populate or depopulate pte
Date: Wed, 6 Sep 2023 20:42:31 +0800
Message-ID: <20230906124234.134200-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.41.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
 dggpemm100001.china.huawei.com (7.185.36.93)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.187
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

This is a RFC, even patch3 is a hack to fix the softlock issue when
populate or depopulate pte with large region, looking forward to your
reply and advise, thanks.

Kefeng Wang (3):
  mm: kasan: shadow: add cond_resched() in kasan_populate_vmalloc_pte()
  mm: kasan: shadow: move free_page() out of page table lock
  mm: kasan: shadow: HACK add cond_resched_lock() in
    kasan_depopulate_vmalloc_pte()

 include/linux/kasan.h |  9 ++++++---
 mm/kasan/shadow.c     | 20 +++++++++++++-------
 mm/vmalloc.c          |  7 ++++---
 3 files changed, 23 insertions(+), 13 deletions(-)

-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230906124234.134200-1-wangkefeng.wang%40huawei.com.
