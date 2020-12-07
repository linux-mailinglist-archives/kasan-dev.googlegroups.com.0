Return-Path: <kasan-dev+bncBAABBKWWW77AKGQEJSRXLCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23b.google.com (mail-oi1-x23b.google.com [IPv6:2607:f8b0:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FFAC2D0BE7
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Dec 2020 09:43:24 +0100 (CET)
Received: by mail-oi1-x23b.google.com with SMTP id f15sf6804024oig.11
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Dec 2020 00:43:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607330602; cv=pass;
        d=google.com; s=arc-20160816;
        b=fw9T2tqH2ECU5moRr9zBE6/MuEMFI/zi0oEw1RWW6xrOE1yEUUQO5iGaIBs2TEYBIJ
         BQHurWOcV+WhNiwdm3rKPA0qAIdrIusNTxvBOXlvZZ8LbmPRJNRzdh7/ZAPm9u9XHmXJ
         iwTMhztIipS9J1LO87o7omJdKrolUl/oIG1TQalFtt+7ZlYCxi9q34CjkriKpQsftYGk
         W5tIvdlWZNsDkuUWXkdKeSqne8Nir567PocEhfTWzUTgstJO99pgzDJyTGHRghxw5PxE
         3JQ1Y5WTf5fePYfPXlTWFkz9BAIgCuuv00mO9wX3vU73zPoCTJH2CE19wyrX5WxuTK9o
         PQBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YZj2i1KMGI4reuBrubkV/fthmdoHnKaK4Q6JxCIuVnU=;
        b=Ejp9w8c+3sc8a+qK6C/dMuDu02EFOxQklRsFydOftcxRyZSPaEGYiudwfSNaRNaDWa
         A6kDBzKk6hFpDwRbOL9rBs0RgLCF10mdShR/kR4UWsddZpoBInFsPaGo8vyhkpZHeyN7
         xVc6XuDKwXCLqNQXYlP+sfXWtwcDjZpOlGGy+XAeGHJe6fwHJ8Qk6YiwuhYc9vflzRf+
         XGaRMOkyhAGfw2fNnxDJ98W3H6f+x6/CWIBe0DsoQiTWOKrUz0/HgfSOzom0dkFWg1Tm
         mUVp704Cbhj+Y/DtnLzhn+crqOqt/IK/ptGTGf04J7/DrAMX1rlqO4Gbm5Ylv3rgj0EK
         ek+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YZj2i1KMGI4reuBrubkV/fthmdoHnKaK4Q6JxCIuVnU=;
        b=hhSaoacrmJUnowE1V8kCA0peq+VbQZ4sHOyMvQVgVg2EdruwcecAtrqSv+mUH68+nW
         +7b/kKImkbVcwwCHtki+MTwg1cFSxAw85pdXy0Ta8TcTG+4q0F/6Z4wEmSeZQpc1kuib
         PVaZEKbfi6tb/+IZq/uGZyoXcMJFoGakTEc8UH5iom6oys22Czw5Mq5EPBtAR8nxguRZ
         CWTPwlR+oEAoy6RATfIs3oTSCscAdFwYraTQF6uyglddvtw2T7yxfqz5gf1dkyqZ+I5l
         dZaZ3w6M0DQLC5wDHmFbX21Auixer0bi5/fR8xdsxSeEQx41+5NiH7im7R8GQ8qMMhf+
         Jx6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YZj2i1KMGI4reuBrubkV/fthmdoHnKaK4Q6JxCIuVnU=;
        b=QNWWZF2n6YJW5k93wb0KbGO/YhRw4sOkmz2a3kurEohjT0ZAS4a+HzVbQvqNBCdcAn
         96pSzv5Jc+YOBBwBgRS1Z+QlSuxk5dYeIeQsoKyyVhUfGbkMxJVEnzbT22hvSar2N1Xy
         mM4WOz5IaKVEPBY7WTWgRqRT0JVHkzD+Sq0A1XMrljltJhEf8aLdw9qqJ6KbI0ppMK51
         YUatDGV+wDaPRtuh9MbWrEOXv7zYMOgnFqWzirkwcmViAfO0j3hpWgeTzQ5r77IZT/rV
         sVqHyj2dUoL0+qDd91DJZTYrMZwgk+QXlgyBc7OtseG0uFl088qBDOcKwFarjuklX/Aq
         Xk9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530QKJjlnIf3kz1xh8YQpuMuQcCct/c91LLLvV3qD8INs03kskmT
	cZD/NPkbtHlFvkH1O7X0Mks=
X-Google-Smtp-Source: ABdhPJzrdj4yAWpe2AQL2gUkN6jrvO+MfPzwX1Al5OFdeu+QwRnSLt4kpE+H/dOsE7GLky+NkFDhEA==
X-Received: by 2002:aca:b40a:: with SMTP id d10mr11736454oif.147.1607330602706;
        Mon, 07 Dec 2020 00:43:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:155:: with SMTP id 79ls20165otu.11.gmail; Mon, 07 Dec
 2020 00:43:22 -0800 (PST)
X-Received: by 2002:a9d:d8a:: with SMTP id 10mr12144048ots.11.1607330602396;
        Mon, 07 Dec 2020 00:43:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607330602; cv=none;
        d=google.com; s=arc-20160816;
        b=aF2ox1eKALaT8sOXN3UsAEHRJcDqMUguoskz3Ng89irlgI/HdYQJKXiVDQPwrajVa+
         8j4Gtq/eoQe5yVa4VFsXmTaQvYEI4KAtiE00+Mq0adYzCB7uzhmNcrh2LhTo6/AJZJD+
         FY6ZLemDNS4QuLHuYUqZPSn5wtAftpl4BomRx1QK197W5uNcVdHYDww+/mmwBgSNr5gV
         1v9Q3g0iUSiBV3OV61ybYACgf8NXolj9udffMalsOBsBwTF1H2xnQ17evbAZOgGX5zfM
         g0NDKgOlKTepQYQO9UO19EG1FKqzl4ttFyo53A76v78LBT/bFNGXIVE84frVlR4NCzZ0
         /7RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=l+9j/MJ7j0lmC2v45gU4N0XrvCt1N7cPIreqO6JUb8g=;
        b=tcdhCdjKeERxolqZOOMJqc31JKLY/Nz3/VwQxsdXZZYax1r5zxMnESXRatOjxW3eOm
         u8lpmnSsqVB0aTpj2GYtguOKNydEfJljPqz3I6/vVJBoBsUUGjawJ3d7n+4t4KrgP2a9
         loATnmQiSFc7QzAoI0+C/5nfF6E99gaq3J5ZcTkHprRsonOG70PIA5CARIp3yWzZ3DRh
         hDMcnMGGjM4gKs05adzXuWT3odxW8UpK84kTBgaR4WxSgLTtHs3B9utJoDFTdHEUDecM
         5JsHoHYsmxAdY/+46wodF0hDm0MtlERa6EKb3NdCzp0RPS5QfQZaDMLRZFqR8XU+hvTI
         qAig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id m13si1120911otn.1.2020.12.07.00.43.21
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Dec 2020 00:43:21 -0800 (PST)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 8450566103d24bb199fd8f928400b60c-20201207
X-UUID: 8450566103d24bb199fd8f928400b60c-20201207
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 425649347; Mon, 07 Dec 2020 16:43:18 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs02n2.mediatek.inc (172.21.101.101) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 7 Dec 2020 16:43:08 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 7 Dec 2020 16:43:08 +0800
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Zqiang <qiang.zhang@windriver.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	Matthias Brugger <matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Kuan-Ying
 Lee <Kuan-Ying.Lee@mediatek.com>
Subject: [PATCH v4 0/1] Fix object remain in offline per-cpu quarantine
Date: Mon, 7 Dec 2020 16:42:57 +0800
Message-ID: <1607330578-417-1-git-send-email-Kuan-Ying.Lee@mediatek.com>
X-Mailer: git-send-email 1.9.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: F870CAB994CC304B1F71C8C2A04196A3049B21FA10F0E5842595FF682C5B255B2000:8
X-MTK: N
X-Original-Sender: kuan-ying.lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

This patch fixes object remain in the offline per-cpu quarantine as
describe below.

Free objects will get into per-cpu quarantine if enable generic KASAN.
If a cpu is offline and users use kmem_cache_destroy, kernel will detect
objects still remain in the offline per-cpu quarantine and report error.

Register a cpu hotplug function to remove all objects in the offline
per-cpu quarantine when cpu is going offline. Set a per-cpu variable
to indicate this cpu is offline.

Changes since v4:
 - Rebase to linux-next
 - Remove the qlist_free for double free issue
 - Thanks Qiang, Qian

Changes since v3:
 - Add a barrier to ensure the ordering
 - Rename the init function

Changes since v2:
 - Thanks for Dmitry suggestion
 - Remove unnecessary code
 - Put offline variable into cpu_quarantine
 - Use single qlist_free_all call instead of iteration over all slabs
 - Add bug reporter in commit message

Kuan-Ying Lee (1):
  kasan: fix object remain in offline per-cpu quarantine

 mm/kasan/quarantine.c | 39 +++++++++++++++++++++++++++++++++++++++
 1 file changed, 39 insertions(+)

-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1607330578-417-1-git-send-email-Kuan-Ying.Lee%40mediatek.com.
