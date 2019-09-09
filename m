Return-Path: <kasan-dev+bncBAABBHFG3DVQKGQE4Q5P7UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id E0CBAAD522
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2019 10:53:49 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id k68sf15492450qkb.19
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Sep 2019 01:53:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568019229; cv=pass;
        d=google.com; s=arc-20160816;
        b=qSShtpwDkXvDCK01hXnybBo8efqFT7V/cvO8hjRhIeA7dtRe50WhOlnPvsZUUAy4ff
         W9eD5vDobJMCbCezaL3bmlmMTmgpMrrIv7vRUWMnwWsf9WrXIqENU+kZZWvzv4ot/Uto
         uqeWYY+ZQQs4REWOZiMOha/+6YBje9xvWjU0Cd6QGM31c6bgx06NkqzPW9eyYjKS5dNY
         Nu+/vN4AQCd42ER1b72dMjlaxG85pG6h2QhdcpQNe5zn0htU5PTR28ws6DaRvGMUiGKo
         pVtWvByVy8T84yXrcZ+c37/tXrG/nSdFxOMS0mCNIA1OxPi5rxXUZNoCkjGxvnHhZ6B2
         Q4BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=K15Lgl8hGEpSWYptGb8mBO04FXm/cItB+gHN6wDNOyI=;
        b=IGd05aF1AB7O02Jwtk8Kf9hsEb0H/4agAy4Y4vKaV9bhTVi91pVXH+ABdRsWju4ojT
         IgmxPw1Kut4QebEIRGh3np+NkTr3oM3krOccUEtnekICuD5onD/Ky2hqItN8DyxJn8bw
         Sg1rQMt5KGMQJGyLCHTczp+fZ/lZY8YUkJpHm77esQsgrWC0SAtK8ShNmB6cVZd3eYnO
         N06zKnLROrar9uP6/3fxb8L5IbHnarbzMOzylqBOo/sI6ClK3DHSxqdOCBrOynVKGkvW
         +i9Ho6DN/oY6CLZuncPEkjsHN2H6ltAGHqKV5MSwSLrIsU0F1MdTo6XmzHZMXKLGn6uQ
         2p4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=K15Lgl8hGEpSWYptGb8mBO04FXm/cItB+gHN6wDNOyI=;
        b=KF9RjKuZDoBOrLojZvqPjD97fLsGnYbgvlWGk2ip6Uqc7fcbhL32ioYNs3/BaAetz6
         TWaAkmMw49VuVpm0iab7WxyWiu4jWQMJBx0QD6kGD1+WBrEnUsCqsEt7d6ughu9yf30B
         K3Dc71GGmXK9TAmQdRGiVTpXSxK0JZ+uZRVM+okuTNc8ob1OWKuPjfl2qA9vT3V/xlR8
         odAhwOb2KcIqEE7k4axxEYz0uOCQNKGlL2U0/GGkShq/rGRxmC/3R2KhXw8bGTOVu+q0
         hI9tXOZrW70TZAKypcNDuoRGcAnHITTFPq1+QdAq8wRWVDsTHQZrAxmzd77ZkMOlWc6S
         +yXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K15Lgl8hGEpSWYptGb8mBO04FXm/cItB+gHN6wDNOyI=;
        b=LGIH1GGwwrTF4dZSJdYXgGGqJoV20+ksA2YFYMYDH3//1FPHvyy1EhweJH+HZSHedc
         yAMiY5788QyLofoGmTtP1DThnMQyi1OryQ2mdfnG8s82oCcisXKX3Trg2lQJbqmRe0H5
         rjGqlmuJWfa8eE9xe4AypoD3nEQiTOw8Dyed0cH/9a+swx6QTqviJqOGLrQK12gkaikP
         H5Vr/Y4dw94pxlBttbCIhHDwRuDpwGhwO+Qob7R9hjvqRqjYlazXuAGIGMIydKSbr4US
         s8K4oztm3F6IyckdneI04EbAwcPzp2Lxkh+jfU5SIdK4fFeKeKqUURurNSJ2tJpSqG/W
         Dbaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUWiRr6RsJ2woyiE2CvWoFbZGq03VJl2QFhm7poY16kexQgXDDQ
	n7r0yUoGkTinvPUcZrzF9ws=
X-Google-Smtp-Source: APXvYqxEy916henGyJlSNNR+/ZqsDLv6dG1F7h4EjkdOj5V6CFy4Az/iysLjG1HJDSKGd4A7CFvI8A==
X-Received: by 2002:a0c:8729:: with SMTP id 38mr10045318qvh.183.1568019228866;
        Mon, 09 Sep 2019 01:53:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4706:: with SMTP id f6ls133619qtp.3.gmail; Mon, 09 Sep
 2019 01:53:48 -0700 (PDT)
X-Received: by 2002:ac8:7088:: with SMTP id y8mr22097003qto.184.1568019228713;
        Mon, 09 Sep 2019 01:53:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568019228; cv=none;
        d=google.com; s=arc-20160816;
        b=KOl9H/+tYhnXd16p5znw1qaMk19rk3ZEf/R0nyKNy6EmclkmzkZI5og6/9kE4znLoA
         y4GTOkkfIKqbnQ58/0A6Q33Nw7gNdB0BAwTuaCFP0iNFFm31qEfTKPoqqv2Sy6r4f1Ik
         JQeCMwry7xzTEnEU1A5EX8CaO08CWl4APg8TU2nAxE2nGWQG91umyFYKvY6Aq6CI4O8o
         eZCX4qkWfVs3SdoQFceZkeROybCG6MGoM+YZ/jc98WUz6H36lY9I+WDMKmvJwK/1ZWBj
         fICu5iYiZ0eEffHzYPyIMuSEZsXdqndhZQaD8J0Dkx9tm0jW5c+2vlBS5D8wRwODB6CC
         uYJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=k+lfAhDHubC1nf1vwT8gJqdGJYjrbwQvEPaTcYAlgTc=;
        b=CUMrDZCGXLH0TIQkUPoN6lgwxd0nnG6ZJA0EJycDKNsu9ECgrHz1sdLdcnDzYBc5n+
         i5bYjxsCJftaaUXU1TloRqfsJs5crk0xi98Sm5fMV6jQoNpP8HjVkuQHAm5hr3Hmeibf
         kBvs8JoDE7lkn9SDrw4Ai/RnQpsSGuPkFD6cuOtlkAGdjhBx1h4sCZSGQyp73Bi7z9BA
         eeivHNX+vpurKIUSj0XHkK/+Y2m2f44ovRcSiFW4ni0lwGwf36bWRHu5sc5a5GYZ5tnP
         ucAe9iQfkkkK662cWyKK3HvvE+OIP0O20m2FT5AvbHoxSXeqxF9XieLn+C3VbwLt+8Go
         Z03A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u44si899983qtb.5.2019.09.09.01.53.47
        for <kasan-dev@googlegroups.com>;
        Mon, 09 Sep 2019 01:53:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 0052279582b546f0bf7107861527c82a-20190909
X-UUID: 0052279582b546f0bf7107861527c82a-20190909
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1143796525; Mon, 09 Sep 2019 16:53:42 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 9 Sep 2019 16:53:40 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 9 Sep 2019 16:53:40 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, Martin
 Schwidefsky <schwidefsky@de.ibm.com>, Will Deacon <will@kernel.org>, Andrey
 Konovalov <andreyknvl@google.com>, Arnd Bergmann <arnd@arndb.de>, Thomas
 Gleixner <tglx@linutronix.de>, Michal Hocko <mhocko@kernel.org>, Qian Cai
	<cai@lca.pw>
CC: <linux-kernel@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v2 1/2] mm/page_ext: support to record the last stack of page
Date: Mon, 9 Sep 2019 16:53:39 +0800
Message-ID: <20190909085339.25350-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
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

KASAN will record last stack of page in order to help programmer
to see memory corruption caused by page.

What is difference between page_owner and our patch?
page_owner records alloc stack of page, but our patch is to record
last stack(it may be alloc or free stack of page).

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
---
 mm/page_ext.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/mm/page_ext.c b/mm/page_ext.c
index 5f5769c7db3b..7ca33dcd9ffa 100644
--- a/mm/page_ext.c
+++ b/mm/page_ext.c
@@ -65,6 +65,9 @@ static struct page_ext_operations *page_ext_ops[] = {
 #if defined(CONFIG_IDLE_PAGE_TRACKING) && !defined(CONFIG_64BIT)
 	&page_idle_ops,
 #endif
+#ifdef CONFIG_KASAN
+	&page_stack_ops,
+#endif
 };
 
 static unsigned long total_usage;
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190909085339.25350-1-walter-zh.wu%40mediatek.com.
