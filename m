Return-Path: <kasan-dev+bncBAABBGP7ZSAQMGQEGGLIXOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 06E14321038
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 06:22:34 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id p18sf5604453wrt.5
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Feb 2021 21:22:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613971353; cv=pass;
        d=google.com; s=arc-20160816;
        b=NwoNFWzkYc/p43ZJdgvh8JYMFm++nCrw2+nn4jPFBR+f2eZ003lWo09I0FY8tOpA5+
         TFkIraJvKaW5wUm26K6/Me9tvR0uCX8ut2q98r1Ts82v6Hf6Elmyih4J2AZoynGF59wE
         Ex2SZM9u6dZUnKEnXcaUlcrS97Vg91MfKnBBCBStPLjvIwEQvDa18JaYZWEWe+gEMP3j
         JSt+HfpWoTcs68/FFdflA60ABCWLYloC82F2hCRLnFxjd4twoLQDOChj1VXxYT3p6AZK
         PO4/bShGLptgW3A4FkOwB5TgyRoIukACHvnnVAR3IokPuIAmdRBizRXUPSvf4P+q5f96
         50oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:message-id:date:subject:cc:to:from
         :mime-version:sender:dkim-signature;
        bh=dZc8s20BCLuLEpjfe4VDUAoxBPJuaw5RUYO7OhnZ3lE=;
        b=A+3WtR9Ym017uVg66fk546XfHKVzt7nLSuv8XQKCIbI8widUblQ7qDIsln0Jdm/59O
         Av034elmpUQ9ByM4SGLIBFeZPi4uTHkH954V13iR87L9wD3cGkFpGm6VDforQxN41b+R
         5DLUJTR/fn1n2bI2UrN+MrmMBfM5XwOjapwXMF5GQCanSCebxWAnVObDVtDyEkl/ZXK9
         IVVbeFdXnykP8CHdT0fNiAImC306NgJUhiWhcZWZ9FMpbmzSWpW/zHeUatAacwjGkGOa
         lmeDlef/oQZUbkPe38rFTn+xskr3hqA+uV1HUUqXEwiy02EO2BegZfor124KEcGykhPE
         Rf0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of daizhiyuan@phytium.com.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=daizhiyuan@phytium.com.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dZc8s20BCLuLEpjfe4VDUAoxBPJuaw5RUYO7OhnZ3lE=;
        b=gwymOgbenC/hOypsnJK3JhsjWjk26L25AESMw/gbIHNzun4GCz6kpIQZMxSkjcQLh+
         TRyuKtHW5We5EUxpuRrsLNA8r6OSQtjVMC+wXr/bKFzpD9XJaAS/V+w6VtAjZc2hYt2A
         2NDcqj94ZxsSTnOVVWMhpzFc9sodrDo6SKvU+x3pFKlMaO8V4ljvOxyB/tH7dKIoC6BF
         JzLjbYJVVsTJlw8YScoeeRQo/7244Lz3g92Db5Rr14vo4ApY68pSTu7k82eDGlmX5wBV
         kcpQ8nZJV6FoEGW8KJHxwX6jmFGJ2dvYo6j1rnUbTk9Jja2IO/BpvMmnbZstWv7cW73d
         7isw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dZc8s20BCLuLEpjfe4VDUAoxBPJuaw5RUYO7OhnZ3lE=;
        b=dqH0bGX8H+8NWyPjnllgeIdv5CP24D7xXCSVjH3NfyguRN03NS7nMtwUml5g2hlGhJ
         iVYhZe5xKX9py/B0NXBqGHNG6d+6ruzq1gowvBiOCSmwf/HbN/oLQo5oWQYY5I0QQNZA
         bhLmdhz5A4pLK9slYXF0OYwQhwbuZ93kaePkfbIMelSjdQ7vrc7A93rl4oOHFSZcQKhU
         NoEw6/e4NBuIju815G9ui3pQ9kAW3AQ2f8C39OHnI5V1Fq/zW6BZqquSgYBg5hMOnwyX
         W9T6VnP0Xtqwaob4F3VoJPKnWO8FJb9HOi0Dbn9MXfn3KQterUM58F+t+LgBmoY6CKCa
         Fv+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533v0OIlIYiZcISs9O75KmTfhL4IQqtC+tjOR3nt9VEQdL5L4pRo
	3FYzymAFxLKDSHOwg+Kx3RM=
X-Google-Smtp-Source: ABdhPJxLWXY8pQDNeZYULlauUIzoufmP/isYcD/ETfA5pexgLVNUr55jjfw/uYIhAu7YMZQEm57L2A==
X-Received: by 2002:a1c:1982:: with SMTP id 124mr18844566wmz.84.1613971353776;
        Sun, 21 Feb 2021 21:22:33 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:385:: with SMTP id 127ls6855032wmd.0.canary-gmail; Sun,
 21 Feb 2021 21:22:32 -0800 (PST)
X-Received: by 2002:a05:600c:410d:: with SMTP id j13mr7308871wmi.55.1613971352752;
        Sun, 21 Feb 2021 21:22:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613971352; cv=none;
        d=google.com; s=arc-20160816;
        b=WvsNdATV8/7XgraLFQhKWiTLr3ww0W9cFE5QgLMlqasoL6kYZxq+XXopHZs5lTFqch
         12cOsEExHuGKukJKSAvQBMtHgEmajvf13ud0NwOhwKalvjb3AfR2Kk7vG3vqRCXhJB3e
         P6gMnzTYqe7Rvy2v3qwzS22am6JS6r7QIBHhQ3XWylLM3OJ5POjvtRa9xhT5hDaS+a1A
         2JnGKq4JVNil3TOKnchqAWHiTiNLUkjm6IB1hQi765bKuSXuokhPBXsJJbCrDOpDWH+H
         lUWnZWM5gpj4T3Bwcc0d8giQjkMytkVB7F3etaewQhI3XUML5tRGdM8sQ9k0WpcRNVYj
         LEpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=message-id:date:subject:cc:to:from;
        bh=h7B1yq60tnrE/fwp0LlRUqy/Hidangv7lnOpIoYhzkU=;
        b=sWs3ZuwAJ6F1BmYS2sRxCdEjbabY0WWZZgsZioZC1FTiI4HIx11OKTKV6ZsPaS2V/p
         lbihoCgG50GXA4Es767Hx3FeznqeV5gmFDIemdWla/KMubVGXT9o2YDUQ8qRr8HJCz1a
         PWgvqbjTOUmtmoZOHHtYB3R1nSJRA3xXlBb4FRji7UdLKVKguusXy8fhsGoP9slM1UZK
         +gAwawGB2Xtg5L6cUfis6Cf8YSLUM66Y4VwnkOQFCEetdIA59bSMvCy3t+XektohdsxM
         Kg9jz5UGapvNdb2ueLUYrvkOAN2ap292wz0YXLe3lCLy2dB22xa7gsykCi715DiUGNX+
         fSGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of daizhiyuan@phytium.com.cn designates 206.189.21.223 as permitted sender) smtp.mailfrom=daizhiyuan@phytium.com.cn
Received: from zg8tmja2lje4os4yms4ymjma.icoremail.net (zg8tmja2lje4os4yms4ymjma.icoremail.net. [206.189.21.223])
        by gmr-mx.google.com with SMTP id y12si253545wrs.5.2021.02.21.21.22.32
        for <kasan-dev@googlegroups.com>;
        Sun, 21 Feb 2021 21:22:32 -0800 (PST)
Received-SPF: pass (google.com: domain of daizhiyuan@phytium.com.cn designates 206.189.21.223 as permitted sender) client-ip=206.189.21.223;
Received: from centos7u5.localdomain (unknown [202.43.158.76])
	by c1app2 (Coremail) with SMTP id AgINCgC3BEGWPzNg8yoUAw--.27007S3;
	Mon, 22 Feb 2021 13:22:30 +0800 (CST)
From: Zhiyuan Dai <daizhiyuan@phytium.com.cn>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Zhiyuan Dai <daizhiyuan@phytium.com.cn>
Subject: [PATCH] mm/kasan: remove volatile keyword
Date: Mon, 22 Feb 2021 13:22:27 +0800
Message-Id: <1613971347-24213-1-git-send-email-daizhiyuan@phytium.com.cn>
X-Mailer: git-send-email 1.8.3.1
X-CM-TRANSID: AgINCgC3BEGWPzNg8yoUAw--.27007S3
X-Coremail-Antispam: 1UD129KBjvJXoW7tFy3Kw1rAr1DuFW8ur45Jrb_yoW8JFWrpF
	9xJ3yxJr45t34j9Fyjyrs5Z3WrGas7JayxtF13CayfZwn5Wr1kXryIg34rAF48GrWkG3W3
	Za4rGFyrZF1UAaDanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUkl14x267AKxVW8JVW5JwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2ocxC64kIII0Yj41l84x0c7CEw4AK67xGY2AK02
	1l84ACjcxK6xIIjxv20xvE14v26r1j6r1xM28EF7xvwVC0I7IYx2IY6xkF7I0E14v26r4j
	6F4UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVWxJr
	0_GcWle2I262IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E
	2Ix0cI8IcVAFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJV
	W8JwACjcxG0xvY0x0EwIxGrwACjI8F5VA0II8E6IAqYI8I648v4I1lc2xSY4AK67AK6r4r
	MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI0_Jr
	0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8ZwCIc40Y0x0E
	wIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxVW8JV
	WxJwCI42IY6xAIw20EY4v20xvaj40_Wr1j6rW3Jr1lIxAIcVC2z280aVAFwI0_Jr0_Gr1l
	IxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7VUb-zV5UUUU
	U==
X-Originating-IP: [202.43.158.76]
X-CM-SenderInfo: hgdl6xpl1xt0o6sk53xlxphulrpou0/
X-Original-Sender: daizhiyuan@phytium.com.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of daizhiyuan@phytium.com.cn designates 206.189.21.223 as
 permitted sender) smtp.mailfrom=daizhiyuan@phytium.com.cn
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

Like volatile, the kernel primitives which make concurrent
access to data safe (spinlocks, mutexes, memory barriers,
etc.) are designed to prevent unwanted optimization.

If they are being used properly, there will be no need to
use volatile as well.  If volatile is still necessary,
there is almost certainly a bug in the code somewhere.
In properly-written kernel code, volatile can only serve
to slow things down.

see: Documentation/process/volatile-considered-harmful.rst

Signed-off-by: Zhiyuan Dai <daizhiyuan@phytium.com.cn>
---
 mm/kasan/shadow.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 7c2c08c..d5ff9ca 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -25,13 +25,13 @@
 
 #include "kasan.h"
 
-bool __kasan_check_read(const volatile void *p, unsigned int size)
+bool __kasan_check_read(const void *p, unsigned int size)
 {
 	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
 }
 EXPORT_SYMBOL(__kasan_check_read);
 
-bool __kasan_check_write(const volatile void *p, unsigned int size)
+bool __kasan_check_write(const void *p, unsigned int size)
 {
 	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
 }
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1613971347-24213-1-git-send-email-daizhiyuan%40phytium.com.cn.
