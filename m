Return-Path: <kasan-dev+bncBAABBP6ORGIAMGQEGHKSG4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EA934AD870
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:13 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id h1-20020a056602008100b0061152382337sf11269848iob.18
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324672; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dy8v8JRNtxaNiLPKUyfzMxufmf20judPxQfPwzuFUAr5rcvQH4PVZCxrLtPD81C6Lh
         ORre2hn1FRGfx4U5ZXNbwO9e5ultxq9J19duA08l5Mbr5OzLcjxHyKeJgaef5GpgiUD8
         YRteNMWQhtv7YawhFOxpdH9UbBOa6vmyKAmTnblDBbQ8xecdDxjC4CEPm7yAkICGj62A
         UIvmf1jr/Ik4zHOj0uaCa+qFfCj4aU8EHdtEolr/0XfZsogjWolwu0p912Gk9jSmcn+1
         3uhc6j44HzIzMWuz9YAeYON+C+vcFn/dhuJZXteXt09Mk6ml4W/ghkSxdj9jasyFiwvH
         re/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=cYakq1ns2/boR+m4FU07powHDBIgfplAXqnXFfhYzWc=;
        b=kPUrmDOxuykYN0X51jNw0Rtr890vsPg3IypEhOjhFsUF+z1XuOEnEdOFLwN4F2hRYU
         DATzaRZ99mM8e2aoEYGbeVcXty2TIZ8LlaxWOn64TK0vvHOWe8HaGwgKiFwQX9ZeKbi0
         PlBBxHIVApWvgq6dkCHgvcN/b239y/HhcxT3WMNIgwr/B0CiWehRWUBvPiT2GtjIRd/i
         pRKVTCiTE5hk7I+YyIXzsoG1XxepF+3iTWjVPXA7F1Ux4L3TUhW2Lf8ankYyKCiPP0Li
         Wae9OXpw2tb56LaCGKQxxjtGZSysPj2E02jSXG+qBeUqweZVJDLvCdEUBvhywBE++BFt
         wDlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYakq1ns2/boR+m4FU07powHDBIgfplAXqnXFfhYzWc=;
        b=CDBV2AvpztwyX4imTOJvCHANaYZhIeQ2SufSBSok7mnhP9mqBmEylyd/5mU10uQV38
         rFQG2cnpc+M+A4AfOM4gDk+5/ahMuV/DA0Jm6uUDIgvEONap2NZTkEOBxANREqgLoYrk
         Hud6+UnS9HzdZ6ZPuG5BOrOcRz1Z14DvGUGvl6NalIyBzTNKfE2nKa2RKH7W0XQjnABW
         g7/3wOUAacOfsFEXNOmqKtAeSidCW0hJ7xzuqSKOtuEQykGO9ZlFEpO8legQ9FLsPj1a
         r1IPmemmcdZSC0hJ9OU2JIBPcEUA+YZgCIvEJhtIm08NLOspoFYIPcCfSE4oJg2vzU2H
         qljw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYakq1ns2/boR+m4FU07powHDBIgfplAXqnXFfhYzWc=;
        b=GVLRiV4N87y/hW/+5TLjmVGDrUJfohmvN/m7kn1N2JjLfNX0+RhGuBbsamW4Z8vS8n
         NsWOE0oU4XrZlDGCbN2hdjEpWZLqhOPHi/SjBq9QeNzEADnbNM2qPxM7fotMSpvDumny
         epA73QIrrxuPFJy3C2ZTxrByJhOEoQ+L+sZXQzNoSIB4EeZL+KNIUtTP9AJATzHBQoYX
         oRd39yRjxHE5IIJnU/2ZzQF+ZFT8s9RFIs7alB7nYdnna+qgCSFqw6hdxeNW6Cl25LJ0
         iyA5KjR7L1dNXsWGCZ0sr3Zc7pmJCy5KyXCrf17Pwzspe51Wpmd3Kk4OCun2Jy9pBUNj
         sopQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GJ8mF5CwswObgte3IRsYeeMJlNyfiW/hBjCIKaCURp2eCLqS7
	/Kr8icAu0GvexuX4D5KPTMQ=
X-Google-Smtp-Source: ABdhPJzX1C4vvHPzHEtTWNMAPXqjDHTQQ4QuV/EAWHWGBrx7Jkkmgpwcv6oYXkwdsa8rhK6RwBEw2Q==
X-Received: by 2002:a6b:f710:: with SMTP id k16mr2003653iog.33.1644324672138;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1808:: with SMTP id a8ls1066312ilv.11.gmail; Tue,
 08 Feb 2022 04:51:11 -0800 (PST)
X-Received: by 2002:a05:6e02:1686:: with SMTP id f6mr2071536ila.275.1644324671621;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324671; cv=none;
        d=google.com; s=arc-20160816;
        b=pZWdvAZiWBB0sz4cFlx1N+l5hmfQGsjXUgrPBZUtvSn6OoM3fBbtlO3bNIDeqwtBdk
         eW98/5PJ4Mw+ADtsoORNiA5qXWsKq1XacKiyYC0Rx6JYgdFv6cyWdY4XB+8cjWghsPK9
         soqAA8iT4lCcJbR3IjkyQT2EWtBMsQtN/J8xwsrjzso7iVteh3pQkzFZnKxRCwZfI6Fg
         BruAe0UQwzl/0tLdVkYS1STOKOo/mepIiESQlGgnwTuxJ1IRi+mEPA2SilR0tleF7UTb
         uut9/22QM7YwSkYX37OYDNvb9BmDGxfJAKFSELJ20yrLndU2ATU0kczy1Y/HBROlyOUR
         rowg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=y+cm3/np/c70fQJflNwA311oacgSp/ReWQ39IP4hCfI=;
        b=Kis3om/L3InT0JK/2I+8ChzykFdUDPdwn6zpS3f/3T48ePePKjztc5dy/vsqnxJwaK
         Q3RrMSulygORtPpNCjzVfJR7Amj9oNH41yvtJBHL3FqrexzGcxRkcdjJa5Q8xesHhfQ4
         lITktNeTayHAfrty9gk3ul5MBbu3wYqNshDLVY10tOo9wryXJE8EYEDMLWiGKR2ca1b3
         TebS3xf2Nmadrs8K11iehe6P5e0Q7VHv3NpYjjYPvF+brQzpjwdMPN4PrQOhfhR8TOm8
         XfoXoOqijcH3Bv4lIHas61uIvm/iuPvmccNFacszSdsv8yMuoF+FN+TayxTIfg4HsrUZ
         UKjQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id n9si632061ilk.1.2022.02.08.04.51.10
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S4;
	Tue, 08 Feb 2022 20:51:08 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Marco Elver <elver@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Xuefeng Li <lixuefeng@loongson.cn>,
	kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v2 2/5] docs: kdump: add scp example to write out the dump file
Date: Tue,  8 Feb 2022 20:51:03 +0800
Message-Id: <1644324666-15947-3-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S4
X-Coremail-Antispam: 1UD129KBjvdXoW7Xw48Gr45JFyUGrWUZF4ktFb_yoWfXrc_Ka
	97WFs7XF17J340qr17tFZ8ZFyfZw45ua9Y9Fs7tr4UAa9rXan0kFyvvFyDJFyUWF9Y9rWf
	Wan5XryxArnF9jkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbgAFF20E14v26rWj6s0DM7CY07I20VC2zVCF04k26cxKx2IYs7xG
	6rWj6s0DM7CIcVAFz4kK6r1j6r18M28IrcIa0xkI8VA2jI8067AKxVWUXwA2048vs2IY02
	0Ec7CjxVAFwI0_Xr0E3s1l8cAvFVAK0II2c7xJM28CjxkF64kEwVA0rcxSw2x7M28EF7xv
	wVC0I7IYx2IY67AKxVW5JVW7JwA2z4x0Y4vE2Ix0cI8IcVCY1x0267AKxVWxJVW8Jr1l84
	ACjcxK6I8E87Iv67AKxVW0oVCq3wA2z4x0Y4vEx4A2jsIEc7CjxVAFwI0_GcCE3s1le2I2
	62IYc4CY6c8Ij28IcVAaY2xG8wAqx4xG64xvF2IEw4CE5I8CrVC2j2WlYx0E2Ix0cI8IcV
	AFwI0_JrI_JrylYx0Ex4A2jsIE14v26r4j6F4UMcvjeVCFs4IE7xkEbVWUJVW8JwACjcxG
	0xvY0x0EwIxGrwACjI8F5VA0II8E6IAqYI8I648v4I1lFIxGxcIEc7CjxVA2Y2ka0xkIwI
	1lc2xSY4AK67AK6ryUMxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I
	3I0E5I8CrVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxV
	WUtVW8ZwCIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8I
	cVCY1x0267AKxVW8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aV
	AFwI0_Jr0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZE
	Xa7VUjZa93UUUUU==
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

Except cp and makedumpfile, add scp example to write out the dump file.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
Acked-by: Baoquan He <bhe@redhat.com>
---
 Documentation/admin-guide/kdump/kdump.rst | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/Documentation/admin-guide/kdump/kdump.rst b/Documentation/admin-guide/kdump/kdump.rst
index d187df2..a748e7e 100644
--- a/Documentation/admin-guide/kdump/kdump.rst
+++ b/Documentation/admin-guide/kdump/kdump.rst
@@ -533,6 +533,10 @@ the following command::
 
    cp /proc/vmcore <dump-file>
 
+or use scp to write out the dump file between hosts on a network, e.g::
+
+   scp /proc/vmcore remote_username@remote_ip:<dump-file>
+
 You can also use makedumpfile utility to write out the dump file
 with specified options to filter out unwanted contents, e.g::
 
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-3-git-send-email-yangtiezhu%40loongson.cn.
