Return-Path: <kasan-dev+bncBAABBQGORGIAMGQEVRNLKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A60E4AD872
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Feb 2022 13:51:13 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id j2-20020a9d7d82000000b005a12a0fb4b0sf8103879otn.5
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Feb 2022 04:51:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644324672; cv=pass;
        d=google.com; s=arc-20160816;
        b=Jfut2hHph+44pmVyhxwmJ5w1POmn0U9Wxs+fekw6N1LhV1lRW+x0J52ZzfM+IWMaA3
         GrdV6L3Vc4mZMNVPo5bW2TkynbU5qdB6RKkHZ1Ezn7LsMOrmWxf558c0BSSC+WzrzIPc
         GN+UNiJdQolzkN+KVc9RmdeSoPhvr+ivLEf93PUNVPa6oybVgxEdf+2iDJX2j8FBGgKi
         H3W4M8VWpVyba42oWjWdGgykfrqVXfg9Ph/IVLhM1kYs2oJ2STa52EiaYvSKoI8ZGXWn
         XsfWH54lKBFFMG+vNY8XoVvBv7D3w8g63uwFy/4ge959QHNUwUmlbHwkaUrPlpKvtry1
         AvJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=TMGCQRg+pqhhk1/c+KD3QAPWmZyMuv64Gqpf30OGMic=;
        b=oJccF0l0pxW/JW8fAtYcj7CYT8SoqMfhaDLNBg2I+iQkAQ4XEFRkclnC5BLqezuvKI
         1E2ILudf0GK9xSGOwIvQ++IG+NrZnbwSgxzT6c5wy6l3dt0aBBTklPlhvPWu+mRZjQAM
         J9wpqYhtgH08qsGZur7pkPc1uKeLlJY+87tkIIrb3/cYrHkgyGF91DW48YuXsNZGgOm6
         AuIglFHOSsE6RHurSFZR6qc9ekJggfs20XToSOsCZXpURUYoXHsRrAUqmaRhPb9WR6NH
         2YvYcybPJwiBsr7v0SZRwhnM4o8yyhwYnci/Az3xi24MJ0kVtwXTnJwaYFwYS6o8Doyy
         fcEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMGCQRg+pqhhk1/c+KD3QAPWmZyMuv64Gqpf30OGMic=;
        b=BDqUNh6ay6Ud0J8+bOJFKACFU1fvW6Cf/OKj/4XsyzIfDceLdHndpIMtnKIJsM6zld
         TzMIOiRdNtVHDuPmkpGCki7BQ6/ux1NGpIyiEgbdq/aQqbLu8G5UVbPd6n7kEq+4M8J2
         ZlQyqDZ/mHVecGY0h4M3gYWMQOomjdGQrD6r5cAS1VElFemieg4U6BQehXPky/0tFwTx
         TKKxFI8tgN4vQINFWA2PwAcuoNRZDd/kk2DzYEDIgp1x/rsVf3SpYFguX6XtBRcYInXo
         XmfOTXjoXPr3M7DkRRVgwc+Mn2b7c6VuysWEIqLUnmrnkiu9DUDeTmr/7MhNWXDVgBa/
         yLmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TMGCQRg+pqhhk1/c+KD3QAPWmZyMuv64Gqpf30OGMic=;
        b=SaTZ+OkQEjGWI2uitaPOxxFN8Frwy1pzi0kxSLJjHnz8RSvJiPr9ZRVSletFQlYjP2
         WmoM4PeqEwSabyPD3TAewC13Eq7jAimOBNpQWqMGI0nhf4+Z5mh7maey7VGjNLLONuEi
         8dA3ErxsWDLest51gBTroOsldntSBvYMwKeD+/MF0l7ZCyAV8pYH65mq+mr/K+n58Nap
         4Cph6514iWFBjxeXUmwSUgYTICQnqJsSemrFVsAjq9UiSPLNLxK6YYYrib0UKsrBN1vo
         VVbdofV2nmYJLTJpN2TBQa30xgQnfF1P2wVBxR9bNaLuzxvBURSPqEXvrJaPuXygGU6m
         uYrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532op8tiTE8vAq+7EApW9Q86WhpUQKpmQczh4z5WcumZQv2+jcHo
	a8WvfNt6P1IPAokoXtFQoZM=
X-Google-Smtp-Source: ABdhPJzTMWcJ/WISQlW7Go1wL9wKkHssYtiATyMFOzP+XHt4JOw+KT4VkjVf6jTbOf6Ljn2mWybhHA==
X-Received: by 2002:a05:6870:6288:: with SMTP id s8mr301348oan.166.1644324672231;
        Tue, 08 Feb 2022 04:51:12 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2463:: with SMTP id x35ls1717990otr.6.gmail; Tue,
 08 Feb 2022 04:51:11 -0800 (PST)
X-Received: by 2002:a9d:7097:: with SMTP id l23mr1755219otj.190.1644324671867;
        Tue, 08 Feb 2022 04:51:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644324671; cv=none;
        d=google.com; s=arc-20160816;
        b=sD2vRWaG0PNSunwb/h3iRTqu5H0r+ukf0gqWJLYgJw5P1jSg1CgVo6xTqv5EZC38Iw
         44Ii781N2QQ0jLiw43vziuCq6mWOhgrxOC240T60HPWhJ7rnuV5ZdtTZUAvfz/qIa5Jp
         ygUd1vh4ekcPMiLbHPmpBdelYARd9UUuRJpSXetLH0p53eL7758BijVitm7NuJMr6r+0
         espyEQ4gvjOkZVsawivmpsGsD8qPX3+M2x5hv0f/xIT/GJJPxWZYbChCpvP4vBnIci+j
         DKaW5apRGCGsHtyiiZZKx6rWTjp7XGvqcx+OlrfxFtKkmyaLhPsjB+lVA47kiru3R7i1
         n1eA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=RJaq0c8TEQzJKGVwd4CSOPf3xUtPtuMIO9uyV8y1y6I=;
        b=xqT3AYCa9oiSSNQB6IrI8NwfnSszjlJQXQ4y9nDmH66y7kt50dVhCdcqwmoMVHJWZ+
         27vPosL4iM4xp27WUfi2HvbsicmTH4Th65GSE7F727VRtd+ox3yubaPDF/3pR4IoDxCd
         dASb3vJg4yhH2XzDkhgTY3HzvXYSryXZkNaYU4VorH3wpFBDVmoR2SqstAe9kn1fvZgd
         chHDlyXrf5kwKl4QNBUAeJUnxqAHRSqhKMa9S4Y1z9O2Jw+5HEjfFyvRV4umF7E+utFl
         F0JMbj5U+LNYDIsny30AJ3iSMoxcJevn9Sqdc813WwaVbPCggTIqav0aYfxKfQIlIv5w
         oZFw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id r31si1139813oiw.0.2022.02.08.04.51.10
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Feb 2022 04:51:10 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9DxL+M6ZwJik0oIAA--.26524S3;
	Tue, 08 Feb 2022 20:51:07 +0800 (CST)
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
Subject: [PATCH v2 1/5] docs: kdump: update description about sysfs file system support
Date: Tue,  8 Feb 2022 20:51:02 +0800
Message-Id: <1644324666-15947-2-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
References: <1644324666-15947-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9DxL+M6ZwJik0oIAA--.26524S3
X-Coremail-Antispam: 1UD129KBjvJXoW7tF1ftr4rurWruF15CFWkXrb_yoW8JFWxpa
	nYyry29FyxAr1kC3yUAF1IgFy5A3WIkayrG34kAry8Xr1Dur97ZrsI9w47JF1DXry8Gayr
	XFWSgFyF9a42y3DanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUPl14x267AKxVW5JVWrJwAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_Jr4l82xGYIkIc2
	x26xkF7I0E14v26r4j6ryUM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2z4x0
	Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UM2
	8EF7xvwVC2z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF7I0E14v26rxl6s0DM2AI
	xVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F40Ex7xfMcIj6xIIjxv20x
	vE14v26r106r15McIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xv
	r2IYc2Ij64vIr41lF7I21c0EjII2zVCS5cI20VAGYxC7M4IIrI8v6xkF7I0E8cxan2IY04
	v7MxkIecxEwVAFwVW5JwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC2
	0s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI
	0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv2
	0xvEc7CjxVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2js
	IE14v26r1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZF
	pf9x0JU8DGOUUUUU=
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

After commit 6a108a14fa35 ("kconfig: rename CONFIG_EMBEDDED to
CONFIG_EXPERT"), "Configure standard kernel features (for small
systems)" is not exist, we should use "Configure standard kernel
features (expert users)" now.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
Acked-by: Baoquan He <bhe@redhat.com>
---
 Documentation/admin-guide/kdump/kdump.rst | 6 +++---
 1 file changed, 3 insertions(+), 3 deletions(-)

diff --git a/Documentation/admin-guide/kdump/kdump.rst b/Documentation/admin-guide/kdump/kdump.rst
index cb30ca3d..d187df2 100644
--- a/Documentation/admin-guide/kdump/kdump.rst
+++ b/Documentation/admin-guide/kdump/kdump.rst
@@ -146,9 +146,9 @@ System kernel config options
 	CONFIG_SYSFS=y
 
    Note that "sysfs file system support" might not appear in the "Pseudo
-   filesystems" menu if "Configure standard kernel features (for small
-   systems)" is not enabled in "General Setup." In this case, check the
-   .config file itself to ensure that sysfs is turned on, as follows::
+   filesystems" menu if "Configure standard kernel features (expert users)"
+   is not enabled in "General Setup." In this case, check the .config file
+   itself to ensure that sysfs is turned on, as follows::
 
 	grep 'CONFIG_SYSFS' .config
 
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1644324666-15947-2-git-send-email-yangtiezhu%40loongson.cn.
