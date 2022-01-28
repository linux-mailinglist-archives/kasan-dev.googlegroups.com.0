Return-Path: <kasan-dev+bncBAABBJVNZ6HQMGQEJLBMZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 21B7549F875
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:32 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id h5-20020a9d5545000000b0059ecbfae94esf3052837oti.17
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370150; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qd0g3bDKcr9ZCz5yWT2vyt6LvVzXGnLFrIEFog0NC9tt9pA9QoNn4QIRsl+fCMfNnC
         /QsWd9ZdKdU5EbSX2mgvTcR7GOaBYXPa8hRbR4UeJQjSdPjd2YgbxOKfs/lh9uMZ/xE8
         4HKJ0Luzw3lUjyHJMXLT82skntfYAM2W6LrUNxhB+jyXFuG+TzaTn07XgI2+Y4QEhU4b
         mwR9iaxO1+CaAMXI4KL0owI8//8ar8KZ6vC/smP3h+51euozkd9BpEeJeD7YWKc2brIA
         IOkX4Y30lFSnuFdrNyxaRGsi+ONiymck4uz3nBTkFvJ+2M4HLaJy+/BTFaeUa6gNUxmu
         /7qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=y99Tt4+u1S6PntEFuALxD5ywQUJ1e1MD5b3cra5Vdhs=;
        b=06sgv/gHYtiYnF7T5puHbrSBINxU3ShgkixELC1EcTrWtLUsA7Lvf8vhw61Qznd+pj
         elggIo9RmTP/hbq5w7ysf05/9Oy60VH7EYFEljJ+9q90EX4Nxs6xd+zZQqqzSKjR92Lk
         De9HNv5YWBjqSi5HViobu0wZ8r9vkIEhOmLeAZjCHb8ZUYnXQ28trYnywBvW2gHrDQv6
         gNfi6OggJXBAWu0IGp55IyjeaiGJPAlWv1XHTX1OgdskmkpSzZxw7Yy+2WVYa4fT9eji
         9QWGDgd9fpmh/2V3ZYW212/MVHqe7q1vDoCTeJYvb8BhSH0MBz/EwjiNu0rljd8DzcID
         lahg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y99Tt4+u1S6PntEFuALxD5ywQUJ1e1MD5b3cra5Vdhs=;
        b=pULoOpFW2iCKscWaSQhxhn3sTU7UMiow0kzGneCOvXlGITfDh+hzSSKT44b4sUzxf0
         dOsb1EjOUqBNG2cC/LasgHJOZslu9ibPZDLc7qLIv172KL0tkGPtL2EqRTNfFJj23pxP
         nXYfcU253JLN8kGjB/KMk5FUn/lNZGBDlyxkmiFLeIM7OdrgEPPuZ8KkP4PKFjfrmNcB
         5SraeiR38MZQwMd0pfj2EcotXLRumNkXkrl05XA3/foAm9UucD97KTU9IgTp9tlDheRq
         WkUCUegCpSrw4sFettAOYreE1BppvV4Jtbjfh9jc0Sp265G+/e35XakMm3Os7hTadgWu
         9dSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y99Tt4+u1S6PntEFuALxD5ywQUJ1e1MD5b3cra5Vdhs=;
        b=y+9DWyW/PnZeQTpH6JpAInjOWxvCLPYis9h5Sxu1BPTXMpNQ9rsjugG1lcMmDx25wz
         IUINgeV50JGxHOLrpvFmQB/8uCArQp2No2PtQnksHABT8/XbMGEaVzwSFXkYsiru0qtO
         NYBnyaLAEnT3KTuWD/p8q3pMWN4Ets/tWThsLXa4aIJDOVuYuxANnvwot9y7CdeQOeNg
         y9wUXYV0gwgLbQZKjyFo9Tyy87yNLVAXWKAb8b1X3ShSey+RZJlBu3KRAofrOTJPwQar
         pex2biIzEhZWcYAo//u00Jf6JJqpupLbEuHs3utSfI4mJVrbEKzdFj+YsdOz98M/t5Fd
         zoXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530iMlkQW0LvqnWs0BLtnGa/x9KOd77d7YHQpChcqfaP7hT9RQ1p
	YvauP498VZv4tWV3/a/3WXo=
X-Google-Smtp-Source: ABdhPJymlSU5BYHa7Ejln5Uif4P+VXLWGUDMvqLwdpwFPoqF+OIRXIVgua1lzNwGqhTZ1Ut3dW5sWw==
X-Received: by 2002:a05:6808:118a:: with SMTP id j10mr9922729oil.198.1643370150533;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:2093:: with SMTP id s19ls3650354oiw.6.gmail; Fri,
 28 Jan 2022 03:42:30 -0800 (PST)
X-Received: by 2002:a05:6808:1827:: with SMTP id bh39mr3981449oib.219.1643370150155;
        Fri, 28 Jan 2022 03:42:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370150; cv=none;
        d=google.com; s=arc-20160816;
        b=u49Vm3d7PMz7NKnN8FBTg+1tmFAG+WMHWeLGKofKk7rPIWVud/B0aWhcCI1y8MaaSZ
         uFoWPIYVB0zSger5ySorWr+BDJJlq8qZT3pzsfik13qmuGqMoGXGmZmwKAwLVczRLZal
         QnTrQQV5M7d22Q4flB87qWaTMbget6vtsHiMkmWTTohhuT69bFN36xuCW2YjHHMJOPX8
         LYa1+Qb+TrH4KQeq5EVBuQQeL3tcPvYU4vAeXhb4/+md049LkBInXzZgTh7vSR4p1v2H
         /hhoca+EPG8u9y/+kskbAZcdhknlbHqlzhuXnoCY2jx6ZFE37IggMoLO6XyLFNMoFWQH
         j7ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=a8ADjFUSsBTSR0OheH/RND9gtdwDvkRlZYsMfO5ij7g=;
        b=Gmy0yB3jvsbfd+7bzt50fwR4wqsFsZtIEi4HbMROHdPxEIqo3TvXRvQ38G8oWaLm4k
         p3SdMVC+PG2DzBtNeLDjRUhLzhBFvARRhpXgCS+RaNOqTIb8u6VvAy/ct7xRQ/YDBqLb
         eqMAj7Ftl1mhN2SrYv4p5zJT3n/f/Ox9P5IjLdltLovsOwt38WuDKwAFX/ABsekt8Ylg
         PATKmrCNKWNAdjbL4gxh67v9ivSUmWl/gqNiE0moEQBR5Xg2NesSq3vGxACGD7gUVGLr
         zKQFjUFhF18qjKMW3+Hl7k+emW39mywYYzcmma5RLUpNd6WvZ8bwFDRbBp7572VepPnA
         maWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id u25si372806otj.4.2022.01.28.03.42.28
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S3;
	Fri, 28 Jan 2022 19:42:26 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 1/5] docs: kdump: update description about sysfs file system support
Date: Fri, 28 Jan 2022 19:42:21 +0800
Message-Id: <1643370145-26831-2-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S3
X-Coremail-Antispam: 1UD129KBjvJXoWrKrW8Jry8Zw43Aw4rAr47Arb_yoW8JF18pa
	nYyry29FW7AF1kC3yUAF1IgFy5A3WIkayrGa4kAr18Xr1kur97ZrsI9w47JF1DXr1kGayr
	XFWSgFyF9a42k3DanT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUPIb7Iv0xC_tr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28IrcIa0xkI8VA2jI
	8067AKxVWUGwA2048vs2IY020Ec7CjxVAFwI0_JFI_Gr1l8cAvFVAK0II2c7xJM28CjxkF
	64kEwVA0rcxSw2x7M28EF7xvwVC0I7IYx2IY67AKxVWUCVW8JwA2z4x0Y4vE2Ix0cI8IcV
	CY1x0267AKxVW8JVWxJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280aVCY
	1x0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4
	xG6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCa
	FVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JM4IIrI8v6xkF7I0E8cxan2IY04v7MxkIec
	xEwVAFwVW8KwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s026c02
	F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw0_GF
	ylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUJVWUCwCI42IY6xIIjxv20xvEc7Cj
	xVAFwI0_Gr0_Cr1lIxAIcVCF04k26cxKx2IYs7xG6r1j6r1xMIIF0xvEx4A2jsIE14v26r
	1j6r4UMIIF0xvEx4A2jsIEc7CjxVAFwI0_Gr0_Gr1UYxBIdaVFxhVjvjDU0xZFpf9x07jI
	zuXUUUUU=
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-2-git-send-email-yangtiezhu%40loongson.cn.
