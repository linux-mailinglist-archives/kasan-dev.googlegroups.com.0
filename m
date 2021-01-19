Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBP5MTSAAMGQEV4MBHMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B4A4A2FBD7C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 18:26:24 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id l17sf13670289pff.17
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 09:26:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611077183; cv=pass;
        d=google.com; s=arc-20160816;
        b=lO21e1i949s1qaCGUrXXD+gBCBqhNPziHLHgS2wtVE3stTm0D7CJkr9KwDbb9x5nn4
         iYN3Knm+W6CYCYhOQ2ZknP+Ziam4kV2pexk4jXgqjAq0GJ3XOgBP/v9+ckp4pvP3WJn5
         V1rhFbdpABKXLulhQqAbE1wbHR81Yh47Ozlb96H+NIvaBUXwHsNQ12OIUfACTDGv7v1Y
         btIevN4nCwM9qhencTcZIFE/J7opD/pVtm/GQ6e14Rz6EyuaDYqI5oXAT89rsIt7D7JE
         61bOSjWK8ed3IV1HwuWLD4uEN975Goc/EgyiBgo9RFdzrQ3IyWpDJsnVhzAFvtynWWG6
         zFUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=noIhWWZ4BzpCPvS2YSEI5l+HaUDbBkUesX6RUmgVF8o=;
        b=t3aQt6Lq6ypydNfk2sNFPDNbaozTLHjnDmf37uJjEEe0PFao6a2c9mh59gX5zctdb8
         FGCA7wH7+Z5GPTKt3Kw8QxAIu6WVUaf5ghjvnLQADpRqp1UYXLiBKhIyBX+1oAA4FV6m
         eQnIDzaal80ytnNMPXDAyBlaOPLQfZJu7mQoupwbvm0R5gM9mmmRj4G9QoGdSjevPZsc
         J3ZZQ4zy+yKVMQsz9UmdCO35gIf7WBdxzmXsaR6KqKrTJ1FoAXIbwO8Mvvhll7ueBecH
         X0lHT0wdp+ygfTOoID2eCx7yVTSHZ3n8JRVBcaiE/DEyYXoHigexI1ODLSMZHcx/tjG4
         SEYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=noIhWWZ4BzpCPvS2YSEI5l+HaUDbBkUesX6RUmgVF8o=;
        b=WFk3QGXnW8HVhK39fvAmm600tkz3kuTq2nkpbddGszJvuog+mpk2FNRwAyus7bpyo5
         u1PFIXsfuqzJDkB56Hp3ywdmCZ0k98/sthCN8SNcketnKTktFdBzGnyXcYEZjqKCAMF7
         or3YQ5ALsOvbsE7m00fnHfozDsfOg+dgpyPUSyi56TG4F2nb5o/YBA5ImPgC1I8G/7HM
         hf2CFlzqz+a5QTJMyTBmHFNlkG4gehAqMVejskWzS87IhF4poXl6fLqQAdi3WMPA7fbw
         xEqLOP4zGdzDc/2Mbljpw9gMLNnd33Wc8gZgBFHhRjgpL8OfuG4fmYFmSxRvfUEz5err
         pI6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=noIhWWZ4BzpCPvS2YSEI5l+HaUDbBkUesX6RUmgVF8o=;
        b=P7T48wOVWh3mJlXiRq8SsmCC377btcFwVcVecbbuYyJEbmYmUfc/emPQuvHyow94fO
         Ecno9eV2/G0dBV42rB39rmrWWNp4xBKufcMpEGaFVxaXPwI7wOv5BhsOuBiTL9Fx06xn
         LpOiD+9JNYm80X+d1CrF3WfKuvOICPoVfiU0M+0YYwmmm/JQMUbIoUd3vu+UrcJVKOj8
         W7cSatZa2WrEJ0Muq94HvRA0G45o8gHskUcOk+TCHqM4fJiBk2QMZcvrpYY4VIJENxGe
         NB/xsTXwxMZCKxZbRN7kpr5l9yt+B+UBagyj5gMHOZZssUfGjqCb91WK9lBzjIQmLY16
         Aw/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533eJaxr4P2YYQAP8KtDlTjcdiU735IKLfeg7Bp3M2fM4zS3aLqh
	C5TMuZTx66rghgIDP7vW5y8=
X-Google-Smtp-Source: ABdhPJy0SAMYE3kLfQo95CgJqSriNEmxtAShrX0FZH+jbKtvxGDo/BupBvppRoOVFNOOJeFhJpmIfQ==
X-Received: by 2002:a17:90a:db50:: with SMTP id u16mr797389pjx.39.1611077183488;
        Tue, 19 Jan 2021 09:26:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9155:: with SMTP id 21ls8165170pfi.3.gmail; Tue, 19 Jan
 2021 09:26:23 -0800 (PST)
X-Received: by 2002:a63:e20b:: with SMTP id q11mr5421266pgh.396.1611077182966;
        Tue, 19 Jan 2021 09:26:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611077182; cv=none;
        d=google.com; s=arc-20160816;
        b=TCdcaxTiNzpWb0+/Gx7PXni8ku4KgOGuzfYbha/c6OAZ7fp/ngKBRf4UV2zaxN3Ppt
         Z78Iu7Oh7T3SXQ5XUWrwJv/M672WdRD2D6rSsQ7uBTU2vW3v12YoJ1X0WqugCiMFVzfv
         JicsvV+UKf6Bfq+L9KhRHZLSKccOmqT50kpy3XGRpAho1KUqWJAdi/DcBWYBotgnn8FK
         M+dOKcfr3LMC8ljuJWAX71lo4kCWfdJETvEL+Sc2ZaDKSOHQpE4gBsDEK/a5oHEFQ7+X
         FRLgKriSnUIGcQCmMxZrWGmfHUoKyQqIDsyw3+YCbLWivApsQQ8odsLlv0kmhFCT9/iI
         LiyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=6IMW/6mmHxZHD2fRzSb91KEkhTY07bcKlo5Fp18s8RU=;
        b=yKVaYdZmyfsLFay5O2qwPbxpK4wZeKcOoVja0gR/pg0gG0KGA/+VFyu/ilf9oAY7WO
         m7TejW6jtZVJ7b/gmhaUt8caoHZVwJqOpM5whJdQAUkbqhwJekyXJL46skFq+T62QCwc
         ISDwCZPxkSBty7otKekanxi74MaRdUvhvcMaJBUYX5FQ3W133aOxvxkXrRPHaH++rDP8
         D798vh0WLB/+XaWh22cyxNLdf+PqnEUB7QD3wrf6E87Qs1ABFz1C0rra8f+YYA0d10Ih
         3/wwzDv8AYB5O99g1DkD71rkT+X2pnc3koBIq5Fat0hhHb4D1F1hI04yGmwqfxXveXtG
         /Y4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id m13si398407pjg.3.2021.01.19.09.26.22
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 09:26:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AB5781396;
	Tue, 19 Jan 2021 09:26:21 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 7594C3F66E;
	Tue, 19 Jan 2021 09:26:20 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Leon Romanovsky <leonro@mellanox.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan: Add explicit preconditions to kasan_report()
Date: Tue, 19 Jan 2021 17:26:07 +0000
Message-Id: <20210119172607.18400-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
the address passed as a parameter.

Add a comment to make sure that the preconditions to the function are
explicitly clarified.

Note: An invalid address (e.g. NULL pointer address) passed to the
function when, KASAN_HW_TAGS is enabled, leads to a kernel panic.

Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Leon Romanovsky <leonro@mellanox.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/report.c | 11 +++++++++++
 1 file changed, 11 insertions(+)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c0fb21797550..2485b585004d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -403,6 +403,17 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	end_report(&flags);
 }
 
+/**
+ * kasan_report - report kasan fault details
+ * @addr: valid address of the allocation where the tag fault was detected
+ * @size: size of the allocation where the tag fault was detected
+ * @is_write: the instruction that caused the fault was a read or write?
+ * @ip: pointer to the instruction that cause the fault
+ *
+ * Note: When CONFIG_KASAN_HW_TAGS is enabled kasan_report() dereferences
+ * the address to access the tags, hence it must be valid at this point in
+ * order to not cause a kernel panic.
+ */
 bool kasan_report(unsigned long addr, size_t size, bool is_write,
 			unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210119172607.18400-1-vincenzo.frascino%40arm.com.
