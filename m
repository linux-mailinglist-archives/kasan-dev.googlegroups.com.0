Return-Path: <kasan-dev+bncBAABBZ6WXKAAMGQE7IELSUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 4410630243E
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 12:28:41 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id gj19sf8427572pjb.6
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Jan 2021 03:28:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611574120; cv=pass;
        d=google.com; s=arc-20160816;
        b=RcRyaQTo6zCK1jr7242dFvgMffwxRrgzS5BxB6llVKCDoCUm5rECtGY6QSizEwiIhc
         bxr6kcgs0VSAtSn88s5XmFsTw6pTSsAws8w+igsSFLuY9wx88wOl39Bw6c2QimzjEOgs
         QKExFkMHfBpkDFwk7bYx+/V/MJACXqiIqUV3IYtVrxlVLh8qGycl81OllxJGi2kGE1cR
         In6HGzPMyNy0ZN97FEg4WnNBzr56vtgJEE+zjBK2b1q4H/+0vk87K7i5TXUC5vZ36/6u
         wUI5RGXTKw58EhO2ZKuBn5TiIwUmgrbOxnAIDHlj7L4fk5GgyfHFpyHhJSgo13guSLyl
         jiIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=CACz5mOmOeH387tVpBZjmbElLYF9WbYRXVhu+Ot2FJw=;
        b=nDnvJIRn5ypHVKL0H15DOtXM/KYXyKKcCARKCTwEkV9CD9ecFyUcI3pl3ycFXC2Cse
         GUV3Z1NbKR/WkM1R2ME7zw39T68BHYNM6xjgziDYRtx3v1sk7pAykmosZgy6fHu+gUsC
         Xss8vSu0xrEG8fTbeN0IxXFI88x3PgeMa4wSjeJuXXp2DU934n6uZcmY6b+iS8UYG4Ke
         ib8we5hPKPZvZ0YzgZ7z8zQGeVFEa63dkFRlFFPEIdUWCEzdVRqsteN/wCyz1KrGCvY7
         xFigPk5Eem1ktoc0dKxwriuLfhcEijKVXyHoKqwC8sBYJpFYDj0udos9gYlOK0ObOBcz
         oHxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QvKH9jeO;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CACz5mOmOeH387tVpBZjmbElLYF9WbYRXVhu+Ot2FJw=;
        b=F3vpW5m2/F7zoBdCpuMhVVEUpJUB1Cbcd6hp6GmoMxI2bP4xAsIkHPzA5b4GQgh4sM
         dzTFjuqfI7MwhElnwbsHhv7yffQC5ZUDl+wthw74j//LkQ7eET6iyxxCElqlPvEGvKos
         CNh8yRJWKu/f8aVSwlVLRCSMRzzPtj3zABb8c+MS1FZn13oGYCvjyzkN33FsFE9BGmYT
         pT/J9Y1kVfMcCjAvHwqs7uYgLqpUkih8lRuERa3h0PEau1cAN/LqZAVlMj/sxkb2V0y0
         pbThSaq4ut9Pl9QZG6Cy/mDp2lFyvdFY7t2krm6HtTsDh2YRMAuBvQdYwT6ronpB+kig
         7uVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=CACz5mOmOeH387tVpBZjmbElLYF9WbYRXVhu+Ot2FJw=;
        b=gCJLGlR/r0M1sJjkt89p5zx9IqafD0kdWBZY3oiS5AJ0iqT867T1t2DHHfBpqhSog9
         qkuaHn8zoT9aJzH6gaVr76iVk2VIAvImXjLnz8UliWJZTV+38NGvfag43eblXULw7b9A
         YVHiH3Mh0W1kwv98JT79v1fWUxqT3MqrcWzK9nosocWrBIgmNfms3/7gJ/IsvwTvuqiU
         YN6uC50n+lJn4IfnzGVM2/AYHUV95KmpvKd+MKd9ORV6ZKeLS/SugpWjfx9G86B+wu69
         CxU6+4AsqyOB646blvO/ebZ7Ftz8AoEkJsX0aYV+8OoDtGo85L45QykQzOlT5SKinFTF
         PqXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530owzEAmoXBev66HYKkMMaM0f1fN5ZzqxR5wH5Axq9+P0UuZUkI
	+Ai581gf1G3XQS0XGTG42V8=
X-Google-Smtp-Source: ABdhPJwjD/CB7QHhanSeuXDPRSz1YPZK3j15FFHjDfpwdMVi7zyjgMRdEh7KOCHidIVfeDVfBrcA4Q==
X-Received: by 2002:a17:90a:6c66:: with SMTP id x93mr20732704pjj.223.1611574119969;
        Mon, 25 Jan 2021 03:28:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7614:: with SMTP id k20ls6236437pll.5.gmail; Mon, 25
 Jan 2021 03:28:39 -0800 (PST)
X-Received: by 2002:a17:90a:1f8e:: with SMTP id x14mr1875148pja.68.1611574119572;
        Mon, 25 Jan 2021 03:28:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611574119; cv=none;
        d=google.com; s=arc-20160816;
        b=GmpSRhi5GAPWu5r/5XBfxRvy6gmIoqkBd6mGyFmUrfbQoYsekRjWsql93EB6uB5Njy
         FQ5aJTz5ancy8HnZMAi4TgaqxlyabEyHo9BTK0YnmD6fhm7cNSlYfikn1NSH0VEDHw6S
         s7TC0VgPVYYxtnNH6UGE6IHtj9+CuVcre0qNJzTKfzLgSGd2JIoRs6s+XdgcjXwGcQk8
         VFF5s/QdDd0H7V3pZZPEYfffVrEXG9IkCKcoYhYj8nHS09GAt7mJc/qC8xhbqkDVDva5
         G/dyoqVP16hj76vSnwcGZ7aeGL9v65A8ZstZCY+iTQvilgyLlLRtzMJs8TM8+NxaZnUW
         NTpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Td28JrBePAudjiQ7ndTJcmkdu3+oI4xsIlcw5TCFLMI=;
        b=BpsERS2J6TbKre6WCxonBXVPYMvDW5DC+wEFgvhfcnnsCBZMc2jIZ137Ps0gwbQkWv
         eso1RBZY6Cbxtlb5j292UPmhWHHcdJtqembKPwBEBoIkOt7AXw8O/qfyBXimTvl3G2G1
         vZAINtXfTtZEzKEl+pEbKyOo0vLVsBCRPPgQNu8pV8mbiExlhDQMGlwQ+xvTzWiMS7W5
         xgPFaV9KRWV5CCMu+ZfddfIn9EPKWCKONu3XRt3WVjl/OTQV8O7oWefGHifsljtGVP/n
         B4IyYBAvUdo9tqiKvAFqSX5G5E7Rvd8+z7GZuWjfEBsNJJ+ER2YNDAlwdsFTE5XEVqaY
         D/nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QvKH9jeO;
       spf=pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x14si10452pgx.2.2021.01.25.03.28.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 25 Jan 2021 03:28:39 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 7DFE9222F9;
	Mon, 25 Jan 2021 11:28:36 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	Andrey Konovalov <andreyknvl@google.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Walter Wu <walter-zh.wu@mediatek.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH] kasan: export kasan_poison
Date: Mon, 25 Jan 2021 12:28:13 +0100
Message-Id: <20210125112831.2156212-1-arnd@kernel.org>
X-Mailer: git-send-email 2.29.2
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QvKH9jeO;       spf=pass
 (google.com: domain of arnd@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

The unit test module fails to build after adding a reference
to kasan_poison:

ERROR: modpost: "kasan_poison" [lib/test_kasan.ko] undefined!

Export this symbol to make it available to loadable modules.

Fixes: b9b322c2bba9 ("kasan: add match-all tag tests")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 mm/kasan/shadow.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index de6b3f074742..32e7a5c148e6 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -94,6 +94,7 @@ void kasan_poison(const void *address, size_t size, u8 value)
 
 	__memset(shadow_start, value, shadow_end - shadow_start);
 }
+EXPORT_SYMBOL_GPL(kasan_poison);
 
 void kasan_unpoison(const void *address, size_t size)
 {
-- 
2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210125112831.2156212-1-arnd%40kernel.org.
