Return-Path: <kasan-dev+bncBCCJX7VWUANBBEE2Y77QKGQEZBEFYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A56C2E8C63
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Jan 2021 14:56:33 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id h206sf10138484iof.18
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jan 2021 05:56:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609682192; cv=pass;
        d=google.com; s=arc-20160816;
        b=nlHraLgTCJQa/hwS58wEmoZkJ6NArHVQhsakUrOY/LojBJ1Q1l83bfO0scExgSvl40
         yL9TUozkGmjsugZx8jE5CduCMzm49TrsRJ1HSCG7Z4c+YfNaxeiQYIzP5Le5uHemQKFi
         jhWWvnKwE6fqZEvANlkvnu61tKsuiVufiWKsDkDuCulQNtvp3xYnXrgRm2sSQfrX4ZJh
         SAgpI2swzP9N862wMRdqIh7W9K4/Yr7L9xHABlVHJVxoN6MAzwQWxQHLkbHDhOvG0sIP
         Q/CN5GUwWV+Rc201mVNMEy56PiPfkrQt7mqHSviGP/E6+/4bavtrn0jyS+sm/GoS9cCC
         BIZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature:dkim-signature;
        bh=AAxBJTqOZt7xOnwiB8WcwKipJZpoJ43jgfauDr8Gq/o=;
        b=NskqKDWmYIxKdywf3lspKjh+k3yfss0/Iw9lr4IGvvuevbM3BDWX8y6e2ZRre+mOtm
         vYXY9wxx8RLV+EoROhHUOwMuIkzcHjscSFEOWstJShkER6/uq30ywinNmYLRyR3rrcrg
         T7aY9VaLL/t1RxPVPQklCU66DHZV8MVGtFNw75LNHMSlWbwXM9Tsw8hE9eo4i3KWaUvP
         e6qu+g8Trzs0nddY0biJUULjn0z/CpTVFcfahAWuzEAxb36de8B2kXHjrdgD1eUGPnZT
         qK7yPbc5//dbhKEr0rpBhGuWYfP7T2N/0+ahECQ1XRvqA0beUOzvYxELsmKitGhzYs66
         uAmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nGjvjcmd;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AAxBJTqOZt7xOnwiB8WcwKipJZpoJ43jgfauDr8Gq/o=;
        b=cW9bci90iC9s5/+DVnY2zsYdUqtdjIynTOThkdrD8Lv59lClUfy9dQhdWOmqmkK02A
         uJLSMN3qBz9KndC3fig0I49FyUL6JYV74x9QbVIODzioZIhGWRiJSJgWxzka1Ybz2uBP
         tmzMqlFzs85Cl5nPfpFZOHzzxV9h55lepZSVZtWXNv3XpWZADMVYqSugYu4ly9nvPPxn
         8Gmt+thc+7es79hL6nDRUnTuip1khupyrXOexgWOkqHFboF8tZQQlrM6xFfbbJFU/TNi
         t/klfwvB0tpvSwLJxYtmHqyqD/kADI+Usuca3kiZ8hx3qMlYIjhJkJ8AUxXIscfh7hWM
         b6Fg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AAxBJTqOZt7xOnwiB8WcwKipJZpoJ43jgfauDr8Gq/o=;
        b=TCBhaDHkqCJL/fgC2MQUYkW7nJUJtfpQ6/uhKOMKcA0T9BFqd0HFQfZzkPe+VKiotf
         7XmKJT9JWf8fvRwY4XftuAsD3N68HS+gxsGRam8Wrj+cfaMfmNktOkxHYGhe5mbYAAXY
         F4YXcdyLx8yc7bWA6GhONu7v5B8WFqrmJHvweS/OAtgjIV2nBMKWyGg4gHslXSOpOuE/
         zvbvkGcQu495Zveq6cBjPibMxInApm/7Fnoiw9qNP1v9KbULg9kFFiKPNs9gteh4ZrOg
         MXTuZB0S0OGKbTa5khxoHx5Mq1CUP4uwqQmkxJyL5/23YWzRlcPE0FJdFxfN1LeE3b/4
         FJiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AAxBJTqOZt7xOnwiB8WcwKipJZpoJ43jgfauDr8Gq/o=;
        b=CjQDYtlNDtWfIoIYAJja3NJfI9DSm/IUSMnT8S/92iQrW5cX3BNYDGKTYhJuEn7/sv
         Kyd4BUZtCtpwu3TFRlv7hqqTGKYmH2CknJNmXA14shdqpkCUZv23qAsyVDE7xCjgviZh
         B/cBEgok4ccgpiEpcMqugCLOOIRN/fgFtoTYWSIsFqgwGf87fBU+1QUw95gc8Jb1ClpM
         y2JhlPmFqykah74hUE6XSeJpXPtqfsVV6ESJjDgJrSzbExQiViSHCiDDjZbdTqnUmpvI
         bJyWQBJUDzwgyqhP37RaqwQureJiJSeLIpeYwkUCZb2yZxqqOkzQcIYB6myaKAqpSVSe
         gfFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dJpb9fiY3u46lStznanX35lvKs0mixAkQplDPaChnph/q9ahJ
	9dtodPw1FAQw6FvF77jvpBU=
X-Google-Smtp-Source: ABdhPJzA+TLl9ldClswe+B0xlCslJQpR89H0xcphibYdTEYvpf51seFzTrQRBB4yYy5GHWKCD5rUHA==
X-Received: by 2002:a92:c986:: with SMTP id y6mr43601680iln.57.1609682192345;
        Sun, 03 Jan 2021 05:56:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:2681:: with SMTP id o1ls8376630jat.3.gmail; Sun, 03
 Jan 2021 05:56:32 -0800 (PST)
X-Received: by 2002:a05:6638:2:: with SMTP id z2mr58599611jao.2.1609682192042;
        Sun, 03 Jan 2021 05:56:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609682192; cv=none;
        d=google.com; s=arc-20160816;
        b=hYh0SkRovEDwrxTO+EeLtEARq1bIdk9L2fXv9Uo9rwtngsZCInjMJJ/EwhOGgT5CXM
         JZ2wqo4GWGjhK9kC1YqZD6PsqigKK1MuO1vEd0AZU99ql95VbACU9E+oWAr+R2QmL/0y
         6EkWNbStWfmbEXBsdFbftcVnShl6orxm8ujosW4EkVAcRdAnc6d67tz/RtLeZgylCFse
         0UL7XTs6wjO5z7yR6X////nTxwf/z6BK1WeqW8ORTOanU2iRTkudhy9rs/+peqNKNY+q
         L9OWpqXy9rB1iw9yZfHJTi+WGihIofaaWCIhygaD1efYykRTqKdK13K+XAINpVbtvoJy
         eNuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OkmIEGZrUYxTikbU8Yd5Ez0Y/58b3wmDmzrHUQ/JMJM=;
        b=cAPQbvpOAhPrBz/59WGzMB1ls4G0iZscZfSG0mTslhvUqFrJ9lResWQ8PzeUHJmBjE
         bj64s071fr1rXNZW2B2Qsainu9ifN/PlcgyE6Oj1fWyLkF9AjgTXoIQocumKFPpFikJ5
         33gzvfn3uOkimC2zEH/vi+WmKpxaEeXQtCffSLsqsvaZubiesGrstks+a/ESkL+mPEB3
         rWuDQdQ+SkyA/d3q1SkrG/1i74wcdyXppiFoPrmvgzdYImaGQJMrlhC19UZ7U8thamlw
         WpS0OHA3/VVOLR8DR7NAPY/aFto/vBNn6WslxLWQ7RUacdJ1A8WDqSqVQwMpyjQqPclL
         XR2w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=nGjvjcmd;
       spf=pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id q4si3769076iog.3.2021.01.03.05.56.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Jan 2021 05:56:32 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id c132so5728662pga.3
        for <kasan-dev@googlegroups.com>; Sun, 03 Jan 2021 05:56:32 -0800 (PST)
X-Received: by 2002:a62:ea17:0:b029:1ad:4788:7815 with SMTP id t23-20020a62ea170000b02901ad47887815mr55124711pfh.1.1609682191812;
        Sun, 03 Jan 2021 05:56:31 -0800 (PST)
Received: from localhost.localdomain (61-230-37-4.dynamic-ip.hinet.net. [61.230.37.4])
        by smtp.gmail.com with ESMTPSA id u12sm25928427pgi.91.2021.01.03.05.56.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 03 Jan 2021 05:56:31 -0800 (PST)
From: Lecopzer Chen <lecopzer@gmail.com>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com
Cc: dan.j.williams@intel.com,
	aryabinin@virtuozzo.com,
	glider@google.com,
	dvyukov@google.com,
	akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org,
	yj.chiang@mediatek.com,
	Lecopzer Chen <lecopzer@gmail.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH] kasan: fix unaligned address is unhandled in kasan_remove_zero_shadow
Date: Sun,  3 Jan 2021 21:56:21 +0800
Message-Id: <20210103135621.83129-1-lecopzer@gmail.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: lecopzer@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=nGjvjcmd;       spf=pass
 (google.com: domain of lecopzer@gmail.com designates 2607:f8b0:4864:20::536
 as permitted sender) smtp.mailfrom=lecopzer@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

During testing kasan_populate_early_shadow and kasan_remove_zero_shadow,
if the shadow start and end address in kasan_remove_zero_shadow() is
not aligned to PMD_SIZE, the remain unaligned PTE won't be removed.

In the test case for kasan_remove_zero_shadow():
    shadow_start: 0xffffffb802000000, shadow end: 0xffffffbfbe000000
    3-level page table:
      PUD_SIZE: 0x40000000 PMD_SIZE: 0x200000 PAGE_SIZE: 4K
0xffffffbf80000000 ~ 0xffffffbfbdf80000 will not be removed because
in kasan_remove_pud_table(), kasan_pmd_table(*pud) is true but the
next address is 0xffffffbfbdf80000 which is not aligned to PUD_SIZE.

In the correct condition, this should fallback to the next level
kasan_remove_pmd_table() but the condition flow always continue to skip
the unaligned part.

Fix by correcting the condition when next and addr are neither aligned.

Fixes: 0207df4fa1a86 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 mm/kasan/init.c | 20 ++++++++++++--------
 1 file changed, 12 insertions(+), 8 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 67051cfae41c..ae9158f7501f 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -372,9 +372,10 @@ static void kasan_remove_pmd_table(pmd_t *pmd, unsigned long addr,
 
 		if (kasan_pte_table(*pmd)) {
 			if (IS_ALIGNED(addr, PMD_SIZE) &&
-			    IS_ALIGNED(next, PMD_SIZE))
+			    IS_ALIGNED(next, PMD_SIZE)) {
 				pmd_clear(pmd);
-			continue;
+				continue;
+			}
 		}
 		pte = pte_offset_kernel(pmd, addr);
 		kasan_remove_pte_table(pte, addr, next);
@@ -397,9 +398,10 @@ static void kasan_remove_pud_table(pud_t *pud, unsigned long addr,
 
 		if (kasan_pmd_table(*pud)) {
 			if (IS_ALIGNED(addr, PUD_SIZE) &&
-			    IS_ALIGNED(next, PUD_SIZE))
+			    IS_ALIGNED(next, PUD_SIZE)) {
 				pud_clear(pud);
-			continue;
+				continue;
+			}
 		}
 		pmd = pmd_offset(pud, addr);
 		pmd_base = pmd_offset(pud, 0);
@@ -423,9 +425,10 @@ static void kasan_remove_p4d_table(p4d_t *p4d, unsigned long addr,
 
 		if (kasan_pud_table(*p4d)) {
 			if (IS_ALIGNED(addr, P4D_SIZE) &&
-			    IS_ALIGNED(next, P4D_SIZE))
+			    IS_ALIGNED(next, P4D_SIZE)) {
 				p4d_clear(p4d);
-			continue;
+				continue;
+			}
 		}
 		pud = pud_offset(p4d, addr);
 		kasan_remove_pud_table(pud, addr, next);
@@ -456,9 +459,10 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
 
 		if (kasan_p4d_table(*pgd)) {
 			if (IS_ALIGNED(addr, PGDIR_SIZE) &&
-			    IS_ALIGNED(next, PGDIR_SIZE))
+			    IS_ALIGNED(next, PGDIR_SIZE)) {
 				pgd_clear(pgd);
-			continue;
+				continue;
+			}
 		}
 
 		p4d = p4d_offset(pgd, addr);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210103135621.83129-1-lecopzer%40gmail.com.
