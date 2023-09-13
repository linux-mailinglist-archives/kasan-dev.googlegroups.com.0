Return-Path: <kasan-dev+bncBAABBTW5Q6UAMGQEPVDZT6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id A4F0979F045
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:18:07 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-402d1892cecsf482485e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:18:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625487; cv=pass;
        d=google.com; s=arc-20160816;
        b=RiRqa1Av4V9S/YP1Ya1mfEIqRaPbwISo71LDQI0qDswIw7tO7fQXDeiDaoyEq8h/z6
         fKmNeH3fgPiywJtKMuj/qyXVwUQY6T3OsG1W6/adRf7WQB1FnWNjBI2VmZQA03Y2kNas
         DohgWKPD8xNX2m1TKarRIjV6igZB/zpe/VRluqr8mQHR2ab57x0wY20+kZDEV84lyhPl
         x0NWPV2Te0xd94Pmj0GZcs9VFrsYbWjCoCtVV2KFirfJBo5WGAb1E1323Ac0FeGxNkK1
         bfcCWXyuOL7hWK+jVqAgC8ItOhmp1OI+woIsVXr67uCUq/gyZa7aN5uJJCP3J5ptEdJJ
         4zyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Gym8MEpT+/biIauBMPZDBurm/8XAj1RiA9hEhfEEP34=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=N+Qf/mlJXXsDKXz3w5/mwybGu9XkVVhtgnR+6fzDzw/iS/IKeb8842Lx6tZI2xNQEC
         TWn6a8hBfBamD/Qc/RG9DOCJzNTqeAL+BnZvCKMKJAcgBlOYCVR3iNseenv/JrkjVlkj
         lPgsXygOL3TcQuLic0JVkiZWYKcGz8TNSP1QjgUfrSzTGpse0E5YKK0NtdqUrxOWVCL8
         ce3req+MGH1lO7/9gFEjfkr8ZM9BPMsj2aF7BBkKmQ/qgtXsLzb+dLXJ/Iwex2PtzuPr
         7kVKFu1voTGkRkVHhqHCraRcelY5I2Xuc/F7vrcP/s3QEYt1KTMXQLmVB9mcHodXvWhR
         Xuog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kykiqu4a;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625487; x=1695230287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Gym8MEpT+/biIauBMPZDBurm/8XAj1RiA9hEhfEEP34=;
        b=enauMAqO+hk0pBvFWCFye+wOvtkyMOGEjBgQyMvMVl+r7D2/GFZNt22d8B0Bspq/sZ
         jNNAYHSLwr27sW31FauRPKHviwY5C7d4ludfOrW/Mnd6qa0U932IrojPUZlfoHykxT/g
         wcwYjXurUgITS1cOkbYqPDhJtOtVDAY3d00g33kTs51wxAptmBWp2GjbSJH8JSFMrByE
         UHaoLKESysBhDAohvhNHvUw5MKbaw9VQBbiwDD6Uru4nYmxhE8kLJ1tW79rRguPcauk1
         ZJn0jVkfdmsY5QscIsiOg19oqpafCsw6i7PjxcUVqVm+bZML6BIuTUZszQLjHb9/m0NM
         /LLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625487; x=1695230287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Gym8MEpT+/biIauBMPZDBurm/8XAj1RiA9hEhfEEP34=;
        b=W+tHuzTDDBvZso4H6TZwAZFpJGuarIY4PsS+P+pcMVNNBaVe6Z8lTZO7qfAQjnrvLB
         8CuIZ3Gia+Qc2KnzY5HPKsuQGpwB+Dhn+3loyG3tZ4/UP/Q0+zPGBfdbwapzGALW2UBV
         a0X+4Pbpd+/LRtNnD3sVh3j/lGS1Norrp6G/gcdmvlDNqRWkzIW5UwFy4hw4iOEc9Kz4
         WMqGN+mOv0BvmY9G23n+hb+8d5kFvhet4Eh7kIYkBk9IA9gpWBV91D267ieTlA8lYZKf
         V04DYJP4of0CL9VNLoIP6lb8aSPUJMhFh/0Kf20zofwUsKZdtX2H7a/64X/7WiXBcgpd
         BSdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyK7Gof7sqKaG3bsr8gARTrRXHGDffCfBE1T+QuekjLuoMaZ3eF
	yLNW87yBxahxNUEM9T3CaJE=
X-Google-Smtp-Source: AGHT+IFGrI3QtDSgYtzu9/wFcQoG1MCq9HUZj6kaCZcZoc90gtrPuTr6bpeexRIiPccDCDCEkd4zVw==
X-Received: by 2002:a05:600c:282:b0:3fb:c075:b308 with SMTP id 2-20020a05600c028200b003fbc075b308mr2722786wmk.12.1694625486373;
        Wed, 13 Sep 2023 10:18:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:624b:0:b0:319:7897:a9df with SMTP id m11-20020a5d624b000000b003197897a9dfls1025706wrv.0.-pod-prod-00-eu;
 Wed, 13 Sep 2023 10:18:05 -0700 (PDT)
X-Received: by 2002:a05:6000:11c9:b0:31f:afeb:4e7d with SMTP id i9-20020a05600011c900b0031fafeb4e7dmr2463852wrx.18.1694625485035;
        Wed, 13 Sep 2023 10:18:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625485; cv=none;
        d=google.com; s=arc-20160816;
        b=iP7uqhfg7XWPvEpBdVrqC2/Pogn83qv9/hmc/VvsI59FSEsz6AX+tkHJApcQrrmoCR
         sI2YT5OQP20m+pNbU8gyY4Qkk5kRnJjF2Bmxyk6JzST9Y4Bjly9u3iF2sQTJ5j0L6MY9
         WPD2NQOlzDsPVEuJ+SSjLuru/UXoMrmbZg/81RAv8I5BeamXXtxZ/6n/gJ+cCAQsNMWf
         525vC7sSFjCew64Yth8jtONZb/q+RzOKlt0NM/OQTmq12lUjEwMBJctPcPAW2+9AhShL
         RCyIPOwWiwblz1pbN2iJL6YnNSRtMd8QnXaJd+ZdPYhqOSKZSyW/rNjd/fu6gyqg5Xg0
         BL9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=gGKJxtryqSg7zyzOR+J62w3w1hKrmZ/huaWffkkgHB8=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=QTQ0f7bHCwGwP58JT5vnQ94C/AUThXrBVYCMyMK7frspJW4tR7Xh4ZC2XS/yjQjDuS
         jK/RdLgkGqkfrVVW9MvrmQbV55DkIF9vmr7PnSEQRG2WZK20lKcSeS2srTROD+zHqz4e
         kIBGKtQMQ6LiWiN/ek3CH4o37AfO/6Bpr9YcDma61K1El6iVkf7ccAqcw9IwB9/OljqK
         0xmNqkItbCvxHNvwhDq42P2ist61nE2nXXavSccMZHEdQ47XJqak26rT6ojMAinusbbJ
         lJC/lWSIJatLMe1SoF3tz5G78wKQXhmBDqDHgiPnBk8z092a10TC1aAlSBDIS+la3aIV
         CfAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Kykiqu4a;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-219.mta1.migadu.com (out-219.mta1.migadu.com. [95.215.58.219])
        by gmr-mx.google.com with ESMTPS id bu29-20020a056000079d00b0031aca87d8f3si839343wrb.0.2023.09.13.10.18.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:18:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as permitted sender) client-ip=95.215.58.219;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 18/19] kasan: check object_size in kasan_complete_mode_report_info
Date: Wed, 13 Sep 2023 19:14:43 +0200
Message-Id: <293d73bcd89932bc026263d3df8ee281ad3f621f.1694625260.git.andreyknvl@google.com>
In-Reply-To: <cover.1694625260.git.andreyknvl@google.com>
References: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Kykiqu4a;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.219 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Check the object size when looking up entries in the stack ring.

If the size of the object for which a report is being printed does not
match the size of the object for which a stack trace has been saved in
the stack ring, the saved stack trace is irrelevant.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/report_tags.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/report_tags.c b/mm/kasan/report_tags.c
index 78abdcde5da9..98c238ba3545 100644
--- a/mm/kasan/report_tags.c
+++ b/mm/kasan/report_tags.c
@@ -58,7 +58,8 @@ void kasan_complete_mode_report_info(struct kasan_report_info *info)
 		entry = &stack_ring.entries[i % stack_ring.size];
 
 		if (kasan_reset_tag(entry->ptr) != info->object ||
-		    get_tag(entry->ptr) != get_tag(info->access_addr))
+		    get_tag(entry->ptr) != get_tag(info->access_addr) ||
+		    info->cache->object_size != entry->size)
 			continue;
 
 		if (entry->is_free) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/293d73bcd89932bc026263d3df8ee281ad3f621f.1694625260.git.andreyknvl%40google.com.
