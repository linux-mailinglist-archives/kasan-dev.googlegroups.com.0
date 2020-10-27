Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBEUJ4H6AKGQEV244HJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id C40D129B798
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 17:02:27 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id v186sf1047072qkb.11
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Oct 2020 09:02:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603814546; cv=pass;
        d=google.com; s=arc-20160816;
        b=pU1AzAlJ768kjGA0BnQiqJJaVuKVU+kGS5zfh/VVwoXhnkAz+QKI/JaDcX8cLbJhvL
         OZeDaxPThygzi0O+zSfWWu5ZAvv7l3VxNw7h5IdT/uXgJcHnWjMq0WvqNNh9c9ZJs6T1
         PAWPU6cn9vfVjofwtBHKcUJ7t8zuJ/0pB5rg2frXbViuWJG2KbPON95cyc6FZ4zHFmiq
         QghI7f4Cm/HxZk2FT5Gp9jbKbtx+KWMzvLt5WxEyGhxvAzCBYzc1r6bcIGlf2TjYsEl1
         NJ9LnRYL00ZyMPyqF0Jh+x+s8zq25AdWTr5YYwrW+0xU0yYywKoadqum+qTyFjDxg6vH
         EFPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=ShZStDHLVYXKFQjIOYjRk0QG72IAgLMFWHaD5YHKomA=;
        b=FfZDDL+uZVwNU9W+lkQI/vZrfuog37LeAArhNU08DbLK8FU67yD5wt/kh1eRB9xBly
         8nf/X/ct5rC/U0cuzrcMW9aUNX4OMtbbmLlApEsSh4K5WzvrmDId8/idXbo/llNkuUMW
         p49Gt3ICGdPV1nB19q0srvHgW6DYd3tpDG+KLktpsmj4GgwhgS5fMxQGXabLXiB6unWB
         8KRZxEaHwC5o9o/l2REsMWPLc1M1wXFBZCFfxc1/4hE/3DXJfI5hAjLckWxi4Z+9HNIA
         XKwIhhbu7sUJNloV2d7Bf/KZPQLxwT5TDBpUDt69tnXoR5YZOFRFgYtjy9dc5UR++FyZ
         Fe9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ShZStDHLVYXKFQjIOYjRk0QG72IAgLMFWHaD5YHKomA=;
        b=tK3dVa7OjViVyeDXUGunPvvGQGPcdSaniFihXjoy/nIb7J2SpKfTKX6zDkwIpI/H3s
         9EQl6Qnpsn5BQf764XjYqDjFCMUV+vdMiVeDjbu3H3FzKO3ytuQ9LNTpSe9sL6JRlU1x
         sgHfnzzgbRbzLTxYHMIRMRU4gp9jVa3E0MrXpg4ffX7UDgSc7L9LFenTMCDLGbkmudRS
         Jh0yzkyfL45gw8cTd0NMtHnKxByVYVKlAmg3SbnnIYLwXUqDoRTCwzABiJqysCWtLuL0
         H9EG6BVHzKwXalh2jnqTnGwXgf9GvuWcwIS8eXij0zjAIvfF1NbQNo/+jcaMg27Aa5CQ
         ktAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ShZStDHLVYXKFQjIOYjRk0QG72IAgLMFWHaD5YHKomA=;
        b=ISnCGqlJ/0JOhVpcEBAHt/VUkylX3Ur2rggsBf7emAZ+oC0C9mhCmQtBCSynjetWRL
         +fc3neHJdlDOoJSRzBr/qJEYDmZyHnKYqF/J35oPaevc4mkvVTwwWBDeaasgkcFivdf4
         svYwz7UhI9hWEkktSa/7Bk97JuoZZ/DM9LvAvmx0XunOvHMhJI6qLQ0edRyCqhhrdmol
         Pvyjut/chuD+uPnPZBuQrR4GTWDRJOxa/ZgZkKS0N4AXiM5hjiMSmPSTWzRAfHjOf6+D
         MKHLZ2+ktDGR2kBy1+GsMl7kk7Kgt54zK+NN3CpIjdDumfk8tO6qH4gJN02nfsSbITnF
         3fMw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531zEeyngx+Pkqm47pFx8J1B++4iIqzgB2ecDhi2rvd+7ka3XoIk
	jM9Galki0VY+15t07FY6Rbo=
X-Google-Smtp-Source: ABdhPJyRrLy5wepCsQkBkHxM23WBQNeOjwHJGzkElwLY0zhBpithXzSagdhZybBnv+z8Oj1OwcWwMQ==
X-Received: by 2002:ac8:7555:: with SMTP id b21mr2839322qtr.119.1603814546410;
        Tue, 27 Oct 2020 09:02:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:efcc:: with SMTP id d195ls880703qkg.10.gmail; Tue, 27
 Oct 2020 09:02:25 -0700 (PDT)
X-Received: by 2002:a05:620a:21d4:: with SMTP id h20mr2973610qka.329.1603814545692;
        Tue, 27 Oct 2020 09:02:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603814545; cv=none;
        d=google.com; s=arc-20160816;
        b=lA/NMjw2GwkyUSr1vLTLQSKUWv+sEnKfTFNO2kVKjXZTtGwRSBY1EY5uH0WBRBgSYG
         wPZq1PljgxjHZENrjFNGql9unnfYGONeGkQ4EEygj0yGZ8G/rv+7I9U/FRUFG9KOhqHL
         /dRH1ci3RKcvf6jhZp9b/o4qFH8AWtS5xaZfJ3Yxl5UhMs8Y8/clQKRUWDO/ZxYqY5lC
         HnzclpeqsVYsBXaLdVosHy3D6qHqVXKLxqlCTyaanbjR5cfzsNF3egNA1tDZ4zgTmImr
         t0a9LcJi+YWG1EYAwyfwEOf1wDPfSvQG/SsJd+DkF83zOGJtRgRLpShkq61RfjIr/lHd
         Od8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=MVJdvoEVB4mW+v1YAWCdthbOMCpD5P+p5c+Z5IlG6Ow=;
        b=ep5GediAhHLjpORPDDHfjuVfd0pixz6Om6i7Y9G6b59GUP670e3MtF+exiqrZ1pAPM
         +bSfTRwwVSvXTvr/TBQi8ZyE5jUBrgZyXinl0GBbOLO4tCINeNMK0D5wHNq9fK85RuUe
         onSHaRNK1GMmtR9KFZPPPNX8+qV70jhRzdfYd7pH+mzJlcJgyT3RmBehIgcAtZX3ESSM
         OREGoTZsiLCLURMWHcO9TbzxJqQUrdKZZ31YorVsNuXiiCb/+b5kMP6qZRqmEL7dHRqi
         SdX64M4ElV+9Kfys/DqTPBEYgtRi6N6iXJ9JplZhBzx9bxOhOy0JAcezp9LxJ0DYGx9z
         tn3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p51si159220qtc.4.2020.10.27.09.02.25
        for <kasan-dev@googlegroups.com>;
        Tue, 27 Oct 2020 09:02:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 14D75139F;
	Tue, 27 Oct 2020 09:02:25 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9DD713F719;
	Tue, 27 Oct 2020 09:02:23 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>
Subject: [PATCH] mm: vmalloc: Fix kasan shadow poisoning size
Date: Tue, 27 Oct 2020 16:02:13 +0000
Message-Id: <20201027160213.32904-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.28.0
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

The size of vm area can be affected by the presence or not of the guard
page. In particular when VM_NO_GUARD is present, the actual accessible
size has to be considered like the real size minus the guard page.

Currently kasan does not keep into account this information during the
poison operation and in particular tries to poison the guard page as
well.

This approach, even if incorrect, does not cause an issue because the
tags for the guard page are written in the shadow memory.
With the future introduction of the Tag-Based KASAN, being the guard
page inaccessible by nature, the write tag operation on this page
triggers a fault.

Fix kasan shadow poisoning size invoking get_vm_area_size() instead of
accessing directly the field in the data structure to detect the correct
value.

Fixes: d98c9e83b5e7c ("kasan: fix crashes on access to memory mapped by vm_map_ram()")
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/vmalloc.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6ae491a8b210..1b5426965e84 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2256,7 +2256,7 @@ static void __vunmap(const void *addr, int deallocate_pages)
 	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
 	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
 
-	kasan_poison_vmalloc(area->addr, area->size);
+	kasan_poison_vmalloc(area->addr, get_vm_area_size(area));
 
 	vm_remove_mappings(area, deallocate_pages);
 
-- 
2.28.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201027160213.32904-1-vincenzo.frascino%40arm.com.
