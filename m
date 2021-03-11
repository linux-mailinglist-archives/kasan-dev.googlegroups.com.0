Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKM3VKBAMGQEL54UQDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 591C8337FB7
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:45 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id n16sf9062968wro.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498665; cv=pass;
        d=google.com; s=arc-20160816;
        b=DeOm+GVzznorVSzCDnv/eLpbMACizakrYA+hsrOpzGOsouuyBXsGqyJh4/6d9PjON+
         U/rhZ99fVGiT1Z/cTIVCxlJJnsL3P6LlntBd2NjoO7+cKcf52bq4oVuAqLaFqD14zmNr
         znCigN0LWXXTxQ6+4tkLO8Lppwf7D4lUv42JJg8tzKskJjdUJ7NPKzuEFGJ/JDVwM1hT
         oyItzM54OhV7cZMmOWwzhC1Qg3vHOBuQ4nvUfv/JGtgKAv1jOzXrEgvxw4740Lz12MDL
         oRA6mjton1ZGKdbnz8sGm5hJZnxz955ngTbtJ84QLqudNShhrbi6f9CQxKEXoc6M7l2P
         iMFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ks0wJpZiWGfVTVQPwxLKYxxErGOeUY6GaOvf2qgvFzk=;
        b=KfSG5AN3lxo7dopsPZdbO757YKSPs7+MiEj7hWdbWSjWNEdiTYX5XzFGTV0ZHiF0PR
         L0X3GssludNwamznAn2VSJRkQKyfg3PIdr4tIkK8orDd0XJF6J/DgUEo61HNmjVzaTwx
         9bLGOXjxfgF0q4kFhxQxHkKA0ogENIsqAfp/ba6WtPd1vfVJjcjFy+zNNpTY/+L+686F
         EJ8IKkAS+c8T4i3saAsGJaTNlRjJyS+uYSOCh7d6L4VVLs3ugb8t+jxsRbckhR4zCCPm
         5hVaLkuz8Tzh1uCPV/pq9xiCOvLN2viAlAcnrYOuOfa7UIBvWt9qB+ZqeltE/kKKyvsJ
         SUDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Plz1xq3S;
       spf=pass (google.com: domain of 3qi1kyaokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qI1KYAoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ks0wJpZiWGfVTVQPwxLKYxxErGOeUY6GaOvf2qgvFzk=;
        b=cHM6Glqk7bOasw1juHVKIky8XU76aRwpOjRUD0mCKJ721hutWqCuMoH0Qb/dPg3B+Y
         Xi5WNfj/RCOhZl5F8Fu1pg8a8vGiKQyVQnDMaoNs5JP+OC0jC0EeKOSy2706LlSii+HP
         A8TyrlANYe0Z2qCl9bbYAY/t82xNczjPu+0Obx+AW7ua/vYC7v7fbUIS/E3BPFi4Eyaj
         GuPGgkLN4X5T1T1FRmsUuk7G65LcC4nZM4iACx8DxJYWghz1QjlD03q17821kOw/sqR2
         d/B+R6YbgR4berEberOLzjGJ3YhNKc7kRQKaKWr37+lHsfNknsfefHfclhuIBs6kqYlZ
         ig0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ks0wJpZiWGfVTVQPwxLKYxxErGOeUY6GaOvf2qgvFzk=;
        b=DKVxW71mc+O1FXIcAmlPJNVjZ1rXf24zarDOTiCFyATHKCRjuZLQZXi2QYBSfq0ADA
         daUm8+WaK+ItHHF5vRsdP3/Ge11s5euVihhw0mzhwGJpJykE+suJt283xTQHqRahL1GH
         xsWv1WgyxF/HXC/qaNkt7jRoMOZmDVeCa4494zzjFM/V0HxUJfTl9ZntCCqDCJHgRadN
         zfM06uhWwUIr9v513CdqZUNGGb0+YfCoJffTp8hHnIJ+f8mjR3rHRjrwyTZ1yXxKOX7/
         KM9XkjxqRS7S9davEB/chxVHHRxZ1mCcHnracR3TFAFNabpZg+cT+80tERs2JuGvDqPF
         uD5g==
X-Gm-Message-State: AOAM531y7Ib4WxKYxekvyO9AVohxqZxHBIdms0jkD4cuVtIvWAmU5P8x
	G8s6K5JnKaamjOIsZ5U1t8c=
X-Google-Smtp-Source: ABdhPJyXJeYCNVo1H5caDI6fWHg9KbMKJyvURlPhRb4ZDwv+9n5rBScJWJ20wplZW+ggj6kAFzbX3Q==
X-Received: by 2002:a1c:498b:: with SMTP id w133mr10405695wma.134.1615498665158;
        Thu, 11 Mar 2021 13:37:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1981:: with SMTP id 123ls3504345wmz.3.gmail; Thu, 11 Mar
 2021 13:37:44 -0800 (PST)
X-Received: by 2002:a7b:c04c:: with SMTP id u12mr10206580wmc.9.1615498664352;
        Thu, 11 Mar 2021 13:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498664; cv=none;
        d=google.com; s=arc-20160816;
        b=EPv9c4WkZOu+tntG1I3M+WYf68CEBxlvRzFpG13Z3O5G8Ur2qciO/WjPBYf3fS5Uj9
         3+iC48oFiktUzK2ePYuztX2yOhhoevIP6CJilUE+ON+WLrbRQ3pcuI97uNl1Wm3OLUih
         dhFZRjvm7Mylg2o7lCZPHj0Au3/GEWZyBmbwPgLvUYB9Kh+HCj6nkcs+fk8dmS+pMtKh
         MNSbjRy8FV6GxoyHJfQRMuCTa5pWkvQQrlxfMRim7i/BqT/nXfINDQWQgCmqXzOeiC0t
         lXL8PQVrkdCxCfAAG9cd3EcSJblwD/xDs7etW1Jp+3bnshFBwA60RoT7ABAcGV7brvLf
         VPSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=jCUwUXSRYRP2LJ367pVG9mu783jEZOVPApZYYYorTcY=;
        b=veAHpAgJDeY1ogSBrCneLz4dOdhTe7pgmXESYn7G+BpcYwCjz9u8Be1XguwZWrM62V
         N/eAo1U7opTn5eWPCng228ZraJ+7R+WBAWN37If3OjSiK50TMrunH3CO7t7LzmgkSMa8
         jaD1u4EgpdjLryhztgNPWgwVMKaGyJqfzwrEuvxnV7pvPmtCHITUN6SGjEdJu4oQSaKx
         lqQQiBZAl7RTEP4fVHw6PyuXAnLm1fwYSAyCK49FgNmnk+xulmLvBjYtOxEhrdjTk5w8
         adCSj2+QHmS3qL8Id8SzKIyio1Ma3Qd9llpzceDr7UHiMDJcfKmO6pGcFdups9nlih8V
         nv0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Plz1xq3S;
       spf=pass (google.com: domain of 3qi1kyaokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qI1KYAoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p65si497062wmp.0.2021.03.11.13.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qi1kyaokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x9so10044995wro.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:44 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c0c4:: with SMTP id
 s4mr10327657wmh.9.1615498664022; Thu, 11 Mar 2021 13:37:44 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:20 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <318ca25e3e3d32482c0155b662ce4057e436f9cd.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 08/11] kasan: docs: update HW_TAGS implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Plz1xq3S;       spf=pass
 (google.com: domain of 3qi1kyaokcfuxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qI1KYAoKCfUXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Implementation details" section for HW_TAGS KASAN:

- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 26 +++++++++++++-------------
 1 file changed, 13 insertions(+), 13 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index dff18e180120..f5c746a475c1 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -270,35 +270,35 @@ memory.
 Hardware tag-based KASAN
 ~~~~~~~~~~~~~~~~~~~~~~~~
 
-Hardware tag-based KASAN is similar to the software mode in concept, but uses
+Hardware tag-based KASAN is similar to the software mode in concept but uses
 hardware memory tagging support instead of compiler instrumentation and
 shadow memory.
 
 Hardware tag-based KASAN is currently only implemented for arm64 architecture
 and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
-Instruction Set Architecture, and Top Byte Ignore (TBI).
+Instruction Set Architecture and Top Byte Ignore (TBI).
 
 Special arm64 instructions are used to assign memory tags for each allocation.
 Same tags are assigned to pointers to those allocations. On every memory
-access, hardware makes sure that tag of the memory that is being accessed is
-equal to tag of the pointer that is used to access this memory. In case of a
-tag mismatch a fault is generated and a report is printed.
+access, hardware makes sure that the tag of the memory that is being accessed is
+equal to the tag of the pointer that is used to access this memory. In case of a
+tag mismatch, a fault is generated, and a report is printed.
 
 Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
-pointers with 0xFF pointer tag aren't checked). The value 0xFE is currently
+pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
 reserved to tag freed memory regions.
 
-Hardware tag-based KASAN currently only supports tagging of
-kmem_cache_alloc/kmalloc and page_alloc memory.
+Hardware tag-based KASAN currently only supports tagging of slab and page_alloc
+memory.
 
-If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
-won't be enabled. In this case all boot parameters are ignored.
+If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
+will not be enabled. In this case, all KASAN boot parameters are ignored.
 
-Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
-enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
+Note that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
+enabled. Even when ``kasan.mode=off`` is provided or when the hardware does not
 support MTE (but supports TBI).
 
-Hardware tag-based KASAN only reports the first found bug. After that MTE tag
+Hardware tag-based KASAN only reports the first found bug. After that, MTE tag
 checking gets disabled.
 
 Shadow memory
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/318ca25e3e3d32482c0155b662ce4057e436f9cd.1615498565.git.andreyknvl%40google.com.
