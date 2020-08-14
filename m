Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOUT3P4QKGQEDRNNXSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 514B8244DD6
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:27 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id a19sf1759553vsr.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426106; cv=pass;
        d=google.com; s=arc-20160816;
        b=EHnihsmebfXUMBb4qV2f+zq49r16JemX49iYWzWhpMvN1tfH2dqkooLFIF08mBrqkv
         fUM+Jmnpy7RCNINS9qmyVmqBATOeBHUmtmKi7WfWg/2V489ABqAqUHq/XOz0/2J+hs1t
         JDjM8etIetdSa5yxCangbj/EfsBPYPu5Dhn+mtm7RMw9GTs97KctTgUAFb/+SrDVo6OA
         btwTlHCKWC98wg32zIj8if0s7WW4Ks415MRcPVwjUkuKFNi9c1/HCmH8AAh3eOzGixYj
         vHLX6feFLDyVL5BnKVBQbyEu4FHTd0Gx880u5aYE/OhpEopBPxiMaDeq6UDmIGCThhiV
         3sAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=gZUyGarwDQV/bFU0qs54OhufsKpZiexT9WybNVpCZdk=;
        b=lhNTGpLeed9fJra4n5KyhaMEw7NbkwfvXjATruFpyjhIAweuIfBnLdYETee8dqhW0F
         QDPR1/gKREulJYd51QT0/NbmrZ3FQ/uD5BEV9C9a5eIRjomTUnEZhiYgvoLy5/aJ07Oc
         ydmuilwj9azdHr+j0sloVevYmJy+5V7zkvrU7ULJomwDq1qzYEPY83J6JTNt+DObpJNm
         qpIoOPPKzQsfuVRfAeB9mt+gYmhxUr795BB8V8IGUfte5u8Vy4M9SXLmL0IOH28nEBu/
         z3Cyfdh+WbZ3vpALP3rJJcuw6RRppeWo8IpbvMG5Tl1um8dqP0nRlspxYIFQBgjaNPYf
         nLRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RoM8+KMI;
       spf=pass (google.com: domain of 3uck2xwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3uck2XwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gZUyGarwDQV/bFU0qs54OhufsKpZiexT9WybNVpCZdk=;
        b=gpRG6YXT2++3WVyvZuf147VJRMIzIbQmqEdvuoxpqUbo195C3d78Zg3JOjGKrmBySG
         oBLBDwhZWwnRDexJ74b7dx9EUcYHdUtsCvuriE8ctlvlafjv66qgedioREUmAvGj2pm4
         w7J0dOFFsEtLOLM7f3DMiD3eW2Tev1sFo/0MbfaPmFSwtOH2gAl7WEHDu4Bevrlv4zo7
         d/3Mto40Geqs6omMaSnx6AVn8LADME4AtdY2+X3adcP4232Bjm9Jbhc2cSOf8iM02DD/
         yh0/kTOtdgE4UqQM0zFspPGXcfeZRI/2v3ku61enzOE5NopGDpwzVby2QEPtp0yzajNP
         0eMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gZUyGarwDQV/bFU0qs54OhufsKpZiexT9WybNVpCZdk=;
        b=g3/sUsBc9Oiy8TE1TyGigq4/G861PetZMk7H3Cf08okoeQwf1r/7QZyiyvRYDjaESI
         WvO/eIh+HIaf6gaFK9V1LLSV16/8180U+21Ao/UDQNJ/18DJu+3Q6UV7mW4c1jW546xn
         /fJz6X0oYgCPIa9wdaFxna+85iM7MhneL4sZWbfdES6c3mDxvO6kDUJvjBd/RjeHGZ9/
         l/3D5Io4nyYzvRRU2OR6alS7jrk+ZucwCInKv0ewFUcqj0icUK9j4Ia4K5KHRLruzQoW
         I4ysuAkI1sm3KFAOTfQQtngRRc5vx5w6tKp8BB9X+EFW57PunZYvu8AsaEthR5Y6kO6N
         WTWA==
X-Gm-Message-State: AOAM532MdJgjI/K/TyV06w7y8SJamk222mF38SBZ6iOaXT3PLWP6HrQW
	c67l7SMQg1+VVL6sMTofKNY=
X-Google-Smtp-Source: ABdhPJwqvwjkCpEFIaZ+tHHlvJh19MaRmr5kgLToyahYUTU3MOGzMIIJ/RFS85IZDs7kJLp90n4+6A==
X-Received: by 2002:ab0:65c3:: with SMTP id n3mr2218920uaq.100.1597426106319;
        Fri, 14 Aug 2020 10:28:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3cc:: with SMTP id n12ls1175412vsq.8.gmail; Fri, 14
 Aug 2020 10:28:26 -0700 (PDT)
X-Received: by 2002:a67:2f0d:: with SMTP id v13mr2223364vsv.30.1597426105888;
        Fri, 14 Aug 2020 10:28:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426105; cv=none;
        d=google.com; s=arc-20160816;
        b=Ghx1nLeXNAO7v8Gqw/BxMu7igOuLNgxOEcHjZG8dbd8wDrfZLnwIS1AJmP27qsOpN9
         50OHN5vMGHOfSPr5mGV5iDouohn7vGkUUzELIETBjCnH5LG0EXx0q3bw62rgj6kAK3xN
         v185iGb2NYUfJJjcemq7ApkO9PTbMzrI1wl+nMnZNSYq0CMBqVTdsmzwszf5COuFbASX
         XF06iwY/OHR5LgGpVlWIalZmCNTyES4VkU8oC+dfrqxTGAxx/7bseDgpdHzntZeBzNVJ
         nZSQGgLHiw5afmqqD21kHfNQ0yiBqIBFmkzXbky0rb5nBLh+SUkm08mOe1XsuxtIZjaB
         sCyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PrZ8Xx7ZOES69PjxJ7W+uco2MTpU8K38pV5r5s6HLuc=;
        b=O+2N0QvIpDdHsPjoAxhVzoIkNZ8fxnzGfSE/t/tI4DG4CY8H7Yo2zJdcUzZVLdfYqn
         JZZPdTUmcH8Td9zh10NR7u5uXrtzM6Q57IvdeqMXdspzvkUfB/61VgDi0vE837T6jwfl
         rPrr6zUe2ws18AmcEI2oU2gyrRd/WoGVwGOZsqoQt5b1RncU44aOrJyI9TVvpwR5izQW
         rkwb7GnzJNzK0FtgNo23rg/3A+hnpIIGyJaU8SHwBWjJ1my8X/eZLBd6UygjL/r3O1tt
         dlW9jsiNYFsCF9fM+3RWrk1gZo/o9sz2jH+XDpkjRKFEuhaujyKRXBMhoi6UIhHbPA0z
         P2dw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RoM8+KMI;
       spf=pass (google.com: domain of 3uck2xwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3uck2XwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id k201si534705vka.4.2020.08.14.10.28.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uck2xwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id g10so7459964qtr.19
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:25 -0700 (PDT)
X-Received: by 2002:a0c:99c8:: with SMTP id y8mr3624054qve.57.1597426105434;
 Fri, 14 Aug 2020 10:28:25 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:08 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 26/35] kasan, arm64: Enable TBI EL1
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RoM8+KMI;       spf=pass
 (google.com: domain of 3uck2xwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3uck2XwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

Hardware tag-based KASAN relies on Memory Tagging Extension (MTE) that is
built on top of the Top Byte Ignore (TBI) feature.

Enable in-kernel TBI when CONFIG_KASAN_HW_TAGS is turned on by enabling
the TCR_TBI1 bit in proc.S.

Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/mm/proc.S | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
index 152d74f2cc9c..6880ddaa5144 100644
--- a/arch/arm64/mm/proc.S
+++ b/arch/arm64/mm/proc.S
@@ -38,7 +38,7 @@
 /* PTWs cacheable, inner/outer WBWA */
 #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
 
-#ifdef CONFIG_KASAN_SW_TAGS
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 #define TCR_KASAN_FLAGS TCR_TBI1
 #else
 #define TCR_KASAN_FLAGS 0
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/518da1e5169a4e343caa3c37feed5ad551b77a34.1597425745.git.andreyknvl%40google.com.
