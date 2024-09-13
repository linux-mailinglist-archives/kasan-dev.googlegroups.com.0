Return-Path: <kasan-dev+bncBDGZVRMH6UCRBDHXR63QMGQEWF7Q7FQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B8B4977B70
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 10:45:02 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-7a99dbffcb5sf278114185a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Sep 2024 01:45:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726217101; cv=pass;
        d=google.com; s=arc-20240605;
        b=Y8SAv9MhNST4SgeT5yCd9d/WoXhzkEs2pzCTkqiIPYoYwNWHxWcGhYUdgEahdE+hNk
         RtQgN1tvNRbH1biyf2jw7jOaTOV24bkvN1bHAC7PXH5i6vbctlD0hLeHF74Y6aR1r+kz
         zBy+rOyLHptQF5UB9UuHr7i6mMLodR7qvd1TJFP9KAF/yE2iWf9RL3t1apzzpqVU7QNd
         Y4TPIm3CWjlV1ZbadaxlJCIE9Toj1prwzx4izluMBy1WtJk2PhuqoEuHuLtd/KNR1il6
         t2gVTAF31TctaX7zkvHNwsGNfO9XMLjwStudwb6z7NybFp+c/JEZh+HqCMc69qY00Djz
         DpqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jhE/eO4yqLjkCt6JUkTOmpYUZFZvYHzJeMG8jGBjcVc=;
        fh=corQpijd76ckGZHxqauoVnuRXPHEBXXOl9iXuTyJQUQ=;
        b=YsozDsAHKBCkK/UYuOaXAvzQW8Ym7Ci0452aqc/0ZsaaG+PX/DXgGQhNGh+LypsR/v
         zbQTrjUUWqeUyNT4ng678GNyajTEPuPndjigkiNkV7GpfZZ7hKf2N5T/4PnFT5jWTqAJ
         Fw0+vPcvH0+O5c5s4Y49LmY5dRwokfXXwve8X5/EEhixdt/dGSc5jFGaoj0/dfR7MGI8
         smnkdfqqy2sTE0O83WIYqAPOtiKsYfhtK5m2SpAOv5jpFiUN2KVDHDLvCFeStrF1Br8B
         1spVMsMUWAp5ji0MsuFV2Hqmd0oV2Fb83kxB0Fvr/1W/A7mvFuAMzFj77oeu4hha9+hr
         gMKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726217101; x=1726821901; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jhE/eO4yqLjkCt6JUkTOmpYUZFZvYHzJeMG8jGBjcVc=;
        b=ENJ6jynCvtKsAeh1a6K9k8RResjYka3JReVhO0WAUcc6AeKofRZIFozEUGBcO94JYV
         BsPdybGdhJ65S5zNvj6d7SCI7wiamC5VmAbQhD0zEjkW8upiYqZqe63Oq9hmQY0ZzXCP
         xQFjRsLlUjGQHXEzMz0tO0MJB1O2nT58jypNhsSTxQ5N5VYbzfHsAtrANiG7KfNeQddD
         ziob2tV/Q5UtRwvz3A4fbI6lJ+dA6Bc5VkSDvGZeyqsH8z9DT2PZwxCSCk/fo98wEGew
         PN34mi4EY5r4+CKRehrkmcB6aTOfAJAGSG895UUcAvjZULORc6fxTx0wKkiYWH968caL
         orag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726217101; x=1726821901;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jhE/eO4yqLjkCt6JUkTOmpYUZFZvYHzJeMG8jGBjcVc=;
        b=CjGwblCXHGaizGcZBlITBNaTWJRG2Dj4dmLwGtiEj/5fmGINTNeRg/nER3IKZJgb/I
         WtBmBXT0pFJp9J15L3/2uEUhihZ7h4CHDbHESiCUMuDUU0PFRSevSUgMrxnLA6kghfKn
         qtMXmjNimg9K7c4a0cNxX6JSzwOYRdZB+jlOtVG53LYUhPNserzqr4mzVeJoBxa5TEop
         mP+Jhg148oU9rOXSvOFhjUtXrrdrmgDwipbqqqCUQDuKFE17YM2UwX1LdRPW+k6O0U3z
         GY1GVw294QRwrxTMa8FNYktWMVSekWKT8Wd19yNROu/j4sRcg/Byge9o7tb3eR3oEG4A
         fG3Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRO8ZS4YKZFmZCQ3UIE8A1O57mKfq/WojskLXRH108uvfkO2rgLBNt8+cnFn7xs22gqLJhtQ==@lfdr.de
X-Gm-Message-State: AOJu0YwQEn2Z/oqaUdi7jw404Ek7QvrlrnUr6BIGUVi9d1c7j392qNQk
	wwzr/pkN1NbtpBKU60ZU4nPmUNy3Jqo5O2sWmbd5iMjQFVp5HGgQ
X-Google-Smtp-Source: AGHT+IFUvPmQPMKHB0OwDfoXBbo+5Po1MgKJ3rMYZ/tsEXvTu3U8qgHq6BE44OnazwRj5QHPAl1+rQ==
X-Received: by 2002:a05:6214:45a0:b0:6c1:6afb:569 with SMTP id 6a1803df08f44-6c573559181mr73713296d6.31.1726217100860;
        Fri, 13 Sep 2024 01:45:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5aac:0:b0:6c5:e73:a956 with SMTP id 6a1803df08f44-6c5734faec9ls3450756d6.1.-pod-prod-01-us;
 Fri, 13 Sep 2024 01:45:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9cZpMCLqoMWgOIXwb85fJQ1sDUt/m7Q3LOmSni9u10ZT/MudVyieOR/SEllQXoUQHLrzoboAgijw=@googlegroups.com
X-Received: by 2002:a05:6102:2ac1:b0:49b:d6cf:8b56 with SMTP id ada2fe7eead31-49d41577d92mr6922901137.19.1726217099856;
        Fri, 13 Sep 2024 01:44:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726217099; cv=none;
        d=google.com; s=arc-20240605;
        b=ST6rkL69O2salVFAnho5Q/UicEepdMFK6e4C8RFxUWfIDG2f10zwSAnbXwpAsXo9Qb
         J1rRiHJHKOb+hNFUK4xyh9ntvKlf4QteJDHIcyBW2lERjs6zUbhUnAWynaga7piBqb/T
         EEVeLnxN0oevJaJgl/8INqP1duCGIv1+a/xkuoZMpPbAr2grXuoInVwn/pUaJICCmArp
         8ixD29EkVYLViMFMt+Bc3OzGbl+FzDW62QqLY8kt2wI1B7PdfS9EPEHqZvw52fOkzCNG
         nz5sQJ1tm0IW+lhyt/1Djqdh2ce1g+lk+95uiTlQWe/IQuFZnZUhwD0DWxdfjlU1XsLJ
         f5kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=xnAQgJcUkss6MVbxBchJezWd1R3vqAyy+/YYfgOLdDI=;
        fh=UQNaMAYHGrpcz1A3KIVW4uNQRqY/Xs/Tgi5PZeMplwM=;
        b=EKSmFrB+BVDOjDaqBh9xzHSlA/n6Mjovs3oKX1khL3t46p90TTrrGVVUn5ZMnBYstf
         qgLFtG7sp1CvdgoPmZtL8jEEV/D6M/XaFJInXLNJMBRBPoCj1SU2rNKVHZb/Lf9utMfv
         jvAh+6BjQ7suq06JVlJ9rAmTEdAjc1roUBvdFIPK2juCA+RsXRKOBxqTGy00vNMTkOQ0
         Bl9rlJbp2M6hDRGmMoTJKxyv8wdERxreFQYdapE+z3cfCnh9hwrMNZ6UdL6Y/byAEYtj
         cp1JV9f3bhECguwSpfqgEuJ9h8SM1/VM/dIGV8zGH0e6FameZPRetOlqwaA/2TNv9Il7
         XFNQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id a1e0cc1a2514c-84906bd3754si165243241.0.2024.09.13.01.44.59
        for <kasan-dev@googlegroups.com>;
        Fri, 13 Sep 2024 01:44:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5B0C6153B;
	Fri, 13 Sep 2024 01:45:28 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.16.84])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 1F8E53F73B;
	Fri, 13 Sep 2024 01:44:54 -0700 (PDT)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-mm@kvack.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Hildenbrand <david@redhat.com>,
	Ryan Roberts <ryan.roberts@arm.com>,
	"Mike Rapoport (IBM)" <rppt@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>,
	x86@kernel.org,
	linux-m68k@lists.linux-m68k.org,
	linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-perf-users@vger.kernel.org
Subject: [PATCH 3/7] mm: Use ptep_get() for accessing PTE entries
Date: Fri, 13 Sep 2024 14:14:29 +0530
Message-Id: <20240913084433.1016256-4-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240913084433.1016256-1-anshuman.khandual@arm.com>
References: <20240913084433.1016256-1-anshuman.khandual@arm.com>
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
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

Convert PTE accesses via ptep_get() helper that defaults as READ_ONCE() but
also provides the platform an opportunity to override when required.

Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: "Mike Rapoport (IBM)" <rppt@kernel.org>
Cc: linux-mm@kvack.org
Cc: linux-kernel@vger.kernel.org
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
 include/linux/pgtable.h | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 2a6a3cccfc36..05e6995c1b93 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1060,7 +1060,7 @@ static inline int pgd_same(pgd_t pgd_a, pgd_t pgd_b)
  */
 #define set_pte_safe(ptep, pte) \
 ({ \
-	WARN_ON_ONCE(pte_present(*ptep) && !pte_same(*ptep, pte)); \
+	WARN_ON_ONCE(pte_present(ptep_get(ptep)) && !pte_same(ptep_get(ptep), pte)); \
 	set_pte(ptep, pte); \
 })
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240913084433.1016256-4-anshuman.khandual%40arm.com.
