Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUO4VODAMGQEXL3HJOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 088DE3AAC91
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:40:19 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id i13-20020a5e9e0d0000b029042f7925649esf1198609ioq.5
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:40:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912018; cv=pass;
        d=google.com; s=arc-20160816;
        b=xaSN3M6+XbZE+21ZP01itQ+i064/KIa8vjB8KyeTK19K0m/3vvrvmknBkWIIqh5YRA
         bIhPKrNK4hmqzNrJjD3f+cx09oUZoa6toQB6cziC7dmIvEXqDnJchyEtOYZW6vJuyhoT
         xFGiNrXQdDToQvQ6YwAB3RCp05iBUvz25KZ6ivAV8DjUqTu5vrfvlWDYgeiq431K+9Bg
         gc9a8hYX0XVxLYlxMaTWem41u1c74x7dd8eDd9WjgkGz92HPkZ6IzohE1G6RsEQrOxi6
         j0jMKyTEirIgzStlZWqCoyt6NyrgRb21X88h+udl0dT+AQmoJyQ3J1tShhPaXnJQWI1D
         enjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=XTF5Duuon1JaVDgzm9qVlyeW0KFd7KbKexYIz3nI7cs=;
        b=V6PCasD39fwwSRoWhTK6dbz7L4VETfVLRyyl2a5RlTtGVPIlSF8MZT+iCRl6tMQYUB
         jSL1Kq932g5RgN5BnkCMq40BeBdZSyAqmfahT0GeKnGtGYf75lZv14UQV1INV0wPAZay
         brArvHF65nTTecY2dp1YkeLSlTF0hvtLRfqAXtIfNXWtBYL0k7HNH49RGcnziM44zd2U
         MSaOnVQ76ztWt76IOSloIXRieqSnmKZ94v94nytElMHwFA7yBhhyPOOHzvsmD0MUbtt2
         3QMzQmGKPx8aijIuG3FlNXtJH0+gX/bleBICGGoRk96ENjPtf6if6ypgVa4ajalmGQ7r
         Pv2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D0qWqK+j;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTF5Duuon1JaVDgzm9qVlyeW0KFd7KbKexYIz3nI7cs=;
        b=TFTFUQeRyBx3Z30k2cJ3z9Zs9mcYpDNcfw3TxOZJkxZKFqd00eZjACdZrEqAA5Klyo
         LkartGm35ZBkkh4L7Y7ST99t09e8+QqeG7o6WK82kzVSRFwEc9+Hg1UYpe36V54XRBnX
         Ut27wx7cJUk9k93/UvxFTgdwQYXYmazcKVMI2zFLyIZMZOOowqAw4ygySArD1lv58ibe
         9v44Z7HWuTOhv6PkyG/1PA40JjDMCJbXNLQnSgEEZFNSJGqS88rsZ6JVyOaWybMgHEr9
         J7wFLeuycSI6c1qfyeIgqOQ4O6o46EhBPX/twGT4gdVJFt38JGFj4ec7zRZGsMfPJ9pT
         KQwA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XTF5Duuon1JaVDgzm9qVlyeW0KFd7KbKexYIz3nI7cs=;
        b=DVw4uxVDyoLAmwGpR/QiPC/Fdi7t+E57pLK/P139t+DptlvMk40OI6Bdl2vgyv5Vdy
         g46XMLnMbxDL4CzP/SvxAC2qVS0C4WYNP0DdLzVHAr5eY6N726aOO+UZSTCJAQ5wYi0Y
         dUg+QU62ZZzE/f2YzULd++RUvRIXX8Cf2Ut2Bj+GpJqQEX8ZSmmKG9Z92Xai5hSVvaTI
         z7pvZForBGN98XptxDvz30Rscgx5xjz8fZ3hTKwDWBvgdJ5nDkfiJuWo+x84XQ0Szwzl
         34z0MmleWMcUIwBKfSjnRg7tbO9+JiajvAASO9w9ue+Dqcwhfu/c5gsxCLY+K7l4Q/9Y
         OfoA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bja/KbbqZ5lE1uyhtmI70cdkTB8AURhy+Q9iMwnxiXjAvb+ON
	jILp2yF9fdW8wL6GhAIeQQk=
X-Google-Smtp-Source: ABdhPJwi7qh+EY2lngdySZc1/PU5zJPaIvMrVCz6Cu6XUxHxNrr2Cp1YuR097hLyJaO07l+G834O6A==
X-Received: by 2002:a02:c642:: with SMTP id k2mr3066791jan.141.1623912017933;
        Wed, 16 Jun 2021 23:40:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c4c5:: with SMTP id h5ls732809jaj.1.gmail; Wed, 16 Jun
 2021 23:40:17 -0700 (PDT)
X-Received: by 2002:a02:ccf2:: with SMTP id l18mr1837560jaq.128.1623912017674;
        Wed, 16 Jun 2021 23:40:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912017; cv=none;
        d=google.com; s=arc-20160816;
        b=tVO9Yq1xOqotlJ0XRY56bBWKHHNzmNuL+AVnQ+P6GcY23rzP3yUdL/ODTz7r8kg7f6
         HiWad6S6IHmcHCSwdS55pvyfQPii71hYe/wMEY9m2maCbCuWLwD4tBLqo1MVzoSTdm0y
         9n+OrSzaGVxPf2mEwwUmKjy5MwCQjCsyvEjatlBXodXyU1UzQBbrhUQ812WoBr404tC6
         b/6vfafzVmzVFbFrZz7q3K3+k4kVEuyM1985v53G8nzGDCztBRE1UIMHjKe+vd4Z25pu
         vEPojaFsOGy1iTHEXx2wZhAOIrm3RzVRkDQXqUMDgZnmPTftIaVjK6H+Q0CV1+M5Sy9q
         17Ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=b1Pi1RzyfsWNKu+C0AG0URkCeCwQ85qxvHvYbK7X+Gk=;
        b=TjZy0sSTPaBZK9NhWrad3laUYcJ+AAMZvOBLtoEBn8WY7B1UZplbGONKetBdDMqbMn
         RoIOAS3B0as9Hd2mEz621ezJp1fyonzwiuvyVX/lnVOJwlVo9dzxxwXVdXcy0bLBvoJt
         gvcXU+LCpED9tT6XH9VW7phDwp7BV2UnjQ+kCUNztbii+QBwbIjFqVJLp/CzH/bIRlYJ
         JHymCXW80cAOhTPZLVxoK33PbNV1k0uXRYkHVFCUO75AypRPgmnpb7QQ9mLaLe3xUOeL
         bF5KRvKiyKICz8AVcgXI9xiXStVUq9xgcwOKZgECBSz0iDM1c9inoqOFe70clo7DSqOO
         YtCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D0qWqK+j;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 1si365322ioe.4.2021.06.16.23.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 23:40:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id d62so2213727pfd.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 23:40:17 -0700 (PDT)
X-Received: by 2002:a63:1e55:: with SMTP id p21mr3505606pgm.412.1623912017140;
        Wed, 16 Jun 2021 23:40:17 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id o3sm3981688pfd.41.2021.06.16.23.40.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:40:16 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v14 3/4] mm: define default MAX_PTRS_PER_* in include/pgtable.h
Date: Thu, 17 Jun 2021 16:39:55 +1000
Message-Id: <20210617063956.94061-4-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617063956.94061-1-dja@axtens.net>
References: <20210617063956.94061-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=D0qWqK+j;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Commit c65e774fb3f6 ("x86/mm: Make PGDIR_SHIFT and PTRS_PER_P4D variable")
made PTRS_PER_P4D variable on x86 and introduced MAX_PTRS_PER_P4D as a
constant for cases which need a compile-time constant (e.g. fixed-size
arrays).

powerpc likewise has boot-time selectable MMU features which can cause
other mm "constants" to vary. For KASAN, we have some static
PTE/PMD/PUD/P4D arrays so we need compile-time maximums for all these
constants. Extend the MAX_PTRS_PER_ idiom, and place default definitions
in include/pgtable.h. These define MAX_PTRS_PER_x to be PTRS_PER_x unless
an architecture has defined MAX_PTRS_PER_x in its arch headers.

Clean up pgtable-nop4d.h and s390's MAX_PTRS_PER_P4D definitions while
we're at it: both can just pick up the default now.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

s390 was compile tested only.
---
 arch/s390/include/asm/pgtable.h     |  2 --
 include/asm-generic/pgtable-nop4d.h |  1 -
 include/linux/pgtable.h             | 22 ++++++++++++++++++++++
 3 files changed, 22 insertions(+), 3 deletions(-)

diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgtable.h
index 7c66ae5d7e32..cf05954ce013 100644
--- a/arch/s390/include/asm/pgtable.h
+++ b/arch/s390/include/asm/pgtable.h
@@ -342,8 +342,6 @@ static inline int is_module_addr(void *addr)
 #define PTRS_PER_P4D	_CRST_ENTRIES
 #define PTRS_PER_PGD	_CRST_ENTRIES
 
-#define MAX_PTRS_PER_P4D	PTRS_PER_P4D
-
 /*
  * Segment table and region3 table entry encoding
  * (R = read-only, I = invalid, y = young bit):
diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pgtable-nop4d.h
index ce2cbb3c380f..2f6b1befb129 100644
--- a/include/asm-generic/pgtable-nop4d.h
+++ b/include/asm-generic/pgtable-nop4d.h
@@ -9,7 +9,6 @@
 typedef struct { pgd_t pgd; } p4d_t;
 
 #define P4D_SHIFT		PGDIR_SHIFT
-#define MAX_PTRS_PER_P4D	1
 #define PTRS_PER_P4D		1
 #define P4D_SIZE		(1UL << P4D_SHIFT)
 #define P4D_MASK		(~(P4D_SIZE-1))
diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
index 9e6f71265f72..69700e3e615f 100644
--- a/include/linux/pgtable.h
+++ b/include/linux/pgtable.h
@@ -1625,4 +1625,26 @@ typedef unsigned int pgtbl_mod_mask;
 #define pte_leaf_size(x) PAGE_SIZE
 #endif
 
+/*
+ * Some architectures have MMUs that are configurable or selectable at boot
+ * time. These lead to variable PTRS_PER_x. For statically allocated arrays it
+ * helps to have a static maximum value.
+ */
+
+#ifndef MAX_PTRS_PER_PTE
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+#endif
+
+#ifndef MAX_PTRS_PER_PMD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#endif
+
+#ifndef MAX_PTRS_PER_PUD
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#endif
+
+#ifndef MAX_PTRS_PER_P4D
+#define MAX_PTRS_PER_P4D PTRS_PER_P4D
+#endif
+
 #endif /* _LINUX_PGTABLE_H */
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-4-dja%40axtens.net.
