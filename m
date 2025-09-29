Return-Path: <kasan-dev+bncBD5MD3MG34LRBMVE47DAMGQE53PSXHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AD52BA79EE
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 02:26:29 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-32eaeba9abasf6134402a91.3
        for <lists+kasan-dev@lfdr.de>; Sun, 28 Sep 2025 17:26:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759105587; cv=pass;
        d=google.com; s=arc-20240605;
        b=K9jY9swlx8tira5B86PqLMlzoGid9Nh2RbZH/sPDFGrlAuNeEe2JwrjdrkN4/8KoqJ
         EOwnWj83iSogTCywAAaGU4cRQ4RnquIxRaIjRiVPpfMbjF1Bzxpie9w6e27u5+Cc5qr0
         Oi1yGgFUBiGn9752QhbuGCVelL76Z8cd0x5n+74yD1crSRXoMpU7RsHHVcLyhZkyyLAc
         +2TtrGEBAkygn/GkOSi0vOH4UQtkPELr4xiiWRxoRNkjyhlSqUSVb80Rl9Vq/oyzC+yK
         ggKz1mp2WozfgoM0y3NEutaFXoCMHHiamXaVu+9L1E4GshnLGcInVvCFj9D9YWiZuZ/Y
         aSHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=FBYhp4puFWMeqJqK/lCGxjNj/NgiM+eseiNaTd1LLHg=;
        fh=HTi/NEKhA949DvknBSHmh9FgGXpTguJYxYJwH2ORglo=;
        b=ZETT0Ba/BA9pbulHre/XaHQUFjENywrK9V2LpJYVkW+qnyUA4qFuOuYVJwk+nF9xTH
         IYiIwWtrn9WQx46kVnII74gixd6Ms4YRsn4TJ+Lur+GmAimTVWvKIIWsCAlerhZbIfDM
         X19/e6HG/CIXxISmexB6HjpftWNMGjNNeSZnXqYniH1w/SfAnPSs0RBbEsDfQ5I+/EyR
         hcpedhzSf2ZRXDLfvU1fPeFQGrahUQLaFOmyNjflKSq+IgG3cXuDW6trxGL4fV0jIZnI
         Dl2Vy7UeXy1o0YrmqvXNzc9Fj7C+LF3reNYR0koG7LMGe5aNNo5a831jXy3JjtYth0j6
         aeZQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="PqPY3uw/";
       spf=pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759105587; x=1759710387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FBYhp4puFWMeqJqK/lCGxjNj/NgiM+eseiNaTd1LLHg=;
        b=pO6jn4CUELjFzh7d5bfhi4PzjFZKVJf9oQk4VXRxv50zD954RuKsClF/g6ElrOLRad
         Z/3tfwkPcYIQySiemNrpl24coJwnVaP5kz6ONDZOuan5A6sYnEl9egl630KzDWQvVcUD
         EnRWUN5bQ0oEPN2z5s3ZZwcvp+CLsUTvIcFS+1NP2kxO5njqKQLPUmrAjfSZ8c1f42BM
         yyTdTspkWztom5fiYEO5JHIVyTMzky5R/IRkDPN7Bxk0HJ3CfKUxImvcdn3Eog8eiiN4
         dsru2STDkXRBJDlobkJyeg6Wjoe6sW395epjM23vRyoMiwMoehD01vZtIYzOXwQsGIW9
         yiKA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1759105587; x=1759710387; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=FBYhp4puFWMeqJqK/lCGxjNj/NgiM+eseiNaTd1LLHg=;
        b=BtdIVAle7jmwPALYb7S6/XiQkRRRUFkF6zjxOK8CmdvCv+zZ4mROpjm26BvAHv6TcB
         kKqdpD+7C00m4rNwW9+zEdFva7gqadziHvgueB/xosqnb6jvk3HpRkyUbhVb7MVr7y2Y
         YNKq+bxf39SguFZ3kT8KZUyH7K1iSTmlmP4Ihhgtkv7Hi+5ik+/owosqq0Zixm6UoALD
         Wh17Gz1GtO5YKgxTI5uvG6tZhFroctfxv1r4m84BG2Mh5Cb8T6BIzjnoIzzo6xbu+zu7
         hHxa8q3hsvaUv2eCGEhn73Y/IDeWPkMZhpVqO9peMJo1BDR7Dd7PHILXQIsncDmzSzhb
         S5Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759105587; x=1759710387;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FBYhp4puFWMeqJqK/lCGxjNj/NgiM+eseiNaTd1LLHg=;
        b=esg3WpS+bCmxcY6rqymOSBhFYUt0GfrMTFncWVNwvS9YrTMJtuc8lNdViPn9o/UmGY
         p2gPm/vzsRAyCh3kvcQ+ZHv/wA5U4aAp5UKm8SGt/PCaodBelVjx+5CBn/+zm3vhG7Xv
         V8nmcArbQmX5Pk+2WU0W8Y5+wo/5idQzzYB+Dc4kMGWOcflSWRdgBhRwO9/OhI6d+Bc7
         dimlu15s4JxAC411lCmVtj2UJS3zzo2Wamq7gh5XdFKZYrFyT73BVjYDD7oUCyW+6hYL
         JAdg9CjMQjRoD1texSldrZzl62tXHnSnT6+MOue2a4OYJ8Wpq/v3sfFjC2oLdfm3YQVS
         QC8A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUGIigqsh0vOCyJjz/YqEz8ej22EZq0PNPhgBKiOtf2YxDusbaELaxceQMWOsCIupWXRRamKQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz1b3rvlYCR/0hcrnJvkAbIbtEE9TQsbD1/MYLfE8p8GX6ZFNX2
	w3ILxHEIGbtxKCC4k86iDmS1gFkpaX8+sXIQdpp8/atEpFf/MHSqqP+G
X-Google-Smtp-Source: AGHT+IGNz0rEBJ8f8mv0pPYN5omXNDYV2o6XAOKOCTAQ/CzxGgLE8R3MoaMV4hwwJQ06Vjx2BV5iyA==
X-Received: by 2002:a17:90b:3ecb:b0:335:28ee:eeaf with SMTP id 98e67ed59e1d1-33528eef006mr13356107a91.29.1759105587279;
        Sun, 28 Sep 2025 17:26:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4FMOxlvo+Stv5K+ejpFFiPBE/wn4glj/iLMfrNlAEyNw=="
Received: by 2002:a17:90b:3d48:b0:32e:ddb7:ede6 with SMTP id
 98e67ed59e1d1-3342a5fd60els5974340a91.1.-pod-prod-08-us; Sun, 28 Sep 2025
 17:26:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXJ/wmSknqkQkMOxrjiuZhtC6FN2Ro33VzuM8eTTYumFTQZt2AGJIGxNIGwI4Z3WHaHrFjppyp22MQ=@googlegroups.com
X-Received: by 2002:a05:6a20:1588:b0:2f7:bbca:c9b7 with SMTP id adf61e73a8af0-2f7bbcaccbdmr11829115637.52.1759105585755;
        Sun, 28 Sep 2025 17:26:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759105585; cv=none;
        d=google.com; s=arc-20240605;
        b=TNV/5tVs+mqacVLeeix4w8/oEbEWWDOf8nQYHk8IHRJolgU8rLz1Rnvezh4YuJCm+u
         HiO+K2ATChfJb+d4x+tVpOhyF8FWAZV55EWGEGt6fkBWhUhJv5l/k3ZT0wuVYLC9CTfz
         WdHIRapJ5VvdPlxApu4hlKIEdXWZk74bYcNo+t0WqQ6exbF+MG9zYgUszVpEq8ZF2RcR
         L30kyB/9FrwZows7DzuL1qm1GBo6CZX8rEmGJNnHeBzmhfNi0mvymhNaNgyMHSH621Cg
         obPtEqOYqrTIR1FE7zYI6ClcZdiLnolotXiJEk+FbbWhkp28wTB59lSel9smbtAtlrQB
         h5AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FZrb9ZvwMY4YVa3pVe0HMYNnPnxeY8/s3k+/iyrjb1c=;
        fh=jpLIs2kK/o/5y6orrhZZQZfAdiKyp5+y7De1ghzyeX4=;
        b=cqgDurUt3mnb2FdF26yUSg1byvLJBZGFW2DJENAC0DE2MuF7rCaAk2StLTupWSKJ8j
         voSM16aRba54o7AqSsNnYARXE9UE+ZSnVazc5gjOrh5AouKkE1t7twgIwqD2cNEjfUDQ
         PvnkZPIcL5fak9NMbZsLYnJdwuNKylW1OOEILexiY9a96W6zpca0LpDN2WngsIDxfkfW
         eVEiMpMdwg7D/nkPufcC+e0l/v4Gczt99iWlKV9EiK5SSa0ARdVH2/0tsY6VrSa5JarB
         xH2n/pg9BfhZkPcorRTaekcb+2QJVFpeibA3FnIjVmyIElZcOazTm7x0N45o1gy3S6c5
         Q1gA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="PqPY3uw/";
       spf=pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-781028a7830si436617b3a.3.2025.09.28.17.26.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 28 Sep 2025 17:26:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id d9443c01a7336-27c369f898fso43996535ad.3
        for <kasan-dev@googlegroups.com>; Sun, 28 Sep 2025 17:26:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUNISfbnXmtIDTjT9LcGS1wrK49PXfHU7dC8QHOUXSmgoA2PV1L4IwehAaXCFCfSxUD1CdR5ZocjpU=@googlegroups.com
X-Gm-Gg: ASbGnctKD46TgZ4BL4iGk97anDNr8DZERWbjDvEhjKKnqfxLj3KkjaLwvckDcoA+8b+
	swJFGvwGBQ55r8Xvx98mIfUXmYNOQFOE04B6ytRxDKFDHeCbBvG0rpPZyYNppdI+zTFGmrbRpIF
	NWMIFzrcSUWvhPGgAAKR6u4RLkw/h1K9iA4ocdS9cfT+CqcQg0mMNu+lY4r+YoyCgUDzx0CdaY3
	NGhGbFQD8stXoiiq0iTKzrXglk6rZC/JwWHj1xWwMeFYdWUZBL3hh/g2iqgUl9nq915bxHu9jGk
	wnxkzaYVsKRydI787GAHpPXazLh1sV8DxaQC7W+uWz0Hj5q0R0EVX9dOcYbahtPv91uUtyU8rms
	rtgS7bJ8bpLUpukF9knLLQbvo/t59KFqLE6eqp3Z3SX1lDTiF424Y/3pqLg9mvA==
X-Received: by 2002:a17:902:e806:b0:267:6754:8fd9 with SMTP id d9443c01a7336-27ed4a3cfedmr156764855ad.39.1759105585085;
        Sun, 28 Sep 2025 17:26:25 -0700 (PDT)
Received: from E07P150077.ecarx.com.cn ([103.52.189.23])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-27ed6882160sm111191395ad.71.2025.09.28.17.26.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 28 Sep 2025 17:26:24 -0700 (PDT)
From: Jianyun Gao <jianyungao89@gmail.com>
To: dev.jain@arm.com
Cc: Liam.Howlett@oracle.com,
	akpm@linux-foundation.org,
	baohua@kernel.org,
	bhe@redhat.com,
	chengming.zhou@linux.dev,
	chrisl@kernel.org,
	cl@gentwo.org,
	damon@lists.linux.dev,
	david@redhat.com,
	dvyukov@google.com,
	elver@google.com,
	glider@google.com,
	harry.yoo@oracle.com,
	jannh@google.com,
	jgg@ziepe.ca,
	jhubbard@nvidia.com,
	jianyungao89@gmail.com,
	kasan-dev@googlegroups.com,
	kasong@tencent.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	lorenzo.stoakes@oracle.com,
	mhocko@suse.com,
	nphamcs@gmail.com,
	peterx@redhat.com,
	pfalcato@suse.de,
	rientjes@google.com,
	roman.gushchin@linux.dev,
	rppt@kernel.org,
	shikemeng@huaweicloud.com,
	sj@kernel.org,
	surenb@google.com,
	vbabka@suse.cz,
	xu.xin16@zte.com.cn
Subject: [PATCH v2] mm: Fix some typos in mm module
Date: Mon, 29 Sep 2025 08:26:08 +0800
Message-Id: <20250929002608.1633825-1-jianyungao89@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <3c3f9032-18ac-4229-b010-b8b95a11d2a4@arm.com>
References: <3c3f9032-18ac-4229-b010-b8b95a11d2a4@arm.com>
MIME-Version: 1.0
X-Original-Sender: jianyungao89@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="PqPY3uw/";       spf=pass
 (google.com: domain of jianyungao89@gmail.com designates 2607:f8b0:4864:20::641
 as permitted sender) smtp.mailfrom=jianyungao89@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

From: "jianyun.gao" <jianyungao89@gmail.com>

Below are some typos in the code comments:

  intevals ==> intervals
  addesses ==> addresses
  unavaliable ==> unavailable
  facor ==> factor
  droping ==> dropping
  exlusive ==> exclusive
  decription ==> description
  confict ==> conflict
  desriptions ==> descriptions
  otherwize ==> otherwise
  vlaue ==> value
  cheching ==> checking
  exisitng ==> existing
  modifed ==> modified
  differenciate ==> differentiate
  refernece ==> reference
  permissons ==> permissions
  indepdenent ==> independent
  spliting ==> splitting

Just fix it.

Signed-off-by: jianyun.gao <jianyungao89@gmail.com>
---
The fix for typos in the hugetlb sub-module has been added.

 mm/damon/sysfs.c     | 2 +-
 mm/gup.c             | 2 +-
 mm/hugetlb.c         | 6 +++---
 mm/hugetlb_vmemmap.c | 6 +++---
 mm/kmsan/core.c      | 2 +-
 mm/ksm.c             | 2 +-
 mm/memory-tiers.c    | 2 +-
 mm/memory.c          | 4 ++--
 mm/secretmem.c       | 2 +-
 mm/slab_common.c     | 2 +-
 mm/slub.c            | 2 +-
 mm/swapfile.c        | 2 +-
 mm/userfaultfd.c     | 2 +-
 mm/vma.c             | 4 ++--
 14 files changed, 20 insertions(+), 20 deletions(-)

diff --git a/mm/damon/sysfs.c b/mm/damon/sysfs.c
index c96c2154128f..25ff8bd17e9c 100644
--- a/mm/damon/sysfs.c
+++ b/mm/damon/sysfs.c
@@ -1232,7 +1232,7 @@ enum damon_sysfs_cmd {
 	DAMON_SYSFS_CMD_UPDATE_SCHEMES_EFFECTIVE_QUOTAS,
 	/*
 	 * @DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS: Update the tuned monitoring
-	 * intevals.
+	 * intervals.
 	 */
 	DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS,
 	/*
diff --git a/mm/gup.c b/mm/gup.c
index 0bc4d140fc07..6ed50811da8f 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2730,7 +2730,7 @@ EXPORT_SYMBOL(get_user_pages_unlocked);
  *
  *  *) ptes can be read atomically by the architecture.
  *
- *  *) valid user addesses are below TASK_MAX_SIZE
+ *  *) valid user addresses are below TASK_MAX_SIZE
  *
  * The last two assumptions can be relaxed by the addition of helper functions.
  *
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index eed59cfb5d21..3420711a81d3 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -2954,7 +2954,7 @@ typedef enum {
 	 * NOTE: This is mostly identical to MAP_CHG_NEEDED, except
 	 * that currently vma_needs_reservation() has an unwanted side
 	 * effect to either use end() or commit() to complete the
-	 * transaction.	 Hence it needs to differenciate from NEEDED.
+	 * transaction. Hence it needs to differentiate from NEEDED.
 	 */
 	MAP_CHG_ENFORCED = 2,
 } map_chg_state;
@@ -5998,7 +5998,7 @@ void __unmap_hugepage_range(struct mmu_gather *tlb, struct vm_area_struct *vma,
 	/*
 	 * If we unshared PMDs, the TLB flush was not recorded in mmu_gather. We
 	 * could defer the flush until now, since by holding i_mmap_rwsem we
-	 * guaranteed that the last refernece would not be dropped. But we must
+	 * guaranteed that the last reference would not be dropped. But we must
 	 * do the flushing before we return, as otherwise i_mmap_rwsem will be
 	 * dropped and the last reference to the shared PMDs page might be
 	 * dropped as well.
@@ -7179,7 +7179,7 @@ long hugetlb_change_protection(struct vm_area_struct *vma,
 		} else if (unlikely(is_pte_marker(pte))) {
 			/*
 			 * Do nothing on a poison marker; page is
-			 * corrupted, permissons do not apply.  Here
+			 * corrupted, permissions do not apply. Here
 			 * pte_marker_uffd_wp()==true implies !poison
 			 * because they're mutual exclusive.
 			 */
diff --git a/mm/hugetlb_vmemmap.c b/mm/hugetlb_vmemmap.c
index ba0fb1b6a5a8..96ee2bd16ee1 100644
--- a/mm/hugetlb_vmemmap.c
+++ b/mm/hugetlb_vmemmap.c
@@ -75,7 +75,7 @@ static int vmemmap_split_pmd(pmd_t *pmd, struct page *head, unsigned long start,
 	if (likely(pmd_leaf(*pmd))) {
 		/*
 		 * Higher order allocations from buddy allocator must be able to
-		 * be treated as indepdenent small pages (as they can be freed
+		 * be treated as independent small pages (as they can be freed
 		 * individually).
 		 */
 		if (!PageReserved(head))
@@ -684,7 +684,7 @@ static void __hugetlb_vmemmap_optimize_folios(struct hstate *h,
 		ret = hugetlb_vmemmap_split_folio(h, folio);
 
 		/*
-		 * Spliting the PMD requires allocating a page, thus lets fail
+		 * Splitting the PMD requires allocating a page, thus let's fail
 		 * early once we encounter the first OOM. No point in retrying
 		 * as it can be dynamically done on remap with the memory
 		 * we get back from the vmemmap deduplication.
@@ -715,7 +715,7 @@ static void __hugetlb_vmemmap_optimize_folios(struct hstate *h,
 		/*
 		 * Pages to be freed may have been accumulated.  If we
 		 * encounter an ENOMEM,  free what we have and try again.
-		 * This can occur in the case that both spliting fails
+		 * This can occur in the case that both splitting fails
 		 * halfway and head page allocation also failed. In this
 		 * case __hugetlb_vmemmap_optimize_folio() would free memory
 		 * allowing more vmemmap remaps to occur.
diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index 1ea711786c52..1bb0e741936b 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -33,7 +33,7 @@ bool kmsan_enabled __read_mostly;
 
 /*
  * Per-CPU KMSAN context to be used in interrupts, where current->kmsan is
- * unavaliable.
+ * unavailable.
  */
 DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
 
diff --git a/mm/ksm.c b/mm/ksm.c
index 160787bb121c..edd6484577d7 100644
--- a/mm/ksm.c
+++ b/mm/ksm.c
@@ -389,7 +389,7 @@ static unsigned long ewma(unsigned long prev, unsigned long curr)
  * exponentially weighted moving average. The new pages_to_scan value is
  * multiplied with that change factor:
  *
- *      new_pages_to_scan *= change facor
+ *      new_pages_to_scan *= change factor
  *
  * The new_pages_to_scan value is limited by the cpu min and max values. It
  * calculates the cpu percent for the last scan and calculates the new
diff --git a/mm/memory-tiers.c b/mm/memory-tiers.c
index 0382b6942b8b..f97aa5497040 100644
--- a/mm/memory-tiers.c
+++ b/mm/memory-tiers.c
@@ -519,7 +519,7 @@ static inline void __init_node_memory_type(int node, struct memory_dev_type *mem
 	 * for each device getting added in the same NUMA node
 	 * with this specific memtype, bump the map count. We
 	 * Only take memtype device reference once, so that
-	 * changing a node memtype can be done by droping the
+	 * changing a node memtype can be done by dropping the
 	 * only reference count taken here.
 	 */
 
diff --git a/mm/memory.c b/mm/memory.c
index 0ba4f6b71847..d6b0318df951 100644
--- a/mm/memory.c
+++ b/mm/memory.c
@@ -4200,7 +4200,7 @@ static inline bool should_try_to_free_swap(struct folio *folio,
 	 * If we want to map a page that's in the swapcache writable, we
 	 * have to detect via the refcount if we're really the exclusive
 	 * user. Try freeing the swapcache to get rid of the swapcache
-	 * reference only in case it's likely that we'll be the exlusive user.
+	 * reference only in case it's likely that we'll be the exclusive user.
 	 */
 	return (fault_flags & FAULT_FLAG_WRITE) && !folio_test_ksm(folio) &&
 		folio_ref_count(folio) == (1 + folio_nr_pages(folio));
@@ -5274,7 +5274,7 @@ vm_fault_t do_set_pmd(struct vm_fault *vmf, struct folio *folio, struct page *pa
 
 /**
  * set_pte_range - Set a range of PTEs to point to pages in a folio.
- * @vmf: Fault decription.
+ * @vmf: Fault description.
  * @folio: The folio that contains @page.
  * @page: The first page to create a PTE for.
  * @nr: The number of PTEs to create.
diff --git a/mm/secretmem.c b/mm/secretmem.c
index 60137305bc20..a350ca20ca56 100644
--- a/mm/secretmem.c
+++ b/mm/secretmem.c
@@ -227,7 +227,7 @@ SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
 	struct file *file;
 	int fd, err;
 
-	/* make sure local flags do not confict with global fcntl.h */
+	/* make sure local flags do not conflict with global fcntl.h */
 	BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);
 
 	if (!secretmem_enable || !can_set_direct_map())
diff --git a/mm/slab_common.c b/mm/slab_common.c
index bfe7c40eeee1..9ab116156444 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -256,7 +256,7 @@ static struct kmem_cache *create_cache(const char *name,
  * @object_size: The size of objects to be created in this cache.
  * @args: Additional arguments for the cache creation (see
  *        &struct kmem_cache_args).
- * @flags: See the desriptions of individual flags. The common ones are listed
+ * @flags: See the descriptions of individual flags. The common ones are listed
  *         in the description below.
  *
  * Not to be called directly, use the kmem_cache_create() wrapper with the same
diff --git a/mm/slub.c b/mm/slub.c
index d257141896c9..5f2622c370cc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -2412,7 +2412,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init,
 		memset((char *)kasan_reset_tag(x) + inuse, 0,
 		       s->size - inuse - rsize);
 		/*
-		 * Restore orig_size, otherwize kmalloc redzone overwritten
+		 * Restore orig_size, otherwise kmalloc redzone overwritten
 		 * would be reported
 		 */
 		set_orig_size(s, x, orig_size);
diff --git a/mm/swapfile.c b/mm/swapfile.c
index b4f3cc712580..b55f10ec1f3f 100644
--- a/mm/swapfile.c
+++ b/mm/swapfile.c
@@ -1545,7 +1545,7 @@ static bool swap_entries_put_map_nr(struct swap_info_struct *si,
 
 /*
  * Check if it's the last ref of swap entry in the freeing path.
- * Qualified vlaue includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
+ * Qualified value includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
  */
 static inline bool __maybe_unused swap_is_last_ref(unsigned char count)
 {
diff --git a/mm/userfaultfd.c b/mm/userfaultfd.c
index aefdf3a812a1..333f4b8bc810 100644
--- a/mm/userfaultfd.c
+++ b/mm/userfaultfd.c
@@ -1508,7 +1508,7 @@ static int validate_move_areas(struct userfaultfd_ctx *ctx,
 
 	/*
 	 * For now, we keep it simple and only move between writable VMAs.
-	 * Access flags are equal, therefore cheching only the source is enough.
+	 * Access flags are equal, therefore checking only the source is enough.
 	 */
 	if (!(src_vma->vm_flags & VM_WRITE))
 		return -EINVAL;
diff --git a/mm/vma.c b/mm/vma.c
index 3b12c7579831..2e127fa97475 100644
--- a/mm/vma.c
+++ b/mm/vma.c
@@ -109,7 +109,7 @@ static inline bool is_mergeable_vma(struct vma_merge_struct *vmg, bool merge_nex
 static bool is_mergeable_anon_vma(struct vma_merge_struct *vmg, bool merge_next)
 {
 	struct vm_area_struct *tgt = merge_next ? vmg->next : vmg->prev;
-	struct vm_area_struct *src = vmg->middle; /* exisitng merge case. */
+	struct vm_area_struct *src = vmg->middle; /* existing merge case. */
 	struct anon_vma *tgt_anon = tgt->anon_vma;
 	struct anon_vma *src_anon = vmg->anon_vma;
 
@@ -798,7 +798,7 @@ static bool can_merge_remove_vma(struct vm_area_struct *vma)
  * Returns: The merged VMA if merge succeeds, or NULL otherwise.
  *
  * ASSUMPTIONS:
- * - The caller must assign the VMA to be modifed to @vmg->middle.
+ * - The caller must assign the VMA to be modified to @vmg->middle.
  * - The caller must have set @vmg->prev to the previous VMA, if there is one.
  * - The caller must not set @vmg->next, as we determine this.
  * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250929002608.1633825-1-jianyungao89%40gmail.com.
