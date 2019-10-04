Return-Path: <kasan-dev+bncBAABBB7L3TWAKGQE34E2FYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 81A2DCB9D3
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Oct 2019 14:05:28 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id d25sf6032435qkk.17
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Oct 2019 05:05:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570190727; cv=pass;
        d=google.com; s=arc-20160816;
        b=LJJAvlt4eFEqeK1TqdCT1AZcaGCda5WieY3MwM3z+DKDwjIhZh1Ln9tt8jKPl53y+Y
         FwIZJlmmOvNSv4+vlBL3W1Aavow3oP7RPAxlsbCnjQ+zhMd0/9HOirTskFGwxv0iEHbB
         hiuF/W4axJM5eklE2uM9/AvdgQaS532+1FvQMpXoIdzctLj6ClFECFNfL8eXp3i0kwLz
         0y+/xoxThVagjQC3TeMPIZXvfKYfMfv1qnvn75VwQ3PUcSHRUAcxf9Ld1aDi5TCKfi1a
         OIbEPAhTjxkBegF+Qn2Pr3r0Xs5mqThenar9mL6w7vLQRjGo04s1E5BxQe0QvY5HuvG7
         Tamw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=Yfjhvc4Us0MzvgdNa2QTIMgyrnHUTHv3QWs6GYQDo18=;
        b=VJ5aUYPoP8jwJEyBu2zXuuUl/ND+Zl9COj63AUlN/8NDR+OJU7+hIIGt1maeafLB8E
         p8MlCTu0jr2ffYC8Nei3De2WpnqZq35P41PpOrTpMORlXtfAqbHTik3pw0Hm2ghTdzot
         Jlzkw03ZD/idEl96JMI7ctgk8gPiOjmq1B77Y5NhW/jjWGQppkPUX8uwDHE4fwwnqXZk
         Lc9JGSt57LWRFwXYKrhqIWwdtQY555ROp5tbTwb8lgXJc5uy1w/XqvVqnaloAdAq3vdV
         8aCsRnCVU3fEGGuiBwXK0js4yO6I17K30sv5SxNTluLEAbTwzWreHn/M0VnHiwDsG81J
         4LBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yfjhvc4Us0MzvgdNa2QTIMgyrnHUTHv3QWs6GYQDo18=;
        b=GWFh1u56Y8g9ppx+hYmTQeuo/AlVSEXTavEcmopaP+XkAg+zSWdJxUe+jfJKHEkB4o
         7mKXCrpwWd8wq+6/Ih2EMmaSvFF1Yq6n9y0CICh+DzPyQX52fnWfC4IaCDkSVHaULCsV
         pIzSRCauYoVLV56y3FGWr1REAuJcE+IwrdWucE71nuWDDxx/zaerfIN78lKnMz350jMS
         M7+v67jdLfbSzIFl0o0S3bRKMvUdX4j0TWWwefpD690EYwmUKfYNU2KI9PtUruFHM7h0
         1cO7VlVlTnkYRDdHzlSgkUvKZZR0r38pVtdcCZG7ETzeQ/jwTEXrls6dYcjC00mXaZRd
         5PgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yfjhvc4Us0MzvgdNa2QTIMgyrnHUTHv3QWs6GYQDo18=;
        b=BHiLmQdqqy9ovVcUuOSX5yGxyS1c17Wepf5HM6jMiMofEO5vNZKRudWVes6vffAm3z
         t0+A/GMhl1lkvrKDl5DBmfHaAiR2K6f2TKvYgYWYmmNVBvMx4FL8cgW5mS7zvhx1DR3e
         2fORK0TBnxqIJJsDuIfhm8LFkLtrmUkWDKdBb5xwkbpKld1eMFZCSntvahiF8cN4YmoL
         zZTnYGKz554mlFntmCMDFWiovvHK/lIopW1HYOx3LLPA1eTHex/jPkDWk9NPfg0W6p33
         U2c/Qv/S8wd349lEQIorabBX3Qi0GuffUl19hgqXy8bK0iTW3JZj1zMtdae4Yb9eg4P7
         +oWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWA7eWJoaHZ2F3tQ8YxtPz4Nzh/remWoNtULK2qOpCf15F96WT2
	M53Qcvp5tSlJcvGvtoUWmyE=
X-Google-Smtp-Source: APXvYqwt0xnURbggsjDLh0wvpC/KMiCgSd57cSNJ36SHu4C2qJs147vBapSm8+eWO4DupV2HiYGGkw==
X-Received: by 2002:ac8:3714:: with SMTP id o20mr15070585qtb.191.1570190727565;
        Fri, 04 Oct 2019 05:05:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:d92:: with SMTP id 140ls1643147qkn.13.gmail; Fri, 04 Oct
 2019 05:05:26 -0700 (PDT)
X-Received: by 2002:ae9:e210:: with SMTP id c16mr1147754qkc.164.1570190726735;
        Fri, 04 Oct 2019 05:05:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570190726; cv=none;
        d=google.com; s=arc-20160816;
        b=KwahGs4tpSO/gADxOJ7/REvsAmhBe6WDx+ZB9xNdc2LVcAb+wALZVC97+wZiLu8jhu
         Y7OVl1ivF38dpegdIsV4fcY4Mhz2H9zlgd8F7RjxNr9XqZIsUDisOXRDQ8kwAVFYIpZy
         c1qik2khTRUSDN+rJoZwQg0PRADMe4mA0AIK8ekJX2SjT6m7QrWr0iNcD7fycOVNzHKR
         Ep7cWPTmlAfz7ZT1yWKmAONYw8EfjjLl+KmGzxsgnwPt0EeNh4vfCjEfvotK2LV27Upu
         mMTsV568QmPx5vHfSuZJBtebYMiyG/LHB14IJ17JbulzqCbZUBrBZU95+Rg/NAJK5/6W
         x7fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=ccwob3Mg5Iqo7bxVKBDeSE4smecI4m4+pxGhjVD8Snc=;
        b=1Esb0G0p/TR9dw5jRrlOmZbfSBQdVre9cEt6ROvnK0paZOs0rkTJE3y6ZBU4NulRNG
         ukRNzx4oZCpr0K5224hVPo/PGqBN3cqCBYh4x3/hSMzO//+gXuNyi2SMaJq1oHHUkH3K
         +Nq3oDjYhbZrj3TaqCJa8Az8oqq3CAKwk3oxqzAWgcSYZRJh3cpapNoxePI2oqOheVHL
         3L3q18fmnXAY4DwZk1rUdkNn9ZUOv/PCtR1XbpZvBCXViMhIkixSZ3l6IXlP3w3aaFLB
         XxU3PvEsmbBa9LZIrmq5NzN5giRDI3oero9mKESAMEs8quP44znpW+CY2sOpRC/yq/7R
         nOpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u44si495336qtb.5.2019.10.04.05.05.24
        for <kasan-dev@googlegroups.com>;
        Fri, 04 Oct 2019 05:05:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: c97804f9dddc466e9f70f2b3cd8152ad-20191004
X-UUID: c97804f9dddc466e9f70f2b3cd8152ad-20191004
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1481575917; Fri, 04 Oct 2019 20:05:20 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Fri, 4 Oct 2019 20:05:16 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Fri, 4 Oct 2019 20:05:16 +0800
Message-ID: <1570190718.19702.125.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, LKML
	<linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
	Linux-MM <linux-mm@kvack.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, <linux-mediatek@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>
Date: Fri, 4 Oct 2019 20:05:18 +0800
In-Reply-To: <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
References: <20190927034338.15813-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+Zxz+R=qQxSMoipXoLjRqyApD3O0eYpK0nyrfGHE4NNPw@mail.gmail.com>
	 <1569594142.9045.24.camel@mtksdccf07>
	 <CACT4Y+YuAxhKtL7ho7jpVAPkjG-JcGyczMXmw8qae2iaZjTh_w@mail.gmail.com>
	 <1569818173.17361.19.camel@mtksdccf07>
	 <1570018513.19702.36.camel@mtksdccf07>
	 <CACT4Y+bbZhvz9ZpHtgL8rCCsV=ybU5jA6zFnJBL7gY2cNXDLyQ@mail.gmail.com>
	 <1570069078.19702.57.camel@mtksdccf07>
	 <CACT4Y+ZwNv2-QBrvuR2JvemovmKPQ9Ggrr=ZkdTg6xy_Ki6UAg@mail.gmail.com>
	 <1570095525.19702.59.camel@mtksdccf07>
	 <1570110681.19702.64.camel@mtksdccf07>
	 <CACT4Y+aKrC8mtcDTVhM-So-TTLjOyFCD7r6jryWFH6i2he1WJA@mail.gmail.com>
	 <1570164140.19702.97.camel@mtksdccf07>
	 <1570176131.19702.105.camel@mtksdccf07>
	 <CACT4Y+ZvhomaeXFKr4za6MJi=fW2SpPaCFP=fk06CMRhNcmFvQ@mail.gmail.com>
	 <1570182257.19702.109.camel@mtksdccf07>
	 <CACT4Y+ZnWPEO-9DkE6C3MX-Wo+8pdS6Gr6-2a8LzqBS=2fe84w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Fri, 2019-10-04 at 11:54 +0200, Dmitry Vyukov wrote:
> > > "out-of-bounds" is the _least_ frequent KASAN bug type. So saying
> > > "out-of-bounds" has downsides of both approaches and won't prevent
> > > duplicate reports by syzbot...
> > >
> > maybe i should add your comment into the comment in get_bug_type?
> 
> Yes, that's exactly what I meant above:
> 
> "I would change get_bug_type() to return "slab-out-of-bounds" (as the
> most common OOB) in such case (with a comment)."
> 
>  ;)


The patchset help to produce KASAN report when size is negative size in
memory operation function. It is helpful for programmer to solve the
undefined behavior issue. Patch 1 based on Dmitry's suggestion and
review, patch 2 is a test in order to verify the patch 1.

[1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
[2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/

Walter Wu (2):
kasan: detect invalid size in memory operation function
kasan: add test for invalid size in memmove

lib/test_kasan.c          | 18 ++++++++++++++++++
mm/kasan/common.c         | 13 ++++++++-----
mm/kasan/generic.c        |  5 +++++
mm/kasan/generic_report.c | 10 ++++++++++
mm/kasan/tags.c           |  5 +++++
mm/kasan/tags_report.c    | 10 ++++++++++
6 files changed, 56 insertions(+), 5 deletions(-)




commit 0bc50c759a425fa0aafb7ef623aa1598b3542c67
Author: Walter Wu <walter-zh.wu@mediatek.com>
Date:   Fri Oct 4 18:38:31 2019 +0800

    kasan: detect invalid size in memory operation function
    
    It is an undefined behavior to pass a negative value to
memset()/memcpy()/memmove()
    , so need to be detected by KASAN.
    
    If size is negative value, then it will be larger than ULONG_MAX/2,
    so that we will qualify as out-of-bounds issue.
    
    KASAN report:
    
     BUG: KASAN: out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
     Read of size 18446744073709551608 at addr ffffff8069660904 by task
cat/72
    
     CPU: 2 PID: 72 Comm: cat Not tainted
5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
     Hardware name: linux,dummy-virt (DT)
     Call trace:
      dump_backtrace+0x0/0x288
      show_stack+0x14/0x20
      dump_stack+0x10c/0x164
      print_address_description.isra.9+0x68/0x378
      __kasan_report+0x164/0x1a0
      kasan_report+0xc/0x18
      check_memory_region+0x174/0x1d0
      memmove+0x34/0x88
      kmalloc_memmove_invalid_size+0x70/0xa0
    
    [1] https://bugzilla.kernel.org/show_bug.cgi?id=199341
    
    Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
    Reported -by: Dmitry Vyukov <dvyukov@google.com>
    Suggested-by: Dmitry Vyukov <dvyukov@google.com>

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..6ef0abd27f06 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -102,7 +102,8 @@ EXPORT_SYMBOL(__kasan_check_write);
 #undef memset
 void *memset(void *addr, int c, size_t len)
 {
-	check_memory_region((unsigned long)addr, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)addr, len, true, _RET_IP_))
+		return NULL;
 
 	return __memset(addr, c, len);
 }
@@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
 #undef memmove
 void *memmove(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	!check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memmove(dest, src, len);
 }
@@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t
len)
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	!check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memcpy(dest, src, len);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..02148a317d27 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,6 +173,11 @@ static __always_inline bool
check_memory_region_inline(unsigned long addr,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	if (unlikely((void *)addr <
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		kasan_report(addr, size, write, ret_ip);
diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
index 36c645939bc9..23951a453681 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,6 +107,16 @@ static const char *get_wild_bug_type(struct
kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * if access_size < 0, then it will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 * out-of-bounds is the _least_ frequent KASAN bug type. So saying
+	 * out-of-bounds has downsides of both approaches and won't prevent
+	 * duplicate reports by syzbot.
+	 */
+	if ((long)info->access_size < 0)
+		return "out-of-bounds";
+
 	if (addr_has_shadow(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 0e987c9ca052..b829535a3ad7 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t
size, bool write,
 	if (unlikely(size == 0))
 		return true;
 
+	if (unlikely((long)size < 0)) {
+		kasan_report(addr, size, write, ret_ip);
+		return false;
+	}
+
 	tag = get_tag((const void *)addr);
 
 	/*
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 969ae08f59d7..19b9e364b397 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,16 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * if access_size < 0, then it will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 * out-of-bounds is the _least_ frequent KASAN bug type. So saying
+	 * out-of-bounds has downsides of both approaches and won't prevent
+	 * duplicate reports by syzbot.
+	 */
+	if ((long)info->access_size < 0)
+		return "out-of-bounds";
+
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;



commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
Author: Walter Wu <walter-zh.wu@mediatek.com>
Date:   Fri Oct 4 18:32:03 2019 +0800

    kasan: add test for invalid size in memmove
    
    Test size is negative vaule in memmove in order to verify
    if it correctly produce KASAN report.
    
    Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 49cc4d570a40..06942cf585cc 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -283,6 +283,23 @@ static noinline void __init
kmalloc_oob_in_memset(void)
 	kfree(ptr);
 }
 
+static noinline void __init kmalloc_memmove_invalid_size(void)
+{
+	char *ptr;
+	size_t size = 64;
+
+	pr_info("invalid size in memmove\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	memset((char *)ptr, 0, 64);
+	memmove((char *)ptr, (char *)ptr + 4, -2);
+	kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
 	char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
 	kmalloc_oob_memset_4();
 	kmalloc_oob_memset_8();
 	kmalloc_oob_memset_16();
+	kmalloc_memmove_invalid_size();
 	kmalloc_uaf();
 	kmalloc_uaf_memset();
 	kmalloc_uaf2();




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570190718.19702.125.camel%40mtksdccf07.
