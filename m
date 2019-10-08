Return-Path: <kasan-dev+bncBAABBI6T6DWAKGQE36NBENQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id CAC2FCF290
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 08:16:04 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id q127sf12942597pfc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 23:16:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570515363; cv=pass;
        d=google.com; s=arc-20160816;
        b=oB+XLH5oM01tIOEvO8f4NoRV6LyfJ+sss0i8HshU4aPit3ofEWlAnRjQYqCSSDI+uv
         sYO81pMzJfNhHU0ef59JId6yn8jbfz25DOLS50WRA9VabDflBF3BSOxAuKTpXkVf/FOm
         cHa4VpEC6Btth5hPJA9dR56Afd5MDG1hLaQO6hjV/s0RF/RhdhQmk+HUBWPxURA52b8f
         bx7aCpCO2aBYqPAa94VBJuwAAYJZxXvtDJjN0MOFbDCchjfkhGSsLv8d8r/d9SS2s8gY
         dixd8XJL3TGUCWqyGRAs8LJfXJ38mHyXeJ1lpb+Umq2V22nuz8NKhUclYRg5g+dphhMt
         9NTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=LvgFyxrZHCph+Gy4lRLZ+BVaYZPCwheDoi7pJtNV2io=;
        b=BCosyGZm8NuVAfuAMmHtiCeuPgKGpYJPTE6k8gktiTbrtV6a+LarOR5z3L11rHP0It
         ut/HdKtNnGWkDs7UoPSFPlQpkveeYaCHS5aQkOoE40RB4DnwcT5z4RF77t4MOiVqRGpS
         bZWN9plskChoRf11rlN0wTPmFBo8q/Q/kC69ydAIgVS2ZbJLvqVPHxs5UsMbIlEz+3h7
         oeaKOdHad1GAK2ki51skyIf84v9RbiyRmKUbjugCxS66Xjxc6m25+TClfdoQnckn+9bu
         0N+bQc4NLbip0f8FCtVuZ5RfLlTFJjWZUAhzIJSC6dmKQxJEAGJZUpQdCMuqncHUHrU+
         I9mA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LvgFyxrZHCph+Gy4lRLZ+BVaYZPCwheDoi7pJtNV2io=;
        b=BJKbkRR9C8qYQ28OI4SfPeJPugjP5olrM5IMJBktvAi4aGlurwqli4gn0HMqPJ228G
         Zus5jduMQg90bROlAOYTenOZ6kZxnaBvJ0rK4n4LsViT/1VvTQN6WHSFgSu+suuQKIpJ
         NiqGN8/rujOi3kRYzdpNblefykQY3c/CDbAmy7RHcUQpc7/XyZRk8J1C2JlGV2Sy4FRA
         uRKuriJEZsxPsCVcsfawoloP11gi7SIYVrnwcvpvFrkvAOB5oqwdf8QK7120D2epyQLj
         cngdbWdKZgkN2iNRRNpoxBiVManCHUlLJwBbNJbYOLLN2gWeDjXwAJ4ePQ6jmA/UaVVa
         8fZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LvgFyxrZHCph+Gy4lRLZ+BVaYZPCwheDoi7pJtNV2io=;
        b=BebmxNsbxb0hEEQVlZwrVVbgO8yZ1jMUqPSGkoXMksVIp9XxB4R+HYOPFtpdDJyCSe
         C2iTSLEWTtBh6GMzuBDnPulv+TkMXtcSQ5iFJoquWWNc+GZPjr7FLqDzz2lppDKilm5O
         ZkRgbRJMyMm0q17J7kWD0vjMU12OfRnKqs6NMLu2krh6JMppCTCFG5PENWpfnXkJPQBf
         EuXgS14MSD+M2wqny8OLOCr5e6io5hgZ5UXW9kJaky5+ykWTBRrP5oN7TBsoqW70Cdqd
         i92eXGBWVDx2qWygeEPL6eIihIIRkTuwlcBOs8472q476iyzKSsKIMBFooZRxkpwaums
         /dxw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWKYv+7zoEK23pNqhnjbbZ9NJYARag0nO5+fAhNmTO6SY1svYTC
	8Zvvz7j1W9M+TBx6WKuceOg=
X-Google-Smtp-Source: APXvYqxhuLbglJbLjXrP+ZkGLvW2WrhEYxTp3rPvuxrPRQSHwwMe+Jc2qR0LUuwoDA6zaJKaK98Yiw==
X-Received: by 2002:a62:2643:: with SMTP id m64mr37504237pfm.76.1570515363065;
        Mon, 07 Oct 2019 23:16:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4301:: with SMTP id j1ls502411pgq.14.gmail; Mon, 07 Oct
 2019 23:16:02 -0700 (PDT)
X-Received: by 2002:a63:4622:: with SMTP id t34mr799083pga.242.1570515362660;
        Mon, 07 Oct 2019 23:16:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570515362; cv=none;
        d=google.com; s=arc-20160816;
        b=jZv6gY15NVwG+X8TyQUwkEj2XjsUPUS0vJCUIrEqFoQ3Fsiq5nYrNBYcooLkLED499
         sQf0UZ9LmH7MTbPH3jJX/2wCX4Jh31UuFc9QPm2MmCww1ilssZy9EtNP2UAfqgfeDmz3
         eyNEtBc78Yi3cCxSOa0SzZZX3++r7KOCYjF6yEeaRLXbTRU53gQApqt7dY1SCSATrZsy
         F7+lk1jgcemHW3iGuddkxbwxiNAFwYjEdtKcy9W9jn6AzpqCz3J83pAfolCo6GUcIXkZ
         7h/TPO8FdVEE+hKonLkODahwFmthxeXaMPypXo+tz5GZPRUW/Lp7/hKSKs3HMf/H3JUV
         MV6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=NSwO3E9oq/DJeyiAvMigW0B/qosnnVkm6/Eg/2e/oGw=;
        b=pvTQEFzoHcOhWrP2/VneTvkUaysZWxL8axmzyU0D+W8WzSo6vq8Qb0WdwT3nm7VrUb
         58tRS0KcniC/SZV2FyusJHadYfh0sB/A/V9s/aQ/jpsRSlqpAaI2K5dW9/8ZO1UKC0Ls
         w1woosQXGf+CRfIce5hDg4Ojx+0zWIXIgN1h1qkLZ3deOqynHJedHARPlWy8YpySOYN5
         2F2jgBslXSoAQb8MP5Z9Y0wMMl1CcacNGOXGqj8tpDwHrmydXlW/r1l+wx5VUW4zw/QI
         BvLGSobGKUNUzzkD30CbNjetAgX3VN9bVpEDn0qHrXDCSxTDQV28I0KLIVgw6zkX3qYg
         aTNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id d3si932288plr.4.2019.10.07.23.16.02
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2019 23:16:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: b2601c2a9cd044218aef01715ebc0982-20191008
X-UUID: b2601c2a9cd044218aef01715ebc0982-20191008
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 127426954; Tue, 08 Oct 2019 14:16:00 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 8 Oct 2019 14:15:58 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 8 Oct 2019 14:15:58 +0800
Message-ID: <1570515358.4686.97.camel@mtksdccf07>
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
Date: Tue, 8 Oct 2019 14:15:58 +0800
In-Reply-To: <CACT4Y+bJFoQPJ4QbGNjAuqiZx-FFsuLansxkhX3kwLOc19NvcA@mail.gmail.com>
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
	 <1570190718.19702.125.camel@mtksdccf07>
	 <CACT4Y+YbkjuW3_WQJ4BB8YHWvxgHJyZYxFbDJpnPzfTMxYs60g@mail.gmail.com>
	 <1570418576.4686.30.camel@mtksdccf07>
	 <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
	 <1570436289.4686.40.camel@mtksdccf07>
	 <CACT4Y+Z6QObZ2fvVxSmvv16YQAu4GswOqfOVQK_1_Ncz0eir_g@mail.gmail.com>
	 <1570438317.4686.44.camel@mtksdccf07>
	 <CACT4Y+Yc86bKxDp4ST8+49rzLOWkTXLkjs0eyFtohCi_uSjmLQ@mail.gmail.com>
	 <1570439032.4686.50.camel@mtksdccf07>
	 <CACT4Y+YL=8jFXrj2LOuQV7ZyDe-am4W8y1WHEDJJ0-mVNJ3_Cw@mail.gmail.com>
	 <1570440492.4686.59.camel@mtksdccf07> <1570441833.4686.66.camel@mtksdccf07>
	 <CACT4Y+Z0A=Zi4AxEjn4jpHk0xG9+Nh2Q-OYEnOmooW0wN-_vfQ@mail.gmail.com>
	 <1570449804.4686.79.camel@mtksdccf07>
	 <CACT4Y+b4VX5cW3WhP6o3zyKxHjNZRo1Lokxr0+MwDcB5hV5K+A@mail.gmail.com>
	 <1570451575.4686.83.camel@mtksdccf07>
	 <CACT4Y+bJFoQPJ4QbGNjAuqiZx-FFsuLansxkhX3kwLOc19NvcA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
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

On Mon, 2019-10-07 at 15:33 +0200, Dmitry Vyukov wrote:
> On Mon, Oct 7, 2019 at 2:33 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > On Mon, 2019-10-07 at 14:19 +0200, Dmitry Vyukov wrote:
> > > On Mon, Oct 7, 2019 at 2:03 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > > My idea was just to always print "heap-out-of-bounds" and don't
> > > differentiate if the size come from userspace or not.
> >
> > Got it.
> > Would you have any other concern about this patch?
> 
> 
> Last versions of the patch looked good to me except for the bug title.
> The comment may also need some updating if you change the title.

Updated, thanks again again.


The patchsets help to produce KASAN report when size is negative numbers
in memory operation function. It is helpful for programmer to solve the 
undefined behavior issue. Patch 1 based on Dmitry's review and
suggestion, patch 2 is a test in order to verify the patch 1. 

[1]https://bugzilla.kernel.org/show_bug.cgi?id=199341 
[2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/ 

Walter Wu (2): 
kasan: detect invalid size in memory operation function 
kasan: add test for invalid size in memmove


 lib/test_kasan.c          | 18 ++++++++++++++++++
 mm/kasan/common.c         | 13 ++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 17 +++++++++++++++++
 6 files changed, 71 insertions(+), 5 deletions(-)


commit 1eb58140ac67debabdca705bafaadea934eb7820
Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
Date:   Fri Oct 4 18:38:31 2019 +0800

    kasan: detect negative size in memory operation function
    
    It is an undefined behavior to pass a negative numbers to
    memset()/memcpy()/memmove(), so need to be detected by KASAN.
    
    If size is negative numbers, then it has three reasons to be
    defined as heap-out-of-bounds bug type.
    1) Casting negative numbers to size_t would indeed turn up as
       a large size_t and its value will be larger than ULONG_MAX/2,
       so that this can qualify as out-of-bounds.
    2) If KASAN has new bug type and user-space passes negative size,
       then there are duplicate reports. So don't produce new bug type
       in order to prevent duplicate reports by some systems (e.g.
syzbot)
       to report the same bug twice.
    3) When size is negative numbers, it may be passed from user-space.
       So we always print heap-out-of-bounds in order to prevent that
       kernel-space and user-space have the same bug but have duplicate
       reports.
    
    KASAN report:
    
     BUG: KASAN: heap-out-of-bounds in kmalloc_memmove_invalid_size
+0x70/0xa0
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
index 36c645939bc9..52a92c7db697 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct
kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has three reasons
+	 * to be defined as heap-out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 *    a large size_t and its value will be larger than ULONG_MAX/2,
+	 *    so that this can qualify as out-of-bounds.
+	 * 2) If KASAN has new bug type and user-space passes negative size,
+	 *    then there are duplicate reports. So don't produce new bug type
+	 *    in order to prevent duplicate reports by some systems
+	 *    (e.g. syzbot) to report the same bug twice.
+	 * 3) When size is negative numbers, it may be passed from user-space.
+	 *    So we always print heap-out-of-bounds in order to prevent that
+	 *    kernel-space and user-space have the same bug but have duplicate
+	 *    reports.
+	 */
+	if ((long)info->access_size < 0)
+		return "heap-out-of-bounds";
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
index 969ae08f59d7..f7ae474aef3a 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,24 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has three reasons
+	 * to be defined as heap-out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 *    a large size_t and its value will be larger than ULONG_MAX/2,
+	 *    so that this can qualify as out-of-bounds.
+	 * 2) If KASAN has new bug type and user-space passes negative size,
+	 *    then there are duplicate reports. So don't produce new bug type
+	 *    in order to prevent duplicate reports by some systems
+	 *    (e.g. syzbot) to report the same bug twice.
+	 * 3) When size is negative numbers, it may be passed from user-space.
+	 *    So we always print heap-out-of-bounds in order to prevent that
+	 *    kernel-space and user-space have the same bug but have duplicate
+	 *    reports.
+	 */
+	if ((long)info->access_size < 0)
+		return "heap-out-of-bounds";
+
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	struct kasan_alloc_meta *alloc_meta;
 	struct kmem_cache *cache;





commit fb5cf7bd16e939d1feef229af0211a8616c9ea03
Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
Date:   Fri Oct 4 18:32:03 2019 +0800

    kasan: add test for invalid size in memmove
    
    Test size is negative vaule in memmove in order to verify
    if it correctly get KASAN report.
    
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
+       char *ptr;
+       size_t size = 64;
+
+       pr_info("invalid size in memmove\n");
+       ptr = kmalloc(size, GFP_KERNEL);
+       if (!ptr) {
+               pr_err("Allocation failed\n");
+               return;
+       }
+
+       memset((char *)ptr, 0, 64);
+       memmove((char *)ptr, (char *)ptr + 4, -2);
+       kfree(ptr);
+}
+
 static noinline void __init kmalloc_uaf(void)
 {
        char *ptr;
@@ -773,6 +790,7 @@ static int __init kmalloc_tests_init(void)
        kmalloc_oob_memset_4();
        kmalloc_oob_memset_8();
        kmalloc_oob_memset_16();
+       kmalloc_memmove_invalid_size();
        kmalloc_uaf();
        kmalloc_uaf_memset();
        kmalloc_uaf2();



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570515358.4686.97.camel%40mtksdccf07.
