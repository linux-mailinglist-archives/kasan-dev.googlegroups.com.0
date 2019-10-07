Return-Path: <kasan-dev+bncBAABBR7J5PWAKGQEO5LD5WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 16438CDD08
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Oct 2019 10:18:17 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id x62sf14197989qkb.7
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 01:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570436296; cv=pass;
        d=google.com; s=arc-20160816;
        b=FCZMxPQ3t39F1xYSELO+Z1s2G82JZSpJvwcOYfujNvtOSu+oTss+P6SkcmEkpGQxek
         yMRZf/xfAKjLjEZ7i56G7eSRNBL0kjW6yUAEeWELRup+DKklXpFTwRxf+QdNt3SJvjQF
         7g8vwvNuewkinIFveAVFSiCMtpqtXOXqA0E4wdd7eaUXfFN3/KcSblE05Rfc48Rvd1gD
         QAL6OJbR8hTZ4nCes3u/tSIulSyZIpsZ/Kb4fz9+eVEdu0PDM+JaaAyAlnK/8wZlU4PJ
         zgEVqvK9huPKvMoTOYqvOsxhnW9DN3MJsC3Cc5doYRHs0l/8XDwRv75+hwSvt0r3qqRI
         +3lQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=VUhRvAm7NrrmzhsWMWa2WdlgIHKPO7gY1xWx0heZ5bU=;
        b=sI3Q/Vf8YX9CpT4VekeACoaBYHNwVYLs+xh+/FF7cgXlfISV4ELKO5aGfDZAsafasI
         Oxo78SS3eIuuwiCdRonyAq2OcMr7/7Gmxn7uAPGwJB7SrRBQATeKKuFk+yYD9J6ZZXrw
         6YGarVNdSDELz/UkAwIDsbXTI8jVFFnvBicZGGdtfHoe7tBGubsLwU0XRpZHB1c9OOYH
         qfQhhLijjFUPMYV9QoWjB1xsbCEv/NCs9Xwl6sNYc7ugsvB54cIQHVqZK3x7Iq1bKWGd
         roWSkHFJMdQzHdSzHKScxoaRSyX0ozLn2CsUk2KYlkfoMRQsysSWnmfPCG1I6Pk+QLF8
         5g2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VUhRvAm7NrrmzhsWMWa2WdlgIHKPO7gY1xWx0heZ5bU=;
        b=G9O+T8In2FWIM+hFY7tMsUm4fQfVfpqCMNjFTM6PW0gJ5bx/jEipicQrthgnBMESuD
         sad52TSdjDwCmTBnB7+KlthYKkx3JVM0A347lmspc3uyGfiRhnvZ8sp+wkqKTqvTloFO
         RJcMKRCUzlH2bDDfBeuK7/vd7dLA+6vg1dzMgncpozgecGY6TNjn+v/0uozpebEE2cgG
         PO0bU1nrlconpCoV2bxPsT7ZNJEYE3/XW3s8KOo+XO++AHXj+A9oVFfBVq4hjEnZbAJp
         EnbNKit80lfRF+u/K1glXmrGKdk78NayLHgpGRFIaQbMVIFlUdePcKwo2X4k4R4M29fo
         2MBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VUhRvAm7NrrmzhsWMWa2WdlgIHKPO7gY1xWx0heZ5bU=;
        b=kH32ZnrO7YeYRiWBXEKtzF46yUKGcnUtRbyuCObatp8j7pdR9YLjsmmWyDo+ckXfSH
         k/AQsON4HTeTBv+kfnxEcZqiAVthdOvu82ntygLDhKLUBS6ah/sBgG4umkd6h0OFK3Ez
         iez8DYrX9eg3UrxFUQFsPHyA3monWYRmRdWpTJVSGFy7rHbAByYq+Oh8GiTsya6nbrXk
         wz+9J4Inm0+2xbNpA9wYtcmVGWx8YqCMwT4Qm1pEerOZ+gUYqlw3PY1/pvzUpsZYr6+M
         1i0bEjTV24GkkQ24LHHgUB+pji7+js7f4ZyOaKhol5VWYvM3pgabaBtxtwnZg7gUQydZ
         5KUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV63yxV2ayzLgyP9diyVu8RBvpIYAQaXe7uAEgETAaJIhR8weje
	8G+915SLmm9bg0bH9eNoXjY=
X-Google-Smtp-Source: APXvYqydo1khb+d3pJghynjeUKuUBCUqo7puTmFAU+9bw0TCoPHOQnl5dza7kvLyg7VekiLAY+rQGA==
X-Received: by 2002:a37:ad8:: with SMTP id 207mr22850800qkk.38.1570436296014;
        Mon, 07 Oct 2019 01:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aed6:: with SMTP id n22ls2218693qvd.6.gmail; Mon, 07 Oct
 2019 01:18:15 -0700 (PDT)
X-Received: by 2002:ad4:41cf:: with SMTP id a15mr13951574qvq.233.1570436295748;
        Mon, 07 Oct 2019 01:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570436295; cv=none;
        d=google.com; s=arc-20160816;
        b=g/47qpxveoigbGxk7SjTJZ9BWqakhyrFT9RTE1gDNJX9xnwgqIORlPwsBAlCkiVz6k
         0U+tYKGmBHftMSrD2ZU+//bvaUsF9/eNkNxgYLMMsJYjCB7/S6a92IzIU8QORhxuJMS1
         7Gj4AHj1eG9eLdbzfYhFnOv49CzFHnlHwQg7mwRzsDuGdUxLVcJilugOnCx6OaaGKOsT
         mgEInajdjhGgjP3iJq6kzsvDvYjWhx2ktihk/7F2JbLh0OTUNnPK+qu2Qh9V7KMvr7Xw
         cdZo0InSDhO/YG10fxLz6O7e5HLKwMfN25upDKhmFt3D6GI5mpi4f6glGedhC0nZa7UT
         ZiRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=fGsI+U8GgGOdjnnxL1ItkmDZj0iQ3fkf/GtmC76Bre8=;
        b=Me/GIwUMlD3qWSV69Z2gKk5wWeDbd+FEu27fuDcfP+9yQrVIZdqSdZ97Axz/Fplrja
         jc9wuCLOTSYIqsiBil+0B07gDFtLkNPGHXkjHIJAERwQwCOx5g0u2evBQrHJ5IC+a8nk
         vp6tdcir6VKjd70qBYp8H4MicqxLeNAeIC9dcVTfelrFebu6yRHsA5uw5aEWRMmXm8di
         f9jefJVciRR4qoQzSDqxrisPvUOPHCu/mfhnLRhfVNiQgg9PxB4ajqz0iE+wuaNMbF2I
         6xs4Ude3OxSqqxMvubO1vzbOlkGjLeAoXKGMLViC7M4tEfPIiRYD/Z9pD2DVY0qgYUSu
         j0DQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id u44si1327752qtb.5.2019.10.07.01.18.14
        for <kasan-dev@googlegroups.com>;
        Mon, 07 Oct 2019 01:18:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 0cf3765dccb24f49a820570fd5e60d7b-20191007
X-UUID: 0cf3765dccb24f49a820570fd5e60d7b-20191007
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 2055440891; Mon, 07 Oct 2019 16:18:10 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 7 Oct 2019 16:18:07 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 7 Oct 2019 16:18:07 +0800
Message-ID: <1570436289.4686.40.camel@mtksdccf07>
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
Date: Mon, 7 Oct 2019 16:18:09 +0800
In-Reply-To: <CACT4Y+aho7BEvQstd2+a2be-jJ0dEsjGebH7bcUFhYp-PoRDxQ@mail.gmail.com>
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

On Mon, 2019-10-07 at 09:29 +0200, Dmitry Vyukov wrote:
> > > > diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
> > > > index 969ae08f59d7..19b9e364b397 100644
> > > > --- a/mm/kasan/tags_report.c
> > > > +++ b/mm/kasan/tags_report.c
> > > > @@ -36,6 +36,16 @@
> > > >
> > > >  const char *get_bug_type(struct kasan_access_info *info)
> > > >  {
> > > > +       /*
> > > > +        * if access_size < 0, then it will be larger than ULONG_MAX/2,
> > > > +        * so that this can qualify as out-of-bounds.
> > > > +        * out-of-bounds is the _least_ frequent KASAN bug type. So saying
> > > > +        * out-of-bounds has downsides of both approaches and won't prevent
> > > > +        * duplicate reports by syzbot.
> > > > +        */
> > > > +       if ((long)info->access_size < 0)
> > > > +               return "out-of-bounds";
> > >
> > >
> > > wait, no :)
> > > I meant we change it to heap-out-of-bounds and explain why we are
> > > saying this is a heap-out-of-bounds.
> > > The current comment effectively says we are doing non useful thing for
> > > no reason, it does not eliminate any of my questions as a reader of
> > > this code :)
> > >
> > Ok, the current comment may not enough to be understood why we use OOB
> > to represent size<0 bug. We can modify it as below :)
> >
> > If access_size < 0, then it has two reasons to be defined as
> > out-of-bounds.
> > 1) Casting negative numbers to size_t would indeed turn up as a "large"
> > size_t and its value will be larger than ULONG_MAX/2, so that this can
> > qualify as out-of-bounds.
> > 2) Don't generate new bug type in order to prevent duplicate reports by
> > some systems, e.g. syzbot."
> 
> Looks good to me. I think it should provide enough hooks for future
> readers to understand why we do this.
> 
Thanks for your review and suggestion again.
If no other questions, We will send this patchset.


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
 mm/kasan/generic_report.c | 12 ++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 12 ++++++++++++
 6 files changed, 60 insertions(+), 5 deletions(-)




commit 5b3b68660b3d420fd2bd792f2d9fd3ccb8877ef7
Author: Walter-zh Wu <walter-zh.wu@mediatek.com>
Date:   Fri Oct 4 18:38:31 2019 +0800

    kasan: detect invalid size in memory operation function
    
    It is an undefined behavior to pass a negative numbers to
memset()/memcpy()/memmove()
    , so need to be detected by KASAN.
    
    If size is negative numbers, then it has two reasons to be defined
as out-of-bounds bug type.
    1) Casting negative numbers to size_t would indeed turn up as a
large
    size_t and its value will be larger than ULONG_MAX/2, so that this
can
    qualify as out-of-bounds.
    2) Don't generate new bug type in order to prevent duplicate reports
by
    some systems, e.g. syzbot.
    
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
index 36c645939bc9..ed0eb94cb811 100644
--- a/mm/kasan/generic_report.c
+++ b/mm/kasan/generic_report.c
@@ -107,6 +107,18 @@ static const char *get_wild_bug_type(struct
kasan_access_info *info)
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has two reasons
+	 * to be defined as out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 * a 'large' size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 * 2) Don't generate new bug type in order to prevent duplicate
reports
+	 * by some systems, e.g. syzbot.
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
index 969ae08f59d7..012fbe3a793f 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,18 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+	/*
+	 * If access_size is negative numbers, then it has two reasons
+	 * to be defined as out-of-bounds bug type.
+	 * 1) Casting negative numbers to size_t would indeed turn up as
+	 * a 'large' size_t and its value will be larger than ULONG_MAX/2,
+	 * so that this can qualify as out-of-bounds.
+	 * 2) Don't generate new bug type in order to prevent duplicate
reports
+	 * by some systems, e.g. syzbot.
+	 */
+	if ((long)info->access_size < 0)
+		return "out-of-bounds";
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570436289.4686.40.camel%40mtksdccf07.
