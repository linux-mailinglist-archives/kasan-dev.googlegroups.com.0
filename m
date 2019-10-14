Return-Path: <kasan-dev+bncBAABBPFWSLWQKGQESEANU2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 35D28D66B0
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:58:54 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id u131sf14004604ywa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:58:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571068733; cv=pass;
        d=google.com; s=arc-20160816;
        b=UOlKtbsvgn8QGODIyAEtwsvPYu06Uo9UhsTXwYi2kXawg+jVOkgOv0WqqO74BJwUiN
         lS8Z2dlFdf4GMRn0yQv4EzM9ch/0C68JoxJ7ELiQqkuN5lJrhbC6lEli0Zw5lgGjamcz
         RuJxybheOM5Y1tSFMT72Yf7wSZrBPpVB0ajCjiDblZwh7stKJsqzo2F/FwFdlYgRRiJj
         H5acjDjxdFGHhF5xWx7sbBTl/CHowoyDx2tNO3tH5+S1zoaFxUNtGUmTJhO5Q7efW4h6
         DOUVqxHCWXKCYiyroQBPcI8AEwx39Y7O3/vsXXEbjIscEF22W+IKVDSgT1+hpqZP6ir2
         4WfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=iYR0jW21pSdX6GxkNUs2cPPaztcAxB4gJwsZyjkiewA=;
        b=glV68BIoRx6eEJwT53fYxr6wtEHxdogK2v1q0r6W60LfoFcw+5YrXYLVgfYXf33ygE
         Io03hpi/fGluneTWelXr6IhznuksFPByjvUXdzgpRZO04MI5M/cAUsFoUNowYaOAetJN
         qKBDebWhEo+uY/S9VZHP/pzn3Dv9ubeCPsS8/DYi/udn9SZvDV/xVP6x1aebSlfYISaK
         QxQZzj0xg2XjTOU7A5GeMyLskQ1EazkZepQqctpp9lyYMSx6/cpiVMiRaFb51ePSMzxn
         Tjh7RD8CemOJpP1mit0729Xzhvx/hOGdsMMp86v8A3UZ+gthoxCFzA0bDIQruULvvS6N
         KbIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iYR0jW21pSdX6GxkNUs2cPPaztcAxB4gJwsZyjkiewA=;
        b=B1Q76qEYnn1wntXa1Lar34Bc0tRYsj/K/KlflGBaIooVIuU2jMAvUksC663fknZJeL
         wo5fFXci121a3oHF3owo5RlWzZfCvFSeJAlfqUwWlbTZmSH3scv11RcAI0ypIEcq787J
         oxyCqTYKsPBFtzTZ4B5YZiv0IHZjJul8GGC2Gw3nK8jPXXM5TpRBts9ed9smOtvz+CwD
         gxemrkjHthDv+W56slZNOPFrhttGEvWPLNhqhezeoubLy/EuKRR/ChydMqPIbhkvPwZp
         jUyuzjtWZU6mdmmdxPzXH/vm/GEJi2CNT64m/FGQu/DSM2AI1WspQ+E6yJIA+ElJNWMR
         aUNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=iYR0jW21pSdX6GxkNUs2cPPaztcAxB4gJwsZyjkiewA=;
        b=AaTmSTaJIIty+Uaps8MixlZVt7Rs1bHL1pT6T/xEDhdZiF2uKeCcx/wK/SAU0tFcd2
         Hrz4n6VXPsbHT/ksbO9RjEcBegGRUPoWEEC95sRBh0wWobdttZ1LGdS7xYQyZ7yiXQlh
         5ZupPhkzgX5J/IZl3PPaa3OUZMpRgNOyzZz34VsGxC1noBNKuPi/Ekt7M3XnWACIJgP5
         mKP41gsCHTWCbQRnYanU4rjRtpVvP3zqWENwH/2B6BpmkKmZyNo8iH1zgdB6Zq95A6+3
         kf+n7DZqtS810MHPU/hweU+ffi6eIzihevS6fqoDcPhs4d6F+wEGtUCP/rK1lr7hWuwR
         QgHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWdzdAjbhqc3JtDT+fr2Zyah0j72aR6S6jpRcNF/ft7oup/SoDP
	euopFmx4sZ7+TVkhcPmvJzw=
X-Google-Smtp-Source: APXvYqxHs2brbREcjFm9FTwbxr5+OnMoushCUConltOqPOJnBuTtbC6yUqcd90J8j+Q+cXLLlmeqfw==
X-Received: by 2002:a81:1b4e:: with SMTP id b75mr13150219ywb.248.1571068733040;
        Mon, 14 Oct 2019 08:58:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6e54:: with SMTP id j81ls2370029ybc.11.gmail; Mon, 14
 Oct 2019 08:58:52 -0700 (PDT)
X-Received: by 2002:a25:d144:: with SMTP id i65mr20289610ybg.266.1571068732736;
        Mon, 14 Oct 2019 08:58:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571068732; cv=none;
        d=google.com; s=arc-20160816;
        b=XZHZYS04u3HmrSQ+QJTFUqPTVRFXb26gXsgZ4QhcEGdUFx4cNnKvCWhI/J9IFpue+T
         DSJUNFAgko/EDRrEwDbiDtQSutA43tkLbDVGPrWQ36NYdkVcfsXgFopIsmVjzHjV28Ef
         ElvMzmQwTPZIomaVzEjowLFcCOycQ9d+Ltf1TxjeZyr8odRvadaYuG422IiT9vHuSPQx
         N1R3uYprdzokgE31DMBDF2lVm9BcazrESNs78/yVk4cZ2IDhLpq9tFE5uyiursLEDNdU
         6tbIYhVb2KnLwutWT+5J40DlecLyaqPVyhjs4lZ7sal3vntLwQRjN76ZeyVoVikPsMTb
         e5ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:subject:cc:to:from;
        bh=Xl1vSam6onJuZAaCaSeXijSeV5qrrQcv6dHC1VtmAxo=;
        b=qOWfO7q6vJW0vbqbRVNxGO+4Ly/92PY0ePPNP+nPlgmaAbpZTN2r1evvXTFMjvgZG9
         F7JOmz5DOHoEy2FMSIjxqYstJEpct9C9MTgO45K6IrciGqqnO07e0sySQSUo7IE92gph
         QcYpof+2MNf5vqptFNKwh3okwj5nALGz0hFLQkJ9uqeW1Jivsm+hml+snq8nMiX6GUxo
         k4NKCFPDyEYGuroe6H/MsYsErSl0WTKnhmCmbd0fTHN9eI47Vo1mhX/nzWys4zUYmpOD
         j2RxTVGYU++Nt4a2EN5a0tyCDpD2aDGYHmVG9EwIMb3wgT7Hppedo312I9tq/0UKV6kA
         KB4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id t73si2010053ybi.4.2019.10.14.08.58.51
        for <kasan-dev@googlegroups.com>;
        Mon, 14 Oct 2019 08:58:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 6f928f6db025499eabd9cee63b0619c1-20191014
X-UUID: 6f928f6db025499eabd9cee63b0619c1-20191014
Received: from mtkmrs01.mediatek.inc [(172.21.131.159)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1125206795; Mon, 14 Oct 2019 23:58:49 +0800
Received: from mtkcas08.mediatek.inc (172.21.101.126) by
 mtkmbs07n2.mediatek.inc (172.21.101.141) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Mon, 14 Oct 2019 23:58:47 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas08.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Mon, 14 Oct 2019 23:58:45 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko
	<glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Matthias Brugger
	<matthias.bgg@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, <wsd_upstream@mediatek.com>, Walter Wu
	<walter-zh.wu@mediatek.com>
Subject: [PATCH v2 1/2] kasan: detect negative size in memory operation function
Date: Mon, 14 Oct 2019 23:58:45 +0800
Message-ID: <20191014155845.26783-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
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

KASAN missed detecting size is negative numbers in memset(), memcpy(),
and memmove(), it will cause underflow bug, so needs to be detected
by KASAN.

If size is negative numbers, then it has three reasons to be
defined as heap-out-of-bounds bug type.
1) Casting negative numbers to size_t would indeed turn up as
   a large size_t and its value will be larger than ULONG_MAX/2,
   so that this can qualify as out-of-bounds.
2) If KASAN has new bug type and user-space passes negative size,
   then there are duplicate reports. So don't produce new bug type
   in order to prevent duplicate reports by some systems (e.g. syzbot)
   to report the same bug twice.
3) When size is negative numbers, it may be passed from user-space.
   So we always print heap-out-of-bounds in order to prevent that
   kernel-space and user-space have the same bug but have duplicate
   reports.

KASAN report:

 BUG: KASAN: heap-out-of-bounds in kmalloc_memmove_invalid_size+0x70/0xa0
 Read of size 18446744073709551608 at addr ffffff8069660904 by task cat/72

 CPU: 2 PID: 72 Comm: cat Not tainted 5.4.0-rc1-next-20191004ajb-00001-gdb8af2f372b2-dirty #1
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

Changes in v2:
fix the indentation, thanks for the reminder Matthew.

Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Reported -by: Dmitry Vyukov <dvyukov@google.com>
Suggested-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 mm/kasan/common.c         | 13 ++++++++-----
 mm/kasan/generic.c        |  5 +++++
 mm/kasan/generic_report.c | 18 ++++++++++++++++++
 mm/kasan/tags.c           |  5 +++++
 mm/kasan/tags_report.c    | 18 ++++++++++++++++++
 5 files changed, 54 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6814d6d6a023..16a370023425 100644
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
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memmove(dest, src, len);
 }
@@ -119,8 +121,9 @@ void *memmove(void *dest, const void *src, size_t len)
 #undef memcpy
 void *memcpy(void *dest, const void *src, size_t len)
 {
-	check_memory_region((unsigned long)src, len, false, _RET_IP_);
-	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))
+		return NULL;
 
 	return __memcpy(dest, src, len);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 616f9dd82d12..02148a317d27 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -173,6 +173,11 @@ static __always_inline bool check_memory_region_inline(unsigned long addr,
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
@@ -107,6 +107,24 @@ static const char *get_wild_bug_type(struct kasan_access_info *info)
 
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
@@ -86,6 +86,11 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
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
-- 
2.18.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014155845.26783-1-walter-zh.wu%40mediatek.com.
