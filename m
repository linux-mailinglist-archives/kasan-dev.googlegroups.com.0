Return-Path: <kasan-dev+bncBAABBWW4SKUQMGQEPP2IKBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1635D7BF084
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Oct 2023 03:52:29 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1c75d501b01sf3089275ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 18:52:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696902747; cv=pass;
        d=google.com; s=arc-20160816;
        b=jBk3WVlyRnWTccC8PzxjTQGJlA1qAZ7b5Oa+X6DD7G9lwdKTMjh8ppq7Q7eWEBz0fw
         eXpeFqMfim7ezGJLU6Bg1aH3jZdfMqf8CYzpvD5r6hQ3M78fDJbKpfgwJUWJ94Tgp754
         dpbTBN7y4hVhsPeRLR1zm/uiS05tI5K5q70Ego5qsl/FR4artD98/ILnEnxb3N6Yju+g
         uJ/bqmVSQ1KgoWO9VIPO2gfiDQCH8kGzfiG88LKa9Ml34LgnaIlrI8qXmhbic6mRCbJz
         HP/Pj8dJhrR1YWFI+kpx8vIEy50/1qI4/Zwx7Z2tc8ap2djLMqJiTx1aDVKIlO60smx5
         QbgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=RtS9//vno78J2kPcjVK9d5DtZjdeY2nj6aFzTkuIoSM=;
        fh=n6kUzP5LKQBZZaJd6g4YOH+s7337rIzf2mByIt/u9HY=;
        b=Ueq0Fqt69ByRZe4PQvmWUUiNFfEMt+Bz+CdfziSoqwApVImWVr7mTA/y2nyYTvB4II
         aZNIDaA80tHYgYtYyugjPiaFUtVbN5dGIRH+vIbqbttsoEbnaP59sDjn+XYBtusR1Ute
         78DXBj0t16zHUZbIBEFCZd5fnB7EeUd2QRtGKFQ2g1ttLkCh1sqnsk25G/He4Lp5Chqy
         l7cPYrkAxe7CCcf8IHuo20vX1J1U7x3nKzSbWilF+wsVuQXyAtVraeFdIOZpjgEssrGK
         xgUQ1iJAV0PO3KbrVmcJBmV+MS7g52K3tzZgkN+8qtkSeelAImh4usgw9fT5ytvmi3Z+
         RCxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZTqiasz2;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696902747; x=1697507547; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RtS9//vno78J2kPcjVK9d5DtZjdeY2nj6aFzTkuIoSM=;
        b=MT/RJ5ZIqd7U8XN2PfOppVyoETN/+O969QzOnsdKWK97oKardbcvFrBSES7cYkfyCh
         iK9jLinESv5BqAAGGIlkkGEzh6xZCaTgShqom69YCT/Q3y8ZxD7HQKG6j/LCT3yvofc5
         22o6JPSiGjf2coZOyTWtmicIoWl0ac2NJcI8zMU4qLhfJsLHxVKsDjQXxnHHva8zBdvF
         kjDsn8QMlmuNrp5e9clX1IIo7l2vR51JIuQAdxHSG+kjKepeuZZ3ExFITh/eUwYfzH+V
         TPKSfVzjth+DePuRV+NbBdqY3nz9hWmkIpy9nnSNZs/h7we/v+R/9YNJv2UvSaA5f0BD
         5aaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696902747; x=1697507547;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RtS9//vno78J2kPcjVK9d5DtZjdeY2nj6aFzTkuIoSM=;
        b=LbBoVN3h1/bvjp9YNUw/4FEAMbPB5dpdE789s/jIegujh/ZJY4FTvIjp1T9RdaNTFL
         V9+qCM5amT8GRRT2GZ6tfwHdPXktLH7NGlrsKzPYfccnh7lH2Z9pzOUPcn3XDbnkebM2
         Bq7HZ/lM2ADdhjv3E8GVG3LarjTwhuoy+dgS9Ht/x1f9rJ//bjT91LVygChEwakJbukD
         gjxdI95nrFSLRpBZ3S1b7NwuzlvIuyt33u5HXjaXc2eTELwv6BibrzCfTDM7kU0eJfcV
         j6cGoESL7OakmoqpvAuAk4N5Lj8TidvGH39mC8YSzd0ytGcz6oU2MS72W82WYEdK9n8U
         6TUg==
X-Gm-Message-State: AOJu0YwHekZZcWZ+C7Km+4JOhk7GLvNuc7cuCCPjxEa3krHj2sfNH7g/
	QCx4CX33lVKWPYfWvoFRYXo=
X-Google-Smtp-Source: AGHT+IEQg8ISQakeZpZQ1x96IK+mNq2STP66O/F4wpa76HgshPoDQew5Vd8uFFhHM2v7B3O0918fKA==
X-Received: by 2002:a17:903:2448:b0:1bc:29c3:5895 with SMTP id l8-20020a170903244800b001bc29c35895mr849467pls.0.1696902747017;
        Mon, 09 Oct 2023 18:52:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:3929:b0:1bb:6485:798a with SMTP id
 b41-20020a056870392900b001bb6485798als8716987oap.1.-pod-prod-02-us; Mon, 09
 Oct 2023 18:52:26 -0700 (PDT)
X-Received: by 2002:a05:6358:3601:b0:143:2f7e:9b with SMTP id v1-20020a056358360100b001432f7e009bmr14365279rwd.16.1696902746086;
        Mon, 09 Oct 2023 18:52:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696902746; cv=none;
        d=google.com; s=arc-20160816;
        b=zXDIy0ZnvxY8L8jPfxnZjVlmADcIwz2CVryWpkn31BtHu7fGZjXJAeLmNPkDqjYIGK
         lJv0UaLLeXBIXpaGYzYLotiu1dnCZN9Xk4jP9lO9Oy/Lsj7udrU3+qGSFOurvuWHWPQ9
         ku/fjeM8MWqhr1IYaqPi0iRwDJjY5UI2sWjsa5hT2ralr+U658zRPbGajH/EZqPJudAQ
         D1RlmUp//A+mxxBr91yzLmZNsQtn90bSntaBE7c26jfEhqR5kL/vsoDLJ2kuTvG0g88j
         tUQYFRCF29ADnaDv+PbRU2Gf003Ap1ZBn7cAHDGz4hQ70/+h7yFmD6HPD8dS/14+PCP7
         oLkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wu/Ez0DKYV6FvYGCa4Fc/RxN6Eo8oqS6inmrf5HcxU4=;
        fh=n6kUzP5LKQBZZaJd6g4YOH+s7337rIzf2mByIt/u9HY=;
        b=bpzkiPeNddaE+/cP24LxSsPnzZmIfhrpGJuniOCrSVTvIOcRRzh6D9UiOgHx0F7TuU
         L32X6vtdfmeWPzQ1IlSGCZIvLxecE9qixZNAqMLlfmQ3P7lrMhr7cmY0Bl9Qq15721KL
         dgw11NU59jJblgCgrUv4h67lT5A0wjZm8bpbsR0qw4iNgGhYUYF5FUNhJlZ3PoemqQ6N
         Q85Bd1+LXJz5cTOEW7tUQIxmk3+pctYljSfyw2o+xPGtjiEagt8K+ZJhHup7Mb9YullE
         qj1kdahLwesCe8VAS7RiBtiJnusZPTo1BQiohkxoYOYtO1yMrnFoB4M/n+66zyBZ4T5/
         drmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZTqiasz2;
       spf=pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=haibo.li@mediatek.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id nw7-20020a17090b254700b0027691d39091si690634pjb.2.2023.10.09.18.52.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 09 Oct 2023 18:52:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: a547ced8670f11ee8051498923ad61e6-20231010
X-CID-P-RULE: Release_Ham
X-CID-O-INFO: VERSION:1.1.32,REQID:3ad6d434-5716-4d22-8262-c4f4dd7bc0bd,IP:0,U
	RL:0,TC:0,Content:0,EDM:0,RT:0,SF:0,FILE:0,BULK:0,RULE:Release_Ham,ACTION:
	release,TS:0
X-CID-META: VersionHash:5f78ec9,CLOUDID:36329cf0-9a6e-4c39-b73e-f2bc08ca3dc5,B
	ulkID:nil,BulkQuantity:0,Recheck:0,SF:817|102,TC:nil,Content:0|-5,EDM:-3,I
	P:nil,URL:11|1,File:nil,Bulk:nil,QS:nil,BEC:nil,COL:0,OSI:0,OSA:0,AV:0,LES
	:1,SPR:NO,DKR:0,DKP:0,BRR:0,BRE:0
X-CID-BVR: 1,FCT|NGT
X-CID-BAS: 1,FCT|NGT,0,_
X-CID-FACTOR: TF_CID_SPAM_SNR,TF_CID_SPAM_ULN
X-UUID: a547ced8670f11ee8051498923ad61e6-20231010
Received: from mtkmbs14n1.mediatek.inc [(172.21.101.75)] by mailgw02.mediatek.com
	(envelope-from <haibo.li@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-GCM-SHA384 256/256)
	with ESMTP id 825313921; Tue, 10 Oct 2023 09:52:19 +0800
Received: from mtkmbs11n1.mediatek.inc (172.21.101.185) by
 mtkmbs11n1.mediatek.inc (172.21.101.185) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1118.26; Tue, 10 Oct 2023 09:52:17 +0800
Received: from mszsdtlt102.gcn.mediatek.inc (10.16.4.142) by
 mtkmbs11n1.mediatek.inc (172.21.101.73) with Microsoft SMTP Server id
 15.2.1118.26 via Frontend Transport; Tue, 10 Oct 2023 09:52:17 +0800
From: "'Haibo Li' via kasan-dev" <kasan-dev@googlegroups.com>
To: <akpm@linux-foundation.org>
CC: <andreyknvl@gmail.com>, <angelogioacchino.delregno@collabora.com>,
	<dvyukov@google.com>, <glider@google.com>, <haibo.li@mediatek.com>,
	<kasan-dev@googlegroups.com>, <linux-arm-kernel@lists.infradead.org>,
	<linux-kernel@vger.kernel.org>, <linux-mediatek@lists.infradead.org>,
	<linux-mm@kvack.org>, <matthias.bgg@gmail.com>, <ryabinin.a.a@gmail.com>,
	<vincenzo.frascino@arm.com>, <xiaoming.yu@mediatek.com>, <jannh@google.com>
Subject: Re: [PATCH v2] kasan:print the original fault addr when access invalid shadow
Date: Tue, 10 Oct 2023 09:52:16 +0800
Message-ID: <20231010015216.67121-1-haibo.li@mediatek.com>
X-Mailer: git-send-email 2.34.3
In-Reply-To: <20231009170031.a294c11575d5d4941b8596a9@linux-foundation.org>
References: <20231009170031.a294c11575d5d4941b8596a9@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: haibo.li@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZTqiasz2;       spf=pass
 (google.com: domain of haibo.li@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=haibo.li@mediatek.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mediatek.com
X-Original-From: Haibo Li <haibo.li@mediatek.com>
Reply-To: Haibo Li <haibo.li@mediatek.com>
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

> On Mon, 9 Oct 2023 15:37:48 +0800 Haibo Li <haibo.li@mediatek.com> wrote:

> 

> > when the checked address is illegal,the corresponding shadow address

> > from kasan_mem_to_shadow may have no mapping in mmu table.

> > Access such shadow address causes kernel oops.

> > Here is a sample about oops on arm64(VA 39bit) 

> > with KASAN_SW_TAGS and KASAN_OUTLINE on:

> > 

> > [ffffffb80aaaaaaa] pgd=000000005d3ce003, p4d=000000005d3ce003,

> >     pud=000000005d3ce003, pmd=0000000000000000

> > Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP

> > Modules linked in:

> > CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43

> > Hardware name: linux,dummy-virt (DT)

> > pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)

> > pc : __hwasan_load8_noabort+0x5c/0x90

> > lr : do_ib_ob+0xf4/0x110

> > ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.

> > The problem is reading invalid shadow in kasan_check_range.

> > 

> > The generic kasan also has similar oops.

> > 

> > It only reports the shadow address which causes oops but not

> > the original address.

> > 

> > Commit 2f004eea0fc8("x86/kasan: Print original address on #GP")

> > introduce to kasan_non_canonical_hook but limit it to KASAN_INLINE.

> > 

> > This patch extends it to KASAN_OUTLINE mode.

> 

> Is 2f004eea0fc8 a suitable Fixes: target for this?  If not, what is?

> 

Yes, 2f004eea0fc8 is a suitable fix.

All we need is a better crash report for this case.

After commit 2f004eea0fc8 and commit 

07b742a4d912 ("arm64: mm: log potential KASAN shadow alias"),

it is easy to understand the original address when

 out-of-bounds KASAN shadow accesses occur.

Currently, this feature is only available for the KASAN_INLINE case.

As Jann said, it is also suitable for the KASAN_OUTLINE case.



> Also, I'm assuming that we want to backport this fix into earlier

> kernel versions?

My opinion:

 As it is to improve crash report,there is no requirement to backport.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231010015216.67121-1-haibo.li%40mediatek.com.
