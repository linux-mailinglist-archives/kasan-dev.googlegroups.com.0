Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEVZ4X7QKGQEG4R7LXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FF7B2EFE4A
	for <lists+kasan-dev@lfdr.de>; Sat,  9 Jan 2021 08:34:43 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id f19sf12514461ilk.8
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Jan 2021 23:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610177682; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fp9zQ5/WEuQ1PoxCmNIoGIaWslQdSfuAKfv63rwY2PDz4t3jk0HQViTdKlHcrDbxZv
         NeDv/0ZurX0dFwdZL5wmOV26k48CH1BvV94Mfc7OF2ZNCeuFlb8TIy/6PP0JRAhGXmTd
         Gej/BJXZKuo4Z/HFyk5puhyd8BHDY6XofXARjCfSLwaoJHnbZd9dIYWQX23jTwZyoxwv
         9Yw11+CKrfN/ceJ3wFCEdnJiga9ePpVXGgr5dyBCSCPgonNSyy4tP0wrNlvuQaXAD2Sa
         PBzH5sa0fXQtOG3czC0h7yDa/R6/T1fpFWky6uxnPhRucKYJ+TCWY1u4lPv4rd33cGkv
         PMCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1RRE2OlEeg2+Lo638ovwiyHuc3O32s9d2vQAgpnWV3s=;
        b=NO2ge+4Hq463t7ssSEoNYrr61XfOvPzZ0r6kmrYbSCMrgx7SZ6jv0hmVSyvpLakcgG
         sO4odz5V81EFv1/j7GV6aRk97zgb469Yk/VQGApmZp5nac1UlwT1flM7UYuBqzHjan5Z
         g5NKcC+tOBcCsREJpZkE5pDuxD0BrPItcqsRy+ag9dNZ3aWGCvmsaw8VLQLo+QcnZPXf
         Bkhdr056IYv7EYvg0Foy3mbiAbJ4PKaUGJSzV5/e81ryX4X3ktIZlVx81WezHAVVpZAI
         sYDcFgZ2hJp4R3sA+lUHG//9Eudgzzuz/MPSu29h7rGfCSxEZ6QhXhHh/2RfGRtFZqTy
         1+ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1RRE2OlEeg2+Lo638ovwiyHuc3O32s9d2vQAgpnWV3s=;
        b=Yw8aLl6nQGAOyupegLSlSbZ3RNo7t4wCRszTduC/LQoglNgqCFQrzoBTonx6+wDuUI
         NFe4+t63BNYBDgZ8RLO6aEvJXW5nPIFT66M9Roz8ZKm06BJfpqGs9sWUO8dG5g9ozYn6
         HkAAbBj8ViFMqBbd2ktSPMtidUPh8/MNgl1WMpkCb7ZVV8/qtceidLDtIRAH91rKdYRQ
         HMRU3r31g3/f748+WuGpiTwU20JtZCcT+LAXnuMWhyy6vTQY+/cnW6CK4De/OulOm3YD
         Zo6X0tYjU99dnetWfiZgThkKf3QXvnK7eme+Z70+swemBrP6d2Haqbg7Ig16wFC74yxg
         lbGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1RRE2OlEeg2+Lo638ovwiyHuc3O32s9d2vQAgpnWV3s=;
        b=JMz9f3lcYtoBtYHQM8AIbU6nAXQzSycGY6t62uXdHoQbP17tUKWTRhnVL0dFE9MXGj
         00JsKXlNsR3IOlYIyrpnSwkCopgZLx2e46Ca+EGjsvMmzQT6Y4vw9yz57HyeNKdwVa9Y
         sZvZDtobIhnE5xbZcuptkEewHU1dBYnAUYIJU62K4DEjUxIlpHwjocMaVGMsq1pPVFqF
         HJvKSZ7QApm59dkmwetSV403DdxuueMDlul1WXiDR2B4FHdNhDVizclebVVbsJCqSu17
         TLSmKrhwNmBZHgLE7D+kdB3VR5itlc97aeHjfzokOm+FtYGqGF1NXHXEa18plTjTB0BQ
         CqCA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cMbKY0qomOFJjU4oPCbdZmRXo9ZRqkr0lfXseEbh928dcQMoe
	dZQWR2i4QWk5/Xdbw3Dv6Wo=
X-Google-Smtp-Source: ABdhPJyutt/ujqprOsia9kU5X9ebp01Y2EehGNu5UfchtnUfWdjcHYxfq1UaZKayv4MkgRXAwinRkw==
X-Received: by 2002:a92:4906:: with SMTP id w6mr7444149ila.234.1610177682248;
        Fri, 08 Jan 2021 23:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:845d:: with SMTP id l90ls3955296ild.5.gmail; Fri, 08 Jan
 2021 23:34:41 -0800 (PST)
X-Received: by 2002:a92:d2cf:: with SMTP id w15mr7512650ilg.214.1610177681886;
        Fri, 08 Jan 2021 23:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610177681; cv=none;
        d=google.com; s=arc-20160816;
        b=qZE1GkMI+c+u92Mkz/2jfMPGjuxDgYQ6EYuGiXRBrOjMymAkcwxLLlCZAWR0KHUWPV
         HBF9WFVm8UQMGiXzUxF1rK7HKuCwNUDg0nnihjIqX5wVXxUSk/HY5wzqTBFyO2eLEXnI
         Da4N5UEU4dpeUODsR4GHTld1EBtmBSgSR6/XwcsUs6xXMvnjR2p/J01Ca7j4oUgN/3+N
         1Xa2c2S0HGTgHYItPk2dzHGguay7TkC1X/Bl3wRS/JI9+jzjBKyyjjHssc5/KCc1dWA1
         8cqk7vms7z1RuCFgXocH34IyqogOer1/xkSneuHUpbMe9YgtGVgMWWzXqvn9fepAOD4Z
         oZNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=J6hNiTS/H6QzcgPODt+X22fORsvgGOfiHxRDqVTG5HY=;
        b=Bfj22rtaQzunDL0IDU6+zaOxJ//JbrveWZz+FB0026SKehxMtXLLTE1wyWtZmLdZiY
         mUFkitacMZxYBPox9BRwyaL1fvrlXLBmHThgDcqmSwcOMVk0L3V/D9gaFr+xLZ5alYvQ
         gq5+xnefW1LTyzkdAVJppjuQcmD3srpHlwXXKH0a2wIGFXxGjJ9CceuOAzz9ALz4ANiq
         jiQf6XE8CBDL9BH3n6Uh1Q1Ne9XUrdTcmc5hQHQ2/lZlf+5tmX99KHQmcY5tEnhiqX74
         yRC+MakMAit5Bq9y+DJeLTf7Le88hWCAKaoMpcKLulanC27jevvW/UpmHGWm3zwkdqnD
         jkfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id e26si978693ios.2.2021.01.08.23.34.41
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Jan 2021 23:34:41 -0800 (PST)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 8283239f5cd546f49b0c3acee954c681-20210109
X-UUID: 8283239f5cd546f49b0c3acee954c681-20210109
Received: from mtkcas10.mediatek.inc [(172.21.101.39)] by mailgw01.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1161108416; Sat, 09 Jan 2021 15:34:36 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs08n2.mediatek.inc (172.21.101.56) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 9 Jan 2021 15:34:28 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 9 Jan 2021 15:34:23 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <andreyknvl@google.com>
CC: <akpm@linux-foundation.org>, <aryabinin@virtuozzo.com>,
	<catalin.marinas@arm.com>, <dan.j.williams@intel.com>, <dvyukov@google.com>,
	<glider@google.com>, <kasan-dev@googlegroups.com>,
	<lecopzer.chen@mediatek.com>, <lecopzer@gmail.com>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-mediatek@lists.infradead.org>, <linux-mm@kvack.org>,
	<will@kernel.org>, <yj.chiang@mediatek.com>
Subject: Re: [PATCH 0/3] arm64: kasan: support CONFIG_KASAN_VMALLOC
Date: Sat, 9 Jan 2021 15:34:23 +0800
Message-ID: <20210109073423.7304-1-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <CAAeHK+xaVvvMfd8LhPssYi+mjS-3OVsDaiNq2Li+J7JLF6k3Gg@mail.gmail.com>
References: <CAAeHK+xaVvvMfd8LhPssYi+mjS-3OVsDaiNq2Li+J7JLF6k3Gg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 7E68C651933D07E578D2C654DCA4A58D67A68FF833FFF0EAAD1CDFA66580C7002000:8
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
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

Hi Andrey,
>  
> On Sun, Jan 3, 2021 at 6:12 PM Lecopzer Chen <lecopzer@gmail.com> wrote:
> >
> > Linux supports KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> > ("kasan: support backing vmalloc space with real shadow memory")
> >
> > Acroding to how x86 ported it [1], they early allocated p4d and pgd,
> > but in arm64 I just simulate how KAsan supports MODULES_VADDR in arm64
> > by not to populate the vmalloc area except for kimg address.
> >
> > Test environment:
> >     4G and 8G Qemu virt,
> >     39-bit VA + 4k PAGE_SIZE with 3-level page table,
> >     test by lib/test_kasan.ko and lib/test_kasan_module.ko
> >
> > It also works in Kaslr with CONFIG_RANDOMIZE_MODULE_REGION_FULL,
> > but not test for HW_TAG(I have no proper device), thus keep
> > HW_TAG and KASAN_VMALLOC mutual exclusion until confirming
> > the functionality.
> 
> Re this: it makes sense to introduce vmalloc support one step a time
> and add SW_TAGS support before taking on HW_TAGS. SW_TAGS doesn't
> require any special hardware. Working on SW_TAGS first will also allow
> dealing with potential conflicts between vmalloc and tags without
> having MTE in the picture as well. Just FYI, no need to include that
> in this change.

Thanks for the information and suggestion, so this serise I'll keep 
only for KASAN_GENERIC support :)



BRs,
Lecopzer

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210109073423.7304-1-lecopzer.chen%40mediatek.com.
