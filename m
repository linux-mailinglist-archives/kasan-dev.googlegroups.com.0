Return-Path: <kasan-dev+bncBAABBEHY6HWAKGQEUGJVPFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0443CCF94A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 14:07:46 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id z13sf13559561pfr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 05:07:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570536464; cv=pass;
        d=google.com; s=arc-20160816;
        b=VEZongdJLLpn0L9MIj/8EM3WgW7aGjqfU8BNGq1BDBzPLzJCq34APk2lUG56ptAxmL
         jY1SRXe/KfYBts/1N/YeFCQ5jHELZwkjagcci17UOpuF8+5qBrYSXu/m6+4nm4nB28qP
         yzetTEzIOmZVBTp+wfPFG301fGcV2tvwJ+KMeZtjOli/gmyhlRTJH+uGIK1mn/bX4zSX
         XFLCH5Bh5VyxU82gBdndLiWB529PWOWhEJE0zCMPhq3KB/aZyH3B9sU/5i4mKz8RjK4j
         VrsxTvQeixecY1ba2rZJFX5VmNewXeJt6YcJw0wWS5zvrZyiCSLy+s77sHuUckhNYLCR
         3PvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=fYBko32h0CwNwmBLNdBDJ/iLqUbkB2+uW+O2Vs8RQG0=;
        b=FRwb3lncZMFaEC542VzFe81MIiU5oI5j53mqDzaJP1rVBGLl/krBRyTuC/Wnz6NWCK
         n0IpFPDM+i2Xu1nyuWhIyTSqZO2FKyzH3rNv5L5A0mMOwTRY/1ig1S/VcfFB4wk5S726
         viik9W8/vbGg5ozTCvo0pcuLUABykAljUqIdW3bXPH3pORATVgbn2ILbB5k0Uye8CNdK
         AhBkjFSgJmW4zpq8/VQgWNw3dLn72mzhzXGvumKkVHeOP+Zbh5aShsJ8B8ijPtbL9HlC
         mKRCAfFl++I1004gKo4XQVUnl/16lbuRiKwzbQ+eE4mnHgMxH3bb7youPImB2la3FmXR
         CUqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYBko32h0CwNwmBLNdBDJ/iLqUbkB2+uW+O2Vs8RQG0=;
        b=oij4x702hS6LeFKFuc839DAnpIQvzn830+GwB7DKkJKSrhyCTqMKAIyI+M2XbtrnII
         U8Zrt0SuWyXcpj6Lx5FQ2bpitLqV5NyBuS78jfLf43o+Ww8BntDgDIdfoxNff5yWWpkm
         hXADqmVPZuahzMGwfrypHEiKIxjFLANB1pSXW6Nq7cgOMgI82j7YGC20m0wgLCv11zMj
         Py7FRDn8h9HyhxEr9HVyrIRWF8MJsFB4h5QCn4zpHKjeYe5LbjOA3Ul93zIXw7XRFjai
         p3rpb/qsE8lSbSgQmGtd4QElGkvBJKhY8iV/jjdynVjHmaBCcy2RXYaM+Rs10a7qlVyp
         hLGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fYBko32h0CwNwmBLNdBDJ/iLqUbkB2+uW+O2Vs8RQG0=;
        b=VsQ1GjSfl3XnEE2eum7dbSQLfZR8w7JoVOXrFEj+u4uuJqpW7FF4mTJ5ft8GqL3QzP
         +fQK4nTA3muiJQ2XCWcC891yxGF394UMVWNLx0c6KyTd1ZC0yMaLy1U58mHtb528dUbb
         UZ1KWjQGlWXiSDi4vbtjZ/w8whk+KsfLNjH2NRV+5WSpJ+eihw5TDsOW25HWJ//1bfpL
         Aq7xKmHytZEhKtnRG+1mP1eLAHpVjLxF68YUqcWmBJ/EFFWDS/1o4moSj0vCFYCLzYZh
         78I9XN1O/uFwwUAX2/qytAzVOJ6/t/7mzcXGebI6P9XvqjHrxFyNe91aNsL7APUuaIeK
         lZ2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV+IAKx8psQ9mayrZUS2ar6tXjBlwBaFffM/W81vg9tyfht+Pil
	6JNK1Z8nckEYdJDyxEFgGfg=
X-Google-Smtp-Source: APXvYqwFZSyC0hnWn3meX3ucsawxlNqaUGaJe7G4AkIUkJr3zWUt9LwujBCaw7tQKkAMqB8UL6buJQ==
X-Received: by 2002:a63:6f87:: with SMTP id k129mr3704243pgc.8.1570536464185;
        Tue, 08 Oct 2019 05:07:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9b08:: with SMTP id f8ls813810pjp.3.canary-gmail;
 Tue, 08 Oct 2019 05:07:43 -0700 (PDT)
X-Received: by 2002:a17:90a:2e8a:: with SMTP id r10mr5623145pjd.128.1570536463906;
        Tue, 08 Oct 2019 05:07:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570536463; cv=none;
        d=google.com; s=arc-20160816;
        b=izO2M5qq1dhU7X06SnjZPNv+0SUyQpf8C5mQExm3xkuU+2n1y+b/FxB2SCFNHYPDWU
         vLNTdlMIbQGuC7HUgZz8Ce4DP0IYWv43ck/9FXSGaI7JIsdqM8+wIWOLbwaVhJ2tZs2l
         gI9tRGCeXG6GE52nSUE5IrSLTSSG0DWHZ+vGm1oD3yrVmIcDNXPFFWI/Ug6+FytxLxZ7
         MALPJqzMzBLKR7gwRt2XevNGWtt5CueOeYcWiTP56vS1wGCiiLvI8Mg3Nd/dfYby/RAu
         mTomhCpYySM3SjuI8iAfuFJSbHgyaB9jffpGA4WdAJBkHo8WfbxaHLHLqLEvsu7cgShG
         DELw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:references:in-reply-to:date
         :cc:to:from:subject:message-id;
        bh=dMleiwFnuHxNmBt/IgHWd5QJozfjf807QRhDOO4Xka8=;
        b=xP5cfTvWDyxpr/Rav0TYXPVSjuPBhfLyq/mV+BBs3QNZOG+ShewrRAWluHVs9vCYpV
         SbOT4mcYfaddjBJczIJAHNL/y9kOX8HJ5CesvQVZNjUDqbAVZpiiULMmZj3qtvh3TTLI
         +zFEai1mif7GdMMwl38vjs9IN72yr3JmJfmfqhSv1lmDINZsfd7+i1X4mijDJ/+3YzLJ
         7Lnpgi2Qw2IaxzKLKn87rNLu6azk98dggCFc/mbFEnPwnViA4OpwPhJ2AmDJ7PKtcReG
         EDKbNmD3XoCl5JKAN/Oz0W8PQjandOpeCRvgrWo/x/2XhbGVf5ff8dB3h6P03IfRkY6/
         K/mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id g12si282558pfi.5.2019.10.08.05.07.43
        for <kasan-dev@googlegroups.com>;
        Tue, 08 Oct 2019 05:07:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 134220af59d1465ebc8848ae4483be8b-20191008
X-UUID: 134220af59d1465ebc8848ae4483be8b-20191008
Received: from mtkcas08.mediatek.inc [(172.21.101.126)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 815412962; Tue, 08 Oct 2019 20:07:41 +0800
Received: from mtkcas07.mediatek.inc (172.21.101.84) by
 mtkmbs07n1.mediatek.inc (172.21.101.16) with Microsoft SMTP Server (TLS) id
 15.0.1395.4; Tue, 8 Oct 2019 20:07:38 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas07.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1395.4 via Frontend
 Transport; Tue, 8 Oct 2019 20:07:38 +0800
Message-ID: <1570536459.4686.109.camel@mtksdccf07>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Qian Cai <cai@lca.pw>
CC: Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Matthias
 Brugger <matthias.bgg@gmail.com>, LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, Linux
 ARM <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>
Date: Tue, 8 Oct 2019 20:07:39 +0800
In-Reply-To: <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
References: <1570532528.4686.102.camel@mtksdccf07>
	 <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
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

On Tue, 2019-10-08 at 07:42 -0400, Qian Cai wrote:
> 
> > On Oct 8, 2019, at 7:02 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > 
> > I don't know very well in UBSAN, but I try to build ubsan kernel and
> > test a negative number in memset and kmalloc_memmove_invalid_size(), it
> > look like no check.
> 
> It sounds like more important to figure out why the UBSAN is not working in this case rather than duplicating functionality elsewhere.

Maybe we can let the maintainer and reviewer decide it :)
And We want to say if size is negative numbers, it look like an
out-of-bounds, too. so KASAN make sense to detect it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1570536459.4686.109.camel%40mtksdccf07.
