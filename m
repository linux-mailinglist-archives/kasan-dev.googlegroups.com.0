Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZEBSL5QKGQEVCN2YOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id D8E8826F979
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 11:41:56 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id t10sf1279034wmi.9
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 02:41:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600422116; cv=pass;
        d=google.com; s=arc-20160816;
        b=CyR5KV/OGptzEzHVORn2ZktvtNDIRZpzVDqsYfypBmlsqyFQYd8V9pV5yDLsRdlWGT
         /Fv/uEThM9afzQ5pjT0bovV5ulrUTSDRECo2YjvYd7V0yLx63OOfJ92REv9iDujqyvSe
         7qhz1/D5jLVvwf9y/yI0yng7N/8XerOY/rL7NU3HfGUdagRkMRgJBec45yyFBs584SyY
         KsPYT5RZZPo93piyBysLZBhOCnPORI+r9DurdacpM/m6nqwfnOX2a/WpCb8aQxWlPKqj
         HZ1hNKDVJ/nbFyKpdrrcFWlrYgmZa9SPLEgR+ge/7FZRI3zyg8uajKpjfEK7MD0MAKct
         UbNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ELTppmYjW8m1B5VynQIh1EOLQW7dYn5R203KEhUam24=;
        b=ANlYigqKBA/Uj1GnVULCtr9malz/V/ZtEuQqsfvJm84npi9dbf8roaXWtdbOJZnUBk
         bfxyzzEjCslukGj/RA469MzX6Nawz761cci1nejU91SYi0LbJmtP9lPSr7XeeV4lQyop
         EOH+iZdog6SL1BMGI7l17HV30WtjZBdt4w4kIY/IYFwHs3em3ETguHN+Kf2ALrlAbUnE
         /AsXaGndymfKF+K22KPzKpyxEVvc9mg4KcxdO1y+M+YfcjGF9mn033nN43XGRPCHQYkj
         Oy8JxZofS+M2gmF20MXyDx6rshEfGapbcFieg8WejV95J56dahRT8NKQUGBg4Wo0jElq
         kX2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jMjmQEvj;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ELTppmYjW8m1B5VynQIh1EOLQW7dYn5R203KEhUam24=;
        b=VdvxJEdWHRtnkQpcYLbAO5b4uHjcTkTlYxc3G1zVqvO/gaNeCFDa65UQBF0+9rTT3k
         xXsZ21CSnT9JiW3GXgEpobTeYYIYDnNmNRGOBxYXK1j1Z1bZ2CSEqDJ2MIjETHph9lZ3
         rOAar7LHSX+eHaPmK1rwYa3lJDDxoZZ63aKoYVMKSQM8SAnhRVeHeFg/70Q9F3COjOhl
         zyvTPiHTVRkrNnft0d9SHN0DsWPOf6SobO28vT5mSNHCvAcxw5qDgh4YnZJXrO9sFMXd
         K9BxROozvieQMwns2n5SOgo3BlWVqJMoUw9A3pPiKWCflv/164B/csktBUF1a/I3wDod
         EBeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ELTppmYjW8m1B5VynQIh1EOLQW7dYn5R203KEhUam24=;
        b=CpRFkN5YqnRj+hyVYV660+f+D7e+4RIF/Jhf4DGbOzIt1dRxG0oW8O2FHeYIfUBLUO
         HVaoakFRiRFit4Hini9XzKZVzOJF2Jw9JJQaRgTv1IbAVjQzNxr58doMS6FYLVkO3Gm8
         Do/wf6oVuhY7Yv2+O6KHN1CWOrYx9HIEx4rn+SJpphQflDv5vv7ENmArOl/JGmO1YeSV
         ni/DH1iL3ZCNZ5jZ9q3/+g/xgxV9bvgGy7de+631oQ43PBSeiDVrHX+/dzpOvodSKIVX
         Chci9S1nOLQaCY6qGJ0cuX3n2wb2JlIIc2GucfEbSXf6RIhzksVXmMpStqJn6bjYxBd5
         E+CQ==
X-Gm-Message-State: AOAM5325dnim8QW/Hru/J682nxC4v3xbHrTxd9BqW5z0LwPwFPH25Ovs
	yqTQ28su/FwlIGJyDvOfx44=
X-Google-Smtp-Source: ABdhPJyNGcAVEtf1mNFEsSHzDCaMISjMLzkkU8ZUcRHz4KZsFLtgbIHJQTQB/GieVJiAf4GSW/8m9A==
X-Received: by 2002:a5d:6cb1:: with SMTP id a17mr33261575wra.386.1600422116643;
        Fri, 18 Sep 2020 02:41:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e3c3:: with SMTP id k3ls4301750wrm.1.gmail; Fri, 18 Sep
 2020 02:41:55 -0700 (PDT)
X-Received: by 2002:a05:6000:1282:: with SMTP id f2mr39386509wrx.251.1600422115639;
        Fri, 18 Sep 2020 02:41:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600422115; cv=none;
        d=google.com; s=arc-20160816;
        b=sp/SNQOuwBorwA0er8p35L/KPVJQMx/zetIUzYYUhKjlGssTlnxgSC32DtbIoFB+0J
         hdNlLX18Jv9Bc/RlxwPL/k/H6gMmUw/rWJih/G3gLvgsLWP4NpET2hXwvLct/5pxfzMn
         TORzXUVNxnhTu0XA+rzGPFNljZwIZNwd43+fN9WpZIV6HA2Vruda+mWtN7g6b+cAUsqv
         1Iq5QnQCOf1/Oi4A0k2cwZq82Xn1BTZXZv2DgtokcV6yJqpssaz2f4mB95QL9owc/HSD
         itw5pBUuXskxTkFGk0KxuahwMKL2ZT4y7wJwJZPcmOsE2EYnuOLpszo1eJzSFqYJzDpI
         9/wA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=shufKx5eku0Isd8JdGv9o7lMkOjjIZQhALDCFPr9wG8=;
        b=CHxRkT30zGcywCQEf7JvmEdMrPdfImst40ccFiNjdayBtu9qbYM42mZM0Tc9R88aJN
         MlenH0o51SwAP6dbw7WW9gNiVsC9XLvG6oUaDv5H435HHqYpxZ1l7s6WHe/zI++OvMWC
         cVKloVwhK3TjWHexxYe5sQiluQfwqFw1hEn5Tp0nOUzeV+XZE/G87sUuRqpSLn4XiTRl
         v9DmMDruL6An6Iu0Yqf0IWFtpa9faITMC8wydcNY1gn/A1F+KxR9rsB5gDEhv6ttZ6rc
         V+8ZaqYln5WyBmdytyfxRE6Ff36xW0APW4rtMFkWhkAQ7NG+hw5H+Z82FQWBq7+EAACb
         VdWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jMjmQEvj;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x344.google.com (mail-wm1-x344.google.com. [2a00:1450:4864:20::344])
        by gmr-mx.google.com with ESMTPS id s79si82517wme.2.2020.09.18.02.41.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 02:41:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as permitted sender) client-ip=2a00:1450:4864:20::344;
Received: by mail-wm1-x344.google.com with SMTP id b79so4855944wmb.4
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 02:41:55 -0700 (PDT)
X-Received: by 2002:a1c:b388:: with SMTP id c130mr14511635wmf.175.1600422115149;
 Fri, 18 Sep 2020 02:41:55 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
In-Reply-To: <28d17537bbd029104cf7de4f7ca92246449efa50.1600204505.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 11:41:43 +0200
Message-ID: <CAG_fn=UACdKuiKq7qkTNM=QHcZ=u4nwfn7ESSPMeWmFXidAVag@mail.gmail.com>
Subject: Re: [PATCH v2 20/37] kasan: rename tags.c to tags_sw.c
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jMjmQEvj;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::344 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 15, 2020 at 11:17 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
>
> Hardware tag-based KASAN will also be using tag-based approach, so rename
> tags.c to tags_sw.c and report_tags.c to report_tags_sw.c to avoid
> confusion once the new mode is added

I find it a bit excessive renaming the same file twice in the same
patch series (tags_report.c -> report_tags.c -> report_tags_sw.c)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUACdKuiKq7qkTNM%3DQHcZ%3Du4nwfn7ESSPMeWmFXidAVag%40mail.gmail.com.
