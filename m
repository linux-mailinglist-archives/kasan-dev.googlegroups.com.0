Return-Path: <kasan-dev+bncBDY7XDHKR4OBBOX33ODAMGQEKBJ2C4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id F04E73B4DEE
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 12:13:15 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id 81-20020a370b540000b02903b31f13f7c5sf6655942qkl.13
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 03:13:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624702395; cv=pass;
        d=google.com; s=arc-20160816;
        b=XUqtohhJwDdEktnMMK7Jrd6pXsyyX4UPVoyD84HPrY+zvKAqF42iJ8zUopUDOKLZma
         taf3MehHE5F1svURuZWJUeZPTcpBofbtkUgrTl/tKFC5G5z5mgtS8VdfKQabN4GLSwtc
         zdbAPCEs//RULnjadhgk3wNtKSxfvjA+pH30dBH6nwTch/PI7y2R4BQViZms/RMDdSio
         6Dn0iplz1kSE8QrFt/N7CyHSfVrsJrPFpQ6+vzs6LBQCTHprVWHHsjD+aBv/VsiUFkK2
         USp069fkkY15BKfr2htKu5l5Zx35PfCBTn+0cKAEHuRKdk8Ibn16+GTJLNTvQZUHhi7R
         AWcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=wkKDY1F4vW6iEVV0+qwy0d/jEnEABk/vAHjHI+Bsylw=;
        b=nNwjnLMx5XjjnYYO7h/mt4B+XurW0sqjKQWjnfX7fI4XhpGzvlXzMns0nkRevxSpAz
         w9Bg6CFP8DPxyzw8Teti6JBvjWlG3XGzTKLaGhW+a66WJPviHUE/0uJ03iFQXwbTuW5N
         qxmk1dtCmnHTGHDL3LFbdjN+EIm+keRj43ha1l6/nSomcPXXJ9zpQxD3kSLLtLk8dOeE
         eQQnlAdq/OgpwukZu5dOvbDwi3doVpAOw7Hhs999DRgrpDwVoTKQRp6I58nGLxThRNkz
         AhzuL9uuHTDIssc9L5CKrCioiWzoIthwxWM7K0MrrO3UQMvFtVvZ/D34ROp6pwU1BVCE
         RGRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LBZCFEQV;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wkKDY1F4vW6iEVV0+qwy0d/jEnEABk/vAHjHI+Bsylw=;
        b=AtTpMsl/kJ7oAGafaEsqoKSZQhWcu0GYQCpchy+NXR0WeUPhJUAexbvaluxwcRd0G3
         IRYRcUu0l2X/4ShetVALiOHhEtbf9qhY2BO2k84tdkcrD3X5Xm0R2rN8PHaJPpvnkXU0
         0imwbbe0VnZLmSvMxevl84zemDLI7idggkzKRnWXXHx/8idBYFZA24pV2SEYiRl9+6KA
         GlDFLja2TqgjSK+1CypJQS+d/8TUnOFQLclwUduBHbPw+9VI6hzXcDcO2fmLuJz63Nx4
         IpE4PaXt9XdUof0uwDX5bdgd3yBWQZDNU/HJNGIQOK01PI1ZRTrS9PxC0ddxfgThVau1
         Pw6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wkKDY1F4vW6iEVV0+qwy0d/jEnEABk/vAHjHI+Bsylw=;
        b=lHdagAPhTIUAVCQyzkuKkvUUv/qDyMoSUCrY2XfZxiTlHJlEK8DIZC/A/Tp0/xKPv1
         HcRX6aMeeJDFFmMBxG9QlZ/Qz1KKmT+ashhFmLH/iU+rNuIbEm5QQFi/7QlbK2FbeyeY
         c1n1fiwiyX9gAqu13qnH5q1MGDDiE91nGdSNxUOuqqgoV7tHnnQouYkJ0dIv7wk4Ykwn
         dlIho7zScWKFM8FJaK7mad1SdaMRqjdaU0b7xK/CvuW/zlRMIc3q1tySUOhLovTNW78W
         DMBB2w7amtgMzZIk116rPVPetOEH9J7IiNuwpI07cBWIxWXj59op829/WWThLbtlPrlz
         CtjA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53215LhLKPnoLP7RT5o4cW74FFbvkNQAMWoC1hwKPvvGKyauAwNp
	7qDnrB5Si1R+21yqwElBn9M=
X-Google-Smtp-Source: ABdhPJxyI86fikivGX53UXJzsK4dCmbFY7XmIizL3wvzzvEfO2S5z212sauNfulAsNbK48w+z55aFw==
X-Received: by 2002:ad4:48d1:: with SMTP id v17mr15447527qvx.16.1624702395092;
        Sat, 26 Jun 2021 03:13:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:e407:: with SMTP id q7ls7848641qkc.9.gmail; Sat, 26 Jun
 2021 03:13:14 -0700 (PDT)
X-Received: by 2002:a05:620a:1278:: with SMTP id b24mr4914813qkl.301.1624702394629;
        Sat, 26 Jun 2021 03:13:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624702394; cv=none;
        d=google.com; s=arc-20160816;
        b=gMJsbxESEjk3Xjlpsb8kqbeajJOg7LGCgbsG0lL4h1EFafsbmRI2eI0b8bvY1mMv+g
         YRO/ztQN2bIh6cfUCBnk1eImgZzfaZDQmPIy0peMFXgJpoKmCM2TCA7st/NK1QxTi5Zy
         wtdW9qZfC8fpD8RX/09rBbreHiJNkbQOLhukyHYblKlEdHpvjq56MdoYUmYJJn+JV0Xv
         t7EskWMV7H+MM9tLB55c7tlEz146qKWgyvtamHKn+XHTepGCDheY7t6gO36zib3HT88/
         FD8mNf56DfN9CIJnyfNbaCIODCvEjHIZBmS+gPdCCygS5RkA6avaHJg9mWPLwZdpvQiw
         f1pQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=ZbumjD0dXA8Fvx3qJdhEZ3HssG9IGyRmQDz1YHlIfM8=;
        b=d2UqoG94TKP6jnWr3Tp7LMzXPGU9ExokH84l6AerLhlRZj+Hp/X4L5tgCYKdci+naC
         Ug0OMrAXHjFhjPxyoypW2j+42RqJDKKrkJIizl23AxK+6H7nPxJNEIPb5lz6K33wrRrA
         9R0UYPcWTvk0i4A6dgHre8oq/YGq/QnHEiSfPlUAB58vtW8qRl8a+u63QqDanMy1KUm8
         AvGQGx07aAeagwFAUW1Q4BWgSlq19g/SsiC+qi74BN7y4/HNSGxo5ED6cY/wJrNT1yE5
         LodbaVd5P9Xde+DJWdbSNzlk4ILFIB0ljWbRXWUwhm6IB/mctC4Jw5c+qz6wi5keWzpW
         DJSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=LBZCFEQV;
       spf=pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTPS id a21si520718qko.0.2021.06.26.03.13.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 26 Jun 2021 03:13:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 0be8d16d27ea4fc1b96c603a54785184-20210626
X-UUID: 0be8d16d27ea4fc1b96c603a54785184-20210626
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <kuan-ying.lee@mediatek.com>)
	(Generic MTA with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1866582415; Sat, 26 Jun 2021 18:13:09 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Sat, 26 Jun 2021 18:13:08 +0800
Received: from mtksdccf07 (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Sat, 26 Jun 2021 18:13:08 +0800
Message-ID: <9e906af1182a9039886b0f86525106df381a6255.camel@mediatek.com>
Subject: Re: [PATCH v3 0/3] kasan: add memory corruption identification
 support for hw tag-based kasan
From: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, "Matthias
 Brugger" <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
	<linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>,
	<linux-mediatek@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <chinwen.chang@mediatek.com>,
	<nicholas.tang@mediatek.com>, <kuan-ying.lee@mediatek.com>
Date: Sat, 26 Jun 2021 18:13:08 +0800
In-Reply-To: <CANpmjNP9n8-m4MhY6Cdnfx_SYLVtG8NJ7raMUR+3rBoNyyfs+Q@mail.gmail.com>
References: <20210620114756.31304-1-Kuan-Ying.Lee@mediatek.com>
	 <CANpmjNP9n8-m4MhY6Cdnfx_SYLVtG8NJ7raMUR+3rBoNyyfs+Q@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.28.5-0ubuntu0.18.04.2
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: Kuan-Ying.Lee@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=LBZCFEQV;       spf=pass
 (google.com: domain of kuan-ying.lee@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=kuan-ying.lee@mediatek.com;       dmarc=pass
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

On Mon, 2021-06-21 at 14:45 +0200, Marco Elver wrote:
> On Sun, 20 Jun 2021 at 13:48, Kuan-Ying Lee <
> Kuan-Ying.Lee@mediatek.com> wrote:
> > 
> > Add memory corruption identification for hardware tag-based KASAN
> > mode.
> > 
> > Changes since v3:
> >  - Preserve Copyright from hw_tags.c/sw_tags.c and
> >    report_sw_tags.c/report_hw_tags.c
> >  - Make non-trivial change in kasan sw tag-based mode
> > 
> > Changes since v2:
> >  - Thanks for Marco's Suggestion
> >  - Rename the CONFIG_KASAN_SW_TAGS_IDENTIFY
> >  - Integrate tag-based kasan common part
> >  - Rebase to latest linux-next
> > 
> > Kuan-Ying Lee (3):
> >   kasan: rename CONFIG_KASAN_SW_TAGS_IDENTIFY to
> >     CONFIG_KASAN_TAGS_IDENTIFY
> >   kasan: integrate the common part of two KASAN tag-based modes
> >   kasan: add memory corruption identification support for hardware
> >     tag-based mode
> 
> I think this looks fine, thank you for your efforts. How did you test
> this? Did you run the lib/test_kasan module with both SW_TAGS and
> HW_TAGS mode? I was about to run that before adding my Reviewed-by.

Thanks for the reminder.
Yes, I run the lib/test_kasan module with SW_TAGS and HW_TAGS mode. :)

> 
> Andrey, Alex, if you have time, please have a quick look at the
> series.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9e906af1182a9039886b0f86525106df381a6255.camel%40mediatek.com.
