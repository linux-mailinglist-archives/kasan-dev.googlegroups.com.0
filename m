Return-Path: <kasan-dev+bncBCTPB5GO2YNBB45YUPXQKGQERJ5MORI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93CD0113F5D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:31:16 +0100 (CET)
Received: by mail-qk1-x73c.google.com with SMTP id u3sf1858476qkk.4
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:31:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575541875; cv=pass;
        d=google.com; s=arc-20160816;
        b=dC/1mxF3avxG1piseEocqNjjdrV3fKZbX8tuTz/2FjBa23F9JQWNWq5ZBfXRpslQEI
         MVJe+fqCu4qEU78DfqfgQ8Ju+fVc3BMe0MyABo6n8GcgNuyaFkVw+nEgv/BQ2ZGkE2Eq
         Drsmi5axLhg9vfXbLEqLv32Cw2Fz/6sHrkE7lbseHDpZYQUkbaYtGiDRyfexS3v41SAB
         CtWYfi8kmaPEU0ShiewQaeWX7lTSUu6enbIiUVj3/TIbxMABgSVFkgX3WS8SKtIxnBtW
         qduPpPZEvJ9INs+DNbGoJColHMDUAXu+cWIiq4f5LGmdcTFDWT9HlTNjEKVxv59x2G6d
         Aucw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aB73AqXNohyKlG/t587Uovm5nktwKsh+mXIRUNn41IA=;
        b=HZRS8MfvciQpNqhlAOPr1tYCKvm1vas5+he6Oh/WrYIFz17UGl2dC6Z0duokcY8fT+
         f1Jl2czp1x14ZHIvwZDwgc4wlzusLYh9fcRlX7DXAzlw2cxTFKmwvHMgXINtoxWVs1XR
         RJTPeDAv26r8bbbAe2BYWaKFGpLbZf9rZiZwy9dp2WsOPzza+NdfJ2ZuU4iLxqVC4z1W
         KnLXmaV6xZali/p6uGS1ye4vkMr1PNZYBF5hoa2uaGD020H1BxmnhdCZzpJFsDfmPQmm
         C438bQP7EW5kS4gdPAdI2IZZhjv6at2C5LCYEJ7PeIaLdgEdzIgJI9H3xGWaFcEJ2EGI
         BTRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aB73AqXNohyKlG/t587Uovm5nktwKsh+mXIRUNn41IA=;
        b=HX6b+0PYM8dIzi5g2J1MV1tvJKaP5KhtCpYzYwNrSelBbZFKbZ7eXxnrdudxq0IBOz
         RYmB4B3PixIsq3x3PpRtFbtgWIwPeZmhlk3Mo2Te5MYxN0jKIJvv7529uUxKYlzcpF/N
         I8oKfSqL9LrwUFmWLrnp5yZXQiuP7MDfq8CvUDTrVRwToHAiRWQyIptcezvsU8zZoJu2
         JGOcBLy3B+hCvDNuDCxcAn+3uvaV6sXZULiifFtJSs76tJ5/WHOTpWRe0J6E/jbm+iBV
         zqeS9qG/BH4Zvk/yzvuACSmue0HaxyHryq4MQc4/QjZOa7pUgX8adl7UNraDThKjMkrg
         DZzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aB73AqXNohyKlG/t587Uovm5nktwKsh+mXIRUNn41IA=;
        b=l+AP1PqWvufJTQcB0QH6E3bmN9CoP9AM2N0Gwo7vaXzcyTcb005TeV9pSQqHla2/X3
         zNdfDbTvKClZ2ACVEWMlsWxQnpWSMDiFfDWLKRUFQ1HaCYBwatiZ6ADhHIiTQU205T6J
         dYlUr9IseQiG1S3+cnFz/2Qu7U9usdCUlFtVeFiOwDxBONCJPYuTdcY5cgPX9szIb98V
         ToE5f+6sMc/a0lyImFJWnoZTXGLjvwWRkoJkU4Zw8kOfixoxWVAXDHliQ93cciSOrJHh
         ToSyLFNgWCkiko1Ag7/LlzPzmjo1G6q4PHaNnRgMyVswMROzDFZqsrwfD/h5pct+M9G7
         W5gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfWM0hoF58KZ/ltC0b/bYe1VcqAmpvlRvKdxCoK3j8pj94VGj5
	y9j0e95yF1WBQ1yfqZz90fA=
X-Google-Smtp-Source: APXvYqxknvNI0EbdLXnQ7AgK1H6Jw6y4wPDCNYrIwBqSyt+tO49cq5jfHV5tBNGn87aCTo4r12idUA==
X-Received: by 2002:ac8:27a3:: with SMTP id w32mr7081920qtw.234.1575541875636;
        Thu, 05 Dec 2019 02:31:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3ea4:: with SMTP id n33ls789958qtf.13.gmail; Thu, 05 Dec
 2019 02:31:15 -0800 (PST)
X-Received: by 2002:ac8:1e05:: with SMTP id n5mr6838127qtl.227.1575541875060;
        Thu, 05 Dec 2019 02:31:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575541875; cv=none;
        d=google.com; s=arc-20160816;
        b=OiiA7/fC5OcJK+plCUybs1r5rXpbIrgl/A1DniG2snsqTft0AMUzmLMle23mDrdo3w
         ZgyfHCvmbDfmKdCa+49Dw8ZI9vRFjZXwzbtG3IEl5HUKXGWkyD7DoFCyIIZJfs1mdYUQ
         9iQz1c6tEnrosVCJOEPEX5mmvBOLygY0wERe8v8/65bgO7Anhg9B/Z6wBtTqHuh8ItEl
         GVajlk33XUv5wWP0UUgPLgM88PQWE+dzVkkmFHVyYwhwZv1raTm95F7OI90DyrPAlNzT
         XbfDu6AODp2rCAr63cxmhxf0sdHALyTL+nQ2mbxDJgx7BPn1Zcpa7ZX8UbeQKjQLZZiW
         d7Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ooDdWc1n9AeXBJ/ZjAQQRV/Tqw0PqnMS9KXT+aVpuB0=;
        b=OY3o0YvsNtbnwSxFDZnqT1zq4WsgkoJilUD2VAr1XwONzW3uBXUqxVn9JFaez4fE4d
         frnm1seXGExy1v/Si4kwz0NuQT7KtGfQHJMuzFpjDFqjhRS9WI4ExZyG4MLWU1WXtqyF
         9qMKNirjAOAJiO/DKuVTaSfkwuG1bqPXH5DaTV8tvIF8fW4UU6RBL5q9anLFKNwZC/Gn
         5691u0Sl5t61CW31Fhh7u36icAF2h6bHmp0l2KdT+3idol1SAortUmmFb6U+JN7rHrlQ
         spLOAazSxZNGnEsz2HCDdHdRZI9ggFuHu24iG1qJyAO2Q7/QOUWXqeXEYotms3bkYdTo
         WTHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id g23si542430qki.4.2019.12.05.02.31.14
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:31:14 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav303.sakura.ne.jp (fsav303.sakura.ne.jp [153.120.85.134])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id xB5AUvCo044363;
	Thu, 5 Dec 2019 19:30:57 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav303.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav303.sakura.ne.jp);
 Thu, 05 Dec 2019 19:30:57 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav303.sakura.ne.jp)
Received: from [192.168.1.9] (softbank126040062084.bbtec.net [126.40.62.84])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id xB5AUqmd044301
	(version=TLSv1.2 cipher=AES256-SHA bits=256 verify=NO);
	Thu, 5 Dec 2019 19:30:57 +0900 (JST)
	(envelope-from penguin-kernel@i-love.sakura.ne.jp)
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Dmitry Vyukov <dvyukov@google.com>, Paolo Bonzini <pbonzini@redhat.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
        Andrey Ryabinin <aryabinin@virtuozzo.com>,
        Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
        Daniel Thompson <daniel.thompson@linaro.org>,
        Daniel Vetter <daniel.vetter@ffwll.ch>,
        DRI
 <dri-devel@lists.freedesktop.org>, ghalat@redhat.com,
        Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com,
        "H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>,
        kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>,
        Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
        LKML <linux-kernel@vger.kernel.org>,
        linux-security-module <linux-security-module@vger.kernel.org>,
        Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
        Ingo Molnar <mingo@redhat.com>, Michael Ellerman <mpe@ellerman.id.au>,
        Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>,
        "Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com,
        syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
        Kentaro Takeda <takedakn@nttdata.co.jp>,
        Thomas Gleixner
 <tglx@linutronix.de>,
        the arch/x86 maintainers <x86@kernel.org>
References: <0000000000003e640e0598e7abc3@google.com>
 <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Message-ID: <811afcac-ec6e-3ff0-1a4e-c83b98540f0d@i-love.sakura.ne.jp>
Date: Thu, 5 Dec 2019 19:30:53 +0900
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp
 designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2019/12/05 19:16, Dmitry Vyukov wrote:
> On Thu, Dec 5, 2019 at 11:13 AM Paolo Bonzini <pbonzini@redhat.com> wrote:
>>
>> On 04/12/19 22:41, syzbot wrote:
>>> syzbot has bisected this bug to:
>>>
>>> commit 2de50e9674fc4ca3c6174b04477f69eb26b4ee31
>>> Author: Russell Currey <ruscur@russell.cc>
>>> Date:   Mon Feb 8 04:08:20 2016 +0000
>>>
>>>     powerpc/powernv: Remove support for p5ioc2
>>>
>>> bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=127a042ae00000
>>> start commit:   76bb8b05 Merge tag 'kbuild-v5.5' of
>>> git://git.kernel.org/p..
>>> git tree:       upstream
>>> final crash:    https://syzkaller.appspot.com/x/report.txt?x=117a042ae00000
>>> console output: https://syzkaller.appspot.com/x/log.txt?x=167a042ae00000
>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
>>> dashboard link:
>>> https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
>>> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
>>> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000
>>>
>>> Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
>>> Fixes: 2de50e9674fc ("powerpc/powernv: Remove support for p5ioc2")
>>>
>>> For information about bisection process see:
>>> https://goo.gl/tpsmEJ#bisection
>>>
>>
>> Why is everybody being CC'd, even if the bug has nothing to do with the
>> person's subsystem?
> 
> The To list should be intersection of 2 groups of emails: result of
> get_maintainers.pl on the file identified as culprit in the crash
> message + emails extracted from the bisected to commit.
> 

There is "#syz uncc" command but it is too hard to utilize?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/811afcac-ec6e-3ff0-1a4e-c83b98540f0d%40i-love.sakura.ne.jp.
