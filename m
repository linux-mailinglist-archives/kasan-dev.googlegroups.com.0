Return-Path: <kasan-dev+bncBCFYN6ELYIORBZFUUPXQKGQE6GVPUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id E1A96113F41
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 11:22:29 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id s3sf1523969pji.18
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 02:22:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575541348; cv=pass;
        d=google.com; s=arc-20160816;
        b=IxL9hMLzWeSLrKSrxfYM7TNaq/wd4H30vpbldM60M8hlJMyi8Y1qfUDhiUFj2tFRJZ
         1jKxS4F8Qw75B0KX9Pkm5BWdMLGNrK8PEIjTr7NeKHlqG9SkO71h/my1ibjZfEPS5Ack
         3ldpf5tUQSDgppBe6XoQ4YHfOpqdzR+23RcyyW1RpwuLd2xPrn2BF8QT0iS6/bUN5LcV
         3iXRBPhjfKq9I3VlvsDlR4S6RYAfDDUha3zWpwnUE2V9ZBbU6gqDLbcjsjqQZxa3vhuZ
         M/u5FjE5J81b9NsPdQUo/85WCYGy6ubq1K2JcIItWXMGC9CgqAkBdRcA7HL+PQayuqZl
         0gmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=nEvImArgi6OHxsBvJsNfZrnit8pqHlP97heHAWA+SRQ=;
        b=bR5vIG37XvZmR694RmcCIvjx/oKIRoKBzMf1+lhIjOGHn5Z4TPNcAkZZcqYfKnJVPj
         sLZY658aOIzeH5afN9PUHVI0JoTp543Ok4lLMX9gle+KEoQaJhdQkGld3KFkJnmKRlg9
         /180AwSSRZ2Zo4VcTW8/TOF5qOPC2JpSViqMYhKxBtPdGaH2KRN1BdKdmA/1kKx39eRw
         XYnoF64FTX5uAGwTO8+ybCdX3Y1RYsgXBcO0QAZofGNNcmQxfowA/cH8BAbgwHo+oBf9
         /kwLbWt/QeAE5DlP4B50fd5r1pDS4R7vBilrRo5v6criFIbncw97i9PDt+SztC3e5gpL
         S7bg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HH5yT8PC;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nEvImArgi6OHxsBvJsNfZrnit8pqHlP97heHAWA+SRQ=;
        b=rqAiN+D5HWOqkL4GRRHma/zsykrwfS6dRp4aeMTUvTHawXgE/8wL7Y7ecezzI0PvIe
         C2az8cmEZJ3dui6Zk2EBYBSUhqohh7JCToDTnW/1GZf0dLe+tgfpl+RLCkqkaM1wAfmB
         8AgJt/BOsp7wdsays2+QU3dUXzXJaVUUreCi/JW1Pf4jGS9/M0/A6f1P3Fetz4wKTEQZ
         gvBgcK/5NDNJVw9tHrhXWYyg+8TO02D7mTkGrm3TDa7EzPqkWO5hXdiAlgo+wlDFh+PM
         6fDf43yV6cG4V9bWkI6GSbazI33MEj6RT7AxtCixMCxsobsXfgrZfxUkTxhvH5+Na5Fn
         j6Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nEvImArgi6OHxsBvJsNfZrnit8pqHlP97heHAWA+SRQ=;
        b=fZWdmCplewDvIkt7HOS/WeAC63k5w7kA6DF6+lBHuhS5sJVRm3R8KEOQH28K83Y3+w
         FNCjg6N2ueveKcZnTbPQqTLBACyrjxS1Hu9FQDq9A59WCjyxcTPt1gOAWf3lffVD0NBd
         6kOzzyuEcoclXsUormYzFY86djOHJ4UH6YoSjrnv8eijlhXITkZ1cYtNTtpSmCgc+ZEs
         j/rulu9yZjM5Ab+neqE/7QWAqlJPLyedGdKd4hSoIKXjzqF/atx6LHwCyq9v4gwZUenv
         0kbgqc1out18eEM5RPLWQ+F0lwATNoyNYmbiuKrQIge3fzYevuIWfnWWkcSyB/jZ6oWz
         dl6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVT1Ox4+DxXl3vKmblW9Jd37T6mt6DWL5qv+h7Mtfzltg2kYHPt
	qVs3nvbA6getG/BmNs7EFCI=
X-Google-Smtp-Source: APXvYqxSGF9edHazLcIvpMsnQmHMFLyMNn9zGX5vSMijqGkBw++noS7JGIG7teX7vYD3Jd67r98YmA==
X-Received: by 2002:a17:90a:21a1:: with SMTP id q30mr8578303pjc.8.1575541348607;
        Thu, 05 Dec 2019 02:22:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d988:: with SMTP id d8ls682493pjv.5.gmail; Thu, 05
 Dec 2019 02:22:28 -0800 (PST)
X-Received: by 2002:a17:90a:c390:: with SMTP id h16mr8554487pjt.131.1575541348149;
        Thu, 05 Dec 2019 02:22:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575541348; cv=none;
        d=google.com; s=arc-20160816;
        b=L3Q6gwc9werLIQHXFZ3ly6GN9Y+u0yec6Kcq8yEGgWkXhNVMiIWYLwPdj9OeQ+wYbl
         ckBoiS8V+KBLV9nFIeaW4yAsWMFgvPRteNqLBRH0fdhGMBBNStL6KfH3rNqWXj7MQ0AB
         /TAvryhj6sek+iyd4AoeBHI5WUsCID//fEn/MrzCntF0vFetYFnuKi0cmwUfqJyvtk/g
         /eVjzWrrk4dxbxg3OldS8QXAe+uynxtv4Ry49gULZHO4LFz7kcVE1ymuTaO2+siKja0v
         dG2AUoMjSKSJtbmT5QaMeEeRBMiUevAjQzF8ULBR+9t5Vk3dcohTeNCD7VD0Ea2rf20O
         Uyrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=HaIFegi+0Clb4nOD0Kmjt0kKgC/aYqjcyu4Ow354nhs=;
        b=wAlV6D//LsKxWn2jqEoLkFcDBQU+Xn92/4DmFkLh3LDsgNvGDwrLNrqn0VDtLjibqy
         YK60FxKxWNTVB+VciWCMYHVPsHI0BYTLmz98LgR6aGhpS1ZnBKU39VayNAoCAVeH8SAy
         oRXhX1TLhL1jSw/PO8MpHbWS1ZT+CCbzjXyOka8XGp24M/12yoGHhmcVRwSIb9pBCN1b
         0WUH2NZ7O2uxXX/RcvimKws93EqI5fibyebKJD0UuU+Q8I0JBG56XIQhM8YlZevlsyNl
         oFEjACXFIysgQkc2hziVaQRxoONhEpCmA0GBqaocOi2PCItr+NQbGrQKZ15b3c58VOoc
         egdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HH5yT8PC;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [205.139.110.120])
        by gmr-mx.google.com with ESMTPS id n12si617383pgr.5.2019.12.05.02.22.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:22:28 -0800 (PST)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.120 as permitted sender) client-ip=205.139.110.120;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-358-cDU2OspJOGKfleme9PwMkw-1; Thu, 05 Dec 2019 05:22:25 -0500
Received: by mail-wr1-f70.google.com with SMTP id i9so1335447wru.1
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 02:22:25 -0800 (PST)
X-Received: by 2002:a05:600c:d7:: with SMTP id u23mr3706997wmm.145.1575541344295;
        Thu, 05 Dec 2019 02:22:24 -0800 (PST)
X-Received: by 2002:a05:600c:d7:: with SMTP id u23mr3706957wmm.145.1575541344042;
        Thu, 05 Dec 2019 02:22:24 -0800 (PST)
Received: from ?IPv6:2001:b07:6468:f312:541f:a977:4b60:6802? ([2001:b07:6468:f312:541f:a977:4b60:6802])
        by smtp.gmail.com with ESMTPSA id c1sm11635129wrs.24.2019.12.05.02.22.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 02:22:23 -0800 (PST)
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Dmitry Vyukov <dvyukov@google.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
 Daniel Thompson <daniel.thompson@linaro.org>,
 Daniel Vetter <daniel.vetter@ffwll.ch>, DRI
 <dri-devel@lists.freedesktop.org>, ghalat@redhat.com,
 Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com,
 "H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>,
 kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>,
 Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 linux-security-module <linux-security-module@vger.kernel.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Ingo Molnar <mingo@redhat.com>, Michael Ellerman <mpe@ellerman.id.au>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>,
 "Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Kentaro Takeda <takedakn@nttdata.co.jp>, Thomas Gleixner
 <tglx@linutronix.de>, the arch/x86 maintainers <x86@kernel.org>
References: <0000000000003e640e0598e7abc3@google.com>
 <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
Date: Thu, 5 Dec 2019 11:22:20 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
Content-Language: en-US
X-MC-Unique: cDU2OspJOGKfleme9PwMkw-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HH5yT8PC;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 205.139.110.120 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 05/12/19 11:16, Dmitry Vyukov wrote:
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

Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
backtrace and I get to share syzkaller's joy every time. :)

This bisect result is bogus, though Tetsuo found the bug anyway.
Perhaps you can exclude commits that only touch architectures other than
x86?

Paolo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f4db22f2-53a3-68ed-0f85-9f4541530f5d%40redhat.com.
