Return-Path: <kasan-dev+bncBC5L5P75YUERBBVZUDXQKGQEPKHIBKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F8B01136C2
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 21:52:23 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id k14sf272220ljh.14
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 12:52:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575492742; cv=pass;
        d=google.com; s=arc-20160816;
        b=MgdIkSqrEMbkIxUKzhxSbbX84/z+Gy9/Fv9fDa4xvWUsszr1wWGfVZUQhQT6eEI47l
         asBDlm7vdINtf8lEdqnQ4oP1w/H9T2MvBwQdOKG93SnAHHUlwmjgn0PjvUl0pa6ZNcdX
         B+1uV+JTAweKDEAJCVW4xGCSt5x0yLOMyWpJdSs4cLocmYmfg/VlWv+fMbl2LnfTf+5/
         SwBo8pqwHwAfyyVakFxaHG+y7xIEx3WpeCOrYO7/qlkGLKQvz7LLiWiFquZYZEDjxLKv
         fD7ZwSRe4Z1CzpuyFlyJ/mywX0GwM9teXbJfk45/WcIiN8Ngl2Vv53VgXOf5xE4plBC6
         mauw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=1Lq6FmCL8Z7KUtTdsphcfrR2t5LioB/XipSSRc/6c0I=;
        b=jxlpQIzisgxu88XsJhY6iwzpD97IG6g5HWwVImy5AOEHTrqAJdJWEVIojifqmSvjEo
         yHIZ6wmtwXbijN0bmoQbbbSSGOnPNV0UX6pUqxNxGLlxyIdn31fUXMgwELHg7zPC/dgT
         sP9cN6FQ20zDF1AY6xvXV791kWtPfjkPXoelweWVhGWXHbXLS5DkUghKz6L0MCA8hj8g
         GYvzLqjzbELCIvih4TS6WqBjohnShn1ZVpBn2qvTPG55YJO6Nm9bPhIpuDvWSc1/MeF0
         0eG4RNMvh6xuxe0I86JnfiOOGY2lCiMpbUQEOd+OtROE4CIkm7hjnk25VrCmFsYOmKUN
         xNIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1Lq6FmCL8Z7KUtTdsphcfrR2t5LioB/XipSSRc/6c0I=;
        b=cxSw5lt9k69Ls5TOShdPm/PXZgpFPNdtNe6hwKDnOAkF4DuSjz3D8QkOftTmo2W9Pe
         hLzyajv+t1AkKXqZ20R1nBkIJtcAxHAqPwEkQN7PoaocsAyGcPHas9u27QrSNQ98hHnT
         rC8ltXaoFnK17PAmCJbNVGU7qJUQosUnc1q+ERuQuEzlNYoDTeSCWk0yJtR/cJV7P/Ic
         7b3ZSHXCfIShpGMtzKt8hY6cqhXD1PcX/9WeqDhjUvQztUZeYik1pDT9v92jQWLWHtrE
         NhX4QSGqiZF6tPgikpQ/hmkoM4wI6ufUQeSpQNPwaKtQf1ukZWgIcZiGAXVCBuvuTDay
         xEUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1Lq6FmCL8Z7KUtTdsphcfrR2t5LioB/XipSSRc/6c0I=;
        b=KdxVIR3kt9Jomo5hQxnuW5japRFzPKiO/OI5zbAwN/oJLhUBf1L5yTrv2KdDUiMII7
         +9KpXHpKjL4X1f3bcb83BLq7bhwIkhP0ytcQrMt84WVpnbrsfcOARG9FT5xhrj1BrFc6
         ORJeIVmKYJdO0Flcedf0glyNtw/L724KeMzmN4sfrRj1PriX2uRzuJKLtFVr7OXS6QOr
         c1oN1EDGddOI7TZNSmT9FoLd7oiJgemtwJnLpMK6oNiTCkcr8RYksafR/XKAz6g3ae4b
         b/x5MGug83n9gxUvFpknSn2d6D7xnpaVokkmItsgGFCfCf9EacEyUpchGnRfo3FqNW3/
         CW0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXFd/0AYKJS7pPHc26URq1jffvC4FjZLMXVAekGMNSSXdRDTa2r
	C+UJnTiLjyI8j1+sjAxWzSk=
X-Google-Smtp-Source: APXvYqwTSNrdioaQgGjRWrTX212KpUy0/i4BlNO8SboEFH6ml6btPpc47kOOIHKGny1K56SWlmz+Bg==
X-Received: by 2002:ac2:5a43:: with SMTP id r3mr3382124lfn.150.1575492742630;
        Wed, 04 Dec 2019 12:52:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc3:: with SMTP id w3ls131516ljj.6.gmail; Wed, 04 Dec
 2019 12:52:22 -0800 (PST)
X-Received: by 2002:a2e:b52a:: with SMTP id z10mr3244692ljm.178.1575492742140;
        Wed, 04 Dec 2019 12:52:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575492742; cv=none;
        d=google.com; s=arc-20160816;
        b=diOIC7co+VU/YHUS6fZzn/S4i6k4zSJaEQTeAWgPdGQhVh0ic6ehA0qyTkvvIFpuYh
         zZjBWVByMKDCDY8hBIZQwShO4W3Hkrk9wfeE9pW6WD8SqYOYzm6SvHShwccXu081BviR
         OG2GLaWVJUbucpN6CrNj8HzO9Vkh/pkcIGUW7fcr04LLoBCYnooZ7805ceTZ+HCFXg9e
         Z7V+371+ll0lbnD3ots44XcX/j9XghrgIVAZdQo6YzusUo5nckyzVJutIjU9gZgoBbUB
         ZiRarI0qcbT1PU6Ed9NGliCuadJLQSyWN9hEz2u/pxLU65dwrPNsAGnpyiXqXv4RNshG
         MG8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=rI921cbdR3FPUrcj6kPsNPEpD4kh09sgPUfwixlZtm8=;
        b=sMgPDjs8VRnVRYkrta7sK+h46mPIAe497yre9BDsHHX/Du2TKk/BKZigd2qh2Al99E
         Mjmu/nE2NvRv03hxsMmNkQdvfN5ohSqgxSuRpF7UYmY9K/O/cqa8Zb1m7ttLIMYQn/68
         M5fSTz7lWk7MaGDVs8NsM7/0RDpqg4YTzoxhJ6NoTCESAd7dW3X7yAeun8gvcyXLO7Bm
         kOfyg7ugqFzLMMejMg0qbb87tYfXN5/F5GQAogK8YD55lHMF2m3p5+WNG6GbIH7NdI7P
         CIvTKueRxT93PNPmsBhA70fP0z/yUVnzEyQI/FZnBYAD2ck9YYxSHWj1858Z6PtqK3mr
         x4tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id f11si607331lfm.2.2019.12.04.12.52.22
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Dec 2019 12:52:22 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [192.168.15.5]
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1icbcl-0001ny-LQ; Wed, 04 Dec 2019 23:51:51 +0300
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Dmitry Vyukov <dvyukov@google.com>, Daniel Vetter
 <daniel.vetter@ffwll.ch>, kasan-dev <kasan-dev@googlegroups.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>,
 Kentaro Takeda <takedakn@nttdata.co.jp>,
 Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
 James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>,
 linux-security-module <linux-security-module@vger.kernel.org>,
 Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
 Daniel Thompson <daniel.thompson@linaro.org>,
 dri-devel <dri-devel@lists.freedesktop.org>, ghalat@redhat.com,
 Linux Fbdev development list <linux-fbdev@vger.kernel.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
 Sam Ravnborg <sam@ravnborg.org>,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>
References: <0000000000002cfc3a0598d42b70@google.com>
 <CAKMK7uFAfw4M6B8WaHx6FBkYDmUBTQ6t3D8RE5BbMt=_5vyp9A@mail.gmail.com>
 <CACT4Y+aV9vzJ6gs9r2RAQP+dQ_vkOc5H6hWu-prF1ECruAE_5w@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <6632ddb6-37bf-dc42-e355-2443c17e6da0@virtuozzo.com>
Date: Wed, 4 Dec 2019 23:49:42 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACT4Y+aV9vzJ6gs9r2RAQP+dQ_vkOc5H6hWu-prF1ECruAE_5w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 12/4/19 9:33 AM, Dmitry Vyukov wrote:
> On Tue, Dec 3, 2019 at 11:37 PM Daniel Vetter <daniel.vetter@ffwll.ch> wrote:
>>
>> On Tue, Dec 3, 2019 at 11:25 PM syzbot
>> <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com> wrote:
>>>
>>> Hello,
>>>
>>> syzbot found the following crash on:
>>>
>>> HEAD commit:    76bb8b05 Merge tag 'kbuild-v5.5' of git://git.kernel.org/p..
>>> git tree:       upstream
>>> console output: https://syzkaller.appspot.com/x/log.txt?x=10bfe282e00000
>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
>>> dashboard link: https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
>>> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>>> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
>>> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000
>>>
>>> IMPORTANT: if you fix the bug, please add the following tag to the commit:
>>> Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
>>>
>>> ==================================================================
>>> BUG: KASAN: slab-out-of-bounds in memcpy include/linux/string.h:380 [inline]
>>> BUG: KASAN: slab-out-of-bounds in fbcon_get_font+0x2b2/0x5e0
>>> drivers/video/fbdev/core/fbcon.c:2465
>>> Read of size 16 at addr ffff888094b0aa10 by task syz-executor414/9999
>>
>> So fbcon allocates some memory, security/tomoyo goes around and frees
>> it, fbcon goes boom because the memory is gone. I'm kinda leaning
>> towards "not an fbcon bug". Adding relevant security folks and mailing
>> lists.
>>
>> But from a very quick look in tomoyo it loosk more like "machine on
>> fire, random corruption all over". No idea what's going on here.
> 
> Hi Daniel,
> 
> This is an out-of-bounds access, not use-after-free.
> I don't know why we print the free stack at all (maybe +Andrey knows),
> but that's what KASAN did from day one. I filed
> https://bugzilla.kernel.org/show_bug.cgi?id=198425 which I think is a
> good idea, I will add your confusion as a data point :)

Because we have that information (free stack) and it usually better to provide
all the information we have rather than hide it. You never known what information
might be needed to fix the bug.
Free memory might be reused and what we report as OOB might be an UAF and free stack
could be useful in such case.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6632ddb6-37bf-dc42-e355-2443c17e6da0%40virtuozzo.com.
