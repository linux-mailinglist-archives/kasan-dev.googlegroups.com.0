Return-Path: <kasan-dev+bncBC2OPIG4UICBBVWMSKBAMGQEGZGKAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DC779330007
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Mar 2021 11:09:27 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id s18sf4717059pfe.10
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Mar 2021 02:09:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615111766; cv=pass;
        d=google.com; s=arc-20160816;
        b=D83qeRFgoKYyhTcR4IndRcLPS2QPVUrDZkFHKj+DqkUBJoPFZNwE0yMKkGr6KYb0cv
         M6dhgg22GryJCxPSLM935+VHYWFhwM/JpG1RC3sWbTMSwK3EmJzabBvyXIGywO40fYij
         pZDF0E9ZJHm46HLUKUrsoyFVnAgvAwjFc+k7ug8g4TsIHNUkpGDx0QJ+aHPxufRsPtg5
         HqHRpcPzTqVgJbFEgbvtNgaZE5jNE3KFrj7o88MUdw7bG1eVzJOQqfxDjCBhtBME7a9I
         xQbH+AlNqiWkYdvxeia6xkpVBy9bLqsTogPSRiMeDwktTIdy4EA5WXcM3QGvD+bTJFgY
         B6aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9aNkVToYQ5/Tn07jBRPlCEHBVM8Uu8fom810cH8+Pak=;
        b=VB0XZk6DHCUw32UTgB0XM0w5bOl5OFXVRtof+n8SL0wfYZHaj9p3eI6Kkzuw3D//ak
         yZVcRfdPOwzl1Tux676cqlQwmvkYyXE+Uc60dPni21m8OcboPgwAXbox52YgKc9d1xF4
         T4KSjVOLsX+NgF6RjRdOdJ1p+naHhvZiDbObppXq3fty/RPJJ6eSyjlQPNFHAbEGONnP
         pMaJ3bEQK25HS+uoq+fg2EgXneepLu9Nnscy/bgi0dCsP1bD4QgMhx5TEH/xJcIH4+jI
         2BwWgpyomEdGfmCMky0s+8v0hqXhvHZZBR4/IAm3C5dzy+vADgVO6FpgEEei27yxXXps
         iFDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.163 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9aNkVToYQ5/Tn07jBRPlCEHBVM8Uu8fom810cH8+Pak=;
        b=l/LKG5IB2Yb+7/cpFKhQV4wctaFsxP2WEdEdHSdFxR10DKS/GXONZCzi14RjPhNbCe
         Kn/9AI4FEAEYraeUM2TN4tPGFGAyTCEkt0e9raPxvKXMzjNW6IBqW9G6TAiV6r4FyLIM
         9S17SwB2Q5OioDmbSmG85FO7C+r8OUWj5v6mUp3WihaZCWqa0nGWUtzEGGbA4exXVzL4
         RnClyd6U+HeVGmPBAHP7JLwNgtGk7wpzhr4CmPGyStYUDQiTiIvw6W/6+jy+V2MqMVaI
         BdVeRNIfce/mcccF3uXrCkRLIWSK+ciFzR22HlAO5AFfdpBUqtV59yGRaWacgHAumKXo
         FUEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9aNkVToYQ5/Tn07jBRPlCEHBVM8Uu8fom810cH8+Pak=;
        b=KX/dEdi5RIGOxUUaKZ68gDc+qvfh+Nms+75fX4grywORlUoaBQA1IGefK44sV2hk7f
         BHmddiRQ9vZ2c2ScW82fCcWBvAbNEiMlmYqXFpc7GFFktHgwcrxIFFDz9JlaZkdB93fR
         Sh7vUXDHQklraBTOqC6ja/VzYt724j3kyTDrs/14NjdvdhqaIBbUn20a1MxPT65UPb1J
         tqxJremAb21g6CWn3XBZw4TjnWRrrGSzz9UQpKBVlV+AAkyWfV8H0k2UL0i2iRFYZz2u
         ZT0ww9gbC+Q4/0r7hXBC/I9gRDbfiNTyEzp34Clw5EdakqRuCFS0wHhiHuprF+CoSgTA
         vwIg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5325BcBxbzVLMo/ofrBAUSKLhrv+4zkcjIETXMosaH/u+waCzaRn
	LBPsoMjd3UMt0JImar6SiII=
X-Google-Smtp-Source: ABdhPJxWZBZfjzJVcHdjBsy+yI6OUVEGtFBc6zeBTr+rPq3Bd5u0BhuFB97d7ZkvNXz7rxOUMQXEqg==
X-Received: by 2002:a17:90b:307:: with SMTP id ay7mr10725038pjb.110.1615111766523;
        Sun, 07 Mar 2021 02:09:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:16d6:: with SMTP id y22ls8063940pje.3.gmail; Sun, 07
 Mar 2021 02:09:26 -0800 (PST)
X-Received: by 2002:a17:90a:8901:: with SMTP id u1mr18857790pjn.21.1615111765988;
        Sun, 07 Mar 2021 02:09:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615111765; cv=none;
        d=google.com; s=arc-20160816;
        b=TrXWXn5np8Xtg0+XKeZVNT1a/DCdkcQjYhNw6BfwpbzDkLPooNZ6aXqXkAiAj2VMfG
         qZCkw90sLzP2+VILrTV02DQk18T4b+JgH3zd2XsZbHAoaQN3byc1/A4ntNSURSv76v9O
         Rqg5deNFIRX/6EvEaKOxV4WpiEn8LjuozPEe9S2/h31/QojYJQwyP1R9BJhIUHKTywkR
         ZCyZMFkxwu5sUY2bgHvZ+EA1EcoDKsU0jd4WeF3Px0cvqtFzwVIEGVibwKn0iikeaOhT
         alKdBJm4H2QGb1zPABgvQtBNRcCBXvE0dt1Vb3rtv1GMPA+7UKnWF6STsx4hN4tGxf9L
         70rA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eqOlLHzvsH3ciJWIHs6ZwXKjE8q6EQYmeLhytY48H6w=;
        b=gl9RwHxGm1nAI4oK9ItXzjv+qCpvgtPlT7P5aOGC1soU+RlEYK2fUvag/tdQnqeAeX
         4jcfrYCMYGVzIArB2CBES66g8DwICbXLVotPtaEtm6dTv46EmbncazYje2vp2F1Ykxbo
         5I4IffChckBH6gEhvQd913W2bA0nxlvYvaeZ+bEebTDOMI9X4wVw0mPjuuaFXLizRxoN
         gnD4WxOiQPZyaGq6tsBpudH6gTk8HKnFuYe/ZMKbD2ZiOBFJUg/Fi8KA3Pn35rhRbRf4
         EyXTZwXfac6mlrm+QiU3K0FEA2QbBihSiHhFidOVxz8QJIMIf4k5MeNYHKGuKIFbE/VE
         Nzgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.163 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from mail3-163.sinamail.sina.com.cn (mail3-163.sinamail.sina.com.cn. [202.108.3.163])
        by gmr-mx.google.com with SMTP id x1si433126plm.5.2021.03.07.02.09.25
        for <kasan-dev@googlegroups.com>;
        Sun, 07 Mar 2021 02:09:25 -0800 (PST)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.163 as permitted sender) client-ip=202.108.3.163;
Received: from unknown (HELO localhost.localdomain)([123.119.98.197])
	by sina.com (172.16.97.27) with ESMTP
	id 6044A6460002DFCB; Sun, 7 Mar 2021 18:09:14 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 1454449283219
From: Hillf Danton <hdanton@sina.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Hillf Danton <hdanton@sina.com>,
	Ming Lei <ming.lei@redhat.com>,
	Paolo Valente <paolo.valente@linaro.org>,
	Ming Lei <tom.leiming@gmail.com>,
	Mikhail Gavrilov <mikhail.v.gavrilov@gmail.com>,
	Palash Oswal <oswalpalash@gmail.com>,
	linux-block <linux-block@vger.kernel.org>,
	Jens Axboe <axboe@fb.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [bugreport 5.9-rc8] general protection fault in __bfq_deactivate_entity
Date: Sun,  7 Mar 2021 18:09:00 +0800
Message-Id: <20210307100900.13768-1-hdanton@sina.com>
In-Reply-To: <CACT4Y+aLnam+7FGx9MiMRRbgFE6v+Vg6Hu0hkx+P=h+DL8Mayg@mail.gmail.com>
References: <CABXGCsP63mN+G1xE7UBfVRuDRcJiRRC7EXU2y25f9rXkoU-0LQ@mail.gmail.com> <CACVXFVOy8928GNowCQRGQKQxuLtHn0V+pYk1kzeOyc0pyDvkjQ@mail.gmail.com> <20210305090022.1863-1-hdanton@sina.com> <CACVXFVPp_byzrYVwyo05u0v3zoPP42FKZhfWMb6GMBno1rCZRw@mail.gmail.com> <E28250BB-FBFF-4F02-B7A2-9530340E481E@linaro.org> <YEIBYLnAqdueErun@T590> <20210307021524.13260-1-hdanton@sina.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.163 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Sun, 7 Mar 2021 08:46:19 +0100  Dmitry Vyukov wrote:
> On Sun, Mar 7, 2021 at 3:15 AM Hillf Danton <hdanton@sina.com> wrote:
> >
> > Dmitry can you shed some light on the tricks to config kasan to print
> > Call Trace as the reports with the leading [syzbot] on the subject line do?
> 
> +kasan-dev
> 
> Hi Hillf,
> 
> KASAN prints stack traces always unconditionally. There is nothing you
> need to do at all.

Got it, thanks.

> Do you have any reports w/o stack traces?

No, but I saw different formats in Call Trace prints.

Below from [1] is the instance without file name and line number printed,
while both info help spot the cause of the reported issue.

>>>>>>>>>>>>>>>>>>>>>>>>>

I was running syzkaller and I found the following issue :

Head Commit : b1313fe517ca3703119dcc99ef3bbf75ab42bcfb ( v5.10.4 )
Git Tree : stable
Console Output :
[  242.769080] INFO: task repro:2639 blocked for more than 120 seconds.
[  242.769096]       Not tainted 5.10.4 #8
[  242.769103] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs"
disables this message.
[  242.769112] task:repro           state:D stack:    0 pid: 2639
ppid:  2638 flags:0x00000004
[  242.769126] Call Trace:
[  242.769148]  __schedule+0x28d/0x7e0
[  242.769162]  ? __percpu_counter_sum+0x75/0x90
[  242.769175]  schedule+0x4f/0xc0
[  242.769187]  __io_uring_task_cancel+0xad/0xf0
[  242.769198]  ? wait_woken+0x80/0x80
[  242.769210]  bprm_execve+0x67/0x8a0
[  242.769223]  do_execveat_common+0x1d2/0x220
[  242.769235]  __x64_sys_execveat+0x5d/0x70
[  242.769249]  do_syscall_64+0x38/0x90
[  242.769260]  entry_SYSCALL_64_after_hwframe+0x44/0xa9

[1] https://lore.kernel.org/lkml/CAGyP=7cFM6BJE7X2PN9YUptQgt5uQYwM4aVmOiVayQPJg1pqaA@mail.gmail.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210307100900.13768-1-hdanton%40sina.com.
