Return-Path: <kasan-dev+bncBDAMN6NI5EERBEU7TH7AKGQEDZY7R2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A3192CA53E
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 15:13:38 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id r5sf1022165wma.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 06:13:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606832018; cv=pass;
        d=google.com; s=arc-20160816;
        b=u9j6jgXLwQ2NSQShaWuYxldTZFk3DQHYeYdnzXllA3l1EbdQPC1jsKnqreEpqR3PPd
         JDbPhTiDdVXT+T3nB0Q2OYLywictXTgpz3QiiibSUgusqv6b4XIdqGeqO6NZwMMzcVm1
         QSMl4bDeBUnkPrFNpR31ETIftV5RPMKtY5cA6oRo/LeZcRx4V/FNwC8gtDrhYO28frU2
         zkIg2g51B3rySox/FTcLg9bBrmpSqIUyo5szkbDVX0x6uHlsZUflXWJHV3mbYJA1SOE+
         AyjYPCUr+RSDFT1v6XzqPPwMDhppmVLvlGQ+uo3Vi+dJPH8DXs+oLf5mV+2YNSfi2pRs
         o/Ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=MopErW93lLe0cSh8aeUP9/l3wq8sK3CqaLIBuQ8oNO8=;
        b=hDSlK5YulrbQsSz8aLKIXK1jGtqme8PoDPN2BBiC6DHByRj+qEMFl0q4JfiGeBwqSm
         /fMUHOTYXRi5I7oTrnceKFkx9Gl4TITI5YSv023c2dODtjiC28OdbaVKhkUQvbXhBBdC
         pLnJPG9D/8ks46LAK3fK4ft4iIHRdu7QCpY1p1VY4ueYNd9bEtSZ1pixJ1EzVtUqz04n
         lpUzOm4tsdM6rB+VKrdgHzIRhJhDIuTllnLofymbcJrjATGnrPnoKWa/93RQPa6AXZWc
         F5WpYRxCZSVmTPkN343PG9kOetyOngNHKLj19u/CfZB+b5vySyYjTBvbuBlXSrBSu0z9
         0tlw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Mw9HOaWV;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MopErW93lLe0cSh8aeUP9/l3wq8sK3CqaLIBuQ8oNO8=;
        b=lWTJWuf7bsIyBei95+zdDH+F0kiqGcKAmH0p1znQLSYbcOZ5PVgAaKKleIu/ea2Oaz
         T2wbypPKKkqN4ZV+X62u66qRqhQ6Es2ndka69lOGb095ARwlvhzlOO7ovDU6qfaw1QMG
         W/Ki6meLTDgw+KmViG9LQb3ESNFzixudMqzzqDVsPbmfu0rzRLUen69H65n0pFjCpF1e
         Q5VNTsqCdQcoWC8+fazKsUI3v0bTZOFvgQxREjkOMtIxgBqhZKyUxZLm6VSDV/On9eW1
         cWng/207qfKFpEtB3GluoJZvDEuBCw2rrnSwLIT+Ds4tdm8sx9W39W0SJ+YyDtLtDtg5
         VWlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MopErW93lLe0cSh8aeUP9/l3wq8sK3CqaLIBuQ8oNO8=;
        b=S1oNpZPXfKnZCsquQNhmyAwykMk9ya+2WUFsHBbFtF7qOYzDLtX3s/YWHVS+l5WxGb
         WEy4jdU6DLxflTySViY7/n+4Shy2C2FU4h7V5GOrYG3a1/ap4mN9WWpl/SXc8vzvZFhW
         dFmrj0UhuaTLHSSE3PtJha3tQmF7cb4g5EzmUfoFgKRaDWenyHqvDztrZOfaHk1DT+nW
         fe3sJD3M9S/+RfurJ+DLOAEZsbwedfCIEcpayoZzYkwAzW0ZOWhqjVRW8BGmiqAqxRPR
         wE1+2DaZfAdhn15HD7v8ajtr0QEvx3EmT7ELNYPNIbR9fMTHLEtoXVa8yhdXCWk0BK6o
         6OTQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ZwwY5ysGBw/V+9mMT5ZUxs4eC7aePO0EwmR6k6obZDq67zO0p
	ouWO4WaUypNTdhcd5LCYWzY=
X-Google-Smtp-Source: ABdhPJxAGY0TXdWnauJiJObTFxnikZ+j7zzgW8QX9HMP/xruPeucD9dTuM5EPPkoO5mEmji+YG8kEA==
X-Received: by 2002:a1c:a9c8:: with SMTP id s191mr2928898wme.89.1606832018285;
        Tue, 01 Dec 2020 06:13:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aa87:: with SMTP id h7ls394191wrc.2.gmail; Tue, 01 Dec
 2020 06:13:37 -0800 (PST)
X-Received: by 2002:a5d:5146:: with SMTP id u6mr4271006wrt.66.1606832017321;
        Tue, 01 Dec 2020 06:13:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606832017; cv=none;
        d=google.com; s=arc-20160816;
        b=lq1+olCu787jb18Z8+4dC5K2AVlne0sPCRCJbZfCY6NXpx+5BML+6MhqweVzy4m8Mn
         nINi2Mg8SuHWZdfW3Z187XGU2v824siwscyhn9hqF1DONmk0Ore8WL0OhZGIJqwLFeWN
         qGmA+VsHk+pK8WovL6chgM6azrM+psfYy+HwY28S1BxPyLM/UaTxRo8VPmEdNXIw+0Mu
         HAO21657ansAPMc0Gz4NWsWPjjw77SppNwGenUKcAeIzs0QE/Sx7o6kwlkbsU9lDMTQX
         qellnti5z3SArWX0hbICpE0LRNcUSeqIO7QY6RWOURp1Viwk9OT83hRp3AMsEUweNpBs
         hFPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=Skhg6O9p2Trnjrbm81ayS393ZogAa9PiayeejAPB7Ow=;
        b=YxeLDsanjX4MFR4di6ymAiKtNs28xwyC7cjkGNInVvyJNw/L7E957UEHwkK+a7Hkhq
         iG5vhK4bCgQTYOVgUm+xlfCWhRHAcOGdoCVtqmmVBpHYKRabQEI+cr3ZMGbLZLchABhQ
         06oWg9ESOPo7tBUw3NhznNKJ2BWG92yg7+fYg1pamKxRwMU1Xt9Oyyy0swBmZ82xJcfQ
         yZCG7kCM645lx7kf8P+id8giSHymRoFJlP4M4CYGew8DhQnNMr9P5ZpY2cCvyytuRXnZ
         O1JzLjRZ3ppuqmooPdCs/95/S6SR5qIq0bZQq6s+EeaGQep65khEw5JocFpbLwq2OHmG
         4PRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=Mw9HOaWV;
       dkim=neutral (no key) header.i=@linutronix.de;
       spf=pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id x12si79090wmk.1.2020.12.01.06.13.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 06:13:37 -0800 (PST)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: Thomas Gleixner <tglx@linutronix.de>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrew Morton <akpm@linux-foundation.org>, John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
In-Reply-To: <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com> <87h7rfi8pn.fsf@nanos.tec.linutronix.de> <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
Date: Tue, 01 Dec 2020 15:13:36 +0100
Message-ID: <871rg9hawf.fsf@nanos.tec.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=Mw9HOaWV;       dkim=neutral
 (no key) header.i=@linutronix.de;       spf=pass (google.com: domain of
 tglx@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender)
 smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE sp=QUARANTINE
 dis=NONE) header.from=linutronix.de
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

On Tue, Dec 01 2020 at 08:59, Dmitry Vyukov wrote:
> On Wed, Sep 30, 2020 at 5:29 PM Thomas Gleixner <tglx@linutronix.de> wrote:
>> On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
>> > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
>> > In some of these access/allocation happened in process_one_work(),
>> > we see the free stack is useless in KASAN report, it doesn't help
>> > programmers to solve UAF on workqueue. The same may stand for times.
>> >
>> > This patchset improves KASAN reports by making them to have workqueue
>> > queueing stack and timer stack information. It is useful for programmers
>> > to solve use-after-free or double-free memory issue.
>> >
>> > Generic KASAN also records the last two workqueue and timer stacks and
>> > prints them in KASAN report. It is only suitable for generic KASAN.
>
> Walter, did you mail v5?
> Checking statuses of KASAN issues and this seems to be not in linux-next.
>
>> > [1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
>> > [2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
>>
>> How are these links useful for people who do not have a gurgle account?
>
> This is a public mailing list archive, so effectively the same way as
> lore links ;)

Just that it asked me to log in last time. That's why I wrote the
above. Today it does not, odd.

Thanks,

        tglx


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rg9hawf.fsf%40nanos.tec.linutronix.de.
