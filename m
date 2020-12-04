Return-Path: <kasan-dev+bncBDGPTM5BQUDRBOVDU37AKGQEIXNLSBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B87A2CE526
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 02:32:43 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id 2sf1403014vkj.11
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 17:32:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607045562; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xio6XXkkV7ANmK32H7fbZ7U7Q0kn3f33w3XFU66kDF8mb72BSqtBTqieHVgBpQqOPB
         79lzudlqtKAVf8bldqUI1SQL9yMx03oEjYJ3nfWpD/yFa63diIrblT9zpg2jvAPCDmHT
         Zs5HdfrBsqDns1r6RB7kL5kNkKYe7Sk77XVGgVS+6mRrh9Mr6BCz7GZvSVMY84bLSlSt
         7+7fURYevpZTu7bjNmFCxT+YC4xytgOLYlLNqwjutrel1xlMB9QGpAjvHKC5gKarXxrY
         NAjWBaItwiGRjg+nrUHZNt1iXdz4b4bfziTCrUbKZ+9QW30REfge9OUnmBPzhQUz68OH
         v5CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=x5/b26eg5flxLOyXHLgTL/sWKfhZf0SatPheqk2Y3rA=;
        b=E3Q0lcb4gxu4bNjzWdaKBNj/r6rgf+ixf1R9o0RwguhjI1BNNtWhPwf7OjjY3y+5Ys
         5VvPjJazSG2WmjedE7pVNprpmJSTsHOv8T+mHe+y/sNZWJ2P4X3d1/1xPgHllJCUZPsx
         +LHK4nApdSkEvQxhWEQzS6FUIbTuGX3i7X2sAYTvTBd21frmsppI9LbwFvA/oDvp1+dp
         jJHO9ZC8VCBqy5DXzJuxEdZuUcESYnAsKl9j++8pCRzvodEbnl6aHhhjI9d5oQaH8o2o
         vqVR+jfv9LboOrCopsb3hZfuKCJV488JzRkIBmVldW6Xwc8Y4K1tyRAPuSeW5bI4Qddc
         wwdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZRa98cbv;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x5/b26eg5flxLOyXHLgTL/sWKfhZf0SatPheqk2Y3rA=;
        b=s//1ikvJGm8q4f5AfDLHHVmKGvHIVJ12SzxJUuUrV8hAHQL+tLqZgL1juyd5Z+8JfK
         VuvXknZP7ahAh2ecOqOUdcHFVxvYHHrE5JdpEivmy3yadhciYZo4FXAwjcmHmJh2Rntz
         k2EuSyyxuSvP7Rfs5II/N/KNoIW2r/a7tbknUfMQlMZ3gC18g0uVke7c6vv6FR2b5xd9
         VMvqAZ+I7HFejy4mBvJ8q5eTn0QxWLS82u0ai1kI0Ea+rp/OlVBpCbZ4URbosNq/U/CH
         +mu5AKI03KIMN0R3I15+RLfaSBN1770v0Afz1ulzGcBdi/tLNwE463WWzayMZJOsxBf4
         0P7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x5/b26eg5flxLOyXHLgTL/sWKfhZf0SatPheqk2Y3rA=;
        b=YJ3ho4iQlNBf/jf8Zu/tJZQVuJYE8BuEkCGQ2g7y+SUGcWxigyFaDTjltPanJHgNM4
         oImrGbR6ZLHAwLjpc1hu7KLbZiwx+hdNtJwHVWpVkFPI8f90dmkwsM3EiDUHjwynnaWU
         4iH4R7KuJ7XsZ+654+IEFW/Jkbcfj2R4Z9fE/6eixIwsklHj6ggx0nCxjojQpU9jzEqZ
         qwVWgQAoCqp0yG5LZhm+NhDmvKULMirL8IP3ZNFCJeyWXL28r1IDXkV6YKx6Pqt1T/yC
         HgtOzKkFp5+Psgcvl4MZLZgRE2vf4e/81Jr3EecxkCjr+13TMhwoy8HHwBxPDspFGO8l
         /ZFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530F+SKLxq+YGqmna1V1A/+gf5/FVGoJe+165niuodNIhV24WlhD
	1cVIWqDFYNGlBIB/sJ7k6js=
X-Google-Smtp-Source: ABdhPJx4XyRnf0CH6S/Y6LNdnzklmb/8YpC/VeOlAMI0XUBbLASVvI57jUhS1IGE+lOrIbNlhjdsNg==
X-Received: by 2002:a67:e43:: with SMTP id 64mr1513057vso.40.1607045562483;
        Thu, 03 Dec 2020 17:32:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2758:: with SMTP id n85ls458567vkn.8.gmail; Thu, 03 Dec
 2020 17:32:42 -0800 (PST)
X-Received: by 2002:a05:6122:1252:: with SMTP id b18mr2014204vkp.18.1607045561994;
        Thu, 03 Dec 2020 17:32:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607045561; cv=none;
        d=google.com; s=arc-20160816;
        b=rUyruKONPXlEzbd0VK01BKxVAvbAMwcNqc2nT5+8nEdNHA24xi22TUfW5NAjxBOczf
         0zrsQ3+6dkK6ik7A/OabtaQaTXgIYYUQLOBbNFJbh1WhazlgQIyz9+v6DEp/gij0nEy6
         bByfi8mYDeUFHj92gLriuU1wJc5tOpwku+Q1KZanSznHPRPhiGNyk3er23k61wWwhEt3
         zGVls6wxRBTpUflMs6MQUy7b8J95VR5i2fsBL7a0s24JXqAu4a7KIdBCzTwUt2vfBykO
         X5RSkQuaeWiWN1la4MDPwB8ZS3gNPkR8uJ9w7tsEX48qrDQyxsE/rMOImd4XWeKZqKsF
         Pf9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=KWikmV/wDlXuDUVsDyFD6GjELptOAMlHj8HVv2I+cPU=;
        b=okrLK0CfHI45YP0NcOLbCl97NBZKRVGKv2qVrYZD0Pxj3EC02sQ71aGjv3p6BX2W5c
         Ub7J3y+wekXLLRsdOR6vIrmmneF+bkdxuxR+U52Lhuxruk53MLhHPzyssw/+iaivrufD
         S4cfKfy53rZJIxT+yCI6/+ZNusAQ3PSir0U1aDFLUYUlk+EPcZHRFFKXPcsXQF4wif3X
         5RMnVQIyJQrAPP2PeQq2s4XUQWutogwsVj7rd1ne18u00rSEYj0dpi0GgNMbkEsYLqKU
         tL3hGQ7q1fp6Xm4ANX3LDKFJoMJ31GJvR55P5SuGD1H+iLwb0W4pS19Qimq1lYyO7Cxw
         rXZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b=ZRa98cbv;
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id y127si106490vsc.0.2020.12.03.17.32.40
        for <kasan-dev@googlegroups.com>;
        Thu, 03 Dec 2020 17:32:41 -0800 (PST)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: d80cba357d9f4d2fb81a75de8ef28301-20201204
X-UUID: d80cba357d9f4d2fb81a75de8ef28301-20201204
Received: from mtkexhb01.mediatek.inc [(172.21.101.102)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 633230048; Fri, 04 Dec 2020 09:32:37 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs01n1.mediatek.inc (172.21.101.68) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Fri, 4 Dec 2020 09:32:34 +0800
Received: from [172.21.84.99] (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Fri, 4 Dec 2020 09:32:36 +0800
Message-ID: <1607045555.4722.7.camel@mtksdccf07>
Subject: Re: [PATCH v5 3/4] lib/test_kasan.c: add workqueue test case
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>
CC: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin
	<aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, "Dmitry
 Vyukov" <dvyukov@google.com>, Andrey Konovalov <andreyknvl@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev
	<kasan-dev@googlegroups.com>, Linux Memory Management List
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Fri, 4 Dec 2020 09:32:35 +0800
In-Reply-To: <CANpmjNNdaiN=J0TU_AjAoH=ECNC8dJWS8HTvJs9nxBkJce9AmQ@mail.gmail.com>
References: <20201203022748.30681-1-walter-zh.wu@mediatek.com>
	 <CANpmjNNdaiN=J0TU_AjAoH=ECNC8dJWS8HTvJs9nxBkJce9AmQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b=ZRa98cbv;       spf=pass
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

On Thu, 2020-12-03 at 11:29 +0100, Marco Elver wrote:
> On Thu, 3 Dec 2020 at 03:27, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Adds a test to verify workqueue stack recording and print it in
> > KASAN report.
> >
> > The KASAN report was as follows(cleaned up slightly):
> >
> >  BUG: KASAN: use-after-free in kasan_workqueue_uaf
> >
> >  Freed by task 54:
> >   kasan_save_stack+0x24/0x50
> >   kasan_set_track+0x24/0x38
> >   kasan_set_free_info+0x20/0x40
> >   __kasan_slab_free+0x10c/0x170
> >   kasan_slab_free+0x10/0x18
> >   kfree+0x98/0x270
> >   kasan_workqueue_work+0xc/0x18
> >
> >  Last potentially related work creation:
> >   kasan_save_stack+0x24/0x50
> >   kasan_record_wq_stack+0xa8/0xb8
> >   insert_work+0x48/0x288
> >   __queue_work+0x3e8/0xc40
> >   queue_work_on+0xf4/0x118
> >   kasan_workqueue_uaf+0xfc/0x190
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Acked-by: Marco Elver <elver@google.com>
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > ---
> >
> > v4:
> > - testcase has merge conflict, so that rebase onto the KASAN-KUNIT
> >
> > ---
> >  lib/test_kasan_module.c | 29 +++++++++++++++++++++++++++++
> >  1 file changed, 29 insertions(+)
> >
> > diff --git a/lib/test_kasan_module.c b/lib/test_kasan_module.c
> > index 2d68db6ae67b..62a87854b120 100644
> > --- a/lib/test_kasan_module.c
> > +++ b/lib/test_kasan_module.c
> > @@ -91,6 +91,34 @@ static noinline void __init kasan_rcu_uaf(void)
> >         call_rcu(&global_rcu_ptr->rcu, kasan_rcu_reclaim);
> >  }
> >
> > +static noinline void __init kasan_workqueue_work(struct work_struct *work)
> > +{
> > +       kfree(work);
> > +}
> > +
> > +static noinline void __init kasan_workqueue_uaf(void)
> > +{
> > +       struct workqueue_struct *workqueue;
> > +       struct work_struct *work;
> > +
> > +       workqueue = create_workqueue("kasan_wq_test");
> > +       if (!workqueue) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +       work = kmalloc(sizeof(struct work_struct), GFP_KERNEL);
> > +       if (!work) {
> > +               pr_err("Allocation failed\n");
> > +               return;
> > +       }
> > +
> > +       INIT_WORK(work, kasan_workqueue_work);
> > +       queue_work(workqueue, work);
> > +       destroy_workqueue(workqueue);
> > +
> > +       pr_info("use-after-free on workqueue\n");
> > +       ((volatile struct work_struct *)work)->data;
> > +}
> >
> >  static int __init test_kasan_module_init(void)
> >  {
> > @@ -102,6 +130,7 @@ static int __init test_kasan_module_init(void)
> >
> >         copy_user_test();
> >         kasan_rcu_uaf();
> > +       kasan_workqueue_uaf();
> 
> 
> Why can't this go into the KUnit based KASAN test?

This test case has not been ported to KUnit, because KUnit's expect
failure will not check whether the work stack is exist. So it remains in
test_kasan_module, it is the same with kasan_rcu_uaf()[1].

[1]https://lkml.org/lkml/2020/8/1/45

Thanks.
Walter



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1607045555.4722.7.camel%40mtksdccf07.
