Return-Path: <kasan-dev+bncBCMIZB7QWENRBC42TH7AKGQENYGCGMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E4D762CA4D2
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 15:02:52 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id o128sf1079487pga.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 06:02:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606831371; cv=pass;
        d=google.com; s=arc-20160816;
        b=C51r3+S5SqWOMVqY5LbKxJi+fYa/nm9P4mg/2CzMpDsnmfh+lskcNSZEq71dYC5K/t
         XsC4jFE6WNWNXumoj5m/QRDXYae9tUHmQPwu0TTulPdJjAg15yO6dHHgcIBBbkO1+VkR
         2UALrAg4GEYv1swxB7AIX5P4+wsGy2vRRwgcZTlMYWQSFlbxkIK5Ja9rluFZ6g6KacXE
         bWmL5zgX37zgK5vS2r9H4cm4TU5hAgg855MBAKGDWKd80jfyHk9kxUdUc54r8KBXH6c+
         lfjyYCYGTj2+/Xm6yCqezG/2GNpWUJ4uzO+u6JiExDcHxuNQmyQf+7tAUQ1Y7wm1iBsU
         oAZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ebIYyxhieVhMc1Bsv3wwKHnLUov5b1ArSTejL2W0Jak=;
        b=KPzJjJMsXfx0vzMOnAN+MSRFe24DDk7O81yslrfGF06DUioN60xHvpwIYV8VyILzAI
         cxhGzJTUB45mpAS1cD3+SdAn+oXakIZntqOzloFIECRZ/1DSUCemMH9KSszM+mWVWbwo
         Xu23tuX4PAFr97ReRhJwjcT8SQGULiuipY0Ep29M60pLdXwTkBLD97lhXhr8SRdGtE20
         JDeYGDVDJ1JjIWXukQS+l/AVIl4xizAXOOS/IvLqXFgiuNWIYDkYObri1vgA+OIx/TeE
         pmWpuQRTfAwYqiZEAKFSdqFaTuwW++8m10zgSKgSDugFhuEn+zxEeksu2QYViXsAoC/C
         B/vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfxTVBHw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ebIYyxhieVhMc1Bsv3wwKHnLUov5b1ArSTejL2W0Jak=;
        b=F4l1R0iwmxgUYZ8+O4e5mJ6Bsucfv3i40jRwIzWK6hf9BFLp440i0pQJewZZY28ZVC
         GYDOauU5UtEcjXuTcaSAb28cTrHNRjAZQ+o2cR3Z1ZXUt7SsoJotr88DxmCDTHKPi6G/
         AyAc6KpxnTCA4hpg+hmb7dp/rH7xQx3N2vdqYECfR2LtEB/zSvRKUzhKh4Xtav/YUp5n
         Na2Uh9Klmo1cOlEN33RvpRc/Gs3GQLezlY5o+6cVbInEa0B4r8GQ35GzoV6AM9ZJqs4l
         yzay0SERyessrdaqs7EKrDu6Px7uaO96HWM87sS7TMKLFx3oM5KrzrzSuocHH3RaZf6m
         OTcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ebIYyxhieVhMc1Bsv3wwKHnLUov5b1ArSTejL2W0Jak=;
        b=Hey4k23tJRh4bTxiXQQiZyqchU/7OybqUXu7VSMq4FsjsGOCfe90Eceo6xaUxjX65N
         ZC4TrGmL/WsVTIYlxmczOIzFeTiMCSag0F+O/9hbnf0KYYwHOH5KqEumAmM1n618aXZ8
         W1UmidHH2qSKdSvSd0717cYeBoNmSRVnQj375A0uHlpUzCwRjg0gmPvtf4SdYQGinUu6
         3zfMuo/5NkdZzYxEjMBluEb6ub7f2QBIaRArVyq/Bs8TzplkS9XeHMb9CZDVcA14I4vr
         uRE3xRBWtuaW5Lxy/FayOxrNut0RozoZGmjLyplVVbv8+aeTyUcJkDTV8Giw5ZdxGFFb
         TvNA==
X-Gm-Message-State: AOAM531vaVAGwlYzltaV9U/R9zAIZQid8DRYqxgN80U8ZDv4LVKZAVML
	FKYS0oYpWQ51oMIn7PusXe0=
X-Google-Smtp-Source: ABdhPJydr6WtFXVT4VaMc2cql6ir/us2jZw+4XEvkc+abodCeRiImODJbHPLpWZqMrXhr9iChleA3w==
X-Received: by 2002:a63:5c19:: with SMTP id q25mr2342820pgb.189.1606831371675;
        Tue, 01 Dec 2020 06:02:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a47:: with SMTP id x7ls1034209plv.1.gmail; Tue, 01
 Dec 2020 06:02:51 -0800 (PST)
X-Received: by 2002:a17:902:b209:b029:d8:e821:efc6 with SMTP id t9-20020a170902b209b02900d8e821efc6mr2878385plr.5.1606831371077;
        Tue, 01 Dec 2020 06:02:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606831371; cv=none;
        d=google.com; s=arc-20160816;
        b=sJOwi67jn0CMJ1nRDfBix28EoJlZcOV1WHlaqmGrwxzgkPjBKVpoDr/JRxfzOjgNNp
         jnL4W2nagHwVi4HWqD2CjWPSW4ijrpbR7RqHhrSWEHS2uoChzeLaSZbGpMUljQAE7oGh
         fHs1mfKrr/dBT69NYTYTnNKLRxuInJqJG5l4N0tQn/k5S1Pv2mLp565syKsDvnS8VsHd
         ziT+5ncSFE13u4Z/sPqbiV20cCpjPVwqYcWZCggjlItGpoLNCzmBGVwJ+Hs0gM/WVDKp
         pqKKR4FpW5fwdc2UauVTa12fIj51GU732ZiZLwzEEQ/WC+7TKX6Ce7LjB+4Csl/vkBKp
         /7tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DowCnJV0jJLxqPNhupVbMRSWGm+7uLhFQL0+P+g8v1E=;
        b=Q3uguuDDGBTTnt5FDZeuKdDfKXthab8ubEKcmgA1Om9/rxK5BhcVXMokXPFNmJyVtO
         +TtzgiCWf/77XshsmBqKklJvp04PmqFEsBpmeVqPRMP8nshHpUJVEdQRdkg0JzT8St+c
         7nYCt2vpZ2q+/l3hEEaVvxRvgad8S3WQWEm+258yS0GGKzRo6CjlbVxA+ZhbmSg0ieKT
         GePWJKJTG3D/2QKvY1mTpflCx0vTXQBdEbo6csGO9vAo1lCiC0zY1cPIBwt8w7rvji3E
         RBJabKyL2UKBC18YyeRI2kskN0Ond1PW9UUPPkKRao4rO2FS0N4hW8O6xjIBpI2Im7+S
         dkQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QfxTVBHw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id d12si125095pll.0.2020.12.01.06.02.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 06:02:51 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id u21so1110213qtw.11
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 06:02:51 -0800 (PST)
X-Received: by 2002:aed:2664:: with SMTP id z91mr2947243qtc.290.1606831369999;
 Tue, 01 Dec 2020 06:02:49 -0800 (PST)
MIME-Version: 1.0
References: <20200924040152.30851-1-walter-zh.wu@mediatek.com>
 <87h7rfi8pn.fsf@nanos.tec.linutronix.de> <CACT4Y+a=GmYVZwwjyXwO=_AeGy4QB9X=5x7cL76erwjPvRW6Zw@mail.gmail.com>
 <1606821422.6563.10.camel@mtksdccf07>
In-Reply-To: <1606821422.6563.10.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Dec 2020 15:02:38 +0100
Message-ID: <CACT4Y+Yy8S0L18u3q1Y1K1r-qqXRWzrVVLPNR_En0hJ9nX7Tbw@mail.gmail.com>
Subject: Re: [PATCH v4 0/6] kasan: add workqueue and timer stack for generic KASAN
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Andrew Morton <akpm@linux-foundation.org>, 
	John Stultz <john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Tejun Heo <tj@kernel.org>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Marco Elver <elver@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QfxTVBHw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Dec 1, 2020 at 12:17 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> Hi Dmitry,
>
> On Tue, 2020-12-01 at 08:59 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> > On Wed, Sep 30, 2020 at 5:29 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > >
> > > On Thu, Sep 24 2020 at 12:01, Walter Wu wrote:
> > > > Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
> > > > In some of these access/allocation happened in process_one_work(),
> > > > we see the free stack is useless in KASAN report, it doesn't help
> > > > programmers to solve UAF on workqueue. The same may stand for times.
> > > >
> > > > This patchset improves KASAN reports by making them to have workqueue
> > > > queueing stack and timer stack information. It is useful for programmers
> > > > to solve use-after-free or double-free memory issue.
> > > >
> > > > Generic KASAN also records the last two workqueue and timer stacks and
> > > > prints them in KASAN report. It is only suitable for generic KASAN.
> >
> > Walter, did you mail v5?
> > Checking statuses of KASAN issues and this seems to be not in linux-next.
> >
>
> Sorry for the delay in responding to this patch. I'm busy these few
> months, so that suspend processing it.
> Yes, I will send it next week. But v4 need to confirm the timer stack is
> useful. I haven't found an example. Do you have some suggestion about
> timer?

Good question.

We had some use-after-free's what mention call_timer_fn:
https://groups.google.com/g/syzkaller-bugs/search?q=%22kasan%22%20%22use-after-free%22%20%22expire_timers%22%20%22call_timer_fn%22%20
In the reports I checked call_timer_fn appears in the "access" stack
rather in the "free" stack.

Looking at these reports I cannot conclude that do_init_timer stack
would be useful.
I am mildly leaning towards not memorizing do_init_timer stack for now
(until we have clear use cases) as the number of aux stacks is very
limited (2).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYy8S0L18u3q1Y1K1r-qqXRWzrVVLPNR_En0hJ9nX7Tbw%40mail.gmail.com.
