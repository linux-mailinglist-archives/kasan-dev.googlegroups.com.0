Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEWUGIQMGQEJ4RTEMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A5094D290A
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 07:37:45 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id d15-20020a0cb2cf000000b00432e2ddeefasf1380549qvf.23
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 22:37:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646807864; cv=pass;
        d=google.com; s=arc-20160816;
        b=vobfGZ/8chRr3LZ63S3rGtKQva/wOhhkwz73PWERjCxXbY42aLIuAIyBpOTIJCL/N7
         gdIYeGtHwYm+c8AE4qD6+sRNWORoaX1MGCmJhWITpXRPfXYdQzXHc47Qe/1xoPTLGYEf
         PmhQs9L7jm5lpepr3XBUeWxHg/GyAaarBRGLBa9JqnKKuN0Nstfj/ozbQHyYi5j6QNzj
         x+5qZzUUFApHSe/F/SaHXwoHT2QtRip9blQu914/SfIP7sy5wrkoBkzPUILRLdzU6yh9
         x2hKmSmlXeGtp8oZkEB9G3zKquEr4M5CuqSt6luBsEmtb5GQ+YTiYx2u+Zx4H5r30HH8
         bpYg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=g76maHZKXAaS1fFqUKQGDDD8kWXfgUO+Osc6vYqYMAs=;
        b=pOEhXOqEPZAMVviOPwgCDCogVVpTpqA65VkjARn3AmTBCE6Gi1DTcB55tSEpdJ2mB0
         QeYJAbGGNJkD+js+zbg5IEDpdT36Jlts5iprjtzjExn5Kit3fjIirb+7aaTfbwEeWcnp
         UcZe7enHXTUGIWo115cWkwRKJ+B4WSlDWd5dJodw8Jx7oi/Gm1Jlvci7Q77j9Rbx258R
         vPET1cDDMVH7KPjv7XoXpUgk2XI1b38SmEuHwj/KPPL7x2e46KB46ELr7QCzV5h31XmF
         /S0TysKczyNYpxMGvIHfneh0xtOW2z0RX8qC4wukSD1yQ4w/fMTBrB+qft585sKk43PB
         P0hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pL4xjYO6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g76maHZKXAaS1fFqUKQGDDD8kWXfgUO+Osc6vYqYMAs=;
        b=dgwLlU8EFf3Ts8NwjXbI6w+qcs4OLf5vLJFxjPDGInLQuCdhAo8uA6M785F+KAN4N5
         QbXIi+VDC4maOpuj8fEVAPvg3e1UrOhnaCsupNmnptOq81qYVutgmlNQrUe/jaSuzXEk
         mC19myZFwiAp0T0YXGk+Oh5nGNaN9cIRgfUgoh5KR4hYaCSAKoxaES99k/Zhb6UbwMN8
         h0xvKpKReny5ZH12Glqj9EQzH6+foFBpX/sCmWxw1oIhUlbhlZxm1tH/oLYU+FTmIf0h
         38X++fhETf6JXQMTkPIA82rOimnHYZJQr9Hk9BMlr9o7VjFc3kwqmlzHB9zcnlDMrcke
         pSrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=g76maHZKXAaS1fFqUKQGDDD8kWXfgUO+Osc6vYqYMAs=;
        b=OU0fCp2OQT5JXRE3zwN7M2UmFqxrpk6KehyqDUFyudRBiHqogybaiq0rSg30S7qgZn
         JOVhGmlVbAd68e6vlrQ4nwTeB5JxSeRC7DEC6Nz0BC1U0/2lRxeh9HqGFnoK42Putde8
         Honyuuru2laLM9Sa7srfrAwaT/2aYCRBZepc14HgHlcn3GI+ipe0V3Ov4oCI/i20s360
         Yh+PfREGfEyqpjrMub09cNujIFUDzUJSlGeaw/aUcyU8FB5G2i/53b/0CF0YHcwbl1A1
         6gR5kABfe5s7IdsN/jbpf1GhHTRzwTtTW072c2WYRSQQi4aVesCI6GtKUW9x2U9C2QuV
         fnvQ==
X-Gm-Message-State: AOAM53177hckSINJ6zVyj0YMHfZ/rJylPgFUGIHERXyUL9aNJwE5D34i
	51DPomQOA7468ofegWafh2Q=
X-Google-Smtp-Source: ABdhPJytMBCPcGPAxqxgJda7IxmKVpVchvID+fPk/VGm/UFZGrtab9jH89ria6Cc1ZFWu2Bqd/vCkg==
X-Received: by 2002:a05:620a:4093:b0:648:ed2a:8ea6 with SMTP id f19-20020a05620a409300b00648ed2a8ea6mr12885484qko.435.1646807864443;
        Tue, 08 Mar 2022 22:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5f49:0:b0:435:b3e3:a56a with SMTP id p9-20020ad45f49000000b00435b3e3a56als558047qvg.4.gmail;
 Tue, 08 Mar 2022 22:37:44 -0800 (PST)
X-Received: by 2002:ad4:5bc7:0:b0:435:8a4e:3afa with SMTP id t7-20020ad45bc7000000b004358a4e3afamr11138484qvt.16.1646807864067;
        Tue, 08 Mar 2022 22:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646807864; cv=none;
        d=google.com; s=arc-20160816;
        b=fgoj+3Ugb9U+jfytIznrYCj23jmQQeXPquN5rc4GV/9vIdWnn1M8pQObItMihkAJn+
         tXLfWRqeg1FBk5z098e5b+ecDVpK5ezeWhr9wnokiaaY7uQO/RbBJ/lGhZ+MY+821XOb
         xL66fTJKuIfyXuPhMXfcl4czrm5XrvFVBjuRUHvBkWSo6ckirZzDOFczCsF7CrE9KhR1
         6i+dvvFHAH4z8oqawy4JfeRXk9Edz5W89ZihM736zgVFfL3qu3F8+pwsAM2s0b51bPe0
         asWGQCoFufUrEUXUg7GiQnQKbFTfIh0qnEPl4PiCCxLkIYeNE8v9S25XwrpJg+AX0P38
         a+ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0OpR5YHkvilOZNO+UTT2Vvr8SNVAoIkBjKa4z5Ar1Ok=;
        b=0I8fzGbHMY6AI3u4baNWwwA8xjKiynk5Mfay0+qWAfozs/BBz4ONqrRfSFqwcKHluD
         7urb6fM3V9vn3MOaA0QRCMbJS2HIuvqDZM8SqB8huFk50qXCgRFdlbt6h+lQaeozsaBP
         FF/CT5ByBRKWIghHIkpdx3NO22TKTNQgHat8CUVmfBVzki/qrZ1yeKysivZr/u+MP2bW
         5I++20NHNcqX5zMeSNzeeOH+qCwD+E61CpeR36eAwQwf/Tu+SYgaMIGzpXkIa0T7iBUa
         WPUZegKlSnIbgBt7NgR/VBrmLBr7s+9JFsWYHRtn1gw5uMN06a69HjhATcoQZPecLH/a
         YxHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pL4xjYO6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id m17-20020a05622a119100b002dcec4472c3si69281qtk.5.2022.03.08.22.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 22:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-2dc585dbb02so11691237b3.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 22:37:44 -0800 (PST)
X-Received: by 2002:a0d:cac2:0:b0:2db:fc7f:7dfa with SMTP id
 m185-20020a0dcac2000000b002dbfc7f7dfamr16012861ywd.362.1646807863492; Tue, 08
 Mar 2022 22:37:43 -0800 (PST)
MIME-Version: 1.0
References: <20220309014705.1265861-1-liupeng256@huawei.com>
 <20220309014705.1265861-3-liupeng256@huawei.com> <CANpmjNOU+M1ZaRTMPMCFE7pm8JXLKsWcMpMAsDmJXZUga3N7=A@mail.gmail.com>
 <0423ef8e-bfd0-3a4b-78a5-17dc621660d2@huawei.com>
In-Reply-To: <0423ef8e-bfd0-3a4b-78a5-17dc621660d2@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 07:37:06 +0100
Message-ID: <CANpmjNNQtODYy7wBuLAOm2GaHNGB10LP=X=xp04DCNiY+KM8ww@mail.gmail.com>
Subject: Re: [PATCH 2/3] kunit: make kunit_test_timeout compatible with comment
To: "liupeng (DM)" <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pL4xjYO6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1134 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 9 Mar 2022 at 07:32, liupeng (DM) <liupeng256@huawei.com> wrote:
>
> Thank you for your advice.
>
> On 2022/3/9 14:03, Marco Elver wrote:
> > On Wed, 9 Mar 2022 at 02:29, 'Peng Liu' via kasan-dev
> > <kasan-dev@googlegroups.com> wrote:
> >> In function kunit_test_timeout, it is declared "300 * MSEC_PER_SEC"
> >> represent 5min. However, it is wrong when dealing with arm64 whose
> >> default HZ = 250, or some other situations. Use msecs_to_jiffies to
> >> fix this, and kunit_test_timeout will work as desired.
> >>
> >> Signed-off-by: Peng Liu <liupeng256@huawei.com>
> > Does this need a:
> >
> > Fixes: 5f3e06208920 ("kunit: test: add support for test abort")
> >
> > ?
>
> Yes, I will add this description.
>
> >> ---
> >>   lib/kunit/try-catch.c | 2 +-
> >>   1 file changed, 1 insertion(+), 1 deletion(-)
> >>
> >> diff --git a/lib/kunit/try-catch.c b/lib/kunit/try-catch.c
> >> index 6b3d4db94077..f7825991d576 100644
> >> --- a/lib/kunit/try-catch.c
> >> +++ b/lib/kunit/try-catch.c
> >> @@ -52,7 +52,7 @@ static unsigned long kunit_test_timeout(void)
> >>           * If tests timeout due to exceeding sysctl_hung_task_timeout_secs,
> >>           * the task will be killed and an oops generated.
> >>           */
> >> -       return 300 * MSEC_PER_SEC; /* 5 min */
> >> +       return 300 * msecs_to_jiffies(MSEC_PER_SEC); /* 5 min */
> > Why not just "300 * HZ" ?
>
> Because I have seen patch
>
> df3c30f6e904 ("staging: lustre: replace direct HZ access with kernel APIs").
>
> Here, both "msecs_to_jiffies(MSEC_PER_SEC)" and "300 * HZ" is ok for me.

I see - let's keep as-is and use msecs_to_jiffies().

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNQtODYy7wBuLAOm2GaHNGB10LP%3DX%3Dxp04DCNiY%2BKM8ww%40mail.gmail.com.
