Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPVYVL7AKGQE6MJP5NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EF5F2CF5A8
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 21:29:51 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id q140sf6333909iod.5
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 12:29:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607113790; cv=pass;
        d=google.com; s=arc-20160816;
        b=EfzwOVcDodxr42HxV7S2KZxU39xmQaWlEtNPsj9h/ghwKlNeLnknfFrmosAjDp6/kv
         veiY3ifrlyKRXHuLbrDQJrLLt6wT1tvGIKVKzP80KjBVf56qHv9UsBIreiKjIRG4aa/V
         9zX8QNH9Yt1nNwej4HmaAWvzpuwbUa9LSV5VFRXVlaMdc5fc/NZXn2SutRGAKAyifSZa
         gjOORuVOMEMjxnQeAIPMV4fm6ppG1syMZN/MEP2JHqz76CB28c8h/MqJXJPBs+oP6/wS
         SNyl8jq+BHi/6AQoCL61+uO5cZ/a+V65+D1gw3mZUNcJZ2MlaP9NHcn9DUReqKoPMU76
         byrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=86AXnndms/Ufl6fzOWTJC6PZ+lUaggN589ErgqiCBMQ=;
        b=TSZRWpaZqPvwyYBj/EpeIWHreQp6FXqdkaTqyGbyHWIjl0R3ZZXh9FLgCZnNTIkmex
         7Vh7twp4OuInLa0dRVhgKhuu+IeK8snhohDjOmAi2dqM6En4qgGQW7LlkdBZ5Z08bF/q
         ANwHq4LAvaYirwDMvyHuaad8M2R9mroW/MbjjzZGZig/r/CCXfbG1P/xkdo7j2PnyFmD
         UQmC+A6k91ckbB4y6gAA0wBcuACETutjPuks71M0+qQF5cJOBtw3PMY9KRM1+xRSYXGy
         UD4hfMWKSuuohjLwA4EtRlYlM0hTmH/XukAT00Pbbfwb5VIwG8yMV5E8vq1lEixe5PDf
         vHWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VookJG2j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=86AXnndms/Ufl6fzOWTJC6PZ+lUaggN589ErgqiCBMQ=;
        b=AJTfKY3CT2lndSks4u7qrHqXZ3B2wZxOdBxBExDuEqrjIGrxjOnzhmUXH2HGt8VMVb
         3lSd62GZ4WS/6YR7MQTl1AvH4ASFL3FiusWZ/l11jqJoH/VKkhtmaHKNVyHpcxl15LxW
         4W7sW1Xqu5U65KH2LpKlhaWrc3nM3HdRMJ0/epxpBJcwsi2HBVHkIlxKWi9nf6Hi+Nrm
         uS82lCdUY30h77cqIDX71pp1FOX20fSfwJa8pwpeOWfOZwvv4sf3zIqeoIYXjxYKiWWu
         JwB74ohoKdrLBVsCmKCdOFkUrEurRxd9AhO0ZbTE9Ib/W5scoELYB3pteSdX+SiFl7Yu
         u6bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=86AXnndms/Ufl6fzOWTJC6PZ+lUaggN589ErgqiCBMQ=;
        b=mnZqcEmD3MYTudV67EWx+46pAqNuAs0AECCNjz1T8Ez85QfzeA85LHj0mLOpAQKWaD
         tZ8+ZKEQnQSIyovg4wBQeaQmkNpnNUPx5jmxJMyEgeg1V8ptdkr5/ysgQavj4I9Rhdod
         Tvm5BMQP2vwcNaL7/MR9qtCL9zFzlRHx5i4Mp5/MbhnqvHEolgkFnyQtjvR0r0KM5Hwx
         Ruk6ro0Pb9doYlmPkt+ErJ28rUrCZSAZRphHJ174t7rq/GglKSfOTZevQU8SmmUU9sT8
         pL9+VY+wMXQbFNakj3q1PNhKQhFh11nNrllKe/0TyaFiWAO+XtApxb4fHp17Rd7efodw
         pNAA==
X-Gm-Message-State: AOAM5335m8NXL4aSCMjoKs/NKT4Si0UICxjSx1tIIp/punaRZwD4kNyk
	2VA3BKR/p5nMQHP2AGzDfd0=
X-Google-Smtp-Source: ABdhPJzgx34Lfp6gS+WAR9pdzCNfptjjnVG91FLc8UKQTK9AV4H0k0cju0z421GuD0Ty+lpIjKYoaw==
X-Received: by 2002:a05:6638:f92:: with SMTP id h18mr8481301jal.118.1607113790388;
        Fri, 04 Dec 2020 12:29:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:6f53:: with SMTP id b19ls1309286jae.8.gmail; Fri, 04 Dec
 2020 12:29:50 -0800 (PST)
X-Received: by 2002:a02:a304:: with SMTP id q4mr8379564jai.97.1607113789970;
        Fri, 04 Dec 2020 12:29:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607113789; cv=none;
        d=google.com; s=arc-20160816;
        b=t2tXN8bs+oK0A9hTzlSxrsSC372QjdeBeCpCJhvpv/i3ZExz0vKIOPeJfytPD8Vemu
         C8NKUARXlgNpuN6mUkfIMlB6lRrMubcO0+jmaphJ7RHPZLohDFGSs8xeppFRndBXYhOc
         FPlYebah+C5dypmTspsXU9ybe3tE2Iwp6VItCi3YWJbsiRSX7fjGVb3TbcebJOoShedD
         d8eD37/x7kKTSqL/z0RhukEzRfP0Y6179P79+5XJPyLIBHjdko/+x6ST5oMclR5AA3sh
         WZfLwj46YB6ce2L3WCjxO0+anhiHkEZwFxSrcejGZttcVeNjqt/Ux1Miq2c6cbno1a1f
         6/1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zHUsBSyMeZd1dobHZ32LUWZNrWUwT+9A3sZRTSG0ma8=;
        b=0NeEv8XDvpvuIet8bHKvM3LReQKigBAbhRIgwIfQXJ/PmPdFH80eb4KPNPLk+dQfY5
         NFsp27fGX9TLOEMI+IgdZEASHyp4FkfTB99hiRWDAG43hWRrxhCQ7DP4Y/VFHyV4UNgG
         JTcIvq5K8fEsezad0SJg6hPXJHO0EI26Y84hyXPJXwft5emgXc9ET29pthtR67s0blWw
         8OYDzxikPyX3BuQ7A/CtMBbmTs4g5l2ls4jsEFqO8t3uGKpvmD1gtqCWQ7pNUxSZLbbT
         yZcydaYz0lcEUAwbr4USRrlj6aqElySg7yE7x6fkVfBnfwNwg4b3O4N007N0wQTjKu7F
         QFrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VookJG2j;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2f.google.com (mail-oo1-xc2f.google.com. [2607:f8b0:4864:20::c2f])
        by gmr-mx.google.com with ESMTPS id b14si293202ios.2.2020.12.04.12.29.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 12:29:49 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as permitted sender) client-ip=2607:f8b0:4864:20::c2f;
Received: by mail-oo1-xc2f.google.com with SMTP id l10so1695231ooh.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 12:29:49 -0800 (PST)
X-Received: by 2002:a4a:48c3:: with SMTP id p186mr4831961ooa.54.1607113789548;
 Fri, 04 Dec 2020 12:29:49 -0800 (PST)
MIME-Version: 1.0
References: <dc46ab93e6b08fa6168591c7f6345b9dc91a81bb.camel@rajagiritech.edu.in>
In-Reply-To: <dc46ab93e6b08fa6168591c7f6345b9dc91a81bb.camel@rajagiritech.edu.in>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 4 Dec 2020 21:29:38 +0100
Message-ID: <CANpmjNMCiCf9w34duqGpQ90=qB4QGnRR8Xny+wOVf=2WG=JVoA@mail.gmail.com>
Subject: Re: BUG: KASAN lib/test_kasan.c
To: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	lkml <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VookJG2j;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2f as
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

On Fri, 4 Dec 2020 at 19:56, Jeffrin Jose T <jeffrin@rajagiritech.edu.in> wrote:
> hello,
>
>  detected   KASAN   BUG
>
> [ related information ]
>
> -------------------x-------------------x------------------------>
> [   43.616259] BUG: KASAN: vmalloc-out-of-bounds in
> vmalloc_oob+0x146/0x2c0
>
> (gdb) l *vmalloc_oob+0x146/0x2c0
> 0xffffffff81b8b0b0 is in vmalloc_oob (lib/test_kasan.c:764).

This is the KASAN test. It's a feature, not a bug. ;-)

> 759             kfree_sensitive(ptr);
> 760             KUNIT_EXPECT_KASAN_FAIL(test, kfree_sensitive(ptr));
> 761     }
> 762
> 763     static void vmalloc_oob(struct kunit *test)
> 764     {
> 765             void *area;
> 766
> 767             if (!IS_ENABLED(CONFIG_KASAN_VMALLOC)) {
> 768                     kunit_info(test, "CONFIG_KASAN_VMALLOC is not
> enabled.");
> (gdb) l *vmalloc_oob+0x146
> 0xffffffff81b8b1f6 is in vmalloc_oob (lib/test_kasan.c:779).
> 774              * The MMU will catch that and crash us.
> 775              */
> 776             area = vmalloc(3000);
> 777             KUNIT_ASSERT_NOT_ERR_OR_NULL(test, area);
> 778
> 779             KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char
> *)area)[3100]);
> 780             vfree(area);
> 781     }
> 782
> 783     static struct kunit_case kasan_kunit_test_cases[] = {
> ----------------x-----------------------------x-------------------->
>
> Reported by: Jeffrin Jose T <jeffrin@rajagiritech.edu.in>

Which CI system is reporting these?

If you look, this is the KASAN test, and the report is very much
intended since it's testing KASAN. Please blacklist the KASAN test
(and any other tests testing debugging tools).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMCiCf9w34duqGpQ90%3DqB4QGnRR8Xny%2BwOVf%3D2WG%3DJVoA%40mail.gmail.com.
