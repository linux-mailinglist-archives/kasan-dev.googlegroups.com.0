Return-Path: <kasan-dev+bncBCQPF57GUQHBBUEX4CFQMGQEXXBGCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EC7D43B39D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 16:08:18 +0200 (CEST)
Received: by mail-pj1-x1040.google.com with SMTP id kx9-20020a17090b228900b001a2956f607fsf235005pjb.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Oct 2021 07:08:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635257296; cv=pass;
        d=google.com; s=arc-20160816;
        b=gfStESnjqUiUbKXFiSMtEiwIVv93ibKD31gKV+ipAdRNZqj8pB9nCAulodu9DYhOgL
         ELsxhGU66tI9J9C8lxGzJ63Yz+6PKGtcvvq4JHxu8fUwp0yZE2dIuAPJ6/5tGeGFvhcc
         XQ5AjXFTkCu97kDSQWHbvnR8lWn+fInjZZ9WNL0cF1Np+3uZtWsmFRJX3YMmtP+aRw8a
         KdTrK0Hav0+hgmxf4gceYzIE47gS1pXyjqYjhB0fvAcyrwfK+ljErO1POgyTiiufBcLc
         OnQJ+HaBCbEoBH04iDlhHBe8WUz//cexfXeCjvAWt+Sb9mZZObS8bwuwZ/2EkxZgy08N
         x0bQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=30koNBGpvOtjCZqOMeEsRVqrdrsI5zo+hsdPCCRfWsE=;
        b=IaxSuAk9qLXlWkPAMD2xObNn2drzqKqIfEBL833KLIgPSOLxoKOyfBaWyiaZm2o1TT
         KaOYT9tfQ1xhrcYan1xs6Qd7konE94n2ou0kklOouWdU/TFzld+6eIAH1k9j7NGPXzO9
         uhHXQhqXdTn0cPp4kTbq2S2MvyZBOIEAZVRmgExn4bqkK4vZBZmhd53fHCxASWy19DWo
         TzxY812u2Ww/tKRUz3qDjwCpM0NXdljdR/n8F7I4iQ5P8RAjHCs6Mhv3NSnRf4jru3uk
         mhNWf4IuxGr0eKZtPjN5pYg++8Uy9MjzYSJlnDeuHAuIXcT/XEriQacpnAL4NsqS6Bu8
         4TdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3zwt4yqkbangmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3zwt4YQkbANgMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=30koNBGpvOtjCZqOMeEsRVqrdrsI5zo+hsdPCCRfWsE=;
        b=V9aFdprhsO5gWVgrSmIyrijs4pAUh1GSX7TLWVHptYd6qMmnYObXUgC6nmd7I1BjPZ
         GNaTj6R/eH6usmrPJV88R0MreJagyOO5AEJ6ECUMELF6fxhGlmTPqbHz9dSIMhIfd6D7
         M2N1KeIAdZ/dloVUlVGweqOwsuGVDA4TWtgusxwdO4burHTdLIGyGfU2H1lWwmpBreqV
         +URkGJ2+LIqYsUzJ4cGbm/cGBFcHOynaPkMZzct2g+WXqaETNHdO6WIuDMGQZcRAxTCD
         zvLNx7CarXN7SrkblKrtohH/RbY3lh/oZRVfg8TQeOdhLN8bS1gamIV+8kEMX7NVYzzl
         msDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=30koNBGpvOtjCZqOMeEsRVqrdrsI5zo+hsdPCCRfWsE=;
        b=RuyIK/5uovW9BXvSSU9sfJPsddjw06xjmXKJKZqNobmqOgYjIfuWPf6fwmwAGaM7L2
         kJLSSCGQFzIqJBnhCtaxhrxrocSBRSVqfMrkUoF+9MyTjuxcwL3X5DCWyBbD68Utk8eK
         Db5puQBn5l0rZLW4buCVIx6dY578N5HkmovpyJKbbmt8iQAp48kIGnpuihI3mGA2AirR
         OaBdjv24CDxk0A+hVQJj7j4gDT1OcbU4UsW5h2whHnNkS59PPTWjKMiy75yy+OqsTekD
         IeM1tjjZHWzYJRH9e/rx62WN1ygai6ESFoWe9TdlS7oSNjJekd2GIz1YM3/mjIU/ZQVG
         ftwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Maw8GNOeucvDHI2Nu8SDN/J6Dat5jqZP9gDf6bO4ezmBZfKQ+
	uojnC1kL6LrbWsDnZ6XgJNw=
X-Google-Smtp-Source: ABdhPJx3k2Z2D1gyUHr7mWnhx03dxNei5X6TwoxzfB516/2ohJw5F4ppB7qJaxN7A9ra+s2YYhdgzg==
X-Received: by 2002:a63:6a05:: with SMTP id f5mr19057648pgc.97.1635257296581;
        Tue, 26 Oct 2021 07:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8cc2:: with SMTP id m185ls8960353pfd.6.gmail; Tue, 26
 Oct 2021 07:08:16 -0700 (PDT)
X-Received: by 2002:a63:89c6:: with SMTP id v189mr14508128pgd.308.1635257295875;
        Tue, 26 Oct 2021 07:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635257295; cv=none;
        d=google.com; s=arc-20160816;
        b=x6XRl7QK78OSjFI/JKBeRMO04jimqOovKnavjlbU82lGTSc0FeaNrN1jKWq0XTCxid
         xDgTmsDetH+8mS5Pvl/gZPigO1Ga5fIfeHlIk9rBUtjv0oZowY6E1JaDXSZDi5laL1M/
         8msratvdp7IOh21YJ2n3N4kkXlCaKt4kk5fELNNJgdwLwDDpKfGo/mAZHwitw4RnTTG+
         yHpRq7yCtRLJrEM8rnWITsEw3CZx7SR3jI9XDQ6zKjQ9xKYB94Bv8m2qMtmIQPnH2nw0
         MGDeIijH17iD+2qs4tAKyuY2Urh/vNbuyYl2Ga8rNSWVqg2vFOQgIIJS4Kk//2Pt6wYO
         9VMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=zAgp8okh6vxIBbMFv4/T2c2F1sXUHx2RabZm01wS4gg=;
        b=kwuwAy+Sp3C3nHopcTikgLEaCdJJpNkj5h0Y+f4/nb7yFZ9oPZa7o/qceZNUXXqidU
         FeB1y49ZpyawwZ1m+cBHf47/FcSQYP8qJxC0JMR2ufA/aP3X0iJTw+ppMmMZGI3L3u0n
         HU2BrbPnu66fY9Qf7puItmPA3uP8Vfe8tEUa0hD9/iTVrC1+QU5redDsuC3Phy6IIiUa
         v1+2Hl7wurKsJl+egk4OqwGCru54vySZ56QByWhbtK2UWxmD3f1kjmGkDmzfAUzkFtOZ
         LchTPT/JWYY+Ne4uUu35qLboGOXoeowA7HQ9qY42n75FftFQAB/RHU+6Ij3wboUffqe9
         xliw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3zwt4yqkbangmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) smtp.mailfrom=3zwt4YQkbANgMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f198.google.com (mail-il1-f198.google.com. [209.85.166.198])
        by gmr-mx.google.com with ESMTPS id p10si83832pfh.2.2021.10.26.07.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Oct 2021 07:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zwt4yqkbangmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.198 as permitted sender) client-ip=209.85.166.198;
Received: by mail-il1-f198.google.com with SMTP id k15-20020a056e02156f00b0025aac886d0aso1558199ilu.14
        for <kasan-dev@googlegroups.com>; Tue, 26 Oct 2021 07:08:15 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:1a23:: with SMTP id g3mr4063920ile.103.1635257295389;
 Tue, 26 Oct 2021 07:08:15 -0700 (PDT)
Date: Tue, 26 Oct 2021 07:08:15 -0700
In-Reply-To: <0000000000009e7f6405c60dbe3b@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000003548bc05cf4202f3@google.com>
Subject: Re: [syzbot] upstream test error: BUG: sleeping function called from
 invalid context in stack_depot_save
From: syzbot <syzbot+e45919db2eab5e837646@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dan.carpenter@oracle.com, 
	desmondcheongzx@gmail.com, dvyukov@google.com, hdanton@sina.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mgorman@techsingularity.net, syzkaller-bugs@googlegroups.com, 
	tonymarislogistics@yandex.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3zwt4yqkbangmste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.198 as permitted sender) smtp.mailfrom=3zwt4YQkbANgMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

This bug is marked as fixed by commit:
187ad460b841 ("mm/page_alloc: avoid page allocator recursion with pagesets.lock held")
But I can't find it in any tested tree for more than 90 days.
Is it a correct commit? Please update it by replying:
#syz fix: exact-commit-title
Until then the bug is still considered open and
new crashes with the same signature are ignored.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000003548bc05cf4202f3%40google.com.
