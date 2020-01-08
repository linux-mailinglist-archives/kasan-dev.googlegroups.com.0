Return-Path: <kasan-dev+bncBCTPB5GO2YNBBKO423YAKGQECKPF2EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 00036133F3F
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Jan 2020 11:25:46 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id o18sf1714410qtt.19
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 02:25:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578479146; cv=pass;
        d=google.com; s=arc-20160816;
        b=owrRI9McQD6YKlikM1pAODSo6fmotR0e4DoqqYk5LVB/reRvlRNLCiCBYN9V5IZMPS
         dW0VW6y6AIEnKXjHMj9etnYe9h+cXrUesr+89DQ/rovY4j5YsHOWR8LeBsFYooGmJWK4
         y1kcMuGmHnczirVJv/j9dKFKqhSL8JWk8n4Q6waGAv+0YR4DRcJ85ojxNVTgYh3vaCQC
         d10V7yZst2FxQzK1KeFQ7dz2e3gZ3ngNnVGBz0ge/Y35xaSBUe/lORDxi/+xg9mb3DSe
         l3T4FRiQGY6wp/FmFvYZIaIEH7AijrtjPg0kXooo/+pg+RAaIzsBz0GtU3uBhOhOW0u6
         jyBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aW7I69809aU8bmbNxDqIDxwLii/CDr1EuUHGfrAQjC0=;
        b=dW7cO8zF7GynrVKmSEubXk6tX4HKIeLDRMbD6Dkn/NoNWMRI6MP/mCATm50Jsn+eIS
         xSWmxmdrkE9sTg+9+B7aiL0VJmIw8RDr5hfo5qm6qjmxyb89x/f/RS7MHCqHSgOkpZyu
         YtIDw3x5KfhoFroOxGief2VtoQyCrZrre0yxhvlowgn6RsJ45yLSg+jsD/lQzAkOh7kI
         r2n8/rFax6lI9FYV5fDnplfrGBYdyYcwDfq8XKgiiNWv2zbgO7NYJ3eiaapOhQCaHzfF
         m+Jnih+0d2lNF9W+v94ipqTwAYiv2X4JExdz1bM2T5K+RJjcXeEiWCBIhymDbBQmDQ9W
         MfVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aW7I69809aU8bmbNxDqIDxwLii/CDr1EuUHGfrAQjC0=;
        b=CZ2Exl9nmqIW3Cshu9ETYI2UMQoaeOfyhnyvjAq4Oon4e3cC17BMUC2odosXFjzytT
         9x/2kLg+28MVVd5MxppqSZxv2DhB1YaBQZuHesVdH0/2Gy3IiNVVkhNS4ae+/BM0LKpa
         42Vn53mtm0/QmRlzK2FVomFqAKG16jnIkb1q91SXMbWN/YVemIQR2BGavUoMMc8JeC46
         LR83deSWyA+PLX5FL4QCc2ixT5AzDUwtdBb8cjRGhyzmXGLDNkKUN8Ww58Yd804xmiCC
         2AiHvU6qkWLsy4Vx95XqOo7NF4UfF0I5WIcS6nq4Ia+jyr6tqQPMXiMj19hH5aIQUJWQ
         2OJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aW7I69809aU8bmbNxDqIDxwLii/CDr1EuUHGfrAQjC0=;
        b=klsC3AlQkzH0BCtsnfWRaSP2/sUY6Zsf+fxkqRiykKQUgwd1bvvehTqHleObCicPZO
         lweAnk5Sc3A0qnqq3Jm1u4iOgKtrNAFNGlBYfUi8XK/N03klZftUMyo0zw+oki87NZrY
         skY3RBjVrrG+K2AkW6EiilAgKYroR4amoaeBDmDB6COdVUV5aixiYvsxEvDgiTlwEiBW
         36J5Os2ZyBMCVwbkTUAooYrJGp+aO8ZWbgCzKV27GTC7ZgaW7tBl31VIZyBl2d58GXlQ
         y8ercO4fa4vFbU5ssGGzclI5HWz2wbXUKeuZB8ZIJQLe+nd0N5wapkQFe8DMQjmWRqZR
         4okQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVuqxnQSfsdMQWBVLZkm6qxHISw3DsvscckB3QjoTNH/DK8UwWQ
	EbQNErh9G41OKYlN2LA1dTk=
X-Google-Smtp-Source: APXvYqzlT9Uket/NI0Qiw2awtn5D9G1MhKz6vCl4me/QhU4Heav2l42+TapWlsWUFQ9AueJhQCAjEA==
X-Received: by 2002:a37:68d5:: with SMTP id d204mr3569777qkc.171.1578479146014;
        Wed, 08 Jan 2020 02:25:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:3690:: with SMTP id a16ls815581qtc.8.gmail; Wed, 08 Jan
 2020 02:25:45 -0800 (PST)
X-Received: by 2002:aed:3242:: with SMTP id y60mr2796701qtd.254.1578479145441;
        Wed, 08 Jan 2020 02:25:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578479145; cv=none;
        d=google.com; s=arc-20160816;
        b=VJFhiF6KYtTvkrRhkD1owCfD/3CIa3yqyExPJV3DDPQmCDo6E/HNFZz2RJScaecgaH
         pMjupPeCVCgtahdyX2r+9u6V+fPAz5CJcpDL4LDfil5Hjh2kw40YiU5SPs3A0fp6xEnt
         LrG71j6cmUlYreThQ1Ld2Phjge8U3K+2V8FHYKK5ATOywST3B2UbLVuEtV+74igoPz31
         zJdNdAQQgO0VHUkrpE7Ov2oJXwNxFYI2fVi4d3lZUPR1YpTl/EbjKeZI2jluMXnb7KhL
         bYzKoCQ/5dtEqkxA/4poZHRRSI2khMLYbiCablqALBZ7kBxXxrtiuIFALoFDQ6j/3EE+
         xybw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=dBBxNGKKqN7Q5RjCrlHxM6SZzPTCuSM6ye5004TsXaM=;
        b=UMlHnRhFYPhuCvnPAy4dvKmTf0CAw6ziKN04OZeb9UjFDv/iU/3te+KdvygKKpKF6j
         SnZiTuVRM8Y0p1hSxghKibHTn5+eCsJjVZwH8aV8d1QjUmMUTNzcaf5DeaOSdh4K4y+V
         C/xq5hpNJUdw1ooTL4+7sV4IcbKCCHY3SfeEyuzZWb18PjmVGirLJOhMyep3xUxnjVGT
         rvLK7gxRL4W3DA33082FuPJ2zISL3zRdTetJ+JM696ldR8Gr/LyAD6m5hZtV1qVAxDIg
         BwngCgjdw4ivgn9G4b9kRga6gxbeCskwWd8GztgRNBPMeVCO1mB7rU7HBi3/5aqd7eia
         o8qQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id d135si106766qke.7.2020.01.08.02.25.44
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Jan 2020 02:25:45 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from fsav107.sakura.ne.jp (fsav107.sakura.ne.jp [27.133.134.234])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 008APecx043436;
	Wed, 8 Jan 2020 19:25:40 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from www262.sakura.ne.jp (202.181.97.72)
 by fsav107.sakura.ne.jp (F-Secure/fsigk_smtp/550/fsav107.sakura.ne.jp);
 Wed, 08 Jan 2020 19:25:40 +0900 (JST)
X-Virus-Status: clean(F-Secure/fsigk_smtp/550/fsav107.sakura.ne.jp)
Received: from [192.168.1.9] (softbank126040062084.bbtec.net [126.40.62.84])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 008APZVQ043386
	(version=TLSv1.2 cipher=DHE-RSA-AES256-SHA bits=256 verify=NO);
	Wed, 8 Jan 2020 19:25:40 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Subject: Re: INFO: rcu detected stall in sys_kill
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Casey Schaufler <casey@schaufler-ca.com>,
        syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>,
        kasan-dev <kasan-dev@googlegroups.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        LKML <linux-kernel@vger.kernel.org>,
        syzkaller-bugs <syzkaller-bugs@googlegroups.com>
References: <00000000000036decf0598c8762e@google.com>
 <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com>
 <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net>
 <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Message-ID: <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp>
Date: Wed, 8 Jan 2020 19:25:33 +0900
User-Agent: Mozilla/5.0 (Windows NT 6.3; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.3.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
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

On 2020/01/08 15:20, Dmitry Vyukov wrote:
> I temporarily re-enabled smack instance and it produced another 50
> stalls all over the kernel, and now keeps spewing a dozen every hour.

Since we can get stall reports rather easily, can we try modifying
kernel command line (e.g. lsm=smack) and/or kernel config (e.g. no kasan) ?

> 
> I've mailed 3 new samples, you can see them here:
> https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
> 
> The config is provided, command line args are here:
> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream-smack.cmdline
> Some non-default sysctls that syzbot sets are here:
> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream.sysctl
> Image can be downloaded from here:
> https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does-not-reproduce
> syzbot uses GCE VMs with 2 CPUs and 7.5GB memory, but this does not
> look to be virtualization-related (?) so probably should reproduce in
> qemu too.

Is it possible to add instance for linux-next.git that uses these configs?
If yes, we could try adding some debug printk() under CONFIG_DEBUG_AID_FOR_SYZBOT=y .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b60c93e-a967-ecac-07e7-67aea1a0208e%40I-love.SAKURA.ne.jp.
