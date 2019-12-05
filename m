Return-Path: <kasan-dev+bncBCFYN6ELYIORBFWUUPXQKGQEPAIRO4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 643CE11401D
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 12:29:28 +0100 (CET)
Received: by mail-oi1-x23e.google.com with SMTP id k11sf1479575oih.23
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 03:29:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575545367; cv=pass;
        d=google.com; s=arc-20160816;
        b=IyEfmwe9sjyfDmHhzjdNH8utNylUwGzkHozPGk63zOKiXKwXI4w9F8KDm0bbMOFx/Z
         RuvPjVeXpKY5VrabFCFwxduhhZUBPOpzCuTUPydbJJGB29VROpFZzo+CGMM3mTls485X
         dhqSxBAiLnfcUWFWyg/X9DTaeOvqFHbodtST4RZrMy7g242jJcMA3V90i/wFE/VTNdjX
         8ySitmGy4Zlw315hCbRspIoncJkwbZJnIDkr+PAgYYd71Zs/zIRDUUKlDrSdEww30Zrt
         2k7EWw3Kw5Hs5mC16USO3t3hurjN5wDRlVGgCMoW4fnKeaSPCSPzObK1mixcd5lAzlyG
         Z/kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=er6SfCjddB3HQopMrW3y4Cs7xFs44wYxiKkwQoPdBFA=;
        b=dNrbSlIbwvotFVm2cDmQP5IcfLCCkr85OiOrZu+3PuL8Hu2Y6xH/m0Pwuhhq7ccWgq
         Le8Wsvy/2oZfWjbUTJvqDQDWFyjOOdDLTlJF6sjQppx8+MSLtB5hHy0gqvxY42Gc8c1+
         ZCnwVahfX2L2Q3FtenqZT3dhF7c9kGhTn5jIctr8HIA6tr0jnD1FignzDoH06TGtsRSc
         DFQL1Fv+topQDUmsGgrt0goarZj4dL/gjra+ECN2fFdP/z9z3dmStFqnjP5WRS2GvoB6
         3xi/E8Lzw+st/g2nBATuhWtHBI3cReHTxs79FWQ8V0hxkgQpnXEFA450gYKwNxMMY270
         bFqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IzY4lWJ0;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=er6SfCjddB3HQopMrW3y4Cs7xFs44wYxiKkwQoPdBFA=;
        b=KhFNJIkEyPsbpt/ydxmBj5iWb/zqqW4mUKZ/BUSPtOAZ/tQCRzGcwPrcbcSVrfQ4/Y
         a8c32kpifsE+3xx8E0mc++sMUgZQ66KHa5/msR7t7qEHwubyLNfbm9tio++vSLZrK9RF
         G2FW/rBEJThu1yYEONt9nxx6z4taW43lODs8qJ2J5noq2YgfUoDnIsulj3B27ri6gSq6
         NgjN3meYKGQ0xYnBtRd4osgFX8qUwiVOPzF51t9cgPgMPrqr4XgNR0dZcZ8PKgpG9IfT
         dkjxYHEbkT9b5ZEaBnAFT37FOU6VqQjBY6U1a+hJV1Hr3kQCgtvsGVS7akkSjY1bVhZ7
         +GYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=er6SfCjddB3HQopMrW3y4Cs7xFs44wYxiKkwQoPdBFA=;
        b=cdqMaPhQBPS6iiuC/8bn1SZtbMtBMBHMoKdmwcusmkVjHu87U6LgvnZUXV0zabifMz
         HNeXsaLiX0xq/+3k8u1TG5eewwemJcg/Hov4IJA5Pup160N3Yc/MEb7OLsJh3Clm3bd2
         fImpBR/a1h6dcXKQVzAh41e24OpFAyQtqglQ9YNyQBc8nC1VpQh9SASrfDfxRdQbvoVV
         WDmjbhnWQkqwq0zZvhmsH9h1NVJAqo+1R2rBU67pUC4v7skx/fnyJcC/LoK5+LxHOocC
         gjAwhuncUkJcSevUFfJRjfVvJgwGf0bz08QJqJsvhYqucoYry1dmusG56UJd2Fr8/Obk
         XzBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVIqlWi8M+tiLA2ZSzVTE9Vs5qbaDYlDS06ZfDXEwRLJscfHMuW
	i3ym2S19Q+zDI8WY0o+LEhc=
X-Google-Smtp-Source: APXvYqyvZ0rchFimqPg2LcbyBHk02nTh2TD/bmRkzs+vH8eU8sCYKCfVwfOT0Zc1g3aY/GY+78VMnQ==
X-Received: by 2002:a9d:75da:: with SMTP id c26mr6259732otl.40.1575545366905;
        Thu, 05 Dec 2019 03:29:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:649:: with SMTP id z9ls575633oih.3.gmail; Thu, 05
 Dec 2019 03:29:26 -0800 (PST)
X-Received: by 2002:a54:4407:: with SMTP id k7mr6921084oiw.56.1575545366558;
        Thu, 05 Dec 2019 03:29:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575545366; cv=none;
        d=google.com; s=arc-20160816;
        b=TpE4SeiwQQKqivUn0q58O3bMmgIMV+/u4DsRYXT1/zOtT7W5pnvVBfTocWMDH3f7eA
         A5FooWeJZqifhjetppDbUb9p2oNq9Ckz5lALezMgMkGtd2ShGhf7BRiPgRG2X4Dr/dHl
         dfUC7KNIKoZ6v96qtBJ5E2Ipjvx7F+RD5+pgTMNtvrZr4b2Sj7QWpyFHbpxlu6Lxcmdf
         xtm39OW/9mIlDbuODLuc58CmbKxn0pR5hfEOVYFiuMbuFiEMoWW7mM5Q66TqSoOwdZ89
         Pb/OAOqWXmjq/JgUadAt3lNWtgB171D5DccsBH4xXz7WBfqCXCMFt3peSjxPbQv0HEcx
         ho6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=lbaSGfutZwhZA116gvr95IAUlIVoaJxPvvW+eFCW8zI=;
        b=nl57O9JMk73J5tynFP2UZr8HF6AWXWSgl0X3KqKUoKMvOO8aW2jQfXKEfaE8S7beiv
         /D6D3RdH79EJv8sFeV5CozyNsFEjP/eMGIBZlHSDHQLBigwMQ35ysza0/8BDHVwURNW9
         Fx35yHXVFhft+KUdaU1YeCg13J3J/RM8sl9z4qRtQ/ZYt0zCOt/uHGLNsIKHlz82X4DX
         Iu+H75IAmHNX7R88P5Z1HGJtIEZhFBKLXwZHRWQ2n7/MyKxje17pROP0+TVcfOV0sxst
         hpTdrRPVrXKHxFJYvU8SbZmoHpa0T7XXMVdnWgE86jXO1sEokPxKcvy9/OKhmGztWir3
         c26Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IzY4lWJ0;
       spf=pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-1.mimecast.com (us-smtp-1.mimecast.com. [205.139.110.61])
        by gmr-mx.google.com with ESMTPS id 5si265000otu.2.2019.12.05.03.29.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Dec 2019 03:29:26 -0800 (PST)
Received-SPF: pass (google.com: domain of pbonzini@redhat.com designates 205.139.110.61 as permitted sender) client-ip=205.139.110.61;
Received: from mail-wr1-f70.google.com (mail-wr1-f70.google.com
 [209.85.221.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-270-fzDCdiacPJCSD8Y3t7HxHA-1; Thu, 05 Dec 2019 06:29:24 -0500
Received: by mail-wr1-f70.google.com with SMTP id h30so1407590wrh.5
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 03:29:24 -0800 (PST)
X-Received: by 2002:a1c:1dc4:: with SMTP id d187mr4900380wmd.46.1575545363047;
        Thu, 05 Dec 2019 03:29:23 -0800 (PST)
X-Received: by 2002:a1c:1dc4:: with SMTP id d187mr4900356wmd.46.1575545362806;
        Thu, 05 Dec 2019 03:29:22 -0800 (PST)
Received: from ?IPv6:2001:b07:6468:f312:541f:a977:4b60:6802? ([2001:b07:6468:f312:541f:a977:4b60:6802])
        by smtp.gmail.com with ESMTPSA id e18sm11632611wrr.95.2019.12.05.03.29.21
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 03:29:22 -0800 (PST)
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
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com>
 <CACT4Y+ZHCmTu4tdfP+iCswU3r6+_NBM9M-pAZEypVSZ9DEq3TQ@mail.gmail.com>
 <e03140c6-8ff5-9abb-1af6-17a5f68d1829@redhat.com>
 <CACT4Y+YopHoCFDRHCE6brnWfHb5YUsTJS1Mc+58GgO8CDEcgHQ@mail.gmail.com>
From: Paolo Bonzini <pbonzini@redhat.com>
Message-ID: <bf93410c-7e59-a679-c00d-5333a9879128@redhat.com>
Date: Thu, 5 Dec 2019 12:29:20 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.1.1
MIME-Version: 1.0
In-Reply-To: <CACT4Y+YopHoCFDRHCE6brnWfHb5YUsTJS1Mc+58GgO8CDEcgHQ@mail.gmail.com>
Content-Language: en-US
X-MC-Unique: fzDCdiacPJCSD8Y3t7HxHA-1
X-Mimecast-Spam-Score: 0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pbonzini@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IzY4lWJ0;
       spf=pass (google.com: domain of pbonzini@redhat.com designates
 205.139.110.61 as permitted sender) smtp.mailfrom=pbonzini@redhat.com;
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

On 05/12/19 12:27, Dmitry Vyukov wrote:
> Oh, you mean the final bisection crash. Indeed it contains a kvm frame
> and it turns out to be a bug in syzkaller code that indeed
> misattributed it to kvm instead of netfilter.
> Should be fixed now, you may read the commit message for details:
> https://github.com/google/syzkaller/commit/4fb74474cf0af2126be3a8989d770c3947ae9478
> 
> Overall this "making sense out of kernel output" task is the ultimate
> insanity, you may skim through this file to get a taste of amount of
> hardcoding and special corner cases that need to be handled:
> https://github.com/google/syzkaller/blob/master/pkg/report/linux.go
> And this is never done, such "exception from exception corner case"
> things pop up every week. There is always something to shuffle and
> tune. It only keeps functioning due to 500+ test cases for all
> possible insane kernel outputs:
> https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
> https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/guilty
> 
> So thanks for persisting and questioning! We are getting better with
> each new test.

Thanks to you!  I "complain" because I know you're so responsive. :)

Paolo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bf93410c-7e59-a679-c00d-5333a9879128%40redhat.com.
