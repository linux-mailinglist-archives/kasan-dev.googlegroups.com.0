Return-Path: <kasan-dev+bncBCT4XGV33UIBBONQYKFQMGQE7KMRZ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id E97874355D9
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Oct 2021 00:29:14 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id x10-20020a17090abc8a00b001a04877d05bsf2467344pjr.5
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Oct 2021 15:29:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634768953; cv=pass;
        d=google.com; s=arc-20160816;
        b=hUvx711zTOk1F9HHqfrnQAedIlZ7g79VOS6BYiacL7JAWB+Zv67j/Esgg1XBn9d2Mj
         NMu+kTAq3FQkH/8rYnwEkf/B4EoffZUSCqirwWQYcFvJt3gY8g+Gz4jhg+cFY1VNhDWt
         vCj0onzEQvM+1UW4ScgIwuLNUankh7UmLhS1ehJBZBRIw9h/WzWfoLj6YnqJCLVkd9XK
         jSa+tCBaubYEYSmsR+ir/NU0FMsYk8cKQUgYPwD6jJBbL+BB+B4tN6jWLNUQ47LhGQ83
         eE+52sFJ7uv1PAOhVvbnkbtucgAYzF5nIdfw58jg6YnXHE3rE+pQ6wQ7ExODf9l4k51L
         +7jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=gP9C8Ztig/NNgWcNU1xMAPuBh0HfaxtfHdS2MF6zcNo=;
        b=gchyFIDp4A9I78+cBDirSSigmJirsI2PSj8+orVCqo6Dor/OOb+rGq7VqZ2Ivh6EiY
         01RElc1IguFvsCBbqatnLA5Xn8XCk1tVfTgAyJJhmWapm6/7TGxRYeaW3p27g14V1gZR
         4DLivcXeLdFa5grotZiQpMD+Ihqor7eFyYStrlg/woSlR2etiXtCvQbHvvvjngC2j1h5
         HjrL1XuGVjTSDKViJo3NRi1pv2MK/qEKC5XbIRk1iNHDcflaSZF735nWDHjmgglJlhNP
         QhMqnBh68PRmIqZ5/acgpholfqaLwVk3pQjNqDbgBf26FcDeQWq7Gb2N/9/LSMv3ufv7
         7TCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TEnlDxKO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gP9C8Ztig/NNgWcNU1xMAPuBh0HfaxtfHdS2MF6zcNo=;
        b=Not9HvDVRnGTK44B6Q2GqvdWZm0OPmHHa+L8cYzVMKFE3EMmevJjtJDshHV6aKIT9g
         DByyqTBad1TxDBVjValAjZnZt2vHJhDpilHKaYstQJdqoEjkwyvScAIZuoBSs28taveO
         ZODWwcAtMTtxfX0CgNNH7s7mnSqfJxpeOBjfHD33nbxioffVUi+RuQALdzWUSRgDU/eG
         GY8eXc8RqOwIOrzoLUggRqVDm+vv3x6DFydaB1ct8vFW6iWObdkzoPNUnHfeYqO4LG1+
         JKWLZmZWltelTyTZc0J4H6QDHfnSt7cKZ5U3fX/nr6MkV45xxsCOrk+Qj9jOH1/hI5PH
         ydbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gP9C8Ztig/NNgWcNU1xMAPuBh0HfaxtfHdS2MF6zcNo=;
        b=4JAEGg1o5SuQSl7ltRLoVNQYFIw6ber52JNcWi0MzHnb1znHZmP9vqbUM+MkAS/sDf
         T8Nm62BhoBcPE9zR5krqycGWXL+9F4k5f0FRTcYCbrS8zp6UZO6E/+pmQTcKgUtjynMY
         uA83Ce1bMNPEo8ceuu5HXjR9z7ZH/PMrsZhX0bNVHWf3VS1cLKxbFzSggJNrbkDIuTKh
         o9mntpJmFTkYeFxx6EAQt66pLa506JvCjTp0HAUzIhPfZROEmAFtjxp4LerzuyCCPPOM
         REKMAJV1KZcUaqr1KzwnQm1M+rWFj3eKV9hXwsUeARMYnOzwYyPsbnC/jWavx9CYi8g3
         O8GQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311G7mbzh5Aug4sM4r0n5Ib785KP2rTLH/TNWOgI06AWSw4USAp
	8mDIR0xxRiXK/xk7e31AMYE=
X-Google-Smtp-Source: ABdhPJytRb8QDHnJZMQJUEfoHr3eWI21R5wyfPACK0LI5f72E4Cj++3akEQ8nvBOnHMMsSUgtCy9kg==
X-Received: by 2002:a62:7752:0:b0:44c:eb65:8561 with SMTP id s79-20020a627752000000b0044ceb658561mr1462791pfc.43.1634768953465;
        Wed, 20 Oct 2021 15:29:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1a48:: with SMTP id h8ls1606013pfv.7.gmail; Wed, 20
 Oct 2021 15:29:12 -0700 (PDT)
X-Received: by 2002:a05:6a00:c8e:b0:44d:f590:e32f with SMTP id a14-20020a056a000c8e00b0044df590e32fmr1570024pfv.3.1634768952801;
        Wed, 20 Oct 2021 15:29:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634768952; cv=none;
        d=google.com; s=arc-20160816;
        b=XMsOVMGkJ2H7j6K30IR4mfmwlBYCfpel3EfOEK8Ryz/dfkUUmCSKawDntdtq544EeO
         mFyNP8ToTMq50JAUdxjQipFQAhn+Nk9s/xfXejcIyg/riDdppiGra0QczQeTncjY+6Lk
         KQBnMteUccLR/JUgS6czAyilg0us6Gk0hDQFnAj/qs+6J3DvIHSa/xKLvGaHT6jnqY97
         93TXgR2Au03kKbdsoz4BBclHlqgxSFa4edYFEVNIA2bZHXzB95HNafHBfOUPaNkRSzXI
         /HvE5VAmdn8a+2MonNiZIg1cuRWPxkNM9l0EQlkyw4jmAnO6CdSpgusJ7xQI7XvHb9Wp
         F7BQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=FIzODl9jZINQHGUHj43LcboxgqM/k/yCmad49nZmNzM=;
        b=vOMthRtK4BnbfsQfjIzuVjoYp7yS+5DVN6DYz+4COPTx31KgVcPBPQWnBzS6XSy0K3
         6WoWIQSEKWYs4iGtVx6H21TSfvA/qHHjvWGEghHjmV938cBupyll+D7dqDt9H2qjVsJo
         CoYge+X3/dBv1MkniLB7JqYXvDmdHUV0Cxnz3zb+Lox/pJJHj6HxpIycwttAoDQrmVM4
         Gsbncc1GkgWfeahNocXabi8hHHUNkPTHcd//Dbtp0QjdAeBKzDUnxEtpdQ9w25MTkJ1Q
         QR4yyqs8I2BYApRMELA2GHGCpfLd0SybuMxQQAo3vEMcy9oOJt4zwTv6ePRHgPjpRMUg
         13bQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=TEnlDxKO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b1si268315pgs.2.2021.10.20.15.29.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Oct 2021 15:29:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F36716056B;
	Wed, 20 Oct 2021 22:29:11 +0000 (UTC)
Date: Wed, 20 Oct 2021 15:29:09 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Matthias Brugger <matthias.bgg@gmail.com>, chinwen.chang@mediatek.com,
 yee.lee@mediatek.com, nicholas.tang@mediatek.com,
 kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-mediatek@lists.infradead.org
Subject: Re: [PATCH v3] kasan: add kasan mode messages when kasan init
Message-Id: <20211020152909.2ea34f8f0c0d70d8b245b234@linux-foundation.org>
In-Reply-To: <CANpmjNMk-2pfBjD3ak9hto+xAFExuG+Pc-_vQRa6DSS=9-=WUg@mail.gmail.com>
References: <20211020094850.4113-1-Kuan-Ying.Lee@mediatek.com>
	<CANpmjNMk-2pfBjD3ak9hto+xAFExuG+Pc-_vQRa6DSS=9-=WUg@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=TEnlDxKO;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 20 Oct 2021 11:58:26 +0200 Marco Elver <elver@google.com> wrote:

> On Wed, 20 Oct 2021 at 11:48, Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:
> >
> > There are multiple kasan modes. It makes sense that we add some messages
> > to know which kasan mode is when booting up. see [1].
> >
> > Link: https://bugzilla.kernel.org/show_bug.cgi?id=212195 [1]
> > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> 
> Reviewed-by: Marco Elver <elver@google.com>
> 
> Thank you.
> 
> Because this is rebased on the changes in the arm64 tree, and also
> touches arch/arm64, it probably has to go through the arm64 tree.

That would be OK, as long as it doesn't also have dependencies on
pending changes elsewhere in the -mm tree.

To solve both potential problems, I've queued it in -mm's
post-linux-next section, so it gets sent to Linus after both -mm and
arm have merged up.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211020152909.2ea34f8f0c0d70d8b245b234%40linux-foundation.org.
