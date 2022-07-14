Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCM3YKLAMGQENXM5O3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 5330C575718
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 23:41:31 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-f15a7ca913sf1793194fac.8
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jul 2022 14:41:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657834890; cv=pass;
        d=google.com; s=arc-20160816;
        b=TC65/5JHlg2F2fXu7QDa2mWe+ULHqeZqq2mYgLAEwhgSBWAs3qybNzpB2RQfMv53vJ
         Ou+EjNfGF77uBOCzcjRcHJnxx0aC/1IibQSJ2aFLChN7WzQQWUP+gkpPUCVOZYLnU2Tp
         /vCjQfFWi+eX+TVaA+oYga8bdal7jqQcKJWWJD+8/c+Cc/BBsf9vtNJHpqTO0GoFa4ie
         eSPcJPVCDhiew7NflU8FmUiVYEBnoSHpogTfR7JRQH/HpVxgQD2frqkz+1Kj44zYpQu3
         LoXECU+l7wRL4OZgWA0XtYLQFXF8tlJCuw7ohhAOWJc7TMpx3m1b/EMGszZOYnNr2rRg
         JDCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Kldb4l8wGNyG63g/dD8vrCp5A2wOX0pFCa9O9t1Yf9s=;
        b=iLvQ7qijykFSCxGKYNmXJwmknqkbsoDLf0UOkf75AnLzU0DNKdyAKubbZJkXWUV91D
         5DiwvjIEsR1AVPg4asLo0QGFsnpaRnH5jpcXsMH3bjJnQpprUwsbrQuSGunZJCTTFemp
         s/ANjbegcZiWyn+cWGzpetIMMWRZqNPsB68UD4AQXT1ayY+UFryZqujz8jDcRZ7N2v7f
         x/ezvUSEPUPSsCnHXtqpu6Bm6UtYWW4hoFiwhnrWDAWJ5lsal/389K1WJsUfOdRC1FVK
         TI/wocBDKH6acB7lG74QP2eY6z14eRcIDsRWe9V9H90FL8NbjcFDNUq7ZVNEECHhKPDX
         c5Ww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xosv3ScU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kldb4l8wGNyG63g/dD8vrCp5A2wOX0pFCa9O9t1Yf9s=;
        b=QuYkp9gFu8JAswGOHX41S+zLLC+UJLQPbT7N91wr6/gQ0j3DN3DE1k44Og5S/tULuC
         KmTQVCI8FemYQC0XUIJnPKmtQKcehApPM51OQHrcy9p/dov0JSEWJ/ybKOQRliSbkkaz
         p1um+1CpR5Hbm9mLFbmie8Reik2PHgWeoNqkCWUqByESoQVrjXq6YSUDp6qUu3Kup9rx
         FOtJ0nk/IjgeWSj2KQjHEdf39LB6MIdcf56d0wXTRaLOcu40i89SvFkwohMj1txyf1Hu
         /wex7AwCcVYT2dPCV/m/XhQlwVPz7I2NUAJnnFNlHU/m1WCThcIjB/gIUkYcBhs3mxkE
         RdzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kldb4l8wGNyG63g/dD8vrCp5A2wOX0pFCa9O9t1Yf9s=;
        b=vanKeUYgZna3ADJHJTXcmZA0AJZ+sUzyqhJXq+79ZHzqDcHhmxVAMRpGLsnoF2fY9c
         nTtRgk/oeka9I8mlCUhmYMNTn+3V+b1U+7uflS0qeUKOK+09b7JJqp+NzqBtSQONDqzZ
         qWGd26jY6Nec0gBNDZQ3ZgTO4rbDetz1SlqapuBOUBdFgCAJQ8n3dIfogaewcCdxXrQq
         E04610Xmo7wc2MstjhCFCoiD9ZJboENpegVzFM2ylOtl/6TUPESYwlddLauKXC7YNdjU
         FkQFXzTZDEst3aqnsjAbRHa9BuUSXmrJT+ugr610LVrqjCdN0mTSLrDrAWUM1tCju1y7
         k1NA==
X-Gm-Message-State: AJIora9/jJsAv/k+svZQJtcOJcb9WkO/pdr0QDldQIZ+eljwLMIxij/F
	16LizcGne5cV2S3paW08dQg=
X-Google-Smtp-Source: AGRyM1vre3F56deRpGU707O5502CEywzZCT3C2oTAKHEmYfecs41dydlsVr/9mpVKFzD22oKcZ/uyg==
X-Received: by 2002:a05:6870:204d:b0:10c:59bf:fe63 with SMTP id l13-20020a056870204d00b0010c59bffe63mr5739547oad.109.1657834889961;
        Thu, 14 Jul 2022 14:41:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a487:b0:10c:45cc:c65a with SMTP id
 j7-20020a056870a48700b0010c45ccc65als1009358oal.6.-pod-prod-gmail; Thu, 14
 Jul 2022 14:41:29 -0700 (PDT)
X-Received: by 2002:a05:6870:f2a3:b0:fe:51a2:cc61 with SMTP id u35-20020a056870f2a300b000fe51a2cc61mr5579261oap.3.1657834889384;
        Thu, 14 Jul 2022 14:41:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657834889; cv=none;
        d=google.com; s=arc-20160816;
        b=VDmlSUy0kgV5wLOXw8pBM/0LTuQClYMkioVLfQnJ/2oOdFxqqVa+cMf6iVAGtoK8WX
         +0ae6kKoMXSEqHx2hY5srKZ/fZk9JyoGtZYVwEKX5LiLABth8DtPA7p5AuAdpUK4dg1g
         TD96xIUYVlkVXcYVY9u5uR6n/pwZKTwx1rAcIJsnmEGdNXT+fgEx4m1WPrkA4CMtzcBm
         3ieQkffhURftT3tl4D+ee9yxr8GELmryYqTbOvqLgGKIVMmCWsd4ZcvwsaOrtV3d/1PR
         KToFq1QZ7y7bCLT/Txvm1CyDf1LV5upmQ0568OAJpJcZ+Z5hnQku93zM8YF0s04H8d+X
         qHtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XrLJ6t8ylgvZSQuZlmobmLCnVlZPRzZJ+MdpYtHUOJI=;
        b=babLhu8UwOpQ/SsxySjbHybxc249IapprUdgtcIgDRkR8T2vspa2giQgZOtSzyS1lR
         +QdYpG14bqbTW9FT7NvK8CQkxFr94eOatEhaSH/aUHa0vbfH3MSxZuOygQUclxF967WI
         Sjb8UsbrpJlcVGOVNL06+DVb2WCQBl0FTJmq0hQaK+zJORtFSlhYRhAk72KqVnI4kCpL
         2G9KJH9GOPAVUFQ1Te6LB53f89UtEW0emq0JqiITqnI1dkowNPvsoUerleJ/snEVOYM8
         7Cl9Adr3KvgjogVyjG/5jq6qa26M4X6AEI+ZiCdqzOEsXZyWbULSpoIKut8aluBBLR9P
         nJZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xosv3ScU;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id fo13-20020a0568709a0d00b00108c292109esi268716oab.2.2022.07.14.14.41.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jul 2022 14:41:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-31caffa4a45so30432057b3.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Jul 2022 14:41:29 -0700 (PDT)
X-Received: by 2002:a81:e17:0:b0:31c:a24c:9ee6 with SMTP id
 23-20020a810e17000000b0031ca24c9ee6mr12223353ywo.362.1657834888937; Thu, 14
 Jul 2022 14:41:28 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
 <YoS6rthXi9VRXpkg@elver.google.com> <CABVgOSmyApbC7en25ZBr7hLJye0mOnUY5ETR-VVEWmbaXq3bdQ@mail.gmail.com>
 <CANpmjNOdSy6DuO6CYZ4UxhGxqhjzx4tn0sJMbRqo2xRFv9kX6Q@mail.gmail.com> <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com>
In-Reply-To: <CAGS_qxr_+KgqXRG-f9XMWsZ+ASOxSHFy9_4OZKnvS5eZAaAT7g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Jul 2022 23:40:53 +0200
Message-ID: <CANpmjNP-YYB05skVuJkk9CRB=KVvS+5Yd+yTAzXC7MAkKAe4jw@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: Daniel Latypov <dlatypov@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xosv3ScU;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1131 as
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

On Thu, 14 Jul 2022 at 22:23, Daniel Latypov <dlatypov@google.com> wrote:
>
> On Thu, May 19, 2022 at 6:24 AM Marco Elver <elver@google.com> wrote:
> > I'd keep it simple for now, and remove both lines i.e. make non-strict
> > the default. It's easy to just run with --kconfig_add
> > CONFIG_KCSAN_STRICT=y, along with other variations. I know that
> > rcutoruture uses KCSAN_STRICT=y by default, so it's already getting
> > coverage there. ;-)
>
> David decided to drop the parent patch (the new QEMU config) now
> --qemu_args was merged into the kunit tree.
> Did we want a standalone v2 of this patch?
>
> Based on Marco's comments, we'd change:
> * drop CONFIG_KCSAN_STRICT=y per this comment [1]
> * drop CONFIG_KCSAN_WEAK_MEMORY per previous comments
> Then for --qemu_args changes:
> * add CONFIG_SMP=y explicitly to this file
> * update the comment to show to include --qemu_args="-smp 8"
>
> Does this sound right?

Yes, sounds good to me, and thanks for remembering this. I'd prefer a
close-to-default config.

> [1] Note: there's also patches in kunit now so you could do
> --kconfig_add=CONFIG_KCSAN_STRICT=n to explicitly disable it. This
> wasn't possible before. Does that change what we want for the default?

I'd just have KCSAN_STRICT=n by default, and if desired it can be
added per kconfig_add just the same way.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP-YYB05skVuJkk9CRB%3DKVvS%2B5Yd%2ByTAzXC7MAkKAe4jw%40mail.gmail.com.
