Return-Path: <kasan-dev+bncBCT4XGV33UIBBUEWROGQMGQE25TMYBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 84BE5460288
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Nov 2021 01:20:33 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id x6-20020a056e021ca600b002a15324045fsf13392186ill.12
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Nov 2021 16:20:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638058832; cv=pass;
        d=google.com; s=arc-20160816;
        b=gwsrq/LKk6vnxd/PZGpfNS0+WF61wISZmF4i/D6LkPYJM3Zo3VOfGeQn7QKAfZAiml
         lOdoPvXanedZnKiFG2E7Ba36f1Cgg3lUfbRU/xSUYj6MC6zrWxRQnLJqUHN64aUZBsKM
         PLCsFRayCXaUFmsx6hh7WWB9/ykfPjZnBw4Mof50BRx0DPYvcIlJ9hCqngB/CU76YGfp
         hAQTaTeaomkdRIzIYvHvwn3q2w4ojNrtHuuBLe8vrM0ZobAG84TH9WMP++Vyb7JnJQs5
         WnLOw1SXP2+dLYqsK7mqva/mk+CyOwpobbiqeyU9oAGcTUdDYCp25WLbEQXLFxmWpBYV
         Hxjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=6WvjTvm6K+xquYGv5pHxO5GV+Ukj2xHljHjPTO25GAs=;
        b=jsWAU1QniHFVaGcDgP5UQc6JDKi0edkgU3YzCXib45Bb/e5EGjs97KDBMhJx5++1zi
         eiGTiAx0LACo4YetRHt/efN+y7o7yiwsXeHM0O2pnhgxMWP3+LHWydF64WLcGFbbOO7H
         symrT40bhmEg/YErUqHJorbC5BiPICJgLAy8RuquYUYOSRe+hobv9RGMQ55w4OCu5vpn
         vBGtsTVql8u2te3tpFP0h05fHF8g2qZDtSOYIgxsmBZY2+2ilzjjT/56ot0bQJ2ms2eg
         TKhYXhsn9uXJ1dyxAPLioxgZ2wqmNDP+gQQpIYHn2cR5VjbszYqNYne1a9AcMAlc3K2E
         HKyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0AOvXxVG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WvjTvm6K+xquYGv5pHxO5GV+Ukj2xHljHjPTO25GAs=;
        b=Rf8NEHDCmyXngQH7l//tR1RLtO4RlozFTP7oozba7wgwY9exPTYDTrJeY2wfeoe2NQ
         tTN18umJ7vxvZVFuyXk27ZwWcCZNVqQWJ0SCMQsS+7NAOzeM0QFOH9GLkc4QeDEC4phH
         4dVf1nUz4PRKaj+rUtagtJft+UZqg+bEwZyGrm/T2KnuMJJiVzLyUU30k9I9YTzaJllA
         wb/ARhAOKyIFpYoLgprMgq7EcuaunkWJdo11FuXBUa7pTBBT8mDCGGyVtHAJt1jSmPhg
         1X1F15n/6Yzbpl8nXaTp1qJgYS4aZ5IYuP9Bc+JGQltCq8OVmsE6SgaXuu/5EHwKynsc
         LjUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6WvjTvm6K+xquYGv5pHxO5GV+Ukj2xHljHjPTO25GAs=;
        b=ZOPKclQ2MgptvkTThAWhw2n5A+7EcJnlokte2shGHcIDRlCdgb86UMWKnbYilWW+DN
         Z36YHe+bj+kNzPbJnqNk4CUDWwkXdJoIKSWCjkShYlxvUWv26qJph5W82+kfqjlZh1Np
         0Jvzvnpw+jeTADBoOUI0kvH9YE9FX7btRYfXMsqyO98a561zsYCG+Yzhvzh0cDgEHSm8
         XTgPepkCoOBeJgv117u4iFrAjPIc3DQq9tkRdqThQQdNbIt1WxYr+MH85acogX7NEBFx
         EVBl5cgyR07LARsZYlg1H8DqPb7kH0LsOLRoL2raWPX4up6pxLZRpDOIvrUBASLgGHDw
         HELg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530XCuLKD9NDfm3YFgzOGktvbUjLm7ecnGh4XgzzXgw/JshppnEt
	ZXDFgk0Dy6TQO+AJgK1RV7g=
X-Google-Smtp-Source: ABdhPJwXs1j2/0HOaGzSlO1fFXB34VWsr3yLA/abGcql2xhCEYD5uwLtTtiY+rR6q5wp6ZF4Z99YdA==
X-Received: by 2002:a6b:3b49:: with SMTP id i70mr47159371ioa.12.1638058832187;
        Sat, 27 Nov 2021 16:20:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9358:: with SMTP id i24ls1006905ioo.4.gmail; Sat, 27 Nov
 2021 16:20:31 -0800 (PST)
X-Received: by 2002:a05:6602:2d49:: with SMTP id d9mr47478070iow.11.1638058831818;
        Sat, 27 Nov 2021 16:20:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638058831; cv=none;
        d=google.com; s=arc-20160816;
        b=FbIgdJoOA1sWaTKriPyXfYFxZSLEskGMqXoqQfsKGWsMHf/p1a99+CUra3P+TJ4cow
         LRroWIhoNrsS1nOrShEVhjz0fcoUGmdQCMwDlJSqKmcmgIAZ7LiKQHX9QkXTO3cP/h2X
         hmt5jowhdZr5VpCfylfnber+SxbFRTPIPl9o6UeTac+VoEsxtn0QaiBBcGD5XNH5Xr6i
         8I/BDXVBmwB93oqhq+cwJLX/ze2evgLMeQhAIyvpvd+2wMgW011GVv5S4cDVe6O584DG
         yery4xAt5jXt49edJGYQPMlEZvI83M5gtsduM0jVl0bqhA0XuzxWGE+GvTnldWTmCGCb
         7QaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=ZbQsuSjDUxJ3CjJwaFVq9cw0S4SFNxcWli4n2WBAKGE=;
        b=XcxYHAWQ5Jzwe9YJ5IUpM9ZBi0aEpm604EcQQiNwuujWK5/TAmr1fCAIpThKIHmLHU
         gMozQhS/f7VGRbKc0RhtdakPO8VeinBsgC6SK4bVltJgRRrWX55utQjvWBMO9820YaiL
         5ZQN0fSgL0bmGciUn0iiw7LxmVlWkpu/rRmSkd+e+qQgNqpltRrUIMibOVRz4G5SBqB1
         pCqtjaDir9xEVEzJvEbQVbxJSdVg7OcZQ7kI+Og4ov4UZcqebGg63eX9hHKjzVPo4UYy
         Zo6SgA0KrGzi+/ALImSQ7TPs6IPGdaRSCK4JitSPSQY8mS4i/IQk4GfbuwXslp4/wPwR
         WyaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0AOvXxVG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g8si1708314ilf.1.2021.11.27.16.20.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 27 Nov 2021 16:20:31 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from mail.kernel.org (unknown [198.145.29.99])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 450BC60F4B;
	Sun, 28 Nov 2021 00:20:31 +0000 (UTC)
Received: by mail.kernel.org (Postfix) with ESMTPSA id 3B29560524;
	Sun, 28 Nov 2021 00:20:30 +0000 (UTC)
Date: Sat, 27 Nov 2021 16:20:28 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, Catalin Marinas
 <catalin.marinas@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 Chinwen Chang (=?UTF-8?Q?=E5=BC=B5=E9=8C=A6=E6=96=87?=)
 <chinwen.chang@mediatek.com>, Nicholas Tang (=?UTF-8?Q?=E9=84=AD=E7=A7=A6?=
 =?UTF-8?Q?=E8=BC=9D?=) <nicholas.tang@mediatek.com>, James Hsu (
 =?UTF-8?Q?=E5=BE=90=E6=85=B6=E8=96=B0?=) <James.Hsu@mediatek.com>, Yee Lee
 (=?UTF-8?Q?=E6=9D=8E=E5=BB=BA=E8=AA=BC?=) <Yee.Lee@mediatek.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>, "linux-kernel@vger.kernel.org"
 <linux-kernel@vger.kernel.org>, "linux-arm-kernel@lists.infradead.org"
 <linux-arm-kernel@lists.infradead.org>,
 "linux-mediatek@lists.infradead.org" <linux-mediatek@lists.infradead.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] kmemleak: fix kmemleak false positive report with HW
 tag-based kasan enable
Message-Id: <20211127162028.07d1a9fc392d91e7d234daae@linux-foundation.org>
In-Reply-To: <CA+fCnZchvHjU9G_SSf_M2--jHPqEa6PEr3u_5q-wJWvZK4N2pA@mail.gmail.com>
References: <20211118054426.4123-1-Kuan-Ying.Lee@mediatek.com>
	<754511d9a0368065768cc3ad8037184d62c3fbd1.camel@mediatek.com>
	<CA+fCnZchvHjU9G_SSf_M2--jHPqEa6PEr3u_5q-wJWvZK4N2pA@mail.gmail.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=0AOvXxVG;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 25 Nov 2021 17:13:36 +0100 Andrey Konovalov <andreyknvl@gmail.com> wrote:

> > > kmemleak_object *object)
> > >  static struct kmemleak_object *lookup_object(unsigned long ptr, int
> > > alias)
> > >  {
> > >       struct rb_node *rb = object_tree_root.rb_node;
> > > +     unsigned long untagged_ptr = (unsigned
> > > long)kasan_reset_tag((void *)ptr);
> > >
> > >       while (rb) {
> > >               struct kmemleak_object *object =
> > >                       rb_entry(rb, struct kmemleak_object, rb_node);
> > > -             if (ptr < object->pointer)
> > > +             unsigned long untagged_objp;
> > > +
> > > +             untagged_objp = (unsigned long)kasan_reset_tag((void
> > > *)object->pointer);
> 
> The two lines above can be squashed together.

That would make a too-long line even longer.  In fact I think it's
better to go the other way:

--- a/mm/kmemleak.c~kmemleak-fix-kmemleak-false-positive-report-with-hw-tag-based-kasan-enable-fix
+++ a/mm/kmemleak.c
@@ -384,10 +384,10 @@ static struct kmemleak_object *lookup_ob
 	unsigned long untagged_ptr = (unsigned long)kasan_reset_tag((void *)ptr);
 
 	while (rb) {
-		struct kmemleak_object *object =
-			rb_entry(rb, struct kmemleak_object, rb_node);
+		struct kmemleak_object *object;
 		unsigned long untagged_objp;
 
+		object = rb_entry(rb, struct kmemleak_object, rb_node);
 		untagged_objp = (unsigned long)kasan_reset_tag((void *)object->pointer);
 
 		if (untagged_ptr < untagged_objp)
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211127162028.07d1a9fc392d91e7d234daae%40linux-foundation.org.
