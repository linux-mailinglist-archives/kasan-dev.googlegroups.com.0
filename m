Return-Path: <kasan-dev+bncBAABBKULU35QKGQE47BRAGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-f189.google.com (mail-pf1-f189.google.com [209.85.210.189])
	by mail.lfdr.de (Postfix) with ESMTPS id F1CC5273A02
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Sep 2020 07:03:39 +0200 (CEST)
Received: by mail-pf1-f189.google.com with SMTP id t201sf10397337pfc.13
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 22:03:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600751018; cv=pass;
        d=google.com; s=arc-20160816;
        b=KeDGaTnjwbu7PH+1vsk23n9KLw9m4Y1PAFe+88u95iwJ7/adl5qjaKcltBhXZhorwc
         j0Y/LNoblFb2w5EK9N6enRbjxyy6wr5id800NmMkxtuhwCAS3w6biNKyko9cRJH5Si9S
         IixWAK5wHCHL/IpRvgMlyqaytN98tkYCXwQSFi/Usf79bl+ogkEHe9RvIw/l3nLjBoK7
         hXeJCjCsXuJ+9YrlO5Teg6vYIx2OkL+psAKJkPjIDUJR64OaXItlq44kTvnDRwCR4v6r
         DzY9VhB/f+6t5o6ZYnGTYaGZfhjrTdJTlftPzH9O+ZqlV+rRTuvQuL65FsoVWmRTKnTx
         nHJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:thread-index
         :mime-version:message-id:date:subject:in-reply-to:references:cc:to
         :from:dmarc-filter:sender;
        bh=reH9AOC1+nasc5Za9WNC2IAUeFs2R0+WtRvKqbzOMqw=;
        b=BHaXUNkvvKgvUbAb94FBM1a5ej9G1zVKL5u66fCbZg5mRowLl7IOjYrIk9T5nI9D1A
         QOWixUNlfyKw4YQvpXBWrSIGlVmxm+eLQSqyjXossO0BRjRKVSeh+MWOTwykv/3dbr7z
         MThlqwi5lwlLj/Fj93smvG/PBebVyOHwtrPvE7at5zIiVfwp1OznpH9AVXLn3u/xZRPM
         Qp+un1K2Y6hpoanMoU5DAODM3Orad+x0YpSd+H9iNqtTJ2YfQPtkBcYbZ5mmAkhJM9Gw
         sbgbOpAHfnSs15/kt067Ac+pXv2LGoezB6b/4sIIKqZZmccfCAaBYsVBfu84Wlh7tgfp
         p4ew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=sCdq8Azf;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.42.4 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:dmarc-filter:from:to:cc:references
         :in-reply-to:subject:date:message-id:mime-version:thread-index
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=reH9AOC1+nasc5Za9WNC2IAUeFs2R0+WtRvKqbzOMqw=;
        b=eZgAXHK3uTCN/Evsn7QS2kS/pp6yoWV2R9K5X+hAjz/QOVIgX+MNaUWPP+mHLm/hYY
         pP/MCSYqx49EgpyV2x7zR5LUoKNT/CbCqRl/8jbfGAAeOV5T052uijpoNnJ5b9ldmwuX
         IH75qFBFsGRyRT8wHAQv0G+ZthjwKszjFYFUub+cJkgm+mm/fXJVgEtOHl4zr006Vhzk
         RS9qmvCWonWEVFYFX59oa1zvcZd2oUK/prriWbPvcmev1yiELjbEnNQQFtNmuOB46603
         JnzcGhViHvGM6o+8bhUX0DdYQqhtLwcNhufaXhh3jaw6fIl+VP4QcB8bwpDrxXjXON08
         8zww==
X-Gm-Message-State: AOAM533ZwaUyG0Q3RcbUVnwTMLxyDaONjzKH64krWlDpLM9gHCFPTbyM
	clhf+CcURbo5tY7sm+dyqm4=
X-Google-Smtp-Source: ABdhPJw2Xi7PhYs9EVUh2KLvXs6vTyYI2lCRtrjfJO/vPghM1jznP9uXODfWfyp9Dl1rgBAU1wg3TA==
X-Received: by 2002:a05:6a00:2db:b029:142:2501:34ed with SMTP id b27-20020a056a0002dbb0290142250134edmr2538368pft.70.1600751018393;
        Mon, 21 Sep 2020 22:03:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3855:: with SMTP id f82ls5347965pfa.10.gmail; Mon, 21
 Sep 2020 22:03:38 -0700 (PDT)
X-Received: by 2002:a63:d946:: with SMTP id e6mr2236574pgj.113.1600751017928;
        Mon, 21 Sep 2020 22:03:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600751017; cv=none;
        d=google.com; s=arc-20160816;
        b=hXF6SAANcUWVlcH+x5kyqF1iRgHlPfi5lP1bG1KTM0cEveabMqQ9adtLH5LArVc3Wt
         cS9/cj1u5+30f4RlPiBcyM3eaqR1MqvQ9VYyz8bBWlGAaYWLLqsdgKK4CiNKr62EaBBy
         +r/vW3pJgbA+K8AxOrx5nFQPhLNik7fdQnkbBA/qZBxmWROAfzPJTRCM2tkMI81pJiFT
         7UbchOLsjr9Nv+WKfcS3juUO5m9iiX0XoK0EttAQQVh7mNQlV5BrosxLWId95dI/01Oa
         FRYCHeHaGMN+ZZCkla69FlQotgb8cb718Qr5qKoL2mra/6edu5ZAhkhMlOMBE+vLwAY8
         JC4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:thread-index:content-transfer-encoding
         :mime-version:message-id:date:subject:in-reply-to:references:cc:to
         :from:dmarc-filter:sender:dkim-signature;
        bh=AcMuH3mkcy9D4E4imkmRc69X8OMYxOw3QnWEelRh8MY=;
        b=gtXC35BkH1HFionJVJhe7ZMlqBeL76hxacXrkEoNwqMFhjGl3uqX5/fVQeNHBZg7fv
         YSlH8AMSfSvZ/9iq3MHoLtlMKZICVkOKC/Fiwgsy8IOm0nPlpBYkPe7X2x/wM7OLbj4w
         mHXwJ0yIUjCvIibYMkNXsbXpdM0K1gFcdSiWq2JX3nkeMe6ApD9/GjF/I/Q3TOcif4wq
         Sxkq7V9PLvoRmiRDHWep1kQXJFy4msi5nG6Gun9VbtPwV2c+5LmkUsObSfpM+nnyzlgx
         kDQpyb9BNpeWciFzaSUud0PuAHcLtn65xSSbYlXW6khOAwjbwHgXs04uS5GnmbBC++bi
         fE3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mg.codeaurora.org header.s=smtp header.b=sCdq8Azf;
       spf=pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.42.4 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
Received: from m42-4.mailgun.net (m42-4.mailgun.net. [69.72.42.4])
        by gmr-mx.google.com with UTF8SMTPS id iq17si87124pjb.3.2020.09.21.22.03.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 22:03:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org designates 69.72.42.4 as permitted sender) client-ip=69.72.42.4;
X-Mailgun-Sending-Ip: 69.72.42.4
X-Mailgun-Sid: WyIyNmQ1NiIsICJrYXNhbi1kZXZAZ29vZ2xlZ3JvdXBzLmNvbSIsICJiZTllNGEiXQ==
Received: from smtp.codeaurora.org
 (ec2-35-166-182-171.us-west-2.compute.amazonaws.com [35.166.182.171]) by
 smtp-out-n02.prod.us-east-1.postgun.com with SMTP id
 5f6985524398385e30a0f85c (version=TLS1.2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256); Tue, 22 Sep 2020 05:02:10
 GMT
Sender: sgrover=codeaurora.org@mg.codeaurora.org
Received: by smtp.codeaurora.org (Postfix, from userid 1001)
	id 852F7C433CB; Tue, 22 Sep 2020 05:02:09 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.4.0 (2014-02-07) on
	aws-us-west-2-caf-mail-1.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-2.9 required=2.0 tests=ALL_TRUSTED,BAYES_00,SPF_FAIL,
	URIBL_BLOCKED autolearn=no autolearn_force=no version=3.4.0
Received: from Sgrover (unknown [202.46.23.19])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	(Authenticated sender: sgrover)
	by smtp.codeaurora.org (Postfix) with ESMTPSA id 5767BC433CA;
	Tue, 22 Sep 2020 05:02:05 +0000 (UTC)
DMARC-Filter: OpenDMARC Filter v1.3.2 smtp.codeaurora.org 5767BC433CA
From: <sgrover@codeaurora.org>
To: "'Marco Elver'" <elver@google.com>,
	"'Mark Rutland'" <mark.rutland@arm.com>
Cc: "'Will Deacon'" <will@kernel.org>,
	"'Dmitry Vyukov'" <dvyukov@google.com>,
	"'kasan-dev'" <kasan-dev@googlegroups.com>,
	"'Paul E. McKenney'" <paulmck@kernel.org>
References: <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com> <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com> <002801d58271$f5d01db0$e1705910$@codeaurora.org> <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com> <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com> <000801d656bb$64aada40$2e008ec0$@codeaurora.org> <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com> <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com> <20200710175300.GA31697@C02TD0UTHF1T.local> <20200727175854.GC68855@C02TD0UTHF1T.local> <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
In-Reply-To: <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
Subject: RE: KCSAN Support on ARM64 Kernel
Date: Tue, 22 Sep 2020 10:32:02 +0530
Message-ID: <000601d6909d$85b40100$911c0300$@codeaurora.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Microsoft Outlook 16.0
Thread-Index: AQJ871Ey62qcfJFKad6wLawrvPX5+wJ4HpWHAmVWtHAB8QNiiQGzPuwLAmub0xQBs7+38QJ58hsiANCDxewCZEdOqQGbh8AHAjN98uSndmVe4A==
Content-Language: en-us
X-Original-Sender: sgrover@codeaurora.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mg.codeaurora.org header.s=smtp header.b=sCdq8Azf;       spf=pass
 (google.com: domain of bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org
 designates 69.72.42.4 as permitted sender) smtp.mailfrom="bounce+2683c2.be9e4a-kasan-dev=googlegroups.com@mg.codeaurora.org"
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

Hi Mark/Other Maintainers,

Is there any update on KCSAN for arm64 now? 

Thanks,
Sachin

-----Original Message-----
From: Marco Elver <elver@google.com> 
Sent: Monday, 27 July, 2020 11:49 PM
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org; Will Deacon <will@kernel.org>; Dmitry Vyukov <dvyukov@google.com>; kasan-dev <kasan-dev@googlegroups.com>; Paul E. McKenney <paulmck@kernel.org>
Subject: Re: KCSAN Support on ARM64 Kernel

On Mon, 27 Jul 2020 at 19:58, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Jul 10, 2020 at 06:53:09PM +0100, Mark Rutland wrote:
> > On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> > > On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > As a heads-up, since KCSAN now requires clang 11, I was waiting 
> > > > for the release before sending the arm64 patch. I'd wanted to 
> > > > stress the result locally with my arm64 Syzkaller instsance etc 
> > > > before sending it out, and didn't fancy doing that from a 
> > > > locally-built clang on an arbitrary commit.
> > > >
> > > > If you think there'sa a sufficiently stable clang commit to test 
> > > > from, I'm happy to give that a go.
> > >
> > > Thanks, Mark. LLVM/Clang is usually quite stable even the 
> > > pre-release (famous last words ;-)). We've been using LLVM commit 
> > > ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> > > (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).
>
> > Regardless of whether the kernel has BTI and BTI_KERNEL selected it 
> > doesn't produce any console output, but that may be something I need 
> > to fix up and I haven't tried to debug it yet.
>
> I had the chance to dig into this, and the issue was that some 
> instrumented code runs before we set up the per-cpu offset for the 
> boot CPU, and this ended up causing a recursive fault.
>
> I have a preparatory patch to address that by changing the way we set 
> up the offset.
>
> > For now I've pushed out my rebased (and currently broken) patch to 
> > my arm64/kcsan-new branch:
> >
> > git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git 
> > arm64/kcsan-new
>
> I've pushed out an updated branch with the preparatory patch, rebased 
> atop today's arm64 for-next/core branch. Note that due to the BTI 
> issue with generated functions this is still broken, and I won't be 
> sending this for review until that's fixed in clang.

Great, thank you! Let's see which one comes first: BTI getting fixed with Clang; or mainlining GCC support [1] and having GCC 11 released.
:-)

[1] https://lore.kernel.org/lkml/20200714173252.GA32057@paulmck-ThinkPad-P72/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000601d6909d%2485b40100%24911c0300%24%40codeaurora.org.
