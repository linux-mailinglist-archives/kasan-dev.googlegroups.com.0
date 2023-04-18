Return-Path: <kasan-dev+bncBDEKVJM7XAHRBHM27KQQMGQEH5HBX6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CA096E6201
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 14:29:19 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id d10-20020a25cd0a000000b00b956d4a5a04sf1225029ybf.22
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Apr 2023 05:29:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681820958; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vx3YkZ8/4aaRyifLrycOaDjbYAuoXPzveqTI664FzDP6HW/saTwjfqGTHDVcU+0RnF
         7b0qQKGgVQAGJVaJ9Kg72qtAOwQwICQblitkJGzuBXYZQaSCsw/LAf3E4dscTsjDGabS
         TZBLjdEMbo6qjlM2khNtp6LVAFP2rI5iu69YQvDh9BftDE0FTVgk/MZlW/Tuv4/pUbPb
         ggC1gWmfRl3eFgnWHiBntLyvdIdvj3+vWJpyRWg7YZThB4VJpooWOmS7y33+b3jFPBSo
         9skOxAOQbsV7zTwQ3vq4VMcnb+34ss/cVZIRTbFTfuCLxmuJc082DplXCETocknEuKnj
         Qwew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=CFQeJGSrQg/WzAZe25NzkP6tNS78G8Pqstq07p7FrB8=;
        b=MY9Y8mF+UIl5Z31JXbf2JuZEmLQHVWGkKtMOUk0JyIAgoFZicQ69rZNwqurPIWKHgr
         tqu+hAwRp8Yx2c5vidn8hOFj22oLsZU6C8ExuqpadGDcX9FLNtO18/+Hw7eK/qlU8lxa
         aOxWfszY7s0MSGdb7hxlKiemcfQ7uPgTyYrnkpX2eAu0z01nrxhSVa1tQUQmwVLJyaYn
         4WTY+7PVwdGHym1KxJe2L9BhI03y+UFhQx6TJ2J0Xb1Fw8mxMJ5cpGHMceC2unH0pEDq
         7vVehT+SP3FJcU1YGwGWwyLDdcFaPg0l7JJM4PT9nujQIGkP5JZlGtow9mDAg2vR3pT8
         nBCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b="fD2wHJI/";
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=fr585nbR;
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.26 as permitted sender) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681820958; x=1684412958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CFQeJGSrQg/WzAZe25NzkP6tNS78G8Pqstq07p7FrB8=;
        b=HCr27Ahg8+UH1X6YlXD3oAf+/bPA6ll2AZSAdGZH4ivjbIEUZfwpJFKnyFDTNt2CFG
         sTowtpnOVl3cRrc1U9p9ghCSqzCkszWjdZFL/V92BbO/jvFw1uKh4wRZjKyZT+5xoDkt
         KGEOut8Lq1qrvvS25mtf4NkFqLZVIALx++CaUIFkVnST9x6EqE2k86gMUDvw4n6yfXKh
         Aey2EFTDqIuQctDsESmIrb6ZcRxra024FENIn8U2hhIjt+XX5LVReMQPUVIOJGMtSZTm
         CHPbrgChmqvzLkDoaWrfLGeYMNMXmbyrDfYMetFmTEX+snSGWNAYU9L+6zhV7Kza76Rz
         rAtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681820958; x=1684412958;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CFQeJGSrQg/WzAZe25NzkP6tNS78G8Pqstq07p7FrB8=;
        b=PA4GeX6H7K8IbSgG03dNhc6frmWA+oSPoZCRCmTQaNAfqmSETZ66fdGj93IdgJOJ8H
         Mxw+WIxoPt0Su6qo4XmtmwuwsiiXCokR8M6GGi+H7plWSl5a5DrIUFYnUvtkaGk+sUDw
         swVNR6GTF1aKeR58lXnSpMby14g+PkoMz0k+HNGsBOQ0yM66Rnu79Nk/+AZUSgIlZUAI
         1dWTs5hC/1HFnitFGABG4ocIIRbuXhm55J8R9xcWK5vSfght+qTPurJ9IxBVZbjiE5sc
         NiElnN+6PiX5tGC/ZgkY2Bjopaoe+qJLGZN6d5+FAjrpwl7pZBfwAl2/JHtfpDvXF4XZ
         E8Uw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9ereJFl1kNk57h3ZQkDYVRCvijk8M1Mt4PLxxsQNpQCToqqk67O
	uluVju0woDTIELhj3FYzBXo=
X-Google-Smtp-Source: AKy350b8wjGonO34eb802uoRnf9qPfE00KW7dEZ8di4vbEJ4WZrf5eSWU39yX+LDP+OAU6O3nZ9SvQ==
X-Received: by 2002:a25:d08d:0:b0:b7c:1144:a708 with SMTP id h135-20020a25d08d000000b00b7c1144a708mr12096557ybg.12.1681820957853;
        Tue, 18 Apr 2023 05:29:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:a8a:b0:54c:a1d:c77e with SMTP id
 ci10-20020a05690c0a8a00b0054c0a1dc77els11292801ywb.8.-pod-prod-gmail; Tue, 18
 Apr 2023 05:29:17 -0700 (PDT)
X-Received: by 2002:a81:9249:0:b0:546:2787:4b93 with SMTP id j70-20020a819249000000b0054627874b93mr21030027ywg.35.1681820957087;
        Tue, 18 Apr 2023 05:29:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681820957; cv=none;
        d=google.com; s=arc-20160816;
        b=I2Sabd9nPDQRiPmxKv3GSNiIsDArgeN40gFaopv8C2YBxTPU+d+zhmRY6o5r2qMGZO
         CzKikhSb/kjIk6G0CwwRlz24zp0gL874bU6VXxz0sD1saOjy+sJVNDaajiTzApHBd7gn
         uLIYtMPflq4K3TK48LCaNacIembsj6PSlEx0tA2VgGEI93PK+PlGViUuj3m551gcD4hs
         Xa8lcXIcUoITx26W3C2tAeyWHd/0GsHVqn+GLI1xNdZqZ8UwqT8vGHQJua+mF+b7KalV
         Oxj8+saC6UjR75ZePO2K1xVtkI1zZz2YVrAvy0bPI+y1JdX55KbqEywYT7eLuZj6Ikgy
         wxmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=VMwb91EjeaIIwMVJOlqozliVSEbH/Bchyh3fjPDYvkE=;
        b=ipb0XomCEvFnhMcVvd4rPR3D7QDAzMdxQocfi+y/SkANNyc5Ccye/HC8L6G6g9Y6zw
         metNTMvoWIUESlqHpMYykjSb0ds1LCFARaQdJaTksSl7Nd2sQAUgxXtmpQx0W2j8NhKQ
         ySEpzJmHZ3TEZitxJx3lPaMSpYTQllY1fp/XhpR2ixpIsAdkZG2PVc5SGe2Bt5NXABw0
         oGK8Vxhq+YCCIJ7ux4dfqQcLzG95Ntzg25nYDkumk26N5cZ+o0h50wjPxJokBrpJ5qtZ
         YZQxSHufAX6Wz6/B+BviACLqHWb4uykQgL3k26VkuTt15CtMIWYkowequSA5QwtFR7bz
         LSpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@arndb.de header.s=fm2 header.b="fD2wHJI/";
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=fr585nbR;
       spf=pass (google.com: domain of arnd@arndb.de designates 66.111.4.26 as permitted sender) smtp.mailfrom=arnd@arndb.de
Received: from out2-smtp.messagingengine.com (out2-smtp.messagingengine.com. [66.111.4.26])
        by gmr-mx.google.com with ESMTPS id bw32-20020a05690c07a000b005343a841489si763344ywb.3.2023.04.18.05.29.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Apr 2023 05:29:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of arnd@arndb.de designates 66.111.4.26 as permitted sender) client-ip=66.111.4.26;
Received: from compute6.internal (compute6.nyi.internal [10.202.2.47])
	by mailout.nyi.internal (Postfix) with ESMTP id 9C6495C00E8;
	Tue, 18 Apr 2023 08:29:16 -0400 (EDT)
Received: from imap51 ([10.202.2.101])
  by compute6.internal (MEProxy); Tue, 18 Apr 2023 08:29:16 -0400
X-ME-Sender: <xms:G40-ZOECZtfLzU_dRwIEh_PFY0w4UQVr2KtuOtXeVZMJ48l5Uil3PA>
    <xme:G40-ZPV7Z2oMUqoPDeSe0vuHqjtC0mhP7wZz96tkK9zTbmTJHq0bX-JV4RbimIrOz
    eloZFjxTvpoONFCcd0>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvhedrvdelkedghedvucetufdoteggodetrfdotf
    fvucfrrhhofhhilhgvmecuhfgrshhtofgrihhlpdfqfgfvpdfurfetoffkrfgpnffqhgen
    uceurghilhhouhhtmecufedttdenucesvcftvggtihhpihgvnhhtshculddquddttddmne
    cujfgurhepofgfggfkjghffffhvfevufgtsehttdertderredtnecuhfhrohhmpedftehr
    nhguuceuvghrghhmrghnnhdfuceorghrnhgusegrrhhnuggsrdguvgeqnecuggftrfgrth
    htvghrnhepffehueegteeihfegtefhjefgtdeugfegjeelheejueethfefgeeghfektdek
    teffnecuvehluhhsthgvrhfuihiivgeptdenucfrrghrrghmpehmrghilhhfrhhomheprg
    hrnhgusegrrhhnuggsrdguvg
X-ME-Proxy: <xmx:G40-ZII9qvrLW9EVD0ArNGrVCJfcHsQkE1vI1ulk9_FEwuyg7aPyTg>
    <xmx:G40-ZIFoemLCyuhosrpjJst5IN9jbd8FSAV4OJ54ri-kWgradjVBLg>
    <xmx:G40-ZEUpMllTfuXekGh_6pVCsNSv2cXoIj9asP96ZSLjiPVdvu_tWA>
    <xmx:HI0-ZAn8YOLM7OFf3Tw8Ff7KmWXEQWEZ5sdyUmu5c62ZBUETdz2YoA>
Feedback-ID: i56a14606:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id B7D7BB60089; Tue, 18 Apr 2023 08:29:15 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.9.0-alpha0-372-g43825cb665-fm-20230411.003-g43825cb6
Mime-Version: 1.0
Message-Id: <c28486a2-dc12-4613-abda-bdeace783d40@app.fastmail.com>
In-Reply-To: <CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com>
References: <20230414082943.1341757-1-arnd@kernel.org>
 <20230414162605.GA2161385@dev-arch.thelio-3990X>
 <CANpmjNMwYosrvqh4ogDO8rgn+SeDHM2b-shD21wTypm_6MMe=g@mail.gmail.com>
Date: Tue, 18 Apr 2023 14:28:55 +0200
From: "Arnd Bergmann" <arnd@arndb.de>
To: "Marco Elver" <elver@google.com>, "Nathan Chancellor" <nathan@kernel.org>
Cc: "Arnd Bergmann" <arnd@kernel.org>,
 "Andrey Ryabinin" <ryabinin.a.a@gmail.com>,
 "Masahiro Yamada" <masahiroy@kernel.org>,
 "Nick Desaulniers" <ndesaulniers@google.com>,
 "Nicolas Schier" <nicolas@fjasle.eu>,
 "Alexander Potapenko" <glider@google.com>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Dmitry Vyukov" <dvyukov@google.com>,
 "Vincenzo Frascino" <vincenzo.frascino@arm.com>, "Tom Rix" <trix@redhat.com>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Michael Ellerman" <mpe@ellerman.id.au>,
 "Peter Zijlstra" <peterz@infradead.org>, linux-kbuild@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 llvm@lists.linux.dev
Subject: Re: [PATCH] kasan: remove hwasan-kernel-mem-intrinsic-prefix=1 for clang-14
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@arndb.de header.s=fm2 header.b="fD2wHJI/";       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=fr585nbR;       spf=pass
 (google.com: domain of arnd@arndb.de designates 66.111.4.26 as permitted
 sender) smtp.mailfrom=arnd@arndb.de
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

On Tue, Apr 18, 2023, at 14:06, Marco Elver wrote:
> On Fri, 14 Apr 2023 at 18:26, Nathan Chancellor <nathan@kernel.org> wrote:
>> On Fri, Apr 14, 2023 at 10:29:27AM +0200, Arnd Bergmann wrote:
> It errors as expected. But with:
>
>> clang -Werror -mllvm -hwasan-does-not-exist -c -x c /dev/null -o /dev/null
>
> It ends up printing _help_ text, because anything "-h..." (if it
> doesn't recognize it as a long-form argument), will make it produce
> the help text.

Ah, that explains a lot. I think I actually tried a few other options, but
probably only edited part of the option name, and not the beginning, so
I always saw the help text.

>> >  # Instrument memcpy/memset/memmove calls by using instrumented __hwasan_mem*().
>> > +ifeq ($(call clang-min-version, 150000),y)
>> >  CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>> > +endif
>> > +ifeq ($(call gcc-min-version, 130000),y)
>> > +CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>> > +endif
>>
>> I do not think you need to duplicate this block, I think
>>
>>   ifeq ($(call clang-min-version, 150000)$(call gcc-min-version, 130000),y)
>>   CFLAGS_KASAN += $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=1)
>>   endif
>
> We just need the clang version check. If the compiler is gcc, it'll do
> the "right thing" (i.e. not print help text). So at a minimum, we need
> if "clang version >= 15 or gcc". Checking if gcc is 13 or later
> doesn't hurt though, so I don't mind either way.

I've sent a v2 now, with an updated help text and the simplified
version check.

It might be possible to change the cc-option check in a way that
parses the output, this variant should do that, if we care:

echo "char *str = \"check that assembler works\";" | clang -Werror -mllvm -hwasan-does-not-exist  -S -x c - -o - | grep -q "check that assembler works"

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c28486a2-dc12-4613-abda-bdeace783d40%40app.fastmail.com.
