Return-Path: <kasan-dev+bncBAABBZ6LQGNQMGQEMQSNJRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id EDDA8614232
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Nov 2022 01:18:48 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id a6-20020a671a06000000b003986a4e277dsf2908963vsa.12
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Oct 2022 17:18:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667261927; cv=pass;
        d=google.com; s=arc-20160816;
        b=kEG1vJGll/6G7AHLkTLCKO7BwZRmrGxBhcqb/Lz14rohEf1FAvtcquROQXv4OGql7H
         x/CbNrXHVr+A++eKRzM3WdqHCYhBNqs0obNIMeq0Kc9LjQ381wVgh2mh2NhOCqAewa7/
         hy8P244pR7pEBp5lRL9tcCvyGOJAi5Z0Aa9E/sd85P8qpjtk4KUOf1bjqUJIwrxKmncf
         gYO11UgyrrnCsiC+5twEMKa83JkR+qbCfvmstgZoIYYwes8fqVKDK8wBshncZJtGWeov
         7zr76xGkz8iFIqZeJJpEZy0uFIODPpRXtTvcokIMbw/IEPXKBOPRoBlF0RHSVPkqt8i9
         z72g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:references
         :in-reply-to:message-id:mime-version:user-agent:feedback-id:sender
         :dkim-signature;
        bh=t3mhP7ICU0ZvQlXWn7SZPX3I7+2TRutiz3n280KqScM=;
        b=BPhi7Fr56Ix4MWlLiiNIlB4Nc68Gh/ihTMztRJp4YkEtyIIC01hNBljNf+1DCswYuH
         oOqndEvEhdhDR6zZyZJhh5nwSQT8emOioYD7yIajd7ZcYrfwoF4H2T0sTt8F4PK6wDUJ
         Nb7lQRJnft8ND9YN7PFYox++jEcVlXqSYm2I9AmeNkUkV00zSyngSF5Mas6VGSpDf5US
         TEFqDzMBUfzJKzGIxsL9j/YS+Oj3brhL+b2T1YWwZUn4+usmAsxg/TdmvDJlSTlkNmWG
         LKlBjlupnwk1rFOFhsKJl5aM9l4fFcbegCd7XpD46FMhktTWnORZxwGi/Pqfb954Lvq4
         QV+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=J1pUU7BE;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=Z3P5fypn;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.25 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:subject:cc:to:from:date:references:in-reply-to
         :message-id:mime-version:user-agent:feedback-id:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=t3mhP7ICU0ZvQlXWn7SZPX3I7+2TRutiz3n280KqScM=;
        b=eS6gwCy7gDIEwIvzMo8CxHJZlA8YeOQLbDxztupqn5nOIz8cm8ttM8484WZCnqxVd5
         HpKoGpjz3trku6nBZRuZCOp8AbJjrwZlUi77XFYp/jq6bCeaFTy2AujccwN1I2LQV/o6
         BcJ8mC+zqI/jt5cGJBsUuf7aP9tvL1MLudpO+hcCU9UMMEu45qCRyp1Tbo2ezLqha1RM
         eZTD+x5nAgrqw9s3+j12VUVpTO7gpjlR0YoeSd6boNOyJXvkAeDWvZYUHxRd72GjMO/V
         80gwOQWtgJi2FTwVmJ259QNzOilSF81Hj2jsw8LaVbZX5KsCAXoYSKUXR/lb+RsU3e7F
         7vXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:subject:cc:to
         :from:date:references:in-reply-to:message-id:mime-version:user-agent
         :feedback-id:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=t3mhP7ICU0ZvQlXWn7SZPX3I7+2TRutiz3n280KqScM=;
        b=upWI1s1+OKUTE/62Vxaccfj88qxpnSk1dh5GQuoT92rd5UCvdfcQTnI1hqf9w0lkYg
         AZjCC5WQhIDFzBcaO3ZA7TtJbFh/7kmgxz0Y7XQnufTVF0dwv04rLcx6Y1aMbw7XBpwU
         iIo9XKtC5jS2kQZSYW5olC8IygM3aaTLpwOTKNxCH14mATbBCFytMeLYo+nyWAjlQiKJ
         9ee7pcRo2UAK5bSAuNwv6v9lZTK+bQ3dRGt1F6trjZzl2w3hDjnsu3HUyWMtlEdBqzdL
         8fdThnPm85QgEmHY1yEPp9UT2HX0GquQgjfAzv3YTj0ihcxEdxaXn/4p3aNH3K8IBVz+
         U4LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2IGv2dLxSHGTJqxgIJocbLVA7bjFdhocORm06suuMCRDFkryFP
	3FHkvvuRTTDpwt9a7kmGPWA=
X-Google-Smtp-Source: AMsMyM7XXpwsuHf+S0Oe8WMwJHLepGK/P7vN3J55KIFH3Fj3gqPvJgsdPC86auqVAinBGHbguMAhzA==
X-Received: by 2002:a1f:4a47:0:b0:3a2:e1f5:6801 with SMTP id x68-20020a1f4a47000000b003a2e1f56801mr6372450vka.20.1667261927631;
        Mon, 31 Oct 2022 17:18:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cb07:0:b0:3aa:3916:1726 with SMTP id b7-20020a67cb07000000b003aa39161726ls2097819vsl.8.-pod-prod-gmail;
 Mon, 31 Oct 2022 17:18:47 -0700 (PDT)
X-Received: by 2002:a67:eada:0:b0:3aa:236a:11d7 with SMTP id s26-20020a67eada000000b003aa236a11d7mr6200763vso.56.1667261927031;
        Mon, 31 Oct 2022 17:18:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667261927; cv=none;
        d=google.com; s=arc-20160816;
        b=rBWrlvjnVS1U+jaXL7zmrMFfn8TdprgiQlBl4WkvBNOp8QKO9Qd1n1aDpyLFQY+UJg
         YevYj6IRsvV9Xu4+au3L+uJhNeaOkBQnEmvhLapL3ikJUg20naCFyrGftwGG/F7DjT6R
         cNyGc9RTedRM9cdCwWRTPn7e8NVDAwjiIXNdeb8YIl90Le4zAZ/FZ66W8HJplJ9Gxw1C
         Unsb54Pw5yGWjkY7bKz0F5AqWvREqJoojr+Ah31ksVHOALpkA/qenAqGGvB14hIVMmqa
         A+buvR/CKZDIVYguWBX0VwROCdJKsReStoTgVMw8NXJLGtGrb+/Q9X289nXlUYw20oEs
         pe8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:references:in-reply-to:message-id
         :mime-version:user-agent:feedback-id:dkim-signature:dkim-signature;
        bh=fimXTSH5ZLpHfGKWM0j4zT+1so1IP4NpiYE5OssGC/c=;
        b=F7cWELFgTmolKK1509E8omwQ8q4EHFOKoIFTkc4GDWy3Gclh8m4QvPP68Dy0neWI6H
         V8G+/2eAsqDv3Oj7NpX9VV5Tzy2opQiObffhYvQZWYgo/ddVhZsw3dJnLRn+yGebRU8k
         s437JbpfGi7tbMdr7R75wsgzHQirhDxc5IH1tZatWNKXQYpc9ivjG6o6zCtYG3rFKBPT
         gOdx7pPNdkyzbf7Zhu7e54MApm2985qCfCFNfzKQBMpQ30pxA1K+wy06S8LNc2efsxhr
         dHAf6iWmPpxrX+FyraBI5CvMllAi5Qr//ykw9/dLmIAHxytaQujZarvAOg89VNN44zOg
         tHsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fastmail.com.au header.s=fm3 header.b=J1pUU7BE;
       dkim=pass header.i=@messagingengine.com header.s=fm3 header.b=Z3P5fypn;
       spf=pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.25 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
Received: from out1-smtp.messagingengine.com (out1-smtp.messagingengine.com. [66.111.4.25])
        by gmr-mx.google.com with ESMTPS id m14-20020a67f70e000000b003980b6c8861si346525vso.2.2022.10.31.17.18.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Oct 2022 17:18:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of lists@johnthomson.fastmail.com.au designates 66.111.4.25 as permitted sender) client-ip=66.111.4.25;
Received: from compute5.internal (compute5.nyi.internal [10.202.2.45])
	by mailout.nyi.internal (Postfix) with ESMTP id 7E4A85C00DA;
	Mon, 31 Oct 2022 20:18:46 -0400 (EDT)
Received: from imap46 ([10.202.2.96])
  by compute5.internal (MEProxy); Mon, 31 Oct 2022 20:18:46 -0400
X-ME-Sender: <xms:5GVgY699hbxKzHuSY6C2zB1vzbhcJfrTYBFw6zJIpB0Y4UJcVYiC2g>
    <xme:5GVgY6vZCxv6bDUxsAm6ECgsB2g9DwFjykHr9X8z2-fhtsqQewgojfFCsS2ZN0Gem
    L2S4UyW-eSGBPz8YQ>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedvgedrudeggddvudcutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpefofgggkfgjfhffhffvvefutgesthdtredtreertdenucfhrhhomhepfdflohhh
    nhcuvfhhohhmshhonhdfuceolhhishhtshesjhhohhhnthhhohhmshhonhdrfhgrshhtmh
    grihhlrdgtohhmrdgruheqnecuggftrfgrthhtvghrnhepkeefhffguddtgeegjedtvedt
    vddvkeevvdehfeehieejhffhhfejkeejgfelveegnecuvehluhhsthgvrhfuihiivgeptd
    enucfrrghrrghmpehmrghilhhfrhhomheplhhishhtshesjhhohhhnthhhohhmshhonhdr
    fhgrshhtmhgrihhlrdgtohhmrdgruh
X-ME-Proxy: <xmx:5GVgYwConxQxZaHrkMScgBLIVSfU_n2Q3-eVscNgZ7QvjD9QPpy_Kw>
    <xmx:5GVgYyf0zV0xhlUqYS56AExooi7Go68jlav443JUV4mdOG-MOaYogw>
    <xmx:5GVgY_PCQxx2lzkC0UmAE1Q1FianhfOY5q98ekgxZsOkucT7AlWxIA>
    <xmx:5mVgY8eDrdN-eX_8gePN0WeOq5TVkwVKJcRXn_uu2i0yNWSbisKDWQ>
Feedback-ID: ia7894244:Fastmail
Received: by mailuser.nyi.internal (Postfix, from userid 501)
	id A370A2A20080; Mon, 31 Oct 2022 20:18:44 -0400 (EDT)
X-Mailer: MessagingEngine.com Webmail Interface
User-Agent: Cyrus-JMAP/3.7.0-alpha0-1087-g968661d8e1-fm-20221021.001-g968661d8
Mime-Version: 1.0
Message-Id: <9b71ae3e-7f53-4c9e-90c4-79d3d649f94c@app.fastmail.com>
In-Reply-To: <Y1+0sbQ3R4DB46NX@feng-clx>
References: <20220913065423.520159-1-feng.tang@intel.com>
 <20220913065423.520159-2-feng.tang@intel.com>
 <becf2ac3-2a90-4f3a-96d9-a70f67c66e4a@app.fastmail.com>
 <af2ba83d-c3f4-c6fb-794e-c2c7c0892c44@suse.cz> <Y180l6zUnNjdCoaE@feng-clx>
 <c4285caf-277c-45fd-8fc7-8a1d61685ce8@app.fastmail.com>
 <Y1+0sbQ3R4DB46NX@feng-clx>
Date: Tue, 01 Nov 2022 00:18:19 +0000
From: "John Thomson" <lists@johnthomson.fastmail.com.au>
To: "Feng Tang" <feng.tang@intel.com>
Cc: "Vlastimil Babka" <vbabka@suse.cz>,
 "Andrew Morton" <akpm@linux-foundation.org>,
 "Christoph Lameter" <cl@linux.com>, "Pekka Enberg" <penberg@kernel.org>,
 "David Rientjes" <rientjes@google.com>,
 "Joonsoo Kim" <iamjoonsoo.kim@lge.com>,
 "Roman Gushchin" <roman.gushchin@linux.dev>,
 "Hyeonggon Yoo" <42.hyeyoo@gmail.com>, "Dmitry Vyukov" <dvyukov@google.com>,
 "Jonathan Corbet" <corbet@lwn.net>,
 "Andrey Konovalov" <andreyknvl@gmail.com>,
 "Hansen, Dave" <dave.hansen@intel.com>,
 "linux-mm@kvack.org" <linux-mm@kvack.org>,
 "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 "Robin Murphy" <robin.murphy@arm.com>, "John Garry" <john.garry@huawei.com>,
 "Kefeng Wang" <wangkefeng.wang@huawei.com>
Subject: Re: [PATCH v6 1/4] mm/slub: enable debugging memory wasting of kmalloc
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lists@johnthomson.fastmail.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fastmail.com.au header.s=fm3 header.b=J1pUU7BE;       dkim=pass
 header.i=@messagingengine.com header.s=fm3 header.b=Z3P5fypn;       spf=pass
 (google.com: domain of lists@johnthomson.fastmail.com.au designates
 66.111.4.25 as permitted sender) smtp.mailfrom=lists@johnthomson.fastmail.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fastmail.com.au
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

On Mon, 31 Oct 2022, at 11:42, Feng Tang wrote:
> On Mon, Oct 31, 2022 at 10:05:58AM +0000, John Thomson wrote:
>> On Mon, 31 Oct 2022, at 02:36, Feng Tang wrote:
>> >> > 
>> >> > possibly relevant config options:
>> >> > grep -E '(SLUB|SLAB)' .config
>> >> > # SLAB allocator options
>> >> > # CONFIG_SLAB is not set
>> >> > CONFIG_SLUB=y
>> >> > CONFIG_SLAB_MERGE_DEFAULT=y
>> >> > # CONFIG_SLAB_FREELIST_RANDOM is not set
>> >> > # CONFIG_SLAB_FREELIST_HARDENED is not set
>> >> > # CONFIG_SLUB_STATS is not set
>> >> > CONFIG_SLUB_CPU_PARTIAL=y
>> >> > # end of SLAB allocator options
>> >> > # CONFIG_SLUB_DEBUG is not set
>> >> 
>> >> Also not having CONFIG_SLUB_DEBUG enabled means most of the code the 
>> >> patch/commit touches is not even active.
>> >> Could this be some miscompile or code layout change exposing some 
>> >> different bug, hmm.
>> 
>> Yes, it could be.
>> 
>> >> Is it any different if you do enable CONFIG_SLUB_DEBUG ?
>> 
>> No change
>> 
>> >> Or change to CONFIG_SLAB? (that would be really weird if not)
>> 
>> This boots fine
>> 
>> > I haven't found any clue from the code either, and I compiled
>> > kernel with the config above and tested booting on an Alder-lake
>> > desktop and a QEMU, which boot fine.
>> >
>> > Could you provide the full kernel config and demsg (in compressed
>> > format if you think it's too big), so we can check more?
>> 
>> Attached
>> 
>> > Thanks,
>> > Feng
>> 
>> vmlinux is bigger, and entry point is larger (0x8074081c vs 0x807407dc revert vs 0x8073fcbc),
>> so that may be it? Or not?
>> revert + SLUB_DEBUG + SLUB_DEBUG_ON is bigger still, but does successfully boot.
>> vmlinux entry point is 0x8074705c
>
> Thanks for prompt info!
>
> As I can't reproduce it locally yet, could you help try 3 tests separately:
> * change the O2/O3 compile option to O1
> * try the attached 0001 patch (which cut part of commit)
> * try attached 0001+0002 patch

None of these changed my outcome.

I also tried compiling the same linux tree & config with the Bootlin toolchain
(mipsel-buildroot-linux-gnu-gcc.br_real (Buildroot 2021.11-4428-g6b6741b) 12.2.0)
with the same results.
I will look into finding or building a mips clang toolchain.

No JTAG capability to debug, sorry.

I get the same outcome with either the ZBOOT vmlinuz, or vmlinux

Same happening with 6.1-rc3


After some blind poking around changing (how much of the commit affected) mm/slub.c,
I may have got lucky. it appears as though this is all I need to boot:
(against 6.1-rc3), and with the Bootlin toolchain. Will test my other build system as well.

--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3276,7 +3276,7 @@ static void *__slab_alloc(struct kmem_cache *s, gfp_t gfpflags, int node,
        c = slub_get_cpu_ptr(s->cpu_slab);
 #endif
 
-       p = ___slab_alloc(s, gfpflags, node, addr, c, orig_size);
+       p = ___slab_alloc(s, gfpflags, node, addr, c, 0);
 #ifdef CONFIG_PREEMPT_COUNT
        slub_put_cpu_ptr(s->cpu_slab);
 #endif


Would like to hear your thoughts, but I will keep digging.

>
> Thanks!
>
>
> - Feng
>
>
>
>
> Attachments:
> * 0001-reduced-slub-patch.patch
> * 0002-reorder-the-partial_context-initialization.patch

-- 
  John Thomson

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9b71ae3e-7f53-4c9e-90c4-79d3d649f94c%40app.fastmail.com.
